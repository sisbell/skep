//! The process: one long-running server owning one `World`. The daemon is
//! transport, configuration, and lifetime — every handler is
//! parse/marshal/dispatch/configure; every decision lives in a store.
//!
//! Split for testability: [`Daemon`] holds the state and routes
//! `&HttpRequest → Routed` with no socket anywhere; [`serve`]/[`Skepd`]
//! wrap it in a synchronous accept loop over a plain `TcpListener`. The
//! HTTP/1.1 subset this daemon speaks (GET/POST/OPTIONS, `Content-Length`
//! bodies, one request per connection, `Connection: close` on every
//! response) is written out here rather than taken from a server library,
//! because the commit stream needs two things a pull-based library response
//! cannot give: event bytes flushed to the socket at commit time, and a
//! server-initiated close at shutdown. Owning the socket makes both
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
//! inside `Engine::open`. The only files this crate writes itself are the
//! commit-metadata sidecar `commits.log` and, transiently while that file
//! is compacted, `commits.log.compact` — both opened here through
//! `WritePath::open` and owned by `sidecar.rs`; nothing here writes any
//! file of the WORLD's, which is why two daemons replaying one journal
//! still converge byte-identically.
//!
//! **Identity is the AUTH session layer** (`auth/`): `GET /challenge` and
//! `POST /session` mint a session by one of two arms — a BARE bind (v1's
//! form, honored only from a loopback peer at an admitted origin, and only
//! while the board is not ENFORCING) or a SIGNED challenge/response — and
//! the daemon maps the opaque token → M10-minted `SessionId` in its own
//! state, so a `SessionId` never rides the wire (M10's non-forgeability
//! precondition). A request with no token, or one whose binding is gone,
//! runs under a pre-retired guest session: reads are principal-free and
//! succeed, writes get M10's own `Unauthenticated`, and a token naming a
//! binding this daemon has closed carries `Skepd-Session: closed` back.
//! `auth/` owns the rest and this file holds none of it: the two origin
//! sets and their publication, the handshake, the credential write lock,
//! the ordered refusal producers, and the identity fold rebuilt beside the
//! engine.
//! What this file adds is the two write sequences that call them in their
//! pinned order, and the `/session` and `/health` marshals. Tokens are
//! uptime-scoped; the daemon binds 127.0.0.1 only.
//!
//! **Cross-origin posture (wire v7)**: every response carries
//! `Access-Control-Allow-Origin: *` and
//! `Access-Control-Expose-Headers: Skepd-Session`, written from one
//! constant ([`UNIVERSAL_HEADERS`]) by both response writers — the reply
//! path and the event stream — so nothing this daemon answers can miss
//! them, and `OPTIONS` on any known path answers a 204 preflight naming
//! the allowed methods and headers. The `*` is a scope decision, and it
//! was revisited when authentication landed (wire.md §Cross-origin
//! access): it stays, because neither credential is browser-ambient.
//! Reads are principal-free, so `*` grants any page the whole read
//! surface. Writes do not follow it: a write needs a session,
//! [`crate::auth::bare_bind_allowed`] refuses a bare bind whose `Origin`
//! is not in the bare set (a browser sends that header on every
//! cross-origin POST), and the signed arm binds its origin inside the
//! signature. A foreign page's POST is fenced by the daemon rather than
//! by what the browser lets it read back, which is why a narrower ACAO
//! was weighed and declined.
//!
//! **Writes go through one card** (`write_path.rs`): `POST /op` — the
//! daemon's only live write path — hands each write to
//! `WritePath::commit_under`, which commits it, records its change-feed
//! entry, and announces its position, in that order and inside the
//! serialization guard the write sequences here hold. What this file adds
//! is the frame's parse, its classification, and the two write sequences,
//! which take `serial_lock` themselves so their gates and the execute they
//! gate stand on one committed state; the ordering the commit stream and
//! the change feed below rest on is not a thing a handler here can take
//! apart. Reads execute directly and take no lock.
//!
//! **The commit stream (wire v4)**: `GET /events` is a `text/event-stream`
//! of committed log positions — one event carrying the last announced
//! position on connect, then an event whenever the head advances.
//! `write_path.rs` owns the stream: what a subscriber is told first and
//! next, and the coalescing that falls out of asking "anything past what I
//! last sent"; [`Subscribers`] below owns the budget, the admission, and
//! the join at shutdown. What this file adds is the SSE framing
//! (`serve_events`) and the hand-off that keeps an open stream off the op
//! pool — the accepting worker gives the socket to a dedicated thread and
//! returns to `accept`.
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

use std::io::{self, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use parking_lot::Mutex;
use serde_json::Value;
use skep_engine::{Engine, EngineError, HistoryError, World};
use skep_febe::{Codec, Disposition, Operation, OpKind, Request, Response, SessionId};
use skep_identity::IdentityState;
use skep_kernel::{BurnedSeqPolicy, CheckpointPolicy, Durability, KernelConfig, Seq, Snapshot};
use skep_namespace::PrincipalId;

use crate::auth::fold::{canonical_identity, key_set_of};
use crate::auth::policy::{
    deposits_credential_link, op_shape_refusal, plain_refusal, CredentialRefusal,
    DepositSpans,
};
use crate::auth::session::{
    handshake, parse_session_body, resolve, Actor, GuestReason, SessionBinding, Token,
    CHALLENGE_TTL,
};
use crate::auth::{
    bare_origins, signed_origins, startup_warnings, AuthOptions, AuthState, OsEntropy,
};
use crate::codec::{
    check_keys, daemon_rejected, key_set_reply, obj, to_bytes, DaemonOp, DaemonRejection,
    JsonCodec, CREDENTIAL_REFUSED,
};
use crate::history::{History, ReconstructPermit, Unavailable};
use crate::sidecar::ChangesAnswer;
use crate::write_path::{op_is_read, write_meta, FrameMeta, StreamStep, WritePath};

pub use crate::auth::session::Peer;

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

/// The deadline for one transfer — the request in, or the answer out. It is
/// checked BETWEEN socket calls, so a call already in flight when it passes
/// runs to its own socket timeout: each direction is bounded at this plus
/// [`REQUEST_READ_TIMEOUT`] or [`WRITE_TIMEOUT`], and a connection — which
/// performs at most one of each — at twice that, plus whatever its handler
/// is doing.
///
/// [`REQUEST_READ_TIMEOUT`] and [`WRITE_TIMEOUT`] bound SILENCE — each is a
/// per-call socket deadline, renewed by any byte — so only this bounds
/// SLOWNESS. Without it a peer sending (or draining) one byte per interval
/// renews the socket deadline indefinitely and holds its worker for as long
/// as it cares to: [`MAX_REQUEST_BODY`] at one byte per interval is years,
/// and `workers` such peers occupy the whole pool, leaving the daemon
/// answering nothing with every structure inside it healthy. It is also
/// what makes [`Skepd::shutdown`]'s bound true, since that stop joins a
/// worker that may be mid-request.
///
/// The two halves are bounded SEPARATELY and not as one window, so that a
/// request refused for exhausting its own deadline still has a deadline in
/// which to be told so: a single shared window would make the refusal
/// undeliverable by construction, which is the never-silent contract lost
/// at the one place it is hardest to notice.
///
/// Loopback delivers the largest admissible body in milliseconds, so 30 s
/// is four orders of magnitude of headroom over any honest client.
const TRANSFER_DEADLINE: Duration = Duration::from_secs(30);

/// Preflight cache lifetime advertised on `OPTIONS` (wire v4).
const CORS_MAX_AGE_SECS: &str = "86400";

/// The headers wire.md promises on EVERY response: the cross-origin
/// posture, the exposure that lets a page read the death signal, and the
/// one-request-per-connection framing. Written once because the event
/// stream's head is composed outside [`write_reply`] — a stream is not a
/// request/response reply — so a change to any of them must reach both
/// writers or reach neither.
///
/// Exported because [`Reply`] names them as a caller's obligation. They are
/// name/value pairs — the same shape [`Reply::headers`] carries — rather
/// than this daemon's own CRLF bytes, so a caller serving replies over a
/// transport of its own supplies them however that transport spells a
/// header instead of parsing a framing only this crate's writer can use.
pub const UNIVERSAL_HEADERS: [(&str, &str); 3] = [
    ("Access-Control-Allow-Origin", "*"),
    // AUTH-6.12: `Skepd-Session` is not CORS-safelisted, so without this a
    // client on a configured non-loopback origin could not read the death
    // signal. Exposing a public header narrows nothing; the fence stays
    // daemon-side.
    ("Access-Control-Expose-Headers", "Skepd-Session"),
    ("Connection", "close"),
];

/// The one request header this daemon reads beyond HTTP's own framing: the
/// opaque session token. Named once because the CORS preflight must
/// advertise exactly the header the reader consults — a header the
/// preflight omits is one the browser will not send, so the two must agree
/// or every cross-origin write fails at a layer this crate's own suite,
/// which writes the header straight onto a socket, never reaches.
const SESSION_HEADER: &str = "Skepd-Session";

/// Request-head size cap. Tokens and headers are small; frames ride in the
/// body, capped separately by the route's [`body_cap`].
///
/// [`read_request`] scans for the head terminator incrementally, so the work
/// this bounds is LINEAR in the head — the property a raise must preserve,
/// since a rescan from zero after every read would make it quadratic in this
/// number.
const MAX_REQUEST_HEAD: usize = 64 * 1024;

/// Request-body cap for the two frame-carrying routes, enforced on the
/// declared `Content-Length` before any body byte is read or allocated.
/// Pre-media value — wire frames are small.
///
/// This bounds the REQUEST, not the allocation it commands, and the ratio
/// between them is what anyone raising it must price. The FLOOR under every
/// JSON-carrying route is `serde_json`'s: the whole `Value` tree is built
/// before any codec cap runs, and a `Value` is order 32 bytes against as
/// little as two wire bytes of dense array, so a body of arbitrary shape
/// buys roughly twenty times its size in transient heap — for a frame the
/// codec is then about to refuse. Above that floor the per-byte write
/// discipline adds the `insert` path's own multiplier, minting one `Val`
/// per input byte, each its own allocation, for roughly forty times the
/// body in live heap; the codec's `MAX_INSERT_VALUES` is what bounds that
/// one. Raising this number alone raises both amplified costs with it.
///
/// REVISIT at the media round: blob upload raises this for its route only,
/// which is the shape [`body_cap`] already has.
const MAX_REQUEST_BODY: usize = 8 * 1024 * 1024;

/// Request-body cap for every route that carries no frame. `POST /session`
/// carries `{"principal": n}`; a body posted to `/health`, `/changes`,
/// `/dump` or an unknown path is read whole and then never looked at. Those
/// routes have no use for the ceiling above, and offering it to them offers
/// the `Value` tree that rides on it.
const MAX_SMALL_BODY: usize = 8 * 1024;

/// The body cap for a path — checked on the declared `Content-Length`
/// before a byte is read, so a route that cannot use a large body is never
/// asked to allocate for one.
///
/// Public because [`HttpRequest`] names it as a caller's obligation: a
/// caller building a request for [`Daemon::route`] over a transport of its
/// own takes the bound from here rather than transcribing it, so a
/// route-scoped raise — the media round [`MAX_REQUEST_BODY`] anticipates —
/// moves for them too.
pub fn body_cap(path: &str) -> usize {
    match path {
        "/op" | "/op-at" => MAX_REQUEST_BODY,
        _ => MAX_SMALL_BODY,
    }
}

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
    /// checkpoint).
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
/// bytes for. `content_type` names the `Content-Type` header verbatim,
/// which is HTTP's word and not the substrate's.
///
/// A REQUEST's body is bare bytes ([`HttpRequest::body`]) because this
/// daemon does not read the type a client declares, while every response it
/// writes must declare one. That is one concept in two shapes, not two
/// concepts.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Body {
    pub content_type: &'static str,
    pub bytes: Vec<u8>,
}

/// One handler result: a status, an optional body, and any extra headers.
/// `POST /op` is always `200` once a `Response` exists — rejections
/// included; the `Response` envelope, not the HTTP status, is the operation
/// protocol. Non-200 codes are transport-level only (`{"error": …}` bodies,
/// wire.md §Transport errors).
///
/// `body: None` is the bodiless answer, written with no content headers
/// at all (the 204 preflight). Making bodilessness the body's own absence
/// is what keeps the writer from inferring it from the status, where a 204
/// built with bytes would drop them in silence.
///
/// A HANDLER'S ANSWER, not a complete HTTP response. Two kinds of header
/// come from [`write_reply`] rather than from any `Reply` value:
/// `Content-Type` and `Content-Length`, which it derives from the `body`
/// field below and omits entirely when there is none, and every member of
/// [`UNIVERSAL_HEADERS`], which wire.md §Transport and §Cross-origin access
/// promise on EVERY response. A caller serving these over a transport of
/// its own owes that constant's members — and takes them from it rather
/// than transcribing them, so a change to the cross-origin posture moves
/// for them too.
#[derive(Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Reply {
    pub status: u16,
    pub body: Option<Body>,
    /// Extra response headers beyond what [`write_reply`] supplies —
    /// `Content-Type` and `Content-Length` from the body, and
    /// [`UNIVERSAL_HEADERS`] always. The preflight trio rides here, as does
    /// the death signal; that constant is `write_reply`'s to supply, not
    /// this list's.
    pub headers: Vec<(&'static str, &'static str)>,
}

/// The body's LENGTH, never its bytes: a `/dump` reply is a whole world and
/// an inlined body would make `dbg!` useless exactly where it is reached
/// for.
impl std::fmt::Debug for Reply {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Reply")
            .field("status", &self.status)
            .field("content_type", &self.body.as_ref().map(|b| b.content_type))
            .field("body_len", &self.bytes().len())
            .field("headers", &self.headers)
            .finish()
    }
}

impl Reply {
    /// The body bytes; empty for a bodiless reply.
    pub fn bytes(&self) -> &[u8] {
        self.body.as_ref().map_or(&[], |b| b.bytes.as_slice())
    }

    /// A reply carrying `bytes` under `content_type`.
    fn bodied(status: u16, content_type: &'static str, bytes: Vec<u8>) -> Reply {
        Reply {
            status,
            body: Some(Body { content_type, bytes }),
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
    /// and header lists. `Access-Control-Allow-Origin: *` is in
    /// [`UNIVERSAL_HEADERS`], which both response writers emit, so it is not
    /// repeated here.
    ///
    /// The method list must name every method [`Daemon::reply`] dispatches,
    /// for the same reason [`SESSION_HEADER`] is a constant: a method the
    /// preflight omits is one the browser will not send, and that failure
    /// appears only cross-origin, where this suite's own TCP clients never
    /// look. The list is a joined `&'static str` and so cannot be built
    /// from the router's arms; the coupling is held by
    /// `the_route_set_agrees_across_preflight_dispatch_and_refusal`, which
    /// discovers the dispatched set rather than restating it.
    fn preflight() -> Reply {
        Reply {
            status: 204,
            body: None,
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
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Routed {
    Reply(Reply),
    /// `GET /events` — the server-sent commit stream (wire v4).
    ///
    /// Serviceable only through [`serve`]: following the stream is
    /// `write_path.rs`'s and crate-private, so a caller routing by hand can
    /// answer this variant only by refusing the route. It is the one
    /// endpoint the socket-free surface names and cannot serve.
    EventStream,
}

/// One request, as [`Daemon::route`] receives it and as the socket reader
/// builds it — one value rather than a list of arguments, so the two
/// `Option<String>`s cannot be handed over in the wrong order.
///
/// PRECONDITION on every field, established by [`read_request`] and owed by
/// any other caller of [`Daemon::route`]: `method` is the uppercase token;
/// `path` is the request target with its query AND its `?` removed; `query`
/// is what followed that `?`, without it; `session_token` and `origin` are
/// the `Skepd-Session` and `Origin` header values VERBATIM, or `None` when
/// the header is absent — never normalized and never defaulted; `peer` is
/// the transport's own answer about the remote address of THIS connection;
/// `body` is exactly the declared `Content-Length` bytes, and at most
/// [`body_cap`] of `path` of them.
///
/// Routing re-checks none of them — it cannot tell a caller's mistake from a
/// client's request — and what a violation costs is not uniform. The first
/// three and the last are answered honestly for the request as given and
/// misleadingly for the one intended: a `path` still carrying its query is
/// an unknown path (`404`), a lowercase `method` matches no arm (`405`), a
/// `query` still carrying its `?` names a parameter called `?since`.
/// `origin` and `peer` are different in kind: a violation there is a SILENT
/// WIDENING of the one privilege this daemon grants without a signature. An
/// absent `origin` reads as "no `Origin` header", which
/// [`crate::auth::bare_bind_allowed`] admits, so a caller that does not
/// forward the header removes the daemon-side fence; and a `peer` reported
/// `Loopback` for a socket that is not one hands the bare bind to the
/// network.
///
/// The body cap is the OUTERMOST bound on what a frame allocates, and the
/// one clause a caller cannot discharge by inspection: every JSON-carrying
/// route builds the whole `serde_json` tree before any codec cap runs, so a
/// body admitted past it buys roughly twenty times its size in transient
/// heap — for a frame the codec is then about to refuse. [`read_request`]
/// enforces it on the declared `Content-Length`, before a byte is read.
pub struct HttpRequest {
    /// The method token, uppercase ASCII (`GET`, `POST`, `OPTIONS`).
    pub method: String,
    /// The request target with any query stripped — `/op`, `/changes`.
    pub path: String,
    /// The raw query string, if the target carried one, without the `?` that
    /// introduced it. Meaningful on `/changes` and `/dump`; ignored
    /// elsewhere.
    pub query: Option<String>,
    /// The `Skepd-Session` header's value, if present: the opaque token a
    /// session was bound to. Absent or unknown resolves to the guest.
    pub session_token: Option<String>,
    /// The `Origin` header's value verbatim, if present — the bare arm's
    /// per-request origin check reads it; `Origin: null` arrives as the
    /// literal string and parses to nothing.
    pub origin: Option<String>,
    /// The TCP peer's loopback-ness — established by the accept path from
    /// the socket's peer address; a caller routing by hand supplies it.
    pub peer: Peer,
    /// The body, exactly `Content-Length` bytes (empty when absent).
    pub body: Vec<u8>,
}

/// The body's LENGTH and the token's PRESENCE: the body runs to the route's
/// [`body_cap`], and the token names a live session, which is not a thing to
/// leave in a log line.
impl std::fmt::Debug for HttpRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HttpRequest")
            .field("method", &self.method)
            .field("path", &self.path)
            .field("query", &self.query)
            .field("session_token", &self.session_token.as_ref().map(|_| "<token>"))
            .field("origin", &self.origin)
            .field("peer", &self.peer)
            .field("body_len", &self.body.len())
            .finish()
    }
}

/// The transport's whole error vocabulary — every `{"error": …}` name this
/// daemon can answer, and the only way one is written. EXHAUSTIVE over the
/// wire's transport-error table (wire.md §Transport errors, §Reading
/// history, §The change feed), so a new failure cannot ship without a
/// documented name, exactly as `code_name` guarantees for M10's rejections.
#[derive(Clone, Copy, Debug)]
enum TransportError {
    // The envelope and query parsers.
    MalformedSessionRequest,
    MalformedChallenge,
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
            TransportError::MalformedChallenge => "malformed_challenge",
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
            | TransportError::MalformedChallenge
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
    matches!(
        path,
        "/session" | "/session/close" | "/challenge" | "/op" | "/op-at" | "/health" | "/events"
            | "/changes"
    ) || (cfg!(feature = "observe") && path == "/dump")
        || (cfg!(feature = "client") && path == "/")
}

/// The principal a guest session is minted under. Arbitrary by
/// construction: the session is retired before any request runs, so the
/// value never reaches a store — what makes a guest a guest is the retired
/// binding, not the principal it named. Named once so the two places that
/// mint one cannot drift, and so a reader meeting `u64::MAX` in either is
/// not left asking whether the number is significant to M3 or M10.
///
/// A client may NAME this id — `POST /session {"principal":
/// 18446744073709551615}` mints a LIVE session under it, since
/// [`session_principal`] accepts any non-negative integer and it is the
/// guest's RETIREMENT, not its number, that makes it a guest. That is free
/// while the value means nothing, so the meaninglessness is load-bearing:
/// the day this id means anything — a reserved identity, a default owner,
/// an audit tag, all of which authentication makes natural — either that
/// meaning must not attach to a nameable principal, or `session_principal`
/// must refuse this one.
pub(crate) const GUEST_PRINCIPAL: PrincipalId = PrincipalId(u64::MAX);

/// Mint one session and retire it at once — THE guest pattern, and the one
/// obligation both the live surface and the history surface need: under a
/// retired session M10 serves reads (which are principal-free) and refuses
/// writes with its own `Unauthenticated`, which is how this daemon holds no
/// authorization policy of its own.
///
/// The retirement is what does the work, so it happens here rather than
/// being left to a caller to remember: a session that stayed open would
/// carry [`GUEST_PRINCIPAL`] into every unauthenticated write.
pub(crate) fn open_guest_session(febe: &Operation<World>) -> SessionId {
    let guest = febe.open_session(GUEST_PRINCIPAL);
    febe.close_session(guest);
    guest
}

// The token ↔ session binding, the handshake, and per-request resolution
// live in `crate::auth` (the AUTH session layer). What remains here is the
// guest pattern above and the glue below.

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
    /// The AUTH session layer: config, the challenge and session stores,
    /// the credential write lock, the identity fold, the credential memo.
    auth: AuthState,
    /// The permanently retired session every guest request runs under.
    guest: SessionId,
    /// The write path: the serialization point, the commit-metadata sidecar
    /// behind `GET /changes` and `head_time` (wire v6), and the commit
    /// stream behind `GET /events` (wire v4). One field because the three
    /// are one ordering — commit, record, announce — that no handler may
    /// take apart.
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
    /// commit-metadata sidecar, and assemble the operation surface.
    ///
    /// PRECONDITION: no other live kernel holds `data_dir`. M2 takes an
    /// exclusive lock on the journal directory, and a second open fails on
    /// it — the one [`DaemonError`] a retry can clear, and so the one
    /// exception to the disposition below. [`Skepd::shutdown`] and `Skepd`'s
    /// `Drop` both release that lock before returning, which is what closes
    /// the race with a stopping server. Every other variant is an
    /// operator-intervention condition (corrupt journal, bad checkpoint,
    /// a data dir refusing I/O the kernel just performed):
    /// surface it and exit, never retry.
    ///
    /// TWO steps here cost more than O(1) in the data dir. The sidecar
    /// replay is one: where commit metadata is missing it reconstructs the
    /// uncovered positions from the journal, one whole-world replay each,
    /// up to the retained window (`CHECKPOINT_EVERY_COMMITS` ×
    /// `RETAINED_CHECKPOINTS`). `Sidecar::open` states that bound. The
    /// identity fold is the other: [`Daemon::open_with`] rebuilds it from
    /// the recovered world, which reads every link in it —
    /// [`crate::auth::fold::canonical_identity`] states that bound.
    pub fn open(data_dir: &Path) -> Result<Daemon, DaemonError> {
        Daemon::open_with(data_dir, AuthOptions::default())
    }

    /// [`Daemon::open`] with the session-layer configuration named: the
    /// local-trust flag and the configured origins. The identity fold is
    /// seeded here from the RECOVERED world (derived state — the canonical
    /// rebuild; the journal stays the one source of truth), which reads
    /// every link in that world: [`crate::auth::fold::canonical_identity`]
    /// states the bound, and [`Daemon::open`] names it beside the sidecar's.
    pub fn open_with(data_dir: &Path, opts: AuthOptions) -> Result<Daemon, DaemonError> {
        let cfg = KernelConfig {
            durability: Durability::Fsync {
                journal_path: data_dir.to_path_buf(),
                retain_checkpoints: RETAINED_CHECKPOINTS,
                burned_seq: BurnedSeqPolicy::Rollback,
            },
            checkpoint: CheckpointPolicy::EveryN(CHECKPOINT_EVERY_COMMITS),
        };
        let engine = Engine::open(cfg).map_err(DaemonError::Engine)?;
        let writes = WritePath::open(data_dir, &engine).map_err(DaemonError::Sidecar)?;
        let febe = Operation::new(Box::new(engine.stores()));
        let guest = open_guest_session(&febe);
        let auth = {
            let snap = engine.kernel().snapshot();
            AuthState::open(opts, snap.world())
        };
        Ok(Daemon {
            engine,
            febe,
            codec: JsonCodec,
            auth,
            guest,
            writes,
            history: History::new(),
        })
    }

    /// Bind the auth surface to the served port — the origin sets and the
    /// `/health.auth` lists derive from it. [`serve`] calls this with the
    /// bound port; a socket-free embedder that wants origin behavior calls
    /// it itself. The two are exclusive: `Err(port)` says a port is already
    /// bound, and the number every live session's origin set was
    /// established against is the one already there, not the one refused.
    pub fn bind_auth_port(&self, port: u16) -> Result<(), u16> {
        self.auth.cfg.bind_port(port)
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
    /// mints an M10 session; `GET /challenge` mints a nonce into the
    /// bounded challenge store and evicts the oldest past
    /// [`crate::auth::MAX_LIVE_NONCES`] — a GET that is not safe, and whose
    /// eviction can spend another caller's outstanding nonce;
    /// `POST /session/close` retires a binding. And EVERY token-accepting
    /// route (`/op`, `/op-at`, `/changes`, `/dump`, `/session/close`, and
    /// `/events` on the accept path) can retire one, because
    /// [`Daemon::resolve_actor`]'s death arm closes the binding a dead or
    /// unknown token names — in this daemon's map, in M10, and in the
    /// credential memo. So routing one write frame twice COMMITS TWICE
    /// unless the frame carries an idempotency `id` (wire.md §Correlation
    /// and idempotency) — a speculative retry after a timeout duplicates
    /// the insert or mints a second document. The only routes that alter
    /// nothing are `GET /health` and, in `client` builds, `GET /`.
    ///
    /// What the caller owes on the way in is [`HttpRequest`]'s field
    /// precondition, which routing cannot check; what a [`Reply`] is not on
    /// the way out is the headers [`write_reply`] supplies,
    /// [`UNIVERSAL_HEADERS`] among them, which wire.md promises on every
    /// response.
    pub fn route(&self, req: &HttpRequest) -> Routed {
        match (req.method.as_str(), req.path.as_str()) {
            ("GET", "/events") => Routed::EventStream,
            _ => Routed::Reply(self.reply(req)),
        }
    }

    /// The request/response routes — every method/path pair but the event
    /// stream, decided in one match. The token-accepting set (AUTH-4.43) is
    /// the arms wearing [`Daemon::token_route`]: `/op`, `/op-at`,
    /// `/changes`, `/dump` and `/session/close` here, plus `/events`, which
    /// the accept path runs by hand because a stream is not a [`Reply`].
    /// `/health`, `/challenge`, `/session` and `/` are token-blind by
    /// design.
    fn reply(&self, req: &HttpRequest) -> Reply {
        match (req.method.as_str(), req.path.as_str()) {
            // CORS preflight (wire v4): 204 on any known path; an unknown
            // path falls through to the ordinary 404 below.
            ("OPTIONS", p) if path_is_known(p) => Reply::preflight(),
            ("GET", "/challenge") => self.get_challenge(req.query.as_deref()),
            ("POST", "/session") => self.post_session(req),
            ("POST", "/session/close") => {
                self.token_route(req, |r| self.post_session_close(r, req))
            }
            ("POST", "/op") => self.token_route(req, |r| self.post_op(r, req)),
            ("POST", "/op-at") => self.token_route(req, |_| self.op_at_reply(&req.body)),
            ("GET", "/health") => self.get_health(),
            ("GET", "/changes") => {
                self.token_route(req, |_| self.get_changes(req.query.as_deref()))
            }
            #[cfg(feature = "observe")]
            ("GET", "/dump") => self.token_route(req, |_| self.get_dump(req.query.as_deref())),
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

    /// [`Daemon::resolve_actor`] against the HEAD — the route-level
    /// resolution run before dispatch on every token-accepting route. The
    /// resolved actor is handed to dispatch; the write sequences re-resolve
    /// at their own sites against the snapshot their gates stand on.
    ///
    /// A COMMAND: `resolve_actor`'s death arm retires the binding a dead or
    /// unknown token names, in this daemon's map, in M10 and in the
    /// credential memo. Idempotent — a second resolution of the same token
    /// finds `Unknown` and closes nothing — which is what makes running it
    /// at the route level and again under the lock harmless.
    fn resolve_at_head(&self, req: &HttpRequest) -> Resolved {
        let snap = self.engine.kernel().snapshot();
        let identity = self.auth.fold.snapshot();
        let (actor, closed) = self.resolve_actor(req, snap.world(), &identity);
        Resolved { actor, closed }
    }

    /// One token-accepting route (AUTH-4.43): resolve the actor against the
    /// HEAD — which may retire the binding a dead or unknown token names —
    /// run the handler, and attach the `Skepd-Session: closed` header the
    /// answer may owe (AUTH-6.7). The arm that wears this IS its
    /// declaration that the route accepts a token, so the set is a fact of
    /// [`Daemon::reply`]'s shape rather than a list each arm keeps for
    /// itself. `/events` is the one member that cannot: a stream is not a
    /// [`Reply`], so the accept path runs the same pair by hand
    /// (AUTH-4.44).
    ///
    /// The two write sequences wrap again, against their own LOCKED
    /// resolution — which can find a death this one did not — and that
    /// double is harmless by construction: [`with_signal`] attaches the
    /// header once however many sites observed the death.
    fn token_route(&self, req: &HttpRequest, f: impl FnOnce(&Resolved) -> Reply) -> Reply {
        let resolved = self.resolve_at_head(req);
        with_signal(f(&resolved), resolved.closed)
    }

    /// Log the config-lockout warnings (AUTH-4.9–4.11) to stderr — at
    /// startup, and again at the claim flip, which RES-30 requires
    /// unconditionally. One method because the three are one obligation:
    /// WHICH warnings apply is [`crate::auth::startup_warnings`]'s, but the
    /// claim reading they are computed against and the stream they go to
    /// are this daemon's, and [`serve`] would otherwise reach two levels
    /// into [`crate::auth::AuthState`] to spell them.
    ///
    /// `at_claim` only labels the line. The claim itself is READ from the
    /// fold rather than supplied, so no caller can hand this method a fact
    /// the daemon can answer.
    fn log_config_warnings(&self, at_claim: bool) {
        let claimed = self.auth.fold.snapshot().claimant().is_some();
        let when = if at_claim { " (at claim)" } else { "" };
        for w in startup_warnings(&self.auth.cfg, claimed) {
            let _ = writeln!(std::io::stderr(), "skepd: warning{when}: {w}");
        }
    }

    /// Close one token's binding in BOTH stores — the sessions map and M10
    /// — plus the credential memo. [`Daemon::resolve_actor`]'s eviction arm
    /// and `/session/close` share it.
    fn close_binding(&self, token: &Token) {
        if let Some(binding) = self.auth.sessions.close(token) {
            self.febe.close_session(binding.sid);
            self.auth.memo.purge(binding.sid);
        }
    }

    /// `GET /challenge?principal=N` (AUTH-6.1): issue a nonce for ANY
    /// principal — nothing is secret; the burn is the credential.
    fn get_challenge(&self, query: Option<&str>) -> Reply {
        let principal = match challenge_principal(query) {
            Ok(p) => p,
            Err(detail) => return refuse(TransportError::MalformedChallenge, Some(&detail)),
        };
        let nonce =
            self.auth.challenges.issue(PrincipalId(principal), Instant::now(), &mut OsEntropy);
        Reply::json(
            200,
            obj(vec![
                ("nonce", Value::String(nonce.to_hex())),
                ("principal", Value::Number(principal.into())),
                // A byte pin of [`CHALLENGE_TTL`], so the wire reports that
                // constant or nothing: a fallback literal here would be a
                // second spelling of the number the store uses, free to
                // drift from it in silence on the one field whose whole
                // contract is that it does not.
                (
                    "ttl_ms",
                    Value::Number(
                        u64::try_from(CHALLENGE_TTL.as_millis())
                            .expect("CHALLENGE_TTL is seconds; its millis fit u64")
                            .into(),
                    ),
                ),
            ]),
        )
    }

    /// `POST /session` — the two-form body (AUTH-6.2): bare (honored per
    /// `bare_bind_allowed`) or signed (the challenge/response handshake,
    /// verified in EVERY mode). A syntax fault is the 400 and spends no
    /// credential; every handshake failure is the ONE 401,
    /// `session_rejected`, byte-identical across causes (AUTH-6.5).
    fn post_session(&self, req: &HttpRequest) -> Reply {
        let body = match parse_session_body(&req.body) {
            Ok(b) => b,
            Err(detail) => {
                return refuse(TransportError::MalformedSessionRequest, Some(&detail))
            }
        };
        let snap = self.engine.kernel().snapshot();
        let identity = self.auth.fold.snapshot();
        let outcome = handshake(
            &self.auth.cfg,
            &self.auth.challenges,
            snap.world(),
            &identity,
            body,
            req.peer,
            req.origin.as_deref(),
            Instant::now(),
        );
        match outcome {
            Ok((principal, signer)) => {
                // Every POST /session mints a DISTINCT SessionId, principal
                // 0 included (AUTH-4.40; M10's bootstrap_session mints
                // fresh per call — confirmed as-built, AUTH-6.35).
                let sid = if principal == skep_namespace::BOOTSTRAP_PRINCIPAL {
                    self.febe.bootstrap_session()
                } else {
                    self.febe.open_session(principal)
                };
                let token = self
                    .auth
                    .sessions
                    .open(SessionBinding { sid, principal, signer }, &mut OsEntropy);
                Reply::json(
                    200,
                    obj(vec![
                        ("principal", Value::Number(principal.0.into())),
                        ("session", Value::String(token.to_wire())),
                    ]),
                )
            }
            Err(_) => Reply::json(
                401,
                obj(vec![("error", Value::String("session_rejected".into()))]),
            ),
        }
    }

    /// `POST /session/close` (AUTH-4.47): idempotent 204. Through
    /// [`Daemon::token_route`], the header falls out with no special case —
    /// a LIVE token's 204 carries no header (the close is the person's own
    /// act); an unknown or already-dead one resolved Guest, so the route
    /// closed it already and its 204 carries `Skepd-Session: closed`.
    fn post_session_close(&self, resolved: &Resolved, req: &HttpRequest) -> Reply {
        if let Actor::Principal(_) = &resolved.actor {
            if let Some(t) = req.session_token.as_deref().and_then(Token::parse) {
                self.close_binding(&t);
            }
        }
        Reply { status: 204, body: None, headers: Vec::new() }
    }

    /// `POST /op` — one frame in, one marshaled answer out; the HTTP
    /// exchange is the correlation envelope. The frame is either the
    /// daemon-served `key_set` read, an M10 read (no lock, the actor's
    /// session), or a write, which runs one of the two pinned write
    /// sequences (AUTH-3.35 / AUTH-3.37) under the credential write lock.
    fn post_op(&self, resolved: &Resolved, req: &HttpRequest) -> Reply {
        match self.codec.parse_daemon(&req.body) {
            Err(e) => self.op_reply(&self.codec.unparseable(e)),
            Ok(DaemonOp::KeySet { account }) => {
                // The one dispatcher (AUTH-6.20): the head pair — the live
                // fold beside the head snapshot. Principal-free.
                let snap = self.engine.kernel().snapshot();
                let identity = self.auth.fold.snapshot();
                let set = key_set_of(snap.world(), &identity, &account);
                op_answer(key_set_reply(snap.seq(), set))
            }
            Ok(DaemonOp::Febe(frame)) => match write_meta(&frame.op) {
                // Reads execute directly and take no lock (AUTH-3.36).
                None => self.op_reply(&self.febe.execute(self.actor_sid(&resolved.actor), *frame)),
                Some(meta) => self.write_sequence(resolved, meta, *frame, req),
            },
        }
    }

    /// The session a request's dispatch runs under: the actor's, or the
    /// permanently retired guest (M10 serves reads and refuses writes
    /// `Unauthenticated` under it).
    fn actor_sid(&self, actor: &Actor) -> SessionId {
        match actor {
            Actor::Principal(e) => e.sid,
            Actor::Guest(_) => self.guest,
        }
    }

    /// One write, through its pinned sequence: the credential path for a
    /// deposit-classified op (`deposits_credential_link`, decided lock-free
    /// off the op's own type slot), the plain path for everything else.
    fn write_sequence(
        &self,
        resolved: &Resolved,
        meta: FrameMeta,
        frame: Request,
        req: &HttpRequest,
    ) -> Reply {
        if deposits_credential_link(&frame.op) {
            self.credential_sequence(resolved, meta, frame, req)
        } else {
            self.plain_sequence(meta, frame, req)
        }
    }

    /// The four-part death sequence's ONE home (AUTH-4.42): the site's own
    /// token parse and lookup, `resolve` against the state the CALLER
    /// supplies, the close-both-stores arm on `Unknown | BindingDead`, and
    /// whether this response owes `Skepd-Session: closed`.
    ///
    /// The state is the caller's because that is the only thing the three
    /// sites differ by: the route level resolves against the HEAD
    /// (AUTH-4.29 — historical routes included), while the two write
    /// sequences must resolve against the snapshot their gates stand on
    /// (AUTH-4.28's WHICH-lookup pin). Every Guest then answers
    /// `unauthenticated` by executing under the retired guest session —
    /// M10's own code, with the op kind named.
    fn resolve_actor(
        &self,
        req: &HttpRequest,
        world: &World,
        identity: &IdentityState,
    ) -> (Actor, bool) {
        // A present-but-unparseable token IS no token (AUTH-4.18):
        // `Guest(NoToken)`, nothing to close, no header.
        let token = req.session_token.as_deref().and_then(Token::parse);
        let lookup = self.auth.sessions.lookup(token.as_ref());
        let actor =
            resolve(&self.auth.cfg, lookup, req.peer, req.origin.as_deref(), world, identity);
        let closed =
            matches!(actor, Actor::Guest(GuestReason::Unknown | GuestReason::BindingDead));
        if closed {
            if let Some(t) = &token {
                self.close_binding(t);
            }
        }
        (actor, closed)
    }

    /// The locked state one write sequence stands on: the world snapshot,
    /// the fold snapshot beside it, and this site's own resolution against
    /// that pair (AUTH-4.28's WHICH-lookup pin). Taken AFTER the
    /// serialization lock — which is what the guard argument proves — so no
    /// commit can intervene between what the gates read and what the
    /// execute they gate runs against.
    ///
    /// The credential lock is the CALLER's: the two sequences hold
    /// different guard types (read for the plain path, write for the
    /// credential path), and holding one is the half this signature cannot
    /// state.
    ///
    /// A COMMAND: [`Daemon::resolve_actor`]'s death arm retires the binding
    /// a dead or unknown token names, in this daemon's map, in M10 and in
    /// the credential memo — so this is not a pure read of the locked
    /// state, despite the name. Idempotent, for the reason
    /// [`Daemon::resolve_at_head`] states.
    fn locked_state(
        &self,
        _serial: &parking_lot::MutexGuard<'_, ()>,
        req: &HttpRequest,
    ) -> (Snapshot<World>, IdentityState, Resolved) {
        let snap = self.engine.kernel().snapshot();
        let identity = self.auth.fold.snapshot();
        let (actor, closed) = self.resolve_actor(req, snap.world(), &identity);
        (snap, identity, Resolved { actor, closed })
    }

    /// The answer every Guest arm gives: execute under the permanently
    /// retired guest session, which is M10's own `Unauthenticated` with the
    /// op kind named. This daemon holds no authorization policy of its own,
    /// so the refusal is M10's to word.
    fn guest_reply(&self, frame: Request) -> Reply {
        self.op_reply(&self.febe.execute(self.guest, frame))
    }

    /// The PLAIN sequence (AUTH-3.35): the read lock → the serialization
    /// lock → [`Daemon::locked_state`] (the head snapshot, the fold beside
    /// it, and this site's own resolve) → `plain_refusal`'s ordered
    /// producers → execute. The serial lock is taken before the snapshot so
    /// the gates' answers and the execute they gate stand on one committed
    /// state; the producers' ORDER is `plain_refusal`'s, not this site's.
    fn plain_sequence(&self, meta: FrameMeta, frame: Request, req: &HttpRequest) -> Reply {
        let credential_lock = self.auth.credential_lock.read();
        let serial = self.writes.serial_lock();
        let (snap, identity, Resolved { actor, closed }) = self.locked_state(&serial, req);
        let binding = match actor {
            Actor::Principal(b) => b,
            Actor::Guest(_) => return with_signal(self.guest_reply(frame), closed),
        };
        if let Some(r) = plain_refusal(
            &credential_lock,
            snap.world(),
            &identity,
            &frame.op,
            binding.principal,
            binding.signer.as_ref(),
        ) {
            return with_signal(credential_refused(meta.kind, &r), closed);
        }
        let resp = self.writes.commit_under(&serial, meta.attributed(binding.testimony()), || {
            self.febe.execute(binding.sid, frame)
        });
        with_signal(self.op_reply(&resp), closed)
    }

    /// The CREDENTIAL sequence (AUTH-3.37): the pre-lock actor is
    /// `resolve_at_head`'s; `op_shape_refusal` runs ahead of the lock; then
    /// the write lock → serial → [`Daemon::locked_state`] → recall →
    /// precheck → execute → the fold step, the memo, and the claim-flip
    /// tail — all under the write guard.
    fn credential_sequence(
        &self,
        resolved: &Resolved,
        meta: FrameMeta,
        frame: Request,
        req: &HttpRequest,
    ) -> Reply {
        // 1 — the pre-lock actor check: both outcomes are refusals that
        // execute nothing (AUTH-3.38). No `with_signal` here: this arm
        // reads the HEAD resolution, whose death signal
        // [`Daemon::token_route`]'s wrap already carries.
        if let Actor::Guest(_) = resolved.actor {
            return self.guest_reply(frame);
        }
        // 2 — slots (1)–(2), ahead of the lock (AUTH-3.5).
        if let Some(r) = op_shape_refusal(&frame.op) {
            return credential_refused(meta.kind, &r);
        }
        // 3 — the credential write lock, the serialization lock, the locked
        // snapshot, and this site's OWN resolution.
        let credential_lock = self.auth.credential_lock.write();
        let serial = self.writes.serial_lock();
        let (snap, identity, Resolved { actor, closed }) = self.locked_state(&serial, req);
        let binding = match actor {
            Actor::Principal(b) => b,
            // 4 — the only reachable arms are Unknown | BindingDead
            // (AUTH-3.37 item 4); the close-and-signal already fired.
            Actor::Guest(_) => return with_signal(self.guest_reply(frame), closed),
        };
        // 5 — recall, kind-blind, atomic with the precheck-and-execute it
        // guards (AUTH-3.40/3.41): the ORIGINAL ack, byte-identical,
        // executing nothing.
        if let Some(id) = &frame.id {
            if let Some(ack) = self.auth.memo.recall(&credential_lock, binding.sid, id) {
                return with_signal(op_answer(ack), closed);
            }
        }
        // 6 — the precheck's ordered slots over the verbatim deposit.
        let Some(dep) = DepositSpans::of(&frame.op) else {
            // Unreachable by construction: only a MakeLink with
            // address-form slots classifies credential past slots (1)–(2).
            // The assert is what makes the premise LOUD — the release
            // answer refuses in the shape vocabulary rather than inventing
            // one, and a `resolved_from` a caller's frame did not earn is
            // indistinguishable from a genuine slot-(2) refusal, which is
            // exactly what a silent arm here would ship. Same treatment
            // `precheck` gives its own `NotCredential` line.
            debug_assert!(false, "a classified deposit is an address-form MakeLink");
            let r = CredentialRefusal::ResolvedFrom;
            return with_signal(credential_refused(meta.kind, &r), closed);
        };
        if let Err(r) = crate::auth::policy::precheck(
            &credential_lock,
            snap.world(),
            &identity,
            &dep,
            binding.signer.as_ref(),
        ) {
            return with_signal(credential_refused(meta.kind, &r), closed);
        }
        // 7 — execute (commit-record-announce under the held serial lock).
        let req_id = frame.id.clone();
        let resp = self.writes.commit_under(&serial, meta.attributed(binding.testimony()), || {
            self.febe.execute(binding.sid, frame)
        });
        let ack = self.codec.marshal(&resp);
        if matches!(resp, Response::AckAddr { .. }) {
            // 8 — the committed tail (AUTH-3.43): the fold step from the
            // committed deposit against the post-commit snapshot, and the
            // memo entry, as one operation under the write guard.
            //
            // The guard is a SHAPE test standing in for "this write
            // committed", on two premises: only an address-form `MakeLink`
            // reaches here ([`DepositSpans::of`] is `Some` for nothing
            // else), and M10 acks a committed `make_link` with `AckAddr`.
            // If either failed, a committed deposit would skip this tail
            // and the live fold would fall SILENTLY behind the world until
            // restart, with `/op`'s `key_set` and `/op-at`'s at the head
            // disagreeing meanwhile.
            let post = self.engine.kernel().snapshot();
            let flipped = self.auth.commit_tail(
                &credential_lock,
                post.world(),
                &dep.deposit(),
                binding.sid,
                req_id,
                &ack,
            );
            if flipped {
                self.log_config_warnings(true);
            }
        }
        with_signal(op_answer(ack), closed)
    }

    /// One M10 answer, marshaled, as its reply — through [`op_answer`],
    /// which is where that channel's status is chosen.
    fn op_reply(&self, resp: &Response) -> Reply {
        op_answer(self.codec.marshal(resp))
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
    fn op_at_reply(&self, body: &[u8]) -> Reply {
        let (at, frame) = match op_at_envelope(body) {
            Ok(x) => x,
            Err(detail) => return refuse(TransportError::MalformedOpAt, Some(&detail)),
        };
        let parsed = match self.codec.parse_daemon_value(frame) {
            Ok(r) => r,
            Err(e) => return self.op_reply(&self.codec.unparseable(e)),
        };
        match parsed {
            DaemonOp::KeySet { account } => {
                // The SAME dispatcher as /op's, over the reconstructed
                // world and its canonical identity rebuild (AUTH-6.20) —
                // under the reconstruction budget like every historical
                // answer.
                match self.history.reconstruct(&self.engine, at) {
                    Ok((_permit, world)) => {
                        let identity = canonical_identity(&world);
                        op_answer(key_set_reply(at, key_set_of(&world, &identity, &account)))
                    }
                    Err(e) => refuse_unavailable(e),
                }
            }
            DaemonOp::Febe(frame) => {
                if !op_is_read(&frame.op) {
                    // The ruling-fixed body, exactly: {"error": "write_at_history"}.
                    return refuse(TransportError::WriteAtHistory, None);
                }
                match self.history.read_at(&self.engine, at, *frame) {
                    Ok(resp) => self.op_reply(&resp),
                    Err(e) => refuse_unavailable(e),
                }
            }
        }
    }

    fn get_health(&self) -> Reply {
        // The head position's recorded wall-clock time (wire v6) — null
        // when the head's own record is bare or nothing is recorded at all
        // (a fresh world): transport metadata, never invented, and never an
        // older position's time offered in the head's place.
        //
        // The two fields are read independently and under no lock, so the
        // PAIR may straddle one in-flight commit: a `head_time` correct for
        // the position the sidecar last recorded, beside a `log_position`
        // one commit newer. Taking the write lock here would serialize a
        // liveness probe behind writes, which is the worse trade;
        // `Sidecar::head_time` states what each field is true of.
        let head_time =
            self.writes.head_time().map(|t| Value::Number(t.into())).unwrap_or(Value::Null);
        // The auth object (AUTH-6.13): claimant, local_trust, and the TWO
        // origin lists — each published VERBATIM from its set function, so
        // the published list and the arm's own rule are one rule. NO
        // `.mode` field (the negative pin): mode is derived client-side
        // from the pair.
        let identity = self.auth.fold.snapshot();
        let claimed = identity.claimant().is_some();
        let origin_list = |set: std::collections::BTreeSet<crate::auth::Origin>| {
            Value::Array(set.iter().map(|o| Value::String(o.as_str().to_string())).collect())
        };
        let auth = obj(vec![
            (
                "claimant",
                identity
                    .claimant()
                    .map(|a| Value::String(a.tumbler().to_string()))
                    .unwrap_or(Value::Null),
            ),
            ("local_trust", Value::Bool(self.auth.cfg.local_trust)),
            ("origins", origin_list(bare_origins(&self.auth.cfg))),
            ("signed_origins", origin_list(signed_origins(&self.auth.cfg, claimed))),
        ]);
        Reply::json(
            200,
            obj(vec![
                ("auth", auth),
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
            ChangesAnswer::Reclaimed { floor } => refuse_reclaimed(floor),
            ChangesAnswer::Page { entries, last, more } => Reply::json(
                200,
                obj(vec![
                    (
                        "changes",
                        Value::Array(
                            entries.into_iter().map(|(at, meta)| meta.into_entry(at)).collect(),
                        ),
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
                Err(e) => return refuse_unavailable(e),
            },
        };
        Reply::bodied(200, "text/plain; charset=utf-8", dump.into_string().into_bytes())
    }
}

/// How one request's session resolved: the actor it acts as, and whether
/// this response owes the `Skepd-Session: closed` header.
struct Resolved {
    actor: Actor,
    closed: bool,
}

/// Attach the death signal (AUTH-6.7) when owed — once, however many
/// resolution sites observed the death on this request.
fn with_signal(mut reply: Reply, closed: bool) -> Reply {
    if closed && !reply.headers.iter().any(|(k, _)| *k == SESSION_HEADER) {
        reply.headers.push((SESSION_HEADER, "closed"));
    }
    reply
}

/// One operation answer, already marshaled, as its reply — always `200`,
/// whatever the answer says: the envelope, not the HTTP status, is the
/// operation protocol. THE constructor for that channel, so a
/// daemon-originated answer (`key_set`, a credential refusal, a memoized
/// ack) cannot choose a status of its own — the standing [`refuse`] has on
/// the transport channel.
fn op_answer(bytes: Vec<u8>) -> Reply {
    Reply::bodied(200, "application/json", bytes)
}

/// One daemon-originated credential refusal as its 200-enveloped rejection
/// (AUTH-3.54): `code: credential_refused`, `disposition: permanent`
/// uniformly, `detail` the machine token. The op field names the refused
/// op, exactly as M10's rejections do — lowered from its `OpKind` here, so
/// the wire name comes from [`crate::codec::op_name`]'s table rather than
/// from a caller holding one to pass on.
fn credential_refused(kind: OpKind, r: &CredentialRefusal) -> Reply {
    op_answer(daemon_rejected(DaemonRejection {
        op: crate::codec::op_name(kind),
        code: CREDENTIAL_REFUSED,
        disposition: Disposition::Permanent,
        detail: Some(r.token()),
    }))
}

/// The `/challenge` query: exactly `principal=<non-negative integer>`.
fn challenge_principal(query: Option<&str>) -> Result<u64, String> {
    let q = match query {
        None | Some("") => return Err("the required parameter is principal=<id>".into()),
        Some(q) => q,
    };
    let mut principal: Option<u64> = None;
    for (k, v) in query_pairs(q)? {
        match k {
            "principal" => {
                if principal.is_some() {
                    return Err("duplicate parameter 'principal'".into());
                }
                principal = Some(
                    v.parse()
                        .map_err(|_| format!("principal: '{v}' is not a non-negative integer"))?,
                );
            }
            other => return Err(format!("unknown parameter '{other}'")),
        }
    }
    principal.ok_or_else(|| String::from("the required parameter is principal=<id>"))
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
fn refuse_reclaimed(floor: Option<u64>) -> Reply {
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
fn refuse_unavailable(e: Unavailable) -> Reply {
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
        HistoryError::Reclaimed { floor } => refuse_reclaimed(floor.map(|f| f.0)),
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
/// Failure is the socket's or the OS's: binding the address, reading back
/// the port it bound, or a refused worker thread — all three `io::Error`,
/// which is what lets a caller dispatch on `ErrorKind` — `AddrInUse` to try
/// the next port, `PermissionDenied` for a privileged one — without a
/// downcast. A refused thread retires whatever has already started before
/// returning, so the port and the journal-directory lock are free for that
/// retry.
pub fn serve(daemon: Daemon, port: u16, workers: usize) -> io::Result<Skepd> {
    assert!(workers >= 1, "serve requires at least one worker thread (workers = 0)");
    let daemon = Arc::new(daemon);
    let listener = Arc::new(TcpListener::bind(("127.0.0.1", port))?);
    let port = listener.local_addr()?.port();
    // The auth surface derives its origin sets from the BOUND port, and the
    // startup warnings are logged here — the one thing the glue does with
    // the config before serving (AUTH-4.11). AFTER the bind, and not before:
    // the port-change arm compares each configured origin against the bound
    // port's loopback defaults, so on an unbound config every configured
    // loopback origin would warn.
    daemon.bind_auth_port(port).expect(
        "serve binds the auth port once; a pre-bound daemon has two callers \
         disagreeing about the number every live session's origin set derives from",
    );
    daemon.log_config_warnings(false);
    let stop = Arc::new(AtomicBool::new(false));
    let subscribers = Arc::new(Subscribers::new());
    // Spawned FALLIBLY, and named: `thread::spawn` panics when the OS
    // refuses a thread, and a panic here would unwind out of a half-built
    // handle vector — detaching the workers that did start, with the
    // listener still bound, the journal-directory lock still held, and no
    // `Skepd` in existence for the settled stop to run against.
    let mut handles = Vec::with_capacity(workers);
    let mut refused = None;
    for _ in 0..workers {
        let daemon = Arc::clone(&daemon);
        let listener = Arc::clone(&listener);
        let stop = Arc::clone(&stop);
        let subscribers = Arc::clone(&subscribers);
        let spawned = thread::Builder::new().name("skepd-worker".into()).spawn(move || loop {
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
        });
        match spawned {
            Ok(h) => handles.push(h),
            Err(e) => {
                refused = Some(e);
                break;
            }
        }
    }
    let server = Skepd { daemon, _listener: listener, workers: handles, subscribers, stop, port };
    match refused {
        // A refused thread costs the whole start, never a half-started
        // server: the stop joins the workers that did start, ends any
        // stream they already admitted, and releases the listener and the
        // journal-directory lock — so the port this caller is about to
        // retry on is free before it sees the error.
        Some(e) => {
            server.shutdown();
            Err(e)
        }
        None => Ok(server),
    }
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

    /// Block until the workers exit — the binary's foreground call. In
    /// practice that is until the process ends: `wait` consumes the server,
    /// so nothing is left to set the stop flag, and crash-stop is the
    /// shutdown story (M2's WAL makes recovery the clean path, so there is
    /// no signal machinery). An embedder that wants to stop a running server
    /// keeps the [`Skepd`] and calls [`Skepd::shutdown`] instead. Returning
    /// would end every event stream too, since the server is dropped here.
    pub fn wait(mut self) {
        for h in self.workers.drain(..) {
            let _ = h.join();
        }
    }

    /// Orderly stop for embedders and tests: release and join the op
    /// workers, then end every event stream — the commit stream's broadcast
    /// wakes each subscriber, which drops its socket (the client sees a
    /// clean close) and exits — and join those threads too. Returning
    /// releases the kernel's journal-directory lock, so the same data dir
    /// can be reopened.
    ///
    /// Bounded, and by more than one number: a worker mid-request runs to at
    /// most one [`TRANSFER_DEADLINE`] plus one socket timeout in each
    /// direction, plus its handler's own time; then every subscriber is woken
    /// by the commit stream's broadcast, and one blocked writing to a peer
    /// that stopped draining is joined only when its socket's
    /// [`WRITE_TIMEOUT`] fires — `serve_events` writes without a deadline by
    /// design (see [`write_bounded`]). So this stop does wait on a client,
    /// for at most that timeout. Interrupting it would mean holding a second
    /// descriptor per live stream, against the budget [`MAX_SUBSCRIBERS`]
    /// exists to keep.
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
    // The peer's loopback-ness, off the socket itself (AUTH-4.14). This
    // daemon binds 127.0.0.1, so every peer is loopback today; deriving it
    // rather than asserting it is what a bind-override needs no change for.
    let peer = match stream.peer_addr() {
        Ok(a) if a.ip().is_loopback() => Peer::Loopback,
        _ => Peer::Remote,
    };
    // One deadline per transfer: the socket's own timeouts bound silence and
    // are renewed by any byte, so this is what bounds a peer that is slow
    // rather than quiet. The reply gets its own below, which is what keeps a
    // request refused AT its deadline still answerable.
    let deadline = Instant::now() + TRANSFER_DEADLINE;
    let req = match read_request(&mut stream, peer, deadline) {
        Ok(Some(r)) => r,
        // Clean close before any byte (a port probe, shutdown's wake
        // connect): no request, so no reply owed.
        Ok(None) => return,
        Err(refusal) => {
            let reply = refuse_request(refusal);
            let _ = write_reply(&mut stream, &reply, Instant::now() + TRANSFER_DEADLINE);
            return;
        }
    };
    // The unwind-safety assertion is sound rather than convenient:
    // `parking_lot`'s locks do not poison, so a panic under one releases it
    // with the data as it stands, and no structure this daemon guards is
    // mutated across a point that can unwind — the session table's map and
    // queue move together under one lock, and the sidecar appends before it
    // inserts. What a panic can cost is the tail of one write, on two
    // cards. `WritePath::commit_under` runs `execute` under the
    // serialization lock, so a panic inside M10 after its commit leaves
    // that position unrecorded and unannounced; the reopen walk re-covers
    // it as a bare entry, and the next commit's announcement carries the
    // stream past it. A panic after a CREDENTIAL commit costs a second
    // thing: `credential_sequence`'s tail runs after `commit_under`
    // returns, so the live identity fold is left one deposit behind the
    // committed world. It fails CLOSED — a key the fold does not hold
    // establishes no session — and it heals at restart, where
    // `crate::auth::fold::canonical_identity` rebuilds from the world.
    // Until then `/op`'s `key_set` (the live fold) and `/op-at` at the head
    // (the canonical rebuild) disagree, and the next `precheck` runs its
    // slots against the short fold.
    let routed = match catch_unwind(AssertUnwindSafe(|| daemon.route(&req))) {
        Ok(r) => r,
        Err(_) => Routed::Reply(refuse(TransportError::InternalPanic, None)),
    };
    match routed {
        Routed::Reply(reply) => {
            let _ = write_reply(&mut stream, &reply, Instant::now() + TRANSFER_DEADLINE);
        }
        Routed::EventStream => {
            // The one token-accepting route `Daemon::token_route` cannot
            // wear, because a stream is not a `Reply`: the same pair by
            // hand, `resolve_at_head` before the stream OPENS (AUTH-4.44), so
            // a dead token meets `Skepd-Session: closed` on the stream's
            // own head, written once, at open.
            let closed = daemon.resolve_at_head(&req).closed;
            subscribers.admit(Arc::clone(daemon), stream, closed);
        }
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
#[derive(Debug)]
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
    fn admit(&self, daemon: Arc<Daemon>, stream: TcpStream, closed: bool) {
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
        let spawned = thread::Builder::new()
            .name("skepd-events".into())
            .spawn(move || serve_events(&daemon, stream, closed));
        if let Ok(h) = spawned {
            live.push(h);
        }
    }

    /// Join every live subscriber. Called after the commit stream has
    /// broadcast its shutdown, so each is already awake and on its way out
    /// — which is what keeps this bounded rather than a wait on a client.
    fn join_all(&self) {
        for h in std::mem::take(&mut *self.live.lock()) {
            let _ = h.join();
        }
    }
}

/// A request refused at the HTTP layer: which transport-error reply the
/// connection is owed. Everything outside the subset this daemon speaks is
/// one bucket; the body cap gets its own honest disposition
/// (`413 payload_too_large`), not a generic parse error.
#[derive(Debug)]
enum RequestRefusal {
    /// Not the HTTP subset this daemon speaks → `400 malformed_http`.
    Malformed(String),
    /// The declared `Content-Length` exceeds the route's [`body_cap`] →
    /// `413 payload_too_large`. Raised before any body byte is read, and
    /// carrying the cap it exceeded so the refusal names the number that
    /// actually bound it rather than the largest one the daemon has.
    BodyTooLarge { declared: usize, cap: usize },
}

impl From<String> for RequestRefusal {
    fn from(detail: String) -> RequestRefusal {
        RequestRefusal::Malformed(detail)
    }
}

impl From<&str> for RequestRefusal {
    fn from(detail: &str) -> RequestRefusal {
        RequestRefusal::Malformed(detail.into())
    }
}

/// Map a request refused at the HTTP layer onto the wire's transport
/// errors — the one place a [`RequestRefusal`] becomes HTTP, as
/// [`refuse_unavailable`] is for the history surface's `Unavailable`. The
/// body cap's diagnostic names the cap that actually bound this route, so
/// the number in the refusal is the one the request met rather than the
/// largest the daemon has.
fn refuse_request(refusal: RequestRefusal) -> Reply {
    match refusal {
        RequestRefusal::Malformed(detail) => refuse(TransportError::MalformedHttp, Some(&detail)),
        RequestRefusal::BodyTooLarge { declared, cap } => refuse(
            TransportError::PayloadTooLarge,
            Some(&format!("Content-Length {declared} exceeds the {cap}-byte body cap")),
        ),
    }
}

/// Read one request off the socket. `Ok(None)` = clean close before any
/// byte; `Err(_)` = the request is refused (the caller answers the
/// [`RequestRefusal`]'s reply and closes). The subset: one request per
/// connection, HTTP/1.0 or 1.1, bodies by `Content-Length` (absent =
/// empty, capped at the route's [`body_cap`]), `Expect: 100-continue`
/// honored, `Transfer-Encoding` refused.
///
/// Each header this daemon READS — `Content-Length`, `Skepd-Session`,
/// `Expect` — may appear at most once; a repeat is `malformed_http`, the
/// same never-silent treatment a duplicate query parameter and an unknown
/// frame field already get. Headers this daemon does not read pass unread
/// however often they appear.
///
/// Both loops below are bounded in bytes AND in time: `deadline` bounds
/// this whole transfer, so a peer that paces its bytes to renew the
/// socket's per-call deadline is refused rather than served for as long as
/// it likes (see [`TRANSFER_DEADLINE`]). The refusal rides `malformed_http`,
/// which is where a timed-out read already lands.
fn read_request(
    stream: &mut TcpStream,
    peer: Peer,
    deadline: Instant,
) -> Result<Option<HttpRequest>, RequestRefusal> {
    // The head, plus whatever early body bytes arrived with it.
    let mut buf: Vec<u8> = Vec::with_capacity(1024);
    // How much of `buf` is known to hold no terminator, so the scan is
    // linear in the head rather than quadratic: a peer pacing one byte per
    // read would otherwise make the daemon rescan from zero every time, and
    // 64 KiB of head costs order 2e9 window comparisons. A terminator can
    // straddle the next read by at most three bytes, which is where the next
    // scan may safely start.
    let mut scanned = 0usize;
    let head_end = loop {
        if let Some(i) = find_head_end(&buf[scanned..]) {
            break scanned + i;
        }
        scanned = buf.len().saturating_sub(3);
        if buf.len() > MAX_REQUEST_HEAD {
            return Err(format!("request head exceeds the {MAX_REQUEST_HEAD}-byte cap").into());
        }
        if Instant::now() >= deadline {
            return Err("request head not delivered within the exchange deadline".into());
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
    let mut origin: Option<String> = None;
    let mut expects_continue: Option<bool> = None;
    fn once<T>(slot: &Option<T>, name: &str) -> Result<(), RequestRefusal> {
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
        } else if name.eq_ignore_ascii_case("Origin") {
            once(&origin, name)?;
            origin = Some(value.to_string());
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
    // (and allocates) a single byte of it. The cap is the ROUTE's, so a
    // route that carries no frame is never asked to allocate for one.
    let cap = body_cap(&path);
    if declared > cap {
        return Err(RequestRefusal::BodyTooLarge { declared, cap });
    }
    if expects_continue && body.len() < declared {
        // The client is holding the body until told to send it (curl does
        // this for large payloads).
        if stream.write_all(b"HTTP/1.1 100 Continue\r\n\r\n").is_err() {
            return Err("client went away at 100-continue".into());
        }
    }
    while body.len() < declared {
        if Instant::now() >= deadline {
            return Err("request body not delivered within the exchange deadline".into());
        }
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
    Ok(Some(HttpRequest { method, path, query, session_token, origin, peer, body }))
}

fn find_head_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n")
}

/// `write_all` under a deadline. The socket's write timeout bounds a peer
/// that stops draining; only the deadline bounds one that drains slowly,
/// since each accepted byte renews that timeout. A reply is written to a
/// worker's socket, so a slow reader here costs one of `workers` threads —
/// which is why the reply path takes the deadline and `serve_events` does
/// not: a subscriber runs on its own thread against a slot [`Subscribers`]
/// already budgets. That exemption is what makes [`Skepd::shutdown`]'s
/// bound include one write timeout — the stop joins a subscriber that may
/// be blocked writing to a peer that stopped draining.
fn write_bounded(stream: &mut TcpStream, mut bytes: &[u8], deadline: Instant) -> io::Result<()> {
    while !bytes.is_empty() {
        if Instant::now() >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "response not taken within the exchange deadline",
            ));
        }
        match stream.write(bytes) {
            Ok(0) => return Err(io::ErrorKind::WriteZero.into()),
            Ok(n) => bytes = &bytes[n..],
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

/// Append one `Name: value` line in this daemon's framing — the one place a
/// header becomes bytes, shared by the reply path and the event stream.
fn push_header(head: &mut Vec<u8>, name: &str, value: &str) {
    head.extend_from_slice(format!("{name}: {value}\r\n").as_bytes());
}

/// Write one complete reply; the connection closes behind it. Every reply
/// carries [`UNIVERSAL_HEADERS`] — the cross-origin posture, the death
/// signal's exposure, and the one-request-per-connection framing — supplied
/// at this one choke point so no reply can miss them, and shared with
/// `serve_events`, which composes its own head because a stream is not a
/// reply. A bodiless reply carries no content headers (RFC 7230's 204).
fn write_reply(stream: &mut TcpStream, reply: &Reply, deadline: Instant) -> io::Result<()> {
    let mut head = Vec::with_capacity(256);
    head.extend_from_slice(
        format!("HTTP/1.1 {} {}\r\n", reply.status, reason(reply.status)).as_bytes(),
    );
    for (name, value) in UNIVERSAL_HEADERS.iter().chain(&reply.headers) {
        push_header(&mut head, name, value);
    }
    // The body and the headers describing it come from one value, so the
    // two cannot disagree about whether there is one.
    if let Some(body) = &reply.body {
        head.extend_from_slice(
            format!(
                "Content-Type: {}\r\nContent-Length: {}\r\n",
                body.content_type,
                body.bytes.len()
            )
            .as_bytes(),
        );
        head.extend_from_slice(b"\r\n");
        // The body is written FROM the reply rather than copied into this
        // buffer first. The largest answer this daemon serves is a whole
        // world dump, and assembling one buffer would hold two copies of
        // it at once — per in-flight request, on a route that needs no
        // session. `set_nodelay` is on, so the cost is the second write
        // call and nothing else.
        write_bounded(stream, &head, deadline)?;
        write_bounded(stream, &body.bytes, deadline)
    } else {
        head.extend_from_slice(b"\r\n");
        write_bounded(stream, &head, deadline)
    }
}

/// The subset's reason phrases — informational only; clients dispatch on
/// the code.
fn reason(status: u16) -> &'static str {
    match status {
        200 => "OK",
        204 => "No Content",
        400 => "Bad Request",
        401 => "Unauthorized",
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
/// carrying the last announced position, then follow the commit stream — a
/// `commit` event when the head advances, a `:ka` comment on silence —
/// until shutdown or the first failed write (a gone subscriber). Exiting
/// drops the socket, which is the client's end-of-stream. Coalescing is
/// inherent: the stream answers "anything past what I last sent", so a
/// burst of commits is one event.
///
/// The initial position comes from [`WritePath::announced`] and not from
/// the kernel, which is what keeps every announced position one
/// `GET /changes` already carries — see that method for the window the
/// distinction closes.
fn serve_events(daemon: &Daemon, mut stream: TcpStream, closed: bool) {
    let mut head = b"HTTP/1.1 200 OK\r\n".to_vec();
    for (name, value) in UNIVERSAL_HEADERS {
        push_header(&mut head, name, value);
    }
    push_header(&mut head, "Content-Type", "text/event-stream");
    push_header(&mut head, "Cache-Control", "no-cache");
    if closed {
        // The death signal, written ONCE at open (AUTH-4.44): a session
        // dying mid-stream is a stated residue.
        push_header(&mut head, SESSION_HEADER, "closed");
    }
    head.extend_from_slice(b"\r\n");
    if stream.write_all(&head).is_err() {
        return;
    }
    let mut last = daemon.writes.announced();
    if write_commit_event(&mut stream, last).is_err() {
        return;
    }
    loop {
        match daemon.writes.next_step(last) {
            StreamStep::Shutdown => return,
            StreamStep::Commit(at) => {
                last = at;
                if write_commit_event(&mut stream, at).is_err() {
                    return;
                }
            }
            StreamStep::Keepalive => {
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
///
/// The payload is built through the codec's key-sorting device like every
/// other JSON object this crate emits, so the day the stream carries a
/// second field its canonical form is the one already in force everywhere
/// else rather than whatever a format string happened to spell.
fn write_commit_event(stream: &mut TcpStream, at: Seq) -> std::io::Result<()> {
    let mut event = b"event: commit\ndata: ".to_vec();
    event.extend_from_slice(&to_bytes(obj(vec![("log_position", Value::Number(at.0.into()))])));
    event.extend_from_slice(b"\n\n");
    stream.write_all(&event)
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
        "/session/close",
        "/challenge",
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

    /// The methods this test asks every route about. Deliberately wider than
    /// the set the daemon serves: the point is to DISCOVER which methods
    /// dispatch rather than to restate them, so a method added to
    /// [`Daemon::reply`] is caught here without anyone remembering to add it.
    const PROBE_METHODS: &[&str] =
        &["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"];

    /// One route set, five consequences. A known path preflights `204`;
    /// refuses an unsupported method with `405` and never `404`; dispatches
    /// at least one method; refuses at least one, so the `405` arm is
    /// exercised somewhere; and has every method it dispatches named by the
    /// CORS preflight. An unknown path is `404` for every method including
    /// `OPTIONS`.
    ///
    /// The first four are the invariant [`path_is_known`] exists to keep — a
    /// route stated in one table and forgotten in another breaks exactly one
    /// of them. The last is [`Reply::preflight`]'s: a method the preflight
    /// omits is one a browser will not send, which fails only cross-origin,
    /// where every client in this suite writes onto a socket directly and so
    /// never looks.
    ///
    /// Every method is DISCOVERED rather than restated, so a route that
    /// starts serving one — the blob upload [`MAX_REQUEST_BODY`] already
    /// anticipates — is caught by the preflight check rather than by a
    /// hardcoded expectation that the method is unsupported.
    #[test]
    fn the_route_set_agrees_across_preflight_dispatch_and_refusal() {
        let dir = tempfile::tempdir().expect("tempdir");
        let daemon = Daemon::open(dir.path()).expect("genesis open");
        let bare = |method: &str, path: &str| HttpRequest {
            method: method.to_string(),
            path: path.to_string(),
            query: None,
            session_token: None,
            origin: None,
            peer: Peer::Loopback,
            body: Vec::new(),
        };
        let status = |method: &str, path: &str| match daemon.route(&bare(method, path)) {
            Routed::Reply(r) => r.status,
            // The one non-reply route; reached only by GET /events, which
            // this test never asks for.
            Routed::EventStream => 200,
        };
        let allow = Reply::preflight()
            .headers
            .iter()
            .find(|(k, _)| *k == "Access-Control-Allow-Methods")
            .map(|&(_, v)| v)
            .expect("the preflight names its allowed methods");
        for path in ROUTES {
            assert!(path_is_known(path), "{path} is served but not known");
            assert_eq!(status("OPTIONS", path), 204, "{path} must answer the CORS preflight");
            let mut served = false;
            let mut refused = false;
            for method in PROBE_METHODS {
                let answered = status(method, path);
                assert_ne!(
                    answered, 404,
                    "{path} is known, so {method} must be refused with 405, not 404"
                );
                // 405 is the daemon saying it does not serve this method
                // here; anything else is a dispatch, which the preflight
                // owes a name.
                if answered == 405 {
                    refused = true;
                    continue;
                }
                served = true;
                assert!(
                    allow.split(',').any(|a| a.trim() == *method),
                    "{path} dispatches {method}, which the preflight does not allow ({allow})"
                );
            }
            assert!(served, "{path} is known but no method dispatches");
            assert!(refused, "{path} serves every probed method; none exercises the 405 arm");
        }
        for unknown in ["/nope", "/op/", "/Health"] {
            assert!(!path_is_known(unknown), "{unknown} must not be known");
            assert_eq!(status("GET", unknown), 404, "{unknown}");
            assert_eq!(status("OPTIONS", unknown), 404, "an unknown path preflights nothing");
        }
    }

    /// The guest policy at the route level: an absent token serves reads
    /// and meets M10's own `Unauthenticated` on writes; an unknown token
    /// additionally carries the death signal (AUTH-6.7) — an evicted or
    /// stale token is never silently a guest.
    #[test]
    fn a_guest_reads_and_an_unknown_token_is_signalled() {
        let dir = tempfile::tempdir().expect("tempdir");
        let daemon = Daemon::open(dir.path()).expect("genesis open");
        let post = |token: Option<&str>, body: &str| {
            let Routed::Reply(r) = daemon.route(&HttpRequest {
                method: "POST".to_string(),
                path: "/op".to_string(),
                query: None,
                session_token: token.map(str::to_string),
                origin: None,
                peer: Peer::Loopback,
                body: body.as_bytes().to_vec(),
            }) else {
                panic!("POST /op is not the event stream")
            };
            r
        };
        let read = post(None, r#"{"op":"next_account_prefix","parent":"1"}"#);
        let v: Value = serde_json::from_slice(read.bytes()).expect("json");
        assert_eq!(v["resp"].as_str(), Some("maybe_addr"), "a guest read serves: {v}");
        let write = post(None, r#"{"op":"fork"}"#);
        let v: Value = serde_json::from_slice(write.bytes()).expect("json");
        assert_eq!(v["code"].as_str(), Some("unauthenticated"), "a guest write refuses: {v}");
        assert!(
            !write.headers.iter().any(|(k, _)| *k == SESSION_HEADER),
            "no token presented, so nothing died and nothing signals"
        );
        // A well-formed but unknown token: the same refusal, WITH the
        // signal — a stale token is never silently a guest.
        let stale = "0123456789abcdef0123456789abcdef";
        let write = post(Some(stale), r#"{"op":"fork"}"#);
        let v: Value = serde_json::from_slice(write.bytes()).expect("json");
        assert_eq!(v["code"].as_str(), Some("unauthenticated"), "{v}");
        assert!(
            write.headers.iter().any(|(k, v)| *k == SESSION_HEADER && *v == "closed"),
            "an unknown token carries Skepd-Session: closed"
        );
        // An unparseable header value IS no token (AUTH-4.18): no signal.
        let junk = post(Some("not-a-token"), r#"{"op":"fork"}"#);
        assert!(
            !junk.headers.iter().any(|(k, _)| *k == SESSION_HEADER),
            "a value Token::parse refuses resolves NoToken — nothing to close"
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
            String::from_utf8(r.bytes().to_vec()).expect("json"),
            r#"{"detail":"too big","error":"payload_too_large"}"#
        );
        let r = refuse_with(
            TransportError::BeyondHead,
            vec![("head", Value::Number(12u64.into()))],
        );
        assert_eq!(r.status, 400);
        assert_eq!(
            String::from_utf8(r.bytes().to_vec()).expect("json"),
            r#"{"error":"beyond_head","head":12}"#
        );
    }

    /// The `observe`-only row of the table below, in the one shape that
    /// compiles under either feature setting.
    #[cfg(feature = "observe")]
    fn observe_rows() -> Vec<(TransportError, &'static str, u16)> {
        vec![(TransportError::MalformedAt, "malformed_at", 400)]
    }

    #[cfg(not(feature = "observe"))]
    fn observe_rows() -> Vec<(TransportError, &'static str, u16)> {
        Vec::new()
    }

    /// wire.md §HTTP status codes, BOTH columns — the discipline
    /// [`code_name`](crate::codec) already gives M10's sixty rejection
    /// codes. The table is transcribed by hand for the reason
    /// [`crate::fuzz_support::TRANSPORT_ERRORS`] is: one read out of the
    /// code under test would agree with whatever that code says.
    ///
    /// Four of these — `internal_panic`, `history_io`, `history_corrupt`,
    /// `no_journal` — are reachable from no test in the tree (three need
    /// at-rest journal damage, one cannot arise under this daemon's
    /// `Fsync` configuration), so their spelling and their status are
    /// watched here and nowhere else.
    #[test]
    fn every_transport_error_pairs_its_documented_name_with_its_documented_status() {
        let mut table: Vec<(TransportError, &'static str, u16)> = vec![
            (TransportError::MalformedSessionRequest, "malformed_session_request", 400),
            (TransportError::MalformedChallenge, "malformed_challenge", 400),
            (TransportError::MalformedOpAt, "malformed_op_at", 400),
            (TransportError::WriteAtHistory, "write_at_history", 400),
            (TransportError::BeyondHead, "beyond_head", 400),
            (TransportError::NotAPosition, "not_a_position", 400),
            (TransportError::MalformedChanges, "malformed_changes", 400),
            (TransportError::MalformedHttp, "malformed_http", 400),
            (TransportError::NoSuchEndpoint, "no_such_endpoint", 404),
            (TransportError::MethodNotAllowed, "method_not_allowed", 405),
            (TransportError::HistoryReclaimed, "history_reclaimed", 410),
            (TransportError::PayloadTooLarge, "payload_too_large", 413),
            (TransportError::InternalPanic, "internal_panic", 500),
            (TransportError::HistoryIo, "history_io", 500),
            (TransportError::HistoryCorrupt, "history_corrupt", 500),
            (TransportError::NoJournal, "no_journal", 500),
            (TransportError::HistoryBusy, "history_busy", 503),
        ];
        table.extend(observe_rows());
        for &(err, name, status) in &table {
            assert_eq!(err.name(), name, "wire name drifted for {err:?}");
            assert_eq!(err.status(), status, "{name} must be answered with {status}");
            // The one builder every refusal goes through takes both from
            // the error, so the pairing a client dispatches on is checked
            // where it is produced rather than only where it is declared.
            let r = refuse(err, None);
            assert_eq!(r.status, status, "{name}: the reply's status");
            let body: Value = serde_json::from_slice(r.bytes()).expect("json");
            assert_eq!(body["error"].as_str(), Some(name), "{name}: the reply's body");
            // The fuzz oracle's list is the other hand transcription of
            // this column; a name in one and not the other is a drift.
            assert!(
                crate::fuzz_support::TRANSPORT_ERRORS.contains(&name),
                "{name} is answerable but absent from the fuzz oracle's list"
            );
        }
        // Both transcriptions of wire.md's error column, measured against
        // each other. A NEW variant is caught by the compiler at `name`
        // and `status`; this catches one that reaches the wire without
        // reaching either list. The `+ 1` is `session_rejected` — the one
        // documented error name that is not a `TransportError` variant
        // (the handshake's single 401, built at its own site per AUTH-6.5).
        #[cfg(feature = "observe")]
        assert_eq!(
            table.len() + 1,
            crate::fuzz_support::TRANSPORT_ERRORS.len(),
            "the two hand transcriptions of wire.md's error column disagree in length"
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
        assert!(pre.body.is_none(), "the preflight names no body");
        assert!(pre.bytes().is_empty());
        let json = Reply::json(200, obj(vec![("ok", Value::Bool(true))]));
        let body = json.body.as_ref().expect("a JSON reply names its body");
        assert_eq!(body.content_type, "application/json");
        assert_eq!(body.bytes, br#"{"ok":true}"#);
    }

    /// The `/changes` query's accepted forms, and the page size the wire
    /// promises when `limit` is absent (wire.md §The change feed: "default
    /// 256, maximum 4096"). Every other test drives this parser through
    /// its refusals; the seeded feeds are four writes long, so a default
    /// silently changed to 4 — or to 4096 — produces an identical wire
    /// answer in all of them.
    #[test]
    fn the_changes_query_defaults_to_the_documented_page_size() {
        assert_eq!(
            changes_params(Some("since=0")).expect("since alone is enough"),
            (0, 256),
            "an absent limit is the documented default"
        );
        assert_eq!(changes_params(Some("since=7&limit=10")).expect("both"), (7, 10));
        assert_eq!(
            changes_params(Some("limit=10&since=7")).expect("order-free"),
            (7, 10),
            "parameters are a set, not a sequence"
        );
        assert_eq!(
            changes_params(Some("since=0&limit=4096")).expect("the maximum is in range").1,
            4096
        );
        for bad in [
            None,
            Some(""),
            Some("limit=2"),
            Some("since=abc"),
            Some("since=0&limit=0"),
            Some("since=0&limit=4097"),
            Some("since=0&since=1"),
            Some("since=0&nope=1"),
            Some("since"),
        ] {
            assert!(changes_params(bad).is_err(), "{bad:?} must be refused");
        }
    }

    /// The `/dump` query is absent or exactly one position — the accepted
    /// half of the parser `tests/history.rs` exercises only through its
    /// refusals.
    #[cfg(feature = "observe")]
    #[test]
    fn the_dump_query_is_absent_or_exactly_one_position() {
        let at = |q| dump_at_param(q).map(|o| o.map(|s| s.0));
        assert_eq!(at(None).expect("no query"), None);
        assert_eq!(at(Some("")).expect("empty query"), None);
        assert_eq!(at(Some("at=9")).expect("a position"), Some(9));
        assert_eq!(at(Some("at=0")).expect("genesis is a position"), Some(0));
        for bad in [Some("at=abc"), Some("at=1&at=2"), Some("position=3"), Some("at")] {
            assert!(dump_at_param(bad).is_err(), "{bad:?} must be refused");
        }
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

    /// The commit stream announces a position only from the section that
    /// recorded it: a committing write announces ITS OWN position, and
    /// nothing else announces at all.
    ///
    /// The read is the load-bearing half, and the head is deliberately
    /// pushed ahead of the stream first — through `febe` directly, the one
    /// path that commits without announcing — because a daemon that
    /// announced the CURRENT HEAD from any `/op` request would look
    /// correct on a quiet socket and wrong under concurrency, leaking a
    /// write another thread had committed but not yet recorded. Here that
    /// gap is opened deliberately instead of raced for.
    /// A bare 0-session's token, opened through the route itself.
    fn bare_session(daemon: &Daemon, principal: u64) -> String {
        let Routed::Reply(r) = daemon.route(&HttpRequest {
            method: "POST".to_string(),
            path: "/session".to_string(),
            query: None,
            session_token: None,
            origin: None,
            peer: Peer::Loopback,
            body: format!("{{\"principal\":{principal}}}").into_bytes(),
        }) else {
            panic!("POST /session is not the event stream")
        };
        assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(r.bytes()));
        let v: Value = serde_json::from_slice(r.bytes()).expect("json");
        v["session"].as_str().expect("token").to_string()
    }

    #[test]
    fn only_a_committing_write_announces_and_only_its_own_position() {
        let dir = tempfile::tempdir().expect("tempdir");
        let daemon = Daemon::open(dir.path()).expect("genesis open");
        let token = bare_session(&daemon, 0);
        let announced = || daemon.writes.announced();
        let post = |body: &str| match daemon.route(&HttpRequest {
            method: "POST".to_string(),
            path: "/op".to_string(),
            query: None,
            session_token: Some(token.clone()),
            origin: None,
            peer: Peer::Loopback,
            body: body.as_bytes().to_vec(),
        }) {
            Routed::Reply(r) => serde_json::from_slice::<Value>(r.bytes()).expect("json"),
            Routed::EventStream => panic!("POST /op is not the event stream"),
        };

        // Commit past the stream without announcing: this is the state a
        // concurrent write leaves behind between its commit and its record.
        // Driven through `febe` directly — the one path that commits
        // without announcing — so the daemon's own gates are deliberately
        // bypassed.
        let frame = br#"{"op":"register_node","addr":"1.9001"}"#;
        let req = daemon.codec.parse(frame).unwrap_or_else(|_| panic!("test frame parses"));
        let sid = daemon.febe.bootstrap_session();
        let ahead = match daemon.febe.execute(sid, req) {
            Response::AckAddr { at, .. } => at,
            // `Response` derives no Debug upstream; marshal to say what came back.
            other => panic!(
                "register_node acks an address: {}",
                String::from_utf8_lossy(&daemon.codec.marshal(&other))
            ),
        };
        assert!(ahead.0 > announced().0, "the head is now ahead of the commit stream");

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

        // A route-level write that commits pre-claim: the ceremony's own
        // delegate from principal 0 (the pre-claim gate admits it).
        let prefix = read["addr"].as_str().expect("a delegable prefix").to_string();
        let write =
            post(&format!(r#"{{"op":"delegate","new_prefix":"{prefix}","new_id":41}}"#));
        let at = write["at"].as_u64().unwrap_or_else(|| panic!("delegate commits: {write}"));
        assert_eq!(
            announced().0,
            at,
            "a committing write announces the position it committed, not the head"
        );
    }

    /// A connecting subscriber is told the last ANNOUNCED position, not the
    /// kernel's head — `write_path.rs`'s guarantee (every position a
    /// subscriber hears is one `/changes` already carries) applied to the
    /// connect event.
    ///
    /// The two differ only between a write's commit and its change-feed
    /// record, so the gap is opened deliberately rather than raced for: a
    /// direct `febe.execute` is the one path that commits without
    /// announcing, and nothing announces afterwards, so the state holds.
    /// Told the head there, a client would ask `/changes` for a delta not
    /// yet containing the position it was handed and show a stale view
    /// until the next write.
    #[test]
    fn a_connecting_subscriber_is_told_the_announced_position_not_the_head() {
        let dir = tempfile::tempdir().expect("tempdir");
        let daemon = Daemon::open(dir.path()).expect("genesis open");
        let server = serve(daemon, 0, 1).expect("bind an ephemeral port");
        let port = server.port();

        let (announced, ahead) = {
            let d = server.daemon();
            let sid = d.febe.bootstrap_session();
            let req = d
                .codec
                .parse(br#"{"op":"register_node","addr":"1.9001"}"#)
                .unwrap_or_else(|_| panic!("test frame parses"));
            let ahead = match d.febe.execute(sid, req) {
                Response::AckAddr { at, .. } => at,
                // `Response` derives no Debug upstream; marshal to say what came back.
                other => panic!(
                    "register_node acks an address: {}",
                    String::from_utf8_lossy(&d.codec.marshal(&other))
                ),
            };
            (d.writes.announced(), ahead)
        };
        assert!(announced.0 < ahead.0, "the head is now ahead of the commit stream");

        let mut stream = TcpStream::connect(("127.0.0.1", port)).expect("connect /events");
        stream.set_read_timeout(Some(Duration::from_secs(5))).expect("read timeout");
        stream
            .write_all(b"GET /events HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")
            .expect("write the stream request");
        let mut buf: Vec<u8> = Vec::new();
        let deadline = Instant::now() + Duration::from_secs(10);
        let first = loop {
            if let Some(i) = buf.windows(6).position(|w| w == b"data: ") {
                if let Some(nl) = buf[i..].iter().position(|&b| b == b'\n') {
                    let v: Value =
                        serde_json::from_slice(&buf[i + 6..i + nl]).expect("event data is JSON");
                    break v["log_position"].as_u64().expect("log_position");
                }
            }
            assert!(
                Instant::now() < deadline,
                "no initial event: {:?}",
                String::from_utf8_lossy(&buf)
            );
            let mut chunk = [0u8; 1024];
            match stream.read(&mut chunk) {
                Ok(0) => panic!("the stream closed before its first event"),
                Ok(n) => buf.extend_from_slice(&chunk[..n]),
                Err(_) => {}
            }
        };
        assert_eq!(
            first, announced.0,
            "the connect event carries the announced position, which `/changes` already covers"
        );
        assert!(first < ahead.0, "and NOT the head, whose change-feed record does not exist yet");

        server.shutdown();
    }
}
