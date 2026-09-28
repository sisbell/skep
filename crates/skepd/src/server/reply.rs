//! The wire value types, the transport refusals, the reply decorators, the query helpers.

use serde_json::Value;
use skep_engine::HistoryError;
use skep_febe::OpKind;

use crate::auth::policy::CredentialRefusal;
use crate::auth::session::{HandshakeRefusal, Peer};
use crate::codec::{credential_refused_reply, obj, to_bytes};
use crate::history::Unavailable;

/// Preflight cache lifetime advertised on `OPTIONS` (wire v4).
const CORS_MAX_AGE_SECS: &str = "86400";

/// The one request header this daemon reads beyond HTTP's own framing: the
/// opaque session token. Named once because the CORS preflight must
/// advertise exactly the header the reader consults — a header the
/// preflight omits is one the browser will not send, so the two must agree
/// or every cross-origin write fails at a layer this crate's own suite,
/// which writes the header straight onto a socket, never reaches.
pub(super) const SESSION_HEADER: &str = "Skepd-Session";

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
/// come from [`super::http::write_reply`] rather than from any `Reply` value:
/// `Content-Type` and `Content-Length`, which it derives from the `body`
/// field below and omits entirely when there is none, and every member of
/// [`UNIVERSAL_HEADERS`](super::UNIVERSAL_HEADERS), which wire.md §Transport and §Cross-origin access
/// promise on EVERY response. A caller serving these over a transport of
/// its own owes that constant's members — and takes them from it rather
/// than transcribing them, so a change to the cross-origin posture moves
/// for them too.
#[derive(Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Reply {
    pub status: u16,
    pub body: Option<Body>,
    /// Extra response headers beyond what [`super::http::write_reply`] supplies —
    /// `Content-Type` and `Content-Length` from the body, and
    /// [`UNIVERSAL_HEADERS`](super::UNIVERSAL_HEADERS) always. The preflight trio rides here, as does
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
    pub(super) fn bodied(status: u16, content_type: &'static str, bytes: Vec<u8>) -> Reply {
        Reply {
            status,
            body: Some(Body { content_type, bytes }),
            headers: Vec::new(),
        }
    }

    /// A JSON reply at `status` — the success answers, which each name
    /// their own code. A refusal names a [`TransportError`] instead and
    /// takes its status from there.
    pub(super) fn json(status: u16, v: Value) -> Reply {
        Reply::bodied(status, "application/json", to_bytes(v))
    }

    /// The CORS preflight answer (wire v4): 204, no body, the fixed method
    /// and header lists. `Access-Control-Allow-Origin: *` is in
    /// [`UNIVERSAL_HEADERS`](super::UNIVERSAL_HEADERS), which both response writers emit, so it is not
    /// repeated here.
    ///
    /// The method list must name every method [`Daemon::reply`](super::Daemon::reply) dispatches,
    /// for the same reason [`SESSION_HEADER`] is a constant: a method the
    /// preflight omits is one the browser will not send, and that failure
    /// appears only cross-origin, where this suite's own TCP clients never
    /// look. The list is a joined `&'static str` and so cannot be built
    /// from the router's arms; the coupling is held by
    /// `the_route_set_agrees_across_preflight_dispatch_and_refusal`, which
    /// discovers the dispatched set rather than restating it.
    pub(super) fn preflight() -> Reply {
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
///
/// `#[non_exhaustive]`, because this is one variant per answer the reply
/// path CANNOT express, which is a category rather than a singleton: a
/// [`Body`] holds its bytes wholly in memory, and [`crate::limits::MAX_REQUEST_BODY`]
/// already names a media round that revisits the body cap per route, so a
/// streaming answer is the natural second member. What it costs a
/// downstream caller is a `_` arm, and the honest answer there is the one
/// a socket-free caller already gives [`Routed::EventStream`]: refuse the
/// route.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Routed {
    Reply(Reply),
    /// `GET /events` — the server-sent commit stream (wire v4).
    ///
    /// Serviceable only through [`serve`](super::serve): following the stream is
    /// `write_path/`'s and crate-private, so a caller routing by hand can
    /// answer this variant only by refusing the route. It is the one
    /// endpoint the socket-free surface names and cannot serve.
    EventStream,
}

/// One request, as [`Daemon::route`](super::Daemon::route) receives it and as the socket reader
/// builds it — one value rather than a list of arguments, so the two
/// `Option<String>`s cannot be handed over in the wrong order.
///
/// PRECONDITION on every field, established by [`super::http::read_request`] and owed by
/// any other caller of [`Daemon::route`](super::Daemon::route): `method` is the uppercase token;
/// `path` is the request target with its query AND its `?` removed; `query`
/// is what followed that `?`, without it; `session_token` and `origin` are
/// the `Skepd-Session` and `Origin` header values VERBATIM, or `None` when
/// the header is absent — never normalized and never defaulted; `peer` is
/// the transport's own answer about the remote address of THIS connection;
/// `body` is exactly the declared `Content-Length` bytes, and at most
/// [`body_cap`](super::body_cap) of `path` of them.
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
/// [`crate::auth::session::bare_bind_allowed`] admits, so a caller that
/// does not forward the header removes the daemon-side fence; and a `peer`
/// reported `Loopback` for a socket that is not one hands the bare bind to
/// the network.
///
/// The body cap is the OUTERMOST bound on what a frame allocates, and the
/// one clause a caller cannot discharge by inspection: every JSON-carrying
/// route builds the whole `serde_json` tree before any codec cap runs, so a
/// body admitted past it buys roughly twenty times its size in transient
/// heap — for a frame the codec is then about to refuse. [`super::http::read_request`]
/// enforces it on the declared `Content-Length`, before a byte is read.
///
/// `Clone`, because this is the value a caller BUILDS, and the precondition
/// above is why it builds one per probe rather than mutating a template:
/// every field is a fact about ONE request. A caller varying one across a
/// table would otherwise spell all seven per row. Deliberately no
/// `Default`, for the same reason — an empty method and path are not a
/// request — and no `PartialEq`, nothing here comparing two requests.
#[derive(Clone)]
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
    /// the socket's peer address. A caller routing over its own transport
    /// supplies it, and takes it from [`Peer::of`] rather than deriving it:
    /// that is this daemon's own rule, and the paragraph above says what
    /// getting it wrong costs. A transport with no address at all — a Unix
    /// socket — names the variant it means.
    pub peer: Peer,
    /// The body, exactly `Content-Length` bytes (empty when absent).
    pub body: Vec<u8>,
}

/// The body's LENGTH and the token's PRESENCE: the body runs to the route's
/// [`body_cap`](super::body_cap), and the token names a live session, which is not a thing to
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
/// The handshake's two answers — the 401 and the 403 — are the table's two
/// rows written elsewhere: [`refuse_handshake`] says why.
#[derive(Clone, Copy, Debug)]
pub(super) enum TransportError {
    // The envelope and query parsers.
    MalformedSessionRequest,
    MalformedChallenge,
    MalformedOpAt,
    MalformedChanges,
    /// The one-parameter `at=<position>` query of `/dump?at` (observe builds)
    /// and `/chain?at` (every build), so it is no longer `observe`-gated.
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
    // The class-scan bound (wire v7.9).
    ScanBusy,
    // The HTTP layer.
    MalformedHttp,
    PayloadTooLarge,
    InternalPanic,
}

impl TransportError {
    pub(super) fn name(self) -> &'static str {
        match self {
            TransportError::MalformedSessionRequest => "malformed_session_request",
            TransportError::MalformedChallenge => "malformed_challenge",
            TransportError::MalformedOpAt => "malformed_op_at",
            TransportError::MalformedChanges => "malformed_changes",
            TransportError::MalformedAt => "malformed_at",
            TransportError::NoSuchEndpoint => "no_such_endpoint",
            TransportError::MethodNotAllowed => "method_not_allowed",
            TransportError::WriteAtHistory => "write_at_history",
            TransportError::BeyondHead => "beyond_head",
            TransportError::NotAPosition => "not_a_position",
            TransportError::HistoryReclaimed => "history_reclaimed",
            TransportError::HistoryBusy => "history_busy",
            TransportError::ScanBusy => "scan_busy",
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
    pub(super) fn status(self) -> u16 {
        match self {
            TransportError::MalformedSessionRequest
            | TransportError::MalformedChallenge
            | TransportError::MalformedOpAt
            | TransportError::MalformedChanges
            | TransportError::WriteAtHistory
            | TransportError::BeyondHead
            | TransportError::NotAPosition
            | TransportError::MalformedHttp
            | TransportError::MalformedAt => 400,
            TransportError::NoSuchEndpoint => 404,
            TransportError::MethodNotAllowed => 405,
            TransportError::HistoryReclaimed => 410,
            TransportError::PayloadTooLarge => 413,
            TransportError::NoJournal
            | TransportError::HistoryIo
            | TransportError::HistoryCorrupt
            | TransportError::InternalPanic => 500,
            // The two retry-class refusals: a pool is momentarily full.
            TransportError::HistoryBusy | TransportError::ScanBusy => 503,
        }
    }
}

/// A transport-level refusal, whole: the status and the `{"error": name}`
/// body wire.md pairs with `err`, plus an optional detail. Deliberately NOT
/// the `{"resp": "rejected"}` shape — no `Op` was involved. Every non-2xx
/// this daemon answers is built here or by [`refuse_with`], so no handler
/// chooses a status of its own.
pub(super) fn refuse(err: TransportError, detail: Option<&str>) -> Reply {
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
pub(super) fn refuse_with(err: TransportError, fields: Vec<(&'static str, Value)>) -> Reply {
    let mut pairs = fields;
    pairs.push(("error", Value::String(err.name().into())));
    Reply::json(err.status(), obj(pairs))
}

/// The handshake's two refusals, as their replies (AUTH-6.5) — the ONE home
/// of both bodies, so the pair cannot drift. Every failure of the CREDENTIAL
/// is `401 {"error":"session_rejected"}`: one code, no detail, byte-identical
/// across its thirteen arms (AUTH-4.62 item 1), which a unit refusal makes
/// true by construction. THE ONE EXCEPTION, BY STATUS, is step 4b's:
/// `403 {"error":"prefix_blocked","record":"<address>"}`, the record's
/// version address its one datum and public by construction — never the 401,
/// because this party's credential was not read.
///
/// Built here and not through [`refuse`], as the 401 always was: the
/// handshake's answers are AUTH-6.5's to word, a pair, and neither name is
/// a [`TransportError`] variant — so neither can grow the optional `detail`
/// every variant of that enum is offered.
pub(super) fn refuse_handshake(refusal: &HandshakeRefusal) -> Reply {
    match refusal {
        HandshakeRefusal::Rejected(_) => {
            Reply::json(401, obj(vec![("error", Value::String("session_rejected".into()))]))
        }
        HandshakeRefusal::Blocked { record } => Reply::json(
            403,
            obj(vec![
                ("error", Value::String("prefix_blocked".into())),
                ("record", Value::String(record.tumbler().to_string())),
            ]),
        ),
    }
}

/// Attach the death signal (AUTH-6.7) when owed — once, however many
/// resolution sites observed the death on this request.
pub(super) fn with_signal(mut reply: Reply, closed: bool) -> Reply {
    if closed && !reply.headers.iter().any(|(k, _)| *k == SESSION_HEADER) {
        reply.headers.push((SESSION_HEADER, "closed"));
    }
    reply
}

/// The cache headers every CLASS-VARYING reply carries (wire v7.6; PUB
/// round 2, lane 3.4 §5): the answer is a function of the presented token's
/// class, so it may be neither stored nor served to another requester.
/// `Cache-Control: no-store` forbids any cache from keeping it;
/// `Vary: Skepd-Session` names the request header the answer turns on, so a
/// cache that keeps one anyway keys it by the token. Applied at the
/// [`Daemon::reply`](super::Daemon::reply) arms of the four routes — `/op`, `/op-at`, `/changes`,
/// `/dump` — rather than at [`op_answer`] (which `/changes` and `/dump` do
/// not use, and which no transport refusal passes through) or at
/// [`Reply::bodied`] (which `/health` and `/` share, and those are
/// class-invariant). `/events` is a stream with its own `Cache-Control:
/// no-cache` written at open, and `/health` is class-invariant by
/// construction (PUB-6.50), so neither wears these.
const CLASS_VARYING_HEADERS: [(&str, &str); 2] =
    [("Cache-Control", "no-store"), ("Vary", SESSION_HEADER)];

/// Stamp a class-varying route's reply with [`CLASS_VARYING_HEADERS`] —
/// once, whatever the reply is: a marshaled answer, a credential refusal, a
/// transport refusal.
pub(super) fn class_varying(mut reply: Reply) -> Reply {
    for (name, value) in CLASS_VARYING_HEADERS {
        if !reply.headers.iter().any(|(k, _)| *k == name) {
            reply.headers.push((name, value));
        }
    }
    reply
}

/// One operation answer, already marshaled, as its reply — always `200`,
/// whatever the answer says: the envelope, not the HTTP status, is the
/// operation protocol. THE constructor for that channel, so a
/// daemon-originated answer (`key_set`, a credential refusal, a memoized
/// ack) cannot choose a status of its own — the standing [`refuse`] has on
/// the transport channel.
pub(super) fn op_answer(bytes: Vec<u8>) -> Reply {
    Reply::bodied(200, "application/json", bytes)
}

/// The `503 scan_busy` refusal (wire v7.9): every class-scan permit is in
/// use. Retry-class — the query may be perfectly good and the pool
/// momentarily full — and the body names the `op` it refused, so a client
/// pipelining reads can pair the refusal with the request it answers, in the
/// diagnostic-field shape `beyond_head`'s `head` and `history_reclaimed`'s
/// `floor` already take. A TRANSPORT refusal like `history_busy` and not an
/// operation response: no `Op` ran, so there is no `resp` and no `code` —
/// the envelope is `{"error": …}`, never `{"resp": "rejected"}`.
pub(super) fn refuse_scan_busy(kind: OpKind) -> Reply {
    refuse_with(
        TransportError::ScanBusy,
        vec![
            (
                "detail",
                Value::String("all class-scan permits are in use; retry shortly".into()),
            ),
            ("op", Value::String(crate::codec::op_name(kind).into())),
        ],
    )
}

/// One daemon-originated credential refusal as its 200-enveloped rejection.
/// The ROW is [`credential_refused_reply`]'s — the code is the wire's and is
/// fixed there; the token and the disposition are the refusal's own
/// ([`CredentialRefusal::token`], [`CredentialRefusal::disposition`]) — and
/// what this adds is the transport's own half: the 200 [`op_answer`] gives
/// every answer on that channel, whatever the answer says.
pub(super) fn credential_refused(kind: OpKind, r: &CredentialRefusal) -> Reply {
    op_answer(credential_refused_reply(kind, r.token(), r.disposition()))
}

/// A query string as its parameter list — `k=v` pairs split on `&`, shape
/// checked and nothing else. Every query this daemon reads walks this, so
/// one discipline covers them all and each parser adds only its own
/// vocabulary: an unknown or repeated parameter is a named refusal, which
/// is the wire's never-silent posture applied to queries.
pub(super) fn query_pairs(query: &str) -> Result<Vec<(&str, &str)>, String> {
    query
        .split('&')
        .map(|pair| pair.split_once('=').ok_or_else(|| format!("malformed parameter '{pair}'")))
        .collect()
}

/// A field that may appear at most ONCE — the never-silent rule applied to
/// repeats, shared by the request head's headers and by every query this
/// daemon reads, so a duplicate is a named refusal rather than a last-wins
/// nobody chose. `field_kind` is the wire's word for the kind of field —
/// `"header"` or `"parameter"` — which is all the header reader and the
/// query parsers differ by.
///
/// One home because the alternative is one literal name per field, kept in
/// step with the field it guards by inspection alone: a `since.is_some()`
/// left standing in the `limit` arm accepts a repeated `limit` and refuses a
/// `limit` that follows a `since`, and the shape compiles either way.
pub(super) fn at_most_once<T>(
    seen: &Option<T>,
    field_kind: &str,
    name: &str,
) -> Result<(), String> {
    match seen {
        Some(_) => Err(format!("duplicate {field_kind} '{name}'")),
        None => Ok(()),
    }
}

/// The `410 history_reclaimed` refusal: the position asked for is older
/// than what can still be answered, and `floor` — when one exists — names
/// the oldest that can. One construction, shared by the history surface and
/// the change feed, so the two cannot describe the same condition
/// differently.
pub(super) fn refuse_reclaimed(floor: Option<u64>) -> Reply {
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
pub(super) fn refuse_unavailable(e: Unavailable) -> Reply {
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
        HistoryError::Reclaimed { floor, .. } => refuse_reclaimed(floor.map(|f| f.0)),
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
