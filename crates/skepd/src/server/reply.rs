//! The reply a handler answers with, every transport refusal, and the reply
//! decorators.

use serde_json::Value;
use skep_address::Address;
use skep_engine::HistoryError;
use skep_febe::{Codec, FaultSite, OpKind, RejectCode, Rejection, Response};

use crate::auth::policy::{CredentialRefusal, RegistryRefusal};
use crate::auth::session::HandshakeRefusal;
use crate::codec::{
    credential_refused_reply, obj, op_name, registry_refused_reply, to_bytes, JsonCodec,
};
use crate::history::Unavailable;
use crate::media::door::MediaRefusal;
use crate::media::serve::{Admitted, CellFace, Refusal as FetchRefusal};

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
/// A REQUEST's body is bare bytes ([`HttpRequest::body`](super::HttpRequest::body)) because this
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
        Reply { status, body: Some(Body { content_type, bytes }), headers: Vec::new() }
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

    /// The CORS preflight of the blob upload's path family (media lane B;
    /// wire.md §Media): the four methods the family dispatches — the
    /// creation and the deposit read, the resume, the end — named, so a
    /// browser sends them cross-origin; every other known path keeps
    /// [`Reply::preflight`]'s three, byte-identical to before the family.
    pub(super) fn preflight_blob() -> Reply {
        Reply {
            status: 204,
            body: None,
            headers: vec![
                ("Access-Control-Allow-Methods", "GET, POST, PATCH, DELETE, OPTIONS"),
                ("Access-Control-Allow-Headers", "Content-Type, Skepd-Session"),
                ("Access-Control-Max-Age", CORS_MAX_AGE_SECS),
            ],
        }
    }

    /// The CORS preflight of the blob FETCH's path (wire.md §Media, THE
    /// FETCH): the two methods the route dispatches — `GET`, and `HEAD` for
    /// the head alone — named, so a browser sends them cross-origin, and
    /// the two headers every preflight carries.
    pub(super) fn preflight_fetch() -> Reply {
        Reply {
            status: 204,
            body: None,
            headers: vec![
                ("Access-Control-Allow-Methods", "GET, HEAD, OPTIONS"),
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
/// path unrepresentable — and the blob fetch's admitted answer is a
/// STREAM of a file the transport writes one chunk at a time, re-resolving
/// the requester between chunks, so it is its own variant too.
///
/// `#[non_exhaustive]`, because this is one variant per answer the reply
/// path CANNOT express, which is a category rather than a singleton: a
/// [`Body`] holds its bytes wholly in memory, and the fetch was that
/// category's second member — [`crate::limits::MAX_REQUEST_BODY`]'s card
/// anticipated it. What it costs a downstream caller is a `_` arm, and the
/// honest answer there is the one a socket-free caller already gives
/// [`Routed::EventStream`]: refuse the route.
///
/// The lifetime is the fetch's: an admitted fetch holds a permit of the
/// daemon's fetch pool for as long as the answer lives, and the permit
/// borrows the pool — so a `Routed` lives no longer than the daemon it was
/// routed by, which every caller already holds. Neither `Clone` nor
/// `PartialEq`: a permit is not a value two answers can share, and nothing
/// compares two routings.
#[derive(Debug)]
#[non_exhaustive]
pub enum Routed<'a> {
    Reply(Reply),
    /// `GET /events` — the server-sent commit stream (wire v4).
    ///
    /// Serviceable only through [`serve`](super::serve): following the stream is
    /// `write_path/`'s and crate-private, so a caller routing by hand can
    /// answer this variant only by refusing the route. It is the one
    /// endpoint the socket-free surface names and cannot serve.
    EventStream,
    /// `GET /blob?i=` and `HEAD /blob?i=` ADMITTED (wire.md §Media, THE
    /// FETCH): the file checked whole against its cell, held with the
    /// fetch pool's permit, streamed by [`serve`](super::serve) under the
    /// idle and transfer bounds with the requester re-resolved between
    /// chunks. Every refusal of the route is an ordinary [`Routed::Reply`].
    /// A caller routing by hand holds the whole file in [`Fetch`] and may
    /// write it over its own transport; what it then owes is the
    /// re-resolution the daemon's transport runs, or a refusal of the
    /// route.
    Fetch(Fetch<'a>),
}

/// The fetch's admitted answer: a 200 whose body is the file, the status
/// fixed — the gate's refusals are each a [`Reply`] of their own — and the
/// headers the route stamped (the class-varying pair, the two inert ones,
/// the death signal where owed). The `GET`'s and the `HEAD`'s answer alike:
/// the transport writes the body for the one and the head alone for the
/// other, HTTP's own rule. The file's bytes are reached by the transport
/// alone (`serve`'s stream); a caller sees the length.
pub struct Fetch<'a> {
    admitted: Admitted<'a>,
    headers: Vec<(&'static str, &'static str)>,
}

impl<'a> Fetch<'a> {
    pub(super) fn new(admitted: Admitted<'a>, closed: bool) -> Fetch<'a> {
        let mut headers: Vec<(&'static str, &'static str)> = FETCH_INERT_HEADERS.to_vec();
        headers.extend(CLASS_VARYING_HEADERS);
        if closed {
            headers.push((SESSION_HEADER, "closed"));
        }
        Fetch { admitted, headers }
    }

    /// The status: `200`, always — an admitted fetch is the file.
    pub fn status(&self) -> u16 {
        200
    }

    /// The file's length — the cell's `size`, by the check: what the
    /// `Content-Length` header carries on the `GET` and the `HEAD` alike.
    pub fn size(&self) -> u64 {
        self.admitted.size()
    }

    /// The headers beyond what the transport supplies — the content pair
    /// from the file, and [`UNIVERSAL_HEADERS`](super::UNIVERSAL_HEADERS).
    pub fn headers(&self) -> &[(&'static str, &'static str)] {
        &self.headers
    }

    /// The address served — the re-check's subject.
    pub(super) fn i(&self) -> &Address {
        self.admitted.i()
    }

    /// The file, whole.
    pub(super) fn bytes(&self) -> &[u8] {
        self.admitted.bytes()
    }
}

/// The length, never the bytes: a fetch is a whole file.
impl std::fmt::Debug for Fetch<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Fetch")
            .field("status", &self.status())
            .field("size", &self.size())
            .field("headers", &self.headers)
            .finish()
    }
}

/// THE FETCH's CONTENT TYPE (wire.md §Media, THE FETCH; the ruled v1 cut):
/// `application/octet-stream` on every admitted answer — the daemon reads
/// no type off the bytes and declares none it did not read, so a page
/// rendering the file names the type itself from the cell's kind.
pub(super) const FETCH_CONTENT_TYPE: &str = "application/octet-stream";

/// THE INERT PAIR every admitted fetch carries (M-I7 (a): THE BYTES ARE
/// INERT AT THE FETCH): `X-Content-Type-Options: nosniff`, so no browser
/// reads a type off the bytes the daemon declared none for; and
/// `Content-Security-Policy: sandbox`, so a file navigated to directly
/// runs nothing and reaches nothing of the daemon's origin. On the 200
/// alone — a refusal's body is JSON the daemon composed.
const FETCH_INERT_HEADERS: [(&str, &str); 2] =
    [("X-Content-Type-Options", "nosniff"), ("Content-Security-Policy", "sandbox")];

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
    /// The `/changes` query out of its range — and, since round 7 (bu7-2),
    /// a `limit` whose page from the given `since` would pass the page byte
    /// budget (`crate::limits::MAX_CHANGES_PAGE_BYTES`): out of range for
    /// that fence, refused whole with `budget` and `fits` beside the name
    /// ([`refuse_over_budget`]) — the same code, so the armed set does not
    /// grow and the fuzz oracle's transcription stands.
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
    // The blob upload (media lane B; wire.md §Media) — every refusal of
    // the PUT's path family, each a transport refusal: no `Op` ran.
    /// The request's query or identifier is not the documented shape.
    MalformedBlob,
    /// The session layer's refusal of an upload act
    /// ([`crate::auth::policy::UploadRefusal`]: a guest, an unclaimed board,
    /// a node-tier principal), or the closed upload setting's
    /// `uploads_closed` — `detail` names which.
    UploadRefused,
    /// An identifier the requester's own records do not name — expired,
    /// ended, another's, never minted: one answer.
    NoUpload,
    /// Another stream holds the upload (clause (5)).
    UploadHeld,
    /// The stated offset is not the record's; carries `offset`, the
    /// record's.
    UploadOffset,
    /// The request's bytes would pass the declared length.
    UploadLength,
    /// The gate's refusal: `scope` names which of the three fired, `ended`
    /// whether the upload was ended (refused as the body was written) or
    /// kept (refused before it), `offset` the bytes received.
    DepositRefused,
    /// The blob store refused I/O.
    BlobIo,
    /// THE READINESS REFUSAL (ms5-R): the cell index's rebuild at open has
    /// not completed, and this is one of its three readers — the PUT's
    /// creation or resume, the deposit read. Retry-class, `history_busy`'s
    /// sibling: the request may be perfectly good and the walk momentarily
    /// unfinished. Every other request is served throughout.
    IndexRebuilding,
    /// THE PERMIT's REFUSAL (M-I5 (f); PATTERNS P29): every upload permit is
    /// in use, and this is the creation or the resume — refused before any
    /// body byte, a creation making no upload, a resume keeping its upload
    /// where it stood. Retry-class, `fetch_busy`'s and `history_busy`'s
    /// sibling; the progress read, the deposit read and the termination
    /// take no permit and are served throughout.
    UploadBusy,
    // The blob fetch (wire.md §Media, THE FETCH) — the refusals of the
    // route's own steps past M10's gate, each a transport refusal: the gate's
    // own rejection is answered in M10's envelope under its status
    // ([`refuse_fetch`]), and no other `Op` ran.
    /// No value is minted at the address.
    NoValue,
    /// The value names no media kind.
    NotACell,
    /// The value names a media kind under no schema this build reads —
    /// D13's halt, the door's token on this surface.
    UnknownCellSchema,
    /// A blind document's cell: this board holds no byte of its picture.
    BlindCell,
    /// The store has no file under the cell's hash; carries `hash` and
    /// `size`, the cell's.
    BlobMissing,
    /// The store's file is not the deposit the cell names; carries `hash`
    /// and `size`, the cell's.
    BlobDamaged,
    /// Every fetch permit is in use: retry-class, `history_busy`'s sibling.
    FetchBusy,
}

impl TransportError {
    fn name(self) -> &'static str {
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
            TransportError::MalformedBlob => "malformed_blob",
            TransportError::UploadRefused => "upload_refused",
            TransportError::NoUpload => "no_upload",
            TransportError::UploadHeld => "upload_held",
            TransportError::UploadOffset => "upload_offset",
            TransportError::UploadLength => "upload_length",
            TransportError::DepositRefused => "deposit_refused",
            TransportError::BlobIo => "blob_io",
            TransportError::IndexRebuilding => "index_rebuilding",
            TransportError::UploadBusy => "upload_busy",
            TransportError::NoValue => "no_value",
            TransportError::NotACell => "not_a_cell",
            TransportError::UnknownCellSchema => "unknown_cell_schema",
            TransportError::BlindCell => "blind_cell",
            TransportError::BlobMissing => "blob_missing",
            TransportError::BlobDamaged => "blob_damaged",
            TransportError::FetchBusy => "fetch_busy",
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
            | TransportError::MalformedHttp
            | TransportError::MalformedAt
            | TransportError::MalformedBlob
            | TransportError::UploadLength => 400,
            TransportError::UploadRefused => 403,
            // The fetch's six "not here" answers are 404 alike: what the
            // address holds, or the store under it, is not a file to serve
            // — told apart by name, never by status, so a client renders one
            // face per token and a cache keeps none (PUB-6.7).
            TransportError::NoSuchEndpoint
            | TransportError::NoUpload
            | TransportError::NoValue
            | TransportError::NotACell
            | TransportError::UnknownCellSchema
            | TransportError::BlindCell
            | TransportError::BlobMissing
            | TransportError::BlobDamaged => 404,
            TransportError::MethodNotAllowed => 405,
            // The standard shape's two conflicts: a held upload, a stated
            // offset that is not the record's.
            TransportError::UploadHeld | TransportError::UploadOffset => 409,
            TransportError::HistoryReclaimed => 410,
            TransportError::PayloadTooLarge => 413,
            TransportError::NoJournal
            | TransportError::HistoryIo
            | TransportError::HistoryCorrupt
            | TransportError::InternalPanic
            | TransportError::BlobIo => 500,
            // The five retry-class refusals: a pool is momentarily full —
            // the reconstruction, class-scan, fetch or upload pool — or the
            // cell index's walk at open is momentarily unfinished.
            TransportError::HistoryBusy
            | TransportError::ScanBusy
            | TransportError::IndexRebuilding
            | TransportError::UploadBusy
            | TransportError::FetchBusy => 503,
            // The gate's: the scope it names has no room for these bytes.
            TransportError::DepositRefused => 507,
        }
    }
}

/// The reason phrase of a status THIS daemon answers — `None` for any other.
/// Informational only (clients dispatch on the code), but the list is a
/// statement of which statuses the daemon answers, so it lives beside where
/// they are chosen: [`TransportError::status`], [`refuse_handshake`]'s pair,
/// and the 200 and 204 every success reply carries. A status chosen and
/// missing here goes out under the writer's fallback phrase, which this
/// module's tests (`server/reply/tests.rs`) exist to catch.
pub(super) fn reason_phrase(status: u16) -> Option<&'static str> {
    Some(match status {
        200 => "OK",
        204 => "No Content",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        409 => "Conflict",
        410 => "Gone",
        413 => "Payload Too Large",
        500 => "Internal Server Error",
        503 => "Service Unavailable",
        507 => "Insufficient Storage",
        _ => return None,
    })
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

/// THE PAGE BUDGET's face (wire.md §The change feed; bu7-2): `400
/// {"error": "malformed_changes", "budget": B, "fits": N, "detail": …}` —
/// the `limit` out of range for this fence, with the budget in bytes and the
/// largest `limit` whose page from the same `since` fits it, so a client
/// re-asks with `limit=N` and is served whole.
pub(super) fn refuse_over_budget(budget: usize, fits: usize) -> Reply {
    let detail = format!(
        "limit: the page would pass the budget of {budget} bytes; the largest limit that \
         fits from this since is {fits}"
    );
    refuse_with(
        TransportError::MalformedChanges,
        vec![
            ("budget", Value::Number((budget as u64).into())),
            ("fits", Value::Number((fits as u64).into())),
            ("detail", Value::String(detail)),
        ],
    )
}

/// The same refusal carrying the diagnostic fields a few errors name —
/// `head`, `nearest`, `floor`, `budget` and `fits`, the blob upload's
/// `offset`, `scope` and `ended` — the coordinate a caller needs to ask a
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
            ("detail", Value::String("all class-scan permits are in use; retry shortly".into())),
            ("op", Value::String(op_name(kind).into())),
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

/// THE REGISTRY SEQUENCE's refusal as its 200-enveloped rejection (the
/// record grade for registry records, 2b; wire.md §Registry). The ROW is
/// [`registry_refused_reply`]'s — the family's code is fixed there; the token
/// and the disposition are the refusal's own ([`RegistryRefusal::token`],
/// [`RegistryRefusal::disposition`]) — and what this adds is the transport's
/// half, the 200 [`op_answer`] gives every answer on that channel.
pub(super) fn registry_refused(kind: OpKind, r: &RegistryRefusal) -> Reply {
    op_answer(registry_refused_reply(kind, r.token(), r.disposition()))
}

/// THE MEDIA DOOR's refusal as its 200-enveloped rejection (media lanes A
/// and B; wire.md §Media): the two arms that are M10's own codes —
/// `published_target`, and `not_owner` naming the draft — are built as M10
/// builds them, [`Rejection::classified`] over the flat code (its
/// disposition and standing detail M10's own, so the bytes are the store's
/// bytes) and marshaled by the one codec; the four that are the daemon's
/// tokens ride `credential_refused` as every daemon-side refusal does
/// ([`credential_refused`]'s row), the token and the class the refusal's
/// own ([`MediaRefusal::token`], [`MediaRefusal::disposition`]) — the
/// window's `index_rebuilding` the one retry-class token among them.
pub(super) fn media_door_refused(kind: OpKind, refusal: MediaRefusal) -> Reply {
    if let Some(token) = refusal.token() {
        return op_answer(credential_refused_reply(kind, token.to_string(), refusal.disposition()));
    }
    let rejection = match refusal {
        MediaRefusal::PublishedTarget => {
            Rejection::classified(kind, RejectCode::PublishedTarget, None)
        }
        MediaRefusal::NotOwner { draft } => Rejection::classified(
            kind,
            RejectCode::NotOwner,
            Some(FaultSite { addr: Some(draft), ..FaultSite::default() }),
        ),
        // All four carry a token: answered above.
        MediaRefusal::UnboundCell
        | MediaRefusal::UnknownCellSchema
        | MediaRefusal::LeaseLapsed
        | MediaRefusal::IndexRebuilding => {
            unreachable!("a media token rides credential_refused")
        }
    };
    op_answer(JsonCodec.marshal(&Response::Rejected(rejection)))
}

/// THE FETCH's REFUSALS (wire.md §Media, THE FETCH), each step's as its
/// reply — the ONE home of the route's statuses and bodies. The gate's own
/// rejection — M10's read by identity refused — is answered in M10's own
/// envelope, the bytes `/op` would answer for the same read (`withheld`
/// naming the derived home with its `reorder` class, and every other code
/// as M10 classifies it), under the STATUS the code's class gives it on this
/// transport route: `403` for `withheld`, `404` for `doc_not_registered`,
/// `400` for the rest (a malformed span, a width past the budget). A
/// status chosen HERE and not through [`refuse`], because the body is not
/// the transport's `{"error"}` shape: no transport error names an M10 code,
/// and inventing seven would make the store's own vocabulary a second
/// time. Every other step's refusal is a transport error of this table's,
/// through [`refuse`] and [`refuse_with`]: the shape `malformed_blob`, the
/// two "the store did not have it" refusals carrying the cell's `hash` and
/// `size`, the halt's detail the client's face. A `HEAD`'s refusal is this
/// same reply: the transport writes its head — the content pair included —
/// and no byte of its body (`http::write_reply`).
pub(super) fn refuse_fetch(refusal: FetchRefusal) -> Reply {
    match refusal {
        FetchRefusal::Shape(detail) => refuse(TransportError::MalformedBlob, Some(&detail)),
        FetchRefusal::Rejected(rejection) => {
            let status = match rejection.code {
                RejectCode::Withheld => 403,
                RejectCode::DocNotRegistered => 404,
                _ => 400,
            };
            Reply::bodied(
                status,
                "application/json",
                JsonCodec.marshal(&Response::Rejected(rejection)),
            )
        }
        FetchRefusal::NoValue => {
            refuse(TransportError::NoValue, Some("no value is minted at this address"))
        }
        FetchRefusal::NotACell => {
            refuse(TransportError::NotACell, Some("the value at this address names no media cell"))
        }
        FetchRefusal::UnknownCellSchema => {
            refuse(TransportError::UnknownCellSchema, Some(UNKNOWN_CELL_SCHEMA_FACE))
        }
        FetchRefusal::BlindCell => refuse(TransportError::BlindCell, Some(BLIND_CELL_FACE)),
        FetchRefusal::BlobMissing(face) => {
            refuse_with(TransportError::BlobMissing, cell_fields(face))
        }
        FetchRefusal::BlobDamaged(face) => {
            refuse_with(TransportError::BlobDamaged, cell_fields(face))
        }
        FetchRefusal::BlobIo(e) => refuse(TransportError::BlobIo, Some(&e.to_string())),
        FetchRefusal::Busy => {
            refuse(TransportError::FetchBusy, Some("all fetch permits are in use; retry shortly"))
        }
    }
}

/// The halt's face (wire.md §Media; PUB-6.7): the one prose a client
/// renders for `unknown_cell_schema`, on the door and on the fetch alike,
/// naming both kinds the classification reads.
const UNKNOWN_CELL_SCHEMA_FACE: &str =
    "this value names a media cell — a picture's or a blind document's — in a form this board \
     does not read";

/// The blind cell's face: the picture is its owner's, and this board holds
/// no byte of it.
const BLIND_CELL_FACE: &str =
    "this address holds a blind document's cell: its picture is kept by its owner, and this \
     board holds no byte of it";

/// The cell's own two members on the refusals that name what the store did
/// not have.
fn cell_fields(face: CellFace) -> Vec<(&'static str, Value)> {
    vec![("hash", Value::String(face.hash)), ("size", Value::Number(face.size.into()))]
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
        HistoryError::BeyondHead { head } => {
            refuse_with(TransportError::BeyondHead, vec![("head", Value::Number(head.0.into()))])
        }
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

#[cfg(test)]
mod tests;
