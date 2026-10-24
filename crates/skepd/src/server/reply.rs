//! The handler's reply, every transport refusal, and the reply decorators.

use serde_json::Value;
use skep_address::Address;
use skep_engine::HistoryError;
use skep_febe::{Codec, FaultSite, OpKind, RejectCode, Rejection, Response};
use skep_media::door::MediaRefusal;
use skep_media::serve::{Admitted, FetchRefusal, NamedBlob};
use skep_util::json::obj;

use skep_core::auth::policy::{CredentialRefusal, RegistryRefusal};
use skep_core::auth::session::HandshakeRefusal;
use skep_core::codec::{
    credential_refused_reply, op_name, registry_refused_reply, to_bytes, JsonCodec,
};
use skep_core::commits::FeedPending;
use crate::history::Unavailable;

/// Preflight cache lifetime advertised on `OPTIONS` (wire v4).
const CORS_MAX_AGE_SECS: &str = "86400";

/// The request header that carries the opaque session token.
///
/// It and `Origin` are the two request headers this daemon reads beyond
/// HTTP's own framing. A constant because the CORS preflight must advertise
/// exactly the header the reader consults — a header the preflight omits is
/// one the browser will not send, so the two must agree or every
/// cross-origin write fails at a layer this crate's own suite, which writes
/// the header straight onto a socket, never reaches.
pub(super) const SESSION_HEADER: &str = "Skepd-Session";

/// A response body and the media type naming it.
///
/// The two are one value, because a reply may neither carry bytes it does
/// not name nor name a type it has no bytes for. `content_type` names the
/// `Content-Type` header verbatim, which is HTTP's word and not the
/// substrate's.
///
/// A *request's* body is bare bytes
/// ([`HttpRequest::body`](super::HttpRequest::body)) because this daemon does
/// not read the type a client declares, while every response body it writes
/// must declare one. That is one concept in two shapes, not two concepts.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Body {
    /// The media type the `Content-Type` header carries, verbatim.
    pub content_type: &'static str,
    /// The body's bytes, held whole in memory.
    pub bytes: Vec<u8>,
}

/// One handler result: a status, an optional body, and any extra headers.
///
/// `POST /op` is always `200` once a `Response` exists — rejections
/// included; the `Response` envelope, not the HTTP status, is the operation
/// protocol. On that route non-200 codes are transport-level only
/// (`{"error": …}` bodies, wire.md §HTTP status codes).
///
/// `body: None` is the bodiless answer, written with no content headers
/// at all (the 204 preflight). Making bodilessness the body's own absence
/// is what keeps the writer from inferring it from the status, where a 204
/// built with bytes would drop them in silence.
///
/// **A handler's answer**, not a complete HTTP response. Two kinds of header
/// come from `http::write_reply` rather than from any `Reply` value:
/// `Content-Type` and `Content-Length`, which it derives from the `body`
/// field below and omits entirely when there is none, and every member of
/// [`UNIVERSAL_HEADERS`](super::UNIVERSAL_HEADERS), which wire.md §Transport
/// and §Cross-origin access promise on every response. A caller serving
/// these over a transport of its own owes that constant's members — and
/// takes them from it rather than transcribing them, so a change to the
/// cross-origin posture moves for them too.
#[derive(Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Reply {
    /// The HTTP status code.
    pub status: u16,
    /// The body, or `None` for a bodiless reply.
    pub body: Option<Body>,
    /// Extra response headers beyond what `http::write_reply` supplies.
    ///
    /// It supplies `Content-Type` and `Content-Length` from the body, and
    /// [`UNIVERSAL_HEADERS`](super::UNIVERSAL_HEADERS) always. The preflight
    /// trio rides here, as does the death signal; that constant is
    /// `write_reply`'s to supply, not this list's.
    pub headers: Vec<(&'static str, &'static str)>,
}

/// The reply's `Debug`, which writes the body's length and never its bytes.
///
/// A `/dump` reply is a whole world and an inlined body would make `dbg!`
/// useless exactly where it is reached for.
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
    /// Returns the body bytes; empty for a bodiless reply.
    pub fn bytes(&self) -> &[u8] {
        self.body.as_ref().map_or(&[], |b| b.bytes.as_slice())
    }

    /// Returns a reply carrying `bytes` under `content_type`.
    pub(super) fn bodied(status: u16, content_type: &'static str, bytes: Vec<u8>) -> Reply {
        Reply { status, body: Some(Body { content_type, bytes }), headers: Vec::new() }
    }

    /// Returns a JSON reply at `status`.
    ///
    /// A success answer names its own code here. A refusal names a
    /// [`TransportError`] instead and takes its status from there — save the
    /// handshake's pair, which [`refuse_handshake`] builds here at statuses
    /// of its own, and the fetch gate's rejections, which [`refuse_fetch`]
    /// gives three statuses of its own through [`Reply::bodied`].
    pub(super) fn json(status: u16, v: Value) -> Reply {
        Reply::bodied(status, "application/json", to_bytes(&v))
    }

    /// Returns the CORS preflight answer (wire v4).
    ///
    /// The answer is a 204 with no body and the fixed method and header
    /// lists. `Access-Control-Allow-Origin: *` is in
    /// [`UNIVERSAL_HEADERS`](super::UNIVERSAL_HEADERS), which every final
    /// response's writer emits, so it is not repeated here.
    ///
    /// The method list must name every method
    /// [`Daemon::reply`](super::Daemon::reply) dispatches on a path this
    /// preflight answers — every known path but the blob upload family's and
    /// the fetch's — for the same reason [`SESSION_HEADER`] is a constant: a
    /// method the preflight omits is one the browser will not send, and that
    /// failure appears only cross-origin, where this suite's own TCP clients
    /// never look. The list is a joined `&'static str` and so cannot be built
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

    /// Returns the CORS preflight of the blob upload's path family.
    ///
    /// The four methods the family dispatches (wire.md §Media) — the
    /// creation and the deposit read, the resume, the end — are named, so a
    /// browser sends them cross-origin; every other known path but the
    /// fetch's ([`Reply::preflight_fetch`]) keeps [`Reply::preflight`]'s
    /// three.
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

    /// Returns the CORS preflight of the blob fetch's path.
    ///
    /// The answer names the two methods the route dispatches
    /// (wire.md §Media, the fetch) — `GET`, and `HEAD` for the head alone —
    /// so a browser sends them cross-origin, and carries the two headers
    /// every preflight carries.
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

/// One routing decision.
///
/// Almost everything is a complete [`Reply`]; the event stream is not
/// request/response at all, so it never becomes one — the accept path
/// spawns a subscriber thread that owns the socket (`serve_events`), and the
/// type makes reaching it through the plain reply path unrepresentable —
/// and the blob fetch's admitted answer is a *stream* of a file the
/// transport writes one chunk at a time, re-resolving the requester between
/// chunks, so it is its own variant too.
///
/// `#[non_exhaustive]`, because this is one variant per answer the reply
/// path cannot express, which is a category rather than a singleton: a
/// [`Body`] holds its bytes wholly in memory, and the fetch is that
/// category's second member. What it costs a downstream caller is a `_`
/// arm, and the honest answer there is the one a socket-free caller already
/// gives [`Routed::EventStream`]: refuse the route.
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
    /// A plain reply: every answer but the event stream and the admitted fetch.
    Reply(Reply),
    /// `GET /events` — the server-sent commit stream (wire v4).
    ///
    /// Serviceable only through [`serve`](super::serve): following the
    /// stream is `skep_core::commits`', which the daemon keeps private, so a
    /// caller routing by hand can answer this variant only by refusing the
    /// route. It and the admitted fetch ([`Routed::Fetch`]) are the answers
    /// the socket-free surface names and cannot serve.
    EventStream,
    /// The admitted answer of `GET /blob?i=` and `HEAD /blob?i=`.
    ///
    /// Admitted (wire.md §Media, the fetch): the file checked whole against
    /// its cell, held with the fetch pool's permit, streamed by
    /// [`serve`](super::serve) under the idle and transfer bounds with the
    /// requester re-resolved between chunks (M-I2 (g)). Every refusal of the
    /// route is an ordinary [`Routed::Reply`].
    ///
    /// Serviceable only through [`serve`](super::serve), as
    /// [`Routed::EventStream`] is: the file's bytes and the mid-stream
    /// re-resolution are the daemon's transport's alone, so a caller routing
    /// by hand can answer this variant only by refusing the route —
    /// [`Fetch`]'s accessors describe the answer the transport writes and
    /// carry no byte of the file. Dropping the value returns its permit to
    /// the fetch pool, which is small (a fetch past it answers
    /// `503 fetch_busy`), so a caller that refuses drops the value at once.
    Fetch(Fetch<'a>),
}

/// The fetch's admitted answer.
///
/// A 200 whose body is the file, the status fixed — the gate's refusals are
/// each a [`Reply`] of their own — and the headers the route stamped (the
/// class-varying pair, the two inert ones, the death signal where owed). The
/// `GET`'s and the `HEAD`'s answer alike: the transport writes the body for
/// the one and the head alone for the other, HTTP's own rule. The file's
/// bytes are reached by the transport alone (`serve`'s stream); a caller
/// sees the length.
pub struct Fetch<'a> {
    admitted: Admitted<'a>,
    headers: Vec<(&'static str, &'static str)>,
}

impl<'a> Fetch<'a> {
    /// Returns the admitted answer, with the death signal when `closed`.
    pub(super) fn new(admitted: Admitted<'a>, closed: bool) -> Fetch<'a> {
        let mut headers: Vec<(&'static str, &'static str)> = FETCH_INERT_HEADERS.to_vec();
        headers.extend(CLASS_VARYING_HEADERS);
        if closed {
            headers.push((SESSION_HEADER, "closed"));
        }
        Fetch { admitted, headers }
    }

    /// Returns the status: `200`, always — an admitted fetch is the file.
    pub fn status(&self) -> u16 {
        200
    }

    /// Returns the file's length.
    ///
    /// It is the cell's `size`, by the check: what the `Content-Length`
    /// header carries on the `GET` and the `HEAD` alike.
    pub fn size(&self) -> u64 {
        self.admitted.size()
    }

    /// Returns the headers beyond what the transport supplies.
    ///
    /// The transport supplies the content pair from the file, and
    /// [`UNIVERSAL_HEADERS`](super::UNIVERSAL_HEADERS).
    pub fn headers(&self) -> &[(&'static str, &'static str)] {
        &self.headers
    }

    /// Returns the address served — the re-check's subject.
    pub(super) fn i(&self) -> &Address {
        self.admitted.i()
    }

    /// Returns the file, whole.
    pub(super) fn bytes(&self) -> &[u8] {
        self.admitted.bytes()
    }
}

/// The fetch's `Debug`, which writes the length and never the bytes.
///
/// A fetch is a whole file.
impl std::fmt::Debug for Fetch<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Fetch")
            .field("status", &self.status())
            .field("size", &self.size())
            .field("headers", &self.headers)
            .finish()
    }
}

/// The content type of every admitted fetch answer.
///
/// `application/octet-stream` on every admitted answer (wire.md §Media, the
/// fetch) — the daemon reads no type off the bytes and declares none it did
/// not read, so a page rendering the file names the type itself from the
/// cell's kind.
pub(super) const FETCH_CONTENT_TYPE: &str = "application/octet-stream";

/// The inert pair every admitted fetch carries (M-I7 (a)).
///
/// The bytes are inert at the fetch: `X-Content-Type-Options: nosniff`, so
/// no browser reads a type off the bytes the daemon declared none for; and
/// `Content-Security-Policy: sandbox`, so a file navigated to directly
/// runs nothing and reaches nothing of the daemon's origin. On the 200
/// alone — a refusal's body is JSON the daemon composed.
const FETCH_INERT_HEADERS: [(&str, &str); 2] =
    [("X-Content-Type-Options", "nosniff"), ("Content-Security-Policy", "sandbox")];

/// The transport's error vocabulary.
///
/// It holds every `{"error": …}` name this daemon can answer but the
/// handshake's two, and is the only way one of those is written. It is
/// exhaustive over the rest of the wire's transport-error table (wire.md
/// §HTTP status codes, §Reading history, §The change feed), so a new failure
/// cannot ship without a documented name, exactly as `code_name` guarantees
/// for M10's rejections. The handshake's two answers — the 401 and the 403 —
/// are the table's two rows written elsewhere: [`refuse_handshake`] says why.
#[derive(Clone, Copy, Debug)]
pub(super) enum TransportError {
    // The envelope and query parsers.
    MalformedSessionRequest,
    MalformedChallenge,
    MalformedOpAt,
    /// The `/changes` query malformed or out of its range.
    ///
    /// It also covers a `limit` whose page from the given `since` would pass
    /// the page byte budget (`skep_core::limits::MAX_CHANGES_PAGE_BYTES`):
    /// out of range for that fence, refused whole with `budget` and `fits`
    /// beside the name ([`refuse_over_budget`]) — the same code, so the
    /// armed set does not grow and the fuzz oracle's transcription stands.
    MalformedChanges,
    /// The one-parameter `at=<position>` query of `/dump?at` and `/chain?at`.
    ///
    /// `/dump?at` is served in observe builds and `/chain?at` in every build,
    /// so the variant is not `observe`-gated.
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
    /// The write permit pool's refusal (`operations.md` §4 rows 25, 27).
    ///
    /// Every write permit is in use — the pool bounds the workers writes can
    /// hold on the write path's guard at once, so an inline backstop's run
    /// parks at most W writers and the board answers `/health` meanwhile.
    /// Retry-class, `scan_busy`'s sibling on the same route; answered before
    /// the credential lock and the guard are taken, so nothing was committed
    /// and no change-feed line was written.
    WriteBusy,
    // The HTTP layer.
    MalformedHttp,
    PayloadTooLarge,
    InternalPanic,
    // The blob upload (wire.md §Media) — the refusals of the PUT's path
    // family's own steps, each a transport refusal: no `Op` ran.
    /// The request's query or identifier is not the documented shape.
    MalformedBlob,
    /// An upload act refused by the session layer or the closed upload setting.
    ///
    /// The session layer's refusal ([`skep_core::auth::policy::UploadRefusal`]:
    /// a guest, an unclaimed board, a node-tier principal), or the closed
    /// upload setting's `uploads_closed` — `detail` names which.
    UploadRefused,
    /// An identifier the requester's own records do not name.
    ///
    /// Expired, ended, another's, never minted: one answer.
    NoUpload,
    /// Another stream holds the upload (clause (5)).
    UploadHeld,
    /// The stated offset is not the record's.
    ///
    /// It carries `offset`, the record's.
    UploadOffset,
    /// The request's bytes would pass the declared length.
    UploadLength,
    /// The gate's refusal.
    ///
    /// `scope` names which of the four fired, `ended` whether the upload was
    /// ended (refused as the body was written) or kept (refused before it),
    /// `offset` the bytes received.
    DepositRefused,
    /// The blob store refused I/O.
    BlobIo,
    /// The readiness refusal: the cell index is not yet rebuilt.
    ///
    /// The cell index's rebuild at open has not completed, and this is one
    /// of its three readers — the PUT's creation or resume, the deposit read.
    /// Retry-class, `history_busy`'s sibling: the request may be perfectly
    /// good and the walk momentarily unfinished. Every other request is
    /// served throughout, save an `/op` write the media door refuses with the
    /// same token on the operation channel ([`media_door_refused`]).
    IndexRebuilding,
    /// The failed-index refusal: the cell index's walk at open died.
    ///
    /// The walk died, on its thread or at the open where the OS refused it
    /// one (`operations.md` §4 row 26; §1.1 row 41; PATTERNS P10) — caught,
    /// the index failed, a third state beside ready and not-ready — and this
    /// is one of its three readers. *Not*
    /// retry-class, though it shares the 503: `index_rebuilding` names a
    /// window that ends, this a state that stands for the life of the
    /// process, so the `detail` names the act that exists elsewhere — a
    /// restart, the operator's — and no retry, and a client that retries
    /// retry-class tokens stops. The door emits no token of its own for the
    /// state: under the failed state it answers the lease arm's verdict as
    /// final. Every other request is served throughout.
    IndexFailed,
    /// The upload permit's refusal (M-I5 (f); PATTERNS P29).
    ///
    /// Every upload permit is in use, and this is the creation or the
    /// resume — refused before any body byte, a creation making no upload, a
    /// resume keeping its upload where it stood. Retry-class, `fetch_busy`'s
    /// and `history_busy`'s sibling; the progress read, the deposit read and
    /// the termination take no permit and are served throughout.
    UploadBusy,
    // The blob fetch (wire.md §Media, the fetch) — the refusals of the
    // route's own steps past M10's gate, each a transport refusal: the gate's
    // own rejection is answered in M10's envelope under its status
    // ([`refuse_fetch`]), and no other `Op` ran.
    /// No value is minted at the address.
    NoValue,
    /// The value names no media kind.
    NotACell,
    /// The value names a media kind under no schema this build reads.
    ///
    /// It is D13's halt, the door's token on this surface.
    UnknownCellSchema,
    /// A blind document's cell: this board holds no byte of its picture.
    BlindCell,
    /// The store has no file under the cell's hash.
    ///
    /// It carries `hash` and `size`, the cell's.
    BlobMissing,
    /// The store's file is not the deposit the cell names.
    ///
    /// It carries `hash` and `size`, the cell's.
    BlobDamaged,
    /// Every fetch permit is in use: retry-class, `history_busy`'s sibling.
    FetchBusy,
    /// The refusal of the walk behind the listener.
    ///
    /// A lost or torn `commits.log` left a region of positions uncovered, or
    /// a lost or cut `feed-index.log` left bare positions of the log
    /// unclassified (`operations.md` §3.3 step 2; §4 row 16), which the write
    /// path's walk thread re-covers and sorts while the board serves, and
    /// this `/changes` page would reach one of them. Retry-class,
    /// `index_rebuilding`'s shape under its own token: pages below and above
    /// the pending positions serve, `/events` is untouched, and the landing
    /// clears it — a position sorted serving as soon as it lands. Served
    /// instead, the page would skip the set's positions in silence or, off
    /// the index files that stand, carry rows a class may not see: an issuer
    /// stream taken whole past the filter's bound, a straddle's `attest`.
    FeedRebuilding,
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
            TransportError::WriteBusy => "write_busy",
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
            TransportError::IndexFailed => "index_failed",
            TransportError::UploadBusy => "upload_busy",
            TransportError::NoValue => "no_value",
            TransportError::NotACell => "not_a_cell",
            TransportError::UnknownCellSchema => "unknown_cell_schema",
            TransportError::BlindCell => "blind_cell",
            TransportError::BlobMissing => "blob_missing",
            TransportError::BlobDamaged => "blob_damaged",
            TransportError::FetchBusy => "fetch_busy",
            TransportError::FeedRebuilding => "feed_rebuilding",
        }
    }

    /// Returns the status this failure is answered with.
    ///
    /// The status is the first column of the table whose second
    /// [`TransportError::name`] transcribes (wire.md §HTTP status codes).
    /// Clients dispatch on the status, so the pairing is contract; stating it
    /// here is what keeps one name from arriving under two statuses depending
    /// on which handler refused.
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
            // The seven retry-class refusals: a pool is momentarily full —
            // the reconstruction, class-scan, fetch, upload or write pool —
            // or the cell index's walk at open, or the feed's walk behind
            // the listener, is momentarily unfinished.
            TransportError::HistoryBusy
            | TransportError::ScanBusy
            | TransportError::WriteBusy
            | TransportError::IndexRebuilding
            | TransportError::UploadBusy
            | TransportError::FetchBusy
            | TransportError::FeedRebuilding => 503,
            // The failed index, 503 in an arm of its own (`operations.md` §4
            // row 26; PATTERNS P10): the service is unavailable, as above —
            // and *not* retry-class, so it is not listed with the seven. The
            // cell index's walk at open died, and no retry can succeed for
            // the life of the process: the detail names a restart and no
            // retry, and a client that retries retry-class tokens stops.
            TransportError::IndexFailed => 503,
            // The gate's: the scope it names has no room for these bytes —
            // or, the standing scope, for another upload.
            TransportError::DepositRefused => 507,
        }
    }
}

/// Returns the reason phrase of a status this daemon answers.
///
/// It answers `None` for any other status. Informational only (clients
/// dispatch on the code), but the list is a statement of which statuses the
/// daemon answers, so it lives beside where they are chosen:
/// [`TransportError::status`], [`refuse_handshake`]'s pair,
/// [`refuse_fetch`]'s three, and the 200 and 204 every success reply
/// carries. A status chosen and missing here goes out under the writer's
/// fallback phrase, which this module's tests (`server/reply/tests.rs`)
/// exist to catch.
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

/// Returns a transport-level refusal, whole.
///
/// The reply is the status and the `{"error": name}` body wire.md pairs with
/// `err`, plus an optional detail. Deliberately *not* the
/// `{"resp": "rejected"}` shape — no `Op` was involved. Every non-2xx this
/// daemon answers is built here or by [`refuse_with`], [`refuse_handshake`]
/// or [`refuse_fetch`], so no handler chooses a status of its own.
pub(super) fn refuse(err: TransportError, detail: Option<&str>) -> Reply {
    let fields = match detail {
        Some(d) => vec![("detail", Value::String(d.into()))],
        None => Vec::new(),
    };
    refuse_with(err, fields)
}

/// Returns the page budget's face (wire.md §The change feed).
///
/// That face is `400 {"error": "malformed_changes", "budget": B, "fits": N,
/// "detail": …}` — the `limit` out of range for this fence, with the budget
/// in bytes and the largest `limit` whose page from the same `since` fits
/// it, so a client re-asks with `limit=N` and is served whole.
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

/// Returns the same refusal carrying the diagnostic fields a few errors name.
///
/// Those fields — `head`, `nearest`, `floor`, `budget` and `fits`, the blob
/// upload's `offset`, `scope` and `ended` — are the coordinate a caller
/// needs to ask a better question; the busy refusals' `op` and the fetch's
/// `hash` and `size` ride here too. `error` is appended here, so a field
/// list can never omit it.
pub(super) fn refuse_with(err: TransportError, fields: Vec<(&'static str, Value)>) -> Reply {
    let mut pairs = fields;
    pairs.push(("error", Value::String(err.name().into())));
    Reply::json(err.status(), obj(pairs))
}

/// Maps the handshake's two refusals to their replies (AUTH-6.5).
///
/// This is the one home of both bodies, so the pair cannot drift. Every
/// failure of the *credential* is `401 {"error":"session_rejected"}`: one
/// code, no detail, byte-identical across its thirteen arms
/// (AUTH-4.62 item 1), which a unit refusal makes true by construction. The
/// one exception, by status, is step 4b's:
/// `403 {"error":"prefix_blocked","record":"<address>"}`, the record's
/// version address its one datum and public by construction — never the 401,
/// because this party's credential was not read.
///
/// Built here and not through [`refuse`]: the handshake's answers are
/// AUTH-6.5's to word, a pair, and neither name is a [`TransportError`]
/// variant — so neither can grow the optional `detail` every variant of that
/// enum is offered.
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

/// Attaches the death signal (AUTH-6.7) when owed.
///
/// The signal is attached once, however many resolution sites observed the
/// death on this request.
pub(super) fn with_signal(mut reply: Reply, closed: bool) -> Reply {
    if closed && !reply.headers.iter().any(|(k, _)| *k == SESSION_HEADER) {
        reply.headers.push((SESSION_HEADER, "closed"));
    }
    reply
}

/// The cache headers every class-varying reply carries (wire v7.6).
///
/// The answer is a function of the presented token's class, so it may be
/// neither stored nor served to another requester.
/// `Cache-Control: no-store` forbids any cache from keeping it;
/// `Vary: Skepd-Session` names the request header the answer turns on, so a
/// cache that keeps one anyway keys it by the token. Applied at the
/// [`Daemon::reply`](super::Daemon::reply) arms of the four routes — `/op`,
/// `/op-at`, `/changes`, `/dump` — and of the blob upload's family, and to
/// every answer of the blob fetch (`fetch_route`'s refusals and
/// [`Fetch::new`]'s admitted answer), rather than at [`op_answer`] (which
/// `/changes` and `/dump` do not use, and which no transport refusal passes
/// through) or at [`Reply::bodied`] (which `/health` and `/` share, and
/// those are class-invariant). `/events` is a stream with its own
/// `Cache-Control: no-cache` written at open, and `/health` is
/// class-invariant by construction (PUB-6.50), so neither wears these.
const CLASS_VARYING_HEADERS: [(&str, &str); 2] =
    [("Cache-Control", "no-store"), ("Vary", SESSION_HEADER)];

/// Stamps a class-varying route's reply with [`CLASS_VARYING_HEADERS`].
///
/// It stamps once, whatever the reply is: a marshaled answer, a credential
/// refusal, a transport refusal.
pub(super) fn class_varying(mut reply: Reply) -> Reply {
    for (name, value) in CLASS_VARYING_HEADERS {
        if !reply.headers.iter().any(|(k, _)| *k == name) {
            reply.headers.push((name, value));
        }
    }
    reply
}

/// Returns one operation answer, already marshaled, as its reply.
///
/// The reply is always `200`, whatever the answer says: the envelope, not
/// the HTTP status, is the operation protocol. *The* constructor for that
/// channel, so a daemon-originated answer (`key_set`, a credential refusal,
/// a memoized ack) cannot choose a status of its own — the standing
/// [`refuse`] has on the transport channel.
pub(super) fn op_answer(bytes: Vec<u8>) -> Reply {
    Reply::bodied(200, "application/json", bytes)
}

/// Returns the `503 scan_busy` refusal (wire v7.9).
///
/// Every class-scan permit is in use. Retry-class — the query may be
/// perfectly good and the pool momentarily full — and the body names the
/// `op` it refused, so a client pipelining reads can pair the refusal with
/// the request it answers, in the diagnostic-field shape `beyond_head`'s
/// `head` and `history_reclaimed`'s `floor` take. A *transport* refusal like
/// `history_busy` and not an operation response: no `Op` ran, so there is no
/// `resp` and no `code` — the envelope is `{"error": …}`, never
/// `{"resp": "rejected"}`.
pub(super) fn refuse_scan_busy(kind: OpKind) -> Reply {
    refuse_with(
        TransportError::ScanBusy,
        vec![
            ("detail", Value::String("all class-scan permits are in use; retry shortly".into())),
            ("op", Value::String(op_name(kind).into())),
        ],
    )
}

/// Returns the `503 write_busy` refusal: every write permit is in use.
///
/// The refusal is the write permit pool's (`operations.md` §4 rows 25, 27).
/// Retry-class — the write may be perfectly good and the pool momentarily
/// full, an inline backstop holding the guard with W − 1 writers parked
/// behind it — and the body names the `op` it refused in
/// [`refuse_scan_busy`]'s shape, the one sibling refused on the same route,
/// so a client pairs the refusal with the frame it answers. A *transport*
/// refusal and not an operation response: it is answered before the
/// credential lock and the guard are taken, so no `Op` ran, nothing was
/// committed, and there is no `resp` and no `code` — the envelope is
/// `{"error": …}`, never `{"resp": "rejected"}`.
pub(super) fn refuse_write_busy(kind: OpKind) -> Reply {
    refuse_with(
        TransportError::WriteBusy,
        vec![
            ("detail", Value::String("all write permits are in use; retry shortly".into())),
            ("op", Value::String(op_name(kind).into())),
        ],
    )
}

/// Returns a daemon-originated credential refusal's 200-enveloped rejection.
///
/// The row is [`credential_refused_reply`]'s — the code is the wire's and is
/// fixed there; the token and the disposition are the refusal's own
/// ([`CredentialRefusal::token`], [`CredentialRefusal::disposition`]) — and
/// what this adds is the transport's own half: the 200 [`op_answer`] gives
/// every answer on that channel, whatever the answer says.
pub(super) fn credential_refused(kind: OpKind, r: &CredentialRefusal) -> Reply {
    op_answer(credential_refused_reply(kind, r.token(), r.disposition()))
}

/// Returns the registry sequence's refusal as its 200-enveloped rejection.
///
/// The sequence is the record grade for registry records (2b; wire.md
/// §Registry). The row is [`registry_refused_reply`]'s — the family's code
/// is fixed there; the token and the disposition are the refusal's own
/// ([`RegistryRefusal::token`], [`RegistryRefusal::disposition`]) — and what
/// this adds is the transport's half, the 200 [`op_answer`] gives every
/// answer on that channel.
pub(super) fn registry_refused(kind: OpKind, r: &RegistryRefusal) -> Reply {
    op_answer(registry_refused_reply(kind, r.token(), r.disposition()))
}

/// Returns the media door's refusal as its 200-enveloped rejection.
///
/// The two arms that are M10's own codes (wire.md §Media) —
/// `published_target`, and `not_owner` naming the draft — are built as M10
/// builds them, [`Rejection::classified`] over the flat code (its
/// disposition and standing detail M10's own, so the bytes are the store's
/// bytes) and marshaled by the one codec; the four that are the daemon's
/// tokens ride `credential_refused` as every daemon-side refusal but the
/// registry sequence's does ([`credential_refused`]'s row), the token and
/// the class the refusal's own ([`MediaRefusal::token`],
/// [`MediaRefusal::disposition`]) — the rebuild window's `index_rebuilding`
/// the one retry-class token among them.
///
/// # Panics
///
/// Panics if [`MediaRefusal::token`] answers `None` for one of the four
/// token refusals — `UnboundCell`, `UnknownCellSchema`, `LeaseLapsed`,
/// `IndexRebuilding`. It cannot be reached while each of the four carries
/// its token, which is answered before the match.
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

/// Maps each [`FetchRefusal`] to its reply (wire.md §Media, the fetch).
///
/// Each step's refusal is answered here — the one home of those steps'
/// statuses and bodies. The fetch's gate's own rejection — M10's read by
/// identity refused — is answered in M10's own envelope, the bytes `/op`
/// would answer for the same read (`withheld` naming the derived home with
/// its `reorder` class, and every other code as M10 classifies it), under
/// the status its code takes on this transport route: `403` for
/// `withheld`, `404` for `doc_not_registered`, `400` for the rest (a
/// malformed span, a width past the budget). A status chosen here and not
/// through [`refuse`], because the body is not the transport's `{"error"}`
/// shape: no transport error names an M10 code, and inventing seven would
/// make the store's own vocabulary a second time. Every other step's refusal
/// is a transport error of this table's, through [`refuse`] and
/// [`refuse_with`]: the shape `malformed_blob`, the two "the store did not
/// have it" refusals carrying the blob the cell names ([`NamedBlob`]: its
/// `hash` and `size`, data the client composes its face from, PUB-6.7), the
/// halt's detail the client's face. A `HEAD`'s refusal is this same reply:
/// the transport writes its head — the content pair included — and no byte
/// of its body (`http::write_reply`).
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
        FetchRefusal::BlobMissing(named) => {
            refuse_with(TransportError::BlobMissing, cell_fields(named))
        }
        FetchRefusal::BlobDamaged(named) => {
            refuse_with(TransportError::BlobDamaged, cell_fields(named))
        }
        FetchRefusal::BlobIo(e) => refuse(TransportError::BlobIo, Some(&e.to_string())),
        FetchRefusal::Busy => {
            refuse(TransportError::FetchBusy, Some("all fetch permits are in use; retry shortly"))
        }
    }
}

/// The halt's face (wire.md §Media; PUB-6.7).
///
/// The one prose a client renders for `unknown_cell_schema`, on the door and
/// on the fetch alike, naming both kinds the classification reads.
const UNKNOWN_CELL_SCHEMA_FACE: &str =
    "this value names a media cell — a picture's or a blind document's — in a form this board \
     does not read";

/// The blind cell's face.
///
/// The picture is its owner's, and this board holds no byte of it.
const BLIND_CELL_FACE: &str =
    "this address holds a blind document's cell: its picture is kept by its owner, and this \
     board holds no byte of it";

/// Returns the cell's own two members.
///
/// They ride the refusals that name what the store did not have.
fn cell_fields(named: NamedBlob) -> Vec<(&'static str, Value)> {
    vec![("hash", Value::String(named.hash)), ("size", Value::Number(named.size.into()))]
}

/// Returns the `410 history_reclaimed` refusal.
///
/// The position asked for is older than what can still be answered, and
/// `floor` — when one exists — names the oldest that can. One construction,
/// shared by the history surface and the change feed, so the two cannot
/// describe the same condition differently.
pub(super) fn refuse_reclaimed(floor: Option<u64>) -> Reply {
    let fields = match floor {
        Some(f) => vec![("floor", Value::Number(f.into()))],
        None => Vec::new(),
    };
    refuse_with(TransportError::HistoryReclaimed, fields)
}

/// The walk behind the listener, as a page refused `feed_rebuilding` meets it.
///
/// It is read off the write path's own state of the walk
/// (`Commits::feed_walk_gone`), and it decides what the refusal's `detail`
/// tells the client to do: retry while the walk runs, restart where it died.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum FeedWalk {
    /// The walk runs: its landing covers the region, and a retry succeeds.
    Walking,
    /// The walk's thread died on a caught panic (`operations.md` §1.1 row
    /// 41): the region stays uncovered until a restart, which walks again.
    Gone,
}

/// Returns the `503 feed_rebuilding` refusal for what the walk has yet to land.
///
/// It takes what pends ([`FeedPending`]): the region alone, which answers as
/// [`refuse_feed_rebuilding`] does; the bare positions a lost or cut
/// `feed-index.log` left unsorted, whose `detail` names their count and the
/// first of them — `the change feed is being rebuilt behind the listener:
/// {n} bare positions whose classification feed-index.log lost are not yet
/// sorted, the first at position {p}, and this page reaches into them; pages
/// below and above serve; retry shortly`; or both, the region's words then
/// the set's. The dead walk's arm ([`FeedWalk::Gone`]) says the rebuild
/// ended at this start and that what pends stays so until a restart, with
/// no retry hint, as the region's door does. Still `error` and `detail`
/// alone: no member for the region or the set rides the wire.
pub(super) fn refuse_feed_rebuilding_over(pending: FeedPending, walk: FeedWalk) -> Reply {
    let what = match (pending.region, pending.unsorted) {
        (Some((low, head)), None) => return refuse_feed_rebuilding(low, head, walk),
        (Some((low, head)), Some(set)) => format!(
            "positions above {low} through {head} are not yet covered and {} bare positions \
             below them, whose classification feed-index.log lost, are not yet sorted",
            set.count
        ),
        (None, Some(set)) => format!(
            "{} bare positions whose classification feed-index.log lost are not yet sorted, the \
             first at position {}",
            set.count, set.first
        ),
        (None, None) => "nothing is left to land".to_string(),
    };
    let detail = match walk {
        FeedWalk::Walking => format!(
            "the change feed is being rebuilt behind the listener: {what}, and this page reaches \
             into them; pages below and above serve; retry shortly"
        ),
        FeedWalk::Gone => format!(
            "the change feed's rebuild behind the listener ended at this start: {what}, and stay \
             so until a restart, which walks and sorts them again; this page reaches into them; \
             pages below and above serve; no retry succeeds before the restart"
        ),
    };
    refuse(TransportError::FeedRebuilding, Some(&detail))
}

/// Returns the `503 feed_rebuilding` refusal for a pending region.
///
/// The page's rows would come from the positions a lost or torn
/// `commits.log` left uncovered (`operations.md` §3.3 step 2; §4 row 16),
/// which the walk behind the listener has yet to land — `index_rebuilding`'s
/// voice under its own token, the `detail` naming the region in words and
/// the retry, and *no* member beyond `error` and `detail`: a region member
/// on the wire is a design the record does not make. Pages below and above
/// the region serve, as the detail says. Where the walk's thread has died
/// ([`FeedWalk::Gone`]), the region stays uncovered for the uptime, and the
/// detail says so, names the restart and gives no retry hint —
/// `index_failed`'s voice (PATTERNS P10) under this token, so a client that
/// retries retry-class refusals is told no retry succeeds before a restart.
/// The region's arm of [`refuse_feed_rebuilding_over`], the door the route
/// takes.
pub(super) fn refuse_feed_rebuilding(low: u64, head: u64, walk: FeedWalk) -> Reply {
    let detail = match walk {
        FeedWalk::Walking => format!(
            "the change feed is being rebuilt behind the listener: positions above {low} \
             through {head} are not yet covered, and this page reaches into them; pages below \
             and above serve; retry shortly"
        ),
        FeedWalk::Gone => format!(
            "the change feed's rebuild behind the listener ended at this start: positions above \
             {low} through {head} stay uncovered until a restart, which walks them again, and \
             this page reaches into them; pages below and above serve; no retry succeeds before \
             the restart"
        ),
    };
    refuse(TransportError::FeedRebuilding, Some(&detail))
}

/// Maps an unavailable historical answer onto the wire's transport errors.
///
/// This is the one place the history surface's `Unavailable` becomes HTTP.
/// The `beyond_head` body is emitted exactly as specified; the rest are this
/// daemon's own wire decisions, documented in wire.md §Reading history.
/// `history_busy` is the one retry-class error: the position may be
/// perfectly good and the daemon momentarily saturated.
///
/// **The I/O arm answers one fixed sentence.** The kernel's account of a
/// failed read names the file, the act and the OS's words, and at the
/// journal directory's own acts — the listing every history read takes
/// before it selects a base — the directory by its name
/// (`skep-kernel`'s `FileFailure`). A guest may ask every history read, and
/// every answer is readable cross-origin (wire.md §Cross-origin access), so
/// that account is the operator's alone:
/// [`Daemon::refuse_history`](super::Daemon::refuse_history) says it on the
/// operator stream where it is the journal's damage, and a client is
/// answered what failed, never where on the host or what the OS said.
///
/// It is also the *first* refusal: the reconstruction permit is taken before
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
        // One fixed sentence, never the kernel's account: the card says why.
        HistoryError::Io(_) => refuse(
            TransportError::HistoryIo,
            Some("reading the journal for this position failed"),
        ),
        HistoryError::Corruption { at, .. } => refuse(
            TransportError::HistoryCorrupt,
            Some(&format!("journal corrupt at rest; next intact frame at {}", at.0)),
        ),
    }
}

#[cfg(test)]
mod tests;
