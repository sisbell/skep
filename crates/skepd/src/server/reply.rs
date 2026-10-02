//! The reply a handler answers with, every transport refusal, and the reply
//! decorators.

use serde_json::Value;
use skep_engine::HistoryError;
use skep_febe::{Codec, FaultSite, OpKind, RejectCode, Rejection, Response};

use crate::auth::policy::CredentialRefusal;
use crate::auth::session::HandshakeRefusal;
use crate::codec::{credential_refused_reply, obj, to_bytes, JsonCodec};
use crate::history::Unavailable;
use crate::media::door::MediaRefusal;

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

/// The reason phrase of a status THIS daemon answers — `None` for any other.
/// Informational only (clients dispatch on the code), but the list is a
/// statement of which statuses the daemon answers, so it lives beside where
/// they are chosen: [`TransportError::status`], [`refuse_handshake`]'s pair,
/// and the 200 and 204 every success reply carries. A status chosen and
/// missing here goes out under the writer's fallback phrase, which the tests
/// at the end of this file exist to catch.
pub(super) fn reason_phrase(status: u16) -> Option<&'static str> {
    Some(match status {
        200 => "OK",
        204 => "No Content",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        410 => "Gone",
        413 => "Payload Too Large",
        500 => "Internal Server Error",
        503 => "Service Unavailable",
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
/// `head`, `nearest`, `floor`, `budget` and `fits` — the coordinate a caller
/// needs to ask a better question. `error` is appended here, so a field list
/// can never omit it.
fn refuse_with(err: TransportError, fields: Vec<(&'static str, Value)>) -> Reply {
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

/// THE MEDIA DOOR's refusal as its 200-enveloped rejection (media lane A;
/// wire.md §Media): the two arms that are M10's own codes —
/// `published_target`, and `not_owner` naming the draft — are built as M10
/// builds them, [`Rejection::classified`] over the flat code (its
/// disposition and standing detail M10's own, so the bytes are the store's
/// bytes) and marshaled by the one codec; the two that are the daemon's
/// tokens ride `credential_refused` as every daemon-side refusal does
/// ([`credential_refused`]'s row), the token and the class the refusal's
/// own ([`MediaRefusal::token`], [`MediaRefusal::disposition`]).
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
        // Both carry a token: answered above.
        MediaRefusal::UnboundCell | MediaRefusal::UnknownCellSchema => {
            unreachable!("a media token rides credential_refused")
        }
    };
    op_answer(JsonCodec.marshal(&Response::Rejected(rejection)))
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

#[cfg(test)]
mod tests {
    use super::*;

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
        let table: Vec<(TransportError, &'static str, u16)> = vec![
            (TransportError::MalformedSessionRequest, "malformed_session_request", 400),
            (TransportError::MalformedChallenge, "malformed_challenge", 400),
            (TransportError::MalformedOpAt, "malformed_op_at", 400),
            (TransportError::WriteAtHistory, "write_at_history", 400),
            (TransportError::BeyondHead, "beyond_head", 400),
            (TransportError::NotAPosition, "not_a_position", 400),
            (TransportError::MalformedAt, "malformed_at", 400),
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
            (TransportError::ScanBusy, "scan_busy", 503),
        ];
        for &(err, name, status) in &table {
            assert_eq!(err.name(), name, "wire name drifted for {err:?}");
            assert_eq!(err.status(), status, "{name} must be answered with {status}");
            assert!(reason_phrase(status).is_some(), "{name}'s {status} has no reason phrase");
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
        // reaching either list. The `+ 2` is the handshake's PAIR, neither
        // a `TransportError` variant — both are built at their own site per
        // AUTH-6.5, [`refuse_handshake`]: `session_rejected`, the 401, and
        // `prefix_blocked`, the 403 that is its one exception. The oracle's
        // list names both because wire.md's error column does; no fuzz
        // daemon is supplied a blocked-prefix list, so the second is a name
        // no fuzz target is answered today.
        for handshake_name in ["session_rejected", "prefix_blocked"] {
            assert!(
                crate::fuzz_support::TRANSPORT_ERRORS.contains(&handshake_name),
                "{handshake_name} is answerable but absent from the fuzz oracle's list"
            );
        }
        #[cfg(feature = "observe")]
        assert_eq!(
            table.len() + 2,
            crate::fuzz_support::TRANSPORT_ERRORS.len(),
            "the two hand transcriptions of wire.md's error column disagree in length"
        );
    }

    /// The statuses answered outside [`TransportError`] have their phrases
    /// too: the handshake's pair, built at its own site, and the success
    /// replies' 204 and 200.
    #[test]
    fn every_status_outside_the_transport_errors_has_a_reason_phrase() {
        use crate::auth::session::SessionRejected;
        let record = crate::codec::wire_address("1.0.1.0.7.1").expect("a record's address");
        let rejected = refuse_handshake(&HandshakeRefusal::Rejected(SessionRejected));
        let blocked = refuse_handshake(&HandshakeRefusal::Blocked { record });
        for status in [rejected.status, blocked.status, Reply::preflight().status, 200] {
            assert!(reason_phrase(status).is_some(), "{status} has no reason phrase");
        }
    }

    /// The `scan_busy` refusal's exact body: a transport refusal (no `resp`,
    /// no `code`) at 503, naming the op it refused beside the detail — the
    /// bytes wire.md shows.
    #[test]
    fn scan_busy_names_the_op_in_a_transport_refusal() {
        let r = refuse_scan_busy(OpKind::CountFtt);
        assert_eq!(r.status, 503);
        assert_eq!(
            String::from_utf8(r.bytes().to_vec()).expect("json"),
            r#"{"detail":"all class-scan permits are in use; retry shortly","error":"scan_busy","op":"count_ftt"}"#
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

    /// The preflight advertises exactly the header
    /// [`read_request`](crate::server::http::read_request) reads.
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
}
