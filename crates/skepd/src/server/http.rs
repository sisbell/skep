//! The HTTP/1.1 reader and writer, their timeouts, and the event framing.

use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::time::{Duration, Instant};

use serde_json::Value;
use skep_kernel::Seq;
use skep_util::json::obj;

use super::blob_routes;
use super::body_cap;
use super::reply::{
    reason_phrase, refuse, Fetch, Reply, TransportError, FETCH_CONTENT_TYPE, SESSION_HEADER,
};
use super::request::{at_most_once, BodySource, HttpRequest};
use skep_core::auth::session::Peer;
use skep_core::codec::to_bytes;
use crate::limits::BLOB_IDLE_BOUND;

/// The socket read deadline for one request's head and body.
///
/// A stalled local client releases its worker instead of pinning it. A
/// streamed blob body reads under the idle bound instead (`BLOB_IDLE_BOUND`,
/// set by [`read_request`]).
pub(super) const REQUEST_READ_TIMEOUT: Duration = Duration::from_secs(30);

/// The socket write deadline, per write call, replies and events alike.
///
/// A subscriber that stops draining errors out instead of blocking a thread
/// forever — which is what keeps shutdown bounded even against a stalled
/// peer.
pub(super) const WRITE_TIMEOUT: Duration = Duration::from_secs(30);

/// The deadline for one transfer: the request in, or the answer out.
///
/// It is checked *between* socket calls, so a call already in flight when it
/// passes runs to its own socket timeout: each direction is bounded at this
/// plus [`REQUEST_READ_TIMEOUT`] or [`WRITE_TIMEOUT`], and a connection —
/// which performs at most one of each — at twice that, plus whatever its
/// handler is doing. Two answers out run outside it: a blob fetch's, under
/// the blob route's own transfer and idle bounds, and an event stream's,
/// under the write deadline per event alone.
///
/// [`REQUEST_READ_TIMEOUT`] and [`WRITE_TIMEOUT`] bound *silence* — each is
/// a per-call socket deadline, renewed by any byte — so only this bounds
/// *slowness*. Without it a peer sending (or draining) one byte per interval
/// renews the socket deadline indefinitely and holds its worker for as long
/// as it cares to:
/// [`MAX_REQUEST_BODY`](skep_core::limits::MAX_REQUEST_BODY) at one byte per
/// interval is years, and `workers` such peers occupy the whole pool,
/// leaving the daemon answering nothing with every structure inside it
/// healthy. It is also what makes
/// [`Skepd::shutdown`](super::Skepd::shutdown)'s bound true, since that stop
/// joins a worker that may be mid-request.
///
/// The two halves are bounded *separately* and not as one window, so that a
/// request refused for exhausting its own deadline still has a deadline in
/// which to be told so: a single shared window would make the refusal
/// undeliverable by construction, which is the never-silent contract lost
/// at the one place it is hardest to notice.
///
/// Loopback delivers the largest admissible body in milliseconds, so 30 s
/// is four orders of magnitude of headroom over any honest client.
pub(super) const TRANSFER_DEADLINE: Duration = Duration::from_secs(30);

/// The headers wire.md promises on every response.
///
/// They are the cross-origin posture, the exposure that lets a page read
/// the death signal, and the one-request-per-connection framing. Emitted by
/// `response_head`, which opens every final response this daemon writes —
/// the reply path's and the event stream's alike, a stream not being a
/// request/response reply — so a change to any of them reaches both by
/// construction.
///
/// Exported because [`Reply`] names them as a caller's obligation. They are
/// name/value pairs — the same shape [`Reply::headers`] carries — rather
/// than this daemon's own CRLF bytes, so a caller serving replies over a
/// transport of its own supplies them however that transport spells a
/// header instead of parsing a framing only this crate's writer can use.
///
/// A slice and not an array on purpose: the length would otherwise be part
/// of the type this crate promises, and this set is not a fixed triple — a
/// header can join it, and a caller who had written the count into a
/// signature of their own would break on a change that adds one.
pub const UNIVERSAL_HEADERS: &[(&str, &str)] = &[
    ("Access-Control-Allow-Origin", "*"),
    // AUTH-6.12: `Skepd-Session` is not CORS-safelisted, so without this a
    // client on a configured non-loopback origin could not read the death
    // signal. Exposing a public header narrows nothing; the fence stays
    // daemon-side.
    ("Access-Control-Expose-Headers", "Skepd-Session"),
    ("Connection", "close"),
];

/// The request head's size cap.
///
/// Tokens and headers are small; frames ride in the body, capped separately
/// by the request's [`body_cap`].
///
/// [`read_request`] scans for the head terminator incrementally, so the work
/// this bounds is linear in the head — the property a raise must preserve,
/// since a rescan from zero after every read would make it quadratic in this
/// number.
const MAX_REQUEST_HEAD: usize = 64 * 1024;

/// A request refused at the HTTP layer: the transport-error reply it is owed.
///
/// Everything outside the subset this daemon speaks is one bucket; the body
/// cap gets its own honest disposition (`413 payload_too_large`), not a
/// generic parse error.
#[derive(Debug)]
pub(super) enum RequestRefusal {
    /// Not the HTTP subset this daemon speaks → `400 malformed_http`.
    Malformed(String),
    /// The declared `Content-Length` exceeds the request's [`body_cap`].
    ///
    /// It answers `413 payload_too_large`, raised before any body byte is
    /// read, and carries the cap it exceeded so the refusal names the number
    /// that actually bound it rather than the largest one the daemon has.
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

/// Maps a request refused at the HTTP layer onto the wire's transport errors.
///
/// It is the one place a [`RequestRefusal`] becomes HTTP, as
/// [`refuse_unavailable`](super::reply::refuse_unavailable) is for the
/// history surface's `Unavailable`. The body cap's diagnostic names the cap
/// that actually bound this route, so the number in the refusal is the one
/// the request met rather than the largest the daemon has.
pub(super) fn refuse_request(refusal: RequestRefusal) -> Reply {
    match refusal {
        RequestRefusal::Malformed(detail) => refuse(TransportError::MalformedHttp, Some(&detail)),
        RequestRefusal::BodyTooLarge { declared, cap } => refuse(
            TransportError::PayloadTooLarge,
            Some(&format!("Content-Length {declared} exceeds the {cap}-byte body cap")),
        ),
    }
}

/// Reads one request off the socket.
///
/// It answers the request, and — for the blob upload's two body-carrying
/// methods — the body left on the socket beside it; `Ok(None)` is a close,
/// or a failed read, before any byte. The subset: one request per
/// connection, HTTP/1.0 or 1.1, bodies by `Content-Length` (absent = empty,
/// capped at the request's [`body_cap`]), `Expect: 100-continue` honored,
/// `Transfer-Encoding` refused.
///
/// **The streaming arm** (`blob_routes`). For the two methods of the blob
/// upload's path family that carry bytes, the body is *not* read here — a
/// body of the request's cap would otherwise sit whole in memory, which is
/// what makes that cap unsafe without this arm. The head is read as for
/// every request, the declared length held to the request's cap, and the
/// body handed back *beside* the request as a [`BodySource`] over a clone
/// of this socket — the bytes that arrived with the head, the length, and
/// the `100 Continue` the client may be waiting for, which the route sends,
/// at the creation with the upload's identifier, once it has decided to
/// invite the body. The socket's read deadline is set to the idle bound for
/// the body's phase, renewed by any byte; the transfer bound is the
/// source's own. A method of the family that carries no bytes reads its
/// body here under the small cap, as every frameless route does.
///
/// Each header this daemon *reads* — `Content-Length`, `Expect`,
/// `Skepd-Session` and `Origin` — may appear at most once; a repeat is
/// `malformed_http`, the same never-silent treatment a duplicate query
/// parameter and an unknown frame field already get, and the one
/// [`HttpRequest`]'s precondition asks of any other caller of the router.
/// Headers this daemon does not read pass unread however often they appear.
///
/// # Errors
///
/// A [`RequestRefusal`], whose reply the caller answers before it closes:
/// [`RequestRefusal::BodyTooLarge`] where the declared length exceeds the
/// request's [`body_cap`], before any body byte; every other refusal
/// [`RequestRefusal::Malformed`] — a request outside the subset, a repeated
/// header this daemon reads, a connection that closes or a read that fails
/// inside the request, or a socket the streaming arm cannot clone or time.
/// Both loops below are bounded in bytes *and* in time: `deadline` bounds
/// this whole transfer, so a peer that paces its bytes to renew the
/// socket's per-call deadline is refused rather than served for as long as
/// it likes (see [`TRANSFER_DEADLINE`]). The refusal rides `malformed_http`,
/// which is where a timed-out read already lands.
pub(super) fn read_request(
    stream: &mut TcpStream,
    peer: Peer,
    deadline: Instant,
) -> Result<Option<(HttpRequest, Option<BodySource<'static>>)>, RequestRefusal> {
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
    let target =
        parts.next().ok_or_else(|| String::from("request line lacks a target"))?.to_string();
    let version = parts.next().ok_or_else(|| String::from("request line lacks an HTTP version"))?;
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
    // HTTP requires. Each of the four is read through `at_most_once`, so a
    // repeat is a named refusal rather than a silent last-wins — two
    // conflicting `Content-Length`s otherwise pick between a stalled read
    // and a truncated frame by which line came last, and answer the same
    // malformed head with two different diagnoses.
    let mut content_length: Option<usize> = None;
    let mut session_token: Option<String> = None;
    let mut origin: Option<String> = None;
    let mut expects_continue: Option<bool> = None;
    for line in lines {
        if line.is_empty() {
            continue;
        }
        let (name, value) =
            line.split_once(':').ok_or_else(|| format!("malformed header line '{line}'"))?;
        let (name, value) = (name.trim(), value.trim());
        if name.eq_ignore_ascii_case("Content-Length") {
            at_most_once(&content_length, "header", name)?;
            // RFC 7230 §3.3.2 is `1*DIGIT`, and `usize::from_str` is wider:
            // it admits a leading `+`. The condition is the one
            // [`Origin::parse`] already spends on a port, at the field where
            // two recipients of the same bytes must agree. The divergence
            // costs nothing here — this daemon answers one request per
            // connection and closes, reading exactly the declared length —
            // but a fronting proxy that follows §3.3.3 and refuses `+13`
            // re-reads this body as the head of a new request on *its*
            // client connection, and a keep-alive refactor would build the
            // same desync inside this parser. Leading zeros stay admitted:
            // `0013` is `1*DIGIT`. The `parse` below keeps the range check,
            // so an over-`usize` length is still refused, in one wording.
            if value.is_empty() || !value.bytes().all(|b| b.is_ascii_digit()) {
                return Err(format!("bad Content-Length '{value}'").into());
            }
            content_length =
                Some(value.parse().map_err(|_| format!("bad Content-Length '{value}'"))?);
        } else if name.eq_ignore_ascii_case(SESSION_HEADER) {
            at_most_once(&session_token, "header", name)?;
            session_token = Some(value.to_string());
        } else if name.eq_ignore_ascii_case("Origin") {
            at_most_once(&origin, "header", name)?;
            origin = Some(value.to_string());
        } else if name.eq_ignore_ascii_case("Expect") {
            at_most_once(&expects_continue, "header", name)?;
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
    // (and allocates) a single byte of it — under the request's own cap
    // ([`body_cap`], which states it per method and path).
    let streams = blob_routes::streams_body(&method, &path);
    let cap = body_cap(&method, &path);
    if declared > cap {
        return Err(RequestRefusal::BodyTooLarge { declared, cap });
    }
    if streams {
        // The streaming arm: the body stays on the socket for the route,
        // handed back beside the request.
        body.truncate(declared);
        let clone = stream.try_clone().map_err(|e| format!("socket: {e}"))?;
        clone.set_read_timeout(Some(BLOB_IDLE_BOUND)).map_err(|e| format!("socket: {e}"))?;
        let source = BodySource::parked(clone, body, declared, expects_continue);
        let req = HttpRequest { method, path, query, session_token, origin, peer, body: Vec::new() };
        return Ok(Some((req, Some(source))));
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
    Ok(Some((HttpRequest { method, path, query, session_token, origin, peer, body }, None)))
}

fn find_head_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n")
}

/// Writes all of `bytes`, as `write_all` does, under a deadline.
///
/// The socket's write timeout bounds a peer that stops draining; only the
/// deadline bounds one that drains slowly, since each accepted byte renews
/// that timeout. A reply is written to a worker's socket, so a slow reader
/// here costs one of `workers` threads — which is why the reply path takes
/// the deadline and `serve_events` does not: a subscriber runs on its own
/// thread against a slot `Subscribers` already budgets. That exemption is
/// what makes [`Skepd::shutdown`](super::Skepd::shutdown)'s bound include
/// one write timeout — the stop joins a subscriber that may be blocked
/// writing to a peer that stopped draining.
///
/// # Errors
///
/// `TimedOut` once `deadline` passes with bytes unwritten, `WriteZero`
/// where the socket takes none, or the socket's own write error.
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

/// Appends one `Name: value` line in this daemon's framing.
///
/// It is the one place a header becomes bytes, shared by the reply path and
/// the event stream — save the content pair, `Content-Type` and
/// `Content-Length`, which [`write_reply`] and [`write_fetch_head`] write
/// beside it, and the interim `100 Continue`'s headers, which
/// `BodySource::begin` writes.
pub(super) fn push_header(head: &mut Vec<u8>, name: &str, value: &str) {
    head.extend_from_slice(format!("{name}: {value}\r\n").as_bytes());
}

/// Returns the opening of every final response this daemon writes.
///
/// It is the status line, then [`UNIVERSAL_HEADERS`] — which wire.md
/// §Transport and §Cross-origin access promise on every response. The one
/// place a final response *begins*, as [`push_header`] is the one place a
/// final response's header but the content pair becomes bytes, and for the
/// same reason: a stream is not a [`Reply`], so `listen::serve_events`
/// composes its own head — but its opening *is* the reply path's at status
/// 200, and spelled by hand it is a second entry in [`reason_phrase`]'s
/// table with nothing keeping the two in step. The caller appends its own
/// headers, the blank line, and whatever body it has. The interim
/// `100 Continue` is written without it.
pub(super) fn response_head(status: u16) -> Vec<u8> {
    let mut head = Vec::with_capacity(256);
    // A status no phrase names — one this daemon does not answer — still
    // opens a well-formed status line.
    let phrase = reason_phrase(status).unwrap_or("Status");
    head.extend_from_slice(format!("HTTP/1.1 {status} {phrase}\r\n").as_bytes());
    for (name, value) in UNIVERSAL_HEADERS {
        push_header(&mut head, name, value);
    }
    head
}

/// Writes one complete reply; the connection closes behind it.
///
/// Every reply carries [`UNIVERSAL_HEADERS`] — the cross-origin posture,
/// the death signal's exposure, and the one-request-per-connection framing —
/// supplied by [`response_head`], which is also what opens the event stream,
/// so no final response this daemon writes can miss them. A bodiless reply
/// carries no content headers (RFC 7230's 204).
///
/// `head_only` is a `HEAD` request's answer (RFC 9110 §9.3.2): the head the
/// `GET` would carry — the status, every header, the content pair the body
/// would be described by — and no byte of the body. HTTP's own rule and so
/// the transport's: the router answers a `HEAD` of the fetch's path with
/// the `GET`'s reply, and this is where the body stays unwritten. A caller
/// serving replies over a transport of its own owes the same to a `HEAD` it
/// routes.
///
/// # Errors
///
/// [`write_bounded`]'s: the socket's write error, `WriteZero` where the
/// socket takes none, or `TimedOut` once `deadline` passes.
pub(super) fn write_reply(
    stream: &mut TcpStream,
    reply: &Reply,
    deadline: Instant,
    head_only: bool,
) -> io::Result<()> {
    let mut head = response_head(reply.status);
    for (name, value) in &reply.headers {
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
        // The body is written from the reply rather than copied into this
        // buffer first. The largest answer this daemon serves is a whole
        // world dump, and assembling one buffer would hold two copies of
        // it at once — per in-flight request, on a route that needs no
        // session. `set_nodelay` is on, so the cost is the second write
        // call and nothing else.
        write_bounded(stream, &head, deadline)?;
        if head_only {
            return Ok(());
        }
        write_bounded(stream, &body.bytes, deadline)
    } else {
        head.extend_from_slice(b"\r\n");
        write_bounded(stream, &head, deadline)
    }
}

/// Writes the fetch's head (wire.md §Media, the fetch).
///
/// It is the 200 through [`response_head`] — so [`UNIVERSAL_HEADERS`] open
/// it as they open every final response — the route's own headers, then the
/// content pair from the file: [`FETCH_CONTENT_TYPE`] and `Content-Length`,
/// the file's length, on the `GET` and the `HEAD` alike. Written whole
/// under `deadline` before any byte of the body.
///
/// # Errors
///
/// [`write_bounded`]'s: the socket's write error, `WriteZero` where the
/// socket takes none, or `TimedOut` once `deadline` passes.
pub(super) fn write_fetch_head(
    stream: &mut TcpStream,
    fetch: &Fetch<'_>,
    deadline: Instant,
) -> io::Result<()> {
    let mut head = response_head(fetch.status());
    for (name, value) in fetch.headers() {
        push_header(&mut head, name, value);
    }
    head.extend_from_slice(
        format!("Content-Type: {FETCH_CONTENT_TYPE}\r\nContent-Length: {}\r\n\r\n", fetch.size())
            .as_bytes(),
    );
    write_bounded(stream, &head, deadline)
}

/// Writes one chunk of a fetch's body, under the transfer `deadline`.
///
/// The socket's own write timeout — the idle bound, set by the stream —
/// bounds a peer that stops draining.
///
/// # Errors
///
/// [`write_bounded`]'s: the socket's write error, `WriteZero` where the
/// socket takes none, or `TimedOut` once `deadline` passes.
pub(super) fn write_chunk(
    stream: &mut TcpStream,
    chunk: &[u8],
    deadline: Instant,
) -> io::Result<()> {
    write_bounded(stream, chunk, deadline)
}

/// Arms the reset close (M-I2 (g)): `SO_LINGER` at zero on `stream`.
///
/// The close that follows sends a reset and not a clean finish — a stream
/// ended by the re-check, the idle bound or the transfer bound must not
/// read to its client as the whole file, and a `Content-Length` already
/// written leaves no other way to say so. The peer meets `ECONNRESET`, or
/// an end short of the declared length. Best-effort: a socket that refuses
/// the option is closed as it stands, which is still short of the length.
pub(super) fn reset_close(stream: &TcpStream) {
    let _ = rustix::net::sockopt::set_socket_linger(stream, Some(Duration::ZERO));
}

/// Writes one commit event in the wire v4 event framing.
///
/// The framing is `event: commit` / `data: {"log_position":N}` / blank,
/// byte-for-byte what wire.md documents (compact JSON, the position alone).
///
/// The payload is built through the codec's key-sorting device like every
/// other JSON object this crate emits, so the day the stream carries a
/// second field its canonical form is the one already in force everywhere
/// else rather than whatever a format string happened to spell.
///
/// # Errors
///
/// The socket's write error.
pub(super) fn write_commit_event(stream: &mut TcpStream, at: Seq) -> std::io::Result<()> {
    let mut event = b"event: commit\ndata: ".to_vec();
    event.extend_from_slice(&to_bytes(&obj(vec![("log_position", Value::Number(at.0.into()))])));
    event.extend_from_slice(b"\n\n");
    stream.write_all(&event)
}
