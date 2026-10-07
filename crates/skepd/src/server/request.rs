//! The request a handler reads (`HttpRequest`), the streaming body the
//! daemon's own transport may hand the router beside it (`BodySource`), and
//! the two rules every read of its headers and query applies: a query is a
//! parameter list, and a field appears at most once.

use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::time::Instant;

use crate::auth::session::Peer;
use crate::limits::{BLOB_CHUNK, BLOB_TRANSFER_BOUND};

/// One request, as [`Daemon::route`](super::Daemon::route) receives it and as the socket reader
/// builds it — one value rather than a list of arguments, so the two
/// `Option<String>`s cannot be handed over in the wrong order.
///
/// PRECONDITION on every field, established by [`super::http::read_request`] and owed by
/// any other caller of [`Daemon::route`](super::Daemon::route): `method` is the uppercase token;
/// `path` is the request target with its query AND its `?` removed; `query`
/// is what followed that `?`, without it; `session_token` and `origin` are
/// the `Skepd-Session` and `Origin` header values VERBATIM, or `None` when
/// the header is absent — never normalized and never defaulted; the request
/// carries neither header — nor `Content-Length` or `Expect` — MORE THAN
/// ONCE, since the socket reader refuses such a request `400 malformed_http`
/// before it is routed, and a caller over its own transport refuses it too,
/// never choosing between the values; `peer` is the transport's own answer
/// about the remote address of THIS connection; `body` is exactly the
/// declared `Content-Length` bytes, and at most
/// [`body_cap`](super::body_cap) of its `method` and `path` of them — the
/// blob upload's creation and resume included, whose body the daemon's own
/// transport leaves on the socket and routes through a door of its own, and
/// which a caller over its own transport hands in here, the route reading it
/// through the same source type.
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
/// the network. A caller that CHOOSES between two `Origin` values, or two
/// tokens, answers one request two ways — the socket path refuses it — and
/// picks for the sender which origin the bare-bind fence reads, or which
/// binding acts.
///
/// The body cap is the OUTERMOST bound on what a frame allocates, and the
/// one clause a caller cannot discharge by inspection: every JSON-carrying
/// route builds the whole `serde_json` tree before any codec cap runs, so a
/// body admitted past it buys roughly twenty times its size in transient
/// heap — for a frame the codec is then about to refuse. [`super::http::read_request`]
/// enforces it on the declared `Content-Length`, before a byte is read.
///
/// This is the value a caller BUILDS, one per probe rather than by mutating
/// a template: every field is a fact about ONE request. Deliberately no
/// `Default` — an empty method and path are not a request — no `PartialEq`,
/// nothing here comparing two requests, and no `Clone`, since nothing in the
/// tree clones a request.
pub struct HttpRequest {
    /// The method token, uppercase ASCII (`GET`, `POST`, `OPTIONS`).
    pub method: String,
    /// The request target with any query stripped — `/op`, `/changes`.
    pub path: String,
    /// The raw query string, if the target carried one, without the `?` that
    /// introduced it. Read by the routes that take parameters — `/challenge`
    /// (`principal=`, required), `/chain` (`at=`, required), `/changes`
    /// (`since=`, required, beside its optional narrowings), the blob fetch
    /// `/blob` (`i=`, required), the upload's creation (`length=`, required)
    /// and resume (`offset=`, required) and, in `observe` builds, `/dump`
    /// (`at=`, optional) — each refusing an unknown or repeated parameter by
    /// name; every other route ignores it.
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
    /// The body, exactly `Content-Length` bytes (empty when absent) — empty,
    /// from the daemon's own transport, for the blob upload's creation and
    /// resume, whose body stays on the socket (`server/http.rs`, THE
    /// STREAMING ARM).
    pub body: Vec<u8>,
}

/// The body's LENGTH and the token's PRESENCE: the body runs to the
/// request's [`body_cap`](super::body_cap), and the token names a live
/// session, which is not a thing to leave in a log line.
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

// ── the streaming body ───────────────────────────────────────────────────

/// Where a body's bytes come from: the connection's socket (its clone,
/// owned here), or the request's own bytes.
enum Conn<'a> {
    Socket(TcpStream),
    Bytes(&'a [u8]),
}

/// THE STREAMING ARM's reader: the body of one blob request, handed to the
/// route one chunk at a time through the ONE buffer this value holds — the
/// arm's whole memory per in-flight upload, [`BLOB_CHUNK`] and the
/// counters beside it (asserted by `the_arm_holds_one_chunk_and_no_body`).
/// Over a socket it carries the early bytes the head's read took with it,
/// the declared length, the `Expect: 100-continue` the transport deferred to
/// the route, and the transfer bound; the socket's own read deadline is the
/// idle bound, set by the transport.
pub(super) struct BodySource<'a> {
    conn: Conn<'a>,
    early: Vec<u8>,
    early_at: usize,
    declared: usize,
    consumed: usize,
    expects_continue: bool,
    continued: bool,
    deadline: Instant,
    buf: Box<[u8]>,
    /// An end met while a chunk was filling — the connection closed, a
    /// deadline — answered AFTER the bytes filled so far, so a dropped
    /// connection's last bytes are received before its drop is.
    pending_end: Option<io::Error>,
}

impl<'a> BodySource<'a> {
    /// A source over the connection's socket, parked by the transport: the
    /// bytes that arrived with the head, the declared length, and whether
    /// the client is holding the body for a `100 Continue`.
    pub(super) fn parked(
        socket: TcpStream,
        early: Vec<u8>,
        declared: usize,
        expects_continue: bool,
    ) -> BodySource<'static> {
        BodySource {
            conn: Conn::Socket(socket),
            early,
            early_at: 0,
            declared,
            consumed: 0,
            expects_continue,
            continued: false,
            deadline: Instant::now() + BLOB_TRANSFER_BOUND,
            buf: vec![0u8; BLOB_CHUNK].into_boxed_slice(),
            pending_end: None,
        }
    }

    /// A source over a request's own bytes — the socket-free router's.
    pub(super) fn bytes(body: &'a [u8]) -> BodySource<'a> {
        BodySource {
            conn: Conn::Bytes(body),
            early: Vec::new(),
            early_at: 0,
            declared: body.len(),
            consumed: 0,
            expects_continue: false,
            continued: false,
            deadline: Instant::now() + BLOB_TRANSFER_BOUND,
            buf: vec![0u8; BLOB_CHUNK].into_boxed_slice(),
            pending_end: None,
        }
    }

    /// The declared length of the body.
    pub(super) fn declared(&self) -> usize {
        self.declared
    }

    /// Invite the body: where the client asked `Expect: 100-continue`, the
    /// interim `100 Continue` carrying `interim`'s headers — the creation's
    /// identifier, so it reaches the uploader before the first body byte
    /// (clause (1)) — written once; nothing otherwise.
    pub(super) fn begin(&mut self, interim: &[(&str, &str)]) -> io::Result<()> {
        if !self.expects_continue || self.continued {
            return Ok(());
        }
        self.continued = true;
        if let Conn::Socket(s) = &mut self.conn {
            let mut head = b"HTTP/1.1 100 Continue\r\n".to_vec();
            for (name, value) in interim {
                head.extend_from_slice(format!("{name}: {value}\r\n").as_bytes());
            }
            head.extend_from_slice(b"\r\n");
            s.write_all(&head)?;
        }
        Ok(())
    }

    /// The next chunk of the body — [`BLOB_CHUNK`] bytes, FILLED to that
    /// grain from the early bytes and the socket however the socket paces
    /// them, or the body's last bytes; `None` once the declared length is
    /// consumed. The grain is what the gate's refusal offset is read at: a
    /// refusal as the body is written fires at a chunk's boundary, never at
    /// whatever a socket read happened to deliver. A connection closed
    /// inside the body, a read past the idle bound, or a transfer past its
    /// bound is an error — answered after the bytes it found filled, so a
    /// dropped connection's last bytes are received before its drop is — and
    /// the route keeps the upload at its durable point.
    pub(super) fn next_chunk(&mut self) -> io::Result<Option<&[u8]>> {
        if let Some(end) = self.pending_end.take() {
            return Err(end);
        }
        let left = self.declared - self.consumed;
        if left == 0 {
            return Ok(None);
        }
        let want = left.min(self.buf.len());
        let mut filled = 0usize;
        while filled < want {
            let n = if self.early_at < self.early.len() {
                let take = (self.early.len() - self.early_at).min(want - filled);
                self.buf[filled..filled + take]
                    .copy_from_slice(&self.early[self.early_at..self.early_at + take]);
                self.early_at += take;
                take
            } else {
                let read = match &mut self.conn {
                    Conn::Bytes(b) => {
                        let at = self.consumed + filled;
                        let take = (want - filled).min(b.len().saturating_sub(at));
                        if take == 0 {
                            Err(io::Error::new(
                                io::ErrorKind::UnexpectedEof,
                                "the request's body is shorter than its declared length",
                            ))
                        } else {
                            self.buf[filled..filled + take].copy_from_slice(&b[at..at + take]);
                            Ok(take)
                        }
                    }
                    Conn::Socket(s) => {
                        if Instant::now() >= self.deadline {
                            Err(io::Error::new(
                                io::ErrorKind::TimedOut,
                                "request body not delivered within the blob transfer bound",
                            ))
                        } else {
                            match s.read(&mut self.buf[filled..want]) {
                                Ok(0) => Err(io::Error::new(
                                    io::ErrorKind::UnexpectedEof,
                                    "connection closed inside the request body",
                                )),
                                other => other,
                            }
                        }
                    }
                };
                match read {
                    Ok(n) => n,
                    Err(e) if filled > 0 => {
                        self.pending_end = Some(e);
                        break;
                    }
                    Err(e) => return Err(e),
                }
            };
            filled += n;
        }
        self.consumed += filled;
        Ok(Some(&self.buf[..filled]))
    }
}

/// A query string as its parameter list — `k=v` pairs split on `&`, shape
/// checked and nothing else. Every query this daemon reads walks this — the
/// one-parameter queries through [`sole_param`] — so one discipline covers
/// them all and each parser adds only its own vocabulary: an unknown or
/// repeated parameter is a named refusal, which is the wire's never-silent
/// posture applied to queries.
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

/// A query that carries ONE parameter, `name`: its value, or `None` where the
/// query is absent or empty — the parameter list [`query_pairs`] reads, a
/// repeat refused through [`at_most_once`] and any other name refused as
/// unknown, naming the one this route reads. Each caller adds its value's
/// grammar and, where the parameter is required, its own refusal of `None`.
pub(super) fn sole_param<'q>(
    query: Option<&'q str>,
    name: &str,
) -> Result<Option<&'q str>, String> {
    let Some(query) = query.filter(|q| !q.is_empty()) else { return Ok(None) };
    let mut value = None;
    for (k, v) in query_pairs(query)? {
        if k != name {
            return Err(format!("unknown parameter '{k}'; the one parameter here is {name}"));
        }
        at_most_once(&value, "parameter", name)?;
        value = Some(v);
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A request's `Debug` carries the token's PRESENCE and the body's
    /// LENGTH, never either's bytes: the token names a live session, and a
    /// request's `{:?}` is what a panic or a trace line would carry.
    #[test]
    fn a_requests_debug_carries_no_token_and_no_body() {
        let token = "0123456789abcdef0123456789abcdef";
        let body = br#"{"op":"fork","id":"the-body"}"#.to_vec();
        let req = HttpRequest {
            method: "POST".to_string(),
            path: "/op".to_string(),
            query: None,
            session_token: Some(token.to_string()),
            origin: None,
            peer: Peer::Loopback,
            body: body.clone(),
        };
        let printed = format!("{req:?}");
        assert!(!printed.contains(token), "the token: {printed}");
        // As text, and as the decimal list a derived `Debug` prints a
        // `Vec<u8>` in.
        assert!(
            !printed.contains("the-body") && !printed.contains(&format!("{body:?}")),
            "the body: {printed}"
        );
        assert!(
            printed.contains("<token>") && printed.contains("body_len"),
            "presence and length: {printed}"
        );
    }

    /// THE RSS BOUND BY CONSTRUCTION (the investigation §3.4, "memory per
    /// in-flight PUT under the streaming arm — O(chunk), never O(body)"):
    /// the arm's one buffer is [`BLOB_CHUNK`] long, the source's own size
    /// is a few words beside it — no `Vec` that grows with the body — and a
    /// body of many chunks comes through it one chunk at a time, every
    /// chunk at most the buffer's length. The number: 64 KiB per in-flight
    /// upload, against a 64 MiB cap.
    #[test]
    fn the_arm_holds_one_chunk_and_no_body() {
        assert_eq!(BLOB_CHUNK, 64 * 1024);
        assert!(std::mem::size_of::<BodySource<'_>>() <= 160, "{}", std::mem::size_of::<BodySource<'_>>());
        let body = vec![7u8; 10 * BLOB_CHUNK + 13];
        let mut source = BodySource::bytes(&body);
        assert_eq!(source.buf.len(), BLOB_CHUNK);
        let mut chunks = 0;
        let mut total = 0;
        while let Some(chunk) = source.next_chunk().expect("bytes") {
            assert!(chunk.len() <= BLOB_CHUNK);
            assert!(chunk.iter().all(|&b| b == 7));
            total += chunk.len();
            chunks += 1;
        }
        assert_eq!(total, body.len());
        assert_eq!(chunks, 11);
        assert_eq!(source.buf.len(), BLOB_CHUNK, "the buffer never grew");
    }

    /// A one-parameter query: its value, or `None` for an absent or empty
    /// query; a repeat, any other name and a pair with no `=` are named
    /// refusals.
    #[test]
    fn a_one_parameter_query_has_one_value_or_a_named_refusal() {
        assert_eq!(sole_param(None, "at"), Ok(None));
        assert_eq!(sole_param(Some(""), "at"), Ok(None));
        assert_eq!(sole_param(Some("at=7"), "at"), Ok(Some("7")));
        assert_eq!(sole_param(Some("at="), "at"), Ok(Some("")), "an empty value is the caller's");
        let refused = |query: &str| sole_param(Some(query), "at").unwrap_err();
        assert!(refused("at=1&at=2").contains("duplicate parameter 'at'"));
        assert!(refused("since=1").contains("unknown parameter 'since'"));
        assert!(refused("at=1&since=1").contains("unknown parameter 'since'"));
        assert!(refused("at").contains("malformed parameter"));
    }
}
