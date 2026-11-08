//! The one outbound dialer (`client.md` §7).
//!
//! It is the `Dialer` seam and its plain-HTTP arm, which the `skep` command
//! and the frontend's shell use and which `client.md` names for the
//! daemon's node-pull, so no second dialer is kept in step with wire.md
//! §Transport.
//!
//! One request, one connection: every response carries `Connection: close`,
//! so a client opens a fresh `TcpStream` per call (wire.md §Transport); the
//! request head is written out — `Host: <authority>` (brackets kept for an
//! IPv6 literal), `Connection: close`, `Content-Type: application/json`
//! where a body follows, `Content-Length` as the body's length in ASCII
//! decimal — the body follows, the answer is read to close and its
//! `Content-Length` checked against what arrived: a short body is a broken
//! connection, never an answer. So is a head cut short: in both forms of the
//! dial, an answer that closes before its head's blank line is
//! [`DialError::Io`] where nothing arrived or what arrived opens as a status
//! line does (`HTTP/1.`, or a prefix of it) — a board that hung up — and
//! [`DialError::Response`], no HTTP response, where it opens any other way.
//! The response's headers are returned whole so the board can read
//! `Skepd-Session: closed`. No redirect is followed — the daemon issues
//! none, and following one would dial an origin the caller did not sign
//! (AUTH-4.8). No proxy environment is honored — a proxy is a peer the
//! signature knows nothing about (§9 item 24). A `Dialer` never rewrites the
//! origin string it is handed (§1.4): a transport that changed the origin
//! under its caller would sign one string and dial another.
//!
//! **Timeouts.** Connect 5 s, read/write 10 s a call for the frames
//! (skep-mcp's constants — a skepd op is milliseconds even under fsync), and
//! a frame's whole exchange held to a deadline besides — the per-call bound
//! plus the time its request body and the largest answer take at the
//! streamed form's rate — re-armed on the socket before every read and
//! write, so a board that trickles a byte inside each per-call bound cannot
//! hold an exchange past it; the streamed form's read timeout scales with
//! the declared size and its body, read by its caller, keeps that per-call
//! bound alone.
//!
//! **A connection never made.** The connection stands before a byte of the
//! request is written: the TCP connect, and for `https://` the TLS
//! handshake over it, run to their end first. So a connect or a handshake
//! that fails — refused, unreachable, broken off or past its bound — is
//! [`DialError::Connect`], or [`DialError::Tls`] where the TLS layer
//! refused the peer: nothing left, and a write its caller holds is held
//! `sent: false` (`client.md` §3c.2, §3c.4). [`DialError::Timeout`] is a
//! read or a write past its bound once the connection stands.
//!
//! **Answered apart from unanswered** (`client.md` §7). A request the board
//! never answered ([`DialError::unanswered`]) is reported apart from any
//! answer it gave ([`DialError::answered`]), and never as one: the name not
//! resolved, the connection refused or not made within its bound, the secure
//! handshake not completed, no answer within the bound once connected, or the
//! connection closed before its answer was whole — a head cut short and a
//! body short of its `Content-Length` among them. An answer the board gave is
//! one whatever it says, bytes that are no HTTP response and an answer past
//! the cap among them. A request refused before any connection opened is
//! neither: it reached no board.
//!
//! The request target and the headers are written as given, so each is
//! checked first for what would end the request line or a header early —
//! refused as [`DialError::Request`] before any connection opens.
//!
//! `https://` is the `tls` feature's arm — rustls with the platform verifier
//! (§9 item 12) — off in the library and on in the `skep` binary; without
//! the feature an `https` origin is [`DialError::NotHeld`], refused before
//! any connection opens and never dialed in the clear.

use std::fmt;
use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::origin::Origin;

#[cfg(test)]
mod tests;

/// The bound on each connection attempt.
///
/// A dead local daemon answers `connection refused` at once; this bounds
/// the pathological cases — an unroutable address, a filtered port. An
/// attempt past it is a connection never made, [`DialError::Connect`], as a
/// refused one is.
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// The per-call read/write bound for a frame.
///
/// Ten seconds is headroom, not an expected wait (the value of skep-mcp's
/// `IO_TIMEOUT`).
pub const IO_TIMEOUT: Duration = Duration::from_secs(10);

/// The most bytes [`PlainHttp`]'s exchange reads of one answer.
///
/// It is the frame routes' request cap, 8 MiB, with room for the head
/// beside it (wire.md §Transport). An answer past it is
/// [`DialError::TooLarge`], read no further: a board never sizes this
/// client's memory past it.
pub const MAX_ANSWER_BYTES: usize = 8 * 1024 * 1024 + 64 * 1024;

/// The streamed form's read bound per declared byte, on top of [`IO_TIMEOUT`].
///
/// It is one second per 256 KiB declared (the scale's constant is the
/// build's).
const STREAM_BYTES_PER_SECOND: u64 = 256 * 1024;

/// A frame exchange's deadline before its request body's allowance.
///
/// It runs from the connection's open: [`IO_TIMEOUT`], and the time an
/// answer at [`MAX_ANSWER_BYTES`] takes at [`STREAM_BYTES_PER_SECOND`] —
/// 42.25 s, the rate the streamed form already demands of a board. The body
/// adds its own bytes at the same rate.
const EXCHANGE_BOUND: Duration =
    Duration::from_millis(IO_TIMEOUT.as_millis() as u64 + MAX_ANSWER_BYTES as u64 * 1000 / STREAM_BYTES_PER_SECOND);

/// The method of one exchange.
///
/// It is a type of its own so the method and the path, both text on the
/// request line, cannot trade places in a call.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Method {
    /// `GET`.
    Get,
    /// `POST`.
    Post,
    /// `PATCH`.
    Patch,
    /// `DELETE`.
    Delete,
}

impl Method {
    /// Returns the method as the request line spells it.
    pub fn as_str(self) -> &'static str {
        match self {
            Method::Get => "GET",
            Method::Post => "POST",
            Method::Patch => "PATCH",
            Method::Delete => "DELETE",
        }
    }
}

/// One request: the method, the path, the extra headers and the body.
///
/// The path carries its query; the extra headers are the ones a caller
/// adds — `Skepd-Session` when a token rides.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    /// The request line's method.
    pub method: Method,
    /// The request target: the path with its query.
    pub path: String,
    /// The headers a caller adds beside the dialer's own.
    pub headers: Vec<(String, String)>,
    /// The body, empty for none.
    pub body: Vec<u8>,
}

impl Request {
    /// Returns a bodiless `GET` of `path`.
    pub fn get(path: impl Into<String>) -> Request {
        Request { method: Method::Get, path: path.into(), headers: Vec::new(), body: Vec::new() }
    }

    /// Returns a `POST` of `body` to `path`.
    pub fn post(path: impl Into<String>, body: Vec<u8>) -> Request {
        Request { method: Method::Post, path: path.into(), headers: Vec::new(), body }
    }

    /// Returns the request with one more header.
    pub fn header(mut self, name: &str, value: &str) -> Request {
        self.headers.push((name.to_string(), value.to_string()));
        self
    }
}

/// The streamed form's head: the request without its body.
///
/// The caller supplies the body as a reader; the head holds the body's
/// declared length where one is declared (`Content-Length`; a
/// `GET /events` declares none and sends none).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestHead {
    /// The request line's method.
    pub method: Method,
    /// The request target: the path with its query.
    pub path: String,
    /// The headers a caller adds beside the dialer's own.
    pub headers: Vec<(String, String)>,
    /// The body's length where a body follows; `None` for a bodiless head.
    pub content_length: Option<u64>,
}

/// A response's headers, whole, looked up case-insensitively.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Headers(pub Vec<(String, String)>);

impl Headers {
    /// Returns the first header named `name`, case-insensitively.
    pub fn get(&self, name: &str) -> Option<&str> {
        self.0.iter().find(|(k, _)| k.eq_ignore_ascii_case(name)).map(|(_, v)| v.as_str())
    }
}

/// One whole answer: the status, the headers and the body.
///
/// It is read to close with its `Content-Length` checked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Response {
    /// The status code.
    pub status: u16,
    /// The headers, whole.
    pub headers: Headers,
    /// The body.
    pub body: Vec<u8>,
}

impl Response {
    /// Returns whether the death signal rides this answer's head.
    ///
    /// The signal is wire.md §Sessions': the one fact the board's `authed`
    /// exchange reads off a response (P28).
    pub fn session_closed(&self) -> bool {
        self.headers.get("Skepd-Session").is_some_and(|v| v.trim() == "closed")
    }
}

/// The streamed form's answer: the head, and a reader over the body.
///
/// The caller holds the declared size against the body as bytes arrive —
/// read to close, or dropped by the caller.
pub struct StreamedResponse {
    /// The answer's status code.
    pub status: u16,
    /// The answer's headers, whole.
    pub headers: Headers,
    /// A reader over the body, cut to a declared `Content-Length`.
    pub body: Box<dyn Read + Send>,
}

impl fmt::Debug for StreamedResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "StreamedResponse(status {}, {} headers)", self.status, self.headers.0.len())
    }
}

/// Why a dial failed — transport, §2.3's exit 4.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum DialError {
    /// The origin's scheme is one this build does not hold.
    ///
    /// It is `https` without the `tls` feature, refused before any
    /// connection opened: it reached no board.
    NotHeld(String),
    /// The host did not resolve to an address.
    ///
    /// It is a request the board never answered.
    Resolve(String),
    /// No connection was made, and no byte of the request was written.
    ///
    /// Each address the host yields refused the connection, was unreachable
    /// or did not take it within [`CONNECT_TIMEOUT`]; or the TLS handshake
    /// over it broke off or ran past its bound. It is a request the board
    /// never answered.
    Connect(String),
    /// A read or a write ran past its bound once the connection was made.
    ///
    /// It is the exchange run past its deadline too, and a request the board
    /// never answered. A connection attempt past its bound is
    /// [`DialError::Connect`].
    Timeout(String),
    /// The request could not be written or the response read.
    ///
    /// It covers a connection closed before its answer's head was whole —
    /// nothing sent, or a head that opened as a status line and was cut off
    /// — the TLS record layer's refusals once the handshake is done, and a
    /// socket whose timeout cannot be set: a request the board never
    /// answered. Its text quotes no byte of the answer (SP-15).
    Io(String),
    /// The bytes read were no HTTP response, or no answer the wire gives.
    ///
    /// It is an answer the board gave. An answer closed before its head was
    /// whole is this only where its bytes open as no status line; one that
    /// sent nothing, or cut off a head that opened as a status line, is
    /// [`DialError::Io`].
    Response(String),
    /// The body ended before its declared `Content-Length`.
    ///
    /// It is a broken connection, never an answer: a request the board never
    /// answered.
    Truncated { declared: usize, got: usize },
    /// The answer ran past the cap and was read no further.
    ///
    /// It is an answer the board gave.
    TooLarge { cap: usize },
    /// The TLS layer refused the server name, its configuration or the peer.
    ///
    /// The peer is refused in the handshake — an untrusted certificate, an
    /// alert, bytes that are no TLS — which ends before a byte of the request
    /// is written: a request the board never answered.
    Tls(String),
    /// The request was refused before any connection opened.
    ///
    /// Its target or a header holds what would end the request line or a
    /// header early. It reached no board.
    Request(String),
}

impl DialError {
    /// Returns whether the board gave an answer, one this dial could not read.
    ///
    /// It is true for bytes that are no HTTP response or no answer the wire
    /// gives ([`DialError::Response`]) and for an answer past the cap
    /// ([`DialError::TooLarge`]), and false for every other variant: a
    /// request the board never answered ([`DialError::unanswered`]) and a
    /// request refused before any connection opened (`client.md` §7).
    pub fn answered(&self) -> bool {
        match self {
            DialError::Response(_) | DialError::TooLarge { .. } => true,
            DialError::NotHeld(_)
            | DialError::Resolve(_)
            | DialError::Connect(_)
            | DialError::Timeout(_)
            | DialError::Io(_)
            | DialError::Truncated { .. }
            | DialError::Tls(_)
            | DialError::Request(_) => false,
        }
    }

    /// Returns whether the board gave the request no answer (`client.md` §7).
    ///
    /// It is true for the name unresolved ([`DialError::Resolve`]), a
    /// connection never made or a handshake not completed
    /// ([`DialError::Connect`], [`DialError::Tls`]), a read past its bound
    /// ([`DialError::Timeout`]) and a connection closed before its answer was
    /// whole ([`DialError::Io`], [`DialError::Truncated`]). It is false for an
    /// answer the board gave ([`DialError::answered`]) and for a request
    /// refused before any connection opened ([`DialError::NotHeld`],
    /// [`DialError::Request`]), which reached no board.
    pub fn unanswered(&self) -> bool {
        match self {
            DialError::Resolve(_)
            | DialError::Connect(_)
            | DialError::Timeout(_)
            | DialError::Io(_)
            | DialError::Truncated { .. }
            | DialError::Tls(_) => true,
            DialError::NotHeld(_) | DialError::Response(_) | DialError::TooLarge { .. } | DialError::Request(_) => false,
        }
    }
}

impl fmt::Display for DialError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DialError::NotHeld(scheme) => write!(
                f,
                "no transport held for {scheme} origins in this build (the `tls` feature is off)"
            ),
            DialError::Request(e) => write!(f, "malformed request: {e}"),
            DialError::Resolve(e) => write!(f, "resolve: {e}"),
            DialError::Connect(e) => write!(f, "connect: {e}"),
            DialError::Timeout(e) => write!(f, "timed out: {e}"),
            DialError::Io(e) => write!(f, "io: {e}"),
            DialError::Response(e) => write!(f, "malformed response: {e}"),
            DialError::Truncated { declared, got } => {
                write!(f, "truncated body ({got} of {declared} bytes) — the connection broke")
            }
            DialError::TooLarge { cap } => write!(f, "the answer runs past {cap} bytes, the most read of one"),
            DialError::Tls(e) => write!(f, "tls: {e}"),
        }
    }
}

impl std::error::Error for DialError {}

/// The seam (`client.md` §1.4): one trait, one v1 arm.
///
/// A later transport is an implementation and never a rewrite. A `Dialer`
/// knows nothing of sessions, keys, the ceremony or the peer rule.
pub trait Dialer: Send + Sync {
    /// Makes one exchange: one request to `origin`, one response.
    ///
    /// The connection is closed after the response.
    ///
    /// # Errors
    ///
    /// The [`DialError`] naming how the dial failed.
    fn exchange(&self, origin: &Origin, req: &Request) -> Result<Response, DialError>;

    /// Makes the streamed form of an exchange.
    ///
    /// The head is sent with `Expect: 100-continue` where a body follows, an
    /// interim answer's headers handed to `on_interim` before any body byte,
    /// the body written from `body`, the answer's head returned with a reader
    /// over its body — read to close, or dropped by the caller — under a read
    /// timeout that scales with the declared size. Where the board answers a
    /// final status instead of the interim one, no body byte is written and
    /// that head is the answer.
    ///
    /// # Errors
    ///
    /// The [`DialError`] naming how the dial failed.
    fn stream(
        &self,
        origin: &Origin,
        head: &RequestHead,
        body: &mut dyn Read,
        on_interim: &mut dyn FnMut(&Headers),
    ) -> Result<StreamedResponse, DialError>;
}

/// A dialer behind a reference is the dialer it refers to.
impl<D: Dialer + ?Sized> Dialer for &D {
    fn exchange(&self, origin: &Origin, req: &Request) -> Result<Response, DialError> {
        (**self).exchange(origin, req)
    }

    fn stream(
        &self,
        origin: &Origin,
        head: &RequestHead,
        body: &mut dyn Read,
        on_interim: &mut dyn FnMut(&Headers),
    ) -> Result<StreamedResponse, DialError> {
        (**self).stream(origin, head, body, on_interim)
    }
}

/// A dialer behind a box is the dialer it holds.
impl<D: Dialer + ?Sized> Dialer for Box<D> {
    fn exchange(&self, origin: &Origin, req: &Request) -> Result<Response, DialError> {
        (**self).exchange(origin, req)
    }

    fn stream(
        &self,
        origin: &Origin,
        head: &RequestHead,
        body: &mut dyn Read,
        on_interim: &mut dyn FnMut(&Headers),
    ) -> Result<StreamedResponse, DialError> {
        (**self).stream(origin, head, body, on_interim)
    }
}

/// A dialer behind an `Arc` is the dialer it shares.
///
/// It is the one dialer a shell holds, handed to a
/// [`Board`](crate::board::Board) and to `resolve`'s transport alike (§7:
/// no second dialer).
impl<D: Dialer + ?Sized> Dialer for Arc<D> {
    fn exchange(&self, origin: &Origin, req: &Request) -> Result<Response, DialError> {
        (**self).exchange(origin, req)
    }

    fn stream(
        &self,
        origin: &Origin,
        head: &RequestHead,
        body: &mut dyn Read,
        on_interim: &mut dyn FnMut(&Headers),
    ) -> Result<StreamedResponse, DialError> {
        (**self).stream(origin, head, body, on_interim)
    }
}

/// Returns the plaintext non-loopback warning for `origin`.
///
/// The text is answered where a signed session over `origin` would ride the
/// token in the clear; `None` where it would not. §9 item 23: a warning
/// citing AUTH-4.53, never a refusal — the bind-override tailnet path is
/// exactly a plaintext non-loopback origin the tunnel encrypts.
pub fn plaintext_non_loopback_warning(origin: &Origin) -> Option<String> {
    if origin.is_https() || origin.names_loopback_host() {
        return None;
    }
    Some(format!(
        "warning: {origin} is a plaintext non-loopback origin — the session token rides in the clear \
         unless a tunnel carries it (AUTH-4.53: a plaintext non-loopback bind is signed-session-unsafe \
         for the dialing client); a captured token is a full session for that principal until it is \
         closed, the key is retired, or the daemon restarts"
    ))
}

/// The plain-HTTP arm — and, under `tls`, the `https://` arm over rustls.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlainHttp {
    connect_timeout: Duration,
    io_timeout: Duration,
    /// A frame exchange's deadline before its body's allowance.
    ///
    /// It is [`EXCHANGE_BOUND`].
    exchange_bound: Duration,
}

impl Default for PlainHttp {
    fn default() -> PlainHttp {
        PlainHttp { connect_timeout: CONNECT_TIMEOUT, io_timeout: IO_TIMEOUT, exchange_bound: EXCHANGE_BOUND }
    }
}

impl PlainHttp {
    /// Returns the arm with the pinned timeouts.
    pub fn new() -> PlainHttp {
        PlainHttp::default()
    }

    fn fail(origin: &Origin, what: &str, e: impl fmt::Display) -> String {
        format!("skepd at {origin}: {what}: {e}")
    }

    /// Opens the TCP connection to `origin`'s host.
    ///
    /// Every address the name yields is tried in order, each within the
    /// connect bound; the timeouts are set — and, where `budget` is given,
    /// the exchange's deadline that far from the open ([`Socket`]).
    ///
    /// # Errors
    ///
    /// [`DialError::Resolve`] where the host yields no address;
    /// [`DialError::Connect`] where no address took the connection, the last
    /// attempt refused, unreachable or past the connect bound;
    /// [`DialError::Io`] where a timeout cannot be set.
    ///
    /// # Panics
    ///
    /// Panics if no address was tried; the addresses are checked non-empty
    /// first, so the `expect` never fires.
    fn tcp(&self, origin: &Origin, read_timeout: Duration, budget: Option<Duration>) -> Result<Socket, DialError> {
        let addrs: Vec<SocketAddr> = (origin.dial_host(), origin.port())
            .to_socket_addrs()
            .map_err(|e| DialError::Resolve(Self::fail(origin, "resolve", e)))?
            .collect();
        if addrs.is_empty() {
            return Err(DialError::Resolve(Self::fail(origin, "resolve", "no addresses")));
        }
        let mut last: Option<io::Error> = None;
        let mut stream = None;
        for addr in &addrs {
            match TcpStream::connect_timeout(addr, self.connect_timeout) {
                Ok(s) => {
                    stream = Some(s);
                    break;
                }
                Err(e) => last = Some(e),
            }
        }
        let stream = match stream {
            Some(s) => s,
            None => {
                let e = last.expect("at least one address was tried");
                return Err(DialError::Connect(Self::fail(origin, "connect", e)));
            }
        };
        stream.set_read_timeout(Some(read_timeout)).map_err(|e| DialError::Io(Self::fail(origin, "socket", e)))?;
        stream
            .set_write_timeout(Some(self.io_timeout))
            .map_err(|e| DialError::Io(Self::fail(origin, "socket", e)))?;
        let _ = stream.set_nodelay(true);
        let deadline = budget.map(|b| Instant::now() + b);
        Ok(Socket { tcp: stream, read_bound: read_timeout, write_bound: self.io_timeout, deadline })
    }

    /// Opens the connection to `origin`.
    ///
    /// It is plain TCP for `http://`; an `https://` origin is the `tls`
    /// module's whole — TLS over TCP, its handshake run to its end, where the
    /// build holds the arm, refused before any connection opens where it
    /// does not.
    ///
    /// # Errors
    ///
    /// `tcp`'s errors; for an `https://` origin, [`DialError::NotHeld`]
    /// where the build holds no TLS arm, [`DialError::Tls`] where the TLS
    /// layer refuses the server name, its configuration or the peer, and
    /// [`DialError::Connect`] where the handshake breaks off or runs past its
    /// bound.
    fn connect(&self, origin: &Origin, read_timeout: Duration, budget: Option<Duration>) -> Result<Box<dyn Conn>, DialError> {
        if origin.is_https() {
            return tls::connect(self, origin, read_timeout, budget);
        }
        Ok(Box::new(self.tcp(origin, read_timeout, budget)?))
    }

    /// Checks that the target and headers are what this dialer writes as given.
    ///
    /// RFC 9112 §3.2, §5: the target visible ASCII alone, a header's name a
    /// token, its value free of CR, LF and NUL. A target or a value carrying
    /// a line break would end the request line or the header early and write
    /// a header of the bytes' own choosing.
    ///
    /// # Errors
    ///
    /// [`DialError::Request`], before any connection opens, where the target
    /// or a header breaks those rules.
    fn well_formed(path: &str, headers: &[(String, String)]) -> Result<(), DialError> {
        if let Some(b) = path.bytes().find(|b| !(0x21..=0x7e).contains(b)) {
            return Err(DialError::Request(format!("the request target holds the byte {b:#04x}")));
        }
        let token = |name: &str| !name.is_empty() && name.bytes().all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b));
        for (name, value) in headers {
            if !token(name) {
                return Err(DialError::Request("a header's name is not a token".into()));
            }
            if value.bytes().any(|b| matches!(b, b'\r' | b'\n' | 0)) {
                return Err(DialError::Request(format!("the value of the header `{name}` holds a line break or a NUL")));
            }
        }
        Ok(())
    }

    /// Returns the request head's bytes.
    ///
    /// The daemon refuses a `Content-Length` with any non-digit, so the
    /// length is ASCII decimal and nothing else.
    fn head_bytes(
        origin: &Origin,
        method: Method,
        path: &str,
        headers: &[(String, String)],
        content_length: Option<u64>,
        expect_continue: bool,
        has_body: bool,
    ) -> Vec<u8> {
        let mut head = format!(
            "{} {path} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n",
            method.as_str(),
            origin.authority()
        );
        if has_body {
            head.push_str("Content-Type: application/json\r\n");
        }
        if let Some(n) = content_length {
            head.push_str(&format!("Content-Length: {n}\r\n"));
        }
        if expect_continue {
            head.push_str("Expect: 100-continue\r\n");
        }
        for (k, v) in headers {
            head.push_str(&format!("{k}: {v}\r\n"));
        }
        head.push_str("\r\n");
        head.into_bytes()
    }
}

/// A connection the dialer writes a request to and reads an answer from.
///
/// It is a [`Socket`], or a TLS stream over one.
trait Conn: Read + Write + Send {}
impl Conn for Socket {}

/// A TCP connection under the dialer's bounds.
///
/// Each read and each write carries the per-call bound, and — where the
/// connection serves a frame exchange — the socket's timeout is re-armed
/// before every call to that bound or the time left before the exchange's
/// deadline, whichever is less, a call past the deadline answering
/// `TimedOut` unmade. A TLS stream rides over it, so every read and write
/// the TLS layer makes of the socket is held to the same deadline.
struct Socket {
    tcp: TcpStream,
    read_bound: Duration,
    write_bound: Duration,
    deadline: Option<Instant>,
}

impl Socket {
    /// Sets the timeout for the next call, where a deadline stands.
    ///
    /// The timeout is the per-call `bound`, cut to the time left.
    ///
    /// # Errors
    ///
    /// `TimedOut` where the deadline has passed, and `set`'s error where the
    /// timeout cannot be set.
    fn arm(&self, bound: Duration, set: fn(&TcpStream, Option<Duration>) -> io::Result<()>) -> io::Result<()> {
        let Some(deadline) = self.deadline else { return Ok(()) };
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Err(io::Error::new(io::ErrorKind::TimedOut, "the exchange ran past its deadline"));
        }
        set(&self.tcp, Some(bound.min(left)))
    }
}

impl Read for Socket {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.arm(self.read_bound, TcpStream::set_read_timeout)?;
        self.tcp.read(buf)
    }
}

impl Write for Socket {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.arm(self.write_bound, TcpStream::set_write_timeout)?;
        self.tcp.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.tcp.flush()
    }
}

impl Dialer for PlainHttp {
    fn exchange(&self, origin: &Origin, req: &Request) -> Result<Response, DialError> {
        Self::well_formed(&req.path, &req.headers)?;
        let body_allowance = Duration::from_millis((req.body.len() as u64).saturating_mul(1000) / STREAM_BYTES_PER_SECOND);
        let mut conn = self.connect(origin, self.io_timeout, Some(self.exchange_bound.saturating_add(body_allowance)))?;
        let head = Self::head_bytes(
            origin,
            req.method,
            &req.path,
            &req.headers,
            Some(req.body.len() as u64),
            false,
            !req.body.is_empty(),
        );
        conn.write_all(&head)
            .and_then(|()| conn.write_all(&req.body))
            .map_err(|e| io_fault(origin, "write", e))?;
        let raw = read_to_close(&mut *conn, MAX_ANSWER_BYTES).map_err(|e| io_fault(origin, "read", e))?;
        let raw = raw.ok_or(DialError::TooLarge { cap: MAX_ANSWER_BYTES })?;
        let body_at = head_len(&raw).ok_or_else(|| closed_before_head(origin, &raw))?;
        let (status, headers) = parse_head(&raw[..body_at]).map_err(|e| DialError::Response(Self::fail(origin, "response", e)))?;
        let mut body = raw[body_at..].to_vec();
        if let Some(cl) = headers.get("Content-Length").and_then(|v| v.trim().parse::<usize>().ok()) {
            if body.len() < cl {
                return Err(DialError::Truncated { declared: cl, got: body.len() });
            }
            body.truncate(cl);
        }
        Ok(Response { status, headers, body })
    }

    fn stream(
        &self,
        origin: &Origin,
        head: &RequestHead,
        body: &mut dyn Read,
        on_interim: &mut dyn FnMut(&Headers),
    ) -> Result<StreamedResponse, DialError> {
        Self::well_formed(&head.path, &head.headers)?;
        let declared = head.content_length.unwrap_or(0);
        let read_timeout = self.io_timeout + Duration::from_secs(declared / STREAM_BYTES_PER_SECOND);
        let mut conn = self.connect(origin, read_timeout, None)?;
        let has_body = head.content_length.is_some();
        let bytes = Self::head_bytes(origin, head.method, &head.path, &head.headers, head.content_length, has_body, has_body);
        conn.write_all(&bytes).map_err(|e| io_fault(origin, "write", e))?;
        // The answer's head — the interim `100 Continue` where a body
        // follows, else the final head.
        let mut reader = HeadReader::new(conn);
        let (mut status, mut headers) = reader.head(origin)?;
        if has_body {
            if status == 100 {
                on_interim(&headers);
                let mut buf = [0u8; 64 * 1024];
                loop {
                    let n = body.read(&mut buf).map_err(|e| io_fault(origin, "read body", e))?;
                    if n == 0 {
                        break;
                    }
                    reader.conn.write_all(&buf[..n]).map_err(|e| io_fault(origin, "write body", e))?;
                }
                let (s, h) = reader.head(origin)?;
                status = s;
                headers = h;
            }
            // A final status instead of the interim one: the body is not
            // sent, and that head is the answer.
        }
        let content_length = headers.get("Content-Length").and_then(|v| v.trim().parse::<u64>().ok());
        let body: Box<dyn Read + Send> = match content_length {
            Some(n) => Box::new(reader.into_body().take(n)),
            None => Box::new(reader.into_body()),
        };
        Ok(StreamedResponse { status, headers, body })
    }
}

fn io_fault(origin: &Origin, what: &str, e: io::Error) -> DialError {
    let text = PlainHttp::fail(origin, what, &e);
    match e.kind() {
        io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock => DialError::Timeout(text),
        _ => DialError::Io(text),
    }
}

/// Reads one whole answer off `conn`, to EOF.
///
/// The answer is `None` where it runs past `cap` bytes, read no further than
/// the byte past the cap.
///
/// # Errors
///
/// The read's I/O error.
fn read_to_close(conn: &mut dyn Read, cap: usize) -> io::Result<Option<Vec<u8>>> {
    let mut raw = Vec::new();
    conn.take(cap as u64 + 1).read_to_end(&mut raw)?;
    Ok((raw.len() <= cap).then_some(raw))
}

/// The opening of every status line this dialer reads: `HTTP/1.`.
///
/// `parse_head` holds a whole head's status line to it, and
/// `closed_before_head` reads the bytes of a head cut short against it.
const STATUS_LINE_OPENING: &str = "HTTP/1.";

/// Returns the length of the response head at the start of `raw`.
///
/// The head runs through its blank line; `None` where `raw` holds none.
fn head_len(raw: &[u8]) -> Option<usize> {
    raw.windows(4).position(|w| w == b"\r\n\r\n").map(|sep| sep + 4)
}

/// Returns the fault of an answer that closed before its head's blank line.
///
/// `got` is what arrived. Nothing at all, or bytes that open as a status line
/// does (`STATUS_LINE_OPENING`, or a prefix of it), are a connection broken
/// before the head was whole: [`DialError::Io`], as a body short of its
/// `Content-Length` is [`DialError::Truncated`], never an answer. Bytes that
/// open any other way are no HTTP response, [`DialError::Response`]. Neither
/// text quotes a byte of `got` (SP-15).
fn closed_before_head(origin: &Origin, got: &[u8]) -> DialError {
    let opening = STATUS_LINE_OPENING.as_bytes();
    if opening.starts_with(&got[..got.len().min(opening.len())]) {
        let closed = format!("the connection closed after {} bytes, before the answer's head was whole", got.len());
        DialError::Io(PlainHttp::fail(origin, "read", closed))
    } else {
        DialError::Response(PlainHttp::fail(origin, "response", "no header terminator"))
    }
}

/// Parses one response head's status and headers.
///
/// `head` is the head through its blank line, as `head_len` measures it.
///
/// # Errors
///
/// The fault in words where the head is not UTF-8, its status line is not
/// `HTTP/1.x`, or its status does not parse.
fn parse_head(head: &[u8]) -> Result<(u16, Headers), String> {
    let head = std::str::from_utf8(head).map_err(|_| String::from("non-UTF-8 response head"))?;
    let mut lines = head.split("\r\n");
    let status_line = lines.next().ok_or_else(|| String::from("no status line"))?;
    if !status_line.starts_with(STATUS_LINE_OPENING) {
        return Err(format!("not an HTTP status line: {status_line:?}"));
    }
    let status: u16 = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| String::from("malformed status line"))?;
    let headers = Headers(
        lines
            .filter_map(|l| l.split_once(':'))
            .map(|(k, v)| (k.trim().to_string(), v.trim().to_string()))
            .collect(),
    );
    Ok((status, headers))
}

/// A head reader over a connection.
///
/// It reads one response head (through its blank line) and keeps whatever
/// body bytes arrived with it.
struct HeadReader {
    conn: Box<dyn Conn>,
    buffered: Vec<u8>,
}

impl HeadReader {
    fn new(conn: Box<dyn Conn>) -> HeadReader {
        HeadReader { conn, buffered: Vec::new() }
    }

    /// Reads the next head off the connection.
    ///
    /// The bytes after its blank line stay buffered for the body (or the
    /// next head).
    ///
    /// # Errors
    ///
    /// [`DialError::Timeout`] or [`DialError::Io`] where a read fails, as
    /// `io_fault` names it; `closed_before_head`'s error where the connection
    /// closes before the head is whole; and [`DialError::Response`] where the
    /// head runs past 64 KiB or `parse_head` refuses it.
    fn head(&mut self, origin: &Origin) -> Result<(u16, Headers), DialError> {
        let mut chunk = [0u8; 4096];
        loop {
            if let Some(len) = head_len(&self.buffered) {
                let head = parse_head(&self.buffered[..len]).map_err(|e| DialError::Response(PlainHttp::fail(origin, "response", e)));
                self.buffered.drain(..len);
                return head;
            }
            if self.buffered.len() > 64 * 1024 {
                return Err(DialError::Response(PlainHttp::fail(origin, "response", "response head past 64 KiB")));
            }
            let n = self.conn.read(&mut chunk).map_err(|e| io_fault(origin, "read", e))?;
            if n == 0 {
                return Err(closed_before_head(origin, &self.buffered));
            }
            self.buffered.extend_from_slice(&chunk[..n]);
        }
    }

    /// Returns the body: the buffered bytes, then the connection to its close.
    fn into_body(self) -> impl Read + Send {
        io::Cursor::new(self.buffered).chain(self.conn)
    }
}

#[cfg(feature = "tls")]
mod tls {
    //! The `https://` arm: rustls over the TCP stream.
    //!
    //! The server's certificate is judged by the platform's own trust store
    //! (`rustls-platform-verifier`; §9 item 12). The crypto provider is
    //! `ring`, named explicitly so the build's provider never depends on
    //! which features another crate turned on.

    use std::io;
    use std::sync::{Arc, OnceLock};
    use std::time::Duration;

    use rustls::pki_types::ServerName;
    use rustls::{ClientConfig, ClientConnection, StreamOwned};
    use rustls_platform_verifier::BuilderVerifierExt;

    use super::{Conn, DialError, Origin, PlainHttp, Socket};

    impl Conn for StreamOwned<ClientConnection, Socket> {}

    fn config() -> Result<Arc<ClientConfig>, DialError> {
        static CONFIG: OnceLock<Result<Arc<ClientConfig>, String>> = OnceLock::new();
        CONFIG
            .get_or_init(|| {
                let provider = Arc::new(rustls::crypto::ring::default_provider());
                ClientConfig::builder_with_provider(provider)
                    .with_safe_default_protocol_versions()
                    .map_err(|e| e.to_string())?
                    .with_platform_verifier()
                    .map_err(|e| e.to_string())
                    .map(|b| Arc::new(b.with_no_client_auth()))
            })
            .clone()
            .map_err(DialError::Tls)
    }

    /// Opens the TCP connection to `origin` and runs the TLS handshake over it.
    ///
    /// The handshake runs to its end here, before a byte of the request is
    /// written, so one that does not finish is a connection never made.
    /// Every socket call the TLS layer makes is held to the connection's
    /// deadline, where one stands.
    ///
    /// # Errors
    ///
    /// `tcp`'s errors; [`DialError::Tls`] where the server name or the TLS
    /// configuration is refused; `handshake_fault`'s error where the
    /// handshake does not finish, and [`DialError::Connect`] where rustls
    /// answers that it can make no progress.
    pub(super) fn connect(dialer: &PlainHttp, origin: &Origin, read_timeout: Duration, budget: Option<Duration>) -> Result<Box<dyn Conn>, DialError> {
        let mut tcp = dialer.tcp(origin, read_timeout, budget)?;
        let name = ServerName::try_from(origin.dial_host().to_string())
            .map_err(|e| DialError::Tls(PlainHttp::fail(origin, "server name", e)))?;
        let mut conn = ClientConnection::new(config()?, name).map_err(|e| DialError::Tls(PlainHttp::fail(origin, "tls", e)))?;
        // `complete_io` can answer mid-handshake — a read past its bound
        // after earlier progress — so it is driven to the handshake's end; an
        // answer of no progress at all ends the loop, which no socket call
        // would bound.
        while conn.is_handshaking() {
            match conn.complete_io(&mut tcp) {
                Ok((0, 0)) => {
                    let stalled = PlainHttp::fail(origin, "tls handshake", "it made no progress");
                    return Err(DialError::Connect(stalled));
                }
                Ok(_) => {}
                Err(e) => return Err(handshake_fault(origin, e)),
            }
        }
        Ok(Box::new(StreamOwned::new(conn, tcp)))
    }

    /// Returns the fault of a TLS handshake that did not finish.
    ///
    /// No byte of the request was written, so it is a connection never made:
    /// [`DialError::Tls`] where the TLS layer refused the peer (`InvalidData`
    /// — an untrusted certificate, an alert, bytes that are no TLS), and
    /// [`DialError::Connect`] where the peer stalled past the bound or broke
    /// the connection off.
    fn handshake_fault(origin: &Origin, e: io::Error) -> DialError {
        match e.kind() {
            io::ErrorKind::InvalidData => {
                DialError::Tls(PlainHttp::fail(origin, "tls handshake", e))
            }
            io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock => {
                DialError::Connect(PlainHttp::fail(origin, "tls handshake timed out", e))
            }
            _ => DialError::Connect(PlainHttp::fail(origin, "tls handshake", e)),
        }
    }
}

#[cfg(not(feature = "tls"))]
mod tls {
    //! Without the feature an `https` origin is no transport this build holds.
    //!
    //! It is refused by name before any connection opens: this arm is handed
    //! no stream, so it can never dial in the clear.

    use std::time::Duration;

    use super::{Conn, DialError, Origin, PlainHttp};

    pub(super) fn connect(_dialer: &PlainHttp, _origin: &Origin, _read_timeout: Duration, _budget: Option<Duration>) -> Result<Box<dyn Conn>, DialError> {
        Err(DialError::NotHeld("https".into()))
    }
}
