//! THE ONE OUTBOUND DIALER (`client.md` §7; RULED, owner 2026-10-04, ps3-3):
//! the `Dialer` seam and its plain-HTTP arm, which the `skep` command, the
//! frontend's shell and — a later lane — the daemon's node-pull all use, so
//! no second dialer is kept in step with wire.md §Transport.
//!
//! One request, one connection: every response carries `Connection: close`,
//! so a client opens a fresh `TcpStream` per call (wire.md §Transport); the
//! request head is written out — `Host: <authority>` (brackets kept for an
//! IPv6 literal), `Connection: close`, `Content-Type: application/json`,
//! `Content-Length` as the body's length in ASCII decimal — the body
//! follows, the answer is read to close and its `Content-Length` CHECKED
//! against what arrived: a short body is a broken connection, never an
//! answer. The response's headers are returned whole so the board can read
//! `Skepd-Session: closed`. NO REDIRECT is followed — the daemon issues none,
//! and following one would dial an origin the caller did not sign
//! (AUTH-4.8). NO proxy environment is honored — a proxy is a peer the
//! signature knows nothing about (§9 item 24). A `Dialer` never rewrites the
//! origin string it is handed (§1.4): a transport that changed the origin
//! under its caller would sign one string and dial another.
//!
//! Timeouts: connect 5 s, read/write 10 s a call for the FRAMES (skep-mcp's
//! constants — a skepd op is milliseconds even under fsync), and a frame's
//! whole EXCHANGE held to a deadline besides — the per-call bound plus the
//! time its request body and the largest answer take at the streamed form's
//! rate — re-armed on the socket before every read and write, so a board
//! that trickles a byte inside each per-call bound cannot hold an exchange
//! past it; the STREAMED form's read timeout scales with the declared size
//! (ps3-14 (c)) and its body, read by its caller, keeps that per-call bound
//! alone.
//!
//! The request target and the headers are written as given, so each is
//! checked first for what would end the request line or a header early —
//! refused as [`DialError::Request`] before any connection opens.
//!
//! `https://` is the `tls` feature's arm — rustls with the platform verifier
//! (§9 item 12) — OFF in the library and ON in the `skep` binary; without
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

/// A dead local daemon answers `connection refused` at once; this bounds
/// the pathological cases — an unroutable address, a filtered port.
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// Per-call read/write bound for a FRAME: ten seconds is headroom, not an
/// expected wait (skep-mcp's `IO_TIMEOUT`, kept).
pub const IO_TIMEOUT: Duration = Duration::from_secs(10);

/// The most bytes [`Dialer::exchange`] reads of one answer — the frame
/// routes' request cap, 8 MiB, with room for the head beside it (wire.md
/// §Transport). An answer past it is [`DialError::TooLarge`], read no
/// further: a board never sizes this client's memory past it.
pub const MAX_ANSWER_BYTES: usize = 8 * 1024 * 1024 + 64 * 1024;

/// The streamed form's read bound per declared byte, on top of
/// [`IO_TIMEOUT`]: one second per 256 KiB declared (the scale's constant is
/// the build's, ps3-14 (c)).
const STREAM_BYTES_PER_SECOND: u64 = 256 * 1024;

/// A frame exchange's deadline before its request body's allowance, from
/// the connection's open: [`IO_TIMEOUT`], and the time an answer at
/// [`MAX_ANSWER_BYTES`] takes at [`STREAM_BYTES_PER_SECOND`] — 42.25 s, the
/// rate the streamed form already demands of a board. The body adds its own
/// bytes at the same rate.
const EXCHANGE_BOUND: Duration =
    Duration::from_millis(IO_TIMEOUT.as_millis() as u64 + MAX_ANSWER_BYTES as u64 * 1000 / STREAM_BYTES_PER_SECOND);

/// The method of one exchange — a type of its own so the method and the
/// path, both text on the request line, cannot trade places in a call.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Method {
    Get,
    Post,
    Patch,
    Delete,
}

impl Method {
    /// The method as the request line spells it.
    pub fn as_str(self) -> &'static str {
        match self {
            Method::Get => "GET",
            Method::Post => "POST",
            Method::Patch => "PATCH",
            Method::Delete => "DELETE",
        }
    }
}

/// One request: the method, the path (with its query), the extra headers
/// a caller adds — `Skepd-Session` when a token rides — and the body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    pub method: Method,
    pub path: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Request {
    /// A bodiless `GET` of `path`.
    pub fn get(path: impl Into<String>) -> Request {
        Request { method: Method::Get, path: path.into(), headers: Vec::new(), body: Vec::new() }
    }

    /// A `POST` of `body` to `path`.
    pub fn post(path: impl Into<String>, body: Vec<u8>) -> Request {
        Request { method: Method::Post, path: path.into(), headers: Vec::new(), body }
    }

    /// The request with one more header.
    pub fn header(mut self, name: &str, value: &str) -> Request {
        self.headers.push((name.to_string(), value.to_string()));
        self
    }
}

/// The streamed form's head: the request without its body, which the
/// caller supplies as a reader, and the body's declared length where one is
/// declared (`Content-Length`; a `GET /events` declares none and sends
/// none).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestHead {
    pub method: Method,
    pub path: String,
    pub headers: Vec<(String, String)>,
    /// The body's length where a body follows; `None` for a bodiless head.
    pub content_length: Option<u64>,
}

/// A response's headers, whole, looked up case-insensitively.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Headers(pub Vec<(String, String)>);

impl Headers {
    /// The first header named `name`, case-insensitively.
    pub fn get(&self, name: &str) -> Option<&str> {
        self.0.iter().find(|(k, _)| k.eq_ignore_ascii_case(name)).map(|(_, v)| v.as_str())
    }
}

/// One whole answer: the status, the headers and the body, read to close
/// with its `Content-Length` checked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Response {
    pub status: u16,
    pub headers: Headers,
    pub body: Vec<u8>,
}

impl Response {
    /// The death signal on this answer's head (wire.md §Sessions): the one
    /// fact the board's `authed` exchange reads off a response (P28).
    pub fn session_closed(&self) -> bool {
        self.headers.get("Skepd-Session").is_some_and(|v| v.trim() == "closed")
    }
}

/// The streamed form's answer: the head, and a reader over the body the
/// caller holds the declared size against as bytes arrive — read to close,
/// or dropped by the caller.
pub struct StreamedResponse {
    pub status: u16,
    pub headers: Headers,
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
    /// The origin's scheme is one this build does not hold (`https` without
    /// the `tls` feature).
    NotHeld(String),
    /// The host did not resolve to an address.
    Resolve(String),
    /// The connection was refused or timed out at every address the host
    /// yields.
    Connect(String),
    /// A read or write ran past its bound.
    Timeout(String),
    /// The request could not be written or the response read.
    Io(String),
    /// The bytes read were no HTTP response.
    Response(String),
    /// The body ended before its declared `Content-Length` — a broken
    /// connection, never an answer.
    Truncated { declared: usize, got: usize },
    /// The answer ran past the cap and was read no further.
    TooLarge { cap: usize },
    /// The TLS handshake or record layer refused.
    Tls(String),
    /// The request's target or a header holds what would end the request
    /// line or a header early — refused before any connection opened.
    Request(String),
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

/// THE SEAM (`client.md` §1.4): one trait, one v1 arm, so a later transport
/// is an implementation and never a rewrite. A `Dialer` knows nothing of
/// sessions, keys, the ceremony or the peer rule.
pub trait Dialer: Send + Sync {
    /// One request to `origin`, one response, connection closed.
    fn exchange(&self, origin: &Origin, req: &Request) -> Result<Response, DialError>;

    /// The streamed form (ps3-14 (c)): the head sent with
    /// `Expect: 100-continue` where a body follows, an interim answer's
    /// headers handed to `on_interim` before any body byte, the body written
    /// from `body`, the answer's head returned with a reader over its body —
    /// read to close, or dropped by the caller — under a read timeout that
    /// scales with the declared size. Where the board answers a FINAL status
    /// instead of the interim one, no body byte is written and that head is
    /// the answer.
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

/// A dialer behind an `Arc` is the dialer it shares — the ONE dialer a shell
/// holds, handed to a [`Board`](crate::board::Board) and to `resolve`'s
/// transport alike (§7: no second dialer).
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

/// The plaintext non-loopback WARNING (§9 item 23, RULED: a warning citing
/// AUTH-4.53, never a refusal — the bind-override tailnet path is exactly a
/// plaintext non-loopback origin the tunnel encrypts): the text, where a
/// SIGNED session over `origin` would ride the token in the clear; `None`
/// where it would not.
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
    /// A frame exchange's deadline before its body's allowance
    /// ([`EXCHANGE_BOUND`]).
    exchange_bound: Duration,
}

impl Default for PlainHttp {
    fn default() -> PlainHttp {
        PlainHttp { connect_timeout: CONNECT_TIMEOUT, io_timeout: IO_TIMEOUT, exchange_bound: EXCHANGE_BOUND }
    }
}

impl PlainHttp {
    /// The arm with the pinned timeouts.
    pub fn new() -> PlainHttp {
        PlainHttp::default()
    }

    fn fail(origin: &Origin, what: &str, e: impl fmt::Display) -> String {
        format!("skepd at {origin}: {what}: {e}")
    }

    /// The TCP connection to `origin`'s host, every address the name yields
    /// tried in order within the connect bound, the timeouts set — and,
    /// where `budget` is given, the exchange's deadline that far from the
    /// open ([`Socket`]).
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
                return Err(if e.kind() == io::ErrorKind::TimedOut {
                    DialError::Timeout(Self::fail(origin, "connect", e))
                } else {
                    DialError::Connect(Self::fail(origin, "connect", e))
                });
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

    /// The connection to `origin`: plain TCP for `http://`; an `https://`
    /// origin is the `tls` module's whole — TLS over TCP where the build
    /// holds the arm, refused before any connection opens where it does not.
    fn connect(&self, origin: &Origin, read_timeout: Duration, budget: Option<Duration>) -> Result<Box<dyn Conn>, DialError> {
        if origin.is_https() {
            return tls::connect(self, origin, read_timeout, budget);
        }
        Ok(Box::new(self.tcp(origin, read_timeout, budget)?))
    }

    /// The request's target and headers held to what this dialer writes as
    /// given (RFC 9112 §3.2, §5): the target visible ASCII alone, a header's
    /// name a token, its value free of CR, LF and NUL — else
    /// [`DialError::Request`], before any connection opens. A target or a
    /// value carrying a line break would end the request line or the header
    /// early and write a header of the bytes' own choosing.
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

    /// The request head's bytes: the daemon refuses a `Content-Length` with
    /// any non-digit, so the length is ASCII decimal and nothing else.
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

/// A connection the dialer writes a request to and reads an answer from —
/// a [`Socket`], or a TLS stream over one.
trait Conn: Read + Write + Send {}
impl Conn for Socket {}

/// A TCP connection under the dialer's bounds: each read and each write
/// carries the per-call bound, and — where the connection serves a frame
/// exchange — the socket's timeout is re-armed before every call to that
/// bound or the time left before the exchange's DEADLINE, whichever is
/// less, a call past the deadline answering `TimedOut` unmade. A TLS stream
/// rides over it, so every read and write the TLS layer makes of the
/// socket is held to the same deadline.
struct Socket {
    tcp: TcpStream,
    read_bound: Duration,
    write_bound: Duration,
    deadline: Option<Instant>,
}

impl Socket {
    /// The timeout for the next call, set where a deadline stands: the
    /// per-call `bound`, cut to the time left.
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
        let (status, headers, body_at) = parse_head(&raw).map_err(|e| DialError::Response(Self::fail(origin, "response", e)))?;
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
        let (mut status, mut headers) = reader.head().map_err(|e| DialError::Response(Self::fail(origin, "response", e)))?;
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
                let (s, h) = reader.head().map_err(|e| DialError::Response(Self::fail(origin, "response", e)))?;
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

/// One whole answer off `conn`, to EOF — or `None` where it runs past `cap`
/// bytes, read no further than the byte past the cap.
fn read_to_close(conn: &mut dyn Read, cap: usize) -> io::Result<Option<Vec<u8>>> {
    let mut raw = Vec::new();
    conn.take(cap as u64 + 1).read_to_end(&mut raw)?;
    Ok((raw.len() <= cap).then_some(raw))
}

/// The status, the headers and where the body begins, out of one response's
/// bytes.
fn parse_head(raw: &[u8]) -> Result<(u16, Headers, usize), String> {
    let sep = raw.windows(4).position(|w| w == b"\r\n\r\n").ok_or_else(|| String::from("no header terminator"))?;
    let head = std::str::from_utf8(&raw[..sep]).map_err(|_| String::from("non-UTF-8 response head"))?;
    let mut lines = head.split("\r\n");
    let status_line = lines.next().ok_or_else(|| String::from("no status line"))?;
    if !status_line.starts_with("HTTP/1.") {
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
    Ok((status, headers, sep + 4))
}

/// A head reader over a connection: reads one response head (through its
/// blank line) and keeps whatever body bytes arrived with it.
struct HeadReader {
    conn: Box<dyn Conn>,
    buffered: Vec<u8>,
}

impl HeadReader {
    fn new(conn: Box<dyn Conn>) -> HeadReader {
        HeadReader { conn, buffered: Vec::new() }
    }

    /// The next head off the connection; the bytes after its blank line
    /// stay buffered for the body (or the next head).
    fn head(&mut self) -> Result<(u16, Headers), String> {
        let mut chunk = [0u8; 4096];
        loop {
            if let Some(sep) = self.buffered.windows(4).position(|w| w == b"\r\n\r\n") {
                let head_bytes: Vec<u8> = self.buffered.drain(..sep + 4).collect();
                let (status, headers, _) = parse_head(&head_bytes)?;
                return Ok((status, headers));
            }
            if self.buffered.len() > 64 * 1024 {
                return Err("response head past 64 KiB".into());
            }
            let n = self.conn.read(&mut chunk).map_err(|e| format!("read: {e}"))?;
            if n == 0 {
                return Err("connection closed before the response head".into());
            }
            self.buffered.extend_from_slice(&chunk[..n]);
        }
    }

    /// The body: the buffered bytes, then the connection to its close.
    fn into_body(self) -> impl Read + Send {
        io::Cursor::new(self.buffered).chain(self.conn)
    }
}

#[cfg(feature = "tls")]
mod tls {
    //! The `https://` arm: rustls over the TCP stream, the server's
    //! certificate judged by the platform's own trust store
    //! (`rustls-platform-verifier`; §9 item 12). The crypto provider is
    //! `ring`, named explicitly so the build's provider never depends on
    //! which features another crate turned on.

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

    /// The TCP connection to `origin`, rustls over it — every socket call the
    /// TLS layer makes held to the connection's deadline, where one stands.
    pub(super) fn connect(dialer: &PlainHttp, origin: &Origin, read_timeout: Duration, budget: Option<Duration>) -> Result<Box<dyn Conn>, DialError> {
        let tcp = dialer.tcp(origin, read_timeout, budget)?;
        let name = ServerName::try_from(origin.dial_host().to_string())
            .map_err(|e| DialError::Tls(PlainHttp::fail(origin, "server name", e)))?;
        let conn = ClientConnection::new(config()?, name).map_err(|e| DialError::Tls(PlainHttp::fail(origin, "tls", e)))?;
        Ok(Box::new(StreamOwned::new(conn, tcp)))
    }
}

#[cfg(not(feature = "tls"))]
mod tls {
    //! Without the feature an `https` origin is a transport this build does
    //! not hold — refused by name before any connection opens: this arm is
    //! handed no stream, so it can never dial in the clear.

    use std::time::Duration;

    use super::{Conn, DialError, Origin, PlainHttp};

    pub(super) fn connect(_dialer: &PlainHttp, _origin: &Origin, _read_timeout: Duration, _budget: Option<Duration>) -> Result<Box<dyn Conn>, DialError> {
        Err(DialError::NotHeld("https".into()))
    }
}
