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
//! Timeouts: connect 5 s, read/write 10 s for the FRAMES (skep-mcp's
//! constants — a skepd op is milliseconds even under fsync); the STREAMED
//! form's read timeout scales with the declared size (ps3-14 (c)).
//!
//! `https://` is the `tls` feature's arm — rustls with the platform verifier
//! (§9 item 12) — OFF in the library and ON in the `skep` binary; without
//! the feature an `https` origin is [`DialError::NotHeld`], refused before
//! any connection opens and never dialed in the clear.

use std::fmt;
use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::sync::Arc;
use std::time::Duration;

use crate::origin::Origin;

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
}

impl fmt::Display for DialError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DialError::NotHeld(scheme) => write!(
                f,
                "no transport held for {scheme} origins in this build (the `tls` feature is off)"
            ),
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
}

impl Default for PlainHttp {
    fn default() -> PlainHttp {
        PlainHttp { connect_timeout: CONNECT_TIMEOUT, io_timeout: IO_TIMEOUT }
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
    /// tried in order within the connect bound, the timeouts set.
    fn tcp(&self, origin: &Origin, read_timeout: Duration) -> Result<TcpStream, DialError> {
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
        Ok(stream)
    }

    /// The connection to `origin`: plain TCP for `http://`; an `https://`
    /// origin is the `tls` module's whole — TLS over TCP where the build
    /// holds the arm, refused before any connection opens where it does not.
    fn connect(&self, origin: &Origin, read_timeout: Duration) -> Result<Box<dyn Conn>, DialError> {
        if origin.is_https() {
            return tls::connect(self, origin, read_timeout);
        }
        Ok(Box::new(self.tcp(origin, read_timeout)?))
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
/// a `TcpStream`, or a TLS stream over one.
trait Conn: Read + Write + Send {}
impl Conn for TcpStream {}

impl Dialer for PlainHttp {
    fn exchange(&self, origin: &Origin, req: &Request) -> Result<Response, DialError> {
        let mut conn = self.connect(origin, self.io_timeout)?;
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
        let declared = head.content_length.unwrap_or(0);
        let read_timeout = self.io_timeout + Duration::from_secs(declared / STREAM_BYTES_PER_SECOND);
        let mut conn = self.connect(origin, read_timeout)?;
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

    use super::{Conn, DialError, Origin, PlainHttp};
    use std::net::TcpStream;

    impl Conn for StreamOwned<ClientConnection, TcpStream> {}

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

    /// The TCP connection to `origin`, rustls over it.
    pub(super) fn connect(dialer: &PlainHttp, origin: &Origin, read_timeout: Duration) -> Result<Box<dyn Conn>, DialError> {
        let tcp = dialer.tcp(origin, read_timeout)?;
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

    pub(super) fn connect(_dialer: &PlainHttp, _origin: &Origin, _read_timeout: Duration) -> Result<Box<dyn Conn>, DialError> {
        Err(DialError::NotHeld("https".into()))
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write;
    use std::net::TcpListener;
    use std::thread;

    use super::*;

    /// A response splits into status, headers and body; a body short of its
    /// `Content-Length` is a broken connection; garbage is no response.
    #[test]
    fn a_response_parses_and_a_short_body_is_a_break() {
        let (st, headers, at) = parse_head(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nSkepd-Session: closed\r\n\r\n{}").expect("parse");
        assert_eq!((st, at), (200, 61));
        assert_eq!(headers.get("skepd-session"), Some("closed"));
        assert!(parse_head(b"garbage").is_err());
        let resp = Response { status: 200, headers, body: b"{}".to_vec() };
        assert!(resp.session_closed());
    }

    /// The answer cap: read no further than the byte past it.
    #[test]
    fn an_answer_past_the_cap_is_read_no_further() {
        assert_eq!(read_to_close(&mut &[7u8; 10][..], 10).unwrap(), Some(vec![7u8; 10]));
        assert_eq!(read_to_close(&mut &[7u8; 11][..], 10).unwrap(), None);
    }

    /// One whole request off `s`: the head to its blank line, then exactly
    /// the body its `Content-Length` declares. The dialer writes the head
    /// and the body in two calls, so a single `read` may answer with the
    /// head alone and the body still in flight.
    fn read_request(s: &mut TcpStream) -> String {
        let mut got = Vec::new();
        let mut buf = [0u8; 4096];
        let body_at = loop {
            let n = s.read(&mut buf).unwrap();
            assert!(n > 0, "the peer closed before the head's blank line");
            got.extend_from_slice(&buf[..n]);
            if let Some(i) = got.windows(4).position(|w| w == b"\r\n\r\n") {
                break i + 4;
            }
        };
        let declared: usize = String::from_utf8_lossy(&got[..body_at])
            .lines()
            .find_map(|l| l.strip_prefix("Content-Length: ").map(|v| v.trim().parse().unwrap()))
            .unwrap_or(0);
        while got.len() < body_at + declared {
            let n = s.read(&mut buf).unwrap();
            assert!(n > 0, "the peer closed before the declared body was in");
            got.extend_from_slice(&buf[..n]);
        }
        String::from_utf8_lossy(&got).to_string()
    }

    /// One request, one connection, `Connection: close`, the `Host` the
    /// authority with brackets kept, no redirect followed — against a
    /// listener that answers a redirect and a short body.
    #[test]
    fn the_plain_arm_writes_one_head_and_checks_the_length() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = thread::spawn(move || {
            let mut heads = Vec::new();
            for answer in [
                "HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1:1/\r\nContent-Length: 2\r\n\r\nok".to_string(),
                "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n{}".to_string(),
            ] {
                let (mut s, _) = listener.accept().unwrap();
                heads.push(read_request(&mut s));
                s.write_all(answer.as_bytes()).unwrap();
            }
            heads
        });
        let origin = Origin::parse(&format!("http://127.0.0.1:{port}")).unwrap();
        let dialer = PlainHttp::new();
        let resp = dialer.exchange(&origin, &Request::post("/op", b"{}".to_vec()).header("Skepd-Session", "abc")).unwrap();
        assert_eq!((resp.status, resp.body.as_slice()), (302, &b"ok"[..]), "a redirect is an answer, never followed");
        let err = dialer.exchange(&origin, &Request::get("/health")).unwrap_err();
        assert_eq!(err, DialError::Truncated { declared: 5, got: 2 });
        let heads = server.join().unwrap();
        assert!(heads[0].starts_with("POST /op HTTP/1.1\r\n"), "{}", heads[0]);
        assert!(heads[0].contains(&format!("Host: 127.0.0.1:{port}\r\n")));
        assert!(heads[0].contains("Connection: close\r\n"));
        assert!(heads[0].contains("Content-Length: 2\r\n"));
        assert!(heads[0].contains("Skepd-Session: abc\r\n"));
        assert!(heads[0].ends_with("\r\n\r\n{}"));
        assert!(heads[1].starts_with("GET /health HTTP/1.1\r\n"));
        assert!(!heads[1].contains("Content-Type"), "a bodiless GET declares no content type");
    }

    /// The streamed form: `Expect: 100-continue` on the head where a body
    /// follows, the interim head handed on before any body byte, the body
    /// written after it, the final head returned with a reader over its body.
    #[test]
    fn the_streamed_form_waits_for_the_interim_head_before_the_body() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = thread::spawn(move || {
            let (mut s, _) = listener.accept().unwrap();
            let mut buf = vec![0u8; 4096];
            let mut got = Vec::new();
            loop {
                let n = s.read(&mut buf).unwrap();
                got.extend_from_slice(&buf[..n]);
                if got.windows(4).any(|w| w == b"\r\n\r\n") {
                    break;
                }
            }
            let head = String::from_utf8_lossy(&got).to_string();
            assert!(!head.contains("hello"), "no body byte before the interim head");
            s.write_all(b"HTTP/1.1 100 Continue\r\nUpload-Id: u1\r\n\r\n").unwrap();
            let mut body = vec![0u8; 5];
            s.read_exact(&mut body).unwrap();
            assert_eq!(&body, b"hello");
            s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\ndone").unwrap();
            head
        });
        let origin = Origin::parse(&format!("http://127.0.0.1:{port}")).unwrap();
        let head = RequestHead { method: Method::Post, path: "/blob/upload?length=5".into(), headers: vec![], content_length: Some(5) };
        let mut interim = Vec::new();
        let mut body = &b"hello"[..];
        let resp = PlainHttp::new().stream(&origin, &head, &mut body, &mut |h: &Headers| interim.push(h.get("Upload-Id").map(str::to_string))).unwrap();
        assert_eq!(resp.status, 200);
        let mut out = String::new();
        let mut reader = resp.body;
        reader.read_to_string(&mut out).unwrap();
        assert_eq!(out, "done");
        assert_eq!(interim, vec![Some("u1".to_string())]);
        let sent = server.join().unwrap();
        assert!(sent.contains("Expect: 100-continue\r\n"), "{sent}");
    }

    /// The plaintext warning fires on a plaintext non-loopback origin alone.
    #[test]
    fn the_plaintext_warning_keys_on_scheme_and_host() {
        assert!(plaintext_non_loopback_warning(&Origin::parse("http://127.0.0.1:8642").unwrap()).is_none());
        assert!(plaintext_non_loopback_warning(&Origin::parse("https://board.example").unwrap()).is_none());
        assert!(plaintext_non_loopback_warning(&Origin::parse("http://board.example:8642").unwrap()).is_some());
    }

    /// Without the `tls` arm an `https` origin is refused BY NAME BEFORE ANY
    /// CONNECTION OPENS: a listening port and a closed one answer the same
    /// refusal in both forms of the dial, and nothing reaches the listener.
    #[cfg(not(feature = "tls"))]
    #[test]
    fn an_https_origin_without_the_tls_arm_is_refused_before_any_connection() {
        let listening = TcpListener::bind("127.0.0.1:0").unwrap();
        listening.set_nonblocking(true).unwrap();
        let open = listening.local_addr().unwrap().port();
        let closed = TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
        let https = |port: u16| Origin::parse(&format!("https://127.0.0.1:{port}")).unwrap();
        let not_held = DialError::NotHeld("https".into());
        for port in [open, closed] {
            assert_eq!(PlainHttp::new().exchange(&https(port), &Request::get("/health")).unwrap_err(), not_held, "port {port}");
        }
        let head = RequestHead { method: Method::Get, path: "/events".into(), headers: Vec::new(), content_length: None };
        assert_eq!(PlainHttp::new().stream(&https(open), &head, &mut io::empty(), &mut |_: &Headers| {}).unwrap_err(), not_held);
        let deadline = std::time::Instant::now() + Duration::from_millis(200);
        while std::time::Instant::now() < deadline {
            match listening.accept() {
                Ok((_, peer)) => panic!("a connection from {peer} reached the listener"),
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => thread::sleep(Duration::from_millis(10)),
                Err(e) => panic!("accept: {e}"),
            }
        }
    }

    /// With the `tls` arm an `https` origin puts no plaintext on the wire:
    /// what reaches a plain listener is a TLS record or nothing — never a
    /// request line, never the session header.
    #[cfg(feature = "tls")]
    #[test]
    fn an_https_origin_puts_no_plaintext_request_on_the_wire() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = thread::spawn(move || {
            let (mut s, _) = listener.accept().unwrap();
            s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
            let mut got = vec![0u8; 16 * 1024];
            let n = s.read(&mut got).unwrap_or(0);
            got.truncate(n);
            got
        });
        let origin = Origin::parse(&format!("https://127.0.0.1:{port}")).unwrap();
        let req = Request::post("/op", b"{}".to_vec()).header("Skepd-Session", "9f3a6c21d4b8e07a5c1b2d4e6f708192");
        PlainHttp::new().exchange(&origin, &req).expect_err("no TLS server answers");
        let got = server.join().unwrap();
        assert!(!got.windows(8).any(|w| w == b"HTTP/1.1") && !got.windows(13).any(|w| w == b"Skepd-Session"), "plaintext on the wire: {got:?}");
        assert!(got.first().is_none_or(|b| *b == 0x16), "not a TLS handshake record: {got:?}");
    }
}
