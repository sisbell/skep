//! THE WIRE, from the client's side: a written-out HTTP/1.1 client over
//! `std::net` ([`Http`]) — skepd speaks one request per connection with
//! `Connection: close` on every response (wire.md §Transport), so a client
//! is a `TcpStream`, one request, and a read to EOF — behind a trait
//! ([`Transport`]) a suite can replay a recorded feed through; and the TYPED
//! READS a mirror makes over it ([`Board`]): the feed's pages (wire.md §The
//! change feed), `/op`, `/op-at` (wire.md §Reading history) and `/chain`,
//! each read COUNTED by kind ([`Reads`]), since what a resolve costs is one
//! of the numbers this crate exists to report.
//!
//! The client speaks plain `http` alone: this crate links no TLS library, so
//! an `https` root in a hint is a transport this build does not hold,
//! refused by name ([`TransportError::NotHeld`]) and never dialed in the
//! clear.

use std::cell::Cell;
use std::fmt;
use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::thread;
use std::time::Duration;

use serde_json::Value;

use crate::origin::Origin;

/// A dead local daemon answers `connection refused` instantly; this bounds
/// the pathological cases (an unroutable address, a filtered port).
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// Per-call read/write bound. A page of the feed or a historical read is at
/// most seconds even on a loaded board; a minute is headroom, not a wait.
const IO_TIMEOUT: Duration = Duration::from_secs(60);

/// How often a `history_busy` or `scan_busy` answer is retried before the
/// read is given up — a retry-class refusal, never a queue (wire.md §Reading
/// history), so the client is the one that waits.
const BUSY_RETRIES: u32 = 200;

/// The pause between two busy retries.
const BUSY_PAUSE: Duration = Duration::from_millis(25);

/// Why an exchange could not be made.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransportError {
    /// The origin's scheme is one this transport does not hold (`https`).
    NotHeld(String),
    /// The host did not resolve to an address.
    Resolve(String),
    /// The connection was refused or timed out.
    Connect(String),
    /// The request could not be written or the response read whole.
    Io(String),
    /// The bytes read were no HTTP response.
    Response(String),
}

impl fmt::Display for TransportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TransportError::NotHeld(scheme) => {
                write!(f, "no transport held for {scheme} origins")
            }
            TransportError::Resolve(e) => write!(f, "resolve: {e}"),
            TransportError::Connect(e) => write!(f, "connect: {e}"),
            TransportError::Io(e) => write!(f, "io: {e}"),
            TransportError::Response(e) => write!(f, "response: {e}"),
        }
    }
}

impl std::error::Error for TransportError {}

/// One exchange with a board: write a request, read the answer whole.
/// `Err` means the board was not reached or did not answer; an answered
/// refusal is a status and a body.
pub trait Transport {
    fn exchange(&self, method: &str, path: &str, body: &[u8]) -> Result<(u16, Vec<u8>), TransportError>;
}

/// The function a mirror dials an origin through: the shipped one is
/// [`dial_http`]; a suite's replays a recording.
pub type Dial<'a> = dyn Fn(&Origin) -> Result<Box<dyn Transport>, TransportError> + 'a;

/// One board's plain-HTTP endpoint: host, port, and the authority string for
/// the `Host` header and error messages.
pub struct Http {
    host: String,
    port: u16,
    authority: String,
}

impl Http {
    /// The transport for `origin`, where it is an `http` origin; an `https`
    /// one is not held.
    pub fn for_origin(origin: &Origin) -> Result<Http, TransportError> {
        if origin.is_https() {
            return Err(TransportError::NotHeld("https".into()));
        }
        let host = origin.host().trim_start_matches('[').trim_end_matches(']').to_string();
        let authority = origin.as_str().trim_start_matches("http://").to_string();
        Ok(Http { host, port: origin.port(), authority })
    }

    /// The authority dialed — host and port as the origin spells them.
    pub fn authority(&self) -> &str {
        &self.authority
    }

    fn fail(&self, what: &str, e: impl fmt::Display) -> String {
        format!("skepd at http://{}: {what}: {e}", self.authority)
    }
}

impl Transport for Http {
    fn exchange(&self, method: &str, path: &str, body: &[u8]) -> Result<(u16, Vec<u8>), TransportError> {
        let addr = (self.host.as_str(), self.port)
            .to_socket_addrs()
            .map_err(|e| TransportError::Resolve(self.fail("resolve", e)))?
            .next()
            .ok_or_else(|| TransportError::Resolve(self.fail("resolve", "no addresses")))?;
        let mut stream = TcpStream::connect_timeout(&addr, CONNECT_TIMEOUT)
            .map_err(|e| TransportError::Connect(self.fail("connect", e)))?;
        stream.set_read_timeout(Some(IO_TIMEOUT)).map_err(|e| TransportError::Io(self.fail("socket", e)))?;
        stream.set_write_timeout(Some(IO_TIMEOUT)).map_err(|e| TransportError::Io(self.fail("socket", e)))?;
        let head = format!(
            "{method} {path} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n",
            self.authority,
            body.len()
        );
        stream
            .write_all(head.as_bytes())
            .and_then(|()| stream.write_all(body))
            .map_err(|e| TransportError::Io(self.fail("write", e)))?;
        let mut raw = Vec::new();
        stream.read_to_end(&mut raw).map_err(|e| TransportError::Io(self.fail("read", e)))?;
        parse_response(&raw).map_err(|e| TransportError::Response(self.fail("response", e)))
    }
}

/// The shipped dial: plain HTTP to the origin.
pub fn dial_http(origin: &Origin) -> Result<Box<dyn Transport>, TransportError> {
    Ok(Box::new(Http::for_origin(origin)?))
}

/// Split status and body out of one complete HTTP response. The daemon
/// always sends `Content-Length`; checking it catches a connection that
/// broke mid-body, which would otherwise surface as truncated JSON.
pub fn parse_response(raw: &[u8]) -> Result<(u16, Vec<u8>), String> {
    let sep = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or_else(|| String::from("no header terminator"))?;
    let head = std::str::from_utf8(&raw[..sep]).map_err(|_| String::from("non-UTF-8 response head"))?;
    let status: u16 = head
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| String::from("malformed status line"))?;
    let mut content_length: Option<usize> = None;
    for line in head.split("\r\n").skip(1) {
        if let Some((k, v)) = line.split_once(':') {
            if k.trim().eq_ignore_ascii_case("Content-Length") {
                content_length = v.trim().parse().ok();
            }
        }
    }
    let mut body = raw[sep + 4..].to_vec();
    if let Some(cl) = content_length {
        if body.len() < cl {
            return Err(format!("truncated body ({} of {cl} bytes)", body.len()));
        }
        body.truncate(cl);
    }
    Ok((status, body))
}

/// THE COUNT OF EVERY READ a board was asked, by kind — the fetch count a
/// resolve's cost is stated in (the investigation §3.1). Reads over `/op-at`
/// are counted under their own kind AND under `op_at`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Reads {
    pub changes: u64,
    pub health: u64,
    pub chain: u64,
    pub read_link: u64,
    pub retrieve: u64,
    pub image: u64,
    pub span_set: u64,
    pub key_set: u64,
    pub find_links: u64,
    pub other: u64,
    pub op_at: u64,
    pub busy_retries: u64,
}

impl Reads {
    /// Every request made (the busy retries not among them: each is a
    /// repeat of one request already counted).
    pub fn total(&self) -> u64 {
        self.changes
            + self.health
            + self.chain
            + self.read_link
            + self.retrieve
            + self.image
            + self.span_set
            + self.key_set
            + self.find_links
            + self.other
    }

    fn count_op(&mut self, op: &str) {
        match op {
            "read_link" => self.read_link += 1,
            "retrieve_v" => self.retrieve += 1,
            "image" => self.image += 1,
            "retrieve_doc_v_span_set" => self.span_set += 1,
            "key_set" => self.key_set += 1,
            "find_links_ftt" | "window_ftt" | "find_links_v" => self.find_links += 1,
            _ => self.other += 1,
        }
    }
}

/// Why a typed read could not be answered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BoardError {
    /// The board was not reached.
    Transport(TransportError),
    /// A status outside the read's shape, with the body.
    Status { status: u16, body: String },
    /// A 200 whose body is not the shape the read expects.
    Malformed(String),
    /// A `rejected` answer: the op, its code and its detail.
    Rejected { op: String, code: String, detail: Option<String> },
    /// `history_busy` or `scan_busy` past the retries.
    Busy,
    /// The feed refused a page past its byte budget, naming the limit that
    /// fits (wire.md §The change feed, Paging).
    PageTooLarge { fits: usize },
    /// The feed's memory does not reach `since` (`history_reclaimed`).
    Reclaimed { floor: Option<u64> },
}

impl fmt::Display for BoardError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BoardError::Transport(e) => write!(f, "{e}"),
            BoardError::Status { status, body } => write!(f, "status {status}: {body}"),
            BoardError::Malformed(what) => write!(f, "malformed answer: {what}"),
            BoardError::Rejected { op, code, detail } => match detail {
                Some(d) => write!(f, "{op} rejected {code}:{d}"),
                None => write!(f, "{op} rejected {code}"),
            },
            BoardError::Busy => f.write_str("the board stayed busy past the retries"),
            BoardError::PageTooLarge { fits } => write!(f, "the page passes the byte budget; {fits} rows fit"),
            BoardError::Reclaimed { floor } => write!(f, "history reclaimed below {floor:?}"),
        }
    }
}

impl std::error::Error for BoardError {}

impl From<TransportError> for BoardError {
    fn from(e: TransportError) -> BoardError {
        BoardError::Transport(e)
    }
}

/// One page of the feed (wire.md §The change feed).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Page {
    /// The entries, oldest first, each as served.
    pub rows: Vec<Value>,
    /// The final entry's position, or `since` echoed when empty.
    pub last: u64,
    /// Whether positions remain past `last`.
    pub more: bool,
    /// The page body's bytes.
    pub bytes: u64,
}

/// A board as the resolver reads it: the typed reads over one
/// [`Transport`], counted.
pub struct Board {
    transport: Box<dyn Transport>,
    reads: Cell<Reads>,
    feed_bytes: Cell<u64>,
}

impl Board {
    pub fn new(transport: Box<dyn Transport>) -> Board {
        Board { transport, reads: Cell::new(Reads::default()), feed_bytes: Cell::new(0) }
    }

    /// Every read made so far, by kind.
    pub fn reads(&self) -> Reads {
        self.reads.get()
    }

    /// The bytes of every feed page read so far.
    pub fn feed_bytes(&self) -> u64 {
        self.feed_bytes.get()
    }

    fn bump(&self, f: impl FnOnce(&mut Reads)) {
        let mut r = self.reads.get();
        f(&mut r);
        self.reads.set(r);
    }

    fn json(body: &[u8]) -> Result<Value, BoardError> {
        serde_json::from_slice(body)
            .map_err(|e| BoardError::Malformed(format!("{e}: {}", String::from_utf8_lossy(body))))
    }

    /// `GET /health`: the board's live pair and auth object.
    pub fn health(&self) -> Result<Value, BoardError> {
        self.bump(|r| r.health += 1);
        let (st, body) = self.transport.exchange("GET", "/health", b"")?;
        if st != 200 {
            return Err(BoardError::Status { status: st, body: String::from_utf8_lossy(&body).into_owned() });
        }
        Board::json(&body)
    }

    /// `GET /changes?since=N[&limit=L]` as the guest: one page.
    pub fn changes(&self, since: u64, limit: Option<usize>) -> Result<Page, BoardError> {
        self.bump(|r| r.changes += 1);
        let path = match limit {
            Some(l) => format!("/changes?since={since}&limit={l}"),
            None => format!("/changes?since={since}"),
        };
        let (st, body) = self.transport.exchange("GET", &path, b"")?;
        let text = || String::from_utf8_lossy(&body).into_owned();
        match st {
            200 => {}
            400 => {
                let v = Board::json(&body)?;
                if let Some(fits) = v["fits"].as_u64() {
                    return Err(BoardError::PageTooLarge { fits: fits as usize });
                }
                return Err(BoardError::Status { status: st, body: text() });
            }
            410 => {
                let v = Board::json(&body)?;
                return Err(BoardError::Reclaimed { floor: v["floor"].as_u64() });
            }
            _ => return Err(BoardError::Status { status: st, body: text() }),
        }
        self.feed_bytes.set(self.feed_bytes.get() + body.len() as u64);
        let v = Board::json(&body)?;
        let rows = v["changes"].as_array().cloned().ok_or_else(|| BoardError::Malformed("no changes".into()))?;
        let last = v["last"].as_u64().ok_or_else(|| BoardError::Malformed("no last".into()))?;
        let more = v["more"].as_bool().ok_or_else(|| BoardError::Malformed("no more".into()))?;
        Ok(Page { rows, last, more, bytes: body.len() as u64 })
    }

    /// `POST /op` as the guest: the answer as served, a `rejected` included
    /// (a caller that cannot take one asks [`Board::op_ok`]).
    pub fn op(&self, frame: &Value) -> Result<Value, BoardError> {
        let op = frame["op"].as_str().unwrap_or("").to_string();
        self.bump(|r| r.count_op(&op));
        self.post_json("/op", &frame.to_string(), &op)
    }

    /// [`Board::op`], a `rejected` answer an error.
    pub fn op_ok(&self, frame: &Value) -> Result<Value, BoardError> {
        let v = self.op(frame)?;
        Board::not_rejected(v)
    }

    /// `POST /op-at` as the guest: `frame` answered AS OF `at` (wire.md
    /// §Reading history), `history_busy` retried.
    pub fn op_at(&self, at: u64, frame: &Value) -> Result<Value, BoardError> {
        let op = frame["op"].as_str().unwrap_or("").to_string();
        self.bump(|r| {
            r.count_op(&op);
            r.op_at += 1;
        });
        let body = format!(r#"{{"at":{at},"frame":{frame}}}"#);
        self.post_json("/op-at", &body, &op)
    }

    /// [`Board::op_at`], a `rejected` answer an error.
    pub fn op_at_ok(&self, at: u64, frame: &Value) -> Result<Value, BoardError> {
        let v = self.op_at(at, frame)?;
        Board::not_rejected(v)
    }

    fn not_rejected(v: Value) -> Result<Value, BoardError> {
        if v["resp"].as_str() == Some("rejected") {
            return Err(BoardError::Rejected {
                op: v["op"].as_str().unwrap_or("").to_string(),
                code: v["code"].as_str().unwrap_or("").to_string(),
                detail: v["detail"].as_str().map(str::to_string),
            });
        }
        Ok(v)
    }

    /// One POST of a JSON body, the busy refusals retried.
    fn post_json(&self, path: &str, body: &str, op: &str) -> Result<Value, BoardError> {
        let mut tries = 0;
        loop {
            let (st, answer) = self.transport.exchange("POST", path, body.as_bytes())?;
            let text = || String::from_utf8_lossy(&answer).into_owned();
            match st {
                200 => return Board::json(&answer),
                410 => {
                    let v = Board::json(&answer)?;
                    return Err(BoardError::Reclaimed { floor: v["floor"].as_u64() });
                }
                503 => {
                    let busy = text().contains("history_busy") || text().contains("scan_busy");
                    if busy && tries < BUSY_RETRIES {
                        tries += 1;
                        self.bump(|r| r.busy_retries += 1);
                        thread::sleep(BUSY_PAUSE);
                        continue;
                    }
                    return Err(if busy { BoardError::Busy } else { BoardError::Status { status: st, body: text() } });
                }
                _ => {
                    return Err(BoardError::Status {
                        status: st,
                        body: format!("{op}: {}", text()),
                    })
                }
            }
        }
    }

    /// `GET /chain?at=N`: the commit chain's value as of `at`, recomputed by
    /// the board (wire.md §Reading history) — `(at, chain)`.
    pub fn chain_at(&self, at: u64) -> Result<(u64, [u8; 32]), BoardError> {
        self.bump(|r| r.chain += 1);
        let mut tries = 0;
        loop {
            let (st, body) = self.transport.exchange("GET", &format!("/chain?at={at}"), b"")?;
            let text = String::from_utf8_lossy(&body).into_owned();
            match st {
                200 => {
                    let v = Board::json(&body)?;
                    let at = v["at"].as_u64().ok_or_else(|| BoardError::Malformed("no at".into()))?;
                    let hex = v["chain"].as_str().ok_or_else(|| BoardError::Malformed("no chain".into()))?;
                    let chain = parse_chain(hex).ok_or_else(|| BoardError::Malformed(format!("chain {hex}")))?;
                    return Ok((at, chain));
                }
                503 if text.contains("history_busy") && tries < BUSY_RETRIES => {
                    tries += 1;
                    self.bump(|r| r.busy_retries += 1);
                    thread::sleep(BUSY_PAUSE);
                }
                503 if text.contains("history_busy") => return Err(BoardError::Busy),
                _ => return Err(BoardError::Status { status: st, body: text }),
            }
        }
    }
}

/// Sixty-four lowercase hex characters as the chain's thirty-two bytes.
pub fn parse_chain(hex: &str) -> Option<[u8; 32]> {
    if hex.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).ok()?;
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn response_parse() {
        let (st, body) = parse_response(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}").expect("parse");
        assert_eq!((st, body.as_slice()), (200, &b"{}"[..]));
        assert!(parse_response(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n{}").is_err(), "a short body is a broken connection");
        assert!(parse_response(b"garbage").is_err());
    }

    /// An `https` root is a transport this build does not hold, refused by
    /// name; an `http` one is dialed at its host and port.
    #[test]
    fn https_is_not_held_and_http_is() {
        let o = Origin::parse("https://registry.example").unwrap();
        assert_eq!(Http::for_origin(&o).err(), Some(TransportError::NotHeld("https".into())));
        let o = Origin::parse("http://[::1]:8642").unwrap();
        let h = Http::for_origin(&o).expect("held");
        assert_eq!((h.host.as_str(), h.port, h.authority()), ("::1", 8642, "[::1]:8642"));
    }

    #[test]
    fn chain_hex_parses_at_sixty_four_characters_alone() {
        assert!(parse_chain(&"ab".repeat(32)).is_some());
        assert!(parse_chain(&"ab".repeat(31)).is_none());
        assert!(parse_chain(&"zz".repeat(32)).is_none());
    }
}
