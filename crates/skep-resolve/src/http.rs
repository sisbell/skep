//! THE WIRE, from the client's side: a written-out HTTP/1.1 client over
//! `std::net` ([`Http`]) — skepd speaks one request per connection with
//! `Connection: close` on every response (wire.md §Transport), so a client
//! is a `TcpStream`, one request, and a read to EOF — behind a trait
//! ([`Transport`]) the board's typed reads ([`crate::board`]) run over and a
//! suite can replay a recorded feed through.
//!
//! The client speaks plain `http` alone: this crate links no TLS library, so
//! an `https` root in a hint is a transport this build does not hold,
//! refused by name ([`TransportError::NotHeld`]) and never dialed in the
//! clear.

use std::fmt;
use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::Duration;

use crate::origin::Origin;

/// A dead local daemon answers `connection refused` instantly; this bounds
/// the pathological cases (an unroutable address, a filtered port).
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// Per-call read/write bound. A page of the feed or a historical read is at
/// most seconds even on a loaded board; a minute is headroom, not a wait.
const IO_TIMEOUT: Duration = Duration::from_secs(60);

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
fn parse_response(raw: &[u8]) -> Result<(u16, Vec<u8>), String> {
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
}
