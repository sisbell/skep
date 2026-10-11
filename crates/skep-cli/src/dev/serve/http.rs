//! THE HTTP/1.1 SUBSET the provider speaks, in the shape of the daemon's
//! (`skepd`'s `server/http.rs`, the pattern copied and never called): one
//! request per connection, read and write timeouts, the head scanned for
//! its terminator under a cap, the body read to its `Content-Length` under
//! a cap, no chunked bodies, `Connection: close` on every answer; and the
//! event stream's framing — `event: <name>` and `data: <json>` and a blank
//! line, the keep-alive comment every [`KEEPALIVE`]. Every response carries
//! the CORS headers for THE ONE ORIGIN and never `*` ([`cors_headers`]): the
//! provider's session is ambient to any page that can reach its port, and
//! the daemon's reasoning for `*` does not transfer (the dev provider
//! record §3.2).

use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::time::Duration;

use super::admission::SECRET_HEADER;

/// The socket's read deadline per call: a stalled page releases its thread.
pub const READ_TIMEOUT: Duration = Duration::from_secs(30);

/// The socket's write deadline per call.
pub const WRITE_TIMEOUT: Duration = Duration::from_secs(30);

/// The request head's cap: a token, an origin and a few headers are small.
pub const MAX_HEAD: usize = 64 * 1024;

/// The request body's cap: the frame routes' 8 MiB and room beside it.
pub const MAX_BODY: usize = 16 * 1024 * 1024;

/// The event stream's keep-alive: a comment line every fifteen seconds of
/// silence, the daemon's own cadence.
pub const KEEPALIVE: Duration = Duration::from_secs(15);

/// One request: the method, the path, the query, the headers and the body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    pub method: String,
    pub path: String,
    pub query: Option<String>,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Request {
    /// The first header named `name`, case-insensitively.
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.iter().find(|(k, _)| k.eq_ignore_ascii_case(name)).map(|(_, v)| v.as_str())
    }

    /// The query member `key`'s value, where the query names one.
    pub fn query_value(&self, key: &str) -> Option<&str> {
        self.query.as_deref()?.split('&').find_map(|pair| {
            let (k, v) = pair.split_once('=')?;
            (k == key).then_some(v)
        })
    }
}

/// A request refused at the HTTP layer: the subset's refusal, or a body
/// past the cap.
#[derive(Debug)]
pub enum Refused {
    Malformed(String),
    TooLarge { declared: usize, cap: usize },
}

/// THE READ: the head to its terminator under the cap, the body to its
/// `Content-Length` under its cap; `None` for a clean close before any
/// byte — a port probe, the stop's wake connect.
pub fn read_request(stream: &mut TcpStream) -> Result<Option<Request>, Refused> {
    let mut buf: Vec<u8> = Vec::with_capacity(1024);
    let mut scanned = 0usize;
    let head_end = loop {
        if let Some(i) = buf[scanned..].windows(4).position(|w| w == b"\r\n\r\n") {
            break scanned + i;
        }
        scanned = buf.len().saturating_sub(3);
        if buf.len() > MAX_HEAD {
            return Err(Refused::Malformed(format!("the request head exceeds the {MAX_HEAD}-byte cap")));
        }
        let mut chunk = [0u8; 4096];
        match stream.read(&mut chunk) {
            Ok(0) if buf.is_empty() => return Ok(None),
            Ok(0) => return Err(Refused::Malformed("the connection closed inside the request head".into())),
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
            Err(_) if buf.is_empty() => return Ok(None),
            Err(e) => return Err(Refused::Malformed(format!("read: {e}"))),
        }
    };
    let head = std::str::from_utf8(&buf[..head_end]).map_err(|_| Refused::Malformed("the request head is not UTF-8".into()))?;
    let mut lines = head.split("\r\n");
    let request_line = lines.next().unwrap_or("");
    let mut parts = request_line.split(' ');
    let method = parts.next().unwrap_or("").to_string();
    let target = parts.next().ok_or_else(|| Refused::Malformed("the request line lacks a target".into()))?.to_string();
    let version = parts.next().ok_or_else(|| Refused::Malformed("the request line lacks an HTTP version".into()))?;
    if parts.next().is_some() || (version != "HTTP/1.1" && version != "HTTP/1.0") {
        return Err(Refused::Malformed("a malformed request line".into()));
    }
    if method.is_empty() || !method.bytes().all(|b| b.is_ascii_uppercase()) {
        return Err(Refused::Malformed("a malformed method token".into()));
    }
    let mut headers = Vec::new();
    let mut content_length: Option<usize> = None;
    for line in lines {
        if line.is_empty() {
            continue;
        }
        let (name, value) = line.split_once(':').ok_or_else(|| Refused::Malformed(format!("a malformed header line `{line}`")))?;
        let (name, value) = (name.trim(), value.trim());
        if name.eq_ignore_ascii_case("Content-Length") {
            if content_length.is_some() {
                return Err(Refused::Malformed("Content-Length given twice".into()));
            }
            if value.is_empty() || !value.bytes().all(|b| b.is_ascii_digit()) {
                return Err(Refused::Malformed(format!("a bad Content-Length `{value}`")));
            }
            content_length = Some(value.parse().map_err(|_| Refused::Malformed(format!("a bad Content-Length `{value}`")))?);
        } else if name.eq_ignore_ascii_case("Transfer-Encoding") {
            return Err(Refused::Malformed("chunked request bodies are unsupported; send Content-Length".into()));
        }
        headers.push((name.to_string(), value.to_string()));
    }
    let (path, query) = match target.split_once('?') {
        Some((p, q)) => (p.to_string(), Some(q.to_string())),
        None => (target, None),
    };
    let declared = content_length.unwrap_or(0);
    if declared > MAX_BODY {
        return Err(Refused::TooLarge { declared, cap: MAX_BODY });
    }
    let mut body = buf[head_end + 4..].to_vec();
    while body.len() < declared {
        let mut chunk = [0u8; 8192];
        match stream.read(&mut chunk) {
            Ok(0) => return Err(Refused::Malformed("the connection closed inside the request body".into())),
            Ok(n) => body.extend_from_slice(&chunk[..n]),
            Err(e) => return Err(Refused::Malformed(format!("read: {e}"))),
        }
    }
    body.truncate(declared);
    Ok(Some(Request { method, path, query, headers, body }))
}

/// THE CORS HEADERS for the one origin: the origin itself and never `*`,
/// the secret header and the content type allowed, the three methods, and
/// `Vary: Origin` so no cache serves one page's answer to another.
pub fn cors_headers(origin: &str) -> Vec<(String, String)> {
    vec![
        ("Access-Control-Allow-Origin".into(), origin.to_string()),
        ("Access-Control-Allow-Headers".into(), format!("Content-Type, {SECRET_HEADER}")),
        ("Access-Control-Allow-Methods".into(), "GET, POST, OPTIONS".into()),
        ("Access-Control-Max-Age".into(), "600".into()),
        ("Vary".into(), "Origin".into()),
    ]
}

/// The reason phrase for the statuses this provider answers.
fn reason(status: u16) -> &'static str {
    match status {
        200 => "OK",
        204 => "No Content",
        400 => "Bad Request",
        403 => "Forbidden",
        404 => "Not Found",
        413 => "Payload Too Large",
        _ => "OK",
    }
}

/// THE HEAD of a response: the status, every header given, the content
/// type where one is named, the length where the body's is known, and
/// `Connection: close`.
pub fn write_head(stream: &mut TcpStream, status: u16, headers: &[(String, String)], content_type: Option<&str>, content_length: Option<usize>) -> io::Result<()> {
    let mut head = format!("HTTP/1.1 {status} {}\r\n", reason(status));
    for (k, v) in headers {
        head.push_str(&format!("{k}: {v}\r\n"));
    }
    if let Some(ct) = content_type {
        head.push_str(&format!("Content-Type: {ct}\r\n"));
    }
    if let Some(n) = content_length {
        head.push_str(&format!("Content-Length: {n}\r\n"));
    }
    head.push_str("Cache-Control: no-store\r\nConnection: close\r\n\r\n");
    stream.write_all(head.as_bytes())
}

/// ONE WHOLE RESPONSE: the head with the body's length, then the body.
pub fn write_response(stream: &mut TcpStream, status: u16, headers: &[(String, String)], content_type: Option<&str>, body: &[u8]) -> io::Result<()> {
    write_head(stream, status, headers, content_type, Some(body.len()))?;
    stream.write_all(body)?;
    stream.flush()
}

/// The event stream's head: `text/event-stream`, no length, the CORS
/// headers.
pub fn write_sse_head(stream: &mut TcpStream, headers: &[(String, String)]) -> io::Result<()> {
    let mut head = String::from("HTTP/1.1 200 OK\r\n");
    for (k, v) in headers {
        head.push_str(&format!("{k}: {v}\r\n"));
    }
    head.push_str("Content-Type: text/event-stream\r\nCache-Control: no-cache\r\nConnection: close\r\n\r\n");
    stream.write_all(head.as_bytes())?;
    stream.flush()
}

/// One event: `event: <name>`, `data: <json>`, a blank line.
pub fn write_sse_event(stream: &mut TcpStream, name: &str, data: &str) -> io::Result<()> {
    stream.write_all(format!("event: {name}\ndata: {data}\n\n").as_bytes())?;
    stream.flush()
}

/// The keep-alive comment and its blank line.
pub fn write_sse_keepalive(stream: &mut TcpStream) -> io::Result<()> {
    stream.write_all(b":ka\n\n")?;
    stream.flush()
}
