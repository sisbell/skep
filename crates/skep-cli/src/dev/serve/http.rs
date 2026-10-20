//! The provider's own HTTP, over the plain HTTP/1.1 subset of `skep-http`.
//!
//! The subset is the one `skep-http` reads and writes for it — one request
//! per connection, the head scanned for its terminator under a cap, the
//! body read to its `Content-Length` under a cap, no chunked bodies,
//! `Connection: close` on every answer — a subset in the shape of the
//! daemon's (`skepd`'s `server/http.rs`, whose pattern it follows and which
//! calls none of it). What is the provider's own stays here: the read and
//! write timeouts; the two caps it reads a request under, [`MAX_HEAD`] and
//! [`MAX_BODY`], handed to `skep_http::read_request`; and the event
//! stream's framing — `event: <name>` and `data: <json>` and a blank line,
//! the keep-alive comment every [`KEEPALIVE`]. Every response carries the
//! CORS headers for the one origin and never `*` ([`cors_headers`]): the
//! provider's session is ambient to any page that can reach its port, and
//! the daemon's reasoning for `*` does not transfer (the dev provider
//! record §3.2).

use std::io::{self, Write};
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

/// The event stream's keep-alive, the daemon's own cadence.
///
/// It is a comment line every fifteen seconds of silence.
pub const KEEPALIVE: Duration = Duration::from_secs(15);

/// Returns the CORS headers for the one origin.
///
/// They are the origin itself and never `*`, the secret header and the
/// content type allowed, the three methods, and `Vary: Origin` so no cache
/// serves one page's answer to another.
pub fn cors_headers(origin: &str) -> Vec<(String, String)> {
    vec![
        ("Access-Control-Allow-Origin".into(), origin.to_string()),
        ("Access-Control-Allow-Headers".into(), format!("Content-Type, {SECRET_HEADER}")),
        ("Access-Control-Allow-Methods".into(), "GET, POST, OPTIONS".into()),
        ("Access-Control-Max-Age".into(), "600".into()),
        ("Vary".into(), "Origin".into()),
    ]
}

/// Writes the event stream's head.
///
/// It is `text/event-stream`, no length, the CORS headers.
///
/// # Errors
///
/// Returns the I/O error the write or its flush meets.
pub fn write_sse_head(stream: &mut TcpStream, headers: &[(String, String)]) -> io::Result<()> {
    let mut head = String::from("HTTP/1.1 200 OK\r\n");
    for (k, v) in headers {
        head.push_str(&format!("{k}: {v}\r\n"));
    }
    head.push_str("Content-Type: text/event-stream\r\nCache-Control: no-cache\r\nConnection: close\r\n\r\n");
    stream.write_all(head.as_bytes())?;
    stream.flush()
}

/// Writes one event: `event: <name>`, `data: <json>`, a blank line.
///
/// # Errors
///
/// Returns the I/O error the write or its flush meets.
pub fn write_sse_event(stream: &mut TcpStream, name: &str, data: &str) -> io::Result<()> {
    stream.write_all(format!("event: {name}\ndata: {data}\n\n").as_bytes())?;
    stream.flush()
}

/// Writes the keep-alive comment and its blank line.
///
/// # Errors
///
/// Returns the I/O error the write or its flush meets.
pub fn write_sse_keepalive(stream: &mut TcpStream) -> io::Result<()> {
    stream.write_all(b":ka\n\n")?;
    stream.flush()
}
