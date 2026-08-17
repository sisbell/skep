//! Shared test plumbing: spawn a real daemon on an ephemeral port and speak
//! HTTP/1.1 to it over a plain TcpStream (`Connection: close`, read to EOF)
//! — the transport is the thing under test, so no client library sits in
//! the middle.

#![allow(dead_code)]

use std::io::{ErrorKind, Read, Write};
use std::net::TcpStream;
use std::path::Path;
use std::time::{Duration, Instant};

use serde_json::Value;
use skepd::{serve, Daemon, Skepd};

pub fn spawn(dir: &Path) -> Skepd {
    let daemon = Daemon::open(dir).expect("daemon open (genesis or recover)");
    serve(daemon, 0, 4).expect("bind an ephemeral port")
}

/// Client-side socket deadline: a daemon that wedges must fail the exchange
/// loudly (panic with context) rather than hang the whole gate, whose log
/// would then carry no failure name at all. Generous — a healthy op is
/// milliseconds even under fsync.
const HTTP_TIMEOUT: Duration = Duration::from_secs(30);

/// One HTTP exchange; returns (status, headers, body bytes).
pub fn http_full(
    port: u16,
    method: &str,
    path: &str,
    session: Option<&str>,
    body: &[u8],
) -> (u16, Vec<(String, String)>, Vec<u8>) {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).expect("connect to skepd");
    stream.set_read_timeout(Some(HTTP_TIMEOUT)).expect("read timeout");
    stream.set_write_timeout(Some(HTTP_TIMEOUT)).expect("write timeout");
    let mut head = format!(
        "{method} {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\nContent-Length: {}\r\n",
        body.len()
    );
    if let Some(tok) = session {
        head.push_str(&format!("Skepd-Session: {tok}\r\n"));
    }
    head.push_str("Content-Type: application/json\r\n\r\n");
    stream.write_all(head.as_bytes()).expect("write request head");
    stream.write_all(body).expect("write request body");
    let mut raw = Vec::new();
    stream.read_to_end(&mut raw).expect("read response");
    let sep = raw.windows(4).position(|w| w == b"\r\n\r\n").expect("header/body separator");
    let head = std::str::from_utf8(&raw[..sep]).expect("ascii response head");
    let mut lines = head.split("\r\n");
    let status: u16 = lines
        .next()
        .expect("status line")
        .split_whitespace()
        .nth(1)
        .expect("status code in the status line")
        .parse()
        .expect("numeric status");
    let headers = lines
        .filter_map(|l| l.split_once(':'))
        .map(|(k, v)| (k.trim().to_string(), v.trim().to_string()))
        .collect();
    (status, headers, raw[sep + 4..].to_vec())
}

/// One HTTP exchange; returns (status, body bytes).
pub fn http(
    port: u16,
    method: &str,
    path: &str,
    session: Option<&str>,
    body: &[u8],
) -> (u16, Vec<u8>) {
    let (status, _headers, body) = http_full(port, method, path, session, body);
    (status, body)
}

/// Case-insensitive response-header lookup.
pub fn header<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.as_str())
}

pub fn options(port: u16, path: &str) -> (u16, Vec<(String, String)>, Vec<u8>) {
    http_full(port, "OPTIONS", path, None, b"")
}

pub fn get(port: u16, path: &str) -> (u16, Vec<u8>) {
    http(port, "GET", path, None, b"")
}

pub fn json(bytes: &[u8]) -> Value {
    serde_json::from_slice(bytes)
        .unwrap_or_else(|e| panic!("non-JSON body ({e}): {}", String::from_utf8_lossy(bytes)))
}

pub fn open_session(port: u16, principal: u64) -> String {
    let body = format!("{{\"principal\":{principal}}}");
    let (st, resp) = http(port, "POST", "/session", None, body.as_bytes());
    assert_eq!(st, 200, "session open failed: {}", String::from_utf8_lossy(&resp));
    json(&resp)["session"].as_str().expect("session token").to_string()
}

/// POST one op frame; transport must succeed (200) — the returned document
/// may still be a rejection, which callers assert on.
pub fn op(port: u16, session: Option<&str>, frame: &str) -> Value {
    let (st, body) = http(port, "POST", "/op", session, frame.as_bytes());
    assert_eq!(st, 200, "op transport failed: {}", String::from_utf8_lossy(&body));
    json(&body)
}

/// Assert the response shape and hand the document back for field checks.
pub fn expect_resp<'a>(v: &'a Value, shape: &str) -> &'a Value {
    assert_eq!(v["resp"].as_str(), Some(shape), "unexpected response: {v}");
    v
}

/// The minted address of an ack_addr response.
pub fn acked_addr(v: &Value) -> String {
    expect_resp(v, "ack_addr")["addr"].as_str().expect("ack_addr carries addr").to_string()
}

/// The deadline every stream assertion runs under — generous for CI; the
/// daemon's own delivery is notification-driven (well under the wire's
/// ~250 ms bound).
const SSE_DEADLINE: Duration = Duration::from_secs(5);

/// A raw `GET /events` subscriber: reads the SSE framing off the socket,
/// skipping `:ka` keepalive comments.
pub struct Sse {
    stream: TcpStream,
    buf: Vec<u8>,
}

impl Sse {
    pub fn connect(port: u16) -> Sse {
        let mut stream = TcpStream::connect(("127.0.0.1", port)).expect("connect /events");
        stream.set_read_timeout(Some(Duration::from_millis(100))).expect("read timeout");
        stream
            .write_all(
                b"GET /events HTTP/1.1\r\nHost: 127.0.0.1\r\nAccept: text/event-stream\r\n\r\n",
            )
            .expect("write /events request");
        let mut sse = Sse { stream, buf: Vec::new() };
        let head = sse.read_until(b"\r\n\r\n");
        let head = String::from_utf8(head).expect("ascii stream head");
        assert!(
            head.starts_with("HTTP/1.1 200 "),
            "the event stream must open 200: {head}"
        );
        let lower = head.to_ascii_lowercase();
        assert!(
            lower.contains("content-type: text/event-stream"),
            "the event stream is text/event-stream: {head}"
        );
        assert!(
            lower.contains("access-control-allow-origin: *"),
            "the event stream carries the CORS header: {head}"
        );
        sse
    }

    /// Read (appending to the persistent buffer) until `delim`; returns the
    /// bytes before it and consumes through it.
    fn read_until(&mut self, delim: &[u8]) -> Vec<u8> {
        let deadline = Instant::now() + SSE_DEADLINE;
        loop {
            if let Some(i) = self.buf.windows(delim.len()).position(|w| w == delim) {
                let mut taken: Vec<u8> = self.buf.drain(..i + delim.len()).collect();
                taken.truncate(i);
                return taken;
            }
            assert!(
                Instant::now() < deadline,
                "no stream data within {SSE_DEADLINE:?}; buffered: {:?}",
                String::from_utf8_lossy(&self.buf)
            );
            let mut chunk = [0u8; 4096];
            match self.stream.read(&mut chunk) {
                Ok(0) => panic!(
                    "stream closed while waiting; buffered: {:?}",
                    String::from_utf8_lossy(&self.buf)
                ),
                Ok(n) => self.buf.extend_from_slice(&chunk[..n]),
                Err(e) if e.kind() == ErrorKind::WouldBlock || e.kind() == ErrorKind::TimedOut => {}
                Err(e) => panic!("read /events: {e}"),
            }
        }
    }

    /// The next event's `log_position`, asserting the `commit` framing;
    /// keepalive comment blocks are skipped.
    pub fn expect_commit(&mut self) -> u64 {
        loop {
            let block = self.read_until(b"\n\n");
            let text = String::from_utf8(block).expect("utf-8 event block");
            if text.trim_start().starts_with(':') {
                continue;
            }
            let lines: Vec<&str> = text.lines().collect();
            assert_eq!(lines.len(), 2, "one event line + one data line: {text:?}");
            assert_eq!(lines[0], "event: commit", "event name: {text:?}");
            let data = lines[1].strip_prefix("data: ").expect("data line");
            let v: Value = serde_json::from_str(data).expect("event data is JSON");
            let obj = v.as_object().expect("event data object");
            assert_eq!(obj.len(), 1, "v1 payload is the position alone: {data}");
            return obj["log_position"].as_u64().expect("log_position number");
        }
    }

    /// Assert the daemon closes the stream (draining any trailing events).
    pub fn expect_eof(&mut self) {
        let deadline = Instant::now() + SSE_DEADLINE;
        loop {
            let mut chunk = [0u8; 4096];
            match self.stream.read(&mut chunk) {
                Ok(0) => return,
                // Reset counts as closed: the daemon is gone either way.
                Err(e)
                    if e.kind() == ErrorKind::ConnectionReset
                        || e.kind() == ErrorKind::BrokenPipe =>
                {
                    return
                }
                Ok(_) => {}
                Err(e) if e.kind() == ErrorKind::WouldBlock || e.kind() == ErrorKind::TimedOut => {}
                Err(e) => panic!("read at stream end: {e}"),
            }
            assert!(Instant::now() < deadline, "stream not closed within {SSE_DEADLINE:?}");
        }
    }
}
