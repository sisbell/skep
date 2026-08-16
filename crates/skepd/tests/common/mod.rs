//! Shared test plumbing: spawn a real daemon on an ephemeral port and speak
//! HTTP/1.1 to it over a plain TcpStream (`Connection: close`, read to EOF)
//! — the transport is the thing under test, so no client library sits in
//! the middle.

#![allow(dead_code)]

use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::Path;

use serde_json::Value;
use skepd::{serve, Daemon, Skepd};

pub fn spawn(dir: &Path) -> Skepd {
    let daemon = Daemon::open(dir).expect("daemon open (genesis or recover)");
    serve(daemon, 0, 4).expect("bind an ephemeral port")
}

/// One HTTP exchange; returns (status, body bytes).
pub fn http(
    port: u16,
    method: &str,
    path: &str,
    session: Option<&str>,
    body: &[u8],
) -> (u16, Vec<u8>) {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).expect("connect to skepd");
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
    let status: u16 = head
        .split_whitespace()
        .nth(1)
        .expect("status code in the status line")
        .parse()
        .expect("numeric status");
    (status, raw[sep + 4..].to_vec())
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
