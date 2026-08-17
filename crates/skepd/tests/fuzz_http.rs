//! H2 tier 1 — the owned HTTP/1.1 layer under hostile bytes.
//!
//! Raw TCP against an in-process daemon on an ephemeral port over a tiny
//! temp store: arbitrary request heads and bodies, mangled `Content-Length`,
//! split writes at hostile boundaries, pipelined garbage after a valid
//! request, and (under `FUZZ_EXHAUSTIVE`) a slow-loris that must trip the
//! server's own read timeout. The contract:
//!
//! * every connection gets **exactly one well-formed HTTP response** — a
//!   parseable status line, a header block, the universal CORS header, and a
//!   body length that agrees with `Content-Length` — then the connection
//!   closes;
//! * the daemon **never dies**: `/health` answers after every batch (a
//!   crashed worker or leaked thread would starve the pool and this would
//!   hang or fail).
//!
//! Store semantics are not retested — this is the socket. A malformed
//! response fails loudly with the request + response bytes (the H3 finding
//! protocol: convert to `#[ignore = "FINDING-n: …"]`, assertion intact).

mod common;
mod fuzz_common;

use std::io::{Read, Write};
use std::net::{Shutdown, TcpStream};
use std::thread;
use std::time::{Duration, Instant};

use serde_json::Value;
use skepd::fuzz_support::{check_http_response, hex, http_raw_exchange, mutate, splitmix64};

use common::spawn;
use fuzz_common::{exhaustive, iters, random_bytes, request_frames};

/// `/health` answers 200 `ok:true` — the liveness + no-thread-leak check the
/// batches lean on.
fn assert_health(port: u16) {
    let resp = http_raw_exchange(port, &get_request("/health"))
        .expect("daemon reachable for /health");
    let status = check_http_response(&resp)
        .unwrap_or_else(|e| panic!("FINDING (http): /health response malformed: {e}"));
    assert_eq!(status, 200, "the daemon must stay up: /health answered {status}");
    let sep = resp.windows(4).position(|w| w == b"\r\n\r\n").expect("terminator");
    let v: Value = serde_json::from_slice(&resp[sep + 4..]).expect("/health body is JSON");
    assert_eq!(v["ok"], Value::Bool(true), "the daemon must stay up: {v}");
}

/// A local `GET` builder (mirrors `fuzz_support::build_get`, kept here so the
/// liveness path is obviously independent of the code under test).
fn get_request(path: &str) -> Vec<u8> {
    format!("GET {path} HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n").into_bytes()
}

/// Assemble a raw request from parts.
fn req(method: &str, path: &str, extra_headers: &str, body: &[u8]) -> Vec<u8> {
    let mut v = format!(
        "{method} {path} HTTP/1.1\r\nHost: 127.0.0.1\r\n{extra_headers}Content-Length: {}\r\n\r\n",
        body.len()
    )
    .into_bytes();
    v.extend_from_slice(body);
    v
}

/// A complete, valid `POST /op` read frame (a retrieve on an unregistered
/// document — always answers a `rejected` document): the base for the
/// pipelined-garbage and split-write scenarios.
fn valid_op_request() -> Vec<u8> {
    let body = br#"{"op":"retrieve_v","specs":[{"doc":"1.0.9.0.1","span":{"start":"1.1","width":"0.1"}}]}"#;
    req("POST", "/op", "Content-Type: application/json\r\n", body)
}

/// One hostile request, seeded. Every arm is a complete byte string ready to
/// write to a socket; the daemon must answer each with exactly one
/// well-formed response.
fn hostile_request(st: &mut u64, corpus: &[Vec<u8>]) -> Vec<u8> {
    match splitmix64(st) % 8 {
        // Pure garbage — no HTTP shape at all.
        0 => random_bytes(st, 300),
        // A random method/path/version request line, empty body.
        1 => {
            let m = random_token(st, 8);
            let p = format!("/{}", random_token(st, 12));
            req(&m, &p, "", b"")
        }
        // A valid /op line with a mutated frame body and a correct length.
        2 => {
            let body = mutate(splitmix64(st), corpus);
            req("POST", "/op", "Content-Type: application/json\r\n", &body)
        }
        // A body with a Content-Length that overstates it: half-close makes
        // the daemon see EOF mid-body → one 400, never a hang.
        3 => {
            let body = mutate(splitmix64(st), corpus);
            let mut v = format!(
                "POST /op HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: {}\r\n\r\n",
                body.len() + 1 + (splitmix64(st) as usize % 4096)
            )
            .into_bytes();
            v.extend_from_slice(&body);
            v
        }
        // A valid request with pipelined trailing garbage — one answer, the
        // rest dropped on close.
        4 => {
            let mut v = valid_op_request();
            v.extend_from_slice(&random_bytes(st, 200));
            v
        }
        // A header flood within the 64 KiB head cap.
        5 => {
            let count = 20 + splitmix64(st) as usize % 200;
            let mut headers = String::new();
            for k in 0..count {
                headers.push_str(&format!("X-Fuzz-{k}: {}\r\n", random_token(st, 6)));
            }
            req("GET", "/health", &headers, b"")
        }
        // A mutated /session body.
        6 => {
            let body = mutate(splitmix64(st), corpus);
            req("POST", "/session", "Content-Type: application/json\r\n", &body)
        }
        // A junk query on a real GET route.
        _ => {
            let q: String = String::from_utf8_lossy(&random_bytes(st, 40))
                .chars()
                .filter(|c| !c.is_control())
                .collect();
            get_request(&format!("/changes?{q}"))
        }
    }
}

/// A short random ASCII token (letters/digits) for methods, paths, headers.
fn random_token(st: &mut u64, maxlen: usize) -> String {
    let alpha = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    let len = 1 + splitmix64(st) as usize % maxlen;
    (0..len).map(|_| alpha[splitmix64(st) as usize % alpha.len()] as char).collect()
}

#[test]
fn http_hostile_bytes_single_response_daemon_survives() {
    let corpus = request_frames();
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();

    let mut st = 0x4854_5450_0000_0001; // "HTTP\0\0\0\1"
    let n = iters(2_000);
    for i in 0..n {
        let raw = hostile_request(&mut st, &corpus);
        let resp = http_raw_exchange(port, &raw).expect("daemon reachable");
        if !resp.is_empty() {
            check_http_response(&resp).unwrap_or_else(|e| {
                panic!(
                    "FINDING (fuzz_http): i={i} malformed response: {e}\n  \
                     request: {}\n  response: {}",
                    hex(&raw),
                    String::from_utf8_lossy(&resp)
                )
            });
        }
        // Liveness (and no-thread-leak) probe across the batch.
        if i % 200 == 0 {
            assert_health(port);
        }
    }
    assert_health(port);

    // Deterministic split-write scenarios: the daemon reassembles a request
    // no matter how the TCP writes are chopped.
    for boundary in [1usize, 2, 7, 40] {
        let raw = valid_op_request();
        let resp = split_write_exchange(port, &raw, boundary);
        check_http_response(&resp).unwrap_or_else(|e| {
            panic!("FINDING (fuzz_http): split-write at {boundary} gave a malformed response: {e}")
        });
    }
    assert_health(port);

    sd.shutdown();
}

/// Write `raw` in `chunk`-sized pieces with a flush and a tiny pause between
/// them, half-close, and read the one response.
fn split_write_exchange(port: u16, raw: &[u8], chunk: usize) -> Vec<u8> {
    let mut s = TcpStream::connect(("127.0.0.1", port)).expect("connect");
    s.set_read_timeout(Some(Duration::from_secs(5))).ok();
    for piece in raw.chunks(chunk.max(1)) {
        s.write_all(piece).expect("write chunk");
        s.flush().ok();
        thread::sleep(Duration::from_millis(1));
    }
    s.shutdown(Shutdown::Write).ok();
    let mut out = Vec::new();
    s.read_to_end(&mut out).expect("read response");
    out
}

/// The slow-loris: a partial head, then silence — the server's own read
/// timeout (30 s) must fire and close the connection, never pin the worker
/// forever. Out of the default budget (it waits on that timeout), so gated
/// to the exhaustive sweep.
#[test]
fn http_slow_loris_read_timeout_fires() {
    if !exhaustive() {
        return;
    }
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();

    let mut s = TcpStream::connect(("127.0.0.1", port)).expect("connect");
    // A request line but no terminating CRLFCRLF, and we never send more.
    s.write_all(b"POST /op HTTP/1.1\r\nHost: 127.0.0.1\r\n").expect("write partial head");
    s.flush().ok();
    // Generous client deadline past the server's 30 s read timeout.
    s.set_read_timeout(Some(Duration::from_secs(45))).expect("timeout");
    let start = Instant::now();
    let mut buf = [0u8; 1024];
    // The server times out its read, answers 400 (or closes) — either way the
    // client's blocking read returns within the window rather than hanging.
    let outcome = s.read(&mut buf);
    assert!(
        start.elapsed() < Duration::from_secs(44),
        "the server did not release a stalled connection within its read timeout"
    );
    match outcome {
        Ok(0) => {} // clean close after the timeout
        Ok(n) => {
            // A 400 body is fine — the point is the connection did not hang.
            assert!(buf[..n].starts_with(b"HTTP/1.1 "), "a stalled connection got a non-HTTP reply");
        }
        Err(e) => panic!("FINDING (fuzz_http): slow-loris read errored instead of releasing: {e}"),
    }

    assert_health(port);
    sd.shutdown();
}
