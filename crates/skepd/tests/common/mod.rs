//! Shared test plumbing: spawn a real daemon on an ephemeral port and speak
//! HTTP/1.1 to it over a plain TcpStream (`Connection: close`, read to EOF)
//! — the transport is the thing under test, so no client library sits in
//! the middle.
//!
//! [`http_full`] speaks exactly one well-formed request shape, which is what
//! every suite about the daemon's SEMANTICS wants. A suite about the
//! TRANSPORT itself needs bytes outside that shape — a `Transfer-Encoding`
//! header, a truncated body, a version that is not 1.1 — and reaches for
//! [`raw_exchange`], which writes what it is given.

#![allow(dead_code)]

use std::io::{ErrorKind, Read, Write};
use std::net::TcpStream;
use std::path::Path;
use std::time::{Duration, Instant};

use ed25519_dalek::{Signer, SigningKey};
use serde_json::Value;
use skep_identity::{encode_enroll, framed, Enrollment, PublicKey, SESSION_TAG};
use skepd::{serve, Daemon, Skepd};

/// The credential type addresses this build allocates (AUTH-7.1 horn B):
/// subspace 3 of the ghost document, ordinals enroll·retire·claim.
pub const T_ENROLL: &str = "1.1.0.1.0.1.0.3.1";
pub const T_RETIRE: &str = "1.1.0.1.0.1.0.3.2";
pub const T_CLAIM: &str = "1.1.0.1.0.1.0.3.3";

/// The claim ceremony's fixed test identity: a high principal id so suite
/// principals (0, 1, 2, …) never collide with it, and deterministic key
/// seeds so a reopened board verifies against the same keys.
pub const OWNER_PRINCIPAL: u64 = 900;
pub const OWNER_ACCOUNT: &str = "1.0.1";
pub const OWNER_DOC1: &str = "1.0.1.0.1";
pub const DEVICE_SEED: [u8; 32] = [7; 32];
pub const ANCHOR_SEED: [u8; 32] = [8; 32];

pub fn device_key() -> SigningKey {
    SigningKey::from_bytes(&DEVICE_SEED)
}

pub fn anchor_key() -> SigningKey {
    SigningKey::from_bytes(&ANCHOR_SEED)
}

fn pubkey_of(sk: &SigningKey) -> PublicKey {
    PublicKey::parse("ed25519", &hex(&sk.verifying_key().to_bytes())).expect("a real point")
}

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Sign the session payload (AUTH-6.4): `framed(SESSION_TAG, [origin,
/// nonce, principal-decimal])`, returning the 128-hex signature.
pub fn sign_session(sk: &SigningKey, origin: &str, nonce: &str, principal: u64) -> String {
    let payload = framed(
        SESSION_TAG,
        &[origin.as_bytes(), nonce.as_bytes(), principal.to_string().as_bytes()],
    );
    hex(&sk.sign(&payload).to_bytes())
}

/// Open a SIGNED session for `principal` over the challenge/response
/// handshake, signing the origin actually dialed.
pub fn open_signed_session(port: u16, principal: u64, sk: &SigningKey) -> String {
    let (st, body) = http(port, "GET", &format!("/challenge?principal={principal}"), None, b"");
    assert_eq!(st, 200, "challenge: {}", String::from_utf8_lossy(&body));
    let nonce = json(&body)["nonce"].as_str().expect("nonce").to_string();
    let origin = format!("http://127.0.0.1:{port}");
    let sig = sign_session(sk, &origin, &nonce, principal);
    let body = format!(
        "{{\"principal\":{principal},\"nonce\":\"{nonce}\",\"origin\":\"{origin}\",\"sig\":\"{sig}\"}}"
    );
    let (st, resp) = http(port, "POST", "/session", None, body.as_bytes());
    assert_eq!(st, 200, "signed session: {}", String::from_utf8_lossy(&resp));
    json(&resp)["session"].as_str().expect("session token").to_string()
}

/// The board claimed? — off `/health.auth.claimant`.
pub fn claimed(port: u16) -> bool {
    let (st, body) = http(port, "GET", "/health", None, b"");
    assert_eq!(st, 200);
    !json(&body)["auth"]["claimant"].is_null()
}

/// Run the notebook claim ceremony (AUTH-5.55 steps 1–5) over the wire:
/// delegate from 0, the home mint, the genesis atom + deposit, the SIGNED
/// claim. Idempotent — a reopened claimed board skips it.
pub fn claim_board(port: u16) {
    if claimed(port) {
        return;
    }
    let boot = open_session(port, 0);
    let v = op(port, Some(&boot), r#"{"op":"next_account_prefix","parent":"1"}"#);
    let prefix = expect_resp(&v, "maybe_addr")["addr"].as_str().expect("prefix").to_string();
    assert_eq!(prefix, OWNER_ACCOUNT, "the ceremony must be the board's first delegate");
    let v = op(
        port,
        Some(&boot),
        &format!(r#"{{"op":"delegate","new_prefix":"{prefix}","new_id":{OWNER_PRINCIPAL}}}"#),
    );
    expect_resp(&v, "ack_addr");
    let owner = open_session(port, OWNER_PRINCIPAL);
    let v = op(
        port,
        Some(&owner),
        &format!(r#"{{"op":"create_new_document","account":"{OWNER_ACCOUNT}"}}"#),
    );
    assert_eq!(acked_addr(&v), OWNER_DOC1, "the home mint is doc 1");
    // The enrollment record — the anchor and the device key — as ONE ATOM.
    let record = encode_enroll(&[
        Enrollment::new(pubkey_of(&anchor_key()), true, Some("paper-a".into()))
            .expect("a legal label"),
        Enrollment::new(pubkey_of(&device_key()), false, Some("notebook".into()))
            .expect("a legal label"),
    ]);
    let record_text = String::from_utf8(record).expect("the record grammar is UTF-8");
    let atom = serde_json::to_string(&Value::String(record_text)).expect("json string");
    let v = op(
        port,
        Some(&owner),
        &format!(
            r#"{{"op":"insert","doc":"{OWNER_DOC1}","at":{{"subspace":"1","ordinal":"1"}},"values":[{{"atom":{atom}}}]}}"#
        ),
    );
    expect_resp(&v, "ack_addr");
    let atom_addr = format!("{OWNER_DOC1}.0.1.1");
    let v = op(
        port,
        Some(&owner),
        &format!(
            r#"{{"op":"make_link","home":"{OWNER_DOC1}","from":{{"addrs":["{atom_addr}"]}},"to":{{"addrs":["{OWNER_ACCOUNT}"]}},"ty":{{"addrs":["{T_ENROLL}"]}}}}"#
        ),
    );
    expect_resp(&v, "ack_addr");
    // The claim, from a session SIGNED by the device key (step 5).
    let signed = open_signed_session(port, OWNER_PRINCIPAL, &device_key());
    let v = op(
        port,
        Some(&signed),
        &format!(
            r#"{{"op":"make_link","home":"{OWNER_DOC1}","from":{{"addrs":["{OWNER_ACCOUNT}"]}},"to":{{"addrs":[]}},"ty":{{"addrs":["{T_CLAIM}"]}}}}"#
        ),
    );
    expect_resp(&v, "ack_addr");
    assert!(claimed(port), "the claim link flips the board claimed");
}

/// Spawn a daemon and CLAIM its board: under the pre-claim admission gate
/// (RES-27) an unclaimed daemon runs nothing but the ceremony, so every
/// suite about ordinary op semantics runs post-claim (CLAIMED-PERMISSIVE —
/// local trust stays the default, so the suites' bare sessions still bind).
pub fn spawn(dir: &Path) -> Skepd {
    let sd = spawn_unclaimed(dir);
    claim_board(sd.port());
    sd
}

/// Spawn without claiming — the AUTH suites drive the window itself.
pub fn spawn_unclaimed(dir: &Path) -> Skepd {
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
    token: Option<&str>,
    body: &[u8],
) -> (u16, Vec<(String, String)>, Vec<u8>) {
    let ctx = |what: &str| format!("{what} ({method} {path})");
    let mut stream = TcpStream::connect(("127.0.0.1", port))
        .unwrap_or_else(|e| panic!("{}: {e}", ctx("connect to skepd")));
    stream.set_read_timeout(Some(HTTP_TIMEOUT)).expect("read timeout");
    stream.set_write_timeout(Some(HTTP_TIMEOUT)).expect("write timeout");
    let mut head = format!(
        "{method} {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\nContent-Length: {}\r\n",
        body.len()
    );
    if let Some(tok) = token {
        head.push_str(&format!("Skepd-Session: {tok}\r\n"));
    }
    head.push_str("Content-Type: application/json\r\n\r\n");
    stream
        .write_all(head.as_bytes())
        .unwrap_or_else(|e| panic!("{}: {e}", ctx("write request head")));
    stream.write_all(body).unwrap_or_else(|e| panic!("{}: {e}", ctx("write request body")));
    let mut raw = Vec::new();
    stream
        .read_to_end(&mut raw)
        .unwrap_or_else(|e| panic!("{}: {e}", ctx("read response")));
    parse_response(&raw, &ctx("response"))
}

/// Parse one HTTP response's bytes into (status, headers, body) — the one
/// response reader these tests use, so [`http_full`] and [`raw_exchange`]
/// cannot disagree about what a header is.
pub fn parse_response(raw: &[u8], ctx: &str) -> (u16, Vec<(String, String)>, Vec<u8>) {
    let sep = raw.windows(4).position(|w| w == b"\r\n\r\n").unwrap_or_else(|| {
        panic!("{ctx}: no header/body separator: {:?}", String::from_utf8_lossy(raw))
    });
    let head = std::str::from_utf8(&raw[..sep]).expect("ascii response head");
    let mut lines = head.split("\r\n");
    let status: u16 = lines
        .next()
        .expect("status line")
        .split_whitespace()
        .nth(1)
        .unwrap_or_else(|| panic!("{ctx}: no status code in {head:?}"))
        .parse()
        .unwrap_or_else(|_| panic!("{ctx}: non-numeric status in {head:?}"));
    let headers = lines
        .filter_map(|l| l.split_once(':'))
        .map(|(k, v)| (k.trim().to_string(), v.trim().to_string()))
        .collect();
    (status, headers, raw[sep + 4..].to_vec())
}

/// One exchange whose request bytes are written VERBATIM — the transport
/// itself is what these callers test, so nothing here builds a head for
/// them. Half-closes the write side (the daemon sees EOF and cannot wait on
/// a body that will never arrive), then reads to close.
///
/// Write errors are deliberately ignored: the daemon may already have
/// answered and closed (an oversized declared length, a refused method)
/// while we were still writing. The response is the judge.
pub fn raw_exchange(port: u16, raw: &[u8]) -> (u16, Vec<(String, String)>, Vec<u8>) {
    let bytes = skepd::fuzz_support::http_raw_exchange(port, raw)
        .unwrap_or_else(|e| panic!("connect to skepd: {e}"));
    assert!(
        !bytes.is_empty(),
        "the daemon closed without answering: {:?}",
        String::from_utf8_lossy(raw)
    );
    parse_response(&bytes, "raw exchange")
}

/// One HTTP exchange; returns (status, body bytes).
pub fn http(
    port: u16,
    method: &str,
    path: &str,
    token: Option<&str>,
    body: &[u8],
) -> (u16, Vec<u8>) {
    let (status, _headers, body) = http_full(port, method, path, token, body);
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
pub fn op(port: u16, token: Option<&str>, frame: &str) -> Value {
    let (st, body) = http(port, "POST", "/op", token, frame.as_bytes());
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

/// The deadline a keepalive assertion runs under. The daemon's cadence is
/// 15 s of silence (wire.md §The commit stream), so this necessarily waits
/// past it — generous, since arriving late is still arriving.
const SSE_KEEPALIVE_DEADLINE: Duration = Duration::from_secs(40);

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
        assert!(
            lower.contains("connection: close"),
            "the event stream declares Connection: close (wire.md §Transport): {head}"
        );
        assert!(
            lower.contains("cache-control: no-cache"),
            "the event stream forbids caching — an intermediary that buffers it \
             delivers nothing until close, so the stream looks dead while the \
             daemon is healthy: {head}"
        );
        sse
    }

    /// Read (appending to the persistent buffer) until `delim`; returns the
    /// bytes before it and consumes through it.
    fn read_until(&mut self, delim: &[u8]) -> Vec<u8> {
        self.read_until_within(delim, SSE_DEADLINE)
    }

    /// [`Sse::read_until`] under a caller-chosen deadline — the keepalive
    /// assertion necessarily waits longer than a commit ever should.
    fn read_until_within(&mut self, delim: &[u8], within: Duration) -> Vec<u8> {
        let deadline = Instant::now() + within;
        loop {
            if let Some(i) = self.buf.windows(delim.len()).position(|w| w == delim) {
                let mut taken: Vec<u8> = self.buf.drain(..i + delim.len()).collect();
                taken.truncate(i);
                return taken;
            }
            assert!(
                Instant::now() < deadline,
                "no stream data within {within:?}; buffered: {:?}",
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

    /// The documented keepalive (wire.md §The commit stream): after each
    /// silent interval the daemon writes the comment line `:ka` and a blank
    /// line, which is how a client tells a live stream from a dead peer.
    /// Necessarily slow — it waits out the daemon's 15 s cadence.
    pub fn expect_keepalive(&mut self) {
        let block = self.read_until_within(b"\n\n", SSE_KEEPALIVE_DEADLINE);
        let text = String::from_utf8(block).expect("utf-8 stream block");
        assert_eq!(text, ":ka", "a silent stream's next block is the documented keepalive");
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
