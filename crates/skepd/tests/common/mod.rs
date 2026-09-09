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
use std::net::{TcpListener, TcpStream};
use std::path::Path;
use std::time::{Duration, Instant};

use ed25519_dalek::{Signer, SigningKey};
use serde_json::Value;
use skep_identity::{encode_enroll, framed, Enrollment, PublicKey, SESSION_TAG};
use skepd::{serve, AuthOptions, Daemon, Origin, Skepd};

/// The credential type addresses this build allocates (AUTH-7.1 horn B):
/// subspace 3 of the ghost document, ordinals enroll·retire·claim.
pub const T_ENROLL: &str = "1.1.0.1.0.1.0.3.1";
pub const T_RETIRE: &str = "1.1.0.1.0.1.0.3.2";
pub const T_CLAIM: &str = "1.1.0.1.0.1.0.3.3";

/// The GRANTS class type address (COMMONS DECISION 5 — 1.1.0.1.0.1.0.3.90):
/// the type a sharing grant's link carries (PUB-5.8, wire.md §The read
/// predicate).
pub const T_GRANT: &str = "1.1.0.1.0.1.0.3.90";

/// The claim ceremony's fixed test identity: a high principal id so suite
/// principals (0, 1, 2, …) never collide with it, and deterministic key
/// seeds so a reopened board verifies against the same keys.
pub const CLAIMANT_PRINCIPAL: u64 = 900;
pub const CLAIMANT_ACCOUNT: &str = "1.0.1";
pub const CLAIMANT_DOC1: &str = "1.0.1.0.1";
pub const DEVICE_SEED: [u8; 32] = [7; 32];
pub const ANCHOR_SEED: [u8; 32] = [8; 32];

pub fn device_key() -> SigningKey {
    SigningKey::from_bytes(&DEVICE_SEED)
}

pub fn anchor_key() -> SigningKey {
    SigningKey::from_bytes(&ANCHOR_SEED)
}

pub fn public_key_of(sk: &SigningKey) -> PublicKey {
    PublicKey::parse("ed25519", &hex(&sk.verifying_key().to_bytes())).expect("a real point")
}

/// A deterministic per-principal signing key: seed `n` in every byte, the
/// first byte XORed with `0x40` so no `distinct_key(n)` collides with the
/// ceremony's [`DEVICE_SEED`]/[`ANCHOR_SEED`] (constant-byte seeds) at any
/// `n`. The suites that hire delegated principals key each one with the
/// principal's own number.
pub fn distinct_key(n: u8) -> SigningKey {
    let mut seed = [n; 32];
    seed[0] = 0x40 ^ n;
    SigningKey::from_bytes(&seed)
}

/// Arbitrary record text as its atom JSON fragment — the escape every record
/// atom the suites insert takes, so a payload no parser admits is written the
/// same way a well-formed one is.
pub fn json_atom(text: &str) -> String {
    serde_json::to_string(&Value::String(text.to_string())).expect("json string")
}

/// One enroll record of DEVICE-flagged keys (no anchor lines — AUTH-5.63's
/// rule for a machine-composed genesis), as its atom JSON fragment.
pub fn enroll_atom(keys: &[&SigningKey]) -> String {
    let flagged: Vec<(&SigningKey, bool)> = keys.iter().map(|sk| (*sk, false)).collect();
    enroll_atom_flagged(&flagged)
}

/// One enroll record with the anchor flag named per key, as its atom JSON
/// fragment.
pub fn enroll_atom_flagged(keys: &[(&SigningKey, bool)]) -> String {
    let entries: Vec<Enrollment> = keys
        .iter()
        .map(|(sk, anchor)| Enrollment::new(public_key_of(sk), *anchor, None).expect("no label"))
        .collect();
    json_atom(&String::from_utf8(encode_enroll(&entries)).expect("utf-8"))
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
    assert_eq!(prefix, CLAIMANT_ACCOUNT, "the ceremony must be the board's first delegate");
    let v = op(
        port,
        Some(&boot),
        &format!(r#"{{"op":"delegate","new_prefix":"{prefix}","new_id":{CLAIMANT_PRINCIPAL}}}"#),
    );
    expect_resp(&v, "ack_addr");
    let claimant = open_session(port, CLAIMANT_PRINCIPAL);
    let v = op(
        port,
        Some(&claimant),
        &format!(r#"{{"op":"create_new_document","account":"{CLAIMANT_ACCOUNT}"}}"#),
    );
    assert_eq!(acked_addr(&v), CLAIMANT_DOC1, "the home mint is doc 1");
    // The enrollment record — the anchor and the device key — as ONE ATOM.
    let record = encode_enroll(&[
        Enrollment::new(public_key_of(&anchor_key()), true, Some("paper-a".into()))
            .expect("a legal label"),
        Enrollment::new(public_key_of(&device_key()), false, Some("notebook".into()))
            .expect("a legal label"),
    ]);
    let record_text = String::from_utf8(record).expect("the record grammar is UTF-8");
    let atom = serde_json::to_string(&Value::String(record_text)).expect("json string");
    // The atom's insert carries the DEPOSIT DECLARATION (PUB-2.63; the
    // DECLARED horn of PUB-9.13): doc 1 is born published, and an undeclared
    // insert into it is the in-place edit the write path refuses (PUB-2.11).
    let v = op(
        port,
        Some(&claimant),
        &format!(
            r#"{{"op":"insert","doc":"{CLAIMANT_DOC1}","at":{{"subspace":"1","ordinal":"1"}},"values":[{{"atom":{atom}}}],"deposit":true}}"#
        ),
    );
    expect_resp(&v, "ack_addr");
    let atom_addr = format!("{CLAIMANT_DOC1}.0.1.1");
    let v = op(
        port,
        Some(&claimant),
        &format!(
            r#"{{"op":"make_link","home":"{CLAIMANT_DOC1}","from":{{"addrs":["{atom_addr}"]}},"to":{{"addrs":["{CLAIMANT_ACCOUNT}"]}},"ty":{{"addrs":["{T_ENROLL}"]}}}}"#
        ),
    );
    expect_resp(&v, "ack_addr");
    // The claim, from a session SIGNED by the device key (step 5).
    let signed = open_signed_session(port, CLAIMANT_PRINCIPAL, &device_key());
    let v = op(
        port,
        Some(&signed),
        &format!(
            r#"{{"op":"make_link","home":"{CLAIMANT_DOC1}","from":{{"addrs":["{CLAIMANT_ACCOUNT}"]}},"to":{{"addrs":[]}},"ty":{{"addrs":["{T_CLAIM}"]}}}}"#
        ),
    );
    expect_resp(&v, "ack_addr");
    assert!(claimed(port), "the claim link flips the board claimed");
}

/// The next FREE content ordinal of `doc` — one past its arranged content
/// extent, read off `retrieve_doc_v_span_set` (the content extent is the
/// `1.1`-started span, its width `0.N`; an empty document has none). Read as
/// `token` (`None` = the guest, enough for a published doc 1). The position a
/// declared deposit into a published document must land at (PUB-2.59), so
/// the helpers that deposit into a doc 1 read it rather than assume it: the
/// claimant's doc 1 already holds the claim atom at 1, and every hire and
/// every walk's deposit advances the head by one.
pub fn next_content_ordinal(port: u16, token: Option<&str>, doc: &str) -> u64 {
    let v = op(port, token, &format!(r#"{{"op":"retrieve_doc_v_span_set","doc":"{doc}"}}"#));
    let set = expect_resp(&v, "span_set")["set"].as_array().expect("a span set");
    let width = set
        .iter()
        .find(|s| s["start"].as_str() == Some("1.1"))
        .and_then(|s| s["width"].as_str())
        .and_then(|w| w.rsplit('.').next())
        .map(|n| n.parse::<u64>().expect("an extent's width ends in its count"))
        .unwrap_or(0);
    width + 1
}

/// THE HIRE (AUTH-5.58, AUTH-2.62, AUTH-2.70): key a DELEGATED, keyless
/// principal so it can open a SIGNED session — what a write into a published
/// home needs on a claimed board (AUTH-3.79; `policy.rs::publish_gate`), a
/// grant being one such write (PUB-5.8). The agent's GENESIS enrollment is
/// homed in its GENESIS REGISTRY — its DELEGATOR's doc 1; for a
/// bootstrap-delegated account, the CLAIMANT's doc 1 (AUTH-2.62) — written
/// from the delegator's SIGNED session as the one-atom verified deposit
/// (AUTH-5.4): the enroll atom of the agent's DEVICE-flagged public key
/// (device-flagged only, AUTH-5.63) inserted into the registry doc 1 at its
/// next free position with `deposit: true`, then the `make_link` naming the
/// atom, the agent's account and `T_ENROLL`. The fold's genesis arm latches
/// the set (AUTH-2.70); the agent then opens a signed session with `key`.
///
/// `registrar_signed` is the delegator's SIGNED session and `registrar_doc1`
/// that delegator's doc 1. A refused deposit is an AUTH finding, not a
/// fixture to bend: the panic names the verdict token.
pub fn hire(
    port: u16,
    registrar_signed: &str,
    registrar_doc1: &str,
    agent_account: &str,
    agent_id: u64,
    key: &SigningKey,
) -> String {
    let ordinal = next_content_ordinal(port, Some(registrar_signed), registrar_doc1);
    let v = op(
        port,
        Some(registrar_signed),
        &format!(
            r#"{{"op":"insert","doc":"{registrar_doc1}","at":{{"subspace":"1","ordinal":"{ordinal}"}},"values":[{{"atom":{}}}],"deposit":true}}"#,
            enroll_atom(&[key])
        ),
    );
    assert_eq!(
        v["resp"].as_str(),
        Some("ack_addr"),
        "hire of {agent_id}: the enroll atom's deposit into {registrar_doc1}: {v}"
    );
    let atom_addr = acked_addr(&v);
    let v = op(
        port,
        Some(registrar_signed),
        &format!(
            r#"{{"op":"make_link","home":"{registrar_doc1}","from":{{"addrs":["{atom_addr}"]}},"to":{{"addrs":["{agent_account}"]}},"ty":{{"addrs":["{T_ENROLL}"]}}}}"#
        ),
    );
    assert_eq!(
        v["resp"].as_str(),
        Some("ack_addr"),
        "hire of {agent_id} ({agent_account}) refused by the fold — an AUTH finding: {v}"
    );
    open_signed_session(port, agent_id, key)
}

/// A GRANT link in `home_doc1`, the issuer's published doc 1, from the
/// issuer's SIGNED session `signed` — a write into the published world:
/// `from` the content-prefix shared (a document, or an account — covering
/// every document under it, later mints included), `to` the grantee account,
/// or `None` for the ANY-PRINCIPAL form (`to: []`, PUB-5.8). Returns the
/// grant link's address.
pub fn deposit_grant(
    port: u16,
    signed: &str,
    home_doc1: &str,
    content_prefix: &str,
    grantee: Option<&str>,
) -> String {
    let to = match grantee {
        Some(g) => format!(r#"{{"addrs":["{g}"]}}"#),
        None => r#"{"addrs":[]}"#.to_string(),
    };
    acked_addr(&op(
        port,
        Some(signed),
        &format!(
            r#"{{"op":"make_link","home":"{home_doc1}","from":{{"addrs":["{content_prefix}"]}},"to":{to},"ty":{{"addrs":["{T_GRANT}"]}}}}"#
        ),
    ))
}

/// Spawn with the local-trust flag NAMED and the board left UNCLAIMED —
/// [`spawn`]'s first half, and the one way to reach ENFORCING, which is
/// `local_trust: false` plus a claim. The flag is fixed at open and the
/// claim is the only runtime transition into that mode, so a caller that
/// wants it runs the ceremony itself.
///
/// A claimed board's signed arm accepts ONLY the configured origins
/// (AUTH-4.3's claim-time drop), and a production claimed board is launched
/// with `--origin` naming what it is reachable at — so this spawn mirrors
/// that shape. Origins carry the port, and configuration happens at open,
/// before any listener exists: reserve an ephemeral port first, configure
/// the loopback origin the suites dial, then serve on the reserved port.
pub fn spawn_configured(dir: &Path, local_trust: bool) -> Skepd {
    let reserved = TcpListener::bind(("127.0.0.1", 0)).expect("reserve an ephemeral port");
    let port = reserved.local_addr().expect("reserved local addr").port();
    let origin =
        Origin::parse(&format!("http://127.0.0.1:{port}")).expect("a canonical loopback origin");
    let mut opts = AuthOptions::default();
    opts.local_trust = local_trust;
    opts.configured = vec![origin];
    let daemon = Daemon::open_with(dir, opts).expect("daemon open (genesis or recover)");
    // The reservation held through the slow open; only the rebind gap races.
    drop(reserved);
    serve(daemon, port, 4).expect("bind the reserved port")
}

/// Spawn a daemon and CLAIM its board: under the pre-claim admission gate
/// (RES-27) an unclaimed daemon runs nothing but the ceremony, so every
/// suite about ordinary op semantics runs post-claim (CLAIMED-PERMISSIVE —
/// local trust stays the default, so the suites' bare sessions still bind).
pub fn spawn(dir: &Path) -> Skepd {
    let sd = spawn_configured(dir, true);
    claim_board(sd.port());
    sd
}

/// Spawn without claiming — the AUTH suites drive the window itself.
pub fn spawn_unclaimed(dir: &Path) -> Skepd {
    let daemon = Daemon::open(dir).expect("daemon open (genesis or recover)");
    serve(daemon, 0, 4).expect("bind an ephemeral port")
}

/// Client-side socket timeout: a daemon that wedges must fail the exchange
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

/// One exchange carrying an `Origin` header — the one request header this
/// suite otherwise never sends, and the one the bare-bind rule reads
/// (wire.md §Sessions). Written verbatim through [`raw_exchange`], so
/// [`http_full`]'s signature stays as it is.
pub fn http_with_origin(
    port: u16,
    method: &str,
    path: &str,
    token: Option<&str>,
    origin: &str,
    body: &[u8],
) -> (u16, Vec<(String, String)>, Vec<u8>) {
    let mut head = format!(
        "{method} {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\
         Origin: {origin}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n",
        body.len()
    );
    if let Some(tok) = token {
        head.push_str(&format!("Skepd-Session: {tok}\r\n"));
    }
    head.push_str("\r\n");
    let mut bytes = head.into_bytes();
    bytes.extend_from_slice(body);
    raw_exchange(port, &bytes)
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
        Sse::open(port, None).0
    }

    /// [`Sse::connect`] presenting a token, with the stream HEAD handed
    /// back: `/events` is the one route whose death signal rides a stream
    /// head rather than a reply (wire.md §Sessions), written once, at open.
    pub fn connect_with_token(port: u16, token: &str) -> (Sse, String) {
        Sse::open(port, Some(token))
    }

    fn open(port: u16, token: Option<&str>) -> (Sse, String) {
        let mut stream = TcpStream::connect(("127.0.0.1", port)).expect("connect /events");
        stream.set_read_timeout(Some(Duration::from_millis(100))).expect("read timeout");
        let mut req = String::from(
            "GET /events HTTP/1.1\r\nHost: 127.0.0.1\r\nAccept: text/event-stream\r\n",
        );
        if let Some(tok) = token {
            req.push_str(&format!("Skepd-Session: {tok}\r\n"));
        }
        req.push_str("\r\n");
        stream.write_all(req.as_bytes()).expect("write /events request");
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
            lower.contains("access-control-expose-headers: skepd-session"),
            "the stream head exposes the death signal it may carry — without \
             it a page on a configured origin cannot read `Skepd-Session: \
             closed` and sees a dead token behave as a silent guest: {head}"
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
        (sse, head)
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

// ═══════════════════════════════════════════════════════════════════════════
// The lane-4 helpers (PUB round 2, lane 4 — the register, vector-matrix,
// H1-residue and cascade suites). ADDITIVE: nothing above changes. A suite
// that defines a local item of one of these names shadows the glob import,
// as Rust's glob rules allow, so the older suites' own `stranger`/`head`
// helpers stand untouched beside these.
// ═══════════════════════════════════════════════════════════════════════════

use std::collections::BTreeSet;

use serde_json::json;

/// The ceremony atom: the claimant's doc 1's one content element, at its
/// first content ordinal.
pub const CEREMONY_ATOM: &str = "1.0.1.0.1.0.1.1";

/// The audit-view classes' type addresses — the engine's commons pins
/// (`skep_engine::types`), spelled as a client names them — and the two
/// classes read under the ACTIVE view beside them.
pub const T_SUCCESSOR_OF_CLASS: &str = "1.1.0.1.0.1.0.3.59";
pub const T_ENDORSE_CLASS: &str = "1.1.0.1.0.1.0.3.42";
pub const T_MARKER_CLASS: &str = "1.1.0.1.0.1.0.3.91";
pub const T_DESIGNATION_CLASS: &str = "1.1.0.1.0.1.0.3.22";
pub const T_RAIL_CLASS: &str = "1.1.0.1.0.1.0.3.60";
pub const T_STEWARD_CLASS: &str = "1.1.0.1.0.1.0.3.61";
pub const T_EDITION_CLASS: &str = "1.1.0.1.0.1.0.3.14";

/// The daemon's publish-class refusal, in the `auth_wire` `code:detail`
/// convention — the verdict every bare-session cell of the gate answers.
pub const GATED: &str = "credential_refused:signed_session_required";

// ── positions, verdicts, shapes ──────────────────────────────────────────

/// The committed head, off `/health`.
pub fn head_position(port: u16) -> u64 {
    json(&get(port, "/health").1)["log_position"].as_u64().expect("log_position")
}

/// The committed position a write's ack carries.
pub fn acked_at(v: &Value) -> u64 {
    assert!(
        matches!(v["resp"].as_str(), Some("ack" | "ack_addr" | "ack_edit")),
        "not a write ack: {v}"
    );
    v["at"].as_u64().expect("write acks carry at")
}

/// A response's verdict: `ok` for any ack; a rejection's code, or
/// `credential_refused:<token>` for the daemon-originated family (the
/// `auth_wire` convention); anything else spelled out.
pub fn verdict(v: &Value) -> String {
    match v["resp"].as_str() {
        Some("ack") | Some("ack_addr") | Some("ack_edit") => "ok".to_string(),
        Some("rejected") => match (v["code"].as_str().unwrap_or("?"), v["detail"].as_str()) {
            ("credential_refused", Some(d)) => format!("credential_refused:{d}"),
            (code, _) => code.to_string(),
        },
        other => format!("resp:{other:?}"),
    }
}

/// PUB-8.4 / PUB-8.5: `withheld`, `reorder`, `site.addr` the document, and
/// no `detail`, ever.
pub fn assert_withheld(v: &Value, doc: &str) {
    let rej = expect_resp(v, "rejected");
    assert_eq!(rej["code"].as_str(), Some("withheld"), "{v}");
    assert_eq!(rej["disposition"].as_str(), Some("reorder"), "{v}");
    assert_eq!(rej["site"]["addr"].as_str(), Some(doc), "the withheld document: {v}");
    assert!(rej.get("detail").is_none(), "withheld carries no detail: {v}");
}

/// The delivery's withheld arm (PUB-8.10): one item per masked RUN.
pub fn withheld_item(origin: &str, width: u64) -> Value {
    json!({"withheld": {"origin": origin, "width": width.to_string()}})
}

/// The addresses of an `addrs` answer.
pub fn addrs_of(v: &Value) -> Vec<String> {
    expect_resp(v, "addrs")["addrs"]
        .as_array()
        .expect("addrs")
        .iter()
        .map(|a| a.as_str().expect("an address").to_string())
        .collect()
}

// ── principals and seats ─────────────────────────────────────────────────

/// A seated principal: its account, its BARE session, and its MINT-FIRST
/// home (doc 1, born published).
pub struct Seat {
    pub account: String,
    pub session: String,
    pub doc1: String,
}

/// The next delegable prefix under `parent`, as `token` (`None` = the guest —
/// the read is exempt from the predicate, PUB-6.50).
pub fn next_prefix_under(port: u16, token: Option<&str>, parent: &str) -> String {
    let v = op(port, token, &format!(r#"{{"op":"next_account_prefix","parent":"{parent}"}}"#));
    expect_resp(&v, "maybe_addr")["addr"]
        .as_str()
        .unwrap_or_else(|| panic!("no delegable prefix under {parent}: {v}"))
        .to_string()
}

/// Delegate a fresh account under `parent` from `by`'s session and open a
/// bare session for principal `id`. Returns `(account, session)`.
pub fn delegate_under(port: u16, by: &str, parent: &str, id: u64) -> (String, String) {
    let account = next_prefix_under(port, Some(by), parent);
    expect_resp(
        &op(port, Some(by), &format!(r#"{{"op":"delegate","new_prefix":"{account}","new_id":{id}}}"#)),
        "ack_addr",
    );
    (account, open_session(port, id))
}

/// A stranger under node 1, delegated from the bootstrap principal — no home
/// yet. Returns `(account, bare session)`.
pub fn bootstrap_delegate(port: u16, id: u64) -> (String, String) {
    let boot = open_session(port, 0);
    delegate_under(port, &boot, "1", id)
}

pub fn create_frame(account: &str, published: Option<bool>) -> String {
    let flag = match published {
        Some(b) => format!(r#","published":{b}"#),
        None => String::new(),
    };
    format!(r#"{{"op":"create_new_document","account":"{account}"{flag}}}"#)
}

/// A flagless mint into `account` from `session` — the home where the
/// account is empty, a private draft afterwards.
pub fn create_doc(port: u16, session: &str, account: &str) -> String {
    acked_addr(&op(port, Some(session), &create_frame(account, None)))
}

/// A stranger under node 1 with its home minted: the NON-ENTITLED reader
/// and writer of the H1 matrix (or the GRANT-HOLDER once granted).
pub fn seat_stranger(port: u16, id: u64) -> Seat {
    let (account, session) = bootstrap_delegate(port, id);
    let doc1 = create_doc(port, &session, &account);
    Seat { account, session, doc1 }
}

/// A sub-account the OWNER delegates beneath the claimant's account, its
/// home minted — a SUBTREE reader of every draft of the owner's (PUB-1.4,
/// PUB-1.32).
pub fn seat_sub_account(port: u16, owner: &str, id: u64) -> Seat {
    let (account, session) = delegate_under(port, owner, CLAIMANT_ACCOUNT, id);
    let doc1 = create_doc(port, &session, &account);
    Seat { account, session, doc1 }
}

/// A later mint into the claimant's account — flagless, hence PRIVATE.
pub fn owner_draft(port: u16, owner: &str) -> String {
    create_doc(port, owner, CLAIMANT_ACCOUNT)
}

/// An EDITION of the claimant's: an explicit `published:true` mint from the
/// signed session the publish class demands — born empty.
pub fn published_edition(port: u16, signed: &str) -> String {
    acked_addr(&op(port, Some(signed), &create_frame(CLAIMANT_ACCOUNT, Some(true))))
}

// ── arrangement writes ───────────────────────────────────────────────────

pub fn insert_frame(doc: &str, ordinal: u64, text: &str, deposit: bool) -> String {
    let flag = if deposit { r#","deposit":true"# } else { "" };
    format!(
        r#"{{"op":"insert","doc":"{doc}","at":{{"subspace":"1","ordinal":"{ordinal}"}},"values":["{text}"]{flag}}}"#
    )
}

/// An UNDECLARED per-byte insert — the draft's own edit.
pub fn insert_text(port: u16, session: &str, doc: &str, ordinal: u64, text: &str) -> Value {
    op(port, Some(session), &insert_frame(doc, ordinal, text, false))
}

/// A DECLARED per-byte deposit at a fresh position — the one insert a
/// published document admits (PUB-2.59). Returns the first minted I-address.
pub fn deposit_text(port: u16, signed: &str, doc: &str, ordinal: u64, text: &str) -> String {
    acked_addr(&op(port, Some(signed), &insert_frame(doc, ordinal, text, true)))
}

/// A private draft of the claimant's holding `text` from ordinal 1.
pub fn draft_with(port: u16, owner: &str, text: &str) -> String {
    let d = owner_draft(port, owner);
    expect_resp(&insert_text(port, owner, &d, 1, text), "ack_addr");
    d
}

/// A published edition of the claimant's holding `text` from ordinal 1 — a
/// declared deposit into the empty edition.
pub fn edition_with(port: u16, signed: &str, text: &str) -> String {
    let e = published_edition(port, signed);
    deposit_text(port, signed, &e, 1, text);
    e
}

pub fn copy_frame(doc: &str, at: u64, source: &str, from: u64, width: u64) -> String {
    format!(
        r#"{{"op":"copy","doc":"{doc}","at":{{"subspace":"1","ordinal":"{at}"}},"specs":[{{"source":"{source}","span":{{"start":"1.{from}","width":"0.{width}"}}}}]}}"#
    )
}

pub fn copy_span(port: u16, session: &str, doc: &str, at: u64, source: &str, from: u64, width: u64) -> Value {
    op(port, Some(session), &copy_frame(doc, at, source, from, width))
}

pub fn delete_frame(doc: &str, at: u64, width: u64) -> String {
    format!(
        r#"{{"op":"delete","doc":"{doc}","p":{{"subspace":"1","ordinal":"{at}"}},"width":"{width}"}}"#
    )
}

pub fn rearrange_frame(doc: &str, cuts: [u64; 3]) -> String {
    let [a, b, c] = cuts;
    format!(
        r#"{{"op":"rearrange","doc":"{doc}","cuts":[{{"subspace":"1","ordinal":"{a}"}},{{"subspace":"1","ordinal":"{b}"}},{{"subspace":"1","ordinal":"{c}"}}]}}"#
    )
}

pub fn fork_frame(published: Option<bool>) -> String {
    match published {
        Some(b) => format!(r#"{{"op":"fork","published":{b}}}"#),
        None => r#"{"op":"fork"}"#.to_string(),
    }
}

/// `version` with the three-valued flag as the client sends it.
pub fn version_frame(d_src: &str, published: Option<bool>) -> String {
    let flag = match published {
        Some(b) => format!(r#","published":{b}"#),
        None => String::new(),
    };
    format!(r#"{{"op":"version","d_src":"{d_src}"{flag}}}"#)
}

pub fn version_of(port: u16, session: &str, d_src: &str, published: Option<bool>) -> Value {
    op(port, Some(session), &version_frame(d_src, published))
}

// ── the publish shot ─────────────────────────────────────────────────────

/// One run of a shot, as the client renders it.
pub fn run(origin: &str, i_start: &str, width: u64) -> String {
    format!(r#"{{"origin":"{origin}","i_start":"{i_start}","width":"{width}"}}"#)
}

/// The shot: `base` with the extent the staged copy took (both or neither —
/// neither is the birth version), the staging `draft` when there is one, and
/// the runs.
pub fn publish_frame(doc: &str, base: Option<(&str, u64)>, draft: Option<&str>, runs: &[String]) -> String {
    let base = base
        .map(|(m, extent)| format!(r#","base":"{m}","base_extent":"{extent}""#))
        .unwrap_or_default();
    let draft = draft.map(|d| format!(r#","draft":"{d}""#)).unwrap_or_default();
    format!(r#"{{"op":"publish","doc":"{doc}"{base}{draft},"runs":[{}]}}"#, runs.join(","))
}

/// One shot from the signed session; the minted member's address.
pub fn shot(
    port: u16,
    signed: &str,
    doc: &str,
    base: Option<(&str, u64)>,
    draft: Option<&str>,
    runs: &[String],
) -> String {
    acked_addr(&op(port, Some(signed), &publish_frame(doc, base, draft, runs)))
}

/// The DOCUMENT that minted a content I-address: the prefix before its last
/// `.0.1.` (subspace 1, the content subspace) — `1.0.1.0.5.0.1.3` is
/// `1.0.1.0.5`'s, and a member-chain mint `1.0.1.0.5.1.0.1.2` is the
/// member's.
pub fn origin_of(i_addr: &str) -> String {
    let idx = i_addr.rfind(".0.1.").unwrap_or_else(|| panic!("{i_addr} is not a content I-address"));
    i_addr[..idx].to_string()
}

/// `width` consecutive content I-addresses of `doc` from its `first`
/// ordinal — the addresses a per-byte insert of that width mints.
pub fn i_range(doc: &str, first: u64, width: u64) -> Vec<String> {
    (0..width).map(|k| format!("{doc}.0.1.{}", first + k)).collect()
}

/// Every I-address an image's runs cover, in order.
pub fn expand_runs(runs: &[(String, u64)]) -> Vec<String> {
    let mut out = Vec::new();
    for (start, width) in runs {
        let (prefix, last) = start.rsplit_once('.').expect("a dotted address");
        let n: u64 = last.parse().expect("a decimal component");
        for k in 0..*width {
            out.push(format!("{prefix}.{}", n + k));
        }
    }
    out
}

/// The runs a shot re-supplies for content ordinals `from ..` of `doc`, each
/// its own origin — what a client renders from the head it stages off.
pub fn shot_runs(port: u16, token: Option<&str>, doc: &str, from: u64, width: u64) -> Vec<String> {
    image_runs(port, token, doc, from, width)
        .iter()
        .map(|(i_start, w)| run(&origin_of(i_start), i_start, *w))
        .collect()
}

// ── reads ────────────────────────────────────────────────────────────────

pub fn retrieve_frame(doc: &str, from: u64, width: u64) -> String {
    format!(
        r#"{{"op":"retrieve_v","specs":[{{"doc":"{doc}","span":{{"start":"1.{from}","width":"0.{width}"}}}}]}}"#
    )
}

pub fn read1_frame(doc: &str) -> String {
    retrieve_frame(doc, 1, 1)
}

pub fn spanset_frame(doc: &str) -> String {
    format!(r#"{{"op":"retrieve_doc_v_span_set","doc":"{doc}"}}"#)
}

pub fn doc_metadata_frame(doc: &str) -> String {
    format!(r#"{{"op":"doc_metadata","doc":"{doc}"}}"#)
}

pub fn image_frame(doc: &str, from: u64, width: u64) -> String {
    format!(r#"{{"op":"image","d":"{doc}","region":[{{"start":"1.{from}","width":"0.{width}"}}]}}"#)
}

pub fn show_origin_frame(doc: &str, from: u64, width: u64) -> String {
    format!(
        r#"{{"op":"show_origin","doc":"{doc}","span":{{"start":"1.{from}","width":"0.{width}"}}}}"#
    )
}

pub fn read_link_frame(a: &str) -> String {
    format!(r#"{{"op":"read_link","a":"{a}"}}"#)
}

/// The `d`/`region` fields naming content ordinals `from ..` of `doc`.
pub fn region(doc: &str, from: u64, width: u64) -> String {
    format!(r#""d":"{doc}","region":[{{"start":"1.{from}","width":"0.{width}"}}]"#)
}

pub fn find_links_frame(doc: &str, from: u64, width: u64) -> String {
    format!(r#"{{"op":"find_links_v",{}}}"#, region(doc, from, width))
}

/// A region for `compare`'s `rho1`/`rho2` and `find_docs_containing`'s
/// `regions`: content ordinals `from ..` of `doc`.
pub fn region_spec(doc: &str, from: u64, width: u64) -> String {
    format!(r#"{{"doc":"{doc}","spans":[{{"start":"1.{from}","width":"0.{width}"}}]}}"#)
}

/// The delivery items of content ordinals `from ..` of `doc`, as `token`.
pub fn delivery(port: u16, token: Option<&str>, doc: &str, from: u64, width: u64) -> Value {
    let v = op(port, token, &retrieve_frame(doc, from, width));
    expect_resp(&v, "delivery")["items"].clone()
}

/// The per-byte text at content ordinals `from ..` of `doc`, as `token`
/// (atoms, refs and withheld items contribute nothing).
pub fn text_of(port: u16, token: Option<&str>, doc: &str, from: u64, width: u64) -> String {
    delivery(port, token, doc, from, width)
        .as_array()
        .expect("items")
        .iter()
        .map(|i| i["content"].as_str().unwrap_or(""))
        .collect()
}

/// The content extent `doc` answers — `retrieve_doc_v_span_set`'s content
/// span width, `0` when the set carries none.
pub fn content_extent(port: u16, token: Option<&str>, doc: &str) -> u64 {
    let v = op(port, token, &spanset_frame(doc));
    expect_resp(&v, "span_set")["set"]
        .as_array()
        .expect("set")
        .iter()
        .find(|s| s["start"].as_str() == Some("1.1"))
        .map(|s| {
            s["width"]
                .as_str()
                .expect("width")
                .strip_prefix("0.")
                .expect("a depth-2 width")
                .parse()
                .expect("a count")
        })
        .unwrap_or(0)
}

/// The runs of a `runs` answer: `(i_start, width)`.
pub fn runs_in(v: &Value) -> Vec<(String, u64)> {
    expect_resp(v, "runs")["runs"]
        .as_array()
        .expect("runs")
        .iter()
        .map(|r| {
            (
                r["i_start"].as_str().expect("i_start").to_string(),
                r["width"].as_str().expect("width").parse().expect("a count"),
            )
        })
        .collect()
}

/// The V→I image of content ordinals `from ..` of `doc`.
pub fn image_runs(port: u16, token: Option<&str>, doc: &str, from: u64, width: u64) -> Vec<(String, u64)> {
    runs_in(&op(port, token, &image_frame(doc, from, width)))
}

/// The origin documents of content ordinals `from ..` of `doc`.
pub fn origins_of(port: u16, token: Option<&str>, doc: &str, from: u64, width: u64) -> Vec<String> {
    addrs_of(&op(port, token, &show_origin_frame(doc, from, width)))
}

/// The whole `doc_metadata` answer for `doc`, as `token`.
pub fn doc_metadata(port: u16, token: Option<&str>, doc: &str) -> Value {
    op(port, token, &doc_metadata_frame(doc))
}

/// The link value at `a` as `token`: `null` where absent.
pub fn read_link(port: u16, token: Option<&str>, a: &str) -> Value {
    let v = op(port, token, &read_link_frame(a));
    expect_resp(&v, "link_value")["link"].clone()
}

pub fn find_links_v(port: u16, token: Option<&str>, doc: &str, from: u64, width: u64) -> Vec<String> {
    addrs_of(&op(port, token, &find_links_frame(doc, from, width)))
}

pub fn count_v(port: u16, token: Option<&str>, doc: &str, from: u64, width: u64) -> u64 {
    let v = op(port, token, &format!(r#"{{"op":"count_v",{}}}"#, region(doc, from, width)));
    expect_resp(&v, "count")["n"].as_u64().expect("n")
}

/// The first page of `window_v` over the region (`cur: null`, `n: 16`).
pub fn window_v(port: u16, token: Option<&str>, doc: &str, from: u64, width: u64) -> Vec<String> {
    let v = op(
        port,
        token,
        &format!(r#"{{"op":"window_v","cur":null,"n":16,{}}}"#, region(doc, from, width)),
    );
    batch_of(&v)
}

/// The addresses of a `page` answer's batch.
pub fn batch_of(v: &Value) -> Vec<String> {
    expect_resp(v, "page")["window"]["batch"]
        .as_array()
        .expect("batch")
        .iter()
        .map(|a| a.as_str().expect("an address").to_string())
        .collect()
}

/// The `(slot, endset)` pairs of `retrieve_endsets` over the region.
pub fn endset_pairs(port: u16, token: Option<&str>, doc: &str, from: u64, width: u64) -> Vec<Value> {
    let v = op(port, token, &format!(r#"{{"op":"retrieve_endsets",{}}}"#, region(doc, from, width)));
    expect_resp(&v, "endsets")["pairs"].as_array().expect("pairs").clone()
}

pub fn find_docs_containing(port: u16, token: Option<&str>, doc: &str, from: u64, width: u64) -> Vec<String> {
    addrs_of(&op(
        port,
        token,
        &format!(r#"{{"op":"find_docs_containing","regions":[{}]}}"#, region_spec(doc, from, width)),
    ))
}

/// The links the delete of `width` positions at `p` in `doc` would orphan —
/// a preview, nothing written.
pub fn orphans_of(port: u16, token: Option<&str>, doc: &str, p: u64, width: u64) -> Vec<String> {
    let v = op(
        port,
        token,
        &format!(
            r#"{{"op":"delete_orphans","d":"{doc}","p":{{"subspace":"1","ordinal":"{p}"}},"width":"{width}"}}"#
        ),
    );
    expect_resp(&v, "orphans")["orphaned"]
        .as_array()
        .expect("orphaned")
        .iter()
        .map(|a| a.as_str().expect("an address").to_string())
        .collect()
}

fn claim_addrs(v: &Value) -> Vec<String> {
    expect_resp(v, "claims")["claims"]
        .as_array()
        .expect("claims")
        .iter()
        .map(|c| c["claim"].as_str().expect("claim").to_string())
        .collect()
}

/// The claims whose `old` is `y`, under `view`, as `token`.
pub fn claims_in(port: u16, token: Option<&str>, y: &str, view: &str) -> Vec<String> {
    claim_addrs(&op(port, token, &format!(r#"{{"op":"in_claims","view":"{view}","y":"{y}"}}"#)))
}

/// The claims whose `new` is `x`, under `view`, as `token`.
pub fn claims_out(port: u16, token: Option<&str>, x: &str, view: &str) -> Vec<String> {
    claim_addrs(&op(port, token, &format!(r#"{{"op":"out_claims","view":"{view}","x":"{x}"}}"#)))
}

/// The shared positions `compare` reports between content ordinals `1 ..
/// w1` of `d1` and `1 .. w2` of `d2`, expanded per position to
/// `(ordinal in d1, ordinal in d2)` — a statement about correspondence that
/// does not depend on how the report cuts its pairs.
pub fn compare_positions(
    port: u16,
    token: Option<&str>,
    d1: &str,
    w1: u64,
    d2: &str,
    w2: u64,
) -> BTreeSet<(u64, u64)> {
    let v = op(
        port,
        token,
        &format!(
            r#"{{"op":"compare","rho1":[{}],"rho2":[{}]}}"#,
            region_spec(d1, 1, w1),
            region_spec(d2, 1, w2)
        ),
    );
    let mut set = BTreeSet::new();
    for p in expect_resp(&v, "compare")["pairs"].as_array().expect("pairs") {
        let ordinal = |u: &Value| -> u64 {
            assert_eq!(u["subspace"].as_str(), Some("1"), "a content correspondence: {v}");
            u["ordinal"].as_str().expect("ordinal").parse().expect("a count")
        };
        let (u1, u2) = (ordinal(&p["u1"]), ordinal(&p["u2"]));
        let width: u64 = p["width"].as_str().expect("width").parse().expect("a count");
        for k in 0..width {
            set.insert((u1 + k, u2 + k));
        }
    }
    set
}

/// The correspondence of a shared PREFIX of `n` positions: ordinal `k` of
/// one document is ordinal `k` of the other.
pub fn shared_prefix(n: u64) -> BTreeSet<(u64, u64)> {
    (1..=n).map(|k| (k, k)).collect()
}

// ── links ────────────────────────────────────────────────────────────────

/// A one-spec V-spec array over content ordinals `from ..` of `doc`.
pub fn vspec(doc: &str, from: u64, width: u64) -> String {
    format!(r#"[{{"source":"{doc}","span":{{"start":"1.{from}","width":"0.{width}"}}}}]"#)
}

/// An address-form slot naming `addrs` verbatim.
pub fn addrs_slot(addrs: &[&str]) -> String {
    let quoted: Vec<String> = addrs.iter().map(|a| format!("\"{a}\"")).collect();
    format!(r#"{{"addrs":[{}]}}"#, quoted.join(","))
}

/// A ghost type under `home`'s never-occupied subspace 3, address-form.
pub fn ghost_ty(home: &str, n: u64) -> String {
    addrs_slot(&[&format!("{home}.0.3.6.{n}")])
}

/// `edit_link`'s content-RESOLVED successor type slot: `{"resolve":
/// [v-specs…]}` (wire.md §Operations, `edit_link`). The successor's `from`
/// and `to` are bare V-spec arrays, its `ty` an OBJECT naming exactly one of
/// `addrs`/`resolve` — a bare array there is `malformed`, unlike
/// `make_link`'s slots, where the bare array IS the resolve form.
pub fn resolve_slot(vspecs: &str) -> String {
    format!(r#"{{"resolve":{vspecs}}}"#)
}

/// `show_deletions` between `d_a` and `d_b`, both directions.
pub fn deletions_frame(d_a: &str, d_b: &str) -> String {
    format!(r#"{{"op":"show_deletions","d_a":"{d_a}","d_b":"{d_b}"}}"#)
}

/// `make_link` homed in `home`, each slot already JSON (a V-spec array or an
/// address form).
pub fn link_frame(home: &str, from: &str, to: &str, ty: &str) -> String {
    format!(r#"{{"op":"make_link","home":"{home}","from":{from},"to":{to},"ty":{ty}}}"#)
}

/// An address-form link of type `ty` homed in `home`.
pub fn typed_link_frame(home: &str, from: &[&str], to: &[&str], ty: &str) -> String {
    link_frame(home, &addrs_slot(from), &addrs_slot(to), &addrs_slot(&[ty]))
}

pub fn typed_link(port: u16, session: &str, home: &str, from: &[&str], to: &[&str], ty: &str) -> Value {
    op(port, Some(session), &typed_link_frame(home, from, to, ty))
}

/// An address-form link under a fresh ghost type `{home}.0.3.6.{n}`, empty
/// `from`/`to`; the link's address.
pub fn ghost_link(port: u16, session: &str, home: &str, n: u64) -> String {
    acked_addr(&op(port, Some(session), &link_frame(home, r#"{"addrs":[]}"#, r#"{"addrs":[]}"#, &ghost_ty(home, n))))
}

/// The shipped `retired` class's unary tuple over a ghost root under `home`
/// — the one class the open `emit` surface may write under standard genesis.
pub fn emit_frame(home: &str) -> String {
    format!(
        r#"{{"op":"emit","home":"{home}","ty":[{{"start":"1.1.0.1.0.1.0.1.3","width":"0.0.0.0.0.0.0.0.1"}}],"from":"{home}.0.3.9.1","to":[]}}"#
    )
}

pub fn nullify_frame(home: &str, target: &str) -> String {
    format!(r#"{{"op":"nullify","home":"{home}","target":"{target}"}}"#)
}

pub fn assert_sup_frame(home: &str, old: &str, new: &str) -> String {
    format!(r#"{{"op":"assert_sup","home":"{home}","new":"{new}","old":"{old}"}}"#)
}

/// `edit_link` of `original`: the successor homed in `d_s`, the claim in
/// `d_a`; the successor's `from` empty, its `to` and `ty` as given (JSON).
pub fn edit_link_frame(original: &str, d_s: &str, d_a: &str, to: &str, ty: &str) -> String {
    format!(
        r#"{{"op":"edit_link","original":"{original}","d_s":"{d_s}","d_a":"{d_a}","successor":{{"from":[],"to":{to},"ty":{ty}}}}}"#
    )
}

/// The unit span at `addr` — `enc([addr])`'s shape — as a one-span slot.
pub fn unit_span(addr: &str) -> String {
    let depth = addr.split('.').count();
    let width = format!("{}1", "0.".repeat(depth - 1));
    format!(r#"[{{"start":"{addr}","width":"{width}"}}]"#)
}

/// A four-set query frame for `op` (`find_links_ftt` / `count_ftt` /
/// `window_ftt`), each slot already JSON (`"any"`, `"empty"` or a span
/// array); the windowed form starts at `cur: null`.
pub fn ftt_frame(op_name: &str, home: &str, from: &str, to: &str, ty: &str) -> String {
    let cur = if op_name == "window_ftt" { r#""cur":null,"n":16,"# } else { "" };
    format!(r#"{{"op":"{op_name}",{cur}"q":{{"from":{from},"home":{home},"to":{to},"ty":{ty}}}}}"#)
}

/// The class scan over `ty` alone: `home`/`from`/`to` all `"any"`.
pub fn class_scan(op_name: &str, ty_addr: &str) -> String {
    ftt_frame(op_name, r#""any""#, r#""any""#, r#""any""#, &unit_span(ty_addr))
}

// ── history and the dump ─────────────────────────────────────────────────

/// One `/op-at` exchange presenting `token` (`None` = the guest).
pub fn op_at(port: u16, token: Option<&str>, at: u64, frame: &str) -> (u16, Value) {
    let body = format!(r#"{{"at":{at},"frame":{frame}}}"#);
    let (st, body) = http(port, "POST", "/op-at", token, body.as_bytes());
    (st, json(&body))
}

/// A `200` historical answer.
pub fn op_at_ok(port: u16, token: Option<&str>, at: u64, frame: &str) -> Value {
    let (st, v) = op_at(port, token, at, frame);
    assert_eq!(st, 200, "historical read failed at {at}: {v}");
    v
}

/// The `/dump` text at `token`'s class, live or as of `at`.
pub fn dump_text(port: u16, token: Option<&str>, at: Option<u64>) -> String {
    let path = match at {
        Some(n) => format!("/dump?at={n}"),
        None => "/dump".to_string(),
    };
    let (st, body) = http(port, "GET", &path, token, b"");
    assert_eq!(st, 200, "{path}: {}", String::from_utf8_lossy(&body));
    String::from_utf8(body).expect("a dump is UTF-8 text")
}

/// The end (exclusive) of the bracketed value opening at `open_at`, skipping
/// quoted strings — the dump's rendered maps and sequences nest.
fn matching_close(text: &str, open_at: usize) -> usize {
    let bytes = text.as_bytes();
    let (open, close) = match bytes[open_at] {
        b'{' => (b'{', b'}'),
        b'[' => (b'[', b']'),
        other => panic!("no bracket opens at {open_at}: {:?}", other as char),
    };
    let mut depth = 0usize;
    let mut in_str = false;
    let mut escaped = false;
    for (i, &b) in bytes.iter().enumerate().skip(open_at) {
        if in_str {
            if escaped {
                escaped = false;
            } else if b == b'\\' {
                escaped = true;
            } else if b == b'"' {
                in_str = false;
            }
            continue;
        }
        if b == b'"' {
            in_str = true;
        } else if b == open {
            depth += 1;
        } else if b == close {
            depth -= 1;
            if depth == 0 {
                return i + 1;
            }
        }
    }
    panic!("an unbalanced bracket at {open_at}")
}

/// The dump with its `authoritative.namespace` section cut out — the
/// identity section a draft's REGISTRATION lands in (existence is visible,
/// PUB-1.14), so what remains is the guest-readable projection proper:
/// content, arrangements, links, grants, hints and the publication slice.
pub fn without_namespace_section(dump: &str) -> String {
    let key = "\"namespace\": ";
    let start = dump.find(key).unwrap_or_else(|| panic!("the dump renders a namespace section:\n{dump}"));
    let end = matching_close(dump, start + key.len());
    let cut_from = if dump[..start].ends_with(", ") { start - 2 } else { start };
    format!("{}{}", &dump[..cut_from], &dump[end..])
}

/// The dump's PUBLICATION section: the draft addresses readable at the
/// dump's class, in address order.
///
/// The ROOT section — a SEQUENCE of dotted addresses, and the root map's
/// last key (`authoritative` < `grants` < `hints` < `publication`) — and NOT
/// M3's own `publication` MAP inside `authoritative.namespace`, which the
/// dump renders first and whose keys are bare tumblers (digit sequences, no
/// quotes): a forward search for `"publication": ` lands on that map and
/// splits it into nothing, which read every owner's slice as empty. The
/// sequence-opening form is unique to the root section (the map opens with
/// `{`, and `hints.publication.drafts` is a map under another key), and
/// `rfind` takes the last one.
pub fn publication_slice(dump: &str) -> Vec<String> {
    let key = "\"publication\": [";
    let start = dump.rfind(key).unwrap_or_else(|| panic!("the dump renders a publication section:\n{dump}"));
    let open = start + key.len() - 1;
    let end = matching_close(dump, open);
    dump[open + 1..end - 1]
        .split('"')
        .enumerate()
        .filter(|(i, _)| i % 2 == 1)
        .map(|(_, s)| s.to_string())
        .collect()
}

// ── the claim ceremony, parameterized ────────────────────────────────────

/// Steps 1–4 of the claim ceremony (AUTH-5.55) for a FRESH top-level account
/// on an UNCLAIMED board: `delegate` from principal 0 at the next top-level
/// prefix, the home mint, the genesis record of `keys` (each with its anchor
/// flag) as one atom at doc 1's first ordinal, and the `T_ENROLL` link
/// naming it — a keyed PARTIAL, the claim (step 5) withheld.
pub fn seed_partial(port: u16, id: u64, keys: &[(&SigningKey, bool)]) -> Seat {
    let (account, session) = bootstrap_delegate(port, id);
    let doc1 = create_doc(port, &session, &account);
    let v = op(
        port,
        Some(&session),
        &format!(
            r#"{{"op":"insert","doc":"{doc1}","at":{{"subspace":"1","ordinal":"1"}},"values":[{{"atom":{}}}],"deposit":true}}"#,
            enroll_atom_flagged(keys)
        ),
    );
    let atom = acked_addr(&v);
    let v = typed_link(port, &session, &doc1, &[atom.as_str()], &[account.as_str()], T_ENROLL);
    assert_eq!(v["resp"].as_str(), Some("ack_addr"), "the genesis deposit of {account}: {v}");
    Seat { account, session, doc1 }
}

/// The claim ceremony's last step: the claim link in `doc1`, `from` the
/// claiming account, `to` empty, no payload.
pub fn claim_frame(doc1: &str, account: &str) -> String {
    typed_link_frame(doc1, &[account], &[], T_CLAIM)
}
