//! The board the suites talk to: a temp data dir, an in-process daemon over
//! it, and — for the suites that write — the claim ceremony (RES-27) and
//! principal 1 provisioned the way wire.md's end-to-end example does; and a
//! scripted stub daemon, for the answers the real one is never made to give.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::thread::JoinHandle;

use serde_json::{json, Value};
use skep_identity::{encode_enroll, framed, Enrollment, PublicKey, SESSION_TAG};
use skep_signature::{Ed25519SigningKey as SigningKey, HybridSigner, TAG_MLDSA65_ED25519};
use skepd::{serve, Daemon, Skepd, DEFAULT_WORKERS};

// ── a self-owned temp dir (kept dependency-free) ────────────────────────

pub struct TempDir(PathBuf);

impl TempDir {
    pub fn new(tag: &str) -> TempDir {
        static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let n = SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let dir =
            std::env::temp_dir().join(format!("skep-mcp-{tag}-{}-{n}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("create temp dir");
        TempDir(dir)
    }

    pub fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// skepd in-process over `dir`: genesis on a fresh dir, recovery on a used
/// one. Port 0 binds an ephemeral port; a restart passes back the port the
/// adapter's URL already names.
pub fn spawn_daemon(dir: &Path, port: u16) -> Skepd {
    let daemon = Daemon::open(dir).expect("daemon open (genesis or recover)");
    serve(daemon, port, DEFAULT_WORKERS).expect("bind")
}

// ── minimal HTTP, for provisioning the daemon-side fixture ──────────────

fn http(port: u16, method: &str, path: &str, session: Option<&str>, body: &[u8]) -> (u16, Vec<u8>) {
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
    let sep = raw.windows(4).position(|w| w == b"\r\n\r\n").expect("header terminator");
    let status: u16 = std::str::from_utf8(&raw[..sep])
        .expect("ascii head")
        .split_whitespace()
        .nth(1)
        .expect("status code")
        .parse()
        .expect("numeric status");
    (status, raw[sep + 4..].to_vec())
}

fn op(port: u16, session: Option<&str>, frame: &str) -> Value {
    let (st, body) = http(port, "POST", "/op", session, frame.as_bytes());
    assert_eq!(st, 200, "op transport: {}", String::from_utf8_lossy(&body));
    serde_json::from_slice(&body).expect("op response is JSON")
}

// ── the claim ceremony (RES-27: an unclaimed daemon runs nothing else) ──
//
// The fixture claims each test board before the adapter drives ordinary
// ops: pre-claim, everything outside the ceremony's own op shapes answers
// `credential_refused claim_first`. A dedicated owner principal claims
// under the board's first delegated account; the suite's principal 1 is
// delegated beside it afterward, so no test address collides with the
// ceremony's.

/// The credential type addresses this build allocates (AUTH-7.1 horn B).
const T_ENROLL: &str = "1.1.0.1.0.1.0.3.1";
const T_CLAIM: &str = "1.1.0.1.0.1.0.3.3";

/// The ceremony's fixed identity: a high principal id the suite's own
/// principals never reach, deterministic key seeds so a reopened board
/// verifies against the same keys.
const OWNER_PRINCIPAL: u64 = 900;
const OWNER_ACCOUNT: &str = "1.0.1";
const OWNER_DOC1: &str = "1.0.1.0.1";

fn device_key() -> SigningKey {
    SigningKey::from_bytes(&[7; 32])
}

fn anchor_key() -> SigningKey {
    SigningKey::from_bytes(&[8; 32])
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// The HYBRID signer a seed carrier derives under tag 1 — the production row
/// (`mldsa65-ed25519`), the KDF PIN's two halves from the key's 32 bytes,
/// never the raw key itself (the ruled "one seed, two halves"): what the
/// ceremony enrols and what signs its sessions, both halves.
fn signer_of(sk: &SigningKey) -> HybridSigner {
    HybridSigner::from_seed(TAG_MLDSA65_ED25519, &sk.to_bytes()).expect("tag 1 is a row")
}

/// The ONE `ALGS` entry a seed carrier enrols: its derived tag-1 hybrid key
/// (the classical `ed25519` row is deleted — the hybrid-only launch).
fn pubkey_of(sk: &SigningKey) -> PublicKey {
    signer_of(sk).public_key().clone()
}

fn open_bare_session(port: u16, principal: u64) -> String {
    let body = format!("{{\"principal\":{principal}}}");
    let (st, answer) = http(port, "POST", "/session", None, body.as_bytes());
    assert_eq!(st, 200, "bare session: {}", String::from_utf8_lossy(&answer));
    let v: Value = serde_json::from_slice(&answer).expect("session JSON");
    v["session"].as_str().expect("session token").to_string()
}

/// A SIGNED session over the challenge handshake, signing the origin
/// actually dialed (the AUTH-6.4 framing) with the seed carrier's derived
/// HYBRID key — `sig` the hybrid blob, the post-quantum signature then the
/// Ed25519 signature, 6,746 hex under tag 1 (AUTH-4.32, AUTH-6.3). The
/// adapter itself opens BARE sessions and signs nothing; this is the
/// fixture's ceremony alone.
fn open_signed_session(port: u16, principal: u64, sk: &SigningKey) -> String {
    let (st, challenge) =
        http(port, "GET", &format!("/challenge?principal={principal}"), None, b"");
    assert_eq!(st, 200, "challenge: {}", String::from_utf8_lossy(&challenge));
    let v: Value = serde_json::from_slice(&challenge).expect("challenge JSON");
    let nonce = v["nonce"].as_str().expect("nonce").to_string();
    let origin = format!("http://127.0.0.1:{port}");
    let payload = framed(
        SESSION_TAG,
        &[origin.as_bytes(), nonce.as_bytes(), principal.to_string().as_bytes()],
    );
    let sig = hex(&signer_of(sk).sign(&payload));
    let body =
        json!({"principal": principal, "nonce": nonce, "origin": origin, "sig": sig}).to_string();
    let (st, answer) = http(port, "POST", "/session", None, body.as_bytes());
    assert_eq!(st, 200, "signed session: {}", String::from_utf8_lossy(&answer));
    let v: Value = serde_json::from_slice(&answer).expect("session JSON");
    v["session"].as_str().expect("session token").to_string()
}

/// Run the notebook claim ceremony over the wire (idempotent — a reopened
/// claimed board skips it): delegate the owner from π₀, the home mint, the
/// genesis enrollment atom + deposit, the signed claim.
fn claim_board(port: u16) {
    let (st, body) = http(port, "GET", "/health", None, b"");
    assert_eq!(st, 200, "health: {}", String::from_utf8_lossy(&body));
    let health: Value = serde_json::from_slice(&body).expect("health JSON");
    if !health["auth"]["claimant"].is_null() {
        return;
    }
    let boot = open_bare_session(port, 0);
    let v = op(port, Some(&boot), r#"{"op":"next_account_prefix","parent":"1"}"#);
    let prefix = v["addr"].as_str().expect("delegable prefix").to_string();
    assert_eq!(prefix, OWNER_ACCOUNT, "the ceremony must be the board's first delegate");
    let v = op(
        port,
        Some(&boot),
        &format!(r#"{{"op":"delegate","new_prefix":"{prefix}","new_id":{OWNER_PRINCIPAL}}}"#),
    );
    assert_eq!(v["resp"], "ack_addr", "owner delegate: {v}");
    let owner = open_bare_session(port, OWNER_PRINCIPAL);
    let v = op(
        port,
        Some(&owner),
        &format!(r#"{{"op":"create_new_document","account":"{OWNER_ACCOUNT}"}}"#),
    );
    assert_eq!(v["resp"], "ack_addr", "owner home mint: {v}");
    assert_eq!(v["addr"], json!(OWNER_DOC1), "the home mint is doc 1");
    // The enrollment record — the anchor and the device key — as ONE ATOM.
    let record_text = encode_enroll(&[
        Enrollment::new(pubkey_of(&anchor_key()), true, Some("paper-a".into()))
            .expect("a legal label"),
        Enrollment::new(pubkey_of(&device_key()), false, Some("notebook".into()))
            .expect("a legal label"),
    ]);
    // The record atom's insert is a DECLARED deposit (PUB-2.63; the
    // DECLARED horn of PUB-9.13): doc 1 is born published, and an undeclared
    // insert into it is the in-place edit the write path refuses (PUB-2.11).
    // The declaration names the record's CLASS TYPE (PUB-2.64) — ENROLL's,
    // the type the pair's `make_link` below carries.
    let v = op(
        port,
        Some(&owner),
        &json!({
            "op": "insert",
            "doc": OWNER_DOC1,
            "at": {"subspace": "1", "ordinal": "1"},
            "values": [{"atom": record_text}],
            "deposit": T_ENROLL,
        })
        .to_string(),
    );
    assert_eq!(v["resp"], "ack_addr", "genesis atom insert: {v}");
    let atom_addr = v["addr"].as_str().expect("the record atom's I-address").to_string();
    let v = op(
        port,
        Some(&owner),
        &json!({
            "op": "make_link",
            "home": OWNER_DOC1,
            "from": {"addrs": [atom_addr]},
            "to": {"addrs": [OWNER_ACCOUNT]},
            "ty": {"addrs": [T_ENROLL]},
        })
        .to_string(),
    );
    assert_eq!(v["resp"], "ack_addr", "genesis deposit: {v}");
    // The claim, from a session SIGNED by the device key.
    let signed = open_signed_session(port, OWNER_PRINCIPAL, &device_key());
    let v = op(
        port,
        Some(&signed),
        &json!({
            "op": "make_link",
            "home": OWNER_DOC1,
            "from": {"addrs": [OWNER_ACCOUNT]},
            "to": {"addrs": []},
            "ty": {"addrs": [T_CLAIM]},
        })
        .to_string(),
    );
    assert_eq!(v["resp"], "ack_addr", "the claim: {v}");
}

/// wire.md's end-to-end bootstrap, on a CLAIMED board: the ceremony first,
/// then π₀ delegates principal 1, then principal 1's own home mint. Doc 1
/// is born published and RES-26 shuts published homes to bare sessions, so
/// minting it here leaves every document the tests create a DRAFT the
/// adapter's bare session may write. Returns principal 1's account address.
pub fn provision_principal_1(port: u16) -> String {
    claim_board(port);
    let boot = open_bare_session(port, 0);
    let v = op(port, Some(&boot), r#"{"op":"next_account_prefix","parent":"1"}"#);
    let prefix = v["addr"].as_str().expect("delegable prefix").to_string();
    let v = op(
        port,
        Some(&boot),
        &format!(r#"{{"op":"delegate","new_prefix":"{prefix}","new_id":1}}"#),
    );
    assert_eq!(v["resp"], "ack_addr", "delegate: {v}");
    let account = v["addr"].as_str().expect("account address").to_string();
    let p1 = open_bare_session(port, 1);
    let v = op(
        port,
        Some(&p1),
        &format!(r#"{{"op":"create_new_document","account":"{account}"}}"#),
    );
    assert_eq!(v["resp"], "ack_addr", "principal 1's home mint: {v}");
    account
}

// ── a stub daemon, for answers the real one is never made to give ───────

/// A stand-in skepd on an ephemeral loopback port, for the rules only an
/// answer the real daemon never gives can show — `unauthenticated` on cue,
/// a reply cut short, bytes no canonical marshal writes. It answers each
/// connection in turn with the next scripted reply, exactly as given, and
/// closes its listener after the last, so a request past the script is
/// refused at once rather than left waiting. The handle yields every
/// request it read, head and body, as text.
pub fn stub_daemon(replies: Vec<Vec<u8>>) -> (u16, JoinHandle<Vec<String>>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind a stub daemon");
    let port = listener.local_addr().expect("stub address").port();
    let stub = std::thread::spawn(move || {
        let mut requests = Vec::new();
        for reply in replies {
            let (mut conn, _) = listener.accept().expect("accept");
            requests.push(read_request(&mut conn));
            // A caller that hangs up first is no fault of the stub's.
            let _ = conn.write_all(&reply);
        }
        requests
    });
    (port, stub)
}

/// One complete HTTP response as skepd frames it: the status, the
/// `Content-Length` that says where the body ends, `Connection: close`.
pub fn reply(status: u16, body: &str) -> Vec<u8> {
    format!(
        "HTTP/1.1 {status} X\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
    .into_bytes()
}

/// One request off a stub connection — its head, then as many body bytes
/// as its `Content-Length` names — as text.
fn read_request(conn: &mut TcpStream) -> String {
    let mut raw = Vec::new();
    let mut buf = [0u8; 1024];
    loop {
        if let Some(sep) = raw.windows(4).position(|w| w == b"\r\n\r\n") {
            let head = String::from_utf8_lossy(&raw[..sep]).to_ascii_lowercase();
            let len: usize = head
                .lines()
                .find_map(|l| l.strip_prefix("content-length:"))
                .and_then(|v| v.trim().parse().ok())
                .unwrap_or(0);
            if raw.len() >= sep + 4 + len {
                return String::from_utf8_lossy(&raw).into_owned();
            }
        }
        let n = conn.read(&mut buf).expect("read the request");
        assert!(n > 0, "the request ended early");
        raw.extend_from_slice(&buf[..n]);
    }
}
