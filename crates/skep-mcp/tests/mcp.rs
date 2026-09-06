//! Integration against the real stack: an in-process skepd (it is a
//! library crate in this workspace) on an ephemeral port over a temp data
//! dir, a principal provisioned exactly as wire.md's end-to-end example,
//! and the built `skep-mcp` binary spawned with env pointing at the daemon
//! — real JSON-RPC driven through its stdin/stdout. Store semantics are
//! trusted to the stores' own tests; these assert the adapter: protocol
//! framing, verbatim pass-through (rejections included), the
//! reopen-and-resend path across a daemon restart, and the
//! tools-file↔dispatch no-drift startup errors.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::time::Duration;

use ed25519_dalek::{Signer, SigningKey};
use serde_json::{json, Value};
use skep_identity::{encode_enroll, framed, Enrollment, PublicKey, SESSION_TAG};
use skepd::{serve, Daemon, Skepd};

// ── a self-owned temp dir (kept dependency-free) ────────────────────────

struct TempDir(PathBuf);

impl TempDir {
    fn new(tag: &str) -> TempDir {
        static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let n = SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let dir =
            std::env::temp_dir().join(format!("skep-mcp-{tag}-{}-{n}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("create temp dir");
        TempDir(dir)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
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

fn pubkey_of(sk: &SigningKey) -> PublicKey {
    PublicKey::parse("ed25519", &hex(&sk.verifying_key().to_bytes())).expect("a real point")
}

fn open_bare_session(port: u16, principal: u64) -> String {
    let body = format!("{{\"principal\":{principal}}}");
    let (st, resp) = http(port, "POST", "/session", None, body.as_bytes());
    assert_eq!(st, 200, "bare session: {}", String::from_utf8_lossy(&resp));
    let v: Value = serde_json::from_slice(&resp).expect("session JSON");
    v["session"].as_str().expect("session token").to_string()
}

/// A SIGNED session over the challenge handshake, signing the origin
/// actually dialed (the AUTH-6.4 framing).
fn open_signed_session(port: u16, principal: u64, sk: &SigningKey) -> String {
    let (st, body) = http(port, "GET", &format!("/challenge?principal={principal}"), None, b"");
    assert_eq!(st, 200, "challenge: {}", String::from_utf8_lossy(&body));
    let v: Value = serde_json::from_slice(&body).expect("challenge JSON");
    let nonce = v["nonce"].as_str().expect("nonce").to_string();
    let origin = format!("http://127.0.0.1:{port}");
    let payload = framed(
        SESSION_TAG,
        &[origin.as_bytes(), nonce.as_bytes(), principal.to_string().as_bytes()],
    );
    let sig = hex(&sk.sign(&payload).to_bytes());
    let body =
        json!({"principal": principal, "nonce": nonce, "origin": origin, "sig": sig}).to_string();
    let (st, resp) = http(port, "POST", "/session", None, body.as_bytes());
    assert_eq!(st, 200, "signed session: {}", String::from_utf8_lossy(&resp));
    let v: Value = serde_json::from_slice(&resp).expect("session JSON");
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
    let record = encode_enroll(&[
        Enrollment::new(pubkey_of(&anchor_key()), true, Some("paper-a".into()))
            .expect("a legal label"),
        Enrollment::new(pubkey_of(&device_key()), false, Some("notebook".into()))
            .expect("a legal label"),
    ]);
    let record_text = String::from_utf8(record).expect("the record grammar is UTF-8");
    // The record atom's insert is a DECLARED deposit (PUB-2.63; the
    // DECLARED horn of PUB-9.13): doc 1 is born published, and an undeclared
    // insert into it is the in-place edit the write path refuses (PUB-2.11).
    let v = op(
        port,
        Some(&owner),
        &json!({
            "op": "insert",
            "doc": OWNER_DOC1,
            "at": {"subspace": "1", "ordinal": "1"},
            "values": [{"atom": record_text}],
            "deposit": true,
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
fn provision_principal_1(port: u16) -> String {
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

fn spawn_daemon(dir: &Path, port: u16) -> Skepd {
    let daemon = Daemon::open(dir).expect("daemon open (genesis or recover)");
    serve(daemon, port, 4).expect("bind")
}

// ── the adapter under test ───────────────────────────────────────────────

struct Mcp {
    child: Child,
    stdin: Option<ChildStdin>,
    stdout: BufReader<ChildStdout>,
    next_id: u64,
}

impl Mcp {
    fn spawn(port: u16, principal: &str) -> Mcp {
        Mcp::spawn_with_commons(port, principal, None)
    }

    fn spawn_with_commons(port: u16, principal: &str, commons: Option<&str>) -> Mcp {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_skep-mcp"));
        cmd.env("SKEPD_URL", format!("http://127.0.0.1:{port}"))
            .env("SKEP_PRINCIPAL", principal)
            .env_remove("SKEP_COMMONS")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit());
        if let Some(addr) = commons {
            cmd.env("SKEP_COMMONS", addr);
        }
        let mut child = cmd.spawn().expect("spawn skep-mcp");
        let stdin = child.stdin.take().expect("child stdin");
        let stdout = BufReader::new(child.stdout.take().expect("child stdout"));
        Mcp { child, stdin: Some(stdin), stdout, next_id: 0 }
    }

    fn send_line(&mut self, line: &str) {
        let stdin = self.stdin.as_mut().expect("stdin open");
        stdin.write_all(line.as_bytes()).expect("write to adapter");
        stdin.write_all(b"\n").expect("write newline");
        stdin.flush().expect("flush to adapter");
    }

    fn read_message(&mut self) -> Value {
        let mut line = String::new();
        loop {
            line.clear();
            let n = self.stdout.read_line(&mut line).expect("read from adapter");
            assert!(n > 0, "adapter closed stdout unexpectedly");
            if !line.trim().is_empty() {
                return serde_json::from_str(line.trim()).unwrap_or_else(|e| {
                    panic!("adapter wrote a non-JSON line ({e}): {line:?}")
                });
            }
        }
    }

    /// One request → its response (the adapter answers in order).
    fn request(&mut self, method: &str, params: Value) -> Value {
        self.next_id += 1;
        let id = self.next_id;
        self.send_line(
            &json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params}).to_string(),
        );
        let v = self.read_message();
        assert_eq!(v["id"], json!(id), "responses correlate by id: {v}");
        v
    }

    fn notify(&mut self, method: &str) {
        self.send_line(&json!({"jsonrpc": "2.0", "method": method}).to_string());
    }

    fn initialize(&mut self) -> Value {
        let v = self.request(
            "initialize",
            json!({
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": {"name": "test-harness", "version": "0"}
            }),
        );
        self.notify("notifications/initialized");
        v["result"].clone()
    }

    /// tools/call, returning (isError, text).
    fn call(&mut self, tool: &str, args: Value) -> (bool, String) {
        let v = self.request("tools/call", json!({"name": tool, "arguments": args}));
        assert!(v.get("error").is_none(), "tools/call is never a JSON-RPC error: {v}");
        let result = &v["result"];
        assert_eq!(result["content"][0]["type"], "text", "one text block: {result}");
        let is_error = result["isError"].as_bool().expect("isError present");
        let text = result["content"][0]["text"].as_str().expect("text block").to_string();
        (is_error, text)
    }

    /// tools/call that must reach skepd: parses the verbatim document.
    fn call_doc(&mut self, tool: &str, args: Value) -> Value {
        let (is_error, text) = self.call(tool, args);
        assert!(!is_error, "unexpected transport failure: {text}");
        serde_json::from_str(&text)
            .unwrap_or_else(|e| panic!("tool text is not JSON ({e}): {text}"))
    }

    /// Close stdin (EOF) and reap — the clean-exit path under test.
    fn finish(mut self) -> std::process::ExitStatus {
        drop(self.stdin.take());
        self.child.wait().expect("wait for adapter")
    }
}

impl Drop for Mcp {
    fn drop(&mut self) {
        drop(self.stdin.take());
        for _ in 0..100 {
            if let Ok(Some(_)) = self.child.try_wait() {
                return;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// The catalog the binary embeds — the expected tools/list and the base
/// for the drift fixtures.
fn embedded_tools() -> Value {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/tools.json");
    serde_json::from_str(&std::fs::read_to_string(path).expect("read tools.json"))
        .expect("tools.json parses")
}

/// A width tumbler at `addr`'s own depth: zeros with `last` in the final
/// component. `width_of(a, 1)` is the unit subtree span width the daemon
/// records for an address-form endset member; `width_of(a, k)` the width of
/// a k-position I-run starting at `a`.
fn width_of(addr: &str, last: u64) -> String {
    let n = addr.split('.').count();
    let mut comps = vec!["0".to_string(); n];
    comps[n - 1] = last.to_string();
    comps.join(".")
}

// ── the tests ────────────────────────────────────────────────────────────

#[test]
fn initialize_and_tools_list_serve_the_catalog() {
    let dir = TempDir::new("init");
    let sd = spawn_daemon(dir.path(), 0);
    let port = sd.port();

    let mut mcp = Mcp::spawn(port, "1");
    let init = mcp.initialize();
    assert_eq!(init["protocolVersion"], "2025-06-18", "protocolVersion echoes the client's");
    assert_eq!(init["serverInfo"]["name"], "skep");
    assert!(
        init["instructions"].as_str().is_some_and(|s| !s.is_empty()),
        "instructions non-empty: {init}"
    );
    assert!(init["capabilities"]["tools"].is_object(), "tools capability: {init}");

    let v = mcp.request("tools/list", json!({}));
    let tools = v["result"]["tools"].as_array().expect("tools array").clone();
    let listed: Vec<&str> = tools.iter().map(|t| t["name"].as_str().expect("name")).collect();
    let file = embedded_tools();
    let expected: Vec<&str> = file["tools"]
        .as_array()
        .expect("file tools")
        .iter()
        .map(|t| t["name"].as_str().expect("file name"))
        .collect();
    assert_eq!(listed, expected, "exactly the tools file's names, in file order");
    assert_eq!(tools.len(), 39, "38 wire ops + session_info");
    for t in &tools {
        assert!(
            t["description"].as_str().is_some_and(|s| !s.is_empty()),
            "every tool carries a description: {t}"
        );
        assert!(t["inputSchema"].is_object(), "every tool carries a schema: {t}");
    }

    // Protocol basics alongside: ping, and unknown method → -32601.
    let v = mcp.request("ping", json!({}));
    assert_eq!(v["result"], json!({}));
    let v = mcp.request("resources/list", json!({}));
    assert_eq!(v["error"]["code"], json!(-32601), "unknown method: {v}");

    // Stdin EOF is the clean exit.
    let status = mcp.finish();
    assert!(status.success(), "clean exit on stdin EOF: {status:?}");

    sd.shutdown();
}

#[test]
fn session_info_reports_principal_account_health() {
    let dir = TempDir::new("sessinfo");
    let sd = spawn_daemon(dir.path(), 0);
    let port = sd.port();
    let account = provision_principal_1(port);

    let mut mcp = Mcp::spawn(port, "1");
    mcp.initialize();
    let doc = mcp.call_doc("session_info", json!({}));
    assert_eq!(doc["principal"], json!(1));
    assert_eq!(doc["account"].as_str(), Some(account.as_str()), "account: {doc}");
    assert_eq!(doc["health"]["ok"], json!(true));
    assert!(doc["health"]["log_position"].is_u64(), "health rides along: {doc}");

    sd.shutdown();
}

#[test]
fn lifecycle_create_insert_retrieve_link_and_rejections() {
    let dir = TempDir::new("life");
    let sd = spawn_daemon(dir.path(), 0);
    let port = sd.port();
    let account = provision_principal_1(port);

    let mut mcp = Mcp::spawn(port, "1");
    mcp.initialize();

    // create → insert → retrieve. The string write form is per-byte:
    // "hello" seats five values at positions 1..=5, so width "0.5" covers
    // it exactly and the delivery is one content item.
    let v = mcp.call_doc("create_new_document", json!({"account": account}));
    assert_eq!(v["resp"], "ack_addr", "create: {v}");
    let doc = v["addr"].as_str().expect("doc addr").to_string();

    let v = mcp.call_doc(
        "insert",
        json!({"doc": doc, "at": {"subspace": "1", "ordinal": "1"}, "values": ["hello"]}),
    );
    assert_eq!(v["resp"], "ack_addr", "insert: {v}");

    let v = mcp.call_doc(
        "retrieve_v",
        json!({"specs": [{"doc": doc, "span": {"start": "1.1", "width": "0.5"}}]}),
    );
    assert_eq!(v["resp"], "delivery");
    assert_eq!(v["items"], json!([{"content": "hello"}]));

    // An atom form: ONE composite value at ONE position, never coalesced
    // into the per-byte run beside it.
    let v = mcp.call_doc(
        "insert",
        json!({"doc": doc, "at": {"subspace": "1", "ordinal": "6"}, "values": [{"atom": "chunk"}]}),
    );
    assert_eq!(v["resp"], "ack_addr", "atom insert: {v}");
    let v = mcp.call_doc(
        "retrieve_v",
        json!({"specs": [{"doc": doc, "span": {"start": "1.1", "width": "0.6"}}]}),
    );
    assert_eq!(v["items"], json!([{"content": "hello"}, {"atom": "chunk"}]));

    // make_link (through the schema's from_ → the wire's from) and
    // follow_link on the TO slot.
    let v = mcp.call_doc("create_new_document", json!({"account": account}));
    let doc2 = v["addr"].as_str().expect("doc2 addr").to_string();
    let v = mcp.call_doc(
        "insert",
        json!({"doc": doc2, "at": {"subspace": "1", "ordinal": "1"}, "values": ["linked"]}),
    );
    assert_eq!(v["resp"], "ack_addr");
    let v = mcp.call_doc("create_new_document", json!({"account": account}));
    let tdoc = v["addr"].as_str().expect("tdoc addr").to_string();
    let v = mcp.call_doc(
        "insert",
        json!({"doc": tdoc, "at": {"subspace": "1", "ordinal": "1"}, "values": ["type:jump"]}),
    );
    assert_eq!(v["resp"], "ack_addr");

    let v = mcp.call_doc(
        "make_link",
        json!({
            "home": doc,
            "from_": [{"source": doc, "span": {"start": "1.1", "width": "0.5"}}],
            "to": [{"source": doc2, "span": {"start": "1.1", "width": "0.6"}}],
            "ty": [{"source": tdoc, "span": {"start": "1.1", "width": "0.1"}}]
        }),
    );
    assert_eq!(v["resp"], "ack_addr", "make_link with from_: {v}");
    let link = v["addr"].as_str().expect("link addr").to_string();

    let v = mcp.call_doc("follow_link", json!({"a": link, "slot": 2}));
    assert_eq!(v["resp"], "follow");
    assert!(
        v["result"]["ok"].as_array().is_some_and(|s| !s.is_empty()),
        "TO coverage nonempty: {v}"
    );

    // A rejection is a NORMAL result: isError false, document verbatim.
    let v = mcp.call_doc(
        "retrieve_v",
        json!({"specs": [{"doc": "1.0.9.0.1", "span": {"start": "1.1", "width": "0.1"}}]}),
    );
    assert_eq!(v["resp"], "rejected", "rejections pass through as content: {v}");
    assert_eq!(v["code"], "doc_not_registered");

    // An unknown tool name is isError with a message naming it.
    let (is_error, text) = mcp.call("frobnicate", json!({}));
    assert!(is_error, "unknown tool is isError");
    assert!(text.contains("frobnicate"), "the message names the tool: {text}");

    // A malformed JSON line gets -32700 with id null, and the process
    // survives to answer the next request.
    mcp.send_line("this is not json");
    let v = mcp.read_message();
    assert_eq!(v["error"]["code"], json!(-32700), "parse error: {v}");
    assert!(v["id"].is_null(), "parse errors carry id null: {v}");
    let v = mcp.request("ping", json!({}));
    assert_eq!(v["result"], json!({}), "the adapter survives malformed input");

    sd.shutdown();
}

#[test]
fn daemon_restart_reopens_the_session_and_resends() {
    let dir = TempDir::new("restart");
    let sd = spawn_daemon(dir.path(), 0);
    let port = sd.port();
    let account = provision_principal_1(port);

    let mut mcp = Mcp::spawn(port, "1");
    mcp.initialize();
    let v = mcp.call_doc("create_new_document", json!({"account": account}));
    let doc = v["addr"].as_str().expect("doc addr").to_string();
    let v = mcp.call_doc(
        "insert",
        json!({"doc": doc, "at": {"subspace": "1", "ordinal": "1"}, "values": ["hello"]}),
    );
    assert_eq!(v["resp"], "ack_addr", "the pre-restart write: {v}");

    // Kill the daemon mid-session — tokens die with the process — and
    // restart on the same data dir and the SAME port (the adapter's URL is
    // fixed for its lifetime).
    sd.shutdown();
    let sd = spawn_daemon(dir.path(), port);

    // The adapter holds a stale token: the daemon answers unauthenticated,
    // the adapter reopens its session and resends once — invisible here.
    let v = mcp.call_doc(
        "insert",
        json!({"doc": doc, "at": {"subspace": "1", "ordinal": "6"}, "values": [", wire"]}),
    );
    assert_eq!(v["resp"], "ack_addr", "the write after restart must succeed: {v}");

    let v = mcp.call_doc(
        "retrieve_v",
        json!({"specs": [{"doc": doc, "span": {"start": "1.1", "width": "0.11"}}]}),
    );
    assert_eq!(v["items"], json!([{"content": "hello, wire"}]));

    sd.shutdown();
}

/// Wire v5's two-form slots through the adapter, one link exercising both:
/// FROM as a V-spec array (content-resolved to permanent I-spans — the v4
/// meaning, pinned by the exact recorded span), TO and TYPE as
/// `{"addrs": […]}` (the names verbatim, one unit subtree span per
/// address, the TYPE a ghost nothing occupies).
#[test]
fn make_link_addrs_form_records_names_verbatim() {
    let dir = TempDir::new("addrs");
    let sd = spawn_daemon(dir.path(), 0);
    let port = sd.port();
    let account = provision_principal_1(port);

    let mut mcp = Mcp::spawn(port, "1");
    mcp.initialize();

    let v = mcp.call_doc("create_new_document", json!({"account": account}));
    let doc = v["addr"].as_str().expect("doc addr").to_string();
    let v = mcp.call_doc(
        "insert",
        json!({"doc": doc, "at": {"subspace": "1", "ordinal": "1"}, "values": ["hello"]}),
    );
    assert_eq!(v["resp"], "ack_addr", "insert: {v}");
    let i_start = v["addr"].as_str().expect("first minted I-address").to_string();

    let v = mcp.call_doc("create_new_document", json!({"account": account}));
    let doc2 = v["addr"].as_str().expect("doc2 addr").to_string();
    // A ghost: doc2's never-occupied subspace 3. Nothing resides there and
    // nothing has to — the addrs form records names, not contents.
    let ghost = format!("{doc2}.0.3.6.1");

    let v = mcp.call_doc(
        "make_link",
        json!({
            "home": doc,
            "from_": [{"source": doc, "span": {"start": "1.1", "width": "0.5"}}],
            "to": {"addrs": [doc2]},
            "ty": {"addrs": [ghost]}
        }),
    );
    assert_eq!(v["resp"], "ack_addr", "two-form make_link: {v}");
    let link = v["addr"].as_str().expect("link addr").to_string();

    let v = mcp.call_doc("read_link", json!({"a": link}));
    assert_eq!(
        v["link"]["slots"],
        json!([
            [{"start": i_start, "width": width_of(&i_start, 5)}],
            [{"start": doc2, "width": width_of(&doc2, 1)}],
            [{"start": ghost, "width": width_of(&ghost, 1)}]
        ]),
        "recorded endsets — resolved I-span, then names verbatim: {v}"
    );

    sd.shutdown();
}

/// The slot forms' failure modes are data, not transport errors: an object
/// mixing the two forms is the daemon's unparseable rejection, an empty
/// addrs TYPE its empty_type_resolution — both isError false.
#[test]
fn slot_form_faults_surface_as_normal_results() {
    let dir = TempDir::new("slotfault");
    let sd = spawn_daemon(dir.path(), 0);
    let port = sd.port();
    let account = provision_principal_1(port);

    let mut mcp = Mcp::spawn(port, "1");
    mcp.initialize();
    let v = mcp.call_doc("create_new_document", json!({"account": account}));
    let doc = v["addr"].as_str().expect("doc addr").to_string();

    // Both forms at once in one slot: not a form ('resolve' is not a
    // make_link key), so the frame never becomes an operation.
    let v = mcp.call_doc(
        "make_link",
        json!({
            "home": doc,
            "from_": [],
            "to": [],
            "ty": {"addrs": ["1.1"], "resolve": []}
        }),
    );
    assert_eq!(v["resp"], "rejected", "mixed forms: {v}");
    assert_eq!(v["op"], "unparseable");
    assert_eq!(v["code"], "malformed");

    // An empty addrs TYPE parses; the store rejects it exactly as an empty
    // resolution always has — the type floor reads the slot as given.
    let v = mcp.call_doc(
        "make_link",
        json!({"home": doc, "from_": [], "to": [], "ty": {"addrs": []}}),
    );
    assert_eq!(v["resp"], "rejected", "empty addrs type: {v}");
    assert_eq!(v["code"], "empty_type_resolution");

    sd.shutdown();
}

/// SKEP_COMMONS set: the instructions carry the registry sentence with the
/// address substituted. Unset: byte-identical to the tools file's
/// instructions. Malformed: startup refusal naming the variable. No daemon
/// anywhere — initialize never dials skepd.
#[test]
fn skep_commons_appends_the_registry_sentence() {
    let file = embedded_tools();
    let base = file["instructions"].as_str().expect("instructions").to_string();
    let template = file["commons_instructions"].as_str().expect("template").to_string();

    let commons = "1.0.2.0.9";
    let mut mcp = Mcp::spawn_with_commons(1, "1", Some(commons));
    let init = mcp.initialize();
    let expected = format!("{base}\n\n{}", template.replace("{addr}", commons));
    assert_eq!(
        init["instructions"].as_str(),
        Some(expected.as_str()),
        "the sentence is appended with the address substituted"
    );
    assert!(
        expected.contains(&format!("{commons}.0.3.50")),
        "the defines-type address rides in the sentence: {expected}"
    );
    assert!(mcp.finish().success());

    let mut mcp = Mcp::spawn_with_commons(1, "1", None);
    let init = mcp.initialize();
    assert_eq!(
        init["instructions"].as_str(),
        Some(base.as_str()),
        "unset leaves the instructions byte-identical"
    );
    assert!(mcp.finish().success());
}

#[test]
fn malformed_skep_commons_refuses_startup() {
    for bad in ["", "banana", "1..2", "0.1", "1.0", "1.0.0.1", "1.0.1.0.1.0.1.0.2"] {
        let out = Command::new(env!("CARGO_BIN_EXE_skep-mcp"))
            .env("SKEPD_URL", "http://127.0.0.1:1")
            .env("SKEP_PRINCIPAL", "1")
            .env("SKEP_COMMONS", bad)
            .output()
            .expect("run skep-mcp");
        assert!(!out.status.success(), "'{bad}' must refuse startup");
        let err = String::from_utf8_lossy(&out.stderr);
        assert!(err.contains("SKEP_COMMONS"), "stderr names the variable for '{bad}': {err}");
    }
}

#[test]
fn tools_file_dispatch_drift_refuses_startup_both_directions() {
    // Catalog validation precedes any network use, so no daemon is needed
    // and SKEPD_URL can point nowhere.
    let dir = TempDir::new("drift");
    let real = embedded_tools();

    // Direction one: a file entry the dispatch doesn't know.
    let mut extra = real.clone();
    extra["tools"].as_array_mut().expect("tools").push(json!({
        "name": "frobnicate",
        "description": "no such wire op",
        "inputSchema": {"type": "object"}
    }));
    let path = dir.path().join("extra.json");
    std::fs::write(&path, extra.to_string()).expect("write doctored file");
    let err = spawn_expect_startup_failure(&path);
    assert!(err.contains("frobnicate"), "stderr names the unknown tool: {err}");

    // Direction two: a dispatch op with no file entry.
    let mut missing = real.clone();
    missing["tools"].as_array_mut().expect("tools").retain(|t| t["name"] != "insert");
    let path = dir.path().join("missing.json");
    std::fs::write(&path, missing.to_string()).expect("write doctored file");
    let err = spawn_expect_startup_failure(&path);
    assert!(err.contains("insert"), "stderr names the uncovered op: {err}");

    // And the undoctored file starts, then exits cleanly on immediate EOF.
    let path = dir.path().join("real.json");
    std::fs::write(&path, real.to_string()).expect("write real file");
    let out = Command::new(env!("CARGO_BIN_EXE_skep-mcp"))
        .args(["--tools-file", path.to_str().expect("utf-8 path")])
        .env("SKEPD_URL", "http://127.0.0.1:1")
        .env("SKEP_PRINCIPAL", "1")
        .env_remove("SKEP_COMMONS")
        .output()
        .expect("run skep-mcp");
    assert!(
        out.status.success(),
        "the real catalog must start: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

fn spawn_expect_startup_failure(tools_file: &Path) -> String {
    let out = Command::new(env!("CARGO_BIN_EXE_skep-mcp"))
        .args(["--tools-file", tools_file.to_str().expect("utf-8 path")])
        .env("SKEPD_URL", "http://127.0.0.1:1")
        .env("SKEP_PRINCIPAL", "1")
        .env_remove("SKEP_COMMONS")
        .output()
        .expect("run skep-mcp");
    assert!(!out.status.success(), "a drifted tools file must refuse startup");
    String::from_utf8_lossy(&out.stderr).into_owned()
}
