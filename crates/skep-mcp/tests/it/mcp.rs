//! Integration against the real stack: an in-process skepd (it is a
//! library crate in this workspace) on an ephemeral port over a temp data
//! dir, a principal provisioned exactly as wire.md's end-to-end example,
//! and the built `skep-mcp` binary spawned with env pointing at the daemon
//! — real JSON-RPC driven through its stdin/stdout. Store semantics are
//! trusted to the stores' own tests; these assert the adapter: protocol
//! framing, verbatim pass-through (rejections included), the session's
//! open, reissue and token, the reopen-and-reissue path across a daemon
//! restart, and startup's refusals, the tools-file↔dispatch no-drift
//! errors among them. The daemon and the principal are `common`'s; this
//! file is the adapter's driver and the tests.
//!
//! Where a rule shows only in an answer the real daemon never gives —
//! `unauthenticated` on cue, a reply cut short, bytes no canonical marshal
//! writes — `common::stub_daemon` answers instead and hands back the
//! requests it read; startup and the line protocol need no daemon at all.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::path::Path;
use std::process::{Child, ChildStderr, ChildStdin, ChildStdout, Command, Output, Stdio};
use std::time::{Duration, Instant};

use serde_json::{json, Value};

use crate::common::{provision_principal_1, reply, spawn_daemon, stub_daemon, TempDir};

// ── the adapter under test ───────────────────────────────────────────────

struct Mcp {
    child: Child,
    stdin: Option<ChildStdin>,
    stdout: BufReader<ChildStdout>,
    /// The adapter's log, when the test reads it (`spawn_logged`).
    stderr: Option<ChildStderr>,
    next_id: u64,
}

impl Mcp {
    fn spawn(port: u16, principal: &str) -> Mcp {
        Mcp::launch(port, principal, None, Stdio::inherit())
    }

    fn spawn_with_commons(port: u16, principal: &str, commons: Option<&str>) -> Mcp {
        Mcp::launch(port, principal, commons, Stdio::inherit())
    }

    /// An adapter whose log the test reads, through `finish_logged`.
    fn spawn_logged(port: u16, principal: &str) -> Mcp {
        Mcp::launch(port, principal, None, Stdio::piped())
    }

    fn launch(port: u16, principal: &str, commons: Option<&str>, log: Stdio) -> Mcp {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_skep-mcp"));
        cmd.env("SKEPD_URL", format!("http://127.0.0.1:{port}"))
            .env("SKEP_PRINCIPAL", principal)
            .env_remove("SKEP_COMMONS")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(log);
        if let Some(addr) = commons {
            cmd.env("SKEP_COMMONS", addr);
        }
        let mut child = cmd.spawn().expect("spawn skep-mcp");
        let stdin = child.stdin.take().expect("child stdin");
        let stdout = BufReader::new(child.stdout.take().expect("child stdout"));
        let stderr = child.stderr.take();
        Mcp { child, stdin: Some(stdin), stdout, stderr, next_id: 0 }
    }

    fn send_line(&mut self, line: &str) {
        let stdin = self.stdin.as_mut().expect("stdin open");
        stdin.write_all(line.as_bytes()).expect("write to adapter");
        stdin.write_all(b"\n").expect("write newline");
        stdin.flush().expect("flush to adapter");
    }

    /// Raw bytes onto the adapter's stdin — for a line no `&str` can hold.
    fn send_bytes(&mut self, bytes: &[u8]) {
        let stdin = self.stdin.as_mut().expect("stdin open");
        stdin.write_all(bytes).expect("write to adapter");
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

    /// tools/call that must reach skepd: its tool result's text, parsed as
    /// JSON — a response document, or session_info's report.
    fn call_json(&mut self, tool: &str, args: Value) -> Value {
        let (is_error, text) = self.call(tool, args);
        assert!(!is_error, "unexpected transport failure: {text}");
        serde_json::from_str(&text)
            .unwrap_or_else(|e| panic!("tool result's text is not JSON ({e}): {text}"))
    }

    /// Close stdin (EOF) and reap — the clean-exit path under test.
    fn finish(mut self) -> std::process::ExitStatus {
        drop(self.stdin.take());
        self.child.wait().expect("wait for adapter")
    }

    /// Close stdin (EOF), read the adapter's log to its end, and reap.
    fn finish_logged(mut self) -> (std::process::ExitStatus, String) {
        drop(self.stdin.take());
        let mut log = String::new();
        let mut stderr = self.stderr.take().expect("an adapter spawned logged");
        stderr.read_to_string(&mut log).expect("read the adapter's log");
        (self.child.wait().expect("wait for adapter"), log)
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
fn embedded_catalog() -> Value {
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

/// wire.md §Rejections' own example: the write gate's answer to a frame
/// that carries no live session — the adapter's one cue to reissue.
const UNAUTHENTICATED: &str =
    r#"{"code":"unauthenticated","disposition":"permanent","op":"insert","resp":"rejected"}"#;

/// An acknowledged write, as skepd spells one.
const ACK: &str = r#"{"addr":"1.0.1.0.1.0.1.1","at":7,"resp":"ack_addr"}"#;

/// Session tokens a stub issues (wire.md §Sessions: 32 lowercase hex).
const TOKEN: &str = "9f3a6c21d4b8e07a5c1b2d4e6f708192";
const OLD: &str = "0123456789abcdef0123456789abcdef";
const NEW: &str = "fedcba9876543210fedcba9876543210";

/// One insert's arguments — any write will do; the stub reads none of it.
fn an_insert() -> Value {
    json!({"doc": "1.0.1.0.1", "at": {"subspace": "1", "ordinal": "1"}, "values": ["x"]})
}

/// A `/session` 200 issuing `token` to principal 1.
fn session_reply(token: &str) -> Vec<u8> {
    reply(200, &format!(r#"{{"principal":1,"session":"{token}"}}"#))
}

/// A reply the connection broke in the middle of: its `Content-Length`
/// promises 64 bytes, and 7 arrive.
fn cut_short() -> Vec<u8> {
    b"HTTP/1.1 200 X\r\nContent-Length: 64\r\nConnection: close\r\n\r\n{\"at\":7".to_vec()
}

/// The session token a stub request carried, if any.
fn session_of(request: &str) -> Option<&str> {
    let (head, _) = request.split_once("\r\n\r\n").expect("a request head");
    head.lines().find_map(|line| {
        let (name, value) = line.split_once(':')?;
        name.eq_ignore_ascii_case("skepd-session").then(|| value.trim())
    })
}

/// A stub request's body: what follows its head.
fn body_of(request: &str) -> &str {
    request.split_once("\r\n\r\n").expect("a request head").1
}

/// The adapter run to completion: `args`, the three variables removed and
/// then `env` set, stdin empty.
fn run_adapter(args: &[&str], env: &[(&str, &str)]) -> Output {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_skep-mcp"));
    cmd.args(args);
    for var in ["SKEPD_URL", "SKEP_PRINCIPAL", "SKEP_COMMONS"] {
        cmd.env_remove(var);
    }
    cmd.envs(env.iter().copied());
    cmd.output().expect("run skep-mcp")
}

// ── the tests ────────────────────────────────────────────────────────────

#[test]
fn initialize_and_tools_list_serve_the_catalog() {
    // No daemon: nothing below dials skepd.
    let mut mcp = Mcp::spawn(1, "1");
    let init = mcp.initialize();
    assert_eq!(
        init["protocolVersion"], "2025-06-18",
        "a client naming 2025-06-18 is answered it — also the fallback, so this cannot tell \
         an echo from a constant"
    );
    assert_eq!(init["serverInfo"]["name"], "skep");
    assert!(
        init["instructions"].as_str().is_some_and(|s| !s.is_empty()),
        "instructions non-empty: {init}"
    );
    assert!(init["capabilities"]["tools"].is_object(), "tools capability: {init}");

    let v = mcp.request("tools/list", json!({}));
    let tools = v["result"]["tools"].as_array().expect("tools array").clone();
    let listed: Vec<&str> = tools.iter().map(|t| t["name"].as_str().expect("name")).collect();
    let file = embedded_catalog();
    let expected: Vec<&str> = file["tools"]
        .as_array()
        .expect("file tools")
        .iter()
        .map(|t| t["name"].as_str().expect("file name"))
        .collect();
    assert_eq!(listed, expected, "exactly the tools file's names, in file order");
    assert_eq!(v["result"]["tools"], file["tools"], "tools/list is the file's entries, verbatim");
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

    // Invalid params and an invalid request, JSON-RPC 2.0's own codes.
    let v = mcp.request("tools/call", json!({}));
    assert_eq!(v["error"]["code"], json!(-32602), "params that name no tool: {v}");
    mcp.send_line(r#"{"jsonrpc":"2.0","id":"no-method"}"#);
    let v = mcp.read_message();
    assert_eq!(v["error"]["code"], json!(-32600), "a request that names no method: {v}");
    assert_eq!(v["id"], json!("no-method"), "answered under its own id: {v}");

    // Stdin EOF is the clean exit.
    let status = mcp.finish();
    assert!(status.success(), "clean exit on stdin EOF: {status:?}");
}

/// A client that names no protocolVersion is answered the revision this
/// server was written against, 2025-06-18 — params without one, or no
/// params at all. No daemon: initialize never dials.
#[test]
fn initialize_answers_the_fallback_revision_when_none_is_named() {
    let mut mcp = Mcp::spawn(1, "1");
    let v = mcp.request("initialize", json!({"capabilities": {}}));
    assert_eq!(v["result"]["protocolVersion"], "2025-06-18", "params without a revision: {v}");
    mcp.send_line(r#"{"jsonrpc":"2.0","id":"bare","method":"initialize"}"#);
    let v = mcp.read_message();
    assert_eq!((&v["id"], &v["result"]["protocolVersion"]), (&json!("bare"), &json!("2025-06-18")));
}

#[test]
fn session_info_reports_principal_account_health() {
    let dir = TempDir::new("sessinfo");
    let daemon = spawn_daemon(dir.path(), 0);
    let port = daemon.port();
    let account = provision_principal_1(port);

    let mut mcp = Mcp::spawn(port, "1");
    mcp.initialize();
    let info = mcp.call_json("session_info", json!({}));
    assert_eq!(info["principal"], json!(1));
    assert_eq!(info["account"].as_str(), Some(account.as_str()), "account: {info}");
    assert_eq!(info["health"]["ok"], json!(true));
    assert!(info["health"]["log_position"].is_u64(), "health rides along: {info}");

    // An undelegated principal's account is null — wire.md's maybe_addr for
    // an unknown principal — and session_info still answers, never isError.
    let mut stranger = Mcp::spawn(port, "2");
    stranger.initialize();
    let info = stranger.call_json("session_info", json!({}));
    assert_eq!(info["principal"], json!(2), "{info}");
    assert!(info["account"].is_null(), "an undelegated principal's account: {info}");

    daemon.shutdown();
}

#[test]
fn lifecycle_create_insert_retrieve_link_and_rejections() {
    let dir = TempDir::new("life");
    let daemon = spawn_daemon(dir.path(), 0);
    let port = daemon.port();
    let account = provision_principal_1(port);

    let mut mcp = Mcp::spawn(port, "1");
    mcp.initialize();

    // create → insert → retrieve. The string write form is per-byte:
    // "hello" seats five values at positions 1..=5, so width "0.5" covers
    // it exactly and the delivery is one content item.
    let v = mcp.call_json("create_new_document", json!({"account": account}));
    assert_eq!(v["resp"], "ack_addr", "create: {v}");
    let doc = v["addr"].as_str().expect("doc addr").to_string();

    let v = mcp.call_json(
        "insert",
        json!({"doc": doc, "at": {"subspace": "1", "ordinal": "1"}, "values": ["hello"]}),
    );
    assert_eq!(v["resp"], "ack_addr", "insert: {v}");

    let v = mcp.call_json(
        "retrieve_v",
        json!({"specs": [{"doc": doc, "span": {"start": "1.1", "width": "0.5"}}]}),
    );
    assert_eq!(v["resp"], "delivery");
    assert_eq!(v["items"], json!([{"content": "hello"}]));

    // An atom form: ONE composite value at ONE position, never coalesced
    // into the per-byte run beside it.
    let v = mcp.call_json(
        "insert",
        json!({"doc": doc, "at": {"subspace": "1", "ordinal": "6"}, "values": [{"atom": "chunk"}]}),
    );
    assert_eq!(v["resp"], "ack_addr", "atom insert: {v}");
    let v = mcp.call_json(
        "retrieve_v",
        json!({"specs": [{"doc": doc, "span": {"start": "1.1", "width": "0.6"}}]}),
    );
    assert_eq!(v["items"], json!([{"content": "hello"}, {"atom": "chunk"}]));

    // make_link (through the schema's from_ → the wire's from) and
    // follow_link on the TO slot.
    let v = mcp.call_json("create_new_document", json!({"account": account}));
    let doc2 = v["addr"].as_str().expect("doc2 addr").to_string();
    let v = mcp.call_json(
        "insert",
        json!({"doc": doc2, "at": {"subspace": "1", "ordinal": "1"}, "values": ["linked"]}),
    );
    assert_eq!(v["resp"], "ack_addr");
    let v = mcp.call_json("create_new_document", json!({"account": account}));
    let tdoc = v["addr"].as_str().expect("tdoc addr").to_string();
    let v = mcp.call_json(
        "insert",
        json!({"doc": tdoc, "at": {"subspace": "1", "ordinal": "1"}, "values": ["type:jump"]}),
    );
    assert_eq!(v["resp"], "ack_addr");

    let v = mcp.call_json(
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

    let v = mcp.call_json("follow_link", json!({"a": link, "slot": 2}));
    assert_eq!(v["resp"], "follow");
    assert!(
        v["result"]["ok"].as_array().is_some_and(|s| !s.is_empty()),
        "TO coverage nonempty: {v}"
    );

    // A rejection is a NORMAL result: isError false, response document
    // verbatim.
    let v = mcp.call_json(
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

    // A line that is not UTF-8 is a parse error too, never the end of stdin.
    mcp.send_bytes(b"\xff\xfe\n");
    let v = mcp.read_message();
    assert_eq!(v["error"]["code"], json!(-32700), "non-UTF-8 parse error: {v}");
    assert!(v["id"].is_null(), "parse errors carry id null: {v}");
    let v = mcp.request("ping", json!({}));
    assert_eq!(v["result"], json!({}), "the adapter survives a non-UTF-8 line");

    daemon.shutdown();
}

#[test]
fn daemon_restart_reopens_the_session_and_reissues() {
    let dir = TempDir::new("restart");
    let daemon = spawn_daemon(dir.path(), 0);
    let port = daemon.port();
    let account = provision_principal_1(port);

    let mut mcp = Mcp::spawn(port, "1");
    mcp.initialize();
    let v = mcp.call_json("create_new_document", json!({"account": account}));
    let doc = v["addr"].as_str().expect("doc addr").to_string();
    let v = mcp.call_json(
        "insert",
        json!({"doc": doc, "at": {"subspace": "1", "ordinal": "1"}, "values": ["hello"]}),
    );
    assert_eq!(v["resp"], "ack_addr", "the pre-restart write: {v}");

    // Kill the daemon mid-session — tokens die with the process — and
    // restart on the same data dir and the SAME port (the adapter's URL is
    // fixed for its lifetime).
    daemon.shutdown();
    let daemon = spawn_daemon(dir.path(), port);

    // The adapter holds a stale token: the daemon answers unauthenticated,
    // the adapter reopens its session and reissues the frame once —
    // invisible here.
    let v = mcp.call_json(
        "insert",
        json!({"doc": doc, "at": {"subspace": "1", "ordinal": "6"}, "values": [", wire"]}),
    );
    assert_eq!(v["resp"], "ack_addr", "the write after restart must succeed: {v}");

    let v = mcp.call_json(
        "retrieve_v",
        json!({"specs": [{"doc": doc, "span": {"start": "1.1", "width": "0.11"}}]}),
    );
    assert_eq!(v["items"], json!([{"content": "hello, wire"}]));

    daemon.shutdown();
}

/// Wire v5's two-form slots through the adapter, one link exercising both:
/// FROM as a V-spec array (content-resolved to permanent I-spans — the v4
/// meaning, pinned by the exact recorded span), TO and TYPE as
/// `{"addrs": […]}` (the names verbatim, one unit subtree span per
/// address, the TYPE a ghost nothing occupies).
#[test]
fn make_link_addrs_form_records_names_verbatim() {
    let dir = TempDir::new("addrs");
    let daemon = spawn_daemon(dir.path(), 0);
    let port = daemon.port();
    let account = provision_principal_1(port);

    let mut mcp = Mcp::spawn(port, "1");
    mcp.initialize();

    let v = mcp.call_json("create_new_document", json!({"account": account}));
    let doc = v["addr"].as_str().expect("doc addr").to_string();
    let v = mcp.call_json(
        "insert",
        json!({"doc": doc, "at": {"subspace": "1", "ordinal": "1"}, "values": ["hello"]}),
    );
    assert_eq!(v["resp"], "ack_addr", "insert: {v}");
    let i_start = v["addr"].as_str().expect("first minted I-address").to_string();

    let v = mcp.call_json("create_new_document", json!({"account": account}));
    let doc2 = v["addr"].as_str().expect("doc2 addr").to_string();
    // A ghost: doc2's never-occupied subspace 3. Nothing resides there and
    // nothing has to — the addrs form records names, not contents.
    let ghost = format!("{doc2}.0.3.6.1");

    let v = mcp.call_json(
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

    let v = mcp.call_json("read_link", json!({"a": link}));
    assert_eq!(
        v["link"]["slots"],
        json!([
            [{"start": i_start, "width": width_of(&i_start, 5)}],
            [{"start": doc2, "width": width_of(&doc2, 1)}],
            [{"start": ghost, "width": width_of(&ghost, 1)}]
        ]),
        "recorded endsets — resolved I-span, then names verbatim: {v}"
    );

    daemon.shutdown();
}

/// The slot forms' failure modes are data, not transport errors: an object
/// mixing the two forms is the daemon's unparseable rejection, an empty
/// addrs TYPE its empty_type_resolution, and FROM spelled both ways the
/// daemon's unknown-field refusal — all isError false.
#[test]
fn slot_form_faults_surface_as_normal_results() {
    let dir = TempDir::new("slotfault");
    let daemon = spawn_daemon(dir.path(), 0);
    let port = daemon.port();
    let account = provision_principal_1(port);

    let mut mcp = Mcp::spawn(port, "1");
    mcp.initialize();
    let v = mcp.call_json("create_new_document", json!({"account": account}));
    let doc = v["addr"].as_str().expect("doc addr").to_string();

    // Both forms at once in one slot: not a form ('resolve' is not a
    // make_link key), so the frame never becomes an operation.
    let v = mcp.call_json(
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
    let v = mcp.call_json(
        "make_link",
        json!({"home": doc, "from_": [], "to": [], "ty": {"addrs": []}}),
    );
    assert_eq!(v["resp"], "rejected", "empty addrs type: {v}");
    assert_eq!(v["code"], "empty_type_resolution");

    // FROM spelled both ways at once: the relay resolves nothing, so the
    // daemon's unknown-field refusal answers, as it would the raw frame.
    let v = mcp.call_json(
        "make_link",
        json!({"home": doc, "from": [], "from_": [], "to": [], "ty": {"addrs": []}}),
    );
    assert_eq!((&v["op"], &v["code"]), (&json!("unparseable"), &json!("malformed")), "{v}");
    assert!(v["detail"].as_str().is_some_and(|d| d.contains("from_")), "{v}");

    daemon.shutdown();
}

// ── the session rules, against a stub daemon ─────────────────────────────

/// Every answer but `unauthenticated` is the tool result, byte for byte and
/// never `isError`, from ONE exchange: an ack — whose reissue would apply
/// the write twice — and a rejection of each disposition, `retry` among
/// them. The session is held first, so no open rides along; a second
/// exchange would take the next case's reply as a session answer, or meet
/// the stub's closed listener, and come back `isError`. The ack is spelled
/// as skepd never spells one (wire.md §Determinism: sorted keys, no
/// whitespace), so a result rebuilt from parsed JSON cannot match it.
#[test]
fn every_answer_but_unauthenticated_comes_back_verbatim_from_one_exchange() {
    let answers = [
        r#"{"resp": "ack_addr", "at": 7, "addr": "1.0.1.0.1.0.1.2"}"#,
        r#"{"code":"durability","disposition":"retry","op":"insert","resp":"rejected"}"#,
        r#"{"code":"doc_not_registered","disposition":"reorder","op":"insert","resp":"rejected"}"#,
        r#"{"code":"poisoned","disposition":"halt","op":"insert","resp":"rejected"}"#,
        r#"{"code":"not_owner","disposition":"permanent","op":"insert","resp":"rejected"}"#,
    ];
    let mut replies = vec![reply(200, UNAUTHENTICATED), session_reply(TOKEN), reply(200, ACK)];
    replies.extend(answers.iter().map(|a| reply(200, a)));
    let (port, stub) = stub_daemon(replies);
    let mut mcp = Mcp::spawn(port, "1");
    mcp.initialize();
    assert_eq!(mcp.call("insert", an_insert()), (false, ACK.to_string()), "premise: a session");
    for answer in answers {
        assert_eq!(mcp.call("insert", an_insert()), (false, answer.to_string()), "{answer}");
    }
    let requests = stub.join().expect("the stub daemon");
    assert_eq!(requests.len(), 3 + answers.len(), "one exchange each");
}

/// `unauthenticated` is the cue: the adapter opens a bare session — a
/// request that carries no token — and reissues the very frame once under
/// the token it was issued; the reissue's answer is the tool result.
#[test]
fn unauthenticated_opens_a_bare_session_and_reissues_the_frame_once_under_its_token() {
    let (port, stub) =
        stub_daemon(vec![reply(200, UNAUTHENTICATED), session_reply(TOKEN), reply(200, ACK)]);
    let mut mcp = Mcp::spawn(port, "1");
    mcp.initialize();
    assert_eq!(mcp.call("insert", an_insert()), (false, ACK.to_string()), "the reissue's answer");
    let r = stub.join().expect("the stub daemon");
    let lines: Vec<&str> = r.iter().map(|q| q.lines().next().unwrap_or("")).collect();
    assert_eq!(lines, ["POST /op HTTP/1.1", "POST /session HTTP/1.1", "POST /op HTTP/1.1"]);
    let tokens: Vec<Option<&str>> = r.iter().map(|q| session_of(q)).collect();
    assert_eq!(tokens, [None, None, Some(TOKEN)], "the token each exchange carried");
    assert_eq!(body_of(&r[2]), body_of(&r[0]), "the reissue is the very frame");
}

/// A second `unauthenticated`, answered to the reissue, is data like any
/// other rejection: the tool result, `isError` false, after three
/// exchanges — no second open, no loop.
#[test]
fn a_second_unauthenticated_passes_through_as_data() {
    let (port, stub) = stub_daemon(vec![
        reply(200, UNAUTHENTICATED),
        session_reply(TOKEN),
        reply(200, UNAUTHENTICATED),
    ]);
    let mut mcp = Mcp::spawn(port, "1");
    mcp.initialize();
    assert_eq!(mcp.call("insert", an_insert()), (false, UNAUTHENTICATED.to_string()));
    assert_eq!(stub.join().expect("the stub daemon").len(), 3, "three exchanges, no more");
}

/// A failed exchange is never reissued — not even one whose answer broke
/// off mid-body, after the daemon may well have committed the write: the
/// failure is the tool result, `isError`, and the reply a reissue would
/// have taken is still waiting when the test comes for it.
#[test]
fn a_failed_exchange_is_never_reissued() {
    let (port, stub) = stub_daemon(vec![cut_short(), reply(200, ACK)]);
    let mut mcp = Mcp::spawn(port, "1");
    mcp.initialize();
    let (is_error, text) = mcp.call("insert", an_insert());
    assert!(is_error, "the broken answer is the result, not a reissue's ack: {text}");
    assert!(text.starts_with(&format!("skepd at http://127.0.0.1:{port}: response: ")), "{text}");
    let mut drain = TcpStream::connect(("127.0.0.1", port)).expect("the stub still listens");
    drain.write_all(b"GET /drain HTTP/1.1\r\n\r\n").expect("the drain request");
    let requests = stub.join().expect("the stub daemon");
    assert!(requests[1].starts_with("GET /drain "), "the second reply went to: {}", requests[1]);
}

/// The token the adapter holds is the newest the daemon issued, and it
/// rides every op from that op's first attempt on: a held token goes out at
/// once, with no reopen; after a restart's `unauthenticated` the reopen
/// carries no token, dead or live, and the reissue the new one alone.
#[test]
fn the_held_token_rides_each_op_until_a_reopen_replaces_it() {
    let (port, stub) = stub_daemon(vec![
        reply(200, UNAUTHENTICATED), // the first write opens
        session_reply(OLD),
        reply(200, ACK),
        reply(200, ACK),             // the next rides OLD at once
        reply(200, UNAUTHENTICATED), // a restart killed OLD
        session_reply(NEW),
        reply(200, ACK),
    ]);
    let mut mcp = Mcp::spawn(port, "1");
    mcp.initialize();
    for _ in 0..3 {
        assert_eq!(mcp.call("insert", an_insert()), (false, ACK.to_string()));
    }
    let r = stub.join().expect("the stub daemon");
    let tokens: Vec<Option<&str>> = r.iter().map(|q| session_of(q)).collect();
    assert_eq!(tokens, [None, None, Some(OLD), Some(OLD), Some(OLD), None, Some(NEW)]);
    assert!(r[5].starts_with("POST /session "), "the reopen: {}", r[5]);
}

/// GET /health is token-blind (wire.md §Sessions): the health read carries
/// no token even while one is held. Its answer rides in session_info whole,
/// a member this adapter never heard of included (wire.md: a seventh member
/// is no violation).
#[test]
fn the_health_read_carries_no_token_and_is_reported_whole() {
    let health = r#"{"log_position":9,"ok":true,"seventh":"unheard of"}"#;
    let (port, stub) = stub_daemon(vec![
        reply(200, UNAUTHENTICATED),
        session_reply(TOKEN),
        reply(200, ACK),
        reply(200, r#"{"addr":"1.0.2","as_of":9,"resp":"maybe_addr"}"#),
        reply(200, health),
    ]);
    let mut mcp = Mcp::spawn(port, "1");
    mcp.initialize();
    assert_eq!(mcp.call("insert", an_insert()), (false, ACK.to_string()), "premise: a session");
    let info = mcp.call_json("session_info", json!({}));
    let whole: Value = serde_json::from_str(health).expect("the stub's health is JSON");
    assert_eq!(info, json!({"account": "1.0.2", "health": whole, "principal": 1}));
    let r = stub.join().expect("the stub daemon");
    assert!(r[4].starts_with("GET /health "), "{}", r[4]);
    assert_eq!(session_of(&r[4]), None, "a held token rode GET /health: {}", r[4]);
}

/// No session token leaves the adapter: not in a tool result — an answer,
/// or a failure after the token rode the request — and not in a log line,
/// across a session's open and its reopen. The stub issues the tokens, so
/// the test knows exactly what must never appear.
#[test]
fn a_session_token_reaches_no_tool_result_and_no_log_line() {
    let (port, stub) = stub_daemon(vec![
        reply(200, UNAUTHENTICATED),
        session_reply(OLD),
        reply(200, ACK),
        reply(200, UNAUTHENTICATED),
        session_reply(NEW),
        cut_short(),
    ]);
    let mut mcp = Mcp::spawn_logged(port, "1");
    mcp.initialize();
    let (_, answer) = mcp.call("insert", an_insert());
    let (is_error, failure) = mcp.call("insert", an_insert());
    assert!(is_error, "premise: the reissue's broken answer is a failure: {failure}");
    let (status, log) = mcp.finish_logged();
    assert!(status.success(), "{status:?}");
    let r = stub.join().expect("the stub daemon");
    assert_eq!((session_of(&r[2]), session_of(&r[5])), (Some(OLD), Some(NEW)), "both rode");
    assert_eq!(log.matches("bare session opened").count(), 2, "both opens logged: {log}");
    let channels = [("an answer", &answer), ("a failure", &failure), ("the log", &log)];
    for token in [OLD, NEW] {
        for (channel, text) in channels {
            assert!(!text.contains(token), "{channel} carries a session token: {text}");
        }
    }
}

// ── startup, and no daemon behind the adapter ────────────────────────────

/// A daemon the adapter cannot reach is what `isError` marks: a wire op and
/// session_info alike answer `isError`, the adapter's own message naming
/// the origin and the failed step, and the adapter keeps answering. Port 1
/// sits below 1024, where no unprivileged process can listen, so the
/// connect is refused.
#[test]
fn calls_to_an_unreachable_daemon_answer_is_error_naming_its_origin() {
    let mut mcp = Mcp::spawn(1, "1");
    mcp.initialize();
    for (tool, args) in [("insert", an_insert()), ("session_info", json!({}))] {
        let (is_error, text) = mcp.call(tool, args);
        assert!(is_error, "{tool}, no daemon: isError: {text}");
        assert!(text.starts_with("skepd at http://127.0.0.1:1: connect: "), "{tool}: {text}");
    }
    assert_eq!(mcp.request("ping", json!({}))["result"], json!({}), "the adapter keeps answering");
}

/// SKEP_PRINCIPAL is required and an integer: unset, startup refuses by
/// name; set to anything that is no non-negative integer, it refuses
/// quoting the value — never binding a default principal.
#[test]
fn skep_principal_is_required_and_an_integer() {
    let url = ("SKEPD_URL", "http://127.0.0.1:1");
    let out = run_adapter(&[], &[url]);
    assert_eq!(out.status.code(), Some(1), "unset: {out:?}");
    assert!(String::from_utf8_lossy(&out.stderr).contains("SKEP_PRINCIPAL is required"), "{out:?}");
    for bad in ["", "abc", "-1", "1.5", "18446744073709551616"] {
        let out = run_adapter(&[], &[url, ("SKEP_PRINCIPAL", bad)]);
        assert_eq!(out.status.code(), Some(1), "'{bad}': {out:?}");
        let err = String::from_utf8_lossy(&out.stderr);
        assert!(err.contains(&format!("SKEP_PRINCIPAL: '{bad}' is not a principal")), "{err}");
    }
}

/// A word the usage does not name, or `--tools-file` without its path, is a
/// usage error — exit 2, the usage on stderr — never ignored: a mistyped
/// `--tools-file` must not quietly serve the embedded catalog instead.
#[test]
fn an_unknown_word_or_a_flag_without_its_value_is_a_usage_error() {
    let env = [("SKEPD_URL", "http://127.0.0.1:1"), ("SKEP_PRINCIPAL", "1")];
    for (args, says) in [
        (&["--tool-file", "mine.json"][..], "unknown argument '--tool-file'"),
        (&["--tools-file"][..], "--tools-file needs a value"),
    ] {
        let out = run_adapter(args, &env);
        assert_eq!(out.status.code(), Some(2), "{args:?}: {out:?}");
        let err = String::from_utf8_lossy(&out.stderr);
        assert!(err.contains(says) && err.contains("usage: skep-mcp"), "{args:?}: {err}");
    }
}

/// SKEPD_URL unset is the origin the usage names; set but malformed,
/// startup refuses naming the variable — never falling back to that
/// default. Nothing is dialed: stdin is empty.
#[test]
fn skepd_url_unset_is_the_default_origin_and_malformed_refuses() {
    let out = run_adapter(&[], &[("SKEP_PRINCIPAL", "1")]);
    assert!(out.status.success(), "{out:?}");
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("http://127.0.0.1:8642"), "the startup line names the default: {err}");
    for bad in ["https://127.0.0.1:8642", "127.0.0.1:8642", "http://127.0.0.1:8642/op"] {
        let out = run_adapter(&[], &[("SKEPD_URL", bad), ("SKEP_PRINCIPAL", "1")]);
        assert_eq!(out.status.code(), Some(1), "'{bad}': {out:?}");
        assert!(String::from_utf8_lossy(&out.stderr).contains("SKEPD_URL"), "'{bad}': {out:?}");
    }
}

/// A harness that hangs up stdout ends the adapter: the first answer it
/// cannot write is its exit, stdin still open — no orphan goes on taking
/// requests whose answers nobody reads.
#[test]
fn a_closed_stdout_ends_the_adapter() {
    let mut child = Command::new(env!("CARGO_BIN_EXE_skep-mcp"))
        .env("SKEPD_URL", "http://127.0.0.1:1")
        .env("SKEP_PRINCIPAL", "1")
        .env_remove("SKEP_COMMONS")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn skep-mcp");
    drop(child.stdout.take());
    let mut stdin = child.stdin.take().expect("child stdin");
    stdin.write_all(b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"ping\"}\n").expect("a request");
    stdin.flush().expect("flush");
    let deadline = Instant::now() + Duration::from_secs(10);
    let exited = loop {
        match child.try_wait().expect("poll the adapter") {
            Some(status) => break Some(status),
            None if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(20)),
            None => break None,
        }
    };
    if exited.is_none() {
        let _ = child.kill();
        let _ = child.wait();
    }
    drop(stdin);
    assert!(exited.is_some(), "the adapter outlived its closed stdout by 10 s, stdin open");
}

/// SKEP_COMMONS set: the instructions carry the commons sentence with the
/// address substituted. Unset: byte-identical to the tools file's
/// instructions. Malformed: startup refusal naming the variable. No daemon
/// anywhere — initialize never dials skepd.
#[test]
fn skep_commons_appends_the_commons_sentence() {
    let file = embedded_catalog();
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

/// A variable set to bytes that are not UTF-8 is refused by name, never
/// read as unset: an unreadable SKEPD_URL must not run against the default.
#[cfg(unix)]
#[test]
fn non_utf8_environment_refuses_startup() {
    use std::os::unix::ffi::OsStrExt;
    let bytes = std::ffi::OsStr::from_bytes(b"\xff");
    for var in ["SKEP_PRINCIPAL", "SKEPD_URL", "SKEP_COMMONS"] {
        let out = Command::new(env!("CARGO_BIN_EXE_skep-mcp"))
            .env("SKEPD_URL", "http://127.0.0.1:1")
            .env("SKEP_PRINCIPAL", "1")
            .env_remove("SKEP_COMMONS")
            .env(var, bytes)
            .output()
            .expect("run skep-mcp");
        assert!(!out.status.success(), "a non-UTF-8 {var} must refuse startup");
        let err = String::from_utf8_lossy(&out.stderr);
        assert!(err.contains(&format!("{var}: the value is not UTF-8 text")), "{var}: {err}");
    }
}

/// A path is an OS string: a `--tools-file` that is not UTF-8 is read as a
/// path — here one that does not exist, a refusal naming the flag — never a
/// panic in argument parsing.
#[cfg(unix)]
#[test]
fn non_utf8_tools_file_path_is_a_path() {
    use std::os::unix::ffi::OsStrExt;
    let out = Command::new(env!("CARGO_BIN_EXE_skep-mcp"))
        .arg("--tools-file")
        .arg(std::ffi::OsStr::from_bytes(b"/nonexistent/\xff.json"))
        .env("SKEPD_URL", "http://127.0.0.1:1")
        .env("SKEP_PRINCIPAL", "1")
        .env_remove("SKEP_COMMONS")
        .output()
        .expect("run skep-mcp");
    assert_eq!(out.status.code(), Some(1), "a refusal, not a panic: {out:?}");
    assert!(String::from_utf8_lossy(&out.stderr).contains("--tools-file"), "{out:?}");
}

#[test]
fn tools_file_dispatch_drift_refuses_startup_both_directions() {
    // Catalog validation precedes any network use, so no daemon is needed
    // and SKEPD_URL can point nowhere.
    let dir = TempDir::new("drift");
    let real = embedded_catalog();

    // Direction one: a file entry the dispatch doesn't know.
    let mut extra = real.clone();
    extra["tools"].as_array_mut().expect("tools").push(json!({
        "name": "frobnicate",
        "description": "no such wire op",
        "inputSchema": {"type": "object"}
    }));
    let path = dir.path().join("extra.json");
    std::fs::write(&path, extra.to_string()).expect("write doctored file");
    let err = tools_file_refusal(&path);
    assert!(err.contains("frobnicate"), "stderr names the unknown tool: {err}");

    // Direction two: a dispatch op with no file entry.
    let mut missing = real.clone();
    missing["tools"].as_array_mut().expect("tools").retain(|t| t["name"] != "insert");
    let path = dir.path().join("missing.json");
    std::fs::write(&path, missing.to_string()).expect("write doctored file");
    let err = tools_file_refusal(&path);
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

/// The adapter run to completion on `tools_file`, which startup must
/// refuse: its stderr, the refusal.
fn tools_file_refusal(tools_file: &Path) -> String {
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
