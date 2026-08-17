//! H2 tier 1 — the skep-mcp JSON-RPC line protocol under hostile lines.
//!
//! Driven through the REAL binary (spawned, stdin/stdout) against a live
//! in-process daemon — the most faithful test of the line protocol there is:
//! it exercises the actual process, the actual stdio framing, and the
//! survive-and-keep-answering property. The contract (MCP over
//! newline-delimited JSON-RPC 2.0):
//!
//! * a line that is a **request** (a method and an `id`) gets **exactly one**
//!   response, correlated by `id`;
//! * a **notification** (method, no `id`) and an **id-less non-request**
//!   (no method) get **none**;
//! * a **parse error** is `-32700` (id `null`); an **unknown method** is
//!   `-32601`;
//! * the process **survives the whole storm** and still answers `tools/list`.
//!
//! Response counting uses a per-line sentinel `ping`: send the fuzz line,
//! then a uniquely-id'd ping, and read until the ping's answer — everything
//! before it is the fuzz line's response(s). A violation fails loudly with
//! the line; per the H3 finding protocol the test is then converted to
//! `#[ignore = "FINDING-n: …"]`, assertion intact.
//!
//! skep-mcp is binary-only (no library seam), so there is no per-input
//! libFuzzer target for it — this spawn-storm IS its fuzzing, and can be run
//! standalone or widened with `FUZZ_EXHAUSTIVE=1`.

use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::time::Duration;

use serde_json::{json, Value};
use skepd::fuzz_support::{mutate, splitmix64};
use skepd::{serve, Daemon, Skepd};

// ── a self-owned temp dir (kept dependency-free, mirroring mcp.rs) ──────────

struct TempDir(PathBuf);

impl TempDir {
    fn new(tag: &str) -> TempDir {
        static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let n = SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!("skep-fuzzmcp-{tag}-{}-{n}", std::process::id()));
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

fn spawn_daemon(dir: &Path) -> Skepd {
    let daemon = Daemon::open(dir).expect("daemon open");
    serve(daemon, 0, 4).expect("bind ephemeral port")
}

// ── the adapter under test, storm-driven ────────────────────────────────────

struct Mcp {
    child: Child,
    stdin: Option<ChildStdin>,
    stdout: BufReader<ChildStdout>,
    ping_seq: u64,
}

impl Mcp {
    fn spawn(port: u16) -> Mcp {
        let mut child = Command::new(env!("CARGO_BIN_EXE_skep-mcp"))
            .env("SKEPD_URL", format!("http://127.0.0.1:{port}"))
            .env("SKEP_PRINCIPAL", "1")
            .env_remove("SKEP_COMMONS")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .expect("spawn skep-mcp");
        let stdin = child.stdin.take().expect("child stdin");
        let stdout = BufReader::new(child.stdout.take().expect("child stdout"));
        Mcp { child, stdin: Some(stdin), stdout, ping_seq: 0 }
    }

    fn send_line(&mut self, line: &str) {
        let stdin = self.stdin.as_mut().expect("stdin open");
        stdin.write_all(line.as_bytes()).expect("write to adapter");
        stdin.write_all(b"\n").expect("write newline");
        stdin.flush().expect("flush to adapter");
    }

    /// Read one JSON-RPC message; a closed stdout mid-storm is the process
    /// having died — a finding.
    fn read_message(&mut self) -> Value {
        let mut line = String::new();
        loop {
            line.clear();
            let n = self.stdout.read_line(&mut line).expect("read from adapter");
            assert!(n > 0, "FINDING (fuzz_mcp): adapter closed stdout mid-storm (it died)");
            if !line.trim().is_empty() {
                return serde_json::from_str(line.trim())
                    .unwrap_or_else(|e| panic!("FINDING (fuzz_mcp): non-JSON line ({e}): {line:?}"));
            }
        }
    }

    /// Send `line`, then a uniquely-id'd sentinel ping; return every message
    /// the adapter emitted for `line` (those before the ping's answer).
    fn responses_for(&mut self, line: &str) -> Vec<Value> {
        // Newlines would split one fuzz input into several lines and skew the
        // count — the payload, not the framing, is under test here.
        let sanitized: String = line.chars().filter(|&c| c != '\n' && c != '\r').collect();
        self.send_line(&sanitized);
        self.ping_seq += 1;
        let sentinel = format!("fzping-{}", self.ping_seq);
        self.send_line(&format!(r#"{{"jsonrpc":"2.0","id":"{sentinel}","method":"ping"}}"#));
        let mut before = Vec::new();
        loop {
            let v = self.read_message();
            if v["id"] == json!(sentinel) {
                assert_eq!(v["result"], json!({}), "the sentinel ping must answer {{}}: {v}");
                return before;
            }
            before.push(v);
            assert!(
                before.len() <= 4,
                "FINDING (fuzz_mcp): one line produced >1 response before the sentinel; \
                 line={sanitized:?} responses={before:?}"
            );
        }
    }

    fn request(&mut self, method: &str, id: u64, params: Value) -> Value {
        self.send_line(
            &json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params}).to_string(),
        );
        let v = self.read_message();
        assert_eq!(v["id"], json!(id), "responses correlate by id: {v}");
        v
    }

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

/// Every emitted message is well-formed JSON-RPC 2.0: version tag, an `id`
/// slot, and exactly one of `result`/`error`.
fn assert_jsonrpc(v: &Value) {
    assert_eq!(v["jsonrpc"], "2.0", "a response carries jsonrpc 2.0: {v}");
    assert!(v.get("id").is_some(), "a response carries an id slot: {v}");
    let has_result = v.get("result").is_some();
    let has_error = v.get("error").is_some();
    assert!(has_result ^ has_error, "exactly one of result/error: {v}");
}

fn exhaustive() -> bool {
    std::env::var_os("FUZZ_EXHAUSTIVE").is_some_and(|v| v == "1")
}

fn budget(default: usize) -> usize {
    if exhaustive() {
        default * 40
    } else {
        default
    }
}

/// The JSON-RPC corpus the storm mutates: requests of each dispatch kind, a
/// notification, an id-less non-request, and a stray response.
fn corpus() -> Vec<Vec<u8>> {
    [
        r#"{"jsonrpc":"2.0","id":1,"method":"ping"}"#,
        r#"{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}"#,
        r#"{"jsonrpc":"2.0","id":3,"method":"initialize","params":{"protocolVersion":"2025-06-18"}}"#,
        r#"{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"fork","arguments":{}}}"#,
        r#"{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"retrieve_v","arguments":{"specs":[]}}}"#,
        r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#,
        r#"{"jsonrpc":"2.0","id":7,"result":{}}"#,
        r#"{"jsonrpc":"2.0","id":8,"method":"no/such/method"}"#,
    ]
    .iter()
    .map(|s| s.as_bytes().to_vec())
    .collect()
}

/// A seeded arbitrary UTF-8 line (no newline) — JSON-ish punctuation biased,
/// so the parser is genuinely exercised.
fn random_utf8_line(st: &mut u64, maxlen: usize) -> String {
    let len = (splitmix64(st) as usize) % (maxlen + 1);
    let mut s = String::with_capacity(len);
    for _ in 0..len {
        let ascii = b" {}[]\":,0123456789tfnul-.abcxyz/";
        let ch = if splitmix64(st) % 8 == 0 {
            char::from_u32(0x100 + (splitmix64(st) as u32 % 0x2000)).unwrap_or('?')
        } else {
            ascii[(splitmix64(st) as usize) % ascii.len()] as char
        };
        if ch != '\n' && ch != '\r' {
            s.push(ch);
        }
    }
    s
}

#[test]
fn mcp_line_protocol_storm_survives_and_stays_correct() {
    let dir = TempDir::new("storm");
    let sd = spawn_daemon(dir.path());
    let port = sd.port();
    let mut mcp = Mcp::spawn(port);

    // Bring the session up the ordinary way first.
    let init = mcp.request(
        "initialize",
        1,
        json!({"protocolVersion": "2025-06-18", "capabilities": {}}),
    );
    assert_eq!(init["result"]["serverInfo"]["name"], "skep", "initialize: {init}");

    // Targeted, documented cases (named so a regression is obvious).
    // Parse error → -32700, id null.
    let r = mcp.responses_for("{ this is not json");
    assert_eq!(r.len(), 1, "a bad line gets one response: {r:?}");
    assert_eq!(r[0]["error"]["code"], json!(-32700), "parse error code: {:?}", r[0]);
    assert!(r[0]["id"].is_null(), "parse error id is null: {:?}", r[0]);
    // Unknown method → -32601.
    let r = mcp.responses_for(r#"{"jsonrpc":"2.0","id":99,"method":"no/such"}"#);
    assert_eq!(r.len(), 1, "unknown method gets one response");
    assert_eq!(r[0]["error"]["code"], json!(-32601), "unknown method code: {:?}", r[0]);
    // Notification → no response.
    let r = mcp.responses_for(r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#);
    assert!(r.is_empty(), "a notification gets no response: {r:?}");
    // Id-less non-request (no method) → no response.
    let r = mcp.responses_for(r#"{"jsonrpc":"2.0","foo":1}"#);
    assert!(r.is_empty(), "an id-less non-request gets no response: {r:?}");
    // A well-formed request → exactly one response, correlated.
    let r = mcp.responses_for(r#"{"jsonrpc":"2.0","id":"probe","method":"ping"}"#);
    assert_eq!(r.len(), 1, "a request gets exactly one response");
    assert_eq!(r[0]["id"], json!("probe"), "the response correlates by id: {:?}", r[0]);

    // The storm: arbitrary and mutated lines.
    let corpus = corpus();
    let mut st = 0x4D43_5000_0000_0001; // "MCP\0\0\0\0\1"
    for i in 0..budget(400) {
        let line = if splitmix64(&mut st) % 3 == 0 {
            random_utf8_line(&mut st, 160)
        } else {
            String::from_utf8_lossy(&mutate(splitmix64(&mut st), &corpus)).into_owned()
        };
        let before = mcp.responses_for(&line);
        for v in &before {
            assert_jsonrpc(v);
        }
        // At most one response per line (the sentinel counts the rest); an
        // id-bearing request must be answered, but classifying a mutated line
        // is the adapter's job — the robust invariants are: ≤1 response, each
        // well-formed, and (below) the process stays alive.
        assert!(
            before.len() <= 1,
            "FINDING (fuzz_mcp): line {i} produced {} responses: {line:?}",
            before.len()
        );
    }

    // Survival: tools/list still answers the full catalog.
    let v = mcp.request("tools/list", 100_000, json!({}));
    let tools = v["result"]["tools"].as_array().expect("tools array after the storm");
    assert_eq!(tools.len(), 39, "38 wire ops + session_info survive the storm");

    // Clean exit on stdin EOF.
    let status = mcp.finish();
    assert!(status.success(), "clean exit after the storm: {status:?}");
    sd.shutdown();
}
