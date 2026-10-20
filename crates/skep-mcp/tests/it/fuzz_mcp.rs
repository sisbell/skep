//! H2 tier 1 — the skep-mcp JSON-RPC line protocol under hostile lines.
//!
//! Driven through the real binary (spawned, stdin/stdout) over a claimed
//! board the adapter's signed session stands at — the most faithful test
//! of the line protocol there is: it exercises the actual process, the
//! actual stdio framing, and the survive-and-keep-answering property. The
//! contract (MCP over newline-delimited JSON-RPC 2.0):
//!
//! * a line that is a **request** (a method and an `id`) gets **exactly one**
//!   response, correlated by `id`;
//! * a **notification** (method, no `id`), an **id-less non-request** (no
//!   method), a **stray response** and a **blank line** get **none**;
//! * a **parse error** is `-32700` and JSON that is **no object** `-32600`,
//!   both id `null`; an **unknown method** is `-32601`;
//! * the process **survives the whole storm** and still answers `tools/list`.
//!
//! Response counting uses a per-line sentinel `ping`: send the fuzz line,
//! then a uniquely-id'd ping, and read until the ping's answer — everything
//! before it is the fuzz line's response(s). The documented shapes are
//! pinned one at a time first, none of them reaching the board; the storm
//! then holds every arbitrary and mutated line to the answer its shape owes
//! (`owed`). A violation fails loudly with the line; per the H3 finding
//! protocol the test is then converted to `#[ignore = "FINDING-n: …"]`,
//! assertion intact.
//!
//! skep-mcp is binary-only (no library target), so there is no per-input
//! libFuzzer target for it — this spawn-storm IS its fuzzing, and can be run
//! standalone or widened with `FUZZ_EXHAUSTIVE=1`.

use std::io::{BufRead, BufReader, Write};
use std::process::{Child, ChildStdin, ChildStdout, Stdio};
use std::time::Duration;

use serde_json::{json, Value};
use skepd::fuzz_support::{mutate, splitmix64};

use crate::common::{Fixture, Launch};

// ── the adapter under test, storm-driven ────────────────────────────────────

struct Mcp {
    child: Child,
    stdin: Option<ChildStdin>,
    stdout: BufReader<ChildStdout>,
    ping_seq: u64,
}

impl Mcp {
    /// The adapter over the fixture's board as the claimant, its stderr
    /// the test's own, its stdin and stdout this driver's.
    fn spawn(fixture: &Fixture) -> Mcp {
        let mut child = Launch::over(fixture, 1).stderr(Stdio::inherit()).child();
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
                return serde_json::from_str(line.trim()).unwrap_or_else(|e| panic!("FINDING (fuzz_mcp): non-JSON line ({e}): {line:?}"));
            }
        }
    }

    /// Send `line` as given — any bytes but a newline — then a uniquely-id'd
    /// sentinel ping; return every message the adapter emitted for `line`
    /// (those before the ping's answer).
    fn responses_for(&mut self, line: &[u8]) -> Vec<Value> {
        let shown = format!("{:.200}", String::from_utf8_lossy(line));
        let stdin = self.stdin.as_mut().expect("stdin open");
        stdin.write_all(line).expect("write to adapter");
        stdin.write_all(b"\n").expect("write newline");
        stdin.flush().expect("flush to adapter");
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
            assert!(before.len() <= 4, "FINDING (fuzz_mcp): one line produced >1 response before the sentinel; line={shown:?} responses={before:?}");
        }
    }

    fn request(&mut self, method: &str, id: u64, params: Value) -> Value {
        self.send_line(&json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params}).to_string());
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
        for _ in 0..250 {
            if let Ok(Some(_)) = self.child.try_wait() {
                return;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Returns the answer one line is owed, by `handle_line`'s documented rule.
///
/// It reads `method` (a string) and `id` (any JSON value) alone: `None` where
/// no response is owed — a blank line, a notification, a stray response, an
/// id-less non-request — else the id the one response carries and, where
/// the adapter refuses the line itself, its code: -32700 for no JSON and
/// -32600 for no object, under a null id; -32600 for a bare id. A request's
/// own outcome is left free.
fn owed(line: &str) -> Option<(Value, Option<i64>)> {
    if line.trim().is_empty() {
        return None;
    }
    let Ok(message) = serde_json::from_str::<Value>(line) else { return Some((Value::Null, Some(-32700))) };
    let Value::Object(message) = message else { return Some((Value::Null, Some(-32600))) };
    match (message.get("method").and_then(Value::as_str), message.get("id")) {
        (Some(_), Some(id)) => Some((id.clone(), None)),
        (None, Some(id)) if !message.contains_key("result") && !message.contains_key("error") => Some((id.clone(), Some(-32600))),
        _ => None,
    }
}

/// Returns a storm line as one line of stdin, its newlines dropped.
///
/// A newline would split one fuzz input into several lines and skew the
/// count: the payload, not the framing, is under test there.
fn one_line(line: &str) -> String {
    line.chars().filter(|&c| c != '\n' && c != '\r').collect()
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

/// The JSON-RPC corpus the storm mutates: requests of each dispatch kind —
/// a wire op, a shell call, an apparatus tool — a notification, an id-less
/// non-request, and a stray response.
fn corpus() -> Vec<Vec<u8>> {
    [
        r#"{"jsonrpc":"2.0","id":1,"method":"ping"}"#,
        r#"{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}"#,
        r#"{"jsonrpc":"2.0","id":3,"method":"initialize","params":{"protocolVersion":"2025-06-18"}}"#,
        r#"{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"fork","arguments":{}}}"#,
        r#"{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"retrieve_v","arguments":{"specs":[]}}}"#,
        r#"{"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"search","arguments":{"query":"hello"}}}"#,
        r#"{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"changes_since","arguments":{"since":0,"limit":3}}}"#,
        r#"{"jsonrpc":"2.0","id":8,"method":"tools/call","params":{"name":"fetch","arguments":{"i":"1.0.1.0.1.0.1.1"}}}"#,
        r#"{"jsonrpc":"2.0","id":9,"method":"tools/call","params":{"name":"session_info","arguments":{}}}"#,
        r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#,
        r#"{"jsonrpc":"2.0","id":10,"result":{}}"#,
        r#"{"jsonrpc":"2.0","id":11,"method":"no/such/method"}"#,
    ]
    .iter()
    .map(|s| s.as_bytes().to_vec())
    .collect()
}

/// A seeded arbitrary UTF-8 line (no newline) — JSON-ish punctuation biased,
/// so the parser is genuinely exercised.
fn random_utf8_line(rng: &mut u64, max_len: usize) -> String {
    let len = (splitmix64(rng) as usize) % (max_len + 1);
    let mut s = String::with_capacity(len);
    for _ in 0..len {
        let ascii = b" {}[]\":,0123456789tfnul-.abcxyz/";
        let ch = if splitmix64(rng).is_multiple_of(8) { char::from_u32(0x100 + (splitmix64(rng) as u32 % 0x2000)).unwrap_or('?') } else { ascii[(splitmix64(rng) as usize) % ascii.len()] as char };
        if ch != '\n' && ch != '\r' {
            s.push(ch);
        }
    }
    s
}

/// Each line shape `handle_line` names gets its documented answer, no other.
///
/// Counted by the sentinel, so a reply where none is owed shows: a request,
/// one response under its id as given — whatever JSON the id is, `jsonrpc`
/// absent or another version — a CRLF-ended one included, a method this server
/// does not offer the -32601, MCP's own `resources/list` among them; an id
/// with no method, no `result` and no `error`, the -32600 under that id; a
/// notification of any method, a stray response, an id-less non-request and a
/// blank line (`\r` alone included), none; a line that is no JSON — bytes that
/// are not UTF-8, and nesting far past the parser's depth bound, included —
/// the -32700 parse error, and JSON that is no object the -32600, both id
/// null; and every sentinel `ping` answers `{}`. No line here reaches the
/// board.
#[test]
fn each_line_shape_gets_its_documented_answer() {
    let fixture = Fixture::new("shapes");
    let mut mcp = Mcp::spawn(&fixture);
    let answered: [(&[u8], Value, Option<i64>); 7] = [
        (br#"{"jsonrpc":"2.0","id":"probe","method":"ping"}"#, json!("probe"), None),
        (b"{\"jsonrpc\":\"2.0\",\"id\":\"crlf\",\"method\":\"ping\"}\r", json!("crlf"), None),
        (br#"{"jsonrpc":"2.0","id":99,"method":"no/such"}"#, json!(99), Some(-32601)),
        (br#"{"jsonrpc":"2.0","id":"listing","method":"resources/list"}"#, json!("listing"), Some(-32601)),
        (br#"{"jsonrpc":"2.0","id":"no-method"}"#, json!("no-method"), Some(-32600)),
        (br#"{"id":"bare","method":"ping"}"#, json!("bare"), None),
        (br#"{"jsonrpc":"1.0","id":"old","method":"ping"}"#, json!("old"), None),
    ];
    for (line, id, code) in answered {
        let r = mcp.responses_for(line);
        assert_eq!(r.len(), 1, "{:?} gets exactly one response: {r:?}", String::from_utf8_lossy(line));
        assert_eq!((&r[0]["id"], r[0]["error"]["code"].as_i64()), (&id, code), "{:?}", r[0]);
    }
    for id in [json!(null), json!(true), json!(-7), json!(1.5), json!(""), json!([1, "a"]), json!({"k": [null]})] {
        let r = mcp.responses_for(json!({"jsonrpc": "2.0", "id": id, "method": "ping"}).to_string().as_bytes());
        assert_eq!(r.len(), 1, "a request under {id} gets exactly one response: {r:?}");
        assert_eq!((r[0].get("id"), &r[0]["result"]), (Some(&id), &json!({})), "answered under {id}, as given");
    }
    let unanswered: [&[u8]; 8] = [
        br#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#,
        br#"{"jsonrpc":"2.0","method":"no/such"}"#,
        br#"{"jsonrpc":"2.0","id":7,"result":{}}"#,
        br#"{"jsonrpc":"2.0","id":8,"error":{"code":-32601,"message":"x"}}"#,
        br#"{"jsonrpc":"2.0","foo":1}"#,
        b"",
        b"   ",
        b"\r",
    ];
    for line in unanswered {
        let r = mcp.responses_for(line);
        assert!(r.is_empty(), "{:?} gets no response: {r:?}", String::from_utf8_lossy(line));
    }
    let deep = "[".repeat(1_000_000);
    let refused: [(&[u8], i64); 8] =
        [(b"{ this is not json", -32700), (b"this is not json", -32700), (b"\xff\xfe", -32700), (deep.as_bytes(), -32700), (b"[]", -32600), (b"7", -32600), (br#""ping""#, -32600), (b"null", -32600)];
    for (line, code) in refused {
        let shown = format!("{:.40}", String::from_utf8_lossy(line));
        let r = mcp.responses_for(line);
        assert_eq!(r.len(), 1, "{shown:?} gets exactly one response: {r:?}");
        let (got_code, got_id) = (&r[0]["error"]["code"], &r[0]["id"]);
        assert_eq!((got_code, got_id), (&json!(code), &Value::Null), "{shown:?}");
    }
    assert!(mcp.finish().success());
}

/// The storm: every line is answered as its shape owes, and the adapter lives.
///
/// Each arbitrary or mutated line draws exactly what `owed` reads off it —
/// no response, or one well-formed response under the line's own id, the
/// adapter's own refusal under its code — and `tools/list` still answers the
/// catalog whole after the last.
#[test]
fn mcp_line_protocol_storm_survives_and_answers_each_line_as_its_shape_owes() {
    let fixture = Fixture::new("storm");
    let mut mcp = Mcp::spawn(&fixture);

    // Bring the session up the ordinary way first.
    let init = mcp.request("initialize", 1, json!({"protocolVersion": "2025-06-18", "capabilities": {}}));
    assert_eq!(init["result"]["serverInfo"]["name"], "skep", "initialize: {init}");
    let catalog = mcp.request("tools/list", 2, json!({}))["result"]["tools"].clone();
    assert!(catalog.as_array().is_some_and(|t| !t.is_empty()), "a nonempty tools array before the storm: {catalog}");

    // The storm: arbitrary and mutated lines.
    let corpus = corpus();
    let mut rng = 0x4D43_5000_0000_0001; // "MCP\0\0\0\0\1"
    for i in 0..budget(400) {
        let raw = if splitmix64(&mut rng).is_multiple_of(3) { random_utf8_line(&mut rng, 160) } else { String::from_utf8_lossy(&mutate(splitmix64(&mut rng), &corpus)).into_owned() };
        let line = one_line(&raw);
        let responses = mcp.responses_for(line.as_bytes());
        for v in &responses {
            assert_jsonrpc(v);
        }
        match owed(&line) {
            None => assert!(responses.is_empty(), "FINDING (fuzz_mcp): line {i} is owed no response and drew {responses:?}: {line:?}"),
            Some((id, code)) => {
                assert_eq!(responses.len(), 1, "FINDING (fuzz_mcp): line {i} is owed one response under {id}, drew {responses:?}: {line:?}");
                assert_eq!(responses[0].get("id"), Some(&id), "FINDING (fuzz_mcp): line {i} is answered under another id: {line:?}");
                if let Some(code) = code {
                    assert_eq!(responses[0]["error"]["code"], json!(code), "FINDING (fuzz_mcp): line {i} is refused under another code: {line:?}");
                }
            }
        }
    }

    // Survival: tools/list still answers the catalog it answered before the
    // storm.
    let v = mcp.request("tools/list", 100_000, json!({}));
    assert_eq!(v["result"]["tools"], catalog, "the catalog survives the storm whole");

    // Clean exit on stdin EOF.
    let status = mcp.finish();
    assert!(status.success(), "clean exit after the storm: {status:?}");
}
