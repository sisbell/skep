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
//! * a line that holds a **lone surrogate escape** is read by the same shapes,
//!   save that its request is refused `-32602` under its id and never run,
//!   and one whose `id` holds the escape is the parse error;
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
/// own outcome is left free, save one read past a lone surrogate escape
/// (`mended`), which is never run: it is owed the -32602.
fn owed(line: &str) -> Option<(Value, Option<i64>)> {
    if line.trim().is_empty() {
        return None;
    }
    let (message, refused) = match serde_json::from_str::<Value>(line) {
        Ok(message) => (message, None),
        Err(_) => match mended(line) {
            Some(message) => (message, Some(-32602)),
            None => return Some((Value::Null, Some(-32700))),
        },
    };
    let Value::Object(message) = message else { return Some((Value::Null, Some(-32600))) };
    match (message.get("method").and_then(Value::as_str), message.get("id")) {
        (Some(_), Some(id)) => Some((id.clone(), refused)),
        (None, Some(id)) if !message.contains_key("result") && !message.contains_key("error") => Some((id.clone(), Some(-32600))),
        _ => None,
    }
}

/// Returns a line as it reads past its lone surrogate escapes, if it does.
///
/// It is the oracle's own statement of the adapter's rule, by another route:
/// `\uXXXX` escapes standing end to end are a run of UTF-16 code units, and
/// the units `char::decode_utf16` cannot pair are the lone ones. `Some` is the
/// line parsed with U+FFFD's escape in place of each. `None` where it holds
/// none, where it does not parse so, and where its `id` holds one: read with
/// a character the id does not hold in their place, the id then holds it.
fn mended(line: &str) -> Option<Value> {
    let unit = |at: usize| {
        let escape = line.get(at..at + 6).filter(|escape| escape.starts_with("\\u") && escape[2..].bytes().all(|b| b.is_ascii_hexdigit()))?;
        u16::from_str_radix(&escape[2..], 16).ok()
    };
    let (mut lone, mut at) = (Vec::new(), 0);
    while at < line.len() {
        if line.as_bytes()[at] != b'\\' {
            at += 1;
            continue;
        }
        let run: Vec<u16> = (0..).map_while(|k| unit(at + 6 * k)).collect();
        let mut k = 0;
        for decoded in char::decode_utf16(run.iter().copied()) {
            if decoded.is_err() {
                lone.push(at + 6 * k);
            }
            k += decoded.map_or(1, char::len_utf16);
        }
        at += if run.is_empty() { 2 } else { 6 * run.len() };
    }
    if lone.is_empty() {
        return None;
    }
    let spelt = |stand_in: char| {
        let mut text = line.to_string();
        lone.iter().for_each(|&at| text.replace_range(at + 2..at + 6, &format!("{:04X}", u32::from(stand_in))));
        serde_json::from_str::<Value>(&text).ok()
    };
    let message = spelt(char::REPLACEMENT_CHARACTER)?;
    let Some(id) = message.get("id") else { return Some(message) };
    let held = id.to_string();
    let absent = ('\u{E000}'..='\u{F8FF}').find(|&private| !held.contains(private))?;
    let holds_one = spelt(absent)?.get("id").is_some_and(|id| id.to_string().contains(absent));
    (!holds_one).then_some(message)
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

/// Returns the JSON-RPC corpus the storm mutates.
///
/// It holds requests of each dispatch kind — a wire op, a shell call, an
/// apparatus tool — and a shell call whose `opts` the door refuses,
/// `search`'s withheld `reindex`, and an `edit_text` call whose second pair
/// carries a member the door refuses; a notification, an id-less non-request,
/// and a stray response; and three lines that hold a lone surrogate escape,
/// which no mutation writes: a request, a notification, and a request whose
/// id holds it. A value recipe passes those three on as written, and a byte
/// recipe cuts and splices them.
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
        r#"{"jsonrpc":"2.0","id":12,"method":"tools/call","params":{"name":"search","arguments":{"query":"hello","opts":{"reindex":true}}}}"#,
        r#"{"jsonrpc":"2.0","id":13,"method":"tools/call","params":{"name":"search","arguments":{"query":"a\ud800b"}}}"#,
        r#"{"jsonrpc":"2.0","id":14,"method":"tools/call","params":{"name":"edit_text","arguments":{"doc":"1.0.1.0.1","edits":[{"old":"a","new":"b"},{"old":"c","new":"d","doc":"1.0.1.0.1"}]}}}"#,
        r#"{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"reason":"\udc00"}}"#,
        r#"{"jsonrpc":"2.0","id":"a\uD83D","method":"ping"}"#,
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
/// blank line (`\r` alone included, and U+3000 alone, which `str::trim` reads
/// as whitespace though JSON does not), none; a line that is no JSON — bytes
/// that are not UTF-8, and nesting far past the parser's depth bound, included
/// — the -32700 parse error, and JSON that is no object the -32600, both id
/// null; and every sentinel `ping` answers `{}`. No line here reaches the
/// board.
///
/// A line holding a lone surrogate escape is read by the same shapes. Its
/// request is refused -32602 under its id, in one sentence that quotes none
/// of it — the escape in a call's argument, in the params of a method that
/// reads none, or in the method itself — and an id's own U+FFFD is kept; its
/// bare id is the -32600 under that id; its notification, stray response and
/// id-less non-request get none; it is the -32700 where its id holds the
/// escape or it does not parse with the escape read past, and the -32600
/// where it is no object. A pair escaped whole, and a `u` behind an escaped
/// backslash, are text as any other. Every -32700 says the parse's own error
/// of the line.
#[test]
fn each_line_shape_gets_its_documented_answer() {
    let fixture = Fixture::new("shapes");
    let mut mcp = Mcp::spawn(&fixture);
    let answered: [(&[u8], Value, Option<i64>); 15] = [
        (br#"{"jsonrpc":"2.0","id":"probe","method":"ping"}"#, json!("probe"), None),
        (b"{\"jsonrpc\":\"2.0\",\"id\":\"crlf\",\"method\":\"ping\"}\r", json!("crlf"), None),
        (br#"{"jsonrpc":"2.0","id":99,"method":"no/such"}"#, json!(99), Some(-32601)),
        (br#"{"jsonrpc":"2.0","id":"listing","method":"resources/list"}"#, json!("listing"), Some(-32601)),
        (br#"{"jsonrpc":"2.0","id":"no-method"}"#, json!("no-method"), Some(-32600)),
        (br#"{"id":"bare","method":"ping"}"#, json!("bare"), None),
        (br#"{"jsonrpc":"1.0","id":"old","method":"ping"}"#, json!("old"), None),
        (br#"{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"replace_text","arguments":{"doc":"1.0.1.0.1","old":"a\ud800b","new":"c"}}}"#, json!(7), Some(-32602)),
        (br#"{"jsonrpc":"2.0","id":"low","method":"tools/list","params":{"cursor":"\udc00"}}"#, json!("low"), Some(-32602)),
        (br#"{"jsonrpc":"2.0","id":"high","method":"ping","params":{"note":"x\uD83D"}}"#, json!("high"), Some(-32602)),
        (br#"{"jsonrpc":"2.0","id":"method","method":"no\udfff/such"}"#, json!("method"), Some(-32602)),
        (br#"{"jsonrpc":"2.0","id":"a\ufffd","method":"ping","params":["\ud800"]}"#, json!("a\u{FFFD}"), Some(-32602)),
        (br#"{"jsonrpc":"2.0","id":"no-method-lone","params":["\ud800"]}"#, json!("no-method-lone"), Some(-32600)),
        (br#"{"jsonrpc":"2.0","id":"pair","method":"ping","params":["\ud83d\ude00"]}"#, json!("pair"), None),
        (br#"{"jsonrpc":"2.0","id":"escaped","method":"ping","params":["\\ud800"]}"#, json!("escaped"), None),
    ];
    let mut lone_surrogate = Vec::new();
    for (line, id, code) in answered {
        let r = mcp.responses_for(line);
        assert_eq!(r.len(), 1, "{:?} gets exactly one response: {r:?}", String::from_utf8_lossy(line));
        assert_eq!((&r[0]["id"], r[0]["error"]["code"].as_i64()), (&id, code), "{:?}", r[0]);
        assert_eq!(r[0].get("result"), code.is_none().then_some(&json!({})), "a `ping` answers {{}}, and a refusal no result: {:?}", r[0]);
        if code == Some(-32602) {
            lone_surrogate.push(r[0]["error"]["message"].as_str().unwrap_or_default().to_string());
        }
    }
    assert_eq!(lone_surrogate.len(), 5, "premise: each request holding a lone surrogate escape was refused");
    assert!(lone_surrogate[0].contains("lone surrogate") && lone_surrogate[0].contains("not run"), "the refusal names its cause: {}", lone_surrogate[0]);
    assert!(lone_surrogate.iter().all(|said| *said == lone_surrogate[0]), "one sentence, whatever the line held: {lone_surrogate:?}");
    for id in [json!(null), json!(true), json!(-7), json!(1.5), json!(""), json!([1, "a"]), json!({"k": [null]})] {
        let r = mcp.responses_for(json!({"jsonrpc": "2.0", "id": id, "method": "ping"}).to_string().as_bytes());
        assert_eq!(r.len(), 1, "a request under {id} gets exactly one response: {r:?}");
        assert_eq!((r[0].get("id"), &r[0]["result"]), (Some(&id), &json!({})), "answered under {id}, as given");
    }
    let unanswered: [&[u8]; 12] = [
        br#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#,
        br#"{"jsonrpc":"2.0","method":"no/such"}"#,
        br#"{"jsonrpc":"2.0","id":7,"result":{}}"#,
        br#"{"jsonrpc":"2.0","id":8,"error":{"code":-32601,"message":"x"}}"#,
        br#"{"jsonrpc":"2.0","foo":1}"#,
        br#"{"jsonrpc":"2.0","method":"tools/call","params":{"name":"replace_text","arguments":{"doc":"1.0.1.0.1","old":"a\ud800b","new":"c"}}}"#,
        br#"{"jsonrpc":"2.0","id":7,"result":{"text":"\udc00"}}"#,
        br#"{"jsonrpc":"2.0","foo":"\ud800"}"#,
        b"",
        b"   ",
        b"\r",
        "\u{3000}".as_bytes(),
    ];
    for line in unanswered {
        let r = mcp.responses_for(line);
        assert!(r.is_empty(), "{:?} gets no response: {r:?}", String::from_utf8_lossy(line));
    }
    let deep = "[".repeat(1_000_000);
    let refused: [(&[u8], i64); 13] = [
        (b"{ this is not json", -32700),
        (b"this is not json", -32700),
        (b"\xff\xfe", -32700),
        (deep.as_bytes(), -32700),
        (br#"{"jsonrpc":"2.0","id":"a\ud800","method":"ping"}"#, -32700),
        (br#"{"jsonrpc":"2.0","id":[1,"a\ud800"],"method":"ping"}"#, -32700),
        (br#"{"jsonrpc":"2.0","id":9,"method":"ping","params":["\ud800"]"#, -32700),
        (br#"{"jsonrpc":"2.0","id":9,"method":"ping","params":["\ud800",1e999]}"#, -32700),
        (b"[]", -32600),
        (b"7", -32600),
        (br#""ping""#, -32600),
        (b"null", -32600),
        (br#"["\ud800"]"#, -32600),
    ];
    for (line, code) in refused {
        let shown = format!("{:.40}", String::from_utf8_lossy(line));
        let r = mcp.responses_for(line);
        assert_eq!(r.len(), 1, "{shown:?} gets exactly one response: {r:?}");
        let (got_code, got_id) = (&r[0]["error"]["code"], &r[0]["id"]);
        assert_eq!((got_code, got_id), (&json!(code), &Value::Null), "{shown:?}");
        if code == -32700 {
            let strict = serde_json::from_slice::<Value>(line).expect_err("a line refused -32700 is one serde_json does not read");
            assert_eq!(r[0]["error"]["message"], json!(format!("parse error: {strict}")), "{shown:?} is refused in the parse's own words");
        }
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
