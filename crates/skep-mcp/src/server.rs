//! The MCP side: the loop over the inbound lines, JSON-RPC 2.0 dispatch, and
//! `tools/call` onto the backend's calls; stdout carries protocol only.
//!
//! A REFUSAL AS A RESULT: every tool's answer is the shell's — a value, or a
//! [`Refusal`] of one of five kinds — and the tool result says which. A
//! `refused` refusal is THE BOARD's VERDICT on the frame: it rides as DATA,
//! `isError: false`, the verdict's body verbatim under `body` with the
//! shell's envelope (`name`, `status`, `code`, `detail`, `op`) beside it — a
//! client that cannot read a rejection has been silently failed. Every
//! other kind — `halt`, `blocked`, `unreachable`, and `shell`, the shell's
//! own names among them — is `isError: true` with the refusal's value as
//! the text: `isError` means ONE thing, that the shell could not get the
//! board's verdict. A call the adapter will not run — a tool outside the
//! catalog, an argument an adapter tool does not take — is no tool result
//! at all: it is refused -32602, as malformed `tools/call` params are.

use std::io::Write;
use std::sync::mpsc::Receiver;

use serde_json::{json, Map, Value};
use skep_shell::Refusal;

use crate::media::{base64, sniff_image, MAX_FETCH_BYTES};
use crate::shell::{Backend, FetchAnswer};
use crate::tools::{wire_frame, Catalog, Tool};

/// When the client's `initialize` names no protocolVersion (it always
/// should), answer the newest revision this server was written against.
const FALLBACK_PROTOCOL_VERSION: &str = "2025-06-18";

/// The JSON-RPC 2.0 error codes this server answers (the spec's §5.1),
/// each the spec's own number: a name for it, never a new one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ErrorCode {
    ParseError = -32700,
    InvalidRequest = -32600,
    MethodNotFound = -32601,
    InvalidParams = -32602,
}

/// What reaches the loop: a line of stdin, stdin's end, or the backend's
/// stop — a death of the session the shell did not re-open, with the plain
/// line the stop says.
#[derive(Debug)]
pub enum Inbound {
    /// One line of stdin, as raw bytes.
    Line(Vec<u8>),
    /// Stdin's end, or a read of it that failed.
    Eof,
    /// The backend's stop: the plain line the loop says before it exits.
    Stop(String),
}

/// The MCP side's state: the backend every tool calls and the catalog
/// `tools/list` and `initialize` answer from.
pub struct Server {
    /// The seam onto the shell, its one session open.
    pub backend: Backend,
    /// The loaded catalog, its commons sentence appended where one is set.
    pub catalog: Catalog,
}

impl Server {
    /// The loop: one JSON-RPC message per line in, one per line out,
    /// nothing else ever on stdout, the calls served one at a time in
    /// arrival order. Stdin's end is the clean exit, `0`; a stop the backend
    /// asked is said and exits `1`; a closed stdout (the harness hung up)
    /// ends the loop too. Each line goes to `handle_line` as raw bytes: what
    /// a line is, its encoding included, is that method's call. The exit
    /// code; the caller runs the shell's stop and exits with it.
    pub fn run(&self, inbound: &Receiver<Inbound>) -> u8 {
        let mut out = std::io::stdout();
        loop {
            match inbound.recv() {
                Ok(Inbound::Line(line)) => {
                    let Some(reply) = self.handle_line(&line) else { continue };
                    let mut bytes = serde_json::to_vec(&reply).expect("serializing a serde_json::Value cannot fail");
                    bytes.push(b'\n');
                    if out.write_all(&bytes).and_then(|()| out.flush()).is_err() {
                        return 0;
                    }
                }
                Ok(Inbound::Stop(line)) => {
                    crate::log(format_args!("stopped: {line}"));
                    return 1;
                }
                Ok(Inbound::Eof) | Err(_) => return 0,
            }
        }
    }

    /// One inbound line, as raw bytes → at most one outbound message,
    /// classified by two members alone: `method` (a string) and `id` (any
    /// JSON value, echoed as given; `jsonrpc` is not read). A request — a
    /// method and an id — gets its response under that id. `None` for a
    /// blank line, a notification (a method, no id: all consumed silently),
    /// a stray response (an id, no method, a `result` or an `error`) or an
    /// id-less non-request: there is nothing to answer under. A line that
    /// does not parse as JSON — bytes that are not UTF-8 included — is the
    /// -32700 parse error and JSON that is no object the -32600, both id
    /// null; an id with no method, no `result` and no `error` is the -32600
    /// under that id.
    fn handle_line(&self, line: &[u8]) -> Option<Value> {
        if std::str::from_utf8(line).is_ok_and(|s| s.trim().is_empty()) {
            return None;
        }
        let msg: Value = match serde_json::from_slice(line) {
            Ok(v) => v,
            Err(e) => {
                let message = format!("parse error: {e}");
                return Some(rpc_error(Value::Null, ErrorCode::ParseError, &message));
            }
        };
        let Value::Object(mut msg) = msg else {
            return Some(rpc_error(Value::Null, ErrorCode::InvalidRequest, "a message is a JSON object"));
        };
        // The message is owned: its id and params move out, never copied.
        let id = msg.remove("id");
        let params = msg.remove("params");
        let method = msg.get("method").and_then(Value::as_str);
        match (method, id) {
            (None, None) => None,
            (None, Some(id)) => {
                if msg.contains_key("result") || msg.contains_key("error") {
                    // A stray response to a request this server never sent.
                    None
                } else {
                    Some(rpc_error(id, ErrorCode::InvalidRequest, "a request names a method"))
                }
            }
            // Notifications — `notifications/initialized` and all others.
            (Some(_), None) => None,
            (Some(m), Some(id)) => Some(self.respond(m, params, id)),
        }
    }

    /// One request → its JSON-RPC response.
    fn respond(&self, method: &str, params: Option<Value>, id: Value) -> Value {
        match method {
            "initialize" => {
                let version = params.as_ref().and_then(|p| p.get("protocolVersion")).and_then(Value::as_str).unwrap_or(FALLBACK_PROTOCOL_VERSION);
                rpc_result(
                    id,
                    json!({
                        "protocolVersion": version,
                        "capabilities": {"tools": {}},
                        "serverInfo": {"name": "skep", "version": env!("CARGO_PKG_VERSION")},
                        "instructions": self.catalog.instructions(),
                    }),
                )
            }
            "ping" => rpc_result(id, json!({})),
            "tools/list" => rpc_result(id, json!({"tools": self.catalog.tools()})),
            "tools/call" => {
                let called = call_params(params).and_then(|(name, args)| self.call(&name, args));
                match called {
                    Ok(result) => rpc_result(id, result),
                    Err(refusal) => rpc_error(id, ErrorCode::InvalidParams, &refusal),
                }
            }
            other => {
                let message = format!("method '{other}' not supported");
                rpc_error(id, ErrorCode::MethodNotFound, &message)
            }
        }
    }

    /// Run one tool: `Ok` its tool result, `Err` the refusal of a call the
    /// adapter will not run — a name outside the catalog, or an argument an
    /// adapter tool's row does not take (the adapter is the one party that
    /// reads those; a wire op's arguments pass through unread as the frame,
    /// the daemon's strict parse their validator) — which `respond` answers
    /// -32602, the channel `call_params`' faults take (MCP 2025-06-18, Tools
    /// §Error Handling: unknown tools and invalid arguments are protocol
    /// errors). A tool's result is its answer rendered by `tool_result`'s
    /// rule: a value or the board's verdict as data, any other refusal
    /// `isError`.
    fn call(&self, name: &str, args: Map<String, Value>) -> Result<Value, String> {
        let tool = Tool::named(name).ok_or_else(|| format!("unknown tool '{name}'; tools/list names the available tools"))?;
        if let Some(members) = tool.members() {
            if let Some(arg) = args.keys().find(|k| !members.contains(&k.as_str())) {
                return Err(match members {
                    [] => format!("{name} takes no arguments; got '{arg}'"),
                    _ => format!("{name} takes {}; got '{arg}'", members.iter().map(|m| format!("'{m}'")).collect::<Vec<_>>().join(", ")),
                });
            }
        }
        let answer = match tool {
            Tool::Op(op) => self.backend.session_call("op", json!({"frame": wire_frame(op, args)})),
            Tool::Boards => self.backend.board_call("boards", json!({})),
            Tool::Health => self.backend.board_call("health", json!({})),
            Tool::Probe => self.backend.board_call("probe", json!({})),
            Tool::Search | Tool::Places | Tool::Held | Tool::Resolve => self.backend.session_call(name, Value::Object(args)),
            Tool::ChangesSince => self.backend.session_call("changes", Value::Object(args)),
            Tool::SessionInfo => self.backend.session_info(),
            Tool::Fetch => return Ok(self.fetch(args.get("i"))),
        };
        Ok(tool_result(answer))
    }

    /// `fetch(i)` as a content block: the board's bytes at `i`, sniffed —
    /// an image block with the type the magic names, else an embedded
    /// resource blob of `application/octet-stream` at the fetch's own URI —
    /// base64 within; a file past the cap refused in plain words naming it,
    /// a stream cut short said so, each `isError`; the shell's refusal by
    /// `tool_result`'s rule.
    fn fetch(&self, i: Option<&Value>) -> Value {
        let Some(i) = i.and_then(Value::as_str) else {
            return tool_result(Err(Refusal::malformed("i")));
        };
        match self.backend.fetch(i) {
            Ok(FetchAnswer::Bytes(bytes)) => {
                let data = base64(&bytes);
                let block = match sniff_image(&bytes) {
                    Some(mime) => json!({"type": "image", "data": data, "mimeType": mime}),
                    None => json!({"type": "resource", "resource": {"uri": format!("{}/blob?i={i}", self.backend.origin().as_str()), "mimeType": "application/octet-stream", "blob": data}}),
                };
                json!({"content": [block], "isError": false})
            }
            Ok(FetchAnswer::PastTheCap { length }) => text_result(
                format!(
                    "the file at {i} is {length} bytes, past this adapter's cap of {MAX_FETCH_BYTES} bytes ({} MiB) on one fetch: no byte of it was read; a smaller file is served whole",
                    MAX_FETCH_BYTES / (1024 * 1024)
                ),
                true,
            ),
            Ok(FetchAnswer::Cut { read, length, error }) => text_result(
                format!(
                    "the fetch of {i} ended before the file was whole: {read} of {} bytes came ({error}); the board resets a stream whose requester it can no longer serve — fetch it again",
                    length.map_or("an undeclared number of".to_string(), |n| n.to_string())
                ),
                true,
            ),
            Err(refusal) => tool_result(Err(refusal)),
        }
    }
}

/// `tools/call` params: `{"name": …, "arguments": {…}?}`; absent or null
/// arguments are the empty object. The params are the message's own, taken
/// by value: the arguments move into the frame, never copied.
fn call_params(params: Option<Value>) -> Result<(String, Map<String, Value>), String> {
    let mut p = params.ok_or("tools/call requires params")?;
    let Some(Value::String(name)) = p.get_mut("name").map(Value::take) else {
        return Err("tools/call params require a string 'name'".into());
    };
    let args = match p.get_mut("arguments").map(Value::take) {
        None | Some(Value::Null) => Map::new(),
        Some(Value::Object(args)) => args,
        Some(_) => return Err("'arguments' must be a JSON object".into()),
    };
    Ok((name, args))
}

fn rpc_result(id: Value, result: Value) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "result": result})
}

fn rpc_error(id: Value, code: ErrorCode, message: &str) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "error": {"code": code as i64, "message": message}})
}

/// A tool result of one text content block, `isError` as given.
fn text_result(text: String, is_error: bool) -> Value {
    json!({"content": [{"type": "text", "text": text}], "isError": is_error})
}

/// THE RULE (the module doc): an answer as the result's text, `isError`
/// false; the board's verdict (`Refusal::Board`) as data, its value — the
/// shell's envelope with the verdict's body verbatim — the text, `isError`
/// false; every other refusal its value as the text, `isError` true.
fn tool_result(answer: Result<Value, Refusal>) -> Value {
    match answer {
        Ok(v) => text_result(v.to_string(), false),
        Err(refusal) => text_result(refusal.to_value().to_string(), !matches!(refusal, Refusal::Board(_))),
    }
}

#[cfg(test)]
mod tests {
    use skep_client::halt::{Face, Refused};
    use skep_shell::Name;

    use super::*;

    /// tools/call params: a string `name`; `arguments` absent, null (both the
    /// empty object) or an object taken whole — anything else refused.
    #[test]
    fn tools_call_params_are_a_string_name_and_object_or_absent_arguments() {
        let (name, args) = call_params(Some(json!({"name": "fork"}))).expect("argument-less call");
        assert_eq!(name, "fork");
        assert!(args.is_empty());
        let p = json!({"name": "fork", "arguments": null});
        assert!(call_params(Some(p)).expect("null arguments").1.is_empty());
        let p = json!({"name": "insert", "arguments": {"doc": "1.0.1.0.1", "values": ["x"]}});
        let (name, args) = call_params(Some(p)).expect("a call with arguments");
        assert_eq!(name, "insert");
        assert_eq!(Value::Object(args), json!({"doc": "1.0.1.0.1", "values": ["x"]}), "whole");
        assert!(call_params(None).is_err());
        assert!(call_params(Some(json!({"name": 7}))).is_err());
        assert!(call_params(Some(json!({"name": "fork", "arguments": 3}))).is_err());
    }

    /// THE RULE: a value is data; the board's verdict is data — its body
    /// verbatim under `body`, the envelope beside it, `isError` false; a
    /// halt, the block, the unreachable board and the shell's own refusals
    /// are `isError` true with the refusal's value as the text (the mutant
    /// that marks every refusal `isError` loses "rejections are data"; the
    /// one that marks none loses `unreachable`).
    #[test]
    fn a_refusal_as_a_result_follows_the_rule() {
        let read = |v: &Value| -> (bool, Value) {
            assert_eq!(v["content"].as_array().map(Vec::len), Some(1));
            let text = v["content"][0]["text"].as_str().expect("a text block");
            (v["isError"].as_bool().expect("isError"), serde_json::from_str(text).expect("JSON text"))
        };
        let (is_error, text) = read(&tool_result(Ok(json!({"resp": "ack_addr", "addr": "1.0.1.0.2", "at": 7}))));
        assert!(!is_error);
        assert_eq!(text["resp"], "ack_addr");
        let verdict = json!({"code": "doc_not_registered", "disposition": "reorder", "op": "retrieve_v", "resp": "rejected"});
        let refused = Refusal::Board(Refused { status: 200, code: "doc_not_registered".into(), detail: None, op: Some("retrieve_v".into()), body: verdict.clone() });
        let (is_error, text) = read(&tool_result(Err(refused)));
        assert!(!is_error, "the board's verdict is data");
        assert_eq!((text["kind"].as_str(), text["name"].as_str(), text["status"].as_u64()), (Some("refused"), Some("doc_not_registered"), Some(200)));
        assert_eq!(text["body"], verdict, "the verdict's body verbatim");
        let face = Face { state: "s".into(), cause: "c".into(), act: "a".into() };
        for other in [
            Refusal::named(Name::NO_KEY, face.clone()),
            Refusal::halt(face),
            Refusal::Blocked(skep_client::Blocked { record: "1.0.1.0.7.1".into(), named_by: "http://x".into(), ground: None }),
            Refusal::Unreachable(skep_client::DialError::Connect("refused".into())),
            Refusal::shell(Name::SESSION_ENDED, json!({"session": "s-1"})),
            Refusal::malformed("since"),
        ] {
            let expected = other.to_value();
            let (is_error, text) = read(&tool_result(Err(other)));
            assert!(is_error, "{expected}");
            assert_eq!(text, expected, "the refusal's value is the text");
        }
    }
}
