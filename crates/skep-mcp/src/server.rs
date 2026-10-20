//! The MCP side: the stdio transport, JSON-RPC 2.0 dispatch, and the tools.
//!
//! [`read_stdin`] reads stdin on a thread of its own and hands each line to
//! the loop, [`Server::run`], which answers it on stdout, where nothing but
//! the protocol is written; the dispatch takes `tools/call` onto the
//! backend's calls.
//!
//! **A refusal as a result**, the crate's rule of that name, is kept here:
//! `tool_result` renders every answer the shell gives by it, the board's
//! verdict as data and any other refusal `isError`; `Server::fetch` adds its
//! own two `isError`, a file past the cap and a stream cut short; and `respond`
//! answers -32602 a call `call_params` or `Tool::admit` refuses, which is no
//! tool result at all.

use std::io::{BufRead, Write};
use std::sync::mpsc::{Receiver, Sender};
use std::thread;

use serde_json::{json, Map, Value};
use skep_shell::Refusal;

use crate::media::{base64, read_whole, sniff_image, FetchAnswer, MAX_FETCH_BYTES};
use crate::shell::Backend;
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

/// What reaches the loop: a stdin line, stdin's end, or the backend's stop.
///
/// The stop comes where a death of the session no one may re-open, or the
/// board's refusal of a session the adapter opened itself, ends the adapter,
/// with the plain line it says.
#[derive(Debug)]
pub enum Inbound {
    /// One line of stdin, as raw bytes.
    Line(Vec<u8>),
    /// Stdin's end, or a read of it that failed.
    Eof,
    /// The backend's stop: the plain line the loop says before it exits.
    Stop(String),
}

/// Reads stdin on a thread of its own, sending each line to the loop.
///
/// The stdio framing is one message per line: each line split off at `\n`
/// goes to `inbound` as raw bytes, for `handle_line` to judge, and stdin's
/// end follows the last; a read that fails is said on the operator's stream
/// and ends the reading as the end does. The reading has a thread of its
/// own so that the loop hears the backend's stop, which rides the same
/// channel, between lines.
pub fn read_stdin(inbound: Sender<Inbound>) {
    thread::spawn(move || {
        let stdin = std::io::stdin();
        for line in stdin.lock().split(b'\n') {
            match line {
                Ok(l) => {
                    if inbound.send(Inbound::Line(l)).is_err() {
                        return;
                    }
                }
                Err(e) => {
                    crate::log(format_args!("stdin: {e}"));
                    break;
                }
            }
        }
        let _ = inbound.send(Inbound::Eof);
    });
}

/// The MCP side's state: the backend every tool calls and the catalog
/// `tools/list` and `initialize` answer from.
pub struct Server {
    /// The backend, its one session open.
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

    /// Runs one tool and returns its tool result.
    ///
    /// The result is the tool's answer rendered by `tool_result`'s rule: a
    /// value or the board's verdict as data, any other refusal `isError`;
    /// `fetch` answers a content block of its own (`Server::fetch`).
    ///
    /// # Errors
    ///
    /// The refusal of a call the adapter will not run, `Tool::admit`'s — a
    /// name outside the catalog, or a member an adapter tool's row does not
    /// take — which `respond` answers -32602, the channel `call_params`'
    /// faults take (MCP 2025-06-18, Tools §Error Handling: unknown tools and
    /// invalid arguments are protocol errors).
    fn call(&self, name: &str, args: Map<String, Value>) -> Result<Value, String> {
        let tool = Tool::admit(name, &args)?;
        let answer = match tool {
            Tool::Op(op) => self.backend.session_call("op", json!({"frame": wire_frame(op, args)})),
            Tool::Boards => self.backend.boards(),
            Tool::Health => self.backend.health(),
            Tool::Probe => self.backend.probe(),
            Tool::Search => self.backend.session_call("search", Value::Object(args)),
            Tool::Places => self.backend.session_call("places", Value::Object(args)),
            Tool::Held => self.backend.session_call("held", Value::Object(args)),
            Tool::Resolve => self.backend.session_call("resolve", Value::Object(args)),
            Tool::ChangesSince => self.backend.session_call("changes", Value::Object(args)),
            Tool::SessionInfo => self.backend.session_info(),
            Tool::Fetch => return Ok(self.fetch(args.get("i").unwrap_or(&Value::Null))),
        };
        Ok(tool_result(answer))
    }

    /// Answers `fetch(i)` as a content block.
    ///
    /// The board's bytes at `i` — `i` as the agent gave it, the shell its one
    /// doorkeeper — are sniffed: an image block with the type the magic
    /// names, else an embedded resource blob of `application/octet-stream`
    /// at the URI the backend names for the bytes, base64 within. A file
    /// past the cap is refused in plain words naming it, and a stream cut
    /// short is said so, each `isError`; the shell's refusal goes by
    /// `tool_result`'s rule.
    fn fetch(&self, i: &Value) -> Value {
        let fetched = match self.backend.fetch(i) {
            Ok(fetched) => fetched,
            Err(refusal) => return tool_result(Err(refusal)),
        };
        // The shell fetched, so `i` is an address in its one spelling.
        let i = i.as_str().unwrap_or_default();
        let cap = format!("this adapter's cap of {MAX_FETCH_BYTES} bytes ({} MiB) on one fetch", MAX_FETCH_BYTES / (1024 * 1024));
        match read_whole(&fetched.headers, fetched.body) {
            FetchAnswer::Bytes(bytes) => {
                let data = base64(&bytes);
                let block = match sniff_image(&bytes) {
                    Some(mime) => json!({"type": "image", "data": data, "mimeType": mime}),
                    None => json!({"type": "resource", "resource": {"uri": self.backend.blob_uri(i), "mimeType": "application/octet-stream", "blob": data}}),
                };
                json!({"content": [block], "isError": false})
            }
            FetchAnswer::DeclaredPastTheCap { length } => text_result(format!("the file at {i} is {length} bytes, past {cap}: no byte of it was read; a smaller file is served whole"), true),
            FetchAnswer::RanPastTheCap { read } => {
                text_result(format!("the file at {i} runs past {cap}: its body was read to {read} bytes, one past the cap, and dropped; a smaller file is served whole"), true)
            }
            FetchAnswer::Cut { read, length, error } => text_result(
                format!(
                    "the fetch of {i} ended before the file was whole: {read} of {} bytes came ({error}); the board resets a stream whose requester it can no longer serve — fetch it again",
                    length.map_or("an undeclared number of".to_string(), |n| n.to_string())
                ),
                true,
            ),
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

/// Renders the shell's answer as a tool result: *a refusal as a result*.
///
/// An answer is the result's text, `isError` false; the board's verdict
/// (`Refusal::Board`) is data, its value — the `refused` refusal, the verdict's
/// body verbatim under `body` — the text, `isError` false; every other refusal
/// is its value as the text, `isError` true. `Server::fetch` answers its own
/// two — a file past the cap, a stream cut short — itself.
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

    /// *A refusal as a result*: the board's verdict is data, and so is a value.
    ///
    /// The board's verdict rides with its body verbatim under `body`, the
    /// refusal's members beside it, `isError` false; a halt, the block, the
    /// unreachable board and the shell's own refusals are `isError` true with
    /// the refusal's value as the text (the mutant that marks every refusal
    /// `isError` loses "rejections are data"; the one that marks none loses
    /// `unreachable`).
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
