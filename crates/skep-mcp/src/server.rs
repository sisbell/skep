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
use std::process::ExitCode;
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

/// Whether a tool result is MCP's `isError`.
///
/// *A refusal as a result* decides it for the shell's answers (`tool_result`),
/// and `Server::fetch` for its own two.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum IsError {
    /// A normal result: an answer, or the board's verdict as data.
    No,
    /// The shell could not get the board's verdict, or `fetch` declined a file.
    Yes,
}

/// What reaches the loop: a stdin line, stdin's end, or the backend's stop.
///
/// All three ride the one channel `main` makes; the stop is `OnStop`'s line.
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
#[derive(Debug)]
pub struct Server {
    /// The backend, its one session open.
    pub backend: Backend,
    /// The loaded catalog, its commons sentence appended where one is set.
    pub catalog: Catalog,
}

impl Server {
    /// Serves the loop to its end, then runs the backend's clean stop.
    ///
    /// One JSON-RPC message per line in, one per line out: nothing else is
    /// ever written on stdout, and the calls are served one at a time in
    /// arrival order. Each line goes to `handle_line` as raw bytes: what a
    /// line is, its encoding included, is that method's call. The loop ends
    /// at stdin's end and at a closed stdout (the harness hung up), each a
    /// success, and at the backend's stop, its line said first, exit 1; the
    /// clean stop (`Backend::shutdown`) runs after any of the three, and the
    /// exit code is returned for `main` to exit with.
    pub fn run(self, inbox: &Receiver<Inbound>) -> ExitCode {
        let mut out = std::io::stdout();
        let mut code = ExitCode::SUCCESS;
        for message in inbox {
            match message {
                Inbound::Line(line) => {
                    let Some(reply) = self.handle_line(&line) else { continue };
                    let mut bytes = serde_json::to_vec(&reply).expect("serializing a serde_json::Value cannot fail");
                    bytes.push(b'\n');
                    if out.write_all(&bytes).and_then(|()| out.flush()).is_err() {
                        break;
                    }
                }
                Inbound::Stop(line) => {
                    crate::log(format_args!("stopped: {line}"));
                    code = ExitCode::from(1);
                    break;
                }
                Inbound::Eof => break,
            }
        }
        self.backend.shutdown();
        code
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
                let outcome = call_params(params).and_then(|(name, args)| self.call(&name, args));
                match outcome {
                    Ok(result) => rpc_result(id, result),
                    Err(message) => rpc_error(id, ErrorCode::InvalidParams, &message),
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
    /// name outside the catalog, a wire op's arguments of the shell's `/op-at`
    /// shape, or a member an adapter tool's row or its `opts` does not take —
    /// which `respond` answers -32602, the channel `call_params`' faults take
    /// (MCP 2025-06-18, Tools §Error Handling: unknown tools and invalid
    /// arguments are protocol errors).
    fn call(&self, name: &str, args: Map<String, Value>) -> Result<Value, String> {
        let tool = Tool::admit(name, &args)?;
        let answer = match tool {
            Tool::Op(op) => self.backend.session_call("op", Map::from_iter([(String::from("frame"), wire_frame(op, args))])),
            Tool::Boards => self.backend.boards(),
            Tool::Health => self.backend.health(),
            Tool::Probe => self.backend.probe(),
            Tool::Search => self.backend.session_call("search", args),
            Tool::Places => self.backend.session_call("places", args),
            Tool::Held => self.backend.session_call("held", args),
            Tool::Resolve => self.backend.session_call("resolve", args),
            Tool::ChangesSince => self.backend.session_call("changes", args),
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
    ///
    /// # Panics
    ///
    /// Where the shell fetched an `i` that is no string, which its `fetch`
    /// row refuses.
    fn fetch(&self, i: &Value) -> Value {
        let fetched = match self.backend.fetch(i) {
            Ok(fetched) => fetched,
            Err(refusal) => return tool_result(Err(refusal)),
        };
        // The shell fetched, so `i` is an address in its one spelling: its
        // `fetch` row refuses any other `malformed_args`.
        let i = i.as_str().expect("the shell's `fetch` row admits a string `i` alone");
        let cap = format!("this adapter's cap of {MAX_FETCH_BYTES} bytes ({} MiB) on one fetch", MAX_FETCH_BYTES / (1024 * 1024));
        match read_whole(&fetched.headers, fetched.body) {
            FetchAnswer::Whole(bytes) => {
                let data = Value::String(base64(&bytes));
                let block = match sniff_image(&bytes) {
                    Some(mime) => Value::from_iter([("type", Value::from("image")), ("data", data), ("mimeType", Value::from(mime))]),
                    None => {
                        let resource = Value::from_iter([("uri", Value::String(self.backend.blob_uri(i))), ("mimeType", Value::from("application/octet-stream")), ("blob", data)]);
                        Value::from_iter([("type", Value::from("resource")), ("resource", resource)])
                    }
                };
                block_result(block, IsError::No)
            }
            FetchAnswer::DeclaredPastTheCap { length } => text_result(format!("the file at {i} is {length} bytes, past {cap}: no byte of it was read; a smaller file is served whole"), IsError::Yes),
            FetchAnswer::RanPastTheCap { read } => {
                text_result(format!("the file at {i} runs past {cap}: its body was read to {read} bytes, one past the cap, and dropped; a smaller file is served whole"), IsError::Yes)
            }
            FetchAnswer::Cut { read, length, error } => text_result(
                format!(
                    "the fetch of {i} ended before the file was whole: {read} of {} bytes came ({error}); the board resets a stream whose requester it can no longer serve — fetch it again",
                    length.map_or("an undeclared number of".to_string(), |n| n.to_string())
                ),
                IsError::Yes,
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

/// Returns a JSON-RPC response carrying `result` under `id`, both moved in.
///
/// Every response, tool result and block here is built by move, and `json!`
/// takes only what is borrowed — the catalog's members, an error's message:
/// it serializes what it is handed by reference, so a value it wrapped would
/// be copied whole, a fetched file's base64 among them.
fn rpc_result(id: Value, result: Value) -> Value {
    Value::from_iter([("jsonrpc", Value::from("2.0")), ("id", id), ("result", result)])
}

/// Returns a JSON-RPC error response under `id`, `id` moved in.
fn rpc_error(id: Value, code: ErrorCode, message: &str) -> Value {
    Value::from_iter([("jsonrpc", Value::from("2.0")), ("id", id), ("error", json!({"code": code as i64, "message": message}))])
}

/// Returns a tool result of one content block, `isError` as `is_error` says.
fn block_result(block: Value, is_error: IsError) -> Value {
    Value::from_iter([("content", Value::Array(vec![block])), ("isError", Value::Bool(is_error == IsError::Yes))])
}

/// Returns a tool result of one text content block.
fn text_result(text: String, is_error: IsError) -> Value {
    block_result(Value::from_iter([("type", Value::from("text")), ("text", Value::String(text))]), is_error)
}

/// Renders the shell's answer as a tool result: *a refusal as a result*.
///
/// An answer is the result's text, `isError` false; the board's verdict
/// (`Refusal::Board`) is data, its value — the `refused` refusal, the verdict's
/// body verbatim under `body` — the text, `isError` false; every other refusal
/// is its value as the text, `isError` true. Each of the refusal's five kinds
/// is named here, so a kind skep-shell adds stops this crate's build until the
/// rule places it. `Server::fetch` answers its own two — a file past the cap,
/// a stream cut short — itself.
fn tool_result(answer: Result<Value, Refusal>) -> Value {
    match answer {
        Ok(value) => text_result(value.to_string(), IsError::No),
        Err(refusal) => {
            let is_error = match refusal {
                // The board's verdict on the frame: data.
                Refusal::Board(_) => IsError::No,
                // The shell could not get the board's verdict.
                Refusal::Halt { .. } | Refusal::Blocked(_) | Refusal::Unreachable(_) | Refusal::Shell { .. } => IsError::Yes,
            };
            text_result(refusal.to_value().to_string(), is_error)
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

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

    /// *A refusal as a result*: an answer and the board's verdict are data.
    ///
    /// An answer is the text whole; the board's verdict rides as the refusal's
    /// whole value — its body verbatim under `body`, every member skep-shell
    /// declares for it beside it and no other — `isError` false; a halt, the
    /// block, the unreachable board and the shell's own refusals are `isError`
    /// true with the refusal's value as the text (the mutant that marks every
    /// refusal `isError` loses "rejections are data"; the one that marks none
    /// loses `unreachable`).
    #[test]
    fn an_answer_and_the_boards_verdict_are_data_and_every_other_refusal_is_an_error() {
        let read = |v: &Value| -> (bool, Value) {
            assert_eq!(v["content"].as_array().map(Vec::len), Some(1));
            let text = v["content"][0]["text"].as_str().expect("a text block");
            (v["isError"].as_bool().expect("isError"), serde_json::from_str(text).expect("JSON text"))
        };
        let answer = json!({"resp": "ack_addr", "addr": "1.0.1.0.2", "at": 7});
        let (is_error, text) = read(&tool_result(Ok(answer.clone())));
        assert!(!is_error);
        assert_eq!(text, answer, "the shell's answer, whole");
        let verdict = json!({"code": "doc_not_registered", "disposition": "reorder", "op": "retrieve_v", "resp": "rejected"});
        let detail = Some("the frame names no registered document".to_string());
        let refused = Refusal::Board(Refused { status: 200, code: "doc_not_registered".into(), detail, op: Some("retrieve_v".into()), body: verdict.clone() });
        let expected = refused.to_value();
        let (is_error, text) = read(&tool_result(Err(refused)));
        assert!(!is_error, "the board's verdict is data");
        assert_eq!((text["kind"].as_str(), text["name"].as_str(), text["status"].as_u64()), (Some("refused"), Some("doc_not_registered"), Some(200)));
        assert_eq!(text["body"], verdict, "the verdict's body verbatim");
        assert_eq!(text, expected, "the board's verdict rides as the refusal's whole value");
        let declared: BTreeSet<&str> = skep_shell::shapes::shape("RefusedByBoard").expect("skep-shell declares the board's refusal").fields.iter().map(|field| field.name).collect();
        let members: BTreeSet<&str> = text.as_object().expect("the refusal is an object").keys().map(String::as_str).collect();
        assert_eq!(members, declared, "every member skep-shell declares, and no other");
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

    /// The builders move what they wrap into the shapes the two specs name.
    ///
    /// Each equals what `json!` builds from the same members: a JSON-RPC
    /// response and error (JSON-RPC 2.0 §5), and a tool result of one text
    /// block, `isError` as given (MCP 2025-06-18, Tools).
    #[test]
    fn the_builders_move_what_they_wrap_into_the_shapes_the_specs_name() {
        assert_eq!(rpc_result(json!(7), json!({"tools": []})), json!({"jsonrpc": "2.0", "id": 7, "result": {"tools": []}}));
        assert_eq!(rpc_error(json!("x"), ErrorCode::InvalidParams, "no"), json!({"jsonrpc": "2.0", "id": "x", "error": {"code": -32602, "message": "no"}}));
        assert_eq!(text_result("t".into(), IsError::Yes), json!({"content": [{"type": "text", "text": "t"}], "isError": true}));
        assert_eq!(text_result("t".into(), IsError::No), json!({"content": [{"type": "text", "text": "t"}], "isError": false}));
    }
}
