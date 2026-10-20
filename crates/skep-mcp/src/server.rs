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
use std::time::{Duration, Instant};

use serde_json::{json, Map, Value};
use skep_shell::Refusal;

use crate::media::{base64, read_whole, sniff_image, FetchAnswer, MAX_FETCH_BYTES};
use crate::shell::Backend;
use crate::tools::{wire_frame, Catalog, Tool};

/// The revision `initialize` answers where the client names none.
///
/// It is the newest revision this server was written against; a client that
/// names one, as it always should, is answered that one (`Server::respond`).
const FALLBACK_PROTOCOL_VERSION: &str = "2025-06-18";

/// The longest a call takes, read to answer, before the log says it.
///
/// It is one dial's read bound (skep-client's `IO_TIMEOUT`), longer than any
/// exchange with a board that answers. The calls are served one at a time, so
/// a call's time is its wait behind the calls read before it and its own hold
/// of the loop, and a harness's timeout counts both, from the moment it sent
/// the request: one that timed the call out holds no answer to join its own
/// record to, and the line is that join (`slow_call_line`). A request of
/// another method takes no time of its own: one that waited this long was
/// taken when the last call read before it ended, so that call's wait and
/// hold together were at least as long, and its line says them.
const SLOW_CALL: Duration = skep_client::dial::IO_TIMEOUT;

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
/// A line and the stop carry the moment they were sent, from which the loop
/// counts their wait behind the calls it served first.
#[derive(Debug)]
pub enum Inbound {
    /// One line of stdin, as raw bytes, and the moment its reader read it.
    Line(Vec<u8>, Instant),
    /// Stdin's end, or a read of it that failed.
    Eof,
    /// The backend's stop: the plain line the loop says before it exits, and
    /// the moment the backend sent it.
    Stop(String, Instant),
}

/// Reads stdin on a thread of its own, sending each line to the loop.
///
/// The stdio framing is one message per line: each line split off at `\n`
/// goes to `inbound` as raw bytes, stamped with the moment it was read, for
/// `handle_line` to judge, and stdin's end follows the last; a read that
/// fails is said in the log and ends the reading as the end does. The
/// reading has a thread of its own, `skep-mcp-stdin`, so that the loop hears
/// the backend's stop, which rides the same channel, between lines.
///
/// # Panics
///
/// Where the OS refuses the thread, as `thread::spawn` panics.
pub fn read_stdin(inbound: Sender<Inbound>) {
    let reader = move || {
        let stdin = std::io::stdin();
        for line in stdin.lock().split(b'\n') {
            match line {
                Ok(l) => {
                    if inbound.send(Inbound::Line(l, Instant::now())).is_err() {
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
    };
    thread::Builder::new().name("skep-mcp-stdin".into()).spawn(reader).expect("the OS starts the adapter's stdin thread");
}

/// What the loop answered, counted for the clean stop's line.
///
/// Each answer written on stdout is counted once it is written: a tool
/// result, `isError` or not, a JSON-RPC error, or any other method's result.
/// Beside the counts it keeps the two figures of the loop's one call at a
/// time: how much of the run the loop was busy, and the longest a line
/// waited behind the calls read before it.
#[derive(Debug, Default)]
struct Served {
    /// The answers written.
    answers: u64,
    /// The tool results among them, and those of them `isError`.
    tool_results: u64,
    is_error: u64,
    /// The JSON-RPC errors among them.
    rpc_errors: u64,
    /// The loop's time on the lines it answered, each from the moment it took
    /// the line to its answer written.
    busy: Duration,
    /// The longest a line waited between its read and the loop taking it.
    longest_wait: Duration,
}

impl Served {
    /// Counts one answer written.
    ///
    /// Its line waited `waited` before the loop took it, and the loop spent
    /// `busy` on it.
    fn count(&mut self, reply: &Value, waited: Duration, busy: Duration) {
        self.answers += 1;
        if let Some(is_error) = reply["result"]["isError"].as_bool() {
            self.tool_results += 1;
            self.is_error += u64::from(is_error);
        }
        self.rpc_errors += u64::from(reply.get("error").is_some());
        self.busy += busy;
        self.longest_wait = self.longest_wait.max(waited);
    }

    /// Returns the figures as the clean stop says them, over `serving`.
    fn said(&self, serving: Duration) -> String {
        let Served { answers, tool_results, is_error, rpc_errors, busy, longest_wait } = self;
        format!(
            "{answers} answers written in {:.1} s of serving, the loop busy {:.1} s of it: {tool_results} tool results, {is_error} of them isError, and {rpc_errors} JSON-RPC errors; no request waited longer than {:.1} s behind earlier calls",
            serving.as_secs_f64(),
            busy.as_secs_f64(),
            longest_wait.as_secs_f64()
        )
    }
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
    /// arrival order. Each line goes to `handle_line` as raw bytes — what a
    /// line is, its encoding included, is that method's call — with its wait
    /// behind the calls read before it, from its read to the loop's taking it.
    /// The loop ends at stdin's end and at a closed stdout (the harness hung
    /// up), each a success, and at the backend's stop, exit 1, said with its
    /// own wait behind the calls before it; each end is said in the log, its
    /// cause before the stop's line. The clean stop (`Backend::shutdown`) runs
    /// after any of the three, its line carrying what the loop served
    /// (`Served`) — how busy the loop was, and the longest a request waited —
    /// and the exit code is returned for `main` to exit with.
    pub fn run(self, inbox: &Receiver<Inbound>) -> ExitCode {
        let mut out = std::io::stdout();
        let mut code = ExitCode::SUCCESS;
        let (serving, mut served) = (Instant::now(), Served::default());
        for message in inbox {
            match message {
                Inbound::Line(line, read_at) => {
                    let started = Instant::now();
                    let waited = started.saturating_duration_since(read_at);
                    let Some(reply) = self.handle_line(line, waited) else { continue };
                    let mut bytes = serde_json::to_vec(&reply).expect("serializing a serde_json::Value cannot fail");
                    bytes.push(b'\n');
                    if let Err(e) = out.write_all(&bytes).and_then(|()| out.flush()) {
                        crate::log(format_args!("stdout: {e}: the harness reads no more answers"));
                        break;
                    }
                    served.count(&reply, waited, started.elapsed());
                }
                Inbound::Stop(line, sent_at) => {
                    crate::log(format_args!("stopped: {line}; the stop waited {:.1} s behind earlier calls", sent_at.elapsed().as_secs_f64()));
                    code = ExitCode::from(1);
                    break;
                }
                Inbound::Eof => {
                    crate::log("stdin's end: no request follows");
                    break;
                }
            }
        }
        self.backend.shutdown(&served.said(serving.elapsed()));
        code
    }

    /// Returns the one message, if any, that answers one inbound line.
    ///
    /// The line, its raw bytes owned and dropped once parsed, is classified
    /// by two members alone: `method` (a string) and `id` (any JSON value,
    /// echoed as given; `jsonrpc` is not read). A request — a method and an
    /// id — gets its response under that id, `waited` its wait behind the
    /// calls read before it (`Server::respond`). `None` for a blank line, a
    /// notification (a method, no id: all consumed silently), a stray
    /// response (an id, no method, a `result` or an `error`) or an id-less
    /// non-request: there is nothing to answer under. A line is blank where it
    /// is UTF-8 that is empty or whitespace alone as `str::trim` reads it —
    /// Unicode's White_Space, wider than JSON's four whitespace characters, so
    /// a line of U+3000 alone is blank, never the -32700. A line that does not
    /// parse as JSON — bytes that are not UTF-8 included — is the -32700 parse
    /// error and JSON that is no object the -32600, both id null; an id with
    /// no method, no `result` and no `error` is the -32600 under that id.
    fn handle_line(&self, line: Vec<u8>, waited: Duration) -> Option<Value> {
        if std::str::from_utf8(&line).is_ok_and(|s| s.trim().is_empty()) {
            return None;
        }
        // Parsed, then dropped: the call that follows — a board's round trip,
        // a fetch up to its deadline — holds the parse alone, never the line's
        // buffer too, which grew by doubling as it was read.
        let parsed = serde_json::from_slice::<Value>(&line);
        drop(line);
        let msg: Value = match parsed {
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
            (Some(m), Some(id)) => Some(self.respond(m, params, id, waited)),
        }
    }

    /// Returns one request's JSON-RPC response.
    ///
    /// `initialize` answers the `protocolVersion` the client named, as it
    /// named it — an echo of any revision, where MCP 2025-06-18's version
    /// negotiation has a server answer a revision it supports, and this
    /// adapter names no such set — or `FALLBACK_PROTOCOL_VERSION` where it
    /// named none, beside the server's name and version, the catalog's
    /// instructions and the tools capability. `ping` answers `{}`,
    /// `tools/list` the catalog's tools, `tools/call` its tool result or
    /// -32602 (`Server::call`) — a call whose wait behind the calls read
    /// before it, `waited`, and its own hold of the loop together reach
    /// `SLOW_CALL` said in the log (`slow_call_line`) — and any other method
    /// -32601.
    fn respond(&self, method: &str, params: Option<Value>, id: Value, waited: Duration) -> Value {
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
            "tools/call" => match call_params(params) {
                Err(message) => rpc_error(id, ErrorCode::InvalidParams, &message),
                Ok((name, args)) => {
                    let started = Instant::now();
                    let outcome = self.call(&name, args);
                    let held = started.elapsed();
                    if waited + held >= SLOW_CALL {
                        crate::log(slow_call_line(&name, &id, waited, held, &outcome));
                    }
                    match outcome {
                        Ok(result) => rpc_result(id, result),
                        Err(message) => rpc_error(id, ErrorCode::InvalidParams, &message),
                    }
                }
            },
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
    /// The file of the picture whose cell sits at `i` — `i` as the agent gave
    /// it, the shell its one doorkeeper — is sniffed: an image block with the
    /// type the magic names, else an embedded resource blob of
    /// `application/octet-stream` at the URI the backend names for the file,
    /// base64 within. A file past the cap is refused in plain words naming
    /// it, and a stream cut short is said so, each `isError`; the shell's
    /// refusal goes by `tool_result`'s rule.
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
            FetchAnswer::DeclaredPastTheCap { length } => {
                text_result(format!("the file the cell at {i} names is {length} bytes, past {cap}: no byte of it was read; a smaller file is served whole"), IsError::Yes)
            }
            FetchAnswer::RanPastTheCap { read } => {
                text_result(format!("the file the cell at {i} names runs past {cap}: its body was read to {read} bytes, one past the cap, and dropped; a smaller file is served whole"), IsError::Yes)
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

/// Returns the line a slow call says: its wait, its hold, and its answer.
///
/// It names the tool, the request by its id — the harness's own record of the
/// call joins it there, the id as JSON spells it, its first 64 characters —
/// how long the request waited behind the calls read before it, the queue
/// the one call at a time makes, which a harness's timeout counts from the
/// moment it sent the request; how long the call then held the loop; and how
/// it was answered: a tool result, one `isError`, or the -32602 of a call the
/// adapter will not run. No argument rides it.
fn slow_call_line(name: &str, id: &Value, waited: Duration, held: Duration, outcome: &Result<Value, String>) -> String {
    let id = id.to_string();
    let id = match id.char_indices().nth(64) {
        Some((cut, _)) => format!("{}…", &id[..cut]),
        None => id,
    };
    let answered = match outcome {
        Ok(result) if result["isError"] == true => "answered isError",
        Ok(_) => "answered",
        Err(_) => "refused -32602",
    };
    format!("the `{name}` call of request {id} waited {:.1} s behind earlier calls and held the loop {:.1} s: {answered}", waited.as_secs_f64(), held.as_secs_f64())
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
        let (is_error, value) = read(&tool_result(Ok(answer.clone())));
        assert!(!is_error);
        assert_eq!(value, answer, "the shell's answer, whole");
        let verdict = json!({"code": "doc_not_registered", "disposition": "reorder", "op": "retrieve_v", "resp": "rejected"});
        let detail = Some("the frame names no registered document".to_string());
        let refused = Refusal::Board(Refused { status: 200, code: "doc_not_registered".into(), detail, op: Some("retrieve_v".into()), body: verdict.clone() });
        let expected = refused.to_value();
        let (is_error, value) = read(&tool_result(Err(refused)));
        assert!(!is_error, "the board's verdict is data");
        assert_eq!((value["kind"].as_str(), value["name"].as_str(), value["status"].as_u64()), (Some("refused"), Some("doc_not_registered"), Some(200)));
        assert_eq!(value["body"], verdict, "the verdict's body verbatim");
        assert_eq!(value, expected, "the board's verdict rides as the refusal's whole value");
        let declared: BTreeSet<&str> = skep_shell::shapes::shape("RefusedByBoard").expect("skep-shell declares the board's refusal").fields.iter().map(|field| field.name).collect();
        let members: BTreeSet<&str> = value.as_object().expect("the refusal is an object").keys().map(String::as_str).collect();
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
            let (is_error, value) = read(&tool_result(Err(other)));
            assert!(is_error, "{expected}");
            assert_eq!(value, expected, "the refusal's value is the text");
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

    /// A slow call is said by its tool, request, wait, hold and answer.
    ///
    /// The line names the tool, the request's id as given — a long one cut at
    /// 64 characters — how long the request waited behind earlier calls, how
    /// long the call held the loop, and the answer: a tool result, one
    /// `isError`, or the -32602; no argument rides it. A call that waited and
    /// was quick is said with its wait as surely as one that held the loop.
    #[test]
    fn a_slow_call_is_said_by_its_tool_request_wait_hold_and_answer() {
        let held = Duration::from_millis(10_240);
        let answered = slow_call_line("fetch", &json!(7), Duration::ZERO, held, &Ok(text_result("x".into(), IsError::No)));
        assert_eq!(answered, "the `fetch` call of request 7 waited 0.0 s behind earlier calls and held the loop 10.2 s: answered");
        let is_error = slow_call_line("create_new_document", &json!("call-1"), Duration::ZERO, held, &Ok(text_result("x".into(), IsError::Yes)));
        assert_eq!(is_error, "the `create_new_document` call of request \"call-1\" waited 0.0 s behind earlier calls and held the loop 10.2 s: answered isError");
        let long = json!("x".repeat(100));
        let refused = slow_call_line("search", &long, Duration::ZERO, held, &Err("search's opts take 'limit', 'offset'; got 'reindex'".into()));
        assert_eq!(refused, format!("the `search` call of request \"{}… waited 0.0 s behind earlier calls and held the loop 10.2 s: refused -32602", "x".repeat(63)));
        let queued = slow_call_line("boards", &json!(9), Duration::from_millis(58_300), Duration::from_micros(40), &Ok(text_result("x".into(), IsError::No)));
        assert_eq!(queued, "the `boards` call of request 9 waited 58.3 s behind earlier calls and held the loop 0.0 s: answered");
    }

    /// What the loop served is counted by the answers written.
    ///
    /// Every answer counts; a tool result counts as one, `isError` or not, and
    /// a JSON-RPC error as one; the loop's time on each adds up as its busy
    /// time, and the longest a line waited before the loop took it is kept,
    /// whichever line it was; the figures are said over the time served.
    #[test]
    fn what_the_loop_served_is_counted_by_the_answers_written() {
        let mut served = Served::default();
        let replies = [
            rpc_result(json!(1), json!({"protocolVersion": "2025-06-18"})),
            rpc_result(json!(2), text_result("x".into(), IsError::No)),
            rpc_result(json!(3), text_result("x".into(), IsError::Yes)),
            rpc_error(json!(4), ErrorCode::InvalidParams, "no"),
            rpc_error(Value::Null, ErrorCode::ParseError, "parse error"),
        ];
        // Waits and times that neither rise nor fall, so the longest wait is
        // neither the last nor a sum, and the busy time no single line's.
        let (waits, busy) = ([100, 400, 0, 300, 200], [300, 200, 500, 100, 400]);
        for ((reply, waited), busy) in replies.iter().zip(waits).zip(busy) {
            served.count(reply, Duration::from_millis(waited), Duration::from_millis(busy));
        }
        assert_eq!(
            served.said(Duration::from_millis(2_000)),
            "5 answers written in 2.0 s of serving, the loop busy 1.5 s of it: 2 tool results, 1 of them isError, and 2 JSON-RPC errors; no request waited longer than 0.4 s behind earlier calls"
        );
    }
}
