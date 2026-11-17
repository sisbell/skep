//! The MCP side: the stdio transport, JSON-RPC 2.0 dispatch, and the tools.
//!
//! [`read_stdin`] reads stdin on a thread of its own and hands each line to
//! the loop, [`Server::run`], which answers on stdout, where nothing but the
//! protocol is written, each line owed an answer; the dispatch takes
//! `tools/call` onto the backend's calls.
//!
//! **A refusal as a result**, the crate's rule of that name, is kept here:
//! `tool_result` renders every answer the shell gives by it but a fetched
//! file, the board's verdict as data and any other refusal `isError`;
//! `Server::fetch` adds its own two `isError`, a file past the cap and a
//! stream cut short; `edit_result` renders `replace_text`'s answer, the
//! shell's `text.replace`, `isError` where the shell's answer carries its
//! error member, which it takes off; and `respond` answers -32602 a call
//! `call_params` or `Tool::admit` refuses, which is no tool result at all.
//!
//! `handle_line` answers the same -32602 a request whose line holds a lone
//! surrogate escape, which JSON's grammar writes and no UTF-8 string holds:
//! the line is read with a stand-in at each for whose request it is
//! (`read_mended`), and the request is not run.

use std::collections::HashSet;
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

/// The JSON-RPC 2.0 error codes this server answers (the spec's §5.1).
///
/// Each is the spec's own number: a name for it, never a new one.
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
/// `Server::fetch` for the file it fetched and its own two, and the shell's
/// text edit for its own answer, by its error member (`edit_result`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum IsError {
    /// A normal result: an answer, or the board's verdict as data.
    No,
    /// The shell could not get the board's verdict, or `fetch` declined a file.
    ///
    /// A fetch whose stream was cut short is one too, and a text edit that
    /// left a line held or landed in part.
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
    /// The backend's stop: the plain line the loop says before it exits.
    ///
    /// The moment the backend sent it rides beside it.
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
/// time: how much of the run the loop was busy, and the longest an answered
/// line waited behind the calls read before it.
#[derive(Debug, Default)]
struct Served {
    /// The answers written.
    answers: u64,
    /// The tool results among them, and those of them `isError`.
    tool_results: u64,
    is_error: u64,
    /// The JSON-RPC errors among them.
    rpc_errors: u64,
    /// The loop's time on the lines it answered.
    ///
    /// Each counts from the moment it took the line to its answer written.
    busy: Duration,
    /// The longest an answered line waited.
    ///
    /// A line's wait runs between its read and the loop taking it.
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

/// The MCP side's state: the backend every tool calls, and the catalog.
///
/// `tools/list` and `initialize` answer from the catalog.
#[derive(Debug)]
pub struct Server {
    /// The backend, its session opened before any tool is served.
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
    /// by two members: `method` (a string) and `id` (any JSON value, echoed
    /// as given; `jsonrpc` is not read), and an id with no method by its
    /// `result` or `error` too. A request — a method and an id — gets its
    /// response under that id, `waited` its wait behind the calls read before
    /// it (`Server::respond`). `None` for a blank line, a
    /// notification (a method, no id: all consumed silently), a stray
    /// response (an id, no method, a `result` or an `error`) or an id-less
    /// non-request: there is nothing to answer under. A line is blank where it
    /// is UTF-8 that is empty or whitespace alone as `str::trim` reads it —
    /// Unicode's White_Space, wider than JSON's four whitespace characters, so
    /// a line of U+3000 alone is blank, never the -32700. A line that does not
    /// parse as JSON — bytes that are not UTF-8 included — is the -32700 parse
    /// error and JSON that is no object the -32600, both id null; an id with
    /// no method, no `result` and no `error` is the -32600 under that id.
    ///
    /// A line the parse refuses that holds a lone surrogate escape — a
    /// `\uD800` to `\uDFFF` with no partner, which JSON's grammar writes and
    /// no UTF-8 string holds — is read once more with a stand-in at each
    /// (`read_mended`), and what reads is classified by the same members,
    /// save that its request is not run: it is answered -32602 under its id,
    /// in `LONE_SURROGATE`'s words, so no call is ever made of a stand-in. A
    /// line whose id holds one itself, or which no stand-in makes parse, is
    /// the -32700 above, in the first parse's own words.
    fn handle_line(&self, mut line: Vec<u8>, waited: Duration) -> Option<Value> {
        if std::str::from_utf8(&line).is_ok_and(|s| s.trim().is_empty()) {
            return None;
        }
        // Parsed, then dropped: the call that follows — a board's round trip,
        // a fetch up to its deadline — holds the parse alone, never the line's
        // buffer too, which grew by doubling as it was read.
        let (msg, mended) = match serde_json::from_slice::<Value>(&line) {
            Ok(v) => (v, false),
            Err(e) => match read_mended(&mut line) {
                Some(v) => (v, true),
                None => {
                    let message = format!("parse error: {e}");
                    return Some(rpc_error(Value::Null, ErrorCode::ParseError, &message));
                }
            },
        };
        drop(line);
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
            // A request read with a stand-in is refused, never run.
            (Some(_), Some(id)) if mended => Some(rpc_error(id, ErrorCode::InvalidParams, LONE_SURROGATE)),
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
    /// `fetch` answers a content block of its own (`Server::fetch`), and
    /// `replace_text`, the shell's `text.replace`, its answer less the error
    /// member the shell marks it by (`edit_result`).
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
            Tool::PublicationOpen => self.backend.session_call("publication.open", args),
            Tool::PublicationCount => self.backend.session_call("publication.count", args),
            Tool::PublicationConfirm => self.backend.session_call("publication.confirm", args),
            Tool::PublicationCancel => self.backend.session_call("publication.cancel", args),
            Tool::PublicationStanding => self.backend.session_call("publication.standing", args),
            Tool::ChangesSince => self.backend.session_call("changes", args),
            Tool::SessionInfo => self.backend.session_info(),
            Tool::Fetch => return Ok(self.fetch(args.get("i").unwrap_or(&Value::Null))),
            Tool::ReplaceText => return Ok(edit_result(self.backend.session_call("text.replace", args))),
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

/// What a request whose line holds a lone surrogate escape is answered.
///
/// It is the -32602's message: it names the cause and what to send instead,
/// and quotes nothing of the line.
const LONE_SURROGATE: &str =
    "a string in this request holds a lone surrogate escape (\\uD800 to \\uDFFF with no partner), which UTF-8 text cannot carry: the request was not run; send the pair whole or leave the half out";

/// Reads a line the strict parse refused, a stand-in at each lone surrogate.
///
/// JSON's grammar lets a string escape one half of a surrogate pair alone
/// (RFC 8259 §8.2), and an encoder writes a string that holds one so; no
/// UTF-8 string holds it, and serde_json refuses the line, by more than one
/// error's words, so any line it refuses is read here. Each such escape
/// (`lone_surrogates`) is overwritten in place by another character's, six
/// bytes for six, and the line parsed again. `Some` is the message as it
/// reads with U+FFFD at each: `handle_line` learns from it whose request the
/// line is and runs nothing of it, since no stand-in is a character its
/// sender wrote.
///
/// `None` where the line holds no such escape, where it does not parse with
/// them stood in for, and where its `id` holds one, since the id an answer
/// would then carry is none its sender sent. An id holds one where it reads
/// otherwise under a second stand-in, a private-use character the id as
/// first read does not hold, so a U+FFFD its sender wrote there is told from
/// a stand-in; an id that holds every such character is not read.
fn read_mended(line: &mut [u8]) -> Option<Value> {
    let lone = lone_surrogates(line);
    if lone.is_empty() {
        return None;
    }
    let mut read_as = |stand_in: char| {
        let hex = format!("{:04X}", u32::from(stand_in));
        for &at in &lone {
            line.get_mut(at + 2..at + 6)?.copy_from_slice(hex.as_bytes());
        }
        serde_json::from_slice::<Value>(line).ok()
    };
    let message = read_as(char::REPLACEMENT_CHARACTER)?;
    let Some(id) = message.get("id") else { return Some(message) };
    let held: HashSet<char> = id.to_string().chars().collect();
    let absent = ('\u{E000}'..='\u{F8FF}').find(|private| !held.contains(private))?;
    (read_as(absent)?.get("id") == Some(id)).then_some(message)
}

/// Returns the offset of each lone surrogate escape's backslash in `line`.
///
/// A surrogate escape is a `\uXXXX` of D800 to DFFF, its hex digits of either
/// case. A high one (D800 to DBFF) with a low one (DC00 to DFFF) right behind
/// it spells one character; any other is lone, which serde_json's strict
/// parse refuses a string for. Escapes are read left to right, each backslash
/// with what it escapes, so an escaped backslash before a `u` opens no
/// escape. No string state is kept: a backslash outside a string leaves a
/// line no stand-in makes parse. Any bytes are scanned, and none panics
/// (SP-19).
fn lone_surrogates(line: &[u8]) -> Vec<usize> {
    let (mut at, mut lone) = (0, Vec::new());
    while let Some(&byte) = line.get(at) {
        if byte != b'\\' {
            at += 1;
            continue;
        }
        at += match (unit_at(line, at), unit_at(line, at + 6)) {
            // A high surrogate and the low one right behind it: a character.
            (Some(0xD800..=0xDBFF), Some(0xDC00..=0xDFFF)) => 12,
            (Some(0xD800..=0xDFFF), _) => {
                lone.push(at);
                6
            }
            (Some(_), _) => 6,
            // Any other escape, an escaped backslash among them.
            (None, _) => 2,
        };
    }
    lone
}

/// Returns the code unit of the `\uXXXX` escape at `at`, where one stands.
fn unit_at(line: &[u8], at: usize) -> Option<u16> {
    let [b'\\', b'u', hex @ ..] = line.get(at..at + 6)? else { return None };
    hex.iter().try_fold(0, |unit, &digit| Some((unit << 4) | u16::try_from(char::from(digit).to_digit(16)?).ok()?))
}

/// Returns a `tools/call`'s tool name and arguments, read off its params.
///
/// The params are `{"name": …, "arguments": {…}?}`; absent or null
/// arguments are the empty object. The params are the message's own, taken
/// by value: the arguments move out of them, never copied, and a wire op's on
/// into its frame.
///
/// # Errors
///
/// The refusal's text, which `respond` answers -32602: no params, no string
/// `name`, or `arguments` that are neither absent, null nor an object.
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
                // The board's verdict on the call: data.
                Refusal::Board(_) => IsError::No,
                // The shell could not get the board's verdict.
                Refusal::Halt { .. } | Refusal::Blocked(_) | Refusal::Unreachable(_) | Refusal::Shell { .. } => IsError::Yes,
            };
            text_result(refusal.to_value().to_string(), is_error)
        }
    }
}

/// The member the shell's text edit marks an error answer by, `true`.
///
/// skep-shell's `text.replace` sets it on every answer that is an error —
/// a write the shell could not get to the board, a read it does not read, a
/// line left held, an edit landed in part — and declares it in its shapes
/// (`TextRefused`, `TextHeld`, `TextPartial`), which the suite holds this
/// spelling to.
pub(crate) const EDIT_ERROR: &str = "error";

/// Renders `replace_text`'s answer, the shell's `text.replace`, as a tool
/// result.
///
/// The edit's answer is its text with the shell's error member
/// (`EDIT_ERROR`) taken off, `isError` where the member stood: a refusal the
/// edit or the board decided is data, and one where the shell could not get
/// the board's verdict on a write, a line left held and an edit that landed
/// in part are `isError`. A refusal of the call goes by `tool_result`'s
/// rule, as every tool's does.
fn edit_result(answer: Result<Value, Refusal>) -> Value {
    match answer {
        Ok(Value::Object(mut answer)) => {
            let is_error = if answer.remove(EDIT_ERROR) == Some(Value::Bool(true)) { IsError::Yes } else { IsError::No };
            text_result(Value::Object(answer).to_string(), is_error)
        }
        other => tool_result(other),
    }
}

#[cfg(test)]
mod tests;
