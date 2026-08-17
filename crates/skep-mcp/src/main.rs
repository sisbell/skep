//! skep-mcp — the adapter between an agent harness (MCP: JSON-RPC 2.0 over
//! stdio, newline-delimited UTF-8, one message per line) and skepd
//! (HTTP/JSON, `skep/docs/wire.md`). One process per agent; a small, boring
//! protocol surface with no semantics of its own:
//!
//! * Tool name → wire op is mechanical: the name IS the frame's `op`, the
//!   arguments ARE the frame (the one mapping is `from_` → `from` on
//!   make_link/emit). Arguments pass through unvalidated — the daemon's
//!   strict parse is the validator, and its verdict comes back as data.
//! * A skepd response document is the tool result, verbatim. `isError` is
//!   ONLY transport failure reaching skepd; an op rejection is a normal
//!   result — a client that cannot read a rejection has been silently
//!   failed.
//! * Sessions are the adapter's apparatus, opened lazily when the daemon
//!   first demands one (`unauthenticated` on a write) and reopened —
//!   resending the frame once — when a restarted daemon has killed the
//!   token. That is the only retry logic anywhere.
//!
//! stdout is protocol-only; all logging goes to stderr. Stdin EOF is the
//! clean exit.

#![forbid(unsafe_code)]

mod http;
mod tools;

use std::io::{BufRead, Write};

use serde_json::{json, Map, Value};

use crate::http::Http;
use crate::tools::{Tools, RENAMES_FROM, SESSION_INFO, WIRE_OPS};

const USAGE: &str = "\
usage: skep-mcp [--tools-file <PATH>]

  --tools-file <PATH>  override the embedded tool catalog (tools.json:
                       names, descriptions, schemas, server instructions)
  --help               this text

environment:
  SKEPD_URL       the daemon's base URL (default http://127.0.0.1:8642)
  SKEP_PRINCIPAL  the principal this adapter binds (required, integer)

Speaks MCP (JSON-RPC 2.0, one message per line) on stdio; the skepd side
is specified in skep/docs/wire.md.";

/// When the client's `initialize` names no protocolVersion (it always
/// should), answer the newest revision this server was written against.
const FALLBACK_PROTOCOL_VERSION: &str = "2025-06-18";

fn main() {
    let mut tools_file: Option<std::path::PathBuf> = None;
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--tools-file" => match args.next() {
                Some(p) => tools_file = Some(p.into()),
                None => die_usage("--tools-file needs a value"),
            },
            "--help" | "-h" => {
                println!("{USAGE}");
                return;
            }
            other => die_usage(&format!("unknown argument '{other}'")),
        }
    }
    // The catalog first: a drifted tools file is a startup error before any
    // environment or network is consulted.
    let text = match &tools_file {
        None => tools::EMBEDDED.to_string(),
        Some(p) => match std::fs::read_to_string(p) {
            Ok(t) => t,
            Err(e) => die(&format!("--tools-file {}: {e}", p.display())),
        },
    };
    let catalog = match tools::load(&text) {
        Ok(c) => c,
        Err(e) => die(&format!("tools file: {e}")),
    };
    let principal = match std::env::var("SKEP_PRINCIPAL") {
        Ok(v) => match v.parse::<u64>() {
            Ok(p) => p,
            Err(_) => die(&format!(
                "SKEP_PRINCIPAL: '{v}' is not a principal (a non-negative integer)"
            )),
        },
        Err(_) => die("SKEP_PRINCIPAL is required (the principal this adapter binds)"),
    };
    let url =
        std::env::var("SKEPD_URL").unwrap_or_else(|_| String::from("http://127.0.0.1:8642"));
    let http = match http::parse_url(&url) {
        Ok(h) => h,
        Err(e) => die(&format!("SKEPD_URL {e}")),
    };
    eprintln!(
        "skep-mcp: skepd at http://{}, principal {principal}, {} tools",
        http.authority(),
        catalog.tools.len()
    );
    Server { skepd: Skepd { http, principal, token: None }, catalog }.run();
}

fn die(msg: &str) -> ! {
    eprintln!("skep-mcp: {msg}");
    std::process::exit(1);
}

fn die_usage(msg: &str) -> ! {
    eprintln!("skep-mcp: {msg}\n\n{USAGE}");
    std::process::exit(2);
}

// ── the skepd side ───────────────────────────────────────────────────────

/// The daemon-side state: one principal, at most one live token. Every
/// method returns `Err(String)` ONLY when skepd could not be reached;
/// whatever document the daemon answered — rejections included — is an
/// `Ok` payload.
struct Skepd {
    http: Http,
    principal: u64,
    token: Option<String>,
}

impl Skepd {
    /// POST one frame to `/op`; hand back the daemon's document verbatim.
    /// On `unauthenticated` — the daemon's own signal that this write needs
    /// a session the adapter doesn't hold (never opened, or the daemon
    /// restarted and the token died with the process) — open a session and
    /// resend once. The rejected attempt executed nothing, so the resend
    /// cannot double-apply; a second `unauthenticated` passes through as
    /// data like any other rejection. This is the only retry anywhere.
    fn op(&mut self, frame: &[u8]) -> Result<Vec<u8>, String> {
        let (_, body) = self.http.request("POST", "/op", self.token.as_deref(), frame)?;
        if !is_unauthenticated(&body) {
            return Ok(body);
        }
        self.open_session()?;
        let (_, body) = self.http.request("POST", "/op", self.token.as_deref(), frame)?;
        Ok(body)
    }

    /// `POST /session` for the configured principal. Local trust: the
    /// principal is named, not proven (wire.md §Identity).
    fn open_session(&mut self) -> Result<(), String> {
        let body = format!("{{\"principal\":{}}}", self.principal);
        let (status, resp) = self.http.request("POST", "/session", None, body.as_bytes())?;
        if status != 200 {
            return Err(format!(
                "session open for principal {} failed ({status}): {}",
                self.principal,
                String::from_utf8_lossy(&resp)
            ));
        }
        let v: Value = serde_json::from_slice(&resp)
            .map_err(|e| format!("session response is not JSON: {e}"))?;
        let token =
            v["session"].as_str().ok_or_else(|| format!("session response has no token: {v}"))?;
        self.token = Some(token.to_string());
        eprintln!("skep-mcp: session opened (principal {})", self.principal);
        Ok(())
    }
}

/// The one response shape the adapter reads instead of forwarding blind:
/// the daemon's "you hold no live session" verdict, the cue to (re)open
/// and resend. Reads never carry it (they are principal-free), so no
/// read/write classification lives in this binary.
fn is_unauthenticated(body: &[u8]) -> bool {
    match serde_json::from_slice::<Value>(body) {
        Ok(v) => v["resp"] == "rejected" && v["code"] == "unauthenticated",
        Err(_) => false,
    }
}

// ── the MCP side ─────────────────────────────────────────────────────────

struct Server {
    skepd: Skepd,
    catalog: Tools,
}

impl Server {
    /// The stdio loop: one JSON-RPC message per line in, one per line out,
    /// nothing else ever on stdout. EOF is the clean exit; a closed stdout
    /// (the harness hung up) ends the process too.
    fn run(&mut self) {
        let stdin = std::io::stdin();
        let mut out = std::io::stdout();
        for line in stdin.lock().lines() {
            let line = match line {
                Ok(l) => l,
                Err(e) => {
                    eprintln!("skep-mcp: stdin: {e}");
                    return;
                }
            };
            if line.trim().is_empty() {
                continue;
            }
            let Some(reply) = self.handle_line(&line) else { continue };
            let mut bytes =
                serde_json::to_vec(&reply).expect("serializing a serde_json::Value cannot fail");
            bytes.push(b'\n');
            if out.write_all(&bytes).and_then(|()| out.flush()).is_err() {
                return;
            }
        }
    }

    /// One inbound line → at most one outbound message. `None` for
    /// notifications (all consumed silently) and for id-less non-requests
    /// there is nothing to answer.
    fn handle_line(&mut self, line: &str) -> Option<Value> {
        let msg: Value = match serde_json::from_str(line) {
            Ok(v) => v,
            Err(e) => return Some(rpc_error(Value::Null, -32700, &format!("parse error: {e}"))),
        };
        let Value::Object(msg) = msg else {
            return Some(rpc_error(Value::Null, -32600, "a message is a JSON object"));
        };
        let id = msg.get("id").cloned();
        let method = msg.get("method").and_then(Value::as_str);
        match (method, id) {
            (None, None) => None,
            (None, Some(id)) => {
                if msg.contains_key("result") || msg.contains_key("error") {
                    // A stray response to a request this server never sent.
                    None
                } else {
                    Some(rpc_error(id, -32600, "a request names a method"))
                }
            }
            // Notifications — `notifications/initialized` and all others.
            (Some(_), None) => None,
            (Some(m), Some(id)) => Some(self.request(m, msg.get("params"), id)),
        }
    }

    /// One request → its response document.
    fn request(&mut self, method: &str, params: Option<&Value>, id: Value) -> Value {
        match method {
            "initialize" => {
                let version = params
                    .and_then(|p| p.get("protocolVersion"))
                    .and_then(Value::as_str)
                    .unwrap_or(FALLBACK_PROTOCOL_VERSION);
                rpc_result(
                    id,
                    json!({
                        "protocolVersion": version,
                        "capabilities": {"tools": {}},
                        "serverInfo": {"name": "skep", "version": env!("CARGO_PKG_VERSION")},
                        "instructions": self.catalog.instructions,
                    }),
                )
            }
            "ping" => rpc_result(id, json!({})),
            "tools/list" => {
                let tools: Vec<Value> = self
                    .catalog
                    .tools
                    .iter()
                    .map(|t| {
                        json!({
                            "name": t.name,
                            "description": t.description,
                            "inputSchema": t.input_schema,
                        })
                    })
                    .collect();
                rpc_result(id, json!({"tools": tools}))
            }
            "tools/call" => match call_params(params) {
                Ok((name, args)) => rpc_result(id, self.call(name, args)),
                Err(e) => rpc_error(id, -32602, &e),
            },
            other => rpc_error(id, -32601, &format!("method '{other}' not supported")),
        }
    }

    /// Run one tool. Every outcome that reached the daemon is a normal
    /// result carrying skepd's document verbatim — rejections are data.
    /// `isError` is reserved for failing to reach skepd (and for a tool
    /// name outside the catalog, which reaches nothing).
    fn call(&mut self, name: &str, mut args: Map<String, Value>) -> Value {
        if name == SESSION_INFO {
            return match self.session_info() {
                Ok(doc) => tool_text(doc.to_string(), false),
                Err(e) => tool_text(e, true),
            };
        }
        if !WIRE_OPS.contains(&name) {
            return tool_text(
                format!("unknown tool '{name}'; tools/list names the available tools"),
                true,
            );
        }
        // The one schema→wire mapping: `from_` rides for the wire's `from`.
        if RENAMES_FROM.contains(&name) {
            if let Some(v) = args.remove("from_") {
                args.insert("from".to_string(), v);
            }
        }
        args.insert("op".to_string(), Value::String(name.to_string()));
        let frame = serde_json::to_vec(&Value::Object(args))
            .expect("serializing a serde_json::Value cannot fail");
        match self.skepd.op(&frame) {
            Ok(body) => tool_text(String::from_utf8_lossy(&body).into_owned(), false),
            Err(e) => tool_text(e, true),
        }
    }

    /// The apparatus tool: this adapter's principal, that principal's
    /// account (`principal_prefix`; null until delegated), and the daemon's
    /// health document.
    fn session_info(&mut self) -> Result<Value, String> {
        let frame =
            format!("{{\"op\":\"principal_prefix\",\"principal\":{}}}", self.skepd.principal);
        let body = self.skepd.op(frame.as_bytes())?;
        let resolved: Value = serde_json::from_slice(&body)
            .map_err(|e| format!("principal_prefix answer is not JSON: {e}"))?;
        let account = resolved.get("addr").cloned().unwrap_or(Value::Null);
        let (status, hbody) = self.skepd.http.request("GET", "/health", None, b"")?;
        if status != 200 {
            return Err(format!(
                "GET /health answered {status}: {}",
                String::from_utf8_lossy(&hbody)
            ));
        }
        let health: Value = serde_json::from_slice(&hbody)
            .map_err(|e| format!("/health answer is not JSON: {e}"))?;
        Ok(json!({
            "account": account,
            "health": health,
            "principal": self.skepd.principal,
        }))
    }
}

/// `tools/call` params: `{"name": …, "arguments": {…}?}`; absent or null
/// arguments are the empty object.
fn call_params(params: Option<&Value>) -> Result<(&str, Map<String, Value>), String> {
    let p = params.ok_or("tools/call requires params")?;
    let name = p
        .get("name")
        .and_then(Value::as_str)
        .ok_or("tools/call params require a string 'name'")?;
    let args = match p.get("arguments") {
        None | Some(Value::Null) => Map::new(),
        Some(Value::Object(m)) => m.clone(),
        Some(_) => return Err("'arguments' must be a JSON object".into()),
    };
    Ok((name, args))
}

fn rpc_result(id: Value, result: Value) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "result": result})
}

fn rpc_error(id: Value, code: i64, message: &str) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "error": {"code": code, "message": message}})
}

/// One text content block; `is_error` marks ONLY transport failure (and
/// the unknown-tool miss).
fn tool_text(text: String, is_error: bool) -> Value {
    json!({"content": [{"type": "text", "text": text}], "isError": is_error})
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The resend trigger is exact: the `unauthenticated` rejection and
    /// nothing else — not other rejections, not acks, not non-JSON.
    #[test]
    fn unauthenticated_detection_is_exact() {
        assert!(is_unauthenticated(
            br#"{"code":"unauthenticated","disposition":"permanent","op":"insert","resp":"rejected"}"#
        ));
        assert!(!is_unauthenticated(br#"{"at":7,"resp":"ack"}"#));
        assert!(!is_unauthenticated(
            br#"{"code":"not_owner","disposition":"permanent","op":"insert","resp":"rejected"}"#
        ));
        assert!(!is_unauthenticated(b"not json"));
    }

    #[test]
    fn call_params_shapes() {
        let p = json!({"name": "fork"});
        let (name, args) = call_params(Some(&p)).expect("argument-less call");
        assert_eq!(name, "fork");
        assert!(args.is_empty());
        assert!(call_params(None).is_err());
        let p = json!({"name": "fork", "arguments": 3});
        assert!(call_params(Some(&p)).is_err());
    }
}
