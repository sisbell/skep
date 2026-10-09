//! The MCP side: the stdio loop, JSON-RPC 2.0 dispatch, and `tools/call`
//! onto the daemon's ops; stdout carries protocol only.

use std::io::{BufRead, Write};

use serde_json::{json, Map, Value};

use crate::daemon::Skepd;
use crate::tools::{wire_frame, Catalog, SESSION_INFO};

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

#[derive(Debug)]
pub struct Server {
    pub skepd: Skepd,
    pub catalog: Catalog,
}

impl Server {
    /// The stdio loop: one JSON-RPC message per line in, one per line out,
    /// nothing else ever on stdout. EOF is the clean exit; a failed read, or
    /// a closed stdout (the harness hung up), ends the process too. Each
    /// line goes to `handle_line` as raw bytes: what a line is, its encoding
    /// included, is that method's call.
    pub fn run(&mut self) {
        let stdin = std::io::stdin();
        let mut out = std::io::stdout();
        for line in stdin.lock().split(b'\n') {
            let line = match line {
                Ok(l) => l,
                Err(e) => {
                    eprintln!("skep-mcp: stdin: {e}");
                    return;
                }
            };
            let Some(reply) = self.handle_line(&line) else { continue };
            let mut bytes =
                serde_json::to_vec(&reply).expect("serializing a serde_json::Value cannot fail");
            bytes.push(b'\n');
            if out.write_all(&bytes).and_then(|()| out.flush()).is_err() {
                return;
            }
        }
    }

    /// One inbound line, as raw bytes → at most one outbound message.
    /// `None` for a blank line, a notification (all consumed silently), a
    /// stray response or an id-less non-request: there is nothing to
    /// answer. A line that does not parse as JSON — bytes that are not
    /// UTF-8 included — is the -32700 parse error, id null.
    fn handle_line(&mut self, line: &[u8]) -> Option<Value> {
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
            return Some(rpc_error(
                Value::Null,
                ErrorCode::InvalidRequest,
                "a message is a JSON object",
            ));
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
            (Some(m), Some(id)) => Some(self.request(m, params, id)),
        }
    }

    /// One request → its JSON-RPC response.
    fn request(&mut self, method: &str, params: Option<Value>, id: Value) -> Value {
        match method {
            "initialize" => {
                let version = params
                    .as_ref()
                    .and_then(|p| p.get("protocolVersion"))
                    .and_then(Value::as_str)
                    .unwrap_or(FALLBACK_PROTOCOL_VERSION);
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
                Ok((name, args)) => rpc_result(id, self.call(&name, args)),
                Err(e) => rpc_error(id, ErrorCode::InvalidParams, &e),
            },
            other => {
                let message = format!("method '{other}' not supported");
                rpc_error(id, ErrorCode::MethodNotFound, &message)
            }
        }
    }

    /// Run one tool. A wire op's result is whatever response document skepd
    /// answered, verbatim — rejections are data. An `Err` from the daemon
    /// side (`Skepd`'s doc says when) is `isError` with the adapter's
    /// message, as is a tool name outside the catalog, which reaches nothing.
    fn call(&mut self, name: &str, args: Map<String, Value>) -> Value {
        if name == SESSION_INFO {
            return match self.session_info() {
                Ok(info) => tool_result(info.to_string(), false),
                Err(e) => tool_result(e, true),
            };
        }
        let Some(frame) = wire_frame(name, args) else {
            return tool_result(
                format!("unknown tool '{name}'; tools/list names the available tools"),
                true,
            );
        };
        match self.skepd.op(&frame) {
            Ok(body) => tool_result(String::from_utf8_lossy(&body).into_owned(), false),
            Err(e) => tool_result(e, true),
        }
    }

    /// The apparatus tool: this adapter's principal, that principal's
    /// account (`principal_prefix`; null until delegated), and the daemon's
    /// health answer.
    fn session_info(&mut self) -> Result<Value, String> {
        let account = self.skepd.account()?;
        let health = self.skepd.health()?;
        Ok(json!({
            "account": account,
            "health": health,
            "principal": self.skepd.principal(),
        }))
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
fn tool_result(text: String, is_error: bool) -> Value {
    json!({"content": [{"type": "text", "text": text}], "isError": is_error})
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn call_params_shapes() {
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
}
