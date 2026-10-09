//! The MCP side: the stdio loop, JSON-RPC 2.0 dispatch, and `tools/call`
//! onto the daemon's ops; stdout carries protocol only.

use std::io::{BufRead, Write};

use serde_json::{json, Map, Value};

use crate::daemon::Skepd;
use crate::tools::{Tools, RENAMES_FROM, SESSION_INFO, WIRE_OPS};

/// When the client's `initialize` names no protocolVersion (it always
/// should), answer the newest revision this server was written against.
const FALLBACK_PROTOCOL_VERSION: &str = "2025-06-18";

pub struct Server {
    pub skepd: Skepd,
    pub catalog: Tools,
}

impl Server {
    /// The stdio loop: one JSON-RPC message per line in, one per line out,
    /// nothing else ever on stdout. EOF is the clean exit; a closed stdout
    /// (the harness hung up) ends the process too.
    pub fn run(&mut self) {
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
            format!("{{\"op\":\"principal_prefix\",\"principal\":{}}}", self.skepd.principal());
        let body = self.skepd.op(frame.as_bytes())?;
        let resolved: Value = serde_json::from_slice(&body)
            .map_err(|e| format!("principal_prefix answer is not JSON: {e}"))?;
        let account = resolved.get("addr").cloned().unwrap_or(Value::Null);
        let (status, hbody) = self.skepd.http().request("GET", "/health", None, b"")?;
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
            "principal": self.skepd.principal(),
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
