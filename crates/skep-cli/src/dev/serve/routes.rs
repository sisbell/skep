//! THE ROUTES (the dev provider record §3.1 (i), §3.3, §3.4, §3.5): one
//! connection, one request, one reply. `OPTIONS` is the preflight, answered
//! for the one origin; every other request passes the admission first and
//! is refused 403 naming the failed check with no dial made. Then:
//! `POST /bridge/<call>` with the call's arguments as a JSON object answers
//! `{"result": …}` or `{"refused": …}` — HTTP 200 either way, a refusal
//! being an answer; a 4xx is the PROVIDER's own refusal (the admission, a
//! malformed body, an unknown call or route). `POST /bridge/answer` and
//! `/bridge/cancel` are the page's two answers to a moment. `GET
//! /bridge/events` is the event stream, held open until the page closes it
//! or the provider stops. `GET /bridge/log` is the call and dial log. `GET
//! /bridge/shapes` is the declarations. `POST /bridge/script` is the
//! SCRIPT SEAM (`client.md` §4b.5): `{call, refusal}` arms the next answer
//! of that call as the named refusal, `{event, data}` fires an event by
//! hand — a dev seam, said as such on TALK when used. `POST
//! /bridge/fault/<door>` reaches the in-process daemon's doors under
//! `dev-hooks` with `--own`, and answers `not_built_in` otherwise. `POST
//! /bridge/fetch` streams the blob's bytes as the response body.

use std::io::{self, Write};
use std::net::TcpStream;
use std::sync::mpsc::RecvTimeoutError;
use std::time::{Duration, Instant};

use serde_json::{json, Value};
use skep_http::{read_request, write_head, write_response, Limits, Refused, Request};
use skep_shell::{CallOutcome, EventName};

use super::http::{cors_headers, write_sse_event, write_sse_head, write_sse_keepalive, KEEPALIVE, MAX_BODY, MAX_HEAD, READ_TIMEOUT, WRITE_TIMEOUT};
use super::{node, Provider};
use crate::terminal::talk;

/// THE CONNECTION: the timeouts, the read, the preflight or the admission,
/// the route.
pub fn connection(provider: &Provider<'_>, mut stream: TcpStream) {
    let _ = stream.set_nodelay(true);
    let _ = stream.set_read_timeout(Some(READ_TIMEOUT));
    let _ = stream.set_write_timeout(Some(WRITE_TIMEOUT));
    let peer = stream.peer_addr().ok();
    let cors = cors_headers(&provider.admission.page_origin);
    let req = match read_request(&mut stream, Limits { max_head: MAX_HEAD, max_body: MAX_BODY }) {
        Ok(Some(req)) => req,
        Ok(None) => return,
        Err(Refused::Malformed(detail)) => {
            let _ = write_response(&mut stream, 400, &cors, Some("text/plain; charset=utf-8"), format!("refused: malformed_http: {detail}\n").as_bytes());
            return;
        }
        Err(Refused::TooLarge { declared, cap }) => {
            let _ = write_response(&mut stream, 413, &cors, Some("text/plain; charset=utf-8"), format!("refused: payload_too_large: {declared} bytes declared against a cap of {cap}\n").as_bytes());
            return;
        }
    };
    if req.method == "OPTIONS" {
        let _ = match provider.admission.preflight(&req, peer) {
            Ok(()) => write_response(&mut stream, 204, &cors, None, b""),
            Err(check) => write_response(&mut stream, 403, &cors, Some("text/plain; charset=utf-8"), format!("refused: {}\n", check.name()).as_bytes()),
        };
        return;
    }
    let events_route = req.method == "GET" && req.path == "/bridge/events";
    if let Err(check) = provider.admission.admit(&req, peer, events_route) {
        let _ = write_response(&mut stream, 403, &cors, Some("text/plain; charset=utf-8"), format!("refused: {}\n", check.name()).as_bytes());
        return;
    }
    let _ = route(provider, &req, &mut stream, &cors);
}

/// A JSON reply.
fn json(stream: &mut TcpStream, status: u16, cors: &[(String, String)], body: &Value) -> io::Result<()> {
    write_response(stream, status, cors, Some("application/json"), body.to_string().as_bytes())
}

/// The request's body as the call's argument object: an empty body is
/// `{}`; anything but an object is the provider's own 400.
fn args_of(req: &Request) -> Result<Value, String> {
    if req.body.iter().all(|b| b.is_ascii_whitespace()) {
        return Ok(json!({}));
    }
    match serde_json::from_slice::<Value>(&req.body) {
        Ok(v) if v.is_object() => Ok(v),
        Ok(_) => Err("the body is not a JSON object".into()),
        Err(e) => Err(format!("the body is not JSON: {e}")),
    }
}

/// THE ROUTE.
fn route(provider: &Provider<'_>, req: &Request, stream: &mut TcpStream, cors: &[(String, String)]) -> io::Result<()> {
    let shell = &provider.shell;
    match (req.method.as_str(), req.path.as_str()) {
        ("GET", "/bridge/events") => events(provider, stream, cors),
        ("GET", "/bridge/log") => json(stream, 200, cors, &Value::Array(shell.log().entries())),
        ("GET", "/bridge/shapes") => write_response(stream, 200, cors, Some("text/plain; charset=utf-8"), skep_shell::shapes::declarations().as_bytes()),
        ("POST", "/bridge/answer") => {
            let args = match args_of(req) {
                Ok(a) => a,
                Err(detail) => return json(stream, 400, cors, &json!({"refused": {"kind": "shell", "name": "malformed_body", "detail": detail}})),
            };
            let Some(id) = args["id"].as_str() else {
                return json(stream, 400, cors, &json!({"refused": {"kind": "shell", "name": "malformed_args", "what": "id"}}));
            };
            if shell.answer(id, args["value"].clone()) {
                json(stream, 200, cors, &json!({"result": {}}))
            } else {
                json(stream, 200, cors, &json!({"refused": {"kind": "shell", "name": "no_such_moment", "id": id}}))
            }
        }
        ("POST", "/bridge/cancel") => {
            let args = match args_of(req) {
                Ok(a) => a,
                Err(detail) => return json(stream, 400, cors, &json!({"refused": {"kind": "shell", "name": "malformed_body", "detail": detail}})),
            };
            let Some(id) = args["id"].as_str() else {
                return json(stream, 400, cors, &json!({"refused": {"kind": "shell", "name": "malformed_args", "what": "id"}}));
            };
            if shell.cancel(id) {
                json(stream, 200, cors, &json!({"result": {}}))
            } else {
                json(stream, 200, cors, &json!({"refused": {"kind": "shell", "name": "no_such_moment", "id": id}}))
            }
        }
        ("POST", "/bridge/script") => {
            let args = match args_of(req) {
                Ok(a) => a,
                Err(detail) => return json(stream, 400, cors, &json!({"refused": {"kind": "shell", "name": "malformed_body", "detail": detail}})),
            };
            script(provider, &args, stream, cors)
        }
        ("POST", "/bridge/fetch") => {
            let args = match args_of(req) {
                Ok(a) => a,
                Err(detail) => return json(stream, 400, cors, &json!({"refused": {"kind": "shell", "name": "malformed_body", "detail": detail}})),
            };
            let started = Instant::now();
            match shell.fetch(&args) {
                Ok(mut fetched) => {
                    let content_type = fetched.headers.get("Content-Type").unwrap_or("application/octet-stream").to_string();
                    let length = fetched.headers.get("Content-Length").and_then(|l| l.parse::<usize>().ok());
                    write_head(stream, 200, cors, Some(&content_type), length)?;
                    let copied = io::copy(&mut fetched.body, stream)?;
                    shell.log().call("fetch", req.body.len(), copied as usize, started.elapsed(), CallOutcome::Stream);
                    stream.flush()
                }
                Err(r) => {
                    shell.log().call("fetch", req.body.len(), 0, started.elapsed(), CallOutcome::Refused);
                    json(stream, 200, cors, &json!({"refused": r.to_value()}))
                }
            }
        }
        ("POST", path) if path.starts_with("/bridge/fault/") => {
            let door = &path["/bridge/fault/".len()..];
            let args = args_of(req).unwrap_or_else(|_| json!({}));
            let answer = match provider.node {
                Some(n) => node::fault(n, &mut provider.doors.lock().expect("the doors' lock"), door, &args),
                None => Err("the fault doors are the in-process daemon's: run with --own in a dev-hooks build".to_string()),
            };
            match answer {
                Ok(v) => {
                    talk(format!("fault door `{door}`: {v}"));
                    json(stream, 200, cors, &json!({"result": v}))
                }
                Err(detail) => json(stream, 200, cors, &json!({"refused": node::not_a_door(detail)})),
            }
        }
        ("POST", path) if path.starts_with("/bridge/") => {
            let call = &path["/bridge/".len()..];
            if !skep_shell::CALLS.contains(&call) {
                return json(stream, 404, cors, &json!({"refused": {"kind": "shell", "name": "unknown_call", "call": call}}));
            }
            let args = match args_of(req) {
                Ok(a) => a,
                Err(detail) => return json(stream, 400, cors, &json!({"refused": {"kind": "shell", "name": "malformed_body", "detail": detail}})),
            };
            if let Some(canned) = provider.canned.lock().expect("the canned lock").remove(call) {
                talk(format!("script: `{call}` answers the canned refusal {}", canned["name"]));
                shell.log().call(call, req.body.len(), canned.to_string().len(), Duration::ZERO, CallOutcome::Canned);
                return json(stream, 200, cors, &json!({"refused": canned}));
            }
            match shell.call(call, &args) {
                Ok(v) => json(stream, 200, cors, &json!({"result": v})),
                Err(r) => json(stream, 200, cors, &json!({"refused": r.to_value()})),
            }
        }
        _ => json(stream, 404, cors, &json!({"refused": {"kind": "shell", "name": "unknown_route", "method": req.method, "path": req.path}})),
    }
}

/// THE SCRIPT SEAM: `{call, refusal}` arms the next answer, `{event,
/// data}` fires an event by hand.
fn script(provider: &Provider<'_>, args: &Value, stream: &mut TcpStream, cors: &[(String, String)]) -> io::Result<()> {
    if let Some(call) = args["call"].as_str() {
        if !skep_shell::CALLS.contains(&call) {
            return json(stream, 400, cors, &json!({"refused": {"kind": "shell", "name": "unknown_call", "call": call}}));
        }
        let refusal = match &args["refusal"] {
            Value::String(name) => json!({"kind": "shell", "name": name, "canned": true}),
            Value::Object(m) => {
                let mut v = Value::Object(m.clone());
                v["canned"] = Value::from(true);
                if v.get("kind").is_none() {
                    v["kind"] = Value::from("shell");
                }
                v
            }
            _ => return json(stream, 400, cors, &json!({"refused": {"kind": "shell", "name": "malformed_args", "what": "refusal"}})),
        };
        talk(format!("script: the next `{call}` is armed to answer {}", refusal["name"]));
        provider.canned.lock().expect("the canned lock").insert(call.to_string(), refusal);
        return json(stream, 200, cors, &json!({"result": {"armed": call}}));
    }
    if let Some(event) = args["event"].as_str() {
        let Ok(name) = event.parse::<EventName>() else {
            return json(stream, 400, cors, &json!({"refused": {"kind": "shell", "name": "unknown_event", "event": event}}));
        };
        talk(format!("script: the event `{name}` is fired by hand"));
        provider.shell.bus().emit(name, args["data"].clone());
        return json(stream, 200, cors, &json!({"result": {"fired": name.as_str()}}));
    }
    json(stream, 400, cors, &json!({"refused": {"kind": "shell", "name": "malformed_args", "what": "call or event"}}))
}

/// THE EVENT STREAM: every event as `event:` and `data:` lines, a comment
/// every [`KEEPALIVE`] of silence, until the page closes the connection or
/// the provider stops.
fn events(provider: &Provider<'_>, stream: &mut TcpStream, cors: &[(String, String)]) -> io::Result<()> {
    let rx = provider.shell.subscribe();
    write_sse_head(stream, cors)?;
    let mut last = Instant::now();
    loop {
        match rx.recv_timeout(Duration::from_secs(1)) {
            Ok(event) => {
                write_sse_event(stream, event.name.as_str(), &event.data.to_string())?;
                last = Instant::now();
            }
            Err(RecvTimeoutError::Timeout) => {
                if provider.stopped() {
                    return Ok(());
                }
                if last.elapsed() >= KEEPALIVE {
                    write_sse_keepalive(stream)?;
                    last = Instant::now();
                }
            }
            Err(RecvTimeoutError::Disconnected) => return Ok(()),
        }
    }
}
