//! The routes (the dev provider record §3.1 (i), §3.3, §3.4, §3.5).
//!
//! One connection, one request, one reply. `OPTIONS` is the preflight,
//! answered for the one origin; every other request passes the admission
//! first and is refused 403 naming the failed check with no dial made.
//! Then: `POST /bridge/<call>` with the call's arguments as a JSON object
//! answers `{"result": …}` or `{"refused": …}` — HTTP 200 either way, a
//! refusal being an answer; a 4xx is the provider's own refusal (the
//! admission, a malformed body, an unknown call or route).
//! `POST /bridge/answer` and `/bridge/cancel` are the page's two answers to
//! a moment. `GET /bridge/events` is the event stream, held open until the
//! page closes it or the provider stops. `GET /bridge/log` is the call and
//! dial log. `GET /bridge/shapes` is the declarations.
//! `POST /bridge/script` is the script seam (`client.md` §4b.5), a dev seam
//! said as such on talk when used: `{call, answer}` arms that call's next
//! answer as its result, served exactly as armed, and `{call, refusal}` as
//! the named refusal; a call holds one armed answer, a later arm replacing
//! it, served once and logged `canned`. A canned answer changes nothing in
//! the shell: a call that relies on what the real answer would have left —
//! a `publication.count` after a canned `publication.open`, an `op` under a
//! session a canned `session` named — gets the shell's own answer unless it
//! is armed too, and an event the real call would fire is fired by hand,
//! `{event, data}`. `fetch`, whose answer is a stream of bytes, takes an
//! armed refusal alone, served on its own route. `POST /bridge/fault/<door>`
//! reaches the in-process daemon's doors under `dev-hooks` with `--own`,
//! and answers `not_built_in` otherwise. `POST /bridge/fetch` streams the
//! blob's bytes as the response body.

use std::io::{self, Write};
use std::net::TcpStream;
use std::sync::mpsc::RecvTimeoutError;
use std::time::{Duration, Instant};

use serde_json::{json, Value};
use skep_http::{read_request, write_head, write_response, Limits, Refused, Request};
use skep_shell::{CallOutcome, EventName};

use super::http::{cors_headers, write_sse_event, write_sse_head, write_sse_keepalive, KEEPALIVE, MAX_BODY, MAX_HEAD, READ_TIMEOUT, WRITE_TIMEOUT};
use super::{node, Canned, Provider};
use crate::shared::clipped;
use crate::terminal::talk;

/// Serves one connection, from its timeouts to its route.
///
/// It sets the timeouts, then takes the read, the preflight or the
/// admission, the route. Every refusal of the read, the preflight or the
/// admission is counted, and said on talk the first time its kind is met
/// in the run, ahead of its answer.
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
            let refusal = format!("malformed_http: {detail}");
            provider.refused("malformed_http", || format!("a request the provider could not read is refused ({}); said once, every one counted at the stop", clipped(&refusal)));
            let _ = write_response(&mut stream, 400, &cors, Some("text/plain; charset=utf-8"), format!("refused: {refusal}\n").as_bytes());
            return;
        }
        Err(Refused::TooLarge { declared, cap }) => {
            let refusal = format!("payload_too_large: {declared} bytes declared against a cap of {cap}");
            provider.refused("payload_too_large", || format!("a request the provider could not read is refused ({refusal}); said once, every one counted at the stop"));
            let _ = write_response(&mut stream, 413, &cors, Some("text/plain; charset=utf-8"), format!("refused: {refusal}\n").as_bytes());
            return;
        }
    };
    if req.method == "OPTIONS" {
        let _ = match provider.admission.preflight(&req, peer) {
            Ok(()) => write_response(&mut stream, 204, &cors, None, b""),
            Err(check) => {
                provider.refused(check.name(), || provider.admission.refusal_line(check, &req, peer));
                write_response(&mut stream, 403, &cors, Some("text/plain; charset=utf-8"), format!("refused: {}\n", check.name()).as_bytes())
            }
        };
        return;
    }
    let events_route = req.method == "GET" && req.path == "/bridge/events";
    if let Err(check) = provider.admission.admit(&req, peer, events_route) {
        provider.refused(check.name(), || provider.admission.refusal_line(check, &req, peer));
        let _ = write_response(&mut stream, 403, &cors, Some("text/plain; charset=utf-8"), format!("refused: {}\n", check.name()).as_bytes());
        return;
    }
    let _ = route(provider, &req, &mut stream, &cors);
}

/// Writes a JSON reply.
///
/// # Errors
///
/// Returns the I/O error the write meets.
fn json(stream: &mut TcpStream, status: u16, cors: &[(String, String)], body: &Value) -> io::Result<()> {
    write_response(stream, status, cors, Some("application/json"), body.to_string().as_bytes())
}

/// Returns the request's body as the call's argument object.
///
/// An empty body is `{}`.
///
/// # Errors
///
/// Anything but an object is refused, the error saying why: the provider's
/// own 400 at every route but the fault doors', which take `{}` instead.
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

/// Answers the request on its route.
///
/// # Errors
///
/// Returns the I/O error the answer's write meets.
///
/// # Panics
///
/// Panics if the doors' lock is poisoned — a fault door that panicked held
/// it — or the script seam's armed answers' lock is.
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
            match shell.answer(id, args["value"].clone()) {
                Ok(()) => json(stream, 200, cors, &json!({"result": {}})),
                Err(refused) => json(stream, 200, cors, &json!({"refused": refused.to_value()})),
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
            match shell.cancel(id) {
                Ok(()) => json(stream, 200, cors, &json!({"result": {}})),
                Err(refused) => json(stream, 200, cors, &json!({"refused": refused.to_value()})),
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
            // A refusal the script seam armed for `fetch` answers here, on
            // the call's own route.
            if let Some(canned) = provider.take_canned("fetch") {
                return canned_answer(provider, "fetch", &args, canned, stream, cors);
            }
            // The shell logs the call: a refusal at once, the stream as its
            // body is dropped, whether the copy ends or the page hangs up.
            match shell.fetch(&args) {
                Ok(mut fetched) => {
                    let content_type = fetched.headers.get("Content-Type").unwrap_or("application/octet-stream").to_string();
                    let length = fetched.headers.get("Content-Length").and_then(|l| l.parse::<usize>().ok());
                    write_head(stream, 200, cors, Some(&content_type), length)?;
                    io::copy(&mut fetched.body, stream)?;
                    stream.flush()
                }
                Err(r) => json(stream, 200, cors, &json!({"refused": r.to_value()})),
            }
        }
        ("POST", path) if path.starts_with("/bridge/fault/") => {
            let door = &path["/bridge/fault/".len()..];
            let args = args_of(req).unwrap_or_else(|_| json!({}));
            let answer = match provider.node {
                Some(n) => node::fault(n, &mut provider.doors.lock().expect("the doors' lock"), door, &args),
                None => Err(format!("the fault doors are the in-process daemon's: run with --own in a dev-hooks build; the doors are {}", node::DOORS.join(", "))),
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
            let named = &path["/bridge/".len()..];
            let Some(&call) = skep_shell::CALLS.iter().find(|c| **c == named) else {
                return json(stream, 404, cors, &json!({"refused": {"kind": "shell", "name": "unknown_call", "call": named}}));
            };
            let args = match args_of(req) {
                Ok(a) => a,
                Err(detail) => return json(stream, 400, cors, &json!({"refused": {"kind": "shell", "name": "malformed_body", "detail": detail}})),
            };
            if let Some(canned) = provider.take_canned(call) {
                return canned_answer(provider, call, &args, canned, stream, cors);
            }
            match shell.call(call, &args) {
                Ok(v) => json(stream, 200, cors, &json!({"result": v})),
                Err(r) => json(stream, 200, cors, &json!({"refused": r.to_value()})),
            }
        }
        _ => json(stream, 404, cors, &json!({"refused": {"kind": "shell", "name": "unknown_route", "method": req.method, "path": req.path}})),
    }
}

/// Serves the script seam: a call's next answer armed, or an event fired.
///
/// `{call, answer}` arms that call's next answer as its result, served
/// exactly as armed; `{call, refusal}` arms it as a refusal — a name, or an
/// object carrying one, `shell` its kind where it names none — marked
/// `canned`. Either replaces the answer armed before it, which the talk
/// line says. `{event, data}` fires the event by hand.
///
/// # Errors
///
/// Returns the I/O error the answer's write meets. The page's refusals are
/// each a 400, the first met answering:
///
/// 1. a call the bridge does not spell: `unknown_call`;
/// 2. an answer beside a refusal: `malformed_args`;
/// 3. an answer for `fetch`, whose answer is a stream of bytes:
///    `streamed_call`;
/// 4. an answer that is neither an object nor an array, or a refusal that
///    is neither a name nor an object: `malformed_args`;
/// 5. a call armed with neither: `malformed_args`;
/// 6. an event the contract does not name: `unknown_event`;
/// 7. neither a call nor an event: `malformed_args`.
///
/// # Panics
///
/// Panics if the armed answers' lock is poisoned: a thread that panicked
/// held it.
fn script(provider: &Provider<'_>, args: &Value, stream: &mut TcpStream, cors: &[(String, String)]) -> io::Result<()> {
    if let Some(named) = args["call"].as_str() {
        let Some(&call) = skep_shell::CALLS.iter().find(|c| **c == named) else {
            return json(stream, 400, cors, &json!({"refused": {"kind": "shell", "name": "unknown_call", "call": named}}));
        };
        let canned = match (args.get("answer"), args.get("refusal")) {
            (Some(_), Some(_)) => {
                let both = json!({"refused": {"kind": "shell", "name": "malformed_args", "what": "answer or refusal", "detail": "one of the two, never both"}});
                return json(stream, 400, cors, &both);
            }
            (Some(_), None) if call == "fetch" => {
                let detail = "fetch answers a stream of bytes, which the seam does not can: arm a refusal";
                return json(stream, 400, cors, &json!({"refused": {"kind": "shell", "name": "streamed_call", "call": "fetch", "detail": detail}}));
            }
            (Some(answer @ (Value::Object(_) | Value::Array(_))), None) => Canned::Answer(answer.clone()),
            (Some(_), None) => return json(stream, 400, cors, &json!({"refused": {"kind": "shell", "name": "malformed_args", "what": "answer"}})),
            (None, Some(Value::String(name))) => Canned::Refusal(json!({"kind": "shell", "name": name, "canned": true})),
            (None, Some(Value::Object(m))) => {
                let mut v = Value::Object(m.clone());
                v["canned"] = Value::from(true);
                if v.get("kind").is_none() {
                    v["kind"] = Value::from("shell");
                }
                Canned::Refusal(v)
            }
            (None, Some(_)) => return json(stream, 400, cors, &json!({"refused": {"kind": "shell", "name": "malformed_args", "what": "refusal"}})),
            (None, None) => return json(stream, 400, cors, &json!({"refused": {"kind": "shell", "name": "malformed_args", "what": "answer or refusal"}})),
        };
        let what = match &canned {
            Canned::Answer(_) => "a canned result".to_string(),
            Canned::Refusal(v) => format!("the canned refusal {}", clipped(&v["name"].to_string())),
        };
        let dropped = if provider.arm(call, canned).is_some() { " — the answer armed before it is dropped" } else { "" };
        talk(format!("script: the next `{call}` is armed to answer {what}{dropped}"));
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

/// Answers `call` with the answer the script seam armed for it.
///
/// A canned result is served as `{"result": …}` exactly as armed, a canned
/// refusal as `{"refused": …}`; either is logged `canned`, measured as the
/// shell measures an answer of its own, and said on talk.
///
/// # Errors
///
/// Returns the I/O error the answer's write meets.
fn canned_answer(provider: &Provider<'_>, call: &'static str, args: &Value, canned: Canned, stream: &mut TcpStream, cors: &[(String, String)]) -> io::Result<()> {
    let (body, bytes_out) = match canned {
        Canned::Answer(v) => {
            talk(format!("script: `{call}` answers its canned result"));
            let bytes_out = v.to_string().len();
            (json!({"result": v}), bytes_out)
        }
        Canned::Refusal(v) => {
            talk(format!("script: `{call}` answers the canned refusal {}", clipped(&v["name"].to_string())));
            let bytes_out = v.to_string().len();
            (json!({"refused": v}), bytes_out)
        }
    };
    provider.shell.log().call(call, args.to_string().len(), bytes_out, Duration::ZERO, CallOutcome::Canned);
    json(stream, 200, cors, &body)
}

/// Serves the event stream: every event as `event:` and `data:` lines.
///
/// A comment goes every [`KEEPALIVE`] of silence, until the page closes the
/// connection or the provider stops.
///
/// # Errors
///
/// Returns the I/O error a write meets, the page's closing among them.
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
