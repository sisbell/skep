//! The daemon side: the adapter's principal, its at-most-one live session
//! token, the one reissue, and every exchange the adapter has with skepd —
//! the op, the bare session open, and the account and health reads
//! `session_info` is built from. Every field is private and no method
//! hands the origin out, so after startup every exchange with skepd is a
//! method of this module. The origin and the principal are set at
//! construction and only read after it, so a token is only ever sent to
//! the origin that issued it, for the principal it was opened for. Only
//! `open_bare_session` stores a token and only `post_op` reads one, to pass
//! as the session header. No tool result or log line can carry it while
//! two rules hold: no error string in this module quotes a `/session`
//! success body — the one answer a token rides, read only by
//! `session_token` — and `Http::request` never quotes the request it
//! wrote. A test beside each holds its rule.

use serde_json::Value;

use crate::http::Http;

/// The header a session token rides (wire.md §Sessions).
const SESSION_HEADER: &str = "Skepd-Session";

/// The adapter's standing with skepd: one origin, one principal, at most
/// one live token. `Err(String)` is the adapter's own message for an
/// exchange that left it no answer to hand on: skepd was not reached or
/// did not answer; the bare session open `op` needs, or the health read,
/// answered a status other than 200 or a body the adapter could not read;
/// or the account read's answer was not JSON. Whatever response document
/// skepd answered to an op itself — rejections included — is an `Ok`
/// payload.
pub struct Skepd {
    http: Http,
    principal: u64,
    token: Option<String>,
}

impl Skepd {
    /// No session yet: the first write the daemon answers `unauthenticated`
    /// opens one.
    pub fn new(http: Http, principal: u64) -> Skepd {
        Skepd { http, principal, token: None }
    }

    /// The principal this adapter binds, fixed for the adapter's life.
    pub fn principal(&self) -> u64 {
        self.principal
    }

    /// POST one frame to `/op`; hand back its response document verbatim.
    /// On `unauthenticated` — wire.md §Sessions' signal to (re)open a
    /// session: this write needs one the adapter doesn't hold (never opened,
    /// or the daemon restarted and the token died with the process) — open a
    /// bare session and reissue the frame once, overriding the rejection's
    /// `permanent` hint as a client that knows its own context may (wire.md
    /// §Rejections). The rejected attempt executed nothing, so the reissue
    /// cannot double-apply; a second `unauthenticated` passes through as data
    /// like any other rejection. This is the only reissue anywhere: no other
    /// rejection is reissued, whatever its disposition, `retry` included.
    pub fn op(&mut self, frame: &[u8]) -> Result<Vec<u8>, String> {
        let body = self.post_op(frame)?;
        if !is_unauthenticated(&body) {
            return Ok(body);
        }
        self.open_bare_session()?;
        self.post_op(frame)
    }

    /// The bound principal's account: `principal_prefix`'s `addr` (wire.md
    /// `maybe_addr`), null while the principal is undelegated — and null
    /// for any other JSON answer that carries no `addr`, a rejection among
    /// them. A namespace read is exempt from the read predicate (AUTH-6.37),
    /// so the answer is the same whether or not a session is live.
    pub fn account(&mut self) -> Result<Value, String> {
        let frame = format!("{{\"op\":\"principal_prefix\",\"principal\":{}}}", self.principal);
        let body = self.op(frame.as_bytes())?;
        let resolved: Value = serde_json::from_slice(&body)
            .map_err(|e| format!("principal_prefix answer is not JSON: {e}"))?;
        Ok(resolved.get("addr").cloned().unwrap_or(Value::Null))
    }

    /// `GET /health`: the daemon's health answer, a live reading of its
    /// `(log_position, chain_head)` pair with no address of its own — not
    /// the published head document that records that pair durably (wire.md
    /// §The other endpoints). The route is token-blind (wire.md §Sessions),
    /// so no token rides it.
    pub fn health(&self) -> Result<Value, String> {
        let (status, body) = self.http.request("GET", "/health", &[], b"")?;
        if status != 200 {
            return Err(format!(
                "GET /health answered {status}: {}",
                String::from_utf8_lossy(&body)
            ));
        }
        serde_json::from_slice(&body).map_err(|e| format!("/health answer is not JSON: {e}"))
    }

    /// `POST /session`'s bare form for the configured principal (wire.md
    /// §Sessions): local trust — the principal is named, not proven
    /// (§Identity) — which a board in ENFORCING mode refuses. A refusal is
    /// quoted in the error, since no non-200 answer carries a token (wire.md
    /// §HTTP status codes); a 200 goes to `session_token`, which never
    /// quotes it.
    fn open_bare_session(&mut self) -> Result<(), String> {
        let body = format!("{{\"principal\":{}}}", self.principal);
        let (status, answer) = self.http.request("POST", "/session", &[], body.as_bytes())?;
        if status != 200 {
            return Err(format!(
                "bare session open for principal {} failed ({status}): {}",
                self.principal,
                String::from_utf8_lossy(&answer)
            ));
        }
        self.token = Some(session_token(&answer)?);
        eprintln!("skep-mcp: bare session opened (principal {})", self.principal);
        Ok(())
    }

    /// One `POST /op`, the live token, if any, riding as the session header.
    fn post_op(&self, frame: &[u8]) -> Result<Vec<u8>, String> {
        let session = self.token.as_deref().map(|t| (SESSION_HEADER, t));
        let (_, body) = self.http.request("POST", "/op", session.as_slice(), frame)?;
        Ok(body)
    }
}

/// The one response shape `op` reads instead of forwarding blind: the
/// `unauthenticated` rejection, wire.md §Sessions' signal to (re)open a
/// session and the cue to reissue. Only writes carry it — a read without a
/// live token runs at guest class instead (wire.md §Sessions) — so no
/// read/write classification lives in this binary.
fn is_unauthenticated(body: &[u8]) -> bool {
    match serde_json::from_slice::<Value>(body) {
        Ok(v) => v["resp"] == "rejected" && v["code"] == "unauthenticated",
        Err(_) => false,
    }
}

/// The token out of a `/session` 200 answer (`{"principal":…,"session":…}`,
/// wire.md §Sessions). That is the one answer a token rides, so a body this
/// adapter cannot read — a daemon that spells or nests the token
/// differently — is refused by naming what is missing, never by quoting
/// it: the refusal reaches the agent in a tool result.
fn session_token(answer: &[u8]) -> Result<String, String> {
    let v: Value =
        serde_json::from_slice(answer).map_err(|e| format!("session answer is not JSON: {e}"))?;
    let token = v["session"].as_str().ok_or("session answer has no string 'session' field")?;
    Ok(token.to_string())
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream};

    use super::*;
    use crate::http::parse_url;

    /// The `unauthenticated` rejection, as wire.md §Rejections spells it.
    const UNAUTHENTICATED: &str =
        r#"{"code":"unauthenticated","disposition":"permanent","op":"insert","resp":"rejected"}"#;

    /// The reissue trigger is exact: the `unauthenticated` rejection and
    /// nothing else — not other rejections, not acks, not non-JSON.
    #[test]
    fn unauthenticated_detection_is_exact() {
        assert!(is_unauthenticated(UNAUTHENTICATED.as_bytes()));
        assert!(!is_unauthenticated(br#"{"at":7,"resp":"ack"}"#));
        assert!(!is_unauthenticated(
            br#"{"code":"not_owner","disposition":"permanent","op":"insert","resp":"rejected"}"#
        ));
        assert!(!is_unauthenticated(b"not json"));
    }

    /// A `/session` 200 is read for its token, and one the adapter cannot
    /// read is refused without quoting it: under a spelling this adapter
    /// doesn't know, the body may still carry a token.
    #[test]
    fn unreadable_session_answer_is_never_quoted() {
        let token = "9f3a6c21d4b8e07a5c1b2d4e6f708192";
        let answer = format!(r#"{{"principal":7,"session":"{token}"}}"#);
        assert_eq!(session_token(answer.as_bytes()), Ok(token.to_string()));
        for unreadable in [
            format!(r#"{{"principal":7,"token":"{token}"}}"#),
            format!(r#"{{"principal":7,"session":{{"id":"{token}"}}}}"#),
            format!(r#"{{"principal":7,"session":"{token}""#),
        ] {
            let err = session_token(unreadable.as_bytes()).expect_err("unreadable");
            assert!(!err.contains(token), "the refusal quotes the body: {err}");
        }
    }

    /// One request off a stub daemon's connection, head and body, as text.
    fn read_request(conn: &mut TcpStream) -> String {
        let mut raw = Vec::new();
        let mut buf = [0u8; 1024];
        loop {
            if let Some(sep) = raw.windows(4).position(|w| w == b"\r\n\r\n") {
                let head = String::from_utf8_lossy(&raw[..sep]).to_ascii_lowercase();
                let len: usize = head
                    .lines()
                    .find_map(|l| l.strip_prefix("content-length:"))
                    .and_then(|v| v.trim().parse().ok())
                    .unwrap_or(0);
                if raw.len() >= sep + 4 + len {
                    return String::from_utf8_lossy(&raw).into_owned();
                }
            }
            let n = conn.read(&mut buf).expect("read the request");
            assert!(n > 0, "the request ended early");
            raw.extend_from_slice(&buf[..n]);
        }
    }

    /// The `unauthenticated` cue opens the bare form — `{"principal": n}`
    /// on `POST /session` — and a board that refuses it (ENFORCING answers
    /// `401 session_rejected`) is the adapter's own error, naming the bare
    /// form and quoting the refusal.
    #[test]
    fn refused_bare_session_is_an_error_naming_the_form() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind a stub daemon");
        let port = listener.local_addr().expect("stub address").port();
        let answers: [(u16, &str); 2] =
            [(200, UNAUTHENTICATED), (401, r#"{"error":"session_rejected"}"#)];
        let stub = std::thread::spawn(move || {
            let mut requests = Vec::new();
            for (status, body) in answers {
                let (mut conn, _) = listener.accept().expect("accept");
                requests.push(read_request(&mut conn));
                let reply = format!(
                    "HTTP/1.1 {status} X\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                conn.write_all(reply.as_bytes()).expect("answer");
            }
            requests
        });
        let http = parse_url(&format!("http://127.0.0.1:{port}")).expect("stub url");
        let err = Skepd::new(http, 7).op(br#"{"op":"insert"}"#).expect_err("the open is refused");
        assert!(err.starts_with("bare session open for principal 7 failed (401): "), "{err}");
        assert!(err.contains("session_rejected"), "the refusal is quoted: {err}");
        let requests = stub.join().expect("the stub daemon");
        assert!(requests[0].starts_with("POST /op "), "the op comes first: {}", requests[0]);
        assert!(requests[1].starts_with("POST /session "), "{}", requests[1]);
        assert!(requests[1].ends_with(r#"{"principal":7}"#), "the bare form: {}", requests[1]);
    }
}
