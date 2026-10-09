//! The daemon side: the adapter's principal, its at-most-one live session
//! token, the one reissue, and every exchange the adapter has with skepd —
//! the op, the bare session open, and the account and health reads
//! `session_info` is built from. Every field is private and no method
//! hands the origin out, so after startup every exchange with skepd is a
//! method of this module. The origin and the principal are set at
//! construction and only read after it, so a token is only ever sent to
//! the origin that issued it, for the principal it was opened for. A token
//! is a `Token`: wire.md §Sessions' 32 lowercase hex and nothing else,
//! printing none of itself and leaving only through `Token::header`. Only
//! `open_bare_session` stores one and only `post_op` sends it, as the
//! session header. Beside the type, two rules keep it out of every tool
//! result and log line: no error string in this module quotes a `/session`
//! success body — the one answer a token rides, read only by
//! `session_token` — and `Http::exchange` never quotes the request it
//! wrote. The type and each rule have a test beside them.

use std::fmt;

use serde_json::{json, Value};

use crate::http::{Http, Method};

/// The header a session token rides (wire.md §Sessions).
const SESSION_HEADER: &str = "Skepd-Session";

/// The longest answer `is_unauthenticated` parses. The cue is M10's
/// `reject(kind, Unauthenticated)` — `Rejection::classified` with no
/// `site`, whose `fixed_detail` gives a `detail` to `Gate` alone — and no
/// response echoes a request id (wire.md §Correlation and idempotency), so
/// it is wire.md §Rejections' own example with the op's name in it: 78
/// bytes and the name, 101 at the longest dispatch op. Forty times that
/// leaves room for any `site` or `detail` a later daemon may add. A longer
/// answer is not the cue and is relayed unparsed: a full `Value` of a
/// `retrieve_v` at skep-retrieval's `MAX_DELIVERY_ITEMS` — 2^17 one-member
/// `{"atom"}` items, 1.7 MB on the wire — is ~90 MB of B-tree leaves,
/// built to read two members.
const MAX_CUE_BYTES: usize = 4096;

/// A live session token: wire.md §Sessions' 32 lowercase hex and nothing
/// else, since the daemon admits nothing else as one. A credential, so it
/// prints none of itself — no `Display`, and a `Debug` that elides it, as
/// skepd's `Token` and skep-client's do — and leaves only through `header`.
struct Token(String);

impl Token {
    /// Exactly 32 lowercase hex, else `None` (wire.md §Sessions). The one
    /// check on bytes the daemon chose that reach a request head: the
    /// grammar admits no CR, LF or `:`, discharging `Http::exchange`'s
    /// precondition on a header value.
    fn parse(s: &str) -> Option<Token> {
        let wire = s.len() == 32 && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'));
        wire.then(|| Token(s.to_string()))
    }

    /// The token as the one header it rides: `post_op`'s session header.
    fn header(&self) -> (&'static str, &str) {
        (SESSION_HEADER, &self.0)
    }
}

/// The token's presence, never its text: a derived `Debug` would put it in
/// any `{:?}`, a log line included.
impl fmt::Debug for Token {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Token(…)")
    }
}

/// The adapter's standing with skepd: one origin, one principal, at most
/// one live token. `Err(String)` is the adapter's own message for an
/// exchange that left it no answer to hand on: skepd was not reached, or
/// did not answer within `Http::exchange`'s bounds — its deadlines and its
/// answer cap; the bare session open `op` needs, or the health read,
/// answered a status other than 200 or a body the adapter could not read;
/// or the account read was answered no well-formed `maybe_addr`. An `Err`
/// that came after a frame was written whole — at the exchange's read or
/// response step, the reissue's included — leaves that write's outcome
/// unknown: it may have committed. Whatever skepd answered to an op itself
/// within those bounds is an `Ok` payload at any status, since `post_op`
/// reads none: a 200's response document, rejections included, or a
/// non-200's `{"error", "detail"?}` body (wire.md §HTTP status codes).
#[derive(Debug)]
pub struct Skepd {
    http: Http,
    principal: u64,
    token: Option<Token>,
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

    /// POST one frame to `/op`; hand back skepd's answer to it verbatim, at
    /// any status. On `unauthenticated` — wire.md §Sessions' signal to
    /// (re)open a session: this write needs one the adapter doesn't hold
    /// (never opened, or ended — a daemon restart ends every session, and
    /// wire.md §Sessions lists the other ends) — open a bare session and
    /// reissue the frame once, overriding the rejection's `permanent` hint
    /// as a client that knows its own context may (wire.md §Rejections). The
    /// rejected attempt executed nothing, so the reissue cannot double-apply;
    /// a second `unauthenticated` passes through as data like any other
    /// rejection. This is the only reissue anywhere: no other rejection is
    /// reissued, whatever its disposition, `retry` included.
    pub fn op(&mut self, frame: &[u8]) -> Result<Vec<u8>, String> {
        let body = self.post_op(frame)?;
        if !is_unauthenticated(&body) {
            return Ok(body);
        }
        self.open_bare_session()?;
        self.post_op(frame)
    }

    /// The bound principal's account: the `addr` of `principal_prefix`'s
    /// `maybe_addr` answer (wire.md §The response envelope), null while the
    /// principal is undelegated. A query: one `POST /op` under the held
    /// token, if any, and never a session open — a read is never answered
    /// `unauthenticated` (wire.md §Sessions), and a namespace read is exempt
    /// from the read predicate (AUTH-6.37), so the answer is the same with a
    /// session live or none. Any other answer — a rejection, a non-200's
    /// `{"error"}` body, a `maybe_addr` whose `addr` is neither a string nor
    /// null — is neither an account nor its absence: `Err`, quoting it,
    /// never a null that would read as "undelegated".
    pub fn account(&self) -> Result<Value, String> {
        let frame = json!({"op": "principal_prefix", "principal": self.principal}).to_string();
        let body = self.post_op(frame.as_bytes())?;
        let answer: Value = serde_json::from_slice(&body)
            .map_err(|e| format!("principal_prefix answer is not JSON: {e}"))?;
        match answer.get("addr").filter(|addr| addr.is_string() || addr.is_null()) {
            Some(addr) if answer["resp"] == "maybe_addr" => Ok(addr.clone()),
            _ => Err(format!(
                "principal_prefix answered no well-formed maybe_addr: {}",
                String::from_utf8_lossy(&body)
            )),
        }
    }

    /// `GET /health`: the daemon's health answer, a live reading of its
    /// `(log_position, chain_head)` pair with no address of its own — not
    /// the published head document that records that pair durably (wire.md
    /// §The other endpoints). The route is token-blind (wire.md §Sessions),
    /// so no token rides it.
    pub fn health(&self) -> Result<Value, String> {
        let (status, body) = self.http.exchange(Method::Get, "/health", &[], b"")?;
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
        let body = json!({"principal": self.principal}).to_string();
        let (status, answer) =
            self.http.exchange(Method::Post, "/session", &[], body.as_bytes())?;
        if status != 200 {
            return Err(format!(
                "bare session open for principal {} failed ({status}): {}",
                self.principal,
                String::from_utf8_lossy(&answer)
            ));
        }
        self.token = Some(session_token(&answer)?);
        crate::log(format_args!("bare session opened (principal {})", self.principal));
        Ok(())
    }

    /// One `POST /op`, the live token, if any, riding as the session header:
    /// the answer's body, whatever its status — the status is not read.
    fn post_op(&self, frame: &[u8]) -> Result<Vec<u8>, String> {
        let session = self.token.as_ref().map(Token::header);
        let (_, body) = self.http.exchange(Method::Post, "/op", session.as_slice(), frame)?;
        Ok(body)
    }
}

/// The one response shape `op` reads instead of forwarding blind: the
/// `unauthenticated` rejection, wire.md §Sessions' signal to (re)open a
/// session and the cue to reissue. Only writes carry it — a read without a
/// live token runs at guest class instead (wire.md §Sessions) — so no
/// read/write classification lives in this binary. Only an answer of the
/// cue's size is parsed (`MAX_CUE_BYTES`).
fn is_unauthenticated(body: &[u8]) -> bool {
    if body.len() > MAX_CUE_BYTES {
        return false;
    }
    match serde_json::from_slice::<Value>(body) {
        Ok(v) => v["resp"] == "rejected" && v["code"] == "unauthenticated",
        Err(_) => false,
    }
}

/// The token out of a `/session` 200 answer (`{"principal":…,"session":…}`,
/// wire.md §Sessions). That is the one answer a token rides, so a body this
/// adapter cannot read — a daemon that spells or nests the token
/// differently, or answers a value that is no token by wire.md's grammar —
/// is refused by naming what is wrong, never by quoting it: the refusal
/// reaches the agent in a tool result.
fn session_token(answer: &[u8]) -> Result<Token, String> {
    let v: Value =
        serde_json::from_slice(answer).map_err(|e| format!("session answer is not JSON: {e}"))?;
    let token = v["session"].as_str().ok_or("session answer has no string 'session' field")?;
    Token::parse(token).ok_or_else(|| {
        String::from("session answer's 'session' field is not a session token (32 lowercase hex)")
    })
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream};

    use super::*;

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

    /// The cue is parsed only at a size it can have: wire.md's rejection
    /// padded with a `detail` to exactly `MAX_CUE_BYTES` is still the cue,
    /// and one byte more is relayed unparsed — so no answer the cap admits,
    /// a 2^17-item delivery among them, is built into a `Value` for it.
    #[test]
    fn the_cue_is_parsed_only_at_a_size_it_can_have() {
        let cue = |pad: usize| {
            let detail = "x".repeat(pad);
            json!({"code": "unauthenticated", "detail": detail, "disposition": "permanent",
                   "op": "insert", "resp": "rejected"})
            .to_string()
        };
        let pad = MAX_CUE_BYTES - cue(0).len();
        assert_eq!(cue(pad).len(), MAX_CUE_BYTES, "the padded cue sits at the bound");
        assert!(is_unauthenticated(cue(pad).as_bytes()), "the cue at the bound is read");
        assert!(!is_unauthenticated(cue(pad + 1).as_bytes()), "past it nothing is parsed");
    }

    /// A `/session` 200 is read for its token, and one the adapter cannot
    /// read — a spelling it doesn't know, or a value that is no token — is
    /// refused without quoting it: the body may still carry a credential.
    #[test]
    fn unreadable_session_answer_is_never_quoted() {
        let token = "9f3a6c21d4b8e07a5c1b2d4e6f708192";
        let answer = format!(r#"{{"principal":7,"session":"{token}"}}"#);
        assert_eq!(session_token(answer.as_bytes()).map(|t| t.0), Ok(token.to_string()));
        for unreadable in [
            format!(r#"{{"principal":7,"token":"{token}"}}"#),
            format!(r#"{{"principal":7,"session":{{"id":"{token}"}}}}"#),
            format!(r#"{{"principal":7,"session":"{token}""#),
            format!(r#"{{"principal":7,"session":"{token}.x"}}"#),
        ] {
            let err = session_token(unreadable.as_bytes()).expect_err("unreadable");
            assert!(!err.contains(token), "the refusal quotes the body: {err}");
        }
    }

    /// A token is wire.md §Sessions' 32 lowercase hex exactly: the daemon
    /// admits nothing else as one, so the adapter holds nothing else.
    #[test]
    fn a_token_is_32_lowercase_hex() {
        let token = "9f3a6c21d4b8e07a5c1b2d4e6f708192";
        assert_eq!(Token::parse(token).map(|t| t.0), Some(token.to_string()));
        for no_token in [
            String::new(),
            token[..31].to_string(),
            format!("{token}0"),
            token.to_ascii_uppercase(),
            format!("{}g", &token[..31]),
            format!(" {token}"),
            format!("{token}.x"),
        ] {
            assert!(Token::parse(&no_token).is_none(), "'{no_token}' is no token");
        }
    }

    /// A held token prints none of itself: neither it nor the `Skepd` that
    /// holds it carries the token into a `{:?}`, a log line included.
    #[test]
    fn a_held_token_prints_none_of_itself() {
        let token = "9f3a6c21d4b8e07a5c1b2d4e6f708192";
        let mut skepd = Skepd::new(Http::parse("http://127.0.0.1:1").expect("a url"), 7);
        skepd.token = Token::parse(token);
        assert!(skepd.token.is_some(), "a wire token parses");
        let printed = format!("{skepd:?}");
        assert!(!printed.contains(token), "Debug prints the token: {printed}");
        assert!(printed.contains("Token(…)"), "Debug shows the token's presence: {printed}");
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
        let http = Http::parse(&format!("http://127.0.0.1:{port}")).expect("stub url");
        let err = Skepd::new(http, 7).op(br#"{"op":"insert"}"#).expect_err("the open is refused");
        assert!(err.starts_with("bare session open for principal 7 failed (401): "), "{err}");
        assert!(err.contains("session_rejected"), "the refusal is quoted: {err}");
        let requests = stub.join().expect("the stub daemon");
        assert!(requests[0].starts_with("POST /op "), "the op comes first: {}", requests[0]);
        assert!(requests[1].starts_with("POST /session "), "{}", requests[1]);
        assert!(requests[1].ends_with(r#"{"principal":7}"#), "the bare form: {}", requests[1]);
    }
}
