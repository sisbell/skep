//! `Board { dialed, signed, dialer }` (`client.md` §1.1's `board` row): the
//! origin this client DIALS and the origin it SIGNS for this board — one
//! string for every direct dial, the `skep` command's and the frontend's
//! (t1), two where a frontend addresses its OWN dual-bound node (AUTH-4.57
//! (a)'s client half) — with the wire's endpoints and the token-free frames,
//! and no CEREMONY semantics.
//!
//! Every token-bearing dial of this crate rides ONE authenticated exchange,
//! [`Board::authed`] (P28): the token in `Skepd-Session`, the request through
//! the one `Dialer`, a `Skepd-Session: closed` on the answer's head returned
//! as [`Authed::Closed`] for AUTH-5.66's `closed` arm — THE ONE READER of the
//! death signal (wire.md §Sessions). A request that presents NO token cannot
//! meet that signal, and the board settles it once: [`Board::guest`], every
//! token-free read's door, the token-free answers of `op_at`, and
//! `changes_key`, which presents no token at all, HALT on it as a fault of
//! the board or the transport, so no reader of a guest answer decides what a
//! `closed` would mean.
//!
//! The three principal-free registry reads — `principal_prefix`,
//! `effective_owner`, `key_set` — are `/op` frames carried as methods because
//! they take no token and every pre-check makes them (AUTH-5.65; AUTH-6.37;
//! AUTH-6.18); `op_at` and `changes_key` are here because `derive`'s one
//! admitted read cannot be made without them (§1.1). `op` is a general frame
//! pipe for an embedder; the fence is a statement of SCOPE, kept by what this
//! crate's own code sends through it — every frame of which [`frames`]
//! spells, and every read answer of which the child `answers` decodes.
//! [`Board::board_term`] reads `H.1`'s pair, once per board (D13).

use std::fmt;
use std::sync::OnceLock;
use std::time::Duration;

use serde_json::{json, Value};
use skep_identity::{BoardTerm, Fingerprint, PublicKey};

use crate::dial::{Dialer, Request, Response};
use crate::halt::{Halt, Refused};
use crate::origin::Origin;

pub(crate) mod answers;
pub mod frames;

/// The three credential type addresses (AUTH-7.1 horn B; wire.md §The claim
/// ceremony and credentials): subspace 3 of the ghost document, ordinals
/// enroll · retire · claim.
pub const T_ENROLL: &str = "1.1.0.1.0.1.0.3.1";
pub const T_RETIRE: &str = "1.1.0.1.0.1.0.3.2";
pub const T_CLAIM: &str = "1.1.0.1.0.1.0.3.3";

/// The SUPERSEDES class's reserved ghost tumbler — the type slot of the
/// claim an `assert_sup` deposits (wire.md §Links (writes)): the one unit
/// span its entry body's type row carries, and the type the supersession
/// trail's resume read discovers by (AUTH-5.59 step 2).
pub const T_SUPERSEDES: &str = "1.1.0.1.0.1.0.1.4";

/// The published head document `H` (wire.md §The other endpoints,
/// PUB-6.65) and its first version member `H.1`, pinned forever: the board
/// term every entry frame names (D13) is read off it, once per board.
pub const HEAD_DOCUMENT: &str = "1.1.0.1.0.2";
pub const HEAD_MEMBER_1: &str = "1.1.0.1.0.2.1";

/// A session token — 32 lowercase hex (wire.md §Sessions); anything else IS
/// no token, so the type admits nothing else.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct Token(String);

impl Token {
    /// Exactly 32 lowercase hex, else `None`.
    pub fn parse(s: &str) -> Option<Token> {
        let s = s.trim();
        (s.len() == 32 && s.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)))
            .then(|| Token(s.to_string()))
    }

    /// The token's text — what `Skepd-Session` carries.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A token is a write capability (AUTH-4.53) and prints as none of itself.
impl fmt::Debug for Token {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Token(…)")
    }
}

/// `GET /health`'s answer, whole (wire.md §The other endpoints): the body
/// VERBATIM for the `health` command's stdout, and the fields the mode and
/// the origin arm derive from (AUTH-6.13).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Health {
    pub body: Value,
    pub raw: Vec<u8>,
}

impl Health {
    /// `auth.claimant` — `null` while unclaimed.
    pub fn claimant(&self) -> Option<&str> {
        self.body["auth"]["claimant"].as_str()
    }

    /// `auth.local_trust`.
    pub fn local_trust(&self) -> bool {
        self.body["auth"]["local_trust"].as_bool().unwrap_or(false)
    }

    fn list(&self, name: &str) -> Vec<&str> {
        self.body["auth"][name].as_array().map(|a| a.iter().filter_map(Value::as_str).collect()).unwrap_or_default()
    }

    /// `auth.origins` — the BARE arm's set.
    pub fn origins(&self) -> Vec<&str> {
        self.list("origins")
    }

    /// `auth.signed_origins` — the SIGNED arm's set (AUTH-6.14).
    pub fn signed_origins(&self) -> Vec<&str> {
        self.list("signed_origins")
    }

    /// `log_position` — the committed head.
    pub fn log_position(&self) -> u64 {
        self.body["log_position"].as_u64().unwrap_or(0)
    }
}

/// `GET /challenge`'s answer: the nonce and the TTL read off the body —
/// 60 000 ms as built — never assumed (`client.md` §2.2).
/// [`Board::challenge`] refuses a body that carries either absent, so the
/// nonce and the TTL it answers are the board's own and never a sentinel
/// standing in for one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Challenge {
    pub nonce: String,
    pub principal: u64,
    pub ttl: Duration,
}

/// A signed session's scope (AUTH RES-63): FULL, the body without `scope`,
/// signed under the v1 bytes; CONTENT, the body carrying `"scope":
/// "content"`, signed under the v2 bytes (AUTH-6.2, AUTH-6.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Scope {
    Full,
    Content,
}

impl Scope {
    /// The body's own `scope` string — `content` — or none at FULL.
    pub fn wire(self) -> Option<&'static str> {
        match self {
            Scope::Full => None,
            Scope::Content => Some("content"),
        }
    }
}

/// `POST /session`'s three body forms (AUTH-6.2).
#[derive(Debug, Clone, Copy)]
pub enum SessionBody<'a> {
    /// `{"principal": n}`.
    Bare { principal: u64 },
    /// The signed body, scoped or full; `origin` is the board's SIGNED
    /// origin, which the board supplies.
    Signed { principal: u64, nonce: &'a str, sig_hex: &'a str, scope: Scope },
}

/// `POST /session`'s answers, the credential's three (wire.md §Sessions): the
/// token, the one 401, and the 403 with its record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Opened {
    Token(Token),
    /// `401 session_rejected` — every failure of the credential, one code.
    Rejected,
    /// `403 prefix_blocked` — the takedown record's version address.
    Blocked { record: String },
}

/// `POST /session/close`'s answer (AUTH-4.47): the `204` that answers the
/// caller's own close — no signal rides a live token's (wire.md §Sessions)
/// — and whether the death signal rode it, the token already dead.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CloseAnswer {
    pub already_dead: bool,
}

/// One authenticated exchange's two outcomes (P28).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Authed {
    /// The answer, the session alive.
    Response(Response),
    /// The answer rode `Skepd-Session: closed`: the token is dead
    /// (wire.md §Sessions, the death signal) — AUTH-5.66's `closed` arm.
    Closed(Response),
}

/// `POST /op`'s answer: the response document — an ack or a `rejected` —
/// or, under a token, the death signal; a token-free frame is read through
/// [`Board::guest`], which answers the document alone.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Answer {
    Document(Value),
    Closed,
}

/// `POST /op-at`'s answers (wire.md §Reading history): the position's own
/// document, the three position faults, the reconstruction bound, and —
/// under a token alone — the death signal. Non-exhaustive: the set is the
/// wire's, which this crate does not own.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum AtAnswer {
    Document(Value),
    /// The death signal on a token-bearing read; a token-free read halts on
    /// it instead (the module's doc).
    Closed,
    /// `410 history_reclaimed` — the position predates retained history;
    /// `floor` where known. An ANSWER, never an exit (`client.md` §2.3).
    HistoryReclaimed { floor: Option<u64> },
    /// `400 beyond_head`.
    BeyondHead { head: Option<u64> },
    /// `400 not_a_position` — `nearest` the greatest position at or below.
    NotAPosition { nearest: Option<u64> },
    /// `503 history_busy` — a retry-class refusal, never a queue.
    Busy,
}

/// The ONE `/changes` point query this crate makes (`client.md` §1.1): the
/// `key` of the row at one position, for an UNSIGNED record alone
/// (AUTH-6.15). Non-exhaustive: the testimony's forms are the wire's.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ChangeKey {
    /// The enrolled key whose signed session committed the row.
    Key(Fingerprint),
    /// A bare-session write.
    Bare,
    /// The board's own daemon, as the system account.
    System,
    /// `null` — lost metadata, never invented.
    Lost,
    /// ABSENT — the row's entry carries its own signature (a signed entry's
    /// marker slot, or a credential record's own `sig`); no second
    /// authority for its hand.
    Signed,
    /// No row at that position on this feed (a read position, or masked).
    NoEntry,
    /// `410 history_reclaimed` below the feed's floor.
    HistoryReclaimed { floor: Option<u64> },
}

/// One enrolled entry of a `key_set` answer (AUTH-6.18): the key, the
/// fingerprint it hashes to — the decode refuses an answer whose two
/// disagree (AUTH-1.7), so every lookup by fingerprint finds the key it
/// names — and the flag it was enrolled under. The key's `ALGS` token is
/// `key.alg()`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnrolledKey {
    pub fingerprint: Fingerprint,
    pub key: PublicKey,
    pub anchor: bool,
}

/// One retired entry of a `key_set` answer — the flag the fingerprint was
/// ENROLLED under (AUTH-1.30).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RetiredKey {
    pub fingerprint: Fingerprint,
    pub anchor: bool,
}

/// An account's credential table as the wire serves it (AUTH-6.18): both
/// lists in fingerprint order. A keyless account — every unseeded account,
/// at every depth (AUTH-6.19) — answers two empty lists.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct KeySet {
    pub as_of: u64,
    pub enrolled: Vec<EnrolledKey>,
    pub retired: Vec<RetiredKey>,
}

impl KeySet {
    /// Both lists empty — the by-reference account's answer.
    pub fn is_empty(&self) -> bool {
        self.enrolled.is_empty() && self.retired.is_empty()
    }

    /// The enrolled entry for `fp`, where one stands.
    pub fn enrolled(&self, fp: &Fingerprint) -> Option<&EnrolledKey> {
        self.enrolled.iter().find(|e| &e.fingerprint == fp)
    }

    /// The retired entry for `fp`, where one stands.
    pub fn retired(&self, fp: &Fingerprint) -> Option<&RetiredKey> {
        self.retired.iter().find(|e| &e.fingerprint == fp)
    }

    /// Whether any enrolled entry carries the anchor flag (AUTH-5.16's test).
    pub fn has_anchor(&self) -> bool {
        self.enrolled.iter().any(|e| e.anchor)
    }
}

/// `key_set`'s answer: the set, or `not_an_account` (AUTH-6.19).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeySetAnswer {
    Set(KeySet),
    NotAnAccount,
}

/// `effective_owner`'s pair (AUTH-6.37): the LONGEST registered prefix
/// containing the address and the principal seated there; the address is
/// an allocated seat iff `prefix` EQUALS it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Owner {
    pub prefix: String,
    pub principal: u64,
}

/// One board, as this client addresses it. Its two origins are read through
/// [`Board::dialed`] and [`Board::signed`] and fixed where it is made — by
/// [`Board::new`] and [`Board::signing_for`] — so no caller moves the dialed
/// origin under `H.1`'s pair, which is cached for the board at that origin:
/// a term carried to another board would sign every record frame wrong.
pub struct Board {
    /// The origin this client DIALS.
    dialed: Origin,
    /// The origin this client SIGNS for this board (AUTH-4.8) — the dialed
    /// one for every direct client; the configured override at a frontend's
    /// own dual-bound node.
    signed: Origin,
    dialer: Box<dyn Dialer>,
    /// `H.1`'s pair, read ONCE per board and cached for good (cs6-2) — set
    /// only once the board answers one.
    term: OnceLock<BoardTerm>,
}

impl fmt::Debug for Board {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Board(dialed {}, signed {})", self.dialed, self.signed)
    }
}

/// A `rejected` document, decoded (wire.md §Rejections). Its parts are read
/// through [`Rejection::key`], the one token a walk dispatches on, and are
/// otherwise rendered whole — [`Rejection::token`] for a face,
/// [`Rejection::refused`] for surfacing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rejection {
    code: String,
    detail: Option<String>,
    op: Option<String>,
}

impl Rejection {
    /// The `rejected` document's parts, where the document is one.
    pub fn of(v: &Value) -> Option<Rejection> {
        if v["resp"].as_str() != Some("rejected") {
            return None;
        }
        Some(Rejection {
            code: v["code"].as_str().unwrap_or("?").to_string(),
            detail: v["detail"].as_str().map(str::to_string),
            op: v["op"].as_str().map(str::to_string),
        })
    }

    /// The ONE token a walk dispatches on (wire.md §Rejections: "key client
    /// behavior on the token, never on prose"): the `detail` of the two
    /// families that carry a machine token there — `credential_refused`,
    /// `registry_refused` — and the `code` itself everywhere else, whose
    /// `detail`, where one rides, is prose.
    pub fn key(&self) -> &str {
        match (self.code.as_str(), self.detail.as_deref()) {
            ("credential_refused" | "registry_refused", Some(d)) => d,
            (code, _) => code,
        }
    }

    /// The `code:detail` token.
    pub fn token(&self) -> String {
        match &self.detail {
            Some(d) => format!("{}:{d}", self.code),
            None => self.code.clone(),
        }
    }

    /// The refusal as the family's `Refused` member.
    pub fn refused(&self, body: &Value) -> Halt {
        Halt::Refused(Refused {
            status: 200,
            code: self.code.clone(),
            detail: self.detail.clone(),
            op: self.op.clone(),
            body: body.clone(),
        })
    }
}

/// A non-200 transport refusal — `{"error": "<name>", "detail": …?}` —
/// as the family's `Refused` member.
fn transport_refused(resp: &Response) -> Halt {
    let body: Value = serde_json::from_slice(&resp.body).unwrap_or(Value::Null);
    Halt::Refused(Refused {
        status: resp.status,
        code: body["error"].as_str().unwrap_or("http_error").to_string(),
        detail: body["detail"].as_str().map(str::to_string),
        op: body["op"].as_str().map(str::to_string),
        body,
    })
}

fn json_of(resp: &Response) -> Result<Value, Halt> {
    serde_json::from_slice(&resp.body).map_err(|e| {
        Halt::Dial(crate::dial::DialError::Response(format!(
            "the answer was not JSON ({e}): {}",
            String::from_utf8_lossy(&resp.body)
        )))
    })
}

/// A write ack's `at`, where the document is an ack.
pub fn acked_at(v: &Value) -> Option<u64> {
    matches!(v["resp"].as_str(), Some("ack" | "ack_addr" | "ack_edit")).then(|| v["at"].as_u64()).flatten()
}

/// An `ack_addr`'s minted address.
pub fn acked_addr(v: &Value) -> Option<&str> {
    (v["resp"].as_str() == Some("ack_addr")).then(|| v["addr"].as_str()).flatten()
}

impl Board {
    /// A board dialed and signed at ONE origin — the `skep` command's shape
    /// (t1): `session_open` frames the origin the dialer dials. The dialer
    /// is any [`Dialer`] — an `Arc<dyn Dialer>` a shell shares with
    /// `resolve`'s transport is one, so one dialer serves both.
    pub fn new(dialed: Origin, dialer: impl Dialer + 'static) -> Board {
        Board { signed: dialed.clone(), dialed, dialer: Box::new(dialer), term: OnceLock::new() }
    }

    /// The board SIGNED for `signed` and still dialed at its own origin — the
    /// frontend's shell at its own dual-bound node (AUTH-4.57 (a)'s client
    /// half; §7): `Board::new(dialed, dialer).signing_for(signed)`, each
    /// origin named by the call that sets it, so the two cannot trade places.
    pub fn signing_for(mut self, signed: Origin) -> Board {
        self.signed = signed;
        self
    }

    /// The origin this client DIALS.
    pub fn dialed(&self) -> &Origin {
        &self.dialed
    }

    /// The origin this client SIGNS for this board (AUTH-4.8) — the dialed
    /// one for every direct client; the configured override at a frontend's
    /// own dual-bound node.
    pub fn signed(&self) -> &Origin {
        &self.signed
    }

    /// The one dialer, for an embedder's own calls over the same transport.
    pub fn dialer(&self) -> &dyn Dialer {
        &*self.dialer
    }

    /// One exchange through the dialer at the dialed origin.
    pub fn exchange(&self, req: &Request) -> Result<Response, Halt> {
        Ok(self.dialer.exchange(&self.dialed, req)?)
    }

    /// ONE AUTHENTICATED EXCHANGE (P28): the token in `Skepd-Session` where
    /// one rides, the request dialed, the death signal on the answer's head
    /// returned as [`Authed::Closed`] — the one reader of it.
    pub fn authed(&self, token: Option<&Token>, req: Request) -> Result<Authed, Halt> {
        let req = match token {
            Some(t) => req.header("Skepd-Session", t.as_str()),
            None => req,
        };
        let resp = self.exchange(&req)?;
        Ok(if resp.session_closed() { Authed::Closed(resp) } else { Authed::Response(resp) })
    }

    /// `GET /health` (AUTH-6.13), the body whole.
    pub fn health(&self) -> Result<Health, Halt> {
        let resp = self.exchange(&Request::get("/health"))?;
        if resp.status != 200 {
            return Err(transport_refused(&resp));
        }
        let body = json_of(&resp)?;
        Ok(Health { body, raw: resp.body })
    }

    /// `GET /challenge?principal=n` — the nonce and `ttl_ms` read off the
    /// body (wire.md §Sessions). A body missing either — or carrying a TTL of
    /// zero — is no challenge this client signs: the face names which member
    /// is missing, and no nonce is spent on it.
    pub fn challenge(&self, principal: u64) -> Result<Challenge, Halt> {
        let resp = self.exchange(&Request::get(format!("/challenge?principal={principal}")))?;
        if resp.status != 200 {
            return Err(transport_refused(&resp));
        }
        let v = json_of(&resp)?;
        let missing = |member: &str| {
            Halt::face(
                format!("the challenge carried no {member}"),
                format!("`GET /challenge` answered a body without the {member} the wire pins (wire.md §Sessions)"),
                "this board is not speaking the wire this client expects; nothing was written",
            )
        };
        let nonce = v["nonce"].as_str().filter(|n| !n.is_empty()).ok_or_else(|| missing("nonce"))?;
        let ttl_ms = v["ttl_ms"].as_u64().filter(|t| *t > 0).ok_or_else(|| missing("ttl_ms"))?;
        Ok(Challenge { nonce: nonce.to_string(), principal: v["principal"].as_u64().unwrap_or(principal), ttl: Duration::from_millis(ttl_ms) })
    }

    /// `POST /session` (AUTH-6.2): the bare body, or the signed body over
    /// the SIGNED origin — `origin` is `self.signed`, never a string the
    /// caller supplies (AUTH-4.8). A `400 malformed_session_request` is this
    /// client's own framing, surfaced as the board's refusal (§2.3's exit 1).
    pub fn session_open(&self, body: SessionBody<'_>) -> Result<Opened, Halt> {
        let body = match body {
            SessionBody::Bare { principal } => json!({"principal": principal}),
            SessionBody::Signed { principal, nonce, sig_hex, scope } => {
                let mut body = json!({"principal": principal, "nonce": nonce, "origin": self.signed.as_str(), "sig": sig_hex});
                if let Some(s) = scope.wire() {
                    body["scope"] = Value::from(s);
                }
                body
            }
        };
        let resp = self.exchange(&Request::post("/session", body.to_string().into_bytes()))?;
        match resp.status {
            200 => {
                let v = json_of(&resp)?;
                let token = v["session"]
                    .as_str()
                    .and_then(Token::parse)
                    .ok_or_else(|| Halt::Dial(crate::dial::DialError::Response("no session token in the answer".into())))?;
                Ok(Opened::Token(token))
            }
            401 => Ok(Opened::Rejected),
            403 => {
                let v = json_of(&resp)?;
                if v["error"].as_str() == Some("prefix_blocked") {
                    Ok(Opened::Blocked { record: v["record"].as_str().unwrap_or("").to_string() })
                } else {
                    Err(transport_refused(&resp))
                }
            }
            _ => Err(transport_refused(&resp)),
        }
    }

    /// `POST /session/close` (AUTH-4.47): idempotent `204`; the death signal
    /// on it says the token was already dead.
    pub fn session_close(&self, token: &Token) -> Result<CloseAnswer, Halt> {
        let resp = self.exchange(&Request::post("/session/close", Vec::new()).header("Skepd-Session", token.as_str()))?;
        if resp.status != 204 {
            return Err(transport_refused(&resp));
        }
        Ok(CloseAnswer { already_dead: resp.session_closed() })
    }

    /// `POST /op` — one frame in, one response document out (200 whenever
    /// the daemon produced one, a rejection included); a non-200 is a
    /// transport refusal, the family's `Refused`.
    pub fn op(&self, token: Option<&Token>, frame: &Value) -> Result<Answer, Halt> {
        let req = Request::post("/op", frame.to_string().into_bytes());
        match self.authed(token, req)? {
            Authed::Closed(_) => Ok(Answer::Closed),
            Authed::Response(resp) => {
                if resp.status != 200 {
                    return Err(transport_refused(&resp));
                }
                Ok(Answer::Document(json_of(&resp)?))
            }
        }
    }

    /// A GUEST read — one frame presenting no token — answered as its
    /// response document, a rejection included; the death signal, which no
    /// tokenless request can meet, halts here (the module's doc).
    pub fn guest(&self, frame: &Value) -> Result<Value, Halt> {
        match self.op(None, frame)? {
            Answer::Closed => Err(guest_closed()),
            Answer::Document(v) => Ok(v),
        }
    }

    /// A guest READ whose answer must be a document and not a rejection —
    /// the registry reads' shape; a rejection is the board's refusal.
    fn read(&self, frame: &Value) -> Result<Value, Halt> {
        let v = self.guest(frame)?;
        match Rejection::of(&v) {
            Some(r) => Err(r.refused(&v)),
            None => Ok(v),
        }
    }

    /// `POST /op-at` — one READ frame answered as of `at` (wire.md §Reading
    /// history); the position faults and the reconstruction bound are
    /// answers of this read, never exits.
    pub fn op_at(&self, token: Option<&Token>, at: u64, frame: &Value) -> Result<AtAnswer, Halt> {
        let body = json!({"at": at, "frame": frame});
        let req = Request::post("/op-at", body.to_string().into_bytes());
        match self.authed(token, req)? {
            Authed::Closed(_) if token.is_none() => Err(guest_closed()),
            Authed::Closed(_) => Ok(AtAnswer::Closed),
            Authed::Response(resp) => {
                let v: Value = serde_json::from_slice(&resp.body).unwrap_or(Value::Null);
                match (resp.status, v["error"].as_str()) {
                    (200, _) => Ok(AtAnswer::Document(json_of(&resp)?)),
                    (410, Some("history_reclaimed")) => Ok(AtAnswer::HistoryReclaimed { floor: v["floor"].as_u64() }),
                    (400, Some("beyond_head")) => Ok(AtAnswer::BeyondHead { head: v["head"].as_u64() }),
                    (400, Some("not_a_position")) => Ok(AtAnswer::NotAPosition { nearest: v["nearest"].as_u64() }),
                    (503, Some("history_busy")) => Ok(AtAnswer::Busy),
                    _ => Err(transport_refused(&resp)),
                }
            }
        }
    }

    /// THE ONE `/changes` POINT QUERY (`client.md` §1.1): the `key` of the
    /// row at `at`, read as a GUEST — the credential rows live in a
    /// published doc 1 — for an UNSIGNED record alone (AUTH-6.15). It
    /// presents no token, so the death signal on its answer is a fault of the
    /// board or the transport (the module's doc).
    pub fn changes_key(&self, at: u64) -> Result<ChangeKey, Halt> {
        let since = at.saturating_sub(1);
        let req = Request::get(format!("/changes?since={since}&limit=1"));
        match self.authed(None, req)? {
            Authed::Closed(_) => Err(guest_closed()),
            Authed::Response(resp) => {
                let v: Value = serde_json::from_slice(&resp.body).unwrap_or(Value::Null);
                match resp.status {
                    200 => {}
                    410 if v["error"].as_str() == Some("history_reclaimed") => {
                        return Ok(ChangeKey::HistoryReclaimed { floor: v["floor"].as_u64() })
                    }
                    _ => return Err(transport_refused(&resp)),
                }
                let Some(entry) = v["changes"].as_array().and_then(|rows| rows.iter().find(|r| r["at"].as_u64() == Some(at)))
                else {
                    return Ok(ChangeKey::NoEntry);
                };
                Ok(match entry.get("key") {
                    None => ChangeKey::Signed,
                    Some(Value::Null) => ChangeKey::Lost,
                    Some(Value::String(s)) if s == "bare" => ChangeKey::Bare,
                    Some(Value::String(s)) if s == "system" => ChangeKey::System,
                    Some(Value::String(s)) => match Fingerprint::parse_hex(s) {
                        Some(fp) => ChangeKey::Key(fp),
                        None => ChangeKey::Lost,
                    },
                    Some(_) => ChangeKey::Lost,
                })
            }
        }
    }

    /// `principal_prefix(n)` — the principal's account address, `None` for
    /// an unknown principal (wire.md §Namespace; AUTH-5.67 (2): the address
    /// is DERIVED, never configured).
    pub fn principal_prefix(&self, principal: u64) -> Result<Option<String>, Halt> {
        let v = self.read(&frames::principal_prefix(principal))?;
        Ok(v["addr"].as_str().map(str::to_string))
    }

    /// `next_account_prefix(parent)` — the next delegable prefix, `None`
    /// for an ineligible parent.
    pub fn next_account_prefix(&self, parent: &str) -> Result<Option<String>, Halt> {
        let v = self.read(&frames::next_account_prefix(parent))?;
        Ok(v["addr"].as_str().map(str::to_string))
    }

    /// `effective_owner(addr)` (AUTH-6.37): the pair, or `None` where both
    /// members are null together.
    pub fn effective_owner(&self, addr: &str) -> Result<Option<Owner>, Halt> {
        let v = self.read(&frames::effective_owner(addr))?;
        match (v["prefix"].as_str(), v["principal"].as_u64()) {
            (Some(prefix), Some(principal)) => Ok(Some(Owner { prefix: prefix.to_string(), principal })),
            _ => Ok(None),
        }
    }

    /// `key_set(account)` (AUTH-6.18) at the head: the set, or
    /// `not_an_account` (AUTH-6.19) as an answer.
    pub fn key_set(&self, account: &str) -> Result<KeySetAnswer, Halt> {
        key_set_of(&self.guest(&frames::key_set(account))?)
    }

    /// `key_set(account)` AS OF `at` (AUTH-2.94's base read, P12).
    pub fn key_set_at(&self, account: &str, at: u64) -> Result<Option<KeySetAnswer>, Halt> {
        match self.op_at(None, at, &frames::key_set(account))? {
            AtAnswer::Document(v) => key_set_of(&v).map(Some),
            _ => Ok(None),
        }
    }

    /// THE BOARD TERM — `H.1`'s `(position, chain)` pair (D13), read ONCE
    /// per board by `retrieve_v` on the pinned first member of the head
    /// document (wire.md §The other endpoints) and parsed off the
    /// `skep-head` record; `None` while the board has no `H.1` (unclaimed,
    /// or the one write after a refused head). The one per-board content
    /// read the fence admits (RULED, owner 2026-10-04, cs6-2).
    pub fn board_term(&self) -> Result<Option<BoardTerm>, Halt> {
        if let Some(term) = self.term.get() {
            return Ok(Some(*term));
        }
        let term = self.read_board_term()?;
        if let Some(term) = term {
            let _ = self.term.set(term);
        }
        Ok(term)
    }

    fn read_board_term(&self) -> Result<Option<BoardTerm>, Halt> {
        let v = self.guest(&frames::retrieve_v(HEAD_MEMBER_1, 1, 1))?;
        let Some(bytes) = answers::first_atom(&v) else {
            return Ok(None);
        };
        let rec: Value = match serde_json::from_slice(&bytes) {
            Ok(r) => r,
            Err(_) => return Ok(None),
        };
        if rec["type"].as_str() != Some("skep-head") {
            return Ok(None);
        }
        let (Some(position), Some(chain)) = (rec["position"].as_u64(), rec["chain"].as_str().and_then(crate::hex::decode32)) else {
            return Ok(None);
        };
        Ok(Some(BoardTerm { log_position: position, chain }))
    }
}

/// The death signal on a request that presented no token — no session's
/// answer, so a fault of the board or the transport (wire.md §Sessions).
fn guest_closed() -> Halt {
    Halt::face(
        "a token-free read met the death signal",
        "the board answered `Skepd-Session: closed` to a request that presented no token",
        "this is a fault in the board or the transport, not in your keys; nothing was written",
    )
}

/// A `key_set` document decoded (AUTH-6.18), or `not_an_account`.
fn key_set_of(v: &Value) -> Result<KeySetAnswer, Halt> {
    if let Some(r) = Rejection::of(v) {
        if r.key() == "not_an_account" {
            return Ok(KeySetAnswer::NotAnAccount);
        }
        return Err(r.refused(v));
    }
    let shape = || Halt::Dial(crate::dial::DialError::Response(format!("not a key_set answer: {v}")));
    if v["resp"].as_str() != Some("key_set") {
        return Err(shape());
    }
    let mut set = KeySet { as_of: v["as_of"].as_u64().unwrap_or(0), ..KeySet::default() };
    for e in v["enrolled"].as_array().ok_or_else(shape)? {
        let alg = e["alg"].as_str().ok_or_else(shape)?;
        let key = PublicKey::parse(alg, e["key"].as_str().ok_or_else(shape)?).map_err(|_| shape())?;
        let fingerprint = e["fingerprint"].as_str().and_then(Fingerprint::parse_hex).ok_or_else(shape)?;
        if Fingerprint::of(&key) != fingerprint {
            return Err(shape());
        }
        set.enrolled.push(EnrolledKey { fingerprint, key, anchor: e["anchor"].as_bool().unwrap_or(false) });
    }
    for e in v["retired"].as_array().ok_or_else(shape)? {
        let fingerprint = e["fingerprint"].as_str().and_then(Fingerprint::parse_hex).ok_or_else(shape)?;
        set.retired.push(RetiredKey { fingerprint, anchor: e["anchor"].as_bool().unwrap_or(false) });
    }
    Ok(KeySetAnswer::Set(set))
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use super::*;

    #[test]
    fn a_token_is_thirty_two_lowercase_hex() {
        assert!(Token::parse("9f3a6c21d4b8e07a5c1b2d4e6f708192").is_some());
        assert!(Token::parse("9F3A6C21D4B8E07A5C1B2D4E6F708192").is_none());
        assert!(Token::parse("9f3a6c21d4b8e07a5c1b2d4e6f70819").is_none());
        assert_eq!(format!("{:?}", Token::parse("9f3a6c21d4b8e07a5c1b2d4e6f708192").unwrap()), "Token(…)");
    }

    #[test]
    fn a_key_set_answer_decodes_and_not_an_account_is_an_answer() {
        let v = json!({"as_of": 9, "resp": "key_set", "enrolled": [], "retired": [{"anchor": false, "fingerprint": "ab".repeat(32)}]});
        match key_set_of(&v).unwrap() {
            KeySetAnswer::Set(set) => {
                assert!(set.enrolled.is_empty() && set.retired.len() == 1 && !set.is_empty());
            }
            KeySetAnswer::NotAnAccount => panic!(),
        }
        let rej = json!({"code": "not_an_account", "disposition": "reorder", "op": "key_set", "resp": "rejected"});
        assert_eq!(key_set_of(&rej).unwrap(), KeySetAnswer::NotAnAccount);
    }

    /// AUTH-1.7 at the decode: an enrolled entry is admitted only where its
    /// fingerprint is its key's hash, so a lookup by fingerprint finds the
    /// key it names; an entry whose two disagree is no `key_set` answer.
    #[test]
    fn an_enrolled_entry_is_admitted_only_where_its_fingerprint_is_its_keys() {
        let key = skep_signature::HybridSigner::from_seed(skep_signature::TAG_MLDSA65_ED25519, &[7; 32]).expect("tag 1").public_key().clone();
        let answer = |fingerprint: String| json!({"as_of": 9, "resp": "key_set", "retired": [], "enrolled": [{"alg": key.alg(), "key": key.to_hex(), "fingerprint": fingerprint, "anchor": true}]});
        let fp = Fingerprint::of(&key);
        match key_set_of(&answer(fp.to_hex())).unwrap() {
            KeySetAnswer::Set(set) => assert!(set.enrolled(&fp).is_some_and(|e| e.anchor && e.key == key)),
            KeySetAnswer::NotAnAccount => panic!(),
        }
        let err = key_set_of(&answer("ab".repeat(32))).expect_err("a fingerprint its key does not hash to");
        assert!(err.to_string().contains("not a key_set answer"), "{err}");
    }

    #[test]
    fn the_frames_spell_the_wire() {
        assert_eq!(frames::unit_span("1.0.1"), json!([{"start": "1.0.1", "width": "0.0.1"}]));
        let f = frames::insert_atom("1.0.1.0.1", 1, "{}", T_ENROLL, Some("x"));
        assert_eq!(f["deposit"], T_ENROLL);
        assert_eq!(f["id"], "x");
        assert_eq!(f["at"]["ordinal"], "1");
        let r = Rejection::of(&json!({"code":"credential_refused","detail":"content_session","disposition":"permanent","op":"make_link","resp":"rejected"})).unwrap();
        assert_eq!(r.token(), "credential_refused:content_session");
    }

    /// wire.md §Rejections: a walk keys on the `detail` of the two families
    /// that carry a machine token there, and on the `code` everywhere else —
    /// never on a `detail` that is prose.
    #[test]
    fn a_rejection_keys_on_the_one_token_the_wire_dispatches_on() {
        let key = |v: Value| Rejection::of(&v).expect("a rejection").key().to_string();
        assert_eq!(key(json!({"code":"credential_refused","detail":"claim_first","disposition":"permanent","op":"delegate","resp":"rejected"})), "claim_first");
        assert_eq!(key(json!({"code":"credential_refused","detail":"attestation_invalid:signature","disposition":"permanent","op":"insert","resp":"rejected"})), "attestation_invalid:signature");
        assert_eq!(key(json!({"code":"registry_refused","detail":"registry_form","disposition":"permanent","op":"make_link","resp":"rejected"})), "registry_form");
        assert_eq!(key(json!({"code":"not_authorized","disposition":"permanent","op":"delegate","resp":"rejected"})), "not_authorized");
        assert_eq!(key(json!({"code":"malformed","detail":"unknown op 'frobnicate'","disposition":"permanent","op":"unparseable","resp":"rejected"})), "malformed");
        assert!(Rejection::of(&json!({"resp":"ack","at":3})).is_none());
    }

    /// A board that answers every request with one body, `200` — the death
    /// signal on its head where `closed` — keeping each request it serves
    /// beside the origin it was dialed at.
    struct Answering {
        body: Vec<u8>,
        closed: bool,
        sent: Mutex<Vec<(Origin, Request)>>,
    }

    impl Answering {
        fn new(body: &str, closed: bool) -> Answering {
            Answering { body: body.as_bytes().to_vec(), closed, sent: Mutex::new(Vec::new()) }
        }
    }

    impl Dialer for Answering {
        fn exchange(&self, origin: &Origin, req: &Request) -> Result<Response, crate::dial::DialError> {
            self.sent.lock().unwrap().push((origin.clone(), req.clone()));
            let headers = crate::dial::Headers(if self.closed { vec![("Skepd-Session".into(), "closed".into())] } else { Vec::new() });
            Ok(Response { status: 200, headers, body: self.body.clone() })
        }

        fn stream(
            &self,
            _origin: &Origin,
            _head: &crate::dial::RequestHead,
            _body: &mut dyn std::io::Read,
            _on_interim: &mut dyn FnMut(&crate::dial::Headers),
        ) -> Result<crate::dial::StreamedResponse, crate::dial::DialError> {
            unreachable!("no read of the board streams")
        }
    }

    fn origin() -> Origin {
        Origin::parse("http://127.0.0.1:8642").unwrap()
    }

    /// The death signal is the board's to settle: under a token it is the
    /// session's answer; on a token-free read it is a fault, halted at the
    /// door — never an empty set, an absent row or a missing head. One
    /// dialer, shared through an `Arc`, serves every board that holds it.
    #[test]
    fn a_guest_read_halts_on_the_death_signal_and_a_session_reads_it() {
        let dialer = Arc::new(Answering::new(r#"{"resp":"key_set","as_of":1,"enrolled":[],"retired":[]}"#, true));
        let board = Board::new(origin(), dialer.clone());
        let token = Token::parse("9f3a6c21d4b8e07a5c1b2d4e6f708192").unwrap();
        let fault = |h: Halt| assert!(h.to_string().contains("a token-free read met the death signal"), "{h}");
        fault(board.guest(&frames::key_set("1.0.1")).unwrap_err());
        fault(board.key_set("1.0.1").unwrap_err());
        fault(board.board_term().unwrap_err());
        fault(board.op_at(None, 3, &frames::key_set("1.0.1")).unwrap_err());
        fault(board.changes_key(3).unwrap_err());
        assert_eq!(board.op(Some(&token), &frames::key_set("1.0.1")).unwrap(), Answer::Closed);
        assert_eq!(board.op_at(Some(&token), 3, &frames::key_set("1.0.1")).unwrap(), AtAnswer::Closed);
        let shared: Arc<dyn Dialer> = dialer.clone();
        fault(Board::new(origin(), shared).key_set("1.0.1").unwrap_err());
        assert_eq!(dialer.sent.lock().unwrap().len(), 8, "both boards rode the one dialer");
    }

    /// A board signed for another origin than it dials (AUTH-4.57 (a)'s
    /// client half): every request goes to the dialed origin, and a signed
    /// session body names the SIGNED one (AUTH-4.8) — its scope where the
    /// session is scoped (AUTH-6.2) — while a bare body names the principal
    /// alone.
    #[test]
    fn a_board_signing_for_another_origin_dials_its_own_and_frames_the_signed_one() {
        let signed = Origin::parse("https://board.example").unwrap();
        let dialer = Arc::new(Answering::new("{}", false));
        let board = Board::new(origin(), dialer.clone()).signing_for(signed.clone());
        assert_eq!((board.dialed(), board.signed()), (&origin(), &signed));
        let nonce = "ab".repeat(32);
        for scope in [Scope::Content, Scope::Full] {
            let _ = board.session_open(SessionBody::Signed { principal: 7, nonce: &nonce, sig_hex: "cd", scope });
        }
        let _ = board.session_open(SessionBody::Bare { principal: 0 });
        let sent = dialer.sent.lock().unwrap();
        assert!(sent.iter().all(|(dialed, req)| *dialed == origin() && req.path == "/session"), "every request dials the dialed origin");
        let body = |i: usize| serde_json::from_slice::<Value>(&sent[i].1.body).unwrap();
        assert_eq!(body(0), json!({"principal": 7, "nonce": nonce, "origin": "https://board.example", "scope": "content", "sig": "cd"}));
        assert_eq!(body(1), json!({"principal": 7, "nonce": nonce, "origin": "https://board.example", "sig": "cd"}));
        assert_eq!(body(2), json!({"principal": 0}));
    }

    /// A challenge is the board's nonce and TTL, never a sentinel: a body
    /// missing either, or naming a TTL of zero, halts naming the member, and
    /// a whole one answers the TTL as a duration.
    #[test]
    fn a_challenge_missing_its_nonce_or_its_ttl_is_refused_by_name() {
        let nonce = "ab".repeat(32);
        let challenge = |body: String| Board::new(origin(), Answering::new(&body, false)).challenge(7);
        let whole = challenge(format!(r#"{{"nonce":"{nonce}","principal":7,"ttl_ms":60000}}"#)).expect("a whole challenge");
        assert_eq!((whole.nonce.as_str(), whole.principal, whole.ttl), (nonce.as_str(), 7, Duration::from_secs(60)));
        for (body, member) in [
            (r#"{"principal":7,"ttl_ms":60000}"#.to_string(), "nonce"),
            (r#"{"nonce":"","principal":7,"ttl_ms":60000}"#.to_string(), "nonce"),
            (format!(r#"{{"nonce":"{nonce}","principal":7}}"#), "ttl_ms"),
            (format!(r#"{{"nonce":"{nonce}","principal":7,"ttl_ms":0}}"#), "ttl_ms"),
        ] {
            let halt = challenge(body).expect_err("no challenge");
            assert!(halt.to_string().contains(&format!("the challenge carried no {member}")), "{halt}");
            assert_eq!(halt.exit_code(), 3);
        }
    }
}
