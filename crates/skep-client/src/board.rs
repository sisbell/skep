//! `Board { dialed, signed, dialer }` (`client.md` §1.1's `board` row).
//!
//! It holds the origin this client dials and the origin it signs for this
//! board — one string for every direct dial, the `skep` command's and the
//! frontend's, two where a frontend addresses its own dual-bound node
//! (AUTH-4.57 (a)'s client half) — with the wire's endpoints and the
//! token-free frames, and no ceremony semantics.
//!
//! Every token-bearing dial of this crate but the close rides one
//! authenticated exchange, [`Board::authed`] (P28): the token in
//! `Skepd-Session`, the request through the one `Dialer`, a
//! `Skepd-Session: closed` on the answer's head returned as
//! [`Authed::Closed`] for AUTH-5.66's `closed` arm — the one reader of the
//! death signal beside [`Board::session_close`], which presents its token
//! through [`Board::exchange`] and reads the signal as
//! [`CloseAnswer::already_dead`] (wire.md §Sessions). A request that
//! presents no token cannot meet that signal, and the board settles it
//! once: [`Board::guest`], the token-free answers of `op_at` and `changes`,
//! and `changes_key`, which presents no token at all, halt on it as a fault
//! of the board or the transport, so no reader of a guest answer decides
//! what a `closed` would mean — save a caller that hands [`Board::op`] no
//! token, which answers the signal as [`Answer::Closed`] all the same.
//!
//! The three principal-free registry reads — `principal_prefix`,
//! `effective_owner`, `key_set` — are `/op` frames carried as methods
//! because they take no token and every pre-check makes them (AUTH-5.65;
//! AUTH-6.37; AUTH-6.18), and `next_account_prefix`, the namespace's
//! frontier read, rides beside them; `op_at` and `changes_key` are here
//! because `derive`'s one admitted read cannot be made without them
//! (§1.1). `op` is a general frame pipe for an embedder; the fence is a
//! statement of scope, kept by what this crate's own code sends through it
//! — every frame of which [`frames`] spells, and whose read answers the
//! child `answers` decodes, but for the registry reads' answers, which
//! `Board` decodes itself, and an envelope member a caller reads in place.
//! [`Board::board_term`] reads `H.1`'s pair, once per board
//! (signed-ops D13). [`Board::changes`] — the feed's page — and
//! [`Board::chain_at`] are the feed consumer's two reads (`client.md`
//! §4e.2, §4e.3), the consumer standing behind the `search` feature, and
//! `changes` is the merge's feed walk's too, behind `merge`: in the default
//! build nothing in this crate calls either, and §1.1's "no `/changes`
//! feed consumer" holds of that build as written.

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
#[cfg(test)]
pub(crate) mod fake;
#[cfg(test)]
mod tests;

pub use answers::{
    edition_claims as edition_claim_rows, history, homes, link_value, EditionClaim, History,
    HistoryRow, HomeCount, LinkSpan, LinkValue,
};

/// The enroll credential type address, the first of the three.
///
/// The three credential type addresses (AUTH-7.1 horn B; wire.md §The claim
/// ceremony and credentials) are subspace 3 of the ghost document, ordinals
/// enroll · retire · claim.
pub const T_ENROLL: &str = "1.1.0.1.0.1.0.3.1";
/// The retire credential type address, the second of the three.
pub const T_RETIRE: &str = "1.1.0.1.0.1.0.3.2";
/// The claim credential type address, the third of the three.
pub const T_CLAIM: &str = "1.1.0.1.0.1.0.3.3";

/// The supersedes class's reserved ghost tumbler.
///
/// It is the type slot of the claim an `assert_sup` deposits (wire.md
/// §Links (writes)): the one unit span its entry body's type row carries,
/// and the type the supersession trail's resume read discovers by
/// (AUTH-5.59 step 2).
pub const T_SUPERSEDES: &str = "1.1.0.1.0.1.0.1.4";

/// The retraction class's reserved ghost tumbler, `[R]`.
///
/// It is the fifth of the format's five (`1.1.0.1.0.1.0.1.x`, x = 1..=5:
/// pred_def, pred_stable, retired, supersedes, retraction) — the type slot
/// of the tuple a `nullify` deposits and of a publication's `retract` entry
/// (wire.md §The publish shot and head-float, the deposits: "a retraction is
/// `nullify`'s tuple at the target's home"), and the type the
/// retraction-stands read discovers by: a tuple of this class whose `to`
/// names the target.
pub const T_RETRACTION: &str = "1.1.0.1.0.1.0.1.5";

/// The published head document `H` (wire.md §The other endpoints, PUB-6.65).
///
/// It and its first version member `H.1` are pinned forever: the board term
/// every entry frame names (signed-ops D13) is read off `H.1`, once per
/// board.
pub const HEAD_DOCUMENT: &str = "1.1.0.1.0.2";
/// The head document's first version member `H.1`, the board term's source.
pub const HEAD_MEMBER_1: &str = "1.1.0.1.0.2.1";

/// A session token — 32 lowercase hex (wire.md §Sessions).
///
/// Anything else is no token, so the type admits nothing else.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct Token(String);

impl Token {
    /// Parses a token: exactly 32 lowercase hex once trimmed, else `None`.
    pub fn parse(s: &str) -> Option<Token> {
        let s = s.trim();
        (s.len() == 32 && s.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)))
            .then(|| Token(s.to_string()))
    }

    /// Returns the token's text — what `Skepd-Session` carries.
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

/// `GET /health`'s answer, whole (wire.md §The other endpoints).
///
/// It holds the body verbatim for the `health` command's stdout, and the
/// fields the mode and the origin arm derive from (AUTH-6.13).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Health {
    /// The body parsed: the fields the mode and the origin arm derive from.
    pub body: Value,
    /// The body's bytes verbatim, for the `health` command's stdout.
    pub raw: Vec<u8>,
}

impl Health {
    /// Returns `auth.claimant` — `null` while unclaimed.
    pub fn claimant(&self) -> Option<&str> {
        self.body["auth"]["claimant"].as_str()
    }

    /// Returns `auth.local_trust`.
    pub fn local_trust(&self) -> bool {
        self.body["auth"]["local_trust"].as_bool().unwrap_or(false)
    }

    fn list(&self, name: &str) -> Vec<&str> {
        self.body["auth"][name].as_array().map(|a| a.iter().filter_map(Value::as_str).collect()).unwrap_or_default()
    }

    /// Returns `auth.origins` — the bare arm's set.
    pub fn origins(&self) -> Vec<&str> {
        self.list("origins")
    }

    /// Returns `auth.signed_origins` — the signed arm's set (AUTH-6.14).
    pub fn signed_origins(&self) -> Vec<&str> {
        self.list("signed_origins")
    }

    /// Returns `log_position` — the committed head.
    pub fn log_position(&self) -> u64 {
        self.body["log_position"].as_u64().unwrap_or(0)
    }

    /// Returns `chain_head` — the commit chain's value at the committed head.
    ///
    /// It is the chain of the `log_position` beside it, the two read off one
    /// kernel snapshot (wire.md §The other endpoints); `None` where the body
    /// carries none as 64 hex digits, either case. With `log_position` it is
    /// the `(position, chain)` pair a feed consumer saves as a range's
    /// `held` (`client.md` §4e.2).
    pub fn chain_head(&self) -> Option<[u8; 32]> {
        self.body["chain_head"].as_str().and_then(crate::hex::decode32)
    }
}

/// The page a `GET /changes` serves where no `limit` is sent.
///
/// It is the route's default (wire.md §The change feed, Paging: "default
/// 256").
pub const DEFAULT_CHANGES_LIMIT: u64 = 256;

/// One `GET /changes` page query (wire.md §The change feed).
///
/// It holds the fence, the two narrowings and the page's cap. `limit` is
/// sent only where set — the route's default is [`DEFAULT_CHANGES_LIMIT`] —
/// so a `fits` answered on `malformed_changes` is re-asked with that limit.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ChangesQuery<'a> {
    /// `since=<position>`: the page is `(since, head]`.
    pub since: u64,
    /// The `under=<address-or-prefix>` narrowing.
    ///
    /// It keeps the entries whose reduced `docs` name a document at or under
    /// that address or prefix.
    pub under: Option<&'a str>,
    /// The `drafts=true` narrowing: the supplement's page.
    ///
    /// It keeps the entries whose reduced `docs` name a draft the presented
    /// class may read.
    pub drafts: bool,
    /// `limit=<n>`, 1 to 4096; the route's default, 256, where unset.
    pub limit: Option<u64>,
}

impl ChangesQuery<'_> {
    /// Returns the request path with its query.
    ///
    /// `since` comes first, and each member is spelled once.
    fn path(&self) -> String {
        let mut path = format!("/changes?since={}", self.since);
        if let Some(under) = self.under {
            path.push_str("&under=");
            path.push_str(under);
        }
        if self.drafts {
            path.push_str("&drafts=true");
        }
        if let Some(limit) = self.limit {
            path.push_str(&format!("&limit={limit}"));
        }
        path
    }
}

/// One page of the change feed (wire.md §The change feed).
///
/// It holds the rows as the wire serves them — a consumer reads the members
/// it knows and ignores the rest, the forward rule — `last`, the next
/// request's `since`, and `more`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChangesPage {
    /// The entries, oldest first, each the wire's own object.
    pub changes: Vec<Value>,
    /// The final entry's position, or the `since` echoed on an empty page.
    pub last: u64,
    /// Whether entries stand past `last`.
    pub more: bool,
}

/// `GET /changes`'s answers (wire.md §The change feed).
///
/// They are the page; the retention floor, an answer and never an exit
/// (`client.md` §2.3); the byte budget's refusal carrying the `limit` that
/// fits; and, under a token alone, the death signal. Non-exhaustive: the
/// set is the wire's.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ChangesAnswer {
    /// One page of the feed.
    Page(ChangesPage),
    /// `410 history_reclaimed` — `since` reaches below the feed's memory.
    ///
    /// `floor` is the oldest position still answerable, when known.
    HistoryReclaimed { floor: Option<u64> },
    /// `400 malformed_changes` naming a `limit` past the 2 MiB page budget.
    ///
    /// `fits` is the largest limit whose page from the same `since` fits,
    /// re-asked at once. A malformed query of this client's own framing
    /// carries no `fits` and is the board's refusal instead.
    TooLarge { fits: u64 },
    /// The death signal on a token-bearing read.
    ///
    /// A token-free read halts on it instead (the module's doc).
    Closed,
}

/// `GET /chain?at=<position>`'s answers (wire.md §Reading history).
///
/// They are the chain's value as of the position, the three position faults
/// and the reconstruction bound — each an answer, the resume's judgment
/// being the embedder's (`client.md` §4e.3). Token-blind, so no death
/// signal has an arm here. Non-exhaustive: the set is the wire's.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ChainAtAnswer {
    /// `200 {"at": N, "chain": …}` — the chain's thirty-two bytes.
    Chain { at: u64, chain: [u8; 32] },
    /// `410 history_reclaimed` — the position predates retained history.
    ///
    /// It carries `floor` where known.
    HistoryReclaimed { floor: Option<u64> },
    /// `400 beyond_head` — the position exceeds the committed head.
    BeyondHead { head: Option<u64> },
    /// `400 not_a_position` — `nearest` the greatest position at or below.
    NotAPosition { nearest: Option<u64> },
    /// `503 history_busy` — every reconstruction permit is in use.
    ///
    /// A retry-class refusal, never a queue.
    Busy,
}

/// `GET /challenge`'s answer: the nonce and the TTL read off the body.
///
/// The TTL is 60 000 ms as built and never assumed (`client.md` §2.2).
/// [`Board::challenge`] refuses a body that carries either absent, so the
/// nonce and the TTL it answers are the board's own and never a sentinel
/// standing in for one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Challenge {
    /// The nonce a signed body names.
    pub nonce: String,
    /// The principal challenged — the one asked, where the body names none.
    pub principal: u64,
    /// The nonce's time to live, the body's `ttl_ms`.
    pub ttl: Duration,
}

/// A signed session's scope (AUTH RES-63).
///
/// `Full`, the body without `scope`, signed under the v1 bytes; `Content`,
/// the body carrying `"scope": "content"`, signed under the v2 bytes
/// (AUTH-6.2, AUTH-6.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Scope {
    /// The body without `scope`, signed under the v1 bytes.
    Full,
    /// The body carrying `"scope": "content"`, signed under the v2 bytes.
    Content,
}

impl Scope {
    /// Returns the body's own `scope` string — `content` — or none at `Full`.
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
    /// The signed body, scoped or full.
    ///
    /// `origin` is the board's signed origin, which the board supplies.
    Signed { principal: u64, nonce: &'a str, sig_hex: &'a str, scope: Scope },
}

/// `POST /session`'s answers, the credential's three (wire.md §Sessions).
///
/// They are the token, the one 401, and the 403 with its record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Opened {
    /// The session opened: its token.
    Token(Token),
    /// `401 session_rejected` — every failure of the credential, one code.
    Rejected,
    /// `403 prefix_blocked` — the takedown record's version address.
    Blocked { record: String },
}

/// `POST /session/close`'s answer (AUTH-4.47).
///
/// It is the `204` that answers the caller's own close — no signal rides a
/// live token's (wire.md §Sessions) — and whether the death signal rode it,
/// the token already dead.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CloseAnswer {
    /// Whether the death signal rode the `204`: the token was already dead.
    pub already_dead: bool,
}

/// One authenticated exchange's two outcomes (P28).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Authed {
    /// The answer, with no death signal on its head.
    Response(Response),
    /// The answer rode `Skepd-Session: closed`: the token is dead.
    ///
    /// It is the death signal (wire.md §Sessions) — AUTH-5.66's `closed` arm.
    Closed(Response),
}

/// `POST /op`'s answer.
///
/// It is the response document — an ack or a `rejected` — or the death
/// signal, whether or not a token rode; [`Board::guest`] reads a token-free
/// frame as the document alone, and halts on the signal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Answer {
    /// The response document — an ack or a `rejected`.
    Document(Value),
    /// The death signal rode the answer.
    Closed,
}

/// `POST /op-at`'s answers (wire.md §Reading history).
///
/// They are the position's own document, the three position faults, the
/// reconstruction bound, and — under a token alone — the death signal.
/// Non-exhaustive: the set is the wire's, which this crate does not own.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum AtAnswer {
    /// The position's own document.
    Document(Value),
    /// The death signal on a token-bearing read.
    ///
    /// A token-free read halts on it instead (the module's doc).
    Closed,
    /// `410 history_reclaimed` — the position predates retained history.
    ///
    /// It carries `floor` where known. An answer, never an exit (`client.md`
    /// §2.3).
    HistoryReclaimed { floor: Option<u64> },
    /// `400 beyond_head`.
    BeyondHead { head: Option<u64> },
    /// `400 not_a_position` — `nearest` the greatest position at or below.
    NotAPosition { nearest: Option<u64> },
    /// `503 history_busy` — a retry-class refusal, never a queue.
    Busy,
}

/// The one `/changes` point query this crate makes (`client.md` §1.1).
///
/// Its answer is the `key` of the row at one position, for an unsigned
/// record alone (AUTH-6.15). Non-exhaustive: the testimony's forms are the
/// wire's.
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
    ///
    /// A `key` this client cannot read as a fingerprint answers so too.
    Lost,
    /// Absent — the row's entry carries its own signature.
    ///
    /// The signature is a signed entry's marker slot, or a credential
    /// record's own `sig`; no second authority for its hand.
    Signed,
    /// No row at that position on this feed (a read position, or masked).
    NoEntry,
    /// `410 history_reclaimed` below the feed's floor.
    HistoryReclaimed { floor: Option<u64> },
}

/// One enrolled entry of a `key_set` answer (AUTH-6.18).
///
/// It holds the key, the fingerprint it hashes to — the decode refuses an
/// answer whose two disagree (AUTH-1.7), so every lookup by fingerprint
/// finds the key it names — and the flag it was enrolled under. The key's
/// `ALGS` token is `key.alg()`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnrolledKey {
    /// The fingerprint `key` hashes to.
    pub fingerprint: Fingerprint,
    /// The enrolled public key.
    pub key: PublicKey,
    /// Whether the key was enrolled under the anchor flag.
    pub anchor: bool,
}

/// One retired entry of a `key_set` answer (AUTH-1.30).
///
/// It carries the flag the fingerprint was *enrolled* under.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RetiredKey {
    /// The retired fingerprint.
    pub fingerprint: Fingerprint,
    /// Whether the fingerprint was enrolled under the anchor flag.
    pub anchor: bool,
}

/// An account's credential table as the wire serves it (AUTH-6.18).
///
/// Both lists are in fingerprint order. A keyless account — every unseeded
/// account, at every depth (AUTH-6.19) — answers two empty lists.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct KeySet {
    /// The answer's `as_of`: the position the set was read at.
    pub as_of: u64,
    /// The enrolled entries, in the order served.
    pub enrolled: Vec<EnrolledKey>,
    /// The retired entries, in the order served.
    pub retired: Vec<RetiredKey>,
}

impl KeySet {
    /// Returns whether both lists are empty.
    ///
    /// An empty set is the by-reference account's answer.
    pub fn is_empty(&self) -> bool {
        self.enrolled.is_empty() && self.retired.is_empty()
    }

    /// Returns the enrolled entry for `fp`, where one stands.
    pub fn enrolled(&self, fp: &Fingerprint) -> Option<&EnrolledKey> {
        self.enrolled.iter().find(|e| &e.fingerprint == fp)
    }

    /// Returns the retired entry for `fp`, where one stands.
    pub fn retired(&self, fp: &Fingerprint) -> Option<&RetiredKey> {
        self.retired.iter().find(|e| &e.fingerprint == fp)
    }

    /// Returns whether any enrolled entry carries the anchor flag.
    ///
    /// It is AUTH-5.16's test.
    pub fn has_anchor(&self) -> bool {
        self.enrolled.iter().any(|e| e.anchor)
    }
}

/// `key_set`'s answer: the set, or `not_an_account` (AUTH-6.19).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeySetAnswer {
    /// The account's credential table.
    Set(KeySet),
    /// The `not_an_account` refusal: the address names no account.
    NotAnAccount,
}

/// `effective_owner`'s pair (AUTH-6.37).
///
/// It holds the longest registered prefix containing the address and the
/// principal seated there; the address is an allocated seat iff `prefix`
/// equals it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Owner {
    /// The longest registered prefix containing the address.
    pub prefix: String,
    /// The principal seated at `prefix`.
    pub principal: u64,
}

/// One board, as this client addresses it.
///
/// Its two origins are read through [`Board::dialed`] and [`Board::signed`]
/// and fixed where it is made — by [`Board::new`] and
/// [`Board::signing_for`] — so no caller moves the dialed origin under
/// `H.1`'s pair, which is cached for the board at that origin: a term
/// carried to another board would sign every record frame wrong.
pub struct Board {
    /// The origin this client dials.
    dialed: Origin,
    /// The origin this client signs for this board (AUTH-4.8).
    ///
    /// It is the dialed one for every direct client; the configured override
    /// at a frontend's own dual-bound node.
    signed: Origin,
    dialer: Box<dyn Dialer>,
    /// `H.1`'s pair, read once per board and cached for good.
    ///
    /// It is set only once the board answers one.
    term: OnceLock<BoardTerm>,
}

impl fmt::Debug for Board {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Board(dialed {}, signed {})", self.dialed, self.signed)
    }
}

/// A rejection's `site` (wire.md §Rejections): where in the request the
/// refusal is about, each member where the code carries it.
///
/// `addr` names a document or a member — `withheld`'s origin, `not_owner`'s
/// `doc`, draft or account, `already_published`'s member; `index` an entry
/// in a list — a `runs` entry at `kept_place_moved` and
/// `stray_place_unrecorded`, a deposit's entry in its own list at the six
/// deposit tokens; `fault` a code's own sub-token where one rides. Empty
/// where the code carries no site.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Site {
    /// `site.addr`.
    pub addr: Option<String>,
    /// `site.index`.
    pub index: Option<u64>,
    /// `site.fault`.
    pub fault: Option<String>,
}

/// A `rejected` document, decoded (wire.md §Rejections).
///
/// Its parts are read through [`Rejection::key`], the one token a walk
/// dispatches on, [`Rejection::site`], where the code names a site, and are
/// otherwise rendered whole — [`Rejection::token`] for a face,
/// [`Rejection::refused`] for surfacing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rejection {
    code: String,
    detail: Option<String>,
    op: Option<String>,
    site: Site,
}

impl Rejection {
    /// Returns the `rejected` document's parts, where the document is one.
    pub fn of(v: &Value) -> Option<Rejection> {
        if v["resp"].as_str() != Some("rejected") {
            return None;
        }
        Some(Rejection {
            code: v["code"].as_str().unwrap_or("?").to_string(),
            detail: v["detail"].as_str().map(str::to_string),
            op: v["op"].as_str().map(str::to_string),
            site: Site {
                addr: v["site"]["addr"].as_str().map(str::to_string),
                index: v["site"]["index"].as_u64(),
                fault: v["site"]["fault"].as_str().map(str::to_string),
            },
        })
    }

    /// Returns the `code`.
    pub fn code(&self) -> &str {
        &self.code
    }

    /// Returns the `detail`, where one rode.
    pub fn detail(&self) -> Option<&str> {
        self.detail.as_deref()
    }

    /// Returns the `op` the rejection answers, where the document names one.
    pub fn op(&self) -> Option<&str> {
        self.op.as_deref()
    }

    /// Returns the `site`, empty where the code carries none.
    pub fn site(&self) -> &Site {
        &self.site
    }

    /// Returns the one token a walk dispatches on.
    ///
    /// wire.md §Rejections: "key client behavior on the token, never on
    /// prose". The token is the `detail` of the two families that carry a
    /// machine token there — `credential_refused`, `registry_refused` — and
    /// the `code` itself everywhere else, whose `detail`, where one rides, is
    /// prose.
    pub fn key(&self) -> &str {
        match (self.code.as_str(), self.detail.as_deref()) {
            ("credential_refused" | "registry_refused", Some(d)) => d,
            (code, _) => code,
        }
    }

    /// Returns the `code:detail` token.
    pub fn token(&self) -> String {
        match &self.detail {
            Some(d) => format!("{}:{d}", self.code),
            None => self.code.clone(),
        }
    }

    /// Returns the refusal as the family's `Refused` member.
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

/// Returns a non-200 transport refusal as the family's `Refused` member.
///
/// The refusal's body is `{"error": "<name>", "detail": …?}`.
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

/// Returns a write ack's `at`, where the document is an ack.
pub fn acked_at(v: &Value) -> Option<u64> {
    matches!(v["resp"].as_str(), Some("ack" | "ack_addr" | "ack_edit")).then(|| v["at"].as_u64()).flatten()
}

/// Returns an `ack_addr`'s minted address.
pub fn acked_addr(v: &Value) -> Option<&str> {
    (v["resp"].as_str() == Some("ack_addr")).then(|| v["addr"].as_str()).flatten()
}

impl Board {
    /// Returns a board dialed and signed at one origin.
    ///
    /// It is the `skep` command's shape: `session_open` frames the origin the
    /// dialer dials. The dialer is any [`Dialer`] — an `Arc<dyn Dialer>` a
    /// shell shares with `resolve`'s transport is one, so one dialer serves
    /// both.
    pub fn new(dialed: Origin, dialer: impl Dialer + 'static) -> Board {
        Board { signed: dialed.clone(), dialed, dialer: Box::new(dialer), term: OnceLock::new() }
    }

    /// Returns the board signed for `signed`, still dialed at its own origin.
    ///
    /// It is the frontend's shell at its own dual-bound node (AUTH-4.57 (a)'s
    /// client half; §7): `Board::new(dialed, dialer).signing_for(signed)`,
    /// each origin named by the call that sets it, so the two cannot trade
    /// places.
    pub fn signing_for(mut self, signed: Origin) -> Board {
        self.signed = signed;
        self
    }

    /// Returns the origin this client dials.
    pub fn dialed(&self) -> &Origin {
        &self.dialed
    }

    /// Returns the origin this client signs for this board (AUTH-4.8).
    ///
    /// It is the dialed one for every direct client; the configured override
    /// at a frontend's own dual-bound node.
    pub fn signed(&self) -> &Origin {
        &self.signed
    }

    /// Returns the one dialer.
    ///
    /// It is for an embedder's own calls over the same transport.
    pub fn dialer(&self) -> &dyn Dialer {
        &*self.dialer
    }

    /// Makes one exchange through the dialer at the dialed origin.
    ///
    /// # Errors
    ///
    /// [`Halt::Dial`] where the dialer fails.
    pub fn exchange(&self, req: &Request) -> Result<Response, Halt> {
        Ok(self.dialer.exchange(&self.dialed, req)?)
    }

    /// Makes one authenticated exchange (P28).
    ///
    /// The token rides in `Skepd-Session` where one rides, the request is
    /// dialed, and the death signal on the answer's head is returned as
    /// [`Authed::Closed`] — the one reader of it beside
    /// [`Board::session_close`].
    ///
    /// # Errors
    ///
    /// [`Halt::Dial`] where the dialer fails.
    pub fn authed(&self, token: Option<&Token>, req: Request) -> Result<Authed, Halt> {
        let req = match token {
            Some(t) => req.header("Skepd-Session", t.as_str()),
            None => req,
        };
        let resp = self.exchange(&req)?;
        Ok(if resp.session_closed() { Authed::Closed(resp) } else { Authed::Response(resp) })
    }

    /// Reads `GET /health` (AUTH-6.13), the body whole.
    ///
    /// # Errors
    ///
    /// A status other than `200` is the board's refusal, [`Halt::Refused`];
    /// a dial that fails or a body that is not JSON is [`Halt::Dial`].
    pub fn health(&self) -> Result<Health, Halt> {
        let resp = self.exchange(&Request::get("/health"))?;
        if resp.status != 200 {
            return Err(transport_refused(&resp));
        }
        let body = json_of(&resp)?;
        Ok(Health { body, raw: resp.body })
    }

    /// Reads `GET /challenge?principal=n` (wire.md §Sessions).
    ///
    /// The nonce and `ttl_ms` are read off the body.
    ///
    /// # Errors
    ///
    /// A body missing either — or carrying an empty nonce or a TTL of zero —
    /// is no challenge this client signs: the face names which member is
    /// missing, and no nonce is spent on it. A status other than `200` is the
    /// board's refusal, [`Halt::Refused`]; a dial that fails or a body that is
    /// not JSON is [`Halt::Dial`].
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

    /// Opens a session: `POST /session` (AUTH-6.2).
    ///
    /// The body is the bare body, or the signed body over the signed origin
    /// — `origin` is `self.signed`, never a string the caller supplies
    /// (AUTH-4.8).
    ///
    /// # Errors
    ///
    /// A `400 malformed_session_request` is this client's own framing,
    /// surfaced as the board's refusal (§2.3's exit 1), as is every status
    /// other than `200`, `401` and a `403 prefix_blocked`. A `200` carrying no
    /// session token, a body that is not JSON or a dial that fails is
    /// [`Halt::Dial`].
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

    /// Closes a session: `POST /session/close` (AUTH-4.47).
    ///
    /// The `204` is idempotent; the death signal on it says the token was
    /// already dead.
    ///
    /// # Errors
    ///
    /// A status other than `204` is the board's refusal, [`Halt::Refused`];
    /// a dial that fails is [`Halt::Dial`].
    pub fn session_close(&self, token: &Token) -> Result<CloseAnswer, Halt> {
        let resp = self.exchange(&Request::post("/session/close", Vec::new()).header("Skepd-Session", token.as_str()))?;
        if resp.status != 204 {
            return Err(transport_refused(&resp));
        }
        Ok(CloseAnswer { already_dead: resp.session_closed() })
    }

    /// Sends `POST /op` — one frame in, one response document out.
    ///
    /// The status is 200 whenever the daemon produced one, a rejection
    /// included.
    ///
    /// # Errors
    ///
    /// A non-200 is a transport refusal, the family's `Refused`; a dial that
    /// fails or a body that is not JSON is [`Halt::Dial`].
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

    /// Makes a guest read — one frame presenting no token.
    ///
    /// The read is answered as its response document, a rejection included.
    ///
    /// # Errors
    ///
    /// The death signal, which no tokenless request can meet, halts here
    /// (the module's doc); otherwise [`Board::op`]'s errors.
    pub fn guest(&self, frame: &Value) -> Result<Value, Halt> {
        match self.op(None, frame)? {
            Answer::Closed => Err(guest_closed()),
            Answer::Document(v) => Ok(v),
        }
    }

    /// Makes a guest read whose answer must be a document, not a rejection.
    ///
    /// It is the registry reads' shape.
    ///
    /// # Errors
    ///
    /// A rejection is the board's refusal; otherwise [`Board::guest`]'s
    /// errors.
    fn read(&self, frame: &Value) -> Result<Value, Halt> {
        let v = self.guest(frame)?;
        match Rejection::of(&v) {
            Some(r) => Err(r.refused(&v)),
            None => Ok(v),
        }
    }

    /// Sends `POST /op-at` — one read frame answered as of `at`.
    ///
    /// The position faults and the reconstruction bound are answers of this
    /// read, never exits (wire.md §Reading history).
    ///
    /// # Errors
    ///
    /// A token-free read halts on the death signal (the module's doc). Any
    /// other status or `error` is a transport refusal, [`Halt::Refused`]; a
    /// dial that fails or a `200` body that is not JSON is [`Halt::Dial`].
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

    /// Reads the `key` of the row at `at` — the one `/changes` point query.
    ///
    /// The query (`client.md` §1.1) is read as a guest — the credential rows
    /// live in a published doc 1 — for an unsigned record alone (AUTH-6.15).
    ///
    /// # Errors
    ///
    /// It presents no token, so the death signal on its answer is a fault of
    /// the board or the transport (the module's doc), a halt. A status other
    /// than `200` and `410 history_reclaimed` is a transport refusal,
    /// [`Halt::Refused`]; a dial that fails is [`Halt::Dial`].
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

    /// Reads one page of the feed from `since` (wire.md §The change feed).
    ///
    /// It is the `/changes` page read (`client.md` §4e.2), under the
    /// narrowings the query names, as a guest where no token rides — the
    /// published feed — or at the presented session's class — the
    /// supplement's `drafts=true` page. The feed consumer behind the `search`
    /// feature and the merge's feed walk behind `merge` are this read's
    /// callers in this crate; `changes_key` above stays the fence's one point
    /// query. The retention floor and the page budget's refusal are answers.
    ///
    /// # Errors
    ///
    /// A token-free read halts on the death signal (the module's doc). Every
    /// answer moves its reader on, or is no answer the wire gives (§The
    /// change feed, Paging): a page's `last` is never below `since` and
    /// passes it wherever `more` stands, and a `fits` is a limit of at least
    /// one row below the one asked — so a reader re-asking as each answer
    /// says advances or shrinks every time; an answer that does not is
    /// [`Halt::Dial`], as are a dial that fails and a `200` body that is not
    /// JSON. Any other status or `error` is a transport refusal,
    /// [`Halt::Refused`].
    pub fn changes(&self, token: Option<&Token>, query: &ChangesQuery<'_>) -> Result<ChangesAnswer, Halt> {
        let req = Request::get(query.path());
        let off_the_wire = |what: String| Halt::Dial(crate::dial::DialError::Response(format!("not a `/changes` answer: {what}")));
        match self.authed(token, req)? {
            Authed::Closed(_) if token.is_none() => Err(guest_closed()),
            Authed::Closed(_) => Ok(ChangesAnswer::Closed),
            Authed::Response(resp) => {
                let v: Value = serde_json::from_slice(&resp.body).unwrap_or(Value::Null);
                match (resp.status, v["error"].as_str()) {
                    (200, _) => {
                        let v = json_of(&resp)?;
                        let changes = v["changes"].as_array().cloned().unwrap_or_default();
                        let last = v["last"].as_u64().unwrap_or(query.since);
                        let more = v["more"].as_bool().unwrap_or(false);
                        if last < query.since || (more && last <= query.since) {
                            return Err(off_the_wire(format!("a page from {} whose `last` is {last} with `more` {more}", query.since)));
                        }
                        Ok(ChangesAnswer::Page(ChangesPage { changes, last, more }))
                    }
                    (410, Some("history_reclaimed")) => Ok(ChangesAnswer::HistoryReclaimed { floor: v["floor"].as_u64() }),
                    (400, Some("malformed_changes")) if v["fits"].as_u64().is_some() => {
                        let fits = v["fits"].as_u64().unwrap_or(0);
                        let asked = query.limit.unwrap_or(DEFAULT_CHANGES_LIMIT);
                        if fits == 0 || fits >= asked {
                            return Err(off_the_wire(format!("a `fits` of {fits} for a page of {asked}")));
                        }
                        Ok(ChangesAnswer::TooLarge { fits })
                    }
                    _ => Err(transport_refused(&resp)),
                }
            }
        }
    }

    /// Reads `GET /chain?at=<position>` (wire.md §Reading history).
    ///
    /// The answer is the commit chain's value as of `at`, recomputed by the
    /// kernel off its own journal under one of the board's two reconstruction
    /// permits — token-blind and class-invariant, so no token rides. The
    /// resume check a saved `(position, chain)` pair is judged by
    /// (`client.md` §4e.3; `search.md` §5.4) is this read's caller; the
    /// judgment is the embedder's, the position faults and the bound its
    /// answers.
    ///
    /// # Errors
    ///
    /// A `200` whose body is not JSON or carries no 32-byte `chain`, and a
    /// dial that fails, are [`Halt::Dial`]; any other status or `error` is a
    /// transport refusal, [`Halt::Refused`].
    pub fn chain_at(&self, at: u64) -> Result<ChainAtAnswer, Halt> {
        let resp = self.exchange(&Request::get(format!("/chain?at={at}")))?;
        let v: Value = serde_json::from_slice(&resp.body).unwrap_or(Value::Null);
        match (resp.status, v["error"].as_str()) {
            (200, _) => {
                let v = json_of(&resp)?;
                let chain = v["chain"].as_str().and_then(crate::hex::decode32).ok_or_else(|| {
                    Halt::Dial(crate::dial::DialError::Response(format!("not a chain answer: {v}")))
                })?;
                Ok(ChainAtAnswer::Chain { at: v["at"].as_u64().unwrap_or(at), chain })
            }
            (410, Some("history_reclaimed")) => Ok(ChainAtAnswer::HistoryReclaimed { floor: v["floor"].as_u64() }),
            (400, Some("beyond_head")) => Ok(ChainAtAnswer::BeyondHead { head: v["head"].as_u64() }),
            (400, Some("not_a_position")) => Ok(ChainAtAnswer::NotAPosition { nearest: v["nearest"].as_u64() }),
            (503, Some("history_busy")) => Ok(ChainAtAnswer::Busy),
            _ => Err(transport_refused(&resp)),
        }
    }

    /// Reads `principal_prefix(n)` — the principal's account address.
    ///
    /// The answer is `None` for an unknown principal (wire.md §Namespace;
    /// AUTH-5.67 (2): the address is derived, never configured).
    ///
    /// # Errors
    ///
    /// A rejection is the board's refusal; otherwise [`Board::guest`]'s
    /// errors.
    pub fn principal_prefix(&self, principal: u64) -> Result<Option<String>, Halt> {
        let v = self.read(&frames::principal_prefix(principal))?;
        Ok(v["addr"].as_str().map(str::to_string))
    }

    /// Reads `next_account_prefix(parent)` — the next delegable prefix.
    ///
    /// The answer is `None` for an ineligible parent.
    ///
    /// # Errors
    ///
    /// A rejection is the board's refusal; otherwise [`Board::guest`]'s
    /// errors.
    pub fn next_account_prefix(&self, parent: &str) -> Result<Option<String>, Halt> {
        let v = self.read(&frames::next_account_prefix(parent))?;
        Ok(v["addr"].as_str().map(str::to_string))
    }

    /// Reads `effective_owner(addr)` (AUTH-6.37).
    ///
    /// The answer is the pair, or `None` where either member is null — the
    /// wire answers the two null together.
    ///
    /// # Errors
    ///
    /// A rejection is the board's refusal; otherwise [`Board::guest`]'s
    /// errors.
    pub fn effective_owner(&self, addr: &str) -> Result<Option<Owner>, Halt> {
        let v = self.read(&frames::effective_owner(addr))?;
        match (v["prefix"].as_str(), v["principal"].as_u64()) {
            (Some(prefix), Some(principal)) => Ok(Some(Owner { prefix: prefix.to_string(), principal })),
            _ => Ok(None),
        }
    }

    /// Reads `key_set(account)` (AUTH-6.18) at the head.
    ///
    /// The set, or `not_an_account` (AUTH-6.19), comes back as an answer.
    ///
    /// # Errors
    ///
    /// Another rejection is the board's refusal; an answer that is no
    /// well-formed `key_set`, or one whose fingerprint disagrees with its
    /// key, is [`Halt::Dial`]; otherwise [`Board::guest`]'s errors.
    pub fn key_set(&self, account: &str) -> Result<KeySetAnswer, Halt> {
        key_set_of(&self.guest(&frames::key_set(account))?)
    }

    /// Reads `key_set(account)` as of `at` (AUTH-2.94's base read, P12).
    ///
    /// # Errors
    ///
    /// [`Board::op_at`]'s errors, and the document refusals
    /// [`Board::key_set`] names.
    pub fn key_set_at(&self, account: &str, at: u64) -> Result<Option<KeySetAnswer>, Halt> {
        match self.op_at(None, at, &frames::key_set(account))? {
            AtAnswer::Document(v) => key_set_of(&v).map(Some),
            _ => Ok(None),
        }
    }

    /// Returns the board term — `H.1`'s `(position, chain)` pair.
    ///
    /// The pair (signed-ops D13) is read once per board by `retrieve_v` on
    /// the pinned first member of the head document (wire.md §The other
    /// endpoints) and parsed off the `skep-head` record; `None` while the
    /// board has no `H.1` (unclaimed, or the one write after a refused head).
    /// It is the one per-board content read the fence admits.
    ///
    /// # Errors
    ///
    /// [`Board::guest`]'s errors.
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

/// Returns the halt for the death signal on a request that presented no token.
///
/// It is no session's answer, so a fault of the board or the transport
/// (wire.md §Sessions).
pub(crate) fn guest_closed() -> Halt {
    Halt::face(
        "a token-free read met the death signal",
        "the board answered `Skepd-Session: closed` to a request that presented no token",
        "this is a fault in the board or the transport, not in your keys; nothing was written",
    )
}

/// Decodes a `key_set` document (AUTH-6.18), or `not_an_account`.
///
/// # Errors
///
/// Another rejection is the board's refusal; a document that is no
/// well-formed `key_set` answer, or one whose fingerprint disagrees with its
/// key, is [`Halt::Dial`].
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
