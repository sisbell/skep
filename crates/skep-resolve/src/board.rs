//! THE TYPED READS the resolver makes of a board ([`Board`]), over any
//! [`Transport`] — the HTTP client the crate ships, or a suite's replay of a
//! recorded feed: the feed's pages (wire.md §The change feed), `/op`, `/op-at`
//! (wire.md §Reading history) and `/chain`, each read COUNTED by kind
//! ([`Reads`]), since what a resolve costs is one of the numbers this crate
//! exists to report.
//!
//! THE VALUES THE RESOLVER TAKES ON THE BOARD'S WORD — answers no check
//! after them re-derives — are typed here, each where the wire spells it:
//! the live head pair off `/health` ([`Board::head_pair`]), the board term
//! off `H.1` ([`Board::board_term`]), a stored link's three slots
//! ([`Board::link_slots`]), an account's key set live and as of a position
//! ([`Board::key_set`], [`Board::key_set_at`]), and whether a retraction
//! stands ([`Board::retraction_stands`]). What each caller makes of them —
//! the copy's chain pair, the verdict's frame, the table a record is judged
//! under — is the caller's. The feed's rows are checked by the base's
//! provenance and a record's bytes by the verify, so the reads that only
//! locate those bytes (the span set, `image`, `retrieve_v`) stay with their
//! callers.
//!
//! The wire's spellings that both readers of the board — the mirror and the
//! guest-reading resolve — read alike are stated here, once: a unit span;
//! the span-set, `image` and one-position `retrieve_v` frames; a span-set
//! answer's content extent; an `image` answer's runs, read whole or not at
//! all, and an atom's V-ordinal among them; and a content element's ordinal
//! in its own document, the append-only guess's position.

use std::cell::Cell;
use std::fmt;
use std::sync::LazyLock;
use std::thread;
use std::time::Duration;

use serde_json::{json, Value};
use skep_address::{document_of, Address, Nat};
use skep_identity::{BoardTerm, Enrolled, PublicKey};

use crate::http::{Transport, TransportError};
use crate::parse_address;

/// How often a `history_busy` or `scan_busy` answer is retried before the
/// read is given up — a retry-class refusal, never a queue (wire.md §Reading
/// history), so the client is the one that waits.
const BUSY_RETRIES: u32 = 200;

/// The pause between two busy retries.
const BUSY_PAUSE: Duration = Duration::from_millis(25);

/// The retraction class's reserved ghost tumbler, the type slot of the link
/// a `nullify` deposits (wire.md §Links (writes)).
static RETRACTION_TYPE: LazyLock<Address> =
    LazyLock::new(|| parse_address("1.1.0.1.0.1.0.1.5").expect("the retraction class's ghost tumbler"));

/// `H.1`'s address — the head document's first chain member, the board
/// term's carrier (wire.md §The other endpoints).
static HEAD_MEMBER_1: LazyLock<Address> =
    LazyLock::new(|| parse_address("1.1.0.1.0.2.1").expect("the head document's first member"));

/// THE COUNT OF EVERY READ a board was asked, by kind — the fetch count a
/// resolve's cost is stated in (the investigation §3.1). Reads over `/op-at`
/// are counted under their own kind AND under `op_at`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Reads {
    pub changes: u64,
    pub health: u64,
    pub chain: u64,
    pub read_link: u64,
    pub retrieve: u64,
    pub image: u64,
    pub span_set: u64,
    pub key_set: u64,
    pub find_links: u64,
    pub other: u64,
    pub op_at: u64,
    pub busy_retries: u64,
}

impl Reads {
    /// Every request made (the busy retries not among them: each is a
    /// repeat of one request already counted).
    pub fn total(&self) -> u64 {
        self.changes
            + self.health
            + self.chain
            + self.read_link
            + self.retrieve
            + self.image
            + self.span_set
            + self.key_set
            + self.find_links
            + self.other
    }

    fn count_op(&mut self, op: &str) {
        match op {
            "read_link" => self.read_link += 1,
            "retrieve_v" => self.retrieve += 1,
            "image" => self.image += 1,
            "retrieve_doc_v_span_set" => self.span_set += 1,
            "key_set" => self.key_set += 1,
            "find_links_ftt" | "window_ftt" | "find_links_v" => self.find_links += 1,
            _ => self.other += 1,
        }
    }
}

/// Why a typed read could not be answered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BoardError {
    /// The board was not reached.
    Transport(TransportError),
    /// A status outside the read's shape, with the body.
    Status { status: u16, body: String },
    /// A 200 whose body is not the shape the read expects.
    Malformed(String),
    /// A `rejected` answer: the op, its code and its detail.
    Rejected { op: String, code: String, detail: Option<String> },
    /// `history_busy` or `scan_busy` past the retries.
    Busy,
    /// The feed refused a page past its byte budget, naming the limit that
    /// fits (wire.md §The change feed, Paging).
    PageTooLarge { fits: usize },
    /// The feed's memory does not reach `since` (`history_reclaimed`).
    Reclaimed { floor: Option<u64> },
}

impl fmt::Display for BoardError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BoardError::Transport(e) => write!(f, "{e}"),
            BoardError::Status { status, body } => write!(f, "status {status}: {body}"),
            BoardError::Malformed(what) => write!(f, "malformed answer: {what}"),
            BoardError::Rejected { op, code, detail } => match detail {
                Some(d) => write!(f, "{op} rejected {code}:{d}"),
                None => write!(f, "{op} rejected {code}"),
            },
            BoardError::Busy => f.write_str("the board stayed busy past the retries"),
            BoardError::PageTooLarge { fits } => write!(f, "the page passes the byte budget; {fits} rows fit"),
            BoardError::Reclaimed { floor } => write!(f, "history reclaimed below {floor:?}"),
        }
    }
}

impl std::error::Error for BoardError {}

impl From<TransportError> for BoardError {
    fn from(e: TransportError) -> BoardError {
        BoardError::Transport(e)
    }
}

/// An account's key set as `key_set` answers it (wire.md §Identity reads).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct KeySetAnswer {
    /// The position the table answers as of — the live read's snapshot;
    /// `None` where the answer names none.
    pub(crate) as_of: Option<u64>,
    /// Every enrolled key: the whole table. An answer with an entry this
    /// build cannot read is no answer — never a smaller table, never an
    /// empty one.
    pub(crate) enrolled: Vec<Enrolled>,
}

/// One page of the feed (wire.md §The change feed).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Page {
    /// The entries, oldest first, each as served.
    pub rows: Vec<Value>,
    /// The final entry's position, or `since` echoed when empty.
    pub last: u64,
    /// Whether positions remain past `last`.
    pub more: bool,
    /// The page body's bytes.
    pub bytes: u64,
}

/// A board as the resolver reads it: the typed reads over one
/// [`Transport`], counted.
pub struct Board {
    transport: Box<dyn Transport>,
    reads: Cell<Reads>,
    feed_bytes: Cell<u64>,
}

impl Board {
    pub fn new(transport: Box<dyn Transport>) -> Board {
        Board { transport, reads: Cell::new(Reads::default()), feed_bytes: Cell::new(0) }
    }

    /// Every read made so far, by kind.
    pub fn reads(&self) -> Reads {
        self.reads.get()
    }

    /// The bytes of every feed page read so far.
    pub fn feed_bytes(&self) -> u64 {
        self.feed_bytes.get()
    }

    fn bump(&self, f: impl FnOnce(&mut Reads)) {
        let mut r = self.reads.get();
        f(&mut r);
        self.reads.set(r);
    }

    fn json(body: &[u8]) -> Result<Value, BoardError> {
        serde_json::from_slice(body)
            .map_err(|e| BoardError::Malformed(format!("{e}: {}", String::from_utf8_lossy(body))))
    }

    /// `GET /health`: the board's live pair and auth object.
    pub fn health(&self) -> Result<Value, BoardError> {
        self.bump(|r| r.health += 1);
        let (st, body) = self.transport.exchange("GET", "/health", b"")?;
        if st != 200 {
            return Err(BoardError::Status { status: st, body: String::from_utf8_lossy(&body).into_owned() });
        }
        Board::json(&body)
    }

    /// `GET /changes?since=N[&limit=L]` as the guest: one page.
    pub fn changes(&self, since: u64, limit: Option<usize>) -> Result<Page, BoardError> {
        self.bump(|r| r.changes += 1);
        let path = match limit {
            Some(l) => format!("/changes?since={since}&limit={l}"),
            None => format!("/changes?since={since}"),
        };
        let (st, body) = self.transport.exchange("GET", &path, b"")?;
        let text = || String::from_utf8_lossy(&body).into_owned();
        match st {
            200 => {}
            400 => {
                let v = Board::json(&body)?;
                if let Some(fits) = v["fits"].as_u64() {
                    return Err(BoardError::PageTooLarge { fits: fits as usize });
                }
                return Err(BoardError::Status { status: st, body: text() });
            }
            410 => {
                let v = Board::json(&body)?;
                return Err(BoardError::Reclaimed { floor: v["floor"].as_u64() });
            }
            _ => return Err(BoardError::Status { status: st, body: text() }),
        }
        self.feed_bytes.set(self.feed_bytes.get() + body.len() as u64);
        let v = Board::json(&body)?;
        let rows = v["changes"].as_array().cloned().ok_or_else(|| BoardError::Malformed("no changes".into()))?;
        let last = v["last"].as_u64().ok_or_else(|| BoardError::Malformed("no last".into()))?;
        let more = v["more"].as_bool().ok_or_else(|| BoardError::Malformed("no more".into()))?;
        Ok(Page { rows, last, more, bytes: body.len() as u64 })
    }

    /// `POST /op` as the guest: the answer as served, a `rejected` included
    /// (a caller that cannot take one asks [`Board::op_ok`]).
    pub fn op(&self, frame: &Value) -> Result<Value, BoardError> {
        let op = frame["op"].as_str().unwrap_or("").to_string();
        self.bump(|r| r.count_op(&op));
        self.post_json("/op", &frame.to_string(), &op)
    }

    /// [`Board::op`], a `rejected` answer an error.
    pub fn op_ok(&self, frame: &Value) -> Result<Value, BoardError> {
        let v = self.op(frame)?;
        Board::not_rejected(v)
    }

    /// `POST /op-at` as the guest: `frame` answered AS OF `at` (wire.md
    /// §Reading history), `history_busy` retried.
    pub fn op_at(&self, at: u64, frame: &Value) -> Result<Value, BoardError> {
        let op = frame["op"].as_str().unwrap_or("").to_string();
        self.bump(|r| {
            r.count_op(&op);
            r.op_at += 1;
        });
        let body = format!(r#"{{"at":{at},"frame":{frame}}}"#);
        self.post_json("/op-at", &body, &op)
    }

    fn not_rejected(v: Value) -> Result<Value, BoardError> {
        if v["resp"].as_str() == Some("rejected") {
            return Err(BoardError::Rejected {
                op: v["op"].as_str().unwrap_or("").to_string(),
                code: v["code"].as_str().unwrap_or("").to_string(),
                detail: v["detail"].as_str().map(str::to_string),
            });
        }
        Ok(v)
    }

    /// One POST of a JSON body, the busy refusals retried.
    fn post_json(&self, path: &str, body: &str, op: &str) -> Result<Value, BoardError> {
        let mut tries = 0;
        loop {
            let (st, answer) = self.transport.exchange("POST", path, body.as_bytes())?;
            let text = || String::from_utf8_lossy(&answer).into_owned();
            match st {
                200 => return Board::json(&answer),
                410 => {
                    let v = Board::json(&answer)?;
                    return Err(BoardError::Reclaimed { floor: v["floor"].as_u64() });
                }
                503 => {
                    let busy = text().contains("history_busy") || text().contains("scan_busy");
                    if busy && tries < BUSY_RETRIES {
                        tries += 1;
                        self.bump(|r| r.busy_retries += 1);
                        thread::sleep(BUSY_PAUSE);
                        continue;
                    }
                    return Err(if busy { BoardError::Busy } else { BoardError::Status { status: st, body: text() } });
                }
                _ => {
                    return Err(BoardError::Status {
                        status: st,
                        body: format!("{op}: {}", text()),
                    })
                }
            }
        }
    }

    /// `GET /chain?at=N`: the commit chain's value as of `at`, recomputed by
    /// the board (wire.md §Reading history) — `(at, chain)`.
    pub fn chain_at(&self, at: u64) -> Result<(u64, [u8; 32]), BoardError> {
        self.bump(|r| r.chain += 1);
        let mut tries = 0;
        loop {
            let (st, body) = self.transport.exchange("GET", &format!("/chain?at={at}"), b"")?;
            let text = String::from_utf8_lossy(&body).into_owned();
            match st {
                200 => {
                    let v = Board::json(&body)?;
                    let at = v["at"].as_u64().ok_or_else(|| BoardError::Malformed("no at".into()))?;
                    let hex = v["chain"].as_str().ok_or_else(|| BoardError::Malformed("no chain".into()))?;
                    let chain = parse_chain(hex).ok_or_else(|| BoardError::Malformed(format!("chain {hex}")))?;
                    return Ok((at, chain));
                }
                503 if text.contains("history_busy") && tries < BUSY_RETRIES => {
                    tries += 1;
                    self.bump(|r| r.busy_retries += 1);
                    thread::sleep(BUSY_PAUSE);
                }
                503 if text.contains("history_busy") => return Err(BoardError::Busy),
                _ => return Err(BoardError::Status { status: st, body: text }),
            }
        }
    }

    /// Whether a retraction link targeting `link` stands — the `nullify`'s
    /// own deposit, found by its type and target (two slots constrained: no
    /// class scan).
    pub(crate) fn retraction_stands(&self, link: &Address) -> Result<bool, BoardError> {
        let v = self.op_ok(&json!({ "op": "find_links_ftt", "q": {
            "home": "any", "from": "any",
            "to": [unit_span_json(link)],
            "ty": [unit_span_json(&RETRACTION_TYPE)],
        }}))?;
        Ok(v["addrs"].as_array().is_some_and(|a| !a.is_empty()))
    }

    /// `/health`'s live pair (wire.md §The other endpoints): the committed
    /// head's position and its chain, read off one kernel snapshot — the
    /// chain as the board spelled it, where it is sixty-four hex characters;
    /// `None` where either member is absent or malformed.
    pub(crate) fn head_pair(&self) -> Result<Option<(u64, String)>, BoardError> {
        let health = self.health()?;
        let (Some(at), Some(chain)) = (health["log_position"].as_u64(), health["chain_head"].as_str()) else {
            return Ok(None);
        };
        Ok(parse_chain(chain).map(|_| (at, chain.to_string())))
    }

    /// THE BOARD TERM (D13): `H.1`'s committed pair, off `retrieve_v` at the
    /// pinned member's first position — the term, and its chain as the board
    /// spelled it; `None` where the board holds none.
    pub(crate) fn board_term(&self) -> Result<Option<(BoardTerm, String)>, BoardError> {
        let v = self.op(&retrieve_frame(&HEAD_MEMBER_1, 1))?;
        let Some(text) = v["items"].as_array().and_then(|i| i.first()).and_then(|i| i["atom"].as_str()) else {
            return Ok(None);
        };
        let Ok(record) = serde_json::from_str::<Value>(text) else { return Ok(None) };
        let (Some(position), Some(chain)) = (record["position"].as_u64(), record["chain"].as_str()) else {
            return Ok(None);
        };
        Ok(parse_chain(chain).map(|bytes| (BoardTerm { log_position: position, chain: bytes }, chain.to_string())))
    }

    /// A stored link's three slots off `read_link` — 0 the `from`, 1 the `to`,
    /// 2 the type — each as the addresses its spans start at; `None` where no
    /// link stands at `link`.
    pub(crate) fn link_slots(&self, link: &Address) -> Result<Option<[Vec<Address>; 3]>, BoardError> {
        let v = self.op_ok(&json!({ "op": "read_link", "a": link.to_string() }))?;
        if v["link"].is_null() {
            return Ok(None);
        }
        Ok(Some([link_slot(&v, 0), link_slot(&v, 1), link_slot(&v, 2)]))
    }

    /// `key_set` of `account`, live; `None` where the answer is no `key_set`
    /// this build can read whole.
    pub(crate) fn key_set(&self, account: &Address) -> Result<Option<KeySetAnswer>, BoardError> {
        Ok(key_set_answer(&self.op(&key_set_frame(account))?))
    }

    /// `key_set` of `account` AS OF `at` (wire.md §Reading history); `None`
    /// where the answer is no `key_set` this build can read whole, and a
    /// reclaimed position [`BoardError::Reclaimed`].
    pub(crate) fn key_set_at(&self, at: u64, account: &Address) -> Result<Option<KeySetAnswer>, BoardError> {
        Ok(key_set_answer(&self.op_at(at, &key_set_frame(account))?))
    }
}

/// The one-position `retrieve_v` frame: the atom at content ordinal `pos`
/// of `doc`.
pub(crate) fn retrieve_frame(doc: &Address, pos: u64) -> Value {
    json!({ "op": "retrieve_v", "specs": [{ "doc": doc.to_string(), "span": { "start": format!("1.{pos}"), "width": "0.1" } }] })
}

/// The `retrieve_doc_v_span_set` frame: `doc`'s V-span set, its content
/// extent among it ([`content_extent`]).
pub(crate) fn span_set_frame(doc: &Address) -> Value {
    json!({ "op": "retrieve_doc_v_span_set", "doc": doc.to_string() })
}

/// The `image` frame: the runs `width` content ordinals from ordinal `from`
/// of `doc` arrange ([`runs_of`]).
pub(crate) fn image_frame(doc: &Address, from: u64, width: u64) -> Value {
    json!({ "op": "image", "d": doc.to_string(), "region": [{ "start": format!("1.{from}"), "width": format!("0.{width}") }] })
}

fn key_set_frame(account: &Address) -> Value {
    json!({ "op": "key_set", "account": account.to_string() })
}

/// A `key_set` answer, where the answer is one this build reads WHOLE —
/// its `enrolled` present and every entry of it read, or no answer at all.
/// The wire sends the list on every answer, empty for a keyless account, so
/// an absent one is a malformed answer and never an empty table: an empty
/// table sends the set that opens an account to the account above it.
fn key_set_answer(v: &Value) -> Option<KeySetAnswer> {
    if v["resp"].as_str() != Some("key_set") {
        return None;
    }
    let enrolled = v["enrolled"].as_array()?.iter().map(enrolled_of).collect::<Option<Vec<_>>>()?;
    Some(KeySetAnswer { as_of: v["as_of"].as_u64(), enrolled })
}

/// Sixty-four lowercase hex characters as the chain's thirty-two bytes.
pub(crate) fn parse_chain(hex: &str) -> Option<[u8; 32]> {
    if hex.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).ok()?;
    }
    Some(out)
}

/// A unit subtree span over `a` as the wire spells one.
pub(crate) fn unit_span_json(a: &Address) -> Value {
    let span = skep_identity::unit_span(a);
    json!({ "start": span.start().to_string(), "width": span.width().to_string() })
}

/// Slot `i` of a `read_link` answer — 0 the `from`, 1 the `to`, 2 the type —
/// as the addresses its spans start at; empty where the slot is absent.
fn link_slot(answer: &Value, i: usize) -> Vec<Address> {
    answer["link"]["slots"][i]
        .as_array()
        .map(|spans| spans.iter().filter_map(|s| s["start"].as_str().and_then(parse_address)).collect())
        .unwrap_or_default()
}

/// A `retrieve_doc_v_span_set` answer's content extent — the width of its
/// span at `1.1` — where it carries one.
pub(crate) fn content_extent(answer: &Value) -> Option<u64> {
    answer["set"]
        .as_array()
        .and_then(|set| set.iter().find(|s| s["start"].as_str() == Some("1.1")))
        .and_then(|s| s["width"].as_str()?.strip_prefix("0.")?.parse::<u64>().ok())
}

/// An `image` answer's runs — each its I-start and its width, in V-order —
/// read WHOLE, or not at all: a run dropped would shift every later run's
/// V-ordinals, and a read at the shifted position fetches another atom.
pub(crate) fn runs_of(answer: &Value) -> Option<Vec<(Address, u64)>> {
    answer["runs"]
        .as_array()?
        .iter()
        .map(|r| Some((parse_address(r["i_start"].as_str()?)?, r["width"].as_str()?.parse::<u64>().ok()?)))
        .collect()
}

/// The V-ordinal `addr` sits at among an `image` answer's runs — each an
/// I-start and a width, in V-order from ordinal 1 — where a run holds it.
pub(crate) fn position_in(runs: &[(Address, u64)], addr: &Address) -> Option<u64> {
    let mut pos = 1u64;
    for (start, width) in runs {
        if let Some(k) = offset_within(start, addr, *width) {
            return Some(pos + k);
        }
        pos += width;
    }
    None
}

/// `addr`'s offset from `start` where it lies within a run of `width`
/// consecutive content ordinals from `start`, else `None`.
fn offset_within(start: &Address, addr: &Address, width: u64) -> Option<u64> {
    let s: Vec<&Nat> = start.tumbler().iter().collect();
    let a: Vec<&Nat> = addr.tumbler().iter().collect();
    if s.len() != a.len() || s[..s.len() - 1] != a[..a.len() - 1] {
        return None;
    }
    let (s_last, a_last) = (u64::try_from(s[s.len() - 1]).ok()?, u64::try_from(a[a.len() - 1]).ok()?);
    (a_last >= s_last && a_last - s_last < width).then(|| a_last - s_last)
}

/// Where `addr` is a content element of `home` itself — `home.0.1.n` — its
/// ordinal `n`: THE APPEND-ONLY GUESS's position, a doc 1 written only by
/// deposits arranging its content ordinal n at V-ordinal n. A link element,
/// a member's mint and another document's element have none.
pub(crate) fn content_ordinal_in(home: &Address, addr: &Address) -> Option<u64> {
    if document_of(addr)? != *home {
        return None;
    }
    let element = addr.element_field()?;
    if element.len() != 2 || element[0] != Nat::from(1u32) {
        return None;
    }
    u64::try_from(&element[1]).ok()
}

/// One `key_set` entry as an [`Enrolled`]: `alg`, `key` (hex), `anchor` —
/// the wire's spelling, read whole or not at all, by [`Board::key_set`] and
/// [`Board::key_set_at`] alone.
fn enrolled_of(e: &Value) -> Option<Enrolled> {
    let key = PublicKey::parse(e["alg"].as_str()?, e["key"].as_str()?).ok()?;
    Some(Enrolled { key, anchor: e["anchor"].as_bool()? })
}

#[cfg(test)]
mod tests {
    use skep_signature::{HybridSigner, TAG_MLDSA65_ED25519};

    use super::*;

    fn a(s: &str) -> Address {
        parse_address(s).unwrap()
    }

    /// A board that answers every exchange with one status and one body.
    struct Canned(u16, String);

    impl Transport for Canned {
        fn exchange(&self, _: &str, _: &str, _: &[u8]) -> Result<(u16, Vec<u8>), TransportError> {
            Ok((self.0, self.1.clone().into_bytes()))
        }
    }

    fn canned(body: Value) -> Board {
        Board::new(Box::new(Canned(200, body.to_string())))
    }

    #[test]
    fn chain_hex_parses_at_sixty_four_characters_alone() {
        assert!(parse_chain(&"ab".repeat(32)).is_some());
        assert!(parse_chain(&"ab".repeat(31)).is_none());
        assert!(parse_chain(&"zz".repeat(32)).is_none());
    }

    /// The values taken on the board's word are read where the wire spells
    /// them: the head pair only where its chain is a chain, the board term
    /// off `H.1`'s record with its chain as spelled, and a key set only where
    /// the answer is one this build reads whole — its `as_of` and every entry
    /// beside it; an entry of an algorithm this build holds no row for, an
    /// answer with no list, and an entry with no anchor flag are no table,
    /// never a smaller one and never an empty one.
    #[test]
    fn the_boards_word_is_typed_where_the_wire_spells_it() {
        let chain = "07".repeat(32);
        assert_eq!(canned(json!({ "log_position": 9, "chain_head": chain })).head_pair(), Ok(Some((9, chain.clone()))));
        assert_eq!(canned(json!({ "log_position": 9, "chain_head": "07" })).head_pair(), Ok(None), "no chain");
        assert_eq!(canned(json!({ "chain_head": chain })).head_pair(), Ok(None), "no position");
        let h1 = json!({ "position": 4, "chain": chain }).to_string();
        let term = canned(json!({ "resp": "delivery", "items": [{ "atom": h1 }] })).board_term().expect("read");
        assert_eq!(term, Some((BoardTerm { log_position: 4, chain: [7; 32] }, chain.clone())));
        assert_eq!(canned(json!({ "resp": "delivery", "items": [] })).board_term(), Ok(None), "no H.1");
        let key = HybridSigner::from_seed(TAG_MLDSA65_ED25519, &[3; 32]).expect("tag 1").public_key().clone();
        let entry = json!({ "alg": key.alg(), "key": key.to_hex(), "anchor": true });
        let answer = canned(json!({ "resp": "key_set", "as_of": 12, "enrolled": [entry] })).key_set(&a("1.0.2"));
        assert_eq!(answer, Ok(Some(KeySetAnswer { as_of: Some(12), enrolled: vec![Enrolled { key: key.clone(), anchor: true }] })));
        let refused = json!({ "resp": "rejected", "op": "key_set", "code": "no_such_account" });
        assert_eq!(canned(refused).key_set(&a("1.0.2")), Ok(None), "a refusal is no key set");
        let newer = json!({ "alg": "a-row-this-build-lacks", "key": key.to_hex(), "anchor": false });
        let partial = json!({ "resp": "key_set", "as_of": 12, "enrolled": [entry, newer] });
        assert_eq!(canned(partial).key_set(&a("1.0.2")), Ok(None), "an entry this build cannot read");
        assert_eq!(canned(json!({ "resp": "key_set", "as_of": 12 })).key_set(&a("1.0.2")), Ok(None), "no list");
        let unflagged = json!({ "alg": key.alg(), "key": key.to_hex() });
        let answer = json!({ "resp": "key_set", "as_of": 12, "enrolled": [unflagged] });
        assert_eq!(canned(answer).key_set(&a("1.0.2")), Ok(None), "an entry with no anchor flag");
        let keyless = json!({ "resp": "key_set", "as_of": 12, "enrolled": [] });
        assert_eq!(canned(keyless).key_set(&a("1.0.2")), Ok(Some(KeySetAnswer { as_of: Some(12), enrolled: Vec::new() })), "a keyless account");
        let link = json!({ "resp": "link", "link": { "slots": [[{ "start": "1.0.2.0.1.0.1.1", "width": "0.1" }], [], [{ "start": "1.0.2", "width": "0.1" }]] } });
        assert_eq!(canned(link).link_slots(&a("1.0.2.0.1.0.2.1")), Ok(Some([vec![a("1.0.2.0.1.0.1.1")], vec![], vec![a("1.0.2")]])));
        assert_eq!(canned(json!({ "resp": "link", "link": null })).link_slots(&a("1.0.2.0.1.0.2.1")), Ok(None), "no link stands");
    }

    /// The answers both readers of the board read alike: a link's slots, a
    /// document's content extent, an image's runs — whole or not at all —
    /// and an atom's V-ordinal among them, the runs taken in V-order, a gap
    /// between two runs no position; and a content element's ordinal in its
    /// own document, never a link element's nor a member's mint.
    #[test]
    fn the_shared_answers_read_one_way() {
        let link = json!({ "link": { "slots": [
            [{ "start": "1.0.1.0.1.0.1.4", "width": "0.1" }],
            [{ "start": "1.0.2", "width": "0.1" }, { "start": "not an address", "width": "0.1" }],
        ] } });
        assert_eq!(link_slot(&link, 0), [a("1.0.1.0.1.0.1.4")]);
        assert_eq!(link_slot(&link, 1), [a("1.0.2")], "a span that starts at no address is dropped");
        assert!(link_slot(&link, 2).is_empty(), "an absent slot is empty");
        let set = json!({ "set": [{ "start": "2.1", "width": "0.3" }, { "start": "1.1", "width": "0.7" }] });
        assert_eq!(content_extent(&set), Some(7));
        assert_eq!(content_extent(&json!({ "set": [{ "start": "2.1", "width": "0.3" }] })), None);
        let image = json!({ "resp": "runs", "runs": [
            { "i_start": "1.0.1.0.1.0.1.1", "width": "2" },
            { "i_start": "1.0.1.0.1.0.1.7", "width": "3" },
        ] });
        let runs = runs_of(&image).expect("every run reads");
        assert_eq!(runs, [(a("1.0.1.0.1.0.1.1"), 2), (a("1.0.1.0.1.0.1.7"), 3)]);
        assert_eq!(position_in(&runs, &a("1.0.1.0.1.0.1.2")), Some(2));
        assert_eq!(position_in(&runs, &a("1.0.1.0.1.0.1.8")), Some(4));
        assert_eq!(position_in(&runs, &a("1.0.1.0.1.0.1.3")), None);
        assert_eq!(position_in(&runs, &a("1.0.1.0.1.0.2.1")), None, "a link element");
        let torn = json!({ "resp": "runs", "runs": [
            { "i_start": "1.0.1.0.1.0.1.1", "width": "2" },
            { "i_start": "not an address", "width": "4" },
            { "i_start": "1.0.1.0.1.0.1.7", "width": "3" },
        ] });
        assert_eq!(runs_of(&torn), None, "a run that does not read would shift every run after it");
        assert_eq!(runs_of(&json!({ "resp": "rejected" })), None);
        assert_eq!(content_ordinal_in(&a("1.0.1.0.1"), &a("1.0.1.0.1.0.1.4")), Some(4));
        assert_eq!(content_ordinal_in(&a("1.0.1.0.1"), &a("1.0.1.0.1.0.2.4")), None, "a link element");
        assert_eq!(content_ordinal_in(&a("1.0.1.0.1"), &a("1.0.1.0.1.1.0.1.4")), None, "a member's mint");
        assert_eq!(content_ordinal_in(&a("1.0.1.0.1"), &a("1.0.2.0.1.0.1.4")), None, "another document's element");
    }
}
