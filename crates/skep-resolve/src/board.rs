//! THE TYPED READS the resolver makes of a board ([`Board`]), over any
//! [`Transport`] — the HTTP client the crate ships, or a suite's replay of a
//! recorded feed: the feed's pages (wire.md §The change feed), `/op`, `/op-at`
//! (wire.md §Reading history) and `/chain`, each read COUNTED by kind
//! ([`Reads`]), since what a resolve costs is one of the numbers this crate
//! exists to report.
//!
//! The wire's spellings that both readers of the board — the mirror and the
//! guest-reading resolve — read alike are stated here, once: a unit span,
//! the retraction query ([`Board::retraction_stands`]), a `read_link`
//! answer's slot, a span-set answer's content extent, an atom's V-ordinal
//! among an `image` answer's runs, and a `key_set` entry.

use std::cell::Cell;
use std::fmt;
use std::sync::LazyLock;
use std::thread;
use std::time::Duration;

use serde_json::{json, Value};
use skep_address::{Address, Nat};
use skep_identity::{Enrolled, PublicKey};

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

    /// [`Board::op_at`], a `rejected` answer an error.
    pub fn op_at_ok(&self, at: u64, frame: &Value) -> Result<Value, BoardError> {
        let v = self.op_at(at, frame)?;
        Board::not_rejected(v)
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
pub(crate) fn link_slot(answer: &Value, i: usize) -> Vec<Address> {
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

/// One `key_set` entry as an [`Enrolled`]: `alg`, `key` (hex), `anchor`.
pub(crate) fn enrolled_of(e: &Value) -> Option<Enrolled> {
    let key = PublicKey::parse(e["alg"].as_str()?, e["key"].as_str()?).ok()?;
    Some(Enrolled { key, anchor: e["anchor"].as_bool().unwrap_or(false) })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn a(s: &str) -> Address {
        parse_address(s).unwrap()
    }

    #[test]
    fn chain_hex_parses_at_sixty_four_characters_alone() {
        assert!(parse_chain(&"ab".repeat(32)).is_some());
        assert!(parse_chain(&"ab".repeat(31)).is_none());
        assert!(parse_chain(&"zz".repeat(32)).is_none());
    }

    /// The answers both readers of the board read alike: a link's slots, a
    /// document's content extent, and an atom's V-ordinal among the runs of
    /// an image — the runs taken in V-order, a gap between two runs no
    /// position.
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
        let runs = [(a("1.0.1.0.1.0.1.1"), 2), (a("1.0.1.0.1.0.1.7"), 3)];
        assert_eq!(position_in(&runs, &a("1.0.1.0.1.0.1.2")), Some(2));
        assert_eq!(position_in(&runs, &a("1.0.1.0.1.0.1.8")), Some(4));
        assert_eq!(position_in(&runs, &a("1.0.1.0.1.0.1.3")), None);
        assert_eq!(position_in(&runs, &a("1.0.1.0.1.0.2.1")), None, "a link element");
    }
}
