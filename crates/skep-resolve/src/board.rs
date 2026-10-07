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
//! off `H.1` ([`Board::board_term`]), a stored link's type and slots
//! ([`Board::link_slots`]), an account's key set live and as of a position
//! ([`Board::key_set`], [`Board::key_set_at`]), whether a deposit stands on
//! the board's active view ([`Board::stands_active`]), and the floor a
//! reclaimed read names ([`BoardError::Reclaimed`]). What each caller makes
//! of them — the copy's head pair, the verdict's frame, the table a record
//! is judged under — is the caller's. The feed's rows are checked by
//! the base's provenance and a record's bytes by the verify, so the reads
//! that only locate those bytes (the span set, `image`, `retrieve_v`) stay
//! with their callers.
//!
//! An answer is held to the shape the wire promises before any caller reads
//! it: a feed page whose entries do not rise past `since` — the feed's own
//! order ([`rises_past`]) — or whose `last` and `more` do not follow them, is
//! refused ([`Board::changes`]), so no row is held twice and no page asked
//! forever; a reclaimed read whose floor does not lie past the position
//! asked is refused ([`Board::op_at`], [`Board::chain_at`]); and an `/op`
//! answer past the transport's cap ([`TransportError::TooLarge`]) is
//! `null`, which every typed read takes as its own cannot-read.
//!
//! The wire's spellings that both readers of the board — the mirror and the
//! guest-reading resolve — read alike are stated here, once: a unit span;
//! the span-set, `image` and one-position `retrieve_v` frames; a span-set
//! answer's content extent; an `image` answer's runs, read whole or not at
//! all, and an atom's V-ordinal among them; and a content element's ordinal
//! in its own document, the append-only guess's V-ordinal.

use std::cell::Cell;
use std::fmt;
use std::sync::LazyLock;
use std::thread;
use std::time::Duration;

use serde_json::{json, Value};
use skep_address::{document_of, Address, Nat};
use skep_identity::{BoardTerm, Enrolled, PublicKey};

use crate::http::{Method, Transport, TransportError};
use crate::{hex_byte, parse_address};

/// How often a `history_busy` or `scan_busy` answer is retried before the
/// read is given up — a retry-class refusal, never a queue (wire.md §Reading
/// history), so the client is the one that waits.
const BUSY_RETRIES: u32 = 200;

/// The pause between two busy retries.
const BUSY_PAUSE: Duration = Duration::from_millis(25);

/// `H.1`'s address — the head document's first chain member, the board
/// term's carrier (wire.md §The other endpoints).
static HEAD_MEMBER_1: LazyLock<Address> =
    LazyLock::new(|| parse_address("1.1.0.1.0.2.1").expect("the head document's first member"));

/// THE COUNT OF EVERY READ a board was asked, by kind — the fetch count a
/// resolve's cost is stated in (the investigation §3.1). Reads over `/op-at`
/// are counted under their own kind AND under `op_at`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
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
#[non_exhaustive]
pub enum BoardError {
    /// The board was not reached, or answered past what the transport reads
    /// of one.
    Transport(TransportError),
    /// A status outside the read's shape: the body as served, prefixed with
    /// the op's name for a read over `/op` or `/op-at`.
    Status { status: u16, body: String },
    /// An answer not the shape the wire promises for its status — a 200
    /// that is no answer of the read, a refusal whose body is no JSON, a
    /// reclaimed read whose floor does not lie past the position asked — or
    /// a feed or a class scan that breaks the paging it promises.
    Malformed(String),
    /// A `rejected` answer: the op, its code and its detail.
    Rejected { op: String, code: String, detail: Option<String> },
    /// `history_busy` or `scan_busy` past the retries.
    Busy,
    /// The feed refused a page past its byte budget, naming the limit that
    /// fits (wire.md §The change feed, Paging).
    PageTooLarge { fits: usize },
    /// `history_reclaimed`: the position asked (`/op-at`, `/chain`) or the
    /// `since` fence (`/changes`) predates the history the board retains;
    /// `floor`, where named, the oldest position still answerable — past the
    /// position asked, which the reads over `/op-at` and `/chain` hold it to.
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
            BoardError::Reclaimed { floor: Some(floor) } => write!(f, "history reclaimed below position {floor}"),
            BoardError::Reclaimed { floor: None } => f.write_str("history reclaimed"),
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

/// A stored link as `read_link` serves it, read only as far as its reader
/// asked: its TYPE, where its type slot is the unit span of one of the
/// types the reader named and nothing else — the daemon's own reading of a
/// registry or credential type slot, one span EQUAL to the type's unit
/// subtree (`single_address`; wire.md §Registry) — and, for a link of such
/// a type, the addresses its `from` and `to` spans start at. A link of any
/// other type holds no slot: none of its spans is parsed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct LinkSlots {
    pub(crate) ty: Option<Address>,
    pub(crate) from: Vec<Address>,
    pub(crate) to: Vec<Address>,
}

/// One page of the feed (wire.md §The change feed).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Page {
    /// The entries, oldest first, each as served.
    pub(crate) rows: Vec<Value>,
    /// The final entry's position, or `since` echoed when empty.
    pub(crate) last: u64,
    /// Whether positions remain past `last`.
    pub(crate) more: bool,
}

/// A board as the resolver reads it: the typed reads over one
/// [`Transport`], counted.
pub struct Board {
    transport: Box<dyn Transport>,
    reads: Cell<Reads>,
    feed_bytes: Cell<u64>,
}

/// What a board shows of itself: the reads made so far, by kind, and the
/// feed's bytes — the transport is the caller's, and shows nothing.
impl fmt::Debug for Board {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Board")
            .field("reads", &self.reads())
            .field("feed_bytes", &self.feed_bytes())
            .finish_non_exhaustive()
    }
}

impl Board {
    /// The typed reads over `transport`, every count at zero.
    pub fn new(transport: Box<dyn Transport>) -> Board {
        Board { transport, reads: Cell::new(Reads::default()), feed_bytes: Cell::new(0) }
    }

    /// Every read made so far, by kind.
    pub fn reads(&self) -> Reads {
        self.reads.get()
    }

    /// The bytes of every feed page read so far.
    pub(crate) fn feed_bytes(&self) -> u64 {
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
    pub(crate) fn health(&self) -> Result<Value, BoardError> {
        self.bump(|r| r.health += 1);
        let (st, body) = self.transport.exchange(Method::Get, "/health", b"")?;
        if st != 200 {
            return Err(BoardError::Status { status: st, body: String::from_utf8_lossy(&body).into_owned() });
        }
        Board::json(&body)
    }

    /// `GET /changes?since=N[&limit=L]` as the guest: one page, held to the
    /// page's own rules (wire.md §The change feed, Paging) — every entry's
    /// position past `since` and past the entry before it, `last` the final
    /// entry's position or `since` echoed on an empty page, and no empty page
    /// announcing more. A page that breaks one re-serves a row or does not
    /// advance, and is refused [`BoardError::Malformed`].
    pub(crate) fn changes(&self, since: u64, limit: Option<usize>) -> Result<Page, BoardError> {
        self.bump(|r| r.changes += 1);
        let path = match limit {
            Some(l) => format!("/changes?since={since}&limit={l}"),
            None => format!("/changes?since={since}"),
        };
        let (st, body) = self.transport.exchange(Method::Get, &path, b"")?;
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
        let mut v = Board::json(&body)?;
        // The rows are moved out of the answer, never copied: the answer is
        // dropped once they are taken.
        let rows = match v.get_mut("changes").map(Value::take) {
            Some(Value::Array(rows)) => rows,
            _ => return Err(BoardError::Malformed("no changes".into())),
        };
        let last = v["last"].as_u64().ok_or_else(|| BoardError::Malformed("no last".into()))?;
        let more = v["more"].as_bool().ok_or_else(|| BoardError::Malformed("no more".into()))?;
        let Some(reached) = rises_past(since, &rows) else {
            return Err(BoardError::Malformed(format!("a page from {since} whose entries do not advance")));
        };
        if last != reached || (more && rows.is_empty()) {
            return Err(BoardError::Malformed(format!("a page from {since} whose last or more does not follow its entries")));
        }
        Ok(Page { rows, last, more })
    }

    /// `POST /op` as the guest: the answer as served, a `rejected` included,
    /// and `null` where the answer runs past the transport's cap
    /// ([`TransportError::TooLarge`]) — an answer every typed read takes as
    /// its own cannot-read: no link, no key set, no image, no atom.
    pub fn op(&self, frame: &Value) -> Result<Value, BoardError> {
        let op = frame["op"].as_str().unwrap_or("");
        self.bump(|r| r.count_op(op));
        self.post_json("/op", &frame.to_string(), op)
    }

    /// [`Board::op`], a `rejected` answer an error.
    pub(crate) fn op_ok(&self, frame: &Value) -> Result<Value, BoardError> {
        let v = self.op(frame)?;
        Board::not_rejected(v)
    }

    /// `POST /op-at` as the guest: `frame` answered AS OF `at` (wire.md
    /// §Reading history), `history_busy` retried; a position the board has
    /// reclaimed is [`BoardError::Reclaimed`], its floor past `at`.
    pub(crate) fn op_at(&self, at: u64, frame: &Value) -> Result<Value, BoardError> {
        let op = frame["op"].as_str().unwrap_or("");
        self.bump(|r| {
            r.count_op(op);
            r.op_at += 1;
        });
        let body = format!(r#"{{"at":{at},"frame":{frame}}}"#);
        floor_past(at, self.post_json("/op-at", &body, op))
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

    /// One POST of a JSON body, the busy refusals retried. An answer past the
    /// transport's cap is `null`: every answer a typed read must take whole
    /// fits it on a conforming board, and a link an owner writes into its
    /// own home need not — read as an error, one such link would stall every
    /// mirror's fold at its row.
    fn post_json(&self, path: &str, body: &str, op: &str) -> Result<Value, BoardError> {
        let mut tries = 0;
        loop {
            let (st, answer) = match self.transport.exchange(Method::Post, path, body.as_bytes()) {
                Ok(exchanged) => exchanged,
                Err(TransportError::TooLarge { .. }) => return Ok(Value::Null),
                Err(e) => return Err(e.into()),
            };
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
                    let refused = BoardError::Status { status: st, body: format!("{op}: {}", text()) };
                    return Err(if busy { BoardError::Busy } else { refused });
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
    /// the board (wire.md §Reading history) — the position the board answers
    /// as of, and the chain; a position the board has reclaimed is
    /// [`BoardError::Reclaimed`], its floor past `at`, as `/op-at`'s is.
    pub(crate) fn chain_at(&self, at: u64) -> Result<(u64, [u8; 32]), BoardError> {
        self.bump(|r| r.chain += 1);
        let mut tries = 0;
        loop {
            let (st, body) = self.transport.exchange(Method::Get, &format!("/chain?at={at}"), b"")?;
            let text = String::from_utf8_lossy(&body).into_owned();
            match st {
                200 => {
                    let v = Board::json(&body)?;
                    let as_of = v["at"].as_u64().ok_or_else(|| BoardError::Malformed("no at".into()))?;
                    let hex = v["chain"].as_str().ok_or_else(|| BoardError::Malformed("no chain".into()))?;
                    let chain = parse_chain(hex).ok_or_else(|| BoardError::Malformed(format!("chain {hex}")))?;
                    return Ok((as_of, chain));
                }
                410 => {
                    let v = Board::json(&body)?;
                    return floor_past(at, Err(BoardError::Reclaimed { floor: v["floor"].as_u64() }));
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

    /// Whether `link` stands on the board's ACTIVE view (REG-1.11) — the
    /// board's own reading, which a link leaves only by the retraction a
    /// `nullify` mints, its target's owner's alone (wire.md §Links (writes))
    /// — asked as the active links homed in `home`, typed `ty`, naming `atom`
    /// in their `from` (`find_links_ftt` answers the active slice, wire.md
    /// §Link discovery reads): where it stands, the link answers itself.
    /// Never a search for a link of the retraction's type: discovery matches
    /// a slot by OVERLAP, and a type slot naming a prefix of the retraction
    /// class's address, a subtype of it, or it beside another address is
    /// another class, which `make_link` admits to any owner in its own home.
    /// `false` only where the answer is an `addrs` list without `link`: a
    /// refusal, or an answer past the cap, takes nothing off the view.
    pub(crate) fn stands_active(
        &self,
        link: &Address,
        home: &Address,
        ty: &Address,
        atom: &Address,
    ) -> Result<bool, BoardError> {
        let v = self.op(&json!({ "op": "find_links_ftt", "q": {
            "home": [unit_span_json(home)],
            "from": [unit_span_json(atom)],
            "to": "any",
            "ty": [unit_span_json(ty)],
        }}))?;
        let Some(addrs) = v["addrs"].as_array() else { return Ok(true) };
        let link = link.to_string();
        Ok(addrs.iter().any(|a| a.as_str() == Some(link.as_str())))
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
    /// pinned member's V-ordinal 1 — the term, and its chain as the board
    /// spelled it; `None` where this reader reads no term off the board: no
    /// atom at `H.1`, one that is no record of a position and a chain, or an
    /// answer past the transport's cap.
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

    /// A stored link off `read_link`, read as far as `types` asks
    /// ([`LinkSlots`]): its type where its type slot is one of their unit
    /// spans exactly — compared as served, so no span of another type's
    /// slot is parsed — and then its `from` and `to`; `None` where no link
    /// stands at `link`, or where its answer runs past the transport's cap —
    /// a link this reader cannot read, folded as none.
    pub(crate) fn link_slots(&self, link: &Address, types: &[&Address]) -> Result<Option<LinkSlots>, BoardError> {
        let v = self.op_ok(&json!({ "op": "read_link", "a": link.to_string() }))?;
        if v["link"].is_null() {
            return Ok(None);
        }
        let served = &v["link"]["slots"][2];
        let Some(ty) = types.iter().find(|t| *served == json!([unit_span_json(t)])) else {
            return Ok(Some(LinkSlots { ty: None, from: Vec::new(), to: Vec::new() }));
        };
        Ok(Some(LinkSlots { ty: Some((*ty).clone()), from: link_slot(&v, 0), to: link_slot(&v, 1) }))
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

/// The one-position `retrieve_v` frame: the atom at V-ordinal `ordinal` of
/// `doc`.
pub(crate) fn retrieve_frame(doc: &Address, ordinal: u64) -> Value {
    json!({ "op": "retrieve_v", "specs": [{ "doc": doc.to_string(), "span": { "start": format!("1.{ordinal}"), "width": "0.1" } }] })
}

/// The `retrieve_doc_v_span_set` frame: `doc`'s V-span set, its content
/// extent among it ([`content_extent`]).
pub(crate) fn span_set_frame(doc: &Address) -> Value {
    json!({ "op": "retrieve_doc_v_span_set", "doc": doc.to_string() })
}

/// The `image` frame: the runs `doc` arranges at the `width` V-ordinals from
/// `from` ([`runs_of`]).
pub(crate) fn image_frame(doc: &Address, from: u64, width: u64) -> Value {
    json!({ "op": "image", "d": doc.to_string(), "region": [{ "start": format!("1.{from}"), "width": format!("0.{width}") }] })
}

fn key_set_frame(account: &Address) -> Value {
    json!({ "op": "key_set", "account": account.to_string() })
}

/// A reclaimed read's answer held to the wire's shape: the floor, where
/// named, is the oldest position still answerable (wire.md §Reading
/// history), so a floor at or below the position asked — `at` itself
/// answerable — is no refusal the wire gives, and is
/// [`BoardError::Malformed`]; the floor clause the mirror reads it by
/// (`mirror/keys.rs`) counts acts in `(at, floor]` and is sound only past
/// `at`. Every other answer passes as it is.
fn floor_past<T>(at: u64, answer: Result<T, BoardError>) -> Result<T, BoardError> {
    match answer {
        Err(BoardError::Reclaimed { floor: Some(floor) }) if floor <= at => {
            Err(BoardError::Malformed(format!("a read at {at} refused as reclaimed, its floor {floor} at or below it")))
        }
        answer => answer,
    }
}

/// THE FEED'S OWN ORDER (wire.md §The change feed, Paging): the position
/// `rows` reach where each names a position past `since` and past the row
/// before it — `since` itself where there are none — else `None`. Every page
/// is held to it ([`Board::changes`]), and every copy an offline rebuild
/// reads.
pub(crate) fn rises_past(since: u64, rows: &[Value]) -> Option<u64> {
    rows.iter().try_fold(since, |reached, row| row["at"].as_u64().filter(|at| *at > reached))
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

/// Sixty-four hex characters, either case, as the chain's thirty-two bytes —
/// read a byte pair at a time ([`hex_byte`]), so text of any other shape,
/// off the board, a copy or a cache, is no chain and never a panic.
pub(crate) fn parse_chain(hex: &str) -> Option<[u8; 32]> {
    let (pairs, rest) = hex.as_bytes().as_chunks::<2>();
    if pairs.len() != 32 || !rest.is_empty() {
        return None;
    }
    let mut out = [0u8; 32];
    for (byte, pair) in out.iter_mut().zip(pairs) {
        *byte = hex_byte(*pair)?;
    }
    Some(out)
}

/// A unit subtree span over `a` as the wire spells one.
pub(crate) fn unit_span_json(a: &Address) -> Value {
    let span = skep_identity::unit_span(a);
    json!({ "start": span.start().to_string(), "width": span.width().to_string() })
}

/// Slot `i` of a `read_link` answer — 0 the `from`, 1 the `to` — as the
/// addresses its spans start at; empty where the slot is absent.
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
/// V-ordinals, and a read at the shifted V-ordinal fetches another atom.
pub(crate) fn runs_of(answer: &Value) -> Option<Vec<(Address, u64)>> {
    answer["runs"]
        .as_array()?
        .iter()
        .map(|r| Some((parse_address(r["i_start"].as_str()?)?, r["width"].as_str()?.parse::<u64>().ok()?)))
        .collect()
}

/// The V-ordinal `addr` sits at among an `image` answer's runs — each an
/// I-start and a width, in V-order from ordinal 1 — where a run holds it.
/// The widths are the board's word, so they are summed checked: an image
/// whose widths overflow places nothing.
pub(crate) fn v_ordinal_in(runs: &[(Address, u64)], addr: &Address) -> Option<u64> {
    let mut v_start = 1u64;
    for (i_start, width) in runs {
        if let Some(k) = offset_within(i_start, addr, *width) {
            return v_start.checked_add(k);
        }
        v_start = v_start.checked_add(*width)?;
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
/// ordinal `n`: THE APPEND-ONLY GUESS's V-ordinal, a doc 1 written only by
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
mod tests;
