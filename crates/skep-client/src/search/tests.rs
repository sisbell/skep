//! The `search` module's unit suite over a SCRIPTED BOARD: a `Dialer` whose
//! answers come from a `World` the test writes — the head record, the feed's
//! rows, each document's text, the chain at every position, the grants —
//! keeping every request it served with whether a token rode and its body,
//! so a test pins what the consumer reads, at what class, in what order, and
//! what it makes of each answer, with no daemon. Each test names the design
//! sentence it fences. The suites that need the daemon itself are
//! `tests/it/search/`.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::io::{self, Read};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde_json::{json, Value};
use skep_address::Address;
use skep_search::{
    Chain, ChainAt, Class, Grant, GrantKind, Header, Index, Kind, RangeRecord, Refusal, Rung, Span,
    Standing, Stats, CEILING_BYTES,
};

use crate::address::parse_address;
use crate::board::{Board, Token, HEAD_DOCUMENT, HEAD_MEMBER_1};
use crate::dial::{DialError, Dialer, Headers, Request, RequestHead, Response, StreamedResponse};
use crate::origin::Origin;

use super::consumer::{EVENT_LINE_BOUND, MAX_DELIVERY_ITEMS};
use super::directory::{BoardDir, SearchDir};
use super::jump::{land, landing_of, Correspondence, Landing};
use super::places::{PlaceRecord, Places};
use super::state::{Facts, Lost, Newer, Part, Range, State};
use super::{events, Consumer, Place, PlacesAnswer, QueryTooLong, SearchDir as _SearchDir, SearchOpts, SessionRef, Who, QUERY_BOUND};

// ── THE SCRIPTED BOARD ───────────────────────────────────────────────────

/// One row of the feed as the world holds it.
#[derive(Debug, Clone)]
struct Row {
    at: u64,
    op: Option<&'static str>,
    docs: Option<Vec<String>>,
    key: Option<&'static str>,
    /// A draft's row — on the `drafts=true` page alone.
    draft: bool,
}

/// One document's content as `retrieve_v` delivers it: per-byte text, or a
/// refusal code.
#[derive(Debug, Clone)]
struct Doc {
    text: Vec<u8>,
    refuse: Option<&'static str>,
}

/// A grant-typed link naming a grantee.
#[derive(Debug, Clone)]
struct GrantRow {
    link: String,
    from: String,
    to: String,
}

/// The board as the test writes it.
#[derive(Debug, Default)]
struct World {
    position: u64,
    /// `H.1`'s pair; `None` while unclaimed.
    head: Option<(u64, String)>,
    /// Every `H.k` member with the pair its record names.
    head_members: BTreeMap<String, (u64, String)>,
    rows: Vec<Row>,
    docs: BTreeMap<String, Doc>,
    /// The addresses `doc_metadata` answers for — trunk members, probed.
    registered: BTreeSet<String>,
    /// The reclaim floor: positions below it answer `history_reclaimed`.
    floor: Option<u64>,
    /// `/chain?at` answers `503 history_busy` this many times first.
    busy: usize,
    /// Chains overridden at a position.
    chains: BTreeMap<u64, String>,
    /// The position advances by one after every delivery — a commit landing
    /// between a document's parts.
    advance_on_read: bool,
    /// `retrieve_v` of these documents fails at the transport.
    transport_fail: BTreeSet<String>,
    grants: Vec<GrantRow>,
    universal: Vec<(String, Vec<String>)>,
    /// `span_set` answers this extent for a document, whatever its text.
    extents: BTreeMap<String, u64>,
    /// `retrieve_v` answers a document's whole text, whatever width it asks.
    deliver_whole: BTreeSet<String>,
    /// `/changes` answers `410 history_reclaimed` with each of these floors in
    /// turn, ahead of any page.
    reclaim: VecDeque<u64>,
    /// `/changes` answers a page that moves nothing: empty, `last` the
    /// `since` asked, `more` true.
    stale: bool,
    /// The `/changes` requests served.
    changes_asked: usize,
    /// `principal_prefix` answers, by principal.
    principals: BTreeMap<u64, String>,
    /// `retrieve_v` answers each part of a document as ONE withheld run of
    /// the width asked, its origin this text.
    withheld_by: BTreeMap<String, String>,
}

/// The chain at `position` as the world computes it: distinct per position.
fn chain_hex(position: u64) -> String {
    format!("{position:064x}")
}

const ACCOUNT: &str = "1.0.1";
const DOC1: &str = "1.0.1.0.1";

impl World {
    /// A claimed board: the claim's own rows, `H.1` published at 20 by the
    /// system account.
    fn claimed() -> World {
        let mut world = World { position: 20, ..World::default() };
        world.head = Some((20, chain_hex(20)));
        world.head_members.insert(HEAD_MEMBER_1.to_string(), (20, chain_hex(20)));
        world.rows.push(Row { at: 2, op: Some("delegate"), docs: Some(vec![]), key: Some("bare"), draft: false });
        world.rows.push(Row { at: 3, op: Some("create_new_document"), docs: Some(vec![DOC1.to_string()]), key: Some("bare"), draft: false });
        world.docs.insert(DOC1.to_string(), Doc { text: Vec::new(), refuse: None });
        world.rows.push(Row { at: 20, op: Some("publish"), docs: Some(vec![HEAD_MEMBER_1.to_string()]), key: Some("system"), draft: false });
        world
    }

    fn chain_at(&self, position: u64) -> String {
        self.chains.get(&position).cloned().unwrap_or_else(|| chain_hex(position))
    }

    fn next(&mut self) -> u64 {
        self.position += 1;
        self.position
    }

    /// A published document minted and written: a memberless edition.
    fn publish(&mut self, doc: &str, text: &str) -> u64 {
        let at = self.next();
        self.rows.push(Row { at, op: Some("insert"), docs: Some(vec![doc.to_string()]), key: Some("bare"), draft: false });
        self.docs.insert(doc.to_string(), Doc { text: text.as_bytes().to_vec(), refuse: None });
        at
    }

    /// A `publish` shot minting `D.k` with `text`, the member registered.
    fn publish_member(&mut self, doc: &str, k: u64, text: &str) -> u64 {
        let at = self.next();
        let member = format!("{doc}.{k}");
        self.rows.push(Row { at, op: Some("publish"), docs: Some(vec![member.clone()]), key: Some("bare"), draft: false });
        self.registered.insert(member.clone());
        self.docs.insert(member, Doc { text: text.as_bytes().to_vec(), refuse: None });
        at
    }

    /// A draft written: a row on the `drafts=true` page alone.
    fn draft(&mut self, doc: &str, text: &[u8]) -> u64 {
        let at = self.next();
        self.rows.push(Row { at, op: Some("insert"), docs: Some(vec![doc.to_string()]), key: Some("bare"), draft: true });
        self.docs.insert(doc.to_string(), Doc { text: text.to_vec(), refuse: None });
        at
    }

    /// A bare row: testimony lost, `op` and `docs` null.
    fn bare(&mut self) -> u64 {
        let at = self.next();
        self.rows.push(Row { at, op: None, docs: None, key: None, draft: false });
        at
    }

    /// A new head `H.k` published by the system account at the current
    /// position.
    fn new_head(&mut self, k: u64) -> u64 {
        let at = self.next();
        let member = format!("{HEAD_DOCUMENT}.{k}");
        self.rows.push(Row { at, op: Some("publish"), docs: Some(vec![member.clone()]), key: Some("system"), draft: false });
        self.head_members.insert(member, (at, self.chain_at(at)));
        at
    }

    fn health(&self) -> Value {
        json!({"ok": true, "log_position": self.position, "chain_head": self.chain_at(self.position), "head_time": null,
               "auth": {"claimant": self.head.as_ref().map(|_| ACCOUNT), "local_trust": true, "origins": [], "signed_origins": []}})
    }

    fn changes(&mut self, path: &str) -> Response {
        self.changes_asked += 1;
        assert!(self.changes_asked <= 50, "the consumer asked the feed past 50 pages");
        let query = path.splitn(2, '?').nth(1).unwrap_or("");
        let mut since = 0u64;
        let mut under: Option<String> = None;
        let mut drafts = false;
        let mut limit = 256usize;
        for pair in query.split('&') {
            match pair.split_once('=') {
                Some(("since", v)) => since = v.parse().unwrap(),
                Some(("under", v)) => under = Some(v.to_string()),
                Some(("drafts", v)) => drafts = v == "true",
                Some(("limit", v)) => limit = v.parse().unwrap(),
                _ => panic!("an unknown `/changes` member: {pair}"),
            }
        }
        if let Some(floor) = self.reclaim.pop_front() {
            return reply(410, json!({"error": "history_reclaimed", "floor": floor}));
        }
        if self.stale {
            return reply(200, json!({"changes": [], "last": since, "more": true}));
        }
        if let Some(floor) = self.floor {
            if since < floor {
                return reply(410, json!({"error": "history_reclaimed", "floor": floor}));
            }
        }
        let under_addr = under.as_deref().and_then(parse_address);
        let visible: Vec<&Row> = self
            .rows
            .iter()
            .filter(|r| r.at > since && r.draft == drafts)
            .filter(|r| match (&under_addr, &r.docs) {
                (None, _) => true,
                (Some(u), Some(docs)) => docs.iter().filter_map(|d| parse_address(d)).any(|d| skep_address::is_prefix(u.tumbler(), d.tumbler())),
                (Some(_), None) => !drafts,
            })
            .collect();
        let page: Vec<Value> = visible
            .iter()
            .take(limit)
            .map(|r| {
                let mut row = json!({"at": r.at, "time": null});
                row["op"] = r.op.map(Value::from).unwrap_or(Value::Null);
                row["docs"] = r.docs.clone().map(Value::from).unwrap_or(Value::Null);
                row["key"] = r.key.map(Value::from).unwrap_or(Value::Null);
                row
            })
            .collect();
        let last = page.last().and_then(|r| r["at"].as_u64()).unwrap_or(since);
        let more = visible.len() > page.len();
        reply(200, json!({"changes": page, "last": last, "more": more}))
    }

    fn chain(&mut self, path: &str) -> Response {
        let at: u64 = path.strip_prefix("/chain?at=").unwrap().parse().unwrap();
        if self.busy > 0 {
            self.busy -= 1;
            return reply(503, json!({"error": "history_busy"}));
        }
        if let Some(floor) = self.floor {
            if at < floor {
                return reply(410, json!({"error": "history_reclaimed", "floor": floor}));
            }
        }
        if at > self.position {
            return reply(400, json!({"error": "beyond_head", "head": self.position}));
        }
        reply(200, json!({"at": at, "chain": self.chain_at(at)}))
    }

    fn op(&mut self, frame: &Value) -> Result<Response, DialError> {
        let op = frame["op"].as_str().unwrap_or("?");
        let rejected = |code: &str| reply(200, json!({"resp": "rejected", "code": code, "disposition": "reorder", "op": op}));
        match op {
            "retrieve_v" => {
                let spec = &frame["specs"][0];
                let doc = spec["doc"].as_str().unwrap().to_string();
                let from: u64 = spec["span"]["start"].as_str().unwrap().strip_prefix("1.").unwrap().parse().unwrap();
                let width: u64 = spec["span"]["width"].as_str().unwrap().strip_prefix("0.").unwrap().parse().unwrap();
                assert!(width <= MAX_DELIVERY_ITEMS, "a read past the delivery budget: {width}");
                if doc == HEAD_MEMBER_1 && self.head.is_none() {
                    return Ok(reply(200, json!({"resp": "delivery", "as_of": self.position, "items": []})));
                }
                if let Some((position, chain)) = self.head_members.get(&doc) {
                    let record = json!({"type": "skep-head", "format": "SKJ4", "position": position, "chain": chain, "base": null, "prev": null}).to_string();
                    return Ok(reply(200, json!({"resp": "delivery", "as_of": self.position, "items": [{"atom": record}]})));
                }
                if self.transport_fail.contains(&doc) {
                    return Err(DialError::Io("the scripted board broke the connection".into()));
                }
                let Some(d) = self.docs.get(&doc) else { return Ok(rejected("doc_not_registered")) };
                if let Some(code) = d.refuse {
                    return Ok(rejected(code));
                }
                if let Some(origin) = self.withheld_by.get(&doc) {
                    return Ok(reply(200, json!({"resp": "delivery", "as_of": self.position, "items": [{"withheld": {"origin": origin, "width": width.to_string()}}]})));
                }
                let (lo, hi) = if self.deliver_whole.contains(&doc) {
                    (0, d.text.len())
                } else {
                    let lo = ((from - 1) as usize).min(d.text.len());
                    (lo, (lo + width as usize).min(d.text.len()))
                };
                // Past the text the span delivers nothing, as a board's
                // delivery is the span within the document's extent at the
                // read's position (skep-retrieval's `retrieve_v`).
                let slice = &d.text[lo..hi];
                let items = match std::str::from_utf8(slice) {
                    Ok(text) => json!([{"content": text}]),
                    Err(_) => json!([{"hex": slice.iter().map(|b| format!("{b:02x}")).collect::<String>()}]),
                };
                let as_of = self.position;
                if self.advance_on_read {
                    self.position += 1;
                }
                Ok(reply(200, json!({"resp": "delivery", "as_of": as_of, "items": items})))
            }
            "retrieve_doc_v_span_set" => {
                let doc = frame["doc"].as_str().unwrap();
                if self.head_members.contains_key(doc) {
                    return Ok(reply(200, json!({"resp": "span_set", "as_of": self.position, "set": [{"start": "1.1", "width": "0.1"}]})));
                }
                if self.transport_fail.contains(doc) {
                    return Err(DialError::Io("the scripted board broke the connection".into()));
                }
                let Some(d) = self.docs.get(doc) else { return Ok(rejected("doc_not_registered")) };
                if let Some(code) = d.refuse {
                    return Ok(rejected(code));
                }
                let extent = self.extents.get(doc).copied().unwrap_or(d.text.len() as u64);
                let set = if extent == 0 { json!([]) } else { json!([{"start": "1.1", "width": format!("0.{extent}")}]) };
                Ok(reply(200, json!({"resp": "span_set", "as_of": self.position, "set": set})))
            }
            "doc_metadata" => {
                let doc = frame["doc"].as_str().unwrap();
                if self.registered.contains(doc) {
                    Ok(reply(200, json!({"resp": "doc_metadata", "as_of": self.position, "doc": doc, "published": true, "owner": ACCOUNT})))
                } else {
                    Ok(rejected("doc_not_registered"))
                }
            }
            "find_links_ftt" => {
                let to = frame["q"]["to"][0]["start"].as_str().unwrap_or("");
                let addrs: Vec<&str> = self.grants.iter().filter(|g| g.to == to).map(|g| g.link.as_str()).collect();
                Ok(reply(200, json!({"resp": "addrs", "as_of": self.position, "addrs": addrs})))
            }
            "read_link" => {
                let a = frame["a"].as_str().unwrap();
                let Some(g) = self.grants.iter().find(|g| g.link == a) else {
                    return Ok(reply(200, json!({"resp": "link_value", "as_of": self.position, "link": null})));
                };
                let slot = |addr: &str| json!([{"start": addr, "width": "0.1"}]);
                Ok(reply(200, json!({"resp": "link_value", "as_of": self.position, "link": {"slots": [slot(&g.from), slot(&g.to), slot(super::consumer::T_GRANT)]}})))
            }
            "universal_grants" => {
                let rows: Vec<Value> = self.universal.iter().map(|(p, i)| json!({"prefix": p, "issuers": i})).collect();
                Ok(reply(200, json!({"resp": "universal_grants", "as_of": self.position, "rows": rows})))
            }
            "principal_prefix" => {
                let addr = frame["principal"].as_u64().and_then(|n| self.principals.get(&n)).cloned();
                Ok(reply(200, json!({"resp": "addr", "as_of": self.position, "addr": addr})))
            }
            "key_set" => Ok(reply(200, json!({"resp": "key_set", "as_of": self.position, "enrolled": [], "retired": []}))),
            other => panic!("the consumer sent an op the scripted board does not answer: {other}"),
        }
    }
}

fn reply(status: u16, body: Value) -> Response {
    Response { status, headers: Headers::default(), body: body.to_string().into_bytes() }
}

/// One request the scripted board served: `METHOD path[ op]`, whether a
/// token rode, and the body.
#[derive(Debug, Clone)]
struct Served {
    line: String,
    token: bool,
    body: Vec<u8>,
}

/// The dialer over a world.
struct Scripted {
    world: Arc<Mutex<World>>,
    served: Mutex<Vec<Served>>,
}

impl Scripted {
    fn lines(&self) -> Vec<String> {
        self.served.lock().unwrap().iter().map(|s| s.line.clone()).collect()
    }

    fn reads_of(&self, op: &str) -> usize {
        self.served.lock().unwrap().iter().filter(|s| s.line == format!("POST /op {op}")).count()
    }

    fn clear(&self) {
        self.served.lock().unwrap().clear();
    }
}

impl Dialer for Scripted {
    fn exchange(&self, _origin: &Origin, req: &Request) -> Result<Response, DialError> {
        let frame: Value = serde_json::from_slice(&req.body).unwrap_or(Value::Null);
        let mut line = format!("{} {}", req.method.as_str(), req.path);
        if req.path == "/op" {
            line.push(' ');
            line.push_str(frame["op"].as_str().unwrap_or("?"));
        }
        let token = req.headers.iter().any(|(k, _)| k == "Skepd-Session");
        self.served.lock().unwrap().push(Served { line, token, body: req.body.clone() });
        let mut world = self.world.lock().unwrap();
        match req.path.as_str() {
            "/health" => Ok(reply(200, world.health())),
            "/op" => world.op(&frame),
            path if path.starts_with("/changes?") => Ok(world.changes(path)),
            path if path.starts_with("/chain?at=") => Ok(world.chain(path)),
            path => panic!("the consumer dialed a path the scripted board does not answer: {path}"),
        }
    }

    fn stream(&self, _: &Origin, _: &RequestHead, _: &mut dyn std::io::Read, _: &mut dyn FnMut(&Headers)) -> Result<StreamedResponse, DialError> {
        unreachable!("no read of the scripted board streams")
    }
}

/// A board over a world, with the dialer kept for its log.
fn board(world: &Arc<Mutex<World>>) -> (Board, Arc<Scripted>) {
    let dialer = Arc::new(Scripted { world: world.clone(), served: Mutex::new(Vec::new()) });
    (Board::new(Origin::parse("http://127.0.0.1:8642").unwrap(), dialer.clone()), dialer)
}

fn shared(world: World) -> Arc<Mutex<World>> {
    Arc::new(Mutex::new(world))
}

fn token() -> Token {
    Token::parse("9f3a6c21d4b8e07a5c1b2d4e6f708192").unwrap()
}

/// Principal 7 at `1.0.1.2`, a sub-account of the claimant's.
const SUB_ACCOUNT: &str = "1.0.1.2";

fn session(token: &Token) -> SessionRef<'_> {
    SessionRef { token, principal: 7, account: SUB_ACCOUNT }
}

fn addr(text: &str) -> Address {
    parse_address(text).expect("an address")
}

fn hits(consumer: &Consumer<'_>, who: Who<'_>, query: &str) -> Vec<String> {
    consumer.search(who, query, &SearchOpts::default()).expect("within the bound").hits.iter().map(|h| h.doc.to_string()).collect()
}

fn board_dir(dir: &SearchDir, world: &Arc<Mutex<World>>) -> BoardDir {
    let (position, _) = world.lock().unwrap().head.clone().expect("claimed");
    let chain = world.lock().unwrap().chain_at(position);
    dir.board(&Chain::parse(&chain).unwrap())
}

fn load_header(path: &std::path::Path, class: Class) -> Header {
    let bytes = std::fs::read(path).expect("the file");
    Index::load(&mut &bytes[..], class).expect("loads").1
}

// ── THE OPEN AND THE FIRST BUILD ─────────────────────────────────────────

/// `search.md` §5.2: "AN UNCLAIMED BOARD HAS NO `H.1` AND NO INDEX"; §4b.2's
/// `none`. The consumer mounts nothing, creates no directory, and answers
/// `none` with no hit — and mounts at the poll that finds the claim landed.
#[test]
fn an_unclaimed_board_mounts_nothing_and_answers_none_until_the_claim_lands() {
    let world = shared(World::default());
    let (b, _) = board(&world);
    let tmp = tempfile::tempdir().unwrap();
    let dir = SearchDir::new(tmp.path());
    let consumer = Consumer::open(&b, dir.clone()).expect("opens");
    assert_eq!(consumer.state(Who::Guest), State::None);
    assert!(!dir.root().exists(), "no directory for an unclaimed board");
    let answer = consumer.search(Who::Guest, "anything", &SearchOpts::default()).unwrap();
    assert!(answer.hits.is_empty() && answer.places.is_empty() && answer.state == State::None);
    assert_eq!(consumer.places(Who::Guest, None), PlacesAnswer { docs: Vec::new(), counts: BTreeMap::new(), state: State::None }, "no listing without an index");
    *world.lock().unwrap() = World::claimed();
    world.lock().unwrap().publish("1.0.1.0.2", "the claim landed");
    consumer.poll().expect("polls");
    assert!(matches!(consumer.state(Who::Guest), State::Complete { .. }), "{:?}", consumer.state(Who::Guest));
    assert_eq!(hits(&consumer, Who::Guest, "landed"), ["1.0.1.0.2"]);
}

/// `client.md` §4e.2: "EVERY CONTENT CHANGE COSTS ONE READ of the changed
/// document … COALESCED to ONE READ PER CHANGED DOCUMENT PER POLL"; §4 (i):
/// the published index is fed by TOKEN-FREE reads; `complete` is C-134's
/// state, `as_of` the `/health` pair's position, which the saved `held`
/// equals (§5.1's fence).
#[test]
fn the_first_build_reads_each_published_document_once_token_free_and_completes_at_the_health_pair() {
    let mut w = World::claimed();
    w.publish("1.0.1.0.2", "alpha beta\nsecond line");
    w.publish("1.0.1.0.3", "gamma delta");
    for _ in 0..3 {
        w.publish("1.0.1.0.3", "gamma delta epsilon");
    }
    let world = shared(w);
    let (b, dialer) = board(&world);
    let tmp = tempfile::tempdir().unwrap();
    let consumer = Consumer::open(&b, SearchDir::new(tmp.path())).unwrap();
    assert!(matches!(consumer.state(Who::Guest), State::Building { position: 0, units: 0, lost: None, aside: false }), "{:?}", consumer.state(Who::Guest));
    let outcome = consumer.poll().unwrap();
    assert_eq!(outcome.documents, 4, "doc 1, the head, and the two documents — one read each, whatever the row count");
    let served = dialer.served.lock().unwrap().clone();
    assert!(served.iter().all(|s| !s.token), "no token rides a read that feeds the published index: {:?}", served.iter().filter(|s| s.token).map(|s| &s.line).collect::<Vec<_>>());
    let retrievals = served.iter().filter(|s| s.line == "POST /op retrieve_v").count();
    assert_eq!(retrievals, 5, "H.1 for the board term, then one `retrieve_v` per document and the head record: {:?}", dialer.lines());
    let health_at = served.iter().position(|s| s.line == "GET /health").unwrap();
    let first_page = served.iter().position(|s| s.line.starts_with("GET /changes?")).unwrap();
    assert!(health_at < first_page, "the `/health` pair is read BEFORE the draining poll");
    assert_eq!(hits(&consumer, Who::Guest, "epsilon"), ["1.0.1.0.3"]);
    assert_eq!(hits(&consumer, Who::Guest, "alpha"), ["1.0.1.0.2"]);
    let position = world.lock().unwrap().position;
    assert_eq!(consumer.state(Who::Guest), State::Complete { as_of: position, floor: None });
    consumer.save().unwrap();
    let dir = board_dir(consumer.dir(), &world);
    let header = load_header(&dir.file(&BoardDir::published_name()), Class::Guest);
    assert_eq!(header.ranges[0].held, ChainAt { position, chain: Chain::parse(&chain_hex(position)).unwrap() }, "`held` is the `/health` pair");
    assert_eq!(header.head.as_ref().map(|h| h.member.to_string()).as_deref(), Some(HEAD_MEMBER_1), "the newest `H.k` the feed delivered");
    let answer = consumer.search(Who::Guest, "alpha beta", &SearchOpts::default()).unwrap();
    assert_eq!(answer.places.len(), 1, "the label matches exactly: {:?}", answer.places);
    assert_eq!((answer.places[0].doc.to_string().as_str(), answer.places[0].standing.clone()), ("1.0.1.0.2", Standing::Public));
    assert_eq!(consumer.search(Who::Guest, "1.0.1.0.3", &SearchOpts::default()).unwrap().places[0].doc.to_string(), "1.0.1.0.3", "an address parses exact");
    assert_eq!(consumer.counts(Who::Guest).get(&addr(ACCOUNT)), Some(&3), "doc 1 and the two documents under the account");
}

/// `search.md` §2.4: "The head member's address is the LATEST TRUNK MEMBER
/// any MINTING row names"; a DAUGHTER's row moves no head; "where the feed
/// above the floor holds no publish row … the shell finds the head by
/// probing the trunk's ordinals … with `doc_metadata` until the board
/// answers `doc_not_registered`"; an edition's parts are read at that
/// member, never at the bare address.
#[test]
fn a_minting_row_moves_the_head_a_daughter_moves_none_and_an_unnamed_trunk_is_probed() {
    let mut w = World::claimed();
    w.publish_member("1.0.1.0.2", 1, "first edition");
    w.publish_member("1.0.1.0.2", 2, "second edition");
    // A daughter `D.2.1` minted by a late shot: indexed nowhere.
    let at = w.next();
    w.rows.push(Row { at, op: Some("publish"), docs: Some(vec!["1.0.1.0.2.2.1".to_string()]), key: Some("bare"), draft: false });
    w.docs.insert("1.0.1.0.2.2.1".to_string(), Doc { text: b"a daughter".to_vec(), refuse: None });
    // A document whose publishes lie below what the feed holds: an `insert`
    // names the bare address; the trunk holds D.1..D.3.
    for k in 1..=3 {
        w.registered.insert(format!("1.0.1.0.4.{k}"));
        w.docs.insert(format!("1.0.1.0.4.{k}"), Doc { text: format!("probed edition {k}").into_bytes(), refuse: None });
    }
    w.publish("1.0.1.0.4", "the bare address floats");
    let world = shared(w);
    let (b, dialer) = board(&world);
    let tmp = tempfile::tempdir().unwrap();
    let consumer = Consumer::open(&b, SearchDir::new(tmp.path())).unwrap();
    consumer.poll().unwrap();
    assert_eq!(hits(&consumer, Who::Guest, "second"), ["1.0.1.0.2"]);
    assert!(hits(&consumer, Who::Guest, "first").is_empty(), "the old head's unit was replaced under the document's key");
    assert!(hits(&consumer, Who::Guest, "daughter").is_empty());
    assert_eq!(hits(&consumer, Who::Guest, "probed"), ["1.0.1.0.4"]);
    assert!(hits(&consumer, Who::Guest, "floats").is_empty(), "read at the pinned member D.3, never at the bare address");
    let answer = consumer.search(Who::Guest, "probed", &SearchOpts::default()).unwrap();
    assert_eq!(answer.hits[0].member.as_ref().map(ToString::to_string).as_deref(), Some("1.0.1.0.4.3"));
    let probes: Vec<String> = dialer.served.lock().unwrap().iter().filter(|s| s.line == "POST /op doc_metadata").map(|s| serde_json::from_slice::<Value>(&s.body).unwrap()["doc"].as_str().unwrap().to_string()).collect();
    assert_eq!(probes, ["1.0.1.0.1.1", "1.0.1.0.4.1", "1.0.1.0.4.2", "1.0.1.0.4.4", "1.0.1.0.4.3"], "the trunk probed once per such document, doubling to `doc_not_registered` then bisecting: {probes:?}");
    let reads: Vec<String> = dialer.served.lock().unwrap().iter().filter(|s| s.line == "POST /op retrieve_v").map(|s| serde_json::from_slice::<Value>(&s.body).unwrap()["specs"][0]["doc"].as_str().unwrap().to_string()).collect();
    assert!(reads.contains(&"1.0.1.0.2.2".to_string()) && !reads.contains(&"1.0.1.0.2".to_string()), "{reads:?}");
}

/// THE PUBLICATION's FEED ROW names every home its one commit touched —
/// `[member, D, N…, S…, E.j]` (wire.md §The change feed; the link-sets design
/// §5.7, THE FEED ROW), reduced per class — and the consumer reads it as it
/// reads any row: on the PUBLISHED face the member moves the edition's head
/// and the public set `S` is re-read as changed, while the older member
/// `E.j` a retraction landed in moves no head back and the bare `E` is never
/// read; on the DRAFTS face the member is passed over and the drafts `D` and
/// `N` are re-read. COST: one `retrieve_v` per home the row names on the
/// face that reads it — the set, the two drafts — beside the member's own,
/// correct and paid for by the publication's reach, not by a defect; the
/// consumer is unchanged.
#[test]
fn a_publications_row_re_reads_each_home_it_names_on_the_face_that_reads_it() {
    let mut w = World::claimed();
    w.publish_member("1.0.1.0.2", 1, "first edition");
    w.publish_member("1.0.1.0.2", 2, "second edition");
    w.publish("1.0.1.0.3", "the public set");
    w.draft("1.0.1.0.5", b"the staging draft");
    w.draft("1.0.1.0.6", b"the notes");
    let world = shared(w);
    let (b, dialer) = board(&world);
    let tmp = tempfile::tempdir().unwrap();
    let consumer = Consumer::open(&b, SearchDir::new(tmp.path())).unwrap();
    consumer.poll().unwrap();
    let tok = token();
    consumer.widen(session(&tok)).unwrap();
    assert_eq!(hits(&consumer, Who::Guest, "second"), ["1.0.1.0.2"]);
    // THE ROW: the member first, then the draft, then the other homes in
    // address order — on the published page reduced to its public homes, on
    // the drafts page whole.
    {
        let mut w = world.lock().unwrap();
        let at = w.next();
        w.docs.insert("1.0.1.0.2.3".to_string(), Doc { text: b"third edition published with links".to_vec(), refuse: None });
        w.registered.insert("1.0.1.0.2.3".to_string());
        w.docs.insert("1.0.1.0.3".to_string(), Doc { text: b"the public set with a copy".to_vec(), refuse: None });
        w.docs.insert("1.0.1.0.5".to_string(), Doc { text: b"the staging draft re-windowed".to_vec(), refuse: None });
        w.docs.insert("1.0.1.0.6".to_string(), Doc { text: b"the notes with a claim".to_vec(), refuse: None });
        w.rows.push(Row { at, op: Some("publish"), docs: Some(vec!["1.0.1.0.2.3".into(), "1.0.1.0.3".into(), "1.0.1.0.2.2".into()]), key: None, draft: false });
        w.rows.push(Row { at, op: Some("publish"), docs: Some(vec!["1.0.1.0.2.3".into(), "1.0.1.0.5".into(), "1.0.1.0.6".into(), "1.0.1.0.3".into(), "1.0.1.0.2.2".into()]), key: None, draft: true });
    }
    dialer.clear();
    consumer.poll().unwrap();
    let served = dialer.served.lock().unwrap().clone();
    let reads: Vec<(String, bool)> = served.iter().filter(|s| s.line == "POST /op retrieve_v").map(|s| (serde_json::from_slice::<Value>(&s.body).unwrap()["specs"][0]["doc"].as_str().unwrap().to_string(), s.token)).collect();
    assert!(reads.contains(&("1.0.1.0.2.3".to_string(), false)), "the member moves the head and is read at its address: {reads:?}");
    assert!(reads.contains(&("1.0.1.0.3".to_string(), false)), "the public set is re-read as changed: {reads:?}");
    assert!(!reads.iter().any(|(d, _)| d == "1.0.1.0.2.2" || d == "1.0.1.0.2"), "an older member moves no head back; the bare edition is never read: {reads:?}");
    assert!(reads.contains(&("1.0.1.0.5".to_string(), true)) && reads.contains(&("1.0.1.0.6".to_string(), true)), "the drafts are re-read under the session's token: {reads:?}");
    assert_eq!(reads.iter().filter(|(d, t)| d == "1.0.1.0.2.3" && *t).count(), 0, "the member is passed over on the drafts face");
    assert_eq!(hits(&consumer, Who::Guest, "third"), ["1.0.1.0.2"]);
    assert_eq!(hits(&consumer, Who::Guest, "copy"), ["1.0.1.0.3"]);
    assert_eq!(hits(&consumer, Who::Session(session(&tok)), "re-windowed"), ["1.0.1.0.5"]);
    assert_eq!(hits(&consumer, Who::Session(session(&tok)), "claim"), ["1.0.1.0.6"]);
    let answer = consumer.search(Who::Guest, "third", &SearchOpts::default()).unwrap();
    assert_eq!(answer.hits[0].member.as_ref().map(ToString::to_string).as_deref(), Some("1.0.1.0.2.3"), "the head is the member the row named first");
}

/// `search.md` §5.4: "a BARE ROW whose `op` is `null` or `publish` … is
/// COUNTED against the range it arrived on … While a range's count stands
/// the state WITHHOLDS `complete`" — §4b.2's `unplaced`; the REFRESH clears
/// it.
#[test]
fn a_bare_row_is_counted_and_withholds_complete_until_the_refresh() {
    let mut w = World::claimed();
    w.publish("1.0.1.0.2", "some text");
    w.bare();
    let world = shared(w);
    let (b, _) = board(&world);
    let tmp = tempfile::tempdir().unwrap();
    let consumer = Consumer::open(&b, SearchDir::new(tmp.path())).unwrap();
    consumer.poll().unwrap();
    assert_eq!(consumer.state(Who::Guest), State::Unplaced { range: Range::Board, count: 1 });
    consumer.reindex(Who::Guest).unwrap();
    assert!(matches!(consumer.state(Who::Guest), State::Complete { .. }));
    assert_eq!(hits(&consumer, Who::Guest, "text"), ["1.0.1.0.2"], "the refresh dropped nothing");
}

// ── THE PARTS RULE ───────────────────────────────────────────────────────

/// `client.md` §4e.2: "A delivery past `MAX_DELIVERY_ITEMS` … is read in
/// parts by span"; `search.md` §2.1: "A DRAFT's parts are read in sequence
/// … The parts are JOINED in order into ONE unit, its `as_of` the last
/// part's position" — a phrase across the parts' edge is found, and the
/// supplement's reads carry the session's token (§4 (i)).
#[test]
fn a_draft_past_the_delivery_budget_is_read_in_parts_and_joined_under_the_sessions_token() {
    let mut w = World::claimed();
    let mut text = vec![b'x'; (MAX_DELIVERY_ITEMS - 3) as usize];
    text.extend_from_slice(b" straddle edge words");
    let at = w.draft("1.0.1.2.0.1", &text);
    let world = shared(w);
    let (b, dialer) = board(&world);
    let tmp = tempfile::tempdir().unwrap();
    let consumer = Consumer::open(&b, SearchDir::new(tmp.path())).unwrap();
    consumer.poll().unwrap();
    dialer.clear();
    let tok = token();
    consumer.widen(session(&tok)).unwrap();
    let served = dialer.served.lock().unwrap().clone();
    let parts: Vec<&Served> = served.iter().filter(|s| s.line == "POST /op retrieve_v").collect();
    assert_eq!(parts.len(), 2, "two parts: {:?}", dialer.lines());
    assert!(parts.iter().all(|s| s.token), "the supplement's reads carry the session's token");
    let pages: Vec<&Served> = served.iter().filter(|s| s.line.starts_with("GET /changes?")).collect();
    assert!(pages.iter().all(|s| s.token && s.line.contains("drafts=true")), "{:?}", pages.iter().map(|s| &s.line).collect::<Vec<_>>());
    assert!(pages.iter().any(|s| s.line.contains(&format!("under={SUB_ACCOUNT}"))) && pages.iter().any(|s| s.line.contains("under=1.0.1&")), "the account's and its ancestor's ranges: {:?}", pages.iter().map(|s| &s.line).collect::<Vec<_>>());
    let answer = consumer.search(Who::Session(session(&tok)), "\"straddle edge\"", &SearchOpts::default()).unwrap();
    assert_eq!(answer.hits.len(), 1, "the phrase across the parts' edge is one phrase");
    assert_eq!((answer.hits[0].kind, answer.hits[0].standing.clone(), answer.hits[0].as_of >= at), (Kind::Draft, Standing::YoursToRead, true));
    assert!(hits(&consumer, Who::Guest, "straddle").is_empty(), "the guest face searches the published index alone (§4 (iii))");
}

/// `search.md` §2.1: "where a feed row naming it lies between its first
/// part's position and its last's, the join is DISCARDED and the draft
/// re-read at the next poll … the joined unit held PENDING in memory beside
/// its range until then, and the range's `held` passing the page that named
/// the draft only once the join is installed or discarded".
#[test]
fn a_straddled_drafts_join_is_held_pending_and_settled_by_the_next_polls_page() {
    let mut w = World::claimed();
    let mut text = vec![b'y'; (MAX_DELIVERY_ITEMS + 2) as usize];
    text.extend_from_slice(b" pending words");
    w.draft("1.0.1.2.0.1", &text);
    w.advance_on_read = true;
    let world = shared(w);
    let (b, _) = board(&world);
    let tmp = tempfile::tempdir().unwrap();
    let consumer = Consumer::open(&b, SearchDir::new(tmp.path())).unwrap();
    consumer.poll().unwrap();
    let tok = token();
    consumer.widen(session(&tok)).unwrap();
    assert!(hits(&consumer, Who::Session(session(&tok)), "pending").is_empty(), "the join is PENDING, not installed");
    consumer.save().unwrap();
    let dir = board_dir(consumer.dir(), &world);
    let header = load_header(&dir.file(&BoardDir::supplement_name(7)), Class::Principal(7));
    let own = header.ranges.iter().find(|r| r.under.as_ref().map(ToString::to_string).as_deref() == Some(SUB_ACCOUNT)).unwrap();
    assert_eq!(own.held.position, 0, "`held` did not pass the page that named the draft");
    // The next poll's page: a row naming the draft lies between the parts'
    // positions, so the join is discarded and the draft re-read whole.
    {
        let mut w = world.lock().unwrap();
        w.advance_on_read = false;
        let mut text = vec![b'z'; 10];
        text.extend_from_slice(b" settled words");
        let at = w.position; // between the first part's as_of and the last's
        w.rows.push(Row { at, op: Some("insert"), docs: Some(vec!["1.0.1.2.0.1".to_string()]), key: Some("bare"), draft: true });
        w.docs.insert("1.0.1.2.0.1".to_string(), Doc { text, refuse: None });
    }
    consumer.poll().unwrap();
    assert!(hits(&consumer, Who::Session(session(&tok)), "pending").is_empty(), "the straddled join was discarded");
    assert_eq!(hits(&consumer, Who::Session(session(&tok)), "settled"), ["1.0.1.2.0.1"], "and the draft re-read");
    consumer.save().unwrap();
    let header = load_header(&dir.file(&BoardDir::supplement_name(7)), Class::Principal(7));
    let position = world.lock().unwrap().position;
    assert!(header.ranges.iter().all(|r| r.held.position == position), "`held` passed once the join settled: {:?}", header.ranges.iter().map(|r| r.held.position).collect::<Vec<_>>());
}

// ── `held` AND THE REFUSALS ──────────────────────────────────────────────

/// `search.md` §4: "A range's `held` advances to a page's `last` only AFTER
/// every document the page named is INDEXED OR ITS REFUSAL RECORDED beside
/// the range — a `withheld` rejection … or `too_many_items` … a TRANSPORT
/// ERROR records nothing and holds `held` at the last whole page before it"
/// — and the recorded refusal is retried at the next widening.
#[test]
fn a_withheld_read_records_its_refusal_a_transport_error_holds_held_and_a_widening_retries() {
    let mut w = World::claimed();
    w.publish("1.0.1.0.2", "readable");
    let world = shared(w);
    let (b, _) = board(&world);
    let tmp = tempfile::tempdir().unwrap();
    let consumer = Consumer::open(&b, SearchDir::new(tmp.path())).unwrap();
    consumer.poll().unwrap();
    let tok = token();
    consumer.widen(session(&tok)).unwrap();
    let after_build = world.lock().unwrap().position;
    // A draft the board withholds mid-page, beside one it delivers.
    {
        let mut w = world.lock().unwrap();
        w.draft("1.0.1.2.0.1", b"shared");
        w.draft("1.0.1.2.0.2", b"withheld");
        w.docs.get_mut("1.0.1.2.0.2").unwrap().refuse = Some("withheld");
    }
    consumer.poll().unwrap();
    consumer.save().unwrap();
    let dir = board_dir(consumer.dir(), &world);
    let header = load_header(&dir.file(&BoardDir::supplement_name(7)), Class::Principal(7));
    let own = header.ranges.iter().find(|r| r.under.as_ref().map(ToString::to_string).as_deref() == Some(SUB_ACCOUNT)).unwrap();
    assert_eq!(own.refusals.iter().map(|r| (r.doc.to_string(), r.reason.clone())).collect::<Vec<_>>(), [("1.0.1.2.0.2".to_string(), "withheld".to_string())]);
    let withheld_at = world.lock().unwrap().position;
    assert_eq!(own.held.position, withheld_at, "the page is whole once the refusal is recorded");
    assert_eq!(hits(&consumer, Who::Session(session(&tok)), "shared"), ["1.0.1.2.0.1"]);
    // A transport error on a later page holds `held`.
    {
        let mut w = world.lock().unwrap();
        w.draft("1.0.1.2.0.3", b"unreachable");
        w.transport_fail.insert("1.0.1.2.0.3".to_string());
    }
    let err = consumer.poll().expect_err("the transport broke");
    assert_eq!(err.exit_code(), 4, "{err}");
    consumer.save().unwrap();
    let header = load_header(&dir.file(&BoardDir::supplement_name(7)), Class::Principal(7));
    let own = header.ranges.iter().find(|r| r.under.as_ref().map(ToString::to_string).as_deref() == Some(SUB_ACCOUNT)).unwrap();
    assert_eq!(own.held.position, withheld_at, "held at the last whole page");
    assert_eq!(own.refusals.len(), 1, "a transport error records nothing");
    // The board now admits the withheld draft: the next widening retries the
    // recorded refusal, and the transport mended, the page completes.
    {
        let mut w = world.lock().unwrap();
        w.docs.get_mut("1.0.1.2.0.2").unwrap().refuse = None;
        w.transport_fail.clear();
    }
    consumer.widen(session(&tok)).unwrap();
    assert_eq!(hits(&consumer, Who::Session(session(&tok)), "withheld"), ["1.0.1.2.0.2"], "retried at the widening");
    assert_eq!(hits(&consumer, Who::Session(session(&tok)), "unreachable"), ["1.0.1.2.0.3"]);
    consumer.save().unwrap();
    let header = load_header(&dir.file(&BoardDir::supplement_name(7)), Class::Principal(7));
    let own = header.ranges.iter().find(|r| r.under.as_ref().map(ToString::to_string).as_deref() == Some(SUB_ACCOUNT)).unwrap();
    assert!(own.refusals.is_empty(), "the record cleared once the document indexed");
    assert!(own.held.position > after_build);
}

/// `search.md` §7.4 at the arm: the ceiling's refusal is the crate's, counted
/// in `seen`, and composes as `past_the_ceiling` — `held` and `seen` in
/// units, `limit` in bytes (§4b.2) — tested at the composition, the crate's
/// own suite holding the refusal at its real constant.
#[test]
fn past_the_ceiling_composes_from_seen_with_units_and_the_limit_in_bytes() {
    let header = Header { board: Chain::from_bytes([1; 32]), floor: None, ranges: Vec::new(), head: None };
    let stats = Stats { units: 10, terms: 0, postings: 0, bytes: 5, tombstones: 0, dead_postings: 0, ceiling: CEILING_BYTES, seen: 3 };
    let facts = Facts { stats, header: &header, building: None, widening: None, resumed: None, lost: None, aside: false };
    assert_eq!(State::compose(&[Part::Index(facts)]), State::PastTheCeiling { held: 10, seen: 3, limit: CEILING_BYTES });
}

/// `search.md` §7.4 at the composition, the consumer's half: a document the
/// consumer refused past the ceiling before reading it whole is a unit
/// `seen` beside the crate's own count — once, whichever ranges recorded it
/// — and a refusal of another word composes nothing.
#[test]
fn past_the_ceiling_counts_the_consumers_own_refusals_once_a_document() {
    let refusal = |doc: &str, reason: &str| Refusal { doc: addr(doc), reason: reason.to_string() };
    let range = |under: Option<&str>, refusals: Vec<Refusal>| RangeRecord {
        under: under.map(addr),
        held: ChainAt { position: 40, chain: Chain::from_bytes([2; 32]) },
        refusals,
        bare_rows: 0,
        grant: None,
    };
    let header = Header {
        board: Chain::from_bytes([1; 32]),
        floor: None,
        ranges: vec![
            range(Some(SUB_ACCOUNT), vec![refusal("1.0.1.2.0.1", "unit_past_the_ceiling"), refusal("1.0.1.2.0.2", "withheld")]),
            range(Some(ACCOUNT), vec![refusal("1.0.1.2.0.1", "unit_past_the_ceiling")]),
        ],
        head: None,
    };
    let withheld = Header { ranges: vec![range(None, vec![refusal("1.0.1.0.2", "withheld")])], ..header.clone() };
    let stats = |seen: u64| Stats { units: 4, terms: 0, postings: 0, bytes: 0, tombstones: 0, dead_postings: 0, ceiling: CEILING_BYTES, seen };
    let facts = |header, seen| Facts { stats: stats(seen), header, building: None, widening: None, resumed: None, lost: None, aside: false };
    assert_eq!(State::compose(&[Part::Index(facts(&header, 0))]), State::PastTheCeiling { held: 4, seen: 1, limit: CEILING_BYTES });
    assert_eq!(State::compose(&[Part::Index(facts(&header, 2))]), State::PastTheCeiling { held: 4, seen: 3, limit: CEILING_BYTES });
    assert_eq!(State::compose(&[Part::Index(facts(&withheld, 0))]), State::Complete { as_of: 40, floor: None });
}

// ── THE RESUME's DISPOSITIONS ────────────────────────────────────────────

/// A consumer built, saved and dropped, so a second open resumes.
fn built_and_closed(world: &Arc<Mutex<World>>, dir: &SearchDir) -> ChainAt {
    let (b, _) = board(world);
    let consumer = Consumer::open(&b, dir.clone()).unwrap();
    consumer.poll().unwrap();
    consumer.close().unwrap();
    let position = world.lock().unwrap().position;
    ChainAt { position, chain: Chain::parse(&chain_hex(position)).unwrap() }
}

/// `search.md` §5.4: "an EQUAL chain resumes" — from `held`: the documents
/// indexed before stand, and only the change since is read.
#[test]
fn an_equal_chain_resumes_from_held_and_reads_only_what_changed_since() {
    let mut w = World::claimed();
    w.publish("1.0.1.0.2", "kept across the restart");
    let world = shared(w);
    let tmp = tempfile::tempdir().unwrap();
    let dir = SearchDir::new(tmp.path());
    let held = built_and_closed(&world, &dir);
    world.lock().unwrap().publish("1.0.1.0.3", "written since");
    world.lock().unwrap().new_head(2);
    let (b, dialer) = board(&world);
    let consumer = Consumer::open(&b, dir.clone()).unwrap();
    assert_eq!(dialer.lines().iter().filter(|l| l.starts_with("GET /chain?at=")).collect::<Vec<_>>(), [&format!("GET /chain?at={}", held.position)], "one read per distinct saved position");
    assert_eq!(hits(&consumer, Who::Guest, "kept"), ["1.0.1.0.2"], "the file's units stand before any poll");
    dialer.clear();
    consumer.poll().unwrap();
    assert_eq!(dialer.reads_of("retrieve_v"), 3, "the one document written since, the new head's unit and its record: {:?}", dialer.lines());
    assert_eq!(hits(&consumer, Who::Guest, "since"), ["1.0.1.0.3"]);
    assert!(matches!(consumer.state(Who::Guest), State::Complete { .. }));
    consumer.close().unwrap();
    let header = load_header(&board_dir(&dir, &world).file(&BoardDir::published_name()), Class::Guest);
    assert_eq!(header.head.as_ref().map(|h| h.member.to_string()).as_deref(), Some(&*format!("{HEAD_DOCUMENT}.2")), "the newest `H.k` the feed delivered, off the read made at its system publish row");
}

/// `search.md` §5.4, ITEM 1 RULED (a) with rider 1: "`history_reclaimed` …
/// KEEPS THE FILE: each range resumes from the `floor` the answer carries …
/// the shell re-reads that `H.k` byte-equal" — §4b.2's
/// `resumed_from_the_floor {floor, held}`; nothing is moved aside.
#[test]
fn history_reclaimed_keeps_the_file_and_resumes_from_the_floor_with_the_hk_byte_equal() {
    let mut w = World::claimed();
    w.publish("1.0.1.0.2", "below the floor");
    let world = shared(w);
    let tmp = tempfile::tempdir().unwrap();
    let dir = SearchDir::new(tmp.path());
    let held = built_and_closed(&world, &dir);
    let floor = {
        let mut w = world.lock().unwrap();
        for _ in 0..5 {
            w.publish("1.0.1.0.3", "above the floor");
        }
        let floor = w.position - 2;
        w.floor = Some(floor);
        floor
    };
    let (b, dialer) = board(&world);
    let consumer = Consumer::open(&b, dir.clone()).unwrap();
    assert_eq!(consumer.state(Who::Guest), State::ResumedFromTheFloor { floor, held });
    let lines = dialer.lines();
    assert!(lines.iter().any(|l| l == &format!("GET /chain?at={}", held.position)));
    let rereads = dialer.served.lock().unwrap().iter().filter(|s| s.line == "POST /op retrieve_v" && serde_json::from_slice::<Value>(&s.body).unwrap()["specs"][0]["doc"] == HEAD_MEMBER_1).count();
    assert!(rereads >= 1, "the saved `H.k` re-read: {lines:?}");
    let bdir = board_dir(&dir, &world);
    assert!(bdir.file(&BoardDir::published_name()).is_file());
    assert!(std::fs::read_dir(bdir.path()).unwrap().filter_map(Result::ok).all(|e| !e.file_name().to_string_lossy().contains(".aside.")), "nothing moved aside");
    assert_eq!(hits(&consumer, Who::Guest, "below"), ["1.0.1.0.2"], "a document written below the floor is searched as last read");
    consumer.poll().unwrap();
    assert_eq!(hits(&consumer, Who::Guest, "above"), ["1.0.1.0.3"]);
    assert_eq!(consumer.state(Who::Guest), State::ResumedFromTheFloor { floor, held }, "the arm stands for the open's life");
    consumer.save().unwrap();
    let header = load_header(&bdir.file(&BoardDir::published_name()), Class::Guest);
    assert_eq!(header.floor, Some(floor), "the file states its completeness");
}

/// §5.4, riders 1 and 2: a DIFFERENT chain, `beyond_head`, and an `H.k`
/// found different are each "FACED BEFORE ANYTHING IS REBUILT … the file
/// with its saved pair is MOVED ASIDE … and this board's index is built
/// fresh" — §4b.2's `building {lost: diverged}`; the aside never overwrites.
#[test]
fn a_different_chain_beyond_head_or_a_changed_hk_moves_the_file_aside_with_its_pair_and_builds_fresh() {
    for case in ["different chain", "beyond head", "changed H.k"] {
        let mut w = World::claimed();
        w.publish("1.0.1.0.2", "the old history");
        let h2_at = w.new_head(2);
        let world = shared(w);
        let tmp = tempfile::tempdir().unwrap();
        let dir = SearchDir::new(tmp.path());
        let held = built_and_closed(&world, &dir);
        {
            let mut w = world.lock().unwrap();
            match case {
                "different chain" => {
                    w.chains.insert(held.position, "ab".repeat(32));
                }
                "beyond head" => w.position = held.position - 3,
                _ => {
                    // Below the floor, the saved `H.2` re-reads with another
                    // chain: the history diverged where the floor hides it.
                    w.floor = Some(held.position + 1);
                    w.head_members.insert(format!("{HEAD_DOCUMENT}.2"), (h2_at, "cd".repeat(32)));
                    for _ in 0..3 {
                        w.publish("1.0.1.0.3", "later");
                    }
                }
            }
        }
        let (b, _) = board(&world);
        let consumer = Consumer::open(&b, dir.clone()).unwrap();
        assert_eq!(consumer.state(Who::Guest), State::Building { position: 0, units: 0, lost: Some(Lost::Diverged { held }), aside: false }, "{case}");
        let bdir = board_dir(&dir, &world);
        let aside = bdir.file(&skep_search::aside_name(&BoardDir::published_name(), bdir.chain(), 1));
        assert!(aside.is_file(), "{case}: the file moved aside with its pair at {}", aside.display());
        let header = load_header(&aside, Class::Guest);
        assert_eq!(header.ranges[0].held, held, "{case}: the saved pair rides the aside");
        assert!(hits(&consumer, Who::Guest, "old").is_empty(), "{case}: nothing of the untrusted file answers");
    }
}

/// §5.4: "`history_busy` is retry-class and retried, never a rebuild".
#[test]
fn history_busy_retries_and_then_resumes() {
    let mut w = World::claimed();
    w.publish("1.0.1.0.2", "kept");
    let world = shared(w);
    let tmp = tempfile::tempdir().unwrap();
    let dir = SearchDir::new(tmp.path());
    built_and_closed(&world, &dir);
    world.lock().unwrap().busy = 2;
    let (b, dialer) = board(&world);
    let consumer = Consumer::open(&b, dir).unwrap();
    assert_eq!(dialer.lines().iter().filter(|l| l.starts_with("GET /chain?at=")).count(), 3, "two busy answers, then the chain");
    assert_eq!(hits(&consumer, Who::Guest, "kept"), ["1.0.1.0.2"]);
    assert!(matches!(consumer.state(Who::Guest), State::Complete { .. }));
}

// ── THE ASIDE AND THE FILE's FACES ───────────────────────────────────────

/// `search.md` §5.4, ITEM 1b (c): a CRC-valid index naming another board is
/// MOVED ASIDE "renamed … to `<name>.aside.<its own board's chain>.<n>` …
/// `<n>` the first free ordinal so a second misplaced file of the same
/// board lands beside the first and nothing is ever overwritten" — §4b.2's
/// `building {aside: true}`; the originals byte-identical after.
#[test]
fn a_misplaced_file_is_set_aside_at_ordinal_one_then_two_and_the_originals_are_byte_identical() {
    // Board B's index, saved under B's chain.
    let mut other = World::claimed();
    other.head = Some((20, "bb".repeat(32)));
    other.head_members.insert(HEAD_MEMBER_1.to_string(), (20, "bb".repeat(32)));
    other.publish("1.0.1.0.2", "board B's text");
    let other = shared(other);
    let other_tmp = tempfile::tempdir().unwrap();
    let other_dir = SearchDir::new(other_tmp.path());
    built_and_closed(&other, &other_dir);
    let b_file = other_dir.board(&Chain::parse(&"bb".repeat(32)).unwrap()).file(&BoardDir::published_name());
    let b_bytes = std::fs::read(&b_file).unwrap();
    // Copied into board A's directory, twice over two opens.
    let world = shared(World::claimed());
    let tmp = tempfile::tempdir().unwrap();
    let dir = SearchDir::new(tmp.path());
    let a_dir = board_dir(&dir, &world);
    a_dir.ensure().unwrap();
    std::fs::write(a_dir.file(&BoardDir::published_name()), &b_bytes).unwrap();
    let (b, _) = board(&world);
    let consumer = Consumer::open(&b, dir.clone()).unwrap();
    assert_eq!(consumer.state(Who::Guest), State::Building { position: 0, units: 0, lost: None, aside: true });
    let aside1 = a_dir.file(&skep_search::aside_name(&BoardDir::published_name(), &Chain::parse(&"bb".repeat(32)).unwrap(), 1));
    assert_eq!(std::fs::read(&aside1).unwrap(), b_bytes, "byte-identical at ordinal 1");
    consumer.close().unwrap();
    let a_bytes = std::fs::read(a_dir.file(&BoardDir::published_name())).unwrap();
    let mut b_again = b_bytes.clone();
    b_again.push(0); // a second, different misplaced copy of B's — damaged, but the aside keeps bytes as they are
    b_again.pop();
    std::fs::write(a_dir.file(&BoardDir::published_name()), &b_again).unwrap();
    let (b2, _) = board(&world);
    let _consumer = Consumer::open(&b2, dir.clone()).unwrap();
    let aside2 = a_dir.file(&skep_search::aside_name(&BoardDir::published_name(), &Chain::parse(&"bb".repeat(32)).unwrap(), 2));
    assert_eq!(std::fs::read(&aside1).unwrap(), b_bytes, "ordinal 1 untouched");
    assert_eq!(std::fs::read(&aside2).unwrap(), b_again, "the second lands at ordinal 2");
    assert_ne!(a_bytes, b_bytes, "board A's own file was built fresh");
}

/// `search.md` §5.4: "an index … whose `kind` and `principal` are not the
/// class its file name and the session name … is a MISPLACED file … MOVED
/// ASIDE", refused at `load` before its body is read (`LoadError::
/// OtherClass`), under its own chain off its header line.
#[test]
fn a_file_of_another_principals_class_is_set_aside_under_its_own_chain() {
    let world = shared(World::claimed());
    let tmp = tempfile::tempdir().unwrap();
    let dir = SearchDir::new(tmp.path());
    let bdir = board_dir(&dir, &world);
    bdir.ensure().unwrap();
    // Principal 9's supplement saved under principal 7's name.
    let mut nine = Index::new(Class::Principal(9));
    let unit = skep_search::Unit::new(skep_search::UnitKey::new(addr("1.0.1.3.0.1")), None, Kind::Draft, Class::Principal(9), 1, vec![skep_search::Item::Text { start: 1, bytes: b"nine's draft".to_vec() }]).unwrap();
    nine.index(unit).unwrap();
    let header = Header { board: *bdir.chain(), floor: None, ranges: Vec::new(), head: None };
    let mut bytes = Vec::new();
    nine.save(&header, &mut bytes).unwrap();
    std::fs::write(bdir.file(&BoardDir::supplement_name(7)), &bytes).unwrap();
    let (b, _) = board(&world);
    let consumer = Consumer::open(&b, dir.clone()).unwrap();
    consumer.poll().unwrap();
    let tok = token();
    consumer.widen(session(&tok)).unwrap();
    let aside = bdir.file(&skep_search::aside_name(&BoardDir::supplement_name(7), bdir.chain(), 1));
    assert_eq!(std::fs::read(&aside).unwrap(), bytes, "set aside, byte-identical");
    assert!(hits(&consumer, Who::Session(session(&tok)), "nine's").is_empty(), "no other principal's holding answers this session");
    assert!(matches!(consumer.state(Who::Session(session(&tok))), State::Complete { .. }), "{:?}", consumer.state(Who::Session(session(&tok))));
}

/// `search.md` §5.1: "a NEWER `v` is FACED and NEVER OVERWRITTEN — this skep
/// searches nothing from that file and writes none in its place" — §4b.2's
/// `newer_skep {v}`.
#[test]
fn a_newer_skeps_file_is_faced_searched_not_and_left_untouched() {
    let mut w = World::claimed();
    w.publish("1.0.1.0.2", "from the future");
    let world = shared(w);
    let tmp = tempfile::tempdir().unwrap();
    let dir = SearchDir::new(tmp.path());
    built_and_closed(&world, &dir);
    let path = board_dir(&dir, &world).file(&BoardDir::published_name());
    let mut bytes = std::fs::read(&path).unwrap();
    let at = bytes.windows(6).position(|w| w == b"\"v\":1,").unwrap();
    bytes[at + 4] = b'2';
    std::fs::write(&path, &bytes).unwrap();
    let (b, _) = board(&world);
    let consumer = Consumer::open(&b, dir.clone()).unwrap();
    assert_eq!(consumer.state(Who::Guest), State::NewerSkep { v: Newer::Version { v: 2 } });
    let answer = consumer.search(Who::Guest, "future", &SearchOpts::default()).unwrap();
    assert!(answer.hits.is_empty() && answer.state == State::NewerSkep { v: Newer::Version { v: 2 } });
    consumer.poll().unwrap();
    consumer.close().unwrap();
    assert_eq!(std::fs::read(&path).unwrap(), bytes, "the file untouched");
}

/// `search.md` §5.1: a file "whose trailer disagrees with its header and
/// body" is "DAMAGED and REBUILT (§5.4), the state event stating what the
/// rebuild cannot restore" — §4b.2's `building {lost: damaged}`.
#[test]
fn a_damaged_file_is_rebuilt_with_its_loss_stated() {
    let mut w = World::claimed();
    w.publish("1.0.1.0.2", "damaged later");
    let world = shared(w);
    let tmp = tempfile::tempdir().unwrap();
    let dir = SearchDir::new(tmp.path());
    built_and_closed(&world, &dir);
    let path = board_dir(&dir, &world).file(&BoardDir::published_name());
    let mut bytes = std::fs::read(&path).unwrap();
    let last = bytes.len() - 1;
    bytes[last] ^= 0xff;
    std::fs::write(&path, &bytes).unwrap();
    let (b, _) = board(&world);
    let consumer = Consumer::open(&b, dir).unwrap();
    match consumer.state(Who::Guest) {
        State::Building { lost: Some(Lost::Damaged { what }), aside: false, .. } => assert!(what.contains("trailer"), "{what}"),
        other => panic!("{other:?}"),
    }
    consumer.poll().unwrap();
    assert_eq!(hits(&consumer, Who::Guest, "damaged"), ["1.0.1.0.2"], "rebuilt from the feed");
}

// ── ONE WRITER ───────────────────────────────────────────────────────────

/// `search.md` §5.6, RULED refuse for v1: "A SECOND PROCESS on the same data
/// directory … finding the lock held is REFUSED ITS SEARCH … no second
/// mount"; the lock "dies with the process" — here with the first
/// consumer's value.
#[test]
fn a_second_consumer_on_the_directory_answers_busy_and_mounts_nothing_until_the_first_is_gone() {
    let mut w = World::claimed();
    w.publish("1.0.1.0.2", "the first's text");
    let world = shared(w);
    let tmp = tempfile::tempdir().unwrap();
    let dir = SearchDir::new(tmp.path());
    let (b1, _) = board(&world);
    let first = Consumer::open(&b1, dir.clone()).unwrap();
    first.poll().unwrap();
    let (b2, dialer2) = board(&world);
    let second = Consumer::open(&b2, dir.clone()).unwrap();
    assert_eq!(second.state(Who::Guest), State::Busy);
    let answer = second.search(Who::Guest, "text", &SearchOpts::default()).unwrap();
    assert!(answer.hits.is_empty() && answer.state == State::Busy);
    dialer2.clear();
    second.poll().unwrap();
    assert!(dialer2.lines().is_empty(), "a busy consumer polls nothing: {:?}", dialer2.lines());
    assert!(second.board_dir().is_none(), "mounted nothing");
    first.close().unwrap();
    let (b3, _) = board(&world);
    let third = Consumer::open(&b3, dir).unwrap();
    assert_eq!(hits(&third, Who::Guest, "text"), ["1.0.1.0.2"], "the lock died with the first");
}

// ── THE SAVE ─────────────────────────────────────────────────────────────

/// `client.md` §4e.4: "WRITTEN WHOLE BY THE SHELL's RENAME — `<name>.tmp`
/// beside the file, written, synced, renamed over the old" — a crash between
/// the two leaves the old file readable, and the next open reads it whole.
#[test]
fn a_crash_between_the_tmp_and_the_rename_leaves_the_old_file_readable() {
    let mut w = World::claimed();
    w.publish("1.0.1.0.2", "the old save");
    let world = shared(w);
    let tmp = tempfile::tempdir().unwrap();
    let dir = SearchDir::new(tmp.path());
    built_and_closed(&world, &dir);
    let bdir = board_dir(&dir, &world);
    let old = std::fs::read(bdir.file(&BoardDir::published_name())).unwrap();
    // The crash: the `.tmp` written and synced, the rename never made.
    bdir.write_tmp(&BoardDir::published_name(), b"a half-saved index").unwrap();
    assert_eq!(std::fs::read(bdir.file(&BoardDir::published_name())).unwrap(), old, "the old file as it was");
    let (b, _) = board(&world);
    let consumer = Consumer::open(&b, dir).unwrap();
    assert_eq!(hits(&consumer, Who::Guest, "old"), ["1.0.1.0.2"]);
    consumer.close().unwrap();
    assert!(!bdir.file("published.index.tmp").is_file() || std::fs::read(bdir.file(&BoardDir::published_name())).unwrap() != b"a half-saved index", "the rename completes a save, never adopts a stray tmp");
}

/// `client.md` §3.3 at the directory (§4e.4; `search.md` §5.3): directories
/// `0700`, files `0600`, set at creation.
#[cfg(unix)]
#[test]
fn the_directory_is_0700_and_its_files_0600() {
    use std::os::unix::fs::PermissionsExt;
    let mut w = World::claimed();
    w.publish("1.0.1.0.2", "modes");
    let world = shared(w);
    let tmp = tempfile::tempdir().unwrap();
    let dir = SearchDir::new(tmp.path());
    built_and_closed(&world, &dir);
    let bdir = board_dir(&dir, &world);
    let mode = |p: &std::path::Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode(dir.root()), 0o700);
    assert_eq!(mode(bdir.path()), 0o700);
    for name in [BoardDir::published_name(), BoardDir::published_places_name(), super::LOCK_NAME.to_string()] {
        assert_eq!(mode(&bdir.file(&name)), 0o600, "{name}");
    }
}

// ── THE TRIGGERS ─────────────────────────────────────────────────────────

/// `client.md` §4e.3: WIDEN "at a FOLD-HONORED GRANT … found by the poll's
/// DISCOVERY READ: the p-keyed grant-typed query and the ANY-PRINCIPAL read
/// … each grant's prefix" fetched; `search.md` §3.1: a hit under a range the
/// honored set no longer admits is `Held` with the departed grant's `{kind,
/// rung, issuer}` off the range's record; a place the same at the document
/// grain (§4e.5); REVOCATION "triggers NOTHING" on the index.
#[test]
fn a_discovered_grant_widens_a_range_and_its_revocation_leaves_the_hit_held_with_the_cell() {
    let mut w = World::claimed();
    // 1.0.2 grants its draft 1.0.2.0.5 to the sub-account, by name.
    w.grants.push(GrantRow { link: "1.0.2.0.1.0.2.1".to_string(), from: "1.0.2.0.5".to_string(), to: SUB_ACCOUNT.to_string() });
    w.draft("1.0.2.0.5", b"granted words");
    // 1.0.3 grants its account to every principal.
    w.universal.push(("1.0.3".to_string(), vec!["1.0.3".to_string()]));
    w.draft("1.0.3.0.1", b"universal words");
    let world = shared(w);
    let (b, dialer) = board(&world);
    let tmp = tempfile::tempdir().unwrap();
    let consumer = Consumer::open(&b, SearchDir::new(tmp.path())).unwrap();
    consumer.poll().unwrap();
    let tok = token();
    consumer.widen(session(&tok)).unwrap();
    let lines = dialer.lines();
    assert!(lines.contains(&"POST /op find_links_ftt".to_string()) && lines.contains(&"POST /op universal_grants".to_string()), "the two discovery reads beside each other: {lines:?}");
    let who = Who::Session(session(&tok));
    let answer = consumer.search(who, "granted", &SearchOpts::default()).unwrap();
    assert_eq!((answer.hits.len(), answer.hits[0].standing.clone()), (1, Standing::YoursToRead));
    assert_eq!(hits(&consumer, who, "universal"), ["1.0.3.0.1"]);
    assert_eq!(consumer.search(who, "granted words", &SearchOpts::default()).unwrap().places[0].standing, Standing::YoursToRead);
    // The revocation: a grant-typed link whose `from` names the grant.
    {
        let mut w = world.lock().unwrap();
        w.grants.push(GrantRow { link: "1.0.2.0.1.0.2.2".to_string(), from: "1.0.2.0.1.0.2.1".to_string(), to: SUB_ACCOUNT.to_string() });
        w.universal.clear();
        w.position += 1;
    }
    consumer.poll().unwrap();
    let held = Standing::Held { kind: GrantKind::Named, rung: Rung::Document, issuer: addr("1.0.2") };
    let answer = consumer.search(who, "granted words", &SearchOpts::default()).unwrap();
    assert_eq!(answer.hits[0].standing, held, "the hit stands, marked Held with the departed grant's cell");
    assert_eq!(answer.places[0].standing, held, "the place at the document grain");
    assert_eq!(consumer.places(who, Some(&addr("1.0.2.0.5"))).docs[0].standing, held, "and the listed document");
    let answer = consumer.search(who, "universal", &SearchOpts::default()).unwrap();
    assert_eq!(answer.hits[0].standing, Standing::Held { kind: GrantKind::AnyPrincipal, rung: Rung::Account, issuer: addr("1.0.3") });
    consumer.save().unwrap();
    let header = load_header(&board_dir(consumer.dir(), &world).file(&BoardDir::supplement_name(7)), Class::Principal(7));
    let granted = header.ranges.iter().find(|r| r.under.as_ref().map(ToString::to_string).as_deref() == Some("1.0.2.0.5")).expect("the range stays");
    assert_eq!(granted.grant, Some(Grant { kind: GrantKind::Named, issuer: addr("1.0.2") }), "the cell's keys written beside the range when the widening added it");
}

/// `client.md` §4e.3: NARROW — "The supplement's file stays"; `search.md` §4:
/// "a query runs over the published index alone"; a re-widening "finds the
/// supplement held below its last position and fetches from there".
#[test]
fn narrow_unmounts_the_supplement_keeps_its_file_and_a_re_widening_resumes_from_held() {
    let mut w = World::claimed();
    w.publish("1.0.1.0.2", "published words");
    w.draft("1.0.1.2.0.1", b"my draft");
    let world = shared(w);
    let (b, dialer) = board(&world);
    let tmp = tempfile::tempdir().unwrap();
    let consumer = Consumer::open(&b, SearchDir::new(tmp.path())).unwrap();
    consumer.poll().unwrap();
    let tok = token();
    consumer.widen(session(&tok)).unwrap();
    let who = Who::Session(session(&tok));
    assert_eq!(hits(&consumer, who, "draft"), ["1.0.1.2.0.1"]);
    consumer.narrow(7).unwrap();
    assert!(!consumer.mounted(7));
    assert!(hits(&consumer, who, "draft").is_empty(), "the published index alone");
    assert_eq!(hits(&consumer, who, "published"), ["1.0.1.0.2"]);
    assert!(consumer.search(who, "my draft", &SearchOpts::default()).unwrap().places.is_empty(), "the principal's part retired from `places`");
    assert!(consumer.places(who, Some(&addr(SUB_ACCOUNT))).docs.is_empty(), "and from the listing");
    let file = board_dir(consumer.dir(), &world).file(&BoardDir::supplement_name(7));
    assert!(file.is_file(), "the file stays");
    dialer.clear();
    consumer.widen(session(&tok)).unwrap();
    assert_eq!(dialer.reads_of("retrieve_v"), 0, "re-widened from `held`: nothing re-read: {:?}", dialer.lines());
    assert_eq!(hits(&consumer, who, "draft"), ["1.0.1.2.0.1"]);
    // The forget: the person's act alone — the files gone.
    consumer.forget(7).unwrap();
    assert!(!file.is_file() && !board_dir(consumer.dir(), &world).file(&BoardDir::supplement_places_name(7)).is_file());
    assert!(!consumer.mounted(7));
}

/// `search.md` §5.5: the REFRESH — "every unit the pair holds RE-READ at
/// its own class, the published units token-free and the supplement's at the
/// principal's … NOTHING DROPPED: a unit whose re-read is refused keeps its
/// last indexed text, its refusal recorded"; "the guest form's refreshes the
/// published index alone, so nothing another principal holds is touched".
#[test]
fn the_refresh_re_reads_every_unit_at_its_own_class_drops_nothing_and_the_guest_form_touches_no_supplement() {
    let mut w = World::claimed();
    w.publish("1.0.1.0.2", "published one");
    w.publish("1.0.1.0.3", "published two");
    w.draft("1.0.1.2.0.1", b"a draft");
    let world = shared(w);
    let (b, dialer) = board(&world);
    let tmp = tempfile::tempdir().unwrap();
    let consumer = Consumer::open(&b, SearchDir::new(tmp.path())).unwrap();
    consumer.poll().unwrap();
    let tok = token();
    consumer.widen(session(&tok)).unwrap();
    // The board now withholds one published document's re-read (a revoked
    // holding's shape) and the draft's.
    {
        let mut w = world.lock().unwrap();
        w.docs.get_mut("1.0.1.0.3").unwrap().refuse = Some("withheld");
        w.docs.get_mut("1.0.1.2.0.1").unwrap().refuse = Some("withheld");
    }
    dialer.clear();
    consumer.reindex(Who::Guest).unwrap();
    let served = dialer.served.lock().unwrap().clone();
    let reads: Vec<&Served> = served.iter().filter(|s| s.line == "POST /op retrieve_doc_v_span_set" || s.line == "POST /op retrieve_v").collect();
    assert!(!reads.is_empty() && reads.iter().all(|s| !s.token), "the guest refresh reads token-free alone: {:?}", served.iter().filter(|s| s.token).map(|s| &s.line).collect::<Vec<_>>());
    assert_eq!(hits(&consumer, Who::Guest, "two"), ["1.0.1.0.3"], "the refused re-read keeps its text");
    consumer.save().unwrap();
    let bdir = board_dir(consumer.dir(), &world);
    let header = load_header(&bdir.file(&BoardDir::published_name()), Class::Guest);
    assert_eq!(header.ranges[0].refusals.iter().map(|r| r.doc.to_string()).collect::<Vec<_>>(), ["1.0.1.0.3"], "its refusal recorded");
    let who = Who::Session(session(&tok));
    assert_eq!(hits(&consumer, who, "draft"), ["1.0.1.2.0.1"], "the supplement untouched");
    dialer.clear();
    consumer.reindex(who).unwrap();
    let served = dialer.served.lock().unwrap().clone();
    assert!(served.iter().any(|s| s.line == "POST /op retrieve_doc_v_span_set" && s.token), "the session's refresh re-reads the supplement under its token");
    assert_eq!(hits(&consumer, who, "draft"), ["1.0.1.2.0.1"], "nothing dropped");
}

// ── THE BRIDGE CALL ──────────────────────────────────────────────────────

/// `client.md` §4e.5: "THE QUERY IS UNTRUSTED INPUT — the shell bounds its
/// length (an INTERIM 1,024 bytes; `query_too_long` its own refusal, its
/// detail echoing no input)"; "PURE LOCAL: no board read on the call's path".
#[test]
fn the_query_is_bounded_at_1024_bytes_the_refusal_echoes_nothing_and_the_call_dials_nothing() {
    let mut w = World::claimed();
    w.publish("1.0.1.0.2", "needle in the index");
    let world = shared(w);
    let (b, dialer) = board(&world);
    let tmp = tempfile::tempdir().unwrap();
    let consumer = Consumer::open(&b, SearchDir::new(tmp.path())).unwrap();
    consumer.poll().unwrap();
    dialer.clear();
    let long = "s".repeat(QUERY_BOUND + 1);
    let err = consumer.search(Who::Guest, &long, &SearchOpts::default()).expect_err("too long");
    assert_eq!(err, QueryTooLong { bound: 1024, length: 1025 });
    assert!(!err.to_string().contains("sss"), "{err}");
    let exact = "n".repeat(QUERY_BOUND);
    assert!(consumer.search(Who::Guest, &exact, &SearchOpts::default()).is_ok(), "the bound admits 1,024 bytes");
    assert_eq!(hits(&consumer, Who::Guest, "needle"), ["1.0.1.0.2"]);
    assert!(dialer.lines().is_empty(), "no board read on the call's path: {:?}", dialer.lines());
}

/// The listing is every document of the parts the call reads (A-255).
///
/// Foundations §2's far scale is "drawn from the client's index read
/// whole", its counts per account "masked at the reader's class" (A-260),
/// as `places` is drawn at the call's class (§4e.5). The listing holds every
/// document of the parts the call reads — the guest's no draft, a session's
/// the guest's and its own part's — in address order, each the place a
/// match of its address answers; its counts are tallied over the documents
/// listed, a prefix narrows both, and the call dials nothing.
#[test]
fn the_listing_is_every_document_of_the_parts_at_the_calls_class() {
    let mut w = World::claimed();
    w.publish("1.0.1.0.2", "alpha\nbeta");
    w.publish("1.0.2.0.1", "elsewhere");
    w.draft("1.0.1.2.0.1", b"my draft\nbody");
    let world = shared(w);
    let (b, dialer) = board(&world);
    let tmp = tempfile::tempdir().unwrap();
    let consumer = Consumer::open(&b, SearchDir::new(tmp.path())).unwrap();
    consumer.poll().unwrap();
    let tok = token();
    consumer.widen(session(&tok)).unwrap();
    let who = Who::Session(session(&tok));
    dialer.clear();
    let docs = |answer: &PlacesAnswer| answer.docs.iter().map(|p| p.doc.to_string()).collect::<Vec<_>>();
    let counts = |pairs: &[(&str, usize)]| pairs.iter().map(|(account, n)| (addr(account), *n)).collect::<BTreeMap<_, _>>();
    let guest = consumer.places(Who::Guest, None);
    assert_eq!(docs(&guest), ["1.0.1.0.1", "1.0.1.0.2", "1.0.2.0.1", HEAD_DOCUMENT], "the published part alone, in address order");
    assert_eq!(guest.counts, counts(&[("1.0.1", 2), ("1.0.2", 1), ("1.1.0.1", 1)]));
    assert_eq!(guest.state, consumer.state(Who::Guest));
    let own = consumer.places(who, None);
    assert_eq!(docs(&own), ["1.0.1.0.1", "1.0.1.0.2", "1.0.1.2.0.1", "1.0.2.0.1", HEAD_DOCUMENT], "the published part and the principal's");
    assert_eq!(own.counts, counts(&[("1.0.1", 2), ("1.0.1.2", 1), ("1.0.2", 1), ("1.1.0.1", 1)]));
    assert_eq!(own.state, consumer.state(who));
    let draft = Place { doc: addr("1.0.1.2.0.1"), kind: Kind::Draft, label: Some("my draft".into()), standing: Standing::YoursToRead };
    assert_eq!(own.docs[2], draft);
    assert!(guest.docs.iter().all(|p| p.kind == Kind::Edition && p.standing == Standing::Public), "{:?}", guest.docs);
    for place in &own.docs {
        let matched = consumer.search(who, &place.doc.to_string(), &SearchOpts::default()).unwrap().places;
        assert_eq!(matched.iter().find(|m| m.doc == place.doc), Some(place), "the listed place is the match of its address");
    }
    let under = |prefix: &str| consumer.places(who, Some(&addr(prefix)));
    assert_eq!((docs(&under("1.0.1")), under("1.0.1").counts), (vec!["1.0.1.0.1".to_string(), "1.0.1.0.2".into(), "1.0.1.2.0.1".into()], counts(&[("1.0.1", 2), ("1.0.1.2", 1)])));
    assert_eq!((under("1.0.1.2.0.1").docs, under("1.0.1.2.0.1").counts), (vec![draft], counts(&[("1.0.1.2", 1)])), "a document's own address lists it alone");
    assert!(under("1.0.9").docs.is_empty() && under("1.0.9").counts.is_empty());
    assert!(dialer.lines().is_empty(), "no board read on the call's path: {:?}", dialer.lines());
}

// ── THE JUMP's LANDING RULE ──────────────────────────────────────────────

fn pair(u1: u64, u2: u64, width: u64) -> Correspondence {
    Correspondence { d1: "1.0.1.0.2.3".into(), d2: "1.0.1.0.2".into(), u1, u2, width }
}

/// `search.md` §3.4's ONE LANDING RULE: CARRIED where the pairs carry the
/// whole span onto one contiguous head span in order; PARTIAL where part;
/// ABSENT where none; the landing at the pair covering the span's FIRST
/// BYTE — of several, the first in the head's order — or, where that byte
/// is cut, at the first pair in the head's order.
#[test]
fn the_jump_lands_carried_partial_absent_at_the_first_bytes_pair_or_the_heads_first() {
    let span = Span { start: 10, width: 6 };
    assert_eq!(land(span, &[pair(1, 101, 20)]), Landing::Carried { at: 110 }, "one pair covering the span");
    assert_eq!(land(span, &[pair(8, 58, 4), pair(12, 62, 10)]), Landing::Carried { at: 60 }, "two pairs, contiguous in the head and in order");
    assert_eq!(land(span, &[pair(8, 58, 4), pair(12, 90, 10)]), Landing::Partial { at: 60 }, "two pairs, not contiguous in the head");
    assert_eq!(land(span, &[pair(8, 58, 4), pair(13, 63, 10)]), Landing::Partial { at: 60 }, "a byte cut from the head");
    assert_eq!(land(span, &[pair(12, 62, 10)]), Landing::Partial { at: 62 }, "the first byte cut: the first pair in the head's order");
    assert_eq!(land(span, &[pair(12, 900, 10), pair(13, 62, 10)]), Landing::Partial { at: 62 });
    assert_eq!(land(span, &[pair(10, 500, 6), pair(10, 40, 6)]), Landing::Carried { at: 40 }, "a passage the head holds twice: the first in the head's order");
    assert_eq!(land(span, &[pair(20, 1, 5)]), Landing::Absent);
    assert_eq!(land(span, &[]), Landing::Absent);
}

/// §3.4: the three budget refusals — "the LEAP lands on the hit's own span
/// at the PINNED MEMBER … with no read"; a `compare` answer decodes to the
/// rule; another rejection is the caller's to face.
#[test]
fn the_three_budget_refusals_land_pinned_and_a_compare_answer_lands_by_the_rule() {
    let span = Span { start: 3, width: 2 };
    for code in ["too_many_blocks", "too_many_pairs", "image_too_large"] {
        let refusal = json!({"resp": "rejected", "code": code, "disposition": "permanent", "op": "compare"});
        assert_eq!(landing_of(&refusal, span), Some(Landing::Pinned), "{code}");
    }
    let withheld = json!({"resp": "rejected", "code": "withheld", "disposition": "reorder", "op": "compare"});
    assert_eq!(landing_of(&withheld, span), None, "the departure face is the page's");
    let answer = json!({"as_of": 9, "resp": "compare", "pairs": [{"d1": "1.0.1.0.1", "d2": "1.0.1.0.2", "u1": {"ordinal": "1", "subspace": "1"}, "u2": {"ordinal": "3", "subspace": "1"}, "width": "5"}]});
    assert_eq!(landing_of(&answer, span), Some(Landing::Carried { at: 5 }));
}

// ── THE DOCUMENT INDEX ───────────────────────────────────────────────────

/// `client.md` §4e.2: the document index's "addresses, first lines, counts
/// per account", one JSON line per document (P39's file per part), round
/// tripped; the exact matches by address and by label.
#[test]
fn the_document_index_round_trips_counts_per_account_and_matches_exactly() {
    let mut places = Places::new();
    places.record(addr("1.0.1.0.2"), PlaceRecord { kind: Kind::Edition, member: Some(addr("1.0.1.0.2.3")), label: Some("A first line".into()) });
    places.record(addr("1.0.1.0.3"), PlaceRecord { kind: Kind::Draft, member: None, label: None });
    places.record(addr("1.0.2.0.1"), PlaceRecord { kind: Kind::Edition, member: None, label: Some("1.0.1.0.2".into()) });
    let bytes = places.encode();
    let text = String::from_utf8(bytes.clone()).unwrap();
    assert_eq!(text.lines().next().unwrap(), r#"{"doc":"1.0.1.0.2","kind":"edition","label":"A first line","member":"1.0.1.0.2.3"}"#);
    assert_eq!(Places::decode(&bytes).unwrap(), places);
    assert_eq!(places.counts(), BTreeMap::from([(addr("1.0.1"), 2), (addr("1.0.2"), 1)]));
    assert_eq!(places.matching("A first line").iter().map(ToString::to_string).collect::<Vec<_>>(), ["1.0.1.0.2"]);
    assert_eq!(places.matching(" 1.0.1.0.2 ").iter().map(ToString::to_string).collect::<Vec<_>>(), ["1.0.1.0.2", "1.0.2.0.1"], "the address exact, and a label spelling it");
    assert!(places.matching("first").is_empty(), "exact, never a substring");
    assert!(Places::decode(b"{\"doc\":7}\n").is_err());
    let unit = skep_search::Unit::new(skep_search::UnitKey::new(addr("1.0.1.0.9")), None, Kind::Edition, Class::Guest, 1, vec![skep_search::Item::Text { start: 1, bytes: b"  the first line \nthe second".to_vec() }]).unwrap();
    assert_eq!(Places::first_line(&unit).as_deref(), Some("the first line"));
}

// ── THE TEN ARMS, THE REST ───────────────────────────────────────────────

/// §4b.2's `widening {range}` — "R90's fetch running" — observed from the
/// search thread while the feed thread's widening fetches: the scripted
/// board holds the drafts page until the state has been read.
#[test]
fn widening_is_the_state_while_a_ranges_fetch_runs() {
    use std::sync::mpsc;
    let mut w = World::claimed();
    w.draft("1.0.1.2.0.1", b"a draft");
    let world = shared(w);
    let (b, dialer) = board(&world);
    let tmp = tempfile::tempdir().unwrap();
    let consumer = Consumer::open(&b, SearchDir::new(tmp.path())).unwrap();
    consumer.poll().unwrap();
    let (hold_tx, hold_rx) = mpsc::channel::<()>();
    let (seen_tx, seen_rx) = mpsc::channel::<()>();
    // The holding dialer: the first drafts page waits for the main thread.
    struct Holding {
        inner: Arc<Scripted>,
        hold: Mutex<Option<mpsc::Receiver<()>>>,
        seen: mpsc::Sender<()>,
    }
    impl Dialer for Holding {
        fn exchange(&self, origin: &Origin, req: &Request) -> Result<Response, DialError> {
            if req.path.contains("drafts=true") {
                if let Some(rx) = self.hold.lock().unwrap().take() {
                    let _ = self.seen.send(());
                    let _ = rx.recv_timeout(Duration::from_secs(10));
                }
            }
            self.inner.exchange(origin, req)
        }
        fn stream(&self, _: &Origin, _: &RequestHead, _: &mut dyn std::io::Read, _: &mut dyn FnMut(&Headers)) -> Result<StreamedResponse, DialError> {
            unreachable!()
        }
    }
    let holding = Board::new(Origin::parse("http://127.0.0.1:8642").unwrap(), Holding { inner: dialer.clone(), hold: Mutex::new(Some(hold_rx)), seen: seen_tx });
    let consumer_two = Consumer::open(&holding, SearchDir::new(tempfile::tempdir().unwrap().path())).unwrap();
    consumer_two.poll().unwrap();
    drop(consumer);
    let tok = token();
    std::thread::scope(|s| {
        s.spawn(|| consumer_two.widen(session(&tok)).unwrap());
        seen_rx.recv_timeout(Duration::from_secs(10)).expect("the fetch began");
        assert_eq!(consumer_two.state(Who::Session(session(&tok))), State::Widening { range: Range::Under(addr(SUB_ACCOUNT)) });
        assert!(matches!(consumer_two.state(Who::Guest), State::Complete { .. }), "`widening` reaches no face without that principal's session");
        hold_tx.send(()).unwrap();
    });
    assert!(matches!(consumer_two.state(Who::Session(session(&tok))), State::Complete { .. }));
}

/// §4b.2's `at_the_floor {floor}`: "the index BEGAN at a reclaim floor above
/// the board's first entry … so its completeness is the floor's".
#[test]
fn an_index_begun_at_a_reclaim_floor_says_so() {
    let mut w = World::claimed();
    w.publish("1.0.1.0.2", "below");
    w.publish("1.0.1.0.3", "above");
    w.floor = Some(w.position - 1);
    let floor = w.floor.unwrap();
    let world = shared(w);
    let (b, _) = board(&world);
    let tmp = tempfile::tempdir().unwrap();
    let consumer = Consumer::open(&b, SearchDir::new(tmp.path())).unwrap();
    consumer.poll().unwrap();
    assert_eq!(consumer.state(Who::Guest), State::AtTheFloor { floor });
    assert_eq!(hits(&consumer, Who::Guest, "above"), ["1.0.1.0.3"]);
    assert!(hits(&consumer, Who::Guest, "below").is_empty(), "a document with no feed entry above the floor never enters an index begun after it");
}

/// The state's composition order, each arm named (§4b.2's ten): `none`,
/// `building`, `widening`, `complete`, `at_the_floor`,
/// `resumed_from_the_floor`, `unplaced`, `past_the_ceiling`, `newer_skep`,
/// `busy` — the last composed by no part.
#[test]
fn the_composition_names_each_arm_in_its_order() {
    let header = |floor: Option<u64>, bare: u64| Header {
        board: Chain::from_bytes([1; 32]),
        floor,
        ranges: vec![RangeRecord { under: None, held: ChainAt { position: 40, chain: Chain::from_bytes([2; 32]) }, refusals: Vec::new(), bare_rows: bare, grant: None }],
        head: None,
    };
    let stats = |seen: u64| Stats { units: 4, terms: 0, postings: 0, bytes: 0, tombstones: 0, dead_postings: 0, ceiling: CEILING_BYTES, seen };
    let plain = header(None, 0);
    fn facts(stats: Stats, header: &Header) -> Facts<'_> {
        Facts { stats, header, building: None, widening: None, resumed: None, lost: None, aside: false }
    }
    assert_eq!(State::compose(&[]), State::None);
    assert_eq!(State::compose(&[Part::Index(facts(stats(0), &plain))]), State::Complete { as_of: 40, floor: None });
    assert_eq!(State::compose(&[Part::Index(Facts { building: Some(7), ..facts(stats(0), &plain) })]), State::Building { position: 7, units: 4, lost: None, aside: false });
    assert_eq!(State::compose(&[Part::Index(Facts { widening: Some(Range::Board), ..facts(stats(0), &plain) })]), State::Widening { range: Range::Board });
    let floored = header(Some(30), 0);
    assert_eq!(State::compose(&[Part::Index(facts(stats(0), &floored))]), State::AtTheFloor { floor: 30 });
    let held = ChainAt { position: 12, chain: Chain::from_bytes([3; 32]) };
    assert_eq!(State::compose(&[Part::Index(Facts { resumed: Some((30, held)), ..facts(stats(0), &floored) })]), State::ResumedFromTheFloor { floor: 30, held });
    let bare = header(None, 2);
    assert_eq!(State::compose(&[Part::Index(facts(stats(0), &bare))]), State::Unplaced { range: Range::Board, count: 2 });
    assert_eq!(State::compose(&[Part::Index(facts(stats(1), &bare))]), State::PastTheCeiling { held: 4, seen: 1, limit: CEILING_BYTES });
    assert_eq!(State::compose(&[Part::Index(facts(stats(0), &plain)), Part::Faced(Newer::Version { v: 3 })]), State::NewerSkep { v: Newer::Version { v: 3 } });
    assert_ne!(State::Busy, State::None, "busy is the lock's, composed by no part");
}

/// The module's bound and the `SearchDir` re-export resolve.
#[test]
fn the_search_dir_is_the_index_directory_under_the_data_directory() {
    let dir = _SearchDir::new("/tmp/data");
    assert_eq!(dir.root(), std::path::Path::new("/tmp/data/index"));
    assert_eq!(QUERY_BOUND, 1024);
    let mut buf = String::new();
    let _ = std::io::empty().read_to_string(&mut buf);
}

// ── THE BOARD's WORD BOUNDS NOTHING THE CONSUMER HOLDS ───────────────────

/// The refusals recorded beside the published index's one range, as saved.
fn published_refusals(consumer: &Consumer<'_>, world: &Arc<Mutex<World>>) -> Vec<(String, String)> {
    consumer.save().unwrap();
    let header = load_header(&board_dir(consumer.dir(), world).file(&BoardDir::published_name()), Class::Guest);
    header.ranges[0].refusals.iter().map(|r| (r.doc.to_string(), r.reason.clone())).collect()
}

/// The `retrieve_v` reads the board served naming `doc`.
fn reads_naming(dialer: &Scripted, doc: &str) -> usize {
    dialer.served.lock().unwrap().iter().filter(|s| s.line == "POST /op retrieve_v" && serde_json::from_slice::<Value>(&s.body).unwrap()["specs"][0]["doc"] == doc).count()
}

/// `search.md` §7.4: a position holds at most one byte of text, so a
/// document whose extent passes the ceiling holds more text than the index
/// admits or is that much gap — refused UNREAD, its refusal recorded beside
/// the range, where every part of it would otherwise be read to learn it —
/// and the index SAYS SO: the state is `past_the_ceiling`, the document one
/// unit `seen`, after a restart as before it.
#[test]
fn a_document_whose_extent_passes_the_ceiling_is_refused_unread() {
    let mut w = World::claimed();
    w.publish("1.0.1.0.2", "a short text");
    w.extents.insert("1.0.1.0.2".to_string(), CEILING_BYTES + 1);
    let world = shared(w);
    let (b, dialer) = board(&world);
    let tmp = tempfile::tempdir().unwrap();
    let consumer = Consumer::open(&b, SearchDir::new(tmp.path())).unwrap();
    consumer.poll().unwrap();
    assert_eq!(reads_naming(&dialer, "1.0.1.0.2"), 0, "no part read");
    assert!(hits(&consumer, Who::Guest, "short").is_empty());
    assert_eq!(published_refusals(&consumer, &world), [("1.0.1.0.2".to_string(), "unit_past_the_ceiling".to_string())]);
    assert!(matches!(consumer.state(Who::Guest), State::PastTheCeiling { seen: 1, limit: CEILING_BYTES, .. }), "{:?}", consumer.state(Who::Guest));
    consumer.close().unwrap();
    let (b, _) = board(&world);
    let reopened = Consumer::open(&b, SearchDir::new(tmp.path())).unwrap();
    assert!(matches!(reopened.state(Who::Guest), State::PastTheCeiling { seen: 1, .. }), "after a restart: {:?}", reopened.state(Who::Guest));
}

/// wire.md §Content values: a delivery is the span it asked, one item per
/// position and one per withheld run — a part that delivers more is no
/// delivery, refused and recorded, its text never held as the document's.
#[test]
fn a_delivery_past_the_width_asked_is_refused() {
    let mut w = World::claimed();
    w.publish("1.0.1.0.2", &"overflowing words ".repeat(2_800));
    w.extents.insert("1.0.1.0.2".to_string(), 5);
    w.deliver_whole.insert("1.0.1.0.2".to_string());
    let world = shared(w);
    let (b, _) = board(&world);
    let tmp = tempfile::tempdir().unwrap();
    let consumer = Consumer::open(&b, SearchDir::new(tmp.path())).unwrap();
    consumer.poll().unwrap();
    assert!(hits(&consumer, Who::Guest, "overflowing").is_empty(), "the over-delivered text is never indexed");
    assert_eq!(published_refusals(&consumer, &world), [("1.0.1.0.2".to_string(), "not_a_delivery".to_string())]);
}

/// A part that delivers FEWER positions than it asked — the document shrank
/// between its extent and the part's read, a board delivering the span
/// within the extent at the part's position — is a delivery all the same:
/// the shorter text is indexed and nothing is refused.
#[test]
fn a_part_short_of_the_width_asked_is_indexed_as_delivered() {
    let mut w = World::claimed();
    w.publish("1.0.1.0.2", "shrunken words");
    w.extents.insert("1.0.1.0.2".to_string(), 50);
    let world = shared(w);
    let (b, _) = board(&world);
    let tmp = tempfile::tempdir().unwrap();
    let consumer = Consumer::open(&b, SearchDir::new(tmp.path())).unwrap();
    consumer.poll().unwrap();
    assert_eq!(hits(&consumer, Who::Guest, "shrunken"), ["1.0.1.0.2"]);
    assert!(published_refusals(&consumer, &world).is_empty());
}

/// The unit's resident charge counts an item as the index holds it — here a
/// withheld run, the slot and its origin a component at a time — and passes
/// the ceiling long before the extent would: the document is refused as
/// past the ceiling, its parts read no further than the charge allowed.
#[test]
fn a_unit_whose_items_pass_the_ceiling_is_refused_as_its_charge_grows() {
    let mut w = World::claimed();
    // Every part a withheld run of the width asked, its origin 60,000
    // components: each item charges ~1.9 MB, so the unit passes the ceiling
    // within fifty parts of the extent's sixty-four.
    let origin = format!("1{}", ".1".repeat(59_999));
    w.publish("1.0.1.0.2", "");
    w.extents.insert("1.0.1.0.2".to_string(), 64 * MAX_DELIVERY_ITEMS);
    w.withheld_by.insert("1.0.1.0.2".to_string(), origin);
    let world = shared(w);
    let (b, dialer) = board(&world);
    let tmp = tempfile::tempdir().unwrap();
    let consumer = Consumer::open(&b, SearchDir::new(tmp.path())).unwrap();
    consumer.poll().unwrap();
    let parts = reads_naming(&dialer, "1.0.1.0.2");
    assert!(parts > 1 && parts < 64, "{parts} parts read");
    assert_eq!(published_refusals(&consumer, &world), [("1.0.1.0.2".to_string(), "unit_past_the_ceiling".to_string())]);
    assert!(matches!(consumer.state(Who::Guest), State::PastTheCeiling { seen: 1, .. }), "{:?}", consumer.state(Who::Guest));
}

/// The consumer's ceiling refusal is ONE unit `seen` whichever ranges record
/// it: a supplement's draft beneath the account is refused under the
/// account's range and again under its ancestor's. Once the board cuts it
/// down and the account's page reads it whole, its merge clears the refusal
/// under EVERY range — the ancestor's page, coalesced, reads it not at all —
/// and the state is `complete` again.
#[test]
fn a_ceiling_refusal_is_one_unit_whichever_ranges_record_it_and_clears_with_its_merge() {
    let mut w = World::claimed();
    w.draft("1.0.1.2.0.1", b"a vast draft");
    w.extents.insert("1.0.1.2.0.1".to_string(), CEILING_BYTES + 1);
    let world = shared(w);
    let (b, _) = board(&world);
    let tmp = tempfile::tempdir().unwrap();
    let consumer = Consumer::open(&b, SearchDir::new(tmp.path())).unwrap();
    consumer.poll().unwrap();
    let tok = token();
    let who = Who::Session(session(&tok));
    consumer.widen(session(&tok)).unwrap();
    assert!(matches!(consumer.state(who), State::PastTheCeiling { seen: 1, limit: CEILING_BYTES, .. }), "{:?}", consumer.state(who));
    let path = board_dir(consumer.dir(), &world).file(&BoardDir::supplement_name(7));
    let recorded = |consumer: &Consumer<'_>| {
        consumer.save().unwrap();
        load_header(&path, Class::Principal(7)).ranges.iter().filter(|r| r.refusals.iter().any(|f| f.reason == "unit_past_the_ceiling")).count()
    };
    assert_eq!(recorded(&consumer), 2, "recorded under the account's range and its ancestor's");
    {
        let mut w = world.lock().unwrap();
        w.extents.clear();
        w.draft("1.0.1.2.0.1", b"a draft cut down");
    }
    consumer.poll().unwrap();
    assert_eq!(hits(&consumer, who, "cut"), ["1.0.1.2.0.1"]);
    assert_eq!(recorded(&consumer), 0, "cleared under every range");
    assert!(matches!(consumer.state(who), State::Complete { .. }), "{:?}", consumer.state(who));
}

/// Each document a page names LANDS as its read returns: a read that fails
/// at the transport keeps what the reads before it landed, while the
/// cursor and `held` still wait for the whole page.
#[test]
fn a_page_lands_each_document_before_reading_the_next() {
    let mut w = World::claimed();
    w.publish("1.0.1.0.2", "landed first");
    w.publish("1.0.1.0.3", "never reached");
    w.transport_fail.insert("1.0.1.0.3".to_string());
    let world = shared(w);
    let (b, _) = board(&world);
    let tmp = tempfile::tempdir().unwrap();
    let consumer = Consumer::open(&b, SearchDir::new(tmp.path())).unwrap();
    let err = consumer.poll().expect_err("the transport broke");
    assert_eq!(err.exit_code(), 4, "{err}");
    assert_eq!(hits(&consumer, Who::Guest, "landed"), ["1.0.1.0.2"]);
    assert!(matches!(consumer.state(Who::Guest), State::Building { .. }), "the page is not whole: {:?}", consumer.state(Who::Guest));
}

/// A board's refusal is recorded under the wire's word only where it is
/// one — every save writes it and every restart reads it — and under
/// `unrecognized_refusal` where the board spelled its own.
#[test]
fn a_refusal_off_the_wires_spelling_is_recorded_as_unrecognized() {
    let mut w = World::claimed();
    w.publish("1.0.1.0.2", "refused at length");
    w.publish("1.0.1.0.3", "refused by a word");
    w.docs.get_mut("1.0.1.0.2").unwrap().refuse = Some(Box::leak("x".repeat(64 * 1024).into_boxed_str()));
    w.docs.get_mut("1.0.1.0.3").unwrap().refuse = Some("withheld");
    let world = shared(w);
    let (b, _) = board(&world);
    let tmp = tempfile::tempdir().unwrap();
    let consumer = Consumer::open(&b, SearchDir::new(tmp.path())).unwrap();
    consumer.poll().unwrap();
    assert_eq!(
        published_refusals(&consumer, &world),
        [("1.0.1.0.2".to_string(), "unrecognized_refusal".to_string()), ("1.0.1.0.3".to_string(), "withheld".to_string())]
    );
}

/// `search.md` §2.4's trunk probe over a dense trunk of a thousand members:
/// the head found by doubling to the first unregistered member and
/// bisecting, in twenty-one reads where a member at a time reads a
/// thousand and one.
#[test]
fn a_dense_trunk_is_probed_by_doubling_then_bisecting() {
    let mut w = World::claimed();
    for k in 1..=1000 {
        w.registered.insert(format!("1.0.1.0.4.{k}"));
    }
    w.docs.insert("1.0.1.0.4.1000".to_string(), Doc { text: b"the thousandth edition".to_vec(), refuse: None });
    w.publish("1.0.1.0.4", "the bare address floats");
    let world = shared(w);
    let (b, dialer) = board(&world);
    let tmp = tempfile::tempdir().unwrap();
    let consumer = Consumer::open(&b, SearchDir::new(tmp.path())).unwrap();
    consumer.poll().unwrap();
    let answer = consumer.search(Who::Guest, "thousandth", &SearchOpts::default()).unwrap();
    assert_eq!(answer.hits[0].member.as_ref().map(ToString::to_string).as_deref(), Some("1.0.1.0.4.1000"));
    let probes = dialer.served.lock().unwrap().iter().filter(|s| s.line == "POST /op doc_metadata" && serde_json::from_slice::<Value>(&s.body).unwrap()["doc"].as_str().unwrap().starts_with("1.0.1.0.4.")).count();
    assert!(probes <= 21, "{probes} probes");
}

/// A session's account is `principal_prefix`'s answer: one deeper than the
/// namespace delegates is the board's fault, refused before anything is read
/// or mounted, its ancestors never made ranges.
#[test]
fn a_session_account_deeper_than_the_namespace_widens_nothing() {
    let world = shared(World::claimed());
    let (b, dialer) = board(&world);
    let tmp = tempfile::tempdir().unwrap();
    let consumer = Consumer::open(&b, SearchDir::new(tmp.path())).unwrap();
    dialer.clear();
    let tok = token();
    let deep = format!("1.0.1{}", ".1".repeat(100));
    let halt = consumer.widen(SessionRef { token: &tok, principal: 7, account: &deep }).expect_err("too deep");
    assert_eq!(halt.exit_code(), 3);
    assert!(dialer.lines().is_empty(), "{:?}", dialer.lines());
    assert!(!consumer.mounted(7));
}

/// The orphan test walks only an account within the namespace's depth: a
/// supplement whose principal the board now names past it is no orphan the
/// shell offers to forget — the board's fault, never the person's — and no
/// `key_set` is read for it; the same supplement at its own account is one.
#[test]
fn the_orphan_test_offers_no_forget_on_an_account_named_past_the_depth() {
    let mut w = World::claimed();
    w.principals.insert(7, SUB_ACCOUNT.to_string());
    let world = shared(w);
    let (b, dialer) = board(&world);
    let tmp = tempfile::tempdir().unwrap();
    let consumer = Consumer::open(&b, SearchDir::new(tmp.path())).unwrap();
    consumer.poll().unwrap();
    let tok = token();
    consumer.widen(session(&tok)).unwrap();
    consumer.narrow(7).unwrap();
    assert_eq!(consumer.orphans(&[]).unwrap().iter().map(|o| o.principal).collect::<Vec<_>>(), [7], "keyless at its own account");
    world.lock().unwrap().principals.insert(7, format!("1.0.1{}", ".1".repeat(100)));
    dialer.clear();
    assert!(consumer.orphans(&[]).unwrap().is_empty());
    assert_eq!(dialer.reads_of("key_set"), 0, "{:?}", dialer.lines());
}

// ── THE FEED's PAGES MOVE THE DRAIN ON ───────────────────────────────────

/// wire.md §The change feed, Paging: a page that moves nothing — empty,
/// its `last` the `since` asked, `more` true — is no answer the wire
/// gives; the poll fails on it at once, never asking again for ever.
#[test]
fn a_feed_page_that_moves_nothing_fails_the_poll() {
    let mut w = World::claimed();
    w.stale = true;
    let world = shared(w);
    let (b, _) = board(&world);
    let tmp = tempfile::tempdir().unwrap();
    let consumer = Consumer::open(&b, SearchDir::new(tmp.path())).unwrap();
    let err = consumer.poll().expect_err("a page that moves nothing");
    assert_eq!(err.exit_code(), 4, "{err}");
    assert_eq!(world.lock().unwrap().changes_asked, 1);
}

/// `search.md` §5.1: a second `history_reclaimed` within one range's drain
/// — the board reclaiming while the drain runs — ends that range's drain at
/// the floor it named, `held` there and never the `/health` pair, and the
/// next poll drains on from it.
#[test]
fn a_second_floor_within_one_drain_ends_the_range_there() {
    let mut w = World::claimed();
    w.publish("1.0.1.0.2", "beyond the second floor");
    w.reclaim.extend([5, 9]);
    let world = shared(w);
    let (b, dialer) = board(&world);
    let tmp = tempfile::tempdir().unwrap();
    let consumer = Consumer::open(&b, SearchDir::new(tmp.path())).unwrap();
    consumer.poll().unwrap();
    assert_eq!(world.lock().unwrap().changes_asked, 2, "two floors, then the range ended");
    consumer.save().unwrap();
    let header = load_header(&board_dir(consumer.dir(), &world).file(&BoardDir::published_name()), Class::Guest);
    assert_eq!(header.ranges[0].held.position, 9, "held at the second floor");
    dialer.clear();
    consumer.poll().unwrap();
    let pages: Vec<String> = dialer.lines().into_iter().filter(|l| l.starts_with("GET /changes?")).collect();
    assert!(pages[0].starts_with("GET /changes?since=9"), "{pages:?}");
    assert_eq!(hits(&consumer, Who::Guest, "beyond"), ["1.0.1.0.2"]);
    assert_eq!(consumer.state(Who::Guest), State::AtTheFloor { floor: 9 }, "complete from the floor the drain ended at");
}

// ── THE COMMIT STREAM ────────────────────────────────────────────────────

/// One chunk a scripted stream body answers: bytes, or a read's error.
type Chunk = Result<Vec<u8>, io::ErrorKind>;

/// A stream body answering its chunks in turn, then the close.
struct Chunks(VecDeque<Chunk>);

impl Read for Chunks {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self.0.pop_front() {
            None => Ok(0),
            Some(Err(kind)) => Err(kind.into()),
            Some(Ok(mut bytes)) => {
                let n = bytes.len().min(buf.len());
                buf[..n].copy_from_slice(&bytes[..n]);
                if n < bytes.len() {
                    self.0.push_front(Ok(bytes.split_off(n)));
                }
                Ok(n)
            }
        }
    }
}

/// A body counting the bytes read off it.
struct Counted {
    inner: Box<dyn Read + Send>,
    taken: Arc<AtomicU64>,
}

impl Read for Counted {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.inner.read(buf)?;
        self.taken.fetch_add(n as u64, Ordering::SeqCst);
        Ok(n)
    }
}

/// A dialer whose `/events` answers come off a queue — a body, or the
/// connect's refusal — each `stream` call counted.
struct Streams {
    bodies: Mutex<VecDeque<Result<Box<dyn Read + Send>, DialError>>>,
    dialed: AtomicUsize,
}

impl Streams {
    fn board(bodies: Vec<Result<Box<dyn Read + Send>, DialError>>) -> (Board, Arc<Streams>) {
        let streams = Arc::new(Streams { bodies: Mutex::new(bodies.into()), dialed: AtomicUsize::new(0) });
        (Board::new(Origin::parse("http://127.0.0.1:8642").unwrap(), streams.clone()), streams)
    }
}

impl Dialer for Streams {
    fn exchange(&self, _: &Origin, req: &Request) -> Result<Response, DialError> {
        panic!("the stream sends no {} {}", req.method.as_str(), req.path)
    }

    fn stream(&self, _: &Origin, head: &RequestHead, _: &mut dyn std::io::Read, _: &mut dyn FnMut(&Headers)) -> Result<StreamedResponse, DialError> {
        assert_eq!(head.path, "/events");
        self.dialed.fetch_add(1, Ordering::SeqCst);
        let body = self.bodies.lock().unwrap().pop_front().unwrap_or_else(|| Err(DialError::Connect("no stream left".into())))?;
        Ok(StreamedResponse { status: 200, headers: Headers::default(), body })
    }
}

fn commit(position: u64) -> Chunk {
    Ok(format!("event: commit\ndata: {{\"log_position\":{position}}}\n\n").into_bytes())
}

/// wire.md §The commit stream: an event is its position alone, so a line
/// past `EVENT_LINE_BOUND` ends the stream as a close does — read no
/// further than the bound, never to the end of a board's sixty-four
/// megabytes — and the stream dialed again answers its event.
#[test]
fn an_events_line_past_its_bound_ends_the_stream_unread() {
    let taken = Arc::new(AtomicU64::new(0));
    let flood: Box<dyn Read + Send> = Box::new(Counted { inner: Box::new(io::repeat(b'a').take(64 << 20)), taken: taken.clone() });
    let calm: Box<dyn Read + Send> = Box::new(Chunks(VecDeque::from([commit(7)])));
    let (b, _) = Streams::board(vec![Ok(flood), Ok(calm)]);
    let mut stream = events(&b);
    assert_eq!(stream.next().map(|r| r.unwrap()), Some(7));
    assert!(taken.load(Ordering::SeqCst) <= 2 * EVENT_LINE_BOUND, "{} bytes taken", taken.load(Ordering::SeqCst));
}

/// A read that times out is silence on a live stream, which the stream
/// survives — the line it was part-way through kept whole across it — and
/// never a reconnect short of the silence bound.
#[test]
fn a_read_that_times_out_is_silence_and_the_stream_survives_it() {
    let chunks = VecDeque::from([Ok(b"event: com".to_vec()), Err(io::ErrorKind::WouldBlock), Ok(b"mit\ndata: {\"log_position\":9}\n\n".to_vec())]);
    let slow: Box<dyn Read + Send> = Box::new(Chunks(chunks));
    let (b, streams) = Streams::board(vec![Ok(slow)]);
    let mut stream = events(&b);
    assert_eq!(stream.next().map(|r| r.unwrap()), Some(9));
    assert_eq!(streams.dialed.load(Ordering::SeqCst), 1, "one stream, never dialed again");
}

/// A board that refuses the stream is dialed again no sooner than the
/// reconnect wait: three attempts take two waits, never a spin.
#[test]
fn a_refused_stream_waits_before_it_is_dialed_again() {
    let (b, streams) = Streams::board(Vec::new());
    let mut stream = events(&b);
    let began = Instant::now();
    for _ in 0..3 {
        assert!(matches!(stream.next(), Some(Err(_))));
    }
    assert!(began.elapsed() >= Duration::from_millis(500), "three attempts in {:?}", began.elapsed());
    assert_eq!(streams.dialed.load(Ordering::SeqCst), 3);
}

// ── THE JUMP AT THE TOP OF THE ORDINALS ──────────────────────────────────

/// The landing rule's ordinals are the board's word: at the top of the
/// range every sum saturates rather than wrap or panic, and a hostile
/// answer lands at the range's edge.
#[test]
fn the_jump_lands_at_the_top_of_the_ordinals_without_wrapping() {
    assert_eq!(land(Span { start: u64::MAX - 1, width: 1 }, &[pair(u64::MAX - 1, u64::MAX, u64::MAX)]), Landing::Carried { at: u64::MAX });
    assert_eq!(land(Span { start: 10, width: 6 }, &[pair(0, u64::MAX, 20)]), Landing::Carried { at: u64::MAX });
    assert_eq!(land(Span { start: 10, width: 6 }, &[pair(8, u64::MAX - 1, 4), pair(12, u64::MAX, 10)]), Landing::Carried { at: u64::MAX });
}
