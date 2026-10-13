//! THE FEED's FENCE: the index state's ten arms and the search words as
//! the bridge spells them — every arm, standing and mark a declared word,
//! and the search answer built as its declarations say; THE FEED THREAD's
//! START, one `/health` read; and THE COMMIT STREAM COALESCED — the waiting
//! tick's mark, and a board committing far faster than the feed thread
//! reads costing it a read per turn, never a read per commit, with a search
//! queued behind them answered after one read at most. ONE READ TO THE HEAD
//! meeting every answer as its paging rule says, and A DRAFTS CURSOR THE
//! RETENTION FLOOR PASSED resumed at the floor, its rows still fed.

use std::io::{self, Read};
use std::sync::atomic::AtomicUsize;
use std::sync::Mutex;
use std::time::Duration;

use skep_client::dial::{DialError, Dialer, Headers, Method, Request, RequestHead, Response, StreamedResponse};
use skep_client::store::FileStore;
use skep_client::Origin;
use skep_search::{Chain, ChainAt};
use tempfile::TempDir;

use super::*;

/// The ten arms spell their names and members as §4b.2 draws them; a saved
/// pair names its chain in the chain's own spelling, sixty-four lowercase
/// hex.
#[test]
fn the_state_spells_its_ten_arms() {
    assert_eq!(state_json(&State::None), json!({"arm": "none"}));
    assert_eq!(state_json(&State::Busy)["arm"], "busy");
    let v = state_json(&State::Complete { as_of: 9, floor: Some(2) });
    assert_eq!((v["arm"].as_str(), v["as_of"].as_u64(), v["floor"].as_u64()), (Some("complete"), Some(9), Some(2)));
    let v = state_json(&State::Widening { range: Range::Board });
    assert_eq!((v["arm"].as_str(), v["range"].as_str()), (Some("widening"), Some("board")));
    let v = state_json(&State::Building { position: 3, units: 4, lost: Some(Lost::Damaged { what: "crc".into() }), aside: true });
    assert_eq!((v["arm"].as_str(), v["lost"]["kind"].as_str(), v["aside"].as_bool()), (Some("building"), Some("damaged"), Some(true)));
    let v = state_json(&State::PastTheCeiling { held: 1, seen: 2, limit: 3 });
    assert_eq!((v["arm"].as_str(), v["limit"].as_u64()), (Some("past_the_ceiling"), Some(3)));
    assert_eq!(state_json(&State::AtTheFloor { floor: 5 })["floor"], 5);
    assert_eq!(state_json(&State::NewerSkep { v: Newer::Version { v: 9 } })["v"]["version"], 9);
    let v = state_json(&State::ResumedFromTheFloor { floor: 5, held: ChainAt { position: 3, chain: Chain::from_bytes([0xab; 32]) } });
    assert_eq!((v["arm"].as_str(), v["held"].clone()), (Some("resumed_from_the_floor"), json!({"position": 3, "chain": "ab".repeat(32)})));
    assert_eq!(standing_json(&Standing::Public), "public");
}

/// The search words are the bridge's own, never a Rust spelling: a held
/// standing names its grant's kind and rung in snake case, a gap mark
/// its width, a hit's and a place's kind the two words declared.
#[test]
fn the_search_words_are_the_bridges_own() {
    let issuer = skep_client::address::parse_address("1.0.1").unwrap();
    let held = standing_json(&Standing::Held { kind: GrantKind::AnyPrincipal, rung: Rung::Account, issuer });
    assert_eq!(held, json!({"held": {"kind": "any_principal", "rung": "account", "issuer": "1.0.1"}}));
    assert_eq!(standing_json(&Standing::YoursToRead), "yours_to_read");
    assert_eq!(mark_json(&Mark { offset: 4, len: 0, kind: MarkKind::Gap { width: 3 } }), json!({"offset": 4, "len": 0, "kind": {"gap": {"width": 3}}}));
    assert_eq!(mark_json(&Mark { offset: 0, len: 2, kind: MarkKind::Term { term: "ab".into() } })["kind"], json!({"term": "ab"}));
    assert_eq!((kind_name(Kind::Edition), kind_name(Kind::Draft)), ("edition", "draft"));
}

/// EVERY INDEX STATE ARM is a declared word: the ten arms built, each
/// spelled as `state_json` spells it, are exactly `IndexState.arm`'s ten
/// (the mutant that misspells an arm, or spells one the table lacks, sends
/// the page a state it cannot name).
#[test]
fn every_index_state_arm_is_a_declared_word() {
    let held = ChainAt { position: 3, chain: Chain::from_bytes([0xab; 32]) };
    let under = Range::Under(skep_client::address::parse_address("1.0.1").unwrap());
    let states = [
        State::None,
        State::Building { position: 3, units: 4, lost: Some(Lost::Diverged { held }), aside: false },
        State::Widening { range: under.clone() },
        State::Complete { as_of: 9, floor: None },
        State::AtTheFloor { floor: 5 },
        State::ResumedFromTheFloor { floor: 5, held },
        State::Unplaced { range: under, count: 2 },
        State::PastTheCeiling { held: 1, seen: 2, limit: 3 },
        State::NewerSkep { v: Newer::Tokenizer { revision: skep_search::REVISION } },
        State::Busy,
    ];
    let spelled: std::collections::BTreeSet<String> = states.iter().map(|s| format!("'{}'", state_json(s)["arm"].as_str().unwrap_or("?"))).collect();
    let declared = crate::shapes::shape("IndexState").unwrap().fields.iter().find(|f| f.name == "arm").unwrap().ty;
    let words: std::collections::BTreeSet<String> = declared.split(" | ").map(str::to_string).collect();
    assert_eq!((spelled.len(), spelled), (10, words), "{declared}");
}

/// EVERY STANDING AND MARK spells a declared word: the standings' words — a
/// held one's kind and rung over every cell of PUB-5.115's KIND × RUNG — are
/// exactly the quoted words of the declared `Standing`, and each mark kind's
/// one key is an arm `Mark.kind` declares (the mutant that misspells a word
/// sends the page a standing or a mark it cannot render).
#[test]
fn every_standing_and_mark_spells_a_declared_word() {
    let issuer = skep_client::address::parse_address("1.0.1").unwrap();
    let mut spelled = std::collections::BTreeSet::new();
    for standing in [Standing::Public, Standing::YoursToRead] {
        spelled.insert(standing_json(&standing).as_str().unwrap_or("?").to_string());
    }
    for kind in [GrantKind::Named, GrantKind::AnyPrincipal] {
        for rung in [Rung::Document, Rung::Account] {
            let held = standing_json(&Standing::Held { kind, rung, issuer: issuer.clone() });
            spelled.insert(held["held"]["kind"].as_str().unwrap_or("?").to_string());
            spelled.insert(held["held"]["rung"].as_str().unwrap_or("?").to_string());
        }
    }
    let declarations = crate::shapes::declarations();
    let line = declarations.lines().find(|l| l.starts_with("export type Standing")).expect("`Standing` is declared");
    let declared: std::collections::BTreeSet<String> = line.split('\'').skip(1).step_by(2).map(str::to_string).collect();
    assert_eq!(spelled, declared, "{line}");
    let mark = crate::shapes::shape("Mark").unwrap().fields.iter().find(|f| f.name == "kind").unwrap().ty;
    for kind in [MarkKind::Span, MarkKind::Term { term: "ab".into() }, MarkKind::Gap { width: 3 }] {
        let spelled = mark_json(&Mark { offset: 0, len: 0, kind });
        let key = spelled["kind"].as_object().and_then(|k| k.keys().next()).cloned().unwrap_or_default();
        assert!(mark.contains(&format!("{{ {key}:")), "`{key}` is no arm of {mark}");
    }
}

/// THE SEARCH ANSWER is built as its declarations say: an answer holding a
/// hit with every optional member present — a member, a snippet carrying a
/// span, a term and a gap mark, a correction, a held standing — and a place
/// with its label, held member by member to `SearchAnswer`, `Hit`,
/// `SpanText`, `Snippet`, `Mark`, `Matched` and `Place` (the mutant that
/// renames a member in the code alone breaks the page and no other test).
#[test]
fn the_search_answer_is_built_as_its_declarations_say() {
    let address = |text: &str| skep_client::address::parse_address(text).unwrap();
    let marks = vec![
        Mark { offset: 0, len: 5, kind: MarkKind::Span },
        Mark { offset: 6, len: 2, kind: MarkKind::Term { term: "ab".into() } },
        Mark { offset: 9, len: 0, kind: MarkKind::Gap { width: 3 } },
    ];
    let hit = Hit {
        doc: address("1.0.1.0.1"),
        member: Some(address("1.0.1.0.1.1")),
        as_of: 7,
        span: skep_search::Span { start: 1, width: 5 },
        score: 1.5,
        snippet: Some(skep_search::Snippet { text: "hello ab world".into(), start: 1, marks }),
        kind: Kind::Edition,
        standing: Standing::Held { kind: GrantKind::Named, rung: Rung::Document, issuer: address("1.0.1") },
        occurrences: 2,
        matched: vec![skep_search::Matched { word: "ac".into(), term: "ab".into() }],
    };
    let place = Place { doc: address("1.0.1.0.2"), kind: Kind::Draft, label: Some("a first line".into()), standing: Standing::YoursToRead };
    let answer = SearchAnswer { hits: vec![hit], total: 1, truncated: false, more_terms: false, fuzzy_bounded: false, positions_bounded: false, places: vec![place], state: State::Complete { as_of: 7, floor: None } };
    let answer = answer_json(&answer);
    crate::shapes::assert_declared("SearchAnswer", &answer);
    let hit = &answer["hits"][0];
    crate::shapes::assert_declared("Hit", hit);
    crate::shapes::assert_declared("SpanText", &hit["span"]);
    crate::shapes::assert_declared("Snippet", &hit["snippet"]);
    let marks = hit["snippet"]["marks"].as_array().expect("the snippet's marks");
    assert_eq!(marks.len(), 3);
    for mark in marks {
        crate::shapes::assert_declared("Mark", mark);
    }
    crate::shapes::assert_declared("Matched", &hit["matched"][0]);
    crate::shapes::assert_declared("Place", &answer["places"][0]);
}

/// A `feed` update's class spells S-24 (b)'s two words: `published` for a
/// row of the guest's feed, `drafts` for a row of a session's supplement.
#[test]
fn an_updates_class_is_published_or_a_sessions_drafts() {
    let board = Arc::new(Board::new(Origin::parse("http://127.0.0.1:9").unwrap(), skep_client::PlainHttp::new()));
    let facts = crate::sessions::Facts { principal: 1, account: Some("1.0.1".into()), kind: crate::sessions::SessionKind::Bare };
    let open = crate::sessions::Open { token: Token::parse(&"9f".repeat(16)).unwrap(), facts, opened_at: 0 };
    let session = Sessions::new(None).register("b-1", board, open, &mut NoSupplements);
    assert_eq!((UpdateClass::Published.as_str(), UpdateClass::Drafts(&session).as_str()), ("published", "drafts"));
}

/// THE WAITING TICK's MARK: the first commit owes a tick and the ones after
/// it none while it waits; taking it clears the mark and reads the latest
/// position, so the next commit owes one tick more.
#[test]
fn the_ticks_owe_one_read_while_one_waits() {
    let ticks = Ticks::default();
    assert!(ticks.note(3), "the first commit owes a tick");
    assert!(!ticks.note(5) && !ticks.note(4), "none more while it waits");
    assert_eq!(ticks.take(), 5, "the read taken reaches the latest");
    assert!(ticks.note(6), "a commit after the take owes one more");
}

/// A board's `/events` stream yielding `commits` commits, served once — none
/// at all where it holds no body: the `/changes` reads it is asked counted,
/// each made `delay` long, as a board across a network makes them, and the
/// `/health` reads counted; `/health` and `/op` answered as a board with no
/// `H.1` answers them.
struct Committing {
    events: Mutex<Option<Vec<u8>>>,
    drained: Arc<AtomicBool>,
    changes_reads: AtomicUsize,
    health_reads: AtomicUsize,
    delay: Duration,
}

impl Committing {
    /// A board whose stream serves `events` once, each `/changes` read
    /// `delay` long.
    fn new(events: Option<Vec<u8>>, drained: &Arc<AtomicBool>, delay: Duration) -> Arc<Committing> {
        Arc::new(Committing { events: Mutex::new(events), drained: Arc::clone(drained), changes_reads: AtomicUsize::new(0), health_reads: AtomicUsize::new(0), delay })
    }
}

/// The shared context of one board's feed thread over `board`, every
/// session in `sessions`, the index under `store`.
fn shared_over(board: &Arc<Board>, sessions: &Arc<Sessions>, bus: &Arc<EventBus>, store: &TempDir) -> Shared {
    let talk: Talk = Arc::new(|_: &str| {});
    let keys = Arc::new(FileStore::open(store.path().join("store")));
    let holds = Holds::new(Arc::clone(sessions), Arc::clone(bus), keys, store.path().to_path_buf(), Arc::clone(&talk), [("b-1".to_string(), Arc::clone(board))]);
    Shared { bus: Arc::clone(bus), sessions: Arc::clone(sessions), data_dir: store.path().to_path_buf(), talk, holds }
}

/// A stream's body that marks itself read to its end.
struct Marked {
    body: io::Cursor<Vec<u8>>,
    drained: Arc<AtomicBool>,
}

impl Read for Marked {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let read = self.body.read(buf)?;
        if read == 0 {
            self.drained.store(true, Ordering::SeqCst);
        }
        Ok(read)
    }
}

fn answer(v: Value) -> Response {
    Response { status: 200, headers: Headers::default(), body: v.to_string().into_bytes() }
}

impl Dialer for Committing {
    fn exchange(&self, _: &Origin, req: &Request) -> Result<Response, DialError> {
        if req.method == Method::Get && req.path.starts_with("/health") {
            self.health_reads.fetch_add(1, Ordering::SeqCst);
            return Ok(answer(json!({"ok": true, "log_position": 10, "auth": {"claimant": null, "local_trust": true, "origins": [], "signed_origins": []}, "writes": {"halted": false}})));
        }
        if req.method == Method::Get && req.path.starts_with("/changes") {
            self.changes_reads.fetch_add(1, Ordering::SeqCst);
            std::thread::sleep(self.delay);
            return Ok(answer(json!({"changes": [], "last": 10, "more": false})));
        }
        Ok(answer(json!({"resp": "delivery", "items": []})))
    }

    fn stream(&self, _: &Origin, _: &RequestHead, _: &mut dyn Read, _: &mut dyn FnMut(&Headers)) -> Result<StreamedResponse, DialError> {
        match self.events.lock().unwrap().take() {
            Some(body) => Ok(StreamedResponse { status: 200, headers: Headers::default(), body: Box::new(Marked { body: io::Cursor::new(body), drained: Arc::clone(&self.drained) }) }),
            None => Err(DialError::Connect("the stream is served once".into())),
        }
    }
}

/// THE COMMIT STREAM COALESCED: a board committing two thousand times faster
/// than the feed thread reads `/changes` costs the feed thread a read per
/// turn — a few — never one per commit, and a search queued as the stream ends is
/// answered after one read at most (the mutant that queues a tick per commit
/// reads two thousand times, the search waiting every one of them out).
#[test]
fn a_board_committing_faster_than_the_feed_thread_reads_costs_a_read_per_turn() {
    let commits = 2000;
    let events: String = (1..=commits).map(|n| format!("event: commit\ndata: {{\"log_position\": {n}}}\n\n")).collect();
    let drained = Arc::new(AtomicBool::new(false));
    let fake = Committing::new(Some(events.into_bytes()), &drained, Duration::from_millis(2));
    let origin = Origin::parse("http://127.0.0.1:9").unwrap();
    let board = Arc::new(Board::new(origin.clone(), Arc::clone(&fake)));
    let store = TempDir::new().unwrap();
    let shared = shared_over(&board, &Arc::new(Sessions::new(None)), &Arc::new(EventBus::new()), &store);
    let threads = FeedThreads::spawn(Arc::new(BoardEntry { reference: "b-1".into(), origin, board }), shared);
    let deadline = Instant::now() + Duration::from_secs(10);
    while !drained.load(Ordering::SeqCst) && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(5));
    }
    assert!(drained.load(Ordering::SeqCst), "the stream was read to its end");
    let started = Instant::now();
    assert!(threads.feed().search(Searcher::Guest, "x", BridgeSearchOpts::default()).is_ok());
    let waited = started.elapsed();
    let reads = fake.changes_reads.load(Ordering::SeqCst);
    threads.stop();
    assert!(reads < commits / 20, "{reads} reads for {commits} commits");
    assert!(waited < Duration::from_secs(1), "the search waited {waited:?} behind the reads queued");
}

/// THE FEED THREAD's START reads `/health` ONCE: the published feed's start,
/// the mode and `writes.halted` all from the one read, made before the feed
/// thread takes its first command — a stream that never connects is announced
/// `unreachable` after it, and no second read was made (the mutant that
/// reads the head apart from the start's `/health` read reads it twice).
#[test]
fn the_feed_thread_reads_health_once_at_its_start() {
    let fake = Committing::new(None, &Arc::new(AtomicBool::new(false)), Duration::ZERO);
    let origin = Origin::parse("http://127.0.0.1:9").unwrap();
    let board = Arc::new(Board::new(origin.clone(), Arc::clone(&fake)));
    let store = TempDir::new().unwrap();
    let bus = Arc::new(EventBus::new());
    let rx = bus.subscribe();
    let threads = FeedThreads::spawn(Arc::new(BoardEntry { reference: "b-1".into(), origin, board: Arc::clone(&board) }), shared_over(&board, &Arc::new(Sessions::new(None)), &bus, &store));
    let deadline = Instant::now() + Duration::from_secs(10);
    let announced = loop {
        match rx.recv_timeout(deadline.saturating_duration_since(Instant::now())) {
            Ok(event) if event.name == EventName::Daemon && event.data["state"] == "unreachable" => break true,
            Ok(_) => {}
            Err(_) => break false,
        }
    };
    let reads = fake.health_reads.load(Ordering::SeqCst);
    threads.stop();
    assert!(announced, "the stream that never connects is announced");
    assert_eq!(reads, 1, "the feed thread's start reads `/health` once");
}

/// A board whose history below `FLOOR` is reclaimed: a drafts read from
/// below it answered `410 history_reclaimed` naming the floor, one from at
/// or above it a page holding the drafts row at `DRAFT_ROW_AT` where the
/// cursor stands before it; the published feed empty at its head; one
/// commit streamed, so one tick reads.
struct Reclaiming {
    events: Mutex<Option<Vec<u8>>>,
}

const FLOOR: u64 = 5;
const DRAFT_ROW_AT: u64 = 6;

/// The `since` a `/changes` path names.
fn since_of(path: &str) -> u64 {
    path.split_once("since=").and_then(|(_, rest)| rest.split('&').next()).and_then(|n| n.parse().ok()).unwrap_or(0)
}

impl Dialer for Reclaiming {
    fn exchange(&self, _: &Origin, req: &Request) -> Result<Response, DialError> {
        if req.method == Method::Get && req.path.starts_with("/health") {
            return Ok(answer(json!({"ok": true, "log_position": 10, "auth": {"claimant": null, "local_trust": true, "origins": [], "signed_origins": []}, "writes": {"halted": false}})));
        }
        if req.method == Method::Get && req.path.starts_with("/changes") {
            let since = since_of(&req.path);
            if !req.path.contains("drafts=true") {
                return Ok(answer(json!({"changes": [], "last": since.max(10), "more": false})));
            }
            if since < FLOOR {
                return Ok(Response { status: 410, headers: Headers::default(), body: json!({"error": "history_reclaimed", "floor": FLOOR}).to_string().into_bytes() });
            }
            let rows: Vec<Value> = if since < DRAFT_ROW_AT { vec![json!({"at": DRAFT_ROW_AT, "op": "insert", "docs": ["1.0.1.0.1"], "key": "bare"})] } else { Vec::new() };
            return Ok(answer(json!({"changes": rows, "last": since.max(DRAFT_ROW_AT), "more": false})));
        }
        Ok(answer(json!({"resp": "delivery", "items": []})))
    }

    fn stream(&self, _: &Origin, _: &RequestHead, _: &mut dyn Read, _: &mut dyn FnMut(&Headers)) -> Result<StreamedResponse, DialError> {
        match self.events.lock().unwrap().take() {
            Some(body) => Ok(StreamedResponse { status: 200, headers: Headers::default(), body: Box::new(io::Cursor::new(body)) }),
            None => Err(DialError::Connect("the stream is served once".into())),
        }
    }
}

struct NoSupplements;
impl Supplements for NoSupplements {
    fn widen(&mut self, _: &Arc<SessionEntry>) {}
    fn narrow(&mut self, _: u64) {}
}

/// A DRAFTS CURSOR THE RETENTION FLOOR PASSED is resumed at the floor, its
/// rows still fed (wire.md §The change feed: an empty page echoes `since`,
/// so a long-open session with no drafts row of its own keeps its open
/// position while the floor rises): a session opened at 0 below a floor at
/// 5, one commit — the tick's drafts read answered `history_reclaimed`,
/// then read on from the floor — and the row at 6 arrives as a `drafts`
/// `feed` event under the session (the mutant that stops at the reclaim
/// feeds that session nothing for the rest of its life).
#[test]
fn a_drafts_cursor_the_floor_passed_reads_on_from_the_floor() {
    let fake = Arc::new(Reclaiming { events: Mutex::new(Some(b"event: commit\ndata: {\"log_position\": 11}\n\n".to_vec())) });
    let origin = Origin::parse("http://127.0.0.1:9").unwrap();
    let board = Arc::new(Board::new(origin.clone(), Arc::clone(&fake)));
    let store = TempDir::new().unwrap();
    let (sessions, bus) = (Arc::new(Sessions::new(None)), Arc::new(EventBus::new()));
    let rx = bus.subscribe();
    let facts = crate::sessions::Facts { principal: 1, account: Some("1.0.1".into()), kind: crate::sessions::SessionKind::Bare };
    let session = sessions.register("b-1", Arc::clone(&board), crate::sessions::Open { token: Token::parse(&"9f".repeat(16)).unwrap(), facts, opened_at: 0 }, &mut NoSupplements);
    let shared = shared_over(&board, &sessions, &bus, &store);
    let threads = FeedThreads::spawn(Arc::new(BoardEntry { reference: "b-1".into(), origin, board }), shared);
    let deadline = Instant::now() + Duration::from_secs(10);
    let fed = loop {
        let wait = deadline.saturating_duration_since(Instant::now());
        match rx.recv_timeout(wait) {
            Ok(event) if event.name == EventName::Feed && event.data["update"]["class"] == "drafts" => break Some(event.data),
            Ok(_) => {}
            Err(_) => break None,
        }
    };
    threads.stop();
    let fed = fed.expect("the drafts row past the floor was fed");
    assert_eq!((fed["update"]["position"].as_u64(), fed["update"]["session"].as_str()), (Some(DRAFT_ROW_AT), Some(session.reference.as_str())), "{fed}");
}

/// A board whose `/changes` answers each `(since, limit)` it is asked as
/// `script` says, every query recorded.
struct Paging {
    script: Box<dyn Fn(u64, Option<u64>) -> Response + Send + Sync>,
    asked: Mutex<Vec<(u64, Option<u64>)>>,
}

/// The `limit` a `/changes` path names, where it names one.
fn limit_of(path: &str) -> Option<u64> {
    path.split_once("limit=").and_then(|(_, rest)| rest.split('&').next()).and_then(|n| n.parse().ok())
}

/// A page of rows at `ats`, with its `last` and its `more`.
fn page(ats: &[u64], last: u64, more: bool) -> Response {
    let rows: Vec<Value> = ats.iter().map(|at| json!({"at": at, "op": "insert", "docs": ["1.0.1.0.1"], "key": "bare"})).collect();
    answer(json!({"changes": rows, "last": last, "more": more}))
}

/// A non-200 answer of `body`.
fn refused(status: u16, body: Value) -> Response {
    Response { status, headers: Headers::default(), body: body.to_string().into_bytes() }
}

impl Dialer for Paging {
    fn exchange(&self, _: &Origin, req: &Request) -> Result<Response, DialError> {
        let (since, limit) = (since_of(&req.path), limit_of(&req.path));
        self.asked.lock().unwrap().push((since, limit));
        Ok((self.script)(since, limit))
    }

    fn stream(&self, _: &Origin, _: &RequestHead, _: &mut dyn Read, _: &mut dyn FnMut(&Headers)) -> Result<StreamedResponse, DialError> {
        Err(DialError::Connect("no stream here".into()))
    }
}

/// What one read to the head over a board scripted by `script` made of its
/// feed from `since` — the published feed's, or a session's drafts under
/// its token where `drafts`: the rows it handed on, where it left the
/// cursor (`None` for the death signal), and the queries it asked. Run on a
/// thread of its own, so a read that never ends fails at the deadline
/// rather than hanging the suite.
fn read_over(script: impl Fn(u64, Option<u64>) -> Response + Send + Sync + 'static, since: u64, drafts: bool) -> (Vec<u64>, Option<u64>, Vec<(u64, Option<u64>)>) {
    let fake = Arc::new(Paging { script: Box::new(script), asked: Mutex::new(Vec::new()) });
    let board = Arc::new(Board::new(Origin::parse("http://127.0.0.1:9").unwrap(), Arc::clone(&fake)));
    let session = drafts.then(|| {
        let facts = crate::sessions::Facts { principal: 1, account: Some("1.0.1".into()), kind: crate::sessions::SessionKind::Bare };
        let open = crate::sessions::Open { token: Token::parse(&"9f".repeat(16)).unwrap(), facts, opened_at: 0 };
        Sessions::new(None).register("b-1", Arc::clone(&board), open, &mut NoSupplements)
    });
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let class = session.as_deref().map_or(UpdateClass::Published, UpdateClass::Drafts);
        let mut rows = Vec::new();
        let to = read_to_head(&board, class, since, |row| rows.push(row["at"].as_u64().unwrap_or(0)));
        let _ = tx.send((rows, match to { ReadTo::At(at) => Some(at), ReadTo::Died => None }));
    });
    let (rows, to) = rx.recv_timeout(Duration::from_secs(5)).expect("the read to the head ends");
    let asked = fake.asked.lock().unwrap().clone();
    (rows, to, asked)
}

/// ONE READ TO THE HEAD meets every answer as its paging rule says (wire.md
/// §The change feed, Paging), cell by cell: a page whose `more` stands read
/// on from its `last`; a page past the budget re-asked at the `fits` it
/// names, the next page at the route's default again; a reclaim resumed at a
/// floor past the cursor, while one at the cursor, or naming no floor, stops
/// where it stands — never spinning; a refusal stopping where it stands; and
/// the death signal on a session's token answered as the death (the mutants
/// that ignore `more`, stop at a page too large or never reset its limit,
/// stop at a reclaim, drop the floor's guard, or read the death as a stop —
/// the first feeding a closing session nothing past its first page, the
/// guard's spinning the board's feed thread for good).
#[test]
fn a_read_to_the_head_meets_every_answer_as_its_paging_rule_says() {
    let (rows, to, _) = read_over(|since, _| if since == 10 { page(&[11], 11, true) } else { page(&[12], 12, false) }, 10, false);
    assert_eq!((rows, to), (vec![11, 12], Some(12)), "a page whose `more` stands is read on");
    let too_large = |since: u64, limit: Option<u64>| match limit {
        Some(1) => page(&[since + 1], since + 1, since == 10),
        _ => refused(400, json!({"error": "malformed_changes", "fits": 1})),
    };
    let (rows, to, asked) = read_over(too_large, 10, false);
    assert_eq!((rows, to), (vec![11, 12], Some(12)), "a page too large is re-asked");
    assert_eq!(asked, [(10, None), (10, Some(1)), (11, None), (11, Some(1))], "at `fits`, the next page at the default again");
    let (rows, to, _) = read_over(|since, _| if since < 5 { refused(410, json!({"error": "history_reclaimed", "floor": 5})) } else { page(&[6], 6, false) }, 3, false);
    assert_eq!((rows, to), (vec![6], Some(6)), "a floor past the cursor is resumed at");
    let (rows, to, _) = read_over(|_, _| refused(410, json!({"error": "history_reclaimed", "floor": 5})), 5, false);
    assert_eq!((rows, to), (vec![], Some(5)), "a floor at the cursor stops the read where it stands");
    let (rows, to, _) = read_over(|_, _| refused(410, json!({"error": "history_reclaimed"})), 5, false);
    assert_eq!((rows, to), (vec![], Some(5)), "a reclaim naming no floor stops it too");
    let (rows, to, _) = read_over(|_, _| refused(503, json!({"error": "feed_rebuilding"})), 10, false);
    assert_eq!((rows, to), (vec![], Some(10)), "a refusal stops it where it stands");
    let closed = |_: u64, _: Option<u64>| Response { status: 200, headers: Headers(vec![("Skepd-Session".into(), "closed".into())]), body: Vec::new() };
    let (rows, to, _) = read_over(closed, 10, true);
    assert_eq!((rows, to), (vec![], None), "the death signal on a session's token is the death");
}
