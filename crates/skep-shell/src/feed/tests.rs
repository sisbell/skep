//! THE FEED's FENCE: the index state's ten arms and the search words as
//! the bridge spells them; THE FEED THREAD's START, one `/health` read; and
//! THE COMMIT STREAM COALESCED — the waiting tick's mark, and a board
//! committing far faster than the feed thread reads costing it a read per
//! turn, never a read per commit, with a search queued behind them answered
//! after one read at most. And A DRAFTS CURSOR THE RETENTION FLOOR PASSED
//! resumed at the floor, its rows still fed.

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
