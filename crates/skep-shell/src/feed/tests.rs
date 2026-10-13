//! THE FEED's FENCE: the index state's ten arms and the search words as
//! the bridge spells them; and THE COMMIT STREAM COALESCED — the waiting
//! tick's mark, and a board committing far faster than the worker reads
//! costing it a read per turn, never a read per commit, with a search queued
//! behind them answered after one read at most.

use std::io::{self, Read};
use std::sync::atomic::AtomicUsize;
use std::sync::Mutex;
use std::time::Duration;

use skep_client::dial::{DialError, Dialer, Headers, Method, Request, RequestHead, Response, StreamedResponse};
use skep_client::Origin;
use tempfile::TempDir;

use super::*;

/// The ten arms spell their names and members as §4b.2 draws them.
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

/// A board's `/events` stream yielding `commits` commits, served once: the
/// `/changes` reads it is asked counted, each made `delay` long, as a board
/// across a network makes them; `/health` and `/op` answered as a board with
/// no `H.1` answers them.
struct Committing {
    events: Mutex<Option<Vec<u8>>>,
    drained: Arc<AtomicBool>,
    changes: AtomicUsize,
    delay: Duration,
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
            return Ok(answer(json!({"ok": true, "log_position": 10, "auth": {"claimant": null, "local_trust": true, "origins": [], "signed_origins": []}, "writes": {"halted": false}})));
        }
        if req.method == Method::Get && req.path.starts_with("/changes") {
            self.changes.fetch_add(1, Ordering::SeqCst);
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
/// than the worker reads `/changes` costs the worker a read per turn — a few
/// — never one per commit, and a search queued as the stream ends is
/// answered after one read at most (the mutant that queues a tick per commit
/// reads two thousand times, the search waiting every one of them out).
#[test]
fn a_board_committing_faster_than_the_worker_reads_costs_a_read_per_turn() {
    let commits = 2000;
    let events: String = (1..=commits).map(|n| format!("event: commit\ndata: {{\"log_position\": {n}}}\n\n")).collect();
    let drained = Arc::new(AtomicBool::new(false));
    let fake = Arc::new(Committing { events: Mutex::new(Some(events.into_bytes())), drained: Arc::clone(&drained), changes: AtomicUsize::new(0), delay: Duration::from_millis(2) });
    let origin = Origin::parse("http://127.0.0.1:9").unwrap();
    let board = Arc::new(Board::new(origin.clone(), Arc::clone(&fake)));
    let store = TempDir::new().unwrap();
    let (sessions, bus, talk): (Arc<Sessions>, Arc<EventBus>, Talk) = (Arc::new(Sessions::new()), Arc::new(EventBus::new()), Arc::new(|_: &str| {}));
    let keys = Arc::new(FileStore::open(store.path().join("store")));
    let holds = Holds::new(Arc::clone(&sessions), Arc::clone(&bus), keys, store.path().to_path_buf(), Arc::clone(&talk), [("b-1".to_string(), Arc::clone(&board))]);
    let shared = Shared { bus, sessions, reopen_store: None, data_dir: store.path().to_path_buf(), talk, holds };
    let threads = FeedThreads::spawn(Arc::new(BoardEntry { reference: "b-1".into(), origin, board }), shared);
    let deadline = Instant::now() + Duration::from_secs(10);
    while !drained.load(Ordering::SeqCst) && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(5));
    }
    assert!(drained.load(Ordering::SeqCst), "the stream was read to its end");
    let started = Instant::now();
    assert!(threads.feed().search(Searcher::Guest, "x", SearchOpts::default(), false).is_ok());
    let waited = started.elapsed();
    let reads = fake.changes.load(Ordering::SeqCst);
    threads.stop();
    assert!(reads < commits / 20, "{reads} reads for {commits} commits");
    assert!(waited < Duration::from_secs(1), "the search waited {waited:?} behind the reads queued");
}
