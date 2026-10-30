//! The feed thread over fake boards, and the words it spells for the bridge.
//!
//! The suite checks the index state's ten arms and the search words as the
//! bridge spells them — every arm, standing and mark a declared word, and
//! the search answer and the listing's built as their declarations say; the
//! feed thread's start, one `/health` read, and a search or a listing where
//! no index stands dialing nothing; the outage's three states, said once and
//! announced where no deliberate stop stands; and the commit stream
//! coalesced — the waiting tick's mark, and a board committing far faster
//! than the feed thread reads costing it a read per turn, never a read per
//! commit, with a search queued behind them answered after one read at most.
//! It checks one read to the head meeting every answer as its paging rule
//! says, a death answered with the position its finished pages reached; a
//! drafts cursor the retention floor passed resumed at the floor, its rows
//! still fed; a drafts row named under every session of its principal, a
//! closing session's last read among them; a principal's drafts read on
//! through the restart's re-open, one cursor per principal; and a read that
//! dies between two pages sending none of their rows again, while a
//! principal's last session dying mid-read leaves no cursor behind.

use std::io::{self, Read};
use std::sync::atomic::AtomicUsize;
use std::sync::Mutex;
use std::time::Duration;

use skep_client::board::Token;
use skep_client::dial::{DialError, Dialer, Headers, Method, Request, RequestHead, Response, StreamedResponse};
use skep_client::store::FileStore;
use skep_client::Origin;
use skep_search::{Chain, ChainAt};
use tempfile::TempDir;

use super::*;
use crate::events::Event;

/// The board `b-1` under test: a board at `127.0.0.1:9` dialed through
/// `dialer`, under the reference its sessions and its holds name it by.
fn entry_over(dialer: impl Dialer + 'static) -> Arc<BoardEntry> {
    Arc::new(BoardEntry { reference: "b-1".into(), board: Arc::new(Board::new(Origin::parse("http://127.0.0.1:9").unwrap(), dialer)) })
}

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

/// The listing's answer is built as its declarations say (A-255).
///
/// An edition with its label, a draft held under a departed grant and an
/// edition with none are held member by member to `PlacesAnswer`, `Place`
/// and `AccountCount`, the counts in address order — `1.0.9` before
/// `1.0.10`, which their spelling's order would reverse. The mutant that
/// spells the counts as an object, or sorts them as text, hands the page an
/// order its plane cannot draw.
#[test]
fn the_places_answer_is_built_as_its_declarations_say() {
    let address = |text: &str| skep_client::address::parse_address(text).unwrap();
    let held = Standing::Held { kind: GrantKind::Named, rung: Rung::Document, issuer: address("1.0.10") };
    let docs = vec![
        Place { doc: address("1.0.9.0.1"), kind: Kind::Edition, label: Some("a first line".into()), standing: Standing::Public },
        Place { doc: address("1.0.10.0.1"), kind: Kind::Draft, label: Some("held words".into()), standing: held },
        Place { doc: address("1.0.10.0.2"), kind: Kind::Edition, label: None, standing: Standing::Public },
    ];
    let counts = BTreeMap::from([(address("1.0.10"), 2), (address("1.0.9"), 1)]);
    let answer = places_answer_json(&PlacesAnswer { docs, counts, state: State::Complete { as_of: 7, floor: None } });
    crate::shapes::assert_declared("PlacesAnswer", &answer);
    let docs = answer["docs"].as_array().expect("the listed documents");
    assert_eq!(docs.len(), 3);
    for place in docs {
        crate::shapes::assert_declared("Place", place);
    }
    assert_eq!(docs[1]["standing"], json!({"held": {"kind": "named", "rung": "document", "issuer": "1.0.10"}}));
    for count in answer["counts"].as_array().expect("the counts") {
        crate::shapes::assert_declared("AccountCount", count);
    }
    assert_eq!(answer["counts"], json!([{"account": "1.0.9", "documents": 1}, {"account": "1.0.10", "documents": 2}]), "in address order");
    assert_eq!(answer["state"]["arm"], "complete");
}

/// A `feed` update's class spells S-24 (b)'s two words: `published` for a
/// row of the guest's feed, `drafts` for a row of a session's supplement.
#[test]
fn an_updates_class_is_published_or_a_sessions_drafts() {
    let entry = entry_over(skep_client::PlainHttp::new());
    let facts = crate::sessions::Facts { principal: 1, account: Some("1.0.1".into()), kind: crate::sessions::SessionKind::Bare };
    let open = crate::sessions::Open { token: Token::parse(&"9f".repeat(16)).unwrap(), facts, opened_at: 0 };
    let session = Sessions::new(None, Arc::new(|_: &str| {})).register(&entry, open, &mut NoSupplements);
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

/// The shared context of one board's feed thread over `entry`, every
/// session in `sessions`, the index under `store`.
fn shared_over(entry: &Arc<BoardEntry>, sessions: &Arc<Sessions>, bus: &Arc<EventBus>, store: &TempDir) -> Shared {
    let talk: Talk = Arc::new(|_: &str| {});
    let keys = Arc::new(FileStore::open(store.path().join("store")));
    let holds = Holds::new(Arc::clone(sessions), Arc::clone(bus), keys, store.path().to_path_buf(), Arc::clone(&talk), [Arc::clone(entry)]);
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

fn ok(v: Value) -> Response {
    Response { status: 200, headers: Headers::default(), body: v.to_string().into_bytes() }
}

impl Dialer for Committing {
    fn exchange(&self, _: &Origin, req: &Request) -> Result<Response, DialError> {
        if req.method == Method::Get && req.path.starts_with("/health") {
            self.health_reads.fetch_add(1, Ordering::SeqCst);
            return Ok(ok(json!({"ok": true, "log_position": 10, "auth": {"claimant": null, "local_trust": true, "origins": [], "signed_origins": []}, "writes": {"halted": false}})));
        }
        if req.method == Method::Get && req.path.starts_with("/changes") {
            self.changes_reads.fetch_add(1, Ordering::SeqCst);
            std::thread::sleep(self.delay);
            return Ok(ok(json!({"changes": [], "last": 10, "more": false})));
        }
        Ok(ok(json!({"resp": "delivery", "items": []})))
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
    let entry = entry_over(Arc::clone(&fake));
    let store = TempDir::new().unwrap();
    let shared = shared_over(&entry, &Arc::new(Sessions::new(None, Arc::new(|_: &str| {}))), &Arc::new(EventBus::new()), &store);
    let threads = FeedThreads::spawn(entry, shared);
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
    let entry = entry_over(Arc::clone(&fake));
    let store = TempDir::new().unwrap();
    let bus = Arc::new(EventBus::new());
    let rx = bus.subscribe();
    let threads = FeedThreads::spawn(Arc::clone(&entry), shared_over(&entry, &Arc::new(Sessions::new(None, Arc::new(|_: &str| {}))), &bus, &store));
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

/// THE OUTAGE's THREE STATES, as one feeder says them: a stream that fails
/// twice is said on TALK once and announced `unreachable` once, the next
/// tick saying `running`; under the own node's deliberate stop a failure is
/// said and announced never, and the next tick says no `running` of its
/// own; and a stop lifted while the stream is still down lets the next
/// failure be announced, said no second time (the mutants that announce
/// under the stop, owe `running` for an outage never announced, or say an
/// outage twice before the stream answers).
#[test]
fn an_outage_is_said_once_and_announced_where_no_stop_stands() {
    let fake = Committing::new(None, &Arc::new(AtomicBool::new(false)), Duration::ZERO);
    let entry = entry_over(Arc::clone(&fake));
    let store = TempDir::new().unwrap();
    let bus = Arc::new(EventBus::new());
    let rx = bus.subscribe();
    let shared = shared_over(&entry, &Arc::new(Sessions::new(None, Arc::new(|_: &str| {}))), &bus, &store);
    let holds = Arc::clone(&shared.holds);
    let lines = Arc::new(Mutex::new(Vec::new()));
    let kept = Arc::clone(&lines);
    let talk: Talk = Arc::new(move |l: &str| kept.lock().unwrap().push(l.to_string()));
    let mut feeder = Feeder::new(&entry, Shared { talk, ..shared });
    let daemon = || -> Vec<String> { rx.try_iter().filter(|e| e.name == EventName::Daemon).map(|e| e.data["state"].as_str().unwrap_or("?").to_string()).collect() };
    let said = || lines.lock().unwrap().iter().filter(|l| l.contains("is not answering")).count();
    feeder.unreachable("refused");
    feeder.unreachable("refused");
    assert_eq!((daemon(), said()), (vec!["unreachable".to_string()], 1), "announced once, said once");
    feeder.tick(10);
    assert_eq!(daemon(), ["running"], "the announced outage owes the next tick's `running`");
    holds.set_node_stopped("b-1", true);
    feeder.unreachable("refused");
    feeder.unreachable("refused");
    assert_eq!((daemon(), said()), (Vec::<String>::new(), 2), "under the stop, said once and announced never");
    feeder.tick(10);
    assert!(daemon().is_empty(), "an outage never announced owes no `running`");
    feeder.unreachable("refused");
    holds.set_node_stopped("b-1", false);
    feeder.unreachable("refused");
    assert_eq!((daemon(), said()), (vec!["unreachable".to_string()], 3), "the lifted stop's next failure is announced, the outage said once");
}

/// A board whose index cannot open: every `/op` dial — the consumer's read
/// of the board's head among them — refused as a connection never made, and
/// counted; `/health` answered as a board with no `H.1` answers it, and its
/// stream never connecting.
struct Unopenable {
    op_dials: AtomicUsize,
}

impl Dialer for Unopenable {
    fn exchange(&self, _: &Origin, req: &Request) -> Result<Response, DialError> {
        if req.method == Method::Post && req.path == "/op" {
            self.op_dials.fetch_add(1, Ordering::SeqCst);
            return Err(DialError::Connect("the board's head is not answered".into()));
        }
        if req.method == Method::Get && req.path.starts_with("/health") {
            return Ok(ok(json!({"ok": true, "log_position": 10, "auth": {"claimant": null, "local_trust": true, "origins": [], "signed_origins": []}, "writes": {"halted": false}})));
        }
        Ok(ok(json!({"changes": [], "last": 10, "more": false})))
    }

    fn stream(&self, _: &Origin, _: &RequestHead, _: &mut dyn Read, _: &mut dyn FnMut(&Headers)) -> Result<StreamedResponse, DialError> {
        Err(DialError::Connect("no stream here".into()))
    }
}

/// A search or a listing dials nothing where no index stands (§4b.1).
///
/// The `search` row says "PURE LOCAL: no board read on the call's path".
/// The feed thread's start tries the index once and the board does not
/// answer; a guest search after it answers `state: none`, and a listing the
/// whole shape with no document, each with no dial of its own. The mutant
/// that opens the index on the call's path reads the board's head again, a
/// connect timeout on every keystroke while the board is down.
#[test]
fn a_search_or_a_listing_dials_nothing_where_no_index_stands() {
    let fake = Arc::new(Unopenable { op_dials: AtomicUsize::new(0) });
    let entry = entry_over(Arc::clone(&fake));
    let store = TempDir::new().unwrap();
    let bus = Arc::new(EventBus::new());
    let rx = bus.subscribe();
    let threads = FeedThreads::spawn(Arc::clone(&entry), shared_over(&entry, &Arc::new(Sessions::new(None, Arc::new(|_: &str| {}))), &bus, &store));
    // The feed thread's start runs before its first command: once the
    // stream's failure is announced, the start's one try at the index is made.
    let deadline = Instant::now() + Duration::from_secs(10);
    let started = loop {
        match rx.recv_timeout(deadline.saturating_duration_since(Instant::now())) {
            Ok(event) if event.name == EventName::Daemon && event.data["state"] == "unreachable" => break true,
            Ok(_) => {}
            Err(_) => break false,
        }
    };
    let tried = fake.op_dials.load(Ordering::SeqCst);
    let answer = threads.feed().search(Searcher::Guest, "x", BridgeSearchOpts::default());
    let listing = threads.feed().places(Searcher::Guest, None);
    let dials = fake.op_dials.load(Ordering::SeqCst);
    threads.stop();
    assert!(started && tried == 1, "the start tried the index once: {tried}");
    assert_eq!(answer.map(|v| v["state"]["arm"].clone()), Ok(json!("none")), "the search answers with no index");
    assert_eq!(listing, Ok(json!({"docs": [], "counts": [], "state": {"arm": "none"}})), "the listing answers with no index");
    assert_eq!(dials, tried, "the search or the listing dialed the board");
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
            return Ok(ok(json!({"ok": true, "log_position": 10, "auth": {"claimant": null, "local_trust": true, "origins": [], "signed_origins": []}, "writes": {"halted": false}})));
        }
        if req.method == Method::Get && req.path.starts_with("/changes") {
            let since = since_of(&req.path);
            if !req.path.contains("drafts=true") {
                return Ok(ok(json!({"changes": [], "last": since.max(10), "more": false})));
            }
            if since < FLOOR {
                return Ok(Response { status: 410, headers: Headers::default(), body: json!({"error": "history_reclaimed", "floor": FLOOR}).to_string().into_bytes() });
            }
            let rows: Vec<Value> = if since < DRAFT_ROW_AT { vec![json!({"at": DRAFT_ROW_AT, "op": "insert", "docs": ["1.0.1.0.1"], "key": "bare"})] } else { Vec::new() };
            return Ok(ok(json!({"changes": rows, "last": since.max(DRAFT_ROW_AT), "more": false})));
        }
        Ok(ok(json!({"resp": "delivery", "items": []})))
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
    let entry = entry_over(Arc::clone(&fake));
    let store = TempDir::new().unwrap();
    let (sessions, bus) = (Arc::new(Sessions::new(None, Arc::new(|_: &str| {}))), Arc::new(EventBus::new()));
    let rx = bus.subscribe();
    let facts = crate::sessions::Facts { principal: 1, account: Some("1.0.1".into()), kind: crate::sessions::SessionKind::Bare };
    let session = sessions.register(&entry, crate::sessions::Open { token: Token::parse(&"9f".repeat(16)).unwrap(), facts, opened_at: 0 }, &mut NoSupplements);
    let shared = shared_over(&entry, &sessions, &bus, &store);
    let threads = FeedThreads::spawn(entry, shared);
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
    ok(json!({"changes": rows, "last": last, "more": more}))
}

/// A non-200 answer of `body`.
fn refused(status: u16, body: Value) -> Response {
    Response { status, headers: Headers::default(), body: body.to_string().into_bytes() }
}

/// Returns the death signal: an answer whose `Skepd-Session` says `closed`.
fn closed() -> Response {
    Response { status: 200, headers: Headers(vec![("Skepd-Session".into(), "closed".into())]), body: Vec::new() }
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

/// Returns what one read to the head made of a scripted board's feed.
///
/// The board answers each `/changes` ask as `script` says, and the read runs
/// from `since` over the published feed, or over a session's drafts under
/// its token where `drafts`. The answer is the rows the read handed on,
/// where it left the feed, and the queries it asked. The read runs on a
/// thread of its own, so a read that never ends fails at the deadline
/// rather than hanging the suite.
fn read_over(script: impl Fn(u64, Option<u64>) -> Response + Send + Sync + 'static, since: u64, drafts: bool) -> (Vec<u64>, ReadTo, Vec<(u64, Option<u64>)>) {
    let fake = Arc::new(Paging { script: Box::new(script), asked: Mutex::new(Vec::new()) });
    let entry = entry_over(Arc::clone(&fake));
    let session = drafts.then(|| {
        let facts = crate::sessions::Facts { principal: 1, account: Some("1.0.1".into()), kind: crate::sessions::SessionKind::Bare };
        let open = crate::sessions::Open { token: Token::parse(&"9f".repeat(16)).unwrap(), facts, opened_at: 0 };
        Sessions::new(None, Arc::new(|_: &str| {})).register(&entry, open, &mut NoSupplements)
    });
    let board = Arc::clone(&entry.board);
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let class = session.as_deref().map_or(UpdateClass::Published, UpdateClass::Drafts);
        let mut rows = Vec::new();
        let to = read_to_head(&board, class, since, |row| rows.push(row["at"].as_u64().unwrap_or(0)));
        let _ = tx.send((rows, to));
    });
    let (rows, to) = rx.recv_timeout(Duration::from_secs(5)).expect("the read to the head ends");
    let asked = fake.asked.lock().unwrap().clone();
    (rows, to, asked)
}

/// Checks that a read to the head meets each answer as its paging rule says.
///
/// It is wire.md §The change feed, Paging, cell by cell: a page whose `more`
/// stands read on from its `last`; a page past the budget re-asked at the
/// `fits` it names, the next page at the route's default again; a reclaim
/// resumed at a floor past the cursor, while one at the cursor, or naming no
/// floor, stops where it stands — never spinning; a refusal stopping where
/// it stands; and the death signal on a session's token answered as the
/// death, with the position the read's finished pages reached. The mutants
/// that ignore `more`, stop at a page too large or never reset its limit,
/// stop at a reclaim, drop the floor's guard, read the death as a stop, or
/// answer it without the position its pages reached each fail a cell — the
/// first feeding a closing session nothing past its first page, the guard's
/// spinning the board's feed thread for good, and the last sending a
/// principal's rows again under every session that reads on.
#[test]
fn a_read_to_the_head_meets_every_answer_as_its_paging_rule_says() {
    let (rows, to, _) = read_over(|since, _| if since == 10 { page(&[11], 11, true) } else { page(&[12], 12, false) }, 10, false);
    assert_eq!((rows, to), (vec![11, 12], ReadTo::At(12)), "a page whose `more` stands is read on");
    let too_large = |since: u64, limit: Option<u64>| match limit {
        Some(1) => page(&[since + 1], since + 1, since == 10),
        _ => refused(400, json!({"error": "malformed_changes", "fits": 1})),
    };
    let (rows, to, asked) = read_over(too_large, 10, false);
    assert_eq!((rows, to), (vec![11, 12], ReadTo::At(12)), "a page too large is re-asked");
    assert_eq!(asked, [(10, None), (10, Some(1)), (11, None), (11, Some(1))], "at `fits`, the next page at the default again");
    let (rows, to, _) = read_over(|since, _| if since < 5 { refused(410, json!({"error": "history_reclaimed", "floor": 5})) } else { page(&[6], 6, false) }, 3, false);
    assert_eq!((rows, to), (vec![6], ReadTo::At(6)), "a floor past the cursor is resumed at");
    let (rows, to, _) = read_over(|_, _| refused(410, json!({"error": "history_reclaimed", "floor": 5})), 5, false);
    assert_eq!((rows, to), (vec![], ReadTo::At(5)), "a floor at the cursor stops the read where it stands");
    let (rows, to, _) = read_over(|_, _| refused(410, json!({"error": "history_reclaimed"})), 5, false);
    assert_eq!((rows, to), (vec![], ReadTo::At(5)), "a reclaim naming no floor stops it too");
    let (rows, to, _) = read_over(|_, _| refused(503, json!({"error": "feed_rebuilding"})), 10, false);
    assert_eq!((rows, to), (vec![], ReadTo::At(10)), "a refusal stops it where it stands");
    let (rows, to, _) = read_over(|_, _| closed(), 10, true);
    assert_eq!((rows, to), (vec![], ReadTo::Died { at: 10 }), "the death signal on a session's token is the death");
    let (rows, to, _) = read_over(|since, _| if since == 10 { page(&[11], 11, true) } else { closed() }, 10, true);
    assert_eq!((rows, to), (vec![11], ReadTo::Died { at: 11 }), "a death after a page answers where the page reached");
}

/// A bare session of `principal` registered at `entry` in `sessions`, its
/// token `token` sixteen times over, opened at `opened_at`.
fn session_of(sessions: &Sessions, entry: &BoardEntry, principal: u64, token: &str, opened_at: u64) -> Arc<SessionEntry> {
    let facts = crate::sessions::Facts { principal, account: Some(format!("1.0.{principal}")), kind: crate::sessions::SessionKind::Bare };
    let open = crate::sessions::Open { token: Token::parse(&token.repeat(16)).unwrap(), facts, opened_at };
    sessions.register(entry, open, &mut NoSupplements)
}

/// The drafts rows `rx` has seen since the last look, each as its position
/// and the session its event names, sorted.
fn drafts_named(rx: &Receiver<Event>) -> Vec<(u64, String)> {
    let mut named: Vec<(u64, String)> = rx
        .try_iter()
        .filter(|e| e.name == EventName::Feed && e.data["update"]["class"] == "drafts")
        .map(|e| (e.data["update"]["at"].as_u64().unwrap_or(0), e.data["update"]["session"].as_str().unwrap_or("?").to_string()))
        .collect();
    named.sort();
    named
}

/// A board whose drafts feed holds one row, at 6: a read from below it
/// answers the row, one from at or past it the empty page.
fn one_drafts_row(since: u64, _: Option<u64>) -> Response {
    if since < 6 {
        page(&[6], 6, false)
    } else {
        page(&[], since, false)
    }
}

/// A DRAFTS ROW IS NAMED UNDER EVERY SESSION OF ITS PRINCIPAL (S-24 (b);
/// `client.md` §4e.3, one supplement per principal): two sessions of
/// principal 1 — two tabs — and one of principal 2; the row principal 1's
/// read meets goes out once under each of its sessions, whichever of them
/// read it, and principal 2's once under its own; and a closing session's
/// last read names the row under it and under the tab still standing (the
/// mutant that names a row under the session that read it alone leaves the
/// other tab's page stale, its index short of a draft with nothing said).
#[test]
fn a_drafts_row_is_named_under_every_session_of_its_principal() {
    let entry = entry_over(Paging { script: Box::new(one_drafts_row), asked: Mutex::new(Vec::new()) });
    for closing in [false, true] {
        let store = TempDir::new().unwrap();
        let (sessions, bus) = (Arc::new(Sessions::new(None, Arc::new(|_: &str| {}))), Arc::new(EventBus::new()));
        let rx = bus.subscribe();
        let first = session_of(&sessions, &entry, 1, "9f", 0);
        let second = session_of(&sessions, &entry, 1, "8e", 0);
        let other = session_of(&sessions, &entry, 2, "7d", 0);
        let mut feeder = Feeder::new(&entry, shared_over(&entry, &sessions, &bus, &store));
        let mut owed: Vec<(u64, String)> = vec![(6, first.reference.clone()), (6, second.reference.clone())];
        if closing {
            assert!(sessions.close(&first.reference).is_some(), "the closing session leaves the table");
            feeder.read_drafts(&first);
        } else {
            feeder.read_feed();
            owed.push((6, other.reference.clone()));
        }
        owed.sort();
        assert_eq!(drafts_named(&rx), owed, "closing {closing}");
    }
}

/// A board whose drafts feed holds rows at 6 and 8, shown up to a head the
/// test moves; every other read answered with an empty delivery, as a board
/// with no `H.1` answers the read of its head.
struct Moving {
    head: AtomicU64,
}

impl Dialer for Moving {
    fn exchange(&self, _: &Origin, req: &Request) -> Result<Response, DialError> {
        if req.method == Method::Get && req.path.starts_with("/changes") {
            let (since, head) = (since_of(&req.path), self.head.load(Ordering::SeqCst));
            let ats: Vec<u64> = [6, 8].into_iter().filter(|at| since < *at && *at <= head).collect();
            return Ok(page(&ats, since.max(head), false));
        }
        Ok(ok(json!({"resp": "delivery", "items": []})))
    }

    fn stream(&self, _: &Origin, _: &RequestHead, _: &mut dyn Read, _: &mut dyn FnMut(&Headers)) -> Result<StreamedResponse, DialError> {
        Err(DialError::Connect("no stream here".into()))
    }
}

/// A PRINCIPAL's DRAFTS READ ON THROUGH THE RESTART's RE-OPEN (`client.md`
/// §4e.3: the supplement "re-mounted with the re-opened session"): a session
/// reads the row at 6, the board commits the row at 8, the session leaves
/// the table with no narrow, as the restart arm leaves it, and the session
/// re-opened at 10 reads on from where its principal's read stopped — the
/// row at 8, committed between the two reads, reaches the page under it (the
/// mutant that keeps a cursor per session starts the re-opened one at its
/// own open, past the row at 8, which then never reaches the page).
#[test]
fn a_principals_drafts_read_on_through_the_restarts_reopen() {
    let fake = Arc::new(Moving { head: AtomicU64::new(6) });
    let entry = entry_over(Arc::clone(&fake));
    let store = TempDir::new().unwrap();
    let (sessions, bus) = (Arc::new(Sessions::new(None, Arc::new(|_: &str| {}))), Arc::new(EventBus::new()));
    let rx = bus.subscribe();
    let mut feeder = Feeder::new(&entry, shared_over(&entry, &sessions, &bus, &store));
    let dying = session_of(&sessions, &entry, 1, "9f", 0);
    Supplements::widen(&mut feeder, &dying);
    feeder.read_drafts(&dying);
    fake.head.store(8, Ordering::SeqCst);
    assert!(sessions.close(&dying.reference).is_some(), "the dying session leaves the table");
    let reopened = session_of(&sessions, &entry, 1, "8e", 10);
    Supplements::widen(&mut feeder, &reopened);
    feeder.read_drafts(&reopened);
    assert_eq!(drafts_named(&rx), [(6, dying.reference.clone()), (8, reopened.reference.clone())]);
}

/// A board whose drafts feed holds rows at 6 and 8, and ends one token at 6.
///
/// A drafts read from below 6 answers the row at 6 with `more` standing.
/// From 6 on, the token `dying` meets the death signal, and any other token
/// the row at 8, then the empty page from 8 on. A published read answers
/// the empty page, and every other read an empty delivery, as a board with
/// no `H.1` answers the read of its head.
struct DiesMidRead {
    dying: String,
}

impl Dialer for DiesMidRead {
    fn exchange(&self, _: &Origin, req: &Request) -> Result<Response, DialError> {
        if !(req.method == Method::Get && req.path.starts_with("/changes")) {
            return Ok(ok(json!({"resp": "delivery", "items": []})));
        }
        let since = since_of(&req.path);
        if !req.path.contains("drafts=true") {
            return Ok(page(&[], since, false));
        }
        let token = req.headers.iter().find(|(name, _)| name.eq_ignore_ascii_case("Skepd-Session")).map(|(_, token)| token.as_str());
        Ok(if since >= 6 && token == Some(self.dying.as_str()) {
            closed()
        } else if since < 6 {
            page(&[6], 6, true)
        } else if since < 8 {
            page(&[8], 8, false)
        } else {
            page(&[], since, false)
        })
    }

    fn stream(&self, _: &Origin, _: &RequestHead, _: &mut dyn Read, _: &mut dyn FnMut(&Headers)) -> Result<StreamedResponse, DialError> {
        Err(DialError::Connect("no stream here".into()))
    }
}

/// Checks that a read dying between two pages keeps the position they reached.
///
/// Two tabs of one principal stand, and the board ends one tab's token
/// between the first and the second page of its drafts read — the tab still
/// in the table, as a death the board alone makes leaves it, or closed
/// already, as the shell's stop leaves a tab whose read is under way. The
/// tab still standing then reads on from where the dead read's pages
/// reached (`client.md` §4e.3: one supplement per principal, one cursor), so
/// each row reaches each tab once. The mutant that answers the death
/// without its position starts the tab still standing where the dead read
/// began, and that tab hears the row at 6 a second time.
#[test]
fn a_read_that_dies_between_two_pages_sends_no_row_again() {
    let entry = entry_over(DiesMidRead { dying: "9f".repeat(16) });
    for left_the_table in [false, true] {
        let store = TempDir::new().unwrap();
        let (sessions, bus) = (Arc::new(Sessions::new(None, Arc::new(|_: &str| {}))), Arc::new(EventBus::new()));
        let rx = bus.subscribe();
        let dying = session_of(&sessions, &entry, 1, "9f", 0);
        let standing = session_of(&sessions, &entry, 1, "8e", 0);
        let mut feeder = Feeder::new(&entry, shared_over(&entry, &sessions, &bus, &store));
        if left_the_table {
            assert!(sessions.close(&dying.reference).is_some(), "the dying session leaves the table first");
        }
        feeder.read_drafts(&dying);
        feeder.read_drafts(&standing);
        let mut owed = vec![(6, dying.reference.clone()), (6, standing.reference.clone()), (8, standing.reference.clone())];
        owed.sort();
        assert_eq!(drafts_named(&rx), owed, "left the table {left_the_table}");
    }
}

/// Checks that a principal's last session dying mid-read leaves no cursor.
///
/// The read's position is set before the session's end, so the narrow the
/// end makes where no session of the principal stands drops it, and a
/// session the principal opens later is fed from its own open (the module
/// doc of `feed`). The mutant that sets the position after the end makes a
/// cursor the narrow had dropped, and the session opened later, at 8, is
/// sent the row at 8 — a row its own read from its open never meets.
#[test]
fn a_principals_last_session_dying_mid_read_keeps_no_cursor() {
    let entry = entry_over(DiesMidRead { dying: "9f".repeat(16) });
    let store = TempDir::new().unwrap();
    let (sessions, bus) = (Arc::new(Sessions::new(None, Arc::new(|_: &str| {}))), Arc::new(EventBus::new()));
    let rx = bus.subscribe();
    let mut feeder = Feeder::new(&entry, shared_over(&entry, &sessions, &bus, &store));
    let dying = session_of(&sessions, &entry, 1, "9f", 0);
    feeder.read_drafts(&dying);
    let later = session_of(&sessions, &entry, 1, "8e", 8);
    Supplements::widen(&mut feeder, &later);
    feeder.read_drafts(&later);
    assert_eq!(drafts_named(&rx), [(6, dying.reference.clone())]);
}
