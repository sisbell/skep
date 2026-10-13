//! THE FEED CONSUMER's THREAD, one per board (`client.md` §4b.2: "THE
//! CONSUMER LIVES IN THE SHELL, which holds the session, and the page reads
//! it through this event" — ps3-6; the dev provider record §3.3): the
//! library's `search::Consumer` opened over the board's directory beside
//! the key store, polled on each commit the `/events` stream yields, and
//! beside it this crate's own read of the `/changes` pages for the `feed`
//! events — the published feed as a guest, and each open session's drafts
//! supplement under its token — the `/health` pair read per tick for the
//! `mode` event, the stream's state for the `daemon` event (every board the
//! shell dials, each event naming its board; silent under the own node's
//! DELIBERATE STOP, which the shell announces `stopped` once —
//! [`Worker::unreachable`]), and the consumer's state for the `index` event,
//! each emitted where it moved.
//! The bridge's `search` call is answered on this thread too, over a
//! channel, so the consumer never crosses a thread: two threads per board,
//! the stream's reader and the consumer's owner, each borrowing the board
//! from the `Arc` it holds. A death signal this thread's reads meet ends
//! the session by the one sequence the shell runs too (`Sessions::end`).
//! A session the page closes is read once more here, to the board's head
//! under its still-standing token, before its close answers
//! ([`Feed::closing`]): every `feed` row of a session precedes its
//! `session-died`, however far this thread trails the commits. The board's
//! held bursts are watched here too: `writes.halted` read at each tick, and
//! THE PROBE (`Holds::probe`) every `PROBE_CADENCE`, measured from the last
//! probe whatever woke the thread between, and at a hand-over
//! ([`Feed::probe`], `resolve(send)`'s). Both feeds are read to the board's
//! head by ONE reader ([`read_to_head`]), the published feed and every
//! drafts supplement alike: a page past the retention floor resumed at the
//! floor, a page past the page budget re-asked at the limit that fits. The
//! commits the stream yields
//! are COALESCED ([`Ticks`]): one tick waits in the worker's queue at most,
//! so a board committing faster than the worker reads costs one read to the
//! head per turn, never a read per commit, and a call queued behind them
//! waits one read at most.
//!
//! THE `feed` UPDATE's SHAPE — THIS CRATE's DEFINITION (S-24 (b), the
//! shell's): the `/changes` row's members VERBATIM (`at`, `op`, `docs`,
//! `key`, `time`, `attest`, `new_prefix`, `new_id`, `link`, `placed`,
//! `base_extent`, and any later member by the wire's forward rule), plus
//! `position` (the row's `at`, named once more so a consumer reading the
//! shell's shape need not know the wire's), and `class` — `published` for a
//! row of the guest's feed, `drafts` for one of a session's supplement, the
//! latter with `session`, the reference it was read under. The event
//! carries `board`, the reference, beside `update`. The published feed
//! starts at the head the board FIRST ANSWERS with — at the thread's start,
//! or at its first `/health` after it, never at 0 for a board not yet up —
//! and a session's drafts at the position the session opened at: a page
//! re-reads what it shows on open and takes the updates from there.

use std::collections::{BTreeMap, HashMap};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{channel, Receiver, RecvTimeoutError, Sender};
use std::sync::Arc;
use std::thread;
use std::time::Instant;

use serde_json::{json, Value};
use skep_client::board::{ChangesAnswer, ChangesQuery, Token};
use skep_client::derive::Mode;
use skep_client::search::{events, Consumer, Lost, Newer, Place, Range, SearchAnswer, SearchDir, SearchOpts, SessionRef, State, Stop, Who};
use skep_client::store::FileStore;
use skep_client::{Board, Origin};
use skep_search::{GrantKind, Hit, Kind, Mark, MarkKind, Rung, Standing};

use crate::events::{EventBus, EventName};
use crate::hold::{Holds, PROBE_CADENCE};
use crate::refusal::{Name, Refusal};
use crate::sessions::{SessionEntry, Sessions, Supplements};
use crate::Talk;

/// One board of the shell: its reference, its origin and the board dialed
/// through the shell's one logging dialer — shared with the board's holds.
pub struct BoardEntry {
    pub reference: String,
    pub origin: Origin,
    pub board: Arc<Board>,
}

impl std::fmt::Debug for BoardEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "BoardEntry({}, {})", self.reference, self.origin)
    }
}

/// Who searches, owned: the guest, or a session's facts.
#[derive(Debug, Clone)]
pub enum Searcher {
    Guest,
    Session { principal: u64, token: Token, account: String },
}

/// What the feed thread is asked.
enum Cmd {
    /// Commits the stream yielded, read off [`Ticks`].
    Tick,
    /// The stream could not connect.
    Unreachable(String),
    /// A session registered: its supplement mounted.
    Widen(Arc<SessionEntry>),
    /// A session ended: its supplement unmounted.
    Narrow(u64),
    /// A session the page is closing, its token still standing: its drafts
    /// rows read to the head, then its supplement released; answered.
    Closing(Arc<SessionEntry>, Sender<()>),
    /// THE PROBE handed over: run at the worker's next turn, unanswered.
    Probe,
    /// The bridge's search call.
    Search { who: Searcher, query: String, opts: SearchOpts, reindex: bool, reply: Sender<Result<Value, Refusal>> },
    /// The consumer closed; the thread ends.
    Stop(Sender<()>),
}

/// What every board's feed thread shares with the shell: the bus its events
/// go out on, the session table, the store the restart arm re-opens a
/// session under (the signed mode's, none under the bare mode), the data
/// directory the index sits under, the TALK sink, and the held-burst holds
/// the worker drives — the `writes.halted` read at each tick and THE PROBE
/// every `PROBE_CADENCE`.
#[derive(Clone)]
pub struct Shared {
    pub bus: Arc<EventBus>,
    pub sessions: Arc<Sessions>,
    pub reopen_store: Option<Arc<FileStore>>,
    pub data_dir: PathBuf,
    pub talk: Talk,
    pub holds: Arc<Holds>,
}

/// THE HANDLE to one board's feed thread: each command sent on the thread's
/// own channel and answered there, so a caller waiting on one board's
/// worker holds nothing another caller needs. A handle is cloned freely;
/// once the thread has stopped, every command answers at once.
#[derive(Debug, Clone)]
pub struct Feed {
    cmds: Sender<Cmd>,
}

impl Feed {
    /// A session registered at this board: its supplement mounted.
    fn widen(&self, session: &Arc<SessionEntry>) {
        let _ = self.cmds.send(Cmd::Widen(Arc::clone(session)));
    }

    /// A session ended: its supplement unmounted.
    fn narrow(&self, principal: u64) {
        let _ = self.cmds.send(Cmd::Narrow(principal));
    }

    /// A session the page is closing — out of the table, its token still
    /// standing at the board: its drafts rows read to the head under that
    /// token, each a `feed` event, then its supplement released
    /// (`Sessions::release`), answered once both are done, so every `feed`
    /// row of the session precedes the `session-died` its close emits next.
    /// A thread that has stopped answers at once.
    pub fn closing(&self, session: &Arc<SessionEntry>) {
        let (reply, rx) = channel();
        if self.cmds.send(Cmd::Closing(Arc::clone(session), reply)).is_ok() {
            let _ = rx.recv();
        }
    }

    /// THE PROBE handed to the board's worker (`Holds::probe`), run on its
    /// thread at its next turn and the probe's cadence counted from it — the
    /// caller does not wait: `resolve(send)`'s hand-over, so the call answers
    /// once the lines are handed back, never after a resend's ack (§4b.1). A
    /// thread that has stopped takes nothing.
    pub fn probe(&self) {
        let _ = self.cmds.send(Cmd::Probe);
    }

    /// The bridge's search call, answered on the consumer's thread;
    /// `feed_stopped` once the thread has stopped.
    pub fn search(&self, who: Searcher, query: &str, opts: SearchOpts, reindex: bool) -> Result<Value, Refusal> {
        let (reply, rx) = channel();
        if self.cmds.send(Cmd::Search { who, query: query.to_string(), opts, reindex, reply }).is_err() {
            return Err(Refusal::shell(Name::FEED_STOPPED, json!({})));
        }
        rx.recv().unwrap_or_else(|_| Err(Refusal::shell(Name::FEED_STOPPED, json!({}))))
    }
}

/// The supplements as the shell reaches them, through a board's handle:
/// each widen and narrow a command the board's thread runs — a shared
/// handle, as `&File` is a `Write`.
impl Supplements for &Feed {
    fn widen(&mut self, session: &Arc<SessionEntry>) {
        Feed::widen(self, session);
    }

    fn narrow(&mut self, principal: u64) {
        Feed::narrow(self, principal);
    }
}

/// THE COMMITS NOT YET READ: the latest position the `/events` stream
/// yielded, and whether a [`Cmd::Tick`] waits in the worker's queue for
/// them. The reader sends a tick only where none waits, and the worker
/// clears the mark as it takes one — BEFORE it reads — so a board committing
/// faster than the worker reads leaves one tick queued, never one per
/// commit, and a commit landing mid-read queues exactly the one more read
/// that sees it.
#[derive(Debug, Default)]
struct Ticks {
    waiting: AtomicBool,
    latest: AtomicU64,
}

impl Ticks {
    /// A commit at `position` yielded: whether a tick is owed, none waiting.
    fn note(&self, position: u64) -> bool {
        self.latest.fetch_max(position, Ordering::SeqCst);
        !self.waiting.swap(true, Ordering::SeqCst)
    }

    /// The waiting tick taken: the mark cleared, then the latest position
    /// read — the one the read about to run reaches at least.
    fn take(&self) -> u64 {
        self.waiting.store(false, Ordering::SeqCst);
        self.latest.load(Ordering::SeqCst)
    }
}

/// One board's TWO THREADS, the shell's until its stop: the stream's
/// reader, and the consumer-owner — JOINED at [`FeedThreads::stop`] so its
/// `Arc`s, the held-burst holds among them, which hold the `held/<chain>/`
/// lock, are dropped before the stop returns; a relaunch in the same
/// process then takes the lock the first shell held.
pub struct FeedThreads {
    feed: Feed,
    stream_stop: Stop,
    worker: thread::JoinHandle<()>,
}

impl std::fmt::Debug for FeedThreads {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("FeedThreads")
    }
}

impl FeedThreads {
    /// The two threads for `entry`, the consumer over `data_dir/index/`.
    pub fn spawn(entry: Arc<BoardEntry>, shared: Shared) -> FeedThreads {
        let (tx, rx) = channel();
        let ticks = Arc::new(Ticks::default());
        // The stream's reader: commits coalesced into a waiting tick, a
        // failed connect said. The stream borrows the board from the `Arc`
        // the thread holds, so its stopper comes back over a channel before
        // the first read.
        let (stop_tx, stop_rx) = channel();
        let (reader_entry, reader_tx, reader_ticks) = (Arc::clone(&entry), tx.clone(), Arc::clone(&ticks));
        thread::spawn(move || {
            let mut stream = events(&reader_entry.board);
            let _ = stop_tx.send(stream.stopper());
            while let Some(next) = stream.next() {
                let cmd = match next {
                    Ok(position) if reader_ticks.note(position) => Cmd::Tick,
                    Ok(_) => continue,
                    Err(h) => Cmd::Unreachable(h.to_string()),
                };
                if reader_tx.send(cmd).is_err() {
                    return;
                }
            }
        });
        let stream_stop = stop_rx.recv().expect("the reader sends its stopper before it reads");
        let worker = thread::spawn(move || Worker::run(entry, shared, rx, &ticks));
        FeedThreads { feed: Feed { cmds: tx }, stream_stop, worker }
    }

    /// A handle to the board's worker.
    pub fn feed(&self) -> Feed {
        self.feed.clone()
    }

    /// The stream ended and the consumer closed — the save at the shell's
    /// exit. The worker thread is JOINED last, so every `Arc` it held (the
    /// holds, and with them the `held/<chain>/` lock) is dropped before this
    /// returns.
    pub fn stop(self) {
        self.stream_stop.stop();
        let (reply, rx) = channel();
        if self.feed.cmds.send(Cmd::Stop(reply)).is_ok() {
            let _ = rx.recv();
        }
        let _ = self.worker.join();
    }
}

/// The consumer's owner.
struct Worker<'b> {
    entry: &'b BoardEntry,
    bus: Arc<EventBus>,
    sessions: Arc<Sessions>,
    /// The store the restart arm re-opens a session under: the signed
    /// mode's, none under the bare mode.
    reopen_store: Option<Arc<FileStore>>,
    data_dir: PathBuf,
    talk: Talk,
    /// The held-burst holds this worker drives.
    holds: Arc<Holds>,
    consumer: Option<Consumer<'b>>,
    /// Where the published feed's next read starts: the head the board first
    /// answered with, then each page's last — none until the board answers.
    published_since: Option<u64>,
    /// Where each mounted principal's drafts read starts: its session's open
    /// position, then each page's last.
    drafts_since: HashMap<u64, u64>,
    last_mode: Option<Mode>,
    last_index: BTreeMap<Option<u64>, Value>,
    /// The session reference per mounted principal, for the `index` event.
    session_references: HashMap<u64, String>,
    /// Whether `unreachable` was announced on the `daemon` event for this
    /// board, its `running` then owed at the next tick.
    announced_unreachable: bool,
    /// The stream is down — said on TALK once per outage, announced or not
    /// ([`Worker::unreachable`]); cleared by the next tick.
    down: bool,
}

impl<'b> Worker<'b> {
    fn run(entry: Arc<BoardEntry>, shared: Shared, rx: Receiver<Cmd>, ticks: &Ticks) {
        let entry_arc = entry;
        let entry: &BoardEntry = &entry_arc;
        let head = entry.board.health().ok().map(|h| h.log_position());
        let Shared { bus, sessions, reopen_store, data_dir, talk, holds } = shared;
        let mut worker = Worker {
            entry,
            bus,
            sessions,
            reopen_store,
            data_dir,
            talk,
            holds,
            consumer: None,
            published_since: head,
            drafts_since: HashMap::new(),
            last_mode: None,
            last_index: BTreeMap::new(),
            session_references: HashMap::new(),
            announced_unreachable: false,
            down: false,
        };
        worker.mount();
        worker.read_health();
        worker.emit_index();
        // THE PROBE (§3c.4) has a deadline of its own: the loop wakes on each
        // command and at the deadline, and probes once the deadline has
        // passed, whatever woke it — a poisoned, halted, stopped
        // or unreachable board commits nothing, so `Cmd::Tick` alone never
        // ends such a hold, and a board that keeps committing must not starve
        // the probe either.
        let mut next_probe = Instant::now() + PROBE_CADENCE;
        loop {
            match rx.recv_timeout(next_probe.saturating_duration_since(Instant::now())) {
                Ok(Cmd::Tick) => worker.tick(ticks.take()),
                Ok(Cmd::Unreachable(text)) => worker.unreachable(&text),
                Ok(Cmd::Widen(session)) => worker.widen(&session),
                Ok(Cmd::Narrow(principal)) => worker.narrow(principal),
                Ok(Cmd::Closing(session, reply)) => {
                    worker.read_drafts(&session);
                    let sessions = Arc::clone(&worker.sessions);
                    sessions.release(&session.board_reference, session.facts.principal, &mut worker);
                    let _ = reply.send(());
                }
                Ok(Cmd::Probe) => {
                    worker.holds.probe(&worker.entry.reference);
                    next_probe = Instant::now() + PROBE_CADENCE;
                }
                Ok(Cmd::Search { who, query, opts, reindex, reply }) => {
                    let _ = reply.send(worker.search(who, &query, &opts, reindex));
                }
                Ok(Cmd::Stop(reply)) => {
                    worker.close();
                    let _ = reply.send(());
                    return;
                }
                Err(RecvTimeoutError::Timeout) => {}
                Err(RecvTimeoutError::Disconnected) => break,
            }
            if Instant::now() >= next_probe {
                worker.holds.probe(&worker.entry.reference);
                next_probe = Instant::now() + PROBE_CADENCE;
            }
        }
        worker.close();
    }

    fn say(&self, line: String) {
        (self.talk)(&format!("feed {}: {line}", self.entry.reference));
    }

    /// The consumer opened, where it is not yet; a failed open said and
    /// tried again at the next tick.
    fn mount(&mut self) {
        if self.consumer.is_some() {
            return;
        }
        match Consumer::open(&self.entry.board, SearchDir::new(self.data_dir.clone())) {
            Ok(c) => self.consumer = Some(c),
            Err(h) => self.say(format!("the index could not open: {h}")),
        }
    }

    fn tick(&mut self, position: u64) {
        let announced = self.announced_unreachable;
        self.down = false;
        if announced {
            self.announced_unreachable = false;
            self.bus.emit(EventName::Daemon, json!({"board": self.entry.reference, "state": "running"}));
        }
        // The `/health` read first: where the board did not answer before,
        // its head is where the published feed starts.
        self.read_health();
        self.mount();
        if let Some(c) = &self.consumer {
            match c.poll() {
                Ok(poll) => {
                    for principal in poll.died {
                        self.died(principal);
                    }
                }
                Err(h) => self.say(format!("the poll at {position} failed: {h}")),
            }
        }
        self.read_feed();
        self.emit_index();
        // The `running` emit ends an unreachable hold at this board (§3c.4):
        // the resend runs where the board is back and a session stands.
        if announced {
            self.holds.probe(&self.entry.reference);
        }
    }

    /// The stream could not connect, or dropped: said on TALK once per
    /// outage (the shell's own window), and announced `unreachable` on the
    /// `daemon` event ONCE — for every board the shell dials, each event
    /// naming its board — EXCEPT under the own node's DELIBERATE STOP
    /// (`Holds::node_stopped`, set by `Shell::set_node_state`): a stop the
    /// person made is announced `stopped` once by the shell, this thread adds
    /// no `unreachable` while the stop stands, and `self.announced_unreachable`
    /// stays false, so the next tick says no `running` of its own either —
    /// `set_node_state(Running)` is the one `running`. Where the stop is
    /// lifted while the stream is still down, the next failure here is
    /// announced as built.
    fn unreachable(&mut self, text: &str) {
        if self.announced_unreachable {
            return;
        }
        if !self.down {
            self.down = true;
            self.say(format!("the commit stream is not answering: {text}"));
        }
        if self.holds.node_stopped(&self.entry.reference) {
            return;
        }
        self.announced_unreachable = true;
        self.bus.emit(EventName::Daemon, json!({"board": self.entry.reference, "state": "unreachable"}));
        // Every session at this board is dead where the board restarted;
        // the arm is read when the board answers again.
    }

    /// A principal whose supplement met the death signal on the consumer's
    /// read: the session whose token the supplement was widened under is
    /// ended. Another session of the principal meets its own death on its
    /// own drafts read, never on this one's.
    fn died(&mut self, principal: u64) {
        let Some(session) = self.session_references.get(&principal).and_then(|r| self.sessions.get(r)) else { return };
        self.end(&session);
    }

    /// A death signal met at this board on `session`'s token: the session
    /// ended by the one sequence the shell runs too.
    fn end(&mut self, session: &SessionEntry) {
        let (sessions, bus, store) = (Arc::clone(&self.sessions), Arc::clone(&self.bus), self.reopen_store.clone());
        let entry: &'b BoardEntry = self.entry;
        sessions.end(session, &entry.board, store.as_deref(), self, &bus);
    }

    /// THE `feed` EVENTS: the published feed's new rows as a guest, from
    /// the head the board first answered with — none read before it answers
    /// — then each open session's drafts supplement under its token.
    fn read_feed(&mut self) {
        let entry: &'b BoardEntry = self.entry;
        if let Some(since) = self.published_since {
            if let ReadTo::At(at) = read_to_head(&entry.board, None, since, false, |row| self.emit_feed(row, "published", None)) {
                self.published_since = Some(at);
            }
        }
        for session in self.sessions.on_board(&entry.reference) {
            self.read_drafts(&session);
        }
    }

    /// `session`'s drafts supplement read to the board's head under its
    /// token ([`read_to_head`]), from where its principal's last read
    /// stopped — at first, the position the session opened at — each row a
    /// `feed` event of the `drafts` class; a cursor the board's retention
    /// floor passed, as a long-open session's with no drafts row of its own
    /// is, resumed at the floor. The death signal ends the session
    /// (`Sessions::end`, which answers a session the page already closed
    /// with that arm and does nothing more).
    fn read_drafts(&mut self, session: &SessionEntry) {
        let entry: &'b BoardEntry = self.entry;
        let principal = session.facts.principal;
        let since = *self.drafts_since.entry(principal).or_insert(session.opened_at);
        match read_to_head(&entry.board, Some(&session.token), since, true, |row| self.emit_feed(row, "drafts", Some(&session.reference))) {
            ReadTo::At(at) => {
                self.drafts_since.insert(principal, at);
            }
            ReadTo::Closed => self.end(session),
        }
    }

    fn emit_feed(&self, row: &Value, class: &str, session: Option<&str>) {
        let mut update = row.clone();
        update["position"] = row["at"].clone();
        update["class"] = Value::from(class);
        if let Some(s) = session {
            update["session"] = Value::from(s);
        }
        self.bus.emit(EventName::Feed, json!({"board": self.entry.reference, "update": update}));
    }

    /// THE `/health` READ of a tick: the `mode` event where the pair moved
    /// (the claim's landing, a restart with the flag changed), `writes.halted`
    /// told the hold, and — the first time the board answers — its head as
    /// the published feed's start.
    fn read_health(&mut self) {
        let Ok(health) = self.entry.board.health() else { return };
        self.published_since.get_or_insert(health.log_position());
        // ONE member more read per tick (§3c.4): `writes.halted` tells the hold,
        // a hold `halted` beginning at the first `true`.
        self.holds.note_health(&self.entry.reference, health.body["writes"]["halted"].as_bool().unwrap_or(false));
        let mode = Mode::of(&health);
        if self.last_mode != Some(mode) {
            let first = self.last_mode.is_none();
            self.last_mode = Some(mode);
            if !first {
                self.bus.emit(EventName::Mode, json!({"board": self.entry.reference, "mode": mode.name(), "claimant": health.claimant(), "local_trust": health.local_trust()}));
            }
        }
    }

    /// THE `index` EVENT for the guest face and each mounted principal,
    /// where the state moved.
    fn emit_index(&mut self) {
        let Some(c) = &self.consumer else { return };
        let mut faces: Vec<(Option<u64>, Value)> = vec![(None, state_json(&c.state(Who::Guest)))];
        for session in self.sessions.on_board(&self.entry.reference) {
            let principal = session.facts.principal;
            if c.mounted(principal) {
                let who = Who::Session(SessionRef { token: &session.token, principal, account: session.facts.account.as_deref().unwrap_or("") });
                faces.push((Some(principal), state_json(&c.state(who))));
            }
        }
        for (principal, state) in faces {
            if self.last_index.get(&principal) != Some(&state) {
                let session = principal.and_then(|p| self.session_references.get(&p).cloned());
                self.bus.emit(EventName::Index, json!({"board": self.entry.reference, "session": session, "state": state}));
                self.last_index.insert(principal, state);
            }
        }
    }

    fn search(&mut self, who: Searcher, query: &str, opts: &SearchOpts, reindex: bool) -> Result<Value, Refusal> {
        self.mount();
        let Some(c) = &self.consumer else { return Ok(answer_without_index()) };
        let answer = match &who {
            Searcher::Guest => {
                if reindex {
                    c.reindex(Who::Guest)?;
                }
                c.search(Who::Guest, query, opts)
            }
            Searcher::Session { principal, token, account } => {
                let who = Who::Session(SessionRef { token, principal: *principal, account });
                if reindex {
                    c.reindex(who)?;
                }
                c.search(who, query, opts)
            }
        };
        let answer = answer.map_err(|e| Refusal::shell(Name::QUERY_TOO_LONG, json!({"bound": e.bound, "length": e.length})))?;
        let value = answer_json(&answer);
        self.emit_index();
        Ok(value)
    }

    fn close(&mut self) {
        if let Some(c) = self.consumer.take() {
            if let Err(h) = c.close() {
                self.say(format!("the index could not save at close: {h}"));
            }
        }
    }
}

/// Where one read to the head left its feed.
enum ReadTo {
    /// The position the next read starts at: the head where every page was
    /// read, or where the read stopped on an answer it cannot read past.
    At(u64),
    /// The death signal on the token the read presented.
    Closed,
}

/// ONE FEED READ TO THE BOARD's HEAD — the published feed's (no token) or
/// a session's drafts supplement (its token, `drafts`) — from `since`, each
/// row handed to `emit` in order (wire.md §The change feed, Paging): a page
/// whose `more` stands read on from its `last`; a `history_reclaimed`
/// resumed at the floor it names, where that floor passes the cursor — a
/// reclaimed cursor is no read's to wait out; a page past the page budget
/// re-asked at the limit that `fits`, every later page at the route's
/// default again. Every answer moves the cursor on or shrinks the page
/// (`Board::changes`'s own guarantee), so the read ends. Any other answer —
/// a refusal, no answer — stops it where it stands, for the next tick to
/// read again.
fn read_to_head(board: &Board, token: Option<&Token>, since: u64, drafts: bool, mut emit: impl FnMut(&Value)) -> ReadTo {
    let (mut since, mut limit) = (since, None);
    loop {
        match board.changes(token, &ChangesQuery { since, under: None, drafts, limit }) {
            Ok(ChangesAnswer::Page(page)) => {
                page.changes.iter().for_each(&mut emit);
                since = page.last;
                limit = None;
                if !page.more {
                    return ReadTo::At(since);
                }
            }
            Ok(ChangesAnswer::HistoryReclaimed { floor: Some(floor) }) if floor > since => since = floor,
            Ok(ChangesAnswer::TooLarge { fits }) => limit = Some(fits),
            Ok(ChangesAnswer::Closed) => return ReadTo::Closed,
            Ok(_) | Err(_) => return ReadTo::At(since),
        }
    }
}

/// The supplements on this thread, reached directly: the sequences of
/// `sessions` widen and narrow here when this thread meets a session's end,
/// and the shell's commands land here.
impl Supplements for Worker<'_> {
    fn widen(&mut self, session: &Arc<SessionEntry>) {
        let Some(account) = session.facts.account.as_deref() else { return };
        let principal = session.facts.principal;
        self.session_references.insert(principal, session.reference.clone());
        self.drafts_since.entry(principal).or_insert(session.opened_at);
        // The face is announced afresh under the reference it now stands
        // under — a re-opened session's as much as a new one's.
        self.last_index.remove(&Some(principal));
        self.mount();
        if let Some(c) = &self.consumer {
            if let Err(h) = c.widen(SessionRef { token: &session.token, principal, account }) {
                self.say(format!("the supplement for principal {principal} could not widen: {h}"));
            }
        }
        self.emit_index();
    }

    fn narrow(&mut self, principal: u64) {
        if let Some(c) = &self.consumer {
            if let Err(h) = c.narrow(principal) {
                self.say(format!("the supplement for principal {principal} could not narrow: {h}"));
            }
        }
        self.session_references.remove(&principal);
        self.drafts_since.remove(&principal);
        self.last_index.remove(&Some(principal));
    }
}

/// A range as the state names it: the board's whole feed, or a prefix.
fn range_json(range: &Range) -> Value {
    match range {
        Range::Board => Value::from("board"),
        Range::Under(a) => Value::from(a.to_string()),
    }
}

/// A saved pair.
fn chain_at_json(held: &skep_search::ChainAt) -> Value {
    json!({"position": held.position, "chain": crate::refs::hex(held.chain.as_bytes())})
}

/// THE STATE's ten arms as the bridge spells them (`client.md` §4b.2's
/// `index` event): `arm` the name, the arm's own members beside it.
pub fn state_json(state: &State) -> Value {
    match state {
        State::None => json!({"arm": "none"}),
        State::Building { position, units, lost, aside } => {
            let lost = lost.as_ref().map(|l| match l {
                Lost::Damaged { what } => json!({"kind": "damaged", "what": what}),
                Lost::Diverged { held } => json!({"kind": "diverged", "held": chain_at_json(held)}),
            });
            json!({"arm": "building", "position": position, "units": units, "lost": lost, "aside": aside})
        }
        State::Widening { range } => json!({"arm": "widening", "range": range_json(range)}),
        State::Complete { as_of, floor } => json!({"arm": "complete", "as_of": as_of, "floor": floor}),
        State::AtTheFloor { floor } => json!({"arm": "at_the_floor", "floor": floor}),
        State::ResumedFromTheFloor { floor, held } => json!({"arm": "resumed_from_the_floor", "floor": floor, "held": chain_at_json(held)}),
        State::Unplaced { range, count } => json!({"arm": "unplaced", "range": range_json(range), "count": count}),
        State::PastTheCeiling { held, seen, limit } => json!({"arm": "past_the_ceiling", "held": held, "seen": seen, "limit": limit}),
        State::NewerSkep { v } => {
            let v = match v {
                Newer::Version { v } => json!({"version": v}),
                Newer::Tokenizer { revision } => json!({"tokenizer": revision.to_string()}),
            };
            json!({"arm": "newer_skep", "v": v})
        }
        State::Busy => json!({"arm": "busy"}),
    }
}

/// Edition or draft, as the bridge spells a hit's and a place's `kind`.
fn kind_name(kind: Kind) -> &'static str {
    match kind {
        Kind::Edition => "edition",
        Kind::Draft => "draft",
    }
}

/// A standing as the bridge spells it; a held one names its departed
/// grant's kind and rung (PUB-5.115's KIND × RUNG) in the bridge's words.
fn standing_json(s: &Standing) -> Value {
    match s {
        Standing::Public => Value::from("public"),
        Standing::YoursToRead => Value::from("yours_to_read"),
        Standing::Held { kind, rung, issuer } => {
            let kind = match kind {
                GrantKind::Named => "named",
                GrantKind::AnyPrincipal => "any_principal",
            };
            let rung = match rung {
                Rung::Document => "document",
                Rung::Account => "account",
            };
            json!({"held": {"kind": kind, "rung": rung, "issuer": issuer.to_string()}})
        }
    }
}

/// One mark of a snippet as the bridge spells it: the hit's span, a
/// matched term, or a gap at its width in positions.
fn mark_json(m: &Mark) -> Value {
    let kind = match &m.kind {
        MarkKind::Span => json!({"span": true}),
        MarkKind::Term { term } => json!({"term": term}),
        MarkKind::Gap { width } => json!({"gap": {"width": width}}),
    };
    json!({"offset": m.offset, "len": m.len, "kind": kind})
}

/// A hit as `search.md` §3.1 shapes it, the bridge's `search` row.
fn hit_json(h: &Hit) -> Value {
    let snippet = h.snippet.as_ref().map(|s| json!({"text": s.text, "start": s.start, "marks": s.marks.iter().map(mark_json).collect::<Vec<_>>()}));
    json!({
        "doc": h.doc.to_string(),
        "member": h.member.as_ref().map(|m| m.to_string()),
        "as_of": h.as_of,
        "span": {"start": h.span.start, "width": h.span.width},
        "score": h.score,
        "snippet": snippet,
        "kind": kind_name(h.kind),
        "standing": standing_json(&h.standing),
        "occurrences": h.occurrences,
        "matched": h.matched.iter().map(|m| json!({"word": m.word, "term": m.term})).collect::<Vec<_>>(),
    })
}

/// A place.
fn place_json(p: &Place) -> Value {
    json!({"doc": p.doc.to_string(), "kind": kind_name(p.kind), "label": p.label, "standing": standing_json(&p.standing)})
}

/// THE SEARCH ANSWER as the row shapes it: `{hits, places, state}` with the
/// crate's five facts beside them.
fn answer_json(a: &SearchAnswer) -> Value {
    json!({
        "hits": a.hits.iter().map(hit_json).collect::<Vec<_>>(),
        "places": a.places.iter().map(place_json).collect::<Vec<_>>(),
        "state": state_json(&a.state),
        "total": a.total,
        "truncated": a.truncated,
        "more_terms": a.more_terms,
        "fuzzy_bounded": a.fuzzy_bounded,
        "positions_bounded": a.positions_bounded,
    })
}

/// THE ANSWER WHERE NO INDEX STANDS, in the row's whole shape: no hit, no
/// place, the state `none` — the search of a board whose consumer could
/// not open its index, and the guest form over an origin this shell holds
/// no index for.
pub fn answer_without_index() -> Value {
    answer_json(&SearchAnswer { hits: Vec::new(), total: 0, truncated: false, more_terms: false, fuzzy_bounded: false, positions_bounded: false, places: Vec::new(), state: State::None })
}

#[cfg(test)]
mod tests;
