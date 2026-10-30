//! The feed thread, one per board.
//!
//! As `search.md` §5.6 ("one feed thread per index"), `client.md` §4b.2
//! ("the consumer lives in the shell, which holds the session, and the page
//! reads it through this event") and the dev provider record §3.3 draw it,
//! it runs the library's `search::Consumer` opened over the board's
//! directory beside the key store, polled on each commit the `/events`
//! stream yields, and beside it this crate's own read of the `/changes`
//! pages for the `feed` events — the published feed as a guest, and each
//! open session's drafts supplement under its token — the `/health` pair
//! read per tick for the `mode` event, the stream's state for the `daemon`
//! event (every board the shell dials, each event naming its board; silent
//! under the own node's deliberate stop, which the shell announces
//! `stopped` once — [`Feeder::unreachable`]), and the consumer's state for
//! the `index` event, each emitted where it moved. The thread's state is
//! the feeder ([`Feeder`]), the board index's one writer. The bridge's two
//! calls over the index, `search` and the listing `places`, are answered on
//! this thread too, each over a channel, so the consumer never crosses a
//! thread: two threads per board, the `/events` stream's reader and the
//! feed thread, each borrowing the board from the `Arc` it holds. A death
//! signal this thread's reads meet ends the session by the one sequence the
//! shell runs too (`Sessions::end`). A session the page closes is read once
//! more here, to the board's head under its still-standing token, before
//! its close answers ([`Feed::closing`]): every `feed` row of a session
//! precedes its `session-died`, however far this thread trails the commits.
//! The board's held bursts are watched here too: each tick's `/health` read
//! handed to the hold, which reads its `writes.halted`
//! (`Holds::note_health`), and the probe (`Holds::probe`) on this thread
//! alone — every `PROBE_CADENCE`, measured from the last cadence's or
//! hand-over's probe whatever woke the thread between, at the tick that
//! ends an announced outage, and at a hand-over ([`Feed::probe`],
//! `resolve(send)`'s and `set_node_state(Running)`'s). Both feeds are read
//! to the board's head by one reader ([`read_to_head`]), the published feed
//! and every drafts supplement alike: a page past the retention floor
//! resumed at the floor, a page past the page budget re-asked at the limit
//! that fits. The commits the stream yields are coalesced ([`Ticks`]): one
//! tick waits in the feed thread's queue at most, so a board committing
//! faster than the feed thread reads costs one read to the head per turn,
//! never a read per commit, and a call queued behind them waits one read at
//! most.
//!
//! **The `feed` update's shape**, this crate's definition, the shell's
//! (S-24 (b)): the `/changes` row verbatim — every member the declared
//! `FeedUpdate` (`shapes`) names beside the three below, and any later member
//! by the wire's forward rule — plus `position` (the row's `at`, named once
//! more so a consumer reading the shell's shape need not know the wire's),
//! and `class` — `published` for a row of the guest's feed, `drafts` for one
//! of a principal's supplement, the latter with `session`, the session the
//! event goes to. The event carries `board`, the reference, beside `update`.
//! The published feed starts at the head the board first answers with — at
//! the thread's start, or at its first `/health` after it, never at 0 for a
//! board not yet up.
//!
//! **What is a principal's is said under each of its sessions.** The drafts
//! supplement is one per principal, read under any of its sessions' tokens
//! (`client.md` §4e.3), and a session's index face is its principal's state,
//! composed from the published index's and that principal's supplement's
//! (§4b.2's `index`); a page knows its own events by the session they name.
//! So each drafts row goes out once per session of its principal at the
//! board — under the session whose token read it first, then under each
//! other — every event naming its own session ([`Feeder::emit_drafts`]), and
//! each face's state goes out once per session whose principal's supplement
//! is mounted ([`Feeder::emit_index`]): every tab of a principal hears its
//! drafts and its face. A principal's drafts rows are each read once — one
//! cursor per principal, whichever of its sessions reads — from where its
//! last read stopped: at first, the position its first session opened at,
//! then on through another tab's open, a release to another of its sessions
//! and the restart's re-open; the cursor is dropped at the narrow, once none
//! of its sessions stands. A page re-reads what it shows on open and takes
//! the updates from there, a row its open re-read perhaps among them.
//!
//! **The catch-up** ([`changes_since`], the `changes` call): what a client
//! that comes back to a board missed — the same feed, read once from a
//! position the client names rather than streamed from the head, on the
//! caller's thread and not this one, each entry in the update's shape above
//! with its class, bounded by the call's `limit` and the wire's page budget,
//! and answered with the position to ask from next and the board's head.

use std::collections::btree_map::Entry;
use std::collections::{BTreeMap, HashMap};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{channel, Receiver, RecvTimeoutError, Sender};
use std::sync::Arc;
use std::thread;
use std::time::Instant;

use serde_json::{json, Value};
use skep_address::Address;
use skep_client::board::{ChangesAnswer, ChangesPage, ChangesQuery};
use skep_client::derive::Mode;
use skep_client::halt::Halt;
use skep_client::search::{events, Consumer, Lost, Newer, Place, PlacesAnswer, QueryTooLong, Range, SearchAnswer, SearchDir, SearchOpts, State, Stop, Who};
use skep_client::Board;
use skep_search::{GrantKind, Hit, Kind, Mark, MarkKind, Rung, Standing};

use crate::events::{EventBus, EventName};
use crate::hold::{Holds, PROBE_CADENCE};
use crate::refs::BoardEntry;
use crate::refusal::{Name, Refusal};
use crate::sessions::{SessionEntry, Sessions, Supplements};
use crate::Talk;

/// Who reads a board's index, as it crosses to the feed thread.
///
/// It is the guest, or a session the table holds, whole — for a search or
/// the listing alike.
#[derive(Debug, Clone)]
pub enum Searcher {
    Guest,
    Session(Arc<SessionEntry>),
}

impl Searcher {
    /// Returns who searches, as the consumer takes it.
    ///
    /// It is the guest, or the session's search view
    /// ([`SessionEntry::search_view`]).
    fn as_who(&self) -> Who<'_> {
        match self {
            Searcher::Guest => Who::Guest,
            Searcher::Session(session) => Who::Session(session.search_view()),
        }
    }
}

/// A `search` call's `opts`, as the bridge declares them.
///
/// They are `shapes`' `SearchOpts`: the library's bounds on the list, and
/// whether the index pair is refreshed before it answers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct BridgeSearchOpts {
    pub bounds: SearchOpts,
    pub reindex: bool,
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
    /// A session the page is closing, its token still standing.
    ///
    /// Its drafts rows are read to the head under its token, each said under
    /// it and under every other session of its principal, then its
    /// supplement released; answered.
    Closing(Arc<SessionEntry>, Sender<()>),
    /// The probe handed over: run at the feed thread's next turn, unanswered.
    Probe,
    /// The bridge's search call.
    Search { who: Searcher, query: String, opts: BridgeSearchOpts, reply: Sender<Result<Value, Refusal>> },
    /// The bridge's listing call, its prefix where one is named.
    Places { who: Searcher, under: Option<Address>, reply: Sender<Value> },
    /// The consumer closed; the thread ends.
    Stop(Sender<()>),
}

/// What every board's feed thread shares with the shell.
///
/// It holds the bus its events go out on, the session table, the data
/// directory the index sits under, the `Talk` sink, and the held-burst
/// holds the feed thread drives — each tick's `/health` read handed over,
/// and the probe every `PROBE_CADENCE`.
#[derive(Clone)]
pub struct Shared {
    pub bus: Arc<EventBus>,
    pub sessions: Arc<Sessions>,
    pub data_dir: PathBuf,
    pub talk: Talk,
    pub holds: Arc<Holds>,
}

/// The handle to one board's feed thread.
///
/// Each command is sent on the thread's own channel and answered there, so
/// a caller waiting on one board's feed thread holds nothing another caller
/// needs. A handle is cloned freely; once the thread has stopped, every
/// command answers at once.
#[derive(Debug, Clone)]
pub struct Feed {
    cmds: Sender<Cmd>,
}

impl Feed {
    /// Reads a closing session's drafts rows, then releases its supplement.
    ///
    /// The session is out of the table, its token still standing at the
    /// board: its drafts rows are read to the head under that token, each a
    /// `feed` event under it and under every other session of its principal
    /// at the board, then its supplement released (`Sessions::release`),
    /// answered once both are done, so every `feed` row of the session
    /// precedes the `session-died` its close emits next. A thread that has
    /// stopped answers at once.
    pub fn closing(&self, session: &Arc<SessionEntry>) {
        let (reply, rx) = channel();
        if self.cmds.send(Cmd::Closing(Arc::clone(session), reply)).is_ok() {
            let _ = rx.recv();
        }
    }

    /// Hands the probe to the board's feed thread (`Holds::probe`).
    ///
    /// It runs there at its next turn and the probe's cadence is counted
    /// from it — the caller does not wait: `resolve(send)`'s hand-over, so
    /// the call answers once the lines are handed back, never after a
    /// resend's ack (§4b.1), and `set_node_state(Running)`'s, so the verb
    /// that owns the node is held by no resend. A thread that has stopped
    /// takes nothing.
    pub fn probe(&self) {
        let _ = self.cmds.send(Cmd::Probe);
    }

    /// Answers the bridge's search call on the feed thread.
    ///
    /// # Errors
    ///
    /// Returns `feed_stopped` once the thread has stopped, and the search's
    /// own refusals ([`Feeder::search`]).
    pub fn search(&self, who: Searcher, query: &str, opts: BridgeSearchOpts) -> Result<Value, Refusal> {
        let (reply, rx) = channel();
        if self.cmds.send(Cmd::Search { who, query: query.to_string(), opts, reply }).is_err() {
            return Err(Refusal::shell(Name::FEED_STOPPED, json!({})));
        }
        rx.recv().unwrap_or_else(|_| Err(Refusal::shell(Name::FEED_STOPPED, json!({}))))
    }

    /// Returns the bridge's listing of the document index (A-255).
    ///
    /// It is answered on the feed thread, under `under` where given.
    ///
    /// # Errors
    ///
    /// `feed_stopped` once the thread has stopped.
    pub fn places(&self, who: Searcher, under: Option<Address>) -> Result<Value, Refusal> {
        let (reply, rx) = channel();
        if self.cmds.send(Cmd::Places { who, under, reply }).is_err() {
            return Err(Refusal::shell(Name::FEED_STOPPED, json!({})));
        }
        rx.recv().map_err(|_| Refusal::shell(Name::FEED_STOPPED, json!({})))
    }
}

/// The supplements as the shell reaches them, through a board's handle.
///
/// Each widen and narrow is a command the board's feed thread runs — a
/// shared handle, as `&File` is a `Write`.
impl Supplements for &Feed {
    fn widen(&mut self, session: &Arc<SessionEntry>) {
        let _ = self.cmds.send(Cmd::Widen(Arc::clone(session)));
    }

    fn narrow(&mut self, principal: u64) {
        let _ = self.cmds.send(Cmd::Narrow(principal));
    }
}

/// The commits not yet read.
///
/// It holds the latest position the `/events` stream yielded, and whether a
/// [`Cmd::Tick`] waits in the feed thread's queue for them. The reader sends
/// a tick only where none waits, and the feed thread clears the mark as it
/// takes one — before it reads — so a board committing faster than the feed
/// thread reads leaves one tick queued, never one per commit, and a commit
/// landing mid-read queues exactly the one more read that sees it.
#[derive(Debug, Default)]
struct Ticks {
    waiting: AtomicBool,
    latest: AtomicU64,
}

impl Ticks {
    /// Notes a commit at `position`: whether a tick is owed, none waiting.
    fn note(&self, position: u64) -> bool {
        self.latest.fetch_max(position, Ordering::SeqCst);
        !self.waiting.swap(true, Ordering::SeqCst)
    }

    /// Takes the waiting tick: the mark cleared, then the latest position read.
    ///
    /// That position is the one the read about to run reaches at least.
    fn take(&self) -> u64 {
        self.waiting.store(false, Ordering::SeqCst);
        self.latest.load(Ordering::SeqCst)
    }
}

/// One board's two threads: the `/events` stream's reader and the feed thread.
///
/// The reader is asked to stop at [`FeedThreads::stop`] and ends at its
/// next read, and the feed thread is joined there, so its `Arc`s, the
/// held-burst holds among them, which hold the `held/<chain>/` lock, are
/// dropped before the stop returns; a relaunch in the same process then
/// takes the lock the first shell held.
pub struct FeedThreads {
    feed: Feed,
    stream_stop: Stop,
    feed_thread: thread::JoinHandle<()>,
}

impl std::fmt::Debug for FeedThreads {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("FeedThreads")
    }
}

impl FeedThreads {
    /// Spawns the two threads for `entry`, the consumer over `data_dir/index/`.
    ///
    /// # Panics
    ///
    /// Panics where the stream's reader ends before it sends its stopper.
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
        let feed_thread = thread::spawn(move || Feeder::run(entry, shared, rx, &ticks));
        FeedThreads { feed: Feed { cmds: tx }, stream_stop, feed_thread }
    }

    /// Returns a handle to the board's feed thread.
    pub fn feed(&self) -> Feed {
        self.feed.clone()
    }

    /// Stops the two threads: the save at the shell's exit.
    ///
    /// The stream's reader is asked to stop — it ends at its next read — and
    /// the consumer closed. The feed thread is joined last, so every `Arc` it
    /// held (the holds, and with them the `held/<chain>/` lock) is dropped
    /// before this returns.
    pub fn stop(self) {
        self.stream_stop.stop();
        let (reply, rx) = channel();
        if self.feed.cmds.send(Cmd::Stop(reply)).is_ok() {
            let _ = rx.recv();
        }
        let _ = self.feed_thread.join();
    }
}

/// The feeder: the feed thread's own state.
///
/// It is the board index's one writer (`search.md` §5.6), holding the lock
/// on the board's directory for the life of its consumer — "the feeder's
/// lock" of `client.md` §4b.2's `busy`.
struct Feeder<'b> {
    entry: &'b BoardEntry,
    bus: Arc<EventBus>,
    sessions: Arc<Sessions>,
    data_dir: PathBuf,
    talk: Talk,
    /// The held-burst holds this feeder drives.
    holds: Arc<Holds>,
    consumer: Option<Consumer<'b>>,
    /// Where the published feed's next read starts.
    ///
    /// It is the head the board first answered with, then each page's last —
    /// none until the board answers.
    published_since: Option<u64>,
    /// Where each principal's drafts read starts.
    ///
    /// It is one cursor per principal, whichever of its sessions reads: the
    /// position its first session opened at, then each page's last — kept
    /// through a release to another of its sessions and through the
    /// restart's re-open (`widen`), dropped at the narrow.
    drafts_since: HashMap<u64, u64>,
    last_mode: Option<Mode>,
    /// The `index` state last sent each face.
    ///
    /// The guest's stands under `None` and each session's under its
    /// reference, so an event goes out only where the state that face was
    /// last sent moved; a face whose session no longer stands at the board
    /// is dropped.
    last_index_state: BTreeMap<Option<String>, Value>,
    /// The session whose token each mounted principal's supplement holds.
    ///
    /// It is the session widened last, the one ended where the consumer's
    /// read meets the death signal ([`Feeder::died`]).
    session_references: HashMap<u64, String>,
    /// The `/events` stream's outage as this thread has said it.
    ///
    /// It is said by [`Feeder::unreachable`] and ended by the next tick.
    outage: Outage,
}

/// The `/events` stream's outage as a feed thread has said it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Outage {
    /// The stream has not failed since the last tick.
    Up,
    /// Down and said on `Talk` once.
    ///
    /// It is the state under the own node's deliberate stop, which the shell
    /// announces, so announced on no event of this thread's.
    Said,
    /// Down, said, and announced `unreachable` on the `daemon` event.
    ///
    /// The next tick owes `running`.
    Announced,
}

impl<'b> Feeder<'b> {
    /// Returns a feeder over `entry`, as the feed thread starts it.
    ///
    /// No consumer is open, no feed read, no outage said.
    fn new(entry: &'b BoardEntry, shared: Shared) -> Feeder<'b> {
        let Shared { bus, sessions, data_dir, talk, holds } = shared;
        Feeder {
            entry,
            bus,
            sessions,
            data_dir,
            talk,
            holds,
            consumer: None,
            published_since: None,
            drafts_since: HashMap::new(),
            last_mode: None,
            last_index_state: BTreeMap::new(),
            session_references: HashMap::new(),
            outage: Outage::Up,
        }
    }

    fn run(entry: Arc<BoardEntry>, shared: Shared, rx: Receiver<Cmd>, ticks: &Ticks) {
        let mut feeder = Feeder::new(&entry, shared);
        // One `/health` read at the thread's start: the published feed's
        // start where the board answers, the mode, and `writes.halted`.
        feeder.read_health();
        feeder.open_consumer();
        feeder.emit_index();
        // The probe (§3c.4) has a deadline of its own: the loop wakes on each
        // command and at the deadline, and probes once the deadline has
        // passed, whatever woke it — a poisoned, halted, stopped
        // or unreachable board commits nothing, so `Cmd::Tick` alone never
        // ends such a hold, and a board that keeps committing must not starve
        // the probe either.
        let mut next_probe = Instant::now() + PROBE_CADENCE;
        loop {
            match rx.recv_timeout(next_probe.saturating_duration_since(Instant::now())) {
                Ok(Cmd::Tick) => feeder.tick(ticks.take()),
                Ok(Cmd::Unreachable(text)) => feeder.unreachable(&text),
                Ok(Cmd::Widen(session)) => feeder.widen(&session),
                Ok(Cmd::Narrow(principal)) => feeder.narrow(principal),
                Ok(Cmd::Closing(session, reply)) => {
                    feeder.read_drafts(&session);
                    let sessions = Arc::clone(&feeder.sessions);
                    sessions.release(&session.board_reference, session.facts.principal, &mut feeder);
                    let _ = reply.send(());
                }
                Ok(Cmd::Probe) => {
                    feeder.holds.probe(&feeder.entry.reference);
                    next_probe = Instant::now() + PROBE_CADENCE;
                }
                Ok(Cmd::Search { who, query, opts, reply }) => {
                    let _ = reply.send(feeder.search(who.as_who(), &query, opts));
                }
                Ok(Cmd::Places { who, under, reply }) => {
                    let _ = reply.send(feeder.places(who.as_who(), under.as_ref()));
                }
                Ok(Cmd::Stop(reply)) => {
                    feeder.close_consumer();
                    let _ = reply.send(());
                    return;
                }
                Err(RecvTimeoutError::Timeout) => {}
                Err(RecvTimeoutError::Disconnected) => break,
            }
            if Instant::now() >= next_probe {
                feeder.holds.probe(&feeder.entry.reference);
                next_probe = Instant::now() + PROBE_CADENCE;
            }
        }
        feeder.close_consumer();
    }

    fn say(&self, line: impl std::fmt::Display) {
        (self.talk)(&format!("feed {}: {line}", self.entry.reference));
    }

    /// Opens the consumer, where it is not open yet.
    ///
    /// A failed open is said and tried again at the next tick.
    fn open_consumer(&mut self) {
        if self.consumer.is_some() {
            return;
        }
        match Consumer::open(&self.entry.board, SearchDir::new(self.data_dir.clone())) {
            Ok(c) => self.consumer = Some(c),
            Err(h) => self.say(format_args!("the index could not open: {h}")),
        }
    }

    fn tick(&mut self, position: u64) {
        let announced = self.outage == Outage::Announced;
        self.outage = Outage::Up;
        if announced {
            self.bus.emit(EventName::Daemon, json!({"board": self.entry.reference, "state": "running"}));
        }
        // The `/health` read first: where the board did not answer before,
        // its head is where the published feed starts.
        self.read_health();
        self.open_consumer();
        if let Some(c) = &self.consumer {
            match c.poll() {
                Ok(poll) => {
                    for principal in poll.died {
                        self.died(principal);
                    }
                }
                Err(h) => self.say(format_args!("the poll at {position} failed: {h}")),
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

    /// Takes the stream's failure: it could not connect, or dropped.
    ///
    /// It is said on `Talk` once per outage (the shell's own window), and
    /// announced `unreachable` on the `daemon` event once — for every board
    /// the shell dials, each event naming its board — except under the own
    /// node's deliberate stop (`Holds::node_stopped`, set by
    /// `Shell::set_node_state`): a stop the person made is announced
    /// `stopped` once by the shell, this thread adds no `unreachable` while
    /// the stop stands, and the outage stays `Said`, so the next tick says no
    /// `running` of its own either — `set_node_state(Running)` is the one
    /// `running`. Where the stop is lifted while the stream is still down,
    /// the next failure here is announced as built.
    fn unreachable(&mut self, text: &str) {
        match self.outage {
            Outage::Announced => return,
            Outage::Up => {
                self.outage = Outage::Said;
                self.say(format_args!("the commit stream is not answering: {text}"));
            }
            Outage::Said => {}
        }
        if self.holds.node_stopped(&self.entry.reference) {
            return;
        }
        self.outage = Outage::Announced;
        self.bus.emit(EventName::Daemon, json!({"board": self.entry.reference, "state": "unreachable"}));
        // Every session at this board is dead where the board restarted;
        // the arm is read when the board answers again.
    }

    /// Ends the session of a principal whose supplement met the death signal.
    ///
    /// The signal was met on the consumer's read: the session whose token the
    /// supplement was widened under is ended. Another session of the
    /// principal meets its own death on its own drafts read, never on this
    /// one's.
    fn died(&mut self, principal: u64) {
        let Some(session) = self.session_references.get(&principal).and_then(|r| self.sessions.get(r)) else { return };
        self.end(&session);
    }

    /// Ends `session` at a death signal met at this board on its token.
    ///
    /// It runs the one sequence the shell runs too.
    fn end(&mut self, session: &SessionEntry) {
        let (sessions, bus) = (Arc::clone(&self.sessions), Arc::clone(&self.bus));
        sessions.end(session, self, &bus);
    }

    /// Reads the feeds for the `feed` events.
    ///
    /// The published feed's new rows are read as a guest, from the head the
    /// board first answered with — none read before it answers — then each
    /// open session's drafts supplement under its token.
    fn read_feed(&mut self) {
        let entry: &'b BoardEntry = self.entry;
        if let Some(since) = self.published_since {
            if let ReadTo::At(at) = read_to_head(&entry.board, UpdateClass::Published, since, |row| self.emit_feed(row, UpdateClass::Published)) {
                self.published_since = Some(at);
            }
        }
        for session in self.sessions.on_board(&entry.reference) {
            self.read_drafts(&session);
        }
    }

    /// Reads `session`'s drafts supplement to the head, under its token.
    ///
    /// The read goes to the head of the board it stands at ([`read_to_head`]),
    /// from where its principal's last read stopped — at first, the position
    /// its first session opened at — each row a `feed` event of the `drafts`
    /// class under every session of the principal ([`Feeder::emit_drafts`]); a
    /// cursor the board's retention floor passed, as a long-open session's
    /// with no drafts row of its own is, resumed at the floor. The death
    /// signal ends the session (`Sessions::end`, which answers a session the
    /// page already closed with that arm and does nothing more), the cursor
    /// first set where the read's finished pages reached (`client.md` §4e.3):
    /// a session of the principal that reads on — another tab, or the
    /// restart's re-open — sends none of their rows again, and the narrow the
    /// end makes where no session of the principal stands still drops it.
    fn read_drafts(&mut self, session: &SessionEntry) {
        let principal = session.facts.principal;
        let since = *self.drafts_since.entry(principal).or_insert(session.opened_at);
        match read_to_head(&session.board, UpdateClass::Drafts(session), since, |row| self.emit_drafts(row, session)) {
            ReadTo::At(at) => {
                self.drafts_since.insert(principal, at);
            }
            ReadTo::Died { at } => {
                // The cursor is set before the end: the narrow the end makes
                // where no session of the principal stands then drops it, and
                // a session that reads on starts past the rows already sent.
                self.drafts_since.insert(principal, at);
                self.end(session);
            }
        }
    }

    /// Emits one drafts row under every session of its principal at the board.
    ///
    /// The row goes out first under `read_under`, the session whose token read
    /// it — out of the table already where it is closing — then once under
    /// each other session of the same principal at the board, every event
    /// naming its own session (the module doc). The table is read as each row
    /// goes out, so a session that registers while a long read runs hears
    /// every row said after it stands.
    fn emit_drafts(&self, row: &Value, read_under: &SessionEntry) {
        self.emit_feed(row, UpdateClass::Drafts(read_under));
        let principal = read_under.facts.principal;
        for other in self.sessions.on_board(&self.entry.reference) {
            if other.facts.principal == principal && other.reference != read_under.reference {
                self.emit_feed(row, UpdateClass::Drafts(&other));
            }
        }
    }

    /// Emits one row as a `feed` event.
    ///
    /// The row is in the update's shape ([`update_of`]) under the event's
    /// `board`.
    fn emit_feed(&self, row: &Value, class: UpdateClass<'_>) {
        self.bus.emit(EventName::Feed, json!({"board": self.entry.reference, "update": update_of(row, class)}));
    }

    /// Reads `/health` at the thread's start and at each tick.
    ///
    /// It emits the `mode` event where the pair moved (the claim's landing, a
    /// restart with the flag changed), hands the read to the hold for its
    /// `writes.halted`, and — the first time the board answers — takes its
    /// head as the published feed's start, which no other read sets.
    fn read_health(&mut self) {
        let Ok(health) = self.entry.board.health() else { return };
        self.published_since.get_or_insert(health.log_position());
        // The hold reads its `writes.halted` off the same read (§3c.4), a hold
        // `halted` beginning at the first `true`.
        self.holds.note_health(&self.entry.reference, &health);
        let mode = Mode::of(&health);
        if self.last_mode != Some(mode) {
            let first = self.last_mode.is_none();
            self.last_mode = Some(mode);
            if !first {
                self.bus.emit(EventName::Mode, json!({"board": self.entry.reference, "mode": mode.name(), "claimant": health.claimant(), "local_trust": health.local_trust()}));
            }
        }
    }

    /// Emits the `index` event for the guest face and each session's face.
    ///
    /// A session's face is its principal's state (the module doc), composed
    /// once per principal and sent under every session at the board whose
    /// principal's supplement is mounted, each event naming its own session
    /// (§4b.2's `index`: "the session reference it is about"). Each goes out
    /// where the state that face was last sent moved, and a face whose
    /// session no longer stands is dropped.
    fn emit_index(&mut self) {
        let Some(c) = &self.consumer else { return };
        let mut faces: Vec<(Option<String>, Value)> = vec![(None, state_json(&c.state(Who::Guest)))];
        let mut composed: HashMap<u64, Value> = HashMap::new();
        for session in self.sessions.on_board(&self.entry.reference) {
            let principal = session.facts.principal;
            if c.mounted(principal) {
                let state = composed.entry(principal).or_insert_with(|| state_json(&c.state(Who::Session(session.search_view()))));
                faces.push((Some(session.reference.clone()), state.clone()));
            }
        }
        self.last_index_state.retain(|face, _| faces.iter().any(|(standing, _)| standing == face));
        for (face, state) in faces {
            if self.last_index_state.get(&face) != Some(&state) {
                self.bus.emit(EventName::Index, json!({"board": self.entry.reference, "session": face, "state": state}));
                self.last_index_state.insert(face, state);
            }
        }
    }

    /// Searches the board's index pair as `who` reads it.
    ///
    /// The pair is refreshed first where `opts` asks; where no index stands
    /// open the answer is the one where no index stands: the call dials
    /// nothing to open one (§4b.1's `search` row: "pure local"), `tick` and
    /// `widen` opening the index. The query's bound is the shell's, asked
    /// before the call reaches this thread (`Shell::search`); the library's
    /// own check stands behind it.
    ///
    /// # Errors
    ///
    /// Returns the halt a refresh meets, as the refusal it is, and
    /// `query_too_long` where the query passes the library's bound.
    fn search(&mut self, who: Who<'_>, query: &str, opts: BridgeSearchOpts) -> Result<Value, Refusal> {
        let Some(c) = &self.consumer else { return Ok(answer_without_index()) };
        if opts.reindex {
            c.reindex(who)?;
        }
        let answer = c.search(who, query, &opts.bounds).map_err(query_too_long)?;
        let value = answer_json(&answer);
        self.emit_index();
        Ok(value)
    }

    /// Returns the board's document index listed as `who` reads it (A-255).
    ///
    /// Where no index stands open it is `places_without_index`'s answer: the
    /// call dials nothing to open one (§4b.1's "pure local", as `search`'s),
    /// `tick` and `widen` opening the index.
    fn places(&self, who: Who<'_>, under: Option<&Address>) -> Value {
        let Some(c) = &self.consumer else { return places_without_index() };
        places_answer_json(&c.places(who, under))
    }

    /// Closes and saves the consumer, at the stop; a failed save is said.
    fn close_consumer(&mut self) {
        if let Some(c) = self.consumer.take() {
            if let Err(h) = c.close() {
                self.say(format_args!("the index could not save at close: {h}"));
            }
        }
    }
}

/// Where one read to the head left its feed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReadTo {
    /// The position the next read starts at.
    ///
    /// It is the head where every page was read, or where the read stopped
    /// on an answer it cannot read past.
    At(u64),
    /// The death signal on the token the read presented.
    Died {
        /// The position the read had reached when the signal answered.
        ///
        /// It is past every page the read finished — the read's start where
        /// the signal answered its first ask.
        at: u64,
    },
}

/// A `feed` update's class (the module doc).
///
/// It is a row of the guest's feed, `published`, read token-free; or a row
/// of a principal's drafts supplement, `drafts`, under one of its sessions:
/// the session whose token a read presents, or the one an update names.
#[derive(Debug, Clone, Copy)]
enum UpdateClass<'s> {
    Published,
    Drafts(&'s SessionEntry),
}

impl UpdateClass<'_> {
    /// Returns the class as the update spells it.
    fn as_str(self) -> &'static str {
        match self {
            UpdateClass::Published => "published",
            UpdateClass::Drafts(_) => "drafts",
        }
    }
}

/// Returns one `/changes` row in the update's shape (the module doc).
///
/// It is the row verbatim, plus `position` (its `at`), `class` — `class`'s
/// word — and, a drafts row's, the `session` the class names: what a `feed`
/// event carries as `update` and a `changes` entry is.
fn update_of(row: &Value, class: UpdateClass<'_>) -> Value {
    let mut update = row.clone();
    update["position"] = row["at"].clone();
    update["class"] = Value::from(class.as_str());
    if let UpdateClass::Drafts(session) = class {
        update["session"] = Value::from(session.reference.as_str());
    }
    update
}

/// What `changes(session, since, limit?)` answers: a page or the death signal.
///
/// The death signal is met on the session's token, whose end is the
/// caller's to run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChangesRead {
    /// The page.
    Page(CaughtUp),
    /// The death signal on the session's token.
    Died,
}

/// One page of catching up, as the `changes` call answers it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CaughtUp {
    /// The entries, oldest first, in the update's shape with their `class`.
    pub entries: Vec<Value>,
    /// The position to ask from next.
    ///
    /// It is past every entry answered, never past one withheld.
    pub next: u64,
    /// The board's latest position, read before the page.
    pub head: u64,
}

/// Reads what changed since `since` at `session`'s class: a `changes` page.
///
/// It is the `changes` call's page (`CaughtUp`), the entries bounded by
/// `limit`. Two reads, merged by position: the published feed as a guest,
/// token-free, and the session's drafts supplement under its token, the
/// `drafts=true` page — so each entry carries the `class` the `feed` event
/// gives a row, `published` or `drafts`, which one plain read under the
/// token could not tell apart; a position both reads answer (a straddle,
/// PUB-6.47: a guest's `[T]` beside the supplement's `[D, T]`) is answered
/// once, by the rendering naming more documents, the token's where they
/// name as many (wire.md §The change feed, Narrowings: "deduplicating by
/// position with the wider rendering winning"). The board's head is read
/// first (`/health`, as the feed thread takes it); each read is one page
/// from `since`, re-asked at the limit that `fits` where it passes the page
/// budget; and the merged page is cut at the lower `last` of a read whose
/// `more` stands, then to `limit` entries, so no position is skipped —
/// `next` is that cut, or the last entry kept, or, both reads read to the
/// head, the greater of their `last`s and the head read first, which a
/// quiet board's next ask meets with the empty page at once (`since ≥
/// head`). A draft the session may not read never appears: the gating is
/// the board's, at the token's class.
///
/// # Errors
///
/// `history_reclaimed`, the board's own 410 with its floor, where `since`
/// lies below the feed's memory; the board's other refusals
/// (`malformed_changes` for a `limit` off the route's range,
/// `feed_rebuilding`) and the unreachable board, as every read carries
/// them; and a `/changes` answer the shell does not read, as a halt.
pub fn changes_since(session: &SessionEntry, since: u64, limit: Option<u64>) -> Result<ChangesRead, Refusal> {
    let board: &Board = &session.board;
    let head = board.health()?.log_position();
    let published = match page_from(board, UpdateClass::Published, since, limit)? {
        PageRead::Page(page) => page,
        PageRead::Died => return Ok(ChangesRead::Died),
    };
    let drafts = match page_from(board, UpdateClass::Drafts(session), since, limit)? {
        PageRead::Page(page) => page,
        PageRead::Died => return Ok(ChangesRead::Died),
    };
    // Merged by position, the wider rendering winning — the token's on a
    // tie, read second.
    let docs_named = |update: &Value| update["docs"].as_array().map_or(0, Vec::len);
    let mut by_position: BTreeMap<u64, Value> = BTreeMap::new();
    for (page, class) in [(&published, UpdateClass::Published), (&drafts, UpdateClass::Drafts(session))] {
        for row in &page.changes {
            // A row with no `at` is no row of the wire's: nothing places it.
            let Some(at) = row["at"].as_u64() else { continue };
            let update = update_of(row, class);
            match by_position.entry(at) {
                Entry::Vacant(v) => {
                    v.insert(update);
                }
                Entry::Occupied(mut o) => {
                    if docs_named(&update) >= docs_named(o.get()) {
                        o.insert(update);
                    }
                }
            }
        }
    }
    // The cut: where a read's `more` stands, nothing past its `last` is
    // answered, since the other read may hold a position between.
    let covered = |page: &ChangesPage| if page.more { page.last } else { u64::MAX };
    let cut = covered(&published).min(covered(&drafts));
    let mut entries: Vec<Value> = by_position.into_iter().filter(|(at, _)| *at <= cut).map(|(_, update)| update).collect();
    let cap = limit.map_or(usize::MAX, |n| usize::try_from(n).unwrap_or(usize::MAX));
    let next = if entries.len() > cap {
        entries.truncate(cap);
        entries.last().and_then(|update| update["at"].as_u64()).unwrap_or(since)
    } else if cut < u64::MAX {
        cut
    } else {
        published.last.max(drafts.last).max(head)
    };
    Ok(ChangesRead::Page(CaughtUp { entries, next, head }))
}

/// One page read for the catch-up: the page, or the death signal.
enum PageRead {
    Page(ChangesPage),
    Died,
}

/// Reads one page of `class`'s feed from `since` for the catch-up.
///
/// It is the published feed token-free, or the session's drafts supplement
/// under its token; a page past the page budget is re-asked at the limit
/// that `fits` (wire.md §The change feed, Paging), and every answer but a
/// page is the caller's to face: the retention floor as the board's own
/// refusal, the death signal as [`PageRead::Died`].
///
/// # Errors
///
/// `history_reclaimed` with its floor; the board's refusals and the
/// unreachable board; an answer the shell does not read, as a halt.
fn page_from(board: &Board, class: UpdateClass<'_>, since: u64, limit: Option<u64>) -> Result<PageRead, Refusal> {
    let (token, drafts) = match class {
        UpdateClass::Published => (None, false),
        UpdateClass::Drafts(session) => (Some(&session.token), true),
    };
    let mut limit = limit;
    loop {
        match board.changes(token, &ChangesQuery { since, under: None, drafts, limit })? {
            ChangesAnswer::Page(page) => return Ok(PageRead::Page(page)),
            ChangesAnswer::TooLarge { fits } => limit = Some(fits),
            ChangesAnswer::HistoryReclaimed { floor } => return Err(history_reclaimed(floor)),
            ChangesAnswer::Closed => return Ok(PageRead::Died),
            other => {
                let state = format!("the board answered `/changes` with {other:?}, which is no answer the shell reads");
                return Err(Refusal::from(Halt::face(state, "`skep-client` read a `/changes` answer this shell does not carry", "report it: the shell's `changes` row is behind the library")));
            }
        }
    }
}

/// Returns the retention floor as the board's verdict.
///
/// It is its `410 history_reclaimed` error document, `floor` riding it where
/// known (wire.md §The change feed, Retention), rebuilt from the answer
/// `skep-client` read it into.
fn history_reclaimed(floor: Option<u64>) -> Refusal {
    let mut body = json!({"error": "history_reclaimed"});
    if let Some(floor) = floor {
        body["floor"] = Value::from(floor);
    }
    Refusal::board(410, body)
}

/// Reads `class`'s feed from `since` to the board's head, in one read.
///
/// The feed is the published feed's, token-free, or a session's drafts
/// supplement under its token, at the board that token is valid at; each
/// row is handed to `emit` in order (wire.md §The change feed, Paging): a
/// page whose `more` stands read on from its `last`; a `history_reclaimed`
/// resumed at the floor it names, where that floor passes the cursor — a
/// reclaimed cursor is no read's to wait out; a page past the page budget
/// re-asked at the limit that `fits`, every later page at the route's
/// default again. Every answer moves the cursor on or shrinks the page
/// (`Board::changes`'s own guarantee), so the read ends. Any other answer —
/// a refusal, no answer — stops it where it stands, for the next tick to
/// read again. The death signal on a session's token stops it too, answered
/// with the position its finished pages reached ([`ReadTo::Died`]); a
/// published read, token-free, never meets it (`Board::changes` halts
/// there).
fn read_to_head(board: &Board, class: UpdateClass<'_>, since: u64, mut emit: impl FnMut(&Value)) -> ReadTo {
    let (token, drafts) = match class {
        UpdateClass::Published => (None, false),
        UpdateClass::Drafts(session) => (Some(&session.token), true),
    };
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
            Ok(ChangesAnswer::Closed) => return ReadTo::Died { at: since },
            Ok(_) | Err(_) => return ReadTo::At(since),
        }
    }
}

/// The supplements on this thread, reached directly.
///
/// The sequences of `sessions` widen and narrow here when this thread meets
/// a session's end, and the shell's commands land here.
impl Supplements for Feeder<'_> {
    fn widen(&mut self, session: &Arc<SessionEntry>) {
        // A session the board answered no account for mounts no supplement.
        if session.facts.account.is_none() {
            return;
        }
        let principal = session.facts.principal;
        self.session_references.insert(principal, session.reference.clone());
        self.drafts_since.entry(principal).or_insert(session.opened_at);
        self.open_consumer();
        if let Some(c) = &self.consumer {
            if let Err(h) = c.widen(session.search_view()) {
                self.say(format_args!("the supplement for principal {principal} could not widen: {h}"));
            }
        }
        // A session new to the board — a tab's, a re-opened one's — is sent
        // its face here; one handed the supplement at a release was sent it
        // already, and hears it again only where the state moved.
        self.emit_index();
    }

    fn narrow(&mut self, principal: u64) {
        if let Some(c) = &self.consumer {
            if let Err(h) = c.narrow(principal) {
                self.say(format_args!("the supplement for principal {principal} could not narrow: {h}"));
            }
        }
        self.session_references.remove(&principal);
        self.drafts_since.remove(&principal);
    }
}

/// Returns a range as the state names it: the board's whole feed, or a prefix.
fn range_json(range: &Range) -> Value {
    match range {
        Range::Board => Value::from("board"),
        Range::Under(a) => Value::from(a.to_string()),
    }
}

/// Returns a saved pair: its position, and its chain.
///
/// The chain is in the chain's own spelling.
fn chain_at_json(held: &skep_search::ChainAt) -> Value {
    json!({"position": held.position, "chain": held.chain.to_string()})
}

/// Returns a state as the bridge spells its ten arms.
///
/// The arms are `client.md` §4b.2's `index` event's: `arm` the name, the
/// arm's own members beside it.
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

/// Returns edition or draft, as the bridge spells a hit's and a place's `kind`.
fn kind_name(kind: Kind) -> &'static str {
    match kind {
        Kind::Edition => "edition",
        Kind::Draft => "draft",
    }
}

/// Returns a standing as the bridge spells it.
///
/// A held one names its departed grant's kind and rung (PUB-5.115's kind ×
/// rung) in the bridge's words.
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

/// Returns one mark of a snippet as the bridge spells it.
///
/// It is the hit's span, a matched term, or a gap at its width in positions.
fn mark_json(m: &Mark) -> Value {
    let kind = match &m.kind {
        MarkKind::Span => json!({"span": true}),
        MarkKind::Term { term } => json!({"term": term}),
        MarkKind::Gap { width } => json!({"gap": {"width": width}}),
    };
    json!({"offset": m.offset, "len": m.len, "kind": kind})
}

/// Returns a hit as `search.md` §3.1 shapes it, the bridge's `search` row.
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

/// Returns a place.
fn place_json(p: &Place) -> Value {
    json!({"doc": p.doc.to_string(), "kind": kind_name(p.kind), "label": p.label, "standing": standing_json(&p.standing)})
}

/// Returns the search answer as the row shapes it.
///
/// It is `{hits, places, state}` with the crate's `total` and its four
/// flags beside them.
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

/// Returns the answer where no index stands, in the row's whole shape.
///
/// It holds no hit, no place, the state `none` — the search of a board
/// whose consumer has not opened its index, and the guest form over an
/// origin this shell holds no index for.
pub fn answer_without_index() -> Value {
    answer_json(&SearchAnswer { hits: Vec::new(), total: 0, truncated: false, more_terms: false, fuzzy_bounded: false, positions_bounded: false, places: Vec::new(), state: State::None })
}

/// Returns the listing's answer as the `places` row shapes it.
///
/// It is `{docs, counts, state}`: each document a place, and each count an
/// `{account, documents}` pair, in address order.
fn places_answer_json(a: &PlacesAnswer) -> Value {
    json!({
        "docs": a.docs.iter().map(place_json).collect::<Vec<_>>(),
        "counts": a.counts.iter().map(|(account, documents)| json!({"account": account.to_string(), "documents": documents})).collect::<Vec<_>>(),
        "state": state_json(&a.state),
    })
}

/// Returns the listing where no index stands, in the row's whole shape.
///
/// It holds no document, no count and the state `none`: the listing of a
/// board whose consumer has not opened its index, and the guest form's over
/// an origin this shell holds no index for.
pub fn places_without_index() -> Value {
    places_answer_json(&PlacesAnswer { docs: Vec::new(), counts: BTreeMap::new(), state: State::None })
}

/// Returns the query's bound refused, the shell's own (§4b.1's `search` row).
///
/// It names the bound and the length, never the query's text.
pub fn query_too_long(e: QueryTooLong) -> Refusal {
    Refusal::shell(Name::QUERY_TOO_LONG, json!({"bound": e.bound, "length": e.length}))
}

#[cfg(test)]
mod tests;
