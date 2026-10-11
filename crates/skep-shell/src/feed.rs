//! THE FEED CONSUMER's THREAD, one per board (`client.md` §4b.2: "THE
//! CONSUMER LIVES IN THE SHELL, which holds the session, and the page reads
//! it through this event" — ps3-6; the dev provider record §3.3): the
//! library's `search::Consumer` opened over the board's directory beside
//! the key store, polled on each commit the `/events` stream yields, and
//! beside it this crate's own read of the `/changes` pages for the `feed`
//! events — the published feed as a guest, and each open session's drafts
//! supplement under its token — the `/health` pair read per tick for the
//! `mode` event, the stream's state for the `daemon` event, and the
//! consumer's state for the `index` event, each emitted where it moved.
//! The bridge's `search` call is answered on this thread too, over a
//! channel, so the consumer never crosses a thread: two threads per board,
//! the stream's reader and the consumer's owner, each borrowing the board
//! from the `Arc` it holds.
//!
//! THE `feed` UPDATE's SHAPE — THIS CRATE's DEFINITION (S-24 (b), the
//! shell's): the `/changes` entry's members VERBATIM (`at`, `op`, `docs`,
//! `key`, `time`, `attest`, `new_prefix`, `new_id`, `link`, `placed`,
//! `base_extent`, and any later member by the wire's forward rule), plus
//! `position` (the entry's `at`, named once more so a consumer reading the
//! shell's shape need not know the wire's), and `class` — `published` for a
//! row of the guest's feed, `drafts` for one of a session's supplement, the
//! latter with `session`, the reference it was read under. The event
//! carries `board`, the reference, beside `update`. The feed starts at the
//! head the thread found at its start: a page re-reads what it shows on
//! open and takes the updates from there.

use std::collections::{BTreeMap, HashMap};
use std::path::PathBuf;
use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::Arc;
use std::thread;

use serde_json::{json, Value};
use skep_client::board::{ChangesAnswer, ChangesQuery, Token};
use skep_client::derive::Mode;
use skep_client::search::{events, Consumer, Lost, Newer, Place, Range, SearchAnswer, SearchDir, SearchOpts, SessionRef, State, Stop, Who};
use skep_client::{Board, Origin};
use skep_search::{Hit, MarkKind, Standing};

use crate::events::{EventBus, DAEMON, FEED, INDEX, MODE, SESSION_DIED};
use crate::refusal::Refusal;
use crate::script::Talk;
use crate::sessions::{self, Sessions};

/// One board of the shell: its reference, its origin and the board dialed
/// through the shell's one logging dialer.
pub struct BoardEntry {
    pub reference: String,
    pub origin: Origin,
    pub board: Board,
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
    /// A commit position the stream yielded.
    Tick(u64),
    /// The stream could not connect.
    Unreachable(String),
    /// A session opened: its supplement mounted.
    Widen { reference: String, principal: u64, token: Token, account: String },
    /// A session ended: its supplement unmounted.
    Narrow(u64),
    /// The bridge's search call.
    Search { who: Searcher, query: String, opts: SearchOpts, reindex: bool, reply: Sender<Result<Value, Refusal>> },
    /// The consumer saved.
    Save(Sender<()>),
    /// The consumer closed; the thread ends.
    Stop(Sender<()>),
}

/// The handle the shell holds per board.
pub struct Feed {
    cmds: Sender<Cmd>,
    stream_stop: Stop,
}

impl std::fmt::Debug for Feed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Feed")
    }
}

impl Feed {
    /// The two threads for `entry`, the consumer over `data_dir/index/`.
    pub fn spawn(entry: Arc<BoardEntry>, bus: Arc<EventBus>, sessions: Arc<Sessions>, store: Option<Arc<skep_client::store::FileStore>>, data_dir: PathBuf, talk: Talk) -> Feed {
        let (tx, rx) = channel();
        // The stream's reader: each commit a tick, a failed connect said.
        // The stream borrows the board from the `Arc` the thread holds, so
        // its stopper comes back over a channel before the first read.
        let (stop_tx, stop_rx) = channel();
        let (reader_entry, reader_tx) = (Arc::clone(&entry), tx.clone());
        thread::spawn(move || {
            let mut stream = events(&reader_entry.board);
            let _ = stop_tx.send(stream.stopper());
            while let Some(next) = stream.next() {
                let cmd = match next {
                    Ok(position) => Cmd::Tick(position),
                    Err(h) => Cmd::Unreachable(h.to_string()),
                };
                if reader_tx.send(cmd).is_err() {
                    return;
                }
            }
        });
        let stream_stop = stop_rx.recv().expect("the reader sends its stopper before it reads");
        thread::spawn(move || Worker::run(entry, bus, sessions, store, data_dir, talk, rx));
        Feed { cmds: tx, stream_stop }
    }

    /// A session opened at this board: its supplement mounted.
    pub fn widen(&self, reference: &str, principal: u64, token: Token, account: &str) {
        let _ = self.cmds.send(Cmd::Widen { reference: reference.to_string(), principal, token, account: account.to_string() });
    }

    /// A session ended: its supplement unmounted.
    pub fn narrow(&self, principal: u64) {
        let _ = self.cmds.send(Cmd::Narrow(principal));
    }

    /// The bridge's search call, answered on the consumer's thread.
    pub fn search(&self, who: Searcher, query: &str, opts: SearchOpts, reindex: bool) -> Result<Value, Refusal> {
        let (reply, rx) = channel();
        if self.cmds.send(Cmd::Search { who, query: query.to_string(), opts, reindex, reply }).is_err() {
            return Err(Refusal::shell("feed_stopped", json!({})));
        }
        rx.recv().unwrap_or_else(|_| Err(Refusal::shell("feed_stopped", json!({}))))
    }

    /// The consumer saved now.
    pub fn save(&self) {
        let (reply, rx) = channel();
        if self.cmds.send(Cmd::Save(reply)).is_ok() {
            let _ = rx.recv();
        }
    }

    /// The stream ended and the consumer closed — the save at the shell's
    /// exit.
    pub fn stop(self) {
        self.stream_stop.stop();
        let (reply, rx) = channel();
        if self.cmds.send(Cmd::Stop(reply)).is_ok() {
            let _ = rx.recv();
        }
    }
}

/// The consumer's owner.
struct Worker<'b> {
    entry: &'b BoardEntry,
    bus: Arc<EventBus>,
    sessions: Arc<Sessions>,
    store: Option<Arc<skep_client::store::FileStore>>,
    data_dir: PathBuf,
    talk: Talk,
    consumer: Option<Consumer<'b>>,
    published_since: u64,
    drafts_since: HashMap<u64, u64>,
    last_mode: Option<Mode>,
    last_index: BTreeMap<Option<u64>, Value>,
    /// The session reference per mounted principal, for the `index` event.
    references: HashMap<u64, String>,
    unreachable: bool,
}

impl<'b> Worker<'b> {
    fn run(entry: Arc<BoardEntry>, bus: Arc<EventBus>, sessions: Arc<Sessions>, store: Option<Arc<skep_client::store::FileStore>>, data_dir: PathBuf, talk: Talk, rx: Receiver<Cmd>) {
        let entry_arc = entry;
        let entry: &BoardEntry = &entry_arc;
        let head = entry.board.health().map(|h| h.log_position()).unwrap_or(0);
        let mut worker = Worker {
            entry,
            bus,
            sessions,
            store,
            data_dir,
            talk,
            consumer: None,
            published_since: head,
            drafts_since: HashMap::new(),
            last_mode: None,
            last_index: BTreeMap::new(),
            references: HashMap::new(),
            unreachable: false,
        };
        worker.mount();
        worker.read_mode();
        worker.emit_index();
        while let Ok(cmd) = rx.recv() {
            match cmd {
                Cmd::Tick(position) => worker.tick(position),
                Cmd::Unreachable(text) => worker.unreachable(&text),
                Cmd::Widen { reference, principal, token, account } => worker.widen(reference, principal, token, &account),
                Cmd::Narrow(principal) => worker.narrow(principal),
                Cmd::Search { who, query, opts, reindex, reply } => {
                    let _ = reply.send(worker.search(who, &query, &opts, reindex));
                }
                Cmd::Save(reply) => {
                    worker.save();
                    let _ = reply.send(());
                }
                Cmd::Stop(reply) => {
                    worker.close();
                    let _ = reply.send(());
                    return;
                }
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
        if self.unreachable {
            self.unreachable = false;
            self.bus.emit(DAEMON, json!({"board": self.entry.reference, "state": "running"}));
        }
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
        self.read_mode();
        self.emit_index();
    }

    fn unreachable(&mut self, text: &str) {
        if !self.unreachable {
            self.unreachable = true;
            self.say(format!("the commit stream is not answering: {text}"));
            self.bus.emit(DAEMON, json!({"board": self.entry.reference, "state": "unreachable"}));
        }
        // Every session at this board is dead where the board restarted;
        // the arm is read when the board answers again.
    }

    /// A principal whose supplement met the death signal: every session of
    /// that principal at this board is dead.
    fn died(&mut self, principal: u64) {
        for entry in self.sessions.on_board(&self.entry.reference) {
            if entry.facts.principal == principal {
                self.sessions.remove(&entry.reference);
                let death = sessions::reason(&self.entry.board, self.store.as_deref(), &entry);
                self.bus.emit(SESSION_DIED, json!({"session": entry.reference, "reason": death.reason}));
                self.drafts_since.remove(&principal);
                self.references.remove(&principal);
            }
        }
    }

    /// THE `feed` EVENTS: the published feed's new rows as a guest, then
    /// each open session's drafts supplement under its token.
    fn read_feed(&mut self) {
        let board = &self.entry.board;
        loop {
            match board.changes(None, &ChangesQuery { since: self.published_since, ..ChangesQuery::default() }) {
                Ok(ChangesAnswer::Page(page)) => {
                    for entry in &page.changes {
                        self.emit_feed(entry, "published", None);
                    }
                    self.published_since = page.last;
                    if !page.more {
                        break;
                    }
                }
                Ok(ChangesAnswer::HistoryReclaimed { floor }) => {
                    self.published_since = floor.unwrap_or(self.published_since);
                    break;
                }
                Ok(ChangesAnswer::TooLarge { fits }) => {
                    if let Ok(ChangesAnswer::Page(page)) = board.changes(None, &ChangesQuery { since: self.published_since, limit: Some(fits), ..ChangesQuery::default() }) {
                        for entry in &page.changes {
                            self.emit_feed(entry, "published", None);
                        }
                        self.published_since = page.last;
                    }
                    break;
                }
                Ok(_) | Err(_) => break,
            }
        }
        for session in self.sessions.on_board(&self.entry.reference) {
            let principal = session.facts.principal;
            let since = *self.drafts_since.entry(principal).or_insert(self.published_since);
            match board.changes(Some(&session.token), &ChangesQuery { since, drafts: true, ..ChangesQuery::default() }) {
                Ok(ChangesAnswer::Page(page)) => {
                    for entry in &page.changes {
                        self.emit_feed(entry, "drafts", Some(&session.reference));
                    }
                    self.drafts_since.insert(principal, page.last);
                }
                Ok(ChangesAnswer::Closed) => {
                    if self.sessions.remove(&session.reference).is_some() {
                        let death = sessions::reason(board, self.store.as_deref(), &session);
                        self.bus.emit(SESSION_DIED, json!({"session": session.reference, "reason": death.reason}));
                    }
                    self.drafts_since.remove(&principal);
                }
                Ok(_) | Err(_) => {}
            }
        }
    }

    fn emit_feed(&self, entry: &Value, class: &str, session: Option<&str>) {
        let mut update = entry.clone();
        update["position"] = entry["at"].clone();
        update["class"] = Value::from(class);
        if let Some(s) = session {
            update["session"] = Value::from(s);
        }
        self.bus.emit(FEED, json!({"board": self.entry.reference, "update": update}));
    }

    /// THE `mode` EVENT where the pair moved (the claim's landing, a
    /// restart with the flag changed).
    fn read_mode(&mut self) {
        let Ok(health) = self.entry.board.health() else { return };
        let mode = Mode::of(&health);
        if self.last_mode != Some(mode) {
            let first = self.last_mode.is_none();
            self.last_mode = Some(mode);
            if !first {
                self.bus.emit(MODE, json!({"board": self.entry.reference, "mode": mode.name(), "claimant": health.claimant(), "local_trust": health.local_trust()}));
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
                let session = principal.and_then(|p| self.references.get(&p).cloned());
                self.bus.emit(INDEX, json!({"board": self.entry.reference, "session": session, "state": state}));
                self.last_index.insert(principal, state);
            }
        }
    }

    fn widen(&mut self, reference: String, principal: u64, token: Token, account: &str) {
        self.references.insert(principal, reference);
        self.drafts_since.entry(principal).or_insert(self.published_since);
        self.mount();
        if let Some(c) = &self.consumer {
            if let Err(h) = c.widen(SessionRef { token: &token, principal, account }) {
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
        self.references.remove(&principal);
        self.drafts_since.remove(&principal);
        self.last_index.remove(&Some(principal));
    }

    fn search(&mut self, who: Searcher, query: &str, opts: &SearchOpts, reindex: bool) -> Result<Value, Refusal> {
        self.mount();
        let Some(c) = &self.consumer else {
            return Ok(json!({"hits": [], "places": [], "state": {"arm": "none"}}));
        };
        let answer = match &who {
            Searcher::Guest => {
                if reindex {
                    c.reindex(Who::Guest).map_err(Refusal::of)?;
                }
                c.search(Who::Guest, query, opts)
            }
            Searcher::Session { principal, token, account } => {
                let who = Who::Session(SessionRef { token, principal: *principal, account });
                if reindex {
                    c.reindex(who).map_err(Refusal::of)?;
                }
                c.search(who, query, opts)
            }
        };
        let answer = answer.map_err(|e| Refusal::shell("query_too_long", json!({"bound": e.bound, "length": e.length})))?;
        let value = answer_json(&answer);
        self.emit_index();
        Ok(value)
    }

    fn save(&mut self) {
        if let Some(c) = &self.consumer {
            if let Err(h) = c.save() {
                self.say(format!("the index could not save: {h}"));
            }
        }
    }

    fn close(&mut self) {
        if let Some(c) = self.consumer.take() {
            if let Err(h) = c.close() {
                self.say(format!("the index could not save at close: {h}"));
            }
        }
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

/// A standing as the bridge spells it.
fn standing_json(s: &Standing) -> Value {
    match s {
        Standing::Public => Value::from("public"),
        Standing::YoursToRead => Value::from("yours_to_read"),
        Standing::Held { kind, rung, issuer } => json!({"held": {"kind": format!("{kind:?}").to_lowercase(), "rung": format!("{rung:?}").to_lowercase(), "issuer": issuer.to_string()}}),
    }
}

/// A hit as `search.md` §3.1 shapes it, the bridge's `search` row.
pub fn hit_json(h: &Hit) -> Value {
    let snippet = h.snippet.as_ref().map(|s| {
        let marks: Vec<Value> = s
            .marks
            .iter()
            .map(|m| {
                let kind = match &m.kind {
                    MarkKind::Span => json!({"span": true}),
                    MarkKind::Term { term } => json!({"term": term}),
                    other => json!({"gap": format!("{other:?}")}),
                };
                json!({"offset": m.offset, "len": m.len, "kind": kind})
            })
            .collect();
        json!({"text": s.text, "start": s.start, "marks": marks})
    });
    json!({
        "doc": h.doc.to_string(),
        "member": h.member.as_ref().map(|m| m.to_string()),
        "as_of": h.as_of,
        "span": {"start": h.span.start, "width": h.span.width},
        "score": h.score,
        "snippet": snippet,
        "kind": format!("{:?}", h.kind).to_lowercase(),
        "standing": standing_json(&h.standing),
        "occurrences": h.occurrences,
        "matched": h.matched.iter().map(|m| json!({"word": m.word, "term": m.term})).collect::<Vec<_>>(),
    })
}

/// A place.
pub fn place_json(p: &Place) -> Value {
    json!({"doc": p.doc.to_string(), "kind": format!("{:?}", p.kind).to_lowercase(), "label": p.label, "standing": standing_json(&p.standing)})
}

/// THE SEARCH ANSWER as the row shapes it: `{hits, places, state}` with the
/// crate's five facts beside them.
pub fn answer_json(a: &SearchAnswer) -> Value {
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

#[cfg(test)]
mod tests {
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
}
