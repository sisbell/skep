//! THE FEED CONSUMER (`client.md` §4e.2, §4e.3; `search.md` §4, §5.1, §5.4,
//! §5.5, §5.6), one per board: [`Consumer`] owns the feeder's lock, the two
//! indexes — the board's PUBLISHED index and one SUPPLEMENT per mounted
//! principal — the document index's two parts beside them, the per-range
//! records, and ONE READ-WRITE LOCK around the engines, under which "the feed
//! thread writes and the bridge's search thread reads" (§5.6): `prepare`
//! outside it, `merge` under its write side, `compacted` under the read side
//! then `install` under the write side ahead of a compacting save, `save`
//! and every query under the read side.
//!
//! THE POLL ([`Consumer::poll`]): "`/changes` CARRIES NO TEXT AND NO SPAN …
//! so EVERY CONTENT CHANGE COSTS ONE READ of the changed document …
//! COALESCED to ONE READ PER CHANGED DOCUMENT PER POLL" (§4e.2). The
//! `/health` pair is read BEFORE the drain; the published index's range is
//! drained from its cursor as a GUEST — every document a plain page names
//! is published and is read token-free at guest class — and each mounted
//! supplement's ranges with the session's token over `drafts=true`, read at
//! the principal's class; the distinct documents a page names are read ONCE
//! each — `retrieve_v` over the extent `span_set` answers, in PARTS past
//! [`MAX_DELIVERY_ITEMS`], an edition at its PINNED MEMBER (the latest trunk
//! member a minting row named, `moved_head`, or the trunk PROBED with
//! `doc_metadata` until `doc_not_registered` where the feed names none,
//! §2.4), a draft in sequence, a straddled draft's join held PENDING until
//! the next page settles it (§2.1); a BARE row whose `op` is `null` or
//! `publish` is COUNTED against its range; a range's `held` advances only
//! behind a WHOLE page — every document indexed or its refusal RECORDED
//! (`withheld`, `too_many_items`), a transport error holding it — and is
//! fixed as the `/health` pair where the poll drained to `more: false`, by
//! `GET /chain?at=<position>` alone at a save no draining poll fenced (§5.1);
//! the newest `H.k` the feed delivered is kept as the header's head record,
//! off the read made of `H` at every `key: "system"` `publish` row (§5.4);
//! the discovery reads — the principal-keyed grant query and
//! `universal_grants` — run beside each poll and feed WIDEN (§4e.3). THE
//! SAVE every [`SAVE_EVERY_UNITS`] changed units or [`SAVE_EVERY`] and at
//! close — INTERIM pins, `search.md` §7.1 — compacting first where
//! `compaction_due`, by the directory's rename. No read the consumer makes
//! carries a query term, and the reads are driven by the board's commits and
//! the session's triggers alone (§4e.2's host-log sentence).
//!
//! AT OPEN ([`Consumer::open`]): an UNCLAIMED board has no `H.1` and no index
//! (`State::None`); the feeder's lock held by another process mounts nothing
//! (`State::Busy`, §5.6 RULED); then THE ASIDE CHECK — a CRC-valid file
//! naming another board or another principal's class is moved aside under
//! its own chain — and THE RESUME: `GET /chain?at=<held>` per saved pair, the
//! saved `H.k` re-read byte-equal where the answer is `history_reclaimed`,
//! `Resume::judge` the verdict — `Equal` resumes, `FromTheFloor` keeps the
//! file and re-fixes each range at the floor, the three divergences move the
//! file aside WITH its pair and build fresh, `history_busy` retries a bounded
//! wait and is left pending for the next poll past it — and the newer-skep
//! and migration dispositions as `LoadError` answers them (§5.4).
//!
//! THE TRIGGERS (§4e.3): [`Consumer::widen`] at a session open, a principal
//! switch and a discovered grant — the ranges the principal's prefix, its
//! ancestors' and each grant's, each from its own `held` or from the floor
//! where new; [`Consumer::narrow`] at close, death and switch-away — the
//! supplement unmounted, its file kept; revocation NO operation (R90).
//! THE PERSON's ACTS (§5.5): [`Consumer::reindex`], the REFRESH — every unit
//! the pair holds re-read at its own class by `keys_by_range`, nothing
//! dropped — and [`Consumer::forget`], offered by the shell off
//! [`Consumer::orphans`] alone (sr-S1): the walk upward from
//! `principal_prefix(n)` and one `key_set` read at its terminus. THE LOOP's
//! INPUT: [`events`], the `/events` stream's commit positions.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File};
use std::io::{self, BufRead, BufReader, Read};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::thread;
use std::time::{Duration, Instant};

use serde_json::Value;
use skep_address::{Address, Level};
use skep_identity::Fingerprint;
use skep_search::header;
use skep_search::{
    moved_head, Chain, ChainAnswer, ChainAt, Class, GapKind, Grant, GrantKind, HeadRecord, Header,
    Index, IndexError, Item, Kind, LoadError, Prefix, Prepared, RangeRecord, Refusal, Resume, Unit,
    UnitKey,
};

use crate::address::{parent_account, parse_address};
use crate::board::answers::{self, Delivered};
use crate::board::{frames, Answer, Board, ChainAtAnswer, ChangesAnswer, ChangesPage, ChangesQuery, KeySetAnswer, Rejection, Token, HEAD_DOCUMENT};
use crate::dial::{Method, RequestHead};
use crate::halt::Halt;

use super::bridge::{SessionRef, Who};
use super::directory::{BoardDir, SearchDir};
use super::places::{account_of, bare_document, member_of, node_of, PlaceRecord, Places};
use super::state::{Facts, Lost, Newer, Part, Range, State};

/// THE SAVE's cadence in changed units (`client.md` §4e.2; `search.md`
/// §7.1): "every 64 changed units or 30 seconds and at the shell's exit
/// (INTERIM pins)".
pub const SAVE_EVERY_UNITS: usize = 64;

/// THE SAVE's cadence in time (the same pin).
pub const SAVE_EVERY: Duration = Duration::from_secs(30);

/// `MAX_DELIVERY_ITEMS`, the delivery budget one `retrieve_v` is bounded by
/// (`crates/skep-retrieval/src/budget.rs`, `1 << 17`; wire.md §Content &
/// provenance reads): a document past it is read in parts (`search.md`
/// §2.1). The number alone is mirrored here, as the index's suite mirrors
/// it.
pub const MAX_DELIVERY_ITEMS: u64 = 1 << 17;

/// The GRANTS class type address (wire.md §The read predicate: "`ty` the
/// grants class `1.1.0.1.0.1.0.3.90`") — the principal-keyed discovery
/// read's `ty`.
pub const T_GRANT: &str = "1.1.0.1.0.1.0.3.90";

/// The resume's bounded wait on `history_busy`: this many retries, each
/// after [`RESUME_RETRY_WAIT`], before the resume is left pending.
const RESUME_RETRIES: usize = 10;

/// The wait between the resume's retries.
const RESUME_RETRY_WAIT: Duration = Duration::from_millis(100);

/// The trunk probe's bound in members (`search.md` §2.4): the members are
/// dense, so a probe ends at the first unregistered; the bound is a guard.
const PROBE_BOUND: u64 = 1 << 20;

/// The wait before the `/events` stream is reconnected after it ended.
const RECONNECT_WAIT: Duration = Duration::from_millis(250);

/// THE CONSUMER, one per board (the module doc). Every method takes `&self`:
/// the mutating ones — `poll`, `widen`, `narrow`, `reindex`, `forget`,
/// `save` — serialize on one feed mutex, the ONE WRITER, and may be called
/// from the shell's feed thread; `search` and `state` read under the
/// engines' read side from any thread.
pub struct Consumer<'b> {
    board: &'b Board,
    dir: SearchDir,
    /// The one writer: the feed thread's calls run one at a time.
    feed: Mutex<()>,
    /// THE READ-WRITE LOCK around the engines (`search.md` §5.6).
    pub(super) mount: RwLock<Mount>,
}

/// What the consumer has mounted.
pub(super) enum Mount {
    /// The board has no `H.1`: no directory, no index.
    Unclaimed,
    /// Another process holds the feeder's lock.
    Busy,
    /// The board's directory, locked, with its engines.
    Live(Live),
}

/// The live mount: the directory, the lock, the engines.
pub(super) struct Live {
    dir: BoardDir,
    chain: Chain,
    /// The feeder's advisory lock, held for the consumer's life.
    _lock: File,
    /// The node's prefix — the whole board's range, for the refreshes.
    node: Prefix,
    pub(super) published: Slot,
    pub(super) supplements: BTreeMap<u64, Supplement>,
}

/// One index's slot: faced as a newer skep's, pending a busy resume, or
/// live.
pub(super) enum Slot {
    Faced(Newer),
    Pending,
    Engine(Engine),
}

/// One live index with everything the consumer keeps beside it.
pub(super) struct Engine {
    class: Class,
    name: String,
    places_name: String,
    pub(super) index: Index,
    pub(super) header: Header,
    pub(super) places: Places,
    /// Per range, the fetch fence: the last page's `last` (in memory; the
    /// durable position is the record's `held`).
    cursors: Vec<u64>,
    /// Drafts read in parts across a commit, held until the next page
    /// settles them (`search.md` §2.1).
    pending: Vec<PendingJoin>,
    /// The published engine's head members, document → `D.k`.
    heads: BTreeMap<Address, Address>,
    building: Option<u64>,
    widening: Option<Range>,
    resumed: Option<(u64, ChainAt)>,
    lost: Option<Lost>,
    aside: bool,
    /// Units changed since the last save.
    changed: usize,
    /// Anything to save since the last save.
    dirty: bool,
    last_save: Instant,
}

/// A draft's join read in parts across a commit: installed or discarded by
/// the next page's rows (`search.md` §2.1).
struct PendingJoin {
    range: usize,
    doc: Address,
    prepared: Prepared,
    first: u64,
    last: u64,
}

/// One mounted principal's supplement with its session's token and its
/// honored set (`search.md` §3.1's inputs).
pub(super) struct Supplement {
    pub(super) slot: Slot,
    token: Token,
    account: Address,
    /// The prefixes the discovery reads currently honor, with their grants.
    pub(super) honored: Vec<Honored>,
    /// Every grant-typed link naming the principal the discovery read has
    /// read, by address — a link is immutable, so one read each.
    links: BTreeMap<String, GrantLink>,
}

/// One honored prefix and the grant that opens it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Honored {
    pub(super) prefix: Address,
    pub(super) grant: Grant,
}

/// What a grant-typed link naming the principal is.
#[derive(Debug, Clone, PartialEq, Eq)]
enum GrantLink {
    /// A grant over `prefix` by `issuer`.
    Grant { prefix: Address, issuer: Address },
    /// A revocation of the grant at `of`.
    Revocation { of: String },
    /// Neither — a record the fold admits for nothing.
    Other,
}

/// Which index a drain feeds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Face {
    Published,
    Supplement(u64),
}

/// What one poll did (the shell's event input beside the state).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Poll {
    /// The pages fetched.
    pub pages: usize,
    /// The documents read — one read each.
    pub documents: usize,
    /// The principals whose session met the death signal on a read: each
    /// narrowed, the shell's `session-died` arm to face.
    pub died: Vec<u64>,
}

/// A supplement no key the store holds can open (`search.md` §5.5): the
/// forget offer's input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Orphan {
    /// The supplement's principal.
    pub principal: u64,
    /// `principal_prefix(n)`, where the board still knows the principal.
    pub account: Option<String>,
}

/// The plan for one page: what to read, what the rows said.
struct Plan {
    reads: Vec<ReadPlan>,
    bare: u64,
    head_rows: Vec<Address>,
    head_moves: Vec<(Address, Address)>,
    /// Pending joins settled by this page: installed, or discarded.
    install: Vec<usize>,
    discard: Vec<usize>,
}

/// One document to read.
struct ReadPlan {
    doc: Address,
    member: Option<Address>,
    kind: Kind,
    /// The trunk is to be probed for the head member first.
    probe: bool,
}

/// What a document's read answered.
enum Fetched {
    Unit { prepared: Prepared, member: Option<Address>, kind: Kind, first: u64, last: u64, parts: u64 },
    Refused(String),
    Closed,
}

/// What a drain ended with.
enum Drained {
    Done,
    Closed,
}

fn io_halt(what: &str, path: &std::path::Path, e: io::Error) -> Halt {
    Halt::face(
        format!("the search index's {what} failed at {}: {e}", path.display()),
        "the index directory could not be read or written",
        "check the data directory's permissions and free space",
    )
}

fn zero_chain() -> Chain {
    Chain::from_bytes([0; 32])
}

impl<'b> Consumer<'b> {
    /// THE OPEN (the module doc): the board term read for the directory's
    /// key, the lock taken, the aside check and the resume run over the
    /// published index. An unclaimed board mounts nothing and answers
    /// `State::None`; a held lock mounts nothing and answers `State::Busy`.
    pub fn open(board: &'b Board, dir: SearchDir) -> Result<Consumer<'b>, Halt> {
        let consumer = Consumer { board, dir, feed: Mutex::new(()), mount: RwLock::new(Mount::Unclaimed) };
        consumer.mount()?;
        Ok(consumer)
    }

    /// The board this consumer feeds from.
    pub fn board(&self) -> &'b Board {
        self.board
    }

    /// The search directory.
    pub fn dir(&self) -> &SearchDir {
        &self.dir
    }

    /// The board's directory, where the board has one.
    pub fn board_dir(&self) -> Option<BoardDir> {
        match &*self.mount.read().expect("the engines' lock") {
            Mount::Live(live) => Some(live.dir.clone()),
            _ => None,
        }
    }

    /// Whether principal `n`'s supplement is mounted.
    pub fn mounted(&self, principal: u64) -> bool {
        match &*self.mount.read().expect("the engines' lock") {
            Mount::Live(live) => live.supplements.contains_key(&principal),
            _ => false,
        }
    }

    fn mount(&self) -> Result<(), Halt> {
        let Some(term) = self.board.board_term()? else { return Ok(()) };
        let chain = Chain::from_bytes(term.chain);
        let dir = self.dir.board(&chain);
        dir.ensure().map_err(|e| io_halt("directory", dir.path(), e))?;
        let Some(lock) = dir.try_lock().map_err(|e| io_halt("lock", dir.path(), e))? else {
            *self.mount.write().expect("the engines' lock") = Mount::Busy;
            return Ok(());
        };
        let head = parse_address(HEAD_DOCUMENT).expect("the head document's address");
        let node = Prefix::new(node_of(&head).expect("the head document lies under a node"));
        let published = self.open_slot(&dir, &chain, Class::Guest, &BoardDir::published_name(), &BoardDir::published_places_name())?;
        *self.mount.write().expect("the engines' lock") =
            Mount::Live(Live { dir, chain, _lock: lock, node, published, supplements: BTreeMap::new() });
        Ok(())
    }

    /// One index file opened: absent → fresh; loaded → the aside check and
    /// the resume; faced, damaged or misplaced as `LoadError` answers.
    fn open_slot(&self, dir: &BoardDir, chain: &Chain, class: Class, name: &str, places_name: &str) -> Result<Slot, Halt> {
        let path = dir.file(name);
        let bytes = match fs::read(&path) {
            Ok(bytes) => Some(bytes),
            Err(e) if e.kind() == io::ErrorKind::NotFound => None,
            Err(e) => return Err(io_halt("read", &path, e)),
        };
        let mut aside = false;
        let mut lost = None;
        let mut resumed = None;
        let mut loaded = None;
        if let Some(bytes) = bytes {
            match Index::load(&mut &bytes[..], class) {
                Ok((index, mut header)) => {
                    if header.board != *chain {
                        // A misplaced file: another board's holding, CRC-valid.
                        self.set_aside(dir, name, places_name, &header.board)?;
                        aside = true;
                    } else {
                        match self.resume(&mut header)? {
                            Resumed::Cursors(cursors, from_floor) => {
                                resumed = from_floor;
                                loaded = Some((index, header, cursors));
                            }
                            Resumed::Aside(saved) => {
                                self.set_aside(dir, name, places_name, &header.board)?;
                                lost = Some(Lost::Diverged { held: saved });
                            }
                            Resumed::Pending => return Ok(Slot::Pending),
                        }
                    }
                }
                Err(LoadError::NewerVersion { v }) => return Ok(Slot::Faced(Newer::Version { v })),
                Err(LoadError::NewerTokenizer { revision }) => return Ok(Slot::Faced(Newer::Tokenizer { revision })),
                Err(LoadError::OtherClass { .. }) => {
                    // Another principal's holding, refused before its body: its own
                    // chain off its header line, by the crate's one parser.
                    let own = first_line(&bytes).and_then(|line| header::parse(line).ok()).map(|p| p.board).unwrap_or(*chain);
                    self.set_aside(dir, name, places_name, &own)?;
                    aside = true;
                }
                Err(LoadError::Damaged { what }) => lost = Some(Lost::Damaged { what }),
                Err(LoadError::UnknownMember { name: member }) => {
                    lost = Some(Lost::Damaged { what: format!("an unknown header member `{member}`") })
                }
                Err(e) => {
                    return Err(Halt::face(
                        format!("the search index at {} could not be read: {e}", path.display()),
                        "the file's reader failed before any byte was judged",
                        "check the data directory",
                    ))
                }
            }
        }
        let places = match fs::read(dir.file(places_name)) {
            Ok(bytes) if loaded.is_some() => Places::decode(&bytes).unwrap_or_default(),
            _ => Places::new(),
        };
        let (index, header, cursors, building) = match loaded {
            // A migrated index is dirty at once, so it is saved under the
            // running revision and the next load migrates nothing (§5.1).
            Some((index, header, cursors)) => (index, header, cursors, None),
            None => {
                let (index, header) = fresh(class, chain);
                let cursors = header.ranges.iter().map(|r| r.held.position).collect();
                // The published index's first build reads the whole board
                // from the floor; a fresh supplement's first fetch is a
                // WIDENING, not a build.
                let building = matches!(class, Class::Guest).then_some(0);
                (index, header, cursors, building)
            }
        };
        let dirty = building.is_some() || index.migrated_from().is_some() || resumed.is_some();
        let mut heads = BTreeMap::new();
        for (doc, record) in places.docs() {
            if let Some(member) = &record.member {
                heads.insert(doc.clone(), member.clone());
            }
        }
        Ok(Slot::Engine(Engine {
            class,
            name: name.to_string(),
            places_name: places_name.to_string(),
            index,
            header,
            places,
            cursors,
            pending: Vec::new(),
            heads,
            building,
            widening: None,
            resumed,
            lost,
            aside,
            changed: 0,
            dirty,
            last_save: Instant::now(),
        }))
    }

    /// The aside: the index file and its places part moved under the file's
    /// own chain.
    fn set_aside(&self, dir: &BoardDir, name: &str, places_name: &str, own: &Chain) -> Result<(), Halt> {
        dir.move_aside(name, own).map_err(|e| io_halt("aside", &dir.file(name), e))?;
        if dir.file(places_name).is_file() {
            dir.move_aside(places_name, own).map_err(|e| io_halt("aside", &dir.file(places_name), e))?;
        }
        Ok(())
    }

    /// THE RESUME (`search.md` §5.4): one `GET /chain?at` per distinct saved
    /// position, the `H.k` re-read where the answer is `history_reclaimed`,
    /// the verdict `Resume::judge`'s.
    fn resume(&self, header: &mut Header) -> Result<Resumed, Halt> {
        let mut answers: BTreeMap<u64, ChainAnswer> = BTreeMap::new();
        let mut cursors = Vec::with_capacity(header.ranges.len());
        let mut from_floor = None;
        let mut refixed: Vec<(usize, ChainAt)> = Vec::new();
        for (i, range) in header.ranges.iter().enumerate() {
            let held = range.held;
            let answer = match answers.get(&held.position) {
                Some(a) => *a,
                None => {
                    let a = self.chain_answer(held.position, header.head.as_ref())?;
                    let Some(a) = a else { return Ok(Resumed::Pending) };
                    answers.insert(held.position, a);
                    a
                }
            };
            match Resume::judge(held, header.head.as_ref(), &answer) {
                Resume::Equal => cursors.push(held.position),
                Resume::FromTheFloor { floor } => {
                    let floor = floor.unwrap_or(0);
                    cursors.push(floor);
                    header.floor = Some(header.floor.map_or(floor, |f| f.max(floor)));
                    from_floor.get_or_insert((floor, held));
                    // The chain re-fixed at the floor where it still answers;
                    // else the next draining poll's pair fixes it.
                    if let ChainAtAnswer::Chain { chain, .. } = self.board.chain_at(floor)? {
                        refixed.push((i, ChainAt { position: floor, chain: Chain::from_bytes(chain) }));
                    }
                }
                Resume::Diverged { saved } | Resume::BeyondHead { saved, .. } | Resume::DifferentChain { saved, .. } => {
                    return Ok(Resumed::Aside(saved))
                }
                Resume::Busy => return Ok(Resumed::Pending),
            }
        }
        for (i, held) in refixed {
            header.ranges[i].held = held;
        }
        Ok(Resumed::Cursors(cursors, from_floor))
    }

    /// `GET /chain?at=<position>` as a `ChainAnswer`, `history_busy` retried
    /// a bounded wait; `None` where it stayed busy.
    fn chain_answer(&self, position: u64, head: Option<&HeadRecord>) -> Result<Option<ChainAnswer>, Halt> {
        for attempt in 0..=RESUME_RETRIES {
            let answer = match self.board.chain_at(position)? {
                ChainAtAnswer::Chain { chain, .. } => ChainAnswer::Chain(Chain::from_bytes(chain)),
                ChainAtAnswer::HistoryReclaimed { floor } => {
                    let reread = match head {
                        Some(record) => self.reread_head(record)?,
                        None => None,
                    };
                    ChainAnswer::Reclaimed { floor, head: reread }
                }
                ChainAtAnswer::BeyondHead { head } => ChainAnswer::BeyondHead { head: head.unwrap_or(0) },
                ChainAtAnswer::NotAPosition { nearest } => ChainAnswer::BeyondHead { head: nearest.unwrap_or(0) },
                ChainAtAnswer::Busy => {
                    if attempt < RESUME_RETRIES {
                        thread::sleep(RESUME_RETRY_WAIT);
                        continue;
                    }
                    return Ok(None);
                }
            };
            return Ok(Some(answer));
        }
        Ok(None)
    }

    /// The saved `H.k` re-read as a guest: the pair its record names now, or
    /// `None` where the member is gone or holds no head record.
    fn reread_head(&self, record: &HeadRecord) -> Result<Option<ChainAt>, Halt> {
        let v = self.board.guest(&frames::retrieve_v(&record.member.to_string(), 1, 1))?;
        Ok(answers::head_pair(&v).map(|(position, chain)| ChainAt { position, chain: Chain::from_bytes(chain) }))
    }

    /// The `/health` pair read before a draining poll (`search.md` §5.1).
    fn health_pair(&self) -> Result<ChainAt, Halt> {
        let health = self.board.health()?;
        let chain = health.chain_head().ok_or_else(|| {
            Halt::Dial(crate::dial::DialError::Response("`/health` carried no `chain_head`".into()))
        })?;
        Ok(ChainAt { position: health.log_position(), chain: Chain::from_bytes(chain) })
    }

    /// THE POLL (the module doc): the `/health` pair, the published range
    /// drained as a guest, each mounted supplement's discovery reads and
    /// ranges with its token, the save at its cadence.
    pub fn poll(&self) -> Result<Poll, Halt> {
        let _feed = self.feed.lock().expect("the feed mutex");
        let mut outcome = Poll::default();
        if matches!(&*self.read(), Mount::Unclaimed) {
            self.mount()?;
        }
        if !matches!(&*self.read(), Mount::Live(_)) {
            return Ok(outcome);
        }
        self.retry_pending_resume()?;
        let pair = self.health_pair()?;
        self.drain(Face::Published, &pair, &mut outcome, false)?;
        let principals: Vec<u64> = match &*self.read() {
            Mount::Live(live) => live.supplements.keys().copied().collect(),
            _ => Vec::new(),
        };
        for principal in principals {
            match self.discover(principal)? {
                Some(honored) => self.adopt_honored(principal, honored),
                None => {
                    self.unmount(principal)?;
                    outcome.died.push(principal);
                    continue;
                }
            }
            if let Drained::Closed = self.drain(Face::Supplement(principal), &pair, &mut outcome, false)? {
                self.unmount(principal)?;
                outcome.died.push(principal);
            }
        }
        self.maybe_save(false)?;
        Ok(outcome)
    }

    /// A published slot left pending by `history_busy` at the open: the file
    /// re-opened and the resume retried.
    fn retry_pending_resume(&self) -> Result<(), Halt> {
        let (dir, chain) = match &*self.read() {
            Mount::Live(live) if matches!(live.published, Slot::Pending) => (live.dir.clone(), live.chain),
            _ => return Ok(()),
        };
        let slot = self.open_slot(&dir, &chain, Class::Guest, &BoardDir::published_name(), &BoardDir::published_places_name())?;
        if let Mount::Live(live) = &mut *self.write() {
            live.published = slot;
        }
        Ok(())
    }

    fn read(&self) -> std::sync::RwLockReadGuard<'_, Mount> {
        self.mount.read().expect("the engines' lock")
    }

    fn write(&self) -> std::sync::RwLockWriteGuard<'_, Mount> {
        self.mount.write().expect("the engines' lock")
    }

    /// The engine of a face under a guard, where it is live.
    fn engine_of(live: &Live, face: Face) -> Option<&Engine> {
        match face {
            Face::Published => match &live.published {
                Slot::Engine(e) => Some(e),
                _ => None,
            },
            Face::Supplement(n) => match live.supplements.get(&n).map(|s| &s.slot) {
                Some(Slot::Engine(e)) => Some(e),
                _ => None,
            },
        }
    }

    fn engine_of_mut(live: &mut Live, face: Face) -> Option<&mut Engine> {
        match face {
            Face::Published => match &mut live.published {
                Slot::Engine(e) => Some(e),
                _ => None,
            },
            Face::Supplement(n) => match live.supplements.get_mut(&n).map(|s| &mut s.slot) {
                Some(Slot::Engine(e)) => Some(e),
                _ => None,
            },
        }
    }

    /// THE DRAIN of one face's ranges (the module doc). `widening` marks the
    /// state while each range fetches.
    fn drain(&self, face: Face, pair: &ChainAt, outcome: &mut Poll, widening: bool) -> Result<Drained, Halt> {
        let (token, class, ranges) = {
            let guard = self.read();
            let Mount::Live(live) = &*guard else { return Ok(Drained::Done) };
            let Some(engine) = Self::engine_of(live, face) else { return Ok(Drained::Done) };
            let token = match face {
                Face::Published => None,
                Face::Supplement(n) => live.supplements.get(&n).map(|s| s.token.clone()),
            };
            let ranges: Vec<(Option<Address>, u64)> =
                engine.header.ranges.iter().zip(&engine.cursors).map(|(r, c)| (r.under.clone(), *c)).collect();
            (token, engine.class, ranges)
        };
        let drafts = matches!(face, Face::Supplement(_));
        // THE COALESCING across this poll (§4e.2: "ONE READ PER CHANGED
        // DOCUMENT PER POLL"): a document read on one range's page is not
        // read again for another range's row at or below that read's
        // position — a sub-account's draft lies under its ancestor's range
        // too.
        let mut recent: BTreeMap<Address, u64> = BTreeMap::new();
        for (i, (under, mut cursor)) in ranges.into_iter().enumerate() {
            if widening {
                self.with_engine(face, |e| e.widening = Some(Range::of(under.as_ref())));
                // The recorded refusals retried at the next widening of a
                // range that covers them (`search.md` §4).
                if let Fetched::Closed = self.retry_refusals(face, i, token.as_ref(), class)? {
                    return Ok(Drained::Closed);
                }
            }
            let mut limit: Option<u64> = None;
            let under_text = under.as_ref().map(ToString::to_string);
            loop {
                let query = ChangesQuery { since: cursor, under: under_text.as_deref(), drafts, limit };
                match self.board.changes(token.as_ref(), &query)? {
                    ChangesAnswer::Page(page) => {
                        outcome.pages += 1;
                        let plan = self.plan(face, i, &page, &recent);
                        let mut reads = Vec::with_capacity(plan.reads.len());
                        for read in &plan.reads {
                            let outcome_of = self.read_document(token.as_ref(), class, read)?;
                            if let Fetched::Closed = outcome_of {
                                return Ok(Drained::Closed);
                            }
                            if let Fetched::Unit { last, .. } = &outcome_of {
                                recent.insert(read.doc.clone(), *last);
                            }
                            outcome.documents += 1;
                            reads.push(outcome_of);
                        }
                        let mut head_records = Vec::new();
                        for member in &plan.head_rows {
                            let v = self.board.guest(&frames::retrieve_v(&member.to_string(), 1, 1))?;
                            if let Some((position, chain)) = answers::head_pair(&v) {
                                head_records.push(HeadRecord { member: member.clone(), at: ChainAt { position, chain: Chain::from_bytes(chain) } });
                            }
                        }
                        self.apply(face, i, &page, plan, reads, head_records);
                        cursor = page.last;
                        if !page.more {
                            break;
                        }
                        self.maybe_save(false)?;
                    }
                    ChangesAnswer::HistoryReclaimed { floor } => {
                        let floor = floor.unwrap_or(pair.position);
                        let refixed = match self.board.chain_at(floor)? {
                            ChainAtAnswer::Chain { chain, .. } => Some(ChainAt { position: floor, chain: Chain::from_bytes(chain) }),
                            _ => None,
                        };
                        self.with_engine(face, |e| {
                            e.header.floor = Some(e.header.floor.map_or(floor, |f| f.max(floor)));
                            if let Some(held) = refixed {
                                e.header.ranges[i].held = held;
                            }
                            e.cursors[i] = floor;
                            e.dirty = true;
                        });
                        if cursor >= floor {
                            // The floor answered no position above the cursor:
                            // nothing below the head can be fetched.
                            cursor = pair.position;
                            self.with_engine(face, |e| e.cursors[i] = pair.position);
                            break;
                        }
                        cursor = floor;
                    }
                    ChangesAnswer::TooLarge { fits } => limit = Some(fits.max(1)),
                    ChangesAnswer::Closed => return Ok(Drained::Closed),
                }
            }
            // THE FENCE (`search.md` §5.1): every entry at or below the pair's
            // position lay on the pages that drained, so `held` is that pair —
            // unless a pending join still holds the range at its last page.
            self.with_engine(face, |e| {
                if !e.pending.iter().any(|p| p.range == i) {
                    e.header.ranges[i].held = *pair;
                    e.dirty = true;
                }
                if e.cursors[i] < cursor {
                    e.cursors[i] = cursor;
                }
                e.widening = None;
                if e.building.is_some() && face == Face::Published {
                    e.building = None;
                }
            });
        }
        Ok(Drained::Done)
    }

    /// THE RECORDED REFUSALS of one range re-read (`search.md` §4: "retried
    /// at the next widening of a range that covers it"; §5.5: the refresh
    /// over every range): each document read again at the face's class,
    /// indexed where the board now admits it — its record then cleared — or
    /// its refusal recorded afresh. Answers `Closed` where the session died.
    fn retry_refusals(&self, face: Face, range: usize, token: Option<&Token>, class: Class) -> Result<Fetched, Halt> {
        let docs: Vec<Address> = {
            let guard = self.read();
            let Mount::Live(live) = &*guard else { return Ok(Fetched::Refused(String::new())) };
            let Some(engine) = Self::engine_of(live, face) else { return Ok(Fetched::Refused(String::new())) };
            engine.header.ranges.get(range).map(|r| r.refusals.iter().map(|f| f.doc.clone()).collect()).unwrap_or_default()
        };
        for doc in docs {
            let plan = {
                let guard = self.read();
                let engine = match &*guard {
                    Mount::Live(live) => Self::engine_of(live, face),
                    _ => None,
                };
                let Some(engine) = engine else { return Ok(Fetched::Refused(String::new())) };
                match face {
                    Face::Published => {
                        let member = engine.heads.get(&doc).cloned();
                        ReadPlan { doc: doc.clone(), member: member.clone(), kind: Kind::Edition, probe: member.is_none() }
                    }
                    Face::Supplement(_) => ReadPlan { doc: doc.clone(), member: Some(doc.clone()), kind: Kind::Draft, probe: false },
                }
            };
            let fetched = self.read_document(token, class, &plan)?;
            if let Fetched::Closed = fetched {
                return Ok(Fetched::Closed);
            }
            self.with_engine(face, |e| match fetched {
                Fetched::Unit { prepared, member, kind, .. } => {
                    if let Some(member) = &member {
                        e.heads.insert(doc.clone(), member.clone());
                    }
                    e.merge(prepared, range, kind, member);
                }
                Fetched::Refused(reason) => {
                    if let Some(record) = e.header.ranges.get_mut(range) {
                        record.refusals.retain(|r| r.doc != doc);
                    }
                    e.refuse(range, doc.clone(), reason);
                }
                Fetched::Closed => {}
            });
        }
        Ok(Fetched::Refused(String::new()))
    }

    /// A short write-locked edit of one face's engine.
    fn with_engine<R>(&self, face: Face, f: impl FnOnce(&mut Engine) -> R) -> Option<R> {
        let mut guard = self.write();
        let Mount::Live(live) = &mut *guard else { return None };
        Self::engine_of_mut(live, face).map(f)
    }

    /// A short read-locked look at one face's engine.
    fn read_live<R>(&self, face: Face, f: impl FnOnce(&Engine) -> R) -> Option<R> {
        let guard = self.read();
        let Mount::Live(live) = &*guard else { return None };
        Self::engine_of(live, face).map(f)
    }

    /// THE PLAN of one page under the read side: the distinct documents its
    /// rows name with the member each is read at, the bare rows, the head
    /// rows, the pending joins it settles.
    fn plan(&self, face: Face, range: usize, page: &ChangesPage, recent: &BTreeMap<Address, u64>) -> Plan {
        let guard = self.read();
        let engine = match &*guard {
            Mount::Live(live) => Self::engine_of(live, face),
            _ => None,
        };
        let mut plan = Plan { reads: Vec::new(), bare: 0, head_rows: Vec::new(), head_moves: Vec::new(), install: Vec::new(), discard: Vec::new() };
        let Some(engine) = engine else { return plan };
        let head_doc = parse_address(HEAD_DOCUMENT).expect("the head document's address");
        let mut changed: BTreeMap<Address, u64> = BTreeMap::new();
        let mut heads: BTreeMap<Address, Address> = BTreeMap::new();
        let mut rows: Vec<(u64, Address)> = Vec::new();
        for row in &page.changes {
            let op = row["op"].as_str();
            let at = row["at"].as_u64().unwrap_or(0);
            let docs = match row["docs"].as_array() {
                Some(docs) => docs,
                None => {
                    if matches!(op, None | Some("publish")) {
                        plan.bare += 1;
                    }
                    continue;
                }
            };
            for d in docs.iter().filter_map(Value::as_str) {
                let Some(addr) = parse_address(d) else { continue };
                let Some(doc) = bare_document(&addr) else { continue };
                if addr != doc && face == Face::Published {
                    let current = heads.get(&doc).or_else(|| engine.heads.get(&doc));
                    if let Some(new_head) = moved_head(&doc, current, &addr) {
                        if row["key"].as_str() == Some("system") && op == Some("publish") && doc == head_doc {
                            plan.head_rows.push(new_head.clone());
                        }
                        heads.insert(doc.clone(), new_head);
                    }
                }
                rows.push((at, doc.clone()));
                let latest = changed.entry(doc).or_insert(at);
                *latest = (*latest).max(at);
            }
        }
        for (i, pending) in engine.pending.iter().enumerate() {
            if pending.range != range {
                continue;
            }
            let straddled = rows.iter().any(|(at, doc)| *doc == pending.doc && *at > pending.first && *at <= pending.last);
            if straddled {
                plan.discard.push(i);
            } else {
                plan.install.push(i);
            }
        }
        for (doc, latest) in changed {
            if recent.get(&doc).is_some_and(|read_at| *read_at >= latest) {
                continue;
            }
            let read = match face {
                Face::Published => {
                    let member = heads.get(&doc).or_else(|| engine.heads.get(&doc)).cloned();
                    let probe = member.is_none() && !engine.places.get(&doc).is_some_and(|r| r.member.is_none() && r.kind == Kind::Edition);
                    ReadPlan { doc, member, kind: Kind::Edition, probe }
                }
                Face::Supplement(_) => ReadPlan { member: Some(doc.clone()), doc, kind: Kind::Draft, probe: false },
            };
            plan.reads.push(read);
        }
        plan.head_moves = heads.into_iter().collect();
        plan
    }

    /// ONE READ of a document (`search.md` §2.1): the trunk probed where the
    /// head is unknown, then `span_set` and `retrieve_v` in parts over the
    /// extent — token-free at guest class for the published index, under the
    /// session's token at the principal's class for the supplement — and
    /// `prepare` outside every lock.
    fn read_document(&self, token: Option<&Token>, class: Class, read: &ReadPlan) -> Result<Fetched, Halt> {
        let mut member = read.member.clone();
        if read.probe {
            member = self.probe_head(&read.doc)?;
        }
        let target = member.clone().unwrap_or_else(|| read.doc.clone());
        let unit_member = match read.kind {
            Kind::Draft => Some(read.doc.clone()),
            Kind::Edition => member.clone(),
        };
        let extent_answer = match self.board.op(token, &frames::span_set(&target.to_string()))? {
            Answer::Closed => return Ok(Fetched::Closed),
            Answer::Document(v) => v,
        };
        if let Some(r) = Rejection::of(&extent_answer) {
            return Ok(Fetched::Refused(r.key().to_string()));
        }
        let extent = answers::content_extent(&extent_answer);
        let mut items: Vec<Item> = Vec::new();
        let mut first: Option<u64> = None;
        let mut last = extent_answer["as_of"].as_u64().unwrap_or(0);
        let mut parts = 0;
        let mut from = 1;
        while from <= extent {
            let width = MAX_DELIVERY_ITEMS.min(extent - from + 1);
            let v = match self.board.op(token, &frames::retrieve_v(&target.to_string(), from, width))? {
                Answer::Closed => return Ok(Fetched::Closed),
                Answer::Document(v) => v,
            };
            if let Some(r) = Rejection::of(&v) {
                return Ok(Fetched::Refused(r.key().to_string()));
            }
            let Some((delivered, as_of)) = answers::delivery(&v) else {
                return Ok(Fetched::Refused("not_a_delivery".to_string()));
            };
            items.extend(items_of(delivered, from));
            first.get_or_insert(as_of);
            last = as_of;
            parts += 1;
            from += width;
        }
        let unit = match Unit::new(UnitKey::new(read.doc.clone()), unit_member.clone(), read.kind, class, last, items) {
            Ok(unit) => unit,
            Err(e) => return Ok(Fetched::Refused(format!("discontiguous:{e}"))),
        };
        Ok(Fetched::Unit { prepared: Index::prepare(unit), member, kind: read.kind, first: first.unwrap_or(last), last, parts })
    }

    /// THE TRUNK PROBE (`search.md` §2.4): `doc_metadata` over `D.1`, `D.2`,
    /// … until `doc_not_registered`; the last registered member is the head,
    /// `None` for a published document without a member.
    fn probe_head(&self, doc: &Address) -> Result<Option<Address>, Halt> {
        let mut head = None;
        for k in 1..=PROBE_BOUND {
            let Some(member) = member_of(doc, k) else { break };
            let v = self.board.guest(&frames::doc_metadata(&member.to_string()))?;
            if Rejection::of(&v).is_some() || answers::published(&v).is_none() {
                break;
            }
            head = Some(member);
        }
        Ok(head)
    }

    /// THE PAGE APPLIED under the write side: the pending joins settled, each
    /// read merged or its refusal recorded, the bare rows counted, the head
    /// record kept, the cursor advanced.
    fn apply(&self, face: Face, range: usize, page: &ChangesPage, plan: Plan, reads: Vec<Fetched>, head_records: Vec<HeadRecord>) {
        let mut guard = self.write();
        let Mount::Live(live) = &mut *guard else { return };
        let Some(engine) = Self::engine_of_mut(live, face) else { return };
        // The pending joins this page settles: installed where no row straddled
        // the parts, discarded — and re-read by this page's own plan — where
        // one did.
        let mut settled: Vec<usize> = plan.install.iter().chain(&plan.discard).copied().collect();
        settled.sort_unstable();
        for i in settled.into_iter().rev() {
            let pending = engine.pending.remove(i);
            if plan.install.contains(&i) {
                engine.merge(pending.prepared, pending.range, Kind::Draft, Some(pending.doc.clone()));
            }
        }
        for (doc, head) in plan.head_moves {
            engine.heads.insert(doc, head);
        }
        for (read, planned) in reads.into_iter().zip(plan.reads) {
            match read {
                Fetched::Unit { prepared, member, kind, first, last, parts } => {
                    if kind == Kind::Draft && parts > 1 && first != last {
                        engine.pending.push(PendingJoin { range, doc: planned.doc, prepared, first, last });
                        continue;
                    }
                    if let Some(member) = &member {
                        engine.heads.insert(planned.doc.clone(), member.clone());
                    }
                    engine.merge(prepared, range, kind, member);
                }
                Fetched::Refused(reason) => engine.refuse(range, planned.doc, reason),
                Fetched::Closed => {}
            }
        }
        if plan.bare > 0 {
            engine.header.ranges[range].bare_rows += plan.bare;
            engine.dirty = true;
        }
        for record in head_records {
            let newer = engine.header.head.as_ref().is_none_or(|h| h.member < record.member);
            if newer {
                engine.header.head = Some(record);
                engine.dirty = true;
            }
        }
        engine.cursors[range] = page.last;
        if engine.building.is_some() {
            engine.building = Some(page.last);
        }
    }

    /// THE DISCOVERY READS (`client.md` §4e.3; R90 (b)): the principal-keyed
    /// grant-typed query and `universal_grants`, beside each other; the
    /// honored set they answer, or `None` where the session met the death
    /// signal.
    fn discover(&self, principal: u64) -> Result<Option<Vec<Honored>>, Halt> {
        let (token, account, known) = {
            let guard = self.read();
            let Mount::Live(live) = &*guard else { return Ok(Some(Vec::new())) };
            let Some(s) = live.supplements.get(&principal) else { return Ok(Some(Vec::new())) };
            (s.token.clone(), s.account.clone(), s.links.clone())
        };
        let mut links = known;
        let v = match self.board.op(Some(&token), &frames::find_links_ftt(T_GRANT, &account.to_string()))? {
            Answer::Closed => return Ok(None),
            Answer::Document(v) => v,
        };
        let mut named: Vec<Honored> = Vec::new();
        if Rejection::of(&v).is_none() {
            let addrs: Vec<String> = answers::addrs(&v).into_iter().map(str::to_string).collect();
            for link in &addrs {
                if links.contains_key(link) {
                    continue;
                }
                let v = match self.board.op(Some(&token), &frames::read_link(link))? {
                    Answer::Closed => return Ok(None),
                    Answer::Document(v) => v,
                };
                let read = match (answers::link_from(&v).and_then(parse_address), answers::link_to(&v).and_then(parse_address)) {
                    (Some(from), Some(to)) if to == account => match from.level() {
                        Level::Document | Level::Account => {
                            let issuer = parse_address(link).and_then(|l| account_of(&l));
                            match issuer {
                                Some(issuer) => GrantLink::Grant { prefix: from, issuer },
                                None => GrantLink::Other,
                            }
                        }
                        Level::Element => GrantLink::Revocation { of: from.to_string() },
                        Level::Node => GrantLink::Other,
                    },
                    _ => GrantLink::Other,
                };
                links.insert(link.clone(), read);
            }
            let revoked: BTreeSet<&str> = links
                .values()
                .filter_map(|l| match l {
                    GrantLink::Revocation { of } => Some(of.as_str()),
                    _ => None,
                })
                .collect();
            for (address, link) in &links {
                if let GrantLink::Grant { prefix, issuer } = link {
                    if addrs.contains(address) && !revoked.contains(address.as_str()) {
                        named.push(Honored { prefix: prefix.clone(), grant: Grant { kind: GrantKind::Named, issuer: issuer.clone() } });
                    }
                }
            }
        }
        let v = match self.board.op(Some(&token), &frames::universal_grants())? {
            Answer::Closed => return Ok(None),
            Answer::Document(v) => v,
        };
        for (prefix, issuers) in answers::universal_rows(&v) {
            let (Some(prefix), Some(issuer)) = (parse_address(prefix), issuers.first().and_then(|i| parse_address(i))) else { continue };
            named.push(Honored { prefix, grant: Grant { kind: GrantKind::AnyPrincipal, issuer } });
        }
        if let Mount::Live(live) = &mut *self.write() {
            if let Some(s) = live.supplements.get_mut(&principal) {
                s.links = links;
            }
        }
        Ok(Some(named))
    }

    /// The honored set adopted: a prefix new to the supplement's header is a
    /// WIDENING at a fold-honored grant — a range from the floor, its grant's
    /// cell keys written beside it (`search.md` §3.1, §4).
    fn adopt_honored(&self, principal: u64, honored: Vec<Honored>) {
        let mut guard = self.write();
        let Mount::Live(live) = &mut *guard else { return };
        let Some(s) = live.supplements.get_mut(&principal) else { return };
        if let Slot::Engine(engine) = &mut s.slot {
            for h in &honored {
                let known = engine.header.ranges.iter().any(|r| r.under.as_ref() == Some(&h.prefix));
                if !known {
                    engine.add_range(Some(h.prefix.clone()), Some(h.grant.clone()));
                }
            }
        }
        s.honored = honored;
    }

    /// WIDEN (`client.md` §4e.3) at a session open, a principal switch, a
    /// re-mount: the principal's supplement opened — the aside check and the
    /// resume as at the published index — its ranges the principal's own
    /// account prefix, its ancestors' and each honored grant's, each fetched
    /// from its own `held` or from the floor where new, the state `Widening`
    /// while each fetches and `Complete` after.
    pub fn widen(&self, session: SessionRef<'_>) -> Result<(), Halt> {
        let _feed = self.feed.lock().expect("the feed mutex");
        if matches!(&*self.read(), Mount::Unclaimed) {
            self.mount()?;
        }
        let principal = session.principal;
        let account = parse_address(session.account).ok_or_else(|| {
            Halt::face(
                "the session's account is no address",
                format!("`principal_prefix({principal})` answered text the address grammar refuses"),
                "check the board",
            )
        })?;
        let (dir, chain, mounted) = match &*self.read() {
            Mount::Live(live) => (live.dir.clone(), live.chain, live.supplements.contains_key(&principal)),
            _ => return Ok(()),
        };
        if !mounted {
            let slot = self.open_slot(&dir, &chain, Class::Principal(principal), &BoardDir::supplement_name(principal), &BoardDir::supplement_places_name(principal))?;
            if let Mount::Live(live) = &mut *self.write() {
                live.supplements.insert(principal, Supplement { slot, token: session.token.clone(), account: account.clone(), honored: Vec::new(), links: BTreeMap::new() });
            }
        } else if let Mount::Live(live) = &mut *self.write() {
            if let Some(s) = live.supplements.get_mut(&principal) {
                s.token = session.token.clone();
            }
        }
        // The subtree's ranges: the account and its ancestors.
        let mut prefixes = vec![account.clone()];
        let mut at = account.to_string();
        while let Some(parent) = parent_account(&at) {
            if let Some(addr) = parse_address(&parent) {
                prefixes.push(addr);
            }
            at = parent;
        }
        self.with_engine(Face::Supplement(principal), |e| {
            for prefix in &prefixes {
                if !e.header.ranges.iter().any(|r| r.under.as_ref() == Some(prefix)) {
                    e.add_range(Some(prefix.clone()), None);
                }
            }
        });
        match self.discover(principal)? {
            Some(honored) => self.adopt_honored(principal, honored),
            None => return self.unmount(principal),
        }
        let pair = self.health_pair()?;
        let mut outcome = Poll::default();
        if let Drained::Closed = self.drain(Face::Supplement(principal), &pair, &mut outcome, true)? {
            self.unmount(principal)?;
        }
        self.maybe_save(false)
    }

    /// NARROW (`client.md` §4e.3) at `close(session)`, at `session-died` in
    /// every arm but the shell's own restart, and at a switch-away: the
    /// supplement saved and UNMOUNTED, its file kept (`search.md` §5.5), the
    /// document index's principal part retired from `places` with it.
    pub fn narrow(&self, principal: u64) -> Result<(), Halt> {
        let _feed = self.feed.lock().expect("the feed mutex");
        self.save_face(Face::Supplement(principal), true)?;
        self.unmount(principal)
    }

    fn unmount(&self, principal: u64) -> Result<(), Halt> {
        if let Mount::Live(live) = &mut *self.write() {
            live.supplements.remove(&principal);
        }
        Ok(())
    }

    /// THE REFRESH (`search.md` §5.5; `client.md` §4b.1's `opts.reindex`):
    /// every unit the pair holds RE-READ at its own class — the published
    /// units token-free, the supplement's at the principal's — enumerated by
    /// `keys_by_range` over each range, each replaced as any re-read is, and
    /// NOTHING DROPPED: a unit whose re-read is refused keeps its text and
    /// records its refusal; the bare-row counts cleared; `Building` while it
    /// runs; the guest form refreshing the published index alone.
    pub fn reindex(&self, who: Who<'_>) -> Result<(), Halt> {
        let _feed = self.feed.lock().expect("the feed mutex");
        let mut faces = vec![Face::Published];
        if let Some(principal) = who.principal() {
            if self.mounted(principal) {
                faces.push(Face::Supplement(principal));
            }
        }
        for face in faces {
            self.refresh(face)?;
        }
        self.maybe_save(true)
    }

    fn refresh(&self, face: Face) -> Result<(), Halt> {
        let (token, class, keys) = {
            let guard = self.read();
            let Mount::Live(live) = &*guard else { return Ok(()) };
            let Some(engine) = Self::engine_of(live, face) else { return Ok(()) };
            let token = match face {
                Face::Published => None,
                Face::Supplement(n) => live.supplements.get(&n).map(|s| s.token.clone()),
            };
            let mut keys: Vec<(usize, Address)> = Vec::new();
            let mut seen: BTreeSet<Address> = BTreeSet::new();
            for (i, range) in engine.header.ranges.iter().enumerate() {
                let prefix = range.under.clone().map(Prefix::new).unwrap_or_else(|| live.node.clone());
                for key in engine.index.keys_by_range(&prefix) {
                    if seen.insert(key.doc().clone()) {
                        keys.push((i, key.doc().clone()));
                    }
                }
            }
            (token, engine.class, keys)
        };
        self.with_engine(face, |e| e.building = Some(e.header.ranges.iter().map(|r| r.held.position).min().unwrap_or(0)));
        let ranges = self.read_live(face, |e| e.header.ranges.len()).unwrap_or(0);
        for range in 0..ranges {
            if let Fetched::Closed = self.retry_refusals(face, range, token.as_ref(), class)? {
                return Ok(());
            }
        }
        for (range, doc) in keys {
            let plan = {
                let guard = self.read();
                let engine = match &*guard {
                    Mount::Live(live) => Self::engine_of(live, face),
                    _ => None,
                };
                let Some(engine) = engine else { return Ok(()) };
                match face {
                    Face::Published => {
                        let member = engine.heads.get(&doc).cloned();
                        let probe = member.is_none() && !engine.places.get(&doc).is_some_and(|r| r.member.is_none());
                        ReadPlan { doc: doc.clone(), member, kind: Kind::Edition, probe }
                    }
                    Face::Supplement(_) => ReadPlan { doc: doc.clone(), member: Some(doc.clone()), kind: Kind::Draft, probe: false },
                }
            };
            let read = self.read_document(token.as_ref(), class, &plan)?;
            self.with_engine(face, |e| match read {
                Fetched::Unit { prepared, member, kind, .. } => {
                    if let Some(member) = &member {
                        e.heads.insert(doc.clone(), member.clone());
                    }
                    e.merge(prepared, range, kind, member);
                }
                Fetched::Refused(reason) => e.refuse(range, doc.clone(), reason),
                Fetched::Closed => {}
            });
        }
        self.with_engine(face, |e| {
            for range in &mut e.header.ranges {
                range.bare_rows = 0;
            }
            e.building = None;
            e.dirty = true;
        });
        Ok(())
    }

    /// THE ORPHAN TEST (`search.md` §5.5; sr-S1; PATTERNS P17): for each
    /// supplement in the board's directory, the walk upward from
    /// `principal_prefix(n)` and ONE `key_set` read at its terminus — orphaned
    /// where no fingerprint the store holds (`held_keys`) stands in its
    /// `enrolled`. Made at the directory's open beside the resume check, by
    /// the shell, and never on the keystroke path; the forget offer is the
    /// shell's own window's.
    pub fn orphans(&self, held_keys: &[Fingerprint]) -> Result<Vec<Orphan>, Halt> {
        let dir = match &*self.read() {
            Mount::Live(live) => live.dir.clone(),
            _ => match self.board.board_term()? {
                Some(term) => self.dir.board(&Chain::from_bytes(term.chain)),
                None => return Ok(Vec::new()),
            },
        };
        let mut orphans = Vec::new();
        for principal in dir.supplements().map_err(|e| io_halt("listing", dir.path(), e))? {
            let Some(account) = self.board.principal_prefix(principal)? else {
                orphans.push(Orphan { principal, account: None });
                continue;
            };
            let mut at = account.clone();
            let opened = loop {
                match self.board.key_set(&at)? {
                    KeySetAnswer::NotAnAccount => break false,
                    KeySetAnswer::Set(set) if !set.is_empty() => {
                        break set.enrolled.iter().any(|e| held_keys.contains(&e.fingerprint));
                    }
                    KeySetAnswer::Set(_) => match parent_account(&at) {
                        Some(parent) => at = parent,
                        None => break false,
                    },
                }
            };
            if !opened {
                orphans.push(Orphan { principal, account: Some(account) });
            }
        }
        Ok(orphans)
    }

    /// FORGET (`search.md` §5.5): the supplement of `principal` unmounted
    /// where mounted and its two files deleted — the person's act alone,
    /// offered by the shell off [`Consumer::orphans`].
    pub fn forget(&self, principal: u64) -> Result<(), Halt> {
        let _feed = self.feed.lock().expect("the feed mutex");
        let dir = match &*self.read() {
            Mount::Live(live) => live.dir.clone(),
            _ => match self.board.board_term()? {
                Some(term) => self.dir.board(&Chain::from_bytes(term.chain)),
                None => return Ok(()),
            },
        };
        self.unmount(principal)?;
        for name in [BoardDir::supplement_name(principal), BoardDir::supplement_places_name(principal)] {
            match fs::remove_file(dir.file(&name)) {
                Ok(()) => {}
                Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                Err(e) => return Err(io_halt("forget", &dir.file(&name), e)),
            }
        }
        Ok(())
    }

    /// THE SAVE, forced: every mounted index written by rename, compacted
    /// first where due.
    pub fn save(&self) -> Result<(), Halt> {
        let _feed = self.feed.lock().expect("the feed mutex");
        self.maybe_save(true)
    }

    /// THE CLOSE: the save at the shell's exit; the lock dies with the value.
    pub fn close(self) -> Result<(), Halt> {
        self.save()
    }

    fn maybe_save(&self, force: bool) -> Result<(), Halt> {
        let faces: Vec<Face> = match &*self.read() {
            Mount::Live(live) => std::iter::once(Face::Published).chain(live.supplements.keys().map(|n| Face::Supplement(*n))).collect(),
            _ => Vec::new(),
        };
        for face in faces {
            self.save_face(face, force)?;
        }
        Ok(())
    }

    /// One face saved where its cadence is due: `held` fixed by
    /// `GET /chain?at` for a range no draining poll fenced, the compaction
    /// where due — `compacted` under the read side, `install` under the write
    /// side — the file serialized under the read side and written by rename.
    fn save_face(&self, face: Face, force: bool) -> Result<(), Halt> {
        let (dir, fixes, compacted) = {
            let guard = self.read();
            let Mount::Live(live) = &*guard else { return Ok(()) };
            let Some(engine) = Self::engine_of(live, face) else { return Ok(()) };
            let due = engine.changed >= SAVE_EVERY_UNITS || engine.last_save.elapsed() >= SAVE_EVERY;
            if !(force || (engine.dirty && due)) || !engine.dirty && !force {
                return Ok(());
            }
            let fixes: Vec<(usize, u64)> = engine
                .header
                .ranges
                .iter()
                .zip(&engine.cursors)
                .enumerate()
                .filter(|(i, (r, c))| r.held.position < **c && !engine.pending.iter().any(|p| p.range == *i))
                .map(|(i, (_, c))| (i, *c))
                .collect();
            let compacted = engine.index.compaction_due().then(|| engine.index.compacted());
            (live.dir.clone(), fixes, compacted)
        };
        let mut fixed: Vec<(usize, ChainAt)> = Vec::new();
        for (i, position) in fixes {
            if let ChainAtAnswer::Chain { chain, .. } = self.board.chain_at(position)? {
                fixed.push((i, ChainAt { position, chain: Chain::from_bytes(chain) }));
            }
        }
        self.with_engine(face, |e| {
            if let Some(compacted) = compacted {
                e.index.install(compacted);
            }
            for (i, held) in fixed {
                e.header.ranges[i].held = held;
            }
        });
        let (name, bytes, places_name, places_bytes) = {
            let guard = self.read();
            let Mount::Live(live) = &*guard else { return Ok(()) };
            let Some(engine) = Self::engine_of(live, face) else { return Ok(()) };
            let mut bytes = Vec::new();
            engine.index.save(&engine.header, &mut bytes).map_err(|e| {
                Halt::face(format!("the search index could not be serialized: {e}"), "the crate's writer failed", "check the data directory")
            })?;
            (engine.name.clone(), bytes, engine.places_name.clone(), engine.places.encode())
        };
        dir.write_whole(&name, &bytes).map_err(|e| io_halt("save", &dir.file(&name), e))?;
        dir.write_whole(&places_name, &places_bytes).map_err(|e| io_halt("save", &dir.file(&places_name), e))?;
        self.with_engine(face, |e| {
            e.changed = 0;
            e.dirty = false;
            e.last_save = Instant::now();
        });
        Ok(())
    }

    /// THE STATE of the pair a face searches (`client.md` §4b.2, §4e.5):
    /// the guest form's from the published index alone, a session's from it
    /// and that principal's supplement.
    pub fn state(&self, who: Who<'_>) -> State {
        let guard = self.read();
        match &*guard {
            Mount::Unclaimed => State::None,
            Mount::Busy => State::Busy,
            Mount::Live(live) => {
                let mut parts = Vec::new();
                match part_of(&live.published) {
                    Some(part) => parts.push(part),
                    None => return State::Busy,
                }
                if let Some(principal) = who.principal() {
                    if let Some(s) = live.supplements.get(&principal) {
                        match part_of(&s.slot) {
                            Some(part) => parts.push(part),
                            None => return State::Busy,
                        }
                    }
                }
                State::compose(&parts)
            }
        }
    }

    /// THE COUNTS PER ACCOUNT the plane reads (A-255), at the call's class:
    /// the published part's, with the principal's part's added for a
    /// session.
    pub fn counts(&self, who: Who<'_>) -> BTreeMap<Address, usize> {
        let guard = self.read();
        let mut counts = BTreeMap::new();
        let Mount::Live(live) = &*guard else { return counts };
        let mut parts = vec![&live.published];
        if let Some(principal) = who.principal() {
            if let Some(s) = live.supplements.get(&principal) {
                parts.push(&s.slot);
            }
        }
        for slot in parts {
            if let Slot::Engine(e) = slot {
                for (account, n) in e.places.counts() {
                    *counts.entry(account).or_insert(0) += n;
                }
            }
        }
        counts
    }
}

impl Engine {
    /// A range added at a widening (`search.md` §4): from the floor where
    /// new — its pair the genesis seed at 0 until a drain fixes it.
    fn add_range(&mut self, under: Option<Address>, grant: Option<Grant>) {
        self.header.ranges.push(RangeRecord { under, held: ChainAt { position: 0, chain: zero_chain() }, refusals: Vec::new(), bare_rows: 0, grant });
        self.cursors.push(self.header.floor.unwrap_or(0));
        self.dirty = true;
    }

    /// A prepared unit merged under the write side (`search.md` §1.4): the
    /// class check and the ceiling the crate's; the places row written from
    /// the same delivery; a recorded refusal of the document cleared.
    fn merge(&mut self, prepared: Prepared, range: usize, kind: Kind, member: Option<Address>) {
        let doc = prepared.key().doc().clone();
        let label = Places::first_line(prepared.unit());
        match self.index.merge(prepared) {
            Ok(()) => {
                self.changed += 1;
                self.dirty = true;
                self.places.record(doc.clone(), PlaceRecord { kind, member, label });
                if let Some(record) = self.header.ranges.get_mut(range) {
                    record.refusals.retain(|r| r.doc != doc);
                }
            }
            Err(IndexError::PastTheCeiling { .. }) => self.dirty = true,
            Err(_) => {}
        }
    }

    /// A read's refusal RECORDED beside the range (`search.md` §4): the
    /// document and the wire's word, once per document.
    fn refuse(&mut self, range: usize, doc: Address, reason: String) {
        if let Some(record) = self.header.ranges.get_mut(range) {
            if !record.refusals.iter().any(|r| r.doc == doc) {
                record.refusals.push(Refusal { doc, reason });
                self.dirty = true;
            }
        }
    }
}

/// The composition's part for a slot: `None` for a pending resume, which
/// the state answers as busy.
fn part_of(slot: &Slot) -> Option<Part<'_>> {
    match slot {
        Slot::Faced(newer) => Some(Part::Faced(newer.clone())),
        Slot::Pending => None,
        Slot::Engine(e) => Some(Part::Index(Facts {
            stats: e.index.stats(),
            header: &e.header,
            building: e.building,
            widening: e.widening.clone(),
            resumed: e.resumed,
            lost: e.lost.clone(),
            aside: e.aside,
        })),
    }
}

/// What the resume decided for a loaded file.
enum Resumed {
    /// Each range's fetch fence, and the floor the ranges resumed from with
    /// the pair they held, where the open met `history_reclaimed`.
    Cursors(Vec<u64>, Option<(u64, ChainAt)>),
    /// The history diverged: the file moved aside with the saved pair.
    Aside(ChainAt),
    /// `history_busy` past its retries: the open leaves the file and the
    /// next poll retries.
    Pending,
}

/// A fresh index of `class` for the board at `chain`: the published index
/// with its one range, the board's whole feed; a supplement with none, its
/// ranges a widening's.
fn fresh(class: Class, chain: &Chain) -> (Index, Header) {
    let ranges = match class {
        Class::Guest => vec![RangeRecord { under: None, held: ChainAt { position: 0, chain: zero_chain() }, refusals: Vec::new(), bare_rows: 0, grant: None }],
        Class::Principal(_) => Vec::new(),
    };
    (Index::new(class), Header { board: *chain, floor: None, ranges, head: None })
}

/// The first line of a file, its `\n` included.
fn first_line(bytes: &[u8]) -> Option<&[u8]> {
    bytes.iter().position(|&b| b == b'\n').map(|at| &bytes[..=at])
}

/// The wire's items typed as the index takes them (`search.md` §2.1), from
/// `from`, each at its start ordinal.
fn items_of(delivered: Vec<Delivered>, from: u64) -> Vec<Item> {
    let mut start = from;
    let mut items = Vec::with_capacity(delivered.len());
    for d in delivered {
        let item = match d {
            Delivered::Text(bytes) => Item::Text { start, bytes },
            Delivered::Atom => Item::Gap { start, width: 1, kind: GapKind::Atom },
            Delivered::Withheld { origin, width } => Item::Gap {
                start,
                width,
                kind: match parse_address(&origin) {
                    Some(origin) => GapKind::Withheld { origin },
                    None => GapKind::Unknown,
                },
            },
            Delivered::Unknown { width } => Item::Gap { start, width, kind: GapKind::Unknown },
        };
        start += item.width();
        items.push(item);
    }
    items
}

// ── THE LOOP's INPUT: `GET /events` ──────────────────────────────────────

/// A handle that stops an [`Events`] iterator from another thread: the next
/// silence or close ends it.
#[derive(Debug, Clone)]
pub struct Stop(Arc<AtomicBool>);

impl Stop {
    /// Stop the iterator at its next read.
    pub fn stop(&self) {
        self.0.store(true, Ordering::SeqCst);
    }
}

/// THE COMMIT STREAM as the shell's loop input (`client.md` §4e.2, §7;
/// wire.md §The commit stream): `GET /events` on the dialer's streamed form,
/// each `commit` event's `log_position` yielded — "React to movement by
/// re-querying", the shell's `poll` the reaction — the stream reconnected
/// where it closes or falls silent past the dialer's read bound, the initial
/// event after a reconnect "potentially having skipped history" and so a
/// poll like any other. The consumer is the shell's: this iterator carries
/// the transport alone and the THREAD it runs on is the embedder's.
pub struct Events<'b> {
    board: &'b Board,
    body: Option<Box<dyn BufRead + Send>>,
    stop: Arc<AtomicBool>,
    event: Option<String>,
    connected_once: bool,
}

/// The stream over `board`'s `/events`.
pub fn events(board: &Board) -> Events<'_> {
    Events { board, body: None, stop: Arc::new(AtomicBool::new(false)), event: None, connected_once: false }
}

impl Events<'_> {
    /// A handle to stop this iterator.
    pub fn stopper(&self) -> Stop {
        Stop(self.stop.clone())
    }

    fn connect(&mut self) -> Result<(), Halt> {
        let head = RequestHead { method: Method::Get, path: "/events".to_string(), headers: Vec::new(), content_length: None };
        let mut empty = io::empty();
        let resp = self.board.dialer().stream(self.board.dialed(), &head, &mut empty, &mut |_| {})?;
        if resp.status != 200 {
            return Err(Halt::Dial(crate::dial::DialError::Response(format!("`GET /events` answered {}", resp.status))));
        }
        let body: Box<dyn Read + Send> = resp.body;
        self.body = Some(Box::new(BufReader::new(body)));
        self.connected_once = true;
        Ok(())
    }
}

impl Iterator for Events<'_> {
    type Item = Result<u64, Halt>;

    fn next(&mut self) -> Option<Result<u64, Halt>> {
        loop {
            if self.stop.load(Ordering::SeqCst) {
                return None;
            }
            if self.body.is_none() {
                if self.connected_once {
                    thread::sleep(RECONNECT_WAIT);
                }
                if let Err(halt) = self.connect() {
                    return Some(Err(halt));
                }
            }
            let body = self.body.as_mut().expect("connected above");
            let mut line = String::new();
            match body.read_line(&mut line) {
                Ok(0) => {
                    self.body = None;
                    continue;
                }
                Ok(_) => {}
                Err(_) => {
                    // Silence past the dialer's read bound, or a broken
                    // connection: reconnected.
                    self.body = None;
                    continue;
                }
            }
            let line = line.trim_end_matches(['\r', '\n']);
            if let Some(event) = line.strip_prefix("event:") {
                self.event = Some(event.trim().to_string());
            } else if let Some(data) = line.strip_prefix("data:") {
                if self.event.as_deref() == Some("commit") {
                    let v: Value = serde_json::from_str(data.trim()).unwrap_or(Value::Null);
                    if let Some(position) = v["log_position"].as_u64() {
                        return Some(Ok(position));
                    }
                }
            } else if line.is_empty() {
                self.event = None;
            }
        }
    }
}
