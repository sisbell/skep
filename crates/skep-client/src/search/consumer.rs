//! The feed consumer, one per board.
//!
//! `client.md` §4e.2, §4e.3 and `search.md` §4, §5.1, §5.4, §5.5, §5.6 draw
//! it: [`Consumer`] owns the feeder's lock, the two indexes — the board's
//! published index and one supplement per mounted principal — the document
//! index's two parts beside them, the per-range records, and one read-write
//! lock around the engines, under which "the feed thread writes and the
//! bridge's search thread reads" (§5.6): `prepare` outside it, `merge` under
//! its write side, `compacted` under the read side then `install` under the
//! write side ahead of a compacting save, `save` and every query under the
//! read side.
//!
//! **The poll** ([`Consumer::poll`]): "`/changes` carries no text and no span
//! … so every content change costs one read of the changed document …
//! coalesced to one read per changed document per poll" (§4e.2). The
//! `/health` pair is read before the drain; the published index's range is
//! drained from its cursor as a guest — every document a plain page names
//! is published and is read token-free at guest class — and each mounted
//! supplement's ranges with the session's token over `drafts=true`, read at
//! the principal's class; the distinct documents a page names are read once
//! each — `retrieve_v` over the extent `span_set` answers, in parts past
//! [`MAX_DELIVERY_ITEMS`], an edition at its pinned member (the latest trunk
//! member a minting row named, `moved_head`, or the trunk probed with
//! `doc_metadata` until `doc_not_registered` where the feed names none,
//! §2.4), a draft in sequence, a straddled draft's join held pending until
//! the next page settles it (§2.1); each document lands as its read
//! returns, so a page holds one unit at a time, and a unit whose extent or
//! resident charge would pass the ceiling is refused before it is read
//! whole, the refusal counted in the state's `seen` (§7.4); a bare row
//! whose `op` is `null` or `publish` is counted against its range; a
//! range's `held` advances only behind a whole page — every document indexed
//! or its refusal recorded (`withheld`, `too_many_items`,
//! `unit_past_the_ceiling`), a transport error holding it — and is
//! fixed as the `/health` pair where the poll drained to `more: false`, by
//! `GET /chain?at=<position>` alone at a save no draining poll fenced (§5.1);
//! the newest `H.k` the feed delivered is kept as the header's head record,
//! off the read made of `H` at every `key: "system"` `publish` row (§5.4);
//! the discovery reads — the principal-keyed grant query and
//! `universal_grants` — run beside each poll and feed widen (§4e.3).
//!
//! **The save** comes every [`SAVE_EVERY_UNITS`] changed units or
//! [`SAVE_EVERY`] and at close — interim pins, `search.md` §7.1 —
//! compacting first where `compaction_due`, by the directory's rename. No
//! read the consumer makes carries a query term, and the reads are driven
//! by the board's commits, the open, the session's triggers and the
//! person's own acts, never by what the person reads or searches (§4e.2's
//! host-log sentence).
//!
//! **At open** ([`Consumer::open`]): an unclaimed board has no `H.1` and no
//! index (`State::None`); the feeder's lock held by another process mounts
//! nothing (`State::Busy`, §5.6); then the aside check — a CRC-valid file
//! naming another board, or a file naming another principal's class, is
//! moved aside under its own chain — and the resume: `GET /chain?at=<held>`
//! per saved pair, the saved `H.k` re-read byte-equal where the answer is
//! `history_reclaimed`, `Resume::judge` the verdict — `Equal` resumes,
//! `FromTheFloor` keeps the file and re-fixes each range at the floor, the
//! three divergences move the file aside with its pair and build fresh,
//! `history_busy` retries a bounded wait and is left pending for the next
//! poll past it — and the newer-skep dispositions as `LoadError` answers
//! them, a migrated index, which `Index::migrated_from` names, marked dirty
//! for its save (§5.4).
//!
//! **The triggers** (§4e.3): [`Consumer::widen`] at a session open and a
//! principal switch, and the poll's discovery reads at a discovered grant —
//! the ranges the principal's prefix, its ancestors' and each grant's, each
//! from its own `held` or from the floor where new; [`Consumer::narrow`] at
//! close, death and switch-away — the supplement unmounted, its file kept;
//! revocation no operation (R90).
//!
//! **The person's acts** (§5.5): [`Consumer::reindex`], the refresh — every
//! unit the pair holds re-read at its own class by `keys_by_range`, nothing
//! dropped — and [`Consumer::forget`], offered by the shell off
//! [`Consumer::orphans`] alone: the walk upward from `principal_prefix(n)`,
//! a `key_set` read at each account until one holds a set, judged at its
//! terminus. The loop's input is [`events`], the `/events` stream's commit
//! positions.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File};
use std::io::{self, BufRead, BufReader, Read};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::thread;
use std::time::{Duration, Instant};

use serde_json::Value;
use skep_address::{Address, Level, Nat};
use skep_identity::Fingerprint;
use skep_search::header;
use skep_search::{
    moved_head, Chain, ChainAnswer, ChainAt, Class, GapKind, Grant, GrantKind, HeadRecord, Header,
    Index, IndexError, Item, Kind, LoadError, Prefix, Prepared, RangeRecord, Refusal, Resume, Unit,
    UnitKey, CEILING_BYTES,
};

use crate::address::{parent_account, parse_address, within_principal_depth};
use crate::board::answers::{self, Delivered};
use crate::board::{frames, Answer, Board, ChainAtAnswer, ChangesAnswer, ChangesPage, ChangesQuery, KeySetAnswer, Rejection, Token, HEAD_DOCUMENT};
use crate::derive::too_deep;
use crate::dial::{Method, RequestHead};
use crate::halt::Halt;

use super::bridge::{SessionRef, Who};
use super::directory::{BoardDir, SearchDir};
use super::places::{account_of, bare_document, member_of, node_of, PlaceRecord, Places};
use super::state::{Facts, Lost, Newer, Part, Range, State, PAST_THE_CEILING};

/// The save's cadence in changed units (`client.md` §4e.2; `search.md` §7.1).
///
/// The pin: "every 64 changed units or 30 seconds and at the shell's exit
/// (interim pins)".
pub const SAVE_EVERY_UNITS: usize = 64;

/// The save's cadence in time (the same pin).
pub const SAVE_EVERY: Duration = Duration::from_secs(30);

/// `MAX_DELIVERY_ITEMS`, the delivery budget one `retrieve_v` is bounded by.
///
/// It is `crates/skep-retrieval/src/budget.rs`'s `1 << 17` (wire.md
/// §Content & provenance reads): a document past it is read in parts
/// (`search.md` §2.1). The number alone is mirrored here, as the index's
/// suite mirrors it.
pub const MAX_DELIVERY_ITEMS: u64 = 1 << 17;

/// The grants class type address.
///
/// It is the principal-keyed discovery read's `ty`, at its one home,
/// `board::frames`, which the `share` module names too.
pub use crate::board::frames::T_GRANT;

/// The resume's bounded wait on `history_busy`: this many retries.
///
/// Each comes after [`RESUME_RETRY_WAIT`], before the resume is left
/// pending.
const RESUME_RETRIES: usize = 10;

/// The wait between the resume's retries.
const RESUME_RETRY_WAIT: Duration = Duration::from_millis(100);

/// The trunk probe's bound in members (`search.md` §2.4).
///
/// The members are dense, so a probe ends at the first unregistered; the
/// bound is a guard.
const PROBE_BOUND: u64 = 1 << 20;

/// The reason recorded for a part that delivers past the span it asked.
///
/// It is recorded for no delivery at all too — the shell's own word.
const NOT_A_DELIVERY: &str = "not_a_delivery";

/// The reason recorded for a board's refusal off the wire's spelling.
const UNRECOGNIZED_REFUSAL: &str = "unrecognized_refusal";

/// The longest refusal recorded as the board spelled it.
const REFUSAL_BOUND: usize = 64;

/// The wait before the `/events` stream is dialed again after an attempt.
///
/// The attempt is a stream that ended, or a connect the board refused.
const RECONNECT_WAIT: Duration = Duration::from_millis(250);

/// The longest line the `/events` stream reads (wire.md §The commit stream).
///
/// An event is its position alone, at most 47 bytes, and 8 KiB is the bound
/// the wire puts on a feed row; a line past it ends the stream as a close
/// does.
pub(crate) const EVENT_LINE_BOUND: u64 = 8 * 1024;

/// The silence past which the `/events` stream is dead.
///
/// wire.md §The commit stream: "After 15 seconds of silence the daemon
/// writes the comment line `:ka` … Treat a stream silent well past that as
/// dead, and reconnect"; the bound is two keepalive intervals with no line.
pub(crate) const SILENCE_BOUND: Duration = Duration::from_secs(30);

/// The consumer, one per board (the module doc).
///
/// Every method but `close` takes `&self`: the mutating ones — `poll`,
/// `widen`, `narrow`, `reindex`, `forget`, `save` — serialize on one feed
/// mutex, the one writer, and may be called from the shell's feed thread;
/// `search` and `state` read under the engines' read side from any thread.
pub struct Consumer<'b> {
    board: &'b Board,
    dir: SearchDir,
    /// The one writer: the feed thread's calls run one at a time.
    feed: Mutex<()>,
    /// The read-write lock around the engines (`search.md` §5.6).
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
///
/// Beside them it holds the board's chain and the node's prefix.
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

/// One index's slot.
///
/// It is faced as a newer skep's, pending a busy resume, or live.
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
    /// Per range, the fetch fence: the last page's `last`.
    ///
    /// It is in memory; the durable position is the record's `held`.
    cursors: Vec<u64>,
    /// Drafts read in parts across a commit.
    ///
    /// They are held until the next page settles them (`search.md` §2.1).
    pending: Vec<PendingJoin>,
    /// The head members, document → `D.k`, for the published engine.
    ///
    /// A supplement's maps each draft to its own address.
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

/// A draft's join read in parts across a commit.
///
/// The next page's rows install or discard it (`search.md` §2.1).
struct PendingJoin {
    range: usize,
    doc: Address,
    prepared: Prepared,
    first: u64,
    last: u64,
}

/// One mounted principal's supplement.
///
/// It carries its slot, its session's token and account, its honored set
/// (`search.md` §3.1's inputs) and the grant-typed links it has read.
pub(super) struct Supplement {
    pub(super) slot: Slot,
    token: Token,
    account: Address,
    /// The prefixes the discovery reads currently honor, with their grants.
    pub(super) honored: Vec<Honored>,
    /// Every grant-typed link naming the principal, by address.
    ///
    /// They are the ones the discovery read has read — a link is immutable,
    /// so one read each.
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
    /// The principals whose session met the death signal on a read.
    ///
    /// Each is unmounted, the shell's `session-died` arm to face.
    pub died: Vec<u64>,
}

/// A supplement no key the store holds can open (`search.md` §5.5).
///
/// It is the forget offer's input.
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
    /// Opens the consumer over `board` and `dir` (the module doc).
    ///
    /// The board term is read for the directory's key, the lock taken, and
    /// the aside check and the resume run over the published index. An
    /// unclaimed board mounts nothing and answers `State::None`; a held lock
    /// mounts nothing and answers `State::Busy`.
    ///
    /// # Errors
    ///
    /// The board term's read; an I/O fault creating the directory, taking
    /// the lock, reading the index file or moving it aside, faced; the
    /// resume's `/chain` and head reads; an index file whose reader fails
    /// before any byte is judged, faced.
    ///
    /// # Panics
    ///
    /// Panics if the head document's pinned address does not parse or lies
    /// under no node; it does, so neither `expect` fires.
    pub fn open(board: &'b Board, dir: SearchDir) -> Result<Consumer<'b>, Halt> {
        let consumer = Consumer { board, dir, feed: Mutex::new(()), mount: RwLock::new(Mount::Unclaimed) };
        consumer.mount()?;
        Ok(consumer)
    }

    /// Returns the board this consumer feeds from.
    pub fn board(&self) -> &'b Board {
        self.board
    }

    /// Returns the search directory.
    pub fn dir(&self) -> &SearchDir {
        &self.dir
    }

    /// Returns the board's directory, where the board has one.
    ///
    /// # Panics
    ///
    /// Panics where the engines' lock is poisoned.
    pub fn board_dir(&self) -> Option<BoardDir> {
        match &*self.mount.read().expect("the engines' lock") {
            Mount::Live(live) => Some(live.dir.clone()),
            _ => None,
        }
    }

    /// Returns whether `principal`'s supplement is mounted.
    ///
    /// # Panics
    ///
    /// Panics where the engines' lock is poisoned.
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

    /// Opens one index file into a slot.
    ///
    /// Absent → fresh; loaded → the aside check and the resume; faced,
    /// damaged or misplaced as `LoadError` answers.
    ///
    /// # Errors
    ///
    /// An I/O fault reading the file or moving it aside, faced; the resume's
    /// halts; an index file whose reader fails before any byte is judged,
    /// faced.
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
                    // Another principal's holding, refused before its body:
                    // its own chain off its header line, by the crate's one
                    // parser.
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
                // widening, not a build.
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

    /// Moves the index file and its places part aside.
    ///
    /// They go under the file's own chain.
    ///
    /// # Errors
    ///
    /// An I/O fault moving either aside, faced.
    fn set_aside(&self, dir: &BoardDir, name: &str, places_name: &str, own: &Chain) -> Result<(), Halt> {
        dir.move_aside(name, own).map_err(|e| io_halt("aside", &dir.file(name), e))?;
        if dir.file(places_name).is_file() {
            dir.move_aside(places_name, own).map_err(|e| io_halt("aside", &dir.file(places_name), e))?;
        }
        Ok(())
    }

    /// Resumes a loaded file's ranges (`search.md` §5.4).
    ///
    /// The resume makes one `GET /chain?at` per distinct saved position, the
    /// `H.k` re-read where the answer is `history_reclaimed`, the verdict
    /// `Resume::judge`'s — and one more at the floor for each range resumed
    /// from it, to re-fix the range's pair there.
    ///
    /// # Errors
    ///
    /// A `/chain` read's or the head re-read's halt.
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

    /// Reads `GET /chain?at=<position>` as a `ChainAnswer`.
    ///
    /// `history_busy` is retried a bounded wait; `None` where it stayed busy.
    ///
    /// # Errors
    ///
    /// The `/chain` read's or the head re-read's halt.
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

    /// Re-reads the saved `H.k` as a guest.
    ///
    /// The answer is the pair its record names now, or `None` where the
    /// member is gone or holds no head record.
    ///
    /// # Errors
    ///
    /// The guest read's halt.
    fn reread_head(&self, record: &HeadRecord) -> Result<Option<ChainAt>, Halt> {
        let v = self.board.guest(&frames::retrieve_v(&record.member.to_string(), 1, 1))?;
        Ok(answers::head_pair(&v).map(|(position, chain)| ChainAt { position, chain: Chain::from_bytes(chain) }))
    }

    /// Reads the `/health` pair before a draining poll (`search.md` §5.1).
    ///
    /// # Errors
    ///
    /// The `/health` read's halt; a `/health` with no `chain_head`, as a
    /// response fault.
    fn health_pair(&self) -> Result<ChainAt, Halt> {
        let health = self.board.health()?;
        let chain = health.chain_head().ok_or_else(|| {
            Halt::Dial(crate::dial::DialError::Response("`/health` carried no `chain_head`".into()))
        })?;
        Ok(ChainAt { position: health.log_position(), chain: Chain::from_bytes(chain) })
    }

    /// Polls the feed once (the module doc).
    ///
    /// The poll reads the `/health` pair, drains the published range as a
    /// guest, makes each mounted supplement's discovery reads and drains its
    /// ranges with its token, and saves at its cadence.
    ///
    /// # Errors
    ///
    /// A read's halt — the board term at a first mount, the `/health` pair,
    /// the feed, a document, a head record, the discovery reads, `/chain` at
    /// a floor or a save; an I/O fault in the index directory, faced. A
    /// session that met the death signal is no error: it lands in
    /// [`Poll::died`].
    ///
    /// # Panics
    ///
    /// Panics where the feed mutex or the engines' lock is poisoned.
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

    /// Retries a published slot left pending by `history_busy` at the open.
    ///
    /// The file is re-opened and the resume retried.
    ///
    /// # Errors
    ///
    /// As `open_slot`'s.
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

    /// Returns the engine of a face under a guard, where it is live.
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

    /// Drains one face's ranges (the module doc).
    ///
    /// `widening` marks the state while each range fetches.
    ///
    /// # Errors
    ///
    /// A read's halt — the feed, a document, a head record, a recorded
    /// refusal's re-read, `/chain` at a floor or a save; an I/O fault at a
    /// save, faced. The session's death is `Drained::Closed`, no error.
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
        // The coalescing across this drain's ranges (§4e.2: "one read per
        // changed document per poll"): a document read on one range's page
        // is not read again for another range's row at or below that read's
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
            let mut reclaimed = false;
            let mut fenced = true;
            let under_text = under.as_ref().map(ToString::to_string);
            loop {
                let query = ChangesQuery { since: cursor, under: under_text.as_deref(), drafts, limit };
                match self.board.changes(token.as_ref(), &query)? {
                    ChangesAnswer::Page(page) => {
                        outcome.pages += 1;
                        let mut plan = self.plan(face, i, &page, &recent);
                        self.settle_page(face, &mut plan);
                        // Each document lands as its read returns, so a page
                        // holds one unit at a time and a read that fails
                        // keeps what the reads before it landed; the cursor
                        // and `held` still move behind the whole page alone.
                        for read in &plan.reads {
                            let fetched = self.read_document(token.as_ref(), class, read)?;
                            match &fetched {
                                Fetched::Closed => return Ok(Drained::Closed),
                                Fetched::Unit { last, .. } => {
                                    recent.insert(read.doc.clone(), *last);
                                }
                                Fetched::Refused(_) => {}
                            }
                            outcome.documents += 1;
                            self.land_read(face, i, read, fetched);
                        }
                        let mut head_records = Vec::new();
                        for member in &plan.head_rows {
                            let v = self.board.guest(&frames::retrieve_v(&member.to_string(), 1, 1))?;
                            if let Some((position, chain)) = answers::head_pair(&v) {
                                head_records.push(HeadRecord { member: member.clone(), at: ChainAt { position, chain: Chain::from_bytes(chain) } });
                            }
                        }
                        self.close_page(face, i, &page, plan.bare, head_records);
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
                        if reclaimed {
                            // A second floor within one range's drain: the
                            // board reclaimed history while the drain ran. The
                            // range ends at this floor, held there, and the
                            // next poll drains on from it.
                            fenced = false;
                            break;
                        }
                        reclaimed = true;
                    }
                    ChangesAnswer::TooLarge { fits } => limit = Some(fits),
                    ChangesAnswer::Closed => return Ok(Drained::Closed),
                }
            }
            // The fence (`search.md` §5.1): every entry at or below the pair's
            // position lay on the pages that drained, so `held` is that pair —
            // unless a pending join still holds the range at its last page, or
            // the drain ended at a floor short of the pair.
            self.with_engine(face, |e| {
                if fenced && !e.pending.iter().any(|p| p.range == i) {
                    e.header.ranges[i].held = *pair;
                    e.dirty = true;
                }
                if e.cursors[i] < cursor {
                    e.cursors[i] = cursor;
                }
                e.widening = None;
                if fenced && e.building.is_some() && face == Face::Published {
                    e.building = None;
                }
            });
        }
        Ok(Drained::Done)
    }

    /// Re-reads one range's recorded refusals.
    ///
    /// `search.md` §4: "retried at the next widening of a range that covers
    /// it"; §5.5: the refresh over every range. Each document is read again
    /// at the face's class, indexed where the board now admits it — its
    /// record then cleared — or its refusal recorded afresh. Answers `Closed`
    /// where the session died.
    ///
    /// # Errors
    ///
    /// A document read's halt.
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
                    e.merge(prepared, kind, member);
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

    /// Makes a short write-locked edit of one face's engine.
    fn with_engine<R>(&self, face: Face, f: impl FnOnce(&mut Engine) -> R) -> Option<R> {
        let mut guard = self.write();
        let Mount::Live(live) = &mut *guard else { return None };
        Self::engine_of_mut(live, face).map(f)
    }

    /// Takes a short read-locked look at one face's engine.
    fn read_live<R>(&self, face: Face, f: impl FnOnce(&Engine) -> R) -> Option<R> {
        let guard = self.read();
        let Mount::Live(live) = &*guard else { return None };
        Self::engine_of(live, face).map(f)
    }

    /// Plans one page under the read side.
    ///
    /// The plan holds the distinct documents its rows name with the member
    /// each is read at, the bare rows, the head rows, the pending joins it
    /// settles.
    ///
    /// # Panics
    ///
    /// Panics if the head document's pinned address does not parse; it does,
    /// so the `expect` never fires. Panics where the engines' lock is
    /// poisoned.
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

    /// Reads one document (`search.md` §2.1).
    ///
    /// The trunk is probed where the head is unknown, then `span_set` and
    /// `retrieve_v` read in parts over the extent — token-free at guest class
    /// for the published index, under the session's token at the principal's
    /// class for the supplement — and `prepare` runs outside every lock. The
    /// board's word bounds nothing the read holds: an extent past the ceiling
    /// is refused unread — a position holds at most one byte of text, so such
    /// a document holds more text than the index admits or is that much gap,
    /// and reading it would take more parts than any unit within the ceiling
    /// needs; no part may deliver past the positions it asked; and the unit's
    /// resident charge is counted as its items are made and refused past the
    /// ceiling ([`items_of`]). A document refused so is never held whole to
    /// learn it, and its refusal, recorded beside its range, is a unit the
    /// state's `seen` counts: the index says what it left out.
    ///
    /// # Errors
    ///
    /// A read's halt — the trunk probe, `span_set` or a part's `retrieve_v`.
    /// The death signal is `Fetched::Closed` and a board's refusal
    /// `Fetched::Refused`, no error.
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
            return Ok(Fetched::Refused(refusal_reason(r.key())));
        }
        let extent = answers::content_extent(&extent_answer);
        if extent > CEILING_BYTES {
            return Ok(Fetched::Refused(PAST_THE_CEILING.to_string()));
        }
        let mut items: Vec<Item> = Vec::new();
        let mut charge: u64 = 0;
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
                return Ok(Fetched::Refused(refusal_reason(r.key())));
            }
            let Some((delivered, as_of)) = answers::delivery(&v) else {
                return Ok(Fetched::Refused(NOT_A_DELIVERY.to_string()));
            };
            if let Err(reason) = items_of(delivered, from, width, &mut charge, &mut items) {
                return Ok(Fetched::Refused(reason.to_string()));
            }
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

    /// Probes the trunk for the head member (`search.md` §2.4).
    ///
    /// The members are dense, so the head is the last registered member
    /// before the first `doc_not_registered` — found by `doc_metadata` over
    /// `D.1`, `D.2`, `D.4`, … doubling to the first unregistered, then
    /// bisecting between the two, in at most 2·log₂ [`PROBE_BOUND`] + 1 reads
    /// where a member at a time would read as many as the board claims;
    /// `None` for a published document without a member.
    ///
    /// # Errors
    ///
    /// A `doc_metadata` read's halt.
    fn probe_head(&self, doc: &Address) -> Result<Option<Address>, Halt> {
        if !self.registered(doc, 1)? {
            return Ok(None);
        }
        // `lo` registered, `hi` not (or past the bound).
        let (mut lo, mut hi) = (1u64, PROBE_BOUND + 1);
        let mut k = 2u64;
        while k <= PROBE_BOUND {
            if !self.registered(doc, k)? {
                hi = k;
                break;
            }
            lo = k;
            k *= 2;
        }
        while hi - lo > 1 {
            let mid = lo + (hi - lo) / 2;
            if self.registered(doc, mid)? {
                lo = mid;
            } else {
                hi = mid;
            }
        }
        Ok(member_of(doc, lo))
    }

    /// Returns whether the trunk member `D.k` of `doc` is registered.
    ///
    /// It is read off one `doc_metadata` read as a guest.
    ///
    /// # Errors
    ///
    /// The guest read's halt.
    fn registered(&self, doc: &Address, k: u64) -> Result<bool, Halt> {
        let Some(member) = member_of(doc, k) else { return Ok(false) };
        let v = self.board.guest(&frames::doc_metadata(&member.to_string()))?;
        Ok(Rejection::of(&v).is_none() && answers::published(&v).is_some())
    }

    /// Settles a page under the write side, ahead of its reads.
    ///
    /// It settles the pending joins — installed where no row straddled the
    /// parts, discarded, and re-read by this page's own plan, where one did —
    /// and the heads its rows moved.
    fn settle_page(&self, face: Face, plan: &mut Plan) {
        let mut guard = self.write();
        let Mount::Live(live) = &mut *guard else { return };
        let Some(engine) = Self::engine_of_mut(live, face) else { return };
        let mut settled: Vec<usize> = plan.install.iter().chain(&plan.discard).copied().collect();
        settled.sort_unstable();
        for i in settled.into_iter().rev() {
            let pending = engine.pending.remove(i);
            if plan.install.contains(&i) {
                engine.merge(pending.prepared, Kind::Draft, Some(pending.doc.clone()));
            }
        }
        for (doc, head) in std::mem::take(&mut plan.head_moves) {
            engine.heads.insert(doc, head);
        }
    }

    /// Lands one read under the write side as it returns.
    ///
    /// It is merged, held pending where a draft's parts straddled a commit,
    /// or its refusal recorded.
    fn land_read(&self, face: Face, range: usize, planned: &ReadPlan, read: Fetched) {
        let mut guard = self.write();
        let Mount::Live(live) = &mut *guard else { return };
        let Some(engine) = Self::engine_of_mut(live, face) else { return };
        match read {
            Fetched::Unit { prepared, member, kind, first, last, parts } => {
                if kind == Kind::Draft && parts > 1 && first != last {
                    engine.pending.push(PendingJoin { range, doc: planned.doc.clone(), prepared, first, last });
                    return;
                }
                if let Some(member) = &member {
                    engine.heads.insert(planned.doc.clone(), member.clone());
                }
                engine.merge(prepared, kind, member);
            }
            Fetched::Refused(reason) => engine.refuse(range, planned.doc.clone(), reason),
            Fetched::Closed => {}
        }
    }

    /// Closes a page under the write side, behind its last read.
    ///
    /// The bare rows are counted, the head record kept, the cursor advanced.
    fn close_page(&self, face: Face, range: usize, page: &ChangesPage, bare: u64, head_records: Vec<HeadRecord>) {
        let mut guard = self.write();
        let Mount::Live(live) = &mut *guard else { return };
        let Some(engine) = Self::engine_of_mut(live, face) else { return };
        if bare > 0 {
            engine.header.ranges[range].bare_rows += bare;
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

    /// Makes the discovery reads (`client.md` §4e.3; R90 (b)).
    ///
    /// They are the principal-keyed grant-typed query and
    /// `universal_grants`, beside each other; it answers the honored set
    /// they yield, or `None` where the session met the death signal.
    ///
    /// # Errors
    ///
    /// A read's halt — the grant query, a link's read or `universal_grants`.
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
            // The discovery's answer as a set: every link the supplement ever
            // read is tested against it once, in log time.
            let addrs: BTreeSet<String> = answers::addrs(&v).into_iter().map(str::to_string).collect();
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

    /// Adopts the honored set.
    ///
    /// A prefix new to the supplement's header is a widening at a
    /// fold-honored grant — a range from the floor, its grant's cell keys
    /// written beside it (`search.md` §3.1, §4).
    fn adopt_honored(&self, principal: u64, honored: Vec<Honored>) {
        let mut guard = self.write();
        let Mount::Live(live) = &mut *guard else { return };
        let Some(s) = live.supplements.get_mut(&principal) else { return };
        if let Slot::Engine(engine) = &mut s.slot {
            // The ranges' prefixes as a set: each honored prefix is tested
            // once, in log time, whatever count of grants the board names.
            let mut known: BTreeSet<Address> = engine.header.ranges.iter().filter_map(|r| r.under.clone()).collect();
            for h in &honored {
                if known.insert(h.prefix.clone()) {
                    engine.add_range(Some(h.prefix.clone()), Some(h.grant.clone()));
                }
            }
        }
        s.honored = honored;
    }

    /// Widens to `session`'s principal (`client.md` §4e.3).
    ///
    /// It runs at a session open, a principal switch, a re-mount: the
    /// principal's supplement opened — the aside check and the resume as at
    /// the published index — its ranges the principal's own account prefix,
    /// its ancestors' and each honored grant's, each fetched from its own
    /// `held` or from the floor where new, the state `Widening` while each
    /// fetches and, after, the one the pair composes.
    ///
    /// # Errors
    ///
    /// In this order: an account deeper than the namespace delegates,
    /// refused before any read; the board term's read and the directory's
    /// faults at a first mount; an account the address grammar refuses,
    /// faced; the supplement's open; the discovery reads' halts; the
    /// `/health` pair's; the drain reads' halts; a save's faults. A session
    /// that met the death signal is unmounted, no error.
    ///
    /// # Panics
    ///
    /// Panics where the feed mutex or the engines' lock is poisoned.
    pub fn widen(&self, session: SessionRef<'_>) -> Result<(), Halt> {
        let _feed = self.feed.lock().expect("the feed mutex");
        // The session's account is `principal_prefix`'s answer: one deeper
        // than the namespace delegates is the board's fault, refused before
        // its ancestors become ranges.
        if !within_principal_depth(session.account) {
            return Err(too_deep(session.account));
        }
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

    /// Narrows away from `principal` (`client.md` §4e.3).
    ///
    /// It runs at `close(session)`, at `session-died` in every arm but the
    /// shell's own restart, and at a switch-away: the supplement saved and
    /// unmounted, its file kept (`search.md` §5.5), the document index's
    /// principal part retired from `places` with it.
    ///
    /// # Errors
    ///
    /// The save's faults: a `/chain` read's halt, the serializer failing, an
    /// I/O fault writing a file, faced.
    ///
    /// # Panics
    ///
    /// Panics where the feed mutex or the engines' lock is poisoned.
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

    /// Refreshes every unit the pair holds (`search.md` §5.5).
    ///
    /// It is `client.md` §4b.1's `opts.reindex`: every unit re-read at its
    /// own class — the published units token-free, the supplement's at the
    /// principal's — enumerated by `keys_by_range` over each range, each
    /// replaced as any re-read is, and nothing dropped: a unit whose re-read
    /// is refused keeps its text and records its refusal; the bare-row
    /// counts cleared; `Building` while it runs; the guest form refreshing
    /// the published index alone.
    ///
    /// # Errors
    ///
    /// A re-read's halt; a save's faults.
    ///
    /// # Panics
    ///
    /// Panics where the feed mutex or the engines' lock is poisoned.
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
                    e.merge(prepared, kind, member);
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

    /// Finds the orphaned supplements (`search.md` §5.5; PATTERNS P17).
    ///
    /// For each supplement in the board's directory: the walk upward from
    /// `principal_prefix(n)`, a `key_set` read at each account until one
    /// holds a set — orphaned where no fingerprint the store holds
    /// (`held_keys`) stands in that set's `enrolled`, where the walk finds no
    /// set, or where the board no longer knows the principal; an account
    /// deeper than the namespace delegates is no orphan. Made at the
    /// directory's open beside the resume check, by the shell, and never on
    /// the keystroke path; the forget offer is the shell's own window's.
    ///
    /// # Errors
    ///
    /// The board term's read where nothing is mounted; an I/O fault listing
    /// the directory, faced; a `principal_prefix` or `key_set` read's halt.
    ///
    /// # Panics
    ///
    /// Panics where the engines' lock is poisoned.
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
            // An account deeper than the namespace delegates is the board's
            // fault, never the person's: no walk climbs it, and no forget is
            // offered on it.
            if !within_principal_depth(&account) {
                continue;
            }
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

    /// Forgets `principal`'s supplement (`search.md` §5.5).
    ///
    /// The supplement is unmounted where mounted and its two files deleted —
    /// the person's act alone, offered by the shell off
    /// [`Consumer::orphans`].
    ///
    /// # Errors
    ///
    /// The board term's read where nothing is mounted; an I/O fault deleting
    /// a file, faced — a file already absent is no fault.
    ///
    /// # Panics
    ///
    /// Panics where the feed mutex or the engines' lock is poisoned.
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

    /// Forces the save: every mounted index written by rename.
    ///
    /// Each is compacted first where due.
    ///
    /// # Errors
    ///
    /// A `/chain` read's halt fixing a range's `held`; the serializer
    /// failing, or an I/O fault writing a file, faced.
    ///
    /// # Panics
    ///
    /// Panics where the feed mutex or the engines' lock is poisoned.
    pub fn save(&self) -> Result<(), Halt> {
        let _feed = self.feed.lock().expect("the feed mutex");
        self.maybe_save(true)
    }

    /// Closes the consumer: the save at the shell's exit.
    ///
    /// The lock dies with the value.
    ///
    /// # Errors
    ///
    /// As [`Consumer::save`]'s.
    ///
    /// # Panics
    ///
    /// As [`Consumer::save`]'s.
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

    /// Saves one face where its cadence is due, or where `force` is set.
    ///
    /// `held` is fixed by `GET /chain?at` for a range no draining poll
    /// fenced, the compaction made where due — `compacted` under the read
    /// side, `install` under the write side — and the file serialized under
    /// the read side and written by rename.
    ///
    /// # Errors
    ///
    /// A `/chain` read's halt; the serializer failing, or an I/O fault
    /// writing a file, faced.
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

    /// Returns the state of the pair `who` searches.
    ///
    /// It is the guest form's from the published index alone, a session's
    /// from it and that principal's supplement where one is mounted
    /// (`client.md` §4b.2, §4e.5).
    ///
    /// # Panics
    ///
    /// Panics where the engines' lock is poisoned.
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

    /// Returns the counts per account the plane reads (A-255).
    ///
    /// They are at the call's class: the published part's, with the
    /// principal's part's added for a session whose supplement is mounted.
    ///
    /// # Panics
    ///
    /// Panics where the engines' lock is poisoned.
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
    /// Adds a range at a widening (`search.md` §4).
    ///
    /// It starts from the floor where new — its pair the genesis seed at 0
    /// until a drain fixes it.
    fn add_range(&mut self, under: Option<Address>, grant: Option<Grant>) {
        self.header.ranges.push(RangeRecord { under, held: ChainAt { position: 0, chain: zero_chain() }, refusals: Vec::new(), bare_rows: 0, grant });
        self.cursors.push(self.header.floor.unwrap_or(0));
        self.dirty = true;
    }

    /// Merges a prepared unit under the write side (`search.md` §1.4).
    ///
    /// The class check and the ceiling are the crate's; the places row is
    /// written from the same delivery; every recorded refusal of the document
    /// is cleared, whichever range recorded it — the index reads at its one
    /// class, so a unit it holds is a refusal no range still stands behind,
    /// and none of them composes a state after it.
    fn merge(&mut self, prepared: Prepared, kind: Kind, member: Option<Address>) {
        let doc = prepared.key().doc().clone();
        let label = Places::first_line(prepared.unit());
        match self.index.merge(prepared) {
            Ok(()) => {
                self.changed += 1;
                self.dirty = true;
                self.places.record(doc.clone(), PlaceRecord { kind, member, label });
                for record in &mut self.header.ranges {
                    record.refusals.retain(|r| r.doc != doc);
                }
            }
            Err(IndexError::PastTheCeiling { .. }) => self.dirty = true,
            Err(_) => {}
        }
    }

    /// Records a read's refusal beside the range (`search.md` §4).
    ///
    /// It records the document and its reason — the wire's word, or the
    /// shell's own — once per document.
    fn refuse(&mut self, range: usize, doc: Address, reason: String) {
        if let Some(record) = self.header.ranges.get_mut(range) {
            if !record.refusals.iter().any(|r| r.doc == doc) {
                record.refusals.push(Refusal { doc, reason });
                self.dirty = true;
            }
        }
    }
}

/// Returns the composition's part for a slot.
///
/// `None` for a pending resume, which the state answers as busy.
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
    /// Each range's fetch fence, with the floor the ranges resumed from.
    ///
    /// The floor comes with the pair they held, where the open met
    /// `history_reclaimed`.
    Cursors(Vec<u64>, Option<(u64, ChainAt)>),
    /// The history diverged: the file moved aside with the saved pair.
    Aside(ChainAt),
    /// `history_busy` past its retries.
    ///
    /// The open leaves the file and the next poll retries.
    Pending,
}

/// Returns a fresh index of `class` for the board at `chain`.
///
/// The published index has its one range, the board's whole feed; a
/// supplement has none, its ranges a widening's.
fn fresh(class: Class, chain: &Chain) -> (Index, Header) {
    let ranges = match class {
        Class::Guest => vec![RangeRecord { under: None, held: ChainAt { position: 0, chain: zero_chain() }, refusals: Vec::new(), bare_rows: 0, grant: None }],
        Class::Principal(_) => Vec::new(),
    };
    (Index::new(class), Header { board: *chain, floor: None, ranges, head: None })
}

/// Returns the first line of a file, its `\n` included.
fn first_line(bytes: &[u8]) -> Option<&[u8]> {
    bytes.iter().position(|&b| b == b'\n').map(|at| &bytes[..=at])
}

/// Types one part's items as the index takes them (`search.md` §2.1).
///
/// Each lands at its start ordinal from `from`, pushed onto the unit's
/// `items`. A part delivers the span it asked as the document stands at the
/// part's own position — `width` positions from `from`, fewer where the
/// extent shrank under the read, the span within the extent being what a
/// delivery holds (wire.md §Content values; M6's `retrieve_v`) — and never
/// more. The unit's resident `charge` grows by each item as the index will
/// hold it — its text, its own slot, a withheld run's origin a component at
/// a time — counted before the item is made, against [`CEILING_BYTES`], the
/// most text the whole index holds (`search.md` §7.4): the item table rests
/// resident beside the text it counts, so one read holds no more for one
/// unit than the index holds for all.
///
/// # Errors
///
/// A part past its span is [`NOT_A_DELIVERY`], refused at the item that
/// passes it; a unit whose charge passes [`CEILING_BYTES`] is
/// [`PAST_THE_CEILING`].
fn items_of(delivered: Vec<Delivered>, from: u64, width: u64, charge: &mut u64, items: &mut Vec<Item>) -> Result<(), &'static str> {
    const SLOT: u64 = std::mem::size_of::<Item>() as u64;
    const COMPONENT: u64 = std::mem::size_of::<Nat>() as u64 + 8;
    let end = from.checked_add(width).ok_or(NOT_A_DELIVERY)?;
    let mut start = from;
    for d in delivered {
        let held = match &d {
            Delivered::Text(bytes) => SLOT.saturating_add(bytes.len() as u64),
            Delivered::Withheld { origin, .. } => {
                let components = origin.bytes().filter(|b| *b == b'.').count() as u64 + 1;
                SLOT.saturating_add(components.saturating_mul(COMPONENT))
            }
            Delivered::Atom | Delivered::Unknown { .. } => SLOT,
        };
        *charge = charge.saturating_add(held);
        if *charge > CEILING_BYTES {
            return Err(PAST_THE_CEILING);
        }
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
        start = start.checked_add(item.width()).filter(|s| *s <= end).ok_or(NOT_A_DELIVERY)?;
        items.push(item);
    }
    Ok(())
}

/// Returns the reason a board's refusal is recorded under beside its range.
///
/// It is the wire's word where it is one (codes of `[a-z0-9_]`, a family's
/// detail after a `:`, at most [`REFUSAL_BOUND`] bytes, the longest wire.md
/// names being 28), else [`UNRECOGNIZED_REFUSAL`]: the record is saved with
/// every save and survives restarts, so it never holds a board's text of its
/// own choosing.
fn refusal_reason(key: &str) -> String {
    let word = |segment: &str| !segment.is_empty() && segment.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_');
    if key.len() <= REFUSAL_BOUND && key.split(':').all(word) {
        key.to_string()
    } else {
        UNRECOGNIZED_REFUSAL.to_string()
    }
}

// ── the loop's input: `GET /events` ──────────────────────────────────────

/// A handle that stops an [`Events`] iterator from another thread.
///
/// The read in progress ends it as it returns — on a line, a silence or a
/// close — a commit that line carries yielded first.
#[derive(Debug, Clone)]
pub struct Stop(Arc<AtomicBool>);

impl Stop {
    /// Stops the iterator at its next read.
    pub fn stop(&self) {
        self.0.store(true, Ordering::SeqCst);
    }
}

/// The commit stream as the shell's loop input.
///
/// It is `GET /events` on the dialer's streamed form (`client.md` §4e.2,
/// §7; wire.md §The commit stream), each `commit` event's `log_position`
/// yielded — "React to movement by re-querying", the shell's `poll` the
/// reaction — the stream reconnected where it closes, falls silent past
/// `SILENCE_BOUND` (a read that times out short of it is silence on a live
/// stream, which the stream survives), or writes a line past
/// `EVENT_LINE_BOUND`; every attempt after the first waits
/// `RECONNECT_WAIT`, so a board that refuses the stream is dialed four times
/// a second at most. The initial event after a reconnect is "potentially
/// having skipped history" and so a poll like any other. The consumer is
/// the shell's: this iterator carries the transport alone and the thread it
/// runs on is the embedder's.
pub struct Events<'b> {
    board: &'b Board,
    body: Option<Box<dyn BufRead + Send>>,
    stop: Arc<AtomicBool>,
    event: Option<String>,
    /// The line read so far, kept across a read that timed out.
    ///
    /// A line the board writes slowly is so read whole.
    line: Vec<u8>,
    /// When the stream last answered a line, or opened.
    heard: Instant,
    /// A connect was attempted: every later one waits [`RECONNECT_WAIT`].
    attempted: bool,
}

/// Returns the stream over `board`'s `/events`.
pub fn events(board: &Board) -> Events<'_> {
    Events {
        board,
        body: None,
        stop: Arc::new(AtomicBool::new(false)),
        event: None,
        line: Vec::new(),
        heard: Instant::now(),
        attempted: false,
    }
}

impl Events<'_> {
    /// Returns a handle to stop this iterator.
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
        self.heard = Instant::now();
        Ok(())
    }

    /// Drops the stream, to be dialed again.
    ///
    /// The line and the event read on it are the old stream's.
    fn hang_up(&mut self) {
        self.body = None;
        self.line.clear();
        self.event = None;
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
                if self.attempted {
                    thread::sleep(RECONNECT_WAIT);
                }
                self.attempted = true;
                if let Err(halt) = self.connect() {
                    return Some(Err(halt));
                }
            }
            let body = self.body.as_mut().expect("connected above");
            let room = EVENT_LINE_BOUND.saturating_sub(self.line.len() as u64);
            let read = Read::take(&mut **body, room).read_until(b'\n', &mut self.line);
            match read {
                Ok(0) => {
                    // The stream closed.
                    self.hang_up();
                    continue;
                }
                Ok(_) if self.line.last() != Some(&b'\n') => {
                    if self.line.len() as u64 >= EVENT_LINE_BOUND {
                        // A line past the bound: no event is that long.
                        self.hang_up();
                    }
                    continue;
                }
                Ok(_) => {}
                Err(e) if matches!(e.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut) => {
                    // A read that timed out: silence on a live stream, dead
                    // past the bound.
                    if self.heard.elapsed() >= SILENCE_BOUND {
                        self.hang_up();
                    }
                    continue;
                }
                Err(_) => {
                    // A broken connection: dialed again.
                    self.hang_up();
                    continue;
                }
            }
            self.heard = Instant::now();
            let line = std::mem::take(&mut self.line);
            let line = String::from_utf8_lossy(&line);
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
