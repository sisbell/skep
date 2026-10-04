//! THE MIRROR (REG-3.10 to REG-3.13, REG-3.17 to REG-3.19; R5 (a), (b)) —
//! the registry board's `/changes` feed IS the mirror protocol: a consumer
//! from the floor that is EXACT, not TTL-bounded-stale, applying no TTL and
//! negative-caching nothing (REG-3.10: a prefix no binding names is asked
//! again at the next delta and never remembered as absent).
//!
//! FETCH-AND-FOLD. The mirror reads every row of the feed as the GUEST and
//! fetches the bytes a row's record needs — the stored link (`read_link`),
//! the binding's or the endpoint's atom (`retrieve_v` at the position the
//! link's `from` names), and the credential table of the home it verifies
//! against, AS OF the record's position and never the live table for a
//! historical verdict: the live `key_set` where the feed the mirror holds
//! proves no credential act of the account lies between the position and
//! the live answer's `as_of` (the same table, by the mirror's own evidence),
//! the historical `key_set` on `/op-at` otherwise — then verifies the record
//! ([`crate::verify`]) and folds it into the index ([`crate::index`]). Every
//! read is the board's own journal (R5 (a)).
//!
//! THE BASE'S PROVENANCE (REG-3.12, REG-3.13; R5 (b)): the base is read FROM
//! GENESIS at the root the hint names — `/changes since=0`, the read that is
//! the check — or from a journal copy this mirror already holds, CHECKED
//! against that same feed before it serves (REG-3.18): the source is read
//! from genesis and the copy resumes only where every position it holds
//! comes back identical through its own head, the chain pairs it held
//! (`/chain?at=N`) answer the same, and the genesis set the realm id is
//! computed from is the one the copy holds. An image that OMITS, RE-ORDERS or
//! REPLAYS genuinely signed rows fails that check at the first position that
//! differs and is REFUSED by provenance, as a signature could never refuse it
//! (REG-3.13, the courier vector).
//!
//! THE TWO REFUSALS (REG-3.19), named: a frontier DIVERGING below the
//! mirror's head ([`Refusal::Diverged`], [`Refusal::ChainDiverged`]) and a
//! source whose head is BELOW the mirror's position ([`Refusal::SourceBehind`])
//! — the mirror refuses the new address and holds the base it has, saying
//! so rather than splicing. A root whose genesis set is not the hint's realm
//! is a LINEAGE CHANGE ([`Refusal::RealmMismatch`]; REG-3.42: the id is
//! compared at the base). A hint RE-POINTED to another realm re-bootstraps
//! afresh from the new root's genesis and resumes nothing (REG-3.17): the old
//! copy is retired beside the new.
//!
//! THE JOURNAL COPY (the copy's on-disk form, an interim pin), under the
//! caller's directory, two append-only files of JSON lines:
//!
//! * `feed.jsonl` — THE COPY OF THE FEED, what the check covers and what a
//!   courier could ship: a header `{"skep-resolve":"feed-v1","realm":<hex>,
//!   "root":<origin>}`, then one `{"row":<entry>}` per feed row in position
//!   order, exactly as the board served it, and a `{"head":{"at":N,
//!   "chain":<hex>}}` after each sync — the chain pair the resume compares.
//! * `fetched.jsonl` — THIS MIRROR'S OWN FETCH CACHE, what the fold read off
//!   the board: `{"link":{…}}` a stored link's slots, `{"atom":{"address",
//!   "text"}}` a record's bytes, `{"keys":{"account","epoch","at",
//!   "enrolled":[…]}}` a credential table as of a position, `{"retracted":
//!   {"at","link"}}` a retraction the fold found, `{"board":{"position",
//!   "chain"}}` the board term, `{"claim":{"at","claimant"}}` the claim. The
//!   REBUILD of the index is a re-read of the feed copy at the deposits' own
//!   positions (REG-3.25) with every fetch served from this cache, so it
//!   reads no wire; where a line is absent the fold fetches afresh. A cache
//!   adopted from a stranger is that stranger's word (REG-3.14's residue):
//!   only the feed copy is checked against the root.
//!
//! THE UN-ARRANGED ATOM (REG-3.25, REG-3.26): a deposit's atom is read at the
//! position its link's `from` names — at the head where it is arranged
//! there, and otherwise recovered BY THE HOME'S CHAIN WALK, one version at a
//! time down the home's chain to the version that arranged it, each version
//! asked for its extent, its image and the value — never by a read of the
//! arranged head; the walk probes the home's members off the board itself,
//! so it needs no feed, and its cost is counted ([`WalkStats`]). Where no
//! version holds it, the POSITION READ off the feed the mirror holds
//! (`/op-at` at the link's position) is the last recourse; where that fails
//! too the record is UNDETERMINABLE HERE, suppressed and counted.
//!
//! THE BINDING-WRITING ACCOUNT (R5 (g); REG-2.8): on an unforked lineage the
//! bindings the walk reads are the CLAIMANT's — a binding deposited in any
//! other home is no registrar's binding and enters no index, counted apart.

use std::collections::BTreeMap;
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, BufWriter, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use serde_json::{json, Value};
use skep_address::{document_of, parent, Address, Level, Nat, Tumbler};
use skep_identity::{doc_1_of, BoardTerm, Enrolled, Fingerprint, PublicKey};
use skep_registry::{commons_type, parse, t_binding, t_endpoint, Body, BodyKind};

use crate::hint::{realm_id, RootHint};
use crate::http::{parse_chain, Board, BoardError, Dial, Reads};
use crate::index::{Cause, Index, Suppressed};
use crate::origin::Origin;
use crate::parse_address;
use crate::state::{BindingRecord, EndpointRecord, Judged, Verdict};
use crate::verify::{judge, Trial};

/// The feed copy's file name under the mirror's directory.
pub const FEED_COPY: &str = "feed.jsonl";
/// The fetch cache's file name under the mirror's directory.
pub const FETCH_CACHE: &str = "fetched.jsonl";
/// The feed copy's format stamp, its header's first member.
const FEED_FORMAT: &str = "feed-v1";

/// `H.1`'s address — the head document's first chain member, the board
/// term's carrier (wire.md §The other endpoints).
const HEAD_MEMBER_1: &str = "1.1.0.1.0.2.1";

/// The retraction class's reserved ghost tumbler, the type slot of the link
/// a `nullify` deposits (wire.md §Links (writes)).
const RETRACTION_TYPE: &str = "1.1.0.1.0.1.0.1.5";

/// Why the mirror could not be opened or synced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MirrorError {
    /// No origin of the hint answered `/health`.
    Unreachable { tried: Vec<String> },
    /// A read the board refused or could not answer.
    Board(BoardError),
    /// The base's provenance refused the source (REG-3.19, REG-3.42).
    Refused(Refusal),
    /// The feed ended with no claim: an unclaimed board resolves nothing.
    NoClaim,
    /// The claim stands on no genesis set: no realm can be computed.
    NoGenesis,
    /// The copy could not be read or written, or is malformed.
    Copy(String),
    /// A wire read was needed and no board is held (an offline rebuild).
    Offline,
}

impl fmt::Display for MirrorError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MirrorError::Unreachable { tried } => write!(f, "no root answered: {}", tried.join(", ")),
            MirrorError::Board(e) => write!(f, "{e}"),
            MirrorError::Refused(r) => write!(f, "{r}"),
            MirrorError::NoClaim => f.write_str("the board is unclaimed: no registry to read"),
            MirrorError::NoGenesis => f.write_str("the claim stands on no genesis set"),
            MirrorError::Copy(e) => write!(f, "the journal copy: {e}"),
            MirrorError::Offline => f.write_str("a wire read was needed with no board held"),
        }
    }
}

impl std::error::Error for MirrorError {}

impl From<BoardError> for MirrorError {
    fn from(e: BoardError) -> MirrorError {
        MirrorError::Board(e)
    }
}

/// THE REFUSALS of the base's provenance (REG-3.19, REG-3.42).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refusal {
    /// The source's genesis set is not the hint's realm: a lineage change,
    /// not a root move (REG-3.19; detection point 1, REG-3.42).
    RealmMismatch { expected: Fingerprint, found: Fingerprint },
    /// A position the mirror holds came back different, or not at all, from
    /// the source read from genesis: a frontier diverging below the mirror's
    /// head — or a courier's image that omits, re-orders or replays rows
    /// (REG-3.13).
    Diverged { at: u64 },
    /// The source's head is below the mirror's position: a root brought up
    /// from a backup cannot answer for what it already served.
    SourceBehind { source_head: u64, held: u64 },
    /// A chain pair the mirror held is contradicted by the source's own
    /// recomputation at that position.
    ChainDiverged { at: u64 },
}

impl fmt::Display for Refusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Refusal::RealmMismatch { expected, found } => {
                write!(f, "the root's genesis set is realm {found}, the hint names {expected}")
            }
            Refusal::Diverged { at } => write!(f, "the source diverges from the held journal at {at}"),
            Refusal::SourceBehind { source_head, held } => {
                write!(f, "the source's head {source_head} is below the held position {held}")
            }
            Refusal::ChainDiverged { at } => write!(f, "the source's chain at {at} contradicts the held pair"),
        }
    }
}

/// How the mirror came to hold its base.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Opened {
    /// From genesis at the root the hint names, no copy held before.
    Bootstrapped,
    /// A copy held, checked byte-identical through its head against the
    /// source read from genesis, and resumed (REG-3.18).
    Resumed { checked_rows: u64 },
    /// The hint named another realm than the copy held: the copy retired to
    /// `retired`, the base established afresh (REG-3.17).
    Rebootstrapped { retired: PathBuf },
}

/// What the chain walk cost (REG-3.25; the investigation §3.3).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct WalkStats {
    /// Atoms recovered by the walk.
    pub atoms: u64,
    /// Versions visited across every walk, the one that held the atom
    /// included.
    pub versions_visited: u64,
    /// Wire reads the walks made: member probes, images and value reads.
    pub reads: u64,
    /// Time spent in the walks.
    pub time: Duration,
    /// Atoms no version held, recovered by the position read instead.
    pub position_reads: u64,
}

/// The numbers a mirror reports.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Stats {
    /// Feed rows folded.
    pub rows: u64,
    /// Feed pages read.
    pub pages: u64,
    /// Bytes of every feed page read.
    pub feed_bytes: u64,
    /// Every wire read, by kind.
    pub reads: Reads,
    /// Registry records judged (binding and endpoint bodies parsed).
    pub records: u64,
    /// Time inside the verify alone — parse, frame, both halves.
    pub verify_time: Duration,
    /// Time inside the fold, fetches included.
    pub fold_time: Duration,
    /// Time to establish the base: the pages, the fetches, the fold.
    pub bootstrap_time: Duration,
    /// Time of the resume check, where one ran.
    pub resume_check: Option<Duration>,
    /// The chain walk's cost.
    pub chain_walk: WalkStats,
    /// Bindings homed outside the claimant's doc 1, no registrar's.
    pub foreign_bindings: u64,
    /// As-of reads answered off the live table where the held feed proved
    /// it the table as of the position.
    pub reads_live_proven: u64,
    /// As-of reads made at the reclaim floor in place of a reclaimed
    /// position, the feed showing no act of the account between.
    pub reads_at_floor: u64,
    /// Records whose table as of their position is gone with the journal: a
    /// credential act lay between the position and the floor.
    pub reclaimed_undeterminable: u64,
    /// Bytes of the two copy files.
    pub copy_bytes: u64,
}

/// A stored link's slots as `read_link` serves them, at its position.
#[derive(Debug, Clone, PartialEq, Eq)]
struct StoredLink {
    at: u64,
    address: Address,
    home: Address,
    ty: Option<Address>,
    from: Vec<Address>,
    to: Vec<Address>,
}

/// A credential table as of a position (`key_set` on `/op-at`).
#[derive(Debug, Clone, PartialEq, Eq)]
struct KeysAsOf {
    account: Address,
    epoch: u64,
    at: u64,
    enrolled: Vec<Enrolled>,
}

/// The fetch cache in memory — what `fetched.jsonl` holds.
#[derive(Debug, Default)]
struct Fetched {
    links: BTreeMap<Address, StoredLink>,
    atoms: BTreeMap<Address, String>,
    keys: BTreeMap<(Address, u64), KeysAsOf>,
    retracted: BTreeMap<u64, Vec<Address>>,
    board: Option<BoardTerm>,
    claim: Option<(u64, Address)>,
}

/// A document's or a member's V→I image: its content runs, in V-order.
#[derive(Debug, Clone)]
struct Image {
    runs: Vec<(Address, u64)>,
}

impl Image {
    /// The V-ordinal `addr` sits at, where the image holds it.
    fn position_of(&self, addr: &Address) -> Option<u64> {
        let mut pos = 1u64;
        for (start, width) in &self.runs {
            if let Some(k) = offset_within(start, addr, *width) {
                return Some(pos + k);
            }
            pos += width;
        }
        None
    }
}

/// `addr`'s offset from `start` where it lies within a run of `width`
/// consecutive content ordinals from `start`, else `None`.
fn offset_within(start: &Address, addr: &Address, width: u64) -> Option<u64> {
    let s: Vec<&Nat> = start.tumbler().iter().collect();
    let a: Vec<&Nat> = addr.tumbler().iter().collect();
    if s.len() != a.len() || s[..s.len() - 1] != a[..a.len() - 1] {
        return None;
    }
    let (s_last, a_last) = (u64::try_from(s[s.len() - 1]).ok()?, u64::try_from(a[a.len() - 1]).ok()?);
    (a_last >= s_last && a_last - s_last < width).then(|| a_last - s_last)
}

/// One appendable JSON-lines file, created at the first line written.
struct Lines {
    path: PathBuf,
    out: Option<BufWriter<File>>,
    bytes: u64,
}

impl Lines {
    fn at(path: PathBuf) -> Lines {
        Lines { path, out: None, bytes: 0 }
    }

    fn append(&mut self, line: &Value) -> Result<(), MirrorError> {
        let text = line.to_string();
        if self.out.is_none() {
            let file = OpenOptions::new()
                .create(true)
                .append(true)
                .open(&self.path)
                .map_err(|e| MirrorError::Copy(format!("{}: {e}", self.path.display())))?;
            self.out = Some(BufWriter::new(file));
        }
        let out = self.out.as_mut().expect("opened above");
        out.write_all(text.as_bytes())
            .and_then(|()| out.write_all(b"\n"))
            .and_then(|()| out.flush())
            .map_err(|e| MirrorError::Copy(format!("{}: {e}", self.path.display())))?;
        self.bytes += text.len() as u64 + 1;
        Ok(())
    }

    /// Every line of the file as JSON, in order; none where the file is
    /// absent.
    fn read(path: &Path) -> Result<Vec<Value>, MirrorError> {
        if !path.exists() {
            return Ok(Vec::new());
        }
        let file = File::open(path).map_err(|e| MirrorError::Copy(format!("{}: {e}", path.display())))?;
        let mut lines = Vec::new();
        for (n, line) in BufReader::new(file).lines().enumerate() {
            let line = line.map_err(|e| MirrorError::Copy(format!("{}: {e}", path.display())))?;
            if line.trim().is_empty() {
                continue;
            }
            let v: Value = serde_json::from_str(&line)
                .map_err(|e| MirrorError::Copy(format!("{}:{}: {e}", path.display(), n + 1)))?;
            lines.push(v);
        }
        Ok(lines)
    }
}

/// The type addresses the fold tells a stored link's kind by: the registry's
/// two record kinds (`skep_registry`'s pins), the three credential kinds at
/// the commons' `3.1`–`3.3` (wire.md §The claim ceremony and credentials)
/// and the retraction class.
struct Types {
    binding: Address,
    endpoint: Address,
    enroll: Address,
    retire: Address,
    claim: Address,
    retraction: Address,
}

impl Types {
    fn new() -> Types {
        Types {
            binding: t_binding().clone(),
            endpoint: t_endpoint().clone(),
            enroll: commons_type(&[1]),
            retire: commons_type(&[2]),
            claim: commons_type(&[3]),
            retraction: parse_address(RETRACTION_TYPE).expect("the retraction class's ghost tumbler"),
        }
    }
}

/// THE MIRROR: the hint it is scoped to, the board it reads, its copy, its
/// fetch cache, and the index it derives.
pub struct Mirror {
    hint: RootHint,
    root: Option<Origin>,
    board: Option<Board>,
    dir: PathBuf,
    feed: Lines,
    cache: Lines,
    pending_feed: Vec<Value>,
    pending_cache: Vec<Value>,
    fetched: Fetched,
    index: Index,
    types: Types,
    /// Every feed row held, in position order — the copy in memory.
    rows: Vec<Value>,
    /// How many of `rows` the fold has consumed.
    folded: usize,
    head: u64,
    checked: bool,
    epochs: BTreeMap<Address, Vec<u64>>,
    members: BTreeMap<Address, Vec<Address>>,
    members_probed: BTreeMap<Address, bool>,
    images: BTreeMap<Address, Image>,
    stats: Stats,
    opened: Opened,
}

impl Mirror {
    /// OPEN the mirror under `dir` against the root `hint` names, through
    /// `dial`: a copy held there is CHECKED and resumed (REG-3.18), a copy of
    /// another realm retired and the base re-established (REG-3.17), no copy
    /// bootstrapped from genesis (REG-3.12); then the delta synced. The
    /// refusals are [`Refusal`]'s, each named.
    pub fn open(hint: &RootHint, dir: &Path, dial: &Dial<'_>) -> Result<Mirror, MirrorError> {
        fs::create_dir_all(dir).map_err(|e| MirrorError::Copy(format!("{}: {e}", dir.display())))?;
        let (root, board) = dial_root(hint, dial)?;
        let feed_path = dir.join(FEED_COPY);
        let held = Lines::read(&feed_path)?;
        let mut mirror = Mirror::fresh(hint, Some(root), Some(board), dir);
        if held.is_empty() {
            let t = Instant::now();
            mirror.bootstrap()?;
            mirror.stats.bootstrap_time = t.elapsed();
            return Ok(mirror);
        }
        let header = &held[0];
        let held_realm = header["realm"].as_str().and_then(Fingerprint::parse_hex);
        if header["skep-resolve"].as_str() != Some(FEED_FORMAT) || held_realm.is_none() {
            return Err(MirrorError::Copy(format!("{}: not a feed copy", feed_path.display())));
        }
        if held_realm != Some(hint.realm) {
            // REG-3.17 — a re-pointed hint: afresh from the new root's genesis.
            let retired = retire(dir, held_realm.expect("checked"))?;
            let t = Instant::now();
            mirror.bootstrap()?;
            mirror.stats.bootstrap_time = t.elapsed();
            mirror.opened = Opened::Rebootstrapped { retired };
            return Ok(mirror);
        }
        // REG-3.18 — the same lineage: check, rebuild, resume.
        let t = Instant::now();
        let rows: Vec<Value> = held[1..].iter().filter_map(|l| l.get("row").cloned()).collect();
        let heads: Vec<(u64, [u8; 32])> = held[1..]
            .iter()
            .filter_map(|l| {
                let h = l.get("head")?;
                Some((h["at"].as_u64()?, parse_chain(h["chain"].as_str()?)?))
            })
            .collect();
        mirror.load_cache()?;
        mirror.check_against_source(&rows, &heads)?;
        mirror.stats.resume_check = Some(t.elapsed());
        mirror.checked = true;
        mirror.feed.bytes = fs::metadata(&feed_path).map(|m| m.len()).unwrap_or(0);
        mirror.cache.bytes = fs::metadata(dir.join(FETCH_CACHE)).map(|m| m.len()).unwrap_or(0);
        let checked_rows = rows.len() as u64;
        mirror.rows = rows;
        mirror.fold_pending()?;
        mirror.opened = Opened::Resumed { checked_rows };
        mirror.sync()?;
        Ok(mirror)
    }

    /// REBUILD the index from the copy under `dir` alone, no board dialed
    /// (REG-3.25: the rebuild is a re-read of the feed at the deposits' own
    /// positions): every fetch served from the cache; a record whose bytes
    /// the cache lacks is UNDETERMINABLE HERE. `sync` and the walk's own
    /// reads refuse [`MirrorError::Offline`] on the mirror this answers.
    pub fn rebuild_offline(hint: &RootHint, dir: &Path) -> Result<Mirror, MirrorError> {
        let feed_path = dir.join(FEED_COPY);
        let held = Lines::read(&feed_path)?;
        if held.is_empty() {
            return Err(MirrorError::Copy(format!("{}: no feed copy", feed_path.display())));
        }
        if held[0]["realm"].as_str().and_then(Fingerprint::parse_hex) != Some(hint.realm) {
            return Err(MirrorError::Copy("the copy is another realm's".into()));
        }
        let mut mirror = Mirror::fresh(hint, None, None, dir);
        mirror.load_cache()?;
        mirror.checked = true;
        mirror.rows = held[1..].iter().filter_map(|l| l.get("row").cloned()).collect();
        mirror.fold_pending()?;
        mirror.opened = Opened::Resumed { checked_rows: 0 };
        Ok(mirror)
    }

    fn fresh(hint: &RootHint, root: Option<Origin>, board: Option<Board>, dir: &Path) -> Mirror {
        Mirror {
            hint: hint.clone(),
            root,
            board,
            dir: dir.to_path_buf(),
            feed: Lines::at(dir.join(FEED_COPY)),
            cache: Lines::at(dir.join(FETCH_CACHE)),
            pending_feed: Vec::new(),
            pending_cache: Vec::new(),
            fetched: Fetched::default(),
            index: Index::new(),
            types: Types::new(),
            rows: Vec::new(),
            folded: 0,
            head: 0,
            checked: false,
            epochs: BTreeMap::new(),
            members: BTreeMap::new(),
            members_probed: BTreeMap::new(),
            images: BTreeMap::new(),
            stats: Stats::default(),
            opened: Opened::Bootstrapped,
        }
    }

    /// THE INDEX as it stands.
    pub fn index(&self) -> &Index {
        &self.index
    }

    /// The hint this mirror is scoped to.
    pub fn hint(&self) -> &RootHint {
        &self.hint
    }

    /// The origin that answered, where a board is held.
    pub fn root(&self) -> Option<&Origin> {
        self.root.as_ref()
    }

    /// The board, where one is held.
    pub fn board(&self) -> Option<&Board> {
        self.board.as_ref()
    }

    /// The mirror's head: the last feed position folded.
    pub fn head(&self) -> u64 {
        self.head
    }

    /// How the base was established.
    pub fn opened(&self) -> &Opened {
        &self.opened
    }

    /// The directory the copy lives under.
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// The claim: its position and the claimant — the binding-writing
    /// account on an unforked lineage.
    pub fn claim(&self) -> Option<(u64, &Address)> {
        self.fetched.claim.as_ref().map(|(at, a)| (*at, a))
    }

    /// The board term, where one has been read.
    pub fn board_term_held(&self) -> Option<BoardTerm> {
        self.fetched.board
    }

    /// The members of `home`'s version chain the mirror knows, oldest first.
    pub fn members_of(&self, home: &Address) -> &[Address] {
        self.members.get(home).map(Vec::as_slice).unwrap_or(&[])
    }

    /// The numbers, with every read the board was asked.
    pub fn stats(&self) -> Stats {
        let mut s = self.stats.clone();
        if let Some(b) = &self.board {
            s.reads = b.reads();
            s.feed_bytes = b.feed_bytes();
        }
        s.copy_bytes = self.feed.bytes + self.cache.bytes;
        s
    }

    fn board_ref(&self) -> Result<&Board, MirrorError> {
        self.board.as_ref().ok_or(MirrorError::Offline)
    }

    // ── the base ────────────────────────────────────────────────────────────

    /// From genesis: `since=0` to the head, the realm checked at the claim.
    fn bootstrap(&mut self) -> Result<(), MirrorError> {
        self.pull(0)?;
        if !self.checked {
            return Err(MirrorError::NoClaim);
        }
        self.record_head()
    }

    /// SYNC the delta `since=head` (REG-3.10): the rows past the mirror's
    /// head, folded; answers how many.
    pub fn sync(&mut self) -> Result<u64, MirrorError> {
        let before = self.stats.rows;
        let from = self.head;
        self.pull(from)?;
        if self.head != from {
            self.record_head()?;
        }
        Ok(self.stats.rows - before)
    }

    /// Pages from `since` to the feed's end, each row appended to the copy
    /// and folded; the page size the feed's own default, and the limit the
    /// feed names where a page passes its byte budget.
    fn pull(&mut self, mut since: u64) -> Result<(), MirrorError> {
        // The images and the members are the live board's at the last pull;
        // new rows may have moved either, so both are read afresh.
        self.images.clear();
        self.members_probed.clear();
        let mut limit: Option<usize> = None;
        loop {
            let page = match self.board_ref()?.changes(since, limit) {
                Ok(page) => page,
                Err(BoardError::PageTooLarge { fits }) => {
                    limit = Some(fits.max(1));
                    continue;
                }
                Err(e) => return Err(e.into()),
            };
            self.stats.pages += 1;
            let last_at = page.rows.last().and_then(|r| r["at"].as_u64()).unwrap_or(0);
            for row in page.rows {
                self.append_feed(json!({ "row": row }))?;
                self.rows.push(row);
            }
            since = page.last.max(last_at);
            if !page.more {
                break;
            }
        }
        // Every row held before any is folded: the fold's as-of reads lean
        // on the rows AFTER a record's position (the floor's clause).
        self.fold_pending()
    }

    /// Fold every held row the fold has not consumed, in order.
    fn fold_pending(&mut self) -> Result<(), MirrorError> {
        let t = Instant::now();
        while self.folded < self.rows.len() {
            let row = self.rows[self.folded].clone();
            self.fold_row(&row)?;
            self.head = row["at"].as_u64().unwrap_or(self.head);
            self.stats.rows += 1;
            self.folded += 1;
        }
        self.stats.fold_time += t.elapsed();
        Ok(())
    }

    /// A chain pair held for the resume's check: `/health`'s live pair, the
    /// committed head's position and chain read off one kernel snapshot
    /// (wire.md §The other endpoints) — a pair `/chain?at` later checks the
    /// source's recomputation against. Read off `/health` rather than
    /// `/chain?at=head`, which recomputes the chain over the surviving
    /// journal per call.
    fn record_head(&mut self) -> Result<(), MirrorError> {
        if self.head == 0 {
            return Ok(());
        }
        let health = self.board_ref()?.health()?;
        let (Some(at), Some(chain)) = (health["log_position"].as_u64(), health["chain_head"].as_str()) else {
            return Ok(());
        };
        if parse_chain(chain).is_none() || at < self.head {
            return Ok(());
        }
        self.append_feed(json!({ "head": { "at": at, "chain": chain } }))
    }

    fn append_feed(&mut self, line: Value) -> Result<(), MirrorError> {
        if self.checked {
            self.feed.append(&line)
        } else {
            self.pending_feed.push(line);
            Ok(())
        }
    }

    fn append_cache(&mut self, line: Value) -> Result<(), MirrorError> {
        if self.board.is_none() {
            return Ok(());
        }
        if self.checked {
            self.cache.append(&line)
        } else {
            self.pending_cache.push(line);
            Ok(())
        }
    }

    /// The realm checked: the copy's header and every pending line written.
    fn flush_pending(&mut self) -> Result<(), MirrorError> {
        let header = json!({
            "skep-resolve": FEED_FORMAT,
            "realm": self.hint.realm.to_hex(),
            "root": self.root.as_ref().map(|o| o.as_str().to_string()),
        });
        self.feed.append(&header)?;
        for line in std::mem::take(&mut self.pending_feed) {
            self.feed.append(&line)?;
        }
        for line in std::mem::take(&mut self.pending_cache) {
            self.cache.append(&line)?;
        }
        Ok(())
    }

    /// The fetch cache read into memory.
    fn load_cache(&mut self) -> Result<(), MirrorError> {
        for line in Lines::read(&self.dir.join(FETCH_CACHE))? {
            if let Some(l) = line.get("link") {
                if let Some(link) = stored_link_of(l) {
                    self.fetched.links.insert(link.address.clone(), link);
                }
            } else if let Some(a) = line.get("atom") {
                if let (Some(addr), Some(text)) = (a["address"].as_str().and_then(parse_address), a["text"].as_str()) {
                    self.fetched.atoms.insert(addr, text.to_string());
                }
            } else if let Some(k) = line.get("keys") {
                if let Some(keys) = keys_of(k) {
                    self.fetched.keys.insert((keys.account.clone(), keys.epoch), keys);
                }
            } else if let Some(r) = line.get("retracted") {
                if let (Some(at), Some(link)) = (r["at"].as_u64(), r["link"].as_str().and_then(parse_address)) {
                    self.fetched.retracted.entry(at).or_default().push(link);
                }
            } else if let Some(b) = line.get("board") {
                if let (Some(p), Some(c)) = (b["position"].as_u64(), b["chain"].as_str().and_then(parse_chain)) {
                    self.fetched.board = Some(BoardTerm { log_position: p, chain: c });
                }
            } else if let Some(c) = line.get("claim") {
                if let (Some(at), Some(who)) = (c["at"].as_u64(), c["claimant"].as_str().and_then(parse_address)) {
                    self.fetched.claim = Some((at, who));
                }
            }
        }
        Ok(())
    }

    /// REG-3.18's CHECK: the source read from genesis must answer every held
    /// row identically through the copy's head, every held chain pair, and
    /// the genesis set the realm stands on.
    fn check_against_source(&mut self, rows: &[Value], heads: &[(u64, [u8; 32])]) -> Result<(), MirrorError> {
        let held_head = rows.last().and_then(|r| r["at"].as_u64()).unwrap_or(0);
        let mut fresh: Vec<Value> = Vec::new();
        let mut since = 0;
        let mut limit = None;
        loop {
            let page = match self.board_ref()?.changes(since, limit) {
                Ok(page) => page,
                Err(BoardError::PageTooLarge { fits }) => {
                    limit = Some(fits.max(1));
                    continue;
                }
                Err(e) => return Err(e.into()),
            };
            self.stats.pages += 1;
            fresh.extend(page.rows);
            since = page.last;
            if !page.more || since >= held_head {
                break;
            }
        }
        for (i, held) in rows.iter().enumerate() {
            let at = held["at"].as_u64().unwrap_or(0);
            match fresh.get(i) {
                None => {
                    let source_head = fresh.last().and_then(|r| r["at"].as_u64()).unwrap_or(0);
                    return Err(MirrorError::Refused(Refusal::SourceBehind { source_head, held: at }));
                }
                Some(f) if f != held => return Err(MirrorError::Refused(Refusal::Diverged { at })),
                Some(_) => {}
            }
        }
        for (at, chain) in heads {
            let (_, fresh_chain) = self.board_ref()?.chain_at(*at)?;
            if fresh_chain != *chain {
                return Err(MirrorError::Refused(Refusal::ChainDiverged { at: *at }));
            }
        }
        // The realm at the base (REG-3.42): the genesis set as the source
        // answers it now, against the hint.
        if let Some((_, claimant)) = self.fetched.claim.clone() {
            if let Some(genesis_at) = self.fetched.keys.keys().filter(|(a, _)| *a == claimant).map(|(_, e)| *e).min() {
                let keys = self.fetch_keys(&claimant, genesis_at)?.ok_or(MirrorError::NoGenesis)?;
                let found = realm_id(&keys.iter().map(|e| Fingerprint::of(&e.key)).collect::<Vec<_>>());
                if found != self.hint.realm {
                    return Err(MirrorError::Refused(Refusal::RealmMismatch { expected: self.hint.realm, found }));
                }
            }
        }
        Ok(())
    }

    // ── the fold ────────────────────────────────────────────────────────────

    /// One feed row, folded (the module doc's fetch-and-fold).
    fn fold_row(&mut self, row: &Value) -> Result<(), MirrorError> {
        let at = row["at"].as_u64().unwrap_or(0);
        let docs: Vec<Address> = row["docs"]
            .as_array()
            .map(|d| d.iter().filter_map(|a| a.as_str().and_then(parse_address)).collect())
            .unwrap_or_default();
        match row["op"].as_str() {
            Some("make_link") if row.get("attest").is_none() => {
                let (Some(link), Some(home)) = (row["link"].as_str().and_then(parse_address), docs.first().cloned()) else {
                    return Ok(());
                };
                let Some(stored) = self.read_link(at, &link, &home)? else { return Ok(()) };
                let Some(ty) = stored.ty.clone() else { return Ok(()) };
                if ty == self.types.claim {
                    if let Some(claimant) = stored.from.first().cloned() {
                        self.fetched.claim = Some((at, claimant.clone()));
                        self.append_cache(json!({ "claim": { "at": at, "claimant": claimant.to_string() } }))?;
                        if !self.checked {
                            self.realm_check()?;
                        }
                    }
                } else if ty == self.types.enroll || ty == self.types.retire {
                    if let Some(subject) = stored.to.first().cloned() {
                        self.epochs.entry(subject).or_default().push(at);
                    }
                } else if ty == self.types.binding {
                    match &self.fetched.claim {
                        Some((_, claimant)) if doc_1_of(claimant) == home => {
                            self.fold_record(BodyKind::Binding, &stored)?;
                        }
                        _ => self.stats.foreign_bindings += 1,
                    }
                } else if ty == self.types.endpoint {
                    self.fold_record(BodyKind::Endpoint, &stored)?;
                }
            }
            Some("nullify") => {
                for doc in &docs {
                    let candidates: Vec<Address> = self
                        .index
                        .endpoints(doc)
                        .iter()
                        .filter(|d| d.record.honored && !d.record.nullified)
                        .map(|d| d.link.clone())
                        .collect();
                    for link in candidates {
                        if self.retracted(at, &link)? {
                            self.index.nullify(&link);
                        }
                    }
                }
            }
            Some("publish") | Some("version") => {
                for member in &docs {
                    if let Some(trunk) = trunk_of(member) {
                        let list = self.members.entry(trunk.clone()).or_default();
                        if !list.contains(member) {
                            list.push(member.clone());
                        }
                        self.members_probed.insert(trunk.clone(), true);
                    }
                }
            }
            _ => {}
        }
        Ok(())
    }

    /// THE REALM CHECK at the base (REG-3.42; REG-3.39): the claimant's
    /// genesis set — its first credential position — fingerprinted and
    /// compared to the hint's realm; a mismatch is REG-3.19's refusal.
    fn realm_check(&mut self) -> Result<(), MirrorError> {
        let (_, claimant) = self.fetched.claim.clone().ok_or(MirrorError::NoClaim)?;
        let genesis_at = *self.epochs.get(&claimant).and_then(|v| v.first()).ok_or(MirrorError::NoGenesis)?;
        let keys = self.fetch_keys(&claimant, genesis_at)?.ok_or(MirrorError::NoGenesis)?;
        let found = realm_id(&keys.iter().map(|e| Fingerprint::of(&e.key)).collect::<Vec<_>>());
        if found != self.hint.realm {
            return Err(MirrorError::Refused(Refusal::RealmMismatch { expected: self.hint.realm, found }));
        }
        self.checked = true;
        if self.board.is_some() {
            self.flush_pending()?;
        }
        Ok(())
    }

    /// One registry record: fetched, parsed, judged, folded or suppressed.
    fn fold_record(&mut self, kind: BodyKind, link: &StoredLink) -> Result<(), MirrorError> {
        let suppress = |m: &mut Mirror, cause: Cause| {
            m.index.suppress(Suppressed { position: link.at, link: link.address.clone(), kind, cause });
        };
        let Some(atom) = link.from.first().cloned() else {
            suppress(self, Cause::UndeterminableHere);
            return Ok(());
        };
        let Some(home_account) = account_of_document(&link.home) else {
            suppress(self, Cause::UndeterminableHere);
            return Ok(());
        };
        let Some(text) = self.fetch_atom(link.at, &link.home, &atom)? else {
            suppress(self, Cause::UndeterminableHere);
            return Ok(());
        };
        let record = match parse(kind, text.as_bytes()) {
            Ok(r) => r,
            Err(refusal) => {
                self.stats.records += 1;
                suppress(self, Cause::Malformed(refusal));
                return Ok(());
            }
        };
        self.stats.records += 1;
        let board = self.board_term()?;
        let keys = self.keys_opening(&home_account, link.at)?;
        let verdict = match (board, keys) {
            (Some(board), Some(keys)) => {
                let t = Instant::now();
                let ty = link.ty.clone().expect("a record link's type was read");
                let v = judge(
                    &record,
                    &Trial { board, home: &link.home, home_account: &home_account, ty: &ty, to: &link.to, keys: &keys },
                );
                self.stats.verify_time += t.elapsed();
                v
            }
            _ => Verdict::UndeterminableHere,
        };
        if !verdict.admits() {
            let cause = match verdict {
                Verdict::UndeterminableHere => Cause::UndeterminableHere,
                _ => Cause::Unsigned,
            };
            suppress(self, cause);
            return Ok(());
        }
        let replaces = match record.body.replaces() {
            None => None,
            Some(r) => match parse_address(r) {
                Some(a) => Some(a),
                None => {
                    suppress(self, Cause::Malformed(skep_registry::Refusal::NotAnAddress("replaces")));
                    return Ok(());
                }
            },
        };
        match record.body {
            Body::Binding(b) => {
                let Some(prefix) = parse_address(&b.prefix) else {
                    suppress(self, Cause::Malformed(skep_registry::Refusal::NotAnAddress("prefix")));
                    return Ok(());
                };
                self.index.fold_binding(Judged {
                    position: link.at,
                    link: link.address.clone(),
                    home: link.home.clone(),
                    record: BindingRecord { prefix, account: link.to.first().cloned(), replaces, honored: false },
                    verdict,
                });
            }
            Body::Endpoint(e) => {
                self.index.fold_endpoint(Judged {
                    position: link.at,
                    link: link.address.clone(),
                    home: link.home.clone(),
                    record: EndpointRecord { origins: e.origins, replaces, honored: false, nullified: false },
                    verdict,
                });
            }
        }
        Ok(())
    }

    // ── the fetches ─────────────────────────────────────────────────────────

    /// The stored link at `link`, from the cache or `read_link`; `None`
    /// where no link stands there.
    fn read_link(&mut self, at: u64, link: &Address, home: &Address) -> Result<Option<StoredLink>, MirrorError> {
        if let Some(s) = self.fetched.links.get(link) {
            return Ok(Some(s.clone()));
        }
        let Some(board) = self.board.as_ref() else { return Ok(None) };
        let v = board.op_ok(&json!({ "op": "read_link", "a": link.to_string() }))?;
        if v["link"].is_null() {
            return Ok(None);
        }
        let slot = |i: usize| -> Vec<Address> {
            v["link"]["slots"][i]
                .as_array()
                .map(|spans| spans.iter().filter_map(|s| s["start"].as_str().and_then(parse_address)).collect())
                .unwrap_or_default()
        };
        let (from, to, ty) = (slot(0), slot(1), slot(2));
        let stored = StoredLink {
            at,
            address: link.clone(),
            home: home.clone(),
            ty: (ty.len() == 1).then(|| ty[0].clone()),
            from,
            to,
        };
        self.append_cache(json!({ "link": {
            "at": at,
            "address": link.to_string(),
            "home": home.to_string(),
            "ty": stored.ty.as_ref().map(ToString::to_string),
            "from": stored.from.iter().map(ToString::to_string).collect::<Vec<_>>(),
            "to": stored.to.iter().map(ToString::to_string).collect::<Vec<_>>(),
        }}))?;
        self.fetched.links.insert(link.clone(), stored.clone());
        Ok(Some(stored))
    }

    /// Whether a retraction link targeting `link` stands at `at` — the
    /// `nullify`'s own deposit, found by its type and target (two slots
    /// constrained: no class scan).
    fn retracted(&mut self, at: u64, link: &Address) -> Result<bool, MirrorError> {
        if self.fetched.retracted.get(&at).is_some_and(|l| l.contains(link)) {
            return Ok(true);
        }
        let Some(board) = self.board.as_ref() else { return Ok(false) };
        let v = board.op_ok(&json!({ "op": "find_links_ftt", "q": {
            "home": "any", "from": "any",
            "to": [unit_span_json(link)],
            "ty": [unit_span_json(&self.types.retraction)],
        }}))?;
        let found = v["addrs"].as_array().is_some_and(|a| !a.is_empty());
        if found {
            self.fetched.retracted.entry(at).or_default().push(link.clone());
            self.append_cache(json!({ "retracted": { "at": at, "link": link.to_string() } }))?;
        }
        Ok(found)
    }

    /// THE BOARD TERM: `H.1`'s pair off `retrieve_v` on the pinned member,
    /// read once; `None` where the board holds none (then every verdict is
    /// UNDETERMINABLE HERE).
    fn board_term(&mut self) -> Result<Option<BoardTerm>, MirrorError> {
        if let Some(b) = self.fetched.board {
            return Ok(Some(b));
        }
        let Some(board) = self.board.as_ref() else { return Ok(None) };
        let v = board.op(&retrieve_frame(HEAD_MEMBER_1, 1))?;
        let Some(text) = v["items"].as_array().and_then(|i| i.first()).and_then(|i| i["atom"].as_str()) else {
            return Ok(None);
        };
        let rec: Value = match serde_json::from_str(text) {
            Ok(v) => v,
            Err(_) => return Ok(None),
        };
        let (Some(position), Some(chain)) = (rec["position"].as_u64(), rec["chain"].as_str().and_then(parse_chain)) else {
            return Ok(None);
        };
        let term = BoardTerm { log_position: position, chain };
        self.fetched.board = Some(term);
        self.append_cache(json!({ "board": { "position": position, "chain": rec["chain"] } }))?;
        Ok(Some(term))
    }

    /// The latest credential position of `account` at or below `at`, or 0.
    fn epoch_of(&self, account: &Address, at: u64) -> u64 {
        self.epochs.get(account).and_then(|v| v.iter().rev().find(|p| **p <= at)).copied().unwrap_or(0)
    }

    /// Whether a credential act of `account` — an enroll or retire link
    /// naming it, homed in its own doc 1 or in the claimant's (its genesis
    /// registry) — lies in `(after, upto]` among the rows the mirror holds.
    fn later_credential_act(&mut self, account: &Address, after: u64, upto: u64) -> Result<bool, MirrorError> {
        let own = doc_1_of(account);
        let registry = self.fetched.claim.as_ref().map(|(_, c)| doc_1_of(c));
        let candidates: Vec<(u64, Address, Address)> = self
            .rows
            .iter()
            .filter(|r| r["at"].as_u64().is_some_and(|p| p > after && p <= upto))
            .filter(|r| r["op"].as_str() == Some("make_link") && r.get("attest").is_none())
            .filter_map(|r| {
                let at = r["at"].as_u64()?;
                let link = parse_address(r["link"].as_str()?)?;
                let home = parse_address(r["docs"][0].as_str()?)?;
                (home == own || Some(&home) == registry.as_ref()).then_some((at, link, home))
            })
            .collect();
        for (at, link, home) in candidates {
            if let Some(stored) = self.read_link(at, &link, &home)? {
                let credential = stored.ty.as_ref().is_some_and(|t| *t == self.types.enroll || *t == self.types.retire);
                if credential && stored.to.first() == Some(account) {
                    return Ok(true);
                }
            }
        }
        Ok(false)
    }

    /// THE SET THAT OPENS `account` as of `at`: its own table where not
    /// empty, else the nearest keyed account above it (AUTH-4.30 (i)'s walk,
    /// as the daemon makes it); `None` where the table cannot be read.
    fn keys_opening(&mut self, account: &Address, at: u64) -> Result<Option<Vec<Enrolled>>, MirrorError> {
        let mut acct = account.clone();
        loop {
            let epoch = self.epoch_of(&acct, at);
            let Some(keys) = self.fetch_keys_epoch(&acct, epoch, at)? else { return Ok(None) };
            if !keys.is_empty() {
                return Ok(Some(keys));
            }
            match parent(&acct) {
                Some(above) if above.level() == Level::Account => acct = above,
                _ => return Ok(Some(keys)),
            }
        }
    }

    /// `key_set` of `account` as of `at` — the table at the credential epoch
    /// the position falls in, cached per epoch.
    fn fetch_keys(&mut self, account: &Address, at: u64) -> Result<Option<Vec<Enrolled>>, MirrorError> {
        let epoch = self.epoch_of(account, at);
        self.fetch_keys_epoch(account, epoch, at)
    }

    /// The read itself, at `at` — or, where the board has RECLAIMED the
    /// position (REG-3.15's floor: a root that cannot answer from genesis),
    /// at the floor WHERE THE FEED THE MIRROR HOLDS SHOWS NO CREDENTIAL ACT
    /// OF THE ACCOUNT BETWEEN THE POSITION AND THE FLOOR: the table is
    /// constant across an epoch, so the read at the floor IS the table as
    /// of the position, derived from inputs the mirror holds and
    /// manufactured from none; where an act does lie between, the table as
    /// of the position is gone with the journal and the record is
    /// UNDETERMINABLE HERE.
    fn fetch_keys_epoch(&mut self, account: &Address, epoch: u64, at: u64) -> Result<Option<Vec<Enrolled>>, MirrorError> {
        if let Some(k) = self.fetched.keys.get(&(account.clone(), epoch)) {
            return Ok(Some(k.enrolled.clone()));
        }
        let Some(board) = self.board.as_ref() else { return Ok(None) };
        let frame = json!({ "op": "key_set", "account": account.to_string() });
        // THE TABLE AS OF THE POSITION, OFF THE LIVE READ WHERE THE FEED
        // PROVES IT: the live `key_set` answers `as_of`, the snapshot's
        // position; where that position is one the mirror holds the feed
        // through, and no credential act of the account lies between the
        // record's position and it, the table has not changed in between
        // and the live answer IS the table as of the record — the mirror's
        // own base is the evidence, and nothing is manufactured. Elsewhere
        // the historical read below is the only exact one. A reconstruction
        // costs the board a whole world per call (wire.md §Reading history:
        // "wrong for a hot loop"), so this is what makes a bootstrap of
        // thousands of homes a matter of seconds and not of hours.
        let held = self.rows.last().and_then(|r| r["at"].as_u64()).unwrap_or(self.head);
        if let Ok(live) = board.op(&frame) {
            if live["resp"].as_str() == Some("key_set") {
                if let Some(as_of) = live["as_of"].as_u64() {
                    if as_of <= held && !self.later_credential_act(account, at, as_of)? {
                        self.stats.reads_live_proven += 1;
                        return self.keep_keys(account, epoch, at, &live);
                    }
                }
            }
        }
        let board = self.board_ref()?;
        let v = match board.op_at(at, &frame) {
            Ok(v) => v,
            Err(BoardError::Reclaimed { floor }) => {
                // The feed the mirror holds reaches its last row, not the
                // fold's cursor: that is the span the scan below covers.
                let held = self.rows.last().and_then(|r| r["at"].as_u64()).unwrap_or(self.head);
                let floor = floor.unwrap_or(held);
                if floor > held || self.later_credential_act(account, at, floor)? {
                    self.stats.reclaimed_undeterminable += 1;
                    return Ok(None);
                }
                self.stats.reads_at_floor += 1;
                match self.board_ref()?.op_at(floor, &frame) {
                    Ok(v) => v,
                    Err(BoardError::Status { .. }) | Err(BoardError::Reclaimed { .. }) => return Ok(None),
                    Err(e) => return Err(e.into()),
                }
            }
            Err(BoardError::Status { .. }) => return Ok(None),
            Err(e) => return Err(e.into()),
        };
        if v["resp"].as_str() != Some("key_set") {
            return Ok(None);
        }
        self.keep_keys(account, epoch, at, &v)
    }

    /// A `key_set` answer kept as the table of `account`'s epoch: cached,
    /// and written to the fetch cache.
    fn keep_keys(&mut self, account: &Address, epoch: u64, at: u64, v: &Value) -> Result<Option<Vec<Enrolled>>, MirrorError> {
        let enrolled: Vec<Enrolled> = v["enrolled"]
            .as_array()
            .map(|entries| entries.iter().filter_map(enrolled_of).collect())
            .unwrap_or_default();
        let keys = KeysAsOf { account: account.clone(), epoch, at, enrolled: enrolled.clone() };
        self.append_cache(json!({ "keys": {
            "account": account.to_string(),
            "epoch": epoch,
            "at": at,
            "enrolled": enrolled.iter().map(|e| json!({ "alg": e.key.alg(), "key": e.key.to_hex(), "anchor": e.anchor })).collect::<Vec<_>>(),
        }}))?;
        self.fetched.keys.insert((account.clone(), epoch), keys);
        Ok(Some(enrolled))
    }

    /// The key set that opens `account` as of the mirror's HEAD — the walk's
    /// read of "the current keys" (REG-3.7), answered as of the position the
    /// mirror stands at.
    pub(crate) fn keys_at_head(&mut self, account: &Address) -> Result<Option<Vec<Enrolled>>, MirrorError> {
        let head = self.head;
        self.keys_opening(account, head)
    }

    /// THE CURRENT KEYS of `account` as this mirror holds them — the set that
    /// opens it as of the mirror's head (REG-3.7, REG-3.39's fold), empty
    /// where none; the claimant's are the registrar's.
    pub fn current_keys(&mut self, account: &Address) -> Result<Vec<Enrolled>, MirrorError> {
        Ok(self.keys_at_head(account)?.unwrap_or_default())
    }

    /// THE ATOM at `addr` in `home`: the cache; the head where it is arranged
    /// there (the append-only guess, then the head's whole image); THE CHAIN
    /// WALK down the home's members (REG-3.25); the position read off the
    /// feed (REG-3.26); else `None`.
    fn fetch_atom(&mut self, at: u64, home: &Address, addr: &Address) -> Result<Option<String>, MirrorError> {
        if let Some(t) = self.fetched.atoms.get(addr) {
            return Ok(Some(t.clone()));
        }
        if self.board.is_none() {
            return Ok(None);
        }
        // The head, through its cached image where one is held.
        if let Some(pos) = self.images.get(home).and_then(|i| i.position_of(addr)) {
            if let Some(text) = self.retrieve(home, pos)? {
                return self.keep_atom(addr, text);
            }
        }
        // The append-only guess: a doc 1 written only by deposits arranges
        // its content ordinal n at V-ordinal n.
        let has_members = self.members.get(home).is_some_and(|m| !m.is_empty());
        if !has_members {
            if let Some(n) = content_ordinal_in(home, addr) {
                if let Some(runs) = self.image(home, n, 1)? {
                    if runs.len() == 1 && runs[0].0 == *addr && runs[0].1 == 1 {
                        if let Some(text) = self.retrieve(home, n)? {
                            return self.keep_atom(addr, text);
                        }
                    }
                }
            }
        }
        // The head's whole image.
        if let Some(image) = self.image_of(home)? {
            if let Some(pos) = image.position_of(addr) {
                if let Some(text) = self.retrieve(home, pos)? {
                    return self.keep_atom(addr, text);
                }
            }
        }
        // THE CHAIN WALK (REG-3.25): every member, newest first.
        let t = Instant::now();
        let reads_before = self.board_ref()?.reads().total();
        self.probe_members(home)?;
        let members = self.members.get(home).cloned().unwrap_or_default();
        let mut visited = 0;
        let mut found = None;
        for member in members.iter().rev() {
            visited += 1;
            if let Some(image) = self.image_of(member)? {
                if let Some(pos) = image.position_of(addr) {
                    found = self.retrieve(member, pos)?;
                    if found.is_some() {
                        break;
                    }
                }
            }
        }
        if visited > 0 {
            self.stats.chain_walk.versions_visited += visited;
            self.stats.chain_walk.reads += self.board_ref()?.reads().total() - reads_before;
            self.stats.chain_walk.time += t.elapsed();
        }
        if let Some(text) = found {
            self.stats.chain_walk.atoms += 1;
            return self.keep_atom(addr, text);
        }
        // THE POSITION READ (REG-3.26), where the reader holds the feed.
        if let Some(text) = self.position_read(at, home, addr)? {
            self.stats.chain_walk.position_reads += 1;
            return self.keep_atom(addr, text);
        }
        Ok(None)
    }

    fn keep_atom(&mut self, addr: &Address, text: String) -> Result<Option<String>, MirrorError> {
        self.append_cache(json!({ "atom": { "address": addr.to_string(), "text": text } }))?;
        self.fetched.atoms.insert(addr.clone(), text.clone());
        Ok(Some(text))
    }

    /// The members of `home`'s chain, probed off the board where the feed
    /// has not named them: `D.1`, `D.2`, … until one is unregistered.
    fn probe_members(&mut self, home: &Address) -> Result<(), MirrorError> {
        if self.members_probed.get(home).copied().unwrap_or(false) {
            return Ok(());
        }
        let mut k = 1u64;
        let mut found = Vec::new();
        while let Some(member) = parse_address(&format!("{home}.{k}")) {
            if self.span_set(&member)?.is_none() {
                break;
            }
            found.push(member);
            k += 1;
        }
        let list = self.members.entry(home.clone()).or_default();
        for m in found {
            if !list.contains(&m) {
                list.push(m);
            }
        }
        self.members_probed.insert(home.clone(), true);
        Ok(())
    }

    /// The whole image of `doc` (a document or a member), cached.
    fn image_of(&mut self, doc: &Address) -> Result<Option<Image>, MirrorError> {
        if let Some(i) = self.images.get(doc) {
            return Ok(Some(i.clone()));
        }
        let Some(extent) = self.span_set(doc)? else { return Ok(None) };
        let runs = if extent == 0 { Some(Vec::new()) } else { self.image(doc, 1, extent)? };
        let Some(runs) = runs else { return Ok(None) };
        let image = Image { runs };
        self.images.insert(doc.clone(), image.clone());
        Ok(Some(image))
    }

    /// `retrieve_doc_v_span_set`: the content extent of `doc`, `None` where
    /// the read is refused (an unregistered member).
    fn span_set(&self, doc: &Address) -> Result<Option<u64>, MirrorError> {
        let v = self.board_ref()?.op(&json!({ "op": "retrieve_doc_v_span_set", "doc": doc.to_string() }))?;
        if v["resp"].as_str() != Some("span_set") {
            return Ok(None);
        }
        let extent = v["set"]
            .as_array()
            .and_then(|set| set.iter().find(|s| s["start"].as_str() == Some("1.1")))
            .and_then(|s| s["width"].as_str()?.strip_prefix("0.")?.parse::<u64>().ok())
            .unwrap_or(0);
        Ok(Some(extent))
    }

    /// `image`: the runs at content ordinals `from ..` of `doc`, `None`
    /// where refused.
    fn image(&self, doc: &Address, from: u64, width: u64) -> Result<Option<Vec<(Address, u64)>>, MirrorError> {
        let v = self.board_ref()?.op(&json!({ "op": "image", "d": doc.to_string(), "region": [{ "start": format!("1.{from}"), "width": format!("0.{width}") }] }))?;
        if v["resp"].as_str() != Some("runs") {
            return Ok(None);
        }
        Ok(runs_of(&v))
    }

    /// `retrieve_v`: the atom at content ordinal `pos` of `doc`, `None`
    /// where refused or no atom stands there.
    fn retrieve(&self, doc: &Address, pos: u64) -> Result<Option<String>, MirrorError> {
        let v = self.board_ref()?.op(&retrieve_frame(&doc.to_string(), pos))?;
        Ok(atom_of(&v))
    }

    /// THE POSITION READ (REG-3.26): the home as of the link's position,
    /// through `/op-at` — the extent, the image, the value.
    fn position_read(&self, at: u64, home: &Address, addr: &Address) -> Result<Option<String>, MirrorError> {
        let board = self.board_ref()?;
        let v = board.op_at(at, &json!({ "op": "retrieve_doc_v_span_set", "doc": home.to_string() }))?;
        let Some(extent) = v["set"]
            .as_array()
            .and_then(|set| set.iter().find(|s| s["start"].as_str() == Some("1.1")))
            .and_then(|s| s["width"].as_str()?.strip_prefix("0.")?.parse::<u64>().ok())
        else {
            return Ok(None);
        };
        let v = board.op_at(at, &json!({ "op": "image", "d": home.to_string(), "region": [{ "start": "1.1", "width": format!("0.{extent}") }] }))?;
        let Some(runs) = runs_of(&v) else { return Ok(None) };
        let Some(pos) = (Image { runs }).position_of(addr) else { return Ok(None) };
        let v = board.op_at(at, &retrieve_frame(&home.to_string(), pos))?;
        Ok(atom_of(&v))
    }
}

/// Dial the hint's origins in order; the first that answers `/health` is the
/// root.
fn dial_root(hint: &RootHint, dial: &Dial<'_>) -> Result<(Origin, Board), MirrorError> {
    let mut tried = Vec::new();
    for origin in &hint.origins {
        match dial(origin) {
            Ok(transport) => {
                let board = Board::new(transport);
                match board.health() {
                    Ok(_) => return Ok((origin.clone(), board)),
                    Err(e) => tried.push(format!("{origin}: {e}")),
                }
            }
            Err(e) => tried.push(format!("{origin}: {e}")),
        }
    }
    Err(MirrorError::Unreachable { tried })
}

/// Retire the copy of another realm beside the new one (REG-3.17).
fn retire(dir: &Path, realm: Fingerprint) -> Result<PathBuf, MirrorError> {
    let suffix = format!("retired-{}", &realm.to_hex()[..16]);
    let feed_to = dir.join(format!("{FEED_COPY}.{suffix}"));
    let cache_to = dir.join(format!("{FETCH_CACHE}.{suffix}"));
    fs::rename(dir.join(FEED_COPY), &feed_to).map_err(|e| MirrorError::Copy(format!("retire: {e}")))?;
    let cache = dir.join(FETCH_CACHE);
    if cache.exists() {
        fs::rename(&cache, &cache_to).map_err(|e| MirrorError::Copy(format!("retire: {e}")))?;
    }
    Ok(feed_to)
}

fn retrieve_frame(doc: &str, pos: u64) -> Value {
    json!({ "op": "retrieve_v", "specs": [{ "doc": doc, "span": { "start": format!("1.{pos}"), "width": "0.1" } }] })
}

/// The one atom a one-position delivery carries, where it carries one.
fn atom_of(v: &Value) -> Option<String> {
    if v["resp"].as_str() != Some("delivery") {
        return None;
    }
    let items = v["items"].as_array()?;
    if items.len() != 1 {
        return None;
    }
    items[0]["atom"].as_str().map(str::to_string)
}

/// A `runs` answer as `(i_start, width)` pairs.
fn runs_of(v: &Value) -> Option<Vec<(Address, u64)>> {
    v["runs"].as_array()?.iter().map(|r| {
        let start = parse_address(r["i_start"].as_str()?)?;
        let width = r["width"].as_str()?.parse::<u64>().ok()?;
        Some((start, width))
    }).collect()
}

/// A unit subtree span over `a` as the wire spells one.
fn unit_span_json(a: &Address) -> Value {
    let span = skep_identity::unit_span(a);
    json!({ "start": span.start().to_string(), "width": span.width().to_string() })
}

/// A stored link line read back.
fn stored_link_of(l: &Value) -> Option<StoredLink> {
    let addrs = |key: &str| -> Vec<Address> {
        l[key].as_array().map(|a| a.iter().filter_map(|x| x.as_str().and_then(parse_address)).collect()).unwrap_or_default()
    };
    Some(StoredLink {
        at: l["at"].as_u64()?,
        address: parse_address(l["address"].as_str()?)?,
        home: parse_address(l["home"].as_str()?)?,
        ty: l["ty"].as_str().and_then(parse_address),
        from: addrs("from"),
        to: addrs("to"),
    })
}

/// A keys line read back.
fn keys_of(k: &Value) -> Option<KeysAsOf> {
    Some(KeysAsOf {
        account: parse_address(k["account"].as_str()?)?,
        epoch: k["epoch"].as_u64()?,
        at: k["at"].as_u64()?,
        enrolled: k["enrolled"].as_array()?.iter().filter_map(enrolled_of).collect(),
    })
}

/// One `key_set` entry as an [`Enrolled`]: `alg`, `key` (hex), `anchor`.
fn enrolled_of(e: &Value) -> Option<Enrolled> {
    let key = PublicKey::parse(e["alg"].as_str()?, e["key"].as_str()?).ok()?;
    Some(Enrolled { key, anchor: e["anchor"].as_bool().unwrap_or(false) })
}

/// The ACCOUNT a document belongs to, by address arithmetic (R5 (j)): the
/// address with its document field removed — ω over a doc 1 is its own
/// account's prefix.
pub fn account_of_document(doc: &Address) -> Option<Address> {
    let d = document_of(doc)?;
    let comps: Vec<Nat> = d.tumbler().iter().cloned().collect();
    // The second separator is the one before the document field.
    let second_zero = comps.iter().enumerate().filter(|(_, c)| **c == Nat::from(0u32)).map(|(i, _)| i).nth(1)?;
    let account = Tumbler::new(comps[..second_zero].iter().cloned()).ok()?;
    skep_address::validate(account).ok()
}

/// The TRUNK of a document or a version member: the document address cut
/// after the document field's first component (`1.0.1.0.1.2` → `1.0.1.0.1`).
pub fn trunk_of(doc: &Address) -> Option<Address> {
    let d = document_of(doc)?;
    let comps: Vec<Nat> = d.tumbler().iter().cloned().collect();
    let second_zero = comps.iter().enumerate().filter(|(_, c)| **c == Nat::from(0u32)).map(|(i, _)| i).nth(1)?;
    let trunk = Tumbler::new(comps[..=second_zero + 1].iter().cloned()).ok()?;
    skep_address::validate(trunk).ok()
}

/// Where `addr` is a content element of `home` itself — `home.0.1.n` — its
/// ordinal `n`.
fn content_ordinal_in(home: &Address, addr: &Address) -> Option<u64> {
    if document_of(addr)? != *home {
        return None;
    }
    let element = addr.element_field()?;
    if element.len() != 2 || element[0] != Nat::from(1u32) {
        return None;
    }
    u64::try_from(&element[1]).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn a(s: &str) -> Address {
        parse_address(s).unwrap()
    }

    /// The address arithmetic the fold rests on: a doc 1's account, a
    /// member's trunk, a content element's ordinal in its own document.
    #[test]
    fn the_homes_account_and_trunk_are_read_by_arithmetic() {
        assert_eq!(account_of_document(&a("1.0.1.0.1")), Some(a("1.0.1")));
        assert_eq!(account_of_document(&a("1.0.2.3.0.1")), Some(a("1.0.2.3")));
        assert_eq!(account_of_document(&a("1.0.1.0.1.2")), Some(a("1.0.1")), "a member's account");
        assert_eq!(account_of_document(&a("1.0.1.0.1.0.1.4")), Some(a("1.0.1")), "an element's");
        assert_eq!(account_of_document(&a("1.0.1")), None);
        assert_eq!(trunk_of(&a("1.0.1.0.1.2")), Some(a("1.0.1.0.1")));
        assert_eq!(trunk_of(&a("1.0.1.0.1.2.1")), Some(a("1.0.1.0.1")), "a daughter's trunk");
        assert_eq!(trunk_of(&a("1.0.1.0.1")), Some(a("1.0.1.0.1")));
        assert_eq!(trunk_of(&a("1.0.1.0.1.0.1.4")), Some(a("1.0.1.0.1")));
        assert_eq!(content_ordinal_in(&a("1.0.1.0.1"), &a("1.0.1.0.1.0.1.4")), Some(4));
        assert_eq!(content_ordinal_in(&a("1.0.1.0.1"), &a("1.0.1.0.1.0.2.4")), None, "a link element");
        assert_eq!(content_ordinal_in(&a("1.0.1.0.1"), &a("1.0.1.0.1.1.0.1.4")), None, "a member's mint");
        let image = Image { runs: vec![(a("1.0.1.0.1.0.1.1"), 2), (a("1.0.1.0.1.0.1.7"), 3)] };
        assert_eq!(image.position_of(&a("1.0.1.0.1.0.1.2")), Some(2));
        assert_eq!(image.position_of(&a("1.0.1.0.1.0.1.8")), Some(4));
        assert_eq!(image.position_of(&a("1.0.1.0.1.0.1.3")), None);
    }
}
