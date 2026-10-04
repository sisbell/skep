//! THE MIRROR (REG-3.10 to REG-3.13, REG-3.17 to REG-3.19; R5 (a), (b)) —
//! the registry board's `/changes` feed IS the mirror protocol: a consumer
//! from the floor that is EXACT, not TTL-bounded-stale, applying no TTL and
//! negative-caching nothing (REG-3.10: a prefix no binding names is asked
//! again at the next delta and never remembered as absent).
//!
//! This file holds the mirror's types and its state, the journal copy's
//! lines, and the fold with the fetches it makes per row. Beneath it, three
//! children, each an `impl Mirror` that reads this module's private state
//! the way a child does, so nothing here is widened for them:
//!
//! * [`base`] — the base: the open, the resume's check and its refusals,
//!   the realm check, the sync and the pull (REG-3.12, REG-3.13, REG-3.17
//!   to REG-3.19, REG-3.42).
//! * [`keys`] — the set that opens an account as of a position, and the
//!   credential acts that set is read by.
//! * [`atoms`] — a record's bytes: the head, the chain walk, the position
//!   read (REG-3.25, REG-3.26), and the walk's memory between two pulls.
//!
//! One ordering crosses them: every row is held before any is folded (the
//! pull, in [`base`]), and the fold takes the held rows in two passes —
//! every credential act among them recorded first, then each row folded —
//! because the fold's as-of reads lean on the acts AFTER a record's position
//! (the floor's clause, in [`keys`]). So three positions are read off the
//! held rows, each for its own use: where the copy ends
//! ([`Mirror::held_through`], the next pull's start), how far the credential
//! pass has read ([`Mirror::acts_through`], how far a live table can be
//! proven), and the head (the last row folded). A sync that fails leaves the
//! copy's end ahead of the head and the credential pass anywhere between the
//! two; the next sync takes each up where it stopped.
//!
//! FETCH-AND-FOLD. The mirror reads every row of the feed as the GUEST and
//! fetches the bytes a row's record needs — the stored link (`read_link`),
//! the binding's or the endpoint's atom (`retrieve_v` at the position the
//! link's `from` names), and the credential table of the home it verifies
//! against, AS OF the record's position and never the live table for a
//! historical verdict: the live `key_set` where the credential acts the
//! mirror holds prove none of the account's lies between the position and
//! the live answer's `as_of` (the same table, by the mirror's own evidence),
//! the historical `key_set` on `/op-at` otherwise — then verifies the record
//! ([`crate::verify`]) and folds it into the index ([`crate::index`]). Every
//! read is the board's own journal (R5 (a)).
//!
//! THE JOURNAL COPY (the copy's on-disk form, an interim pin), under the
//! caller's directory, two files of JSON lines, begun together by a new base
//! and appended to by a held one — so a cache that outlived its feed copy is
//! never read as this base's own. No line reaches either file before the
//! realm is compared at the claim's row (REG-3.42): until then every line
//! waits, so a base refused at the realm — a fresh one or a held one —
//! writes nothing.
//!
//! * `feed.jsonl` — THE COPY OF THE FEED, what the check covers and what a
//!   courier could ship: a header `{"skep-resolve":"feed-v1","realm":<hex>,
//!   "root":<origin>}`, then one `{"row":<entry>}` per feed row in position
//!   order, exactly as the board served it, and a `{"head":{"at":N,
//!   "chain":<hex>}}` after each sync — the chain pair the resume compares;
//!   every line of it written and read back in [`base`], the format stamp
//!   checked on every read.
//! * `fetched.jsonl` — THIS MIRROR'S OWN FETCH CACHE, what the fold read off
//!   the board: `{"link":{…}}` a stored link's slots, `{"atom":{"address",
//!   "text"}}` a record's bytes, `{"keys":{"account","epoch","at",
//!   "enrolled":[…]}}` a credential table as of a position, `{"retracted":
//!   {"at","link"}}` a retraction the fold found, `{"board":{"position",
//!   "chain"}}` the board term, `{"claim":{"at","claimant"}}` the claim —
//!   each line written and read back by `Fetched` alone, the format's one
//!   writer and one reader, which writes a line only for a value it does not
//!   hold already. The REBUILD of the index is a re-read of the
//!   feed copy at the deposits' own positions (REG-3.25) with every fetch
//!   served from this cache, so it reads no wire; where a line is absent the
//!   fold fetches afresh. A cache adopted from a stranger is that stranger's
//!   word (REG-3.14's residue): only the feed copy is checked against the
//!   root, and the realm is never read off the cache.
//!
//! THE BINDING-WRITING ACCOUNT (R5 (g); REG-2.8): on an unforked lineage the
//! bindings the walk reads are the CLAIMANT's — a binding deposited in any
//! other home is no registrar's binding and enters no index, counted apart.

mod atoms;
mod base;
mod keys;

use std::collections::BTreeMap;
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, BufWriter, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use serde_json::{json, Value};
use skep_address::{document_of, Address, Nat, Tumbler};
use skep_identity::{doc_1_of, BoardTerm, Enrolled, Fingerprint, PublicKey};
use skep_registry::{commons_type, parse, t_binding, t_endpoint, Body, BodyKind};

use atoms::Chains;
use crate::board::{parse_chain, Board, BoardError, Reads};
use crate::hint::RootHint;
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
    /// The claimant's genesis set is not held, or this build could not read
    /// it: no realm can be computed.
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
            MirrorError::NoGenesis => f.write_str("the claim's genesis set could not be read"),
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
    /// Rebuilt from the copy under the directory alone, no board dialed
    /// (REG-3.25): nothing checked against a source, and the realm the one
    /// the copy's header names.
    Rebuilt,
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

/// A credential table kept under the epoch it belongs to: the account, the
/// epoch, the position it was read for, and the enrolled keys.
#[derive(Debug, Clone, PartialEq, Eq)]
struct KeysAsOf {
    account: Address,
    epoch: u64,
    at: u64,
    enrolled: Vec<Enrolled>,
}

/// The fetch cache in memory — what `fetched.jsonl` holds — and THE ONE
/// WRITER AND READER of that file's format: each kind of line is spelled by
/// its `keep_*` method, which holds the value and answers the line, and read
/// back by [`Fetched::recall`]. A `keep_*` answers a line only for a value
/// it does not hold already — a credential table counting as held where the
/// same keys stand under its account and epoch — so a value read twice, or
/// read again by a resume's fold, is written once.
#[derive(Debug, Default, PartialEq, Eq)]
struct Fetched {
    links: BTreeMap<Address, StoredLink>,
    atoms: BTreeMap<Address, String>,
    keys: BTreeMap<(Address, u64), KeysAsOf>,
    retracted: BTreeMap<u64, Vec<Address>>,
    board: Option<BoardTerm>,
    claim: Option<(u64, Address)>,
}

impl Fetched {
    /// One line of `fetched.jsonl` taken back into memory; a line of no kind
    /// this format writes, or one that does not read whole, holds nothing —
    /// the fold then fetches what it would have held afresh.
    fn recall(&mut self, line: &Value) {
        if let Some(l) = line.get("link") {
            if let Some(link) = stored_link_of(l) {
                self.links.insert(link.address.clone(), link);
            }
        } else if let Some(a) = line.get("atom") {
            if let (Some(addr), Some(text)) = (a["address"].as_str().and_then(parse_address), a["text"].as_str()) {
                self.atoms.insert(addr, text.to_string());
            }
        } else if let Some(k) = line.get("keys") {
            if let Some(keys) = keys_of(k) {
                self.keys.insert((keys.account.clone(), keys.epoch), keys);
            }
        } else if let Some(r) = line.get("retracted") {
            if let (Some(at), Some(link)) = (r["at"].as_u64(), r["link"].as_str().and_then(parse_address)) {
                self.retracted.entry(at).or_default().push(link);
            }
        } else if let Some(b) = line.get("board") {
            if let (Some(p), Some(c)) = (b["position"].as_u64(), b["chain"].as_str().and_then(parse_chain)) {
                self.board = Some(BoardTerm { log_position: p, chain: c });
            }
        } else if let Some(c) = line.get("claim") {
            if let (Some(at), Some(who)) = (c["at"].as_u64(), c["claimant"].as_str().and_then(parse_address)) {
                self.claim = Some((at, who));
            }
        }
    }

    /// A stored link held; its `{"link":{…}}` line, where it is new.
    fn keep_link(&mut self, link: StoredLink) -> Option<Value> {
        if self.links.get(&link.address) == Some(&link) {
            return None;
        }
        let line = json!({ "link": {
            "at": link.at,
            "address": link.address.to_string(),
            "home": link.home.to_string(),
            "ty": link.ty.as_ref().map(ToString::to_string),
            "from": link.from.iter().map(ToString::to_string).collect::<Vec<_>>(),
            "to": link.to.iter().map(ToString::to_string).collect::<Vec<_>>(),
        }});
        self.links.insert(link.address.clone(), link);
        Some(line)
    }

    /// A record's bytes held; its `{"atom":{…}}` line, where they are new.
    fn keep_atom(&mut self, address: Address, text: String) -> Option<Value> {
        if self.atoms.get(&address) == Some(&text) {
            return None;
        }
        let line = json!({ "atom": { "address": address.to_string(), "text": text } });
        self.atoms.insert(address, text);
        Some(line)
    }

    /// A credential table held under its epoch; its `{"keys":{…}}` line, each
    /// enrolled key spelled as [`enrolled_line_of`] reads it back, where the
    /// account's table at that epoch is not these keys already.
    fn keep_keys(&mut self, keys: KeysAsOf) -> Option<Value> {
        let key = (keys.account.clone(), keys.epoch);
        if self.keys.get(&key).is_some_and(|held| held.enrolled == keys.enrolled) {
            return None;
        }
        let line = json!({ "keys": {
            "account": keys.account.to_string(),
            "epoch": keys.epoch,
            "at": keys.at,
            "enrolled": keys.enrolled.iter().map(|e| json!({ "alg": e.key.alg(), "key": e.key.to_hex(), "anchor": e.anchor })).collect::<Vec<_>>(),
        }});
        self.keys.insert(key, keys);
        Some(line)
    }

    /// A retraction held; its `{"retracted":{…}}` line, where it is new.
    fn keep_retracted(&mut self, at: u64, link: Address) -> Option<Value> {
        if self.retracted.get(&at).is_some_and(|held| held.contains(&link)) {
            return None;
        }
        let line = json!({ "retracted": { "at": at, "link": link.to_string() } });
        self.retracted.entry(at).or_default().push(link);
        Some(line)
    }

    /// The board term held; its `{"board":{…}}` line, the chain as the board
    /// spelled it, where the term is new.
    fn keep_board(&mut self, term: BoardTerm, chain: &str) -> Option<Value> {
        if self.board == Some(term) {
            return None;
        }
        self.board = Some(term);
        Some(json!({ "board": { "position": term.log_position, "chain": chain } }))
    }

    /// The claim held; its `{"claim":{…}}` line, where it is new.
    fn keep_claim(&mut self, at: u64, claimant: Address) -> Option<Value> {
        if self.claim.as_ref().is_some_and(|(held_at, held)| *held_at == at && *held == claimant) {
            return None;
        }
        let line = json!({ "claim": { "at": at, "claimant": claimant.to_string() } });
        self.claim = Some((at, claimant));
        Some(line)
    }
}

/// One JSON-lines file of the copy, written a line at a time: a file this
/// mirror holds, appended to ([`Lines::held`]), or one a new base begins,
/// whatever the path held before cut away by its first line
/// ([`Lines::begin`]).
struct Lines {
    path: PathBuf,
    out: Option<BufWriter<File>>,
    /// Whether the first line written truncates what the path held.
    begins: bool,
    bytes: u64,
}

impl Lines {
    /// A file this mirror holds, appended to — its bytes counted from the
    /// length it has now, none where it is absent.
    fn held(path: PathBuf) -> Lines {
        let bytes = fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
        Lines { path, out: None, begins: false, bytes }
    }

    /// A file a new base begins: nothing of what the path held survives its
    /// first line, and nothing is cut before that line — so a base refused
    /// before its first line leaves the path as it found it.
    fn begin(path: PathBuf) -> Lines {
        Lines { path, out: None, begins: true, bytes: 0 }
    }

    fn append(&mut self, line: &Value) -> Result<(), MirrorError> {
        let text = line.to_string();
        if self.out.is_none() {
            let mut options = OpenOptions::new();
            if self.begins {
                options.write(true).create(true).truncate(true);
            } else {
                options.create(true).append(true);
            }
            let file = options
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
/// two record kinds (`skep_registry`'s pins) and the three credential kinds
/// at the commons' `3.1`–`3.3` (wire.md §The claim ceremony and
/// credentials).
struct Types {
    binding: Address,
    endpoint: Address,
    enroll: Address,
    retire: Address,
    claim: Address,
}

impl Types {
    fn new() -> Types {
        Types {
            binding: t_binding().clone(),
            endpoint: t_endpoint().clone(),
            enroll: commons_type(&[1]),
            retire: commons_type(&[2]),
            claim: commons_type(&[3]),
        }
    }
}

/// THE MIRROR: the hint it is scoped to, the board it reads, its copy, its
/// fetch cache, and the index it derives.
///
/// A mirror stays on the thread that opened it: the board it reads holds
/// the caller's [`Transport`](crate::Transport), which this crate does not
/// require to be `Send`. What it answers crosses threads. The twin below
/// compiles and the refusal beside it does not, the type the one difference:
///
/// ```
/// fn send<T: Send>() {}
/// send::<skep_resolve::Resolution>();
/// ```
/// ```compile_fail,E0277
/// fn send<T: Send>() {}
/// send::<skep_resolve::Mirror>();
/// ```
pub struct Mirror {
    hint: RootHint,
    root: Option<Origin>,
    board: Option<Board>,
    dir: PathBuf,
    feed: Lines,
    cache: Lines,
    /// The lines waiting on the realm's comparison, in order.
    pending_feed: Vec<Value>,
    pending_cache: Vec<Value>,
    fetched: Fetched,
    index: Index,
    types: Types,
    /// Every feed row held, in position order — the copy in memory.
    rows: Vec<Value>,
    /// How many of `rows` the credential pass has read.
    scanned: usize,
    /// How many of `rows` the fold has consumed.
    folded: usize,
    /// The position of the last row the fold took.
    head: u64,
    /// Whether this mirror compared the claimant's genesis set against the
    /// hint (REG-3.42) — the gate every line passes to reach the copy: until
    /// it, lines wait in `pending_feed` and `pending_cache`.
    realm_compared: bool,
    /// Every credential position of each account among the held rows, in
    /// position order — the epochs a table is kept under, and the acts the
    /// as-of reads are proven by.
    epochs: BTreeMap<Address, Vec<u64>>,
    /// The chain walk's memory between two pulls.
    chains: Chains,
    stats: Stats,
    opened: Opened,
}

impl Mirror {
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

    /// The members of `home`'s version chain the mirror knows, oldest first.
    pub fn members_of(&self, home: &Address) -> &[Address] {
        self.chains.members_of(home)
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

    /// THE COPY'S FRONTIER: the position of the last row held, the copy's
    /// last — where the next pull starts. Ahead of `head` where a sync held
    /// rows and failed before the fold took them; those rows wait for the
    /// next fold and are never asked for again.
    fn held_through(&self) -> u64 {
        self.rows.last().and_then(position).unwrap_or(self.head)
    }

    /// How far THE CREDENTIAL ACTS are known: the position of the last row
    /// the credential pass read — the bound inside which the held feed proves
    /// a table unchanged. Behind [`Mirror::held_through`] where a sync failed
    /// inside that pass.
    fn acts_through(&self) -> u64 {
        self.scanned.checked_sub(1).and_then(|last| position(&self.rows[last])).unwrap_or(self.head)
    }

    // ── the copy's lines ────────────────────────────────────────────────────

    fn append_feed(&mut self, line: Value) -> Result<(), MirrorError> {
        if self.realm_compared {
            self.feed.append(&line)
        } else {
            self.pending_feed.push(line);
            Ok(())
        }
    }

    /// A line a `keep_*` of [`Fetched`] answered, written — none where the
    /// value was held already, and none on a mirror with no board, whose
    /// every value came off the cache.
    fn append_cache(&mut self, line: Option<Value>) -> Result<(), MirrorError> {
        let Some(line) = line else { return Ok(()) };
        if self.board.is_none() {
            return Ok(());
        }
        if self.realm_compared {
            self.cache.append(&line)
        } else {
            self.pending_cache.push(line);
            Ok(())
        }
    }

    /// The realm compared: every line that waited on it written, in order —
    /// a new copy's header first.
    fn flush_pending(&mut self) -> Result<(), MirrorError> {
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
            self.fetched.recall(&line);
        }
        Ok(())
    }

    // ── the fold ────────────────────────────────────────────────────────────

    /// One feed row, folded (the module doc's fetch-and-fold).
    fn fold_row(&mut self, row: &Value) -> Result<(), MirrorError> {
        if let Some((at, link, home)) = link_row(row) {
            return self.fold_link(at, &link, &home);
        }
        let at = position(row).unwrap_or(0);
        let docs = docs_of(row);
        match row["op"].as_str() {
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
                    self.chains.learn(member);
                }
            }
            _ => {}
        }
        Ok(())
    }

    /// One link row: the claim — the realm compared at its row, on every open
    /// that holds a board — or a binding or an endpoint, judged and folded.
    /// A credential act moves nothing here: the first pass recorded it.
    fn fold_link(&mut self, at: u64, link: &Address, home: &Address) -> Result<(), MirrorError> {
        let Some(stored) = self.read_link(at, link, home)? else { return Ok(()) };
        let Some(ty) = stored.ty.clone() else { return Ok(()) };
        if ty == self.types.claim {
            if let Some(claimant) = stored.from.first().cloned() {
                let line = self.fetched.keep_claim(at, claimant);
                self.append_cache(line)?;
                if !self.realm_compared && self.board.is_some() {
                    self.realm_check()?;
                }
            }
        } else if ty == self.types.binding {
            match &self.fetched.claim {
                Some((_, claimant)) if doc_1_of(claimant) == *home => {
                    self.fold_record(BodyKind::Binding, &stored)?;
                }
                _ => self.stats.foreign_bindings += 1,
            }
        } else if ty == self.types.endpoint {
            self.fold_record(BodyKind::Endpoint, &stored)?;
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
                // The lineage row EMPTY: this build composes every record
                // grade so (D2; wire.md §Registry), and the hint's fork point
                // is not read into the frame.
                let trial = Trial {
                    board,
                    home: &link.home,
                    home_account: &home_account,
                    ty: &ty,
                    to: &link.to,
                    lineage: None,
                    keys: &keys,
                };
                let v = judge(&record, &trial);
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

    // ── the fetches a row makes ─────────────────────────────────────────────

    /// The stored link at `link`, from the cache or `read_link`; `None`
    /// where no link stands there.
    fn read_link(&mut self, at: u64, link: &Address, home: &Address) -> Result<Option<StoredLink>, MirrorError> {
        if let Some(s) = self.fetched.links.get(link) {
            return Ok(Some(s.clone()));
        }
        let Some(board) = self.board.as_ref() else { return Ok(None) };
        let Some([from, to, ty]) = board.link_slots(link)? else { return Ok(None) };
        let stored = StoredLink {
            at,
            address: link.clone(),
            home: home.clone(),
            ty: (ty.len() == 1).then(|| ty[0].clone()),
            from,
            to,
        };
        let line = self.fetched.keep_link(stored.clone());
        self.append_cache(line)?;
        Ok(Some(stored))
    }

    /// Whether a retraction link targeting `link` stands at `at` — the
    /// `nullify`'s own deposit ([`Board::retraction_stands`]), from the cache
    /// or the board.
    fn retracted(&mut self, at: u64, link: &Address) -> Result<bool, MirrorError> {
        if self.fetched.retracted.get(&at).is_some_and(|l| l.contains(link)) {
            return Ok(true);
        }
        let Some(board) = self.board.as_ref() else { return Ok(false) };
        let found = board.retraction_stands(link)?;
        if found {
            let line = self.fetched.keep_retracted(at, link.clone());
            self.append_cache(line)?;
        }
        Ok(found)
    }

    /// THE BOARD TERM ([`Board::board_term`]), read once; `None` where the
    /// board holds none (then every verdict is UNDETERMINABLE HERE).
    fn board_term(&mut self) -> Result<Option<BoardTerm>, MirrorError> {
        if let Some(b) = self.fetched.board {
            return Ok(Some(b));
        }
        let Some(board) = self.board.as_ref() else { return Ok(None) };
        let Some((term, chain)) = board.board_term()? else { return Ok(None) };
        let line = self.fetched.keep_board(term, &chain);
        self.append_cache(line)?;
        Ok(Some(term))
    }
}

/// A LINK ROW — an unattested `make_link`, the row every record deposit and
/// every credential deposit commits (wire.md §Registry: "the link's row on
/// `/changes` carries neither `key` nor `attest`, as a credential deposit's
/// does") — as its position, its link and its home, the first document the
/// row names; `None` for every other row. The fold and the credential pass
/// both read a row's link through here.
fn link_row(row: &Value) -> Option<(u64, Address, Address)> {
    if row["op"].as_str() != Some("make_link") || row.get("attest").is_some() {
        return None;
    }
    let link = row["link"].as_str().and_then(parse_address)?;
    let home = docs_of(row).into_iter().next()?;
    Some((position(row).unwrap_or(0), link, home))
}

/// A feed row's position, where it names one — the one reading of a row's
/// `at` every position the mirror keeps is taken through.
fn position(row: &Value) -> Option<u64> {
    row["at"].as_u64()
}

/// The documents a feed row names, in its order, each that is an address.
fn docs_of(row: &Value) -> Vec<Address> {
    row["docs"]
        .as_array()
        .map(|d| d.iter().filter_map(|a| a.as_str().and_then(parse_address)).collect())
        .unwrap_or_default()
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

/// A keys line read back — whole, or not at all: an entry that does not read
/// refuses the line, so the cache never holds a smaller table than the one
/// it kept.
fn keys_of(k: &Value) -> Option<KeysAsOf> {
    Some(KeysAsOf {
        account: parse_address(k["account"].as_str()?)?,
        epoch: k["epoch"].as_u64()?,
        at: k["at"].as_u64()?,
        enrolled: k["enrolled"].as_array()?.iter().map(enrolled_line_of).collect::<Option<_>>()?,
    })
}

/// One enrolled key as a keys line spells it — `alg`, `key` (hex), `anchor`
/// — the cache's own spelling, as [`Fetched::keep_keys`] writes it.
fn enrolled_line_of(e: &Value) -> Option<Enrolled> {
    let key = PublicKey::parse(e["alg"].as_str()?, e["key"].as_str()?).ok()?;
    Some(Enrolled { key, anchor: e["anchor"].as_bool()? })
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

#[cfg(test)]
mod tests {
    use skep_signature::{HybridSigner, TAG_MLDSA65_ED25519};

    use super::*;

    fn a(s: &str) -> Address {
        parse_address(s).unwrap()
    }

    /// The address arithmetic the fold rests on: a doc 1's account.
    #[test]
    fn the_homes_account_is_read_by_arithmetic() {
        assert_eq!(account_of_document(&a("1.0.1.0.1")), Some(a("1.0.1")));
        assert_eq!(account_of_document(&a("1.0.2.3.0.1")), Some(a("1.0.2.3")));
        assert_eq!(account_of_document(&a("1.0.1.0.1.2")), Some(a("1.0.1")), "a member's account");
        assert_eq!(account_of_document(&a("1.0.1.0.1.0.1.4")), Some(a("1.0.1")), "an element's");
        assert_eq!(account_of_document(&a("1.0.1")), None);
    }

    /// A link row is an unattested `make_link` with a link and a home — the
    /// row a record deposit and a credential deposit alike commit; an
    /// attested one, a row of another op, and one naming no document are
    /// none.
    #[test]
    fn a_link_row_is_an_unattested_make_link() {
        let row = json!({ "at": 7, "op": "make_link", "link": "1.0.2.0.1.0.2.1", "docs": ["not an address", "1.0.2.0.1"] });
        assert_eq!(link_row(&row), Some((7, a("1.0.2.0.1.0.2.1"), a("1.0.2.0.1"))), "the home is the first document that is an address");
        let mut attested = row.clone();
        attested["attest"] = json!({});
        assert_eq!(link_row(&attested), None);
        assert_eq!(link_row(&json!({ "at": 7, "op": "nullify", "link": "1.0.2.0.1.0.2.1", "docs": ["1.0.2.0.1"] })), None);
        assert_eq!(link_row(&json!({ "at": 7, "op": "make_link", "link": "1.0.2.0.1.0.2.1", "docs": [] })), None);
    }

    /// THE FETCH CACHE'S FORMAT has one writer and one reader: every kind of
    /// line `Fetched` keeps reads back into the value it kept; a value it
    /// holds already — a credential table read again for another position
    /// of its epoch among them — writes no second line, and another table
    /// under the same epoch does; and a keys line one of whose entries does
    /// not read holds no table at all, never a smaller one.
    #[test]
    fn every_cache_line_reads_back_as_what_was_kept() {
        let key = |seed: u8| HybridSigner::from_seed(TAG_MLDSA65_ED25519, &[seed; 32]).expect("tag 1").public_key().clone();
        let mut kept = Fetched::default();
        let link = StoredLink {
            at: 5,
            address: a("1.0.1.0.1.0.2.1"),
            home: a("1.0.1.0.1"),
            ty: Some(a("1.1.0.1.0.1.0.3.1")),
            from: vec![a("1.0.1.0.1.0.1.1")],
            to: vec![a("1.0.2")],
        };
        let keys = KeysAsOf {
            account: a("1.0.2"),
            epoch: 5,
            at: 9,
            enrolled: vec![Enrolled { key: key(3), anchor: true }, Enrolled { key: key(4), anchor: false }],
        };
        let atom = (a("1.0.1.0.1.0.1.1"), r#"{"type":"binding","prefix":"1.5"}"#.to_string());
        let (term, chain) = (BoardTerm { log_position: 12, chain: [7; 32] }, "07".repeat(32));
        let lines: Vec<Value> = [
            kept.keep_link(link.clone()),
            kept.keep_atom(atom.0.clone(), atom.1.clone()),
            kept.keep_keys(keys.clone()),
            kept.keep_retracted(14, a("1.0.2.0.1.0.2.1")),
            kept.keep_board(term, &chain),
            kept.keep_claim(3, a("1.0.1")),
        ]
        .into_iter()
        .map(|line| line.expect("a value not held writes its line"))
        .collect();
        let mut recalled = Fetched::default();
        for line in &lines {
            recalled.recall(&serde_json::from_str(&line.to_string()).expect("a line is JSON"));
        }
        assert_eq!(recalled, kept);
        let again = [
            kept.keep_link(link),
            kept.keep_atom(atom.0, atom.1),
            kept.keep_keys(KeysAsOf { at: 11, ..keys.clone() }),
            kept.keep_retracted(14, a("1.0.2.0.1.0.2.1")),
            kept.keep_board(term, &chain),
            kept.keep_claim(3, a("1.0.1")),
        ];
        assert!(again.iter().all(Option::is_none), "a value held already writes no line: {again:?}");
        assert_eq!(recalled, kept, "and holds what it held");
        let rotated = KeysAsOf { enrolled: vec![Enrolled { key: key(4), anchor: false }], ..keys };
        assert!(kept.keep_keys(rotated).is_some(), "another table under the epoch is a new line");
        let mut torn = lines[2].clone();
        torn["keys"]["enrolled"][1]["alg"] = json!("no-such-alg");
        let mut held = Fetched::default();
        held.recall(&torn);
        assert!(held.keys.is_empty(), "an entry that does not read refuses the line whole");
    }
}
