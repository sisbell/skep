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
//!   the sync and the pull (REG-3.12, REG-3.13, REG-3.17 to REG-3.19).
//! * [`keys`] — the set that opens an account as of a position.
//! * [`atoms`] — a record's bytes: the head, the chain walk, the position
//!   read (REG-3.25, REG-3.26).
//!
//! One ordering crosses them: every row is held before any is folded (the
//! pull, in [`base`]), because the fold's as-of reads lean on the rows
//! AFTER a record's position (the floor's clause, in [`keys`]).
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
//! THE BINDING-WRITING ACCOUNT (R5 (g); REG-2.8): on an unforked lineage the
//! bindings the walk reads are the CLAIMANT's — a binding deposited in any
//! other home is no registrar's binding and enters no index, counted apart.

mod atoms;
mod base;
mod keys;

use std::collections::BTreeMap;
use std::fmt;
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, BufWriter, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use serde_json::{json, Value};
use skep_address::{document_of, Address, Nat, Tumbler};
use skep_identity::{doc_1_of, BoardTerm, Enrolled, Fingerprint};
use skep_registry::{commons_type, parse, t_binding, t_endpoint, Body, BodyKind};

use atoms::Image;
use crate::board::{enrolled_of, link_slot, parse_chain, Board, BoardError, Reads};
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

/// `H.1`'s address — the head document's first chain member, the board
/// term's carrier (wire.md §The other endpoints).
const HEAD_MEMBER_1: &str = "1.1.0.1.0.2.1";

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

    // ── the copy's lines ────────────────────────────────────────────────────

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

    // ── the fetches a row makes ─────────────────────────────────────────────

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
        let (from, to, ty) = (link_slot(&v, 0), link_slot(&v, 1), link_slot(&v, 2));
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
    /// `nullify`'s own deposit ([`Board::retraction_stands`]), from the cache
    /// or the board.
    fn retracted(&mut self, at: u64, link: &Address) -> Result<bool, MirrorError> {
        if self.fetched.retracted.get(&at).is_some_and(|l| l.contains(link)) {
            return Ok(true);
        }
        let Some(board) = self.board.as_ref() else { return Ok(false) };
        let found = board.retraction_stands(link)?;
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
}

fn retrieve_frame(doc: &str, pos: u64) -> Value {
    json!({ "op": "retrieve_v", "specs": [{ "doc": doc, "span": { "start": format!("1.{pos}"), "width": "0.1" } }] })
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
fn trunk_of(doc: &Address) -> Option<Address> {
    let d = document_of(doc)?;
    let comps: Vec<Nat> = d.tumbler().iter().cloned().collect();
    let second_zero = comps.iter().enumerate().filter(|(_, c)| **c == Nat::from(0u32)).map(|(i, _)| i).nth(1)?;
    let trunk = Tumbler::new(comps[..=second_zero + 1].iter().cloned()).ok()?;
    skep_address::validate(trunk).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn a(s: &str) -> Address {
        parse_address(s).unwrap()
    }

    /// The address arithmetic the fold rests on: a doc 1's account and a
    /// member's trunk.
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
    }
}
