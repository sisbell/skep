//! THE BASE'S PROVENANCE (REG-3.12, REG-3.13; R5 (b)): the base is read FROM
//! GENESIS at the root the hint names — `/changes since=0`, the read that is
//! the check — or from a journal copy this mirror already holds, CHECKED
//! against that same feed before it serves (REG-3.18): the source is read
//! from genesis and the copy resumes only where every position it holds
//! comes back identical through its own head and the chain pairs it held
//! (`/chain?at=N`) answer the same; and the realm is compared at the claim's
//! row on every open that holds a board, against the genesis set the source
//! answers. An image that OMITS, RE-ORDERS or REPLAYS genuinely signed rows
//! fails that check at the first position that differs and is REFUSED by
//! provenance, as a signature could never refuse it (REG-3.13, the courier
//! vector).
//!
//! THE TWO REFUSALS (REG-3.19), named: a frontier DIVERGING below the
//! mirror's head ([`Refusal::Diverged`], [`Refusal::ChainDiverged`]) and a
//! source whose head is BELOW the mirror's position ([`Refusal::SourceBehind`])
//! — the mirror refuses the new address and holds the base it has, saying
//! so rather than splicing. A root whose genesis set is not the hint's realm
//! is a LINEAGE CHANGE ([`Refusal::RealmMismatch`]; REG-3.42: the id is
//! compared at the base) — under a held copy as under a fresh base, the
//! copy's header naming the hint's realm being the copy's word and never
//! the root's. A hint RE-POINTED to another realm re-bootstraps afresh from
//! the new root's genesis and resumes nothing (REG-3.17): the old copy is
//! retired beside the new.
//!
//! An `impl Mirror` child of `mirror`: the open, the resume's check, the
//! realm check, the sync and the pull, reading the mirror's private state
//! the way a child does. The fold calls one method here,
//! [`Mirror::realm_check`], at the claim's row.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Instant;

use serde_json::{json, Value};
use skep_identity::Fingerprint;

use super::{Fetched, Lines, Mirror, MirrorError, Opened, Refusal, Stats, Types, FEED_COPY, FEED_FORMAT, FETCH_CACHE};
use crate::board::{parse_chain, Board, BoardError};
use crate::hint::{realm_id, RootHint};
use crate::http::Dial;
use crate::index::Index;
use crate::origin::Origin;

impl Mirror {
    /// OPEN the mirror under `dir` against the root `hint` names, through
    /// `dial`: a copy held there is CHECKED and resumed (REG-3.18), a copy of
    /// another realm retired and the base re-established (REG-3.17), no copy
    /// bootstrapped from genesis (REG-3.12); then the delta synced. On every
    /// path the realm is compared at the claim's row (REG-3.42), and a base
    /// whose feed holds no claim through the source's head is
    /// [`MirrorError::NoClaim`]. The refusals are [`Refusal`]'s, each named,
    /// and a refused base writes nothing.
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
        // REG-3.18 — the same lineage: check, rebuild, resume. The header's
        // realm is the copy's word: the realm is compared at the claim's row
        // as on a fresh base, and no line reaches the copy before it is.
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
        mirror.feed.bytes = fs::metadata(&feed_path).map(|m| m.len()).unwrap_or(0);
        mirror.cache.bytes = fs::metadata(dir.join(FETCH_CACHE)).map(|m| m.len()).unwrap_or(0);
        let checked_rows = rows.len() as u64;
        mirror.rows = rows;
        mirror.fold_pending()?;
        mirror.opened = Opened::Resumed { checked_rows };
        mirror.sync()?;
        if !mirror.realm_compared {
            return Err(MirrorError::NoClaim);
        }
        Ok(mirror)
    }

    /// REBUILD the index from the copy under `dir` alone, no board dialed
    /// (REG-3.25: the rebuild is a re-read of the feed at the deposits' own
    /// positions): every fetch served from the cache; a record whose bytes
    /// the cache lacks is UNDETERMINABLE HERE, and so is a table the walk
    /// asks for that the cache lacks. Nothing is checked against a source
    /// and the realm is the one the copy's header names
    /// ([`Opened::Rebuilt`]); `sync` refuses [`MirrorError::Offline`] on the
    /// mirror this answers.
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
        mirror.rows = held[1..].iter().filter_map(|l| l.get("row").cloned()).collect();
        mirror.fold_pending()?;
        mirror.opened = Opened::Rebuilt;
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
            scanned: 0,
            folded: 0,
            head: 0,
            realm_compared: false,
            epochs: BTreeMap::new(),
            members: BTreeMap::new(),
            members_probed: BTreeMap::new(),
            images: BTreeMap::new(),
            stats: Stats::default(),
            opened: Opened::Bootstrapped,
        }
    }

    /// From genesis: a new copy's header, then `since=0` to the head, the
    /// realm compared at the claim.
    fn bootstrap(&mut self) -> Result<(), MirrorError> {
        let header = self.header();
        self.append_feed(header)?;
        self.pull(0)?;
        if !self.realm_compared {
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
        // on the acts AFTER a record's position (the floor's clause).
        self.fold_pending()
    }

    /// Fold every held row the fold has not consumed, in two passes: the
    /// credential pass first ([`Mirror::scan_credential_acts`]), so every act
    /// among the held rows is recorded before any record is judged; then each
    /// row folded, in order.
    fn fold_pending(&mut self) -> Result<(), MirrorError> {
        let t = Instant::now();
        self.scan_credential_acts()?;
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

    /// A chain pair held for the resume's check: the live head pair
    /// ([`Board::head_pair`]) — a pair `/chain?at` later checks the source's
    /// recomputation against. Read off `/health` rather than
    /// `/chain?at=head`, which recomputes the chain over the surviving
    /// journal per call.
    fn record_head(&mut self) -> Result<(), MirrorError> {
        if self.head == 0 {
            return Ok(());
        }
        let Some((at, chain)) = self.board_ref()?.head_pair()? else { return Ok(()) };
        if at < self.head {
            return Ok(());
        }
        self.append_feed(json!({ "head": { "at": at, "chain": chain } }))
    }

    /// REG-3.18's CHECK: the source read from genesis must answer every held
    /// row identically through the copy's head, and every held chain pair
    /// the same.
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
        Ok(())
    }

    /// THE REALM CHECK at the base (REG-3.42; REG-3.39): the claimant's
    /// genesis set — its table at its first credential position — read off
    /// the board and never off the fetch cache, fingerprinted and compared to
    /// the hint's realm; a mismatch is REG-3.19's refusal. Compared, every
    /// line that waited reaches the copy, and the genesis table is kept where
    /// the cache does not hold it already.
    pub(super) fn realm_check(&mut self) -> Result<(), MirrorError> {
        let (_, claimant) = self.fetched.claim.clone().ok_or(MirrorError::NoClaim)?;
        let genesis_at = *self.epochs.get(&claimant).and_then(|v| v.first()).ok_or(MirrorError::NoGenesis)?;
        let keys = self.read_keys_at(&claimant, genesis_at)?.ok_or(MirrorError::NoGenesis)?;
        let found = realm_id(&keys.iter().map(|e| Fingerprint::of(&e.key)).collect::<Vec<_>>());
        if found != self.hint.realm {
            return Err(MirrorError::Refused(Refusal::RealmMismatch { expected: self.hint.realm, found }));
        }
        self.realm_compared = true;
        self.flush_pending()?;
        // The genesis position is the claimant's first act, so the epoch the
        // table belongs to is the position itself.
        if !self.fetched.keys.contains_key(&(claimant.clone(), genesis_at)) {
            self.keep_keys(&claimant, genesis_at, genesis_at, keys)?;
        }
        Ok(())
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
