//! THE BASE'S PROVENANCE (REG-3.12, REG-3.13; R5 (b)): the base is read FROM
//! GENESIS at the root the hint names — `/changes since=0`, the read that is
//! the check — or from a journal copy this mirror already holds, CHECKED
//! against that same feed before it serves (REG-3.18): the source is read
//! from genesis and the copy resumes only where every position it holds
//! comes back identical through its own head and the head pairs it held
//! answer the same at the source's recomputation (`/chain?at=N`); and the
//! realm is compared at the claim's row on every open that holds a board,
//! for the board's own claimant at the board's own genesis act, against the
//! genesis set the source answers there. An image that OMITS, RE-ORDERS or
//! REPLAYS genuinely signed rows fails that check at the first position that
//! differs and is REFUSED by provenance, as a signature could never refuse
//! it (REG-3.13, the courier vector).
//!
//! THE TWO REFUSALS (REG-3.19), named: a frontier DIVERGING below the
//! mirror's head ([`Refusal::Diverged`], [`Refusal::ChainDiverged`]) and a
//! source whose head is BELOW the mirror's position ([`Refusal::SourceBehind`])
//! — the mirror refuses the new address and holds the base it has, saying
//! so rather than splicing. A root whose genesis set does not fingerprint to
//! the genesis half of the hint's realm id is a LINEAGE CHANGE
//! ([`Refusal::RealmMismatch`]; REG-3.42's comparison at the base, made on
//! the id's genesis fingerprint) — under a held copy as under a fresh base:
//! the copy's header naming the hint's genesis fingerprint is the copy's
//! word and never the root's, and the claimant and its genesis act are the
//! board's, never the fetch cache's. A claim row past the one the realm was
//! compared for moves nothing. A hint RE-POINTED to another genesis
//! re-bootstraps afresh from the new root's genesis and resumes nothing
//! (REG-3.17): the old copy is retired beside the new.
//!
//! An `impl Mirror` child of `mirror`: the open, the resume's check, the
//! realm check, the sync and the pull, reading the mirror's private state
//! the way a child does — and THE FEED COPY's every line, the header, the
//! rows and the head pairs, written here and read back by [`read_copy`]
//! alone. The fold calls one method here, [`Mirror::realm_check`], at the
//! claim's row.

use std::fs;
use std::path::{Path, PathBuf};
use std::time::Instant;

use serde_json::{json, Value};
use skep_address::Address;
use skep_identity::Fingerprint;

use super::{position, Lines, Mirror, MirrorError, Opened, Refusal, FEED_COPY, FEED_FORMAT, FETCH_CACHE};
use crate::board::{parse_chain, rises_past, Board, BoardError, Page};
use crate::hint::{RealmId, RootHint};
use crate::http::Dial;
use crate::origin::Origin;

/// A feed copy as [`read_copy`] reads it back: the genesis fingerprint its
/// header names — the copy's word, never the root's — its rows in position
/// order, and the head pairs it held.
struct HeldCopy {
    genesis: Fingerprint,
    rows: Vec<Value>,
    head_pairs: Vec<(u64, [u8; 32])>,
}

impl Mirror {
    /// OPEN the mirror under `dir` against the root `hint` names, through
    /// `dial`: a copy held there is CHECKED and resumed (REG-3.18), a copy
    /// naming another genesis fingerprint retired and the base re-established
    /// (REG-3.17), no copy bootstrapped from genesis (REG-3.12); then the
    /// delta synced. On every path the realm is compared at the claim's row
    /// (REG-3.42), and a base whose feed holds no claim through the source's
    /// head is [`MirrorError::NoClaim`].
    ///
    /// Its refusals are met in this order: the directory not made
    /// ([`MirrorError::Copy`]); no root answering
    /// ([`MirrorError::Unreachable`] — the root is dialed before the copy is
    /// read, whatever the directory holds); a held copy that does not read
    /// ([`MirrorError::Copy`]); then the base's own — the check's
    /// ([`Refusal::SourceBehind`] or [`Refusal::Diverged`], then
    /// [`Refusal::ChainDiverged`]), the realm's at the claim
    /// ([`Refusal::RealmMismatch`], [`MirrorError::NoGenesis`]), and a feed
    /// with no claim ([`MirrorError::NoClaim`]) — with any read the board
    /// cannot answer ([`MirrorError::Board`]) or any line not written
    /// ([`MirrorError::Copy`]) along the way. A refused base writes no line
    /// of either file. The directory is made before the dial, and a copy of
    /// another genesis is retired before its successor's realm is compared,
    /// so a refused re-bootstrap leaves it retired.
    pub fn open(hint: &RootHint, dir: &Path, dial: &Dial<'_>) -> Result<Mirror, MirrorError> {
        fs::create_dir_all(dir).map_err(|e| MirrorError::Copy(format!("{}: {e}", dir.display())))?;
        let (root, board) = dial_root(hint, dial)?;
        let held = read_copy(dir)?;
        let mut mirror = Mirror::fresh(hint, Some(root), Some(board), dir);
        let Some(held) = held else {
            let t = Instant::now();
            mirror.bootstrap()?;
            mirror.stats.bootstrap_time = t.elapsed();
            return Ok(mirror);
        };
        if held.genesis != hint.realm().genesis {
            // REG-3.17 — a hint re-pointed to another genesis: afresh from the
            // new root's genesis.
            let retired = retire(dir, held.genesis)?;
            let t = Instant::now();
            mirror.bootstrap()?;
            mirror.stats.bootstrap_time = t.elapsed();
            mirror.opened = Opened::Rebootstrapped { retired };
            return Ok(mirror);
        }
        // REG-3.18 — the same genesis: check, rebuild, resume. The header's
        // genesis fingerprint is the copy's word: the realm is compared at the
        // claim's row as on a fresh base, and no line reaches the copy before
        // it is.
        let t = Instant::now();
        mirror.load_cache()?;
        mirror.check_against_source(&held.rows, &held.head_pairs)?;
        mirror.stats.resume_check_time = Some(t.elapsed());
        let checked_rows = held.rows.len() as u64;
        mirror.rows = held.rows;
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
    /// and the genesis fingerprint is the one the copy's header names
    /// ([`Opened::Rebuilt`]); a copy of no format this build writes is
    /// refused, as at the open, and so is one whose rows do not hold the
    /// feed's own order — each past the one before (wire.md §The change
    /// feed, Paging) — which no source check holds them to here: on an open
    /// the check does, identical rows to the source's rising ones, its
    /// refusal REG-3.13's named one. `sync` refuses
    /// [`MirrorError::Offline`] on the mirror this answers.
    pub fn rebuild_offline(hint: &RootHint, dir: &Path) -> Result<Mirror, MirrorError> {
        let Some(held) = read_copy(dir)? else {
            return Err(MirrorError::Copy(format!("{}: no feed copy", dir.join(FEED_COPY).display())));
        };
        if held.genesis != hint.realm().genesis {
            return Err(MirrorError::Copy("the copy is another realm's".into()));
        }
        if rises_past(0, &held.rows).is_none() {
            return Err(MirrorError::Copy(format!("{}: its rows do not rise", dir.join(FEED_COPY).display())));
        }
        let mut mirror = Mirror::fresh(hint, None, None, dir);
        mirror.load_cache()?;
        mirror.rows = held.rows;
        mirror.fold_pending()?;
        mirror.opened = Opened::Rebuilt;
        Ok(mirror)
    }

    /// From genesis: both files of the copy begun — a line either held
    /// before is another base's, never this one's — then a new copy's
    /// header and `since=0` to the head, the realm compared at the claim.
    fn bootstrap(&mut self) -> Result<(), MirrorError> {
        self.feed_copy = Lines::begin(self.dir.join(FEED_COPY));
        self.fetch_cache = Lines::begin(self.dir.join(FETCH_CACHE));
        let header = self.header();
        self.append_feed(header)?;
        self.pull(0)?;
        if !self.realm_compared {
            return Err(MirrorError::NoClaim);
        }
        self.record_head_pair()
    }

    /// A NEW copy's header, the first line it holds: the format stamp, the
    /// realm id's genesis fingerprint (under `realm`), and the root that
    /// answered — as [`read_copy`] reads it back.
    fn header(&self) -> Value {
        json!({
            "skep-resolve": FEED_FORMAT,
            "realm": self.hint.realm().genesis.to_hex(),
            "root": self.root.as_ref().map(|o| o.as_str().to_string()),
        })
    }

    /// SYNC (REG-3.10): the rows past the copy's frontier pulled, and every
    /// held row the fold has not taken folded — a sync that failed leaves its
    /// rows held, and the next takes them up where it stopped; answers how
    /// many rows were folded.
    pub fn sync(&mut self) -> Result<u64, MirrorError> {
        let before = self.stats.rows;
        let head = self.head;
        self.pull(self.held_through())?;
        if self.head != head {
            self.record_head_pair()?;
        }
        Ok(self.stats.rows - before)
    }

    /// Pages from `since` to the feed's end, each row appended to the copy
    /// and folded; the page size the feed's own default, and the limit the
    /// feed names where a page passes its byte budget ([`page_from`]). Each
    /// page is held to its own rules ([`Board::changes`]), so the next one is
    /// asked past its `last`.
    fn pull(&mut self, mut since: u64) -> Result<(), MirrorError> {
        self.chains.forget_stale();
        let mut limit: Option<usize> = None;
        loop {
            let page = page_from(self.board_ref()?, since, &mut limit)?;
            self.stats.pages += 1;
            for row in page.rows {
                self.append_feed(json!({ "row": row }))?;
                self.rows.push(row);
            }
            since = page.last;
            if !page.more {
                break;
            }
        }
        // Every row held before any is folded: the fold's as-of reads lean
        // on the acts AFTER a record's position (the floor's clause).
        self.fold_pending()
    }

    /// A HEAD PAIR held for the resume's check: `/health`'s live pair
    /// ([`Board::head_pair`]) — the committed head's position and its chain —
    /// kept where its position is at or above the mirror's head, and checked
    /// at a later resume against the source's recomputation (`/chain?at`).
    /// Read off `/health` rather than `/chain?at=head`, which recomputes the
    /// chain over the surviving journal per call.
    fn record_head_pair(&mut self) -> Result<(), MirrorError> {
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
    /// row identically through the copy's head, and its chain, recomputed at
    /// each held head pair's position, must be that pair's chain.
    fn check_against_source(&mut self, held_rows: &[Value], head_pairs: &[(u64, [u8; 32])]) -> Result<(), MirrorError> {
        let held_head = held_rows.last().and_then(position).unwrap_or(0);
        let mut source_rows: Vec<Value> = Vec::new();
        let mut since = 0;
        let mut limit = None;
        loop {
            let page = page_from(self.board_ref()?, since, &mut limit)?;
            self.stats.pages += 1;
            source_rows.extend(page.rows);
            since = page.last;
            if !page.more || since >= held_head {
                break;
            }
        }
        for (i, held) in held_rows.iter().enumerate() {
            let at = position(held).unwrap_or(0);
            match source_rows.get(i) {
                None => {
                    let source_head = source_rows.last().and_then(position).unwrap_or(0);
                    return Err(MirrorError::Refused(Refusal::SourceBehind { source_head, held: at }));
                }
                Some(served) if served != held => return Err(MirrorError::Refused(Refusal::Diverged { at })),
                Some(_) => {}
            }
        }
        for (at, chain) in head_pairs {
            let (_, source_chain) = self.board_ref()?.chain_at(*at)?;
            if source_chain != *chain {
                return Err(MirrorError::Refused(Refusal::ChainDiverged { at: *at }));
            }
        }
        Ok(())
    }

    /// THE REALM CHECK at the base (REG-3.42; REG-3.39), for `claimant` —
    /// the account the board's own claim link names, the fold having read
    /// it off the board ([`Mirror::fold_claim`]): its genesis set
    /// ([`Mirror::genesis_keys`], at the genesis act the board answered,
    /// read exactly and never off the fetch cache), fingerprinted and
    /// compared to the GENESIS FINGERPRINT the hint's realm id carries, its
    /// first half — the fork point is not compared here; a mismatch is
    /// REG-3.19's refusal, and no genesis to read [`MirrorError::NoGenesis`].
    /// Compared, every line that waited reaches the copy, the genesis
    /// table's among them.
    pub(super) fn realm_check(&mut self, claimant: &Address) -> Result<(), MirrorError> {
        let keys = self.genesis_keys(claimant)?.ok_or(MirrorError::NoGenesis)?;
        let found = RealmId::genesis_fingerprint(&keys.iter().map(|e| Fingerprint::of(&e.key)).collect::<Vec<_>>());
        let expected = self.hint.realm().genesis;
        if found != expected {
            return Err(MirrorError::Refused(Refusal::RealmMismatch { expected, found }));
        }
        self.realm_compared = true;
        self.flush_pending()
    }
}

/// THE FEED COPY under `dir`, read back — the one reader of the lines
/// [`Mirror::header`], [`Mirror::pull`] and [`Mirror::record_head_pair`]
/// write: `None` where no copy is held (the file absent, or no line in it),
/// and refused where its header is no feed copy of the format this build
/// writes, or a line of it is no JSON. The lines are taken by value, each
/// row moved out of its line.
fn read_copy(dir: &Path) -> Result<Option<HeldCopy>, MirrorError> {
    let path = dir.join(FEED_COPY);
    let mut lines = Lines::read(&path)?.into_iter();
    let Some(header) = lines.next() else { return Ok(None) };
    let stamped = header["skep-resolve"].as_str() == Some(FEED_FORMAT);
    let Some(genesis) = header["realm"].as_str().and_then(Fingerprint::parse_hex).filter(|_| stamped) else {
        return Err(MirrorError::Copy(format!("{}: not a feed copy", path.display())));
    };
    let mut rows = Vec::new();
    let mut head_pairs = Vec::new();
    for mut line in lines {
        if let Some(h) = line.get("head") {
            if let (Some(at), Some(chain)) = (h["at"].as_u64(), h["chain"].as_str().and_then(parse_chain)) {
                head_pairs.push((at, chain));
            }
        }
        if let Some(row) = line.get_mut("row").map(Value::take) {
            rows.push(row);
        }
    }
    Ok(Some(HeldCopy { genesis, rows, head_pairs }))
}

/// One page of the feed from `since` at `limit` — re-asked ONCE, at the
/// limit the feed names, where it refuses the page past its byte budget
/// (wire.md §The change feed, Paging: "re-ask with `limit=N` and the page is
/// served whole"), never at `limit=0`, which the wire refuses; the limit is
/// kept for the pages after it. A feed that refuses again the page it was
/// re-asked at its own limit is malformed, and is not asked a third time.
fn page_from(board: &Board, since: u64, limit: &mut Option<usize>) -> Result<Page, MirrorError> {
    let mut re_asked = false;
    loop {
        match board.changes(since, *limit) {
            Err(BoardError::PageTooLarge { fits }) if !re_asked => {
                re_asked = true;
                *limit = Some(fits.max(1));
            }
            Err(BoardError::PageTooLarge { .. }) => {
                let refused = format!("the feed refuses the page from {since} at the limit it named");
                return Err(BoardError::Malformed(refused).into());
            }
            page => return Ok(page?),
        }
    }
}

/// Dial the hint's origins in order; the first that answers `/health` is the
/// root. Where none does, every origin is named beside its own error — the
/// transport's where the dial failed, the board's where `/health` did.
fn dial_root(hint: &RootHint, dial: &Dial<'_>) -> Result<(Origin, Board), MirrorError> {
    let mut tried = Vec::new();
    for origin in hint.origins() {
        match dial(origin) {
            Ok(transport) => {
                let board = Board::new(transport);
                match board.health() {
                    Ok(_) => return Ok((origin.clone(), board)),
                    Err(e) => tried.push((origin.clone(), e)),
                }
            }
            Err(e) => tried.push((origin.clone(), BoardError::Transport(e))),
        }
    }
    Err(MirrorError::Unreachable { tried })
}

/// Retire the copy of another genesis beside the new one (REG-3.17), named
/// by the genesis fingerprint its header names: the cache first, then the
/// feed copy — so a failure between the two leaves a feed copy without its
/// cache, which resumes and fetches afresh, and never a cache without its
/// feed copy.
fn retire(dir: &Path, genesis: Fingerprint) -> Result<PathBuf, MirrorError> {
    let suffix = format!("retired-{}", &genesis.to_hex()[..16]);
    let cache = dir.join(FETCH_CACHE);
    if cache.exists() {
        let cache_to = dir.join(format!("{FETCH_CACHE}.{suffix}"));
        fs::rename(&cache, &cache_to).map_err(|e| MirrorError::Copy(format!("retire: {e}")))?;
    }
    let feed_to = dir.join(format!("{FEED_COPY}.{suffix}"));
    fs::rename(dir.join(FEED_COPY), &feed_to).map_err(|e| MirrorError::Copy(format!("retire: {e}")))?;
    Ok(feed_to)
}

#[cfg(test)]
mod tests;
