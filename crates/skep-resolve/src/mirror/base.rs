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
//! the way a child does — and THE FEED COPY's every line, the header, the
//! rows and the chain pairs, written here and read back by [`read_copy`]
//! alone. The fold calls one method here, [`Mirror::realm_check`], at the
//! claim's row.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Instant;

use serde_json::{json, Value};
use skep_identity::Fingerprint;

use super::{
    position, Chains, Fetched, Lines, Mirror, MirrorError, Opened, Refusal, Stats, Types, FEED_COPY, FEED_FORMAT,
    FETCH_CACHE,
};
use crate::board::{parse_chain, Board, BoardError};
use crate::hint::{realm_id, RootHint};
use crate::http::Dial;
use crate::index::Index;
use crate::origin::Origin;

/// A feed copy as [`read_copy`] reads it back: the realm its header names —
/// the copy's word, never the root's — its rows in position order, and the
/// chain pairs it held.
struct HeldCopy {
    realm: Fingerprint,
    rows: Vec<Value>,
    heads: Vec<(u64, [u8; 32])>,
}

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
        let held = read_copy(dir)?;
        let mut mirror = Mirror::fresh(hint, Some(root), Some(board), dir);
        let Some(held) = held else {
            let t = Instant::now();
            mirror.bootstrap()?;
            mirror.stats.bootstrap_time = t.elapsed();
            return Ok(mirror);
        };
        if held.realm != hint.realm {
            // REG-3.17 — a re-pointed hint: afresh from the new root's genesis.
            let retired = retire(dir, held.realm)?;
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
        mirror.load_cache()?;
        mirror.check_against_source(&held.rows, &held.heads)?;
        mirror.stats.resume_check = Some(t.elapsed());
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
    /// and the realm is the one the copy's header names
    /// ([`Opened::Rebuilt`]); a copy of no format this build writes is
    /// refused, as at the open; `sync` refuses [`MirrorError::Offline`] on
    /// the mirror this answers.
    pub fn rebuild_offline(hint: &RootHint, dir: &Path) -> Result<Mirror, MirrorError> {
        let Some(held) = read_copy(dir)? else {
            return Err(MirrorError::Copy(format!("{}: no feed copy", dir.join(FEED_COPY).display())));
        };
        if held.realm != hint.realm {
            return Err(MirrorError::Copy("the copy is another realm's".into()));
        }
        let mut mirror = Mirror::fresh(hint, None, None, dir);
        mirror.load_cache()?;
        mirror.rows = held.rows;
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
            feed: Lines::held(dir.join(FEED_COPY)),
            cache: Lines::held(dir.join(FETCH_CACHE)),
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
            chains: Chains::default(),
            stats: Stats::default(),
            opened: Opened::Bootstrapped,
        }
    }

    /// From genesis: both files of the copy begun — a line either held
    /// before is another base's, never this one's — then a new copy's
    /// header and `since=0` to the head, the realm compared at the claim.
    fn bootstrap(&mut self) -> Result<(), MirrorError> {
        self.feed = Lines::begin(self.dir.join(FEED_COPY));
        self.cache = Lines::begin(self.dir.join(FETCH_CACHE));
        let header = self.header();
        self.append_feed(header)?;
        self.pull(0)?;
        if !self.realm_compared {
            return Err(MirrorError::NoClaim);
        }
        self.record_head()
    }

    /// A NEW copy's header, the first line it holds: the format stamp, the
    /// realm, and the root that answered — as [`read_copy`] reads it back.
    fn header(&self) -> Value {
        json!({
            "skep-resolve": FEED_FORMAT,
            "realm": self.hint.realm.to_hex(),
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
            self.record_head()?;
        }
        Ok(self.stats.rows - before)
    }

    /// Pages from `since` to the feed's end, each row appended to the copy
    /// and folded; the page size the feed's own default, and the limit the
    /// feed names where a page passes its byte budget.
    fn pull(&mut self, mut since: u64) -> Result<(), MirrorError> {
        self.chains.stale();
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
            let last_at = page.rows.last().and_then(position).unwrap_or(0);
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
            self.head = position(&row).unwrap_or(self.head);
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
        let held_head = rows.last().and_then(position).unwrap_or(0);
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
            let at = position(held).unwrap_or(0);
            match fresh.get(i) {
                None => {
                    let source_head = fresh.last().and_then(position).unwrap_or(0);
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
    /// genesis set ([`Mirror::genesis_keys`], read off the board and never
    /// off the fetch cache), fingerprinted and compared to the hint's realm;
    /// a mismatch is REG-3.19's refusal. Compared, every line that waited
    /// reaches the copy, the genesis table's among them.
    pub(super) fn realm_check(&mut self) -> Result<(), MirrorError> {
        let (_, claimant) = self.fetched.claim.clone().ok_or(MirrorError::NoClaim)?;
        let keys = self.genesis_keys(&claimant)?.ok_or(MirrorError::NoGenesis)?;
        let found = realm_id(&keys.iter().map(|e| Fingerprint::of(&e.key)).collect::<Vec<_>>());
        if found != self.hint.realm {
            return Err(MirrorError::Refused(Refusal::RealmMismatch { expected: self.hint.realm, found }));
        }
        self.realm_compared = true;
        self.flush_pending()
    }
}

/// THE FEED COPY under `dir`, read back — the one reader of the lines
/// [`Mirror::header`], [`Mirror::pull`] and [`Mirror::record_head`] write:
/// `None` where no copy is held (the file absent, or no line in it), and
/// refused where its header is no feed copy of the format this build
/// writes.
fn read_copy(dir: &Path) -> Result<Option<HeldCopy>, MirrorError> {
    let path = dir.join(FEED_COPY);
    let lines = Lines::read(&path)?;
    let Some((header, held)) = lines.split_first() else { return Ok(None) };
    let stamped = header["skep-resolve"].as_str() == Some(FEED_FORMAT);
    let Some(realm) = header["realm"].as_str().and_then(Fingerprint::parse_hex).filter(|_| stamped) else {
        return Err(MirrorError::Copy(format!("{}: not a feed copy", path.display())));
    };
    let rows = held.iter().filter_map(|l| l.get("row").cloned()).collect();
    let heads = held
        .iter()
        .filter_map(|l| {
            let h = l.get("head")?;
            Some((h["at"].as_u64()?, parse_chain(h["chain"].as_str()?)?))
        })
        .collect();
    Ok(Some(HeldCopy { realm, rows, heads }))
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

/// Retire the copy of another realm beside the new one (REG-3.17): the
/// cache first, then the feed copy — so a failure between the two leaves a
/// feed copy without its cache, which resumes and fetches afresh, and never
/// a cache without its feed copy.
fn retire(dir: &Path, realm: Fingerprint) -> Result<PathBuf, MirrorError> {
    let suffix = format!("retired-{}", &realm.to_hex()[..16]);
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
mod tests {
    use std::cell::{Cell, RefCell};
    use std::rc::Rc;

    use skep_address::Address;
    use skep_identity::PublicKey;
    use skep_signature::{HybridSigner, TAG_MLDSA65_ED25519};

    use super::*;
    use crate::http::{Transport, TransportError};
    use crate::parse_address;

    fn a(s: &str) -> Address {
        parse_address(s).unwrap()
    }

    fn key(seed: u8) -> PublicKey {
        HybridSigner::from_seed(TAG_MLDSA65_ED25519, &[seed; 32]).expect("tag 1").public_key().clone()
    }

    /// A span over one address as `read_link` answers a slot.
    fn span(start: &str) -> Value {
        json!({ "start": start, "width": "0.1" })
    }

    /// A BOARD THE SUITE HOLDS FIXED: two link rows on its feed — at 5 a link
    /// of no type, at 6 an enroll naming `1.0.2` — the enroll's `read_link`
    /// refused `refusals` times; `1.0.2`'s live table answers as of 6, its
    /// table as of any earlier position is `before`.
    struct Scripted {
        refusals: Cell<u32>,
        asked: RefCell<Vec<String>>,
        live: PublicKey,
        before: PublicKey,
    }

    impl Transport for Rc<Scripted> {
        fn exchange(&self, method: &str, path: &str, body: &[u8]) -> Result<(u16, Vec<u8>), TransportError> {
            self.asked.borrow_mut().push(format!("{method} {path}"));
            let answer = |v: Value| -> Result<(u16, Vec<u8>), TransportError> { Ok((200, v.to_string().into_bytes())) };
            if let Some(since) = path.strip_prefix("/changes?since=") {
                let since: u64 = since.parse().expect("a position");
                let feed = [
                    json!({ "at": 5, "op": "make_link", "link": "1.0.2.0.1.0.2.1", "docs": ["1.0.2.0.1"] }),
                    json!({ "at": 6, "op": "make_link", "link": "1.0.2.0.1.0.2.2", "docs": ["1.0.2.0.1"] }),
                ];
                let rows: Vec<Value> = feed.into_iter().filter(|r| position(r) > Some(since)).collect();
                let last = rows.last().and_then(position).unwrap_or(since);
                return answer(json!({ "changes": rows, "last": last, "more": false }));
            }
            if path == "/health" {
                return answer(json!({ "log_position": 6, "chain_head": "07".repeat(32) }));
            }
            let request: Value = serde_json::from_slice(body).expect("a JSON body");
            let (frame, at) = if path == "/op-at" { (&request["frame"], request["at"].as_u64()) } else { (&request, None) };
            let table = |k: &PublicKey, as_of: u64| {
                json!({ "resp": "key_set", "as_of": as_of, "enrolled": [{ "alg": k.alg(), "key": k.to_hex(), "anchor": true }] })
            };
            match (frame["op"].as_str(), frame["a"].as_str(), at) {
                (Some("read_link"), Some("1.0.2.0.1.0.2.1"), None) => {
                    answer(json!({ "resp": "link", "link": { "slots": [[span("1.0.2.0.1.0.1.1")], [], []] } }))
                }
                (Some("read_link"), Some("1.0.2.0.1.0.2.2"), None) if self.refusals.get() > 0 => {
                    self.refusals.set(self.refusals.get() - 1);
                    Ok((503, b"unavailable".to_vec()))
                }
                (Some("read_link"), Some("1.0.2.0.1.0.2.2"), None) => answer(json!({ "resp": "link", "link": { "slots": [
                    [span("1.0.2.0.1.0.1.2")], [span("1.0.2")], [span("1.1.0.1.0.1.0.3.1")],
                ] } })),
                (Some("key_set"), None, None) => answer(table(&self.live, 6)),
                (Some("key_set"), None, Some(at)) => answer(table(&self.before, at)),
                _ => panic!("a read this board does not answer: {path} {request}"),
            }
        }
    }

    /// A SYNC THAT FAILED IS TAKEN UP WHERE IT STOPPED (REG-3.10): the two
    /// rows the failed sync held are folded by the next, which asks the
    /// board only past the copy's frontier and holds each row once; and
    /// between the two, the credential pass having stopped short of the act
    /// at 6, the live table answered as of 6 proves nothing of the table at
    /// the head — it is read as of the head — while once the act is read it
    /// does.
    #[test]
    fn a_sync_that_failed_is_taken_up_where_it_stopped() {
        let dir = tempfile::tempdir().expect("tempdir");
        let board = Rc::new(Scripted { refusals: Cell::new(1), asked: RefCell::new(Vec::new()), live: key(3), before: key(4) });
        let realm = Fingerprint::parse_hex(&"ab".repeat(32)).unwrap();
        let hint = RootHint::new(vec![Origin::parse("http://127.0.0.1:1").unwrap()], realm, None).unwrap();
        let mut mirror = Mirror::fresh(&hint, None, Some(Board::new(Box::new(board.clone()))), dir.path());
        let keys = |m: &mut Mirror| -> Vec<PublicKey> {
            m.current_keys(&a("1.0.2")).expect("read").expect("a table").into_iter().map(|e| e.key).collect()
        };
        assert!(matches!(mirror.sync(), Err(MirrorError::Board(BoardError::Status { status: 503, .. }))));
        assert_eq!((mirror.rows.len(), mirror.head), (2, 0), "held, and not folded");
        assert_eq!((mirror.held_through(), mirror.acts_through()), (6, 5));
        assert_eq!(keys(&mut mirror), [key(4)], "the act at 6 unread: the table as of the head, off /op-at");
        assert_eq!(mirror.sync(), Ok(2), "the two held rows folded, each once");
        assert_eq!((mirror.rows.len(), mirror.head, mirror.acts_through()), (2, 6, 6));
        let pulls: Vec<String> = board.asked.borrow().iter().filter(|r| r.contains("/changes")).cloned().collect();
        assert_eq!(pulls, ["GET /changes?since=0", "GET /changes?since=6"], "the second pull past the copy's frontier");
        assert_eq!(keys(&mut mirror), [key(3)], "the act read: the live table is the table at the head");
    }
}
