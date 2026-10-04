//! THE SET THAT OPENS AN ACCOUNT AS OF A POSITION (REG-1.86 (e)) — the
//! table a record is judged under, and never the live one for a historical
//! verdict: ARCHITECTURE.md's "The table as of the position", whose three
//! reads — the live table where the feed the mirror holds proves it the
//! same, `/op-at` otherwise, the reclaim floor where the same proof reaches
//! it — are [`Mirror::fetch_keys_epoch`]'s. An `impl Mirror` child of
//! `mirror`, reading the mirror's private state the way a child does.

use serde_json::{json, Value};
use skep_address::{parent, Address, Level};
use skep_identity::{doc_1_of, Enrolled};

use super::{KeysAsOf, Mirror, MirrorError};
use crate::board::{enrolled_of, BoardError};
use crate::parse_address;

impl Mirror {
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
    pub(super) fn keys_opening(&mut self, account: &Address, at: u64) -> Result<Option<Vec<Enrolled>>, MirrorError> {
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
    pub(super) fn fetch_keys(&mut self, account: &Address, at: u64) -> Result<Option<Vec<Enrolled>>, MirrorError> {
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

    /// THE CURRENT KEYS of `account` as this mirror holds them — the set that
    /// opens it as of the mirror's HEAD, the position the mirror stands at
    /// (REG-3.7, REG-3.39's fold): the walk's read of "the current keys".
    /// Empty where none; the claimant's are the registrar's.
    pub fn current_keys(&mut self, account: &Address) -> Result<Vec<Enrolled>, MirrorError> {
        let head = self.head;
        Ok(self.keys_opening(account, head)?.unwrap_or_default())
    }
}
