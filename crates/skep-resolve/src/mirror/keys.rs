//! THE SET THAT OPENS AN ACCOUNT AS OF A POSITION (REG-1.86 (e)) — the
//! table a record is judged under, and never the live one for a historical
//! verdict: ARCHITECTURE.md's "The table as of the position", whose three
//! reads — the live table where the credential acts the mirror holds prove
//! it the same, `/op-at` otherwise, the reclaim floor where the same proof
//! reaches it — are [`Mirror::read_keys_at`]'s. THE CREDENTIAL ACTS that
//! proof is read by are recorded here too, by the fold's first pass
//! ([`Mirror::scan_credential_acts`]), before any record is judged; and THE
//! GENESIS SET the realm is compared against ([`Mirror::genesis_keys`]) is
//! read here, by the same acts. An `impl Mirror` child of `mirror`, reading
//! the mirror's private state the way a child does.

use skep_address::{parent, Address, Level};
use skep_identity::Enrolled;

use super::{link_row, KeysAsOf, Mirror, MirrorError};
use crate::board::BoardError;

impl Mirror {
    /// THE CREDENTIAL PASS, the fold's first: every link row among the held
    /// rows this pass has not read — its stored link from the cache or the
    /// board — whose type is an enroll or a retire records its position under
    /// the account it names. An act is that link in ANY home: the subject's
    /// own doc 1, its genesis registry's (the claimant's, or the delegating
    /// account's for an account beneath another, AUTH-2.62), or a home the
    /// board's own fold holds inert. Counting one act too many only reads
    /// more — an as-of read sent to `/op-at` it could have answered live, an
    /// epoch's table read twice — and never keeps a table that is not the
    /// one as of the position; counting one too few would.
    pub(super) fn scan_credential_acts(&mut self) -> Result<(), MirrorError> {
        while self.scanned < self.rows.len() {
            if let Some((at, link, home)) = link_row(&self.rows[self.scanned]) {
                if let Some(stored) = self.read_link(at, &link, &home)? {
                    let credential =
                        stored.ty.as_ref().is_some_and(|t| *t == self.types.enroll || *t == self.types.retire);
                    if let (true, Some(subject)) = (credential, stored.to.first()) {
                        self.epochs.entry(subject.clone()).or_default().push(at);
                    }
                }
            }
            self.scanned += 1;
        }
        Ok(())
    }

    /// The latest credential position of `account` at or below `at`, or 0.
    fn epoch_of(&self, account: &Address, at: u64) -> u64 {
        self.epochs.get(account).and_then(|v| v.iter().rev().find(|p| **p <= at)).copied().unwrap_or(0)
    }

    /// Whether a credential act of `account` lies in `(after, upto]` among
    /// the held rows — an act as the credential pass records one.
    fn later_credential_act(&self, account: &Address, after: u64, upto: u64) -> bool {
        self.epochs.get(account).is_some_and(|acts| acts.iter().any(|p| *p > after && *p <= upto))
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

    /// The table of `account` at `epoch`, read for `at`: the cache's, else
    /// [`Mirror::read_keys_at`]'s, kept.
    fn fetch_keys_epoch(&mut self, account: &Address, epoch: u64, at: u64) -> Result<Option<Vec<Enrolled>>, MirrorError> {
        if let Some(k) = self.fetched.keys.get(&(account.clone(), epoch)) {
            return Ok(Some(k.enrolled.clone()));
        }
        let Some(enrolled) = self.read_keys_at(account, at)? else { return Ok(None) };
        self.keep_keys(account, epoch, at, enrolled.clone())?;
        Ok(Some(enrolled))
    }

    /// THE TABLE OF `account` AS OF `at`, off the board: the live table where
    /// the acts the mirror holds prove it the same, `/op-at` otherwise — or,
    /// where the board has RECLAIMED the position (REG-3.15's floor: a root
    /// that cannot answer from genesis), the read at the floor WHERE THE ACTS
    /// THE MIRROR HOLDS SHOW NONE OF THE ACCOUNT'S BETWEEN THE POSITION AND
    /// THE FLOOR: the table is constant across an epoch, so the read at the
    /// floor IS the table as of the position, derived from inputs the mirror
    /// holds and manufactured from none; where an act does lie between, the
    /// table as of the position is gone with the journal and the answer is
    /// `None` — UNDETERMINABLE HERE, as it is with no board held, and as it
    /// is for a table this build cannot read whole.
    fn read_keys_at(&mut self, account: &Address, at: u64) -> Result<Option<Vec<Enrolled>>, MirrorError> {
        let Some(board) = self.board.as_ref() else { return Ok(None) };
        // The acts are known through the last row the credential pass read;
        // a table is proven unchanged only inside it.
        let known = self.acts_through();
        // THE TABLE AS OF THE POSITION, OFF THE LIVE READ WHERE THE ACTS
        // PROVE IT: the live `key_set` answers `as_of`, the snapshot's
        // position; where that position is one the mirror holds the feed
        // through, and no credential act of the account lies between the
        // record's position and it, the table has not changed in between
        // and the live answer IS the table as of the record — the mirror's
        // own base is the evidence, and nothing is manufactured. Elsewhere
        // the historical read below is the only exact one. A reconstruction
        // costs the board a whole world per call (wire.md §Reading history:
        // "wrong for a hot loop"), so this is what makes a bootstrap of
        // thousands of homes a matter of seconds and not of hours.
        if let Ok(Some(live)) = board.key_set(account) {
            if let Some(as_of) = live.as_of {
                if as_of <= known && !self.later_credential_act(account, at, as_of) {
                    self.stats.reads_live_proven += 1;
                    return Ok(Some(live.enrolled));
                }
            }
        }
        let answer = match board.key_set_at(at, account) {
            Ok(answer) => answer,
            Err(BoardError::Reclaimed { floor }) => {
                let floor = floor.unwrap_or(known);
                if floor > known || self.later_credential_act(account, at, floor) {
                    self.stats.reclaimed_undeterminable += 1;
                    return Ok(None);
                }
                self.stats.reads_at_floor += 1;
                match board.key_set_at(floor, account) {
                    Ok(answer) => answer,
                    Err(BoardError::Status { .. }) | Err(BoardError::Reclaimed { .. }) => return Ok(None),
                    Err(e) => return Err(e.into()),
                }
            }
            Err(BoardError::Status { .. }) => return Ok(None),
            Err(e) => return Err(e.into()),
        };
        Ok(answer.map(|a| a.enrolled))
    }

    /// A table kept as `account`'s at `epoch`, read for `at`: held, and its
    /// line written to the fetch cache where the cache does not hold it.
    fn keep_keys(&mut self, account: &Address, epoch: u64, at: u64, enrolled: Vec<Enrolled>) -> Result<(), MirrorError> {
        let line = self.fetched.keep_keys(KeysAsOf { account: account.clone(), epoch, at, enrolled });
        self.append_cache(line)
    }

    /// THE GENESIS SET of `account`: its table at its first credential act,
    /// read off the board and never off the fetch cache — the realm is never
    /// read off the cache (REG-3.42) — and kept under that act's epoch, the
    /// first act's position being its own epoch; `None` where no act of the
    /// account is held or the table cannot be read.
    pub(super) fn genesis_keys(&mut self, account: &Address) -> Result<Option<Vec<Enrolled>>, MirrorError> {
        let Some(&genesis) = self.epochs.get(account).and_then(|acts| acts.first()) else { return Ok(None) };
        let Some(keys) = self.read_keys_at(account, genesis)? else { return Ok(None) };
        self.keep_keys(account, genesis, genesis, keys.clone())?;
        Ok(Some(keys))
    }

    /// THE CURRENT KEYS of `account` as this mirror holds them — the set that
    /// opens it as of the mirror's HEAD, the position the mirror stands at
    /// (REG-3.7, REG-3.39's fold): the walk's read of "the current keys",
    /// the claimant's being the registrar's. `None` where this reader could
    /// not read the table — UNDETERMINABLE HERE, never an empty set.
    pub fn current_keys(&mut self, account: &Address) -> Result<Option<Vec<Enrolled>>, MirrorError> {
        let head = self.head;
        self.keys_opening(account, head)
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use serde_json::json;
    use skep_identity::Fingerprint;

    use super::super::{FEED_COPY, FEED_FORMAT, FETCH_CACHE};
    use super::*;
    use crate::hint::RootHint;
    use crate::origin::Origin;
    use crate::parse_address;

    fn a(s: &str) -> Address {
        parse_address(s).unwrap()
    }

    /// A CREDENTIAL ACT is the enroll or retire link naming the account in
    /// ANY home: the genesis of an account beneath another, seeded in its
    /// delegating account's doc 1 (AUTH-2.62's genesis registry), is an act
    /// of the account — so the live table is never taken for the one before
    /// it. The act at 5 lies in `(4, 6]` and not in `(5, 6]`, and is the
    /// subject's alone.
    #[test]
    fn a_credential_act_in_the_delegators_doc_one_is_an_act_of_the_account() {
        let dir = tempfile::tempdir().expect("tempdir");
        let genesis = Fingerprint::parse_hex(&"ab".repeat(32)).unwrap();
        let header = json!({ "skep-resolve": FEED_FORMAT, "realm": genesis.to_hex(), "root": null });
        let row = json!({ "row": { "at": 5, "op": "make_link", "link": "1.0.2.0.1.0.2.1", "docs": ["1.0.2.0.1"] } });
        fs::write(dir.path().join(FEED_COPY), format!("{header}\n{row}\n")).expect("the feed copy");
        let seeding = json!({ "link": {
            "at": 5, "address": "1.0.2.0.1.0.2.1", "home": "1.0.2.0.1",
            "ty": "1.1.0.1.0.1.0.3.1", "from": ["1.0.2.0.1.0.1.1"], "to": ["1.0.2.3"],
        }});
        fs::write(dir.path().join(FETCH_CACHE), format!("{seeding}\n")).expect("the fetch cache");
        let hint = RootHint::new(vec![Origin::parse("http://127.0.0.1:1").unwrap()], genesis, None).unwrap();
        let mirror = Mirror::rebuild_offline(&hint, dir.path()).expect("rebuilt");
        assert!(mirror.later_credential_act(&a("1.0.2.3"), 4, 6), "the seeding in the delegator's doc 1");
        assert!(!mirror.later_credential_act(&a("1.0.2.3"), 5, 6), "the interval is open below");
        assert!(!mirror.later_credential_act(&a("1.0.2"), 4, 6), "the act is the subject's, not its delegator's");
        assert_eq!(mirror.epoch_of(&a("1.0.2.3"), 9), 5);
    }
}
