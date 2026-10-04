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

use super::{Epoch, KeysAsOf, Mirror, MirrorError, Row};
use crate::board::BoardError;

/// THE DEEPEST PRINCIPAL PREFIX A BOARD MINTS, in components — its node
/// field, the separator and its account field together: skep-namespace's
/// `MAX_PRINCIPAL_COMPONENTS`, which `delegate` refuses past, restated here
/// because this crate links no engine. An account deeper than it is one no
/// board of this build wrote, so the walk that opens it — a read per level,
/// each carrying the whole prefix, quadratic in its depth — is never made:
/// its table is one this reader cannot read.
const MAX_PRINCIPAL_COMPONENTS: usize = 64;

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
            if let Row::Link { at, link, home } = Row::of(&self.rows[self.scanned]) {
                if let Some(stored) = self.read_link(at, &link, &home)? {
                    let credential =
                        stored.ty.as_ref().is_some_and(|t| *t == self.types.enroll || *t == self.types.retire);
                    if let (true, Some(subject)) = (credential, stored.to.first()) {
                        self.credential_acts.entry(subject.clone()).or_default().push(at);
                    }
                }
            }
            self.scanned += 1;
        }
        Ok(())
    }

    /// The EPOCH of `account`'s table as of `at`: its latest credential
    /// position at or below `at`, or 0.
    fn epoch_of(&self, account: &Address, at: u64) -> Epoch {
        let acts = self.credential_acts.get(account).map(Vec::as_slice).unwrap_or_default();
        Epoch(acts.iter().rev().find(|p| **p <= at).copied().unwrap_or(0))
    }

    /// Whether a credential act of `account` lies in `(after, upto]` among
    /// the held rows — an act as the credential pass records one.
    fn later_credential_act(&self, account: &Address, after: u64, upto: u64) -> bool {
        self.credential_acts.get(account).is_some_and(|acts| acts.iter().any(|p| *p > after && *p <= upto))
    }

    /// THE SET THAT OPENS `account` as of `at`: its own table where not
    /// empty, else the nearest keyed account above it (AUTH-4.30 (i)'s walk,
    /// as the daemon makes it); `None` where the table cannot be read, as it
    /// cannot for an account deeper than any board mints
    /// ([`MAX_PRINCIPAL_COMPONENTS`]).
    pub(super) fn keys_opening(&mut self, account: &Address, at: u64) -> Result<Option<Vec<Enrolled>>, MirrorError> {
        if account.tumbler().len() > MAX_PRINCIPAL_COMPONENTS {
            return Ok(None);
        }
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
    fn fetch_keys_epoch(&mut self, account: &Address, epoch: Epoch, at: u64) -> Result<Option<Vec<Enrolled>>, MirrorError> {
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
    fn keep_keys(&mut self, account: &Address, epoch: Epoch, at: u64, enrolled: Vec<Enrolled>) -> Result<(), MirrorError> {
        let line = self.fetched.keep_keys(KeysAsOf { account: account.clone(), epoch, at, enrolled });
        self.append_cache(line)
    }

    /// THE GENESIS SET of `account`: its table at its first credential act,
    /// read off the board and never off the fetch cache — the realm is never
    /// read off the cache (REG-3.42) — and kept under that act's epoch, the
    /// first act's position being its own epoch; `None` where no act of the
    /// account is held or the table cannot be read.
    pub(super) fn genesis_keys(&mut self, account: &Address) -> Result<Option<Vec<Enrolled>>, MirrorError> {
        let Some(&genesis_at) = self.credential_acts.get(account).and_then(|acts| acts.first()) else { return Ok(None) };
        let Some(keys) = self.read_keys_at(account, genesis_at)? else { return Ok(None) };
        self.keep_keys(account, Epoch(genesis_at), genesis_at, keys.clone())?;
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
    use skep_identity::{Fingerprint, PublicKey};
    use skep_signature::{HybridSigner, TAG_MLDSA65_ED25519};

    use super::super::{Fetched, FEED_COPY, FEED_FORMAT, FETCH_CACHE};
    use super::*;
    use crate::hint::RootHint;
    use crate::origin::Origin;
    use crate::parse_address;

    fn a(s: &str) -> Address {
        parse_address(s).unwrap()
    }

    fn key(seed: u8) -> PublicKey {
        HybridSigner::from_seed(TAG_MLDSA65_ED25519, &[seed; 32]).expect("tag 1").public_key().clone()
    }

    /// The hint the copies below are rebuilt under, and its genesis.
    fn hint() -> RootHint {
        let genesis = Fingerprint::parse_hex(&"ab".repeat(32)).unwrap();
        RootHint::new(vec![Origin::parse("http://127.0.0.1:1").unwrap()], genesis, None).unwrap()
    }

    /// Writes a copy under `dir` holding `rows` and a fetch cache of `cache`'s
    /// lines.
    fn write_copy(dir: &std::path::Path, rows: &[serde_json::Value], cache: &[serde_json::Value]) {
        let header = json!({ "skep-resolve": FEED_FORMAT, "realm": hint().realm().genesis.to_hex(), "root": null });
        let feed: String = std::iter::once(&header).chain(rows).map(|line| format!("{line}\n")).collect();
        fs::write(dir.join(FEED_COPY), feed).expect("the feed copy");
        fs::write(dir.join(FETCH_CACHE), cache.iter().map(|line| format!("{line}\n")).collect::<String>()).expect("the fetch cache");
    }

    /// A CREDENTIAL ACT is the enroll or retire link naming the account in
    /// ANY home: the genesis of an account beneath another, seeded in its
    /// delegating account's doc 1 (AUTH-2.62's genesis registry), is an act
    /// of the account — so the live table is never taken for the one before
    /// it. The act at 5 lies in `(4, 6]` and in `(4, 5]`, closed above, and
    /// not in `(5, 6]`, open below; and it is the subject's alone.
    #[test]
    fn a_credential_act_in_the_delegators_doc_one_is_an_act_of_the_account() {
        let dir = tempfile::tempdir().expect("tempdir");
        let row = json!({ "row": { "at": 5, "op": "make_link", "link": "1.0.2.0.1.0.2.1", "docs": ["1.0.2.0.1"] } });
        let seeding = json!({ "link": {
            "at": 5, "address": "1.0.2.0.1.0.2.1", "home": "1.0.2.0.1",
            "ty": "1.1.0.1.0.1.0.3.1", "from": ["1.0.2.0.1.0.1.1"], "to": ["1.0.2.3"],
        }});
        write_copy(dir.path(), &[row], &[seeding]);
        let mirror = Mirror::rebuild_offline(&hint(), dir.path()).expect("rebuilt");
        assert!(mirror.later_credential_act(&a("1.0.2.3"), 4, 6), "the seeding in the delegator's doc 1");
        assert!(mirror.later_credential_act(&a("1.0.2.3"), 4, 5), "the interval is closed above");
        assert!(!mirror.later_credential_act(&a("1.0.2.3"), 5, 6), "the interval is open below");
        assert!(!mirror.later_credential_act(&a("1.0.2"), 4, 6), "the act is the subject's, not its delegator's");
        assert_eq!(mirror.epoch_of(&a("1.0.2.3"), 9), Epoch(5));
    }

    /// THE SET THAT OPENS AN ACCOUNT (AUTH-4.30 (i)'s walk): the account's own
    /// table where it holds a key, whatever the account above holds; where it
    /// is empty, the nearest keyed account above it, and the empty set itself
    /// where the walk reaches the node; and where a table on the walk cannot
    /// be read — the account's own, or one above an empty one — none at all,
    /// never the table of an account further up and never an empty set.
    #[test]
    fn an_empty_table_opens_through_the_account_above_and_an_unread_one_does_not() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut kept = Fetched::default();
        let tables: [(&str, &[u8]); 7] = [
            ("1.0.2.3", &[]),
            ("1.0.2", &[2]),
            ("1.0.5.1", &[]),
            ("1.0.6", &[6]),
            ("1.0.7", &[]),
            ("1.0.8", &[8]),
            ("1.0.8.1", &[9]),
        ];
        let lines: Vec<serde_json::Value> = tables
            .iter()
            .map(|(account, seeds)| {
                let enrolled = seeds.iter().map(|s| Enrolled { key: key(*s), anchor: true }).collect();
                kept.keep_keys(KeysAsOf { account: a(account), epoch: Epoch(0), at: 0, enrolled }).expect("a new table")
            })
            .collect();
        write_copy(dir.path(), &[], &lines);
        let mut mirror = Mirror::rebuild_offline(&hint(), dir.path()).expect("rebuilt");
        let mut opening = |account: &str| -> Option<Vec<PublicKey>> {
            let keys = mirror.keys_opening(&a(account), 9).expect("no board, no wire error");
            keys.map(|keys| keys.into_iter().map(|e| e.key).collect())
        };
        assert_eq!(opening("1.0.2.3"), Some(vec![key(2)]), "empty: the account above");
        assert_eq!(opening("1.0.8.1"), Some(vec![key(9)]), "its own keys, whatever the account above holds");
        assert_eq!(opening("1.0.6.1"), None, "its own table unread: never the one above");
        assert_eq!(opening("1.0.5.1"), None, "empty, and the account above unread");
        assert_eq!(opening("1.0.7"), Some(Vec::new()), "empty, and above it the node: the empty set itself");
    }

    /// AN ACCOUNT DEEPER THAN ANY BOARD MINTS opens nothing: past sixty-four
    /// components — the node field, the separator and the account field
    /// together — its table is one this reader cannot read, and the walk up
    /// its levels is never made, though an account above it holds a key; at
    /// sixty-four the walk is made as for any account.
    #[test]
    fn an_account_deeper_than_any_board_mints_opens_nothing() {
        let dir = tempfile::tempdir().expect("tempdir");
        let account = |components: usize| a(&format!("1.0{}", ".1".repeat(components - 2)));
        let mut kept = Fetched::default();
        let tables = [(account(65), vec![]), (account(64), vec![]), (account(63), vec![key(5)])];
        let lines: Vec<serde_json::Value> = tables
            .iter()
            .map(|(acct, keys)| {
                let enrolled = keys.iter().map(|k| Enrolled { key: k.clone(), anchor: true }).collect();
                kept.keep_keys(KeysAsOf { account: acct.clone(), epoch: Epoch(0), at: 0, enrolled }).expect("a new table")
            })
            .collect();
        write_copy(dir.path(), &[], &lines);
        let mut mirror = Mirror::rebuild_offline(&hint(), dir.path()).expect("rebuilt");
        assert_eq!(account(65).tumbler().len(), 65);
        assert_eq!(mirror.keys_opening(&account(65), 9), Ok(None), "past the deepest prefix a board mints");
        let opened = mirror.keys_opening(&account(64), 9).expect("no board, no wire error");
        assert_eq!(opened.map(|keys| keys.into_iter().map(|e| e.key).collect::<Vec<_>>()), Some(vec![key(5)]), "at it");
    }
}
