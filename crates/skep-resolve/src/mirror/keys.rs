//! THE CREDENTIAL PASS AND THE TABLE IT FOLDS (REG-3.39, REG-2.33, REG-5.9;
//! the signed-ops design record §7.2's mirror duty) — the SIGNATURE-FILTERED
//! KEY TABLE every registry record is judged under, built by this mirror's
//! own fetch-and-fold and never read off the board: the board's `key_set` is
//! the fold's table, which the party that runs the daemon writes without a
//! key (REG-5.9), so a key it planted would open every record the plant
//! signs. The table itself is `skep-identity`'s ([`FilteredTable`]); what is
//! this crate's is the fetch of its inputs and the walk over the feed.
//!
//! THE PASS, the fold's first ([`Mirror::scan_credential_acts`]): every link
//! row among the held rows this pass has not read, its stored link from the
//! cache or the board. A CLAIM row is the claim the fold honors — the first,
//! a board admitting one (AUTH-2.68) — and the realm is compared at it
//! ([`Mirror::realm_check`]) before any line reaches the copy; the table is
//! born there, under that claim, and every credential act met before it is
//! admitted then, in journal order. A CREDENTIAL ACT — an enroll or a retire
//! link, in ANY home — has its record value fetched (the atom its link's
//! `from` names, through the mirror's atom read, kept in the fetch cache),
//! parsed by `skep-identity`'s one parse ([`parse_record_value`]) and handed
//! to the table with its home, its home's account by address arithmetic
//! ([`account_of_document`]), its subject and its position. The rules — the
//! home pin, the claimant's genesis alone host-trusted, every other genesis
//! under its delegator's table, the grades read off the tables, a record
//! with no `sig` or no admitted signer inert — are the table's, stated once
//! in `skep-identity`; this pass hands the signature check in as the
//! closure every caller of that table passes. A record whose value this
//! reader cannot fetch is a GAP: the subject's table is undeterminable from
//! that position on, and every verdict read through it UNDETERMINABLE HERE
//! — never the board's word, never an empty set.
//!
//! UNTIL THE REALM IS COMPARED, the pass reads every link and every record
//! value OFF THE BOARD and never off the fetch cache (REG-3.42): the
//! claimant, its genesis act and its genesis set are the board's own
//! wherever an adopted cache stands, and the realm is compared against that
//! genesis record's own keys ([`Mirror::genesis_keys`]). From the claim on,
//! the cache answers first, as it does for every other fetch.
//!
//! **The genesis read, alone** ([`Mirror::read_genesis`]; REG-3.2,
//! REG-3.39): the same pass over a board no copy is kept of, from the
//! feed's first row to the claim's and no further, answering what the realm
//! check would compare ([`Mirror::genesis_found`]) to a caller that holds no
//! hint yet — the printer of a registry's root hint. It reads each row
//! through the pass's own reader ([`Mirror::read_row`]) and names the
//! claimant by the pass's own rule (`claimant_of`), so a mirror and a
//! printer reach one genesis set by one read.
//!
//! THE READS OFF THE TABLE: the set that opens an account AS OF a record's
//! position ([`Mirror::opening_keys_at`]), the verify's candidates (REG-1.86
//! (e)); and the set that opens it at the mirror's head
//! ([`Mirror::current_keys`]), the walk's answer (REG-3.7). An `impl Mirror`
//! child of `mirror`, reading the mirror's private state the way a child does.

use std::path::Path;
use std::time::Instant;

use skep_address::Address;
use skep_identity::{
    parse_record_value, CredentialRecord, Enrolled, Enrollment, FilteredTable, Fingerprint, RecordKind,
    MAX_RECORD_BYTES,
};

use super::base::dial_root;
use super::{account_of_document, Mirror, MirrorError, Row, StoredLink};
use crate::hint::{RealmId, RootHint};
use crate::http::Dial;
use crate::origin::Origin;
use crate::Genesis;

/// One credential record the pass fetched and parsed, owned: the members the
/// shared table reads, lent to it as a [`CredentialRecord`].
pub(super) struct HeldRecord {
    kind: RecordKind,
    link: Address,
    home: Address,
    home_account: Address,
    subject: Address,
    ty: Address,
    sigless: String,
    sig: Option<String>,
    enrolled: Vec<Enrollment>,
    retired: Vec<Fingerprint>,
    position: u64,
}

impl HeldRecord {
    /// The record as the table reads it.
    fn view(&self) -> CredentialRecord<'_> {
        CredentialRecord {
            kind: self.kind,
            link: &self.link,
            home: &self.home,
            home_account: &self.home_account,
            subject: &self.subject,
            ty: &self.ty,
            sigless: self.sigless.as_bytes(),
            sig: self.sig.as_deref(),
            enrolled: &self.enrolled,
            retired: &self.retired,
            position: Some(self.position),
        }
    }
}

/// One act of the pass, as it is handed to the table: a record fetched and
/// parsed, or a gap — a record of `subject` at `at` this reader could not
/// fetch.
pub(super) enum HeldAct {
    Record(HeldRecord),
    Missing { subject: Address, at: u64 },
}

/// What the fetch of a credential act's record value answered.
enum Fetch {
    /// The record, parsed.
    Record(HeldRecord),
    /// The transport will not serve the value: a gap in the subject's table.
    Unfetchable,
    /// No record the fold would honor: a link with no subject or no atom, a
    /// home with no account, or bytes the one parse refuses — out of the
    /// table whatever a `sig` would say (the design record §4.5's clause
    /// (c)), and no gap.
    NoRecord,
}

impl Mirror {
    /// THE CREDENTIAL PASS, the fold's first: every link row among the held
    /// rows this pass has not read — its stored link from the cache or the
    /// board — read for the claim it carries or the credential act it is
    /// ([`Mirror::scan_link`]). A row the pass fails at is read again by the
    /// next sync, which takes the pass up where it stopped.
    pub(super) fn scan_credential_acts(&mut self) -> Result<(), MirrorError> {
        while self.scanned < self.rows.len() {
            if let Row::Link { at, link, home } = Row::of(&self.rows[self.scanned]) {
                self.scan_link(at, &link, &home)?;
            }
            self.scanned += 1;
        }
        Ok(())
    }

    /// Scans one link row of the pass.
    ///
    /// The row is read ([`Mirror::read_row`]), and where it is a claim row
    /// the claim it carries is taken ([`Mirror::take_claim`]).
    fn scan_link(&mut self, at: u64, link: &Address, home: &Address) -> Result<(), MirrorError> {
        match self.read_row(at, link, home)? {
            Some(claim) => self.take_claim(at, &claim),
            None => Ok(()),
        }
    }

    /// Reads one link row of the pass, answering a claim row's stored link.
    ///
    /// A claim's stored link is answered with the claim not yet taken: the
    /// pass takes it ([`Mirror::take_claim`]), and the genesis read alone
    /// stops at it ([`Mirror::read_genesis`]). An enroll or a retire has its
    /// record fetched and handed to the table ([`Mirror::hand_to_table`]) —
    /// the link in any home, the home pin being the table's to apply — and
    /// answers nothing, as a link of any other type does. Until the realm
    /// is compared on a mirror that holds a board, the link and the record
    /// value are read off the board and never off the fetch cache
    /// (REG-3.42).
    ///
    /// # Errors
    ///
    /// The [`MirrorError`] of a read the board refused or could not answer,
    /// or of a cache line not written.
    fn read_row(&mut self, at: u64, link: &Address, home: &Address) -> Result<Option<StoredLink>, MirrorError> {
        let off_board = !self.realm_compared && self.board.is_some();
        let stored = if off_board { self.read_link_off_board(at, link, home)? } else { self.read_link(at, link, home)? };
        let Some(stored) = stored else { return Ok(None) };
        let Some(ty) = stored.ty.clone() else { return Ok(None) };
        if ty == self.types.claim {
            return Ok(Some(stored));
        }
        let kind = if ty == self.types.enroll {
            RecordKind::Enroll
        } else if ty == self.types.retire {
            RecordKind::Retire
        } else {
            return Ok(None);
        };
        match self.fetch_credential(kind, ty, at, &stored, off_board)? {
            Fetch::Record(record) => self.hand_to_table(HeldAct::Record(record))?,
            Fetch::Unfetchable => {
                if let Some(subject) = stored.to.first() {
                    self.hand_to_table(HeldAct::Missing { subject: subject.clone(), at })?;
                }
            }
            Fetch::NoRecord => {}
        }
        Ok(None)
    }

    /// A claim row (AUTH-2.67): the first the pass takes is the claim the
    /// fold honors ([`Mirror::claim`]), its claimant the account the row's
    /// link names in its `from` ([`claimant_of`]) — on a mirror that holds a
    /// board, the board's own link, and the realm compared for that claimant
    /// ([`Mirror::realm_check`]) before the claim is taken. The table is born
    /// under it, and every act the pass held back enters, in order. A claim
    /// row after it moves nothing: a board admits one claim (AUTH-2.68 — a
    /// second is `already_claimed`), so a second served names no binding home,
    /// compares no realm and births no table.
    fn take_claim(&mut self, at: u64, stored: &StoredLink) -> Result<(), MirrorError> {
        if self.claim.is_some() {
            return Ok(());
        }
        let Some(claimant) = claimant_of(stored) else { return Ok(()) };
        let line = self.fetched.keep_claim(at, claimant.clone());
        self.append_cache(line)?;
        if self.board.is_some() {
            self.realm_check(&claimant)?;
        }
        self.claim = Some((at, claimant.clone()));
        self.table = Some(FilteredTable::new(Some((at, claimant))));
        for act in std::mem::take(&mut self.pending_acts) {
            self.hand_to_table(act)?;
        }
        Ok(())
    }

    /// The record value of a credential act: the atom the stored link's
    /// `from` names, fetched ([`Mirror::fetch_atom`]; off the board alone
    /// where `off_board`) and parsed by the kind's one parse, with the
    /// members the table reads — the home and its account by address
    /// arithmetic, the subject the link's `to`, the position the row's.
    fn fetch_credential(&mut self, kind: RecordKind, ty: Address, at: u64, stored: &StoredLink, off_board: bool) -> Result<Fetch, MirrorError> {
        let (Some(subject), Some(atom)) = (stored.to.first(), stored.from.first()) else {
            return Ok(Fetch::NoRecord);
        };
        let Some(home_account) = account_of_document(&stored.home) else { return Ok(Fetch::NoRecord) };
        let text = if off_board {
            self.fetch_atom_off_board(at, &stored.home, atom, MAX_RECORD_BYTES)?
        } else {
            self.fetch_atom(at, &stored.home, atom, MAX_RECORD_BYTES)?
        };
        let Some(text) = text else { return Ok(Fetch::Unfetchable) };
        let (enrolled, retired, sig, sigless) = match kind {
            RecordKind::Enroll => match parse_record_value::<Enrollment>(text.as_bytes()) {
                Ok(v) => {
                    let sigless = v.sigless_canonical_record();
                    (v.entries, Vec::new(), v.sig, sigless)
                }
                Err(_) => return Ok(Fetch::NoRecord),
            },
            RecordKind::Retire => match parse_record_value::<Fingerprint>(text.as_bytes()) {
                Ok(v) => {
                    let sigless = v.sigless_canonical_record();
                    (Vec::new(), v.entries, v.sig, sigless)
                }
                Err(_) => return Ok(Fetch::NoRecord),
            },
        };
        Ok(Fetch::Record(HeldRecord {
            kind,
            link: stored.address.clone(),
            home: stored.home.clone(),
            home_account,
            subject: subject.clone(),
            ty,
            sigless,
            sig,
            enrolled,
            retired,
            position: at,
        }))
    }

    /// One act handed to the table: admitted, with the signature check this
    /// crate passes in — `skep_signature::verify`, both halves — and the
    /// checks counted; or a gap marked. Held back where the table is not yet
    /// born — no claim taken — and admitted at the claim, in order.
    fn hand_to_table(&mut self, act: HeldAct) -> Result<(), MirrorError> {
        let board = self.board_term()?;
        let Some(table) = self.table.as_mut() else {
            self.pending_acts.push(act);
            return Ok(());
        };
        match act {
            HeldAct::Record(record) => {
                let t = Instant::now();
                let mut verifies = 0u64;
                table.admit(&record.view(), board, |tag, key, message, blob| {
                    verifies += 1;
                    skep_signature::verify(tag, key, message, blob).is_ok()
                });
                self.stats.credential_records += 1;
                self.stats.credential_verifies += verifies;
                self.stats.credential_time += t.elapsed();
            }
            HeldAct::Missing { subject, at } => table.missing(&subject, at),
        }
        Ok(())
    }

    /// THE GENESIS SET of `account` (REG-3.39): the keys its genesis record
    /// enrolls — the first enroll record naming the account among the acts
    /// the pass read before the claim, every one off the board — the set the
    /// realm id is compared against (REG-3.42); `None` where the board
    /// answered no such record before the claim. Unclaimed, a board admits
    /// no deposit but the ceremony's own genesis and claim (wire.md
    /// §Credential refusals: `claim_first`), a genesis fires once per account
    /// (AUTH-2.70), and a keyless claimant cannot claim, so the claimant's
    /// lies before its claim.
    pub(super) fn genesis_keys(&self, account: &Address) -> Option<Vec<Enrolled>> {
        self.pending_acts.iter().find_map(|act| match act {
            HeldAct::Record(r) if r.kind == RecordKind::Enroll && r.subject == *account => {
                Some(r.enrolled.iter().map(|e| Enrolled { key: e.key.clone(), anchor: e.anchor }).collect())
            }
            _ => None,
        })
    }

    /// Returns the genesis fingerprint the board's records name for `account`.
    ///
    /// It is the account's genesis set ([`Mirror::genesis_keys`])
    /// fingerprinted in the realm id's form (REG-3.39;
    /// [`RealmId::genesis_fingerprint`]): the value the realm check compares
    /// to its hint's ([`Mirror::realm_check`]) and the genesis read alone
    /// answers ([`Mirror::read_genesis`]), computed here and nowhere else.
    ///
    /// # Errors
    ///
    /// [`MirrorError::NoGenesis`] where the board answered no genesis record
    /// of the account before its claim.
    pub(super) fn genesis_found(&self, account: &Address) -> Result<Fingerprint, MirrorError> {
        let keys = self.genesis_keys(account).ok_or(MirrorError::NoGenesis)?;
        Ok(RealmId::genesis_fingerprint(&keys.iter().map(|e| Fingerprint::of(&e.key)).collect::<Vec<_>>()))
    }

    /// Reads the genesis a board's realm is named by (REG-3.39).
    ///
    /// The read is a cold mirror's credential pass over the board at `root`,
    /// stopped at the claim, so it reads what the realm check reads
    /// (REG-3.42): the root dialed and asked `/health` as an open asks it,
    /// then the feed paged from its first row and each link row read off
    /// the board — a claim, an enroll or a retire told apart by its stored
    /// link, a credential act's record value fetched — until the first
    /// claim row that names a claimant. The answer is that claim's
    /// position, its claimant, and the fingerprint of the key set the
    /// claimant's genesis record enrolls: the first enroll record naming
    /// the claimant among the acts read before the claim, and never the set
    /// the account holds now. It is the value a mirror opened against the
    /// same board compares to the genesis half of its hint's realm id,
    /// reached by the same reads, so a hint composed from it is one that
    /// mirror's realm check passes.
    ///
    /// The pass reads as a guest, keeps no copy and compares no realm: it
    /// holds no hint to compare against, and no row past the claim's is
    /// read. The fork point of a forked lineage is no part of it (REG-3.40):
    /// no read answers one.
    ///
    /// # Errors
    ///
    /// In the order they are met:
    ///
    /// 1. [`MirrorError::Unreachable`] where the root's dial fails or its
    ///    `/health` does not answer, the origin named beside its error.
    /// 2. [`MirrorError::Board`] where the board refuses or cannot answer a
    ///    read the pass makes.
    /// 3. [`MirrorError::NoGenesis`] where the claim is met and the board
    ///    answered no genesis record of its claimant before it.
    /// 4. [`MirrorError::NoClaim`] where the feed ends with no claim: an
    ///    unclaimed board has no realm.
    pub fn read_genesis(root: &Origin, dial: &Dial<'_>) -> Result<Genesis, MirrorError> {
        // The pass is a mirror's own, and a mirror is scoped to a hint: this
        // one's names the root and the fingerprint of no key, which nothing
        // reads — the pass ends before the realm check. No line reaches a
        // file before that check either, so the directory is never written.
        let unscoped = RootHint::new(vec![root.clone()], RealmId::genesis_fingerprint(&[]), None)
            .expect("one origin and no fork point make a hint");
        let (root, board) = dial_root(&unscoped, dial)?;
        let mut pass = Mirror::fresh(&unscoped, Some(root), Some(board), Path::new(""));
        let (mut since, mut limit) = (0, None);
        loop {
            let page = pass.board_ref()?.changes(since, &mut limit)?;
            for row in &page.rows {
                let Row::Link { at, link, home } = Row::of(row) else { continue };
                let Some(claim) = pass.read_row(at, &link, &home)? else { continue };
                let Some(claimant) = claimant_of(&claim) else { continue };
                let fingerprint = pass.genesis_found(&claimant)?;
                return Ok(Genesis { claim_at: at, claimant, fingerprint, reads: pass.board_ref()?.reads() });
            }
            if !page.more {
                return Err(MirrorError::NoClaim);
            }
            since = page.last;
        }
    }

    /// THE SET THAT OPENS `account` AS OF `at` (REG-1.86 (e)): the table's
    /// own walk (AUTH-4.30 (i)) over the records admitted below `at` — the
    /// candidates a record at `at` is judged under, its own effects not yet
    /// posted. `None` where no claim is taken yet, or a table on the walk is
    /// undeterminable at that position: UNDETERMINABLE HERE, never an empty
    /// set and never the board's word.
    pub(super) fn opening_keys_at(&self, account: &Address, at: u64) -> Option<Vec<Enrolled>> {
        self.table.as_ref()?.opening_at(account, at)
    }

    /// THE CURRENT KEYS of `account` — the set that opens it as of the
    /// mirror's HEAD, the position the index stands at (REG-3.7, REG-3.39's
    /// fold): the walk's read of "the current keys", the claimant's being the
    /// registrar's. Read off the signature-filtered table the pass folded,
    /// through the head's own row; no wire read is made and the answer is the
    /// same before and after a sync that held no row. `Some` of the empty set
    /// where no account on the walk holds a key; `None` where no claim is
    /// taken yet or a table on the walk is undeterminable — UNDETERMINABLE
    /// HERE, never an empty set. Refused never: the `Result` is the walk's
    /// shape, kept for its callers.
    pub fn current_keys(&mut self, account: &Address) -> Result<Option<Vec<Enrolled>>, MirrorError> {
        Ok(self.opening_keys_at(account, self.head + 1))
    }
}

/// Returns the claimant a claim link names (AUTH-2.48).
///
/// It is the account in the link's `from`, none where the link names none:
/// the one rule both readers of a claim row name its claimant by, the pass
/// that takes the claim and the genesis read that stops at it.
fn claimant_of(claim: &StoredLink) -> Option<Address> {
    claim.from.first().cloned()
}

#[cfg(test)]
mod tests {
    use std::rc::Rc;

    use skep_registry::{commons_type, t_binding};

    use super::*;
    use crate::board::BoardError;
    use crate::http::{Transport, TransportError};
    use crate::mirror::testing::{
        binding_text, enroll_text, hint_of, key, realm_of, retire_text, signer, KeySetArm, Script, ScriptedBoard,
    };
    use crate::mirror::Refusal;
    use crate::parse_address;

    fn a(s: &str) -> Address {
        parse_address(s).unwrap()
    }

    /// Returns the root every read below names.
    ///
    /// The dial answers it with the board, whatever it names.
    fn root() -> Origin {
        Origin::parse("http://127.0.0.1:1").unwrap()
    }

    /// Returns a dial that answers every origin with `board`.
    fn dial_of(board: &Rc<ScriptedBoard>) -> impl Fn(&Origin) -> Result<Box<dyn Transport>, TransportError> {
        let board = board.clone();
        move |_: &Origin| -> Result<Box<dyn Transport>, TransportError> { Ok(Box::new(board.clone())) }
    }

    /// Returns a feed's opening rows, before any claim.
    ///
    /// At 1 stands a link of no type the pass reads, at 2 the genesis of
    /// `1.0.2`, another account than the claimant every board below names.
    fn opening() -> Script {
        let other = a("1.0.2.0.1");
        let mut script = Script::new();
        script.deposit(&other, &a("1.1.0.1.0.1.0.7.1"), &[], "no record the pass reads");
        script.deposit(&other, &commons_type(&[1]), &[a("1.0.2")], &enroll_text(None, &other, &a("1.0.2"), &[(&key(3), true)]));
        script
    }

    /// Checks that the genesis read answers what the realm check compares.
    ///
    /// The board's claimant `1.0.1` enrolls `key(1)` at 3, claims at 4, then
    /// rotates: `key(2)` enrolled at 5 and `key(1)` retired at 6, so the set
    /// the account holds now is `key(2)` alone. The read answers the claim
    /// and the fingerprint of the genesis set, `key(1)`'s — never the living
    /// set's, and never the earlier genesis of another account; it reads one
    /// page of the feed and the four links through the claim's, none past
    /// it, and asks the board for no key set and no position read. A mirror
    /// opened under that fingerprint passes its realm check, and one opened
    /// under the living set's is refused naming the read's own answer as
    /// what it found (the mutant that fingerprints the living set fails all
    /// three).
    #[test]
    fn the_genesis_read_answers_what_the_realm_check_compares_and_stops_at_the_claim() {
        let (registry, claimant) = (a("1.0.1.0.1"), a("1.0.1"));
        let (one, two) = (signer(1), signer(2));
        let mut script = opening();
        script.deposit(&registry, &commons_type(&[1]), std::slice::from_ref(&claimant), &enroll_text(None, &registry, &claimant, &[(one.public_key(), true)]));
        script.claim(&claimant);
        script.deposit(&registry, &commons_type(&[1]), std::slice::from_ref(&claimant), &enroll_text(Some(&one), &registry, &claimant, &[(two.public_key(), true)]));
        script.deposit(&registry, &commons_type(&[2]), std::slice::from_ref(&claimant), &retire_text(&two, &registry, &claimant, &[Fingerprint::of(one.public_key())]));
        script.deposit(&registry, t_binding(), &[a("1.0.2")], &binding_text(&two, &registry, &[a("1.0.2")], &a("1.5")));
        let board = Rc::new(script.board(KeySetArm::Refused));
        let dial = dial_of(&board);
        let genesis = Mirror::read_genesis(&root(), &dial).expect("the genesis read");
        let (of_genesis, of_living) = (realm_of(&[one.public_key()]), realm_of(&[two.public_key()]));
        assert_eq!(genesis.fingerprint, of_genesis, "the genesis set's fingerprint");
        assert_ne!(genesis.fingerprint, of_living, "never the living set's");
        assert_eq!((genesis.claim_at, &genesis.claimant), (4, &claimant));
        let reads = genesis.reads;
        assert_eq!((reads.health, reads.changes, reads.read_link, reads.key_set, reads.op_at), (1, 1, 4, 0, 0), "{reads:?}");
        let asked = board.asked.borrow().clone();
        assert_eq!(asked.iter().filter(|r| r.as_str() == "POST /op read_link").count(), 4, "no link past the claim's: {asked:?}");
        assert_eq!(asked.iter().filter(|r| r.contains("/changes")).collect::<Vec<_>>(), ["GET /changes?since=0"], "{asked:?}");
        let dir = tempfile::tempdir().expect("tempdir");
        let mirror = Mirror::open(&hint_of(genesis.fingerprint), dir.path(), &dial).expect("the realm check passes on the read's answer");
        assert_eq!(mirror.claim(), Some((4, &claimant)), "the claim the read stopped at");
        let other = tempfile::tempdir().expect("tempdir");
        let refused = Mirror::open(&hint_of(of_living), other.path(), &dial).unwrap_err();
        assert_eq!(refused, MirrorError::Refused(Refusal::RealmMismatch { expected: of_living, found: genesis.fingerprint }));
    }

    /// Checks each refusal of the genesis read, by name.
    ///
    /// A feed with no claim through its end is an unclaimed board; a claim
    /// whose claimant has no genesis record before it — another account's
    /// alone stands there — and one whose genesis record the board will not
    /// serve, are no genesis to fingerprint; and a root whose dial fails is
    /// named beside its error, no read made.
    #[test]
    fn the_genesis_read_refuses_by_name() {
        let (registry, claimant) = (a("1.0.1.0.1"), a("1.0.1"));
        let unclaimed = Rc::new(opening().board(KeySetArm::Refused));
        assert_eq!(Mirror::read_genesis(&root(), &dial_of(&unclaimed)), Err(MirrorError::NoClaim));
        let mut script = opening();
        script.claim(&claimant);
        let no_genesis = Rc::new(script.board(KeySetArm::Refused));
        assert_eq!(Mirror::read_genesis(&root(), &dial_of(&no_genesis)), Err(MirrorError::NoGenesis), "another account's genesis is not the claimant's");
        let mut script = opening();
        script.deposit(&registry, &commons_type(&[1]), std::slice::from_ref(&claimant), &enroll_text(None, &registry, &claimant, &[(&key(1), true)]));
        script.claim(&claimant);
        let withheld = Rc::new(script.board(KeySetArm::Refused));
        withheld.withhold(&a("1.0.1.0.1.0.1.1"));
        assert_eq!(Mirror::read_genesis(&root(), &dial_of(&withheld)), Err(MirrorError::NoGenesis), "a genesis record the board will not serve");
        let down = |_: &Origin| -> Result<Box<dyn Transport>, TransportError> { Err(TransportError::Connect("refused".into())) };
        let tried = vec![(root(), BoardError::Transport(TransportError::Connect("refused".into())))];
        assert_eq!(Mirror::read_genesis(&root(), &down), Err(MirrorError::Unreachable { tried }));
    }
}
