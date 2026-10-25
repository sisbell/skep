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
//! THE READS OFF THE TABLE: the set that opens an account AS OF a record's
//! position ([`Mirror::opening_keys_at`]), the verify's candidates (REG-1.86
//! (e)); and the set that opens it at the mirror's head
//! ([`Mirror::current_keys`]), the walk's answer (REG-3.7). An `impl Mirror`
//! child of `mirror`, reading the mirror's private state the way a child does.

use std::time::Instant;

use skep_address::Address;
use skep_identity::{
    parse_record_value, CredentialRecord, Enrolled, Enrollment, FilteredTable, Fingerprint, RecordKind,
    MAX_RECORD_BYTES,
};

use super::{account_of_document, Mirror, MirrorError, Row, StoredLink};

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

    /// One link row of the pass: the claim, taken ([`Mirror::take_claim`]);
    /// an enroll or a retire, its record fetched and handed to the table
    /// ([`Mirror::hand_to_table`]) — the link in ANY home, the home pin being
    /// the table's to apply; a link of any other type, nothing. Until the
    /// realm is compared on a mirror that holds a board, the link and the
    /// record value are read off the board and never off the fetch cache
    /// (REG-3.42).
    fn scan_link(&mut self, at: u64, link: &Address, home: &Address) -> Result<(), MirrorError> {
        let off_board = !self.realm_compared && self.board.is_some();
        let stored = if off_board { self.read_link_off_board(at, link, home)? } else { self.read_link(at, link, home)? };
        let Some(stored) = stored else { return Ok(()) };
        let Some(ty) = stored.ty.clone() else { return Ok(()) };
        if ty == self.types.claim {
            return self.take_claim(at, &stored);
        }
        let kind = if ty == self.types.enroll {
            RecordKind::Enroll
        } else if ty == self.types.retire {
            RecordKind::Retire
        } else {
            return Ok(());
        };
        match self.fetch_credential(kind, ty, at, &stored, off_board)? {
            Fetch::Record(record) => self.hand_to_table(HeldAct::Record(record)),
            Fetch::Unfetchable => match stored.to.first() {
                Some(subject) => self.hand_to_table(HeldAct::Missing { subject: subject.clone(), at }),
                None => Ok(()),
            },
            Fetch::NoRecord => Ok(()),
        }
    }

    /// A claim row (AUTH-2.67): the first the pass takes is the claim the
    /// fold honors ([`Mirror::claim`]), its claimant the account the row's
    /// link names in its `from` — on a mirror that holds a board, the board's
    /// own link, and the realm compared for that claimant
    /// ([`Mirror::realm_check`]) before the claim is taken. The table is born
    /// under it, and every act the pass held back enters, in order. A claim
    /// row after it moves nothing: a board admits one claim (AUTH-2.68 — a
    /// second is `already_claimed`), so a second served names no binding home,
    /// compares no realm and births no table.
    fn take_claim(&mut self, at: u64, stored: &StoredLink) -> Result<(), MirrorError> {
        if self.claim.is_some() {
            return Ok(());
        }
        let Some(claimant) = stored.from.first().cloned() else { return Ok(()) };
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
