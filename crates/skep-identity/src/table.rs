//! The signature-filtered key table — the check beside the fold (AUTH-2.94).
//!
//! The fold honors a credential record whatever its `sig` holds (AUTH-2.13,
//! AUTH-2.94), so on the board it runs the operator can rotate an account's
//! keys without holding one (REG-5.9). A VERIFYING reader keeps a second
//! table beside the fold's, this one — REG-3.39's "SIGNATURE-FILTERED table
//! from the genesis set forward", the design record §4.5's table paragraph,
//! clauses (a)–(d) — and judges every record it reads under it, never under
//! the key set the board serves: a rotation carrying no signature of the
//! account's keys enters no verifier's table, and an entry or a registry
//! record signed by the planted key reads UNSIGNED.
//!
//! **The filter.** One table per account ([`FilteredTable`]), stepped in
//! JOURNAL ORDER over the credential records a reader fetched for itself
//! (clause (d): a delegator's own enrolment before the genesis it signs).
//! A record is admitted only where its own `sig` verifies over its record
//! frame ([`RecordFrame`]) under the set that OPENS the account that owns
//! its HOME — AUTH-4.30 (i)'s walk, up from an account whose table is empty
//! to the nearest keyed account above it (clause (a)) — as the tables stood
//! at the record's base (clause (b)), at the grade the act needs
//! (AUTH-3.20–3.22): anchors alone for an anchor-flagged enrollment, a
//! retirement naming an anchor of THIS table, or a handoff genesis whose
//! giver's table holds an anchor (AUTH-3.21), and of those the keys whose
//! row's width is the blob's. The table filters the fold's honored records
//! and manufactures none (clause (c)): a record the fold refuses — homed
//! outside its account's doc 1 (AUTH-2.127), a genesis homed outside the
//! subject's genesis registry (AUTH-2.62) or naming a key the set above the
//! subject already holds (AUTH-2.71's handoff latch), a holder act on a
//! never-keyed account, a retirement that would empty a set (I3) — is out
//! whatever its `sig` says, and a fingerprint has one lifecycle per set
//! (I4, AUTH-2.98).
//! One record alone is HOST-TRUSTED: the board claimant's own genesis at or
//! below the claim (AUTH-4.55 (3), AUTH-4.58); every other genesis is judged
//! under its delegator's table.
//!
//! **A missing input is a verdict, never a fallback.** A record a reader
//! could not fetch ([`FilteredTable::missing`]) makes its account's table
//! undeterminable from that position on, and every opening set read through
//! that account ([`FilteredTable::opening_at`]) answers `None` — the design
//! record §7.2's REFUSE disposition, UNDETERMINABLE HERE at every reader —
//! and never the board's word.
//!
//! **The check is the caller's.** This crate links no signature library
//! (AUTH-2.1, AUTH-2.2): the table composes each candidate's frame and
//! hands the verify in as a parameter of `skep_signature::verify`'s own
//! shape — the marker tag, the key, the message, the blob — which every
//! caller passes as one closure. The fold ([`IdentityState`]) never reads
//! this table, and this module never reads the fold: the two share a crate
//! under the module map `lib.rs` states, and AUTH-2.94's "no input to the
//! fold" holds by construction.
//!
//! [`IdentityState`]: crate::IdentityState

use std::collections::BTreeMap;

use skep_address::{checked_inc, parent, Address, Level};

use crate::entry::{BoardTerm, RecordFrame, RecordRows};
use crate::key::{Fingerprint, HybridBlob, PublicKey};
use crate::keyset::Enrolled;
use crate::payload::Enrollment;

#[cfg(test)]
mod tests;

/// The two record kinds the table reads (AUTH-1.18).
///
/// They are the kinds whose record reserves a `sig` (AUTH-2.130): the
/// enrollment, a genesis's or a holder's, and the retirement. A claim
/// carries no record and never reaches the table.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RecordKind {
    /// An enrollment record, an [`Enrollment`] per entry.
    Enroll,
    /// A retirement record, a [`Fingerprint`] per entry.
    Retire,
}

/// One credential record as the filter reads it.
///
/// It is what a verifying reader fetched for itself (the design record
/// §4.5's "THE TABLE'S INPUTS ARE FETCHED, NEVER SERVED"): the link's
/// members and the atom's, each read the caller's own way — the home's
/// account by ω over the home or by address arithmetic, the entries and the
/// `sig` through [`parse_record_value`](crate::parse_record_value). Every
/// member is borrowed; the table copies what it admits.
///
/// **Precondition.** `enrolled` is the record's entries where `kind` is
/// [`RecordKind::Enroll`] and `retired` its fingerprints where it is
/// [`RecordKind::Retire`], each as the kind's parser answered them —
/// non-empty and duplicate-free — and `sigless` is that record's sig-less
/// canonical projection ([`canonical_record`](crate::canonical_record) over
/// the entries with no `sig`). The table re-checks none of it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CredentialRecord<'a> {
    /// The record's kind.
    pub kind: RecordKind,
    /// The deposit's link address, the name the record is refused under.
    pub link: &'a Address,
    /// The home — the document the link is deposited in.
    pub home: &'a Address,
    /// The home's account — the frame's `account`, ω over the home.
    pub home_account: &'a Address,
    /// The subject — the link's `to`, the account the record acts on.
    pub subject: &'a Address,
    /// The link's type address — the frame's type slot row.
    pub ty: &'a Address,
    /// The sig-less canonical record — the frame's body-bytes row.
    pub sigless: &'a [u8],
    /// The `sig` member, where the record carries one.
    pub sig: Option<&'a str>,
    /// An enrollment's entries; empty at a retirement.
    pub enrolled: &'a [Enrollment],
    /// A retirement's fingerprints; empty at an enrollment.
    pub retired: &'a [Fingerprint],
    /// The link's commit position; `None` read position-free, below a
    /// retention floor.
    pub position: Option<u64>,
}

/// One admission of an account's table.
///
/// It is a key, from the record that admitted it, until the record that
/// retired it — positions where known.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Admission {
    /// The key's fingerprint.
    pub fingerprint: Fingerprint,
    /// The admitted key.
    pub key: PublicKey,
    /// Whether the key is an anchor (AUTH-1.26).
    pub anchor: bool,
    /// The label the admitting record carried (AUTH-5.69).
    pub label: Option<String>,
    /// The admitting record's position; `None` position-free.
    pub since: Option<u64>,
    /// Where the admission's lifecycle stands.
    pub until: Until,
}

/// Where an admission's lifecycle stands.
///
/// There is one lifecycle per fingerprint and set (I4, AUTH-2.98).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Until {
    /// No admitted retirement names it: it stands enrolled.
    Enrolled,
    /// Retired by an admitted record at this position.
    RetiredAt(u64),
    /// Retired by an admitted record read position-free.
    ///
    /// The record lies below the retention floor: no base reads the key as
    /// enrolled.
    RetiredPositionFree,
}

/// Why the filter refused a record.
///
/// The first seven are the fold's own refusals (AUTH-2.66–2.76), which the
/// table repeats so a record the fold refuses is out whatever its `sig`
/// says (the design record §4.5's clause (c)); the rest are the trial's.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefusedCause {
    /// The home is not the home account's doc 1 (AUTH-2.127).
    NotDocOne,
    /// A genesis homed outside the subject's genesis registry (AUTH-2.62),
    /// or an enrollment of a keyed account homed outside its own doc 1.
    NotGenesisRegistry,
    /// A holder act in the subject's own doc 1 on a never-keyed account.
    NoHolder,
    /// A retirement homed outside the subject's own doc 1 (AUTH-2.76).
    NotHolderRetirement,
    /// An act that changes nothing: every key enrolled already held, or
    /// every fingerprint retired already out of the set.
    NothingChanged,
    /// A retirement of every enrolled key (I3, AUTH-2.74).
    WouldEmpty,
    /// No `sig` on a record the table does not host-trust.
    NoSig,
    /// No board term: the record frame cannot be composed.
    NoBoardTerm,
    /// The `sig` is no hybrid blob's hex (no [`SIG_ALGS`] row's width).
    ///
    /// [`SIG_ALGS`]: crate::SIG_ALGS
    NoBlob,
    /// The `sig` verifies under no candidate of the set that opens the
    /// home's account at the act's grade.
    Unsigned,
    /// The set that opens the home's account cannot be read here: a record
    /// of an account on the walk was never fetched.
    Undeterminable,
}

/// One record the filter refused, and why — inert to the table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refused {
    /// The record's link address.
    pub link: Address,
    /// The account the record acted on.
    pub subject: Address,
    /// The record's position, where known.
    pub position: Option<u64>,
    /// Why the filter refused it.
    pub cause: RefusedCause,
}

/// What [`FilteredTable::admit`] made of one record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// The record entered the table.
    Admitted {
        /// The key whose `sig` admitted it; `None` for the one host-trusted
        /// record, the claimant's own genesis.
        signer: Option<Fingerprint>,
    },
    /// The record is inert to the table, for the cause.
    Refused(RefusedCause),
}

/// A gap on the walk: an account whose records this reader could not fetch.
struct Gap;

/// What a judged record posts.
enum Decision {
    Refuse(RefusedCause),
    Enroll { new: Vec<usize>, signer: Option<Fingerprint> },
    Retire { removed: Vec<Fingerprint>, signer: Fingerprint },
}

/// The signature-filtered key tables of every account a reader holds
/// records of, keyed by account and stepped in journal order.
///
/// It is the design record §4.5's table, the module doc's rules: built by
/// [`FilteredTable::admit`] over each credential record in position order,
/// read by [`FilteredTable::opening_at`] for the candidates a record at a
/// position is judged under and by [`FilteredTable::opening_now`] for the
/// current ones. The claim it is built under — the position and the
/// claimant — decides the one host-trusted record; a table built with none
/// trusts nothing.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FilteredTable {
    claim: Option<(u64, Address)>,
    tables: BTreeMap<Address, Vec<Admission>>,
    refused: Vec<Refused>,
    /// Per account, the first position a record of it could not be read
    /// at: the table is undeterminable from there on.
    missing: BTreeMap<Address, u64>,
}

impl FilteredTable {
    /// Returns an empty table built under `claim`.
    ///
    /// `claim` is the board's claim entry — its position and the claimant
    /// (AUTH-2.67) — under which the claimant's own genesis at or below it
    /// is host-trusted; `None` where the board is unclaimed or the claim is
    /// not derivable, and then no record is.
    pub fn new(claim: Option<(u64, Address)>) -> FilteredTable {
        FilteredTable { claim, ..FilteredTable::default() }
    }

    /// Returns the claim the table is built under.
    pub fn claim(&self) -> Option<(u64, &Address)> {
        self.claim.as_ref().map(|(at, claimant)| (*at, claimant))
    }

    /// Admits `record` where the rules admit it, and answers what it did.
    ///
    /// `board` is `H.1`'s pair, the record frame's `board`; `verify` is
    /// the signature check, `skep_signature::verify`'s own shape — the
    /// marker tag, the candidate key, the frame's bytes under that key's
    /// token, the blob — answering whether both halves verify. A record
    /// refused is kept under [`FilteredTable::refused`] with its cause; one
    /// refused [`RefusedCause::Undeterminable`] marks its subject's table
    /// missing from its position, as [`FilteredTable::missing`] does.
    ///
    /// **Precondition.** Records are admitted in journal order — position
    /// order where positions are known, record order below the floor
    /// (AUTH-5.69) — so the table as it stands is the table at each
    /// record's base.
    pub fn admit<V>(&mut self, record: &CredentialRecord<'_>, board: Option<BoardTerm>, verify: V) -> Outcome
    where
        V: FnMut(u8, &PublicKey, &[u8], &[u8]) -> bool,
    {
        match self.judge(record, board, verify) {
            Decision::Refuse(cause) => {
                self.refused.push(Refused {
                    link: record.link.clone(),
                    subject: record.subject.clone(),
                    position: record.position,
                    cause,
                });
                if cause == RefusedCause::Undeterminable {
                    self.missing(record.subject, record.position.unwrap_or(0));
                }
                Outcome::Refused(cause)
            }
            Decision::Enroll { new, signer } => {
                let table = self.tables.entry(record.subject.clone()).or_default();
                for i in new {
                    let e = &record.enrolled[i];
                    table.push(Admission {
                        fingerprint: Fingerprint::of(&e.key),
                        key: e.key.clone(),
                        anchor: e.anchor,
                        label: e.label().map(str::to_string),
                        since: record.position,
                        until: Until::Enrolled,
                    });
                }
                Outcome::Admitted { signer }
            }
            Decision::Retire { removed, signer } => {
                let until = record.position.map_or(Until::RetiredPositionFree, Until::RetiredAt);
                if let Some(table) = self.tables.get_mut(record.subject) {
                    for a in table.iter_mut().filter(|a| a.until == Until::Enrolled && removed.contains(&a.fingerprint)) {
                        a.until = until;
                    }
                }
                Outcome::Admitted { signer: Some(signer) }
            }
        }
    }

    /// Marks `account`'s table undeterminable from `at` on.
    ///
    /// It is the reader's word that a record of `account` at `at` could not
    /// be fetched: from there every opening set read through the account
    /// answers `None`, never the table as it stood.
    pub fn missing(&mut self, account: &Address, at: u64) {
        let first = self.missing.entry(account.clone()).or_insert(at);
        *first = (*first).min(at);
    }

    /// Returns the records the filter refused, in the order admitted.
    pub fn refused(&self) -> &[Refused] {
        &self.refused
    }

    /// Returns every account holding an admission, in address order.
    pub fn accounts(&self) -> impl Iterator<Item = &Address> + '_ {
        self.tables.keys()
    }

    /// Returns `account`'s admissions, in the order admitted.
    pub fn admissions(&self, account: &Address) -> &[Admission] {
        self.tables.get(account).map(Vec::as_slice).unwrap_or(&[])
    }

    /// Returns `account`'s admissions enrolled as of `position` (P12).
    ///
    /// They are those admitted at a position below it, or position-free,
    /// and not yet retired at one below it — the set a record at `position`
    /// is judged under, its own effects not yet posted (the design record
    /// §4.5's clause (b)).
    pub fn as_of(&self, account: &Address, position: u64) -> impl Iterator<Item = &Admission> + '_ {
        self.admissions(account).iter().filter(move |a| a.since.is_none_or(|s| s < position)).filter(move |a| match a.until {
            Until::Enrolled => true,
            Until::RetiredAt(r) => r >= position,
            Until::RetiredPositionFree => false,
        })
    }

    /// Returns `account`'s admissions enrolled now — every one not retired.
    pub fn current(&self, account: &Address) -> impl Iterator<Item = &Admission> + '_ {
        self.admissions(account).iter().filter(|a| a.until == Until::Enrolled)
    }

    /// Returns the set that opens `account` as of `position`.
    ///
    /// It is AUTH-4.30 (i)'s walk over these tables: the account's own set
    /// where it is not empty, else the nearest keyed account's above it,
    /// and the empty set where the walk reaches the node. `None` where a
    /// table on the walk is undeterminable at that position
    /// ([`FilteredTable::missing`]) — never an empty set in its place.
    pub fn opening_at(&self, account: &Address, position: u64) -> Option<Vec<Enrolled>> {
        self.walk(account, Some(position)).ok().map(enrolled_of)
    }

    /// Returns the set that opens `account` now, by the same walk.
    pub fn opening_now(&self, account: &Address) -> Option<Vec<Enrolled>> {
        self.walk(account, None).ok().map(enrolled_of)
    }

    /// Returns what `record` posts, deciding under the tables as they stand.
    fn judge<V>(&self, r: &CredentialRecord<'_>, board: Option<BoardTerm>, verify: V) -> Decision
    where
        V: FnMut(u8, &PublicKey, &[u8], &[u8]) -> bool,
    {
        use Decision::Refuse;
        // The home pin (AUTH-2.127; clause (c)): a credential record is
        // honored in its home account's first document alone.
        if doc_1(r.home_account).as_ref() != Some(r.home) {
            return Refuse(RefusedCause::NotDocOne);
        }
        let own_space = r.home_account == r.subject;
        let held = self.admissions(r.subject);
        let keyed = held.iter().any(|a| a.until == Until::Enrolled);
        let every_entry: Vec<usize> = (0..r.enrolled.len()).collect();
        // The one host-trusted record (AUTH-4.55 (3)): the claimant's own
        // genesis at or below the claim.
        if r.kind == RecordKind::Enroll && own_space && !keyed && self.host_trusts(r) {
            return Decision::Enroll { new: every_entry, signer: None };
        }
        // The arms (AUTH-2.69–2.76), each with the grade the act needs
        // (AUTH-3.20–3.22) read off these tables.
        let (new, removed, anchor_grade) = match (r.kind, own_space, keyed) {
            (RecordKind::Enroll, true, true) => {
                // The holder arm: the entries the set admits — fingerprints
                // it has never held, enrolled or retired (I4, I9).
                let new: Vec<usize> = every_entry
                    .into_iter()
                    .filter(|&i| !held.iter().any(|a| a.fingerprint == Fingerprint::of(&r.enrolled[i].key)))
                    .collect();
                if new.is_empty() {
                    return Refuse(RefusedCause::NothingChanged);
                }
                let grade = new.iter().any(|&i| r.enrolled[i].anchor);
                (new, Vec::new(), grade)
            }
            (RecordKind::Enroll, _, false) => match self.genesis_registry(r) {
                // The genesis arm (AUTH-2.70): homed in the registry's doc 1,
                // the handoff latch (AUTH-2.71) inside the cell it would honor.
                Some(registry) if registry == *r.home_account => match self.handoff_latch_fires(r) {
                    Ok(true) => return Refuse(RefusedCause::NotGenesisRegistry),
                    Ok(false) => match self.genesis_grade(r.subject) {
                        Ok(grade) => (every_entry, Vec::new(), grade),
                        Err(Gap) => return Refuse(RefusedCause::Undeterminable),
                    },
                    Err(Gap) => return Refuse(RefusedCause::Undeterminable),
                },
                // The refusal arms (AUTH-2.71), in the written order.
                None => return Refuse(RefusedCause::NotGenesisRegistry),
                Some(_) if own_space => return Refuse(RefusedCause::NoHolder),
                Some(_) => return Refuse(RefusedCause::NotGenesisRegistry),
            },
            // The latch arm: a genesis attempt on a keyed account.
            (RecordKind::Enroll, false, true) => return Refuse(RefusedCause::NotGenesisRegistry),
            (RecordKind::Retire, true, true) => {
                let enrolled: Vec<&Admission> = held.iter().filter(|a| a.until == Until::Enrolled).collect();
                let removed: Vec<Fingerprint> =
                    r.retired.iter().filter(|fp| enrolled.iter().any(|a| a.fingerprint == **fp)).copied().collect();
                if removed.is_empty() {
                    return Refuse(RefusedCause::NothingChanged);
                }
                if removed.len() == enrolled.len() {
                    return Refuse(RefusedCause::WouldEmpty);
                }
                // Anchor-grade where it names an anchor of THIS table at its
                // base, never of the fold's (clause (a)).
                let grade = enrolled.iter().any(|a| a.anchor && removed.contains(&a.fingerprint));
                (Vec::new(), removed, grade)
            }
            (RecordKind::Retire, true, false) => return Refuse(RefusedCause::NoHolder),
            (RecordKind::Retire, false, _) => return Refuse(RefusedCause::NotHolderRetirement),
        };
        // The trial (the design record §4.5 (4), steps 3 to 6).
        let Some(sig) = r.sig else { return Refuse(RefusedCause::NoSig) };
        let Some(board) = board else { return Refuse(RefusedCause::NoBoardTerm) };
        let Some(blob) = HybridBlob::parse_hex(sig) else { return Refuse(RefusedCause::NoBlob) };
        let Ok(opening) = self.walk(r.home_account, None) else { return Refuse(RefusedCause::Undeterminable) };
        let candidates = opening.iter().filter(|a| !anchor_grade || a.anchor).map(|a| (&a.fingerprint, &a.key));
        match signer_of(r, board, blob.as_bytes(), candidates, verify) {
            None => Refuse(RefusedCause::Unsigned),
            Some(signer) => match r.kind {
                RecordKind::Enroll => Decision::Enroll { new, signer: Some(signer) },
                RecordKind::Retire => Decision::Retire { removed, signer },
            },
        }
    }

    /// Returns whether `r` is the claimant's own genesis at or below the
    /// claim (AUTH-4.55 (3)).
    ///
    /// A position-free record counts as below the claim: it was read below
    /// the retention floor, where the claimant's genesis lies (a keyless
    /// claimant cannot claim), and position-free reads come genesis-first
    /// (AUTH-5.69).
    fn host_trusts(&self, r: &CredentialRecord<'_>) -> bool {
        self.claim.as_ref().is_some_and(|(claim_at, claimant)| r.subject == claimant && r.position.is_none_or(|at| at <= *claim_at))
    }

    /// Returns the subject's genesis registry (AUTH-2.62), by address
    /// arithmetic: the parent account for an account delegated beneath one
    /// — none for the first child of a bootstrap-tier account, the agent
    /// space (RES-80, AUTH-5.87) — and, for a bootstrap-tier account, the
    /// claimant once the board is claimed as of the record's position, the
    /// account's own space before.
    fn genesis_registry(&self, r: &CredentialRecord<'_>) -> Option<Address> {
        if let Some(delegator) = parent(r.subject).filter(|p| p.level() == Level::Account) {
            let bootstrap_tier = parent(&delegator).is_none_or(|above| above.level() != Level::Account);
            let agent_space = checked_inc(&delegator, 1).ok().as_ref() == Some(r.subject);
            return (!(bootstrap_tier && agent_space)).then_some(delegator);
        }
        match &self.claim {
            Some((claim_at, claimant)) if r.position.is_none_or(|at| at > *claim_at) => Some(claimant.clone()),
            _ => Some(r.subject.clone()),
        }
    }

    /// Returns whether AUTH-2.71's handoff latch fires at the genesis `r`:
    /// the subject is a subdivision — its parent an account — and a key the
    /// genesis names already stands in the set that opens the account above
    /// it, read off these tables. A handoff gives an account to a party that
    /// could not already open it; a party that could needs no genesis. A gap
    /// on that walk is a gap.
    fn handoff_latch_fires(&self, r: &CredentialRecord<'_>) -> Result<bool, Gap> {
        let Some(above) = parent(r.subject).filter(|p| p.level() == Level::Account) else { return Ok(false) };
        let opening = self.walk(&above, None)?;
        Ok(r.enrolled.iter().any(|e| opening.iter().any(|a| a.fingerprint == Fingerprint::of(&e.key))))
    }

    /// Returns AUTH-3.21's grade of a genesis at `subject`, read off these
    /// tables: anchor-grade where the genesis is a handoff whose giver's set
    /// holds an anchor; device-grade for a hire (a child of the giver's agent
    /// space), a spawn (the giver itself an agent) and a top-level account's
    /// genesis, which enters no cone. The forked seat's admission carve has
    /// no object here: no reader of this table holds a seat.
    fn genesis_grade(&self, subject: &Address) -> Result<bool, Gap> {
        let Some(giver) = self.keyed_above(subject)? else { return Ok(false) };
        let agent_space_of = |of: &Address| checked_inc(of, 1).ok();
        if parent(subject) == agent_space_of(&giver) {
            return Ok(false);
        }
        if let Some(holder) = self.keyed_above(&giver)? {
            if parent(&giver) == agent_space_of(&holder) {
                return Ok(false);
            }
        }
        Ok(self.current(&giver).any(|a| a.anchor))
    }

    /// Returns the nearest account above `a` whose table holds a key now —
    /// AUTH-4.30 (i)'s walk, over account-tier ancestors alone — or a gap
    /// where an account on the way is undeterminable.
    fn keyed_above(&self, a: &Address) -> Result<Option<Address>, Gap> {
        let mut above = parent(a);
        while let Some(account) = above.filter(|x| x.level() == Level::Account) {
            if self.missing.contains_key(&account) {
                return Err(Gap);
            }
            if self.current(&account).next().is_some() {
                return Ok(Some(account));
            }
            above = parent(&account);
        }
        Ok(None)
    }

    /// Returns the set that opens `account` — now, or as of `as_of` — by
    /// AUTH-4.30 (i)'s walk, or a gap where a table on the walk is
    /// undeterminable there.
    fn walk(&self, account: &Address, as_of: Option<u64>) -> Result<Vec<&Admission>, Gap> {
        let mut at = account.clone();
        loop {
            if self.missing.get(&at).is_some_and(|&first| as_of.is_none_or(|position| first < position)) {
                return Err(Gap);
            }
            let set: Vec<&Admission> = match as_of {
                Some(position) => self.as_of(&at, position).collect(),
                None => self.current(&at).collect(),
            };
            if !set.is_empty() {
                return Ok(set);
            }
            match parent(&at) {
                Some(above) if above.level() == Level::Account => at = above,
                _ => return Ok(Vec::new()),
            }
        }
    }
}

/// Returns the first candidate whose own row verifies `blob` — the trial.
///
/// It is the design record §4.5 (4)'s steps 5 and 6, run over candidates a
/// caller chose: each candidate's frame is `record`'s record frame under
/// that key's own `ALGS` token, and `verify` — `skep_signature::verify`'s
/// shape, the caller's — is asked of its marker tag, the key, the frame and
/// `blob`. A candidate of another row's width than the blob's is passed
/// over untried. [`FilteredTable::admit`] runs it over the set that opens
/// the record's home; a reader naming a record's hand may run it over
/// candidates of its own first.
pub fn signer_of<'k, V>(
    record: &CredentialRecord<'_>,
    board: BoardTerm,
    blob: &[u8],
    candidates: impl IntoIterator<Item = (&'k Fingerprint, &'k PublicKey)>,
    mut verify: V,
) -> Option<Fingerprint>
where
    V: FnMut(u8, &PublicKey, &[u8], &[u8]) -> bool,
{
    let to = [record.subject.clone()];
    let frame = RecordFrame {
        board,
        home_account: record.home_account,
        home: record.home,
        rows: RecordRows {
            ty: record.ty,
            to: &to,
            replaces: None,
            lineage_fork_point: None,
            sigless_canonical_record: record.sigless,
        },
    };
    for (fingerprint, key) in candidates {
        let row = key.sig_alg_row();
        if row.sig_len() != blob.len() {
            continue;
        }
        if verify(row.tag, key, &frame.to_bytes(key.alg()), blob) {
            return Some(*fingerprint);
        }
    }
    None
}

/// Returns the address of `account`'s first document (AUTH-2.126) — the
/// arithmetic `doc_1_of` states, `inc(a, 2)`, restated here because the
/// fold's module owns that function and this module names no fold; `None`
/// where the operand is element-level, which no account is.
fn doc_1(account: &Address) -> Option<Address> {
    checked_inc(account, 2).ok()
}

/// Returns the admissions as the key set's shape, key and flag.
fn enrolled_of(set: Vec<&Admission>) -> Vec<Enrolled> {
    set.into_iter().map(|a| Enrolled { key: a.key.clone(), anchor: a.anchor }).collect()
}
