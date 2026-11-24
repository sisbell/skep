//! The merge records a landing reads and writes (the merge record's §4).
//!
//! [`Newest`] is the merger's newest record for the key as the landing read
//! it, beside the draft landings its records of the key stand for and the
//! records a landing begun is judged by; the `Writer` methods here read it,
//! find a landing of the composition standing in a draft its records name,
//! find a landing begun and never recorded, and write a record and its link
//! into a journal (the `land` module's doc; P20).

use serde_json::Value;
use skep_address::Address;

use crate::address::parse_address;
use crate::board::{acked_addr, frames, Rejection};
use crate::halt::Halt;
use crate::merge::journal::{self, Unfound};
use crate::merge::reads::{feed_rows, Merged, Refusal, Role};
use crate::merge::record::{
    newest, records_of, taken_back_links, Found, PartAnswer, Record, RecordLanding,
};
use crate::publication::{owned_by, SCAN_BUSY_REISSUES};

use super::draft::{marked_sides, row_marks};
use super::faults::{own_fault_face, record_owed, shape_face, Unfit, Unwritten};
use super::landing::Landed;
use super::writer::{Stem, Writer};

/// A draft landing of the key as a record of the merger's own names it.
///
/// It is the draft, the position of the write that first landed the key
/// there — a later landing of the key in the draft is the same landing and
/// moves only the draft's mark (skep #790) — and the record's link.
struct RecordedLanding {
    draft: Address,
    position: u64,
    link: Address,
}

impl RecordedLanding {
    /// Returns this landing as a fresh landing answers it found standing.
    ///
    /// The draft is the record's, `position` where its draft marks the
    /// landing, the record its link, no newer head told and nothing staged.
    fn found(&self, position: u64) -> Landed {
        Landed::Draft {
            into: self.draft.clone(),
            position,
            record: self.link.clone(),
            head_moved: None,
            staged: false,
        }
    }
}

/// The merger's newest record for the key, as the landing read it.
///
/// Only [`Writer::newest_record`] builds one, from the board, so what a
/// landing finds standing, the record a draft landing's ids follow and the
/// record it writes replaces are the board's state at the landing (P20),
/// never what the composition saw. Its newest is empty where no record of
/// the merger's own of the key stands. Beside it are the draft landings the
/// merger's own records of the key stand for, each draft's newest record of
/// the key naming it as landed in that no take-back's record replaces,
/// newest first, which a fresh landing looks for its own landing among
/// ([`Writer::found_standing`]); the merger's own records of the key's
/// composition read in another state — the key the same but for the fork's
/// or the draft side's state — which name a member a shot minted once
/// ([`Newest::recording`]); and every draft a record of the merger's own of
/// the merge names as landed in, whatever its state, and no take-back's
/// record replaces, which no landing begun stands in
/// ([`Newest::recorded_in`]).
pub(super) struct Newest {
    /// The newest record of the key, with its link.
    newest: Option<(Address, Record)>,
    /// The draft landings the records of the key stand for, newest first.
    drafts: Vec<RecordedLanding>,
    /// The merger's own records whose key is this one's with other states.
    other_states: Vec<Found>,
    /// The drafts the merger's own standing records of the merge name.
    landed_in: Vec<Address>,
}

impl Newest {
    /// Returns whether a record of the merger's own stands for `draft`.
    ///
    /// The record is of the merge, its states ignored, and names `draft` as
    /// landed in. One in any state, the newest of the key or not, testifies
    /// to the landing it names until a take-back's record replaces it, so
    /// the draft holds no landing begun and left unrecorded: a merge
    /// composed again after a fork or a draft side moved since its landing
    /// is another key, and its landing in that draft is the embedder's to
    /// make, never a landing begun; and a later landing in the draft with no
    /// take-back recorded between is that record's, the same landing (skep
    /// #790). A record a take-back replaced stands for none, so a landing in
    /// the draft since, its record unwritten, is a landing begun.
    fn recorded_in(&self, draft: &Address) -> bool {
        self.landed_in.contains(draft)
    }

    /// Returns the newest record's link: what a record written now replaces.
    pub(super) fn link(&self) -> Option<&Address> {
        self.newest.as_ref().map(|(link, _)| link)
    }

    /// Returns the link of the merger's newest record naming `member`.
    ///
    /// The record names it as landed in, its key this one's with other states.
    /// A member is minted once and never rearranged, so a record naming it is
    /// its landing's whatever state a later composition read: the merge
    /// composed again after its own shot re-windowed its draft side, which
    /// moves the draft's state, finds its member through it and writes no
    /// second record. `None` where no such record names the member.
    pub(super) fn recording(&self, member: &Address) -> Option<&Address> {
        let naming = self.other_states.iter().filter(|f| {
            matches!(&f.record.landed, Some(RecordLanding::Member { member: m, .. }) if m == member)
        });
        naming.max_by_key(|f| f.age()).map(|f| &f.link)
    }

    /// Returns the record a landing into `draft` follows, which its ids name.
    ///
    /// It is the newest record's link, or — where that record names `draft`
    /// as landed in — the link it replaces: the record is then this
    /// landing's own, met on a retry, or the first landing's, which a
    /// landing of the key into the same draft keeps (skep #790), and either
    /// follows the record that stood before it. So every call over one
    /// landing names one record, and a landing after a take-back recorded
    /// since names the take-back's. `None` where no record stands, or where
    /// the one naming `draft` replaces none.
    pub(super) fn follows(&self, draft: &Address) -> Option<&Address> {
        let (link, record) = self.newest.as_ref()?;
        match &record.landed {
            Some(RecordLanding::Draft { draft: landed, .. }) if landed == draft => {
                record.replaces.as_ref()
            }
            _ => Some(link),
        }
    }

    /// Returns the newest record's link where it names `landed`.
    ///
    /// It does where both land in the same member, or both in the same
    /// draft, whatever either's position. An undo's or a withdrawal's
    /// record names no landing and a landing of the key elsewhere names
    /// another, so either leaves nothing standing for `landed`.
    ///
    /// **The same landing (skep #790).** A landing of the key into the
    /// draft the newest record names — no take-back recorded since, whether
    /// the draft was edited in between or a take-back's record went
    /// unwritten — is that record's landing: its write lands, and no record
    /// is written. The record keeps the first landing's body and position,
    /// while the draft's marker, or for a baseless draft the row of the
    /// landing standing by its rows, names the later write. Nothing that
    /// writes reads that position: the undo goes by the marker's `at` or
    /// that row, the withdrawal by its own read, and a take-back's record
    /// names this one by its link, carrying no landing. `verify` reads the
    /// draft at it, where the draft held the first landing's M. A fresh
    /// landing that finds the record standing answers the position the
    /// marker, else that row, names, and finds none standing where the draft
    /// marks no landing of the merge at or past the record's position, the
    /// landing taken back whether or not its take-back's record was written
    /// ([`Writer::found_standing`]). A merge composed again after a
    /// fork or a draft side moved has another key, so no newest record of
    /// it names the draft, and its landing there writes a record of its own.
    pub(super) fn naming(&self, landed: &RecordLanding) -> Option<&Address> {
        let (link, record) = self.newest.as_ref()?;
        let same = match (record.landed.as_ref()?, landed) {
            (RecordLanding::Member { member: a, .. }, RecordLanding::Member { member: b, .. }) => {
                a == b
            }
            (RecordLanding::Draft { draft: a, .. }, RecordLanding::Draft { draft: b, .. }) => {
                a == b
            }
            _ => false,
        };
        same.then_some(link)
    }
}

impl Writer<'_> {
    /// Returns the record's read: the merger's newest record for the key.
    ///
    /// It is the merger's current record for the key (the merge record's
    /// §1.5 (ii), read first as §1.3's step 7 reads; §4's currency, newest
    /// per key), read by the landing from the board. It is found as the
    /// composition's prior records are, by the links of the kind to each
    /// side of the key, each homed in the journal holding its record, and
    /// kept to the merger's own account, exactly: the newest of those by the
    /// order their links were minted, in whichever of its journals, is the
    /// record. A record of the key in another account's journal — a
    /// sub-account's among them — is never the merger's: its landing is
    /// another's, and a record names in `replaces` one of its own account's
    /// (P20). It stands for a landing it names ([`Newest::naming`]); one
    /// naming no landing or another — an undo's or a withdrawal's, or a
    /// landing of the key elsewhere — replaced the record of this landing. A
    /// landing into a draft named spells its ids over the record it follows
    /// ([`Newest::follows`]). The links are walked once, every record whose
    /// key is the key with its states ignored kept: those of the key itself
    /// give the newest and the draft landings they stand for — each draft's
    /// newest record naming it as landed in that no take-back's record
    /// replaces, newest first ([`Writer::found_standing`]) — the others name
    /// a member a shot minted once ([`Newest::recording`]), and the drafts all
    /// of them name as landed in, but those a take-back's record replaced,
    /// stand for no landing begun ([`Newest::recorded_in`]).
    ///
    /// # Errors
    ///
    /// A halt reading the links or a record.
    pub(super) fn newest_record(&self, merged: &Merged) -> Result<Newest, Refusal> {
        let stateless = merged.key.stateless();
        let found: Vec<Found> = records_of(&self.reader, &merged.inputs.kind, &merged.key, |k| {
            k.stateless() == stateless
        })?
        .into_iter()
        .filter(|f| f.lies_in(self.merger.account))
        .collect();
        // A record stands for its draft's landing until a take-back's record,
        // which names no landing, replaces it.
        let taken_back = taken_back_links(&found);
        let landed_in = found
            .iter()
            .filter(|f| !taken_back.contains(&f.link))
            .filter_map(|f| match &f.record.landed {
                Some(RecordLanding::Draft { draft, .. }) => Some(draft.clone()),
                _ => None,
            })
            .collect();
        let (mut exact, other_states): (Vec<Found>, Vec<Found>) =
            found.into_iter().partition(|f| f.record.key() == merged.key);
        exact.sort_by_key(|f| std::cmp::Reverse(f.age()));
        let mut drafts: Vec<RecordedLanding> = Vec::new();
        for f in exact.iter().filter(|f| !taken_back.contains(&f.link)) {
            let Some(RecordLanding::Draft { draft, position }) = &f.record.landed else {
                continue;
            };
            if drafts.iter().all(|d| d.draft != *draft) {
                drafts.push(RecordedLanding {
                    draft: draft.clone(),
                    position: *position,
                    link: f.link.clone(),
                });
            }
        }
        let newest = newest(exact).map(|f| (f.link, f.record));
        Ok(Newest { newest, drafts, other_states, landed_in })
    }

    /// Returns the landing of the composition standing in a recorded draft.
    ///
    /// It is a fresh landing's answer. The drafts are those the merger's own
    /// records of the key name, one a draft, newest first (`Newest`'s draft
    /// landings), so a newer record — a landing of the key in another draft,
    /// a take-back of that landing, a take-back of another landing written
    /// late — hides no landing standing in a draft an older record names.
    /// Each draft is read as it stands, its `doc_metadata` and, with no
    /// recorded base, its rows and the past states their walk needs
    /// ([`Writer::landing_mark`]), and the first whose mark is this merge's
    /// landing at or past the position its record names, and whose words as
    /// of that mark are M (`holds_merge`), is answered at the mark with
    /// nothing staged ([`Landed::Draft`]'s `staged` false). The record names
    /// the write that first landed the key in the draft, and a later landing
    /// of the key there moves the mark past it (skep #790); a mark below it
    /// is an earlier merge's standing again — its marker put back, or on a
    /// draft with no recorded base its landing beneath one taken back — and
    /// no mark is a landing taken back: the board's mark is the fact and the
    /// record its testimony, so a take-back whose record went unwritten
    /// leaves no landing standing, whatever the record names. A mark whose
    /// landing placed another list than M is another composition's of the
    /// same key — the key holds no choice — and is no landing of this one,
    /// whose merger's choices it would drop unsaid. A draft whose mark
    /// cannot be read, the walk of its rows needing a past state the board
    /// has reclaimed, is answered at the position its record names: a
    /// landing that cannot be judged is never made a second time. `None`
    /// where no draft so judged holds this composition's landing.
    ///
    /// # Errors
    ///
    /// Each draft's reads' but [`Refusal::HistoryReclaimed`] at its mark —
    /// its `doc_metadata`, its rows and past states, and its `image` as of
    /// the mark, [`Refusal::HistoryBusy`] past the bounded retries among them
    /// — each as itself (SP-14).
    pub(super) fn found_standing(
        &self,
        merged: &Merged,
        newest: &Newest,
    ) -> Result<Option<Landed>, Refusal> {
        for recorded in &newest.drafts {
            let meta = self.reader.metadata(&recorded.draft, None)?;
            let at = match self.landing_mark(merged, &recorded.draft, &meta) {
                Ok(Some(at)) if at >= recorded.position => at,
                Ok(_) => continue,
                Err(Refusal::HistoryReclaimed { .. }) => {
                    return Ok(Some(recorded.found(recorded.position)))
                }
                Err(e) => return Err(e),
            };
            if self.holds_merge(merged, &recorded.draft, at)? {
                return Ok(Some(recorded.found(at)));
            }
        }
        Ok(None)
    }

    /// Returns a landing of the merge begun in a draft and never recorded.
    ///
    /// It is the read a fresh landing makes before its stage, the mint a
    /// cut-off landing would make twice (PUB-8.32, resume-by-read): the
    /// merger's drafts' `set_arrangement` rows on the supplement (wire.md
    /// §The change feed), `under` the merger's account with `drafts=true`,
    /// walked past the position the head was minted at — its `doc_metadata`'s
    /// `at`, read at the board's head, the walk from the floor where the
    /// board serves none — since every landing on the head was made after
    /// it, whatever position the composition was read at. A row is kept
    /// where its draft is the merger's account's own, exactly, never a
    /// sub-account's, and its `merge` names the head and the sides a landing
    /// there marks ([`marked_sides`]), and where the draft is no side of the
    /// merge: a landing in a side itself moves that side's text and base, so
    /// no composition read since is the one that landed there. Each draft
    /// so named that no record of the merger's own of the merge stands for
    /// ([`Newest::recorded_in`]) is read as it stands, latest row first, and
    /// the first the board still marks this merge's landing in
    /// ([`Writer::marked_landing`]) is answered with that mark's position: an
    /// undo, a withdrawal, another merge's landing standing over it or a
    /// publication of the draft since leaves no landing begun, while on a
    /// draft with no recorded base a restore or any other re-arrangement
    /// leaves it standing (skep #914). `None` where none stands; a landing
    /// past the retention floor's reach is not found, the walk restarting at
    /// the floor (`feed_rows`), nor is one whose draft's walk needs a past
    /// state the board has reclaimed.
    ///
    /// # Errors
    ///
    /// The head's `doc_metadata` read's, the feed walk's and each draft's
    /// reads' ([`Writer::marked_landing`]), each as itself (SP-14).
    pub(super) fn landing_begun(
        &self,
        merged: &Merged,
        newest: &Newest,
    ) -> Result<Option<(Address, u64)>, Refusal> {
        let head = merged.inputs.head.to_string();
        let minted = self.reader.metadata(&merged.inputs.head, None)?.at.unwrap_or(0);
        let account = self.merger.account;
        let mut drafts: Vec<Address> = Vec::new();
        feed_rows(&self.reader, account, true, minted, |row| {
            if row["op"].as_str() != Some("set_arrangement") {
                return;
            }
            let draft = row["docs"].as_array().and_then(|d| d.first()).and_then(Value::as_str);
            let Some(draft) = draft.filter(|d| owned_by(d, account)).and_then(parse_address) else {
                return;
            };
            let marks = row_marks(&row["merge"], &head, &marked_sides(merged, &draft));
            let side = merged.inputs.sides.iter().any(|s| *s.address() == draft);
            if marks && !side && !newest.recorded_in(&draft) {
                drafts.retain(|d| *d != draft);
                drafts.push(draft);
            }
        })?;
        for draft in drafts.iter().rev() {
            let meta = self.reader.metadata(draft, None)?;
            if let Some(at) = self.marked_landing(merged, draft, &meta)? {
                return Ok(Some((draft.clone(), at)));
            }
        }
        Ok(None)
    }

    /// Writes a landing's record, answering its link's address.
    ///
    /// The record is the composition's with `landed`, `claims` and the window
    /// parts' `answers` filled and `replaces` the link of `newest`, the
    /// merger's newest record for the key as the landing read it — none where
    /// none stands (P20). It is written through [`Writer::write_record`] under
    /// `stem` — the shot's, over the key and its answers, or the draft
    /// landing's, over the key, the draft, the position its write is typed
    /// against and, for a draft named, the record the landing follows (the
    /// `land` module's doc) — the link's first end the landed address, and a
    /// journal it cannot find or write into faced as the landing standing with
    /// its record unwritten ([`record_owed`]).
    ///
    /// # Errors
    ///
    /// [`Writer::write_record`]'s.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn write_landing_record(
        &self,
        merged: &Merged,
        landed: RecordLanding,
        claims: &[Address],
        newest: &Newest,
        stem: &Stem,
        journal: Option<&Address>,
        answers: &[PartAnswer],
    ) -> Result<Address, Refusal> {
        let target = match &landed {
            RecordLanding::Member { member, .. } => member.clone(),
            RecordLanding::Draft { draft, .. } => draft.clone(),
        };
        let mut record = merged.record.clone();
        record.landed = Some(landed.clone());
        record.claims = claims.to_vec();
        record.answers = answers.to_vec();
        record.replaces = newest.link().cloned();
        let owed = |why: Unwritten, cause: String| record_owed(&landed, &why, cause);
        self.write_record(&merged.inputs.kind, &record, &target, stem.as_str(), journal, &owed)
    }

    /// Writes `record` under `kind`, answering its link's address.
    ///
    /// The journal is found or minted, the atom appended at its end as a
    /// plain insert, and the link homed in the journal beside it, from the
    /// atom to `target` — the landed address, or the draft an undo or a
    /// withdrawal names — and every side of the record besides its head
    /// under the kind (§4, "Its home"). Both are writes into a private
    /// draft, which takes no `attest`, so no head is read and nothing is
    /// signed. The two writes carry the per-session ids `<stem>.record` and
    /// `<stem>.link`; `owed` faces the act standing with its record
    /// unwritten, for the [`Unwritten`] reason it is given: the account's
    /// journal not found, its find refused busy past the bounded reissues
    /// (the `journal` module's doc); a journal whose extent read answers
    /// `withheld` or `doc_not_registered`; or a journal named whose atom the
    /// board refuses `published_target` or `not_owner` — the caller's
    /// journal, where the account's own is this library's choice.
    ///
    /// # Errors
    ///
    /// The find of the account's journal refused busy past its reissues,
    /// faced by `owed` with nothing of the record sent; the journal's other
    /// refusals ([`journal::of`]); a journal this merger may not read or this
    /// board does not register, faced by `owed` with nothing of the record
    /// sent; the extent read's other refusals; a journal named whose atom the
    /// board refuses as published or another account's, faced by `owed` with
    /// nothing of the record written; the account's own journal refused so,
    /// a journal that is full, and a journal whose link this session may not
    /// make, as the library's own faults; an answer of a shape this client
    /// does not know, faced; [`Refusal::NeedsSignedSession`] at the link; the
    /// death signal, [`Refusal::SessionEnded`]; the board's other refusals
    /// verbatim.
    pub(in crate::merge) fn write_record(
        &self,
        kind: &Address,
        record: &Record,
        target: &Address,
        stem: &str,
        journal: Option<&Address>,
        owed: &dyn Fn(Unwritten, String) -> Halt,
    ) -> Result<Address, Refusal> {
        let named = journal.is_some();
        let on_end = self.reader.on_end();
        let journal = match journal::found(self.board, &self.merger, kind, journal.cloned(), on_end) {
            Ok(journal) => journal,
            Err(Unfound::Busy(r)) => {
                return Err(owed(Unwritten::Busy, format!("{}: the board refused the find of the account's merge journal, a class scan, on its first send and its {SCAN_BUSY_REISSUES} reissues — every class-scan permit was in use — so no write of the record was sent", r.code)).into())
            }
            Err(Unfound::Other(r)) => return Err(r),
        };
        let text = record.to_value().to_string();
        // The journal's read at the record, after the act it records: a
        // journal the act cannot write its record into leaves the act
        // standing.
        let extent = self.reader.extent(&journal, None).map_err(|e| {
            let unfit = match e {
                Refusal::Unreadable(_) => Unfit::Withheld,
                Refusal::NoSuchDocument(_) => Unfit::Unregistered,
                e => return e,
            };
            Refusal::from(owed(Unwritten::Journal(journal.clone(), unfit), format!("the board refused the read of {journal}'s extent, the end the record's atom is appended at, so no write of the record was sent")))
        })?;
        let ordinal = extent.checked_add(1).ok_or_else(|| {
            own_fault_face(
                "the journal is full",
                format!("{journal} answered an extent with no ordinal after it"),
            )
        })?;
        // Typed against the state the extent was read at (skep #442): the
        // reader's highest `as_of`, which that read just raised.
        let v = self.answered_write(
            &frames::insert_plain_atom(
                &journal.to_string(),
                ordinal,
                &text,
                self.reader.as_of(),
                Some(&format!("{stem}.record")),
            ),
            "appending the record",
        )?;
        let atom = match acked_addr(&v) {
            Some(a) => parse_address(a).ok_or_else(|| shape_face("insert", &v))?,
            None => {
                let Some(r) = Rejection::of(&v) else {
                    return Err(shape_face("insert", &v).into());
                };
                // A journal the caller named is the caller's: the act stands
                // with its record unwritten. The account's own is this
                // library's choice, so its refusal is the library's fault.
                let refused = |unfit: Unfit| -> Refusal {
                    owed(Unwritten::Journal(journal.clone(), unfit), format!("{}: the board refused the record's atom into {journal}, so nothing of the record was written", r.token())).into()
                };
                return Err(match r.key() {
                    "published_target" if named => refused(Unfit::Published),
                    "not_owner" if named => refused(Unfit::Foreign),
                    "published_target" => own_fault_face("the journal is not a draft", format!("{}: the merge journal {journal} is published, and a record is appended as a plain insert into a draft", r.token())),
                    "not_owner" => own_fault_face("the journal is not this account's", format!("{}: {journal} is owned by another account", r.token())),
                    _ => Refusal::Halt(r.refused(&v)),
                });
            }
        };
        // The link homed in the journal, beside the record: the atom's unit
        // span to the target and every side of the record besides its head,
        // typed the kind (§4, "Its home") — a private draft's link, unsigned.
        let mut to: Vec<Address> = vec![target.clone()];
        for side in record.sides.iter().filter(|s| s.role() != Role::Head) {
            if !to.contains(side.address()) {
                to.push(side.address().clone());
            }
        }
        let atom_text = atom.to_string();
        let to_text: Vec<String> = to.iter().map(ToString::to_string).collect();
        let to_refs: Vec<&str> = to_text.iter().map(String::as_str).collect();
        let frame = frames::make_link(
            &journal.to_string(),
            &[&atom_text],
            &to_refs,
            &kind.to_string(),
            Some(&format!("{stem}.link")),
        );
        let v = self.answered_write(&frame, "linking the record")?;
        if let Some(link) = acked_addr(&v) {
            return parse_address(link).ok_or_else(|| shape_face("make_link", &v).into());
        }
        let Some(r) = Rejection::of(&v) else { return Err(shape_face("make_link", &v).into()) };
        Err(match r.key() {
            "not_owner" => own_fault_face(
                "this session does not own the journal its record's link is homed in",
                format!(
                    "{}: the record's link is homed in {journal}, the journal that took its atom",
                    r.token()
                ),
            ),
            "signed_session_required" => Refusal::NeedsSignedSession,
            _ => Refusal::Halt(r.refused(&v)),
        })
    }
}
