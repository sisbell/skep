//! The merge records a landing reads and writes (the merge record's §4).
//!
//! [`Newest`] is the merger's newest record for the key as the landing read
//! it, beside the records a landing begun is judged by; the `Writer`
//! methods here read it, find a landing begun and never recorded, and write
//! a record and its link into a journal (the `land` module's doc; P20).

use serde_json::Value;
use skep_address::Address;

use crate::address::parse_address;
use crate::board::{acked_addr, frames, Rejection};
use crate::halt::Halt;
use crate::merge::journal::{self, Unfound};
use crate::merge::reads::{feed_rows, Merged, Refusal, Role};
use crate::merge::record::{newest, records_of, Found, PartAnswer, Record, RecordLanding};
use crate::publication::{owned_by, SCAN_BUSY_REISSUES};

use super::draft::{marked_sides, row_marks};
use super::faults::{own_fault_face, record_owed, shape_face, Unfit, Unwritten};
use super::landing::Landed;
use super::writer::{Stem, Writer};

/// The merger's newest record for the key, as the landing read it.
///
/// Only [`Writer::newest_record`] builds one, from the board, so what a
/// landing finds standing, the record a draft landing's ids follow and the
/// record it writes replaces are the board's state at the landing (P20),
/// never what the composition saw. Its newest is empty where no record of
/// the merger's own of the key stands. Beside it are the merger's own
/// records of the key's composition read in another state — the key the
/// same but for the fork's or the draft side's state — which name a member
/// a shot minted once ([`Newest::recording`]), and every draft a record of
/// the merger's own of the merge names as landed in, whatever its state,
/// and no take-back's record replaces, which no landing begun stands in
/// ([`Newest::recorded_in`]).
pub(super) struct Newest {
    /// The newest record of the key, with its link.
    newest: Option<(Address, Record)>,
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
    /// while the draft's marker, or for a baseless draft its feed row, names
    /// the later write. Nothing that writes reads that position: the undo
    /// goes by the marker's `at` or the feed row, the withdrawal by its own
    /// read, and a take-back's record names this one by its link, carrying
    /// no landing. `verify` reads the draft at it, where the draft held the
    /// first landing's M. A fresh landing that finds the record standing
    /// answers the position the marker, else the feed row, names, and the
    /// record's only where the draft marks no landing of the merge at or
    /// past it ([`Newest::draft_landing`]). A merge composed again after a
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

    /// Returns the draft landing the newest record names, found standing.
    ///
    /// It is a fresh landing's answer with nothing staged: the draft, the
    /// position its draft marks the landing at — `marked`'s answer for the
    /// draft, the board's mark as [`Writer::marked_landing`] reads it — and
    /// the record's link, with no newer head told and `staged` false. The
    /// record names the write that first landed the key in the draft, and a
    /// later landing of the key there moves the mark past it (skep #790), so
    /// a mark below that position is an earlier merge's, its marker put back
    /// since; where `marked` answers none, or only such a one, the position
    /// the record names is answered. `None` where the newest names no draft
    /// landing or none stands, `marked` then never called.
    ///
    /// # Errors
    ///
    /// `marked`'s, each as itself (SP-14).
    pub(super) fn draft_landing(
        &self,
        marked: impl FnOnce(&Address) -> Result<Option<u64>, Refusal>,
    ) -> Result<Option<Landed>, Refusal> {
        let Some((link, record)) = &self.newest else { return Ok(None) };
        let Some(RecordLanding::Draft { draft, position: recorded }) = &record.landed else {
            return Ok(None);
        };
        let position = marked(draft)?.filter(|at| at >= recorded).unwrap_or(*recorded);
        Ok(Some(Landed::Draft {
            into: draft.clone(),
            position,
            record: link.clone(),
            head_moved: None,
            staged: false,
        }))
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
    /// give the newest, the others name a member a shot minted once
    /// ([`Newest::recording`]), and the drafts all of them name as landed in,
    /// but those a take-back's record replaced, stand for no landing begun
    /// ([`Newest::recorded_in`]).
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
        let taken_back: Vec<&Address> = found
            .iter()
            .filter(|f| f.record.landed.is_none())
            .filter_map(|f| f.record.replaces.as_ref())
            .collect();
        let landed_in = found
            .iter()
            .filter(|f| !taken_back.contains(&&f.link))
            .filter_map(|f| match &f.record.landed {
                Some(RecordLanding::Draft { draft, .. }) => Some(draft.clone()),
                _ => None,
            })
            .collect();
        let (exact, other_states): (Vec<Found>, Vec<Found>) =
            found.into_iter().partition(|f| f.record.key() == merged.key);
        Ok(Newest { newest: newest(exact).map(|f| (f.link, f.record)), other_states, landed_in })
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
    /// the first the board still marks
    /// this merge's landing in ([`Writer::marked_landing`]) is answered with
    /// that mark's position: an undo, a withdrawal, another merge's landing
    /// or a publication of the draft since leaves no landing begun. `None`
    /// where none stands; a landing past the retention floor's reach is not
    /// found, the walk restarting at the floor (`feed_rows`).
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
