//! The shot: the one `publish` of M from the head (the merge record's §1.5).
//!
//! [`Writer::publish`] composes the frame through the publication's request
//! builder and sends it, signed over the board's head where the board has
//! one, and sends it once more where the twin fence meets it or a claim
//! landed past the head's read; the daughters' skip is read before signing
//! and their claims after the shot (the `land` module's doc).

use serde_json::Value;
use skep_address::Address;
use skep_identity::{BoardTerm, EntryBody};

use crate::address::parse_address;
use crate::board::{acked_addr, acked_at, answers, frames, Answer, Rejection};
use crate::halt::{Halt, Refused};
use crate::merge::compose::Run;
use crate::merge::reads::{session_ended, stretches, values_of, Family, Merged, Refusal, Side};
use crate::merge::windows::{self, ShotParts};
use crate::publication::{self, own_claim_names, Piece, SupersedeCause};

use super::faults::{head_owed, own_fault, own_fault_face, shape_face};
use super::standing::Standing;
use super::writer::{Stem, Writer};
use super::SHOT_BODY_BUDGET;

impl Writer<'_> {
    /// Sends the shot, answering the member minted and the ack's position.
    ///
    /// The frame is composed and sent by [`Writer::send_shot`]. Where the board
    /// answers `already_published`, a publication of the draft's words having
    /// landed since [`windows::step`] read the records (the `land` module's
    /// doc, the twin fence), nothing is committed: the records are read again
    /// and `shot` recomposed ([`windows::retwin`]), a member found holding the
    /// list it now states is answered as the landing, and else the shot is sent
    /// once more, its new runs signed afresh under its own id — a refusal
    /// leaves the id unmemoized (wire.md §Correlation and idempotency).
    ///
    /// # Errors
    ///
    /// [`Writer::send_shot`]'s; the re-read's, [`windows::retwin`]'s and a
    /// member's reads' ([`Writer::standing_member`]); a second
    /// `already_published` as [`Refusal::AlreadyPublished`], naming the draft
    /// and the member the board names; [`Refusal::WindowWithheld`] naming
    /// the origin as the board names it and beside it its words in the list
    /// `shot` places that the head does not carry — a `withheld` naming in
    /// `site.addr` no document this client parses is the board's refusal
    /// verbatim (SP-18) — [`Refusal::NeedsSignedSession`] and
    /// [`Refusal::NoSuchDocument`] as the board answers them; `not_owner`
    /// naming the draft side as
    /// [`Refusal::UnownedDraft`], `supersede_refused` as
    /// [`Refusal::SupersedeRefused`] with its entry and cause,
    /// `publication_over_budget` as the board's refusal verbatim, never this
    /// library's fault, `kept_place_moved` as the board's verdict in the
    /// person's words, naming the draft that changed since the merge was
    /// composed and that nothing was published, and
    /// `attestation_invalid:board_unavailable` faced as the head the board
    /// owes; the board's refusal of the frame's substance — the shot's own
    /// table, a place the records do not name (`stray_place_unrecorded`), or
    /// another deposit's token, which this frame never carries — as the
    /// library's own faults; an answer of a shape this client does not know,
    /// faced; the board's other refusals verbatim.
    pub(super) fn publish(&self, merged: &Merged, draft: Option<&Address>, shot: &mut ShotParts) -> Result<(Address, u64), Refusal> {
        let doc = &merged.inputs.doc;
        let draft_side = merged.inputs.sides.iter().find_map(|s| match s {
            Side::Draft { at, .. } => Some(at.clone()),
            _ => None,
        });
        let fresh = merged.families.contains(&Family::DraftNative);
        let draft = draft.cloned().or(if fresh { draft_side } else { None });
        let mut v = self.send_shot(merged, draft.as_ref(), shot)?;
        if Rejection::of(&v).is_some_and(|r| r.key() == "already_published") {
            windows::retwin(self, merged, shot)?;
            match self.standing_member(merged, shot)? {
                Standing::Trunk(member, at) | Standing::Daughter(member, at) => return Ok((member, at)),
                Standing::Absent => {}
            }
            v = self.send_shot(merged, draft.as_ref(), shot)?;
        }
        if let (Some(addr), Some(at)) = (acked_addr(&v), acked_at(&v)) {
            let member = parse_address(addr).ok_or_else(|| shape_face("publish", &v))?;
            return Ok((member, at));
        }
        let Some(r) = Rejection::of(&v) else { return Err(shape_face("publish", &v).into()) };
        let site = r.site().addr.as_deref().and_then(parse_address);
        Err(match r.key() {
            // The words refused: the runs of the list the shot placed whose
            // origin the board names, but those the head carries, which
            // the source gate never consults (PUB-6.24). Where it names no
            // document this client parses, none is typed in its place: the
            // wire names one on every `withheld` (wire.md §Rejections), and
            // never the trunk, whose own words the gate never consults. The
            // answer rides verbatim (SP-18).
            "withheld" => match site {
                Some(origin) => {
                    let head = merged.maps.first().map_or(&[][..], |head| head.runs.as_slice());
                    let positions = stretches(shot.runs.iter().map(|placed| {
                        (placed.run.origin == origin && !windows::carried(head, &placed.run), placed.run.width)
                    }));
                    Refusal::WindowWithheld { origin, positions }
                }
                None => Refusal::Halt(r.refused(&v)),
            },
            "signed_session_required" => Refusal::NeedsSignedSession,
            "doc_not_registered" => Refusal::NoSuchDocument(doc.clone()),
            // The draft side another account's, named.
            "not_owner" if site.is_some() && site == draft => match site.clone() {
                Some(draft) => Refusal::UnownedDraft { draft },
                None => own_fault("the shot", &r),
            },
            // The plan's judgement of the daughters, typed: the board's
            // verdict, never this frame's fault; a detail this client does
            // not know rides verbatim.
            "supersede_refused" => match SupersedeCause::of(r.detail(), r.site()) {
                Some(cause) => {
                    Refusal::SupersedeRefused { index: r.site().index.unwrap_or(0), cause }
                }
                None => Refusal::Halt(r.refused(&v)),
            },
            // The twin fence met again past the one re-read, or naming no
            // draft and no member: a second race, typed, or an answer this
            // client can only say verbatim.
            "already_published" => match (draft.clone(), site.clone()) {
                (Some(draft), Some(member)) => Refusal::AlreadyPublished { draft, member },
                _ => Refusal::Halt(r.refused(&v)),
            },
            "publication_over_budget" => Refusal::Halt(r.refused(&v)),
            // The draft changed past the position its kept places were read
            // at: the board's verdict, nothing committed, never this client's
            // fault, in the person's words.
            "kept_place_moved" => {
                let changed = site.as_ref().or(draft.as_ref()).unwrap_or(doc);
                Refusal::Halt(Halt::Refused(Refused {
                    status: 200,
                    code: r.code().to_string(),
                    detail: Some(format!(
                        "{changed} changed after the merge was composed at position {} — nothing was published; run the merge again, which reads the draft as it stands",
                        merged.as_of
                    )),
                    op: r.op().map(str::to_string),
                    body: v.clone(),
                }))
            }
            "base_superseded"
            | "base_not_in_chain"
            | "base_extent_too_large"
            | "bad_run"
            | "dangling_source"
            | "source_not_registered"
            | "not_owner"
            | "too_many_runs"
            | "too_many_values"
            | "private_source_versionless"
            | "stray_place_unrecorded"
            | "link_home_refused"
            | "old_refused"
            | "duplicate_original"
            | "read_with_in_links"
            | "retract_refused"
            | "read_with_refused"
            | "malformed" => own_fault("the shot", &r),
            // The board's state, never this library's frame (a reorder).
            "attestation_invalid:board_unavailable" => head_owed(format!(
                "{}: the board refused the shot, serving no head record (`H.1`) to verify its signature over — a head the board owes, never this library's frame",
                r.token()
            ))
            .into(),
            k if k.starts_with("attestation_") => own_fault("the shot's attest", &r),
            _ => Refusal::Halt(r.refused(&v)),
        })
    }

    /// Composes the shot and sends it, answering the board's document.
    ///
    /// The frame and its body go through the publication's request builder
    /// with the daughters as its one deposit list — every copied run's values
    /// re-read at the head through the side that holds them, each holder's
    /// runs in as few reads as the budgets allow, every window by address, the
    /// base group the head and its extent as read, `supersede` the `Member`
    /// sides with the skip read first ([`Writer::daughters`]) — and, where the
    /// shot renders a draft side, the list cut where that draft cuts it with
    /// its kept place beside each piece ([`windows::kept_places`]; none for
    /// a draft named beside the sides, whose image no read made) — then the
    /// frame with its `attest` and its id, the records read again first
    /// ([`windows::recheck`]), one re-ask under the same id on a lost
    /// acknowledgment, and the frame sent once more, signed, under the same
    /// id where it went unsigned and a claim landed past the head's read
    /// ([`Writer::attest_after_claim`]).
    ///
    /// # Errors
    ///
    /// [`Refusal::OverCap`] over the list the kept places cut, nothing sent;
    /// then the head's refusal and halts ([`Writer::signing_term`]), read
    /// before the values, nothing sent, and read again after a claim,
    /// nothing sent past it; the skip reads' refusals at the daughters;
    /// [`Refusal::WindowPartsOwed`] naming a part a record names since its
    /// answer was given; the value reads' refusals; the attest's fault; a
    /// body past [`SHOT_BODY_BUDGET`], a run with no address and a window of
    /// width 0, as the library's own faults; the death signal,
    /// [`Refusal::SessionEnded`]; a dial fault after the one re-ask.
    fn send_shot(&self, merged: &Merged, draft: Option<&Address>, shot: &ShotParts) -> Result<Value, Refusal> {
        let doc = &merged.inputs.doc;
        let head = &merged.inputs.head;
        // The list as sent: cut at the kept places of the draft side the shot
        // renders, its image the one the composition read — at the head
        // inside its fences, or as of the draft's named position.
        let rendered = draft.filter(|d| merged.inputs.sides.iter().any(|s| matches!(s, Side::Draft { at, .. } if at == *d)));
        let image = rendered.and_then(|d| merged.maps.iter().find(|m| m.doc == *d)).map(|m| m.runs.as_slice());
        let sent = windows::kept_places(&shot.runs, image);
        if sent.len() > merged.cap {
            return Err(Refusal::OverCap { runs: sent.len(), cap: merged.cap });
        }
        let term = self.signing_term()?;
        let supersede = self.daughters(merged)?;
        // Every copied run's values, read at the head through the side that
        // holds it, each holder's runs in as few reads as the budgets allow.
        let copied: Vec<(Option<usize>, &Run)> = sent
            .iter()
            .filter(|(placed, _)| matches!(placed.family, Family::Own | Family::DraftNative))
            .map(|(placed, _)| (placed.side.map(|s| s.0 as usize), &placed.through))
            .collect();
        let mut values = values_of(&self.reader, doc, &merged.maps, &copied)?.into_iter();
        let mut runs = Vec::with_capacity(sent.len());
        let mut pieces = Vec::with_capacity(sent.len());
        let mut places = Vec::with_capacity(sent.len());
        for (placed, place) in &sent {
            places.push(*place);
            let run = &placed.run;
            let i_start = run
                .address_at(0)
                .ok_or_else(|| own_fault_face("a run of M names no address", format!("{run:?}")))?;
            runs.push(publication::Run::new(run.origin.clone(), run.i_start, run.width));
            match placed.family {
                Family::Window => {
                    if run.width == 0 {
                        return Err(own_fault_face("a window of width 0", format!("{run:?}")));
                    }
                    pieces.push(Piece::Window { start: i_start, width: run.width });
                }
                Family::Own | Family::DraftNative => {
                    let items = values.next().ok_or_else(|| own_fault_face("a copied run's values were not read", format!("{run:?}")))?;
                    pieces.push(Piece::Values(items));
                }
            }
        }
        // THE REQUEST BUILDER, with the daughters alone: the merge's delta
        // from a publication is no other deposit and no `also_places`.
        let n = runs.len();
        let request = publication::Request {
            doc: Some(doc.clone()),
            mint: None,
            claim: false,
            base: Some((head.clone(), merged.head_extent)),
            draft: draft.cloned(),
            also: Vec::new(),
            // A merge shot is no publication of the draft it names: M holds
            // the other sides' words, so the draft's recorded base stands
            // (skep #944) wherever a draft rides.
            keep_base: draft.is_some(),
            runs,
            places,
            also_places: Vec::new(),
            stray_records: vec![0; n],
            pieces,
            entries: Vec::new(),
            retract: Vec::new(),
            originals: Vec::new(),
            read_with: Vec::new(),
            supersede,
            unspellable: Vec::new(),
            id: Stem::of(&shot.text(merged)).id("publish"),
            count: publication::Count::default(),
            price: publication::Price::default(),
            as_of: self.reader.as_of(),
        };
        let body = request.body();
        if body.as_bytes().len() > SHOT_BODY_BUDGET {
            return Err(own_fault_face("the shot's body cannot be composed", format!("the merged list's values pass what one shot's body may carry ({SHOT_BODY_BUDGET} bytes)")));
        }
        // The records read again just before the send: a part a record names
        // since its answer was given is refused again, nothing published.
        windows::recheck(self, merged, shot, draft)?;
        let mut v = self.shoot(&request.frame(self.attest(term, doc, &body)?))?;
        // A claim landed past the head's read: the shot once more, signed,
        // under its own id (the `land` module's doc).
        if let Some(attest) = self.attest_after_claim(term, &v, doc, &body)? {
            v = self.shoot(&request.frame(Some(attest)))?;
        }
        Ok(v)
    }

    /// Sends the shot's frame, answering the board's document.
    ///
    /// A lost acknowledgment is re-asked once under the same id in the same
    /// session (§1.5: the per-session idempotency key), else `resume`.
    ///
    /// # Errors
    ///
    /// The death signal, [`Refusal::SessionEnded`]; a dial fault after the
    /// one re-ask; the frame's other halts.
    fn shoot(&self, frame: &Value) -> Result<Value, Refusal> {
        let answer = match self.board.op(Some(self.merger.token), frame) {
            Err(Halt::Dial(_)) => self.board.op(Some(self.merger.token), frame)?,
            other => other?,
        };
        match answer {
            Answer::Closed => Err(session_ended("publishing the merge", self.reader.on_end())),
            Answer::Document(v) => Ok(v),
        }
    }

    /// Returns the `attest` a shot sent unsigned is sent again with, where a
    /// claim landed past the head's read.
    ///
    /// The shot went out with `sent_with`, the term [`Writer::signing_term`]
    /// read before it; where that was none — a board read as no one's — and
    /// the board answered `v` refusing it `attestation_required`, a claim
    /// landed between the read and the shot's turn, its head written, and
    /// the board refused the shot before its transaction (wire.md
    /// §Credential refusals, a reorder). The head is read again and the
    /// `attest` composed over `body`, the shot's `doc` row `doc`, for the
    /// shot's one re-send under its own id: the refusal left the id
    /// unmemoized (wire.md §Correlation and idempotency). `None` where the
    /// shot went signed, or `v` is another answer: a signed shot refused so
    /// is the shot's own fault arm.
    ///
    /// # Errors
    ///
    /// The second read's: a head that stands and cannot be read; a claimed
    /// board serving no head record, faced as [`head_owed`]; and one serving
    /// none with no claimant named, faced the same, naming the board's token
    /// — the board refused the shot for want of a signature this read finds
    /// no head to make. Then the attest's fault. Nothing is sent past any of
    /// them.
    fn attest_after_claim(
        &self,
        sent_with: Option<BoardTerm>,
        v: &Value,
        doc: &Address,
        body: &EntryBody,
    ) -> Result<Option<Value>, Refusal> {
        if sent_with.is_some() {
            return Ok(None);
        }
        let Some(r) = Rejection::of(v).filter(|r| r.key() == "attestation_required") else {
            return Ok(None);
        };
        let Some(term) = self.signing_term()? else {
            return Err(head_owed(format!(
                "{}: the board refused the shot for want of its signature and serves no head record (`H.1`) to sign it over",
                r.token()
            ))
            .into());
        };
        self.attest(Some(term), doc, body)
    }

    /// Returns the shot's `supersede`: the daughters — every `Member` side, in
    /// side order — with THE SKIP read first, as the board's plan decides it:
    /// `in_claims{y: the daughter, view: active}` at each, one an active claim
    /// of the merger's own already names dropped, so the body signed is the
    /// body the board composes (the `land` module's doc). A draft side and a
    /// fork side name no daughter.
    ///
    /// # Errors
    ///
    /// The `in_claims` read's refusal at a daughter.
    fn daughters(&self, merged: &Merged) -> Result<Vec<Address>, Refusal> {
        let mut out = Vec::new();
        for side in &merged.inputs.sides {
            let Side::Member(daughter) = side else { continue };
            let v =
                self.reader.answered(daughter, &frames::in_claims(&daughter.to_string()), None)?;
            if !own_claim_names(&answers::claims(&v), self.merger.account) {
                out.push(daughter.clone());
            }
        }
        Ok(out)
    }

    /// Returns the claims' read: the active claims whose `new` is the member,
    /// read at each daughter after the shot — the claims the shot deposited
    /// (the `land` module's doc), each homed in the trunk, and any another
    /// writer filed naming the member.
    ///
    /// # Errors
    ///
    /// The `in_claims` read's refusal at a daughter.
    pub(super) fn claims_standing(&self, merged: &Merged, member: &Address) -> Result<Vec<Address>, Refusal> {
        let mut out = Vec::new();
        let member = member.to_string();
        for side in &merged.inputs.sides {
            let Side::Member(daughter) = side else { continue };
            let v =
                self.reader.answered(daughter, &frames::in_claims(&daughter.to_string()), None)?;
            for claim in answers::claims(&v) {
                if claim.active && claim.new == member {
                    if let Some(a) = parse_address(&claim.claim) {
                        out.push(a);
                    }
                }
            }
        }
        Ok(out)
    }
}
