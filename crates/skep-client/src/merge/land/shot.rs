//! The shot: the one `publish` of M from the head (the merge record's §1.5).
//!
//! [`Writer::publish`] composes the frame through the publication's request
//! builder and sends it, signed over the board's head where the board has
//! one, and sends it once more where the twin fence meets it or a claim
//! landed past the head's read; the daughters' skip is read before signing
//! and their claims after the shot (the `land` module's doc). A shot naming
//! no daughter whose list the head already holds is refused before its
//! values are read, so no version identical to the head is minted
//! ([`Refusal::HeadHolds`]).

use serde_json::Value;
use skep_address::Address;
use skep_identity::{BoardTerm, EntryBody};

use crate::address::parse_address;
use crate::board::{acked_addr, acked_at, answers, frames, Rejection};
use crate::halt::{Halt, Refused};
use crate::merge::compose::Run;
use crate::merge::reads::{
    comps, first_difference, is_trunk_member, runs_of, stretches, values_of, Family, Merged,
    Refusal, Side,
};
use crate::merge::windows::{self, AnsweredRun, ShotParts};
use crate::publication::request::{cut_against, Cut};
use crate::publication::{self, own_claim_names, owned_by, Piece, Stretch, SupersedeCause, MAX_WIRE_LIST, WHOLE_FORM_EVERY};

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
    /// ([`windows::recheck`]), sent through [`Writer::answered_write`], so a
    /// lost acknowledgment is asked again once under the same id, and the
    /// frame sent once more, signed, under the same id where it went
    /// unsigned and a claim landed past the head's read
    /// ([`Writer::attest_after_claim`]). Where the skip leaves no daughter
    /// and the head holds the whole list (`head_holds`), nothing is sent.
    ///
    /// **Sent by its places against the head.** The list is cut against the
    /// head's image, which the composition read ([`Writer::form_of`]): the
    /// frame carries the stretches of the head the merge replaces and the
    /// runs that replace them, and no run the head holds where the merged
    /// list does — so the values read, the body signed and the frame sent
    /// follow the change, and a file of any length lands where its change
    /// fits one write. The whole list is sent, with the head as its base,
    /// where the head stands one short of the chain's bound
    /// ([`WHOLE_FORM_EVERY`]).
    ///
    /// # Errors
    ///
    /// The head's `doc_metadata` read's refusal, where its depth is read;
    /// [`Refusal::OverCap`] over the runs the frame would carry — the
    /// change's, or the whole list's where the whole is sent — the list the
    /// kept places cut, nothing sent;
    /// [`Refusal::BodyOverBudget`] where the copied positions alone pass
    /// [`SHOT_BODY_BUDGET`] at four bytes each, nothing read; then the head's
    /// refusal and halts ([`Writer::signing_term`]), read before the values,
    /// nothing sent, and read again after a claim, nothing sent past it; the
    /// skip reads' refusals at the daughters; [`Refusal::HeadHolds`] where no
    /// daughter is left and the head holds the list, nothing sent;
    /// [`Refusal::WindowPartsOwed`] naming a part a record names since its
    /// answer was given; the value reads' refusals;
    /// [`Refusal::BodyOverBudget`] where the composed body passes the budget,
    /// nothing sent; the attest's fault; a run with no address and a window
    /// of width 0, as the library's own faults; the death signal,
    /// [`Refusal::SessionEnded`]; a dial fault after the one re-ask.
    fn send_shot(
        &self,
        merged: &Merged,
        draft: Option<&Address>,
        shot: &ShotParts,
    ) -> Result<Value, Refusal> {
        let doc = &merged.inputs.doc;
        let head = &merged.inputs.head;
        // The list as sent: cut at the kept places of the draft side the shot
        // renders, its image the one the composition read — at the head
        // inside its fences, or as of the draft's named position.
        let rendered = draft.filter(|d| merged.inputs.sides.iter().any(|s| matches!(s, Side::Draft { at, .. } if at == *d)));
        let image = rendered.and_then(|d| merged.maps.iter().find(|m| m.doc == *d)).map(|m| m.runs.as_slice());
        let sent = windows::kept_places(&shot.runs, image);
        // The form: the change against the head, or the whole list. What
        // one write sends is held to the cap, never the merged list's count.
        let form = self.form_of(merged, &sent)?;
        let (sent, stretches) = match form {
            Some(cut) => (cut.of(&sent), cut.stretches),
            None => (sent, Vec::new()),
        };
        if sent.len() > merged.cap {
            return Err(Refusal::OverCap { runs: sent.len(), cap: merged.cap });
        }
        // Every copied word costs the body its four-byte length at least,
        // after the eight-byte count of positions: a list past the budget so
        // counted is refused before any value is read.
        let copied =
            |placed: &AnsweredRun| matches!(placed.family, Family::Own | Family::DraftNative);
        let least = sent
            .iter()
            .filter(|(placed, _)| copied(placed))
            .fold(8u64, |least, (placed, _)| {
                least.saturating_add(placed.run.width.saturating_mul(4))
            });
        if least > SHOT_BODY_BUDGET as u64 {
            return Err(Refusal::BodyOverBudget {
                bytes: least,
                budget: SHOT_BODY_BUDGET,
            });
        }
        let term = self.signing_term()?;
        let supersede = self.daughters(merged)?;
        // A shot that supersedes nothing and places the head's own list
        // would mint a version identical to the head.
        if supersede.is_empty() && head_holds(merged, &shot.runs)? {
            return Err(Refusal::HeadHolds { head: head.clone() });
        }
        // Every copied run's values, read at the head through the side that
        // holds it, each holder's runs in as few reads as the budgets allow.
        let through: Vec<(Option<usize>, &Run)> = sent
            .iter()
            .filter(|(placed, _)| copied(placed))
            .map(|(placed, _)| (placed.side.map(|s| s.0 as usize), &placed.through))
            .collect();
        let mut values = values_of(&self.reader, doc, &merged.maps, &through)?.into_iter();
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
            stretches,
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
            let bytes = body.as_bytes().len() as u64;
            return Err(Refusal::BodyOverBudget {
                bytes,
                budget: SHOT_BODY_BUDGET,
            });
        }
        // The records read again just before the send: a part a record names
        // since its answer was given is refused again, nothing published.
        windows::recheck(self, merged, shot, draft)?;
        let frame = request.frame(self.attest(term, doc, &body)?);
        let mut v = self.answered_write(&frame, "publishing the merge")?;
        // A claim landed past the head's read: the shot once more, signed,
        // under its own id (the `land` module's doc).
        if let Some(attest) = self.attest_after_claim(term, &v, doc, &body)? {
            v = self.answered_write(&request.frame(Some(attest)), "publishing the merge")?;
        }
        Ok(v)
    }

    /// Returns the cut of `sent`, the list a shot would send whole, against
    /// the head — the stretches of the head the merge replaces and which
    /// runs replace them — or `None` where the shot sends the whole list.
    ///
    /// The head's image is the composition's own, read at the head's extent
    /// ([`Merged::head_extent`]), so the cut reads nothing of the board
    /// (`cut_against`). A run rides the shot, whatever the head holds, where
    /// the commit re-mints it — a draft side's words — and where it carries
    /// a kept place: its index is the place's. The whole list is sent where
    /// the head stands one short of the chain's bound, its depth read off
    /// its `doc_metadata` — so the member minted ends the chain, signed over
    /// its whole arrangement — where the cut replaces the head whole, and
    /// where it names more stretches than one list carries.
    ///
    /// # Errors
    ///
    /// The head's `doc_metadata` read's refusal.
    fn form_of(&self, merged: &Merged, sent: &[(AnsweredRun, Option<u64>)]) -> Result<Option<Cut>, Refusal> {
        let Some(head) = merged.maps.first() else { return Ok(None) };
        let depth = self.reader.metadata(&merged.inputs.head, None)?.chain_depth.unwrap_or(0);
        if depth.saturating_add(1) >= WHOLE_FORM_EVERY {
            return Ok(None);
        }
        let runs: Vec<publication::Run> = sent
            .iter()
            .map(|(placed, _)| publication::Run::new(placed.run.origin.clone(), placed.run.i_start, placed.run.width))
            .collect();
        let rides = |index: usize| sent[index].0.family == Family::DraftNative || sent[index].1.is_some();
        let cut = cut_against(&head.runs, merged.head_extent, &runs, &rides);
        let whole = cut.stretches == [Stretch { start: 1, width: merged.head_extent, count: runs.len() }];
        Ok((!whole && cut.stretches.len() <= MAX_WIRE_LIST).then_some(cut))
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
    /// A daughter an active claim of the merger's own names superseded by a
    /// trunk member past the head the merge composed on is kept: that claim
    /// rode a shot the trunk took after the composition read its head, so
    /// the trunk moved, and the board refuses a list naming the daughter
    /// whole, `head_moved`, ahead of any skip (wire.md §The publish shot and
    /// head-float, the deposits). The shot then lands on the trunk or not at
    /// all, never as a permanent daughter holding another copy of a merge the
    /// trunk already took (ruling (ii) of the supersede race; skep #806).
    ///
    /// # Errors
    ///
    /// The `in_claims` read's refusal at a daughter.
    fn daughters(&self, merged: &Merged) -> Result<Vec<Address>, Refusal> {
        let (doc, head) = (&merged.inputs.doc, &merged.inputs.head);
        let account = self.merger.account;
        // The head is a trunk member of `doc` (`check_shape`), so a claim's
        // `new` on the trunk compares with it by its version alone.
        let past_the_head = |claim: &answers::Claim| {
            claim.active
                && owned_by(&claim.home, account)
                && parse_address(&claim.new)
                    .is_some_and(|new| is_trunk_member(doc, &new) && comps(&new) > comps(head))
        };
        let mut out = Vec::new();
        for side in &merged.inputs.sides {
            let Side::Member(daughter) = side else { continue };
            let v =
                self.reader.answered(daughter, &frames::in_claims(&daughter.to_string()), None)?;
            let claims = answers::claims(&v);
            if !own_claim_names(&claims, account) || claims.iter().any(past_the_head) {
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

/// Returns whether the head, as the composition imaged it, holds `runs`.
///
/// It does where no run re-mints a draft side's words and the head's image
/// is the list itself, run for run by identity, nothing beside it: a shot of
/// `runs` from the head would mint the head's own list again.
///
/// # Errors
///
/// A run of the head's image that is no content I-address, the board's
/// fault, faced.
fn head_holds(merged: &Merged, runs: &[AnsweredRun]) -> Result<bool, Refusal> {
    let Some(head) = merged.maps.first() else {
        return Ok(false);
    };
    if runs
        .iter()
        .any(|placed| placed.family == Family::DraftNative)
    {
        return Ok(false);
    }
    let held = runs_of(&head.runs)?;
    let placed: Vec<(Run, Family)> = runs
        .iter()
        .map(|placed| (placed.run.clone(), Family::Own))
        .collect();
    Ok(first_difference(&placed, &held, &merged.inputs.doc).is_none())
}
