//! The merge's LANDING — the merge record's §1.5: the one `publish` of the
//! merged list from the head with its signed body, then the claim's read and
//! the record in the journal with its public link, each step idempotent by
//! reading first (P4, P14); the draft landing, the core's edit script applied
//! in place (decision 16); and [`resume`], the residue walk that completes
//! what a lost acknowledgment left, writing nothing twice.
//!
//! THE ORDER, and what each step reads first. The cap: `counts.m` against
//! the shot's run cap before any frame (decision 13; P13). The shot: the
//! trunk's next member, then the head's daughters, read for a member whose
//! first `placed` positions already hold M — else one `publish` from the
//! head, its body every copied run's bytes re-read through the side that
//! holds them and every window signed by address, re-asked ONCE under the
//! same per-session `id` where the acknowledgment was lost. A daughter in
//! the acknowledgment is reported at once ([`Landed::AsDaughter`]): the head
//! moved under the merge, the library never re-runs, the embedder does with
//! `retries` one higher (decision 17). The record: the links of the kind to
//! the member, read for a record of this key and this landing — else the
//! journal found or minted, the atom appended at its end, the link from the
//! merger's doc 1 to the member and every alternative side under the kind.
//!
//! THE CLAIM, as this wire admits it. The record's step (i) files
//! `assert_sup{home: the merger's doc 1, old: the daughter, new: the member}`
//! over two VERSION MEMBERS. The wire's `assert_sup` takes resident LINKS
//! alone as its endpoints — wire.md §Links (writes): "a link named by
//! ADDRESS", `endpoint_not_resident` for "an address no link occupies" — and
//! a version member is no link, so the claim the record spells is refused by
//! the daemon as built, ahead of any transaction. This build therefore makes
//! the claim's READ, `in_claims{y: the daughter, view: active}`, recording a
//! claim another writer filed, and sends no `assert_sup`. What states the
//! supersession on this wire is the record's own PUBLIC link from the
//! merger's doc 1 to the member AND the daughter under the merge kind, which
//! a reader at the daughter finds by `find_links_ftt{ty, to}`. A claim over
//! version members is a wire ruling to come, not a frame this library sends.

use std::num::NonZeroU64;

use serde_json::{json, Value};
use skep_address::Address;
use skep_identity::{
    entry_body_make_link, entry_frame, unit_span, DocTerm, EntryBody, EntrySlot, LinkSlots,
    PublishBody, PublishRefusal, ShotBase,
};

use crate::address::{doc_1_of, parse_address};
use crate::board::{acked_addr, acked_at, answers, frames, Answer, Board, Rejection, Token};
use crate::halt::Halt;
use crate::sign::{sig_hex, Signer};

use super::compose::{script, InPlaceOp, Run};
use super::journal;
use super::reads::{
    daughter_of, first_difference, is_trunk_member, next_trunk_member, position_of, runs_of,
    values_for, Family, Merged, Reader, Refusal, Side,
};
use super::record::{read_record, RecordLanding};

/// The most bytes a shot's signed body may run to — the frame routes'
/// request-body cap, 8 MiB (wire.md §HTTP status codes, `413
/// payload_too_large`), the parity the daemon holds a shot's body to. The
/// body is composed under it ([`PublishBody::within`]) and a body past it
/// is refused by name, never built.
pub const SHOT_BODY_BUDGET: usize = 8 * 1024 * 1024;

/// THE MERGER — a signed session's facts and its hand (the merge record's
/// §7, "What it reads through"): the session's token, the account it acts
/// as, and the signer it was opened with. Taken as facts, never as the
/// ceremony's own session type, which this module does not name: the
/// embedder opens the session with a content scope through the handshake
/// and lends its token, its account and its signer here.
#[derive(Clone, Copy)]
pub struct Merger<'a> {
    /// The signed session's token — what every write presents.
    pub token: &'a Token,
    /// The account the session acts as, `principal_prefix(principal)` — the
    /// record link's home is its doc 1.
    pub account: &'a str,
    /// The signer the session was opened with — the shot's and the record
    /// link's hand.
    pub signer: &'a dyn Signer,
}

/// How a merge lands (the merge record's §7, `Landing`): the SHOT from the
/// head, or the DRAFT landing into a staging draft.
pub enum Landing<'a> {
    /// One `publish` from the head with M as the runs, then the claim's read
    /// and the record (§1.5).
    Shot {
        /// The merger's signed session and hand.
        merger: Merger<'a>,
        /// The staging draft whose fresh text the shot re-inserts, where the
        /// merger typed any; a draft side's is named without asking.
        draft: Option<Address>,
        /// The merge journal the record goes to; the account's default
        /// private one where `None` (decision 7).
        journal: Option<Address>,
    },
    /// The core's edit script applied into `into` by identity, then the
    /// record with `landed` the draft — no claim: the person's own shot is
    /// the claim's moment (decision 16).
    Draft {
        /// The merger's signed session and hand.
        merger: Merger<'a>,
        /// The staging draft M is landed into.
        into: Address,
        /// The merge journal, or the account's default.
        journal: Option<Address>,
    },
}

/// What a landing answered (the merge record's §7, `Landed`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Landed {
    /// The merge landed on the trunk: the member, the shot's position, the
    /// claims standing at the daughters, the record's public link, and the
    /// retries the record carries.
    Member {
        /// The merged member, `D.h+1`.
        address: Address,
        /// The shot's commit position.
        position: u64,
        /// The supersession claims standing at the daughters, as read.
        claims: Vec<Address>,
        /// The record's public link, homed in the merger's doc 1.
        record: Address,
        /// `Options::retries`, as written into the record.
        retries: u32,
    },
    /// The head moved under the merge: the shot landed as the head's
    /// daughter. Reported, never a success; the embedder re-runs with the
    /// new head and `retries` one higher (decision 17).
    AsDaughter {
        /// The daughter minted.
        address: Address,
        /// The shot's commit position.
        position: u64,
    },
    /// M landed into the staging draft: the draft, how many in-place edits
    /// it took, and the record's public link.
    Draft {
        /// The draft.
        into: Address,
        /// The `delete` and `reinstate` ops applied — 0 where the draft
        /// already held M.
        ops: usize,
        /// The record's public link.
        record: Address,
    },
}

impl<'a> Landing<'a> {
    fn merger(&self) -> Merger<'a> {
        match self {
            Landing::Shot { merger, .. } | Landing::Draft { merger, .. } => *merger,
        }
    }

    fn journal(&self) -> Option<&Address> {
        match self {
            Landing::Shot { journal, .. } | Landing::Draft { journal, .. } => journal.as_ref(),
        }
    }
}

/// Lands a composed merge (the merge record's §7, `land`): the shot or the
/// draft landing, then the claim's read and the record, each step read
/// first, so a second call over the same `merged` writes nothing twice.
///
/// # Errors
///
/// In this order: [`Refusal::OverCap`] before any frame; the reads'
/// refusals; the shot's — [`Refusal::WindowWithheld`],
/// [`Refusal::NeedsSignedSession`], [`Refusal::NoSuchDocument`], the
/// library's own faults as [`Refusal::Halt`]; a lost acknowledgment as the
/// dialer's halt after one re-ask, for [`resume`] to complete.
pub fn land(board: &Board, merged: &Merged, landing: Landing<'_>) -> Result<Landed, Refusal> {
    walk(board, merged, landing, true)
        .map(|landed| landed.expect("a landing that shoots answers a landing"))
}

/// The residue walk (the merge record's §1.5, P14): where the shot landed
/// and its acknowledgment was lost, finds the member whose first `placed`
/// positions equal M — the trunk's next member, else a daughter of the head
/// — or the draft already holding M, and completes the claim's read and the
/// record, writing nothing twice; `None` where nothing landed, with nothing
/// written.
///
/// # Errors
///
/// As [`land`]'s but the shot's.
pub fn resume(
    board: &Board,
    merged: &Merged,
    landing: Landing<'_>,
) -> Result<Option<Landed>, Refusal> {
    walk(board, merged, landing, false)
}

/// The three steps, each read first; `shoot` whether a landing not found
/// standing is made.
fn walk(
    board: &Board,
    merged: &Merged,
    landing: Landing<'_>,
    shoot: bool,
) -> Result<Option<Landed>, Refusal> {
    let (m, cap) = (merged.composed.counts.m, merged.cap);
    if m > cap {
        return Err(Refusal::OverCap { runs: m, cap });
    }
    let merger = landing.merger();
    let writer = Writer { board, merger, reader: Reader::new(board, Some(merger.token)) };
    match &landing {
        Landing::Shot { draft, .. } => {
            let (member, position) = match writer.standing_member(merged)? {
                Standing::Trunk(member, at) => (member, at),
                Standing::Daughter(address, position) => {
                    return Ok(Some(Landed::AsDaughter { address, position }))
                }
                Standing::Absent => {
                    if !shoot {
                        return Ok(None);
                    }
                    let (address, position) = writer.publish(merged, draft.as_ref())?;
                    if !is_trunk_member(&merged.inputs.doc, &address) {
                        return Ok(Some(Landed::AsDaughter { address, position }));
                    }
                    (address, position)
                }
            };
            let claims = writer.claims_standing(merged, &member)?;
            let landed = RecordLanding::Member { member: member.clone(), position };
            let record = match writer.record_standing(merged, &landed)? {
                Some(link) => link,
                None => writer.write_record(merged, landed, &claims, landing.journal())?,
            };
            Ok(Some(Landed::Member {
                address: member,
                position,
                claims,
                record,
                retries: merged.inputs.options.retries,
            }))
        }
        Landing::Draft { into, .. } => {
            let Some((ops, position)) = writer.land_into_draft(merged, into, shoot)? else {
                return Ok(None);
            };
            let landed = RecordLanding::Draft { draft: into.clone(), position };
            let record = match writer.record_standing(merged, &landed)? {
                Some(link) => link,
                None => writer.write_record(merged, landed, &[], landing.journal())?,
            };
            Ok(Some(Landed::Draft { into: into.clone(), ops, record }))
        }
    }
}

/// Whether a member already holds the merge.
enum Standing {
    /// No member of the head's reach holds M.
    Absent,
    /// The trunk's next member holds M, minted at this position.
    Trunk(Address, u64),
    /// A daughter of the head holds M: the shot landed under a moved head.
    Daughter(Address, u64),
}

/// What one member of the chain holds against M.
enum Holds {
    /// Not registered.
    Nothing,
    /// Another arrangement, or one this reader cannot read.
    Other,
    /// M over its first `placed` positions, minted at this position.
    Merged(u64),
}

/// The landing's writer: the merger and a reader under its token.
struct Writer<'a> {
    board: &'a Board,
    merger: Merger<'a>,
    reader: Reader<'a>,
}

impl Writer<'_> {
    /// The shot's read-first: the trunk's next member, then — where that is
    /// another's — the head's daughters in order until the first absent.
    fn standing_member(&self, merged: &Merged) -> Result<Standing, Refusal> {
        let head = &merged.inputs.head;
        let next = next_trunk_member(head).ok_or_else(|| {
            own_fault_face(
                "the head's next member cannot be spelled",
                format!("{head} has no component to count on"),
            )
        })?;
        match self.holds(merged, &next)? {
            Holds::Merged(at) => return Ok(Standing::Trunk(next, at)),
            Holds::Nothing => return Ok(Standing::Absent),
            Holds::Other => {}
        }
        for k in 1u64.. {
            let daughter = daughter_of(head, k).ok_or_else(|| {
                own_fault_face(
                    "a daughter's address cannot be spelled",
                    format!("{head} extended by {k}"),
                )
            })?;
            match self.holds(merged, &daughter)? {
                Holds::Merged(at) => return Ok(Standing::Daughter(daughter, at)),
                Holds::Nothing => return Ok(Standing::Absent),
                Holds::Other => {}
            }
        }
        Ok(Standing::Absent)
    }

    /// Whether `member` holds M over its first `placed` positions.
    fn holds(&self, merged: &Merged, member: &Address) -> Result<Holds, Refusal> {
        let meta = match self.reader.metadata(member) {
            Ok(m) => m,
            Err(Refusal::NoSuchDocument(_)) => return Ok(Holds::Nothing),
            Err(Refusal::Unreadable(_)) => return Ok(Holds::Other),
            Err(e) => return Err(e),
        };
        let Some(placed) = meta.placed else { return Ok(Holds::Other) };
        let image = match self.reader.image(member, None, 1, placed) {
            Ok(runs) => runs,
            Err(Refusal::Unreadable(_)) | Err(Refusal::TooFragmented { .. }) => {
                return Ok(Holds::Other)
            }
            Err(e) => return Err(e),
        };
        let actual = runs_of(&image)?;
        let expected: Vec<(Run, Family)> = merged
            .composed
            .runs
            .iter()
            .map(|p| p.run.clone())
            .zip(merged.families.iter().copied())
            .collect();
        if first_difference(&expected, &actual, &merged.inputs.doc).is_some() {
            return Ok(Holds::Other);
        }
        let at = position_of(self.board, Some(self.merger.token), member)?
            .unwrap_or_else(|| self.reader.as_of());
        Ok(Holds::Merged(at))
    }

    /// THE SHOT: the body through [`PublishBody`] — every copied run's values
    /// re-read through the side that holds them, every window by address,
    /// the base group the head and its extent as read — the frame with its
    /// `attest` and its id, one re-ask under the same id on a lost
    /// acknowledgment; the member minted and the ack's position.
    fn publish(&self, merged: &Merged, draft: Option<&Address>) -> Result<(Address, u64), Refusal> {
        let doc = &merged.inputs.doc;
        let head = &merged.inputs.head;
        let draft_side = merged.inputs.sides.iter().find_map(|s| match s {
            Side::Draft { at, .. } => Some(at.clone()),
            _ => None,
        });
        let fresh = merged.families.contains(&Family::DraftNative);
        let draft = draft.cloned().or(if fresh { draft_side } else { None });
        let past_budget = |e: PublishRefusal| -> Refusal {
            own_fault_face("the shot's body cannot be composed", format!("{e}: the merged list's values pass what one shot's body may carry ({SHOT_BODY_BUDGET} bytes)"))
        };
        let mut body = PublishBody::within(
            SHOT_BODY_BUDGET,
            Some(ShotBase { member: head, extent: merged.head_extent }),
        )
        .map_err(past_budget)?;
        let mut runs = Vec::with_capacity(merged.composed.runs.len());
        for (placed, family) in merged.composed.runs.iter().zip(&merged.families) {
            let run = &placed.run;
            let i_start = run
                .address_at(0)
                .ok_or_else(|| own_fault_face("a run of M names no address", format!("{run:?}")))?;
            runs.push(frames::shot_run(&run.origin.to_string(), &i_start.to_string(), run.width));
            match family {
                Family::Window => {
                    let width = NonZeroU64::new(run.width)
                        .ok_or_else(|| own_fault_face("a window of width 0", format!("{run:?}")))?;
                    body = body.window(&i_start, width).map_err(past_budget)?;
                }
                Family::Own | Family::DraftNative => {
                    let items = values_for(
                        &self.reader,
                        &merged.maps,
                        placed.side.map(|s| s.0 as usize),
                        run,
                    )?;
                    for item in &items {
                        body = body.push(item).map_err(past_budget)?;
                    }
                }
            }
        }
        let body = body.finish();
        let attest = self.attest(doc, &body)?;
        let id = format!("{}.publish", merged.key.text());
        let draft_text = draft.as_ref().map(ToString::to_string);
        let frame = frames::publish(
            &doc.to_string(),
            Some((&head.to_string(), merged.head_extent)),
            draft_text.as_deref(),
            &runs,
            attest,
            Some(&id),
        );
        // A lost acknowledgment is re-asked ONCE under the same id in the same
        // session (§1.5: the per-session idempotency key), else `resume`.
        let answer = match self.board.op(Some(self.merger.token), &frame) {
            Err(Halt::Dial(_)) => self.board.op(Some(self.merger.token), &frame)?,
            other => other?,
        };
        let v = match answer {
            Answer::Closed => return Err(closed("publishing the merge").into()),
            Answer::Document(v) => v,
        };
        if let (Some(addr), Some(at)) = (acked_addr(&v), acked_at(&v)) {
            let member = parse_address(addr).ok_or_else(|| shape_face("publish", &v))?;
            return Ok((member, at));
        }
        let Some(r) = Rejection::of(&v) else { return Err(shape_face("publish", &v).into()) };
        Err(match r.key() {
            "withheld" => Refusal::WindowWithheld(
                v["site"]["addr"].as_str().and_then(parse_address).unwrap_or_else(|| doc.clone()),
            ),
            "signed_session_required" => Refusal::NeedsSignedSession,
            "doc_not_registered" => Refusal::NoSuchDocument(doc.clone()),
            "base_superseded"
            | "base_not_in_chain"
            | "base_extent_too_large"
            | "bad_run"
            | "dangling_source"
            | "source_not_registered"
            | "not_owner"
            | "too_many_runs"
            | "too_many_values"
            | "private_source_versionless" => own_fault("the shot", &r),
            k if k.starts_with("attestation_") => own_fault("the shot's attest", &r),
            _ => Refusal::Halt(r.refused(&v)),
        })
    }

    /// THE CLAIM'S READ: the active claims at each daughter whose `new` is
    /// the member — what another writer filed; this wire admits none over
    /// version members (the module's doc).
    fn claims_standing(&self, merged: &Merged, member: &Address) -> Result<Vec<Address>, Refusal> {
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

    /// THE RECORD'S READ: a standing record for this key and this landing,
    /// found by the links of the kind to the landed address — its public
    /// link, where one stands.
    fn record_standing(
        &self,
        merged: &Merged,
        landed: &RecordLanding,
    ) -> Result<Option<Address>, Refusal> {
        let target = match landed {
            RecordLanding::Member { member, .. } => member,
            RecordLanding::Draft { draft, .. } => draft,
        };
        let v = self.reader.answered(
            target,
            &frames::find_links_ftt(&merged.inputs.kind.to_string(), &target.to_string()),
            None,
        )?;
        for link in answers::addrs(&v) {
            let Some(link) = parse_address(link) else { continue };
            let Some(record) = read_record(&self.reader, &link)? else { continue };
            let same_landing = match (&record.landed, landed) {
                (
                    Some(RecordLanding::Member { member: a, .. }),
                    RecordLanding::Member { member: b, .. },
                ) => a == b,
                (
                    Some(RecordLanding::Draft { draft: a, .. }),
                    RecordLanding::Draft { draft: b, .. },
                ) => a == b,
                _ => false,
            };
            if same_landing && record.key() == merged.key {
                return Ok(Some(link));
            }
        }
        Ok(None)
    }

    /// THE RECORD: the journal found or minted, the atom appended at its end
    /// as a plain insert, the public link from the merger's doc 1 to the
    /// landed address and every alternative side under the kind, attested;
    /// the link's address.
    fn write_record(
        &self,
        merged: &Merged,
        landed: RecordLanding,
        claims: &[Address],
        journal: Option<&Address>,
    ) -> Result<Address, Refusal> {
        let kind = &merged.inputs.kind;
        let journal = journal::of(self.board, &self.merger, kind, journal.cloned())?;
        let target = match &landed {
            RecordLanding::Member { member, .. } => member.clone(),
            RecordLanding::Draft { draft, .. } => draft.clone(),
        };
        let mut record = merged.record.clone();
        record.landed = Some(landed);
        record.claims = claims.to_vec();
        let text = record.to_value().to_string();
        let ordinal = self.reader.extent(&journal, None)?.checked_add(1).ok_or_else(|| {
            own_fault_face(
                "the journal is full",
                format!("{journal} answered an extent with no ordinal after it"),
            )
        })?;
        let stem = merged.key.text();
        let v = self.answered_write(
            &frames::insert_plain_atom(
                &journal.to_string(),
                ordinal,
                &text,
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
                return Err(match r.key() {
                    "published_target" => own_fault_face("the journal is not a draft", format!("{}: the merge journal {journal} is published, and a record is appended as a plain insert into a draft", r.token())),
                    "not_owner" => own_fault_face("the journal is not this account's", format!("{}: {journal} is owned by another account", r.token())),
                    _ => Refusal::Halt(r.refused(&v)),
                });
            }
        };
        // The link from doc 1: the atom's unit span to the landed address and
        // every alternative side, typed the kind (§4, "Its HOME").
        let home_text = doc_1_of(self.merger.account);
        let home = parse_address(&home_text).ok_or_else(|| {
            own_fault_face("the account's doc 1 cannot be spelled", home_text.clone())
        })?;
        let mut to: Vec<Address> = vec![target];
        for side in &merged.inputs.sides {
            if !to.contains(side.address()) {
                to.push(side.address().clone());
            }
        }
        let from_spans = [unit_span(&atom)];
        let to_spans: Vec<_> = to.iter().map(unit_span).collect();
        let ty_spans = [unit_span(kind)];
        let body = entry_body_make_link(LinkSlots {
            from: EntrySlot(&from_spans),
            to: EntrySlot(&to_spans),
            ty: EntrySlot(&ty_spans),
        });
        let attest = self.attest(&home, &body)?;
        let atom_text = atom.to_string();
        let to_text: Vec<String> = to.iter().map(ToString::to_string).collect();
        let to_refs: Vec<&str> = to_text.iter().map(String::as_str).collect();
        let mut frame = frames::make_link(
            &home_text,
            &[&atom_text],
            &to_refs,
            &kind.to_string(),
            Some(&format!("{stem}.link")),
        );
        if let Some(a) = attest {
            frame["attest"] = a;
        }
        let v = self.answered_write(&frame, "linking the record")?;
        if let Some(link) = acked_addr(&v) {
            return parse_address(link).ok_or_else(|| shape_face("make_link", &v).into());
        }
        let Some(r) = Rejection::of(&v) else { return Err(shape_face("make_link", &v).into()) };
        Err(match r.key() {
            "not_owner" => own_fault_face(
                "this session does not own its doc 1",
                format!("{}: the record's link is homed in the merger's own doc 1", r.token()),
            ),
            "signed_session_required" => Refusal::NeedsSignedSession,
            k if k.starts_with("attestation_") => own_fault("the record link's attest", &r),
            _ => Refusal::Halt(r.refused(&v)),
        })
    }

    /// THE DRAFT LANDING: the draft imaged at the head, the core's script
    /// from its runs to M applied op by op — each `delete` and `reinstate`
    /// one commit — where the draft does not hold M already; the ops applied
    /// and the last commit's position, or `None` where it holds another list
    /// and `shoot` is off.
    fn land_into_draft(
        &self,
        merged: &Merged,
        into: &Address,
        shoot: bool,
    ) -> Result<Option<(usize, u64)>, Refusal> {
        let current = runs_of(&self.reader.imaged(into, None)?.runs)?;
        let target: Vec<Run> = merged.composed.runs.iter().map(|p| p.run.clone()).collect();
        let as_own: Vec<(Run, Family)> = target.iter().cloned().map(|r| (r, Family::Own)).collect();
        if first_difference(&as_own, &current, &merged.inputs.doc).is_none() {
            return Ok(Some((0, self.reader.as_of())));
        }
        if !shoot {
            return Ok(None);
        }
        let ops = script(&current, &target);
        let stem = merged.key.text();
        let doc = into.to_string();
        let mut position = self.reader.as_of();
        for (k, op) in ops.iter().enumerate() {
            let id = format!("{stem}.draft.{}", k + 1);
            let frame = match op {
                InPlaceOp::Delete { p, width } => frames::delete(&doc, *p, *width, Some(&id)),
                InPlaceOp::Reinstate { at, runs } => {
                    let runs: Vec<Value> = runs
                        .iter()
                        .map(|r| {
                            let i_start = r.address_at(0).ok_or_else(|| {
                                own_fault_face(
                                    "a run of the script names no address",
                                    format!("{r:?}"),
                                )
                            })?;
                            Ok(frames::shot_run(
                                &r.origin.to_string(),
                                &i_start.to_string(),
                                r.width,
                            ))
                        })
                        .collect::<Result<_, Refusal>>()?;
                    frames::reinstate(&doc, *at, &runs, Some(&id))
                }
            };
            let v = self.answered_write(&frame, "editing the draft")?;
            match acked_at(&v) {
                Some(at) => position = at,
                None => {
                    let Some(r) = Rejection::of(&v) else {
                        return Err(shape_face("the draft's edit", &v).into());
                    };
                    return Err(match r.key() {
                        "withheld" => Refusal::WindowWithheld(
                            v["site"]["addr"]
                                .as_str()
                                .and_then(parse_address)
                                .unwrap_or_else(|| into.clone()),
                        ),
                        "signed_session_required" => Refusal::NeedsSignedSession,
                        "published_target"
                        | "not_owner"
                        | "bad_run"
                        | "dangling_source"
                        | "source_not_registered"
                        | "not_arranged"
                        | "out_of_bounds" => own_fault("the draft landing", &r),
                        _ => Refusal::Halt(r.refused(&v)),
                    });
                }
            }
        }
        Ok(Some((ops.len(), position)))
    }

    /// One write under the merger's token, its answer the response document.
    fn answered_write(&self, frame: &Value, during: &str) -> Result<Value, Refusal> {
        match self.board.op(Some(self.merger.token), frame)? {
            Answer::Closed => Err(closed(during).into()),
            Answer::Document(v) => Ok(v),
        }
    }

    /// The `attest` member over `body` for a write whose `doc` row is `doc`:
    /// the entry frame under `H.1`'s pair, the merger's account and the
    /// row, signed by the merger's signer (signed ops;
    /// `skep_identity::entry_frame`, the one composer). `None` on a board
    /// with no `H.1`, where the member is dropped unread.
    fn attest(&self, doc: &Address, body: &EntryBody) -> Result<Option<Value>, Refusal> {
        let Some(term) = self.board.board_term()? else { return Ok(None) };
        let account = parse_address(self.merger.account).ok_or_else(|| {
            own_fault_face(
                "the merger's account cannot be spelled",
                self.merger.account.to_string(),
            )
        })?;
        let alg = self.merger.signer.public_key().alg().to_string();
        let bytes = entry_frame(&alg, term, &account, DocTerm::One(doc), body);
        Ok(Some(json!({"alg": alg, "sig": sig_hex(&self.merger.signer.sign(&bytes))})))
    }
}

/// The death signal under the session, faced.
fn closed(during: &str) -> Halt {
    Halt::face(
        format!("the session ended while {during}"),
        "the board answered `Skepd-Session: closed` (wire.md §Sessions)",
        "open a session again and resume: every step of the landing resumes by reading",
    )
}

/// A board refusal of this library's own frame (A-288's own-bug class):
/// nothing a person can act on.
fn own_fault(what: &str, r: &Rejection) -> Refusal {
    own_fault_face(format!("the board refused {what}"), format!("{}: the frame this library composed is wrong in substance — its base, its runs, its home or its attest", r.token()))
}

/// This library's own fault, faced: there is no user-facing act to offer.
fn own_fault_face(state: impl Into<String>, cause: impl Into<String>) -> Refusal {
    Refusal::Halt(Halt::face(state, cause, "this is a fault in this library, not in your keys or your act; nothing further was written"))
}

/// An answer without the shape the write's ack promises.
fn shape_face(op: &str, v: &Value) -> Halt {
    Halt::face(
        format!("`{op}` answered a document this client cannot read"),
        crate::halt::clipped(&v.to_string(), 200).to_string(),
        "this board is not speaking the wire this client expects",
    )
}
