//! The landing's walk, and the member found standing before a shot.
//!
//! [`walk`] runs the landing's steps, each read first, for
//! [`land`](super::land) and [`resume`](super::resume) alike;
//! [`Writer::standing_member`] reads for a member that already holds the
//! answered list before a shot is sent (P4, P14). The order is the `land`
//! module's doc.

use skep_address::Address;

use crate::board::Board;
use crate::merge::compose::Run;
use crate::merge::reads::{
    daughter_of, first_difference, is_trunk_member, next_trunk_member, position_of, runs_of,
    Family, Merged, OnEnd, Refusal,
};
use crate::merge::record::RecordLanding;
use crate::merge::windows::{self, ShotParts};

use super::faults::own_fault_face;
use super::landing::{Landed, Landing};
use super::writer::{Stem, Writer};

/// Runs the landing's steps, each read first.
///
/// They are the shot, the claim's read and the record, or the draft landing
/// and the record. `shoot` is whether a landing not found standing is made.
/// A fresh draft landing looks for this composition's landing standing in a
/// draft the merger's records of the key name ([`Writer::found_standing`]),
/// then for a landing begun and never recorded, before its journal's check
/// and its stage, with `shoot` on or off ([`Writer::landing_begun`]), then
/// reads every document M windows ([`Writer::windows_readable`]) before the
/// stage. A journal named is checked once, after the read-first steps and
/// before the landing's first write ([`Writer::check_journal`]); a landing
/// found standing writes nothing before its record and checks none.
///
/// # Errors
///
/// As [`land`]'s, or as [`resume`]'s with `shoot` off.
///
/// [`land`]: super::land
/// [`resume`]: super::resume
pub(super) fn walk(
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
    let writer = Writer::new(board, merger, OnEnd::Resume);
    let check_journal = || writer.check_journal(landing.journal(), "the merge cannot land");
    match &landing {
        Landing::Shot { draft, answers, .. } => {
            let mut shot = windows::step(&writer, merged, answers, draft.as_ref())?;
            if shot.runs.len() > cap {
                return Err(Refusal::OverCap { runs: shot.runs.len(), cap });
            }
            let (member, position) = match writer.standing_member(merged, &shot)? {
                Standing::Trunk(member, at) => (member, at),
                Standing::Daughter(address, position) => {
                    return Ok(Some(Landed::AsDaughter { address, position }))
                }
                Standing::Absent => {
                    if !shoot {
                        return Ok(None);
                    }
                    check_journal()?;
                    let (address, position) = writer.publish(merged, draft.as_ref(), &mut shot)?;
                    if !is_trunk_member(&merged.inputs.doc, &address) {
                        return Ok(Some(Landed::AsDaughter { address, position }));
                    }
                    (address, position)
                }
            };
            let claims = writer.claims_standing(merged, &member)?;
            let landed = RecordLanding::Member { member: member.clone(), position };
            let newest = writer.newest_record(merged)?;
            let record = match newest.naming(&landed).or_else(|| newest.recording(&member)) {
                Some(link) => link.clone(),
                None => {
                    let stem = Stem::of(&shot.text(merged));
                    let journal = landing.journal();
                    writer.write_landing_record(merged, landed, &claims, &newest, &stem, journal, &shot.kept())?
                }
            };
            Ok(Some(Landed::Member {
                address: member,
                position,
                claims,
                record,
                retries: merged.inputs.options.retries,
                answers: shot.given.clone(),
            }))
        }
        Landing::Draft { into, .. } => {
            // The merger's newest record for the key, read from the board
            // before any write: the record a named draft's ids follow, and
            // beside it the drafts its records of the key name, a fresh
            // landing's answer where one still holds this composition's
            // landing. The stage and the one write write no record, so it is
            // the record step's read too.
            let newest = writer.newest_record(merged)?;
            // The draft, the position the write is typed against, the text the
            // landing's per-session ids are spelled over (the `land` module's
            // doc), and whether this call staged the draft: for a draft named,
            // the merge's one position and the record the landing follows, so a
            // landing composed after a take-back, into another draft, or into
            // its draft again after a take-back recorded since, is a write of
            // its own; for a fresh draft, the stage's own draft and position.
            let (into, as_of, text, staged) = match into {
                Some(into) => {
                    if shoot {
                        check_journal()?;
                    }
                    let text = format!("{}:{into}@{}", merged.key.text(), merged.as_of);
                    let text = match newest.follows(into) {
                        Some(link) => format!("{text}~{link}"),
                        None => text,
                    };
                    (into.clone(), merged.as_of, text, false)
                }
                None => {
                    // Each draft the records name, judged by its mark and the
                    // list that landing placed: a draft whose rows' walk needs
                    // a past state the board reclaimed is answered by its
                    // record, never landed into again.
                    if let Some(standing) = writer.found_standing(merged, &newest)? {
                        return Ok(Some(standing));
                    }
                    // A landing of the merge begun in a draft of the
                    // merger's and never recorded is named, nothing staged
                    // or written, at a landing and a resume alike: never a
                    // second landing, and never finished unasked (PUB-8.32).
                    if let Some((draft, position)) = writer.landing_begun(merged, &newest)? {
                        return Err(Refusal::LandingBegun { draft, position });
                    }
                    if !shoot {
                        return Ok(None);
                    }
                    // Every window's origin read before the stage, so the
                    // one write's source gate refuses nothing past it.
                    writer.windows_readable(merged)?;
                    check_journal()?;
                    let (fresh, at) = writer.stage(merged, &newest)?;
                    let text = format!("{}:{fresh}@{at}", merged.key.text());
                    (fresh, at, text, true)
                }
            };
            let stem = Stem::of(&text);
            let Some((position, head_moved)) =
                writer.land_into_draft(merged, &into, as_of, &stem, &newest, shoot)?
            else {
                return Ok(None);
            };
            let landed = RecordLanding::Draft { draft: into.clone(), position };
            let record = match newest.naming(&landed) {
                Some(link) => link.clone(),
                None => {
                    let journal = landing.journal();
                    writer.write_landing_record(merged, landed, &[], &newest, &stem, journal, &[])?
                }
            };
            Ok(Some(Landed::Draft { into, position, record, head_moved, staged }))
        }
    }
}

/// Whether a member already holds the merge.
pub(super) enum Standing {
    /// No member of the head's reach holds M.
    Absent,
    /// The trunk's next member holds M, minted at this position.
    ///
    /// Where the feed holds no row of the mint, the position is the reads'
    /// highest `as_of`.
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
    ///
    /// Where the feed holds no row of the mint, the position is the reads'
    /// highest `as_of`.
    Merged(u64),
}

impl Writer<'_> {
    /// Finds the member that already holds the answered list, the shot's
    /// read-first.
    ///
    /// It reads the trunk's next member, then — where that is another's —
    /// the head's daughters in order until the first absent.
    ///
    /// # Errors
    ///
    /// A member's reads' refusals, as `holds` answers them; a head or a
    /// daughter whose address cannot be spelled, as the library's own fault.
    pub(super) fn standing_member(&self, merged: &Merged, shot: &ShotParts) -> Result<Standing, Refusal> {
        let head = &merged.inputs.head;
        let next = next_trunk_member(head).ok_or_else(|| {
            own_fault_face(
                "the head's next member cannot be spelled",
                format!("{head} has no component to count on"),
            )
        })?;
        match self.holds(merged, shot, &next)? {
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
            match self.holds(merged, shot, &daughter)? {
                Holds::Merged(at) => return Ok(Standing::Daughter(daughter, at)),
                Holds::Nothing => return Ok(Standing::Absent),
                Holds::Other => {}
            }
        }
        Ok(Standing::Absent)
    }

    /// Returns whether `member` holds the answered list over its first
    /// `placed` positions.
    ///
    /// # Errors
    ///
    /// The member's reads' refusals but `withheld`, a `doc_not_registered`
    /// on its metadata and a member too fragmented to image, which answer as
    /// what it holds; an `image` run that is no content I-address; the feed
    /// walk's halts.
    fn holds(&self, merged: &Merged, shot: &ShotParts, member: &Address) -> Result<Holds, Refusal> {
        let meta = match self.reader.metadata(member, None) {
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
        let expected: Vec<(Run, Family)> =
            shot.runs.iter().map(|a| (a.run.clone(), a.family)).collect();
        if first_difference(&expected, &actual, &merged.inputs.doc).is_some() {
            return Ok(Holds::Other);
        }
        let at = position_of(&self.reader, member)?.unwrap_or_else(|| self.reader.as_of());
        Ok(Holds::Merged(at))
    }
}
