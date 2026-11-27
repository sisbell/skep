//! The landing's walk, and the member found standing before a shot.
//!
//! [`walk`] runs the landing's steps, each read first, for
//! [`land`](super::land) and [`resume`](super::resume) alike;
//! [`Writer::standing_member`] reads for a member that already holds the
//! answered list before a shot is sent (P4, P14). The order is the `land`
//! module's doc.

use skep_address::Address;

use crate::board::answers::Metadata;
use crate::board::Board;
use crate::merge::compose::Run;
use crate::merge::reads::{
    daughter_of, first_difference, first_word_difference, is_trunk_member, next_trunk_member,
    position_of, runs_of, Family, Merged, OnEnd, Refusal,
};
use crate::merge::record::RecordLanding;
use crate::merge::windows::{self, ShotParts};
use crate::publication;
use crate::publication::landed::{clipped, hulls, Positions, Stands};
use crate::publication::request::cut_against;

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
/// and its stage, with `shoot` on or off ([`Writer::check_landing_begun`],
/// whose answer the stage is spelled over), then reads every document M
/// windows ([`Writer::windows_readable`]) before the stage. A journal named
/// is checked once, after the read-first steps and
/// before the landing's first write ([`Writer::check_journal`]); a landing
/// found standing writes nothing before its record and checks none. The
/// record a draft landing made now answers by is the newest record of the
/// key where it names the draft (skep #790; `Newest::naming`); a landing
/// the residue walk finds in the draft named answers by the record of the
/// key standing for it there (`Newest::standing_in`), whatever the newest
/// names, and is recorded only where none stands. A shot and a fresh draft
/// landing read the merger's records of the whole merge, which judge a
/// member found and a landing begun (`Writer::records_of_the_merge`); a
/// landing into a draft named reads the key's alone
/// (`Writer::newest_record`).
///
/// **The cap binds what one write sends.** A draft landing writes the
/// merged list whole, in one frame, so a list past the cap is refused
/// [`Refusal::OverCap`] here, before any read, with its count. A shot sends
/// what the merge changes in the head, so the merged list's count refuses
/// nothing: the shot's own frame is judged where it is composed
/// ([`Writer::publish`]), by the runs it would carry.
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
    if matches!(landing, Landing::Draft { .. }) && m > cap {
        return Err(Refusal::OverCap { runs: m, cap });
    }
    let merger = landing.merger();
    let writer = Writer::new(board, merger, OnEnd::Resume);
    let check_journal = || writer.check_journal(landing.journal(), "the merge cannot land");
    match &landing {
        Landing::Shot { draft, answers, .. } => {
            let mut shot = windows::step(&writer, merged, answers, draft.as_ref())?;
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
            let records = writer.records_of_the_merge(merged)?;
            let record = match records.key.naming(&landed).or_else(|| records.recording(&member)) {
                Some(link) => link.clone(),
                None => {
                    let stem = Stem::of(&shot.text(merged));
                    let journal = landing.journal();
                    let kept = shot.kept();
                    writer.write_landing_record(merged, landed, &claims, &records.key, &stem, journal, &kept)?
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
            // the record step's read too. The draft, the position the write
            // is typed against, the text the landing's per-session ids are
            // spelled over (the `land` module's doc), and whether this call
            // staged the draft: for a draft named, the merge's one position
            // and the record the landing follows, so a landing composed after
            // a take-back, into another draft, or into its draft again after
            // a take-back recorded since, is a write of its own; for a fresh
            // draft, the stage's own draft and position.
            let (newest, into, as_of, text, staged) = match into {
                Some(into) => {
                    let newest = writer.newest_record(merged)?;
                    if shoot {
                        check_journal()?;
                    }
                    let text = format!("{}:{into}@{}", merged.key.text(), merged.as_of);
                    let text = match newest.follows(into) {
                        Some(link) => format!("{text}~{link}"),
                        None => text,
                    };
                    (newest, into.clone(), merged.as_of, text, false)
                }
                None => {
                    let records = writer.records_of_the_merge(merged)?;
                    // Each draft the records name, judged by its mark and the
                    // list that landing placed: a draft whose rows' walk needs
                    // a past state the board reclaimed is answered by its
                    // record, never landed into again.
                    if let Some(standing) = writer.found_standing(merged, &records.key)? {
                        return Ok(Some(standing));
                    }
                    // A landing of the merge begun in a draft of the
                    // merger's and never recorded is named, nothing staged
                    // or written, at a landing and a resume alike: never a
                    // second landing, and never finished unasked (PUB-8.32).
                    let none_begun = writer.check_landing_begun(merged, &records)?;
                    if !shoot {
                        return Ok(None);
                    }
                    // Every window's origin read before the stage, so the
                    // one write's source gate refuses nothing past it.
                    writer.windows_readable(merged)?;
                    check_journal()?;
                    let (fresh, at) = writer.stage(merged, &records.key, &none_begun)?;
                    let text = format!("{}:{fresh}@{at}", merged.key.text());
                    (records.key, fresh, at, text, true)
                }
            };
            let stem = Stem::of(&text);
            let Some((position, head_moved)) =
                writer.land_into_draft(merged, &into, as_of, &stem, &newest, shoot)?
            else {
                return Ok(None);
            };
            let landed = RecordLanding::Draft { draft: into.clone(), position };
            // A write made now is the record's where the newest record names
            // its draft (#790); a landing the walk found is the record's that
            // stands for it in its draft, whatever the newest names.
            let standing = if shoot {
                newest.naming(&landed)
            } else {
                newest.standing_in(&into, position)
            };
            let record = match standing {
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
    /// The position is the member's own `doc_metadata` `at` (`Holds::Merged`).
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
    /// M — over its first `placed` positions where its shot named its whole
    /// arrangement, and as the head with its stretches replaced where its
    /// shot named them — minted at this position.
    ///
    /// It is the member's own `doc_metadata` `at`, the position of the
    /// commit that minted it, which the board serves whatever its feed
    /// still holds. Where the board serves none — a member a build before
    /// the position map minted — it is the position of the member's mint
    /// row on the feed, and where the feed holds no such row, the reads'
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

    /// Returns whether `member` holds the answered list: the landed test at
    /// the merge's resume walk.
    ///
    /// The test is the publication's (`publication/landed.rs`), in its two
    /// cases, and this site's base is the head the merge composed on, its
    /// request's runs the answered list. A member whose shot named its whole
    /// arrangement — its `doc_metadata` serves no stretch — holds the list
    /// over its first `placed` positions: one whose `placed` is not the
    /// list's width holds another list, and its image is not read. A member
    /// whose shot named its stretches holds it by its arrangement
    /// ([`Writer::holds_change`]): the head the merge composed on is its
    /// base, and it is that head with the stretches of this merge replaced,
    /// read where its own stretches or this merge's lie — whatever
    /// stretches its shot spelled, so a landing cut one way is found by a
    /// walk that cuts another. A member whose addresses match the list
    /// holds it where its words at the draft side's re-minted runs are that
    /// side's own (`first_word_difference`): the shot gave those words new
    /// addresses, so a version of other words of the same widths is never
    /// taken for this merge's landing. A member that holds it answers the
    /// position it was minted at (`Holds::Merged`), so a landing found
    /// standing is told apart from one made now by its own position.
    ///
    /// # Errors
    ///
    /// The member's reads' refusals but `withheld`, a `doc_not_registered`
    /// on its metadata and a member too fragmented to image, which answer as
    /// what it holds; an `image` run that is no content I-address; the word
    /// reads' refusals, each as itself; where the board serves no mint
    /// position, the feed walk's halts.
    fn holds(&self, merged: &Merged, shot: &ShotParts, member: &Address) -> Result<Holds, Refusal> {
        let meta = match self.reader.metadata(member, None) {
            Ok(m) => m,
            Err(Refusal::NoSuchDocument(_)) => return Ok(Holds::Nothing),
            Err(Refusal::Unreadable(_)) => return Ok(Holds::Other),
            Err(e) => return Err(e),
        };
        let Some(placed) = meta.placed else { return Ok(Holds::Other) };
        let re_minted = if meta.stretches.is_empty() {
            if placed != shot.runs.iter().map(|a| a.run.width).sum::<u64>() {
                return Ok(Holds::Other);
            }
            let image = match self.reader.image(member, None, 1, placed) {
                Ok(runs) => runs,
                Err(Refusal::Unreadable(_)) => return Ok(Holds::Other),
                Err(e) => return Err(e),
            };
            let actual = runs_of(&image)?;
            let expected: Vec<(Run, Family)> =
                shot.runs.iter().map(|a| (a.run.clone(), a.family)).collect();
            if first_difference(&expected, &actual, &merged.inputs.doc).is_some() {
                return Ok(Holds::Other);
            }
            windows::re_minted(&shot.runs)
        } else {
            match self.holds_change(merged, shot, member, &meta)? {
                Some(re_minted) => re_minted,
                None => return Ok(Holds::Other),
            }
        };
        let doc = &merged.inputs.doc;
        if first_word_difference(&self.reader, doc, &merged.maps, member, &re_minted)?.is_some() {
            return Ok(Holds::Other);
        }
        let at = match meta.at {
            Some(minted) => minted,
            None => position_of(&self.reader, member)?.unwrap_or_else(|| self.reader.as_of()),
        };
        Ok(Holds::Merged(at))
    }

    /// Returns where `member`, born of a shot that named its stretches,
    /// holds the draft side's re-minted runs — or `None` where it is not the
    /// head the merge composed on with this merge's stretches replaced.
    ///
    /// The landed test's second case at this site. The member's `shot_base`
    /// is the head, at the extent the composition read; the answered list is
    /// cut against the head's image, which the composition holds
    /// (`cut_against`, a draft side's runs alone made to ride — the cut is
    /// this walk's own, and need not be the one the shot spelled); and the
    /// member is read in the hulls of its own stretch list and that cut's
    /// ([`hulls`]), each compared with what the cut places there — the
    /// list's runs, and the head's own between them, read off the image in
    /// hand. So the reads are the member's, where the change lies, and
    /// nothing of the head. The answer is each re-minted run with the
    /// member's ordinal it lands at, the side its words are read through and
    /// the run they are read as, for the words' own check
    /// (`first_word_difference`).
    ///
    /// # Errors
    ///
    /// The member's image reads' refusals but `withheld`, which answers as
    /// what it holds; an `image` run that is no content I-address.
    #[allow(clippy::type_complexity)]
    fn holds_change<'s>(
        &self,
        merged: &Merged,
        shot: &'s ShotParts,
        member: &Address,
        meta: &Metadata,
    ) -> Result<Option<Vec<(u64, Option<usize>, &'s Run)>>, Refusal> {
        let head = merged.inputs.head.to_string();
        if meta.shot_base.as_deref() != Some(head.as_str()) || meta.base_extent != Some(merged.head_extent) {
            return Ok(None);
        }
        let Some(held) = merged.maps.first() else { return Ok(None) };
        let listed: Vec<publication::Run> = shot
            .runs
            .iter()
            .map(|a| publication::Run::new(a.run.origin.clone(), a.run.i_start, a.run.width))
            .collect();
        let re_mints = |index: usize| shot.runs[index].family == Family::DraftNative;
        let cut = cut_against(&held.runs, merged.head_extent, &listed, &re_mints);
        let placed = cut.of(&shot.runs.iter().collect::<Vec<_>>());
        // Each stretch of the cut with the positions it places, and where
        // its runs begin among the runs the cut places.
        let mut first_run = Vec::with_capacity(cut.stretches.len());
        let mut taken = 0usize;
        let asked: Vec<Positions> = cut
            .stretches
            .iter()
            .map(|stretch| {
                first_run.push(taken);
                let width = placed.iter().skip(taken).take(stretch.count).map(|a| a.run.width).sum();
                taken += stretch.count;
                (stretch.start, stretch.width, width)
            })
            .collect();
        let Some(plan) = hulls(&meta.stretches, &asked) else { return Ok(None) };
        let doc = &merged.inputs.doc;
        let mut re_minted = Vec::new();
        for hull in plan {
            let actual = if hull.member.1 == 0 {
                Vec::new()
            } else {
                match self.reader.image(member, None, hull.member.0, hull.member.1) {
                    Ok(runs) => runs_of(&runs)?,
                    Err(Refusal::Unreadable(_)) => return Ok(None),
                    Err(e) => return Err(e),
                }
            };
            let mut expected: Vec<(Run, Family)> = Vec::new();
            let mut at = hull.member.0;
            for stands in &hull.expected {
                match *stands {
                    Stands::Base { from, width } => {
                        let kept = runs_of(&clipped(&held.runs, from.saturating_sub(1), width))?;
                        expected.extend(kept.into_iter().map(|run| (run, Family::Window)));
                        at = at.saturating_add(width);
                    }
                    Stands::Stretch { index } => {
                        for answered in placed.iter().skip(first_run[index]).take(cut.stretches[index].count) {
                            if answered.family == Family::DraftNative {
                                re_minted.push((at, answered.side.map(|s| usize::from(s.0)), &answered.through));
                            }
                            expected.push((answered.run.clone(), answered.family));
                            at = at.saturating_add(answered.run.width);
                        }
                    }
                }
            }
            if first_difference(&expected, &actual, doc).is_some() {
                return Ok(None);
            }
        }
        Ok(Some(re_minted))
    }
}
