//! The draft landing: M set as a draft's whole arrangement in one write.
//!
//! A fresh draft is staged from the head where none is named, every document
//! M windows read first so the one write's source gate cannot refuse past
//! the stage; M is sent in one `set_arrangement` typed against the position
//! the merge was composed at, and a landing is found by the board's mark —
//! the draft's marker, or where the draft records no base the landing
//! standing by its rows (the `landings` module's doc) — never by its words,
//! the list the landing placed read as of the mark's position (the `land`
//! module's doc; the landing lane's rulings R1–R5).

use serde_json::Value;
use skep_address::Address;

use crate::address::parse_address;
use crate::board::{acked_addr, acked_at, acked_head_moved, answers, frames, Rejection};
use crate::halt::{Halt, Refused};
use crate::merge::compose::Run;
use crate::merge::landings::Landings;
use crate::merge::reads::{first_difference, runs_of, stretches, Family, Merged, Refusal, Side};

use super::faults::{own_fault, own_fault_face, shape_face};
use super::records::Newest;
use super::writer::{Stem, Writer};

impl Writer<'_> {
    /// Stages a fresh draft from the head, answering it and its position.
    ///
    /// It is `stage {from: the head the merge composed on}` (R3) under the
    /// per-session id `<stem>.stage`, its [`Stem`] over `<key>@<P>`, P the
    /// position the merge was composed at, or over `<key>@<P>~<link>` where
    /// `newest`, the merger's newest record for the key, stands — `<link>`
    /// its link, the record the landing's own will replace. A retry of the
    /// same landing reads the same newest record, so it is answered its
    /// stage again where its one write was never sent — one made after that
    /// write finds the landing first, standing with its record
    /// ([`Writer::found_standing`]) or begun without it
    /// ([`Writer::landing_begun`]), and stages nothing; one composed after a
    /// take-back stages afresh, and so does the same composition landed again
    /// after its landing was taken back, whose newest record is the
    /// take-back's. The board mints a private draft of the merger's account
    /// holding the head by identity and records the head as its base, so the
    /// write that follows re-records that base on the same head. A private
    /// draft's mint, it carries no `attest` and reads no head (the `land`
    /// module's doc).
    ///
    /// # Errors
    ///
    /// [`Refusal::Unreadable`] and [`Refusal::NoSuchDocument`] naming
    /// the head, as the board's `withheld` and `source_not_registered` on the
    /// stage's source — the first never met at a version member, since every
    /// member of a published chain is published (wire.md §Arrangement,
    /// `version`); an answer of a shape this client does not know,
    /// faced; the death signal, [`Refusal::SessionEnded`]; a dial fault; the
    /// board's other refusals verbatim — `mint_home_first` among them.
    pub(super) fn stage(&self, merged: &Merged, newest: &Newest) -> Result<(Address, u64), Refusal> {
        let head = &merged.inputs.head;
        let text = match newest.link() {
            None => format!("{}@{}", merged.key.text(), merged.as_of),
            Some(link) => format!("{}@{}~{link}", merged.key.text(), merged.as_of),
        };
        let id = Stem::of(&text).id("stage");
        let frame = frames::stage(&head.to_string(), Some(&id));
        let v = self.answered_write(&frame, "staging a fresh draft")?;
        if let (Some(addr), Some(at)) = (acked_addr(&v), acked_at(&v)) {
            let fresh = parse_address(addr).ok_or_else(|| shape_face("stage", &v))?;
            return Ok((fresh, at));
        }
        let Some(r) = Rejection::of(&v) else { return Err(shape_face("stage", &v).into()) };
        Err(match r.key() {
            "withheld" => Refusal::Unreadable(head.clone()),
            "source_not_registered" => Refusal::NoSuchDocument(head.clone()),
            _ => Refusal::Halt(r.refused(&v)),
        })
    }

    /// Lands M into the draft in one write, answering its position and the
    /// newer head where the board told one.
    ///
    /// The one frame is `set_arrangement` (the `land` module's doc): M's runs,
    /// typed against `as_of` — the merge's one position for a draft named, the
    /// stage's position for a fresh one — with the head the merge composed on
    /// and its extent as read, the same pair as the base to record where the
    /// draft's `doc_metadata`, read as it stands, records a base, and the
    /// merge's sides but the draft itself; its id `<stem>.draft`, `stem` the [`Stem`]
    /// over the key, the draft, `as_of` and, for a draft named, the record the
    /// landing follows, which the board answers again in the same session for
    /// the same landing. It is sent where the draft already holds M too, so the
    /// base and the marker are recorded; a private draft's write, it reads no
    /// head (the `land` module's doc). A write refused `arrangement_moved` is
    /// said in words read off the draft as it stands ([`Writer::moved_words`]),
    /// `newest` the record they name. With `shoot` off nothing is sent: the
    /// draft is read as it stands, and it answers the position of this merge's
    /// landing as the board marks it ([`Writer::marked_landing`]) where that
    /// landing placed M whole, the draft read as of it (`holds_merge`), so an
    /// edit made in the draft since changes nothing; or `None` where the board
    /// marks no landing of this merge — a take-back cleared it, none was made,
    /// or the draft's marker is the one its stage copied from the draft it was
    /// staged from — or the landing it marks placed another list. Where the
    /// list it placed cannot be read back, the board having reclaimed the
    /// mark's position since the draft was edited, it answers the mark where a
    /// record of the merger's own of the key stands for it
    /// ([`Newest::standing_in`]), and `None` where none does: a landing no
    /// record names is recorded only where it can be judged (#914 F16).
    ///
    /// # Errors
    ///
    /// The draft's reads' refusals — its `doc_metadata`, read as it stands,
    /// [`Refusal::NoSuchDocument`] naming the draft where the board does not
    /// register it, the reads of its rows and past states, with `shoot` off,
    /// on a draft with no recorded base ([`Writer::marked_landing`]), and its
    /// image as of the landing's position but a reclaimed one,
    /// [`Refusal::HistoryBusy`] past the bounded retries among them — and a
    /// draft minted after `as_of`, faced, naming the way out; the board's
    /// `arrangement_moved` as its verdict, [`Refusal::Halt`] with the
    /// `Refused` re-said in [`Writer::moved_words`]'s words — this merge's
    /// own landing named where it moved the draft after `as_of`, else the
    /// draft that changed after the merge was composed and nothing merged —
    /// or those reads' refusals, each as itself (SP-14);
    /// [`Refusal::ForkBaseMoved`], naming the fork's source the board names,
    /// and [`Refusal::BaseNotInChain`], the two refusals a person meets;
    /// [`Refusal::WindowWithheld`] where a run names an origin the merger may
    /// not read, naming it as the board names it and beside it its words in
    /// M — a `withheld` or a `fork_base_moved` naming in `site.addr` no
    /// document this client parses is the board's refusal verbatim (SP-18);
    /// [`Refusal::NeedsSignedSession`];
    /// [`Refusal::NoSuchDocument`] naming the draft; a run with no address
    /// and the board's refusal of the frame's substance — the head and the
    /// extent the merge read and the base the draft records as it stands
    /// (`source_not_registered`, `no_base_to_record`,
    /// `base_extent_too_large`), a run's origin (`source_not_registered`,
    /// `bad_run`, `dangling_source`, `too_many_runs`), the draft's standing
    /// (`published_target`, `not_owner`) — as the library's own faults; an
    /// answer of a shape this client does not know, faced; the death signal,
    /// [`Refusal::SessionEnded`]; a dial fault; the board's other refusals
    /// verbatim.
    pub(super) fn land_into_draft(
        &self,
        merged: &Merged,
        into: &Address,
        as_of: u64,
        stem: &Stem,
        newest: &Newest,
        shoot: bool,
    ) -> Result<Option<(u64, Option<Address>)>, Refusal> {
        let head = &merged.inputs.head;
        if !shoot {
            // The residue walk: the landing the board marks in the draft as
            // it stands, then M as that landing placed it — never the
            // draft's words alone.
            let meta = self.reader.metadata(into, None)?;
            let Some(at) = self.marked_landing(merged, into, &meta)? else {
                return Ok(None);
            };
            return match self.holds_merge(merged, into, at, meta.arranged_at.position()) {
                Ok(held) => Ok(held.then_some((at, None))),
                // The list it placed cannot be read back: the landing a
                // record of the key stands for is answered, one no record
                // names judged by nothing and recorded never (#914 F16).
                Err(Refusal::HistoryReclaimed { .. }) => {
                    Ok(newest.standing_in(into, at).map(|_| (at, None)))
                }
                Err(e) => Err(e),
            };
        }
        let target: Vec<Run> = merged.composed.runs.iter().map(|p| p.run.clone()).collect();
        // The base to record: the head's pair, only where the board records
        // a base for the draft as it stands (N4) — a baseless draft and a
        // fork get none. The board judges the base at the commit after
        // `arrangement_moved`, so a draft changed since `as_of` is refused
        // for its change.
        let meta = self.reader.metadata(into, None)?;
        if meta.at.is_some_and(|minted| minted > as_of) {
            return Err(Halt::face(
                format!("{into} did not exist at position {as_of}, the position this merge was composed at"),
                "the merge stands at one board position and types its landing against it, so the draft it lands into must stand there: a draft minted after the composition changed after it",
                "run the merge again naming the draft, or land it in a fresh draft (`into` none; the command's --new)",
            )
            .into());
        }
        let head_text = head.to_string();
        let pair = Some((head_text.as_str(), merged.head_extent));
        let base = if meta.base.is_some() { pair } else { None };
        let runs: Vec<Value> = target
            .iter()
            .map(|r| {
                let i_start = r
                    .address_at(0)
                    .ok_or_else(|| own_fault_face("a run of M names no address", format!("{r:?}")))?;
                Ok(frames::shot_run(&r.origin.to_string(), &i_start.to_string(), r.width))
            })
            .collect::<Result<_, Refusal>>()?;
        let sides = marked_sides(merged, into);
        let side_refs: Vec<&str> = sides.iter().map(String::as_str).collect();
        let id = stem.id("draft");
        let frame = frames::set_arrangement(
            &into.to_string(),
            &runs,
            as_of,
            pair,
            base,
            Some((&side_refs, None)),
            Some(&id),
        );
        let v = self.answered_write(&frame, "landing the merge in the draft")?;
        if let Some(at) = acked_at(&v) {
            let head_moved = match acked_head_moved(&v) {
                Some(h) => Some(parse_address(h).ok_or_else(|| shape_face("set_arrangement", &v))?),
                None => None,
            };
            return Ok(Some((at, head_moved)));
        }
        let Some(r) = Rejection::of(&v) else {
            return Err(shape_face("set_arrangement", &v).into());
        };
        let site = r.site().addr.as_deref().and_then(parse_address);
        Err(match r.key() {
            // The words refused: M's runs whose origin the board names.
            // Where it names no document this client parses, none is typed
            // in its place: the wire names one on every `withheld` (wire.md
            // §Rejections), and never the draft, whose own words the source
            // gate never consults. The answer rides verbatim (SP-18).
            "withheld" => match site {
                Some(origin) => {
                    let positions =
                        stretches(target.iter().map(|run| (run.origin == origin, run.width)));
                    Refusal::WindowWithheld { origin, positions }
                }
                None => Refusal::Halt(r.refused(&v)),
            },
            "signed_session_required" => Refusal::NeedsSignedSession,
            "doc_not_registered" => Refusal::NoSuchDocument(into.clone()),
            // The draft changed past the position the write was typed
            // against: the board's verdict, nothing changed (the one write
            // wipes nothing), never this client's fault, in the person's
            // words read off the draft as it stands — this merge's own
            // landing where it made the change, else another hand's race.
            "arrangement_moved" => {
                let current = v["site"]["current"].as_u64();
                match self.moved_words(merged, into, as_of, newest, current) {
                    Ok(detail) => Refusal::Halt(Halt::Refused(Refused {
                        status: 200,
                        code: r.code().to_string(),
                        detail: Some(detail),
                        op: r.op().map(str::to_string),
                        body: v.clone(),
                    })),
                    Err(e) => e,
                }
            }
            // The fork's source, `site.addr` on every `fork_base_moved`
            // (wire.md §Rejection codes): where no document this client
            // parses is named, the answer rides verbatim (SP-18).
            "fork_base_moved" => match site {
                Some(source) => Refusal::ForkBaseMoved {
                    fork: into.clone(),
                    source,
                    head: head.clone(),
                },
                None => Refusal::Halt(r.refused(&v)),
            },
            "base_not_in_chain" => Refusal::BaseNotInChain { into: into.clone(), head: head.clone() },
            // The head and its extent are the merge's own reads — a member
            // registered for good, whose count never falls (PUB-2.43) — the
            // base is sent only where the draft records one as it stands, a
            // recorded base never cleared, and every run was composed from
            // the merge's images: a refusal of them is its own fault.
            "no_base_to_record"
            | "base_extent_too_large"
            | "source_not_registered"
            | "published_target"
            | "not_owner"
            | "bad_run"
            | "dangling_source"
            | "too_many_runs"
            | "malformed" => own_fault("the draft landing", &r),
            _ => Refusal::Halt(r.refused(&v)),
        })
    }

    /// Returns whether the landing at `at` placed M whole in `into`.
    ///
    /// It reads `into` as it stood at `at`, the position the board marks this
    /// merge's landing at, so the edits made in the draft since its landing
    /// change nothing: a landing stands until it is taken back (skep #914),
    /// and the test is of the list it placed, which tells this composition's
    /// landing from one of another composition of the same head and sides —
    /// the key holds no choice. A `resume` naming the draft, a fresh landing
    /// looking for its own ([`Writer::found_standing`]) and the words of a
    /// refused landing all judge a landing by it.
    ///
    /// `arranged_at` is the draft's own as the caller's `doc_metadata` read
    /// it. Where it is `at`, the text has not changed since the landing, so
    /// the draft is read at the head and its `doc_metadata` read again after
    /// the image: an `arranged_at` still `at` keeps that image, the state as
    /// of the landing, with no past state rebuilt. Else, and where a write
    /// landed between the two reads, `into` is read as of `at` through
    /// `/op-at`. Where the board has reclaimed that position, `into` is read
    /// as it stands instead: holding M whole there, it holds this
    /// composition's landing; holding anything else, it tells nothing of the
    /// list the landing placed, which the draft's edits since may have
    /// changed, and the landing is answered as one that cannot be judged.
    ///
    /// # Errors
    ///
    /// [`Refusal::HistoryReclaimed`] where the board has reclaimed `at` and
    /// the draft as it stands does not hold M whole: the list the landing
    /// placed cannot be read back, and whether it is this composition's
    /// is the caller's to answer. The draft's `image` reads' other refusals,
    /// and the `doc_metadata` read's after a head image;
    /// [`Refusal::HistoryBusy`] past the bounded retries; an `image` run that
    /// is no content I-address.
    pub(super) fn holds_merge(
        &self,
        merged: &Merged,
        into: &Address,
        at: u64,
        arranged_at: Option<u64>,
    ) -> Result<bool, Refusal> {
        let target: Vec<(Run, Family)> =
            merged.composed.runs.iter().map(|p| (p.run.clone(), Family::Own)).collect();
        let holds = |runs: &[answers::IRun]| -> Result<bool, Refusal> {
            let current = runs_of(runs)?;
            Ok(first_difference(&target, &current, &merged.inputs.doc).is_none())
        };
        let unchanged = if arranged_at == Some(at) {
            let imaged = self.reader.imaged(into, None)?;
            let still = self.reader.metadata(into, None)?.arranged_at.position() == Some(at);
            still.then_some(imaged)
        } else {
            None
        };
        match unchanged {
            Some(imaged) => holds(&imaged.runs),
            None => match self.reader.imaged(into, Some(at)) {
                Err(reclaimed @ Refusal::HistoryReclaimed { .. }) => {
                    if holds(&self.reader.imaged(into, None)?.runs)? {
                        Ok(true)
                    } else {
                        Err(reclaimed)
                    }
                }
                imaged => holds(&imaged?.runs),
            },
        }
    }

    /// Checks that the merger may read every document M windows, before a
    /// fresh draft is staged for the landing (P13).
    ///
    /// The one write's source gate consults each window's origin (wire.md
    /// §Arrangement, `set_arrangement`), and its refusal past the stage
    /// would leave the staged draft standing with nothing landed in it, so
    /// each distinct origin of M's windows is read first, in M's order, one
    /// `doc_metadata` at the head.
    ///
    /// # Errors
    ///
    /// [`Refusal::WindowWithheld`] naming the first origin that answers
    /// `withheld`, beside its words in M; each read's other refusals as
    /// themselves.
    pub(super) fn windows_readable(&self, merged: &Merged) -> Result<(), Refusal> {
        let runs = &merged.composed.runs;
        let mut read: Vec<&Address> = Vec::new();
        for (placed, family) in runs.iter().zip(&merged.families) {
            let origin = &placed.run.origin;
            if *family != Family::Window || read.contains(&origin) {
                continue;
            }
            read.push(origin);
            match self.reader.metadata(origin, None) {
                Ok(_) => {}
                Err(Refusal::Unreadable(_)) => {
                    let refused = runs.iter().map(|p| (p.run.origin == *origin, p.run.width));
                    let positions = stretches(refused);
                    return Err(Refusal::WindowWithheld {
                        origin: origin.clone(),
                        positions,
                    });
                }
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }

    /// Returns the position of this merge's landing in `into`, as the board
    /// marks it.
    ///
    /// It is the landing the board shows, read by the base record `meta`
    /// answers for the draft as it stands (P4, N4). With a base, it is the
    /// marker (`meta`'s `merge`) where it names the head the merge composed
    /// on and the sides the landing marks ([`marked_sides`]): set by the
    /// landing whether or not its record was written, cleared by a take-back
    /// and by the draft's `publish`. A marker whose `at` is the draft's own
    /// mint, `meta`'s `at`, marks none: the stage that minted the draft
    /// copied it from the draft it was staged from, stamped at that stage's
    /// commit (P2), while a landing's own stands past the mint, the board
    /// writing only into a draft it has registered. With no base, the draft
    /// carries no marker, and it is the landing standing by the draft's
    /// `set_arrangement` rows on the supplement where its row's `merge` names
    /// them (skep #914; the `landings` module's doc): a landing stands from
    /// its write until a row naming no merge leaves the draft as it stood
    /// before it, the landing it went over then standing again, and a
    /// restore or any other re-arrangement neither ends it nor brings it
    /// back. A past state that walk needs, reclaimed by the board, leaves
    /// none standing. `None` where no such landing stands, whatever the
    /// draft holds: a withdrawal keeps M's words, a stage copies them with
    /// the marker, and another write can leave a list equal to M, so the
    /// words never tell a landing (R2).
    ///
    /// # Errors
    ///
    /// On a draft with no recorded base, the walk's (`standing_mark`): the
    /// feed walk's, and where a plain row follows a landing the reads of the
    /// draft's past states but a reclaimed one, [`Refusal::HistoryBusy`] past
    /// the bounded retries among them, each as itself (SP-14).
    pub(super) fn marked_landing(
        &self,
        merged: &Merged,
        into: &Address,
        meta: &answers::Metadata,
    ) -> Result<Option<u64>, Refusal> {
        match self.landing_mark(merged, into, meta) {
            Err(Refusal::HistoryReclaimed { .. }) => Ok(None),
            mark => mark,
        }
    }

    /// Returns the position of this merge's landing in `into` as the board
    /// marks it, or that the draft cannot be judged.
    ///
    /// It is [`Writer::marked_landing`]'s mark, but where the walk of a draft
    /// with no recorded base needs a past state the board has reclaimed it is
    /// [`Refusal::HistoryReclaimed`], never none: a reader that would land
    /// the merge again where no landing stands tells a landing it cannot
    /// judge from one taken back.
    ///
    /// # Errors
    ///
    /// [`Writer::marked_landing`]'s, and [`Refusal::HistoryReclaimed`].
    pub(super) fn landing_mark(
        &self,
        merged: &Merged,
        into: &Address,
        meta: &answers::Metadata,
    ) -> Result<Option<u64>, Refusal> {
        let head = merged.inputs.head.to_string();
        let sides = marked_sides(merged, into);
        if meta.base.is_some() {
            return Ok(meta
                .merge
                .as_ref()
                .filter(|m| m.head == head && m.sides == sides)
                .and_then(|m| m.at)
                .filter(|at| meta.at != Some(*at)));
        }
        let standing = Landings::read(&self.reader, into)?.standing(&self.reader)?;
        Ok(standing
            .map(|s| s.mark)
            .filter(|m| m.head == head && m.sides == sides)
            .and_then(|m| m.at))
    }

    /// Returns the words of a draft landing refused `arrangement_moved`.
    ///
    /// The board refused the one write into `into`: the draft changed past
    /// `as_of`, the position the write was typed against, at `current` where
    /// the refusal names it. Where this merge's own landing stands
    /// ([`Writer::marked_landing`]) at a position past `as_of` — met by a
    /// composition landed again in a session that holds no memo of its
    /// write — the words name it and its record, the record of the key
    /// standing for it ([`Newest::standing_in`]), else unwritten, and what
    /// that landing placed: M, whatever was edited in `into` since, and
    /// `resume` is the way on, which answers that landing and writes a
    /// record it lacks; another list — a composition of the same head and
    /// sides with other choices — and nothing to resume; or a list that
    /// cannot be read back, the board having reclaimed its position, and
    /// `resume` the way on only where its record is written. Else the words
    /// name the change and that nothing was merged, and what a merge run
    /// again does with it: it reads `into` as it stands where `into` is a
    /// side of the merge, and where it is none, it never reads the change,
    /// so landing there again replaces it with the merged list.
    ///
    /// # Errors
    ///
    /// The reads' refusals, each as itself (SP-14): the draft's
    /// `doc_metadata` as it stands, on a draft with no recorded base the
    /// reads of its rows and past states ([`Writer::marked_landing`]) and,
    /// where a landing stands, the draft's `image` as of it, but a reclaimed
    /// one.
    fn moved_words(
        &self,
        merged: &Merged,
        into: &Address,
        as_of: u64,
        newest: &Newest,
        current: Option<u64>,
    ) -> Result<String, Refusal> {
        let meta = self.reader.metadata(into, None)?;
        if let Some(at) = self.marked_landing(merged, into, &meta)?.filter(|at| *at > as_of) {
            let link = newest.standing_in(into, at);
            let record = match link {
                Some(link) => format!("its record is {link}"),
                None => "its record is not written".to_string(),
            };
            let landed = format!("it landed there at position {at}, after the merge was composed at position {as_of}, and {record}");
            return Ok(match self.holds_merge(merged, into, at, meta.arranged_at.position()) {
                Ok(true) => {
                    let writes = if link.is_some() { "" } else { " and writes its record" };
                    format!("{into} already holds this merge: {landed} — nothing was written now; resume answers that landing{writes}")
                }
                Ok(false) => format!("this merge landed in {into} at position {at}, after it was composed at position {as_of}, and {record}, placing another list than this composition's — nothing was written"),
                Err(Refusal::HistoryReclaimed { .. }) => {
                    let way_on = match link {
                        Some(_) => "; resume answers that landing",
                        None => ", so no resume records it",
                    };
                    format!("{into} holds a landing of this merge: {landed}; the list that landing placed cannot be read back, the board having reclaimed position {at} — nothing was written now{way_on}")
                }
                Err(e) => return Err(e),
            });
        }
        let since = match current {
            Some(c) => format!(" (composed at position {as_of}, the draft changed at {c})"),
            None => format!(" at position {as_of}"),
        };
        let again = if merged.inputs.sides.iter().any(|s| s.address() == into) {
            "run the merge again, which reads the draft as it stands".to_string()
        } else {
            format!("{into} is no side of this merge, which never read that change, so landing the merge there again replaces the change with the merged list")
        };
        Ok(format!(
            "{into} changed after the merge was composed{since} — nothing was merged; {again}"
        ))
    }
}

/// Returns the sides a landing into `into` marks.
///
/// They are every side of the merge but `into` itself, in side order, as
/// the landing's `set_arrangement` names them in its `merge` and the board
/// carries them back on the marker and on the write's feed row.
pub(super) fn marked_sides(merged: &Merged, into: &Address) -> Vec<String> {
    merged
        .inputs
        .sides
        .iter()
        .map(Side::address)
        .filter(|s| *s != into)
        .map(ToString::to_string)
        .collect()
}

/// Returns whether a draft's row's `merge` names `head` and `sides`.
///
/// They are the head a landing composed on and the sides it marks, as the
/// board carries a `set_arrangement`'s merge on the write's row (wire.md
/// §The change feed, `merge`): the mark of a draft with no recorded base,
/// and of a landing begun in any draft of the merger's.
pub(super) fn row_marks(merge: &Value, head: &str, sides: &[String]) -> bool {
    merge["head"].as_str() == Some(head)
        && merge["sides"]
            .as_array()
            .is_some_and(|s| s.iter().map(Value::as_str).eq(sides.iter().map(|x| Some(x.as_str()))))
}
