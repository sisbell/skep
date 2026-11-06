//! The undo and the withdrawal of a merge landed in a draft (skep #783; the
//! landing lane's rulings R6 and N4 with their precisions P2, P3 and P4,
//! and the withdrawal ruled beside them).
//!
//! A merge landed in a draft (the `land` module's draft landing) leaves the
//! draft holding M, its base re-recorded on the head the merge composed on,
//! and the marker beside it (`doc_metadata`'s `merge`) saying the draft's
//! next version replaces the merged sides. Two acts take that back, each
//! ONE `set_arrangement` of the draft (wire.md §Arrangement):
//!
//! * [`undo`] puts the draft back as it stood before the landing — its
//!   arrangement C and its base as they were, the marker cleared — typed
//!   against the landing's position;
//! * [`withdraw`] takes the merge out and keeps the words — the draft's
//!   current arrangement sent back whole, its recorded base re-sent
//!   unmoved, no `merge` — typed against the position it read the draft at.
//!
//! **The dispatch (P4).** The undo reads the draft's `doc_metadata` live
//! and dispatches on the BASE RECORD first, then the marker:
//!
//! * a base recorded AND a marker — the undo by the marker: the state
//!   before the landing is read at the pre-landing read (below) for the
//!   marker's `at`; a draft that did not exist there inherited the marker
//!   when it was staged (P2), and there is nothing of its own to take back
//!   ([`NoUndo::Inherited`]); else the one write sends C with the base read
//!   there — address and extent, P1's pair — and no `merge`, `as_of` the
//!   landing's position (P3: the command's and an agent's rule; the editor
//!   types its own undo against its own last ack);
//! * a base recorded, NO marker — nothing to undo: the merge was published
//!   from the draft, the base record stands on that version, and an undo
//!   from the feed would re-record the base BACKWARD, the false fact N4
//!   forbids ([`NoUndo::Published`]); the words alone come from the draft's
//!   own latest feed row of the kinds that end a marker, read and never
//!   acted on — a `publish` row P4's words, a `set_arrangement` row naming
//!   a base and no merge an undo's or a withdrawal's already made
//!   ([`NoUndo::TakenBack`]), neither a draft carrying no merge
//!   ([`Refusal::NoMerge`]);
//! * NO base record (N4's baseless case: a free-standing draft, an admitted
//!   fork) — the landing's position is the draft's own latest
//!   `set_arrangement` row carrying a `merge` term, read off the supplement
//!   (`/changes?under=S&drafts=true`, wire.md §The change feed); the one
//!   write sends C from the pre-landing read with no `base`, no `head` and
//!   no `merge`, `as_of` that row's `at`; no such row is nothing to undo
//!   ([`Refusal::NoMerge`]).
//!
//! **The pre-landing read.** The state before a commit at position `at` is
//! read through `/op-at` at the answer for `at − 1`: a landing with a base
//! record is ONE commit of three records, so `at − 1` lies inside it and
//! the board answers `not_a_position` naming the greatest position at or
//! below as `nearest`; the library then reads at `nearest`, never at
//! `at − 1` itself, and never at the head. `image` and `doc_metadata` of
//! the draft are both read at that one position. `history_reclaimed` there
//! is [`Refusal::HistoryReclaimed`] — the state before the merge is no
//! longer on this board, and nothing is sent; `doc_not_registered` there
//! is the inherited marker's case; `beyond_head` there is this library's
//! own fault.
//!
//! **The guarantees.** Each act is one write: a draft changed since the
//! position it is typed against is refused `arrangement_moved` by the board
//! with nothing changed — the undo's `as_of` is the landing's position, so
//! another hand's edit since the landing refuses it; the withdrawal's is
//! its read's, so an edit between its read and its write refuses it. The
//! base record is never made false: the undo restores the base read before
//! the landing, the withdrawal re-sends the base it read unmoved, a draft
//! whose base record has no marker is never undone from the feed, and a
//! baseless document is never sent a `base`.
//!
//! **The record.** After the write lands, the current record naming the
//! draft as landed in — found by the links of the kind to the draft, the
//! newest — is replaced: a record composed from it with `landed` none and
//! `replaces` its link is appended to the journal (`journal`, or the
//! account's default) and linked from the merger's doc 1, so a reader of
//! the journal sees the merge no longer stands on the draft. A merge landed
//! in the draft again with no take-back recorded between is the same
//! landing (skep #790; the `land` module's doc): the undo takes back the
//! later write, the one the marker or the feed row names, and the record it
//! replaces is the first landing's. Where no record stands none is written,
//! and the act stands all the same. A re-run after either act finds no
//! marker and writes nothing — so where the record is not written after the
//! act's write, for a lost acknowledgment at its writes, a head owed there,
//! or a journal this merger may not read or this board does not register,
//! the landing's record stands alone, which the halt says. A landing of the
//! key made after either act writes a record of its own, which replaces
//! this one: the landing's read-first takes the merger's newest record of
//! the key, and this one names no landing (the `land` module's doc).
//!
//! **The head, before the write.** The board's head (`Board::board_head`;
//! SP-14) is read before the one write, as the landing reads it: a claimed
//! board serving no head record halts with nothing sent, since the record's
//! link could not be signed. A lost acknowledgment of the one write is the
//! dialer's halt, with no re-ask: each act reads first on a re-run. The
//! record's link is the landing's, sent once more, signed, under its own id
//! where it went unsigned and a claim landed past the head's read
//! (`Writer::write_record`).

use serde_json::Value;
use skep_address::Address;

use crate::address::parse_address;
use crate::board::answers::Metadata;
use crate::board::{acked_at, frames, Board, Rejection, Token};
use crate::halt::{Halt, Refused};

use super::compose::Run;
use super::land::{own_fault, own_fault_face, shape_face, Merger, Unwritten, Writer};
use super::reads::{feed_rows, runs_of, NoUndo, Reader, Refusal};
use super::record::{self, Record};

/// What an undo answered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Undone {
    /// The draft the merge was taken back out of.
    pub draft: Address,
    /// The one write's commit position, its ack's `at`.
    pub position: u64,
    /// The replacing record's public link, where a record of the landing
    /// stood; `None` where none did, and none was written.
    pub record: Option<Address>,
    /// The base restored — the pair read before the landing, address and
    /// extent — where the board records a base for the draft; `None` where
    /// the undo went by the draft's feed row, a baseless document whose
    /// landing moved nothing.
    pub restored: Option<(Address, u64)>,
}

/// What a withdrawal answered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Withdrawn {
    /// The draft the merge was taken out of, its words kept.
    pub draft: Address,
    /// The one write's commit position, its ack's `at`.
    pub position: u64,
    /// The replacing record's public link, where a record of the landing
    /// stood; `None` where none did, and none was written.
    pub record: Option<Address>,
}

/// Puts a draft back as it stood before the latest merge landed in it (R6).
///
/// The latest landing is the write the draft's marker names, or for a
/// baseless draft its feed row. The dispatch, the pre-landing read, the one
/// write and the record are the module's doc. `journal` is the merge
/// journal the replacing record goes to, or the account's default where
/// `None`, as a landing's.
///
/// # Errors
///
/// In this order:
///
/// - the draft's `doc_metadata` read's refusals — [`Refusal::Unreadable`],
///   [`Refusal::NoSuchDocument`] — and [`Refusal::Published`] for a
///   published document;
/// - [`Refusal::NothingToUndo`] with its reason, and [`Refusal::NoMerge`],
///   each with nothing sent; the feed walk's halts;
/// - the pre-landing read's: [`Refusal::HistoryReclaimed`] where the board
///   no longer answers the position before the landing, nothing sent; its
///   other refusals, a position past the board's head among them as the
///   library's own fault;
/// - a claimed board serving no head record, as [`Refusal::Halt`] naming
///   `H.1`, before the one write, with nothing sent (SP-14);
/// - the one write's: `arrangement_moved` as the board's verdict,
///   [`Refusal::Halt`] with `Refused` saying the draft changed since the
///   merge landed and nothing was changed; [`Refusal::NotOwner`];
///   [`Refusal::Published`]; [`Refusal::WindowWithheld`];
///   [`Refusal::NeedsSignedSession`]; [`Refusal::NoSuchDocument`];
///   `source_not_registered`, `no_base_to_record`, `base_not_in_chain`,
///   `base_extent_too_large` and the runs' refusals as the library's own
///   faults, since it sends only the base and the runs it read; a lost
///   acknowledgment as the dialer's halt, with no re-ask;
/// - the record's reads' refusals; a journal this merger may not read or
///   this board does not register, as [`Refusal::Halt`] saying the merge is
///   out of the draft and the record is not written, nothing of the record
///   sent; then the record's writes' as `Writer::write_record` answers
///   them, the act standing.
pub fn undo(
    board: &Board,
    merger: Merger<'_>,
    draft: &Address,
    kind: &Address,
    journal: Option<&Address>,
) -> Result<Undone, Refusal> {
    let writer = Writer::new(board, merger);
    let reader = &writer.reader;
    let meta = reader.metadata(draft, None)?;
    if meta.published {
        return Err(Refusal::Published { doc: draft.clone() });
    }
    // THE DISPATCH (P4): the base record first, then the marker.
    let (as_of, restored, runs) = match (meta.base.as_deref(), meta.merge.as_ref()) {
        (Some(_), Some(marker)) => {
            let at = marker.at.ok_or_else(|| {
                own_fault_face(
                    "the marker names no position",
                    format!("{draft}'s `doc_metadata` carries a merge with no `at`, which every marker the wire serves carries (wire.md §The response envelope)"),
                )
            })?;
            let (then, runs) = match before(reader, draft, at)? {
                Before::Unregistered => {
                    return Err(Refusal::NothingToUndo {
                        draft: draft.clone(),
                        why: NoUndo::Inherited,
                    })
                }
                Before::Stood { meta, runs } => (meta, runs),
            };
            let old = match (then.base.as_deref().and_then(parse_address), then.base_copied) {
                (Some(base), Some(copied)) => (base, copied),
                _ => {
                    return Err(own_fault_face(
                        "the draft recorded no base before the landing",
                        format!("{draft} carries a base record and a marker now, and `doc_metadata` as of the position before the landing answers none: a landing records a base only where one stood (wire.md §Arrangement, `no_base_to_record`)"),
                    ))
                }
            };
            (at, Some(old), runs)
        }
        (Some(base), None) => {
            // Nothing to undo, never the feed (N4): the words alone are the
            // feed's.
            let why = match latest_ending_row(board, merger.token, draft)? {
                Some(Ending::Publish) => NoUndo::Published {
                    version: parse_address(base).ok_or_else(|| {
                        own_fault_face(
                            "the draft's recorded base cannot be spelled",
                            format!("{draft}'s `doc_metadata` names the base `{base}`"),
                        )
                    })?,
                },
                Some(Ending::TakenBack) => NoUndo::TakenBack,
                None => return Err(Refusal::NoMerge { draft: draft.clone() }),
            };
            return Err(Refusal::NothingToUndo { draft: draft.clone(), why });
        }
        (None, _) => {
            let Some(at) = latest_landing_row(board, merger.token, draft)? else {
                return Err(Refusal::NoMerge { draft: draft.clone() });
            };
            let runs = match before(reader, draft, at)? {
                Before::Stood { runs, .. } => runs,
                Before::Unregistered => {
                    return Err(own_fault_face(
                        "the draft did not exist before its landing",
                        format!("{draft}'s feed names a landing at position {at}, and `doc_metadata` as of the position before it answers `doc_not_registered`"),
                    ))
                }
            };
            (at, None, runs)
        }
    };
    let stem = format!("undo:{draft}:{as_of}");
    let base_text = restored.as_ref().map(|(base, copied)| (base.to_string(), *copied));
    let frame = frames::set_arrangement(
        &draft.to_string(),
        &frame_runs(&runs)?,
        as_of,
        None,
        base_text.as_ref().map(|(base, copied)| (base.as_str(), *copied)),
        None,
        Some(&format!("{stem}.arrangement")),
    );
    let position = send(&writer, &frame, draft, as_of, Act::Undo)?;
    let record = replace_record(&writer, kind, draft, &stem, journal, Act::Undo)?;
    Ok(Undone { draft: draft.clone(), position, record, restored })
}

/// Takes the merge out of a draft and keeps its words.
///
/// The draft's `doc_metadata` is read live and its image at THAT read's
/// position through `/op-at`; the one write sends the image back whole with
/// the recorded base re-sent unmoved — address and extent as read — and no
/// `merge`, typed against that position, so the marker is cleared and the
/// draft's words and base stay as they are; an inherited marker is taken
/// out the same way. The record and the journal are as [`undo`]'s.
///
/// # Errors
///
/// In this order:
///
/// - the draft's `doc_metadata` read's refusals — [`Refusal::Unreadable`],
///   [`Refusal::NoSuchDocument`] — and [`Refusal::Published`] for a
///   published document;
/// - [`Refusal::NoMerge`] where the draft carries no marker, nothing sent;
/// - the image read's refusals at the read's position;
/// - a claimed board serving no head record, as [`Refusal::Halt`] naming
///   `H.1`, before the one write, with nothing sent (SP-14);
/// - the one write's, as [`undo`]'s, `arrangement_moved` saying the draft
///   changed since it was read;
/// - the record's, as [`undo`]'s.
pub fn withdraw(
    board: &Board,
    merger: Merger<'_>,
    draft: &Address,
    kind: &Address,
    journal: Option<&Address>,
) -> Result<Withdrawn, Refusal> {
    let writer = Writer::new(board, merger);
    let reader = &writer.reader;
    let (meta, as_of) = reader.metadata_read(draft, None)?;
    if meta.published {
        return Err(Refusal::Published { doc: draft.clone() });
    }
    if meta.merge.is_none() {
        return Err(Refusal::NoMerge { draft: draft.clone() });
    }
    let as_of = as_of.ok_or_else(|| {
        Halt::face(
            "`doc_metadata` answered no `as_of`",
            format!("the read of {draft} named no position (wire.md §The response envelope: every response names where it sits)"),
            "this board is not speaking the wire this client expects; nothing was written",
        )
    })?;
    let base = match (meta.base.as_deref().and_then(parse_address), meta.base_copied) {
        (Some(base), Some(copied)) => (base, copied),
        _ => {
            return Err(own_fault_face(
                "the draft carries a marker and no base",
                format!("{draft}'s `doc_metadata` carries a merge beside no base record, and the marker is recorded only beside a base (wire.md §Arrangement)"),
            ))
        }
    };
    // THE ONE POSITION: the image as of the metadata's read.
    let runs = runs_of(&reader.imaged(draft, Some(as_of))?.runs)?;
    let stem = format!("withdraw:{draft}:{as_of}");
    let base_text = base.0.to_string();
    let frame = frames::set_arrangement(
        &draft.to_string(),
        &frame_runs(&runs)?,
        as_of,
        None,
        Some((base_text.as_str(), base.1)),
        None,
        Some(&format!("{stem}.arrangement")),
    );
    let position = send(&writer, &frame, draft, as_of, Act::Withdraw)?;
    let record = replace_record(&writer, kind, draft, &stem, journal, Act::Withdraw)?;
    Ok(Withdrawn { draft: draft.clone(), position, record })
}

/// Which act a `set_arrangement` is, for its words.
///
/// The three acts that send a draft one `set_arrangement` of a state the
/// board already held: the two take-backs here, and the `history` module's
/// restore, whose write is judged by [`judge`] as theirs are.
#[derive(Clone, Copy)]
pub(crate) enum Act {
    Undo,
    Withdraw,
    Restore,
}

impl Act {
    /// The act's name in a face.
    fn name(self) -> &'static str {
        match self {
            Act::Undo => "the undo",
            Act::Withdraw => "the withdrawal",
            Act::Restore => "the restore",
        }
    }
}

/// What stood before a commit (the module's doc, the pre-landing read).
enum Before {
    /// The draft did not exist at the position before the commit: an
    /// inherited marker's case (P2).
    Unregistered,
    /// The draft's metadata and arrangement as they stood.
    Stood {
        /// `doc_metadata` as of the position before the commit.
        meta: Metadata,
        /// The arrangement as of the same position.
        runs: Vec<Run>,
    },
}

/// Reads the draft's state before the commit at `at`.
///
/// It is the pre-landing read of the module's doc: `doc_metadata` asked at
/// `at − 1`, re-asked at the `nearest` a `not_a_position` names, then the
/// image at that one position.
///
/// # Errors
///
/// [`Refusal::HistoryReclaimed`] at either read, with nothing read
/// elsewhere; a position past the board's head, or a `not_a_position`
/// naming no `nearest`, or a landing at position 0, as the library's own
/// fault; the reads' other refusals.
fn before(reader: &Reader<'_>, draft: &Address, at: u64) -> Result<Before, Refusal> {
    let below = at.checked_sub(1).ok_or_else(|| {
        own_fault_face("a landing at position 0", format!("{draft}'s landing is at the genesis position, before which nothing stood"))
    })?;
    let own_fault = |e: Refusal| match e {
        Refusal::BeyondHead { at, head, .. } => own_fault_face(
            "the position before the landing is past the board's head",
            format!(
                "a read of {draft} as of {at} answered beyond_head{}",
                head.map(|h| format!(" (the head is {h})")).unwrap_or_default()
            ),
        ),
        Refusal::NotAPosition { at, .. } => own_fault_face(
            "the position before the landing is inside a commit and the board named no position below it",
            format!("a read of {draft} as of {at} answered not_a_position with no `nearest`"),
        ),
        e => e,
    };
    let (position, meta) = match reader.metadata(draft, Some(below)) {
        Ok(meta) => (below, meta),
        Err(Refusal::NoSuchDocument(_)) => return Ok(Before::Unregistered),
        Err(Refusal::NotAPosition { nearest: Some(nearest), .. }) => {
            match reader.metadata(draft, Some(nearest)) {
                Ok(meta) => (nearest, meta),
                Err(Refusal::NoSuchDocument(_)) => return Ok(Before::Unregistered),
                Err(e) => return Err(own_fault(e)),
            }
        }
        Err(e) => return Err(own_fault(e)),
    };
    let runs = runs_of(&reader.imaged(draft, Some(position)).map_err(own_fault)?.runs)?;
    Ok(Before::Stood { meta, runs })
}

/// What the latest feed row that ends a marker under a draft is.
enum Ending {
    /// A `publish` row: the merge was published from the draft.
    Publish,
    /// A `set_arrangement` row naming a base and no merge: an undo's or a
    /// withdrawal's.
    TakenBack,
}

/// Returns the kind of the latest row under `draft` that ends a marker.
///
/// It walks the supplement under the draft (`drafts=true`), keeping the
/// last of the `publish` rows and the `set_arrangement` rows whose `base`
/// is present and `merge` null (wire.md §The change feed); a bare row of
/// either kind, carrying neither term, counts as neither. `None` where no
/// such row stands.
///
/// # Errors
///
/// The feed's halts.
fn latest_ending_row(board: &Board, token: &Token, draft: &Address) -> Result<Option<Ending>, Halt> {
    let mut latest = None;
    feed_rows(board, Some(token), &draft.to_string(), true, |row| match row["op"].as_str() {
        Some("publish") => latest = Some(Ending::Publish),
        Some("set_arrangement") if row["base"].is_string() && row["merge"].is_null() => {
            latest = Some(Ending::TakenBack);
        }
        _ => {}
    })?;
    Ok(latest)
}

/// Returns the position of the latest landing on `draft` by its feed row.
///
/// It is the `at` of the last `set_arrangement` row under the draft on the
/// supplement (`drafts=true`) whose `merge` term is present — the merge it
/// marked, `{sides, head}` (wire.md §The change feed) — or `None` where no
/// such row stands.
///
/// # Errors
///
/// The feed's halts.
fn latest_landing_row(board: &Board, token: &Token, draft: &Address) -> Result<Option<u64>, Halt> {
    let mut at = None;
    feed_rows(board, Some(token), &draft.to_string(), true, |row| {
        if row["op"].as_str() == Some("set_arrangement") && row["merge"].is_object() {
            if let Some(p) = row["at"].as_u64() {
                at = Some(p);
            }
        }
    })?;
    Ok(at)
}

/// Returns `runs` as a `set_arrangement` frame spells them.
///
/// # Errors
///
/// A run with no address, as the library's own fault.
pub(crate) fn frame_runs(runs: &[Run]) -> Result<Vec<Value>, Refusal> {
    runs.iter()
        .map(|r| {
            let i_start = r
                .address_at(0)
                .ok_or_else(|| own_fault_face("a run of the draft names no address", format!("{r:?}")))?;
            Ok(frames::shot_run(&r.origin.to_string(), &i_start.to_string(), r.width))
        })
        .collect()
}

/// Sends the one write, answering its position.
///
/// The board's head is read first (SP-14), then the frame under the
/// merger's token; its answer is judged by [`judge`].
///
/// # Errors
///
/// As [`undo`]'s one write's.
fn send(writer: &Writer<'_>, frame: &Value, draft: &Address, as_of: u64, act: Act) -> Result<u64, Refusal> {
    let owed = |cause: String| {
        Halt::face(
            format!("this board has no H.1 yet, so the merge cannot be taken out of {draft}"),
            cause,
            "retry once the board has written its head; nothing was written",
        )
    };
    writer.signing_term(&owed)?;
    let v = writer.answered_write(
        frame,
        match act {
            Act::Undo => "taking the merge back out of the draft",
            Act::Withdraw => "taking the merge out of the draft",
            Act::Restore => "restoring the draft",
        },
    )?;
    judge(&v, draft, as_of, act)
}

/// Judges a `set_arrangement`'s answer `v`, answering the write's position.
///
/// The frame was typed against `as_of` for `act`; its refusals are mapped
/// as the module's doc lists them, each the same at every act but
/// `arrangement_moved`, whose words are the act's own.
///
/// # Errors
///
/// As [`undo`]'s one write's: `arrangement_moved` as the board's verdict in
/// the person's words; [`Refusal::WindowWithheld`],
/// [`Refusal::NeedsSignedSession`], [`Refusal::NoSuchDocument`],
/// [`Refusal::NotOwner`] and [`Refusal::Published`] by their codes; the
/// refusals of what the library composed as its own fault; the board's
/// other refusals verbatim; an answer that is no acknowledgment and no
/// rejection, faced.
pub(crate) fn judge(v: &Value, draft: &Address, as_of: u64, act: Act) -> Result<u64, Refusal> {
    if let Some(at) = acked_at(v) {
        return Ok(at);
    }
    let Some(r) = Rejection::of(v) else { return Err(shape_face("set_arrangement", v).into()) };
    let site = r.site().addr.as_deref().and_then(parse_address);
    Err(match r.key() {
        // Another hand's edit past the typed position: the board's verdict,
        // its words the person's, and nothing was changed (the one write
        // wipes nothing).
        "arrangement_moved" => {
            let current = v["site"]["current"].as_u64();
            let since = |what: &str| match current {
                Some(c) => format!(" ({what} at position {as_of}, the draft changed at {c})"),
                None => format!(" ({what} at position {as_of})"),
            };
            let detail = match act {
                Act::Undo => format!("{draft} changed since the merge landed{} — nothing was changed; undo the later changes first, or edit", since("the merge landed")),
                Act::Withdraw | Act::Restore => format!("{draft} changed since it was read{} — nothing was changed; run this again, which reads the draft as it stands", since("read")),
            };
            Refusal::Halt(Halt::Refused(Refused {
                status: 200,
                code: r.code().to_string(),
                detail: Some(detail),
                op: r.op().map(str::to_string),
                body: v.clone(),
            }))
        }
        "withheld" => Refusal::WindowWithheld(site.unwrap_or_else(|| draft.clone())),
        "signed_session_required" => Refusal::NeedsSignedSession,
        "doc_not_registered" => Refusal::NoSuchDocument(draft.clone()),
        "not_owner" => Refusal::NotOwner { draft: draft.clone() },
        "published_target" => Refusal::Published { doc: draft.clone() },
        // The base is the one the draft recorded, read; the runs are the
        // draft's own image; no head rides: a refusal of them is this
        // library's own fault.
        "source_not_registered"
        | "no_base_to_record"
        | "base_not_in_chain"
        | "base_extent_too_large"
        | "fork_base_moved"
        | "bad_run"
        | "dangling_source"
        | "too_many_runs"
        | "malformed" => own_fault(&format!("{}'s write", act.name()), &r),
        _ => Refusal::Halt(r.refused(&v)),
    })
}

/// Writes the replacing record, answering its link where one is written.
///
/// It is the module's doc's record: the current record naming the draft as
/// landed in, with `landed` none and `replaces` its link, under the act's
/// stem; `None` where no record stands, nothing written.
///
/// # Errors
///
/// The record's read's refusals (`Writer::landed_record`), then its writes'
/// (`Writer::write_record`).
fn replace_record(
    writer: &Writer<'_>,
    kind: &Address,
    draft: &Address,
    stem: &str,
    journal: Option<&Address>,
    act: Act,
) -> Result<Option<Address>, Refusal> {
    let Some(current) = writer.landed_record(kind, draft)? else { return Ok(None) };
    let record = Record {
        landed: None,
        claims: Vec::new(),
        replaces: current.link.clone(),
        by: record::by(),
        link: None,
        ..current
    };
    let owed = |why: Unwritten, cause: String| {
        Halt::face(
            format!("the merge is out of {draft}, and the record of {} is not written: {}", act.name(), why.reason()),
            cause,
            "nothing more is written: the draft stands as the act left it, and a re-run writes no record, finding no merge to take out; the landing's record stands alone in the journal",
        )
    };
    writer.write_record(kind, &record, draft, stem, journal, &owed).map(Some)
}
