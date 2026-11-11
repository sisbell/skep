//! The probe and the resend (`client.md` §3c.4, §3c.5).
//!
//! They are the hold's walk that drains a board's queue once the board
//! returns. The probe ([`Holds::probe`]) runs on the board's feed thread
//! every [`PROBE_CADENCE`](super::PROBE_CADENCE) while a session that may
//! write stands at the board, a line stands, its writes stand halted or its
//! head unreadable, or its silence awaits a verdict, and there too at its
//! daemon-running tick and at the hand-overs of `resolve(send)`, of a
//! `resolve(drop)` that kept its line (skep #866) and of
//! `set_node_state(Running)`, because `Cmd::Tick` is
//! driven by committed writes and a poisoned, halted, stopped or
//! unreachable board commits nothing. Each probe first runs the store's
//! retry (`Holds::retry_store`, §3c.1, §3c.3; skep #813, #821, #857, #859,
//! #873): the board's locks this shell does not hold are tried again, each
//! principal's queue is brought to the store as it stands — its file read
//! where the device refused it, the pending → chain change made where the
//! board's own directory is this shell's now — and the copies each held file
//! owes its queue — a line's, a re-mark's or a `done`'s the device refused —
//! are written, whatever the board's state: the retry's clock. The resend
//! it lets run is automatic at the hold's end and at reopen, under a standing
//! session of the principal's that may write — never a bare one, the keyless
//! session that reads alone (foundations §3.3 state 3), whose principal's
//! lines stay held until a session that may write stands; a halted
//! principal's lines, and a line parked on the pending file until its copy
//! to the board's file lands (`HeldQueue::parked`), are walked by none.
//!
//! **The drain runs in turns** (skep #817, #862). One probe runs one turn of
//! at most [`TURN_STEPS`] steps — a document's read, a line's send, a shift
//! of a line the board refused as typed against an older state — and
//! answers whether it stopped at that bound with a line still to send
//! ([`Turn`]); the feed thread then serves the work queued behind the turn
//! and runs the next at once, so a `search`, a listing or a session's swap
//! at the board never waits a whole drain out, nor a document another
//! writer keeps moving. The turns of one *pass* walk the principal's lines
//! in `k` order, a document read as the walk reaches its first line, and a
//! document a turn stopped at — its read undecided, its head awaiting the
//! person's act, not taken, or refused again past the turn's last step —
//! passed over by every later turn of the pass
//! (`PrincipalHold::stopped_in_pass`), so no later turn of a pass reads a
//! document or dials its head again however many turns the pass takes; the
//! pass ends at a turn no bound stopped, and the next starts at the next
//! probe.
//!
//! **The pass ends at the board's silence** (§3c.5; skep #863). It ends at
//! the first request the board gives no answer to (`DialError::unanswered`:
//! the name unresolved, the connection refused or not made within its bound,
//! the handshake not completed, no answer within the bound once connected,
//! the connection closed before any answer) — the probe's
//! `/health`, its read of the board's head, a document's read or its site's,
//! a line's send, a shift's live read or the hands' read ([`Turn::Unanswered`];
//! [`Step::Unanswered`]). A request the board answers, with any refusal or
//! status, ends nothing. From that request the turn dials none of its other
//! documents and changes nothing of them — no state, no line in the shell's
//! window, no count; the line a send was cut at goes back to holding
//! `unreachable` with its `sent`, its document's `held` event saying it so,
//! a read's line stands as it was, and the board is marked unanswered until
//! the next probe's verdict (`Holds::note_unanswered`), a send owed to it as
//! its line's failure where its request may have left. The document the
//! silence cut is entered in `PrincipalHold::cut_in_pass`, and the next turn
//! walks every principal's documents the pass did not reach first and the
//! cut ones last (`Round`), so a document whose line keeps going unanswered
//! while the board answers its probe never holds back another document's
//! words. The probe runs while the board is silent or a request pends its
//! verdict, a line standing or none. A shift whose live read the board gives
//! no answer to is not tried: its verdict is kept
//! (`PrincipalHold::shift_owed`), and the line's next send runs the shift
//! from it, no stale frame dialed first; a moved face whose hands' read goes
//! unanswered, or is answered with no page, is said with them not read
//! (`Hand::UNREAD`), and the walk reads them again, a step, as it meets the
//! document, under its own session and every other session told them not
//! read (`Holds::reread_hands`; skep #972) — a principal no session of which
//! may write having them read so at each pass (`Holds::pay_hands_owed`).
//!
//! **A moved document's head is tested against its document** (§3c.5;
//! skep #867), so the page knows what its "send again" would do: `sendable`,
//! true where the shift a `send` would run is exact against the text as it
//! now stands, false where the line would be held moved again, absent where
//! no read answered (`Tested`; `Holds::test_shift`). The test is that shift —
//! `shifted_frame` over the document's image, the line's deadline reset as a
//! `send` resets it, a head with no anchors or no span false with no read —
//! and it never changes what a `send` does. A moved hold that ran the shift
//! enters its answer, no second read (`Holds::note_shift_refused`). The head
//! owes the walk a test, one step of the turn right after the hands', where
//! it has no answer of its own — held at its deadline, after a relaunch — or
//! where its answer stands stale: a row has named the document since
//! (`Holds::note_rows`, the feed thread's drafts read handing over what it
//! named, dialing nothing) or the board gave the read no answer. One read per
//! document per pass, then, however many rows land. A test tells the page
//! only a change to or from true, which is all its act keys on, the `moved`
//! event naming the hands as every moved face does; an unanswered read
//! tells nothing and ends the pass, as every unanswered request does.
//!
//! The walk's read: one per document (`GET
//! /changes`) before its first resend, which answers one question of the
//! document's head — did its own write land? — and nothing more: (i)
//! no landing of it found, or none confirmed, send from the head, or, the
//! head's first failed send standing [`HAND_OVER_DEADLINE`] of the board's
//! answering past, whatever the failure, hand it to the person as a refused
//! run (`answers_lost`), naming the last failure and the wall time since it,
//! dialed never again until the person sends it; (ii)
//! the in-flight burst landed, the head `done kept` and its
//! position the document's base, as an ack's is (§3c.2). A head no dial of
//! which left is not read at all: it goes from the head. A row that is not
//! the head's own landing is no verdict — the person's own later write, a
//! sibling's, another hand's — and the head goes from the head; and a read
//! the board answered with no page, or with the death signal, decides
//! nothing: the next probe reads again, as it does after a read the board
//! gave no answer to, which ends the pass. The same read decides the
//! person's drop of a `sent` line handed over as `answers_lost`, made first
//! (`Holds::resolve`; skep #866): a landing found keeps the line, no row
//! that could be its landing drops it, and a row that could be and is not
//! confirmed, or a read that decides nothing, drops nothing.
//! Whether the *document moved* is the board's to say, (iii), by one route: a
//! line it refuses as typed against an older state of its document
//! (`arrangement_moved`, the frame's `as_of` below the arrangement's last
//! change). Such a line is *shifted* where it can be, by identity
//! (skep #442, #751), in [`Holds::shift_and_send`] — the one function the first
//! dial takes too: the page's anchors — the I-addresses on either side of the
//! span the burst edits and, for a delete or a rearrange, the I-runs of the
//! units the span holds, kept with the line — are found in the document's
//! current image by one live read, and where each anchor stands at one place
//! with the span's own units between them, every position the burst names moves
//! by their one displacement, the shifted frame is written to the line before
//! it is dialed, and the line is sent again, each refusal that shifts it a
//! failed send of the line and each shift at a resend a step of the turn: a
//! turn with no step left for the next shift leaves the line as its last dial
//! left it — the cause it was held with, its `sent`, the frame its last shift
//! wrote — for the drain's next pass, whose read decides it afresh, so the
//! shifts stop at the line's deadline, met at a shift or at that read; where
//! the shift is not exact — no anchors, a delete or a rearrange without its
//! span, an anchor lost or standing at two places, the span cut or refilled,
//! the read refused, the deadline passed — the document is
//! faced `moved`, never rebased inexactly, the verdict kept on the line and the
//! hands read once since the line's typed state, or since the person's last
//! `send` on the document where that is later. The death signal met at the
//! shift's read, or at the read of the hands, is no verdict on the document:
//! it is met as the death at the line's dial is, nothing faced `moved`
//! (§3c.4). A rearrange that landed where
//! the read cannot see it — its row's testimony lost, or the feed's history
//! reclaimed — leaves the span's own units between its anchors in another
//! order, so its resend, refused by the board, is held moved and never applied
//! twice. The read judges no move, and no line is shifted before it: the shift
//! lives in the send, which runs for a line the read let go alone. The lines
//! of the documents the reads let go go out in `k` order across the
//! documents (§3c.5's order, "which keeps each document's order"), each
//! document read as the walk reaches it, so a `copy` held between two bursts
//! on its source transcludes the source as it stood when the person wrote it.
//! Each line goes
//! out through the hold's one reader of a write's answer, as a first dial does,
//! every failed send of it noted on its clock and its "sent again" said once
//! per change of the failure; one the board refuses under a code the table
//! holds nowhere is handed to the person at once, a refused run under the
//! board's token, since it cannot resolve (§3c.4). Each line the walk keeps,
//! at its ack or found landed by the read, is named on its document's `held`
//! event — its ordinal, its frame's `id`, the position the board took it at
//! and, at an insert's ack, the I-address it minted (`LandedLine`;
//! skep #968). A line kept whose words a later line's anchors name places
//! them at that I-address (skep #969): its ack's, or, for a landing the read
//! found, the one an `image` of its confirmed site through `/op-at` at the
//! site read's position answers (`Holds::minted_at`) — a read that decides
//! nothing deciding nothing of the line either, and one that names no single
//! run of the words keeping the line with the naming lines' anchors dropped.
//! A resend marks its line as one that may have landed before it dials, synced,
//! and the line stays so through every resend short of its ack and through a
//! move, so its next read takes a landing it finds as the line's own — after a
//! crash or a refused write between a dial and its answer too (§3c.2's `sent`);
//! a mark the device refuses is owed and written by the retry, and a close
//! while it is owed relaunches the line as one never sent.
//!
//! **Every resend dials under the line's dial id** (skep #971). A line names
//! a dial id of its own (`refs::DialId`) as it is first readied, in the copy
//! that marks it as one that may have landed, and every resend of it, a
//! shift's dial among them, sets that id on the copy it dials in the page's
//! `id`'s place (`AttestedWhereOwed::under`). The walk resends every line of
//! a principal's under one session, whichever page held it, and the board's
//! retry memo takes a frame for a reissue by its session, its `id` and its
//! kind alone (wire.md §Correlation and idempotency): under the page's `id`,
//! which two tabs or a reload give two lines alike, the board would answer
//! one line with another's acknowledgment, and the shell keep a line the
//! board never wrote. The frame the line keeps, the frame an ack is noted by
//! and the `held` event's `burst` carry the page's own. A burst's first dial
//! and the shifts its call makes go out under the page's `id`, so a resend of
//! a burst whose first dial landed meets no memo entry of it: the board
//! judges it by the state it was typed against (`as_of`), as it judges every
//! frame, and refuses it as typed against an older state, and its shift,
//! finding the words the burst landed between its anchors where they stand,
//! holds it moved — the outcome of every landing the read cannot see.

use std::borrow::Cow;
use std::collections::{BTreeSet, HashSet};
use std::fmt;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use serde_json::{json, Value};
use skep_client::board::{acked_addr, acked_at, frames, Answer, AtAnswer, ChangesAnswer, ChangesQuery, Rejection};
use skep_client::halt::Halt;

use super::{
    awaits_act, cause, line_state, millis, minted_by, unanswered, AttestedWhereOwed, BoardHold, BoardSlot, CutSend, Dialed, Hand, HandsRead, HeldState, Holds, KeptShift, LandedLine, MovedFace,
    Tested, Turn, Verdict, HAND_OVER_DEADLINE, TURN_STEPS,
};
use crate::held::{i_address, Anchor, Anchors, HeldLine, Reason, SpanRun};
use crate::refusal::{Name, Refusal};
use crate::sessions::{board_head, SessionEntry};
use crate::wire::{delivered_values, values_of};

/// The window the shift's one read images: every arranged content position
/// from the first.
///
/// The board clips an `image` region to the arrangement (M5's resolution
/// clips silently, and a natural rides the wire unbounded), so one read over
/// this window answers the document's whole content image — its runs in
/// V-order, a run the document places twice answered at each place
/// ([`Image`]) — whatever its extent, and the anchors are found wherever
/// they now stand; a document past the board's run budget answers
/// `image_too_large`, and the shift is not made.
const IMAGE_WINDOW: u64 = u64::MAX;

/// Why a line was not shifted ([`Holds::shift_and_send`]): the document is
/// held as moved.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum Unshiftable {
    /// The burst carried no anchors: an agent's through the MCP tools.
    NoAnchors,
    /// No line of the ordinal stands.
    NoLine,
    /// The line's first failed send stands its deadline or more past.
    ///
    /// `elapsed_ms` is the time since it ([`HAND_OVER_DEADLINE`]).
    PastTheDeadline { elapsed_ms: u64 },
    /// The image read answered no image.
    ///
    /// It was refused, an answer no read takes, or runs that are no
    /// I-extents.
    ///
    /// A read the board gave no answer to is none of these: the shift is not
    /// tried, its verdict kept ([`Holds::shift_and_send`]; skep #863).
    Unread(String),
    /// The burst is a delete or a rearrange whose anchors name no span.
    ///
    /// No identity says which units its span held.
    NoSpan,
    /// An anchor is in the document no longer: `before` or `after`.
    AnchorLost(&'static str),
    /// An anchor stands at two places in the document: `before` or `after`.
    ///
    /// No one place says where the burst's span stands now.
    AnchorTwice(&'static str),
    /// The span between the anchors holds other positions than it held
    /// when the burst was typed: another write cut it, or filled it.
    SpanCut { between: u64, were: u64 },
    /// The span between the anchors holds other units than the burst names.
    ///
    /// It holds as many positions as it held when the burst was typed, and
    /// other units than the span's own, or its own in another order: another
    /// write emptied it and filled it again, or rearranged it.
    SpanRefilled,
    /// The frame names a span its anchors cannot bound or do not name.
    Malformed(String),
}

impl fmt::Display for Unshiftable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Unshiftable::NoAnchors => write!(f, "the burst carries no anchors"),
            Unshiftable::NoLine => write!(f, "the line stands no longer"),
            Unshiftable::PastTheDeadline { elapsed_ms } => write!(f, "its first failed send was {} s ago, past the two-minute deadline", elapsed_ms / 1000),
            Unshiftable::Unread(why) => write!(f, "the document's image could not be read: {why}"),
            Unshiftable::NoSpan => write!(f, "its anchors name no span of the units it edits"),
            Unshiftable::AnchorLost(which) => write!(f, "its {which} anchor is in the document no longer"),
            Unshiftable::AnchorTwice(which) => write!(f, "its {which} anchor stands at two places in the document"),
            Unshiftable::SpanCut { between, were } => write!(f, "the span its anchors bound holds {between} positions now, not the {were} it held when the burst was typed"),
            Unshiftable::SpanRefilled => write!(f, "the span its anchors bound no longer holds the units the burst names, in their order"),
            Unshiftable::Malformed(why) => write!(f, "{why}"),
        }
    }
}

impl Unshiftable {
    /// Returns what this refusal says of a `send` of the line now.
    ///
    /// It answers none where the shift was not tried against the document:
    /// the line's deadline, which a `send` resets, or no line (skep #867). An
    /// image read that answered no image knows nothing; every other refusal
    /// is the shift's own, and a `send` would meet it.
    pub(super) fn tested(&self) -> Option<Tested> {
        match self {
            Unshiftable::NoLine | Unshiftable::PastTheDeadline { .. } => None,
            Unshiftable::Unread(_) => Some(Tested::Unknown),
            Unshiftable::NoAnchors
            | Unshiftable::NoSpan
            | Unshiftable::AnchorLost(_)
            | Unshiftable::AnchorTwice(_)
            | Unshiftable::SpanCut { .. }
            | Unshiftable::SpanRefilled
            | Unshiftable::Malformed(_) => Some(Tested::Sendable(false)),
        }
    }
}

/// What stopped a shift before it had an exact frame (§3c.5).
#[derive(Debug)]
enum ShiftStop {
    /// The shift cannot move the line exactly, or its image read answered no
    /// image ([`Unshiftable`]).
    Refused(Unshiftable),
    /// The death signal on the session's token met the image read.
    Died,
    /// The board gave the image read no answer.
    Unanswered(Halt),
}

/// Why a resend's shift was not made ([`Holds::send_line`]).
#[derive(Debug)]
enum NotShifted {
    /// The shift cannot move the line exactly: the document is held as moved.
    Unshiftable(Unshiftable),
    /// The turn has no step left for the shift ([`TURN_STEPS`]).
    ///
    /// Nothing is read, written or dialed: the line stands as its last dial
    /// left it, and its document waits for the drain's next pass.
    NoStep,
}

impl From<Unshiftable> for NotShifted {
    fn from(why: Unshiftable) -> NotShifted {
        NotShifted::Unshiftable(why)
    }
}

/// Which `id` a held line's dial goes out under (skep #971).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Dialing {
    /// A burst's first dial, and each shift its call makes: the page's `id`.
    First,
    /// A resend of the line: its dial id, readied before the dial leaves.
    Resend,
}

/// Takes no step: a first dial's shift spends none.
///
/// A first dial's shifts run within the page's `op` call, which no turn
/// bounds (`Holds::shift_at_first_dial`): the line's deadline alone ends
/// them ([`HAND_OVER_DEADLINE`]). A resend's shift spends one of its turn's
/// [`TURN_STEPS`] ([`Holds::send_line`]).
pub(super) fn no_step() -> Result<(), Unshiftable> {
    Ok(())
}

/// A shift's send ([`Holds::shift_and_send`]): the line shifted and dialed,
/// or no dial left.
#[derive(Debug)]
pub(super) struct Shifted {
    /// What the dial answered, or why no dial left.
    pub(super) dialed: Dialed,
    /// The frame on the line: shifted and dialed where the dial left, as it
    /// stood otherwise.
    pub(super) frame: Value,
    /// Whether the dial left — its attest composed, the mark made before
    /// it; false where the shift's read met the death signal or the attest
    /// could not be composed, nothing dialed and the line left as it was.
    pub(super) left: bool,
}

/// The span a burst's frame edits, in the V-positions it names.
///
/// It is what the anchors bound: `first`, the first position the burst
/// names, the unit before which is the `before` anchor; and `units`, the
/// positions that lay between the two anchors when the burst was typed,
/// whose units the anchors' `span` names — `None` for an insert, a copy or
/// a reinstate, which place at a point, nothing between the anchors; a
/// delete's `width`; a rearrange's cut span, its first cut to its last.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct EditedSpan {
    first: u64,
    units: Option<u64>,
}

impl EditedSpan {
    /// Returns the span `frame` edits, where its positions read.
    ///
    /// Every position is a content V-position (`subspace` 1) with an
    /// ordinal; a rearrange's cuts ascend.
    fn of(frame: &Value) -> Option<EditedSpan> {
        match frame["op"].as_str()? {
            // A placement at a point: the anchors are the units on either
            // side of `at`, nothing between them.
            "insert" | "copy" | "reinstate" => Some(EditedSpan { first: ordinal(&frame["at"])?, units: None }),
            // A removal: the anchors are the units on either side of the
            // `width` positions from `p`.
            "delete" => Some(EditedSpan { first: ordinal(&frame["p"])?, units: Some(nat(&frame["width"])?) }),
            // A rearrangement about its cuts: the anchors are the units on
            // either side of the span from the first cut to the last, every
            // cut moving with it.
            "rearrange" => {
                let cuts: Vec<u64> = frame["cuts"].as_array()?.iter().map(ordinal).collect::<Option<_>>()?;
                let (first, last) = (*cuts.first()?, *cuts.last()?);
                (cuts.windows(2).all(|w| w[0] < w[1])).then_some(EditedSpan { first, units: Some(last - first) })
            }
            _ => None,
        }
    }

    /// Returns how many positions lay between the anchors when it was typed.
    ///
    /// A placement at a point has none between them.
    fn interior(self) -> u64 {
        self.units.unwrap_or(0)
    }

    /// Returns `frame` with every position it names moved by `displacement`,
    /// typed against `as_of`.
    ///
    /// An insert's, a copy's or a reinstate's `at` moves; a delete's `p`; a
    /// rearrange's every cut — each re-spelled as the wire's natural. `None`
    /// where a moved ordinal is no position.
    fn displaced(self, frame: &Value, displacement: i128, as_of: u64) -> Option<Value> {
        let mut moved = frame.clone();
        let shift = |position: &mut Value| -> Option<()> {
            let ordinal = u64::try_from(i128::from(nat(&position["ordinal"])?).checked_add(displacement)?).ok().filter(|o| *o >= 1)?;
            position["ordinal"] = Value::from(ordinal.to_string());
            Some(())
        };
        match moved["op"].as_str()? {
            "insert" | "copy" | "reinstate" => shift(&mut moved["at"])?,
            "delete" => shift(&mut moved["p"])?,
            "rearrange" => {
                for cut in moved["cuts"].as_array_mut()? {
                    shift(cut)?;
                }
            }
            _ => return None,
        }
        moved["as_of"] = Value::from(as_of);
        Some(moved)
    }
}

/// A list of I-runs: each its I-prefix, its first position and its width.
type RunList<'a> = Vec<(&'a str, u64, u64)>;

/// Returns a natural as the wire spells it: a decimal string, or a number.
fn nat(v: &Value) -> Option<u64> {
    v.as_str().map_or_else(|| v.as_u64(), |text| text.parse().ok())
}

/// Returns a content V-position's ordinal: `{subspace: 1, ordinal}`.
fn ordinal(position: &Value) -> Option<u64> {
    (nat(&position["subspace"])? == 1).then(|| nat(&position["ordinal"])).flatten()
}

/// A document's content image as the shift reads it.
///
/// It is the runs one `image` read answered, in V-order from the first
/// position: the board's run decomposition (M5's runs tile the content prefix
/// contiguously), a run the document places twice answered at each place, so
/// every position stands here where the document arranges it. Made by
/// [`Image::of`] alone, which admits each run only where its every position
/// is within a `u64`, and the runs only where their positions end within one
/// at `past_end`, so no sum the shift makes over them passes a `u64`.
#[derive(Debug)]
struct Image<'a> {
    /// The runs, each its I-prefix, its first position and its width.
    runs: RunList<'a>,
    /// The V-position past the last run's: the image's extent plus one.
    past_end: u64,
}

impl<'a> Image<'a> {
    /// Returns the image an `image` read answered.
    ///
    /// An answer naming no runs, a run that is no I-extent — its start no
    /// I-address, its width none of 1 or more, or its positions past a
    /// `u64` — or runs whose positions pass every position, is no image.
    fn of(image: &'a Value) -> Result<Image<'a>, Unshiftable> {
        let answered = image["runs"].as_array().ok_or_else(|| Unshiftable::Unread("the image read answered no runs".into()))?;
        let runs = answered
            .iter()
            .map(|run| {
                let (prefix, first) = run["i_start"].as_str().and_then(i_address)?;
                let width = nat(&run["width"]).filter(|w| *w >= 1)?;
                first.checked_add(width - 1)?;
                Some((prefix, first, width))
            })
            .collect::<Option<Vec<_>>>()
            .ok_or_else(|| Unshiftable::Unread("a run the image read answered is no I-extent".into()))?;
        let past_end = runs.iter().try_fold(1u64, |v, (_, _, width)| v.checked_add(*width)).ok_or_else(|| Unshiftable::Unread("the image's runs pass every position".into()))?;
        Ok(Image { runs, past_end })
    }

    /// Returns the V-position `anchor` stands at, the `which` anchor.
    ///
    /// It is found in a run of the anchor's prefix holding its position, at
    /// the V-position the run gives it — in every run, so an anchor found
    /// at two places is refused, as one found nowhere is lost. A piece of a
    /// held insert's words names no unit an image holds, and places nothing.
    fn position_of(&self, anchor: &Anchor, which: &'static str) -> Result<u64, Unshiftable> {
        let anchor = anchor.address().ok_or(Unshiftable::NoAnchors)?;
        let (prefix, n) = i_address(anchor).ok_or_else(|| Unshiftable::Malformed(format!("the {which} anchor is no I-address")))?;
        let mut found = None;
        let mut v = 1u64;
        for &(run_prefix, first, width) in &self.runs {
            if run_prefix == prefix && n >= first && n - first < width {
                if found.is_some() {
                    return Err(Unshiftable::AnchorTwice(which));
                }
                found = Some(v + (n - first));
            }
            v += width;
        }
        found.ok_or(Unshiftable::AnchorLost(which))
    }

    /// Returns the runs the image arranges at `width` positions from `from`.
    ///
    /// They are its runs clipped to those positions, and joined
    /// ([`joined`]).
    fn runs_at(&self, from: u64, width: u64) -> RunList<'a> {
        let to = from.saturating_add(width);
        let mut v = 1u64;
        let mut cut = Vec::new();
        for &(prefix, first, run_width) in &self.runs {
            let (lo, hi) = (v.max(from), (v + run_width).min(to));
            if lo < hi {
                cut.push((prefix, first + (lo - v), hi - lo));
            }
            v += run_width;
        }
        joined(cut)
    }
}

/// Returns `runs` with each run that continues the one before joined to it.
///
/// A run continues the one before where its prefix is the same and its
/// first position the one past the other's last. The joined list is the one
/// spelling two run lists compare in, however the board split a list's runs
/// when each was read.
fn joined<'a>(runs: impl IntoIterator<Item = (&'a str, u64, u64)>) -> RunList<'a> {
    let mut out: RunList<'a> = Vec::new();
    for (prefix, first, width) in runs {
        match out.last_mut() {
            Some(last) if last.0 == prefix && last.1.checked_add(last.2) == Some(first) => last.2 = last.2.saturating_add(width),
            _ => out.push((prefix, first, width)),
        }
    }
    out
}

/// Returns `frame` shifted by its anchors through the document's image.
///
/// The shifted frame is typed against `as_of` (skep #442, #751). The checks
/// of the frame and the anchors alone come first: the anchors bound the
/// span the frame names — a span at the document's start alone has no unit
/// before it — and name the units it holds where it holds some, a delete's
/// or a rearrange's `span` as many as the frame's span holds, and none for
/// an insert, a copy or a reinstate, which place at a point. Then the search
/// ([`Image::position_of`]): each anchor's I-address is found in `image`'s
/// runs — a run of the anchor's prefix holding its position — at the
/// V-position the run gives it; an anchor found nowhere is lost, and one
/// found at two places — a document arranging its I-address twice, as a
/// passage quoted twice does — gives the span no one place to stand. Then
/// the wholeness test, by identity: the positions between the two anchors
/// now — `before`'s V-position standing for 0 where the span began at the
/// document's start, `after`'s for the extent plus one where it reached the
/// end — are as many as lay between them when the burst was typed
/// ([`EditedSpan`]), and their units are the span's own, in its order: the
/// image's runs clipped to them and the span's runs, each list joined
/// ([`joined`]), equal run for run, however the board split either read's
/// runs. A placement's span holds nothing, so its anchors stand adjacent
/// still; a delete's or a rearrange's span another write cut, filled,
/// emptied and filled again with as many other units, or rearranged, is not
/// whole; and the shift is not made. The displacement is one for every
/// position: the `before` anchor's V-position plus one, less the first
/// position the burst named — so a change that sat wholly before the span
/// moves it by its width, one wholly after by nothing — applied to every
/// position the frame names ([`EditedSpan::displaced`]).
fn shifted_frame(frame: &Value, anchors: &Anchors, image: &Value, as_of: u64) -> Result<Value, Unshiftable> {
    let (span, named) = named_span(frame, anchors)?;
    let image = Image::of(image)?;
    let before = match &anchors.before {
        None => 0,
        Some(anchor) => image.position_of(anchor, "before")?,
    };
    let after = match &anchors.after {
        None => image.past_end,
        Some(anchor) => image.position_of(anchor, "after")?,
    };
    let were = span.interior();
    let between = after.checked_sub(before).and_then(|n| n.checked_sub(1)).ok_or(Unshiftable::SpanCut { between: 0, were })?;
    if between != were {
        return Err(Unshiftable::SpanCut { between, were });
    }
    if image.runs_at(before + 1, between) != named {
        return Err(Unshiftable::SpanRefilled);
    }
    let displacement = i128::from(before) + 1 - i128::from(span.first);
    span.displaced(frame, displacement, as_of).ok_or_else(|| Unshiftable::Malformed("a position the frame names moves to no position".into()))
}

/// Returns the anchors a shift of `line` places it by.
///
/// It answers [`Unshiftable::NoAnchors`] where the burst carried none, and
/// where an edge is a piece of a held insert's words (skep #969): a line
/// naming such words is sent only once the line it names has left the queue
/// and placed it (`held`'s module doc), so a piece here places nothing.
fn shifting_anchors(line: &HeldLine) -> Result<&Anchors, Unshiftable> {
    line.anchors.as_ref().filter(|anchors| !anchors.names_pieces()).ok_or(Unshiftable::NoAnchors)
}

/// Returns the span `frame` edits and the runs `anchors` name of it.
///
/// They are the checks of the frame and the anchors alone
/// ([`shifted_frame`]'s first): no image could make a shift exact where one
/// of them refuses.
fn named_span<'a>(frame: &Value, anchors: &'a Anchors) -> Result<(EditedSpan, RunList<'a>), Unshiftable> {
    let span = EditedSpan::of(frame).ok_or_else(|| Unshiftable::Malformed("the frame names no content positions the anchors could bound".into()))?;
    if anchors.before.is_none() != (span.first == 1) {
        return Err(Unshiftable::Malformed("the anchors do not bound the span the frame names: a span at the document's start alone has no unit before it".into()));
    }
    let named = match (span.units, &anchors.span) {
        (None, None) => Vec::new(),
        (None, Some(_)) => return Err(Unshiftable::Malformed("the anchors name a span of units, and the frame places at a point".into())),
        (Some(_), None) => return Err(Unshiftable::NoSpan),
        (Some(units), Some(runs)) => {
            if runs.iter().try_fold(0u64, |n, run| n.checked_add(run.extent().2)) != Some(units) {
                return Err(Unshiftable::Malformed(format!("the anchors' span names other than the {units} units the frame's span holds")));
            }
            joined(runs.iter().map(SpanRun::extent))
        }
    };
    Ok((span, named))
}

/// Reads the document's content image: the shift's one live read.
///
/// It is the read over the whole content window ([`IMAGE_WINDOW`]) under the
/// session, made outside every lock as every dial is.
///
/// # Errors
///
/// Returns [`ShiftStop::Refused`], [`Unshiftable::Unread`] within it, where
/// the read was refused or answered no document, [`ShiftStop::Died`] at the
/// death signal on the session's token and [`ShiftStop::Unanswered`] where
/// the board gave the read no answer.
fn read_image(session: &SessionEntry, doc: &str) -> Result<Value, ShiftStop> {
    match session.board.op(Some(&session.token), &frames::image(doc, 1, IMAGE_WINDOW)) {
        Ok(Answer::Document(v)) => match Rejection::of(&v) {
            None => Ok(v),
            Some(r) => Err(ShiftStop::Refused(Unshiftable::Unread(format!("the image read was refused {}", r.token())))),
        },
        Ok(Answer::Closed) => Err(ShiftStop::Died),
        Err(h) if unanswered(&h) => Err(ShiftStop::Unanswered(h)),
        Err(h) => Err(ShiftStop::Refused(Unshiftable::Unread(h.to_string()))),
    }
}

/// Runs the shift a `send` of `head` would run, against its document now.
///
/// It is [`shifted_frame`] over one live read, the shifted frame dropped: no
/// read is made where the frame and its anchors alone refuse the shift. A
/// `send` resets the line's deadline, so the deadline is not read.
///
/// # Errors
///
/// Returns what stopped the shift ([`ShiftStop`]).
fn shift_as_a_send_would(session: &SessionEntry, head: &HeldLine) -> Result<(), ShiftStop> {
    let anchors = shifting_anchors(head).map_err(ShiftStop::Refused)?;
    named_span(&head.frame, anchors).map_err(ShiftStop::Refused)?;
    let image = read_image(session, &head.doc)?;
    let as_of = image["as_of"].as_u64().unwrap_or(0);
    shifted_frame(&head.frame, anchors, &image, as_of).map(|_| ()).map_err(ShiftStop::Refused)
}

/// The outcome of the hold's one read for a line's landing (§3c.5).
///
/// The read answers whether the document's head's own write landed, and
/// nothing more: whether the document moved is the board's verdict on the
/// send ([`Holds::send_line`]'s moved arm), never the read's. Two readers
/// take it. The resend sends the head wherever no landing was found
/// ([`ReadOutcome::NoLanding`], [`ReadOutcome::Undecided`]), the board
/// judging the send's typed state. The drop of a line whose answer was lost
/// drops the line only where no row could be its landing, and refuses where
/// the read cannot tell (`Holds::resolve`; skep #866).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum ReadOutcome {
    /// No row since `base` could be the head's own landing.
    ///
    /// Every row read is no verdict: the person's own later write of another
    /// kind, a sibling's, another hand's.
    NoLanding,
    /// A row since `base` could be the head's landing, and is not confirmed.
    ///
    /// It is a row whose testimony the board lost, on a kind no site read
    /// confirms; a row of the session's own hand or of a lost testimony
    /// whose site holds other values than the head's, the landing moved
    /// since or no landing; or a `history_reclaimed`, no row read, the site
    /// confirming nothing.
    Undecided,
    /// The in-flight burst landed — the head is `done kept` with this `at`.
    ///
    /// The position, where the read names one, becomes the document's base,
    /// as an ack's does (§3c.2), and joins the board's acked positions.
    /// `minted` is the first I-address the head's words stand at, read where
    /// a line's anchors name them ([`Holds::minted_at`]; skep #969).
    Landed { at: Option<u64>, minted: Option<String> },
    /// The board answered no page: nothing is decided.
    ///
    /// It answered a refusal (`feed_rebuilding`) or an answer no read takes
    /// — or the site read the landing needed did — and the next probe reads
    /// again.
    Unread,
    /// The board gave the read no answer: nothing is decided.
    ///
    /// The read is the document's, or the site read the landing needed; the
    /// pass ends there.
    Unanswered,
    /// The death signal on the session's token met the read or its site read.
    ///
    /// Nothing is decided: it is the session's death and no verdict on the
    /// line (§3c.4).
    Died,
}

/// What a step of the walk at a document leaves the walk to do (§3c.5).
///
/// The step is a document's read ([`Holds::resume_doc`]) or a line's send
/// ([`Holds::send_line`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Step {
    /// The document's lines go on.
    Goes,
    /// The document stops for the pass (`PrincipalHold::stopped_in_pass`).
    Stops,
    /// The board gave the step's request no answer: the pass ends there.
    ///
    /// The document is entered among those the silence cut
    /// (`PrincipalHold::cut_in_pass`).
    Unanswered,
}

/// Which documents a walk of the drain's turn takes (§3c.5; skep #863).
///
/// A turn walks every principal's documents in [`Round::Unreached`] first,
/// then in [`Round::Cut`], so the documents a pass the board's silence ended
/// did not reach go before the ones it cut, whoever's they are.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Round {
    /// Every document but those the board's silence cut the pass at.
    Unreached,
    /// The documents the board's silence cut the pass at.
    ///
    /// They are taken out of the set as the walk begins
    /// (`PrincipalHold::cut_in_pass`).
    Cut,
}

/// What one `retrieve_v` at a held burst's site says of its values.
///
/// It is §3c.5's content confirm.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Site {
    /// The values read back equal: the burst stands there.
    ///
    /// `as_of` is the position the read answered at, where it names one: the
    /// state the address of the burst's words is read at (skep #969).
    Equal { as_of: Option<u64> },
    /// Other values, or none (the site out of the document's bounds).
    Differs,
    /// No read can decide.
    ///
    /// It is a burst of another kind than `insert`, or a frame that names no
    /// site.
    Unconfirmable,
    /// The board answered the read with no delivery: an answer no read takes.
    Unread,
    /// The board gave the read no answer (skep #863).
    Unanswered,
    /// The death signal on the session's token met the read.
    Died,
}

/// A board's drain mark (`BoardSlot`'s `draining`), held for one drain.
///
/// It is cleared when the drain ends — however it ends, a dial that unwinds
/// included — so no board stays marked by a drain that never finished.
#[derive(Debug)]
struct Draining<'h>(&'h AtomicBool);

impl<'h> Draining<'h> {
    /// Takes the mark: `None` where a drain of the board already runs.
    fn begin(mark: &'h AtomicBool) -> Option<Draining<'h>> {
        // No guard is built where no mark was taken: dropped, it would clear
        // the mark of the drain that holds it.
        (!mark.swap(true, Ordering::SeqCst)).then_some(Draining(mark))
    }
}

impl Drop for Draining<'_> {
    fn drop(&mut self) {
        self.0.store(false, Ordering::SeqCst);
    }
}

impl Holds {
    /// Runs the probe (§3c.4) and one turn of the resend (§3c.5) it lets run.
    ///
    /// It runs on the board's feed thread alone — every
    /// [`PROBE_CADENCE`](super::PROBE_CADENCE), at its daemon-running tick,
    /// at the hand-overs of `resolve(send)`, of a `resolve(drop)` that kept
    /// its line and of `set_node_state(Running)`, and after a turn its bound
    /// stopped, once the work queued behind that turn is served. First,
    /// whatever the board's state — its node stopped, the board away — the
    /// store's retry ([`Holds::retry_store`], §3c.1, §3c.3;
    /// skep #813, #821, #857, #859, #873): the board's locks this shell does
    /// not hold are tried again, each principal's queue is brought to the
    /// store as it stands — its file read where the device refused it before,
    /// the pending → chain change made where the board's own directory is
    /// this shell's now — and the copies each held file owes — a line's, a
    /// re-mark's or a `done`'s — are written where the device takes them
    /// (`HeldQueue::retry`), a wait that ends said ([`Holds::note_waiting`])
    /// and each document whose lines were written told so
    /// ([`Holds::say_landed`]): the retry needs no dial. A session told no
    /// face of such a document that stands moved is told it once the board's
    /// lock is let go, its hands read first where the board answers and the
    /// own node runs, and named not read otherwise
    /// ([`Holds::say_with_hands`]; skep #972) — before the drain's mark is
    /// asked, so a probe that finds another drain running says them too.
    /// Then, at a board whose own node is not stopped, one turn of the drain
    /// runs ([`Holds::drain`]), one drain per board at a time, a halted
    /// principal's lines never among them (P38; skep #858), where a session
    /// that may write stands — so a board that halts or whose head will not
    /// read is found with no line held, before any write meets it (§3c.3;
    /// P37; skep #865) — or a read is owed it with none
    /// ([`BoardHold::probe_owed`](super::BoardHold::probe_owed); skep #863).
    ///
    /// It answers [`Turn::Bounded`] where the turn stopped at its bound with
    /// a line still to send, the pass going on at the next turn;
    /// [`Turn::Unanswered`] where the board gave a request of the turn's no
    /// answer, the pass going on at the next probe it answers; and
    /// [`Turn::Done`] otherwise — the pass ended where this probe ran the
    /// drain, its stopped documents walked again by the next
    /// ([`BoardHold::end_pass`](super::BoardHold::end_pass)); a probe that
    /// finds another drain of the board running leaves that drain's pass as it
    /// stands.
    pub fn probe(&self, board_reference: &str) -> Turn {
        // Gathered under the lock and dialed outside it, so `op` never waits
        // on a dead board's connect timeout; the sessions' own lock is taken
        // before the board's and let go.
        let slot = self.slot(board_reference);
        let sessions = self.sessions.on_board(board_reference);
        let writer = sessions.iter().any(|session| session.may_write());
        let (due, owed) = {
            let mut board_hold = slot.lock();
            let owed = self.retry_store(board_reference, &mut board_hold, slot.board.dialed(), &sessions);
            (!board_hold.node_stopped && (writer || board_hold.probe_owed()), owed)
        };
        // The moved faces the landings owe their hands, each read outside the
        // lock as every dial is.
        for (session, owed) in owed {
            self.say_with_hands(&session, owed);
        }
        // One drain per board at a time, its mark cleared however it ends;
        // the drain that holds the mark alone ends the pass.
        let Some(_draining) = Draining::begin(&slot.draining) else { return Turn::Done };
        let turn = if due { self.drain(board_reference, slot) } else { Turn::Done };
        if turn == Turn::Done {
            slot.lock().end_pass();
        }
        turn
    }

    /// Runs the probe's dial and one turn of the resend.
    ///
    /// It is the body of [`Holds::probe`].
    ///
    /// It runs once per board at a time. First the probe's `/health`, the
    /// board's verdict ([`Holds::note_health_read`]; skep #863): one the board
    /// gives no answer to is its silence, the turn answering
    /// [`Turn::Unanswered`] with nothing walked, and one that answers with
    /// the board's writes halted, or refused — or one refused before any
    /// connection opened, which reached no board — holds every line, the head
    /// not read (skep #865). Then ONE read of the board's head
    /// (`sessions::board_head`) before any document (skep #727), with no line
    /// held too, bounded as every dial of the hold's is and outside the
    /// board's lock, a pair once read costing no dial (skep #865): the same
    /// answer establishes the directory ([`Holds::establish`]) and decides
    /// which documents the resend skips — never two reads in one probe for
    /// the hold's sake — and the board's head state is said once per change
    /// ([`Holds::note_head`]). A head read
    /// the board gives no answer to is its silence, never `head_unreadable`:
    /// the board marked unanswered, nothing walked. While the head answers
    /// `head_unreadable`, every document whose head line is held so is
    /// skipped: no `/changes` read, no `sending`, no attest attempted; the
    /// other documents resend as they do. The principals with lines walk in
    /// their order, each under a standing session of its own that may write
    /// (`SessionEntry::may_write`) — under no bare session — sharing the
    /// turn's [`TURN_STEPS`] steps ([`Holds::walk`]), every principal's
    /// documents the pass has not reached before any the board's silence cut
    /// it at ([`Round`]); a principal no session of which may write sends
    /// nothing, and the hands its moved faces were told not read are read in
    /// the pass's first round for the sessions told so, from the same steps
    /// ([`Holds::pay_hands_owed`]; skep #972). It answers [`Turn::Bounded`]
    /// where they ran out with a line still to send, or a hands read still
    /// owed, [`Turn::Unanswered`] where the board gave a
    /// request of a walk's no answer, no later walk made, and
    /// [`Turn::Done`] where every principal's walk reached its end, or the
    /// board holds every line.
    fn drain(&self, board_reference: &str, slot: &BoardSlot) -> Turn {
        let board = &slot.board;
        // The probe's one `/health` read (§3c.4): a board that does not answer
        // is silent, read again at the next probe, and one whose writes are
        // halted, or that this build cannot dial, holds every line.
        match self.note_health_read(board_reference, &board.health()) {
            Verdict::Silent => return Turn::Unanswered,
            Verdict::Undialed | Verdict::Holds => return Turn::Done,
            Verdict::Writes => {}
        }
        // The board answers and takes writes: the hold ends. The head is read
        // once; a directory no touch of the store could establish is tried
        // again with it, and each principal with lines resends them under a
        // session of its own that may write; a bare one, which reads alone,
        // sends none (foundations §3.3 state 3), so a principal with no other
        // session keeps its lines held.
        let head = board_head(board);
        self.note_head(board_reference, &head);
        self.establish(board_reference, slot, &head);
        if matches!(head, Err(Refusal::Unreachable(_))) {
            self.note_unanswered(&mut slot.lock(), None);
            return Turn::Unanswered;
        }
        let head_unreadable = matches!(head, Err(Refusal::Halt { name: Name::HEAD_UNREADABLE, .. }));
        // A halted principal's lines are walked never (P38; skep #858): the
        // halt may have been found as the store was established just now.
        let principals: BTreeSet<u64> = slot.lock().principals.iter().filter(|(_, ph)| ph.drains()).map(|(p, _)| *p).collect();
        let mut steps = TURN_STEPS;
        for round in [Round::Unreached, Round::Cut] {
            for &principal in &principals {
                let Some(session) = self.sessions.on_board(board_reference).into_iter().find(|s| s.facts.principal == principal && s.may_write()) else {
                    // No walk meets the documents of a principal no session of
                    // which may write: the hands its faces were told not read
                    // are read for the sessions told so.
                    if round == Round::Unreached {
                        match self.pay_hands_owed(board_reference, principal, &mut steps) {
                            Turn::Done => {}
                            stopped => return stopped,
                        }
                    }
                    continue;
                };
                match self.walk(&session, head_unreadable, &mut steps, round) {
                    Turn::Done => {}
                    stopped => return stopped,
                }
            }
        }
        Turn::Done
    }

    /// Walks one session's principal's lines in `k` order (§3c.5; skep #817).
    ///
    /// It is a turn's share of the pass: wire.md's resume-by-read (PUB-8.32)
    /// at the board the session stands at, every document the pass has
    /// stopped at passed over (`PrincipalHold::stopped_in_pass`). A document
    /// the turn has not met is decided at the first of its lines the walk
    /// reaches, its head, by [`Holds::resume_doc`] — its read, where its head
    /// may have landed, one of the turn's `steps`, made only where a step is
    /// left for the send it may let go, so no turn of the pass reads the
    /// document again — and where its lines do not go out now the pass stops
    /// at it. Each line of a
    /// document that goes out is sent ([`Holds::send_line`]), a step — a
    /// normal `op` under the session, as §3c.5 has "lines in `k` order across
    /// the board's documents, which keeps each document's order" — and each
    /// shift its send makes through a move of the document a step more, the
    /// turn's `steps` handed to the send; its document is stopped where the
    /// line awaits the person's act or its send stops it — a send that finds
    /// no step left for its next shift among them — the others going on.
    /// Each send settles its line, an ack taking it out of the queue, or
    /// stops its document, and each decision lets its document go or stops
    /// it, so the walk ends; each line is found by ordinal from the last one
    /// the walk handled on (`HeldQueue::next_after`), so a turn reads the
    /// queue once beside its steps, and each settle and count reads one
    /// document's entry alone (skep #816).
    /// `head_unreadable` is whether the probe's one read of the board's head
    /// answered so: the documents whose head line waits on the head are then
    /// passed over ([`passed_over`]). `round` is which documents the walk
    /// takes ([`Round`]; skep #863): in [`Round::Unreached`] every document
    /// the board's silence cut the pass at is passed over beside the stopped
    /// ones, and in [`Round::Cut`] those alone are walked, the set taken out
    /// as the walk begins, the walk none where it holds none. A moved
    /// document whose hands went unread is read for them as the walk meets
    /// it, under the walk's session and every other session told them not
    /// read, a step ([`Holds::reread_hands`]), and a moved head that owes its
    /// shift test is tested, a step ([`Holds::test_shift`]). It answers
    /// [`Turn::Bounded`]
    /// where a document's read or a line's send was owed a step and the turn
    /// had none left for it; [`Turn::Unanswered`] where the board gave a
    /// request of the walk's no answer, its document entered among those the
    /// silence cut the pass at (`PrincipalHold::cut_in_pass`) and nothing
    /// more walked, or where a request of the hold's elsewhere — a burst's
    /// first dial — went unanswered since the probe's verdict; and
    /// [`Turn::Done`] where the walk reached the principal's last line.
    fn walk(&self, session: &SessionEntry, head_unreadable: bool, steps: &mut usize, round: Round) -> Turn {
        let (board_reference, principal) = (session.board_reference.as_str(), session.facts.principal);
        // The second round walks the documents the board's silence cut the
        // pass at, and none where it cut none.
        if round == Round::Cut && !self.with_principal(board_reference, principal, |ph| !std::mem::take(&mut ph.cut_in_pass).is_empty()).unwrap_or(false) {
            return Turn::Done;
        }
        // The documents this turn let go, and the ordinal the walk handled
        // last: no line's ordinal is 0.
        let mut sending: HashSet<String> = HashSet::new();
        let mut after = 0u64;
        loop {
            // A request of the hold's the board gave no answer to since the
            // probe's verdict — a burst's first dial on another thread among
            // them — holds the walk too, until the next verdict.
            if !self.lock(board_reference).answers() {
                return Turn::Unanswered;
            }
            let next = self.with_principal(board_reference, principal, |ph| {
                let line = ph.queue.next_after(after, |doc| ph.stopped_in_pass.contains(doc) || ph.cut_in_pass.contains(doc))?;
                let parked = ph.queue.parked(line.k);
                let hands_owed = ph.hands_owed.contains_key(&line.doc);
                let test_owed = ph.shift_test_owed(&line);
                Some((line, parked, hands_owed, test_owed))
            });
            let Some((line, parked, hands_owed, test_owed)) = next.flatten() else { return Turn::Done };
            // A line parked on the pending file its queue's file took it from
            // waits for its copy to land (I5): its document stops at it.
            if parked {
                after = line.k;
                sending.remove(&line.doc);
                self.stop_in_pass(board_reference, principal, &line.doc);
                continue;
            }
            let step = if !sending.contains(&line.doc) {
                // A moved document whose hands went unread is read for them
                // as the walk meets it, a step (skep #863).
                if hands_owed {
                    let Some(left) = steps.checked_sub(1) else { return Turn::Bounded };
                    *steps = left;
                    if self.reread_hands(Some(session), board_reference, principal, &line.doc) == Step::Unanswered {
                        self.cut_in_pass(board_reference, principal, &line.doc);
                        return Turn::Unanswered;
                    }
                }
                // A moved head tested against its document as it now stands,
                // a step (skep #867).
                if test_owed {
                    let Some(left) = steps.checked_sub(1) else { return Turn::Bounded };
                    *steps = left;
                    if self.test_shift(session, &line) == Step::Unanswered {
                        self.cut_in_pass(board_reference, principal, &line.doc);
                        return Turn::Unanswered;
                    }
                }
                // A read is made only where the send it may let go can follow
                // it in this turn, so no later turn of the pass reads the
                // document again.
                if read_owed(&line, head_unreadable) {
                    if *steps < 2 {
                        return Turn::Bounded;
                    }
                    *steps -= 1;
                }
                let step = self.resume_doc(session, &line, head_unreadable);
                if step == Step::Goes {
                    sending.insert(line.doc.clone());
                } else {
                    after = line.k;
                }
                step
            } else if awaits_act(&line.reason) {
                after = line.k;
                Step::Stops
            } else {
                let Some(left) = steps.checked_sub(1) else { return Turn::Bounded };
                *steps = left;
                after = line.k;
                self.send_line(session, &line, steps)
            };
            match step {
                Step::Goes => {}
                Step::Stops => {
                    sending.remove(&line.doc);
                    self.stop_in_pass(board_reference, principal, &line.doc);
                }
                Step::Unanswered => {
                    self.cut_in_pass(board_reference, principal, &line.doc);
                    return Turn::Unanswered;
                }
            }
        }
    }

    /// Enters `doc` among the documents the pass has stopped at
    /// (`PrincipalHold::stopped_in_pass`): no later turn of the pass reads it
    /// or sends its lines.
    fn stop_in_pass(&self, board_reference: &str, principal: u64, doc: &str) {
        self.with_principal(board_reference, principal, |ph| ph.stopped_in_pass.insert(doc.to_string()));
    }

    /// Enters `doc` among the documents the board's silence cut the pass at.
    ///
    /// The next turn walks it after every document the pass did not reach
    /// (`PrincipalHold::cut_in_pass`).
    fn cut_in_pass(&self, board_reference: &str, principal: u64, doc: &str) {
        self.with_principal(board_reference, principal, |ph| ph.cut_in_pass.insert(doc.to_string()));
    }

    /// Reads the hands owed a principal no session of which may write.
    ///
    /// No walk meets `principal`'s documents at the board (§3c.5), so each
    /// document owed its hands (`PrincipalHold::hands_owed`) that the pass
    /// has not met (`PrincipalHold::stopped_in_pass`) is entered among those
    /// it met and read for the sessions told its hands not read
    /// ([`Holds::reread_hands`]; skep #972), a step of the turn's `steps`
    /// each. It answers [`Turn::Bounded`] where a document is owed its read
    /// and the turn has no step left, [`Turn::Unanswered`] where the board
    /// gave a read no answer — or a request of the hold's elsewhere went
    /// unanswered since the probe's verdict — and [`Turn::Done`] where the
    /// pass has met every document owed.
    fn pay_hands_owed(&self, board_reference: &str, principal: u64, steps: &mut usize) -> Turn {
        loop {
            if !self.lock(board_reference).answers() {
                return Turn::Unanswered;
            }
            let next = self.with_principal(board_reference, principal, |ph| ph.hands_owed.keys().find(|doc| !ph.stopped_in_pass.contains(*doc)).cloned()).flatten();
            let Some(doc) = next else { return Turn::Done };
            let Some(left) = steps.checked_sub(1) else { return Turn::Bounded };
            *steps = left;
            self.stop_in_pass(board_reference, principal, &doc);
            if self.reread_hands(None, board_reference, principal, &doc) == Step::Unanswered {
                return Turn::Unanswered;
            }
        }
    }

    /// Reads the unread hands of a moved document, and says them (§3c.5).
    ///
    /// A face of it named them not read before: their read went unanswered
    /// or was answered with no page, met the death signal or was not made.
    ///
    /// `doc` is owed its hands (`PrincipalHold::hands_owed`), the line the
    /// board's verdict rides named beside it. Where that line stands moved
    /// still, the hands are read as the moved hold reads them
    /// ([`Holds::hands_since_typed_state`]) under each session owed them: the
    /// walk's own, `walking`, where a walk reads them, and every other
    /// standing session of `principal`'s at the board whose last face of
    /// `doc` names them not read ([`Hand::UNREAD`]; skep #972), each
    /// session's own key deciding which hand is `own`. Each read that names
    /// them has the `held` event say the document `moved` again with them
    /// under its session, where the line still stands at the head as it was
    /// read; the debt is paid once every read has named them. A read the
    /// board gives no answer to marks the board unanswered and answers
    /// [`Step::Unanswered`], the debt standing; one it answers with no page,
    /// or the death signal, leaves the session's face as it stood and the
    /// debt standing, read again at the next pass. A line moved no more owes
    /// no hands. It answers [`Step::Goes`] otherwise, the walk going on to
    /// the document's head.
    fn reread_hands(&self, walking: Option<&SessionEntry>, board_reference: &str, principal: u64, doc: &str) -> Step {
        let owed = self.with_principal(board_reference, principal, |ph| {
            let judged = ph.hands_owed.get(doc).and_then(|&k| ph.queue.line(k)).filter(|line| line.reason.cause == cause::MOVED);
            if judged.is_none() {
                ph.hands_owed.remove(doc);
            }
            judged
        });
        let Some(judged) = owed.flatten() else { return Step::Goes };
        let standing = self.sessions.on_board(board_reference);
        let told_unread = |session: &SessionEntry| self.told(session, doc).is_some_and(|told| told.state == HeldState::Moved && told.hands.contains(&Hand::UNREAD));
        let others = standing.iter().filter(|s| s.facts.principal == principal && walking.is_none_or(|w| w.reference != s.reference) && told_unread(s));
        let mut paid = true;
        for session in walking.into_iter().chain(others.map(Arc::as_ref)) {
            match self.hands_since_typed_state(session, doc, Some(judged.k), &judged.reason) {
                HandsRead::Named(hands) => {
                    let face = self
                        .with_principal(board_reference, principal, |ph| {
                            let stands = ph.queue.reasons_on(doc).next().is_some_and(|(head, reason)| head == judged.k && *reason == judged.reason);
                            stands.then(|| (ph.lines_on(doc), if session.may_write() { ph.sendable_told(doc) } else { None }))
                        })
                        .flatten();
                    // A person's act moved the document on while the read was
                    // out: no session is told the face the read made.
                    let Some((lines, sendable)) = face else { return Step::Goes };
                    self.emit_held(session, doc, lines, HeldState::Moved, None, MovedFace { hands: &hands, sendable });
                }
                HandsRead::Unanswered => {
                    self.note_unanswered(&mut self.lock(board_reference), None);
                    return Step::Unanswered;
                }
                HandsRead::Unread | HandsRead::Died => paid = false,
            }
        }
        if paid {
            self.with_principal(board_reference, principal, |ph| {
                if ph.hands_owed.get(doc) == Some(&judged.k) {
                    ph.hands_owed.remove(doc);
                }
            });
        }
        Step::Goes
    }

    /// Tests a moved document's head against the text as it now stands.
    ///
    /// It is §3c.5's `sendable` (skep #867): owed where
    /// `PrincipalHold::shift_test_owed` says, and what a `send` would do
    /// ([`shift_as_a_send_would`]), changing nothing a `send` does. Its
    /// answer is entered under the lock again, and dropped where the line
    /// stands moved at the head no more — the person's `send` having handed
    /// it back while the read was out. A change to or from true, the one the
    /// page's act keys on, is told on the `moved` event ([`Holds::emit_held`]),
    /// its hands read first ([`Holds::hands_since_typed_state`]) as every
    /// moved face names them; an answer that moves nothing the page acts on
    /// tells nothing and reads no hands. A read the board gives no answer to
    /// marks the answer unknown and owed and the board unanswered, tells
    /// nothing and answers [`Step::Unanswered`]; a told change whose hands'
    /// read goes so is said with them not read, as a moved hold's is, and
    /// answers the same, and one whose hands' read the board answers with no
    /// page is said with them not read too, owed to the walk (skep #972). The
    /// death signal leaves the test owed for the session that stands next. It
    /// answers [`Step::Goes`] otherwise.
    fn test_shift(&self, session: &SessionEntry, head: &HeldLine) -> Step {
        let (board_reference, principal, doc, k) = (session.board_reference.as_str(), session.facts.principal, head.doc.as_str(), head.k);
        let tested = match shift_as_a_send_would(session, head) {
            Ok(()) => Tested::Sendable(true),
            Err(ShiftStop::Refused(why)) => why.tested().unwrap_or(Tested::Unknown),
            Err(ShiftStop::Died) => return Step::Goes,
            Err(ShiftStop::Unanswered(_)) => {
                self.with_principal(board_reference, principal, |ph| ph.note_tested(doc, k, Tested::Unknown, true));
                self.note_unanswered(&mut self.lock(board_reference), None);
                return Step::Unanswered;
            }
        };
        let tells = self.with_principal(board_reference, principal, |ph| tested.live() != ph.told_live(doc, k)).unwrap_or(false);
        let (hands, unanswered) = if tells {
            let Some(face) = self.hands_since_typed_state(session, doc, Some(k), &head.reason).face() else { return Step::Goes };
            face
        } else {
            (Vec::new(), false)
        };
        let told = self
            .with_principal(board_reference, principal, |ph| {
                ph.note_tested(doc, k, tested, false).then(|| {
                    if hands.contains(&Hand::UNREAD) {
                        ph.hands_owed.insert(doc.to_string(), k);
                    }
                    (ph.lines_on(doc), ph.sendable_told(doc))
                })
            })
            .flatten();
        let Some((lines, sendable)) = told else { return Step::Goes };
        if tells {
            if unanswered {
                self.note_unanswered(&mut self.lock(board_reference), None);
            }
            self.emit_held(session, doc, lines, HeldState::Moved, None, MovedFace { hands: &hands, sendable });
        }
        if unanswered {
            Step::Unanswered
        } else {
            Step::Goes
        }
    }

    /// Enters what a shift that was not made tested of line `k`, its document
    /// just held moved, and returns the `sendable` its `moved` event says.
    ///
    /// It is the moved hold's half of the shift test (§3c.5; skep #867): the
    /// shift a moved hold ran is the test, no second read, and a hold that
    /// tried no shift against the document enters nothing, the test owed.
    pub(super) fn note_shift_refused(&self, board_reference: &str, principal: u64, doc: &str, k: u64, why: &Unshiftable) -> Option<bool> {
        self.with_principal(board_reference, principal, |ph| {
            if let Some(tested) = why.tested() {
                ph.note_tested(doc, k, tested, false);
            }
            ph.sendable_told(doc)
        })
        .flatten()
    }

    /// Resumes one document by its read (resume-by-read, §3c.5).
    ///
    /// `head` is the document's head, its first standing line, as the walk
    /// reached it. It runs the read and its outcome — a landed head kept
    /// ([`Holds::keep_landing`]) — and answers whether the document's lines
    /// go out now ([`Step::Goes`]): a document the read sends from the head,
    /// no landing found or none confirmed, or whose landed head leaves lines
    /// behind it; never one whose head awaits the person's act, which is
    /// read never, nor one whose read decided nothing — the board answering
    /// no page, or the death signal, the line left standing for the session
    /// that stands next — nor one whose head it hands to the person: a head
    /// no landing of which the read found, its first failed send
    /// [`HAND_OVER_DEADLINE`] of the board's answering past or more
    /// ([`Holds::hand_over`]) — each [`Step::Stops`]. A read the board gives
    /// no answer to decides nothing and ends the pass ([`Step::Unanswered`];
    /// skep #863): the board marked unanswered, the line as it was, nothing
    /// said. The read runs first, so a landing it finds is kept and never
    /// handed over. A head no dial of which left (`sent` false) is not read
    /// at all: nothing of it can stand on the board, so it goes from the
    /// head — or is handed over, where its deadline has passed. A head held
    /// `head_unreadable` while the probe's read of the board's head answers
    /// so (`head_unreadable`) is skipped whole — no read, no `sending`,
    /// nothing said (skep #727): its send would fail the same way, and the
    /// `held` event and the `Talk` line were said once as the state began;
    /// it is tried again the probe the head reads. Whether a read is made is
    /// [`read_owed`]'s, which the walk counts it by.
    ///
    /// A landed head's `held` event names it, at the position the read found
    /// ([`LandedLine`]; skep #968), and no I-address: no ack names one.
    fn resume_doc(&self, session: &SessionEntry, head: &HeldLine, head_unreadable: bool) -> Step {
        let (board_reference, principal, doc) = (session.board_reference.as_str(), session.facts.principal, head.doc.as_str());
        if passed_over(head, head_unreadable) {
            return Step::Stops;
        }
        let outcome = if read_owed(head, head_unreadable) { self.read_outcome(session, doc, head) } else { ReadOutcome::NoLanding };
        match outcome {
            ReadOutcome::Unread | ReadOutcome::Died => Step::Stops,
            ReadOutcome::Unanswered => {
                self.note_unanswered(&mut self.lock(board_reference), None);
                Step::Unanswered
            }
            ReadOutcome::Landed { at, minted } => {
                self.keep_landing(&mut self.lock(board_reference), principal, head, at, minted.as_deref());
                let lines = self.lines_on(board_reference, principal, doc);
                let goes = lines.held > 0;
                self.say_kept(session, doc, lines, &LandedLine::of(head, at, None));
                if goes {
                    Step::Goes
                } else {
                    Step::Stops
                }
            }
            ReadOutcome::NoLanding | ReadOutcome::Undecided => {
                // No landing of the head was found: its first failed send two
                // minutes of the board's answering past or more, it is the
                // person's, dialed never again, the hand-over naming the wall
                // time since (§3c.4; skep #716, #863).
                if let Some((elapsed, last)) = self.since_first_failure(board_reference, principal, head.k) {
                    if elapsed.answering >= HAND_OVER_DEADLINE {
                        self.hand_over(session, head, &last, elapsed.wall);
                        return Step::Stops;
                    }
                }
                self.emit_held(session, doc, self.lines_on(board_reference, principal, doc), HeldState::Sending, None, MovedFace::default());
                Step::Goes
            }
        }
    }

    /// Reads the document once (§3c.5), to one of the outcomes.
    ///
    /// The read is `GET /changes?since=<base>&under=<doc>&drafts=true` under
    /// the session, the rows since `base` IN ORDER — a page whose `more`
    /// stands with no landing found read on from its `last`, at the route's
    /// default page and, where a page is too large to serve, at the limit
    /// that `fits`, as the feed's reads are — and it asks one question of a
    /// `sent` head: did its own write land? At most one held burst can have
    /// landed without its ack (§7b's single writer, the head), so THE FIRST
    /// ROW that is the head's landing is its landing, whatever rows follow
    /// it — the lines behind the head are nobody's to judge here: each is
    /// read as a head in its turn, and the board judges every send's typed
    /// state. A row is the landing where it is of the session's own hand
    /// ([`own_row`]), its `op` the head's, and the head's site does not
    /// contradict it — or where the board lost its testimony
    /// ([`testimony_lost`]: the `poisoned` burst a restart replays, a burst
    /// whose write panicked past its commit) and the site confirms it — AND
    /// it stands at no position this shell acked
    /// ([`BoardHold::acked`](super::BoardHold::acked)): a row of the same key
    /// and kind at an acked position is a sibling's write through this shell,
    /// answered, never the lost landing; a row of the same key not through
    /// this shell — the `skep` command's — the set cannot tell apart, named as
    /// the residue. The site ([`Holds::site`])
    /// is the document's now, read once for the first row that asks for it:
    /// an `insert` whose values stand at its site landed; one whose values do
    /// not is no landing the read can confirm, so the read ends there
    /// [`ReadOutcome::Undecided`]; a kind no read confirms trusts the own
    /// hand and the op alone, and trusts a row whose hand is lost not at all,
    /// such a row leaving the read undecided where no later row is the
    /// landing. Every other row — the person's own later write of another
    /// kind, a sibling's, another hand's — is no verdict: whether the
    /// document moved is the board's (`arrangement_moved`,
    /// [`Holds::send_line`]), not this read's. A page, or the site read, the
    /// board gives no answer to is [`ReadOutcome::Unanswered`] (skep #863),
    /// the death signal at either is [`ReadOutcome::Died`], and every other
    /// answer that is no page [`ReadOutcome::Unread`]. It is the resend's
    /// read and the drop's (`Holds::resolve`; skep #866), made outside every
    /// lock.
    pub(super) fn read_outcome(&self, session: &SessionEntry, doc: &str, head: &HeldLine) -> ReadOutcome {
        let board_reference = session.board_reference.as_str();
        let mut query = ChangesQuery { since: head.base, under: Some(doc), drafts: true, limit: None };
        // The site is the document's, not a row's: read once, for the first
        // row that asks.
        let mut site = None;
        // Whether a row read so far could be the landing, and is not confirmed.
        let mut undecided = false;
        loop {
            let page = match session.board.changes(Some(&session.token), &query) {
                Ok(ChangesAnswer::Page(page)) => page,
                // `base` lies below the feed's floor — a hole in the feed's
                // files (wire.md §`/changes`): the arrangement alone decides.
                Ok(ChangesAnswer::HistoryReclaimed { .. }) => return self.reclaimed_outcome(session, doc, head),
                // A page past the board's budget is re-asked at the limit that
                // fits, as `feed::page_from` re-asks it; the client refuses a
                // `fits` that does not shrink the page, so the re-asks end.
                Ok(ChangesAnswer::TooLarge { fits }) => {
                    query.limit = Some(fits);
                    continue;
                }
                Ok(ChangesAnswer::Closed) => return ReadOutcome::Died,
                Err(h) if unanswered(&h) => return ReadOutcome::Unanswered,
                Ok(_) | Err(_) => return ReadOutcome::Unread,
            };
            for row in &page.changes {
                let at = row["at"].as_u64();
                // A write this shell was answered for is never the lost landing.
                if at.is_some_and(|at| self.acked(board_reference, at)) {
                    continue;
                }
                let own = own_row(session, row) && row["op"].as_str() == head.frame["op"].as_str();
                if !own && !testimony_lost(row) {
                    continue;
                }
                let (landed, as_of) = match *site.get_or_insert_with(|| self.site(session, doc, head)) {
                    Site::Equal { as_of } => (true, as_of),
                    // A kind the site read cannot confirm trusts the op-and-hand
                    // match; a row whose hand the board lost has none to trust.
                    Site::Unconfirmable => (own, None),
                    // The head's values do not stand at its site: the row is no
                    // landing the read can confirm, nor any row after it.
                    Site::Differs => return ReadOutcome::Undecided,
                    Site::Unread => return ReadOutcome::Unread,
                    Site::Unanswered => return ReadOutcome::Unanswered,
                    Site::Died => return ReadOutcome::Died,
                };
                if landed {
                    return self.landed(session, doc, head, at, as_of);
                }
                undecided = true;
            }
            if !page.more {
                return if undecided { ReadOutcome::Undecided } else { ReadOutcome::NoLanding };
            }
            query.since = page.last;
            query.limit = None;
        }
    }

    /// Returns the outcome of a `history_reclaimed` on the read (§3c.5).
    ///
    /// No row can be read, so the arrangement alone decides the one
    /// question: a `sent` head's values read back equal at its site is (ii),
    /// kept with no position to name; any difference, or a kind no read
    /// confirms, is no landing confirmed ([`ReadOutcome::Undecided`]), and
    /// the resend sends the head from the head — the board judging its typed
    /// state (`arrangement_moved`), as it judges every send; a site read the
    /// board answers with no delivery decides nothing, the death signal at it
    /// is the session's, and one it gives no answer to decides nothing and
    /// ends the pass.
    fn reclaimed_outcome(&self, session: &SessionEntry, doc: &str, head: &HeldLine) -> ReadOutcome {
        match self.site(session, doc, head) {
            Site::Equal { as_of } => self.landed(session, doc, head, None, as_of),
            Site::Differs | Site::Unconfirmable => ReadOutcome::Undecided,
            Site::Unread => ReadOutcome::Unread,
            Site::Unanswered => ReadOutcome::Unanswered,
            Site::Died => ReadOutcome::Died,
        }
    }

    /// Returns the outcome of a head the read found landed at `at`.
    ///
    /// Where a line's anchors name the head's words (skep #969), the address
    /// they were minted at is read first, at `as_of`, the position the site
    /// read answered at ([`Holds::minted_at`]): a read that decides nothing
    /// is the outcome, so the head stands and is read again — the pieces
    /// naming its words never dropped for a read the board left unanswered —
    /// and a read that names no address keeps the head with none.
    fn landed(&self, session: &SessionEntry, doc: &str, head: &HeldLine, at: Option<u64>, as_of: Option<u64>) -> ReadOutcome {
        let named = self.with_principal(&session.board_reference, session.facts.principal, |ph| ph.queue.is_named(head.k)).unwrap_or(false);
        if !named {
            return ReadOutcome::Landed { at, minted: None };
        }
        match self.minted_at(session, doc, head, as_of) {
            Ok(minted) => ReadOutcome::Landed { at, minted },
            Err(decides_nothing) => decides_nothing,
        }
    }

    /// Reads the first I-address a landed insert's words stand at.
    ///
    /// It is one `image` of the head's site — its frame's `at`, as wide as its
    /// values — through `/op-at` at `as_of`, the position the site read
    /// confirmed its values at, so a write since names no other unit there
    /// (wire.md §Reading history). The address is taken where the answer is one
    /// run of that width in the document's own content I-space, which an insert
    /// mints into; any other answer — a refusal, a reclaimed position, other
    /// runs, a site read that named no position — names none (`Ok(None)`). It
    /// is made only where a line's anchors name the head's words (skep #969).
    ///
    /// # Errors
    ///
    /// Returns the outcome that decides nothing: [`ReadOutcome::Unanswered`]
    /// where the board gave the read no answer, [`ReadOutcome::Died`] at the
    /// death signal on the session's token, and [`ReadOutcome::Unread`] where
    /// every reconstruction permit was in use (`history_busy`) or the answer
    /// could not be read, the next probe reading again.
    fn minted_at(&self, session: &SessionEntry, doc: &str, head: &HeldLine, as_of: Option<u64>) -> Result<Option<String>, ReadOutcome> {
        let from = head.frame["at"]["ordinal"].as_str().and_then(|o| o.parse::<u64>().ok());
        let (Some(as_of), Some(from), Ok(values)) = (as_of, from, values_of(&head.frame["values"])) else { return Ok(None) };
        let width = values.len() as u64;
        match session.board.op_at(Some(&session.token), as_of, &frames::image(doc, from, width)) {
            Ok(AtAnswer::Document(v)) if Rejection::of(&v).is_none() => {
                let own = format!("{doc}.0.1");
                let runs = v["runs"].as_array().map(Vec::as_slice).unwrap_or_default();
                let minted = match runs {
                    [run] if nat(&run["width"]) == Some(width) => run["i_start"].as_str().filter(|i| i_address(i).is_some_and(|(prefix, _)| prefix == own)),
                    _ => None,
                };
                Ok(minted.map(str::to_owned))
            }
            Ok(AtAnswer::Closed) => Err(ReadOutcome::Died),
            Ok(AtAnswer::Busy) => Err(ReadOutcome::Unread),
            // The board answered, and named no address: a refusal of the
            // read, the position reclaimed or none of its giving.
            Ok(_) | Err(Halt::Refused(_)) => Ok(None),
            Err(h) if unanswered(&h) => Err(ReadOutcome::Unanswered),
            Err(_) => Err(ReadOutcome::Unread),
        }
    }

    /// Confirms an `insert`'s site by its content (§3c.5).
    ///
    /// It makes one `retrieve_v` at the site, as wide as the values its frame
    /// spells, the delivery read back as values and held to them, and the
    /// position it answered at kept beside an equal one (skep #969).
    fn site(&self, session: &SessionEntry, doc: &str, head: &HeldLine) -> Site {
        if head.frame["op"].as_str() != Some("insert") {
            return Site::Unconfirmable;
        }
        let ordinal = head.frame["at"]["ordinal"].as_str().and_then(|o| o.parse::<u64>().ok());
        let (Ok(want), Some(from)) = (values_of(&head.frame["values"]), ordinal) else { return Site::Unconfirmable };
        match session.board.op(Some(&session.token), &frames::retrieve_v(doc, from, want.len() as u64)) {
            Ok(Answer::Document(v)) if Rejection::of(&v).is_none() => {
                if delivers(&v, &want) {
                    Site::Equal { as_of: v["as_of"].as_u64() }
                } else {
                    Site::Differs
                }
            }
            Ok(Answer::Document(_)) => Site::Differs,
            Ok(Answer::Closed) => Site::Died,
            Err(h) if unanswered(&h) => Site::Unanswered,
            Err(_) => Site::Unread,
        }
    }

    /// Keeps `line`, whose write the read found landed at `at` (§3c.5).
    ///
    /// `board_hold` is the board's hold, under its lock. The landing is noted
    /// as the session's ack is (§3c.2): `at` joins the board's acked
    /// positions, so no read takes its row for another line's landing, and
    /// becomes the base of the next hold on its document and the principal's
    /// latest arrangement write there — a held line is a burst — each where
    /// it is past the position noted, a later write noted since the read
    /// standing; the line is `done kept` with `at`. `minted` is the first
    /// I-address its words stand at, where the read found one
    /// ([`Holds::minted_at`]): the pieces naming the words are placed there,
    /// and the insert is noted among the principal's landed inserts, as an
    /// ack is (skep #969). It is the resend's keep of a head
    /// ([`Holds::resume_doc`]) and the drop's, where the read the drop makes
    /// first finds the line landed (`Holds::resolve`; skep #866), each caller
    /// saying the `held` event that names the line kept at `at`
    /// ([`LandedLine`]; skep #968).
    pub(super) fn keep_landing(&self, board_hold: &mut BoardHold, principal: u64, line: &HeldLine, at: Option<u64>, minted: Option<&str>) {
        if let Some(at) = at {
            board_hold.acked.insert(at);
        }
        if let Some(ph) = board_hold.principals.get_mut(&principal) {
            if let Some(at) = at {
                ph.note_position(&line.doc, at);
                ph.note_arranged(&line.doc, at);
            }
            if let Some(minted) = minted {
                ph.note_landed_insert(&line.frame, minted);
            }
            self.keep_line(principal, ph, line.k, at, minted);
        }
    }

    /// Sends one held line as the `op` it is, under the session that stands.
    ///
    /// Its attest is composed now (§3c.2), the line marked as one that may have
    /// landed before the dial leaves, and the line settled by what the dial
    /// answered: an ack `done kept`, the pieces naming an insert's words placed
    /// at the address its ack minted (skep #969); the line refused as typed
    /// against an older state of its document shifted through the change and
    /// dialed again ([`Holds::shift_and_send`]), each shift one of the turn's
    /// `steps` — its answer settled here as any dial's is, the verdict again
    /// shifting it again as far as the turn's steps and the line's deadline let
    /// it, and a turn with no step left for the next shift leaving the line as
    /// its last dial left it, the cause it was held with, its `sent` and the
    /// frame its last shift wrote, for the drain's next pass, no `held` event
    /// emitted — or, where the shift is not exact, the document faced `moved`
    /// ([`Holds::mark_moved`]) — the one route to that face — the board's
    /// verdict kept on the line and the hands whose rows moved it named; a
    /// hold-class answer or a refused run re-marked and faced, the line keeping
    /// its `sent` — a resend that never left, or one the board refused, says
    /// nothing of an earlier dial's write (§3c.2); a reissue-class answer
    /// counted against the line and reissued at the next probe, so its second
    /// `write_busy` and its third `durability` hold it, as hold-class answers
    /// of the table's; any other code of the board's the table holds nowhere
    /// handed to the person at once, a refused run under the board's token with
    /// its verdict verbatim and its `sent` kept, through the door a `permanent`
    /// refusal takes, since it cannot resolve (§3c.4; skep #720); a refusal of
    /// the shell's own — a request refused before any connection, or an attest
    /// that could not be composed — left standing for the next probe, never
    /// `done`; the death signal — at the dial, at the shift's read, or at the
    /// read of the hands, before anything is marked — left to the caller that
    /// ends the session, the line standing as its dial left it: the session
    /// that stands resends it after its read. A request the board gives no
    /// answer to — the dial, a read the attest's composer made, the shift's
    /// live read — ends the pass ([`Step::Unanswered`]; skep #863): the line
    /// re-marked `unreachable`, its `sent` kept, its document's `held` event
    /// back to `holding`, nothing said and no failure noted, the board marked
    /// unanswered and the send owed to the next probe's verdict where its
    /// request may have left (`Holds::note_unanswered`); a shift whose read
    /// went so is untried, its verdict kept (`PrincipalHold::shift_owed`), and
    /// the line's next send starts at it, the shift run and no stale frame
    /// dialed first. A moved face whose hands' read the board gives no answer
    /// to stands on the verdict, its hands named not read ([`Hand::UNREAD`]),
    /// owed (`PrincipalHold::hands_owed`), and ends the pass too; one whose
    /// hands' read the board answers with no page names them so, owed, the
    /// line's document stopping as any moved one does (skep #972). Every failed
    /// send of the line ([`Dialed::failure`]) is noted on its clock
    /// ([`HAND_OVER_DEADLINE`]), and a line left standing — for the next probe,
    /// or for the drain's next pass — says so where a failure this send met
    /// changed the last failure's token, so once per change (SP-11).
    /// [`Step::Goes`] where the line is settled and sending goes on,
    /// [`Step::Stops`] where the line's document stops at it.
    ///
    /// **The landed test comes first.** This runs for a line
    /// [`Holds::resume_doc`] let go alone — a `sent` head read for its own
    /// landing and found unlanded — so no line is shifted before its read,
    /// and a landing the read keeps is shifted never.
    ///
    /// **The ack names the line.** An ack's `held` event names the line kept,
    /// the ack's position and an insert's minted I-address ([`LandedLine`];
    /// skep #968): the page's one word of a line's ack once its `op` answered
    /// `held`.
    ///
    /// **Under the line's dial id** (skep #971). Each dial this send makes,
    /// its shifts' among them ([`Dialing::Resend`]), goes out under the line's
    /// dial id, named as the line is first readied (`Holds::ready_to_resend`),
    /// never the page's `id`, which another line of the principal's can carry
    /// too: an ack is then the line's own. The page's first dial alone went
    /// out under the page's `id`, so a resend of a burst that landed there is
    /// never answered from that dial's memo entry: the board judges it by the
    /// state it was typed against, and its shift holds it moved where the
    /// words it landed stand between its anchors.
    fn send_line(&self, session: &SessionEntry, line: &HeldLine, steps: &mut usize) -> Step {
        let (board_reference, principal) = (session.board_reference.as_str(), session.facts.principal);
        let given = || self.with_principal(board_reference, principal, |ph| ph.reissues.get(&line.k).cloned()).flatten().unwrap_or_default();
        // A shift the board's silence left untried runs first, from the
        // verdict it kept: nothing dialed before it (`left` false).
        let kept = self.with_principal(board_reference, principal, |ph| ph.shift_owed.remove(&line.k)).flatten();
        // The line is marked as one that may have landed before its dial
        // leaves (§3c.2's `sent`), synced, so a crash or a refused write
        // between the dial and its answer never leaves a write that may have
        // landed read as one never sent, and names its dial id in the same
        // copy where it names none, the `id` the dial goes out under (skep
        // #971); a line carrying both already writes nothing. The mark stands
        // whatever the dial answers, a connection never made among them, and
        // a copy the device refuses is owed, written by the retry, and the
        // dial made all the same — a close while it is owed relaunches the
        // line as one never sent. A line that left the queue as it was
        // readied — a person's drop the walk's read did not see — is sent
        // nothing. An attest that could not be composed dials nothing and
        // marks nothing: the line keeps its own `sent`, and nothing left
        // (`left` false).
        let (mut dialed, mut sent, mut left) = match kept {
            Some(KeptShift { reason, refusal }) => (Dialed::Held { reason, refusal }, line.reason.sent, false),
            None => match self.attest_where_owed(session, &line.frame) {
                Ok(frame) => {
                    let Some(dial_id) = self.with_principal(board_reference, principal, |ph| self.ready_to_resend(principal, ph, line.k)).flatten() else { return Step::Goes };
                    (self.dial(session, &frame.under(&dial_id), &given()), true, true)
                }
                Err(why) => (Dialed::from(why), line.reason.sent, false),
            },
        };
        // The frame the dial sent, for its ack's noting: the line's, or the
        // shifted one.
        let mut frame = Cow::Borrowed(&line.frame);
        // Whether a failure this send met changed the line's last failure's
        // token: a line its turn's steps leave for the next pass says so
        // once per change (SP-11), whichever refusal of its shifts made it.
        let mut changed = false;
        // The verdict the shift this send tries runs from, kept where the
        // board gives the shift's live read no answer.
        let mut shifting: Option<KeptShift> = None;
        loop {
            // A failed send of the line notes its token on the line's clock:
            // `Some(true)` where the token differs from the last failure's as
            // it stood, a line's first failure among them; `Some(false)` where
            // it repeats it, said already; none where no send failed — an
            // ack, the death signal, a request the board gave no answer to, or
            // a dial that never left.
            let failed = if left { dialed.failure().map(|token| self.note_failure(board_reference, principal, line.k, token)) } else { None };
            changed |= failed == Some(true);
            match dialed {
                Dialed::Acked(ack) => {
                    self.note_ack(session, &frame, &ack);
                    let at = acked_at(&ack);
                    self.keep(board_reference, principal, line.k, at, minted_by(&frame, &ack));
                    let rest = self.lines_on(board_reference, principal, &line.doc);
                    self.say_kept(session, &line.doc, rest, &LandedLine::of(line, at, acked_addr(&ack)));
                    return Step::Goes;
                }
                Dialed::Held { reason, refusal } if reason.cause == cause::MOVED => {
                    // The board refused the line as typed against an older
                    // state of its document: shifted through the change where
                    // the shift is exact, and dialed again, each shift a step
                    // of the turn; else the document is faced moved — the
                    // board's verdict the one judge of a move — each line
                    // keeping its own `sent`, the line refused keeping the
                    // verdict, and named by the hands whose rows moved it
                    // since the line's typed state, or since the person's last
                    // `send` on it where that is later (§3c.5).
                    let verdict = reason.refusal.clone().unwrap_or(Value::Null);
                    let kept = KeptShift { reason: reason.clone(), refusal: refusal.clone() };
                    let step = || -> Result<(), NotShifted> {
                        *steps = steps.checked_sub(1).ok_or(NotShifted::NoStep)?;
                        Ok(())
                    };
                    match self.shift_and_send(session, line.k, &verdict, Dialing::Resend, step, |shifted| self.dial(session, shifted, &given())) {
                        Ok(shifted) => {
                            shifting = Some(kept);
                            sent |= shifted.left;
                            left = shifted.left;
                            frame = Cow::Owned(shifted.frame);
                            dialed = shifted.dialed;
                        }
                        // The turn has no step left for the shift: the line
                        // stands as its last dial left it — the cause it was
                        // held with, its `sent`, the frame its last shift
                        // wrote — and its document waits for the drain's next
                        // pass, faced `sending` still, as its read let it go;
                        // a verdict this send started from, no dial made, is
                        // kept for it.
                        Err(NotShifted::NoStep) => {
                            if !left {
                                self.with_principal(board_reference, principal, |ph| ph.shift_owed.insert(line.k, kept));
                            }
                            if changed {
                                self.say(format_args!(
                                    "line {} on {} was not taken ({refusal}) and the turn has no step left to shift it; it is shifted and sent again at the drain's next pass",
                                    line.k, line.doc
                                ));
                            }
                            return Step::Stops;
                        }
                        Err(NotShifted::Unshiftable(why)) => {
                            // The hands are read before anything is marked:
                            // the death at the read leaves the line standing,
                            // as the death at its dial does; the board's
                            // silence at it, or an answer with no page, faces
                            // the document moved, its hands not read.
                            let Some((hands, unanswered)) = self.hands_since_typed_state(session, &line.doc, Some(line.k), &reason).face() else { return Step::Stops };
                            self.say(format_args!("line {} on {} was not shifted ({why}); the document is held as moved", line.k, line.doc));
                            self.mark_moved(board_reference, principal, &line.doc, reason.refusal.map(|verdict| (line.k, verdict)));
                            if hands.contains(&Hand::UNREAD) {
                                self.with_principal(board_reference, principal, |ph| ph.hands_owed.insert(line.doc.clone(), line.k));
                            }
                            if unanswered {
                                self.note_unanswered(&mut self.lock(board_reference), None);
                            }
                            let sendable = self.note_shift_refused(board_reference, principal, &line.doc, line.k, &why);
                            self.emit_held(session, &line.doc, self.lines_on(board_reference, principal, &line.doc), HeldState::Moved, None, MovedFace { hands: &hands, sendable });
                            return if unanswered { Step::Unanswered } else { Step::Stops };
                        }
                    }
                }
                Dialed::Unanswered { reason, refusal } => {
                    // The board gave the request no answer: the line holds
                    // `unreachable`, its `sent` kept, the shift its read left
                    // untried keeping its verdict, and its document goes back
                    // to `holding`; the next probe's verdict decides whether
                    // a send that may have left was the line's own failure.
                    let cut = (left && reason.sent).then(|| CutSend { principal, k: line.k, doc: line.doc.clone(), at: self.now(), refusal: refusal.to_string() });
                    self.with_principal(board_reference, principal, |ph| {
                        if let Some(kept) = shifting.take().filter(|_| !left) {
                            ph.shift_owed.insert(line.k, kept);
                        }
                        self.remark_line(principal, ph, line.k, Reason::of(cause::UNREACHABLE, reason.sent || sent));
                    });
                    self.note_unanswered(&mut self.lock(board_reference), cut);
                    self.emit_held(session, &line.doc, self.lines_on(board_reference, principal, &line.doc), HeldState::Holding, Some(cause::UNREACHABLE), MovedFace::default());
                    return Step::Unanswered;
                }
                Dialed::Held { reason, refusal } => {
                    let state = line_state(&reason);
                    let said = reason.cause.clone();
                    // The line keeps its `sent`, the mark made before the dial
                    // included: a resend that never left, or one the board
                    // refused, says nothing of an earlier dial's write. The
                    // read decides at the next probe whether it landed.
                    let reason = Reason { sent: reason.sent || sent, ..reason };
                    self.with_principal(board_reference, principal, |ph| self.remark_line(principal, ph, line.k, reason));
                    // A failure the line stands through for the next probe is
                    // said once per change; a refused run's face is its
                    // `held` event, and a dial that never left is the
                    // board's outage, no failure of the line.
                    if failed == Some(true) && state == HeldState::Holding {
                        self.say(format_args!("line {} on {} was not taken ({refusal}); it is sent again at the next probe", line.k, line.doc));
                    }
                    self.emit_held(session, &line.doc, self.lines_on(board_reference, principal, &line.doc), state, Some(&said), MovedFace::default());
                    return Step::Stops;
                }
                Dialed::Reissue { kind, refusal } => {
                    // The rider's count (§3c.4), per line across its probes:
                    // the third `durability` holds it.
                    self.with_principal(board_reference, principal, |ph| ph.reissues.entry(line.k).or_default().note(kind));
                    if failed != Some(false) {
                        self.say(format_args!("line {} on {} was not taken ({refusal}); it is sent again at the next probe", line.k, line.doc));
                    }
                    return Step::Stops;
                }
                // The board's own verdict under a code the table holds
                // nowhere: it cannot resolve, so the line is the person's at
                // once (§3c.4; skep #720) — a refused run under the board's
                // token with its verdict verbatim, its `sent` kept, through
                // the door a `permanent` refusal takes, the lines behind it
                // waiting with it. A refusal of the board's that reached no
                // dial — a read the attest's composer made — is the shell's
                // own.
                Dialed::Faced(Refusal::Board(r)) if left => {
                    let token = r.token();
                    let reason = Reason { sent, ..Reason::refused(&token, r.body.clone()) };
                    self.with_principal(board_reference, principal, |ph| self.remark_line(principal, ph, line.k, reason));
                    self.say(format_args!("line {} on {} was not taken ({r}), a code the shell holds no row for; it is handed to the person, who may send it again or drop it", line.k, line.doc));
                    self.emit_held(session, &line.doc, self.lines_on(board_reference, principal, &line.doc), HeldState::Refused, Some(&token), MovedFace::default());
                    return Step::Stops;
                }
                // A refusal of the shell's own, which dialed nothing the
                // board judged and starts no clock: the line stands for the
                // next probe, and the refusal is said at each.
                Dialed::Faced(refusal) => {
                    if failed != Some(false) {
                        self.say(format_args!("line {} on {} was not taken ({refusal}); it is sent again at the next probe", line.k, line.doc));
                    }
                    return Step::Stops;
                }
                Dialed::Died => return Step::Stops,
            }
        }
    }

    /// Shifts a line the board refused as typed stale, and sends it again.
    ///
    /// It is the one function the first dial ([`Holds::shift_at_first_dial`])
    /// and the resend ([`Holds::send_line`]) call for a line the board refused
    /// as typed against an older state of its document (skep #442, #751), each
    /// spending its `step` and dialing as it does — a resend's shift one of
    /// its turn's [`TURN_STEPS`], refused where none is left
    /// ([`NotShifted::NoStep`]), a first dial's none ([`no_step`]) — under the
    /// `id` `dialing` names, the page's at a first dial and the line's dial id
    /// at a resend (skep #971), and each answered in a refusal type of its own
    /// (`E`), which carries [`Unshiftable`]'s reasons. `verdict` is the
    /// board's `arrangement_moved`,
    /// its `site.current` the floor the shifted frame is typed against. The
    /// line stands, with its anchors, its first failed send less than
    /// [`HAND_OVER_DEADLINE`] of the board's answering past — each refusal
    /// that brings a line here is a failed send of it, noted by the caller
    /// before it calls, so a document another writer keeps moving stops the
    /// shell at the line's deadline, the refusal naming the wall time since —
    /// and the step is taken, all before anything is read: a line with no
    /// anchors, or past its deadline, is held moved at once, whatever the
    /// turn has left. Then one live read is made, `image` over the whole
    /// content window ([`IMAGE_WINDOW`]) under the session, the one read of
    /// the shift (no `/changes`, no history: the anchors are found at any
    /// age); the anchors found in it at one place each and the span between
    /// them whole — the units it held when the burst was typed, in their
    /// order — every position the frame names moved
    /// by the one displacement ([`shifted_frame`]), the frame typed against
    /// the read's own `as_of`, the state its positions are true of, never
    /// below the verdict's `site.current`. The death signal the read meets is
    /// no reason the shift was not made: it is answered as a dial that never
    /// left and met the death ([`Dialed::Died`], `left` false, the line as it
    /// was), so each caller meets it as the death at its dial (§3c.4), never
    /// as a moved document; and a read the board gives no answer to leaves
    /// the shift untried, never inexact: it is answered as a request the
    /// board gave no answer to that dialed nothing ([`Dialed::Unanswered`],
    /// `left` false, the line as it was; skep #863), each caller keeping the
    /// verdict for the shift the board's answer runs. Then the frame is
    /// attested (an attest that cannot
    /// be composed dials nothing and writes nothing: the dial that never left,
    /// `left` false, the line as it was), written to the line before it is
    /// dialed — `HeldQueue::rewrite`, synced, a copy the device refuses owed
    /// and one the writer refuses said on `Talk` — and the line marked as one
    /// that may have landed where it is not so marked yet, a resend's in the
    /// copy that names the line's dial id where it names none
    /// (`Holds::ready_to_resend`), so a relaunch after the shifted answer is
    /// lost reads the landed test at the shifted positions; then dialed by
    /// `dial`, a resend's copy under the line's dial id
    /// ([`AttestedWhereOwed::under`]).
    ///
    /// # Errors
    ///
    /// Returns why the shift was not made, nothing written and nothing
    /// dialed — the first that holds, in this order:
    ///
    /// 1. no line of ordinal `k` stands ([`Unshiftable::NoLine`]);
    /// 2. the line carries no anchors ([`Unshiftable::NoAnchors`]);
    /// 3. its first failed send stands [`HAND_OVER_DEADLINE`] of the board's
    ///    answering past or more ([`Unshiftable::PastTheDeadline`]);
    /// 4. `step` refuses, nothing read: its refusal is answered;
    /// 5. the image read is refused, or answered with no image
    ///    ([`Unshiftable::Unread`]);
    /// 6. the shift is not exact ([`shifted_frame`]'s refusal);
    /// 7. at a resend, the line left the queue while the read was out, and
    ///    stands no more to be readied ([`Unshiftable::NoLine`]).
    pub(super) fn shift_and_send<E: From<Unshiftable>>(
        &self,
        session: &SessionEntry,
        k: u64,
        verdict: &Value,
        dialing: Dialing,
        step: impl FnOnce() -> Result<(), E>,
        dial: impl FnOnce(&AttestedWhereOwed<'_>) -> Dialed,
    ) -> Result<Shifted, E> {
        let (board_reference, principal) = (session.board_reference.as_str(), session.facts.principal);
        let line = self.line_of(board_reference, principal, k).ok_or(Unshiftable::NoLine)?;
        let anchors = shifting_anchors(&line)?;
        // The line's deadline (HAND_OVER_DEADLINE), read before the shift's
        // read: past it the line falls to the moved hold, the person's act,
        // the refusal naming the wall time since its first failed send.
        if let Some((elapsed, _)) = self.since_first_failure(board_reference, principal, k).filter(|(elapsed, _)| elapsed.answering >= HAND_OVER_DEADLINE) {
            return Err(Unshiftable::PastTheDeadline { elapsed_ms: millis(elapsed.wall) }.into());
        }
        // The step the read and the shifted dial cost (TURN_STEPS), taken
        // past every check that reads nothing.
        step()?;
        // The one live read, outside every lock as every dial is.
        let image = match read_image(session, &line.doc) {
            Ok(image) => image,
            Err(ShiftStop::Refused(why)) => return Err(why.into()),
            // The session's death, and no verdict on the document: no dial
            // leaves, and the caller meets the death as at its dial.
            Err(ShiftStop::Died) => return Ok(Shifted { dialed: Dialed::Died, frame: line.frame, left: false }),
            // The board's silence, and no verdict on the document either: the
            // shift is not tried and no dial leaves (skep #863).
            Err(ShiftStop::Unanswered(h)) => return Ok(Shifted { dialed: Dialed::unanswered(false, Refusal::from(h)), frame: line.frame, left: false }),
        };
        let as_of = image["as_of"].as_u64().unwrap_or(0).max(verdict["site"]["current"].as_u64().unwrap_or(0));
        let shifted = shifted_frame(&line.frame, anchors, &image, as_of)?;
        let attested = match self.attest_where_owed(session, &shifted) {
            Ok(frame) => frame,
            Err(why) => return Ok(Shifted { dialed: Dialed::from(why), frame: line.frame, left: false }),
        };
        let dial_id = self
            .with_principal(board_reference, principal, |ph| {
                if let Err(e) = ph.queue.rewrite(k, shifted.clone()) {
                    self.say(format_args!("line {k}'s shifted frame could not be written ({e}); a reopen reads the frame copied last, which the board judges as it judges every send"));
                }
                match dialing {
                    Dialing::First => {
                        self.remark_line(principal, ph, k, Reason { sent: true, ..line.reason.clone() });
                        None
                    }
                    Dialing::Resend => self.ready_to_resend(principal, ph, k),
                }
            })
            .flatten();
        let dialed = match (dialing, dial_id) {
            (Dialing::First, _) => dial(&attested),
            (Dialing::Resend, Some(dial_id)) => dial(&attested.under(&dial_id)),
            // The line left the queue as its shift read: nothing is dialed.
            (Dialing::Resend, None) => return Err(Unshiftable::NoLine.into()),
        };
        Ok(Shifted { dialed, frame: shifted, left: true })
    }

    /// Hands a line at its deadline to the person (§3c.4).
    ///
    /// Its first failed send stands `elapsed` past in wall time, the line's
    /// [`HAND_OVER_DEADLINE`] of the board's answering run or more, and the
    /// read found no landing: the line is re-marked a refused
    /// run under the shell's `answers_lost`, its refusal naming `last`, the
    /// last failure's token, and `elapsed_ms`, its `sent` kept — so the
    /// person's `send` reads before it dials, and a landing the read finds
    /// then is kept (§3c.5) — and the lines behind it wait with it, as behind
    /// any refused run, until `resolve` sends or drops it, the drop of a
    /// `sent` line read for its landing first (`Holds::resolve`; skep #866).
    /// It is said once in the shell's own window, and on the `held` event as
    /// `refused` (skep #716).
    fn hand_over(&self, session: &SessionEntry, head: &HeldLine, last: &str, elapsed: Duration) {
        let (board_reference, principal) = (session.board_reference.as_str(), session.facts.principal);
        let refusal = Refusal::shell(Name::ANSWERS_LOST, json!({"last": last, "elapsed_ms": millis(elapsed)})).to_value();
        // The line keeps its `sent`: a resend marks it before its dial, so a
        // line resent before its deadline may have landed and is read before
        // the person's `send` dials it again.
        let reason = Reason { sent: head.reason.sent, ..Reason::refused(Name::ANSWERS_LOST.as_str(), refusal) };
        self.with_principal(board_reference, principal, |ph| self.remark_line(principal, ph, head.k, reason));
        self.say(format_args!(
            "line {} on {}: no landing {} s after its first failed send (last: {last}); it is handed to the person, who may send it again or drop it",
            head.k,
            head.doc,
            elapsed.as_secs()
        ));
        self.emit_held(session, &head.doc, self.lines_on(board_reference, principal, &head.doc), HeldState::Refused, Some(Name::ANSWERS_LOST.as_str()), MovedFace::default());
    }

    /// Marks every line of a moved document `cause: moved`.
    ///
    /// No line is rebased inexactly. It is reached from the board's verdict
    /// alone — a resend or a first dial refused as typed against an older state
    /// of its document that the shift could not move through the change exactly
    /// ([`Holds::shift_and_send`]: no anchors, a delete or a rearrange without
    /// its span, an anchor lost or at two places, the span between them cut or
    /// refilled, the read refused, the line's deadline passed), once the read
    /// of the hands has answered or gone unanswered, the hands then named not
    /// read: the death signal there marks nothing, being the session's death
    /// and no verdict on the document ([`Holds::hands_since_typed_state`]) —
    /// never from the resend's read, which judges no move, nor from a shift
    /// whose live read went unanswered, which is untried (skep #863). A moved
    /// document is one the shift could not
    /// move through exactly: the exact rebase by identity is the shift, made
    /// where the page's anchors stand at one place each with the span's own
    /// units between them, and a burst it cannot carry so is held here, since a
    /// silent inexact rebase could put words where the person did not. No line
    /// is sent. Each keeps its own `sent`, so a line that may have landed reads
    /// before it is sent again (§3c.2). The marks are one run, written to the
    /// held file as one copy with one sync however many lines the document
    /// holds ([`Holds::remark_lines`]; skep #861). `judged` is the line the
    /// board refused, with the board's verdict, kept as its refusal — the state
    /// the line was typed against and the document's current one; a moved
    /// reason carries one (`Dialed::refused`). The hands whose rows moved it
    /// ride the `held` event's `moved` state (§3c.5; §4b.2), the data of the
    /// face's three forms. The page's half — what the burst machine does at a
    /// `held` answer, how it re-projects the held frames at a launch, the moved
    /// document's face — is the frontend's and in neither repository at this
    /// pin (unverified here, the record §7 item 4; stated from
    /// assisted-frontend §7b).
    pub(super) fn mark_moved(&self, board_reference: &str, principal: u64, doc: &str, judged: Option<(u64, Value)>) {
        self.with_principal(board_reference, principal, |ph| {
            let marks: Vec<(u64, Reason)> = ph
                .queue
                .reasons_on(doc)
                .map(|(k, reason)| {
                    let refusal = judged.as_ref().filter(|(judged, _)| *judged == k).map(|(_, verdict)| verdict.clone());
                    (k, Reason { refusal, ..Reason::of(cause::MOVED, reason.sent) })
                })
                .collect();
            self.remark_lines(principal, ph, marks, None);
        });
    }

    /// Keeps one line at `at`, the file compacting where the queue empties.
    ///
    /// `minted` is the first I-address a kept insert's words were minted at,
    /// where its ack names one, which places the pieces naming them
    /// ([`Holds::keep_line`]; skep #969).
    fn keep(&self, board_reference: &str, principal: u64, k: u64, at: Option<u64>, minted: Option<&str>) {
        self.with_principal(board_reference, principal, |ph| self.keep_line(principal, ph, k, at, minted));
    }
}

/// Returns whether the walk passes a document over at `head`, its head,
/// with no read and no send (§3c.5; skep #727).
///
/// It does where the head awaits the person's act, which no probe sends, or
/// is held `head_unreadable` while the probe's one read of the board's head
/// answers so (`head_unreadable`), its send bound to fail the same way.
fn passed_over(head: &HeldLine, head_unreadable: bool) -> bool {
    awaits_act(&head.reason) || (head_unreadable && head.reason.cause == cause::HEAD_UNREADABLE)
}

/// Returns whether deciding a document at `head` reads the board for the
/// head's own landing (§3c.5).
///
/// It does where a dial of the head may have landed (`sent`) and the walk
/// does not pass the document over ([`passed_over`]): the read is one step
/// of the turn (`TURN_STEPS`), and a head no dial of which left goes from
/// the head unread.
fn read_owed(head: &HeldLine, head_unreadable: bool) -> bool {
    head.reason.sent && !passed_over(head, head_unreadable)
}

/// Returns whether `delivery` delivers `want`, value for value and no more.
///
/// It reads lazily, so a board answering more than it was asked costs the
/// comparison the values asked for and one past them, never a value per
/// position it chose to deliver.
fn delivers(delivery: &Value, want: &[Cow<'_, [u8]>]) -> bool {
    let mut got = delivered_values(delivery);
    want.iter().all(|w| matches!(got.next(), Some(Ok(g)) if g == *w)) && got.next().is_none()
}

/// Returns whether a `/changes` row is of the session's own hand (§3c.5).
///
/// The hand is its key's. An unsigned entry carries `key`, the key's
/// fingerprint. A signed entry carries no `key` (wire.md §`/changes`: `key`
/// is present iff the entry is unsigned) and `attest` in its place, and is
/// the session's own — §3c.5's "its `key` the session's fingerprint" reads
/// the unsigned form alone. The shell attests every `insert` at a board
/// with `H.1` ("Attach when in doubt"), but the daemon keeps an attest on a
/// publish-class write alone and drops it on a draft's (wire.md §The two
/// attestation codes), so a burst's row is the unsigned form today, its
/// `key` the signing key's fingerprint; the signed form stands for a row
/// the wire's rule admits. The read's other guards (`op` equal, the content
/// confirmed, the position not one this shell acked) stand beside this one,
/// so another key's signed row of another kind is no landing. A bare
/// session has no hand of its own: it writes nothing
/// (`SessionEntry::may_write`) and the resend reads under no bare session,
/// so every row is another's to one.
fn own_row(session: &SessionEntry, row: &Value) -> bool {
    let Some(fingerprint) = session.key() else { return false };
    row["key"].as_str() == Some(fingerprint.to_hex().as_str()) || (row.get("key").is_none() && row.get("attest").is_some())
}

/// Whether a `/changes` row's testimony is lost.
///
/// Its `docs`, `key` and `op` are the reserved null (wire.md §`/changes`:
/// "`null` only for lost metadata"): a commit whose testimony the write path
/// never recorded — re-derived from the journal at the board's open, or
/// written bare by the write path's catch of a panic past the commit
/// (`operations.md` §4 row 34) — classified to its documents, its hand and
/// kind the feed cannot name. A signed row has no `key` but names its `op`;
/// a bare session's row says `bare`; neither is this.
fn testimony_lost(row: &Value) -> bool {
    row["docs"].is_null() && row["key"].is_null() && row["op"].is_null()
}
