//! The probe and the resend (`client.md` §3c.4, §3c.5).
//!
//! They are the hold's walk that drains a board's queue once the board
//! returns. The probe ([`Holds::probe`]) runs on the board's feed thread
//! every [`PROBE_CADENCE`](super::PROBE_CADENCE) while a line stands, and
//! there too at its daemon-running tick and at the hand-overs of
//! `resolve(send)` and `set_node_state(Running)`, because `Cmd::Tick` is
//! driven by committed writes and a poisoned, halted, stopped or
//! unreachable board commits nothing. The resend it lets run is automatic
//! at the hold's end and at reopen, under a standing session of the
//! principal's that may write — never a bare one, the keyless session that
//! reads alone (foundations §3.3 state 3), whose principal's lines stay held
//! until a session that may write stands: one read per document (`GET
//! /changes`) before its first resend, which answers one question of the
//! document's head — did its own write land? — and nothing more: (i)
//! nothing of it landed, send from the head, or, the head's first failed
//! send standing [`HAND_OVER_DEADLINE`] past, whatever the failure, hand it
//! to the person as a refused run (`answers_lost`), naming the last failure
//! and the time elapsed, dialed never again until the person sends it; (ii)
//! the in-flight burst landed, the head `done kept` and its
//! position the document's base, as an ack's is (§3c.2). A head no dial of
//! which left is not read at all: it goes from the head. A row that is not
//! the head's own landing is no verdict — the person's own later write, a
//! sibling's, another hand's — and the head goes from the head; and a read
//! the board did not answer decides nothing: the next probe reads again.
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
//! failed send of the line, so the shifts stop at its deadline; where the
//! shift is not exact — no anchors, a delete or a rearrange without its span,
//! an anchor lost or standing at two places, the span cut or refilled, the
//! read refused, the deadline passed — the document is
//! faced `moved`, never rebased inexactly, the verdict kept on the line and the
//! hands read once since the line's typed state, or since the person's last
//! `send` on the document where that is later. A rearrange that landed where
//! the read cannot see it — its row's testimony lost, or the feed's history
//! reclaimed — leaves the span's own units between its anchors in another
//! order, so its resend, refused by the board, is held moved and never applied
//! twice. The read judges no move, and no line is shifted before it: the shift
//! lives in the send, which runs for a line the read let go alone. Every
//! document is read first, and the lines of those its reads let go then go out
//! in `k` order across the documents (§3c.5's order, "which keeps each
//! document's order"), so a `copy` held between two bursts on its source
//! transcludes the source as it stood when the person wrote it. Each line goes
//! out through the hold's one reader of a write's answer, as a first dial does,
//! every failed send of it noted on its clock and its "sent again" said once
//! per change of the failure; one the board refuses under a code the table
//! holds nowhere is handed to the person at once, a refused run under the
//! board's token, since it cannot resolve (§3c.4).
//! A resend marks its line as one that may have landed before it dials, synced,
//! and the line stays so through every resend short of its ack and through a
//! move, so its next read takes a landing it finds as the line's own — after a
//! crash or a refused write between a dial and its answer too (§3c.2's `sent`).

use std::borrow::Cow;
use std::collections::HashSet;
use std::fmt;
use std::ops::ControlFlow;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use serde_json::{json, Value};
use skep_client::board::{acked_at, frames, Answer, ChangesAnswer, ChangesQuery, Rejection};

use super::{awaits_act, cause, line_state, millis, AttestedWhereOwed, BoardSlot, Dialed, HeldState, Holds, HAND_OVER_DEADLINE};
use crate::held::{i_address, Anchors, Done, HeldLine, Reason, SpanRun};
use crate::refusal::{Name, Refusal};
use crate::sessions::{board_head, SessionEntry, SessionKind};
use crate::wire::{delivered_values, values_of};

/// The window the shift's one read images: every arranged content position
/// from the first.
///
/// The board clips an `image` region to the arrangement (M5's resolution
/// clips silently, and a natural rides the wire unbounded), so one read over
/// this window answers the document's whole content image — its runs in
/// V-order, a run the document places twice identical in start and width
/// answered once ([`Image`]) — whatever its extent, and the anchors are found
/// wherever they now stand; a document past the board's run budget answers
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
    /// The image read answered no image: refused, the death signal, no
    /// answer, or runs that are no I-extents.
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

/// A line shifted and dialed ([`Holds::shift_and_send`]).
#[derive(Debug)]
pub(super) struct Shifted {
    /// What the dial answered.
    pub(super) dialed: Dialed,
    /// The frame as shifted: the one on the line, and the one dialed.
    pub(super) frame: Value,
    /// Whether the dial left — its attest composed, the mark made before
    /// it; false where the attest could not be composed, nothing dialed and
    /// the line left as it was.
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
/// contiguously), save that the board answers each run once — deduped on its
/// start and width — so a run the document places twice, identical in start and
/// width, stands here at its first place alone. Made by [`Image::of`] alone,
/// which admits each run only where its every position is within a `u64`, and
/// the runs only where their positions end within one at `past_end`, so no sum
/// the shift makes over them passes a `u64`.
#[derive(Debug)]
struct Image<'a> {
    /// The runs, each its I-prefix, its first position and its width.
    runs: Vec<(&'a str, u64, u64)>,
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
    /// at two places is refused, as one found nowhere is lost.
    fn position_of(&self, anchor: &str, which: &'static str) -> Result<u64, Unshiftable> {
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
    fn runs_at(&self, from: u64, width: u64) -> Vec<(&'a str, u64, u64)> {
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
fn joined<'a>(runs: impl IntoIterator<Item = (&'a str, u64, u64)>) -> Vec<(&'a str, u64, u64)> {
    let mut out: Vec<(&'a str, u64, u64)> = Vec::new();
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
/// whole; and the shift is not made. What the test cannot tell, named: a
/// document the board images as fewer runs than it arranges — an I-run
/// placed twice, identical in start and width, imaged once ([`Image`]) — is
/// counted short past the run's second place, which neither the search nor
/// the clip sees, so an anchor past it is found short by the run's width,
/// its count and its units passing the test and the burst landing that far
/// early. The displacement is one for every position: the `before` anchor's
/// V-position plus one, less the first position the burst named — so a
/// change that sat wholly before the span moves it by its width, one wholly
/// after by nothing — applied to every position the frame names
/// ([`EditedSpan::displaced`]).
fn shifted_frame(frame: &Value, anchors: &Anchors, image: &Value, as_of: u64) -> Result<Value, Unshiftable> {
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

/// The outcome of the resend's one read per document (§3c.5).
///
/// The read answers whether the document's head's own write landed, and
/// nothing more: whether the document moved is the board's verdict on the
/// send ([`Holds::send_line`]'s moved arm), never the read's.
#[derive(Debug, Clone, PartialEq, Eq)]
enum ReadOutcome {
    /// No row since `base` is the head's own landing — send from the head.
    ///
    /// Every row read is no verdict: the person's own later write, a
    /// sibling's, another hand's. The board judges the send's typed state.
    SendFromHead,
    /// The in-flight burst landed — the head is `done kept` with this `at`.
    ///
    /// The position, where the read names one, becomes the document's base,
    /// as an ack's does (§3c.2), and joins the board's acked positions.
    Landed { at: Option<u64> },
    /// The board answered no page: nothing is decided.
    ///
    /// It answered a refusal (`feed_rebuilding`), the death signal, or no
    /// answer — or the site read the landing needed went unanswered — and
    /// the next probe reads again.
    Unread,
}

/// What one `retrieve_v` at a held burst's site says of its values.
///
/// It is §3c.5's content confirm.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Site {
    /// The values read back equal: the burst stands there.
    Equal,
    /// Other values, or none (the site out of the document's bounds).
    Differs,
    /// No read can decide.
    ///
    /// It is a burst of another kind than `insert`, or a frame that names no
    /// site.
    Unconfirmable,
    /// The board did not answer the read.
    Unread,
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
    /// Runs the probe (§3c.4), and the resend it lets run (§3c.5).
    ///
    /// It runs on the board's feed thread alone — every
    /// [`PROBE_CADENCE`](super::PROBE_CADENCE), at its daemon-running tick,
    /// and at the hand-overs of `resolve(send)` and `set_node_state(Running)`.
    /// While a line stands at a board whose own node is not stopped,
    /// `/health` is read; where the board answers and takes writes, each
    /// principal with lines resends them under a standing session of its own
    /// that may write (`SessionEntry::may_write`) — under no bare session.
    pub fn probe(&self, board_reference: &str) {
        // Gathered under the lock and dialed outside it, so `op` never waits
        // on a dead board's connect timeout.
        let slot = self.slot(board_reference);
        let due = {
            let board_hold = slot.lock();
            !board_hold.node_stopped && board_hold.principals.values().any(|ph| !ph.queue.lines().is_empty())
        };
        if !due {
            return;
        }
        // One drain per board at a time, its mark cleared however it ends.
        let Some(_draining) = Draining::begin(&slot.draining) else { return };
        self.drain(board_reference, slot);
    }

    /// Runs the probe's dial and the resend: the body of [`Holds::probe`].
    ///
    /// It runs once per board at a time. After `/health`, ONE read of the
    /// board's head (`sessions::board_head`) before any document (skep #727):
    /// the same answer establishes the directory ([`Holds::establish`]) and
    /// decides which documents the resend skips — never two reads in one
    /// probe for the hold's sake — and the board's head state is said once
    /// per change ([`Holds::note_head`]). While the head answers
    /// `head_unreadable`, every document whose head line is held so is
    /// skipped: no `/changes` read, no `sending`, no attest attempted; the
    /// other documents resend as they do.
    fn drain(&self, board_reference: &str, slot: &BoardSlot) {
        let board = &slot.board;
        // The probe's one `/health` read (§3c.4): a board that does not answer
        // is read again at the next probe, and one whose writes are halted
        // holds every line.
        let Ok(health) = board.health() else { return };
        if self.note_health(board_reference, &health) {
            return;
        }
        // The board answers and takes writes: the hold ends. The head is read
        // once; a directory no session's open could establish is tried again
        // with it, and each principal with lines resends them under a session
        // of its own that may write; a bare one, which reads alone, sends none
        // (foundations §3.3 state 3), so a principal with no other session
        // keeps its lines held.
        let head = board_head(board);
        self.note_head(board_reference, &head);
        self.establish(board_reference, slot, &head);
        let head_unreadable = matches!(head, Err(Refusal::Halt { name: Name::HEAD_UNREADABLE, .. }));
        let principals: Vec<u64> = slot.lock().principals.iter().filter(|(_, ph)| !ph.queue.lines().is_empty()).map(|(p, _)| *p).collect();
        for principal in principals {
            let Some(session) = self.sessions.on_board(board_reference).into_iter().find(|s| s.facts.principal == principal && s.may_write()) else { continue };
            self.resume(&session, head_unreadable);
        }
    }

    /// Runs the resend for one session (§3c.5), resumed by read.
    ///
    /// It is wire.md's resume-by-read (PUB-8.32) at the board the session
    /// stands at: each document with held lines read once, in the order its
    /// first line was held, then the lines of every document its read lets
    /// go sent in `k` order across the documents ([`Holds::send_in_order`]).
    /// The documents are gathered by one pass over the queue, each found
    /// among those already seen by a set's lookup, never a scan of them.
    /// `head_unreadable` is whether the probe's one read of the board's head
    /// answered so: the documents whose head line waits on the head are then
    /// skipped ([`Holds::resume_doc`]).
    fn resume(&self, session: &SessionEntry, head_unreadable: bool) {
        let Some(docs) = self.with_principal(&session.board_reference, session.facts.principal, |ph| {
            let mut seen = HashSet::new();
            ph.queue.lines().iter().filter(|l| seen.insert(l.doc.as_str())).map(|l| l.doc.clone()).collect::<Vec<String>>()
        }) else {
            return;
        };
        let sending: HashSet<String> = docs.into_iter().filter(|doc| self.resume_doc(session, doc, head_unreadable)).collect();
        self.send_in_order(session, sending);
    }

    /// Resumes one document by its read (resume-by-read, §3c.5).
    ///
    /// It runs the read and its outcome — a landed head kept, its position
    /// made the document's base (§3c.2) and entered in the board's acked
    /// positions — and answers whether the document's lines go out now: a
    /// document the read sends from the head, or whose landed head leaves
    /// lines behind it; never one whose head awaits the person's act, which
    /// is read never, nor one the read left undecided, nor one whose head it
    /// hands to the person: a head no landing of which the read found, its
    /// first failed send [`HAND_OVER_DEADLINE`] past or more
    /// ([`Holds::hand_over`]). The read runs first, so a landing it finds is
    /// kept and never handed over. A head no dial of which left (`sent`
    /// false) is not read at all: nothing of it can stand on the board, so it
    /// goes from the head — or is handed over, where its deadline has passed.
    /// A head held `head_unreadable` while the probe's read of the board's
    /// head answers so (`head_unreadable`) is skipped whole — no read, no
    /// `sending`, nothing said (skep #727): its send would fail the same way,
    /// and the `held` event and the `Talk` line were said once as the state
    /// began; it is tried again the probe the head reads.
    fn resume_doc(&self, session: &SessionEntry, doc: &str, head_unreadable: bool) -> bool {
        let (board_reference, principal) = (session.board_reference.as_str(), session.facts.principal);
        let Some(head) = self.head_of(board_reference, principal, doc) else { return false };
        if awaits_act(&head) || (head_unreadable && head.reason.cause == cause::HEAD_UNREADABLE) {
            return false;
        }
        let outcome = if head.reason.sent { self.read_outcome(session, doc, &head) } else { ReadOutcome::SendFromHead };
        match outcome {
            ReadOutcome::Unread => false,
            ReadOutcome::Landed { at } => {
                // The landing is noted as the session's ack is (§3c.2, §3c.5):
                // a line held on the document from here reads past it, and no
                // read takes its row for another line's landing; a later write
                // noted since the read stands.
                {
                    let mut board_hold = self.lock(board_reference);
                    if let Some(at) = at {
                        board_hold.acked.insert(at);
                    }
                    if let Some(ph) = board_hold.principals.get_mut(&principal) {
                        if let Some(at) = at {
                            ph.note_position(doc, at);
                        }
                        self.done_line(ph, head.k, Done::Kept { at });
                    }
                }
                match self.count(board_reference, principal, doc) {
                    0 => {
                        self.emit_held(session, doc, 0, HeldState::Kept, None, &[]);
                        false
                    }
                    rest => {
                        self.emit_held(session, doc, rest, HeldState::Sending, None, &[]);
                        true
                    }
                }
            }
            ReadOutcome::SendFromHead => {
                // Nothing of the head has landed: its first failed send at
                // the deadline or past it, it is the person's, dialed never
                // again (§3c.4; skep #716).
                let clock = self.with_principal(board_reference, principal, |ph| ph.reissues.get(&head.k).and_then(|given| given.first_failed.zip(given.last.clone()))).flatten();
                if let Some((first_failed, last)) = clock {
                    let elapsed = self.now().saturating_duration_since(first_failed);
                    if elapsed >= HAND_OVER_DEADLINE {
                        self.hand_over(session, &head, &last, elapsed);
                        return false;
                    }
                }
                self.emit_held(session, doc, self.count(board_reference, principal, doc), HeldState::Sending, None, &[]);
                true
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
    /// it stands at no position this shell acked ([`BoardHold::acked`]): a
    /// row of the same key and kind at an acked position is a sibling's
    /// write through this shell, answered, never the lost landing; a row of
    /// the same key not through this shell — the `skep` command's — the set
    /// cannot tell apart, named as the residue. The site ([`Holds::site`])
    /// is the document's now, read once for the first row that asks for it:
    /// an `insert` whose values stand at its site landed; one whose values do
    /// not is no landing of any row, so the head goes from the head at once;
    /// a kind no read confirms trusts the own hand and the op alone, and
    /// trusts a row whose hand is lost not at all. Every other row — the
    /// person's own later write of another kind, a sibling's, another hand's
    /// — is no verdict: whether the document moved is the board's
    /// (`arrangement_moved`, [`Holds::send_line`]), not this read's.
    fn read_outcome(&self, session: &SessionEntry, doc: &str, head: &HeldLine) -> ReadOutcome {
        let board_reference = session.board_reference.as_str();
        let mut query = ChangesQuery { since: head.base, under: Some(doc), drafts: true, limit: None };
        // The site is the document's, not a row's: read once, for the first
        // row that asks.
        let mut site = None;
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
                let landed = match *site.get_or_insert_with(|| self.site(session, doc, head)) {
                    Site::Equal => true,
                    // A kind the site read cannot confirm trusts the op-and-hand
                    // match; a row whose hand the board lost has none to trust.
                    Site::Unconfirmable => own,
                    // The head's values do not stand at its site: no row is its
                    // landing, and the board judges the send's typed state.
                    Site::Differs => return ReadOutcome::SendFromHead,
                    Site::Unread => return ReadOutcome::Unread,
                };
                if landed {
                    return ReadOutcome::Landed { at };
                }
            }
            if !page.more {
                return ReadOutcome::SendFromHead;
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
    /// confirms, is no landing found, and the head goes from the head — the
    /// board judging its typed state (`arrangement_moved`), as it judges
    /// every send; a site read the board does not answer decides nothing.
    fn reclaimed_outcome(&self, session: &SessionEntry, doc: &str, head: &HeldLine) -> ReadOutcome {
        match self.site(session, doc, head) {
            Site::Equal => ReadOutcome::Landed { at: None },
            Site::Differs | Site::Unconfirmable => ReadOutcome::SendFromHead,
            Site::Unread => ReadOutcome::Unread,
        }
    }

    /// Confirms an `insert`'s site by its content (§3c.5).
    ///
    /// It makes one `retrieve_v` at the site, as wide as the values its frame
    /// spells, the delivery read back as values and held to them.
    fn site(&self, session: &SessionEntry, doc: &str, head: &HeldLine) -> Site {
        if head.frame["op"].as_str() != Some("insert") {
            return Site::Unconfirmable;
        }
        let ordinal = head.frame["at"]["ordinal"].as_str().and_then(|o| o.parse::<u64>().ok());
        let (Ok(want), Some(from)) = (values_of(&head.frame["values"]), ordinal) else { return Site::Unconfirmable };
        match session.board.op(Some(&session.token), &frames::retrieve_v(doc, from, want.len() as u64)) {
            Ok(Answer::Document(v)) if Rejection::of(&v).is_none() => {
                if delivers(&v, &want) {
                    Site::Equal
                } else {
                    Site::Differs
                }
            }
            Ok(Answer::Document(_)) => Site::Differs,
            Ok(Answer::Closed) | Err(_) => Site::Unread,
        }
    }

    /// Sends the standing lines of `docs` in `k` order: §3c.5's order.
    ///
    /// §3c.5 has "lines in `k` order across the board's documents, which
    /// keeps each document's order": each line is a normal `op` under the
    /// session — a document stopping at a line that awaits the person's act
    /// or is not taken, the others going on. Every turn settles its line (an
    /// ack, the one `Continue`, takes it out of the queue) or drops its
    /// document, so the walk ends; a turn finds its line by one set lookup
    /// per line it passes, so the walk's work is the queue's lines — a hold
    /// adds none past `held::MAX_HELD_LINES` — times its turns.
    fn send_in_order(&self, session: &SessionEntry, mut docs: HashSet<String>) {
        let (board_reference, principal) = (session.board_reference.as_str(), session.facts.principal);
        let next = |docs: &HashSet<String>| self.with_principal(board_reference, principal, |ph| ph.queue.lines().iter().find(|l| docs.contains(&l.doc)).cloned()).flatten();
        while let Some(line) = next(&docs) {
            if awaits_act(&line) || self.send_line(session, &line).is_break() {
                docs.remove(&line.doc);
            }
        }
    }

    /// Sends one held line as the `op` it is, under the session that stands.
    ///
    /// Its attest is composed now (§3c.2), the line marked as one that may
    /// have landed before the dial leaves, and the line settled by what the
    /// dial answered: an ack `done kept`; the line refused as typed against
    /// an older state of its document shifted through the change and dialed
    /// again ([`Holds::shift_and_send`]) — its answer settled here as any
    /// dial's is, the verdict again shifting it again as far as the line's
    /// deadline lets it — or, where the shift is not exact, the document
    /// faced `moved` ([`Holds::mark_moved`]) — the one route to that face —
    /// the board's verdict kept on the line and the hands whose rows moved it
    /// named; a hold-class answer or a refused run re-marked and faced, the
    /// line keeping its `sent` — a resend that never left, or one the board
    /// refused, says nothing of an earlier dial's write (§3c.2); a
    /// reissue-class answer counted against the line and reissued at the
    /// next probe, so its third `durability` holds it, and a `write_busy`
    /// past its one reissue left standing for the next probe too; any other
    /// code of the board's the table holds nowhere handed to the person at
    /// once, a refused run under the board's token with its verdict verbatim
    /// and its `sent` kept, through the door a `permanent` refusal takes,
    /// since it cannot resolve (§3c.4; skep #720); a refusal of the shell's
    /// own — a request refused before any connection, or an attest that
    /// could not be composed — left standing for the next probe, never
    /// `done`; the death signal left to the caller that ends the session —
    /// the session that stands resends after its read. Every failed send of
    /// the line ([`Dialed::failure`]) is noted on its clock
    /// ([`HAND_OVER_DEADLINE`]), and a line standing for the next probe says
    /// "sent again" where its failure's token differs from the last
    /// failure's, so once per change. `Continue` where the line is settled
    /// and sending goes on, `Break` where the line's document stops at it.
    ///
    /// THE LANDED TEST COMES FIRST: this runs for a line
    /// [`Holds::resume_doc`] let go alone — a `sent` head read for its own
    /// landing and found unlanded — so no line is shifted before its read,
    /// and a landing the read keeps is shifted never.
    fn send_line(&self, session: &SessionEntry, line: &HeldLine) -> ControlFlow<()> {
        let (board_reference, principal) = (session.board_reference.as_str(), session.facts.principal);
        let given = || self.with_principal(board_reference, principal, |ph| ph.reissues.get(&line.k).cloned()).flatten().unwrap_or_default();
        // The line is marked as one that may have landed before its dial
        // leaves (§3c.2's `sent`), synced, so a crash or a refused write
        // between the dial and its answer never leaves a write that may have
        // landed read as one never sent; a line marked so already writes
        // nothing. The mark stands whatever the dial answers, a connection
        // never made among them, and a copy the device refuses is said and
        // the dial made all the same. An attest that could not be composed
        // dials nothing and marks nothing: the line keeps its own `sent`, and
        // nothing left (`left` false).
        let (mut dialed, mut sent, mut left) = match self.attest_where_owed(session, &line.frame) {
            Ok(frame) => {
                self.with_principal(board_reference, principal, |ph| self.remark_line(ph, line.k, Reason { sent: true, ..line.reason.clone() }));
                (self.dial(session, &frame, &given()), true, true)
            }
            Err(why) => (Dialed::from(why), line.reason.sent, false),
        };
        // The frame the dial sent, for its ack's noting: the line's, or the
        // shifted one.
        let mut frame = Cow::Borrowed(&line.frame);
        loop {
            // A failed send of the line notes its token on the line's clock:
            // `Some(true)` where the token differs from the last failure's as
            // it stood, a line's first failure among them; `Some(false)` where
            // it repeats it, said already; none where no send failed — an
            // ack, the death signal, or a dial that never left.
            let failed = if left { dialed.failure().map(|token| self.note_failure(board_reference, principal, line.k, token)) } else { None };
            match dialed {
                Dialed::Acked(ack) => {
                    self.note_ack(session, &frame, &ack);
                    self.done(board_reference, principal, line.k, Done::Kept { at: acked_at(&ack) });
                    let rest = self.count(board_reference, principal, &line.doc);
                    self.emit_held(session, &line.doc, rest, if rest == 0 { HeldState::Kept } else { HeldState::Sending }, None, &[]);
                    return ControlFlow::Continue(());
                }
                Dialed::Held { reason, .. } if reason.cause == cause::MOVED => {
                    // The board refused the line as typed against an older
                    // state of its document: shifted through the change where
                    // the shift is exact, and dialed again; else the document
                    // is faced moved — the board's verdict the one judge of a
                    // move — each line keeping its own `sent`, the line
                    // refused keeping the verdict, and named by the hands
                    // whose rows moved it since the line's typed state, or
                    // since the person's last `send` on it where that is
                    // later (§3c.5).
                    let verdict = reason.refusal.clone().unwrap_or(Value::Null);
                    match self.shift_and_send(session, line.k, &verdict, |shifted| self.dial(session, shifted, &given())) {
                        Ok(shifted) => {
                            sent |= shifted.left;
                            left = shifted.left;
                            frame = Cow::Owned(shifted.frame);
                            dialed = shifted.dialed;
                        }
                        Err(why) => {
                            self.say(format_args!("line {} on {} was not shifted ({why}); the document is held as moved", line.k, line.doc));
                            let hands = self.hands_since_typed_state(session, &line.doc, Some(line.k), &reason);
                            self.mark_moved(board_reference, principal, &line.doc, reason.refusal.map(|verdict| (line.k, verdict)));
                            self.emit_held(session, &line.doc, self.count(board_reference, principal, &line.doc), HeldState::Moved, None, &hands);
                            return ControlFlow::Break(());
                        }
                    }
                }
                Dialed::Held { reason, refusal } => {
                    let state = line_state(&reason);
                    let said = reason.cause.clone();
                    // The line keeps its `sent`, the mark made before the dial
                    // included: a resend that never left, or one the board
                    // refused, says nothing of an earlier dial's write. The
                    // read decides at the next probe whether it landed.
                    let reason = Reason { sent: reason.sent || sent, ..reason };
                    self.with_principal(board_reference, principal, |ph| self.remark_line(ph, line.k, reason));
                    // A failure the line stands through for the next probe is
                    // said once per change; a refused run's face is its
                    // `held` event, and a dial that never left is the
                    // board's outage, no failure of the line.
                    if failed == Some(true) && state == HeldState::Holding {
                        self.say(format_args!("line {} on {} was not taken ({refusal}); it is sent again at the next probe", line.k, line.doc));
                    }
                    self.emit_held(session, &line.doc, self.count(board_reference, principal, &line.doc), state, Some(&said), &[]);
                    return ControlFlow::Break(());
                }
                Dialed::Reissue { kind, refusal } => {
                    // The rider's count (§3c.4), per line across its probes:
                    // the third `durability` holds it.
                    self.with_principal(board_reference, principal, |ph| ph.reissues.entry(line.k).or_default().note(kind));
                    if failed != Some(false) {
                        self.say(format_args!("line {} on {} was not taken ({refusal}); it is sent again at the next probe", line.k, line.doc));
                    }
                    return ControlFlow::Break(());
                }
                // The board's own verdict under a code the table holds
                // nowhere, save a `write_busy` past its one reissue: it cannot
                // resolve, so the line is the person's at once (§3c.4; skep
                // #720) — a refused run under the board's token with its
                // verdict verbatim, its `sent` kept, through the door a
                // `permanent` refusal takes, the lines behind it waiting with
                // it. A refusal of the board's that reached no dial — a read
                // the attest's composer made — is the shell's own.
                Dialed::Faced(Refusal::Board(r)) if left && r.code != "write_busy" => {
                    let token = r.token();
                    let reason = Reason { sent, ..Reason::refused(&token, r.body.clone()) };
                    self.with_principal(board_reference, principal, |ph| self.remark_line(ph, line.k, reason));
                    self.say(format_args!("line {} on {} was not taken ({r}), a code the shell holds no row for; it is handed to the person, who may send it again or drop it", line.k, line.doc));
                    self.emit_held(session, &line.doc, self.count(board_reference, principal, &line.doc), HeldState::Refused, Some(&token), &[]);
                    return ControlFlow::Break(());
                }
                // A `write_busy` past its one reissue, the line's clock
                // running on, or a refusal of the shell's own, which dialed
                // nothing the board judged and starts no clock: the line
                // stands for the next probe, and the shell's own is said at
                // each.
                Dialed::Faced(refusal) => {
                    if failed != Some(false) {
                        self.say(format_args!("line {} on {} was not taken ({refusal}); it is sent again at the next probe", line.k, line.doc));
                    }
                    return ControlFlow::Break(());
                }
                Dialed::Died => return ControlFlow::Break(()),
            }
        }
    }

    /// Shifts a line the board refused as typed stale, and sends it again.
    ///
    /// It is the one function the first dial ([`Holds::shift_at_first_dial`])
    /// and the resend ([`Holds::send_line`]) call for a line the board refused
    /// as typed against an older state of its document (skep #442, #751), each
    /// dialing as it dials. `verdict` is the board's `arrangement_moved`, its
    /// `site.current` the floor the shifted frame is typed against. In this
    /// order, the first that holds answering why the shift was not made
    /// ([`Unshiftable`]): a line of ordinal `k` stands; it carries anchors; its
    /// first failed send stands less than [`HAND_OVER_DEADLINE`] past — each
    /// refusal that brings a line here is a failed send of it, noted by the
    /// caller before it calls, so a document another writer keeps moving stops
    /// the shell at the line's deadline, the clock alone bounding the shifts —
    /// and one live read is made, `image` over
    /// the whole content window ([`IMAGE_WINDOW`]) under the session, the one
    /// read of the shift (no `/changes`, no history: the anchors are found at
    /// any age); the anchors found in it at one place each and the span between
    /// them whole — the units it held when the burst was typed, in their order
    /// — every position the frame names moved by the one displacement
    /// ([`shifted_frame`]), the frame typed against the read's own `as_of`, the
    /// state its positions are true of, never below the verdict's
    /// `site.current`. Then the frame is attested (an attest that cannot be
    /// composed dials nothing and writes nothing: the dial that never left,
    /// `left` false, the line as it was), written to the line before it is
    /// dialed — `HeldQueue::rewrite`, synced, a copy refused said on `Talk` —
    /// and the line marked as one that may have landed where it is not so
    /// marked yet, so a relaunch after the shifted answer is lost reads the
    /// landed test at the shifted positions; then dialed by `dial`.
    pub(super) fn shift_and_send(&self, session: &SessionEntry, k: u64, verdict: &Value, dial: impl FnOnce(&AttestedWhereOwed<'_>) -> Dialed) -> Result<Shifted, Unshiftable> {
        let (board_reference, principal) = (session.board_reference.as_str(), session.facts.principal);
        let line = self.line_of(board_reference, principal, k).ok_or(Unshiftable::NoLine)?;
        let anchors = line.anchors.as_ref().ok_or(Unshiftable::NoAnchors)?;
        // The line's deadline (HAND_OVER_DEADLINE), read before the shift's
        // read: past it the line falls to the moved hold, the person's act.
        let first_failed = self.with_principal(board_reference, principal, |ph| ph.reissues.get(&k).and_then(|given| given.first_failed)).flatten();
        if let Some(elapsed) = first_failed.map(|first| self.now().saturating_duration_since(first)).filter(|elapsed| *elapsed >= HAND_OVER_DEADLINE) {
            return Err(Unshiftable::PastTheDeadline { elapsed_ms: millis(elapsed) });
        }
        // The one live read, outside every lock as every dial is.
        let image = match session.board.op(Some(&session.token), &frames::image(&line.doc, 1, IMAGE_WINDOW)) {
            Ok(Answer::Document(v)) => match Rejection::of(&v) {
                None => v,
                Some(r) => return Err(Unshiftable::Unread(format!("the image read was refused {}", r.token()))),
            },
            Ok(Answer::Closed) => return Err(Unshiftable::Unread("the image read met the death signal".into())),
            Err(h) => return Err(Unshiftable::Unread(h.to_string())),
        };
        let as_of = image["as_of"].as_u64().unwrap_or(0).max(verdict["site"]["current"].as_u64().unwrap_or(0));
        let shifted = shifted_frame(&line.frame, anchors, &image, as_of)?;
        let attested = match self.attest_where_owed(session, &shifted) {
            Ok(frame) => frame,
            Err(why) => return Ok(Shifted { dialed: Dialed::from(why), frame: line.frame, left: false }),
        };
        self.with_principal(board_reference, principal, |ph| {
            if let Err(e) = ph.queue.rewrite(k, shifted.clone()) {
                self.say(format_args!("line {k}'s shifted frame could not be written ({e}); a reopen reads the frame copied last, which the board judges as it judges every send"));
            }
            self.remark_line(ph, k, Reason { sent: true, ..line.reason.clone() });
        });
        let dialed = dial(&attested);
        Ok(Shifted { dialed, frame: shifted, left: true })
    }

    /// Hands a line at its deadline to the person (§3c.4).
    ///
    /// Its first failed send stands `elapsed` past, [`HAND_OVER_DEADLINE`] or
    /// more, and the read found no landing: the line is re-marked a refused
    /// run under the shell's `answers_lost`, its refusal naming `last`, the
    /// last failure's token, and `elapsed_ms`, its `sent` kept — so the
    /// person's `send` reads before it dials, and a landing the read finds
    /// then is kept (§3c.5) — and the lines behind it wait with it, as behind
    /// any refused run, until `resolve` sends or drops it. It is said once in
    /// the shell's own window, and on the `held` event as `refused` (skep
    /// #716).
    fn hand_over(&self, session: &SessionEntry, head: &HeldLine, last: &str, elapsed: Duration) {
        let (board_reference, principal) = (session.board_reference.as_str(), session.facts.principal);
        let refusal = Refusal::shell(Name::ANSWERS_LOST, json!({"last": last, "elapsed_ms": millis(elapsed)})).to_value();
        // The line keeps its `sent`: a resend marks it before its dial, so a
        // line resent before its deadline may have landed and is read before
        // the person's `send` dials it again.
        let reason = Reason { sent: head.reason.sent, ..Reason::refused(Name::ANSWERS_LOST.as_str(), refusal) };
        self.with_principal(board_reference, principal, |ph| self.remark_line(ph, head.k, reason));
        self.say(format_args!(
            "line {} on {}: no landing {} s after its first failed send (last: {last}); it is handed to the person, who may send it again or drop it",
            head.k,
            head.doc,
            elapsed.as_secs()
        ));
        self.emit_held(session, &head.doc, self.count(board_reference, principal, &head.doc), HeldState::Refused, Some(Name::ANSWERS_LOST.as_str()), &[]);
    }

    /// Marks every line of a moved document `cause: moved`.
    ///
    /// No line is rebased inexactly. It is reached from the board's verdict
    /// alone — a resend or a first dial refused as typed against an older state
    /// of its document that the shift could not move through the change exactly
    /// ([`Holds::shift_and_send`]: no anchors, a delete or a rearrange without
    /// its span, an anchor lost or at two places, the span between them cut or
    /// refilled, the read refused, the line's deadline passed) — never from the
    /// read, which judges no move. A moved document is one the shift could not
    /// move through exactly: the exact rebase by identity is the shift, made
    /// where the page's anchors stand at one place each with the span's own
    /// units between them, and a burst it cannot carry so is held here, since a
    /// silent inexact rebase could put words where the person did not. No line
    /// is sent. Each keeps its own `sent`, so a line that may have landed reads
    /// before it is sent again (§3c.2). `judged` is the line the board refused,
    /// with the board's verdict, kept as its refusal — the state the line was
    /// typed against and the document's current one; a moved reason carries one
    /// (`Dialed::refused`). The hands whose rows moved it ride the `held`
    /// event's `moved` state (§3c.5; §4b.2), the data of the face's three
    /// forms. The page's half — what the burst machine does at a `held` answer,
    /// how it re-projects the held frames at a launch, the moved document's
    /// face — is the frontend's and in neither repository at this pin
    /// (unverified here, the record §7 item 4; stated from assisted-frontend
    /// §7b).
    pub(super) fn mark_moved(&self, board_reference: &str, principal: u64, doc: &str, judged: Option<(u64, Value)>) {
        self.with_principal(board_reference, principal, |ph| {
            let marks: Vec<(u64, bool)> = ph.queue.lines().iter().filter(|l| l.doc == doc).map(|l| (l.k, l.reason.sent)).collect();
            for (k, sent) in marks {
                let refusal = judged.as_ref().filter(|(judged, _)| *judged == k).map(|(_, verdict)| verdict.clone());
                self.remark_line(ph, k, Reason { refusal, ..Reason::of(cause::MOVED, sent) });
            }
        });
    }

    /// Resolves one line `done`, the file compacting where the queue empties.
    ///
    /// The `done` is [`Done::Kept`] or [`Done::Dropped`].
    fn done(&self, board_reference: &str, principal: u64, k: u64, done: Done) {
        self.with_principal(board_reference, principal, |ph| self.done_line(ph, k, done));
    }

    /// Returns the document's head: its first standing line in `k` order.
    fn head_of(&self, board_reference: &str, principal: u64, doc: &str) -> Option<HeldLine> {
        self.with_principal(board_reference, principal, |ph| ph.queue.lines().iter().find(|l| l.doc == doc).cloned()).flatten()
    }

    /// Returns how many lines stand on the document.
    fn count(&self, board_reference: &str, principal: u64, doc: &str) -> u64 {
        self.with_principal(board_reference, principal, |ph| ph.count(doc)).unwrap_or(0)
    }
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
    let SessionKind::Signed { fingerprint, .. } = &session.facts.kind else { return false };
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
