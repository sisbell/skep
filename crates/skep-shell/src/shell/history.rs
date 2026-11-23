//! The two rows of a draft's past state: its read, and its restore.
//!
//! Both are reached from [`Shell::call`] alone, over
//! `skep_client::history`'s two calls, the reads apart from the write
//! (B3-S7): `history.past`, the state read and mapped with nothing written
//! (skep #853), and `history.restore`, drawn in `client.md` §4b.1's merge
//! row, the state made current by one write.
//!
//! **The read.** `history.past(session, {draft, at})` makes the reads alone
//! (`skep_client::history::past`): the draft's state as of the position
//! `at`, and at the head the correspondence records of every draft the
//! state holds words of, each read in its owner's account, the state's runs
//! mapped through them so words published since — the person's, or those
//! of another account's draft the state holds — come back as the published
//! words they became. It is the page's read while the person rests on a
//! past state, before "make this state current": what the state brings
//! back, and the links the change would orphan, which the page reads over
//! the runs the write would send (B3-S7's orphan line). It sends no write,
//! so it asks no write door (SP-31 binds the rows that write), and it asks
//! nothing of the session's account: a bare session reads it, a second
//! window reads it, a hold standing at the board stops none of its reads,
//! and nothing of the hold, the panels or the compositions is touched. Its
//! answer is `{draft, at, as_of, state, sent, written, covered, marker}`:
//! `state` the runs as read at `at` and `sent` the same positions mapped,
//! both the core's runs, for drawing; `written` the mapped runs as a
//! restore made now would send them (**The runs**); `covered` the positions
//! a record covers; `marker` as the restore answers it; and `as_of` the
//! position the reads were made at, which is no typed state (**The typed
//! state is the page's**). The restore reads again for itself, so nothing
//! this answer carries reaches its write.
//!
//! **The runs.** A word's identity is its I-address on the chain that
//! minted it, and a declared deposit naming a member of a published chain
//! mints under that member's chain (wire.md §The publish shot and
//! head-float, the deposit cell; PUB-2.65): `D.v.0.1.k` and the trunk's
//! `D.0.1.k` are two words. The core's runs name each origin as the trunk,
//! a member's version component stripped (`skep_client::merge::origin_of`),
//! so in `state` and `sent` a member's own word stands as the trunk's
//! position of the same ordinal: runs to draw by, and no identity there.
//! `written` is the image the restore's one write sets (`Past::written`),
//! each run's `origin` as the write's one speller spells it
//! (`skep_client::history::written_runs`) — the document that minted the
//! run, a member's version component kept — with its first ordinal on that
//! document's chain and its width. It alone of the three names every word
//! by its identity, so the orphan line takes the links a restore keeps from
//! it (skep #1122). The three cover the same positions in the same order,
//! and not run for run: the core's runs join a member's run to a run of its
//! trunk's that its ordinals follow, which `written` keeps apart.
//!
//! **The restore.** `history.restore(session, {draft, at, as_of})` makes
//! the same reads, then sets the mapped state as the draft's whole
//! arrangement by ONE `set_arrangement` naming no base and no merge
//! (`skep_client::history::restore`): the draft's recorded base and its
//! merge marker stand as they are. The reads and the mapping are the
//! library's, never the page's, so no page sends as draft-native words a
//! run a record names, which the board refuses `already_published`.
//!
//! **The typed state is the page's.** The write is typed against `as_of`,
//! the page's own state of the draft — the `as_of` its burst frames on the
//! draft carry, the read its view came from raised by the page's own acks
//! there (B3-S7: "typed against this editor's own last ack as every burst
//! is"; wire.md §Arrangement). It is never the position the shell's read
//! finds, under which a change the page never showed would be written
//! over, nor the shell's own last acknowledgment on the draft
//! (`Holds::last_arranged`), which knows nothing of a change the page has
//! read since, of the library's writes, or of the shell's earlier runs. A
//! draft whose arrangement changed past the page's state is refused
//! `arrangement_moved`, the board's verdict — `site.as_of` the page's
//! state, `site.current` the draft's — nothing changed; the page reads the
//! change and restores from there.
//!
//! **The order.** The read's members are read before the session — `draft`
//! an address in its one spelling, `at` a non-negative integer — then the
//! session; then the reads. The restore's members are read before the
//! session — `draft`, then `at` and `as_of`, non-negative integers — then
//! the session; then the shell's one write door and the session's hand, as
//! the publication and merge families take them (`Shell::signed`,
//! `Shell::write_door`): the bare session, another window, the hold
//! standing at the board, which refuses the `set_arrangement` at once under
//! its cause (§3c.4; `Holds::unholdable_refusal`), and THE HELD-LINES GATE —
//! a line of the principal's the board has not kept standing on the draft,
//! in any state, refuses the restore `held_lines` naming the draft and the
//! count (§3c.4; `Holds::held_lines`; skep #854): the restore would
//! otherwise land first and the held lines replay over the restored state,
//! a draft matching neither the state picked nor the one last seen — all
//! before any read; then the reads; then the write.
//!
//! **The restore's answer** is `{draft, at, position, as_of, marker}`:
//! `position` the write's commit; `as_of` a position the draft stood at
//! before the write — the way back, this row again at `{at: as_of}` typed
//! at `position`; and `marker` the draft's merge marker as it stands, which
//! a restore never takes out, or null. The way back is the shell's read
//! where the write committed past it, and the call's own `as_of` where it
//! did not: the same restore sent again in one session is answered from the
//! board's memo (the frame's `id` names the draft, `at` and `as_of`;
//! wire.md §Correlation and idempotency), its `position` the first write's,
//! which a read made after it finds already landed, and the board took that
//! write typed at the call's `as_of`, so the draft's arrangement stood
//! unchanged from there to the write (`way_back`).
//!
//! **The note.** The write's position is noted in the hold as an
//! acknowledged arrangement write of the principal's on the draft
//! (`Holds::note_restored`): `merge.undo`, typed against the editor's own
//! last arrangement write on the draft (P3), takes a restore of the
//! person's as their own, and the next hold on the draft reads from past it;
//! and the session is recorded as the writer of its row, the write standing
//! out at the board until then (`hold::WriteOut`; skep #1000).
//!
//! **The refusals** of both rows cross as the merge family's
//! (`Shell::merge_refusal`): at the reads, `not_owner` with `published` for
//! a published document, `no_such_document`, `unreadable`, `over_cap` where
//! the mapped state is in more runs than one write may name, `merge_refused`
//! with `not_past` where `at` is at or past the draft's position, or with
//! `history_reclaimed`, `not_a_position`, `history_busy` or
//! `too_fragmented`; at the restore's write, `not_owner` for another
//! account's draft, `no_such_document`, `merge_refused` with
//! `window_withheld` or `needs_signed_session`, and the board's verdicts
//! verbatim, `arrangement_moved` among them; `session_died` where a read or
//! the write met the death signal; every other halt as itself. The read
//! reads another account's draft the session may read as it reads the
//! person's own: its owner is the board's to judge at a write.

use serde_json::{json, Value};
use skep_client::board::{Image, MergeMarker};
use skep_client::halt::Halt;
use skep_client::history;
use skep_client::merge::Run;

use super::publication::address_arg;
use super::{Shell, Write};
use crate::refusal::Refusal;

impl Shell {
    /// Answers `history.past`: the draft's state at `at`, read and mapped.
    ///
    /// The call is `history.past(session, {draft, at})`, its answer `{draft,
    /// at, as_of, state, sent, written, covered, marker}` (the module doc;
    /// `shapes`' `Past`). It sends no write and asks no write door, and its
    /// reads are `skep_client::history::past`'s, the ones
    /// [`Shell::history_restore`] makes before its write (B3-S7).
    ///
    /// # Errors
    ///
    /// In this order:
    ///
    /// 1. `malformed_args` naming `draft` where it is no address in its one
    ///    spelling, then naming `at` where it is no non-negative integer;
    /// 2. `malformed_args` naming `session`, then `session_died` or
    ///    `session_ended` ([`Shell::session`]);
    /// 3. the reads', as [`Shell::history_restore`]'s step 4 names them;
    /// 4. the reads made, a halt's face where a run the restore would send
    ///    is no content I-address, the board's fault (`written_json`);
    /// 5. `session_died` where a read met the death signal, and
    ///    `unreachable` where a dial failed.
    pub(super) fn history_past(&self, args: &Value) -> Result<Value, Refusal> {
        let draft = address_arg(&args["draft"]).ok_or_else(|| Refusal::malformed("draft"))?;
        let at = args["at"].as_u64().ok_or_else(|| Refusal::malformed("at"))?;
        let session = self.session(&args["session"])?;
        let past = history::past(&session.board, &session.token, &draft, at).map_err(|r| self.merge_refusal(&session, r))?;
        let written = written_json(&past.written)?;
        Ok(json!({
            "draft": past.draft.to_string(),
            "at": past.at,
            "as_of": past.as_of,
            "state": runs_json(&past.state),
            "sent": runs_json(&past.sent),
            "written": written,
            "covered": past.covered(),
            "marker": past.marker.as_ref().map(marker_json),
        }))
    }

    /// Answers `history.restore`: the draft's state at `at` made current.
    ///
    /// The call is `history.restore(session, {draft, at, as_of})`, its
    /// answer `{draft, at, position, as_of, marker}` (the module doc;
    /// `shapes`' `Restored`).
    ///
    /// # Errors
    ///
    /// In this order:
    ///
    /// 1. `malformed_args` naming `draft` where it is no address in its one
    ///    spelling, then naming `at`, then `as_of`, where it is no
    ///    non-negative integer;
    /// 2. `malformed_args` naming `session`, then `session_died` or
    ///    `session_ended` ([`Shell::session`]);
    /// 3. the write door's, in its order (`Shell::write_door`):
    ///    `write_in_bare_session`, then `another_window`, naming the call;
    ///    `stopped`, `poisoned` or `halted` naming the op, `set_arrangement`,
    ///    where a hold stands at the board; `held_lines` naming the `draft`
    ///    and `held`, the lines of the principal's standing on it, where the
    ///    board has not kept them all — nothing read and nothing sent at any
    ///    of the four; then `store_unreadable`, `no_account`
    ///    (`Shell::signed`);
    /// 4. the reads' (`skep_client::history::past`): `unreadable` and
    ///    `no_such_document` at the draft's read, then `not_owner` with
    ///    `published` for a published document; `merge_refused` with
    ///    `not_past`, before any read at a position; at the state's reads,
    ///    `merge_refused` with `history_reclaimed`, `not_a_position`,
    ///    `history_busy` or `too_fragmented`, and `no_such_document` for a
    ///    draft that did not exist then; the records' reads' refusals; then
    ///    `over_cap`;
    /// 5. the write's (`skep_client::history::restore`): the board's
    ///    `arrangement_moved` verbatim where the draft's arrangement changed
    ///    past `as_of`, nothing changed; `not_owner`; `no_such_document`;
    ///    `merge_refused` with `window_withheld` or `needs_signed_session`;
    ///    the board's other verdicts verbatim; a halt's face where the
    ///    acknowledgment was lost;
    /// 6. `session_died` where a read or the write met the death signal,
    ///    and `unreachable` where a dial failed, at either step.
    pub(super) fn history_restore(&self, args: &Value) -> Result<Value, Refusal> {
        let draft = address_arg(&args["draft"]).ok_or_else(|| Refusal::malformed("draft"))?;
        let at = args["at"].as_u64().ok_or_else(|| Refusal::malformed("at"))?;
        let as_of = args["as_of"].as_u64().ok_or_else(|| Refusal::malformed("as_of"))?;
        let session = self.session(&args["session"])?;
        // The one write door, over the draft the restore sets whole.
        self.signed(&session, Write::call("history.restore", "set_arrangement").over([draft.to_string()]))?;
        let mut past = history::past(&session.board, &session.token, &draft, at).map_err(|r| self.merge_refusal(&session, r))?;
        // The write typed against the page's state; the read's position
        // kept for the answer's way back.
        let read_at = std::mem::replace(&mut past.as_of, as_of);
        // The write out until its position is noted, let go before a death
        // at it ends the session (`hold::WriteOut`; skep #1000).
        let out = self.holds.write_out(&session);
        let restored = out.noted(history::restore(&session.board, &session.token, &past), |restored| self.holds.note_restored(&session, restored));
        let restored = restored.map_err(|r| self.merge_refusal(&session, r))?;
        Ok(json!({
            "draft": restored.draft.to_string(),
            "at": restored.at,
            "position": restored.position,
            "as_of": way_back(read_at, as_of, restored.position),
            "marker": past.marker.as_ref().map(marker_json),
        }))
    }
}

/// Returns a restore's way back: a position the draft stood at before it.
///
/// The restore's write committed at `position`, typed at `typed`, the
/// shell's read made at `read_at`. A `position` past the read is a write
/// committed after it, and the draft stood at the read before that write:
/// the way back is `read_at`. A `position` at or below the read is the
/// board's memo answering the same restore sent again in the session — the
/// first write's, landed before this read, which found the restored state
/// (wire.md §Correlation and idempotency) — and the way back is `typed`:
/// the board took that write typed there, so the draft's arrangement did
/// not change between `typed` and the write (wire.md §Arrangement, the
/// typed state).
fn way_back(read_at: u64, typed: u64, position: u64) -> u64 {
    if position > read_at {
        read_at
    } else {
        typed
    }
}

/// Returns the core's runs as the page reads them (`shapes`' `Run`).
///
/// They are `state` and `sent`, in their V order. Each `origin` is the
/// trunk the run's words were minted under, so a member's own words stand
/// as the trunk's positions of the same ordinals (the module doc, **The
/// runs**).
fn runs_json(runs: &[Run]) -> Value {
    runs.iter().map(|run| json!({"origin": run.origin.to_string(), "i_start": run.i_start, "width": run.width})).collect()
}

/// Returns the runs a restore sends as the page reads them (`shapes`' `Run`).
///
/// They are `written`'s runs in V order (the module doc, **The runs**).
/// Each `origin` is the one the write names, taken from the write's own
/// spelling of the run (`history::written_runs`) — the document that minted
/// it, a member's version component kept (PUB-2.65) — so the answer and the
/// write name one address by one speller. `i_start` is the run's first
/// ordinal on that document's chain and `width` its positions, numbers as
/// `Run` declares them: the write's own `i_start` is the whole I-address
/// and its `width` a decimal string.
///
/// # Errors
///
/// A run that is no content I-address, the board's fault, faced: the fault
/// the restore's write meets over the same image (`history::written_runs`).
fn written_json(written: &Image) -> Result<Value, Halt> {
    let spelled = history::written_runs(written)?;
    Ok(written.runs().iter().zip(&spelled).map(|(run, wire)| json!({"origin": wire["origin"], "i_start": run.first, "width": run.width})).collect())
}

/// Returns a merge marker as the page reads it (`shapes`' `MergeMarker`).
///
/// Its `head_copied` is the decimal string `doc_metadata` serves it as.
pub(super) fn marker_json(m: &MergeMarker) -> Value {
    json!({"sides": m.sides, "head": m.head, "head_copied": m.head_copied.map(|n| n.to_string()), "at": m.at})
}

#[cfg(test)]
mod tests {
    use skep_client::board::whole_image;

    use super::*;

    /// Returns the image of `runs`, in V order.
    ///
    /// Each is an `image` answer's run: its first I-address and its width.
    fn image_of(runs: &[(&str, u64)]) -> Image {
        let runs: Vec<Value> = runs.iter().map(|(i_start, width)| json!({"i_start": i_start, "width": width.to_string()})).collect();
        whole_image(&json!({"resp": "runs", "runs": runs})).expect("an image")
    }

    /// Checks that the written runs name each run's own document.
    ///
    /// A trunk's run, a member's run whose ordinals follow it, a daughter's
    /// run and a draft's are answered in V order, each declared: `origin` the
    /// document that minted the run, its version components kept, `i_start`
    /// the run's first ordinal on that document's chain and `width` its
    /// positions, as numbers — four runs, the member's apart from the
    /// trunk's (the mutants that strip an origin to its trunk, join the
    /// member's run to the trunk's as the core's runs do, answer a run's
    /// V-ordinal as its `i_start`, or answer the write's own strings).
    #[test]
    fn the_written_runs_name_each_runs_own_document_and_its_ordinal_there() {
        let image = image_of(&[("1.0.1.0.64.0.1.5", 3), ("1.0.1.0.64.1.0.1.8", 4), ("1.0.1.0.64.1.1.0.1.2", 1), ("1.0.1.0.67.0.1.1", 2)]);
        let written = written_json(&image).unwrap_or_else(|halt| panic!("{halt:?}"));
        assert_eq!(
            written,
            json!([
                {"origin": "1.0.1.0.64", "i_start": 5, "width": 3},
                {"origin": "1.0.1.0.64.1", "i_start": 8, "width": 4},
                {"origin": "1.0.1.0.64.1.1", "i_start": 2, "width": 1},
                {"origin": "1.0.1.0.67", "i_start": 1, "width": 2},
            ])
        );
        for run in written.as_array().expect("the runs") {
            crate::shapes::assert_declared("Run", run);
        }
    }

    /// Checks that a run the write could not send is faced.
    ///
    /// An image holding a run in the link subspace, which is no content
    /// I-address, is the board's fault: the face names the run, as the
    /// restore's write over the same image would, and no run is answered
    /// (the mutant that answers the runs it could spell hands the page a
    /// state the restore refuses to write).
    #[test]
    fn a_run_that_is_no_content_i_address_is_faced_and_no_run_answered() {
        let image = image_of(&[("1.0.1.0.64.0.1.1", 3), ("1.0.1.0.64.0.2.1", 1)]);
        let halt = written_json(&image).unwrap_err();
        let Halt::Halt(face) = &halt else { panic!("a halt's face: {halt:?}") };
        assert!(face.cause.contains("1.0.1.0.64.0.2.1"), "the face names the run: {face:?}");
    }
}
