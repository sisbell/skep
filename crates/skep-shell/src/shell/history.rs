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
//! `at` and the person's correspondence records at the head, the state's
//! runs mapped through them so words published since come back as the
//! published words they became. It is the page's read while the person
//! rests on a past state, before "make this state current": what the
//! state brings back, and the links the change would orphan, which the
//! page reads over the mapped runs (B3-S7's orphan line). It sends no
//! write, so it asks no write door (SP-31 binds the rows that write): a
//! bare session reads it, a second window reads it, a hold standing at the
//! board stops none of its reads, and nothing of the hold, the panels or
//! the compositions is touched. Its answer is `{draft, at, as_of, state,
//! sent, covered, marker}`: `state` the runs as read at `at`, for drawing;
//! `sent` the same positions mapped, what a restore made now would send;
//! `covered` the positions a record covers; `marker` as the restore
//! answers it; and `as_of` the position the reads were made at, which is
//! no typed state (**The typed state is the page's**). The restore reads
//! again for itself, so nothing this answer carries reaches its write.
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
//! session, then the account it acts as, whose records the reads ask for;
//! then the reads. The restore's members are read before the session —
//! `draft`, then `at` and `as_of`, non-negative integers — then the
//! session; then the shell's one write door and the session's hand, as the
//! publication and merge families take them (`Shell::signed`,
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
//! `position` the write's commit; `as_of` the position the draft stood at
//! as the shell's read found it, before the write — the way back, this row
//! again at `{at: as_of}` typed at `position`; and `marker` the draft's
//! merge marker as it stands, which a restore never takes out, or null.
//!
//! **The note.** The write's position is noted in the hold as an
//! acknowledged arrangement write of the principal's on the draft
//! (`Holds::note_restored`): `merge.undo`, typed against the editor's own
//! last arrangement write on the draft (P3), takes a restore of the
//! person's as their own, and the next hold on the draft reads from past it.
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
use skep_client::board::MergeMarker;
use skep_client::history;
use skep_client::merge::Run;

use super::publication::address_arg;
use super::{Shell, Write};
use crate::refusal::{Name, Refusal};

impl Shell {
    /// Answers `history.past`: the draft's state at `at`, read and mapped.
    ///
    /// The call is `history.past(session, {draft, at})`, its answer `{draft,
    /// at, as_of, state, sent, covered, marker}` (the module doc; `shapes`'
    /// `Past`). It sends no write and asks no write door, and its reads are
    /// `skep_client::history::past`'s, the ones [`Shell::history_restore`]
    /// makes before its write (B3-S7).
    ///
    /// # Errors
    ///
    /// In this order:
    ///
    /// 1. `malformed_args` naming `draft` where it is no address in its one
    ///    spelling, then naming `at` where it is no non-negative integer;
    /// 2. `malformed_args` naming `session`, then `session_died` or
    ///    `session_ended` ([`Shell::session`]);
    /// 3. `no_account` where the board answered the session no account;
    /// 4. the reads', as [`Shell::history_restore`]'s step 4 names them;
    /// 5. `session_died` where a read met the death signal, and
    ///    `unreachable` where a dial failed.
    pub(super) fn history_past(&self, args: &Value) -> Result<Value, Refusal> {
        let draft = address_arg(&args["draft"]).ok_or_else(|| Refusal::malformed("draft"))?;
        let at = args["at"].as_u64().ok_or_else(|| Refusal::malformed("at"))?;
        let session = self.session(&args["session"])?;
        let account = session.facts.account.as_deref().ok_or_else(|| Refusal::shell(Name::NO_ACCOUNT, json!({})))?;
        let past = history::past(&session.board, &session.token, account, &draft, at).map_err(|r| self.merge_refusal(&session, r))?;
        Ok(json!({
            "draft": past.draft.to_string(),
            "at": past.at,
            "as_of": past.as_of,
            "state": runs_json(&past.state),
            "sent": runs_json(&past.sent),
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
        let account = self.signed(&session, Write::call("history.restore", "set_arrangement").over([draft.to_string()]))?.account;
        let mut past = history::past(&session.board, &session.token, &account, &draft, at).map_err(|r| self.merge_refusal(&session, r))?;
        // The write typed against the page's state; the read's position
        // kept for the answer, the way back.
        let read_at = std::mem::replace(&mut past.as_of, as_of);
        let restored = history::restore(&session.board, &session.token, &past).map_err(|r| self.merge_refusal(&session, r))?;
        self.holds.note_restored(&session, &restored);
        Ok(json!({
            "draft": restored.draft.to_string(),
            "at": restored.at,
            "position": restored.position,
            "as_of": read_at,
            "marker": past.marker.as_ref().map(marker_json),
        }))
    }
}

/// Returns a past state's runs as the page reads them (`shapes`' `Run`).
///
/// They keep their V order.
fn runs_json(runs: &[Run]) -> Value {
    runs.iter().map(|run| json!({"origin": run.origin.to_string(), "i_start": run.i_start, "width": run.width})).collect()
}

/// Returns a merge marker as the page reads it (`shapes`' `MergeMarker`).
///
/// Its `head_copied` is the decimal string `doc_metadata` serves it as.
pub(super) fn marker_json(m: &MergeMarker) -> Value {
    json!({"sides": m.sides, "head": m.head, "head_copied": m.head_copied.map(|n| n.to_string()), "at": m.at})
}
