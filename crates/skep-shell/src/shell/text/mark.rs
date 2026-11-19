//! `text.mark`: a private copy of a draft to diff against later (skep #1091).
//!
//! A caller about to change a draft marks it first:
//! `text.mark(session, {doc})`, the `text` family's fourth call, mints a
//! private document in the session's own account and places the draft's
//! whole content in it by identity, so the mark holds the very I-addresses
//! the draft held at the copy and `text.diff` later tells, by identity, what
//! the draft has kept of them. Nothing of the text is read or written anew.
//! The module makes the call out of the parent's own pieces — its calls
//! under the session the call stands under, its one burst and the line it
//! settles.
//!
//! **The writes.** The draft's extent is read first, so a draft the session
//! may not read, or one the board does not register, refuses the call with
//! nothing written (SP-8). Then, in order:
//!
//! 1. `create_new_document` in the session's account, private: the mark.
//! 2. One `copy` into it of the draft's whole content — one source span
//!    from the first content position past every position a draft can hold,
//!    which the board clips to what the draft arranges at the copy's commit
//!    — typed against the create's commit. A draft read empty is not copied.
//! 3. One `make_link` typed `marks` (`3.25`) and homed in the mark: its
//!    `from` the mark's whole content in the V-spec form, the span the copy
//!    named, which the board stores as the I-spans the mark holds — the
//!    draft's own, a `copy` minting none — and the empty list for a draft
//!    read empty; its `to` the draft, by address. The link says what the
//!    document is and which draft it marks, so a mark is found from its
//!    draft by a link read, and from the draft's text, whose bytes its
//!    `from` is.
//!
//! The mark is no staged draft: it records no base and no source, so no
//! publication of the draft lists it among the drafts it leaves behind, and
//! its link is a record class no publication offers
//! (`skep_client::publication`'s `is_record_class`).
//!
//! **What each write leaves.** The create's refusal is the call's, nothing
//! written; under a hold standing at the board the call is refused at the
//! write door before its first read (`Shell::text_mark`). The copy is a
//! burst: its line, where the shell holds it, is settled as `text.replace`
//! settles one (`settle`) — dropped, the call answers `refused` with the
//! board's verdict, naming the empty document the create left (`mark`);
//! found landed, the call goes on; and where the shell would not drop it,
//! the call answers `held`, an error naming the line and the mark. A link
//! the board refuses — a mark holding more runs than a slot's budget is
//! refused `slot_too_large` — or whose answer is lost answers `partial`, an
//! error: the copy stands, usable as `text.diff`'s `since`, and carries no
//! `marks` link. The link is not sent again. A process that ends between
//! two of the writes answers nothing: after the create it leaves an empty
//! document, after the copy a copy with no link.
//!
//! **The answer.** One JSON object keyed by `outcome`: `marked`, `refused`,
//! `held` and `partial` (`shapes`' `TextMarked`, `TextRefused`,
//! `TextMarkHeld`, `TextMarkPartial`). `marked` names the mark, the link and
//! the link's commit.
//!
//! **The cost** (SP-23). One read and three writes at most, whatever the
//! draft holds: the board resolves the copy and the link's `from` against
//! its own arrangements.

use serde_json::{json, Value};
use skep_client::address::is_address_text;
use skep_client::board::frames;

use super::{content_extent, held, refused_write, settle, unread, write, Answer, Calls, Settled, Wrote, WHOLE_CONTENT};
use crate::refusal::Refusal;

/// What the call is asked: the draft to mark.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Asked<'a> {
    /// The draft, an address in its one spelling.
    doc: &'a str,
}

impl<'a> Asked<'a> {
    /// Reads `text.mark`'s one member off `args`.
    ///
    /// # Errors
    ///
    /// `malformed_args` naming `doc` where it is no address in its one
    /// spelling.
    pub(super) fn read(args: &'a Value) -> Result<Asked<'a>, Refusal> {
        let doc = args["doc"].as_str().filter(|doc| is_address_text(doc)).ok_or_else(|| Refusal::malformed("doc"))?;
        Ok(Asked { doc })
    }
}

/// Returns `answer` naming `mark`, the document the create left.
///
/// A refusal made after the first write names what that write left (SP-8).
fn naming(mut answer: Answer, mark: &str) -> Answer {
    answer.value["mark"] = Value::from(mark);
    answer
}

/// Returns the answer of a mark whose link did not land, an error.
///
/// The copy stands in `mark` with no `marks` link. `at` is the last write
/// that landed — the copy's commit, the create's where the draft was read
/// empty — absent where the copy's own answer was lost; `why` says what
/// stopped the link: a `cause`, and the `refusal` or the `op` beside it.
fn partial(doc: &str, mark: &str, at: Option<u64>, why: Value) -> Answer {
    let mut value = json!({"outcome": "partial", "doc": doc, "mark": mark});
    if let Some(at) = at {
        value["at"] = Value::from(at);
    }
    if let (Some(members), Value::Object(why)) = (value.as_object_mut(), why) {
        members.extend(why);
    }
    Answer::error(value)
}

/// Makes the mark `asked` in `account`, the session's, through `calls`.
///
/// In order: the draft's extent is read; the mark is minted; the draft's
/// whole content is copied into it, typed against the mint, where the draft
/// was read to hold any; and the `marks` link is written (the module doc's
/// *The writes*). Nothing is written before the refusals the read decides
/// (SP-8), and a refusal past the mint names the mark.
///
/// # Errors
///
/// The board's verdict on the read or the mint, or the shell's refusal of
/// either, nothing written. Every other outcome is an [`Answer`].
pub(super) fn mark(calls: &impl Calls, asked: &Asked<'_>, account: &str) -> Result<Answer, Refusal> {
    let doc = asked.doc;
    let Some(extent) = content_extent(&calls.op(frames::span_set(doc))?) else {
        return Ok(unread(doc, "retrieve_doc_v_span_set"));
    };
    let minted = calls.op(frames::create_document(account, false, None))?;
    let (Some(mark), Some(minted_at)) = (minted["addr"].as_str(), minted["at"].as_u64()) else {
        return Ok(unread(doc, "create_new_document"));
    };
    let whole = [(mark, 1, WHOLE_CONTENT)];
    let (from, at) = if extent == 0 {
        (&whole[..0], Some(minted_at))
    } else {
        let at = match write(calls, frames::copy(mark, 1, &[(doc, 1, WHOLE_CONTENT)], minted_at, None)) {
            Ok(Wrote::Acked(ack)) => ack["at"].as_u64(),
            Ok(Wrote::Held(line)) => match settle(calls, line) {
                Settled::Landed => None,
                Settled::Dropped { cause, verdict } => return Ok(naming(refused_write(doc, &cause, verdict), mark)),
                Settled::Standing(line) => return Ok(held(doc, &line, "copy", json!({"mark": mark}))),
            },
            Err(refusal) => return Ok(Answer::error(json!({"outcome": "refused", "cause": refusal.name(), "doc": doc, "mark": mark, "refusal": refusal.to_value()}))),
        };
        (&whole[..], at)
    };
    Ok(match calls.op(frames::make_link_spec(mark, from, &[doc], frames::T_MARKS, None)) {
        Ok(ack) => match (ack["addr"].as_str(), ack["at"].as_u64()) {
            (Some(link), Some(at)) => Answer::data(json!({"outcome": "marked", "doc": doc, "mark": mark, "link": link, "at": at})),
            _ => partial(doc, mark, at, json!({"cause": "unread", "op": "make_link"})),
        },
        Err(refusal) => partial(doc, mark, at, json!({"cause": refusal.name(), "refusal": refusal.to_value()})),
    })
}

#[cfg(test)]
mod tests;
