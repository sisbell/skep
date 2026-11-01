//! THE DRAFT'S BASE (`client.md` §4b.1's `publication.open` row, item 61;
//! B3-S10): the version a draft's publication lands after — the member the
//! request's `base` names — read off the board and never handed in, so a
//! draft publishes against the same base from any device and any index.
//!
//! A draft's base is the member its own newest publication into the chain
//! made, else the version its fork record names — the vocabulary's `3.9.4`,
//! written by the act that made the draft (`frames::T_FORK`):
//!
//! 1. **The trunk and the draft.** `doc_metadata(doc)` first — a trunk the
//!    board does not hold, or one the reader may not read, is that fault —
//!    then `doc_metadata(draft)`, whose `at`, the draft's mint, is where the
//!    feed read starts: no row at or before it can name the draft.
//! 2. **The newest rendering row.** `GET /changes?since=<the draft's
//!    mint>&under=<doc>` under the token, paged to the head — the trunk's
//!    history, not the draft's every keystroke — keeping the last `publish`
//!    row whose `docs` lead with a member of `doc`'s chain and name the
//!    draft as the first document after it that is not the trunk (the mint
//!    form's edition stands between): a publish row always names its
//!    rendering draft there, and an `also` draft only after it (wire.md §The
//!    change feed).
//! 3. **Else the fork record.** One four-set read of the draft's links of
//!    the type, `{home: [the draft], ty: [3.9.4]}`, each hit read once and
//!    kept where its stored type is `3.9.4` exactly (a query by type answers
//!    the parent `3.9` too), in address order — the first whose `to` names,
//!    as a unit span, `doc` itself or a member of its chain: the version the
//!    draft was begun from, the bare document while the chain is empty
//!    (wire.md §The publish shot and head-float: "a memberless document is
//!    its own base").
//! 4. **Its extent.** The address found, its content extent read: the
//!    request's `base_extent`.
//!
//! Where neither names a version of `doc` — a draft made with no record and
//! never published into the chain — the answer is `None`, never the trunk's
//! head: a draft begun from an older version would publish over the newer
//! words, and the caller refuses the open by name.
//!
//! **What the read cannot see.** A row whose testimony the board lost
//! (`docs` null, wire.md §`/changes`) names no draft and is no rendering
//! row, so a base it alone held is read older and the next publication
//! lands as a daughter beside the versions after it, never over them. A
//! `since` below the feed's first held line (`history_reclaimed`) is a fault,
//! never read as a history holding no row (SP-14).

use serde_json::Value;
use skep_address::Address;

use crate::address::parse_address;
use crate::board::frames::{self, Slot, T_FORK};
use crate::board::{ChangesAnswer, ChangesQuery};
use crate::halt::Halt;

use super::{trunk_of, Door, Fault, Publisher};

/// Returns `draft`'s base in `doc`'s chain and its content extent.
///
/// It is the member the draft's newest publication into the chain made,
/// else the version its fork record names — `doc` itself while the chain is
/// empty — read as the module doc orders; `None` where neither names one.
///
/// # Errors
///
/// In this order: the reads of `doc` and of `draft` — `Fault::NoSuchDocument`
/// or `Fault::Unreadable` naming the one at fault; the feed's — a
/// `Fault::Halt` for a `history_reclaimed` past the draft's mint, a
/// transport fault or a refusal; the record read's faults; and the extent's,
/// `NoSuchDocument` for a version the record names that the board does not
/// hold. Any read answers `Fault::SessionEnded` at the death signal, and a
/// read through the door `Fault::Busy` past its bounded reissues.
pub fn draft_base(p: &Publisher<'_>, doc: &Address, draft: &Address) -> Result<Option<(Address, u64)>, Fault> {
    let door = Door::new(p.board, p.token);
    door.step("base");
    let (doc_text, draft_text) = (doc.to_string(), draft.to_string());
    door.metadata(&doc_text)?;
    let minted = door.metadata(&draft_text)?.at.unwrap_or(0);
    let found = match newest_rendering_member(p, &doc_text, &draft_text, minted)? {
        Some(member) => Some(member),
        None => fork_record_base(&door, &doc_text, &draft_text)?,
    };
    let Some(base) = found else { return Ok(None) };
    let extent = door.extent(&base.to_string())?;
    Ok(Some((base, extent)))
}

/// Returns the member `draft`'s newest publication into `doc`'s chain made,
/// off the feed under `doc` from `since` to the head.
///
/// # Errors
///
/// `Fault::SessionEnded` at the death signal; a `Fault::Halt` for a
/// `history_reclaimed` (a hole in the feed past the draft's mint), a
/// transport fault or a refusal.
fn newest_rendering_member(p: &Publisher<'_>, doc: &str, draft: &str, mut since: u64) -> Result<Option<Address>, Fault> {
    let mut limit = None;
    let mut newest = None;
    loop {
        let query = ChangesQuery { since, under: Some(doc), drafts: false, limit };
        match p.board.changes(Some(p.token), &query)? {
            ChangesAnswer::Page(page) => {
                if let Some(member) = page.changes.iter().rev().find_map(|row| rendering_member(row, doc, draft)) {
                    newest = Some(member);
                }
                if !page.more {
                    return Ok(newest);
                }
                since = page.last;
            }
            // The page past the budget, re-asked at the limit that fits.
            ChangesAnswer::TooLarge { fits } => limit = Some(fits),
            ChangesAnswer::HistoryReclaimed { floor } => return Err(Fault::Halt(reclaimed(doc, draft, since, floor))),
            ChangesAnswer::Closed => return Err(Fault::SessionEnded),
        }
    }
}

/// Returns the member a `/changes` row minted where the row is a
/// publication into `doc`'s chain whose rendering draft is `draft`.
///
/// The row's `docs` lead with the member and name the rendering draft as
/// the first document after it that is not the trunk — the mint form's
/// edition stands between the two.
fn rendering_member(row: &Value, doc: &str, draft: &str) -> Option<Address> {
    if row["op"].as_str() != Some("publish") {
        return None;
    }
    let docs: Vec<&str> = row["docs"].as_array()?.iter().filter_map(Value::as_str).collect();
    let (&member, after) = docs.split_first()?;
    if member == doc || trunk_of(member).as_deref() != Some(doc) {
        return None;
    }
    let renderer = after.iter().find(|named| **named != doc)?;
    (*renderer == draft).then(|| parse_address(member)).flatten()
}

/// Returns the version `draft`'s fork record names in `doc`'s chain: the
/// first record of the exact type, in address order, whose `to` holds a unit
/// span at `doc` or at a member of its chain.
///
/// # Errors
///
/// The four-set read's and the record reads' faults.
fn fork_record_base(door: &Door<'_>, doc: &str, draft: &str) -> Result<Option<Address>, Fault> {
    let home = frames::unit_span(draft).as_array().cloned().unwrap_or_default();
    let ty = frames::unit_span(T_FORK).as_array().cloned().unwrap_or_default();
    let mut records: Vec<Address> = door.addrs(draft, &frames::find_links_four(Slot::Spans(&home), Slot::Any, Slot::Any, Slot::Spans(&ty)))?.iter().filter_map(|a| parse_address(a)).collect();
    records.sort();
    for record in records {
        let Some(value) = door.link(&record.to_string())? else { continue };
        if !value.typed_exactly(T_FORK) {
            continue;
        }
        if let Some(named) = value.to.iter().find(|span| span.is_unit() && in_chain(&span.start, doc)) {
            return Ok(parse_address(&named.start));
        }
    }
    Ok(None)
}

/// Returns whether `addr` is `doc` or a member of its version chain: `doc`
/// followed by version components alone, never an element of its subspaces.
fn in_chain(addr: &str, doc: &str) -> bool {
    addr == doc || addr.strip_prefix(doc).and_then(|rest| rest.strip_prefix('.')).is_some_and(|rest| rest.split('.').all(|c| c != "0"))
}

/// Returns the face of a feed whose history past the draft's mint lies in a
/// hole the board holds no rows for.
fn reclaimed(doc: &str, draft: &str, since: u64, floor: Option<u64>) -> Halt {
    let held = floor.map_or_else(|| "a later position".to_string(), |f| format!("position {f}"));
    Halt::face(
        format!("the board's change feed holds no rows from position {since} to {held}, where {draft}'s publications into {doc} may stand, so its base cannot be read"),
        "`/changes` answered `history_reclaimed`: a hole an earlier build's compaction left, or a region a lost record the journal could not re-cover",
        "nothing was published: stage a fresh draft from the version this one is to publish after",
    )
}
