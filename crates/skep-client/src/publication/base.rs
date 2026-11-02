//! THE DRAFT'S BASE (`client.md` §4b.1's `publication.open` row, item 61;
//! B3-S10): the version a draft's publication lands after — the member the
//! request's `base` names — read off the board and never handed in, so a
//! draft publishes against the same base from any device and any index.
//!
//! A draft's base is THE BOARD'S RECORD of it (wire.md §Namespace, `stage`;
//! §The response envelope, `doc_metadata`): the `stage` that minted the
//! draft records the surface it copied — the version staged from, the bare
//! document while the chain is empty, or, for an alternative, the base its
//! source draft stood on — with the count the copy took, and each
//! publication the draft renders moves the record to the member it minted,
//! at that member's whole count. The newest member a draft made is the
//! board's to keep, so the read is two reads and no walk:
//!
//! 1. **The trunk.** `doc_metadata(doc)` first — a trunk the board does not
//!    hold, or one the reader may not read, is that fault, ahead of the
//!    draft's.
//! 2. **The draft.** `doc_metadata(draft)` once: its `base` and
//!    `base_copied`, the request's `base` and `base_extent` as the board
//!    records them — the extent the record's own, never read again.
//!
//! Where the board records no base — a draft `create_new_document` or `fork`
//! minted and never published, an alternative of such a draft — or records
//! one outside `doc`'s chain, the answer is `None`, never the trunk's head: a
//! draft begun from an older version would publish over the newer words, and
//! the caller refuses the open by name. A base the board names without its
//! count is an answer this client cannot read, never read as no base (SP-14).

use skep_address::Address;

use crate::address::parse_address;
use crate::board::{answers, frames};

use super::{shape, Door, Fault, Publisher};

/// Returns `draft`'s base in `doc`'s chain and the extent the copy took of
/// it, as the board records them.
///
/// It is the draft's `base` and `base_copied` where the base is `doc` itself
/// or a member of its chain, read as the module doc orders; `None` where the
/// board records no base for the draft, or one in another document's chain.
///
/// # Errors
///
/// In this order: the read of `doc`, then of `draft` — `Fault::NoSuchDocument`
/// or `Fault::Unreadable` naming the one at fault, a `Fault::Halt` for a
/// transport fault or another refusal; then `Fault::Shape` for a draft whose
/// answer names a base without its count, or one that is no address. Either
/// read answers `Fault::SessionEnded` at the death signal, and `Fault::Busy`
/// past its bounded reissues.
pub fn draft_base(p: &Publisher<'_>, doc: &Address, draft: &Address) -> Result<Option<(Address, u64)>, Fault> {
    let door = Door::new(p.board, p.token);
    door.step("base");
    let (doc_text, draft_text) = (doc.to_string(), draft.to_string());
    door.metadata(&doc_text)?;
    let frame = frames::doc_metadata(&draft_text);
    let answer = door.answered(&draft_text, &frame)?;
    let meta = answers::metadata(&answer).ok_or_else(|| shape(&frame, &answer))?;
    let Some(base) = meta.base else { return Ok(None) };
    let (Some(member), Some(copied)) = (parse_address(&base), meta.base_copied) else { return Err(shape(&frame, &answer)) };
    Ok(in_chain(&base, &doc_text).then_some((member, copied)))
}

/// Returns whether `addr` is `doc` or a member of its version chain: `doc`
/// followed by version components alone, never an element of its subspaces.
fn in_chain(addr: &str, doc: &str) -> bool {
    addr == doc || addr.strip_prefix(doc).and_then(|rest| rest.strip_prefix('.')).is_some_and(|rest| rest.split('.').all(|c| c != "0"))
}
