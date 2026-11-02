//! THE DRAFT'S BASE (`client.md` §4b.1's `publication.open` row, item 61;
//! B3-S10): the version a draft's publication lands after — the member the
//! request's `base` names — read off the board and never handed in, so a
//! draft publishes against the same base from any device and any index;
//! THE BASE'S STANDING against the document's newest version; and THE
//! FAMILY a publication leaves behind.
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
//! Where the board records no base in `doc`'s chain the answer is
//! [`Base::Unrecorded`] with its reason, never the trunk's head: a draft
//! begun from an older version would publish over the newer words, and the
//! caller refuses the open by name. The reason is read off the same answer:
//! no base and no `source` outside the chain, a draft `create_new_document`
//! or `fork` minted and never staged; a base in another document's chain;
//! no base and a `source` outside the chain, an alternative of a draft the
//! board records no base for. A base the board names without its count is
//! an answer this client cannot read, never read as no base (SP-14).
//!
//! **The standing** ([`standing`]) is typed by ONE PROBE: the trunk member
//! after the base's — `doc`'s first member for the bare document, the
//! member after `⟨doc⟩.k` for a base `⟨doc⟩.k` or any daughter under it —
//! read by `doc_metadata`. Its answer says the trunk moved past the base;
//! `doc_not_registered` says it did not. No read answers a document's head
//! member, and a walk of the feed for it fails where the history is
//! reclaimed; the probe needs neither, and names no head member. The
//! successor rule is the merge's (`merge::reads`), copied here, since this
//! module stands outside the merge's feature.
//!
//! **The family left behind** ([`left_behind`]) is every draft `also` names,
//! then — where this publication becomes the head — every other draft of
//! the person's own whose recorded base is this draft's: one `doc_metadata`
//! of each, read as the draft's own is. No read answers the drafts staged
//! on a version, so the loop is over the caller's own list of drafts.

use skep_address::{validate, Address, Nat, Tumbler};

use crate::address::parse_address;
use crate::board::{answers, frames};

use super::{shape, Door, Fault, Inputs, Publisher};

/// A draft's base as the board records it, asked of `doc`'s chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Base {
    /// The base in `doc`'s chain, as the request carries it.
    Recorded {
        /// `doc` itself, or a member of its chain.
        base: Address,
        /// The extent the draft's copy took of it, `base_copied`.
        copied: u64,
    },
    /// No base in `doc`'s chain, and why.
    Unrecorded(Unrecorded),
}

/// Why the board records no base in `doc`'s chain for a draft.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Unrecorded {
    /// No base, and no `source` or one in `doc`'s own chain: a draft
    /// `create_new_document` or `fork` minted and never staged.
    NoRecord,
    /// A recorded base in another document's chain.
    OtherChain,
    /// No base, and a `source` outside `doc`'s chain: an alternative of a
    /// draft the board records no base for.
    FreeStanding,
}

/// Where a draft's recorded base stands against `doc`'s newest version.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Standing {
    /// No trunk member follows the base's: the next publication is the
    /// trunk's next member, the head.
    AtHead,
    /// A trunk member follows the base's: the next publication lands as the
    /// base's daughter, and the head does not move.
    Behind,
    /// The base is the bare document and its chain is empty: the next
    /// publication is its first member.
    First,
    /// The base is the bare document and its first member stands: the board
    /// refuses the shot `base_superseded`.
    SupersededFirst {
        /// `doc`'s first member, `⟨doc⟩.1`.
        first: Address,
    },
}

/// Returns `draft`'s base in `doc`'s chain and the extent the copy took of
/// it, as the board records them, or why it records none there.
///
/// It is the draft's `base` and `base_copied` where the base is `doc` itself
/// or a member of its chain, read as the module doc orders; else
/// [`Base::Unrecorded`] naming the reason.
///
/// # Errors
///
/// In this order: the read of `doc`, then of `draft` — `Fault::NoSuchDocument`
/// or `Fault::Unreadable` naming the one at fault, a `Fault::Halt` for a
/// transport fault or another refusal; then `Fault::Shape` for a draft whose
/// answer names a base without its count, or one that is no address. Either
/// read answers `Fault::SessionEnded` at the death signal, and `Fault::Busy`
/// past its bounded reissues.
pub fn draft_base(p: &Publisher<'_>, doc: &Address, draft: &Address) -> Result<Base, Fault> {
    let door = Door::new(p.board, p.token);
    door.step("base");
    let doc_text = doc.to_string();
    door.metadata(&doc_text)?;
    recorded(&door, &doc_text, draft)
}

/// Reads `draft`'s base off one `doc_metadata` of it, typed against `doc`'s
/// chain: the draft's read of [`draft_base`], and each of [`left_behind`]'s.
fn recorded(door: &Door<'_>, doc: &str, draft: &Address) -> Result<Base, Fault> {
    let draft_text = draft.to_string();
    let frame = frames::doc_metadata(&draft_text);
    let answer = door.answered(&draft_text, &frame)?;
    let meta = answers::metadata(&answer).ok_or_else(|| shape(&frame, &answer))?;
    let Some(base) = meta.base else {
        let free = meta.source.is_some_and(|source| !in_chain(&source, doc));
        return Ok(Base::Unrecorded(if free { Unrecorded::FreeStanding } else { Unrecorded::NoRecord }));
    };
    let (Some(member), Some(copied)) = (parse_address(&base), meta.base_copied) else { return Err(shape(&frame, &answer)) };
    Ok(if in_chain(&base, doc) { Base::Recorded { base: member, copied } } else { Base::Unrecorded(Unrecorded::OtherChain) })
}

/// Returns where `base` stands against `doc`'s newest version, off one probe.
///
/// The probe is `doc_metadata` of the trunk member after `base`'s (the
/// module doc): an answer is [`Standing::SupersededFirst`] for the bare
/// document and [`Standing::Behind`] otherwise; `doc_not_registered` is
/// [`Standing::First`] for the bare document and [`Standing::AtHead`]
/// otherwise.
///
/// # Errors
///
/// The probe's other faults, as [`draft_base`]'s reads answer them:
/// `Fault::Unreadable`, `Fault::Shape`, `Fault::SessionEnded`, `Fault::Busy`
/// and a `Fault::Halt` — never read as the member's absence (SP-14).
///
/// # Panics
///
/// Panics where `base` is neither `doc` nor a member of its chain: the
/// caller owes the base [`draft_base`] answers, which is.
pub fn standing(p: &Publisher<'_>, doc: &Address, base: &Address) -> Result<Standing, Fault> {
    let next = successor(doc, base).expect("a base in doc's chain");
    let bare = base == doc;
    let door = Door::new(p.board, p.token);
    door.step("standing");
    match door.metadata(&next.to_string()) {
        Ok(_) if bare => Ok(Standing::SupersededFirst { first: next }),
        Ok(_) => Ok(Standing::Behind),
        Err(Fault::NoSuchDocument(_)) if bare => Ok(Standing::First),
        Err(Fault::NoSuchDocument(_)) => Ok(Standing::AtHead),
        Err(e) => Err(e),
    }
}

/// Returns the drafts a publication of `inputs.draft` leaves behind.
///
/// Every draft `inputs.also` names, in its order; then, where the
/// publication becomes the head — `standing` [`Standing::AtHead`] or
/// [`Standing::First`] — every other draft of `own`, the person's own in the
/// caller's order, whose recorded base is the rendering draft's
/// (`inputs.base`): one `doc_metadata` of each, read as [`draft_base`] reads
/// the draft's, the rendering draft and those `also` names read never. At
/// [`Standing::Behind`] the publication lands as a daughter and leaves no
/// other draft behind. None at the mint form, which has no base.
///
/// # Errors
///
/// A read's faults as [`draft_base`]'s draft read answers them, but
/// `Fault::NoSuchDocument`: a draft the board no longer holds is passed
/// over, since the caller's list can lag a removal.
pub fn left_behind(p: &Publisher<'_>, inputs: &Inputs, standing: &Standing, own: &[Address]) -> Result<Vec<Address>, Fault> {
    let (Some(doc), Some((base, _))) = (&inputs.doc, &inputs.base) else { return Ok(Vec::new()) };
    let mut out = inputs.also.clone();
    if !matches!(standing, Standing::AtHead | Standing::First) {
        return Ok(out);
    }
    let door = Door::new(p.board, p.token);
    door.step("left_behind");
    let doc = doc.to_string();
    for other in own.iter().filter(|o| !inputs.is_named_draft(o)) {
        match recorded(&door, &doc, other) {
            Ok(Base::Recorded { base: theirs, .. }) if theirs == *base => out.push(other.clone()),
            Ok(_) | Err(Fault::NoSuchDocument(_)) => {}
            Err(e) => return Err(e),
        }
    }
    Ok(out)
}

/// Returns whether `addr` is `doc` or a member of its version chain: `doc`
/// followed by version components alone, never an element of its subspaces.
fn in_chain(addr: &str, doc: &str) -> bool {
    addr == doc || addr.strip_prefix(doc).and_then(|rest| rest.strip_prefix('.')).is_some_and(|rest| rest.split('.').all(|c| c != "0"))
}

/// Returns the trunk member after the one `base` is or lies under: `doc`'s
/// first member where `base` is `doc` itself, `⟨doc⟩.(k+1)` for `⟨doc⟩.k`
/// and every member under it — the merge's successor rule, its one version
/// component plus one. `None` where `base` is neither `doc` nor a member of
/// its chain.
fn successor(doc: &Address, base: &Address) -> Option<Address> {
    let doc: Vec<Nat> = doc.tumbler().iter().cloned().collect();
    let comps: Vec<Nat> = base.tumbler().iter().cloned().collect();
    let version = comps.strip_prefix(doc.as_slice())?;
    if version.contains(&Nat::from(0u32)) {
        return None;
    }
    let one = Nat::from(1u32);
    let next = version.first().map_or_else(|| one.clone(), |k| k + &one);
    validate(Tumbler::new(doc.into_iter().chain(std::iter::once(next))).ok()?).ok()
}
