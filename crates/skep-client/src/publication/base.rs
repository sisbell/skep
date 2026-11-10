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
//! **The standing** ([`standing`]) is typed off the base's place in `doc`'s
//! chain and `doc_metadata` reads of the trunk members past it. The head a
//! shot's base is judged against is a trunk member `⟨doc⟩.k`, never a
//! daughter (PUB-2.53), so a base under a trunk member — `⟨doc⟩.k.…`, where
//! a daughter's publication moves its draft's base, or a member a draft was
//! staged from — is never the head: its shot lands as the base's own
//! daughter, the head unmoved (PUB-2.37, PUB-2.55), and it stands
//! [`Standing::Behind`] by its address, whatever the reads find (skep #807).
//! The bare document is typed by one read of `doc`'s first member, a trunk
//! member by a read of the member after it: an answer says the trunk moved
//! past the base, `doc_not_registered` says it did not. The successor rule
//! is the merge's (`merge::reads`), a trunk member's one version component
//! plus one, copied here, since this module stands outside the merge's
//! feature. Every standing is told, none refused: a draft begun from the
//! bare document whose first member now stands
//! ([`Standing::SupersededFirst`]) publishes beside that member as its
//! daughter, as a draft behind the head publishes beside its base.
//!
//! **The head** a behind base names is the trunk's newest member. No read
//! answers it, and a walk of the feed for it fails where the history is
//! reclaimed, so it is found from the trunk member the base stands on or
//! under: the members `k+1`, `k+2`, `k+4`, … read until one is not
//! registered, then a binary search between the last that was and that one,
//! as a home's frontier is found (`landed`'s `deposits_at`). Trunk members
//! are minted one after another off one frontier, so none stands past one
//! that does not and the search's test is monotonic: a base at the head
//! takes one read, a base one version behind two, a base a hundred behind
//! fourteen. The doubling ends with `u64`: a board answering every member
//! read is refused [`Fault::Shape`] after 64 reads, not walked without end
//! (SP-17).
//!
//! **The family left behind** ([`left_behind`]) is every draft `also` names,
//! then — where this publication becomes the head — every other draft of
//! the person's own whose recorded base is this draft's: one `doc_metadata`
//! of each, read as the draft's own is. No read answers the drafts staged
//! on a version, so the loop is over the caller's own list of drafts.

use skep_address::{validate, Address, Nat, Tumbler};

use crate::address::parse_address;
use crate::board::{answers, frames};

use super::{shape, Door, Fault, Publisher};

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
    /// The base is the trunk's newest member: the next publication is the
    /// trunk's next member, the new head.
    AtHead,
    /// The base is a trunk member a later one follows, or a member under a
    /// trunk member: the next publication lands as the base's daughter, and
    /// the head does not move.
    Behind {
        /// The trunk's newest member. Under a trunk member no later one
        /// follows, that member itself.
        head: Address,
    },
    /// The base is the bare document and its chain is empty: the next
    /// publication is its first member.
    First,
    /// The base is the bare document and its first member stands: the next
    /// publication lands beside `first` as its daughter, and the head does
    /// not move — a draft begun before any version, published beside
    /// version 1.
    SupersededFirst {
        /// `doc`'s first member, `⟨doc⟩.1`, the daughter's parent.
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

/// Returns where `base` stands against `doc`'s newest version.
///
/// The bare document is typed by `doc_metadata` of its first member: an
/// answer is [`Standing::SupersededFirst`] and `doc_not_registered` is
/// [`Standing::First`]. A trunk member is typed by the head read: a later
/// member standing is [`Standing::Behind`] naming the newest, and none is
/// [`Standing::AtHead`]. A base under a trunk member is
/// [`Standing::Behind`] by its address, the head read from the trunk
/// member above it, which names that member where no later one stands
/// (the module doc).
///
/// # Errors
///
/// The reads' other faults, as [`draft_base`]'s reads answer them:
/// `Fault::Unreadable`, `Fault::Shape`, `Fault::SessionEnded`, `Fault::Busy`
/// and a `Fault::Halt` — never read as the member's absence (SP-14); and
/// `Fault::Shape` where the board answers every member the head read asks,
/// its doubling spent.
///
/// # Panics
///
/// Panics where `base` is neither `doc` nor a member of its chain: the
/// caller owes the base [`draft_base`] answers, which is.
pub fn standing(p: &Publisher<'_>, doc: &Address, base: &Address) -> Result<Standing, Fault> {
    let door = Door::new(p.board, p.token);
    door.step("standing");
    Ok(match place(doc, base).expect("a base in doc's chain") {
        Place::Bare { first } => if stands(&door, &first)? { Standing::SupersededFirst { first } } else { Standing::First },
        Place::Trunk => head_past(&door, base)?.map_or(Standing::AtHead, |head| Standing::Behind { head }),
        Place::Under { trunk } => Standing::Behind { head: head_past(&door, &trunk)?.unwrap_or(trunk) },
    })
}

/// Returns whether `member` is registered, off one `doc_metadata` of it.
///
/// # Errors
///
/// The read's faults but `Fault::NoSuchDocument`, which is its answer.
fn stands(door: &Door<'_>, member: &Address) -> Result<bool, Fault> {
    match door.metadata(&member.to_string()) {
        Ok(_) => Ok(true),
        Err(Fault::NoSuchDocument(_)) => Ok(false),
        Err(e) => Err(e),
    }
}

/// Returns the newest trunk member past `member`, a registered trunk member:
/// the trunk's head, or `None` where the member after `member` is not
/// registered, `member` then being the head itself.
///
/// The read is the module doc's: doubling, then a binary search.
///
/// # Errors
///
/// [`stands`]'s; and `Fault::Shape` where every member the doubling asks is
/// registered, up to the last offset a `u64` holds.
fn head_past(door: &Door<'_>, member: &Address) -> Result<Option<Address>, Fault> {
    let past = |by: u64| -> Address {
        let mut comps: Vec<Nat> = member.tumbler().iter().cloned().collect();
        *comps.last_mut().expect("an address has a component") += by;
        validate(Tumbler::new(comps).expect("an address has a component")).expect("a trunk member's version component, raised, spells a trunk member")
    };
    let (mut found, mut probe) = (0u64, 1u64);
    while stands(door, &past(probe))? {
        found = probe;
        probe = probe.checked_mul(2).ok_or_else(|| Fault::Shape { op: "doc_metadata".to_string(), body: format!("every trunk member asked past {member} answered, to {}", past(found)) })?;
    }
    let mut missing = probe;
    while missing - found > 1 {
        let mid = found + (missing - found) / 2;
        if stands(door, &past(mid))? {
            found = mid;
        } else {
            missing = mid;
        }
    }
    Ok((found > 0).then(|| past(found)))
}

/// Returns the drafts a publication of `draft`, based on `base` in `doc`'s
/// chain, leaves behind.
///
/// Every draft `also` names, in its order; then, where the publication
/// becomes the head — `standing` [`Standing::AtHead`] or
/// [`Standing::First`] — every other draft of `own`, the person's own in the
/// caller's order, whose recorded base is `base`: one `doc_metadata` of
/// each, read as [`draft_base`] reads the draft's, `draft` and those `also`
/// names read never. At [`Standing::Behind`] and
/// [`Standing::SupersededFirst`] the publication lands as a daughter and
/// leaves no other draft behind.
///
/// # Errors
///
/// A read's faults as [`draft_base`]'s draft read answers them, but
/// `Fault::NoSuchDocument`: a draft the board no longer holds is passed
/// over, since the caller's list can lag a removal.
pub fn left_behind(p: &Publisher<'_>, doc: &Address, base: &Address, draft: &Address, also: &[Address], standing: &Standing, own: &[Address]) -> Result<Vec<Address>, Fault> {
    let mut out = also.to_vec();
    if !matches!(standing, Standing::AtHead | Standing::First) {
        return Ok(out);
    }
    let door = Door::new(p.board, p.token);
    door.step("left_behind");
    let doc = doc.to_string();
    for other in own.iter().filter(|o| *o != draft && !also.contains(o)) {
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

/// Where a base lies in `doc`'s version chain.
enum Place {
    /// `doc` itself, read at its first member, `⟨doc⟩.1`.
    Bare { first: Address },
    /// A trunk member `⟨doc⟩.k`, the head read from it.
    Trunk,
    /// A member under a trunk member, `⟨doc⟩.k.…`: never the head
    /// (PUB-2.53), the head read from `trunk`, that member.
    Under { trunk: Address },
}

/// Returns where `base` lies in `doc`'s version chain.
///
/// That is `doc` itself, a trunk member — `doc` and one version component —
/// or a member under one, the first naming `⟨doc⟩.1` and the last its trunk
/// member by the version component it opens with. `None` where `base` is
/// neither `doc` nor a member of its chain.
fn place(doc: &Address, base: &Address) -> Option<Place> {
    let doc: Vec<Nat> = doc.tumbler().iter().cloned().collect();
    let comps: Vec<Nat> = base.tumbler().iter().cloned().collect();
    let version = comps.strip_prefix(doc.as_slice())?;
    if version.contains(&Nat::from(0u32)) {
        return None;
    }
    let member = |k: &Nat| -> Option<Address> { validate(Tumbler::new(doc.iter().cloned().chain(std::iter::once(k.clone()))).ok()?).ok() };
    match version {
        [] => Some(Place::Bare { first: member(&Nat::from(1u32))? }),
        [_] => Some(Place::Trunk),
        [k, ..] => Some(Place::Under { trunk: member(k)? }),
    }
}
