//! The landing's terms (the landing lane; skep #764): the head a merge was
//! composed on, the base to record and the merge a draft is to carry, as an
//! edit carries them, judged against the draft's chain and written as the
//! base record beside the edit's own.
//!
//! The edit ([`Vstream::edit`](super::Vstream::edit)) is one composition
//! under two wire names, and the terms ride it under both: a merge's
//! landing into a draft, its undo, a withdrawal and a restore are sent as
//! `set_arrangement`, whose changes place runs by identity, and a call that
//! mints text may name the same three members. This module holds what is
//! theirs alone — [`SetMerge`], the judgment of the three off the
//! transaction's working world ([`judge`]) and the record that moves the
//! base ([`base_record`]): the one that stamps a landing's marker at the
//! commit, or the one that puts a marker the fold stamped on the draft back
//! as it stood (skep #870). It adds no rule of composition: what an edit
//! places is what it is sent, as REINSTATE places what it is sent.

use skep_address::Address;
use skep_kernel::Seq;
use skep_namespace::M3State;

use crate::chain::{published_target, trunk_head, trunk_of};
use crate::error::EditError;
use crate::shot::Base;
use crate::state::{DraftBase, M5Rec, M5State, Marker, Merge};

/// The merge an edit carries where it lands one (skep #870).
///
/// It is the marker's sides and, where the request puts a marker back, its
/// position.
/// A landing names the sides alone, and the fold stamps the marker at the
/// landing's own commit. A take-back's undo names the position too: the
/// marker the take-back cleared is put back as it stood, so the draft and
/// its marker stand after the undo as they stood before the take-back,
/// the marker's `at` still its landing's. The position is admitted only
/// where it names a marker the fold stamped on the draft
/// ([`DraftBase::stamped`]), so no request makes a marker's `at` a
/// position where nothing landed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SetMerge {
    /// The sides merged, by address; empty for the draft-side shape.
    pub sides: Vec<Address>,
    /// The position of the marker put back, or `None` for a landing.
    ///
    /// Where present, the marker of these sides, the request's head pair
    /// and this position must be one of the draft's stamps, and the request
    /// must name the base to record beside it
    /// (`EditError::MarkerNotRestorable` otherwise).
    pub at: Option<Seq>,
}

/// The three terms of one request, lent: its head, its base and its merge.
#[derive(Clone, Copy, Debug)]
pub(super) struct Terms<'a> {
    /// The head the merge was composed on, at the extent read.
    pub(super) head: Option<&'a Base>,
    /// The base to record, with its extent.
    pub(super) base: Option<&'a Base>,
    /// The marker's sides and position.
    pub(super) merge: Option<&'a SetMerge>,
}

/// What [`judge`] found, which [`base_record`] writes by.
#[derive(Clone, Debug)]
pub(super) struct Judged {
    /// The draft's recorded base as it stands, where the board records one.
    standing: Option<DraftBase>,
    /// The stamped marker the request's merge puts back, where it names a
    /// position.
    restored: Option<Marker>,
    /// The trunk's current head, where the request named a head that is no
    /// longer it: the tell (R5).
    pub(super) head_moved: Option<Address>,
}

/// Judges a request's terms against `doc`'s chain, off one working world.
///
/// **The head, and the tell** (R5, P1). Where the request carries the head
/// the merge was composed on and the draft has a chain — the one its
/// recorded base lies in, else its fork's source's — the head is checked
/// against that chain: a registered member of it, its registration asked
/// first, as the shot asks its base's (PUB-6.37), its extent within its
/// current count. It is not checked against the trunk's current head: a
/// version published since the compose is NOT refused — the op lands,
/// records what it was told, and answers the trunk's current head beside
/// the position where that head is not the one named, so the caller learns
/// a newer version stands. On a draft with no chain the head meets the
/// registration check alone — every head names a registered document
/// (PUB-6.37), and the refusal tells nothing a caller may not learn, a
/// document's existence being visible (PUB-1.14) — and neither its chain
/// nor its count is judged, since nothing of it is recorded (N4) and a
/// count read of a document the caller may not read would answer that
/// document's size (PUB-1.13). Only the tell reads the head's trunk there,
/// and it answers a published chain's head alone, a private document being
/// versionless (PUB-2.9). The head is read, never written: no head key is
/// taken, and a shot landing between the read and the commit makes the tell
/// stale by one member, which the next read corrects.
///
/// **The fork gate** (N4, P5). A destination with no recorded base whose
/// fork source is a published surface is a fork: landing into it is
/// admitted where the request's head IS its source — the way out the ruling
/// names, a fresh fork from the head — and refused by name where it is not,
/// since the source the board records is immutable and a landing composed
/// on another head would make it false. An admitted fork gains no base and
/// no marker. A destination with neither a recorded base nor a published
/// source — a free-standing draft, an alternative of one — is admitted
/// where its head is registered, nothing moved.
///
/// **The base, judged as the head is** (N4). Where `base` is present it
/// must be a registered member of the chain the recorded base lies in and
/// its extent must not pass its member's current count — the head's three
/// checks — so the record never names a member no mint made, nor claims
/// more of its base than the base holds. A published document's count never
/// falls (PUB-2.43: it changes only by deposits appended at fresh
/// positions), so the extent stays within the count after the commit, and
/// the draft's next shot carrying it as its base extent never meets
/// `BaseExtentTooLarge`.
///
/// **The marker put back** (skep #870). A `merge` naming one position
/// ([`SetMerge::at`]) puts back a marker the fold stamped on this draft
/// since its base last moved at a shot — the marker of its sides, the
/// request's head pair and that position, found among the draft's stamps
/// ([`DraftBase::stamped`]).
///
/// **Cost.** The content count of each pair judged — the head on a draft
/// with a chain, the base to record — a sum over that member's runs, never
/// the draft's; and where the merge names a position, one scan of the
/// draft's stamps, each compared whole.
///
/// # Errors
///
/// In this order, the first refusing: where `head` is present,
/// `SourceNotRegistered` (the head names no registered document) → and
/// where the draft has one of the two chains, `BaseNotInChain` (the head
/// off the chain the recorded base lies in, or the fork's source's
/// document) → `BaseExtentTooLarge` (the head's extent past its current
/// count) — a draft with neither chain asked neither — → `ForkBaseMoved`
/// (the fork gate) → where `base` is present, `NoBaseToRecord` →
/// `SourceNotRegistered` (the base to record names no registered document)
/// → `BaseNotInChain` (the base off the recorded base's chain) →
/// `BaseExtentTooLarge` (the base's extent past its current count) → where
/// `merge` names a position, `MarkerNotRestorable` (no `head` or no `base`
/// beside it, or no stamp of the draft's of those sides, that head pair and
/// that position). Each `SourceNotRegistered` names no change.
pub(super) fn judge(
    m3: &M3State,
    m5: &M5State,
    doc: &Address,
    terms: Terms<'_>,
) -> Result<Judged, EditError> {
    let standing = m5.draft_base(doc).cloned();
    // The fork (P5): no recorded base, and a source that is a published
    // surface — a member or a bare published document. A source that is a
    // draft is an alternative's, and the document free-standing.
    let fork_source = match (&standing, m5.fork_source(doc)) {
        (None, Some(source)) if published_target(m3, source) => Some(source.clone()),
        _ => None,
    };
    if let Some(head) = terms.head {
        // The chain the head must lie in: the recorded base's, else the
        // fork's source's. A document with neither has none, and its head
        // meets the registration check alone: a document's existence is
        // visible (PUB-1.14), while nothing of the head is recorded (N4)
        // and a count read of a document the caller may not read would
        // answer that document's size (PUB-1.13).
        let chain = standing
            .as_ref()
            .map(|b| trunk_of(&b.base))
            .or_else(|| fork_source.as_ref().map(trunk_of));
        match &chain {
            Some(chain) => judge_pair(m3, m5, head, chain)?,
            None => judge_registration(m3, head)?,
        }
        // The fork gate (N4): admitted where the source IS the head.
        if let Some(source) = &fork_source {
            if *source != head.member {
                return Err(EditError::ForkBaseMoved(source.clone()));
            }
        }
    }
    if let Some(base) = terms.base {
        let Some(standing) = &standing else {
            return Err(EditError::NoBaseToRecord);
        };
        // Judged as the head is, so no record names a member no mint made
        // or claims more of its base than the base holds (N4).
        judge_pair(m3, m5, base, &trunk_of(&standing.base))?;
    }
    // The marker put back (skep #870): a position the merge names is a
    // stamp of the draft's, so no marker's `at` is made a position where
    // nothing stamped it.
    let restored = match terms.merge {
        Some(SetMerge { sides, at: Some(at) }) => {
            Some(restorable(terms, standing.as_ref(), sides, *at)?)
        }
        _ => None,
    };
    // The tell (R5): the trunk's current head where it is not the one
    // named — asked of a head the checks above found registered, as
    // `trunk_head` requires, and read, never locked.
    let head_moved = terms
        .head
        .and_then(|head| trunk_head(m3, &head.member).filter(|current| *current != head.member));
    Ok(Judged { standing, restored, head_moved })
}

/// Returns the record that moves `doc`'s base, where the request names one.
///
/// **What moves and what stands** (N3). Where `base` is present — and the
/// board records a base for the draft, which [`judge`] has held it to — the
/// base record is replaced whole: `base` and `extent` the request's,
/// `source` kept, the marker put back as it stood where the merge named its
/// position ([`M5Rec::MarkerRestore`]; skep #870), else the request's
/// `merge` beside its `head`, which the fold stamps at the commit and adds
/// to the draft's stamps, or cleared where the request carries none
/// ([`M5Rec::DraftBase`]). `None` where `base` is absent: the record is
/// untouched — base and marker alike — so an edit of a marked draft ends no
/// merge the base still carries.
pub(super) fn base_record(doc: &Address, terms: Terms<'_>, judged: Judged) -> Option<M5Rec> {
    let (base, standing) = terms.base.zip(judged.standing)?;
    let (draft, member, extent) = (doc.clone(), base.member.clone(), base.extent.clone());
    let source = standing.source;
    Some(match (judged.restored, terms.head, terms.merge) {
        (Some(marker), _, _) => M5Rec::MarkerRestore { draft, base: member, extent, source, marker },
        (None, Some(head), Some(merge)) => M5Rec::DraftBase {
            draft,
            base: member,
            extent,
            source,
            merge: Some(Merge {
                sides: merge.sides.clone(),
                head: head.member.clone(),
                head_copied: head.extent.clone(),
            }),
        },
        (None, _, _) => M5Rec::DraftBase { draft, base: member, extent, source, merge: None },
    })
}

/// Returns the stamped marker a request's merge puts back (skep #870).
///
/// It is the marker of `sides`, the request's head pair and `at`, which
/// must be one of the draft's stamps ([`DraftBase::stamped`]) and stand
/// beside a base to record: the commit installs it as it stood.
///
/// # Errors
///
/// `MarkerNotRestorable` where the request names no head or no base to
/// record, where the draft has no recorded base, or where its stamps hold
/// no such marker.
fn restorable(
    terms: Terms<'_>,
    standing: Option<&DraftBase>,
    sides: &[Address],
    at: Seq,
) -> Result<Marker, EditError> {
    let (Some(head), Some(_), Some(standing)) = (terms.head, terms.base, standing) else {
        return Err(EditError::MarkerNotRestorable);
    };
    let marker = Marker {
        sides: sides.to_vec(),
        head: head.member.clone(),
        head_copied: head.extent.clone(),
        at,
    };
    if standing.stamped.contains(&marker) {
        Ok(marker)
    } else {
        Err(EditError::MarkerNotRestorable)
    }
}

/// Judges a pair the request names as the shot judges its base (PUB-2.37).
///
/// The pair is the head or the base to record, and `trunk` the document
/// whose chain it must lie in. The member must be a registered document of
/// it: its registration asked first, by `judge_registration` — an
/// unregistered argument answers registration and nothing later
/// (PUB-6.37), as the shot's base does — then its address against the
/// chain. The extent — the head's as read at the compose (P1) — is checked
/// against the member's own arrangement: `content_count` answers the
/// address named, a bare document's pre-chain arrangement included, and
/// never floats to the head.
///
/// **Precondition.** `trunk` is a published document. The count is read
/// of a member of its chain alone, and every member of a published trunk
/// reads as the trunk does, so the count answers nothing a caller may not
/// read (PUB-1.13). Both calls keep it: a recorded base lies in a published
/// chain, and a fork's source is a published surface.
///
/// # Errors
///
/// `SourceNotRegistered` where `pair.member` names no registered document,
/// then `BaseNotInChain` where it lies outside `trunk`'s chain, then
/// `BaseExtentTooLarge` where `pair.extent` exceeds the member's current
/// content count.
///
/// # Panics
///
/// Panics in a debug build where the member passes both checks and
/// `trunk` is not published: the precondition broken.
fn judge_pair(
    m3: &M3State,
    m5: &M5State,
    pair: &Base,
    trunk: &Address,
) -> Result<(), EditError> {
    judge_registration(m3, pair)?;
    if !in_chain(&pair.member, trunk) {
        return Err(EditError::BaseNotInChain);
    }
    debug_assert!(
        published_target(m3, &pair.member),
        "a pair is judged against a published chain alone: {trunk:?}"
    );
    if pair.extent > m5.content_count(&pair.member) {
        return Err(EditError::BaseExtentTooLarge);
    }
    Ok(())
}

/// Refuses a pair whose member names no registered document.
///
/// It is `judge_pair`'s first check, and the only one a head meets on a
/// draft with no chain: an unregistered argument answers registration and
/// nothing later (PUB-6.37), and a document's existence is visible to every
/// caller (PUB-1.14), so the refusal tells nothing a caller may not learn.
/// It reads no chain and no count, so it holds no precondition on the
/// pair's trunk.
///
/// # Errors
///
/// `SourceNotRegistered` where `pair.member` names no registered document.
fn judge_registration(m3: &M3State, pair: &Base) -> Result<(), EditError> {
    if m3.is_registered_document(&pair.member) {
        Ok(())
    } else {
        Err(EditError::SourceNotRegistered { change: None })
    }
}

/// Returns whether `member`'s address lies in `trunk`'s chain (PUB-2.15).
///
/// It is `trunk` itself or an address `trunk_of` projects to `trunk`:
/// address arithmetic alone, reading no frontier, so an address no mint has
/// made answers `true`. `judge_pair` asks the member's registration first.
fn in_chain(member: &Address, trunk: &Address) -> bool {
    member == trunk || trunk_of(member) == *trunk
}

#[cfg(test)]
pub(crate) mod tests;
