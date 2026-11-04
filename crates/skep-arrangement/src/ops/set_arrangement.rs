//! SET_ARRANGEMENT (the landing lane; skep #764): a draft's whole content
//! arrangement set by identity in one commit, its recorded base moved and
//! the merge it carries set or cleared where the frame names a base, and a
//! newer head told in the answer.
//!
//! The body composes the two staging functions the in-place edits offer —
//! the whole content span removed by [`stage_delete_at`], the runs placed at
//! content ordinal 1 by [`stage_reinstate_at`] — under the one transaction
//! the public op opens, and pushes the base record beside them. It adds no
//! rule of composition: what it places is what it is sent, as REINSTATE
//! places what it is sent.

use num_traits::{One, Zero};
use skep_address::{Address, Nat};
use skep_content::HasContent;
use skep_kernel::{Seq, Staging, TxnError, WorldState};
use skep_namespace::{HasM3, M3State};

use super::{arrangement_moved, stage_delete_at, stage_reinstate_at, AsOf, Vstream};
use crate::chain::{published_target, trunk_head, trunk_of};
use crate::error::{DeleteError, ReinstateError, SetArrangementError};
use crate::ownership::{gate_write, Caller};
use crate::shot::{Base, ShotRun};
use crate::state::{M5Rec, M5State, Merge};
use crate::vspace::VPos;
use crate::HasM5;

/// One `set_arrangement` request: the whole arrangement a draft is set to,
/// the head it was composed on, the base to record and the merge's sides.
///
/// `runs` are content I-runs the client names beside the document each
/// states minted it, in REINSTATE's form ([`ShotRun`]): placed at content
/// ordinal 1 in the order given, by identity, in place of everything the
/// draft arranged; an EMPTY list sets an empty arrangement, which a draft
/// may hold. `head` is the head the merge was composed on with its content
/// count AS READ at the compose (the owner's ruling R5 and its precision
/// P1) — present on a merge landing, absent on an undo and on a plain
/// re-arrangement. `base` is the base to record (the owner's ruling R6): a
/// landing sends the head pair, an undo the old base, a plain
/// re-arrangement none; where present the draft must have a recorded base
/// to move. `merge` is the marker's sides — the sides merged, by address,
/// possibly empty — present only beside `head`, which is the marker's own
/// head; the marker is recorded where `base` is recorded, and nowhere else
/// (the owner's ruling N3: the marker travels with the base). The members a
/// landing composes are the client's statement, as the shot's `base` is:
/// the store checks the head and the base against the draft's chain, as
/// registered members of it, each extent against its member's current
/// count, and nothing against `runs`. A draft with no chain — no recorded
/// base and no published source — has nothing of its head checked, the
/// extent included, and no base to record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SetArrangement {
    /// The runs the draft is set to, in order; empty for an empty arrangement.
    pub runs: Vec<ShotRun>,
    /// The head the merge was composed on, at the extent read; `None` on an
    /// undo and a plain re-arrangement.
    pub head: Option<Base>,
    /// The base to record, with its extent; `None` moves no record.
    pub base: Option<Base>,
    /// The marker's sides, present only beside `head`; `None` records no
    /// marker and, where `base` is present, clears one.
    pub merge: Option<Vec<Address>>,
}

impl<W> Vstream<'_, W>
where
    W: WorldState + HasM5 + HasM3 + HasContent, // reads M3 (registration) + M4 (the existence probe) + M5
    W::Record: From<M5Rec>,                     // stages only M5Rec (no mint, no byte write)
{
    /// Sets `doc`'s whole content arrangement to `request.runs`, by
    /// identity, in one commit.
    ///
    /// SET_ARRANGEMENT (the landing lane; skep #764) is the board's half of
    /// a merge's landing into a draft, and the write by which a client
    /// changes a draft's whole text at once: in ONE transaction the draft's
    /// whole content span is removed and the request's runs are placed at
    /// content ordinal 1 — the removal [`stage_delete_at`]'s body, the
    /// placement [`stage_reinstate_at`]'s, exactly as the publication's
    /// re-window composes the two — so the draft holds the arrangement sent
    /// or what it held, never a state between; and, where the request names
    /// a base to record, the draft's recorded base moves to it in the same
    /// commit (the owner's ruling R4), carrying the request's merge as the
    /// marker the draft now carries, or none (R2, N3). The runs are the
    /// client's: nothing here composes a merge, and a run of any registered
    /// document's I-space may be placed, under the precondition
    /// [`reinstate`](Vstream::reinstate) states on its origins' readability
    /// — M10's door discharges it per distinct origin, the destination's own
    /// excepted.
    ///
    /// **The head, and the tell** (R5, P1). Where the request carries the
    /// head the merge was composed on and the draft has a chain — the one
    /// its recorded base lies in, else its fork's source's — the head is
    /// checked against that chain: a registered member of it, its
    /// registration asked first, as the shot asks its base's (PUB-6.37),
    /// its extent within its current count. It is not checked against the
    /// trunk's current head: a version published since the compose is NOT
    /// refused — the op lands, records what it was told, and answers the
    /// trunk's current head beside the position where that head is not the
    /// one named, so the caller learns a newer version stands. A draft with
    /// no chain has its head judged by nothing — registration, chain and
    /// count alike — since nothing of it is recorded (N4) and a count read
    /// of a document the caller may not read would answer that document's
    /// size (PUB-1.13). Only the tell reads the head's trunk there, and it
    /// answers a published chain's head alone, a private document being
    /// versionless (PUB-2.9). The head is read, never written: no head key
    /// is taken, and a shot landing between the read and the commit makes
    /// the tell stale by one member, which the next read corrects.
    ///
    /// **The fork gate** (N4, P5). A destination with no recorded base
    /// whose fork source is a published surface is a fork: landing into it
    /// is admitted where the request's head IS its source — the way out the
    /// ruling names, a fresh fork from the head — and refused by name where
    /// it is not, since the source the board records is immutable and a
    /// landing composed on another head would make it false. An admitted
    /// fork gains no base and no marker. A destination with neither a
    /// recorded base nor a published source — a free-standing draft, an
    /// alternative of one — is admitted, its head unchecked and nothing
    /// moved.
    ///
    /// **The base, judged as the head is** (N4). Where `base` is present it
    /// must be a registered member of the chain the recorded base lies in
    /// and its extent must not pass its member's current count — the head's
    /// three checks — so the record never names a member no mint made, nor
    /// claims more of its base than the base holds. A published document's
    /// count never falls (PUB-2.43: it changes only by deposits appended at
    /// fresh positions), so the extent stays within the count after the
    /// commit, and the draft's next shot carrying it as its base extent
    /// never meets `BaseExtentTooLarge`. A frame sending the base the wire
    /// asks for meets none of the three: a landing's is its head, judged the
    /// same way, and an undo's a record read before the landing, naming a
    /// member a mint made — registered for good, M3 deleting nothing (B0) —
    /// and kept within its count by the same never-falling count.
    ///
    /// **What moves and what stands** (N3). Where `base` is present the
    /// base record is replaced whole: `base` and `extent` the request's,
    /// `source` kept, the marker the request's `merge` beside its `head` or
    /// cleared where the request carries none. Where `base` is absent the
    /// record is untouched — base and marker alike — so a plain
    /// re-arrangement of a marked draft ends no merge the base still
    /// carries.
    ///
    /// **Locks.** `content_lock_key(doc)` alone, as REINSTATE's: no origin
    /// is locked, and the chain's head key is not taken — the head is read
    /// for the tell and the chain is read for the checks, neither written.
    ///
    /// **Cost.** The removal's, one record; REINSTATE's probe over every
    /// address of every run; the content count of each pair judged — the
    /// head on a draft with a chain, the base to record — a sum over that
    /// member's runs; and one base record. The wire caps the run
    /// count at the parse; [`MAX_PLACED_RUNS`](super::MAX_PLACED_RUNS)
    /// binds the placement as it binds REINSTATE's.
    ///
    /// Returns the commit position and, where the request named a head the
    /// trunk has moved past, the trunk's current head.
    ///
    /// # Errors
    ///
    /// Each refusal comes as `TxnError::Rejected`, in this order (which error
    /// wins), the first refusing with nothing written: `DocNotRegistered` →
    /// `NotOwner` → `PublishedTarget` → `ArrangementMoved` (the destination's
    /// own four, as the in-place edits judge them) → where `head` is present
    /// and the draft has one of the two chains, `SourceNotRegistered` (the
    /// head names no registered document) → `BaseNotInChain` (the head off
    /// the chain the recorded base lies in, or the fork's source's document)
    /// → `BaseExtentTooLarge` (the head's extent past its current count) — a
    /// draft with neither chain asked none of the three — → `ForkBaseMoved`
    /// (the fork gate) → where `base` is present,
    /// `NoBaseToRecord` → `SourceNotRegistered` (the base to record names no
    /// registered document) → `BaseNotInChain` (the base off the recorded
    /// base's chain) → `BaseExtentTooLarge` (the base's extent past its
    /// current count) → per run, in the order given, the first
    /// defective run deciding: `BadRun` → `SourceNotRegistered` →
    /// `DanglingSource` → `TooManyRuns`. The removal is staged ahead of the
    /// runs' judgment, so a defective run is refused past one staged record
    /// — M2 commits nothing of a refused transaction, the removal included.
    /// The kernel's own failures — `OverBudget`, `Unencodable`,
    /// `Durability`, `Poisoned` — come back as `transact` returns them.
    pub fn set_arrangement(
        &self,
        caller: Caller,
        doc: &Address,
        request: &SetArrangement,
        as_of: AsOf,
    ) -> Result<(Seq, Option<Address>), TxnError<SetArrangementError>> {
        let key = M3State::content_lock_key(doc);
        self.kernel
            .transact(&[key], |stg| stage_set_arrangement(stg, caller, doc, request, as_of))
            .map(|(head_moved, seq)| (seq, head_moved))
    }
}

/// Stages `set_arrangement`'s body into the transaction.
///
/// It is [`Vstream::set_arrangement`]'s closure: every check in the order
/// the op states, off the transaction's working world, then the removal,
/// the placement and the base record. Returns the trunk's current head
/// where the request's head is not it.
///
/// # Errors
///
/// `set_arrangement`'s refusals, in the order it states.
fn stage_set_arrangement<W>(
    stg: &mut Staging<W>,
    caller: Caller,
    doc: &Address,
    request: &SetArrangement,
    as_of: AsOf,
) -> Result<Option<Address>, SetArrangementError>
where
    W: WorldState + HasM5 + HasM3 + HasContent,
    W::Record: From<M5Rec>,
{
    // Every judgment off one reading of the working world, ahead of the
    // first record staged.
    let (count, standing, head_moved) = {
        let world = stg.working();
        let (m3, m5) = (world.m3(), world.m5());
        gate_write(
            m3,
            caller,
            doc,
            SetArrangementError::DocNotRegistered,
            SetArrangementError::NotOwner,
        )?;
        // PUB-6.36 slot 5: the in-place advance refusal (PUB-2.11).
        if published_target(m3, doc) {
            return Err(SetArrangementError::PublishedTarget);
        }
        // The stale-edit refusal (skep #442), ahead of every shape check:
        // the one typed judgment, the two bodies below asked unchecked.
        if let Some((as_of, current)) = arrangement_moved(m5, doc, as_of) {
            return Err(SetArrangementError::ArrangementMoved { as_of, current });
        }
        let standing = m5.draft_base(doc).cloned();
        // The fork (P5): no recorded base, and a source that is a published
        // surface — a member or a bare published document. A source that is
        // a draft is an alternative's, and the document free-standing.
        let fork_source = match (&standing, m5.fork_source(doc)) {
            (None, Some(source)) if published_target(m3, source) => Some(source.clone()),
            _ => None,
        };
        if let Some(head) = &request.head {
            // The chain the head must lie in: the recorded base's, else the
            // fork's source's. A document with neither has none, and its
            // head is judged by nothing: nothing of it is recorded (N4), and
            // a count read of a document the caller may not read would
            // answer that document's size (PUB-1.13).
            let chain = standing
                .as_ref()
                .map(|b| trunk_of(&b.base))
                .or_else(|| fork_source.as_ref().map(trunk_of));
            if let Some(chain) = &chain {
                judge_pair(m3, m5, head, chain)?;
            }
            // The fork gate (N4): admitted where the source IS the head.
            if let Some(source) = &fork_source {
                if *source != head.member {
                    return Err(SetArrangementError::ForkBaseMoved(source.clone()));
                }
            }
        }
        if let Some(base) = &request.base {
            let Some(standing) = &standing else {
                return Err(SetArrangementError::NoBaseToRecord);
            };
            // Judged as the head is, so no record names a member no mint
            // made or claims more of its base than the base holds (N4).
            judge_pair(m3, m5, base, &trunk_of(&standing.base))?;
        }
        // The tell (R5): the trunk's current head where it is not the one
        // named — read, never locked.
        let head_moved = request
            .head
            .as_ref()
            .and_then(|head| trunk_head(m3, &head.member).filter(|current| *current != head.member));
        (m5.content_count(doc), standing, head_moved)
    };
    // The whole span removed, where there is one: DELETE's body at ordinal
    // 1 over the count read above, unchecked — the typed judgment was made.
    if !count.is_zero() {
        stage_delete_at(stg, caller, doc, VPos::content(Nat::one()), count, AsOf::Unchecked)
            .map_err(of_delete)?;
    }
    // The runs placed at ordinal 1, where there are any: REINSTATE's body,
    // which judges each run in order and keeps its budget.
    if !request.runs.is_empty() {
        stage_reinstate_at(
            stg,
            caller,
            doc,
            VPos::content(Nat::one()),
            &request.runs,
            AsOf::Unchecked,
        )
        .map_err(of_reinstate)?;
    }
    // The record, where a base is to be recorded: the base told, the source
    // kept, the marker the request's merge beside its head or none (N3).
    if let (Some(base), Some(standing)) = (&request.base, &standing) {
        let merge = match (&request.head, &request.merge) {
            (Some(head), Some(sides)) => Some(Merge {
                sides: sides.clone(),
                head: head.member.clone(),
                head_copied: head.extent.clone(),
            }),
            _ => None,
        };
        stg.push(
            M5Rec::DraftBase {
                draft: doc.clone(),
                base: base.member.clone(),
                extent: base.extent.clone(),
                source: standing.source.clone(),
                merge,
            }
            .into(),
        );
    }
    Ok(head_moved)
}

/// Judges a pair the request names as the shot judges its base (PUB-2.37).
///
/// The pair is the head or the base to record, and `trunk` the document
/// whose chain it must lie in. The member must be a registered document of
/// it: its registration asked first — an unregistered argument answers
/// registration and nothing later (PUB-6.37), as the shot's base does —
/// then its address against the chain. The extent — the head's as read at
/// the compose (P1) — is checked against the member's own arrangement:
/// `content_count` answers the address named, a bare document's pre-chain
/// arrangement included, and never floats to the head.
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
) -> Result<(), SetArrangementError> {
    if !m3.is_registered_document(&pair.member) {
        return Err(SetArrangementError::SourceNotRegistered);
    }
    if !in_chain(&pair.member, trunk) {
        return Err(SetArrangementError::BaseNotInChain);
    }
    debug_assert!(
        published_target(m3, &pair.member),
        "a pair is judged against a published chain alone: {trunk:?}"
    );
    if pair.extent > m5.content_count(&pair.member) {
        return Err(SetArrangementError::BaseExtentTooLarge);
    }
    Ok(())
}

/// Returns whether `member`'s address lies in `trunk`'s chain (PUB-2.15).
///
/// It is `trunk` itself or an address `trunk_of` projects to `trunk`:
/// address arithmetic alone, reading no frontier, so an address no mint has
/// made answers `true`. `judge_pair` asks the member's registration first.
fn in_chain(member: &Address, trunk: &Address) -> bool {
    member == trunk || trunk_of(member) == *trunk
}

/// Lowers the removal's verdict to this op's.
///
/// The removal is staged at content ordinal 1 over the count read off the
/// same working world, and only where that count is at least one, so no
/// input reaches DELETE's four shape verdicts: ordinal 1 is arranged by
/// every non-empty content arrangement, `[1, count]` is contained by
/// construction, and the width is the count. The three gates and the typed
/// check were asked ahead of it on the same world.
fn of_delete(e: DeleteError) -> SetArrangementError {
    match e {
        DeleteError::DocNotRegistered => SetArrangementError::DocNotRegistered,
        DeleteError::NotOwner(a) => SetArrangementError::NotOwner(a),
        DeleteError::PublishedTarget => SetArrangementError::PublishedTarget,
        DeleteError::ArrangementMoved { as_of, current } => {
            SetArrangementError::ArrangementMoved { as_of, current }
        }
        DeleteError::NotContentSubspace
        | DeleteError::NotArranged
        | DeleteError::OutOfBounds
        | DeleteError::EmptyWidth => {
            unreachable!("the whole span at ordinal 1 over a count of at least one meets no shape verdict: {e:?}")
        }
    }
}

/// Lowers the placement's verdict to this op's.
///
/// The placement is staged at content ordinal 1 — a content position, and
/// the boundary every arrangement admits, the one the removal just left
/// included — and only where `runs` is non-empty, so no input reaches
/// REINSTATE's two shape verdicts or its empty-list one; the per-run four
/// are this op's own, by name.
fn of_reinstate(e: ReinstateError) -> SetArrangementError {
    match e {
        ReinstateError::DocNotRegistered => SetArrangementError::DocNotRegistered,
        ReinstateError::NotOwner(a) => SetArrangementError::NotOwner(a),
        ReinstateError::PublishedTarget => SetArrangementError::PublishedTarget,
        ReinstateError::ArrangementMoved { as_of, current } => {
            SetArrangementError::ArrangementMoved { as_of, current }
        }
        ReinstateError::BadRun => SetArrangementError::BadRun,
        ReinstateError::SourceNotRegistered => SetArrangementError::SourceNotRegistered,
        ReinstateError::DanglingSource => SetArrangementError::DanglingSource,
        ReinstateError::TooManyRuns => SetArrangementError::TooManyRuns,
        ReinstateError::NotContentSubspace
        | ReinstateError::OutOfBounds
        | ReinstateError::EmptyResult => {
            unreachable!("a non-empty placement at content ordinal 1 meets no shape verdict: {e:?}")
        }
    }
}

#[cfg(test)]
mod tests;
