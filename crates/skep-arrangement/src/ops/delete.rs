//! DELETE (ASN-0117; §4): a content range removed and the gap closed.
//!
//! The content store and R are untouched.

use num_traits::Zero;
use skep_address::{Address, Nat};
use skep_kernel::{Seq, Staging, TxnError, WorldState};
use skep_namespace::{HasM3, M3State};

use super::Vstream;
use crate::chain::published_target;
use crate::error::DeleteError;
use crate::ownership::{gate_write, Caller};
use crate::state::M5Rec;
use crate::vspace::VPos;
use crate::HasM5;

impl<W> Vstream<'_, W>
where
    W: WorldState + HasM5 + HasM3, // reads M3 registration + M5 only
    W::Record: From<M5Rec>,        // stages only M5Rec
{
    /// Removes the content range `[p, p + width)` and closes the gap.
    ///
    /// DELETE (ASN-0117; §4) shifts the suffix left. Content store and R
    /// untouched — NonDestruction is structural (M5 has no reclamation path);
    /// link survival is automatic (a text delete never touches the link
    /// run-list).
    ///
    /// **The body is [`stage_delete_at`]**, the closure this method opens its
    /// transaction for under `content_lock_key(doc)`: a caller composing the
    /// removal with other stagings under one transaction calls it over a
    /// staging of its own, under the union of the keys.
    ///
    /// # Errors
    ///
    /// Each refusal comes as `TxnError::Rejected`, in this order (which error
    /// wins): `DocNotRegistered` → `NotOwner` (the ω gate) →
    /// `PublishedTarget` (PUB-2.11 on the document `doc` projects to,
    /// PUB-2.15 — a delete is an in-place edit and has no deposit form) →
    /// `NotContentSubspace` → `NotArranged` (`p.ordinal ∉ [1, n_C]`) →
    /// `OutOfBounds` (`ordinal + width − 1 > n_C`) → `EmptyWidth`
    /// (`width = 0`). The kernel's own failures — `OverBudget`,
    /// `Unencodable`, `Durability`, `Poisoned` — come back as `transact`
    /// returns them.
    ///
    /// **The arranged and containment checks may not be transposed**, and the
    /// reason is not only which verdict a caller reads: `NotArranged` also
    /// discharges the next check's precondition. `contains_content_range`
    /// tests the upper bound alone and means containment only for
    /// `p.ordinal ≥ 1`, which the arranged-position check has just
    /// established. Asked the other way round, a range opening at ordinal 0
    /// would be admitted as contained.
    pub fn delete(
        &self,
        caller: Caller,
        doc: &Address,
        p: VPos,
        width: Nat,
    ) -> Result<Seq, TxnError<DeleteError>> {
        let key = M3State::content_lock_key(doc);
        self.kernel
            .transact(&[key], |stg| stage_delete_at(stg, caller, doc, p, width))
            .map(|((), seq)| seq)
    }
}

/// Stages `delete`'s body into the caller's transaction.
///
/// It is [`Vstream::delete`]'s closure as a function over a caller-opened
/// [`Staging`]: it removes the content range `[p, p + width)` of `doc` and
/// closes the gap — every check in the order `delete` states, the arranged
/// and containment checks in that order, every refusal, and the one
/// [`M5Rec::ContentRemove`] it pushes, `delete`'s own. Offered so a caller
/// can compose the removal with other stagings under ONE transaction, which
/// the public ops cannot, each opening a transaction of its own and the
/// kernel refusing a nested one: the last step of the link-sets design's one
/// commit, after the shot ([`stage_publish`](crate::stage_publish)) and the
/// fresh run's placement ([`stage_reinstate_at`](crate::stage_reinstate_at))
/// — "a `reinstate` of the fresh I-run at the run's place and a `delete` of
/// the draft-native run, staged in the same commit and applied in turn so
/// positions stay true" (the link-sets design, §5.7): the position it is
/// given is the draft-native run's AFTER the placement, which the caller
/// reads off `stg.working()` once the placement is staged.
///
/// It reads the transaction's working world, `stg.working()`: the registry
/// for the gate and the publication bit, and the arrangement as the records
/// staged so far left it, so the positions it judges are the ones an earlier
/// staging's placement moved to. It opens no transaction and takes no lock:
/// the kernel's lock keys are the caller's, `delete`'s own being
/// `content_lock_key(doc)` alone — a caller composing several stagings under
/// one transaction supplies the union of their keys.
///
/// # Errors
///
/// `delete`'s refusals, in the order it states — `DocNotRegistered` through
/// `EmptyWidth` — as the bare `DeleteError` the caller's transaction answers
/// as `TxnError::Rejected`; an `Err` commits nothing of that transaction,
/// the records this staged and every other staging's alike.
pub fn stage_delete_at<W>(
    stg: &mut Staging<W>,
    caller: Caller,
    doc: &Address,
    p: VPos,
    width: Nat,
) -> Result<(), DeleteError>
where
    W: WorldState + HasM5 + HasM3,
    W::Record: From<M5Rec>,
{
    gate_write(
        stg.working().m3(),
        caller,
        doc,
        DeleteError::DocNotRegistered,
        DeleteError::NotOwner,
    )?;
    // PUB-6.36 slot 5: the in-place advance refusal (PUB-2.11).
    if published_target(stg.working().m3(), doc) {
        return Err(DeleteError::PublishedTarget);
    }
    if !p.is_content() {
        return Err(DeleteError::NotContentSubspace);
    }
    let m5 = stg.working().m5();
    if !m5.arranges_content_position(doc, &p.ordinal) {
        return Err(DeleteError::NotArranged);
    }
    if !m5.contains_content_range(doc, &p.ordinal, &width) {
        return Err(DeleteError::OutOfBounds);
    }
    if width.is_zero() {
        return Err(DeleteError::EmptyWidth);
    }
    stg.push(M5Rec::ContentRemove { doc: doc.clone(), from: p.ordinal, width }.into());
    Ok(())
}
