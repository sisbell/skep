//! DELETE (ASN-0117; §4): a content range removed and the gap closed, the
//! content store and R untouched.

use num_traits::Zero;
use skep_address::{Address, Nat};
use skep_kernel::{Seq, TxnError, WorldState};
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
    /// DELETE (ASN-0117; §4): remove content range `[p, p + width)` and
    /// close the gap (shift the suffix left). Content store and R untouched
    /// — NonDestruction is structural (M5 has no reclamation path); link
    /// survival is automatic (a text delete never touches the link
    /// run-list).
    ///
    /// Check order (which error wins): `DocNotRegistered` → `NotOwner` (the ω
    /// gate) → `PublishedTarget` (PUB-2.11 on the document `doc` projects
    /// to, PUB-2.15 — a delete is an in-place edit and has no deposit form)
    /// → `NotContentSubspace` → `NotArranged`
    /// (`p.ordinal ∉ [1, n_C]`) → `OutOfBounds` (`ordinal + width − 1 > n_C`)
    /// → `EmptyWidth` (`width = 0`).
    ///
    /// THE ARRANGED AND CONTAINMENT CHECKS MAY NOT BE TRANSPOSED, and the
    /// reason is not only which verdict a caller reads: `NotArranged` also
    /// DISCHARGES the next check's precondition. `contains_content_range`
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
            .transact(&[key], |stg| {
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
                stg.push(
                    M5Rec::ContentRemove {
                        doc: doc.clone(),
                        from: p.ordinal,
                        width,
                    }
                    .into(),
                );
                Ok(())
            })
            .map(|((), seq)| seq)
    }
}
