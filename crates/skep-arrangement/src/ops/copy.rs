//! COPY (ASN-0118; §5): transclusion by reference — existing content resolved
//! from its sources and placed, allocating none.

use skep_address::Address;
use skep_content::HasContent;
use skep_kernel::{Seq, TxnError, WorldState};
use skep_namespace::{HasM3, M3State};

use super::{Vstream, MAX_COPY_RESOLVE_STEPS, MAX_PLACED_RUNS};
use crate::chain::published_target;
use crate::error::CopyError;
use crate::ownership::{gate_write, Caller};
use crate::run::Run;
use crate::runlist::extend_or_push_run;
use crate::state::M5Rec;
use crate::vspace::{as_ordinal_vspan, VPos, VSpec};
use crate::HasM5;

impl<W> Vstream<'_, W>
where
    W: WorldState + HasM5 + HasM3 + HasContent, // reads M3 (registration) + M4 (`contains` gate) + M5
    W::Record: From<M5Rec>,                     // stages only M5Rec (no mint, no byte write)
{
    /// COPY (ASN-0118; §5): transclude existing content by reference —
    /// resolve `specs` against source arrangements off the transaction's
    /// working state, splice into doc's content subspace at `at`, record
    /// provenance for the placed runs. Allocates NO content (CP1/CP2); the
    /// resolved addresses stay valid forever by content immutability (S0),
    /// so no source lock is needed.
    ///
    /// SOURCES ARE READ AS NAMED — no head-float (wire.md pins this seam): a
    /// spec naming a bare published document with members resolves against
    /// that document's own pre-chain arrangement, which the chain has
    /// superseded, never against the trunk head its readers answer from;
    /// `EmptySource` and the clipping are judged against that same
    /// arrangement. A caller wanting what a reader of the bare address sees
    /// names the head — [`trunk_head`](crate::trunk_head), or
    /// [`reading_surface`](crate::reading_surface) of the address — as a
    /// stager's copy names the member it stages from (PUB-2.27).
    /// Contrast [`version`](Vstream::version), which snapshots the reading
    /// surface.
    ///
    /// REQUIRES — the caller has established that the principal it writes
    /// for may read every `specs[].source` (PUB-6.23's source gate). M5 knows
    /// no principal's read rights and takes no consult for COPY, so nothing
    /// here checks it: a caller that skips it transcludes a document its
    /// principal may not read into one that principal owns, and the
    /// destination's ω — the only question COPY asks of its caller — admits
    /// the write. On the wire route M10's pre-dispatch consult discharges it;
    /// a caller driving COPY directly owes its own.
    ///
    /// `specs` is borrowed: COPY reads each spec's source and span and keeps
    /// neither, so a caller that holds its spec list behind a reference is not
    /// made to clone it.
    ///
    /// Check order (which error wins). Destination first, as INSERT:
    /// `DocNotRegistered` → `NotOwner` (the ω gate on the DESTINATION only;
    /// source spans are unrestricted BY OWNERSHIP, transclusion of another's
    /// content being the point of the medium, and are not judged for
    /// READABILITY here — the REQUIRES above) → `PublishedTarget` (PUB-2.11
    /// on the DESTINATION's document, PUB-2.15 projected; copy-into is an
    /// in-place edit and carries no deposit exemption — the sources,
    /// published or private, are never what this refuses on) →
    /// `NotContentSubspace` → `OutOfBounds`. Then, per spec:
    /// `SourceNotRegistered`
    /// → `NotOrdinalVSpan` (the span fails
    /// [`is_ordinal_vspan`](crate::is_ordinal_vspan) — the one shape `resolve`
    /// folds on, so a span COPY rejects is exactly a span `resolve` would
    /// refuse to serve, Conflicts #7)
    /// → `SourceNotContentSubspace` (that span's subspace ≠ s_C)
    /// → `EmptySource` (ASN-0118
    /// enabled(COPY)) → `TooManyRuns` (the WALK's charge: this spec's source's
    /// whole run count, summed with the specs before it, past
    /// [`MAX_COPY_RESOLVE_STEPS`] — taken before
    /// the spec is resolved, so a spec the budget refuses is never walked) →
    /// per-run `DanglingSource` (`M4::contains` on the run
    /// start — S3★, Open decision #5 default) → `TooManyRuns`
    /// ([`MAX_PLACED_RUNS`](crate::MAX_PLACED_RUNS), measured after each run
    /// is accumulated; the resolution is pulled LAZILY, so an over-budget spec
    /// stops the source walk at the cap rather than being resolved in full and
    /// measured afterwards); finally `EmptyResult` when nothing survives
    /// clipping. Cross-origin runs never coalesce
    /// (the placement accumulator's I-adjacency guard), preserving the origin
    /// multiset (CP11).
    ///
    /// WHICH SPEC SPEAKS, when more than one is defective: the specs are
    /// examined in the order given and the FIRST spec to fail any of its
    /// guards decides, with the per-spec order above applying within that
    /// spec. So a mis-shaped span in an earlier spec outranks an unregistered
    /// source in a later one — the list is walked, not the guards.
    ///
    /// The two guards whose subject is not the request's shape but an
    /// invariant, stated so that widening what they gate obliges widening
    /// them:
    ///
    /// * `SourceNotContentSubspace` keeps LINK addresses out of content
    ///   V-positions. It is not a formality: `resolve` serves whichever
    ///   run-list the span's subspace numeral selects, so a link-subspace span
    ///   resolves against the source's LINK runs, and placing those here would
    ///   bind link addresses at content positions — links seated under an
    ///   origin that is not this document, which CL-OWN forbids and no read
    ///   downstream would report.
    /// * `DanglingSource` is S3★ on the content side, and it is checked on run
    ///   STARTS alone. Sound for the interior by induction over the ways an
    ///   address enters a content arrangement, each of which either admits a
    ///   present address or inherits one: a run this gate admits was arranged
    ///   in its source, whose interior is present by the same induction;
    ///   INSERT and the shot's re-insert write every address they place, in
    ///   the composite that places it (`allocate_for_placement`, J0); the
    ///   shot's by-reference runs are probed at EVERY address before placement
    ///   (they were not resolved from any arrangement), and its carried tail is
    ///   read off the base's own arrangement, already inside the induction;
    ///   VERSION shares an arrangement already inside it. Outside the induction
    ///   is a record staged past the ops or decoded from a corrupt store —
    ///   [`M5Rec`]'s seals and
    ///   [`M5State::apply_m5`](crate::M5State::apply_m5)'s input class say
    ///   how, and that is M2's integrity, not this gate's. A new way in joins
    ///   this list, or this gate is re-examined.
    pub fn copy(
        &self,
        caller: Caller,
        doc: &Address,
        at: VPos,
        specs: &[VSpec],
    ) -> Result<Seq, TxnError<CopyError>> {
        let key = M3State::content_lock_key(doc);
        self.kernel
            .transact(&[key], |stg| {
                let world = stg.working();
                gate_write(
                    world.m3(),
                    caller,
                    doc,
                    CopyError::DocNotRegistered,
                    CopyError::NotOwner,
                )?;
                // PUB-6.36 slot 5: the in-place advance refusal on the
                // destination (PUB-2.11).
                if published_target(world.m3(), doc) {
                    return Err(CopyError::PublishedTarget);
                }
                if !at.is_content() {
                    return Err(CopyError::NotContentSubspace);
                }
                if !world.m5().admits_content_boundary(doc, &at.ordinal) {
                    return Err(CopyError::OutOfBounds);
                }
                let mut runs: Vec<Run> = Vec::new();
                // The run-list steps the specs before this one were charged
                // (`MAX_COPY_RESOLVE_STEPS`).
                let mut steps: usize = 0;
                for spec in specs {
                    if !world.m3().is_registered_document(&spec.source) {
                        return Err(CopyError::SourceNotRegistered);
                    }
                    let span = &spec.span;
                    let Some(vspan) = as_ordinal_vspan(span) else {
                        return Err(CopyError::NotOrdinalVSpan);
                    };
                    if !vspan.is_content() {
                        return Err(CopyError::SourceNotContentSubspace);
                    }
                    if world.m5().content_is_empty(&spec.source) {
                        return Err(CopyError::EmptySource);
                    }
                    // The WALK's charge, ahead of the walk: the source's whole
                    // run count, the most this spec's resolution can step past
                    // — the request's spec list multiplies it, under the
                    // applier lock, whatever the specs keep.
                    steps = steps.saturating_add(world.m5().content_run_count(&spec.source));
                    if steps > MAX_COPY_RESOLVE_STEPS {
                        return Err(CopyError::TooManyRuns);
                    }
                    // Resolved BEFORE staging ⇒ a self-copy sees the pre-edit
                    // arrangement. Resolved LAZILY, so what one spec makes
                    // this closure hold live is the accumulator (capped
                    // below) and not the source's whole run-list, whose size
                    // the request does not choose.
                    for run in world.m5().iter_resolve(&spec.source, span) {
                        if !world.content().contains(run.i_start().tumbler()) {
                            return Err(CopyError::DanglingSource);
                        }
                        extend_or_push_run(&mut runs, run);
                        // Measured where the run is produced, not after the
                        // whole spec list has been folded: the accumulator is
                        // what a request's spec count multiplies, and a
                        // refusal that arrives at the end has already been
                        // paid for. With the resolution pulled lazily, this
                        // return also ends the source walk, so an over-budget
                        // spec is not resolved past the cap.
                        if runs.len() > MAX_PLACED_RUNS {
                            return Err(CopyError::TooManyRuns);
                        }
                    }
                }
                // Every `Run` has `width ≥ 1` by standing invariant, so a
                // nonempty accumulator places at least one position: the net
                // placement is empty exactly when nothing survived clipping.
                if runs.is_empty() {
                    return Err(CopyError::EmptyResult);
                }
                stg.push(
                    M5Rec::ContentPlace {
                        doc: doc.clone(),
                        at: at.ordinal,
                        runs,
                    }
                    .into(),
                );
                Ok(())
            })
            .map(|((), seq)| seq)
    }
}

#[cfg(test)]
mod tests;
