//! REINSTATE (the replacement act's record, E2 (a)): the write by identity —
//! runs of PERMANENT content I-addresses placed into a draft at a position,
//! allocating none; `retrieve_i`'s twin as COPY is `retrieve_v`'s.

use skep_address::Address;
use skep_content::HasContent;
use skep_kernel::{Seq, TxnError, WorldState};
use skep_namespace::{HasM3, M3State};

use super::{Vstream, MAX_PLACED_RUNS};
use crate::chain::{published_target, trunk_of};
use crate::error::ReinstateError;
use crate::ownership::{gate_write, Caller};
use crate::run::Run;
use crate::run_list::extend_or_push_run;
use crate::shot::{run_origin_document, ShotRun};
use crate::state::M5Rec;
use crate::vspace::VPos;
use crate::HasM5;

impl<W> Vstream<'_, W>
where
    W: WorldState + HasM5 + HasM3 + HasContent, // reads M3 (registration) + M4 (the existence probe) + M5
    W::Record: From<M5Rec>,                     // stages only M5Rec (no mint, no byte write)
{
    /// REINSTATE (the replacement act's record §2 P3, E2 (a)): place `runs`
    /// — content I-runs the CLIENT names, each beside the document it states
    /// minted it, the form the publish shot's runs take ([`ShotRun`]) — into
    /// `doc`'s content subspace at `at`, by IDENTITY: the addresses are
    /// placed as given, whether or not any arrangement holds them now, so a
    /// run a DELETE un-arranged comes back at its own addresses and every
    /// link whose recorded endset covers them returns with it (the links
    /// store records I-spans, M7's `slot_endset`; its region reads stab by
    /// I-overlap). Allocates NO content (CP1/CP2, as COPY); records
    /// provenance for the placed runs (J1★). The one thing COPY cannot do:
    /// COPY reaches arranged V-spans alone, and a removed span has no
    /// V-position to name, so an editor's undo re-inserted the words as new
    /// bytes and every link on the old ones stayed behind.
    ///
    /// THE REACH IS WIDE (the record's Q2, the owner's ruling): a run's
    /// origin may be ANY registered document, as a shot's by-reference run
    /// may window one. REQUIRES — the caller has established that the
    /// principal it writes for may READ every DISTINCT `runs[].origin`
    /// (PUB-6.23's source gate), the destination's own I-space excepted, as
    /// the shot's gate excepts it. M5 knows no principal's read rights and
    /// takes no consult for REINSTATE, exactly as it takes none for COPY: a
    /// caller that skips it re-places, into a document its principal owns,
    /// bytes that principal may not read. On the wire route M10's
    /// pre-dispatch consult discharges it (its `Op::source_arguments` names
    /// the distinct origins in run order); a caller driving REINSTATE
    /// directly owes its own.
    ///
    /// DUPLICATES ARE ADMITTED (the record's edge 1 under the wide reach): a
    /// run already arranged elsewhere in `doc` is placed again, as a
    /// self-COPY places a duplicate — the arrangement keeps the multiplicity
    /// (S5), and no `arranges_any` test gates it.
    ///
    /// `runs` is borrowed: each run is cloned into the placement, and the
    /// client's list is kept whole for a caller that reports it.
    ///
    /// Check order (which error wins). Destination first, as COPY:
    /// `DocNotRegistered` → `NotOwner` (the ω gate on the DESTINATION only)
    /// → `PublishedTarget` (PUB-2.11 on the DESTINATION's document, PUB-2.15
    /// projected; a re-placement is an in-place edit and carries no deposit
    /// exemption) → `NotContentSubspace` → `OutOfBounds`. Then, per run, IN
    /// THE ORDER GIVEN, the FIRST defective run deciding (COPY's "which spec
    /// speaks" rule): `BadRun` (the start is no content element, or the
    /// stated `origin` does not project to the document the start settles —
    /// `run_origin_document`, the shot's own arithmetic) →
    /// `SourceNotRegistered` (that origin document is unregistered) →
    /// `DanglingSource` (an address the run names holds no value — EVERY
    /// address of the run is probed through `value_at`, not its start alone,
    /// since a client-named run was resolved from no arrangement and S3★'s
    /// induction does not cover its interior; the shot's rule for a
    /// by-reference run) → `TooManyRuns` ([`MAX_PLACED_RUNS`], measured as
    /// each run is accumulated, so an over-budget list stops at the cap);
    /// finally `EmptyResult` when `runs` is empty — a `Run` has width ≥ 1 by
    /// standing invariant, so an empty placement is exactly an empty list.
    /// Cross-origin runs never coalesce (the accumulator's I-adjacency
    /// guard), preserving the origin multiset (CP11).
    ///
    /// COST, AND WHO OWNS IT. The probe walks every address of every run,
    /// run by run — `Σ width` of the request, a run named twice walked
    /// twice — under M2's applier lock. The wire caps the run COUNT
    /// (`MAX_WIRE_LIST`) and not a run's WIDTH, as it caps a shot's; a route
    /// that carries this op owes that number, as the shot's does.
    ///
    /// LOCKS: `content_lock_key(doc)` alone, as COPY. No origin is locked —
    /// the placed addresses stay valid forever by content immutability (S0)
    /// — and the chain's head key is not taken: REINSTATE reads no
    /// arrangement at all, its own or any origin's, so it never asks where
    /// a head is.
    pub fn reinstate(
        &self,
        caller: Caller,
        doc: &Address,
        at: VPos,
        runs: &[ShotRun],
    ) -> Result<Seq, TxnError<ReinstateError>> {
        let key = M3State::content_lock_key(doc);
        self.kernel
            .transact(&[key], |stg| {
                let world = stg.working();
                gate_write(
                    world.m3(),
                    caller,
                    doc,
                    ReinstateError::DocNotRegistered,
                    ReinstateError::NotOwner,
                )?;
                // PUB-6.36 slot 5: the in-place advance refusal on the
                // destination (PUB-2.11) — the edition is append-only, and
                // a re-placement is an edit in place.
                if published_target(world.m3(), doc) {
                    return Err(ReinstateError::PublishedTarget);
                }
                if !at.is_content() {
                    return Err(ReinstateError::NotContentSubspace);
                }
                if !world.m5().admits_content_boundary(doc, &at.ordinal) {
                    return Err(ReinstateError::OutOfBounds);
                }
                let (m3, content) = (world.m3(), world.content());
                let mut placement: Vec<Run> = Vec::new();
                for ShotRun { origin, run } in runs {
                    // The shape, settled from the run's own start and
                    // checked against the client's statement (the shot's
                    // `BadRun`): address arithmetic, disclosing nothing.
                    let origin_doc = run_origin_document(run).ok_or(ReinstateError::BadRun)?;
                    if origin_doc != trunk_of(origin) {
                        return Err(ReinstateError::BadRun);
                    }
                    if !m3.is_registered_document(&origin_doc) {
                        return Err(ReinstateError::SourceNotRegistered);
                    }
                    // Existence (S3★) at EVERY address: the run is the
                    // client's I-extent and no arrangement's, so nothing
                    // vouches for its interior but the probe itself — M4's run
                    // read, which walks the extent piece by piece and says
                    // whether every address of it is covered.
                    if !content.pieces(run.i_start().tumbler(), run.width()).covered() {
                        return Err(ReinstateError::DanglingSource);
                    }
                    extend_or_push_run(&mut placement, run.clone());
                    // Measured where the run is accumulated, as COPY's and
                    // the shot's placements are, so an over-budget list is
                    // refused at the cap and never built past it.
                    if placement.len() > MAX_PLACED_RUNS {
                        return Err(ReinstateError::TooManyRuns);
                    }
                }
                if placement.is_empty() {
                    return Err(ReinstateError::EmptyResult);
                }
                stg.push(
                    M5Rec::ContentPlace {
                        doc: doc.clone(),
                        at: at.ordinal,
                        runs: placement,
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
