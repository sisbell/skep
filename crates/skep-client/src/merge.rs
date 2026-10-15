//! MERGING VERSIONS — the editor's act on a daughter, behind the `merge`
//! feature (the merge record: `_designs/CLIENT/2026-10-14-reconciling-
//! versions-design.md` in the skep-ux-design repository, §0 and §7).
//!
//! The merge reads the base member and the two sides as run lists, and
//! from those three lists alone it knows what each side removed (a base
//! position absent from that side), what each side added (a position not
//! the base's) and where each addition sits (between which two base
//! positions). It builds the merged list M by walking the surviving base
//! positions in the base's order — or the order the one side that moved
//! them gave — dropping every position either side removed, and placing
//! each side's additions back at the place their anchors name, under the
//! rules. It never guesses: every gap gets a deterministic placement, and
//! the ones the rules do not settle are marked unsettled with that
//! placement shown as the default, so whoever is merging — a person or an
//! agent — sees them and resolves them with judgment, or stops. The list,
//! the gap report and the counts come back before anything is written.
//!
//! THIS BUILD holds the pure core alone: [`compose_runs`] over three run
//! lists, with [`base_of`] and [`script`] beside it. The record's other
//! parts are absent, by name: the reads (`merge/reads.rs` — the three
//! `image` reads, the value reads, the head's address), the landing
//! (`merge/land.rs` — the publish, the draft's edit script applied, the
//! supersession claim), the record (`merge/record.rs` — the D13 `merge`
//! kind, its key and currency) and the journal (`merge/journal.rs` — the
//! account's merge journal, found or minted). A later lane builds them
//! over this core.
//!
//! THE ONE RULE (merge record §2, as ruled): a case is safe when the two
//! sides touched different material; a conflict when they touched the same
//! material or the same spot — "same material" known exactly by run
//! identity, so a move is not a touch and an identical addition is not a
//! difference. Six kinds of gap carry it, and the rules settle one:
//!
//! * `order` — both sides added at one spot: unsettled, the commit order
//!   shown as the default, each side's runs together.
//! * `anchor` — an addition beside a removal, one anchor surviving and the
//!   adding side's own removal overlapping nothing the other side removed:
//!   SETTLED, placed beside the survivor.
//! * `corner` — an addition whose anchors are both gone: unsettled, the
//!   default after the nearest surviving base position to its left.
//! * `cut` — an addition at a cut the other side's move opened: unsettled,
//!   the default after the left anchor.
//! * `collision` — both sides removed overlapping material, whether both,
//!   one or neither put something in its place: unsettled, the default what
//!   was put there kept in the commit order.
//! * `moves` — both sides moved overlapping material: unsettled, the
//!   default the earlier side's order.
//!
//! Beside them the value rule (§5), the client's and optional: the same
//! bytes added by both sides are kept once, the earlier side's identity,
//! and that settles the gap; a retype beside an edit keeps the retyping
//! side's identity unless the caller asks the base's back.

mod compose;

#[cfg(test)]
mod tests;

pub use compose::{
    base_of, compose_runs, script, Choice, Composed, Gap, GapId, GapKind, InPlaceOp, Item, Options,
    PlacedRun, Placement, ResolvedBy, Resolution, Run, RunCounts, SideIx, ValueLog,
};
