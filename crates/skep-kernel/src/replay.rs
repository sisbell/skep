//! Deriving a world from the journal (§6/§7): choose a base at or below a
//! boundary, then fold the committed records above it up to that boundary.
//!
//! Recovery and bounded replay are the SAME derivation — they differ only in
//! their bound (recovery's is §7's `W`, bounded replay's is the requested
//! boundary) and in what else they do around it (recovery truncates the tail;
//! bounded replay checks the requested value is a boundary at all). So
//! the base-selection fallback chain, the `rebuild_derived` seeding and the
//! exactly-once fold are stated once, here, and each caller supplies its
//! bound and its own error vocabulary.

use crate::checkpoint::CheckpointMeta;
use crate::journal::{self, CommittedRecord, ScanFail, ScanOutcome, SegmentMeta};
use crate::WorldState;

/// A base to fold onto: the world embodying every record with
/// `Seq ≤ s_load`, already seeded through [`WorldState::rebuild_derived`].
///
/// The two travel together and neither is settable from outside this module,
/// so [`select_base`] is the only site that can mint one. That is what makes
/// the pairing an invariant rather than a habit: a world at a coordinate it
/// does not embody folds records it already holds, and since
/// [`WorldState::apply`] need not be idempotent, that is silent double
/// application answered `Ok`.
pub(crate) struct Base<W> {
    s_load: u64,
    world: W,
}

impl<W> Base<W> {
    /// The coordinate this base embodies — §7's `S_load`.
    pub(crate) fn s_load(&self) -> u64 {
        self.s_load
    }

    /// The base itself, for a boundary that IS the base and so has nothing
    /// above it to fold.
    pub(crate) fn into_world(self) -> W {
        self.world
    }

    /// Scan the journal above THIS base (§7). The base a scan is judged
    /// against is the base it will be folded onto, by construction: this takes
    /// no `S_load` a caller could have got from somewhere else, and a scan run
    /// against a HIGHER base than this one would skip closed segments whose
    /// records the fold still wants — a world missing records, answered `Ok`.
    pub(crate) fn scan(&self, segs: &[SegmentMeta]) -> Result<ScanOutcome, ScanFail> {
        journal::scan(segs, self.s_load)
    }
}

/// No base at or below the requested boundary remains derivable: no retained
/// checkpoint there loads, and the journal no longer reaches back to `Seq(1)`
/// so genesis cannot stand in (§6/§7). `floor` is the oldest retained
/// checkpoint's seq when one exists — the oldest boundary a base could still
/// be derived at.
pub(crate) struct Unreachable {
    pub floor: Option<u64>,
}

/// Choose the base (§6/§7): the newest checkpoint that loads — at or below
/// `bound`, when one is given — else genesis while it is still reachable.
/// A checkpoint failing its header checksum is skipped and the next-older
/// RETAINED one tried, which is what makes the fallback chain real rather
/// than nominal.
///
/// Whichever base is chosen is seeded through
/// [`WorldState::rebuild_derived`] BEFORE anything is folded onto it: the
/// seed stands in for the fold over `Seq ≤ s_load`, and [`WorldState::apply`]
/// carries the hints forward across everything above it (§7, seam
/// contract 2).
///
/// `genesis` is borrowed and copied only on the branch that uses it, so the
/// common case — a checkpoint that loads — costs no copy of a world at all.
pub(crate) fn select_base<W: WorldState>(
    checkpoints: &[CheckpointMeta],
    segs: &[SegmentMeta],
    bound: Option<u64>,
    genesis: &W,
) -> Result<Base<W>, Unreachable> {
    for cp in checkpoints.iter().rev() {
        if bound.is_some_and(|b| cp.seq > b) {
            continue;
        }
        if let Some(world) = cp.load::<W>() {
            return Ok(Base {
                s_load: cp.seq,
                world: world.rebuild_derived(),
            });
        }
    }
    // Genesis stands in only while the journal still reaches back to it.
    if !journal::reaches_genesis(segs) {
        return Err(Unreachable {
            floor: checkpoints.first().map(|cp| cp.seq),
        });
    }
    Ok(Base {
        s_load: 0,
        world: genesis.clone().rebuild_derived(),
    })
}

/// Fold the scanned region's committed records onto `base`, in `Seq` order,
/// over exactly `(base.s_load, bound]` — each record exactly once, since
/// [`WorldState::apply`] is not required to be idempotent, and with no
/// contiguity required, since a burned-`Seq` gap folds harmlessly (§6/§7).
///
/// The scan is BORROWED, so its other answers — the tail cut among them —
/// outlive the fold. That is what lets a caller refuse on this fold's verdict
/// before it acts on any of them.
///
/// `scan` must be THIS base's own ([`Base::scan`]). A scan judged against
/// another base makes the `(base.s_load, bound]` filter meaningless and this
/// answers `Ok` with a world missing records; a [`ScanOutcome`]'s own base is
/// private to [`crate::journal`], so nothing here can check it — [`Base::scan`]
/// is what makes it true by construction.
///
/// `Err` carries the `Seq` of a committed, CRC-intact record that fails to
/// decode as `W::Record` — corrupt committed data the derived state needs —
/// or one the committed set presents TWICE. That `Seq` is the record's own,
/// readable one, unlike a corrupt run's (see
/// [`ScanOutcome::fatal_run_anywhere`]).
/// Halt, never drop, and never twice (§7): the sequencer mints each `Seq`
/// once, so a repeat is a journal this kernel did not write, and folding a
/// coordinate twice through a fold that need not be idempotent is exactly
/// what recovery may not do.
pub(crate) fn fold_to<W: WorldState>(
    base: Base<W>,
    scan: &ScanOutcome,
    bound: u64,
) -> Result<W, u64> {
    let mut journaled: Vec<&CommittedRecord> = scan.committed_records.iter().collect();
    journaled.sort_by_key(|entry| entry.seq);
    let mut world = base.world;
    let mut prev: Option<u64> = None;
    for entry in journaled {
        let seq = entry.seq;
        if seq <= base.s_load || seq > bound {
            continue;
        }
        if prev == Some(seq) {
            return Err(seq);
        }
        prev = Some(seq);
        let record: W::Record = journal::decode_record(&entry.bytes).map_err(|_| seq)?;
        world = world.apply(&record);
    }
    Ok(world)
}
