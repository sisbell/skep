//! Deriving a world from the journal (§6/§7): choose a base at or below a
//! position, then fold the committed records above it up to that position.
//!
//! Recovery and bounded replay are the SAME derivation — they differ only in
//! their bound (recovery's is the trustworthy boundary `W`, bounded replay's
//! is the requested position) and in what else they do around it (recovery
//! truncates the tail; bounded replay checks the position is a boundary). So
//! the base-selection fallback chain, the `rebuild_derived` seeding and the
//! exactly-once fold are stated once, here, and each caller supplies its
//! bound and its own error vocabulary.

use crate::checkpoint::{self, CkptMeta};
use crate::journal::{ScanOutcome, SegmentMeta};
use crate::WorldState;

/// A base to fold onto: the world embodying every record with
/// `Seq ≤ s_load`, already seeded through [`WorldState::rebuild_derived`].
pub(crate) struct Base<W> {
    pub s_load: u64,
    pub world: W,
}

/// No base at or below the requested position remains derivable: no retained
/// checkpoint there loads, and the journal no longer reaches back to `Seq(1)`
/// so genesis cannot stand in (§6/§7). `floor` is the oldest retained
/// checkpoint's seq when one exists — the oldest position a base could still
/// be derived at.
pub(crate) struct Unreachable {
    pub floor: Option<u64>,
}

/// Choose the base (§6/§7): the newest checkpoint that loads — at or below
/// `ceiling`, when one is given — else genesis while it is still reachable.
/// A checkpoint failing its header checksum is skipped and the next-older
/// RETAINED one tried, which is what makes the fallback chain real rather
/// than nominal.
///
/// Whichever base is chosen is seeded through
/// [`WorldState::rebuild_derived`] BEFORE anything is folded onto it: the
/// seed stands in for the fold over `Seq ≤ s_load`, and [`WorldState::apply`]
/// carries the hints forward across everything above it (§7, seam
/// contract 2).
pub(crate) fn select_base<W: WorldState>(
    cps: &[CkptMeta],
    segs: &[SegmentMeta],
    ceiling: Option<u64>,
    genesis: W,
) -> Result<Base<W>, Unreachable> {
    for cp in cps.iter().rev() {
        if ceiling.is_some_and(|c| cp.seq > c) {
            continue;
        }
        if let Some(world) = checkpoint::load::<W>(&cp.path, cp.seq) {
            return Ok(Base {
                s_load: cp.seq,
                world: world.rebuild_derived(),
            });
        }
    }
    // Genesis is reachable while the earliest surviving segment still starts
    // at `Seq(1)` — an empty journal reaches it trivially.
    if !(segs.is_empty() || segs[0].first_seq == 1) {
        return Err(Unreachable {
            floor: cps.first().map(|c| c.seq),
        });
    }
    Ok(Base {
        s_load: 0,
        world: genesis.rebuild_derived(),
    })
}

/// Fold the scanned region's committed records onto `base`, in `Seq` order,
/// over exactly `(base.s_load, upto]` — each record exactly once, since
/// [`WorldState::apply`] is not required to be idempotent, and with no
/// contiguity required, since a burned-`Seq` gap folds harmlessly (§6/§7).
///
/// `Err` carries the `Seq` of a committed, CRC-intact record that fails to
/// decode as `W::Record`: corrupt committed data the derived state needs —
/// halt, never drop (§7). That `Seq` is the record's own, readable one,
/// unlike a corrupt run's (see [`ScanOutcome::fatal_run`]).
pub(crate) fn fold_to<W: WorldState>(
    base: Base<W>,
    scan: ScanOutcome,
    upto: u64,
) -> Result<W, u64> {
    let mut recs = scan.committed_records;
    recs.sort_by_key(|(seq, _)| *seq);
    let mut world = base.world;
    for (seq, bytes) in recs {
        if seq <= base.s_load || seq > upto {
            continue;
        }
        let rec: W::Record = bincode::deserialize(&bytes).map_err(|_| seq)?;
        world = world.apply(&rec);
    }
    Ok(world)
}
