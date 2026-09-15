//! Deriving a world from the journal (§6/§7): choose a base at or below a
//! boundary, then fold the committed records above it up to that boundary.
//!
//! Recovery and bounded replay are the SAME derivation — they differ only in
//! their bound (recovery's is §7's `W`, bounded replay's is the requested
//! boundary) and in what else they do around it (recovery truncates the tail;
//! bounded replay checks the requested value is a boundary at all). So
//! the base-selection fallback chain, the `rebuild_derived` seeding and the
//! fold itself are stated once, here, and each caller supplies its bound and
//! its own error vocabulary. What makes that fold exactly-once is settled
//! where the records are — [`crate::journal::ScanOutcome::records_to`] hands
//! over an ordered, ranged set with no coordinate twice — so this module
//! applies what it is given.

use crate::checkpoint::{CheckpointMeta, LoadRefused};
use crate::journal::{self, ScanFail, ScanOutcome, SegmentMeta};
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
    ///
    /// `bound` is the boundary this base will be folded to, when the caller has
    /// one: the scan then collects only what a fold to it can read. Recovery
    /// passes `None`, since its own bound is the committed head the scan is
    /// about to derive. A LOWER bound than the fold's leaves the records
    /// between them uncollected, which nothing downstream can restore — the
    /// outcome refuses that pairing ([`ScanOutcome::records_to`]) rather than
    /// answering a short world.
    pub(crate) fn scan(
        &self,
        segs: &[SegmentMeta],
        bound: Option<u64>,
    ) -> Result<ScanOutcome, ScanFail> {
        journal::scan(segs, self.s_load, bound)
    }
}

/// No base at or below the requested boundary remains derivable: no retained
/// checkpoint there loads, and the journal no longer reaches back to `Seq(1)`
/// so genesis cannot stand in (§6/§7).
pub(crate) struct Unreachable {
    /// The oldest retained checkpoint's seq when one exists — the oldest
    /// boundary a base could still be derived at.
    pub floor: Option<u64>,
    /// Why the NEWEST base this derivation could have used refused, which is
    /// the whole of what is left to tell an operator once the chain is
    /// exhausted: a body that will not decode says roll the binary, a failed
    /// checksum says restore the media, and a bare refusal says neither.
    /// `None` when no candidate was tried at all — no retained checkpoint, or
    /// every one of them above the requested boundary.
    ///
    /// Only an exhausted chain reaches a caller, so a refusal the fallback
    /// walked past is dropped: the derivation then succeeded, and why an
    /// older base was preferred is not a failure to report.
    pub cause: Option<LoadRefused>,
}

/// Choose the base (§6/§7): the newest checkpoint that loads — at or below
/// `bound`, when one is given — else genesis while it is still reachable.
/// A checkpoint that refuses ([`CheckpointMeta::load`]) is skipped and the
/// next-older RETAINED one tried, which is what makes the fallback chain real
/// rather than nominal; if nothing stands in, [`Unreachable`] carries why the
/// newest candidate refused, since by then that account is all an operator
/// has.
///
/// Whichever base is chosen is seeded through
/// [`WorldState::rebuild_derived`] BEFORE anything is folded onto it: the
/// seed stands in for the fold over `Seq ≤ s_load`, and [`WorldState::apply`]
/// carries the hints forward across everything above it (§7, seam
/// contract 2).
///
/// `genesis` is borrowed and copied only on the branch that uses it, so the
/// common case — a checkpoint that loads — costs no copy of a world at all.
///
/// `checkpoints` must be ASCENDING by seq, as [`crate::checkpoint::list`]
/// produces it: this walks it from the back as newest-first and reads its front
/// as the oldest base still derivable, so an out-of-order slice picks a base
/// that is not the newest and names a floor that is not the oldest. `segs`
/// must be ascending by `firstSeq` for [`journal::reaches_genesis`]'s own
/// reason.
pub(crate) fn select_base<W: WorldState>(
    checkpoints: &[CheckpointMeta],
    segs: &[SegmentMeta],
    bound: Option<u64>,
    genesis: &W,
) -> Result<Base<W>, Unreachable> {
    let mut cause: Option<LoadRefused> = None;
    for cp in checkpoints.iter().rev() {
        if bound.is_some_and(|b| cp.seq > b) {
            continue;
        }
        match cp.load::<W>() {
            Ok(world) => {
                return Ok(Base {
                    s_load: cp.seq,
                    world: world.rebuild_derived(),
                });
            }
            // Newest-first, so the first refusal met is the newest base's —
            // the one this derivation most wanted, and the one an operator
            // needs if nothing below it stands in either.
            Err(refused) => {
                cause.get_or_insert(refused);
            }
        }
    }
    // Genesis stands in only while the journal still reaches back to it.
    if !journal::reaches_genesis(segs) {
        return Err(Unreachable {
            floor: checkpoints.first().map(|cp| cp.seq),
            cause,
        });
    }
    Ok(Base {
        s_load: 0,
        world: genesis.clone().rebuild_derived(),
    })
}

/// Why a fold refused: the coordinate naming the damage, and — where there
/// was one — the account of what could not be read there.
///
/// The two conditions differ in whether an account exists at all. A record
/// that does not decode has the serializer's own refusal, and that refusal is
/// what separates a writer/reader skew (roll the binary forward) from bit-rot
/// (restore the media) — two conditions [`journal::decode_record`] answers
/// alike and an operator must not. A `Seq` the committed set presents twice
/// has none: the journal is malformed rather than unreadable, and the
/// coordinate is the whole of what there is to say.
pub(crate) struct FoldFail {
    /// The record's own, readable coordinate — unlike a corrupt run's (see
    /// [`ScanOutcome::fatal_run_anywhere`]).
    pub at: u64,
    /// The decode's own account, for the condition that has one.
    pub cause: Option<Box<dyn std::error::Error + Send + Sync + 'static>>,
}

/// Apply the committed records of `(base.s_load, bound]` onto `base`, one at
/// a time, decoding each. The order they arrive in is `Seq` order and each
/// coordinate arrives once, because [`ScanOutcome::records_to`] settles both
/// — they are facts about the set that scan derived, and it is the element
/// holding the set (§6/§7). This fold therefore applies what it is handed,
/// which is what [`WorldState::apply`] not being idempotent requires of it.
///
/// The scan is BORROWED, so its other answers — the tail cut among them —
/// outlive the fold. That is what lets a caller refuse on this fold's verdict
/// before it acts on any of them.
///
/// `scan` must be THIS base's own ([`Base::scan`]). A scan judged against
/// another base makes its own `(s_load, bound]` range a range over a different
/// base, and this answers `Ok` with a world missing records; a
/// [`ScanOutcome`]'s base is private to [`crate::journal`], so nothing here can
/// check it — [`Base::scan`] is what makes it true by construction.
///
/// `Err` is a committed, CRC-intact record that fails to decode as
/// `W::Record` — corrupt committed data the derived state needs, and the one
/// refusal only a fold can make, since only a fold names `W::Record` — or a
/// `Seq` the scan presents TWICE, which is [`ScanOutcome::records_to`]'s
/// verdict carried out in this caller's vocabulary. [`FoldFail`] carries
/// which. Halt, never drop, and never twice (§7): folding a coordinate twice
/// through a fold that need not be idempotent is exactly what recovery may
/// not do.
pub(crate) fn fold_to<W: WorldState>(
    base: Base<W>,
    scan: &ScanOutcome,
    bound: u64,
) -> Result<W, FoldFail> {
    let journaled = scan
        .records_to(bound)
        .map_err(|at| FoldFail { at, cause: None })?;
    let mut world = base.world;
    for entry in journaled {
        let record: W::Record = journal::decode_record(&entry.bytes).map_err(|e| FoldFail {
            at: entry.seq,
            cause: Some(Box::new(e)),
        })?;
        world = world.apply(&record);
    }
    Ok(world)
}
