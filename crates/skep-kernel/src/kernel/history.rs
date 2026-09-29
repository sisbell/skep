//! The history reads — the world, the commit chain and the signature slot as
//! of a committed boundary — derived read-only from the journal directory,
//! with no kernel lock taken and nothing written. The rest of `kernel` never
//! sees [`Kernel::bounded_read`] or its answer.

use crate::checkpoint;
use crate::error::HistoryError;
use crate::journal::{self, Attestation, ScanFail};
use crate::replay;
use crate::{Seq, WorldState};

use super::Kernel;

/// Where a bounded read at `at` stands once every refusal short of the
/// boundary judgment has spoken — [`Kernel::bounded_read`]'s answer, which
/// [`Kernel::world_at`] and [`Kernel::chain_at`] each finish with the one
/// question that is theirs alone.
// Returned by one private method and matched once by its caller, never
// stored: the size difference between the variants costs one move.
#[allow(clippy::large_enum_variant)]
enum BoundedRead<W> {
    /// `at` IS the base's own coordinate — a retained checkpoint's seq, or
    /// 0 — so the base answers, and the journal is not consulted.
    AtBase(replay::Base<W>),
    /// `at` lies above the base: the base, and the scan above it collected to
    /// `at`, with every at-rest verdict already refused.
    Above(replay::Base<W>, journal::ScanOutcome),
}

impl<W: WorldState> Kernel<W> {
    /// The committed world as of boundary `at` — READ-ONLY bounded replay
    /// over this kernel's own journal directory (the journal already holds
    /// every committed state; this makes a prefix of it answerable). Base =
    /// the newest retained checkpoint at or below `at` (else `genesis` while
    /// the journal still reaches back to `Seq(1)`),
    /// seeded through [`WorldState::rebuild_derived`], then folded over
    /// exactly `(base, at]` — recovery's Pass 2 with `W := at`. Deterministic:
    /// the same `at` yields a value-equal world on every call, across
    /// processes and regardless of which base is selected (a checkpoint
    /// embodies the same fold it stands in for — §6/§7).
    ///
    /// `at` must be a committed transaction boundary — one of the `Seq`
    /// values `transact` has returned (or 0 = genesis); a composite's
    /// interior `Seq` names a state that was never externally observable
    /// (§3) and is refused with [`HistoryError::NotABoundary`].
    ///
    /// A corrupt run at rest anywhere in the scanned region is a halt
    /// ([`HistoryError::Corruption`]), independently of where `at` sits: a
    /// run's own seqs are unreadable, so answering around it could answer
    /// from a hole. A boundary that IS the base — a retained checkpoint's seq,
    /// or 0 — is answered from that base without consulting the journal, and
    /// so never halts.
    ///
    /// The Σ₀ the fold starts from is the one this kernel was opened under,
    /// so the bounded replay applies journaled deltas onto exactly the genesis
    /// recovery would.
    ///
    /// REFUSAL PRECEDENCE — several of these can hold at once, and this is
    /// the order in which they speak: [`HistoryError::Unjournaled`] first,
    /// being a property of the kernel that no choice of `at` can avoid; then
    /// [`HistoryError::BeyondHead`]; then [`HistoryError::Reclaimed`], since
    /// with no base the journal's contents cannot matter; then
    /// [`HistoryError::Corruption`] from the SCAN — an unenumerable or
    /// oversized segment, a corrupt run, a chain verdict — since each makes
    /// the boundary set itself underivable; then
    /// [`HistoryError::NotABoundary`]; and last [`HistoryError::Corruption`]
    /// from the FOLD — a record in `(base, at]` that does not decode, or a
    /// `Seq` presented twice — which only a boundary reaches.
    /// [`HistoryError::Io`] speaks wherever the read that failed sits.
    /// Everything in that order up to the boundary judgment is one private
    /// derivation that [`Kernel::chain_at`] shares, so the two refuse alike up
    /// to it.
    ///
    /// COST, per call, uncached: one whole checkpoint file read and
    /// deserialized into a `W`, [`WorldState::rebuild_derived`] run over all
    /// of it, every journal segment above that base READ, and every committed
    /// record in `(base, at]` materialized before the fold begins. Segments
    /// above `at` are read and not collected — the corrupt-run sweep is at any
    /// height, so they must be read, and nothing above `at` is folded — so a
    /// caller choosing `at` chooses the base, the fold length and the records
    /// held, but not the bytes read. Nothing here is memoized, and peak memory
    /// is that figure times the number of calls in flight. Admission and
    /// concurrency are the caller's to gate; this method gates neither.
    ///
    /// Safe concurrently with the live appender and with `checkpoint()`:
    /// takes no kernel lock and writes nothing. Every frame of a commit
    /// `≤ current_seq()` is fully durable before that head was installed
    /// (§1 durable-before-visible), so the bounded region is stable under
    /// the reader; a racing append can contribute at most a torn suffix,
    /// which classifies as an EOF run beyond the last committed marker and
    /// is ignored here. Two things a concurrent writer can still make this
    /// call refuse with, both transient and neither a wrong world: a
    /// checkpoint's retention removing a file between listing and reading
    /// ([`HistoryError::Io`]/[`HistoryError::Reclaimed`]), and a commit whose
    /// barrier fails truncating its tail while a read is mid-file, which
    /// leaves the read holding a discontinuity that classifies as at-rest
    /// [`HistoryError::Corruption`]. A retry re-derives from the file as it
    /// now stands.
    pub fn world_at(&self, at: Seq) -> Result<W, HistoryError> {
        let (base, scan) = match self.bounded_read(at)? {
            BoundedRead::AtBase(base) => return Ok(base.into_world()),
            BoundedRead::Above(base, scan) => (base, scan),
        };
        if let Err(nearest) = scan.require_boundary(at.0) {
            return Err(HistoryError::NotABoundary {
                nearest: Seq(nearest),
            });
        }
        // Recovery's fold, bounded at `at` (§6/§7).
        replay::fold_to(base, &scan, at.0).map_err(|fail| HistoryError::Corruption {
            at: Seq(fail.at),
            cause: fail.cause,
        })
    }

    /// The commit chain's value AS OF boundary `at` — the `chain` the marker
    /// closing `at`'s transaction carries, READ-ONLY off this kernel's own
    /// journal directory under the verification [`Kernel::world_at`] runs,
    /// with no world folded and none kept (QUEUE item 10, the chain's open
    /// items: `chain_at(N)`). What a peer holding a saved `(position,
    /// chain)` pair — a `/health` reading, a published head's members —
    /// checks against the board's RECOMPUTATION rather than against the
    /// board's stored claim: a re-chained journal answers the forgery here,
    /// which the saved value contradicts, where the claim it left untouched
    /// would still byte-compare. At the installed head this equals
    /// [`Kernel::chain_head`]; at `0` it is the seed.
    ///
    /// THE SAME DERIVATION as `world_at`, bound for bound: the same base
    /// selection capped at `at`, the same scan above it — which verifies
    /// every committed link from that base to the journal's END, not to
    /// `at`, so a boundary below the newest checkpoint is a full
    /// verification of the surviving journal from the base it selects — the
    /// same refusals in the same order as far as `world_at`'s scan goes
    /// ([`HistoryError::Unjournaled`], [`HistoryError::BeyondHead`],
    /// [`HistoryError::Reclaimed`], [`HistoryError::Corruption`] — an
    /// unenumerable or oversized segment, the corrupt run, then the chain's
    /// own verdicts — then [`HistoryError::NotABoundary`]) and none of the
    /// fold's: this folds nothing, so an undecodable record or a `Seq`
    /// presented twice refuses `world_at` and not this, the chain being over
    /// the framed bytes, which verify; and the same answer for a boundary
    /// that IS the base: the base's own chain, the `SKC4` header's
    /// `chain_head` or the seed at genesis, answered without consulting the
    /// journal and so never halting. Deterministic in `at` across calls,
    /// processes and base choices, since a checkpoint's header carries the
    /// very marker value it stands in for.
    ///
    /// COST, per call, uncached: `world_at`'s minus the fold and the resident
    /// world — the base is still LOADED, since its body hash is the base's
    /// door and the header is read through it, and every segment above the
    /// base is still READ and its committed records at or below `at` still
    /// collected; the world is dropped unfolded. Admission and concurrency
    /// are the caller's to gate, as they are there; safe beside the live
    /// appender and `checkpoint()` for the same reasons, with the same two
    /// transient refusals.
    pub fn chain_at(&self, at: Seq) -> Result<[u8; 32], HistoryError> {
        match self.bounded_read(at)? {
            // The base's own chain — the `SKC4` header's `chain_head`, or the
            // seed at genesis — with the journal not consulted, as `world_at`
            // does not consult it for the base's own world.
            BoundedRead::AtBase(base) => Ok(base.chain_head()),
            // Collected to exactly `at`, above its base: the chain captured
            // there answers both whether `at` is a boundary and the value at
            // it.
            BoundedRead::Above(_, scan) => {
                scan.chain_at_boundary(at.0)
                    .map_err(|nearest| HistoryError::NotABoundary {
                        nearest: Seq(nearest),
                    })
            }
        }
    }

    /// THE SIGNATURE SLOT of the transaction that committed the boundary `at`
    /// (signed ops): the [`Attestation`] [`Kernel::transact_attested`] wrote
    /// into its marker, or `None` where the slot is empty — a READ of the
    /// marker's own bytes, the one place the slot is journal-resident, and the
    /// read a feed sidecar mirroring the slot rebuilds from. Answered by the
    /// same bounded scan [`Kernel::chain_at`] runs, with ONE difference: the
    /// base is selected strictly BELOW `at`, so that the marker closing `at`
    /// is scanned rather than embodied — a checkpoint carries the chain at
    /// its coordinate and no marker, so a boundary that IS a checkpoint's
    /// seq answers from the segment below it, and refuses
    /// [`HistoryError::Reclaimed`] where that segment is gone even though
    /// `chain_at` still answers there. Genesis (`Seq(0)`) is no transaction
    /// and answers `None`. The other refusals are `chain_at`'s, in its order.
    ///
    /// The kernel INTERPRETS nothing it answers: which pair a tag names and
    /// whether the blob verifies are the verifier's questions, beside the
    /// table.
    pub fn attestation_at(&self, at: Seq) -> Result<Option<Attestation>, HistoryError> {
        let Some(journaled) = &self.journaled else {
            return Err(HistoryError::Unjournaled);
        };
        let installed_head = self.current_seq();
        if at > installed_head {
            return Err(HistoryError::BeyondHead {
                head: installed_head,
            });
        }
        if at.0 == 0 {
            return Ok(None);
        }
        let checkpoints = checkpoint::list(&journaled.dir)?;
        let segs = journal::list_segments(&journaled.dir)?;
        // Strictly below `at`, so the marker closing `at` is in the scanned
        // region (a base AT `at` would embody it and read no marker).
        let base = replay::select_base(&checkpoints, &segs, Some(at.0 - 1), &journaled.genesis)
            .map_err(|fail| HistoryError::Reclaimed {
                floor: fail.floor.map(Seq),
                cause: fail.cause,
            })?;
        let scan = base.scan(&segs, Some(at.0)).map_err(|fail| match fail {
            ScanFail::Io(e) => HistoryError::Io(e),
            ScanFail::Unbounded { at } => HistoryError::Corruption {
                at: Seq(at),
                cause: None,
            },
        })?;
        if let Some((halt_at, cause)) = scan.halt_anywhere() {
            return Err(HistoryError::Corruption {
                at: Seq(halt_at),
                cause,
            });
        }
        scan.attestation_at_boundary(at.0)
            .map_err(|nearest| HistoryError::NotABoundary {
                nearest: Seq(nearest),
            })
    }

    /// THE BOUNDED DERIVATION, stated once for [`Kernel::world_at`] and
    /// [`Kernel::chain_at`], which differ only in what they ask of its answer
    /// — so the two cannot refuse differently up to that question, and the
    /// one a peer checks a saved chain against cannot answer over a region
    /// the other refuses. Its refusals are the first four of `world_at`'s
    /// REFUSAL PRECEDENCE, in that order, and this is where that order is
    /// kept: [`HistoryError::Unjournaled`]; [`HistoryError::BeyondHead`]
    /// above the installed head; [`HistoryError::Reclaimed`] — the base
    /// selection recovery runs, capped at `at` so a later checkpoint cannot
    /// stand in for an earlier boundary; then the scan's own
    /// [`HistoryError::Corruption`], an unenumerable or oversized segment and
    /// then every at-rest verdict at any height
    /// ([`journal::ScanOutcome::halt_anywhere`]). A boundary that IS the base
    /// is answered from the base alone: checkpoint seqs are committed
    /// boundaries (a checkpoint serializes an installed root) and 0 is
    /// genesis, so there is nothing to fold or verify, and consulting the
    /// journal could only refuse a question the base already answers.
    fn bounded_read(&self, at: Seq) -> Result<BoundedRead<W>, HistoryError> {
        // A kernel with no journal can answer no boundary, so that refusal
        // precedes every question about `at`: a caller told `BeyondHead` here
        // would walk `at` down to genesis before learning that none of it was
        // ever answerable.
        let Some(journaled) = &self.journaled else {
            return Err(HistoryError::Unjournaled);
        };
        let installed_head = self.current_seq();
        if at > installed_head {
            return Err(HistoryError::BeyondHead {
                head: installed_head,
            });
        }
        let checkpoints = checkpoint::list(&journaled.dir)?;
        let segs = journal::list_segments(&journaled.dir)?;
        let base = replay::select_base(&checkpoints, &segs, Some(at.0), &journaled.genesis)
            .map_err(|fail| HistoryError::Reclaimed {
                floor: fail.floor.map(Seq),
                cause: fail.cause,
            })?;
        if at.0 == base.s_load() {
            return Ok(BoundedRead::AtBase(base));
        }
        let scan = base.scan(&segs, Some(at.0)).map_err(|fail| match fail {
            ScanFail::Io(e) => HistoryError::Io(e),
            ScanFail::Unbounded { at } => HistoryError::Corruption {
                at: Seq(at),
                cause: None,
            },
        })?;
        // Any at-rest verdict above the base is a halt, even beyond `at`: a
        // corrupt run's own seqs are unreadable, so answering around it could
        // answer from a hole, and a link that failed above `at` says the
        // region is not the history it claims. (A racing live append never
        // produces a Landed run: it can tear only the file's suffix, after the
        // last committed marker, which reaches EOF.)
        if let Some((halt_at, cause)) = scan.halt_anywhere() {
            return Err(HistoryError::Corruption {
                at: Seq(halt_at),
                cause,
            });
        }
        Ok(BoundedRead::Above(base, scan))
    }
}
