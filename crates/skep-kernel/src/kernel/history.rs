//! The history reads — the world, the commit chain and the signature slot as
//! of a committed boundary, and the committed boundaries above a position
//! with their slots — derived read-only from the journal directory, with no
//! kernel lock taken and nothing written: the three boundary reads through
//! one derivation, [`Kernel::history_read`], and the boundary list through
//! the steps that derivation is built from, in the same order. The rest of
//! `kernel` never sees any of it or its answers.

use crate::checkpoint;
use crate::error::HistoryError;
use crate::journal::{self, Attestation, ScanFail, ScanOutcome, SegmentMeta};
use crate::replay;
use crate::{Seq, WorldState};

use super::{Journaled, Kernel};

/// Where a history read at `at` stands once every refusal before the fold has
/// spoken, the boundary judgment included — [`Kernel::history_read`]'s answer,
/// which each of the three boundary reads finishes with the one thing it
/// reads there: the fold, the chain, or the slot.
// Returned by one private method and matched at once by each caller, never
// stored: the size difference between the variants costs one move.
#[allow(clippy::large_enum_variant)]
enum HistoryRead<W> {
    /// `at` IS the base's own coordinate — a retained checkpoint's seq, or
    /// 0 — so the base answers, and the journal is not consulted.
    AtBase(replay::Base<W>),
    /// `at` lies above the base and IS a committed boundary: the base, the
    /// scan above it collected to `at` with every at-rest verdict already
    /// refused, and what the marker closing `at` carries.
    Above {
        base: replay::Base<W>,
        scan: journal::ScanOutcome,
        closing: journal::ClosingMarker,
    },
}

impl<W: WorldState> Kernel<W> {
    /// The committed world as of boundary `at` — READ-ONLY bounded replay
    /// over this kernel's own journal directory (the journal already holds
    /// every committed state; this makes a prefix of it answerable). Base =
    /// the newest retained checkpoint at or below `at` that loads — one that
    /// refuses is passed over for the next-older, as recovery passes it (§6)
    /// — else `genesis` while the journal still reaches back to `Seq(1)`,
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
    /// Everything in that order through the boundary judgment is one private
    /// derivation that [`Kernel::chain_at`] and [`Kernel::attestation_at`]
    /// share, so the three refuse alike up to the fold — save where
    /// [`Kernel::attestation_at`]'s base must sit below the boundary, which it
    /// states — and whose steps [`Kernel::boundaries_above`] takes in the
    /// same order as far as its own question goes.
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
        match self.history_read(at, at.0)? {
            HistoryRead::AtBase(base) => Ok(base.into_world()),
            // Recovery's fold, bounded at `at` (§6/§7).
            HistoryRead::Above { base, scan, .. } => {
                replay::fold_to(base, &scan, at.0).map_err(|fail| HistoryError::Corruption {
                    at: Seq(fail.at),
                    cause: fail.cause,
                })
            }
        }
    }

    /// The commit chain's value AS OF boundary `at` — the `chain` the marker
    /// closing `at`'s transaction carries, READ-ONLY off this kernel's own
    /// journal directory under the verification [`Kernel::world_at`] runs,
    /// with no world folded and none kept (QUEUE item 10, the chain's open
    /// items: `chain_at(N)`). What a peer holding a saved `(seq, chain)` pair
    /// — a `/health` reading, a published head's members — checks against
    /// this kernel's RECOMPUTATION rather than against the journal's stored
    /// claim: a re-chained journal answers the forgery here, which the saved
    /// value contradicts, where the claim it left untouched would still
    /// byte-compare. At the installed head this equals [`Kernel::chain_head`];
    /// at `0` it is the chain's genesis value.
    ///
    /// THE SAME DERIVATION as `world_at`, bound for bound: the same base
    /// selection capped at `at`, the same scan above it — which verifies
    /// every committed chain link from that base to the journal's END, not
    /// to `at`, so a boundary below the newest checkpoint is a full
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
    /// `chain_head` or the chain's genesis value at genesis, answered without
    /// consulting the journal and so never halting. Deterministic in `at`
    /// across calls, processes and base choices, since a checkpoint's header
    /// carries the very marker value it stands in for.
    ///
    /// COST, per call, uncached: `world_at`'s minus the fold and the resident
    /// world — the base is still LOADED and seeded through
    /// [`WorldState::rebuild_derived`], since its body hash is the base's
    /// door and the header is read through it, and every segment above the
    /// base is still READ and its committed records at or below `at` still
    /// collected; the world is dropped unfolded. Admission and concurrency
    /// are the caller's to gate, as they are there; safe beside the live
    /// appender and `checkpoint()` for the same reasons, with the same two
    /// transient refusals.
    pub fn chain_at(&self, at: Seq) -> Result<[u8; 32], HistoryError> {
        Ok(match self.history_read(at, at.0)? {
            // The base's own chain — the `SKC4` header's `chain_head`, or the
            // chain's genesis value at genesis — with the journal not
            // consulted, as `world_at` does not consult it for the base's own
            // world.
            HistoryRead::AtBase(base) => base.chain(),
            // The chain the marker closing `at` carries, verified with every
            // chain link from the base to the journal's end.
            HistoryRead::Above { closing, .. } => closing.chain,
        })
    }

    /// THE SIGNATURE SLOT of the transaction that committed the boundary `at`
    /// (signed ops): the [`Attestation`] [`Kernel::transact_attested`] wrote
    /// into its marker, or `None` where the slot is empty — a READ of the
    /// marker's own bytes, the one place the slot is journal-resident.
    /// Answered by the same bounded scan [`Kernel::chain_at`] runs, with ONE
    /// difference: the base is selected strictly BELOW `at`, so that the
    /// marker closing `at` is scanned rather than embodied — a checkpoint
    /// carries the chain at its coordinate and no marker, so a boundary that
    /// IS a checkpoint's seq answers from the segment below it, and refuses
    /// [`HistoryError::Reclaimed`] where that segment is gone even though
    /// `chain_at` still answers there. Genesis (`Seq(0)`) is no transaction
    /// and answers `None`. The other refusals are `chain_at`'s, in its order.
    /// At a checkpoint's own seq it answers only while an older base remains
    /// derivable — an older retained checkpoint that loads, or genesis while
    /// the journal reaches back to it — so the `nearest` of its
    /// [`HistoryError::NotABoundary`] and the `floor` of its
    /// [`HistoryError::Reclaimed`] can name a seq it refuses, as those
    /// variants say. Every slot above a position in ONE scan is
    /// [`Kernel::boundaries_above`], which answers at each boundary what this
    /// answers there.
    ///
    /// COST, per call, uncached: [`Kernel::chain_at`]'s, from a base strictly
    /// below `at` — never that read's base-only answer, so at a checkpoint's
    /// own seq it loads an older base and reads the segments above it. Safe
    /// beside the live appender and `checkpoint()`, with the same two
    /// transient refusals.
    ///
    /// The kernel INTERPRETS nothing it answers: which pair a tag names and
    /// whether the blob verifies are the verifier's questions, beside the
    /// table.
    pub fn attestation_at(&self, at: Seq) -> Result<Option<Attestation>, HistoryError> {
        // Genesis closes no transaction, so its slot is empty: answered
        // without a scan by any kernel that answers history at all (no head
        // lies below 0, so `BeyondHead` has nothing to say here).
        let Some(below) = at.0.checked_sub(1) else {
            return if self.journaled.is_some() {
                Ok(None)
            } else {
                Err(HistoryError::Unjournaled)
            };
        };
        // A base strictly below `at`, so the marker closing `at` is scanned
        // rather than embodied: a checkpoint carries the chain at its seq and
        // no marker.
        let HistoryRead::Above { closing, .. } = self.history_read(at, below)? else {
            unreachable!("a base at or below {below} lies below {at}, so the read is above it");
        };
        Ok(closing.attestation)
    }

    /// THE COMMITTED BOUNDARIES ABOVE A POSITION, each with its signature
    /// slot — §3.3 step 2 of the operations design, the one-pass seam the
    /// attest store's rebuild takes its positions from: every committed
    /// boundary in `(position, head]`, in `Seq` order, paired with the
    /// [`Attestation`] its marker carries or `None` for the empty slot —
    /// value for value what [`Kernel::attestation_at`] answers at each — READ
    /// in ONE scan from a base at or below `position` to the journal's end,
    /// where that read runs a scan per boundary. `head` is the INSTALLED head
    /// at the call ([`Kernel::current_seq`]), as [`HistoryError::BeyondHead`]
    /// reads it.
    ///
    /// `position` is a POSITION, not a boundary: a committed boundary, a
    /// composite's interior `Seq`, a burned one — whatever a caller's own
    /// coverage names, which need not be a boundary at all — and it is never
    /// judged one, so this read has no [`HistoryError::NotABoundary`]. The
    /// list holds boundaries alone: a composite contributes its `last_seq`
    /// and never an interior coordinate (§3).
    ///
    /// THE BASE, at or below `position` — the newest retained checkpoint
    /// there that loads and seeds, else genesis while the journal reaches it
    /// — through the base selection the three boundary reads run, capped at
    /// `position`: a `position` that IS a checkpoint's seq takes that
    /// checkpoint and scans the markers above it; `Seq(0)` takes genesis
    /// while the journal reaches back to `Seq(1)`, and refuses
    /// [`HistoryError::Reclaimed`] once it does not, exactly as
    /// `attestation_at(Seq(1))` refuses; a `position` below the oldest
    /// retained checkpoint refuses the same way, naming that checkpoint as
    /// the `floor` — at which this read answers, its base sitting AT the
    /// floor where `attestation_at`'s must sit below it. Every marker above
    /// the base is scanned and the chain verified from the base to the
    /// journal's END, as `chain_at` verifies it; what is answered is the
    /// boundaries above `position`.
    ///
    /// THE ENDS: `position == head` names an empty range and answers the
    /// empty list WITHOUT consulting the journal — no base is loaded and no
    /// segment read, as genesis's slot is answered without a scan — since
    /// nothing the journal holds could change an answer the range alone
    /// settles; `position > head` refuses [`HistoryError::BeyondHead`].
    ///
    /// THE BOUND AT THE HEAD: the list is bounded at the head the call began
    /// with. A commit that lands while the read runs — its marker durable
    /// and scanned, its root installed after the head was read — is NOT
    /// answered, so a caller holds a prefix of the boundaries it can reason
    /// about against a head it read, never a list reaching past one; the
    /// next call answers from the next head. A boundary the journal no
    /// longer closes — a last marker rotted at rest, which reads as the torn
    /// tail (the open item in [`Kernel::open`]'s damage model) — is absent
    /// from the list, as `attestation_at` refuses it
    /// [`HistoryError::NotABoundary`].
    ///
    /// REFUSAL PRECEDENCE — the three boundary reads' steps in their order,
    /// as far as this read's question goes: [`HistoryError::Unjournaled`]
    /// first; then [`HistoryError::BeyondHead`]; then
    /// [`HistoryError::Reclaimed`], the base selection; then
    /// [`HistoryError::Corruption`] from the scan — an unenumerable or
    /// oversized segment, a corrupt run at any height, the chain's own
    /// verdicts — each at the coordinate and with the account `world_at`
    /// gives it, since a run's own seqs are unreadable and a region whose
    /// chain fails is not the history it claims, so the boundary set itself
    /// is underivable; and none of the fold's, since nothing is folded.
    /// [`HistoryError::Io`] speaks wherever the read that failed sits.
    ///
    /// COST, per call, uncached: the base LOADED and seeded through
    /// [`WorldState::rebuild_derived`], as every history read loads its base
    /// — a whole checkpoint file read and deserialized, dropped unfolded —
    /// then ONE scan from that base to the journal's end: every segment
    /// above the base READ, the retained window at most, and one entry kept
    /// per committed transaction above the base, an [`Attestation`] per
    /// attested one — never the records, which the scan reads, checksums
    /// and releases. So a caller asking over a long window pays the window's
    /// commits in memory, and the bytes of every signature in it; what it
    /// does not pay is a scan per boundary. Nothing here is memoized; peak
    /// memory is that figure times the calls in flight; admission and
    /// concurrency are the caller's to gate, as they are for `world_at`.
    ///
    /// Safe concurrently with the live appender and with `checkpoint()`:
    /// takes no kernel lock and writes nothing, under the argument
    /// [`Kernel::world_at`] states — every frame of a commit at or below the
    /// head is durable before that head was installed, and a racing append
    /// can leave at most a torn suffix beyond the last committed marker,
    /// which classifies as an EOF run and is ignored. The same two transient
    /// refusals: a checkpoint's retention removing a segment between the
    /// listing and the read ([`HistoryError::Io`]/[`HistoryError::Reclaimed`]),
    /// and a commit whose barrier fails truncating its tail under a read
    /// mid-file, which the read meets as at-rest
    /// [`HistoryError::Corruption`]. A retry re-derives from the files as
    /// they then stand.
    ///
    /// The kernel INTERPRETS nothing it answers, here as at
    /// [`Kernel::attestation_at`]: which pair a tag names and whether a blob
    /// verifies are the verifier's questions, beside the table.
    pub fn boundaries_above(
        &self,
        position: Seq,
    ) -> Result<Vec<(Seq, Option<Attestation>)>, HistoryError> {
        let (journaled, head) = self.journaled_head(position)?;
        // `(position, head]` is empty: nothing the journal holds could change
        // that, so no base is loaded and no segment read.
        if position == head {
            return Ok(Vec::new());
        }
        let (base, segs) = self.base_at_or_below(journaled, position.0)?;
        let scan = base.scan_boundaries(&segs).map_err(scan_refusal)?;
        at_rest_halt(&scan)?;
        let mut above: Vec<(Seq, Option<Attestation>)> = scan
            .into_boundaries()
            .into_iter()
            // Above the position, which the base may sit below; at or below
            // the head the call began with, which a commit landing under the
            // read may have passed.
            .filter(|&(seq, _)| seq > position.0 && seq <= head.0)
            .map(|(seq, slot)| (Seq(seq), slot))
            .collect();
        // Journal order is `Seq` order for every region whose chain verified,
        // which this one has; the sort makes the order this read promises a
        // property of the answer rather than an inference from the verdicts.
        above.sort_by_key(|&(seq, _)| seq);
        Ok(above)
    }

    /// THE HISTORY READ, stated once for the three one-boundary reads —
    /// [`Kernel::world_at`], [`Kernel::chain_at`] and [`Kernel::attestation_at`]
    /// — which differ only in how high their base may sit and in what they ask
    /// of its answer: so none can refuse differently from another up to that
    /// question, and the one a peer checks a saved chain against cannot answer
    /// over a region another refuses. The fourth read,
    /// [`Kernel::boundaries_above`], takes the same steps in the same order as
    /// far as its own question goes, and takes them as the same code: the
    /// head judgment ([`Kernel::journaled_head`]), the base selection
    /// ([`Kernel::base_at_or_below`]) and the at-rest halt ([`at_rest_halt`])
    /// are each stated once, here, for both.
    ///
    /// `base_ceiling`, at most `at`, is the highest coordinate the base may
    /// embody: `at` itself for a read the base answers at its own coordinate —
    /// the world and the chain there are the base's own — and `at − 1` for
    /// one that must READ the marker closing `at`, which a checkpoint does not
    /// carry (the signature slot). Only a ceiling of `at` can meet a base AT
    /// `at`.
    ///
    /// Its refusals are the first five of `world_at`'s REFUSAL PRECEDENCE, in
    /// that order, and this is where that order is kept:
    /// [`HistoryError::Unjournaled`]; [`HistoryError::BeyondHead`] above the
    /// installed head; [`HistoryError::Reclaimed`] — the base selection
    /// recovery runs, capped at `base_ceiling` so a later checkpoint cannot
    /// stand in for an earlier boundary; then the scan's own
    /// [`HistoryError::Corruption`], an unenumerable or oversized segment and
    /// then every at-rest verdict at any height
    /// ([`journal::ScanOutcome::halt_anywhere`]); then
    /// [`HistoryError::NotABoundary`], judged once, by the capture of the
    /// marker closing `at` ([`journal::ScanOutcome::closing_marker`]). A
    /// boundary that IS the base is answered from the base alone: checkpoint
    /// seqs are committed boundaries (a checkpoint serializes an installed
    /// root) and 0 is genesis, so there is nothing to fold or verify, and
    /// consulting the journal could only refuse a question the base already
    /// answers.
    fn history_read(&self, at: Seq, base_ceiling: u64) -> Result<HistoryRead<W>, HistoryError> {
        debug_assert!(
            base_ceiling <= at.0,
            "a base at {base_ceiling} lies above the boundary {at} it is asked to answer"
        );
        let (journaled, _) = self.journaled_head(at)?;
        let (base, segs) = self.base_at_or_below(journaled, base_ceiling)?;
        if at.0 == base.s_load() {
            return Ok(HistoryRead::AtBase(base));
        }
        let scan = base.scan(&segs, Some(at.0)).map_err(scan_refusal)?;
        at_rest_halt(&scan)?;
        let closing = scan
            .closing_marker(at.0)
            .cloned()
            .map_err(|nearest| HistoryError::NotABoundary {
                nearest: Seq(nearest),
            })?;
        Ok(HistoryRead::Above {
            base,
            scan,
            closing,
        })
    }

    /// The journal and its INSTALLED head — the two refusals every history
    /// read makes before it reads anything, in their order. A kernel with no
    /// journal can answer no coordinate, so that refusal precedes every
    /// question about `at`: a caller told [`HistoryError::BeyondHead`] here
    /// would walk `at` down to genesis before learning that none of it was
    /// ever answerable. Then `at` above the installed head
    /// ([`Kernel::current_seq`]) is refused with that head — the greatest
    /// coordinate this kernel answers, read ONCE here, so what a read judges
    /// `at` against and what bounds its answer are one reading.
    fn journaled_head(&self, at: Seq) -> Result<(&Journaled<W>, Seq), HistoryError> {
        let Some(journaled) = &self.journaled else {
            return Err(HistoryError::Unjournaled);
        };
        let installed_head = self.current_seq();
        if at > installed_head {
            return Err(HistoryError::BeyondHead { head: installed_head });
        }
        Ok((journaled, installed_head))
    }

    /// The base selection every history read runs, capped at `ceiling`, and
    /// the segment listing taken beside it, which the scan above that base
    /// walks: the checkpoints and the segments listed, then
    /// [`replay::select_base`] — recovery's own fallback chain, the newest
    /// retained checkpoint at or below `ceiling` that loads and seeds, else
    /// genesis while the journal reaches it — refused as
    /// [`HistoryError::Reclaimed`] when nothing stands in. One listing serves
    /// the selection and the scan, so the scan walks the segments the base
    /// was chosen against.
    ///
    /// THE ONE SITE A HISTORY READ LOADS A BASE, so it is where the base is
    /// COUNTED: under `test-hooks` the base that stands moves this kernel's
    /// seam's count by one — the `#[doc(hidden)]` door `Kernel::bases_loaded`
    /// reads it — so a suite pins what a caller costs in bases, a consumer
    /// asking once over a window against one asking once per boundary (§3.3
    /// step 2 of the operations design). `journaled` is this kernel's own,
    /// as [`Kernel::journaled_head`] answered it; the receiver is here for
    /// the seam. Recovery's base at the open runs the selection directly and
    /// is not counted, nor is a candidate the chain passed over, nor a
    /// selection that refused.
    fn base_at_or_below(
        &self,
        journaled: &Journaled<W>,
        ceiling: u64,
    ) -> Result<(replay::Base<W>, Vec<SegmentMeta>), HistoryError> {
        let checkpoints = checkpoint::list(&journaled.dir)?;
        let segs = journal::list_segments(&journaled.dir)?;
        let base = replay::select_base(&checkpoints, &segs, Some(ceiling), &journaled.genesis)
            .map_err(reclaimed)?;
        #[cfg(feature = "test-hooks")]
        self.seam.base_loaded();
        Ok((base, segs))
    }
}

/// An exhausted base selection, in the history reads' vocabulary: the floor
/// a base could still be derived at, and why the newest candidate refused.
fn reclaimed(fail: replay::Unreachable) -> HistoryError {
    HistoryError::Reclaimed { floor: fail.floor.map(Seq), cause: fail.cause }
}

/// A scan that produced no outcome, in the history reads' vocabulary: a
/// segment that could not be read, and a segment that could not be taken in
/// within the scan's bounds — [`HistoryError::Corruption`] at the base's own
/// coordinate, with no account, as [`crate::OpenError::Corruption`] carries
/// it.
fn scan_refusal(fail: ScanFail) -> HistoryError {
    match fail {
        ScanFail::Io(e) => HistoryError::Io(e),
        ScanFail::Unscannable { at } => HistoryError::Corruption { at: Seq(at), cause: None },
    }
}

/// The at-rest halt every history read makes of its scan, before it asks
/// the scan anything: any at-rest verdict above the base is a halt, even
/// beyond the coordinate asked — a corrupt run's own seqs are unreadable, so
/// answering around it could answer from a hole, and a chain link that
/// failed above the coordinate says the region is not the history it claims.
/// (A racing live append never produces a Landed run: it can tear only the
/// file's suffix, after the last committed marker, which reaches EOF.)
fn at_rest_halt(scan: &ScanOutcome) -> Result<(), HistoryError> {
    match scan.halt_anywhere() {
        Some((at, cause)) => Err(HistoryError::Corruption { at: Seq(at), cause }),
        None => Ok(()),
    }
}
