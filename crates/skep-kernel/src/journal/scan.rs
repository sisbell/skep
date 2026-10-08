//! The scan, which is recovery's read side.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

use bincode::Options;

use super::attest::{self, Attestation};
use super::chain::{slot_digest, ChainLink};
use super::segment::{fsync_dir, scanned_above, SegmentMeta};
use super::{
    codec, find_magic, frame_len, parse_frame, CommittedRecord, FramePayload, LogRecord, Marker,
    Parsed, Txn, FRAME_HEADER_LEN, MAGIC, MARKER_FRAME_LEN, MAX_SEGMENT_LEN, MAX_TXN_BYTES,
    RESYNC_BUDGET_PASSES, STAMP_PREFIX,
};
use crate::error::{stamp_text, Cause};

/// How a corrupt run (a span the scan skipped via magic-resync) ended (§7).
#[derive(Debug, PartialEq, Eq)]
enum RunEnd {
    /// The resync landed on an intact frame. `at` = that next-intact
    /// coordinate; `inferred_max` = the greatest `Seq` the run itself can
    /// hold. The run's own seqs are unreadable, so these two are all that is
    /// known of it (§7). What each landing contributes is
    /// [`RunEnd::landed_on_record`] and [`RunEnd::landed_on_marker`], which
    /// are the only way one of these is built.
    Landed { inferred_max: u64, at: u64 },
    /// The run reached end-of-journal with no next intact frame: classes as
    /// the un-acked / torn tail (`> W`), sound because the last committed
    /// marker is itself intact and so precedes any EOF-reaching run (§7) —
    /// sound against torn writes and CRC-failing damage under §1's storage
    /// assumptions, save §7's documented post-commit-rot exception; NOT
    /// against a rewrite that leaves one of the last transaction's frames
    /// intact and undecodable, which reads as a run reaching here and is cut
    /// (the open item in [`crate::Kernel::open`]'s damage model).
    Eof,
}

impl RunEnd {
    /// The resync landed on an intact RECORD: the run ends one below that
    /// record's own coordinate, and is reported at it (§7).
    fn landed_on_record(seq: u64) -> RunEnd {
        RunEnd::Landed {
            inferred_max: seq.saturating_sub(1),
            at: seq,
        }
    }

    /// …on an intact MARKER, which carries no `Seq` of its own, so the
    /// coordinate it contributes is one past its `last_seq`. At the ceiling
    /// there is no such coordinate and the run is reported at the ceiling
    /// itself — never wrapped to `0`, which would report a run above the base
    /// as one below it (§7).
    fn landed_on_marker(last_seq: u64) -> RunEnd {
        RunEnd::Landed {
            inferred_max: last_seq,
            at: last_seq.saturating_add(1),
        }
    }
}

/// Why a scan could not produce an outcome (§7). Both answers are the
/// caller's to phrase in its own error vocabulary; neither leaves a partial
/// [`ScanOutcome`] for anyone to draw a verdict from.
#[derive(Debug)]
pub(crate) enum ScanFail {
    /// A segment could not be read.
    Io(io::Error),
    /// A segment the scan could not take in within its bounds: its
    /// resynchronization exceeded [`RESYNC_BUDGET_PASSES`], so its frame
    /// stream could not be enumerated in bounded work, or the file is longer
    /// than [`MAX_SEGMENT_LEN`], so it could not be read in bounded memory.
    /// Either way nothing derived from it would be more than a PREFIX of what
    /// the segment holds — a committed head that may be short, records that
    /// may be missing, a boundary set that may not be the journal's. Fatal at
    /// any height, which is why the scan refuses rather than answering with a
    /// qualification.
    Unscannable {
        /// The base's own coordinate, where the scan began: the damage lies
        /// somewhere in the segments it reads — above the base, or below it in
        /// a segment straddling it — and the scan could not get past the
        /// damage to say where.
        at: u64,
    },
}

impl From<io::Error> for ScanFail {
    fn from(e: io::Error) -> Self {
        ScanFail::Io(e)
    }
}

/// Where the un-acked / torn tail begins: the segment file to cut, the offset
/// to cut it at, and the wholly-later segment files to remove (§7). Resolved
/// to paths by the scan itself, while the segment list is in hand, so a
/// truncation cannot be aimed at a list other than the one that was scanned.
struct TailCut {
    segment: PathBuf,
    offset: u64,
    discard: Vec<PathBuf>,
}

/// What a scan COLLECTS of the committed transactions above its base, beyond
/// what every scan derives — the head, the chain's running value, the
/// verdicts, the cut: the one thing the two entry functions differ in,
/// applied by [`ScanOutcome::collect_commit`], the only writer of either
/// collection, and read back by the outcome's doors to hold each caller to
/// what was collected — records above a fold bound were read and dropped,
/// and a boundary scan read every record and kept none.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Collect {
    /// The committed records a fold to `bound` reads — those at or below it,
    /// every one when `None` — and, at `Some`, the marker closing `bound` and
    /// the nearest boundary below it: [`scan`]'s, for recovery and the three
    /// one-boundary history reads.
    Records { bound: Option<u64> },
    /// Every committed marker above the base, as its `last_seq` and its
    /// signature slot, and no record: [`scan_boundaries`]'s, for the boundary
    /// read ([`crate::Kernel::boundaries_above`]).
    Boundaries,
}

/// Pass-1 result (§7): the committed head (§7's `W`), the committed records a
/// fold may read, the corrupt runs, the commit chain's running value and the
/// verdicts of its links, where the tail to truncate begins, and — for a scan
/// collected to a boundary — what the marker closing it carries, or — for a
/// boundary scan — every committed boundary above the base with its slot. A
/// scan that could not enumerate the frame stream produces none of this — it
/// answers [`ScanFail`] — so nothing here is a PREFIX of what the region
/// holds. What it COLLECTED is bounded by the caller's own fold bound, or is
/// the boundaries and no record at all ([`Collect`]), which is why the
/// records are reached through [`ScanOutcome::records_to`] and the
/// boundaries through [`ScanOutcome::into_boundaries`] rather than read as a
/// set; and whether a caller must halt on what it found is ONE question,
/// answered in the order the verdicts speak ([`ScanOutcome::halt_to_head`],
/// [`ScanOutcome::halt_anywhere`]), the same under either mode.
pub(crate) struct ScanOutcome {
    /// The base this scan ran against — §7's `S_load`. Every judgment it
    /// answers is relative to that base, so it is carried here rather than
    /// re-supplied per question, where a caller could hand back a different
    /// one than the scan was run with.
    s_load: u64,
    /// The base's own chain value — the `SKC4` header's `chain_head`, or
    /// [`super::chain::CHAIN_GENESIS`] at genesis — which the marker closing
    /// the base's seq is compared with: the base-mismatch check. Carried for
    /// the reason `s_load` is.
    chain_at_base: [u8; 32],
    /// What this scan COLLECTED, as [`scan`] or [`scan_boundaries`] was
    /// called — a record scan's fold bound, `None` for the whole scanned
    /// region, or the boundary mode. Applied by
    /// [`ScanOutcome::collect_commit`], the only writer of the records
    /// collected below, of the nearest boundary below the bound, of the
    /// marker captured at it and of the boundaries, and read back by
    /// [`ScanOutcome::covers`], [`ScanOutcome::closing_marker`] and
    /// [`ScanOutcome::into_boundaries`] to hold a caller to it: records above
    /// a bound were read and dropped, so a fold past it is one this outcome
    /// cannot answer, and a boundary scan kept no record at all. Bounding the
    /// collection is what keeps a history read of one boundary from
    /// materializing the whole retained window; the boundary mode is what
    /// keeps the boundary read from materializing any record.
    collect: Collect,
    /// The last COMMITTED marker's `last_seq`, floored at `S_load` — §7's `W`
    /// (if no committed marker sits above the loaded checkpoint it is
    /// `S_load` itself and Pass 2 folds nothing). Never bounded: it is
    /// recovery's own fold bound, so it names the last committed marker of the
    /// whole scanned region.
    pub committed_head: u64,
    /// The COMMITTED TRANSACTIONS above the base — every marker
    /// [`ScanOutcome::collect_commit`] took whose `last_seq` exceeds `s_load`,
    /// counted: the commits in `(S_load, W]`, which is what a recovery
    /// replays and reports as such ([`crate::Recovery`]'s `replayed`) — a
    /// count of transactions, never of the records they carry. Never bounded,
    /// for the reason the head is not: it counts the whole scanned region's.
    pub commits_above_base: u64,
    /// The records a fold may apply, unordered and unfiltered as collected.
    /// Written only by [`ScanOutcome::collect_commit`], which is where the
    /// collection bound is applied — and never under the boundary mode,
    /// which keeps no record; read through [`ScanOutcome::records_to`],
    /// which is where the order, the range and the one-coordinate-once rule
    /// are settled.
    committed_records: Vec<CommittedRecord>,
    /// The greatest committed boundary strictly below `bound`, floored at the
    /// base — what a history read refuses a non-boundary with. Seeded with
    /// `s_load` and only ever raised, by [`ScanOutcome::collect_commit`], so a
    /// boundary below the base never names it: a segment straddling the base
    /// contributes boundaries with no base left to fold from. Never raised
    /// when `bound` is `None`, which asks no boundary question.
    nearest_below_bound: u64,
    /// Corrupt runs in scan order — what [`ScanOutcome::halt_to_head`] and
    /// [`ScanOutcome::halt_anywhere`] classify, through
    /// [`ScanOutcome::fatal_run`]. The verdict on a run belongs to those, not
    /// to a caller re-deriving the classifier.
    runs: Vec<RunEnd>,
    /// The tail-truncation cut, `None` when nothing was scanned — what
    /// [`truncate_tail`] cuts. Resolved here and read there, so no caller can
    /// aim a truncation at a region other than the one this scan judged.
    tail: Option<TailCut>,
    /// The commit chain's running value: the chain of the last committed
    /// marker above the base, in journal order, else the base's own. Once the
    /// scan returns, that is the chain at the committed head — what the
    /// appender continues from and the recovered root carries. Advanced only
    /// by [`ScanOutcome::collect_commit`]; never bounded, for the reason the
    /// head is not.
    pub chain_head: [u8; 32],
    /// The first CHAIN BREAK above the base, as the `last_seq` of the
    /// committed transaction whose marker's `chain` was not the recomputation
    /// ([`ChainLink`]) over the previous committed transaction's value and
    /// its own records — `None` when every link above the base verified.
    /// Recorded by [`ScanOutcome::collect_commit`] rather than refused on the
    /// spot, so the corrupt-run classification, which names the root cause
    /// when a run swallowed the predecessor, speaks first; ordered by
    /// [`ScanOutcome::chain_verdict`].
    chain_break: Option<u64>,
    /// THE BASE MISMATCH (QUEUE item 10's case 9, the at-head fork): the
    /// base's seq when the committed marker closing `s_load` itself was
    /// scanned and its `chain` is not `chain_at_base` — the `SKC4` header's
    /// `chain_head`, which nothing in the header covers. Two STORED values
    /// disagreeing, nothing recomputed: the header was rewritten, or the
    /// marker was. `None` when they agree, and `None` — vacuously — when
    /// that marker was not scanned: a closed segment ending exactly at
    /// `s_load` is skipped, and one below the reclaim floor is gone. At the
    /// HEAD the marker is scanned whenever the active segment holds it — not
    /// while that segment is EMPTY after a rotation whose transaction failed
    /// or never landed, when the head's marker ends the closed segment before
    /// it and is skipped as the rest are. Recorded by
    /// [`ScanOutcome::collect_commit`], not refused, for the reason
    /// `chain_break` is; ordered by [`ScanOutcome::chain_verdict`].
    base_mismatch: Option<u64>,
    /// THE EDITED TRANSACTION (case 2's coordinate): the last seq of the
    /// first transaction whose frames were ALL intact and which an intact
    /// marker failed to close — its own marker refusing it
    /// ([`PendingTxn::commits`]), or its next intact frame being ANOTHER
    /// transaction's marker, the marker's `txn` rewritten — the GROUP's own
    /// last seq, since in the `last_seq`-edited shape the marker's is the
    /// forged field. NO WRITER OF THIS JOURNAL PRODUCES THAT SHAPE:
    /// [`super::encode_txn`] streams `records_checksum` over the frames it writes
    /// and sets `last_seq` to the last record's, emits one transaction's
    /// frames contiguously and `Seq`-ascending — so a clean group's next
    /// intact frame is its own marker — and refuses a group past the budget
    /// before a byte lands; a crash truncates (a frame fails its CRC) or
    /// loses frames (they are absent), and never leaves a complete marker
    /// disagreeing with complete records. So the marker was rewritten — and
    /// the transaction it should have closed is un-committed, which on the
    /// LAST transaction is the tail cut in disguise this names before
    /// recovery cuts it. Recorded at any height, below the base as well: the
    /// verdict compares a marker with its own records and needs no link from
    /// the base. A group that met a corrupt or undecodable frame while open,
    /// or whose first record closed a corrupt run (the run may have eaten its
    /// own earlier frames), is not clean and never records here: that is the
    /// corrupt-run verdict's — which mid-history halts, and in the last
    /// transaction does not (the open item in [`crate::Kernel::open`]'s
    /// damage model). Recorded by the walk itself, not refused; ordered by
    /// [`ScanOutcome::chain_verdict`].
    uncommitted_intact: Option<u64>,
    /// The committed marker closing `bound`, above the base — `None` when
    /// `bound` is `None`, is not a committed boundary above the base, or is
    /// the base's own seq (the base answers that itself). Captured by
    /// [`ScanOutcome::collect_commit`]; read through
    /// [`ScanOutcome::closing_marker`], which reads its presence as the
    /// membership test and holds its caller to the bound it is keyed on.
    closing_at_bound: Option<ClosingMarker>,
    /// THE COMMITTED BOUNDARIES above the base, in journal order, each as its
    /// marker's `last_seq` and the signature slot that marker carries — one
    /// entry per committed marker [`ScanOutcome::collect_commit`] took above
    /// `s_load`, under [`Collect::Boundaries`] alone; empty under a record
    /// scan, which captures the one marker closing its bound instead. Read
    /// through [`ScanOutcome::into_boundaries`], which holds its caller to
    /// the mode. The term that grows with the journal under the boundary
    /// mode: one entry per commit, an [`Attestation`] per attested one, and
    /// never a record.
    boundaries: Vec<(u64, Option<Attestation>)>,
}

/// What the committed marker closing a bounded scan's `bound` carries —
/// captured once, by [`ScanOutcome::collect_commit`], as that marker is taken
/// in the pass that verifies every link to the journal's end. Its presence is
/// the membership test every history read makes of its boundary, and its
/// fields are what the reads ask of one: the commit chain there
/// ([`crate::Kernel::chain_at`]) and the signature slot
/// ([`crate::Kernel::attestation_at`]).
#[derive(Clone)]
pub(crate) struct ClosingMarker {
    /// The marker's `chain`: the commit chain at the boundary.
    pub(crate) chain: [u8; 32],
    /// The marker's signature slot, `None` for the empty one.
    pub(crate) attestation: Option<Attestation>,
}

/// What a caller halts on: the coordinate naming the damage, and its account
/// where it has one — the two a caller wraps as its own `Corruption`.
type Halt = (u64, Option<Cause>);

impl ScanOutcome {
    /// The first chain break above the base (the field), for
    /// [`ScanOutcome::chain_verdict`] to order. A caller asks
    /// [`ScanOutcome::halt_to_head`] or [`ScanOutcome::halt_anywhere`], never
    /// this alone: two verdicts outrank it.
    fn chain_break(&self) -> Option<u64> {
        self.chain_break
    }

    /// The base mismatch (the field), for
    /// [`ScanOutcome::chain_verdict`] to order: `Some(s_load)` when the
    /// scanned marker closing the base's seq does not carry the header's
    /// `chain_head`.
    fn base_mismatch(&self) -> Option<u64> {
        self.base_mismatch
    }

    /// The first intact transaction which an intact marker failed to close
    /// (the field), by its own last seq, for [`ScanOutcome::chain_verdict`]
    /// to order.
    fn uncommitted_intact(&self) -> Option<u64> {
        self.uncommitted_intact
    }

    /// THE CHAIN'S VERDICTS, in the order they speak — the coordinate and
    /// the account of each: the base mismatch
    /// ([`ScanOutcome::base_mismatch`]), then the intact transaction no
    /// intact marker closes ([`ScanOutcome::uncommitted_intact`]), then the
    /// chain break ([`ScanOutcome::chain_break`]). A verdict of an earlier
    /// kind speaks first whatever its coordinate: the base mismatch sits at
    /// the base, below every chain link a scan judges, and the un-committed
    /// transaction is the ROOT of the break the next committed one shows. The
    /// corrupt run's verdict speaks before all three, in
    /// [`ScanOutcome::halt_on`] — this method's only caller, which both halts
    /// go through. `None` when every link verified.
    fn chain_verdict(&self) -> Option<(u64, Cause)> {
        if let Some(at) = self.base_mismatch() {
            return Some((at, base_mismatch_cause(at)));
        }
        if let Some(at) = self.uncommitted_intact() {
            return Some((at, uncommitted_intact_cause(at)));
        }
        self.chain_break().map(|at| (at, chain_break_cause(at)))
    }

    /// Collect everything a COMMITTED transaction contributes, judging its
    /// link first, since a link is judged against the chain the transaction
    /// found. ABOVE the base, the marker's `chain` must be the recomputation
    /// over the running value the group opened on and the group's own records
    /// ([`PendingTxn::recomputed_chain`]), else the first CHAIN BREAK is
    /// recorded at its `last_seq`; the running chain then continues from the
    /// marker's own claim, so one edit is one verdict at its own coordinate,
    /// and the marker closing the collection bound is captured for
    /// [`ScanOutcome::closing_marker`]. AT the base, the marker's stored
    /// chain must be `chain_at_base` — two stored values compared, nothing
    /// recomputed — else THE BASE MISMATCH is recorded. BELOW the base, the base
    /// embodies the transaction and nothing is judged, exactly as a corrupt
    /// run there is harmless. Recorded, never refused: the callers halt.
    ///
    /// Then the collection: the marker's `last_seq` raises the committed head
    /// and — below a record scan's collection bound — the nearest boundary
    /// below it, and the group's records join the committed set, those at or
    /// below the bound. The head is deliberately UNBOUNDED: it is recovery's
    /// own fold bound, so it must name the last committed marker wherever it
    /// sits. What is COLLECTED obeys `bound`, and per RECORD rather than per
    /// group, so a transaction straddling the bound keeps the half below it.
    /// That asymmetry is the whole of what `bound` means, and stating it here
    /// is what keeps it off the walk — this is the only writer of either, so
    /// the rule has one site. Under the BOUNDARY MODE ([`Collect::Boundaries`])
    /// the same site keeps, of every committed marker above the base, its
    /// `last_seq` and its slot, and releases the group's records with the
    /// group: the mode answers boundaries, not a fold, so no record is kept
    /// — which is the whole of what the mode means, stated at the one site
    /// that could keep one.
    ///
    /// Both are TAKEN: the walk is done with a marker and its group once they
    /// commit, so the slot's blob moves whole into the captured
    /// [`ClosingMarker`], or into the boundary list, converted by the slot
    /// rule ([`admitted_slot`]) — the rule the marker decoder asked of these
    /// very bytes, so the conversion answers as the decode did.
    fn collect_commit(&mut self, marker: Marker, group: PendingTxn) {
        if marker.last_seq > self.s_load {
            if group.recomputed_chain(&marker) != marker.chain {
                self.chain_break.get_or_insert(marker.last_seq);
            }
            self.chain_head = marker.chain;
            self.commits_above_base += 1;
            match self.collect {
                Collect::Records { bound } if bound == Some(marker.last_seq) => {
                    self.closing_at_bound = Some(ClosingMarker {
                        chain: marker.chain,
                        attestation: admitted_slot(marker.sig_alg, marker.sig),
                    });
                }
                Collect::Records { .. } => {}
                Collect::Boundaries => {
                    self.boundaries
                        .push((marker.last_seq, admitted_slot(marker.sig_alg, marker.sig)));
                }
            }
        } else if marker.last_seq == self.s_load && marker.chain != self.chain_at_base {
            self.base_mismatch.get_or_insert(self.s_load);
        }
        self.committed_head = self.committed_head.max(marker.last_seq);
        let Collect::Records { bound } = self.collect else {
            // The boundary mode keeps no record: the group, and every record
            // it holds, is released here.
            return;
        };
        if bound.is_some_and(|b| marker.last_seq < b) {
            self.nearest_below_bound = self.nearest_below_bound.max(marker.last_seq);
        }
        self.committed_records.extend(
            group
                .records
                .into_iter()
                .filter(|entry| bound.is_none_or(|b| entry.seq <= b)),
        );
    }

    /// Why a RECOVERY cannot answer from this scan, if it cannot: the first
    /// at-rest verdict, in the order the verdicts speak — the corrupt run a
    /// recovery cannot answer around, then the chain's own, in
    /// [`ScanOutcome::chain_verdict`]'s order — as the coordinate naming the
    /// damage and its account where it has one (a corrupt run's own bytes are
    /// unreadable, so it carries none). The run speaks first because it is
    /// the root cause: a run that swallowed a transaction breaks the chain at
    /// the next one. The order has one site, [`ScanOutcome::halt_on`], which
    /// this and [`ScanOutcome::halt_anywhere`] share, so no caller can ask the
    /// chain before the run, or one of the chain's verdicts without the
    /// others.
    ///
    /// The run is classified within the committed region this scan derived:
    /// a run above the committed head is the un-acked / torn tail, which
    /// recovery is about to discard (§7) — the tail against torn writes and
    /// CRC-failing damage; NOT against a rewrite that leaves one of the last
    /// transaction's frames intact and undecodable, whose run lands here above
    /// the head, or reaches end-of-journal, and is cut with the transaction
    /// (the open item in [`crate::Kernel::open`]'s damage model).
    pub(crate) fn halt_to_head(&self) -> Option<Halt> {
        self.halt_on(self.fatal_run(Some(self.committed_head)))
    }

    /// Why a HISTORY READ cannot answer from this scan, if it cannot — the
    /// same order as [`ScanOutcome::halt_to_head`], with the run classified
    /// at any height. A history read truncates nothing, so a run above the
    /// committed head is at-rest damage rather than a tail — and since a
    /// run's own seqs are unreadable, its reach below `inferred_max` is
    /// unknowable, so answering around it could answer from a hole (§7).
    pub(crate) fn halt_anywhere(&self) -> Option<Halt> {
        self.halt_on(self.fatal_run(None))
    }

    /// The order both halts share, once each has classified its run: the run
    /// first, carrying no account, then the chain's own verdicts.
    fn halt_on(&self, fatal_run: Option<u64>) -> Option<Halt> {
        fatal_run
            .map(|at| (at, None))
            .or_else(|| self.chain_verdict().map(|(at, cause)| (at, Some(cause))))
    }

    /// The corrupt run a fold over `(s_load, bound]` cannot answer around: the
    /// `at` payload of the first run whose inferred `Seq` max lands in that
    /// range — durable committed data the folded state needs, and unreadable.
    /// Halt, never drop (§7). `bound = None` is unbounded above: every run
    /// above the base is fatal, however far above it lands.
    ///
    /// The run is classified by its `inferred_max` and REPORTED by its `at`,
    /// and keeping the two apart is what the boundary case turns on: a run
    /// wholly embodied in the base can still land on the very next coordinate
    /// (`at = s_load + 1`), which is harmless — its content is already in the
    /// base — where classifying by `at` would spuriously halt. An
    /// [`RunEnd::Eof`] run is never fatal: it is the un-acked / torn tail,
    /// which the last committed marker precedes.
    fn fatal_run(&self, bound: Option<u64>) -> Option<u64> {
        self.runs.iter().find_map(|run| match *run {
            RunEnd::Landed { inferred_max, at }
                if inferred_max > self.s_load && bound.is_none_or(|b| inferred_max <= b) =>
            {
                Some(at)
            }
            _ => None,
        })
    }

    /// Whether a fold over `(s_load, bound]` can be answered from this scan:
    /// whether `bound` is at or below the boundary this scan COLLECTED to.
    /// Records above that boundary were read and dropped, so a fold past it
    /// cannot restore them and would answer `Ok` with a world missing exactly
    /// the range between (§7). A boundary scan read every record and kept
    /// none, so it covers no fold at all.
    fn covers(&self, bound: u64) -> bool {
        match self.collect {
            Collect::Records { bound: collected } => collected.is_none_or(|c| bound <= c),
            Collect::Boundaries => false,
        }
    }

    /// The committed marker closing boundary `at` — the one question a history
    /// read asks of a scan above its base: whether a committed marker closes
    /// `at`, and what it carries. The capture is keyed on the collection bound,
    /// so its presence is the membership test, and one answer serves every
    /// read. `Err` is the nearest boundary below `at`, never below the base —
    /// the value a refusal of a non-boundary names.
    ///
    /// PRECONDITION — this scan COLLECTED to exactly `at`, above its base
    /// ([`scan`]'s `bound` was `Some(at)`, and `at > s_load`). The capture is
    /// keyed on that bound and on nothing else, so a scan collected to any
    /// other — a boundary scan among them, which captures no closing marker
    /// — would answer every boundary as absent: a caller's bug, answered as
    /// one, as [`ScanOutcome::records_to`] answers a fold past its
    /// collection.
    pub(crate) fn closing_marker(&self, at: u64) -> Result<&ClosingMarker, u64> {
        assert!(
            self.collect == Collect::Records { bound: Some(at) } && at > self.s_load,
            "boundary {at} asked of a scan that collected {:?} above {}: the capture is keyed \
             on the collection bound (Base::scan)",
            self.collect,
            self.s_load
        );
        self.closing_at_bound.as_ref().ok_or(self.nearest_below_bound)
    }

    /// THE COMMITTED BOUNDARIES above the base — every one, each with the
    /// signature slot its marker carries, in journal order, which is `Seq`
    /// order for any region whose chain verified: the one question the
    /// boundary read asks of a scan ([`crate::Kernel::boundaries_above`]),
    /// asked after the at-rest verdicts ([`ScanOutcome::halt_anywhere`]) have
    /// spoken, as every history read asks its question. Taken rather than
    /// borrowed: the outcome holds nothing else that read wants, and the
    /// slots move rather than copy.
    ///
    /// PRECONDITION — this scan COLLECTED boundaries ([`scan_boundaries`]).
    /// A record scan captures the one marker closing its bound and lists
    /// none, so asking it would answer every boundary as absent: a caller's
    /// bug, answered as one, as [`ScanOutcome::closing_marker`] answers a
    /// scan collected to another bound.
    pub(crate) fn into_boundaries(self) -> Vec<(u64, Option<Attestation>)> {
        assert!(
            self.collect == Collect::Boundaries,
            "the boundaries asked of a scan that collected {:?}: only a boundary scan lists \
             them (Base::scan_boundaries)",
            self.collect
        );
        self.boundaries
    }

    /// The committed records a fold over `(s_load, bound]` must apply, in
    /// `Seq` order and each coordinate once. Order, range and uniqueness are
    /// all facts about the set THIS scan derived, so they are settled here
    /// rather than by whoever folds: [`crate::WorldState::apply`] is not
    /// required to be idempotent, so a coordinate applied twice is silent
    /// double application answered `Ok` — while a `Seq` merely MISSING is not
    /// corruption at all, since a burned-`Seq` gap folds harmlessly (§6/§7).
    ///
    /// `Err` is a `Seq` this scan saw twice in that range — a journal no
    /// sequencer here wrote, since each coordinate is minted once. This is the
    /// ACROSS-transactions half of "no coordinate twice"; [`PendingTxn`]'s
    /// `ordered` is the within-transaction half, and both sit with the journal
    /// they are properties of.
    ///
    /// PRECONDITION — `bound` must be at or below the boundary this scan
    /// COLLECTED to ([`ScanOutcome::covers`]), which a boundary scan never
    /// is: records above the bound were read and dropped, and a boundary
    /// scan kept none, so a fold past either reads records that were never
    /// collected, which no filter can restore — a caller's bug, answered as
    /// one rather than with a world short by exactly that range.
    pub(crate) fn records_to(&self, bound: u64) -> Result<Vec<&CommittedRecord>, u64> {
        assert!(
            self.covers(bound),
            "fold to {bound} against a scan that did not collect that far, or collected no \
             record at all: what was never collected cannot be restored (Base::scan, \
             Base::scan_boundaries)"
        );
        let mut records: Vec<&CommittedRecord> = self
            .committed_records
            .iter()
            .filter(|entry| entry.seq > self.s_load && entry.seq <= bound)
            .collect();
        records.sort_by_key(|entry| entry.seq);
        match records.windows(2).find(|pair| pair[0].seq == pair[1].seq) {
            Some(pair) => Err(pair[0].seq),
            None => Ok(records),
        }
    }
}

/// The record frames of the ONE transaction a scan currently has open,
/// accumulated as they arrive (§1/§7).
///
/// A scan holds one of these at a time. That is the writer's own shape:
/// [`super::encode_txn`] emits a transaction's records contiguously and closes them
/// with its marker, so a group left open by an intervening transaction's
/// record can never be closed by a later marker.
///
/// One group at a time is not by itself a memory bound, because a journal is
/// not obliged to have been written by this writer: frames spread across all
/// its segments, all carrying one `txn`, are one group. So the size of the
/// group is bounded HERE, by the same [`MAX_TXN_BYTES`] the write path refuses
/// at ([`Self::oversize`]) — one segment's bytes plus one transaction's worth,
/// which is the memory floor [`crate::Kernel::open`] promises on every replica.
struct PendingTxn {
    txn: Txn,
    /// CRC32C over the record-frame payloads in ARRIVAL order — which is `Seq`
    /// order for anything this writer produced. Streaming it is what lets the
    /// group carry one copy of each record instead of a second copy kept only
    /// to checksum later.
    checksum: u32,
    last_seq: Option<u64>,
    /// Cleared by a record that does not exceed its predecessor. That is a
    /// transaction this writer cannot emit, and it is the shape that would
    /// have a non-idempotent [`crate::WorldState::apply`] fold one coordinate
    /// twice, so such a transaction never commits however its checksum lands.
    ordered: bool,
    /// What this group counts against [`MAX_TXN_BYTES`], accounted to the
    /// figure the write side's budget charges ([`super::Journal::commit_txn`]):
    /// seeded with the EMPTY marker's frame, [`MARKER_FRAME_LEN`], whatever the
    /// slot of the marker that closes the group holds — the slot sits outside
    /// the budget on both sides, as [`MARKER_FRAME_LEN`]'s card says — then
    /// charged [`frame_len`] per record, which is [`super::record_frame_len`]
    /// reached from the framed payload a reader actually holds rather than from
    /// the record's own bytes. For an unattested group that is the very length
    /// [`super::txn_encoded_len`] gives the write side; an attested one occupies
    /// its blob's width more, which neither side's budget counts.
    accounted: u64,
    /// Set once [`Self::accounted`] passes [`MAX_TXN_BYTES`]. A group past the
    /// budget is one no writer here can emit — [`super::Journal::commit_txn`] refuses
    /// it before a byte is appended — so the READER enforces the same bound
    /// rather than trusting it, which is what holds a scan's group memory to
    /// one transaction's worth against a journal this writer did not write.
    oversize: bool,
    /// The group's records, in arrival order. Released the moment the group is
    /// known dead, since nothing downstream can want it.
    records: Vec<CommittedRecord>,
    /// The chain link this group would close, streamed beside the checksum
    /// from the same payloads: opened on the running chain value
    /// ([`ScanOutcome::chain_head`]) — which cannot move while a group is
    /// open, since only a committed marker moves it and a committed marker
    /// closes the group — and closed with the marker's fields by
    /// [`PendingTxn::recomputed_chain`].
    link: ChainLink,
    /// Whether every frame this group could have had was seen intact: set at
    /// [`PendingTxn::open`], and cleared by the walk when a corrupt run lands
    /// on one of the group's records — opened there, the run may have been
    /// this transaction's own earlier frames — or when a corrupt or
    /// undecodable frame is met while the group is open. A clean group no
    /// intact marker closes — its own refusing it, or another transaction's
    /// following it — is the shape no writer produces
    /// ([`ScanOutcome::uncommitted_intact`]); an unclean one is the
    /// corrupt-run verdict's, whatever its marker says.
    clean: bool,
}

impl PendingTxn {
    /// A group with nothing in it yet, whose link opens on `prev_chain`, the
    /// running chain value. It starts CLEAN; the walk, which alone sees what
    /// could have cost it frames, clears that on the group itself.
    fn open(txn: Txn, prev_chain: &[u8; 32]) -> PendingTxn {
        PendingTxn {
            txn,
            checksum: 0,
            last_seq: None,
            ordered: true,
            // The write side's own starting figure, so an honest transaction
            // AT the budget accounts to exactly the budget and is admitted.
            accounted: MARKER_FRAME_LEN,
            oversize: false,
            records: Vec::new(),
            link: ChainLink::open(prev_chain),
            clean: true,
        }
    }

    /// The chain value `marker` MUST carry to be this group's honest close:
    /// the link opened on the running value, streamed with this group's
    /// payloads, closed with the marker's own pre-chain fields, the SALT the
    /// marker carries and the digest of the SLOT it carries — the writer's
    /// computation ([`super::encode_txn`]) re-run from the bytes the CRC
    /// verified. The salt and the slot are READ here, never drawn: a replay
    /// under any [`crate::SaltSource`] recomputes the link the writer closed,
    /// and an edited salt, or a slot stripped or altered since the commit,
    /// is a link that fails.
    fn recomputed_chain(&self, marker: &Marker) -> [u8; 32] {
        self.link.clone().close(
            marker.txn,
            marker.last_seq,
            marker.records_checksum,
            &marker.salt,
            &slot_digest(marker.sig_alg, &marker.sig),
        )
    }

    /// Take one record frame of this transaction: `payload` is the frame
    /// payload exactly as framed, which is what `records_checksum` covers —
    /// and the chain, and what [`frame_len`] charges, a framed payload being
    /// the inner level [`super::record_payload_len`] gives the write side.
    fn push(&mut self, record: LogRecord, payload: &[u8]) {
        if self.last_seq.is_some_and(|prev| record.seq <= prev) {
            self.ordered = false;
        }
        self.last_seq = Some(record.seq);
        self.checksum = crc32c::crc32c_append(self.checksum, payload);
        self.link.add_payload(payload);
        self.accounted = self.accounted.saturating_add(frame_len(payload.len() as u64));
        self.oversize |= self.accounted > MAX_TXN_BYTES;
        if self.ordered && !self.oversize {
            self.records.push(CommittedRecord {
                seq: record.seq,
                bytes: record.bytes,
            });
        } else {
            // Dead: this group can never commit, so its records are released
            // as soon as that is known. The checksum and `last_seq` keep
            // advancing, so the refusal stays the one `commits` states.
            self.records = Vec::new();
        }
    }

    /// Whether `marker` commits this group: intact + durable (it is on the
    /// disk we read) + `records_checksum`-valid over a `Seq`-ascending group
    /// that the marker's own `last_seq` closes and that fits the journal's
    /// per-transaction budget (§1).
    ///
    /// The `last_seq` conjunct is the one the checksum cannot supply: the
    /// checksum ties the RECORDS to the marker, while `last_seq` is a separate
    /// field under no protection but the frame CRC. [`super::encode_txn`] sets it to
    /// the last record's own `Seq`, so a marker claiming less is one this
    /// writer cannot emit — and it is the shape that has the fold drop
    /// committed records above the claim while the sequencer restarts over
    /// their coordinates, which the next recovery then meets as one `Seq`
    /// presented twice.
    ///
    /// The budget conjunct is the reader's half of a bound the write path
    /// already keeps: accepting a group past [`MAX_TXN_BYTES`] would fold a
    /// transaction this kernel could not have committed, and would let a
    /// journal spread one `txn` over all its segments while the scan held
    /// every record of it.
    fn commits(&self, marker: &Marker) -> bool {
        self.ordered
            && !self.oversize
            && self.last_seq == Some(marker.last_seq)
            && self.checksum == marker.records_checksum
    }
}

/// Read one segment whole for [`scan`], refusing a file longer than
/// [`MAX_SEGMENT_LEN`] on its length alone, before a byte of it is read: that
/// length is the file's own claim, and an allocation sized by it is what the
/// ceiling exists to refuse. `take` bounds the read even when the file grows
/// after its length is read — a live appender beneath
/// [`crate::Kernel::world_at`] — and a read that reaches past the ceiling
/// refuses as well, since what it holds is then a prefix of the file.
fn read_segment(path: &Path, s_load: u64) -> Result<Vec<u8>, ScanFail> {
    let file = File::open(path)?;
    let claimed = file.metadata()?.len();
    if claimed > MAX_SEGMENT_LEN {
        return Err(ScanFail::Unscannable { at: s_load });
    }
    // `claimed` is at most the ceiling, 2^27, so the cast is exact on any 32-
    // or 64-bit target and the reservation is the file's own size, as
    // `fs::read` would make it.
    let mut buf = Vec::with_capacity(claimed as usize);
    file.take(MAX_SEGMENT_LEN + 1).read_to_end(&mut buf)?;
    if buf.len() as u64 > MAX_SEGMENT_LEN {
        return Err(ScanFail::Unscannable { at: s_load });
    }
    Ok(buf)
}

/// Pass 1 (§7): scan in file order (== `Seq` order — in-order append plus the
/// prior recovery's tail truncation), resynchronizing past bad frames via the
/// magic word (accepting only intact frames — a coincidental magic inside a
/// payload fails the CRC check and the scan continues), grouping record
/// frames by `txn` — NOT file position — to validate each marker's
/// `records_checksum`, and deriving `W`.
///
/// A transaction commits only if its records arrive `Seq`-ascending as well
/// as checksum-valid ([`PendingTxn`]), so no journal can present one
/// coordinate twice inside a transaction and have it folded twice.
///
/// Closed segments whose inferred `lastSeq` (successor's `firstSeq` − 1, a
/// conservative upper bound under TolerateGap burns) is `≤ s_load` are
/// skipped without opening them; the active (final) segment is always scanned
/// (§1/§7) — [`scanned_above`], the one statement of the rule. A corrupt run
/// persists across a segment boundary: the journal is one logical
/// `Seq`-ordered stream.
///
/// `bound` is the boundary the caller will fold to, when it has one: committed
/// records above it are not COLLECTED, since no caller reads them, so a
/// history read of one boundary above a checkpoint does not materialize
/// every committed record in the retained window. `None` collects
/// the whole scanned region, which recovery needs — its own bound is
/// [`ScanOutcome::committed_head`], and that is not known until this returns.
/// Every segment above the base is still READ either way: the corrupt-run
/// classification is at any height, and [`ScanOutcome::committed_head`] and the
/// tail cut must name the last committed marker wherever it sits.
///
/// Memory: one segment's bytes — at most [`MAX_SEGMENT_LEN`], a longer file
/// being refused ([`ScanFail::Unscannable`]) before a byte of it is read, since
/// its length is its own claim — one transaction's records, and the committed
/// records of the scanned region at or below `bound` — the last of which is
/// the term that grows with the journal, and is what a caller bounds by
/// checkpointing, or by asking for a lower boundary.
///
/// Work: the sequential walk is one pass per scanned segment, and
/// resynchronization is bounded at [`RESYNC_BUDGET_PASSES`] more. A segment
/// that exhausts that budget refuses the scan outright
/// ([`ScanFail::Unscannable`]) rather than answering with a prefix, so a payload
/// that plants frame headers costs a bounded scan and a halt rather than an
/// unbounded one.
///
/// THE CHAIN IS VERIFIED HERE, in the same pass (QUEUE item 10), by
/// [`ScanOutcome::collect_commit`] as each committed marker is taken: every
/// committed transaction above `s_load` must carry, in its marker, the
/// recomputation of [`ChainLink`] over the previous committed transaction's
/// value — `chain_at_base` for the first, which is [`super::chain::CHAIN_GENESIS`] from
/// genesis and the `SKC4` header's `chain_head` off a checkpoint — its own
/// record payloads as the CRC verified them, and the salt the marker itself
/// carries (`SKJ4`; read, never drawn). A mismatch is recorded as
/// the first CHAIN BREAK ([`ScanOutcome::chain_break`]) and the running value
/// continues from the marker's own claim; transactions at or below the base
/// are not verified, being embodied in it, exactly as a corrupt run there is
/// harmless. The link is verified in JOURNAL order, which is the order the
/// writer chained in, and it is verified without re-serializing anything:
/// the bytes hashed are the framed payloads in the buffer.
///
/// TWO MORE VERDICTS ARE RECORDED in the same pass, refused by the callers
/// as the break is (the chain's open items, 2026-09-23). THE BASE MISMATCH,
/// judged by [`ScanOutcome::collect_commit`] beside the chain: when the
/// committed marker closing `s_load` itself is scanned — at the head
/// whenever the active segment holds it, which it does unless that segment
/// is EMPTY after a rotation whose transaction failed or never landed;
/// mid-history whenever the base's segment is — its `chain` must
/// equal `chain_at_base`, the header's `chain_head`, else
/// [`ScanOutcome::base_mismatch`] names the base: two stored values
/// disagree, and a header edited at the head, which no link above it would
/// ever judge, is seen here rather than forked from. THE EDITED
/// TRANSACTION, judged by the walk itself, since it concerns a group that
/// did not commit: a group whose every frame was intact and which an intact
/// marker fails to close — refusing it, or naming another transaction as its
/// own — a shape no writer of this format produces, is recorded as
/// [`ScanOutcome::uncommitted_intact`] at the group's own last seq, naming
/// the transaction that was edited rather than the next one, whose link then
/// also fails. Neither moves `committed_head`, what is collected or the tail
/// cut: the scan records, the callers halt. And ONE MARKER IS CAPTURED, by
/// [`ScanOutcome::collect_commit`] too: the committed marker closing `bound`,
/// its chain and its signature slot, which [`ScanOutcome::closing_marker`]
/// answers every one-boundary history read's boundary judgment with — or,
/// under [`scan_boundaries`], the same pass in its other collection mode,
/// EVERY committed marker above the base, as its boundary and its slot.
///
/// `segs` must be ASCENDING by `firstSeq`, as [`super::segment::list_segments`]
/// produces it. The skip rule ([`scanned_above`]), the tail resolution and the
/// segment file's own `inferred_last_seq` all read a neighbour's name as this
/// segment's bound, so an out-of-order slice makes those inferences meaningless
/// — and [`super::segment::reclaim_below`], which reads the same order, deletes
/// on one of them.
///
/// Reached through [`crate::replay::Base::scan`], which supplies `s_load` and
/// `chain_at_base` from the base it selected. A scan and the fold that
/// consumes it must agree on their base, and that is the one route where they
/// cannot disagree.
pub(crate) fn scan(
    segs: &[SegmentMeta],
    s_load: u64,
    bound: Option<u64>,
    chain_at_base: [u8; 32],
) -> Result<ScanOutcome, ScanFail> {
    walk(segs, s_load, Collect::Records { bound }, chain_at_base)
}

/// THE SAME PASS, COLLECTING BOUNDARIES — the M2 seam §3.3 step 2 of the
/// operations design names, "the committed boundaries above a position with
/// their attestation slots": [`scan`]'s walk over the same segments — the
/// skip rule, the resynchronization and its budget, the grouping by `txn`,
/// the committed head, the cut, the chain verified link by link and the two
/// other verdicts, each derived and recorded exactly as there, so
/// [`ScanOutcome::halt_anywhere`] judges a boundary scan as it judges a scan
/// collected to one boundary — differing in ONE thing, what
/// [`ScanOutcome::collect_commit`] keeps of each committed transaction above
/// the base: its marker's `last_seq` and the signature slot that marker
/// carries, every one, and NO RECORD. The records are read, checksummed and
/// chained as they are in every scan, and released with their group. What a
/// caller reads of it is [`ScanOutcome::into_boundaries`]; a fold asked of
/// it is refused as a caller's bug ([`ScanOutcome::records_to`]), since
/// nothing was collected for one, and so is a closing marker
/// ([`ScanOutcome::closing_marker`]), since none was captured.
///
/// Memory: one segment's bytes and one open transaction's records, as
/// [`scan`] holds them, and — the term that grows with the journal — one
/// entry per committed transaction above the base, an [`Attestation`] per
/// attested one, never the committed records of the scanned region: that is
/// what the mode is for. A reader that wanted every boundary of the retained
/// window with its slot had otherwise to run [`scan`] once per boundary, each
/// a pass from the base to the journal's end, or collect the window's
/// records whole. Work: [`scan`]'s — one pass over the scanned segments,
/// resynchronization bounded.
///
/// Reached through [`crate::replay::Base::scan_boundaries`], as [`scan`] is
/// reached through [`crate::replay::Base::scan`], for the same reason: the
/// base the chain's first link is judged against, and whose closed segments
/// are skipped, is the base the derivation selected and never an `S_load` a
/// caller supplied.
pub(crate) fn scan_boundaries(
    segs: &[SegmentMeta],
    s_load: u64,
    chain_at_base: [u8; 32],
) -> Result<ScanOutcome, ScanFail> {
    walk(segs, s_load, Collect::Boundaries, chain_at_base)
}

/// The pass itself, which both entry functions run — [`scan`]'s card states
/// it whole, and `collect` is the one thing the two differ in.
fn walk(
    segs: &[SegmentMeta],
    s_load: u64,
    collect: Collect,
    chain_at_base: [u8; 32],
) -> Result<ScanOutcome, ScanFail> {
    let mut outcome = ScanOutcome {
        s_load,
        chain_at_base,
        collect,
        committed_head: s_load,
        commits_above_base: 0,
        committed_records: Vec::new(),
        nearest_below_bound: s_load,
        runs: Vec::new(),
        tail: None,
        chain_head: chain_at_base,
        chain_break: None,
        base_mismatch: None,
        uncommitted_intact: None,
        closing_at_bound: None,
        boundaries: Vec::new(),
    };
    // The scanned-segment index and the BYTE offset just past the last
    // committed marker's frame — where the tail begins. Resolved to a
    // `TailCut` once at the end rather than at each committed marker, which
    // would clone the discard list per commit.
    let mut cut: Option<(usize, u64)> = None;
    // The first segment this scan did not skip: what the tail resolution
    // below falls to when no committed marker is found anywhere.
    let mut first_scanned: Option<usize> = None;
    let mut pending: Option<PendingTxn> = None;
    // A corrupt run has begun and its end is not yet known. The next intact
    // frame closes it — `RunEnd::landed_on_record` or `landed_on_marker` —
    // and end-of-journal closes it as `RunEnd::Eof`.
    let mut run_open = false;
    for (seg_index, seg) in scanned_above(segs, s_load) {
        if first_scanned.is_none() {
            first_scanned = Some(seg_index);
        }
        let buf = read_segment(&seg.path, s_load)?;
        // This segment's resynchronization budget. EVERY rejected candidate
        // charges, not only the ones a resync landed on: a payload can plant
        // a valid frame between two expensive rejections, which clears the
        // resync and would leave the alternation uncharged.
        let budget = (buf.len() as u64).saturating_mul(RESYNC_BUDGET_PASSES);
        let mut spent = 0u64;
        let mut pos = 0usize;
        while pos < buf.len() {
            match parse_frame(&buf, pos) {
                Parsed::Intact { payload } => {
                    // The frame ends where its payload does, so the advance is
                    // one fact taken once — before the payload is consumed by
                    // the indexing below, and stated once for all three arms.
                    let end = payload.end;
                    let payload = &buf[payload];
                    match codec().deserialize::<FramePayload>(payload) {
                        Ok(FramePayload::Record(record)) => {
                            let mut group = pending
                                .take()
                                .filter(|group| group.txn == record.txn)
                                .unwrap_or_else(|| {
                                    PendingTxn::open(record.txn, &outcome.chain_head)
                                });
                            if run_open {
                                outcome.runs.push(RunEnd::landed_on_record(record.seq));
                                run_open = false;
                                // A record a run landed on cannot vouch for its
                                // group: opened here, the run may have been
                                // this transaction's own earlier frames; already
                                // open, the group met the run while open and
                                // was marked then.
                                group.clean = false;
                            }
                            group.push(record, payload);
                            pending = Some(group);
                        }
                        Ok(FramePayload::Marker(marker)) => {
                            if run_open {
                                outcome.runs.push(RunEnd::landed_on_marker(marker.last_seq));
                                run_open = false;
                            }
                            if let Some(group) = pending.take_if(|group| group.txn == marker.txn) {
                                if group.commits(&marker) {
                                    outcome.collect_commit(marker, group);
                                    // The cut is unbounded for the reason the
                                    // head is: it must name the last committed
                                    // marker wherever it sits.
                                    cut = Some((seg_index, end as u64));
                                } else if group.clean && outcome.uncommitted_intact.is_none() {
                                    // Every frame intact, the marker intact,
                                    // and it does not close them: no writer
                                    // produces this — the marker was edited.
                                    // Named at the GROUP's last seq, the
                                    // marker's being the forged field in one
                                    // of the two shapes. Not committed all
                                    // the same: the scan records, the
                                    // callers halt.
                                    outcome.uncommitted_intact =
                                        Some(group.last_seq.unwrap_or(marker.last_seq));
                                }
                                // else: torn txn — not committed; its frames are
                                // either beyond W (tail, truncated) or explained
                                // by a corrupt run the caller classifies (§7).
                            } else if let Some(group) =
                                pending.as_ref().filter(|group| group.clean)
                            {
                                // A clean group whose next intact frame is
                                // ANOTHER transaction's marker: the writer
                                // emits a transaction's marker immediately
                                // after its own records, so no writer leaves
                                // this — the marker's `txn` was rewritten, and
                                // the group it should have closed can never
                                // commit. Named at the group's own last seq,
                                // as a refused close is; the group stays open
                                // and inert, as a non-matching marker leaves it.
                                if outcome.uncommitted_intact.is_none() {
                                    outcome.uncommitted_intact = group.last_seq;
                                }
                            }
                        }
                        // Intact by CRC but undecodable: under one stamp no
                        // writer of this format writes it and no torn write
                        // leaves it, so it is a rewrite. It joins run
                        // classification, and an open group is no longer
                        // clean: mid-history the run lands on the next intact
                        // frame and halts the caller; in the LAST transaction
                        // the run lies above the committed head, where §7
                        // calls it the torn tail, and the transaction is cut
                        // though its CRC proves these are the bytes that were
                        // written — the open item in `Kernel::open`'s damage
                        // model.
                        Err(_) => {
                            run_open = true;
                            if let Some(group) = pending.as_mut() {
                                group.clean = false;
                            }
                        }
                    }
                    pos = end;
                }
                Parsed::Bad { crc_bytes } => {
                    spent += crc_bytes;
                    if spent > budget {
                        // Everything derived so far is a prefix, so none of it
                        // travels: no verdict can be drawn from it and no
                        // truncation aimed with it.
                        return Err(ScanFail::Unscannable { at: s_load });
                    }
                    run_open = true;
                    // A group open across a corrupt frame may have lost one
                    // of its own: whatever its marker says of it is the
                    // run's to explain, never the edited-transaction verdict.
                    if let Some(group) = pending.as_mut() {
                        group.clean = false;
                    }
                    pos = match find_magic(&buf, pos + 1) {
                        Some(p) => p,
                        None => buf.len(),
                    };
                }
            }
        }
    }
    if run_open {
        outcome.runs.push(RunEnd::Eof);
    }
    // Everything past the last committed marker is tail. When the scanned
    // region holds no committed marker at all, everything scanned is tail:
    // the first scanned segment is cut at offset 0. Harmless corrupt runs
    // (inferred max ≤ `s_load`) sit below the cut and are not touched.
    outcome.tail = cut
        .or_else(|| first_scanned.map(|first| (first, 0)))
        .map(|(seg_index, offset)| TailCut {
            segment: segs[seg_index].path.clone(),
            offset,
            discard: segs[seg_index + 1..]
                .iter()
                .map(|seg| seg.path.clone())
                .collect(),
        });
    Ok(outcome)
}

/// The slot of a marker the decoder admitted, as the [`Attestation`] it
/// spells — `None` for the empty one — interpreted not at all. Every marker
/// reaches the walk through `MarkerShadow`'s door, which admitted these very
/// bytes by this same pure rule ([`attest::slot`]), so asking it again gives
/// the decode's own answer; the blob moves whole, since the walk is done with
/// a marker once it commits.
fn admitted_slot(sig_alg: u8, sig: Vec<u8>) -> Option<Attestation> {
    attest::slot(sig_alg, sig)
        .expect("the marker decoder admitted this slot through this very rule")
}

/// The account a chain break travels with, in the callers' `cause` slot: what
/// the marker at `at` should have carried and did not.
fn chain_break_cause(at: u64) -> Cause {
    format!(
        "chain break: the commit marker closing the transaction at {at} does not carry SHA-256 \
         over the previous committed transaction's chain value and this transaction's own record \
         frames — the transaction was rewritten consistently with its frame CRCs, or the one it \
         follows is not the one before it"
    )
    .into()
}

/// The account the base mismatch travels with
/// ([`ScanOutcome::base_mismatch`]): two stored values at one coordinate
/// disagree, and which party lies is not said — so the remedy is the
/// operator's, named here, rather than a silent fallback to an older base
/// that would leave the edited header on disk for the next head to publish.
fn base_mismatch_cause(at: u64) -> Cause {
    format!(
        "chain break at the base: the checkpoint at {at} carries a chain_head that is not the \
         chain the journal's own commit marker closing {at} carries — the checkpoint header was \
         rewritten, or the marker was; nothing was recomputed, two stored values disagree. Remove \
         or restore the checkpoint and the open re-verifies from the base below it"
    )
    .into()
}

/// The account the edited transaction travels with
/// ([`ScanOutcome::uncommitted_intact`]): the shape, the five ways an intact
/// marker fails to close an intact group, and why no writer leaves it.
fn uncommitted_intact_cause(at: u64) -> Cause {
    format!(
        "chain break at an edited transaction: the transaction ending at {at} is intact frame by \
         frame but no commit marker closes it — the marker after its records disagrees with them \
         in records_checksum or last_seq, or they are not Seq-ascending, or they exceed the \
         transaction budget, or that marker names another transaction as its own; no writer of \
         this journal produces that shape, so the marker was rewritten, and the transaction it \
         should have closed is un-committed"
    )
    .into()
}

/// The account a damaged sync word travels with ([`FirstSyncWord::Damaged`]):
/// the word found, why it is damage and not a format, and the remedy — which
/// is NOT [`crate::OpenError::ForeignFormat`]'s, the journal being this build's.
pub(crate) fn damaged_sync_word_cause(found: [u8; 4]) -> Cause {
    format!(
        "damaged sync word: the first frame the scan would read opens with `{found}`, where the \
         frame after it opens with this build's `{ours}` — another format's journal carries its \
         stamp in every frame, so this is one damaged word in a journal this build wrote, and the \
         frame's CRC does not cover it. Restore the segment from a copy, or rewrite those four \
         bytes to `{ours}` and reopen, when the scan judges the frame by its CRC; this journal \
         needs no migration",
        found = stamp_text(&found),
        ours = stamp_text(&MAGIC),
    )
    .into()
}

/// What the first segment [`scan`] would read opens with — the answer of
/// [`first_sync_word`], which [`crate::Kernel::open`] asks BEFORE the scan.
/// A format shows in EVERY frame's sync word, and damage in ONE: the two are
/// told apart by the frame after the first.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum FirstSyncWord {
    /// This build's stamp, an empty or absent segment, or no well-formed sync
    /// word at all — zeros, a torn header, junk: the scan's to classify, as a
    /// corrupt run or the un-acked tail (the dirty-crash suite's honest
    /// outcomes), never a format event.
    Scan,
    /// A well-formed sync word of ANOTHER format — [`STAMP_PREFIX`] and a
    /// numeral this build does not write — on a frame whose successor does
    /// not open with this build's stamp, or cannot be read: another format's
    /// journal.
    Foreign([u8; 4]),
    /// A well-formed sync word that is not this build's, on a frame whose
    /// successor opens with this build's: ONE damaged word in a journal this
    /// build wrote. The frame CRC covers the length and the payload and not
    /// the sync word, so nothing else about the frame says so.
    Damaged([u8; 4]),
}

/// THE FIRST-SYNC-WORD PROBE (§8 of the encoding report): what the first
/// segment [`scanned_above`] yields opens with — the one [`scan`] reads
/// first, so this looks where the scan will look by construction.
///
/// Read BEFORE the scan by [`crate::Kernel::open`], because the scan cannot
/// tell a format from damage: an old-format segment contains no frame the new
/// sync word anchors, so its resynchronization runs to end-of-file, classifies
/// the whole segment as the un-acked tail, and the tail cut then TRUNCATES it
/// to nothing and serves an empty world — an old-stamp journal wiped rather
/// than refused. Refusing on this probe, ahead of the scan and the cut, is
/// what leaves the files untouched.
///
/// And a foreign-shaped word alone does not name a format: every one-bit flip
/// of this build's numeral keeps the [`STAMP_PREFIX`], and the frame CRC does
/// not cover the sync word, so one flipped bit would read as a journal of
/// another format — whose ruled remedy discards it. So such a word is
/// judged by its frame's SUCCESSOR, at the offset the first frame's own `len`
/// names: this build's stamp there is [`FirstSyncWord::Damaged`], anything
/// else [`FirstSyncWord::Foreign`]. A successor that cannot be read — a
/// header too short to name its offset, a segment ending first — stays
/// foreign: a format whose frame header is not this one's puts its successor
/// wherever it likes, and scanning such a journal would wipe it.
///
/// Reads the first frame's header and four bytes at its successor, whatever
/// the segment's size.
pub(crate) fn first_sync_word(segs: &[SegmentMeta], s_load: u64) -> io::Result<FirstSyncWord> {
    let Some((_, first)) = scanned_above(segs, s_load).next() else {
        return Ok(FirstSyncWord::Scan);
    };
    let mut file = File::open(&first.path)?;
    let mut header = Vec::with_capacity(FRAME_HEADER_LEN);
    (&mut file)
        .take(FRAME_HEADER_LEN as u64)
        .read_to_end(&mut header)?;
    // The header's first two fields, each read as the four bytes it is: the
    // sync word, then the `len` that says where the successor begins.
    let Some((&word, rest)) = header.split_first_chunk::<4>() else {
        return Ok(FirstSyncWord::Scan); // shorter than a sync word: damage or empty
    };
    if word == MAGIC || !word.starts_with(STAMP_PREFIX) {
        return Ok(FirstSyncWord::Scan);
    }
    let Some(&len) = rest.first_chunk::<4>() else {
        return Ok(FirstSyncWord::Foreign(word));
    };
    let len = u32::from_le_bytes(len);
    file.seek(SeekFrom::Start(FRAME_HEADER_LEN as u64 + u64::from(len)))?;
    let mut successor = Vec::with_capacity(MAGIC.len());
    file.take(MAGIC.len() as u64).read_to_end(&mut successor)?;
    Ok(if successor == MAGIC {
        FirstSyncWord::Damaged(word)
    } else {
        FirstSyncWord::Foreign(word)
    })
}

/// The tail-truncation step (§7), run AFTER every refusal and BEFORE any
/// write is served: durably remove everything after the last committed marker
/// — cut its segment at the marker's frame end, delete every wholly-later
/// segment, fsync file and directory. Every halt precedes it — every route to
/// [`crate::OpenError::Corruption`], which enumerates them, and the exhausted
/// checkpoint chain of [`crate::OpenError::BadCheckpoint`] — which is what
/// leaves the journal directory an operator images after a halt exactly as it
/// was found (§7); [`crate::Kernel::open`] is where that order is kept and
/// stated. This is what makes cross-session `Txn` uniqueness and
/// file-order == `Seq`-order true at the next recovery (§1/§7). Idempotent; a
/// failure fails `open()` with `Io`.
///
/// The files are the scan's own [`TailCut`], so this cuts exactly what was
/// scanned and nothing else.
///
/// Answers the bytes it removed — the cut segment's length above the cut,
/// read before the cut, plus each wholly-later segment's length, read before
/// its removal — which a journaled open reports as the tail it cut
/// ([`crate::Recovery`]'s `tail_cut`). `0` where the last committed marker
/// ends the journal, and where nothing was scanned: a cut that took nothing
/// and no cut leave the same journal, so the two are one answer. The lengths
/// read are the lengths the scan read — recovery holds the journal's lock, so
/// nothing appends between the scan and this cut.
pub(crate) fn truncate_tail(dir: &Path, scan: &ScanOutcome) -> io::Result<u64> {
    let Some(tail) = &scan.tail else {
        return Ok(0);
    };
    let f = OpenOptions::new().write(true).open(&tail.segment)?;
    let mut cut = f.metadata()?.len().saturating_sub(tail.offset);
    f.set_len(tail.offset)?;
    f.sync_data()?;
    for path in &tail.discard {
        cut = cut.saturating_add(fs::metadata(path)?.len());
        fs::remove_file(path)?;
    }
    fsync_dir(dir)?;
    Ok(cut)
}

#[cfg(test)]
mod tests;
