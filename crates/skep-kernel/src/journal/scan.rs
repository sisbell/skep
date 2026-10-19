//! The scan, which is recovery's read side.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use bincode::Options;

use super::attest::{self, Attestation};
use super::chain::{slot_digest, ChainLink};
use super::segment::{file_options, fsync_dir, scanned_above, SegmentMeta};
use super::{
    codec, find_magic, frame_len, parse_frame, CommittedRecord, FramePayload, LogRecord, Marker,
    Parsed, Txn, FRAME_HEADER_LEN, MAGIC, MARKER_FRAME_LEN, MAX_SEGMENT_LEN, MAX_TXN_BYTES,
    RESYNC_BUDGET_PASSES, STAMP_PREFIX,
};
use crate::error::{at_file, stamp_text, Cause};
use crate::{Seam, Step};

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

/// One corrupt run as the walk met it: how it ended ([`RunEnd`]), which the
/// halts classify, and where its bytes lie in the journal's files
/// ([`RunPlace`]), which the account of a fatal one names ([`run_cause`]).
#[derive(Debug, PartialEq, Eq)]
struct Run {
    end: RunEnd,
    place: RunPlace,
}

/// Where a corrupt run's bytes lie: resolved to file names by the walk while
/// the segment list is in hand, as [`TailCut`] is, so the account names the
/// files that were scanned and no others. The run's own `Seq`s are
/// unreadable, but its place in the files is not — which is what the act
/// that clears it turns on: a run wholly in CLOSED segments, whose bytes
/// never change once the segment after them begins (the writer appends only
/// to the active segment and rotates only after a committed marker, and the
/// tail cut never shortens a segment that ends on one), is cleared by those
/// files alone from any copy that holds the segment after them; a run in
/// the ACTIVE segment, which every commit extends, is not.
#[derive(Debug, PartialEq, Eq)]
struct RunPlace {
    /// The segment files holding the run's bytes, first to last, by name.
    segments: Vec<String>,
    /// The byte of the first of them at which the run begins.
    from: usize,
    /// The byte of the last of them at which the intact frame that closed
    /// the run begins; `None` where the run reaches that segment's end.
    to: Option<usize>,
    /// The segment listed after the last of them — `None` where the last is
    /// the active segment.
    next: Option<String>,
}

impl RunPlace {
    /// The place of a run the walk opened at byte `from` of `segs[first]`
    /// and closed at `landing` — the segment index and byte of the intact
    /// frame that closed it, `None` for a run that reached the journal's end.
    /// A landing at a segment's first byte holds none of the run: the run
    /// ended with the segment before, which is never the run's own first
    /// segment, since a run begins at a byte before the frame it lands on.
    fn of(
        segs: &[SegmentMeta],
        (first, from): (usize, usize),
        landing: Option<(usize, usize)>,
    ) -> RunPlace {
        let (last, to) = match landing {
            Some((segment, 0)) => (segment - 1, None),
            Some((segment, byte)) => (segment, Some(byte)),
            None => (segs.len() - 1, None),
        };
        RunPlace {
            segments: segs[first..=last].iter().map(SegmentMeta::name).collect(),
            from,
            to,
            next: segs.get(last + 1).map(SegmentMeta::name),
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
        /// damage to say which coordinates it holds.
        at: u64,
        /// The segment that refused, by name, the bound it broke, and the act
        /// that clears it ([`oversized_cause`], [`unenumerable_cause`]).
        cause: Cause,
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
    /// Corrupt runs in scan order, each with where its bytes lie — what
    /// [`ScanOutcome::halt_to_head`] and [`ScanOutcome::halt_anywhere`]
    /// classify, through [`ScanOutcome::fatal_run`], and name the fatal one
    /// by. The verdict on a run belongs to those, not to a caller re-deriving
    /// the classifier.
    runs: Vec<Run>,
    /// The intact frames in the tail of a kind no torn write leaves.
    ///
    /// They are a commit marker that commits nothing, or a frame whose CRC
    /// passes and that does not decode, after the last committed marker.
    /// Counted by the walk and reset by every committed marker
    /// ([`ScanOutcome::collect_commit`]), so once the scan returns it counts
    /// them in the tail the cut removes ([`truncate_tail`]) — what a recovery
    /// reports as [`crate::Recovery`]'s `tail_cut_intact`. A crash leaves one
    /// only where the disk wrote an append's pages out of order; rot in the
    /// last committed transaction, or a rewrite of it, leaves one too (the
    /// open item in [`crate::Kernel::open`]'s damage model), which is why it
    /// is counted, and why a tail that holds one is kept beside the journal
    /// before a byte of it is cut rather than cut in silence. Never bounded,
    /// for the reason the head is not.
    pub tail_intact: u64,
    /// The greatest `last_seq` an intact commit marker after the last
    /// committed one CLAIMS — a marker [`ScanOutcome::tail_intact`] counts,
    /// whose group it did not close — or `None` where no such marker stands.
    /// That claim is the position the transaction's acknowledgement named,
    /// where it was acknowledged: rot in the last committed transaction's
    /// records leaves its own marker intact and committing nothing, and this
    /// is that marker's `last_seq`. An intact frame that does not decode
    /// claims nothing, its fields unread. Reset beside the count by every
    /// committed marker ([`ScanOutcome::collect_commit`]), so once the scan
    /// returns it is the claim of the tail the cut removes — what a recovery
    /// reports as [`crate::Recovery`]'s `tail_cut_claimed`.
    pub tail_claimed: Option<u64>,
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
        // Whatever intact frame of no writer's preceded this marker lies below
        // a committed one now, and so outside any tail a cut removes.
        self.tail_intact = 0;
        self.tail_claimed = None;
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
    /// damage and its account (a corrupt run's own bytes are unreadable, so
    /// its account is where they lie, which the walk knows, and the act that
    /// clears it). The run speaks first because it is the root cause: a run
    /// that swallowed a transaction breaks the chain at the next one. The
    /// order has one site, [`ScanOutcome::halt_on`], which this and
    /// [`ScanOutcome::halt_anywhere`] share, so no caller can ask the chain
    /// before the run, or one of the chain's verdicts without the others.
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
    /// first, with the account of where its bytes lie and the act that clears
    /// it ([`run_cause`]), then the chain's own verdicts.
    fn halt_on(&self, fatal_run: Option<(u64, &RunPlace)>) -> Option<Halt> {
        fatal_run
            .map(|(at, place)| (at, Some(run_cause(place))))
            .or_else(|| self.chain_verdict().map(|(at, cause)| (at, Some(cause))))
    }

    /// The corrupt run a fold over `(s_load, bound]` cannot answer around: the
    /// `at` payload of the first run whose inferred `Seq` max lands in that
    /// range — durable committed data the folded state needs, and unreadable
    /// — and where its bytes lie. Halt, never drop (§7). `bound = None` is
    /// unbounded above: every run above the base is fatal, however far above
    /// it lands.
    ///
    /// The run is classified by its `inferred_max` and REPORTED by its `at`,
    /// and keeping the two apart is what the boundary case turns on: a run
    /// wholly embodied in the base can still land on the very next coordinate
    /// (`at = s_load + 1`), which is harmless — its content is already in the
    /// base — where classifying by `at` would spuriously halt. An
    /// [`RunEnd::Eof`] run is never fatal: it is the un-acked / torn tail,
    /// which the last committed marker precedes.
    fn fatal_run(&self, bound: Option<u64>) -> Option<(u64, &RunPlace)> {
        self.runs.iter().find_map(|run| match run.end {
            RunEnd::Landed { inferred_max, at }
                if inferred_max > self.s_load && bound.is_none_or(|b| inferred_max <= b) =>
            {
                Some((at, &run.place))
            }
            _ => None,
        })
    }

    /// THE CORRUPT RUNS BELOW THE BASE that this scan read and passed over:
    /// how many, and the account of the first in scan order — where its bytes
    /// lie, the position it can hold none above, and the act that clears it
    /// ([`passed_over_account`]). Exactly the landed runs [`fatal_run`] passes
    /// over at every bound, whose inferred `Seq` max the base embodies — save
    /// a run inferred to hold no position at all, junk ahead of a journal's
    /// first frame, which no base lies below and so no derivation meets.
    ///
    /// The base embodies every position such a run can hold, so a recovery
    /// answers around it; a derivation from a base BELOW the run's inferred
    /// max does not — a history read from an older base, an open that falls
    /// back past this one — and halts on it ([`ScanOutcome::halt_anywhere`]).
    /// So a recovery reports them ([`crate::Recovery`]'s `runs_passed_over`)
    /// rather than passing over in silence damage the next fallback meets.
    ///
    /// [`fatal_run`]: ScanOutcome::fatal_run
    pub(crate) fn runs_passed_over(&self) -> (u64, Option<String>) {
        let below: Vec<(u64, &RunPlace)> = self
            .runs
            .iter()
            .filter_map(|run| match run.end {
                RunEnd::Landed { inferred_max, .. }
                    if inferred_max > 0 && inferred_max <= self.s_load =>
                {
                    Some((inferred_max, &run.place))
                }
                _ => None,
            })
            .collect();
        let first =
            below.first().map(|&(inferred_max, place)| passed_over_account(inferred_max, place));
        (below.len() as u64, first)
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
/// refuses as well, since what it holds is then a prefix of the file. Either
/// refusal names the segment and its length ([`oversized_cause`]); a read that
/// fails names the segment and the act.
fn read_segment(seg: &SegmentMeta, s_load: u64) -> Result<Vec<u8>, ScanFail> {
    let name = seg.name();
    let file = File::open(&seg.path).map_err(at_file(&name, "read"))?;
    let claimed = file.metadata().map_err(at_file(&name, "read"))?.len();
    if claimed > MAX_SEGMENT_LEN {
        return Err(ScanFail::Unscannable { at: s_load, cause: oversized_cause(&name, claimed) });
    }
    // `claimed` is at most the ceiling, 2^27, so the cast is exact on any 32-
    // or 64-bit target and the reservation is the file's own size, as
    // `fs::read` would make it.
    let mut buf = Vec::with_capacity(claimed as usize);
    file.take(MAX_SEGMENT_LEN + 1).read_to_end(&mut buf).map_err(at_file(&name, "read"))?;
    if buf.len() as u64 > MAX_SEGMENT_LEN {
        return Err(ScanFail::Unscannable {
            at: s_load,
            cause: oversized_cause(&name, buf.len() as u64),
        });
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
        tail_intact: 0,
        tail_claimed: None,
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
    // A corrupt run has begun — at this segment index and byte — and its end
    // is not yet known. The next intact frame closes it —
    // `RunEnd::landed_on_record` or `landed_on_marker` — and end-of-journal
    // closes it as `RunEnd::Eof`; either way the run is recorded with the
    // place its bytes span (`RunPlace::of`).
    let mut run_began: Option<(usize, usize)> = None;
    for (seg_index, seg) in scanned_above(segs, s_load) {
        if first_scanned.is_none() {
            first_scanned = Some(seg_index);
        }
        let buf = read_segment(seg, s_load)?;
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
                            if let Some(began) = run_began.take() {
                                outcome.runs.push(Run {
                                    end: RunEnd::landed_on_record(record.seq),
                                    place: RunPlace::of(segs, began, Some((seg_index, pos))),
                                });
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
                            if let Some(began) = run_began.take() {
                                outcome.runs.push(Run {
                                    end: RunEnd::landed_on_marker(marker.last_seq),
                                    place: RunPlace::of(segs, began, Some((seg_index, pos))),
                                });
                            }
                            match pending.take_if(|group| group.txn == marker.txn) {
                                Some(group) if group.commits(&marker) => {
                                    outcome.collect_commit(marker, group);
                                    // The cut is unbounded for the reason the
                                    // head is: it must name the last committed
                                    // marker wherever it sits.
                                    cut = Some((seg_index, end as u64));
                                }
                                Some(group) => {
                                    // An intact marker that commits nothing:
                                    // a crash leaves one only where the disk
                                    // wrote an append's pages out of order, so
                                    // it is counted as the tail's own tell
                                    // (`ScanOutcome::tail_intact`), and the
                                    // position it claims kept beside the count.
                                    outcome.tail_intact += 1;
                                    outcome.tail_claimed =
                                        outcome.tail_claimed.max(Some(marker.last_seq));
                                    if group.clean && outcome.uncommitted_intact.is_none() {
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
                                    // else: torn txn — not committed; its frames
                                    // are either beyond W (tail, truncated) or
                                    // explained by a corrupt run the caller
                                    // classifies (§7).
                                }
                                None => {
                                    outcome.tail_intact += 1;
                                    outcome.tail_claimed =
                                        outcome.tail_claimed.max(Some(marker.last_seq));
                                    if let Some(group) = pending.as_ref().filter(|group| group.clean)
                                    {
                                        // A clean group whose next intact frame
                                        // is ANOTHER transaction's marker: the
                                        // writer emits a transaction's marker
                                        // immediately after its own records, so
                                        // no writer leaves this — the marker's
                                        // `txn` was rewritten, and the group it
                                        // should have closed can never commit.
                                        // Named at the group's own last seq, as
                                        // a refused close is; the group stays
                                        // open and inert, as a non-matching
                                        // marker leaves it.
                                        if outcome.uncommitted_intact.is_none() {
                                            outcome.uncommitted_intact = group.last_seq;
                                        }
                                    }
                                }
                            }
                        }
                        // Intact by CRC but undecodable: under one stamp no
                        // writer of this format writes it and no torn write
                        // leaves it, so it is a rewrite. It joins run
                        // classification, it is counted as the tail's own tell
                        // where no committed marker follows it, and an open
                        // group is no longer clean: mid-history the run lands
                        // on the next intact frame and halts the caller; in the
                        // LAST transaction the run lies above the committed
                        // head, where §7 calls it the torn tail, and the
                        // transaction is cut from the journal though its CRC
                        // proves these are the bytes that were written — the
                        // open item in `Kernel::open`'s damage model, which the
                        // count reports and whose bytes the count has kept
                        // beside the journal (`truncate_tail`).
                        Err(_) => {
                            run_began.get_or_insert((seg_index, pos));
                            outcome.tail_intact += 1;
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
                        return Err(ScanFail::Unscannable {
                            at: s_load,
                            cause: unenumerable_cause(&seg.name()),
                        });
                    }
                    run_began.get_or_insert((seg_index, pos));
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
    if let Some(began) = run_began {
        outcome.runs.push(Run { end: RunEnd::Eof, place: RunPlace::of(segs, began, None) });
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
/// the marker at `at` should have carried and did not — the position spelled
/// as the operator's stream spells every one, `position N`.
fn chain_break_cause(at: u64) -> Cause {
    format!(
        "chain break: the commit marker closing the transaction at position {at} does not carry \
         SHA-256 over the previous committed transaction's chain value and this transaction's own \
         record frames — the transaction was rewritten consistently with its frame CRCs, or the \
         one it follows is not the one before it"
    )
    .into()
}

/// The account the base mismatch travels with
/// ([`ScanOutcome::base_mismatch`]): two stored values at one coordinate
/// disagree, and which party lies is not said — so the remedy is the
/// operator's, named here, rather than a silent fallback to an older base
/// that would leave the edited header on disk for the next head to publish.
fn base_mismatch_cause(at: u64) -> Cause {
    // The checkpoint's own file name at `at` (`checkpoint.<seq>`, §6), spelled
    // here because the journal's module sits below the checkpoint's.
    let checkpoint = format!("checkpoint.{at}");
    format!(
        "chain break at the base: {checkpoint} carries a chain_head that is not the chain the \
         journal's own commit marker closing position {at} carries — the checkpoint header was \
         rewritten, or the marker was; nothing was recomputed, two stored values disagree. Remove \
         or restore {checkpoint} and the open re-verifies from the base below it"
    )
    .into()
}

/// The account a fatal corrupt run travels with ([`ScanOutcome::halt_on`]):
/// where its bytes lie ([`span_words`]) and the act that clears it, which
/// turns on whether those segments are CLOSED ([`RunPlace`]): restoring them
/// alone from a copy that holds the segment after them loses nothing, and the
/// open verifies what was restored by the commit chain
/// ([`closed_segments_act`]); a run in the ACTIVE segment is cleared only by a
/// whole directory's copy, which rewinds the journal to it.
fn run_cause(place: &RunPlace) -> Cause {
    let act = closed_segments_act(place).unwrap_or_else(|| {
        format!(
            "{last} is the active segment, which every commit extends, so a copy of it holds only \
             the commits made before the copy was taken: restore the journal directory whole from \
             one copy, which rewinds the journal to that copy",
            last = run_ends(place).1
        )
    });
    format!(
        "corrupt run {span}: its frames fail their CRC or do not decode, and an intact frame \
         follows it; {act}",
        span = span_words(place)
    )
    .into()
}

/// The account a corrupt run BELOW the base travels with
/// ([`ScanOutcome::runs_passed_over`]): where its bytes lie, the position it
/// can hold none above — its inferred max, `inferred_max` — which bases meet
/// it, and the act that clears it. A run wholly in closed segments is
/// cleared as a fatal one is ([`closed_segments_act`]); one in the ACTIVE
/// segment has no copy to come from while the board writes — a copy holds
/// only the commits made before it was taken, so restoring one would rewind
/// the journal — and leaves the journal only once its segment has closed and
/// a landing reclaims below it. Positions are spelled as the operator's
/// stream spells every one, `position N`.
fn passed_over_account(inferred_max: u64, place: &RunPlace) -> String {
    let act = closed_segments_act(place).unwrap_or_else(|| {
        let last = run_ends(place).1;
        format!(
            "{last} is the active segment, which every commit extends, so a copy of it holds only \
             the commits made before the copy was taken and restoring one would rewind the \
             journal: the run stays in the journal until {last} has closed and a landing reclaims \
             the journal below it"
        )
    });
    format!(
        "corrupt run {span}, holding no position above position {inferred_max}: a history read \
         from a base below position {inferred_max}, or an open that falls back to one, meets it \
         and refuses; {act}",
        span = span_words(place)
    )
}

/// The first and the last segment a run's bytes lie in — one name twice for
/// a run in one segment.
fn run_ends(place: &RunPlace) -> (&str, &str) {
    match place.segments.as_slice() {
        [only] => (only.as_str(), only.as_str()),
        [first, .., last] => (first.as_str(), last.as_str()),
        // `RunPlace::of` slices from the segment the run began in, which
        // holds its first byte, so the list is never empty.
        [] => unreachable!("a corrupt run's bytes lie in the segment it began in"),
    }
}

/// Where a corrupt run's bytes lie, in a sentence's words: the segment or
/// segments, the byte it begins at, and the byte or the end it reaches.
fn span_words(place: &RunPlace) -> String {
    let (first, last) = run_ends(place);
    match (place.segments.len() == 1, place.to) {
        (true, Some(to)) => format!("in {first} from byte {} to byte {to}", place.from),
        (true, None) => format!("in {first} from byte {} to its end", place.from),
        (false, Some(to)) => format!("from byte {} of {first} to byte {to} of {last}", place.from),
        (false, None) => format!("from byte {} of {first} to the end of {last}", place.from),
    }
}

/// The act that clears a run whose segments are all CLOSED — those files
/// alone, from a copy that holds the segment after them, since a closed
/// segment's bytes never change — or `None` where the run reaches the
/// ACTIVE segment, which every commit extends and no one file's copy
/// restores.
fn closed_segments_act(place: &RunPlace) -> Option<String> {
    let next = place.next.as_ref()?;
    let files = names_list(&place.segments);
    let (are, them) = if place.segments.len() == 1 { ("is", "it") } else { ("are", "them") };
    Some(format!(
        "{files} {are} closed — {next} follows {them} — and a closed segment's bytes never change: \
         restore {files} alone from a copy that holds {next}, and reopen; the open verifies what \
         it restores by the commit chain, and nothing is lost"
    ))
}

/// `names` as one list in a sentence: `a`, `a and b`, `a, b and c`.
fn names_list(names: &[String]) -> String {
    match names {
        [] => String::new(),
        [only] => only.clone(),
        [init @ .., last] => format!("{} and {last}", init.join(", ")),
    }
}

/// The account a segment longer than any this journal's writer produces
/// travels with ([`ScanFail::Unscannable`]): the file, its length and the
/// ceiling, and the act — the file is not read whole, so what it holds is the
/// operator's to judge.
fn oversized_cause(segment: &str, len: u64) -> Cause {
    format!(
        "{segment} is {len} bytes, past the {MAX_SEGMENT_LEN} no segment this journal's writer \
         produces reaches: a file that is not one of this journal's segments, or one grown by \
         damage, refused rather than read whole — move it out of the journal directory where it \
         is not this journal's, and restore it from a copy where it is"
    )
    .into()
}

/// The account a segment whose frames could not be enumerated within the
/// resynchronization budget travels with ([`ScanFail::Unscannable`]): the
/// file and the budget, and the act. Honest damage almost never spends the
/// budget; damage that sends the scan into a record whose own bytes plant
/// frame headers does, and a copy of the segment from before the damage
/// clears it.
fn unenumerable_cause(segment: &str) -> Cause {
    format!(
        "{segment}'s frames could not be enumerated within {RESYNC_BUDGET_PASSES} passes over it: \
         damage inside it sent the scan into a record whose own bytes plant frame headers; \
         restore {segment} from a copy"
    )
    .into()
}

/// The account the edited transaction travels with
/// ([`ScanOutcome::uncommitted_intact`]): the shape, the five ways an intact
/// marker fails to close an intact group, and why no writer leaves it.
fn uncommitted_intact_cause(at: u64) -> Cause {
    format!(
        "chain break at an edited transaction: the transaction ending at position {at} is intact \
         frame by frame but no commit marker closes it — the marker after its records disagrees \
         with them in records_checksum or last_seq, or they are not Seq-ascending, or they exceed \
         the transaction budget, or that marker names another transaction as its own; no writer \
         of this journal produces that shape, so the marker was rewritten, and the transaction it \
         should have closed is un-committed"
    )
    .into()
}

/// The account a damaged sync word travels with ([`FirstSyncWord::Damaged`]):
/// the segment and the word found, why it is damage and not a format, and the
/// remedy — which is NOT [`crate::OpenError::ForeignFormat`]'s, the journal
/// being this build's — named on the file it applies to.
pub(crate) fn damaged_sync_word_cause(found: [u8; 4], segment: &str) -> Cause {
    format!(
        "damaged sync word: {segment} opens with `{found}`, where its second frame opens with \
         this build's `{ours}` — another format's journal carries its stamp in every frame, so \
         this is one damaged word in a journal this build wrote, and the frame's CRC does not \
         cover it. Restore {segment} from a copy, or rewrite its first four bytes to `{ours}` and \
         reopen, when the scan judges the frame by its CRC; this journal needs no migration",
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
    Foreign {
        /// The word the segment opens with.
        found: [u8; 4],
        /// The segment's name in the journal directory, which the refusal
        /// names: the file found under another format.
        segment: String,
    },
    /// A well-formed sync word that is not this build's, on a frame whose
    /// successor opens with this build's: ONE damaged word in a journal this
    /// build wrote. The frame CRC covers the length and the payload and not
    /// the sync word, so nothing else about the frame says so.
    Damaged {
        /// The word the segment opens with.
        found: [u8; 4],
        /// The segment's name in the journal directory, which the remedy
        /// names: the one file to restore, or whose four bytes to rewrite.
        segment: String,
    },
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
/// the segment's size; a read that fails names the segment and the act.
pub(crate) fn first_sync_word(segs: &[SegmentMeta], s_load: u64) -> io::Result<FirstSyncWord> {
    let Some((_, first)) = scanned_above(segs, s_load).next() else {
        return Ok(FirstSyncWord::Scan);
    };
    let name = first.name();
    let mut file = File::open(&first.path).map_err(at_file(&name, "read"))?;
    let mut header = Vec::with_capacity(FRAME_HEADER_LEN);
    (&mut file)
        .take(FRAME_HEADER_LEN as u64)
        .read_to_end(&mut header)
        .map_err(at_file(&name, "read"))?;
    // The header's first two fields, each read as the four bytes it is: the
    // sync word, then the `len` that says where the successor begins.
    let Some((&word, rest)) = header.split_first_chunk::<4>() else {
        return Ok(FirstSyncWord::Scan); // shorter than a sync word: damage or empty
    };
    if word == MAGIC || !word.starts_with(STAMP_PREFIX) {
        return Ok(FirstSyncWord::Scan);
    }
    let Some(&len) = rest.first_chunk::<4>() else {
        return Ok(FirstSyncWord::Foreign { found: word, segment: name });
    };
    let len = u32::from_le_bytes(len);
    let mut successor = Vec::with_capacity(MAGIC.len());
    file.seek(SeekFrom::Start(FRAME_HEADER_LEN as u64 + u64::from(len)))
        .and_then(|_| file.take(MAGIC.len() as u64).read_to_end(&mut successor))
        .map_err(at_file(&name, "read"))?;
    Ok(if successor == MAGIC {
        FirstSyncWord::Damaged { found: word, segment: name }
    } else {
        FirstSyncWord::Foreign { found: word, segment: name }
    })
}

/// Removes everything after the last committed marker from the journal (§7).
///
/// The tail-truncation step, run after every refusal and before any write is
/// served: it cuts the marker's segment at the marker's frame end, takes
/// every wholly-later segment out, and fsyncs file and directory. Every halt
/// precedes it — every route to [`crate::OpenError::Corruption`], which
/// enumerates them, and the exhausted checkpoint chain of
/// [`crate::OpenError::BadCheckpoint`] — which is what leaves the journal
/// directory an operator images after a halt exactly as it was found (§7);
/// [`crate::Kernel::open`] is where that order is kept and stated. This is
/// what makes cross-session `Txn` uniqueness and file-order == `Seq`-order
/// true at the next recovery (§1/§7). Idempotent at the open: a failed cut
/// is retried by the next `open()`.
///
/// **The keep.** Where the tail holds an intact frame no torn write leaves
/// ([`ScanOutcome::tail_intact`]) — the sign that the cut may take a
/// transaction this kernel acknowledged, rot in or a rewrite of the journal's
/// last transaction (the open item in [`crate::Kernel::open`]'s damage
/// model), whose bytes are then the one record of that write and of what
/// befell it — every byte the cut takes is first kept beside the journal,
/// durably ([`keep_aside`]). The cut segment's bytes from the cut on are
/// copied to `{segment}.cut-{byte}`, and each wholly-later segment that holds
/// a byte is moved whole to `{segment}.cut-0`, so no byte leaves the journal
/// that a durable file beside it does not hold. A crash's tail holds no such
/// frame — a torn write leaves a frame that fails its CRC, and the intact
/// records before it were never acknowledged — and is cut and gone, as §7
/// rules. No listing of the kernel's reads a kept file's name, so the next
/// session's appends and every recovery's scan go on as if the tail were
/// gone; the kept files are the operator's, and no open removes or writes
/// over one ([`keep_a_copy`]).
///
/// The files are the scan's own [`TailCut`], so this cuts exactly what was
/// scanned and nothing else.
///
/// Answers what it removed ([`Truncated`]), which a journaled open reports
/// as the tail it cut ([`crate::Recovery`]'s `tail_cut`, `tail_cut_from` and
/// `tail_cut_kept`): the bytes — the cut segment's length above the cut,
/// read before the cut, plus each wholly-later segment's length, read before
/// it is removed or moved — where the cut began, the first file a byte left,
/// and the files the keep left beside the journal. `0` and nowhere where the
/// last committed marker ends the journal, and where nothing was scanned: a
/// cut that took nothing and no cut leave the same journal, so the two are
/// one answer. The lengths read are the lengths the scan read — recovery
/// holds the journal's lock, so nothing appends between the scan and this
/// cut.
///
/// **The seam** (`test-hooks`): the keep's copy is synced through `seam`'s
/// [`Step::TailKeep`]. [`crate::Kernel::open`] hands it the seam it makes,
/// which nothing can arm before the open runs, so only a test that hands the
/// cut a seam of its own fails that step; in a build without the feature the
/// hook is a no-op.
///
/// # Errors
///
/// Fails, and fails `open()` with `Io`, where a file of the cut cannot be
/// opened, sized, cut, synced or removed, named `{file}: {act}`, or where
/// the keep fails ([`keep_aside`]). A keep that fails cuts nothing and puts
/// back what it made, so the next open keeps and cuts.
pub(crate) fn truncate_tail(dir: &Path, scan: &ScanOutcome, seam: &Seam) -> io::Result<Truncated> {
    let Some(tail) = &scan.tail else {
        return Ok(Truncated { bytes: 0, from: None, kept: Vec::new() });
    };
    let name = file_name(&tail.segment);
    let segment =
        OpenOptions::new().write(true).open(&tail.segment).map_err(at_file(&name, "truncate"))?;
    let above = segment
        .metadata()
        .map_err(at_file(&name, "truncate"))?
        .len()
        .saturating_sub(tail.offset);
    let kept = if scan.tail_intact > 0 {
        keep_aside(dir, tail, above, seam)?
    } else {
        Kept::default()
    };
    segment
        .set_len(tail.offset)
        .and_then(|()| segment.sync_data())
        .map_err(at_file(&name, "truncate"))?;
    let mut cut = above;
    let mut from = (above > 0).then_some((name, tail.offset));
    for path in &tail.discard {
        // A segment the keep moved aside stands under its kept name, its
        // length read before the move. Every other is removed here.
        let len = match kept.moved.iter().find(|(moved, _)| moved == path) {
            Some(&(_, len)) => len,
            None => fs::metadata(path)
                .and_then(|meta| fs::remove_file(path).map(|()| meta.len()))
                .map_err(at_file(file_name(path), "remove"))?,
        };
        if from.is_none() && len > 0 {
            from = Some((file_name(path), 0));
        }
        cut = cut.saturating_add(len);
    }
    fsync_dir(dir)?;
    Ok(Truncated { bytes: cut, from, kept: kept.names })
}

/// What [`truncate_tail`] removed from the journal, and where it kept it.
///
/// `bytes` is the bytes cut. `from` is where the cut began — the name in the
/// journal directory of the first file a byte left, and the byte of it the
/// cut began at: the cut segment at the cut's offset, or else the first
/// wholly-later segment that held a byte, at byte `0` — and `None` where
/// nothing was cut. `kept` is the files the keep left the cut bytes in, by
/// name, in journal order: empty where the tail held no intact frame no torn
/// write leaves, and where nothing was cut.
#[derive(Debug)]
pub(crate) struct Truncated {
    pub(crate) bytes: u64,
    pub(crate) from: Option<(String, u64)>,
    pub(crate) kept: Vec<String>,
}

/// What the keep left beside the journal ([`keep_aside`]).
///
/// `names` is the files the cut bytes were kept in, by name, in journal
/// order; `moved` is the wholly-later segments the keep moved there, each by
/// the path it stood at and its length, which the cut counts and leaves where
/// the keep put them.
#[derive(Default)]
struct Kept {
    names: Vec<String>,
    moved: Vec<(PathBuf, u64)>,
}

/// Keeps every byte of `tail` beside the journal before a byte of it is cut.
///
/// The keep of §7's tail truncation, run ahead of the cut: the cut segment's
/// `above` bytes from the cut on are copied ([`keep_a_copy`]) and synced, and
/// the directory synced; then each wholly-later segment that holds a byte is
/// moved whole ([`move_aside`]), and the directory synced again. A segment
/// that holds none has nothing to keep, and the cut removes it. The order
/// keeps every journal byte the cut takes in a durable file beside it: the
/// copy is durable before any segment moves, and every move before the cut,
/// so a crash anywhere in between leaves the cut segment uncut and every
/// byte already moved kept — the next open scans what of the tail remains,
/// completes a copy it finds standing, and cuts.
///
/// # Errors
///
/// Fails where the copy cannot be made or synced, a later segment cannot be
/// sized or moved, or the directory cannot be synced, each named
/// `{file}: {act}`. A failure answers with what this call made put back
/// ([`undone`]) — the segments it moved renamed to their own names, the copy
/// it made removed — so the cut that does not follow leaves the journal as
/// the keep found it, and the room a copy took is free again for the next
/// open's.
fn keep_aside(dir: &Path, tail: &TailCut, above: u64, seam: &Seam) -> io::Result<Kept> {
    let mut kept = Kept::default();
    let mut copy: Option<PathBuf> = None;
    let mut moves: Vec<(PathBuf, PathBuf)> = Vec::new();
    let done = (|| -> io::Result<()> {
        if above > 0 {
            kept.names.push(keep_a_copy(dir, &tail.segment, tail.offset, seam, &mut copy)?);
            fsync_dir(dir)?;
        }
        for path in &tail.discard {
            let len = fs::metadata(path).map_err(at_file(file_name(path), "stat"))?.len();
            if len == 0 {
                continue;
            }
            let (name, to) = move_aside(dir, path)?;
            moves.push((path.clone(), to));
            kept.moved.push((path.clone(), len));
            kept.names.push(name);
        }
        if !moves.is_empty() {
            fsync_dir(dir)?;
        }
        Ok(())
    })();
    match done {
        Ok(()) => Ok(kept),
        Err(failed) => Err(undone(failed, copy.as_deref(), &moves)),
    }
}

/// Returns the name of a synced copy of `segment` from its byte `offset` on.
///
/// The copy [`keep_aside`] makes of the cut segment's tail, in a file of its
/// own beside the journal, `{segment}.cut-{offset}`, born owner-only as every
/// file the kernel makes ([`file_options`]).
///
/// A name already standing is never written over: the copy takes the first
/// of [`kept_name`]'s names that is absent, or that holds a regular file
/// whose bytes are a prefix of the bytes kept — a copy of these very bytes
/// an earlier attempt began and a crash cut short, completed in place, so a
/// crash loop over one open's keep leaves one copy and not one per attempt.
/// Any other file under a name — an earlier cut's bytes, kept by an earlier
/// open under the name the same segment and byte gave — is passed over
/// whole. `made` names the copy once it is created or opened, so a failure
/// past that point removes it ([`undone`]). The seam's [`Step::TailKeep`] is
/// hooked before the copy's fsync, its bytes written.
///
/// # Errors
///
/// Fails where the segment cannot be read, a name cannot be looked at, or the
/// copy cannot be created, opened, written or synced, each named
/// `{file}: {act}`.
fn keep_a_copy(
    dir: &Path,
    segment: &Path,
    offset: u64,
    seam: &Seam,
    made: &mut Option<PathBuf>,
) -> io::Result<String> {
    let segment_name = file_name(segment);
    let mut bytes = Vec::new();
    let mut source = File::open(segment).map_err(at_file(&segment_name, "read"))?;
    source
        .seek(SeekFrom::Start(offset))
        .and_then(|_| source.take(MAX_SEGMENT_LEN).read_to_end(&mut bytes))
        .map_err(at_file(&segment_name, "read"))?;
    let mut k = 0;
    loop {
        let name = kept_name(&segment_name, offset, k);
        let path = dir.join(&name);
        let standing = match fs::symlink_metadata(&path) {
            Err(e) if e.kind() == io::ErrorKind::NotFound => None,
            Err(e) => return Err(at_file(&name, "stat")(e)),
            Ok(meta) => match unfinished_copy(&path, &meta, &bytes, &name)? {
                Some(len) => Some(len),
                None => {
                    k += 1;
                    continue;
                }
            },
        };
        let opened = match standing {
            None => file_options()
                .write(true)
                .create_new(true)
                .open(&path)
                .map_err(at_file(&name, "create")),
            Some(_) => file_options().write(true).open(&path).map_err(at_file(&name, "open")),
        };
        let mut copy = opened?;
        *made = Some(path);
        let from = standing.unwrap_or(0);
        copy.seek(SeekFrom::Start(from))
            .and_then(|_| copy.write_all(&bytes[from as usize..]))
            .map_err(at_file(&name, "write"))?;
        seam.before(Step::TailKeep)
            .and_then(|()| copy.sync_all())
            .map_err(at_file(&name, "fsync"))?;
        return Ok(name);
    }
}

/// Returns the length of `path`'s file where it holds a short copy of `bytes`.
///
/// A copy of `bytes` a crash cut short is a regular file whose whole content
/// is a prefix of them, the whole of them included; `None` answers anything
/// else standing there.
///
/// # Errors
///
/// Fails where the file cannot be read, named `{name}: read`.
fn unfinished_copy(
    path: &Path,
    meta: &fs::Metadata,
    bytes: &[u8],
    name: &str,
) -> io::Result<Option<u64>> {
    if !meta.is_file() || meta.len() > bytes.len() as u64 {
        return Ok(None);
    }
    let held = fs::read(path).map_err(at_file(name, "read"))?;
    Ok(bytes.starts_with(&held).then_some(meta.len()))
}

/// Moves the wholly-later segment `discard` aside whole.
///
/// The segment goes to the first of [`kept_name`]'s names for its byte `0`
/// that is absent — a rename, which takes no room and keeps the segment's
/// own bytes and mode — and the name and the path it stands at are answered.
/// A name already standing, of whatever kind, is passed over: a rename
/// replaces its target, so the target is one no file holds.
///
/// # Errors
///
/// Fails where a name cannot be looked at, named `{name}: stat`, or the
/// rename is refused, named `{segment}: rename to {name}`.
fn move_aside(dir: &Path, discard: &Path) -> io::Result<(String, PathBuf)> {
    let segment_name = file_name(discard);
    let mut k = 0;
    loop {
        let name = kept_name(&segment_name, 0, k);
        let to = dir.join(&name);
        match fs::symlink_metadata(&to) {
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                fs::rename(discard, &to)
                    .map_err(at_file(&segment_name, format!("rename to {name}")))?;
                return Ok((name, to));
            }
            Err(e) => return Err(at_file(&name, "stat")(e)),
            Ok(_) => k += 1,
        }
    }
}

/// Returns the `k`th name the keep may give `segment`'s bytes from `byte` on.
///
/// `segment` is a file of the journal directory by its name; the names are
/// `{segment}.cut-{byte}`, then `{segment}.cut-{byte}.{k}` where the earlier
/// ones stand. No listing of the kernel's reads one back — a segment's name
/// ends `.wal`, a checkpoint's opens `checkpoint.` — so a kept file is never
/// a segment or a base.
fn kept_name(segment: &str, byte: u64, k: u64) -> String {
    match k {
        0 => format!("{segment}.cut-{byte}"),
        k => format!("{segment}.cut-{byte}.{k}"),
    }
}

/// Returns a failed keep's account, once what the keep made is put back.
///
/// The segments it moved are renamed to their own names, newest first, and
/// then — every one of them back — the copy it made is removed, so the cut
/// that does not follow leaves the journal and its directory as the keep
/// found them. Best-effort: what could not be put back is folded into the
/// account beside the failure, never masking it, its kind kept; and the copy
/// stands where a moved segment could not go back, so a byte missing from
/// the next open's tail stays kept.
fn undone(failed: io::Error, copy: Option<&Path>, moves: &[(PathBuf, PathBuf)]) -> io::Error {
    let mut left = Vec::new();
    for (from, to) in moves.iter().rev() {
        if let Err(e) = fs::rename(to, from) {
            left.push(format!(
                "{} could not be moved back to {}: {e}",
                file_name(to),
                file_name(from)
            ));
        }
    }
    if let Some(copy) = copy.filter(|_| left.is_empty()) {
        match fs::remove_file(copy) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => left.push(format!("{} could not be removed: {e}", file_name(copy))),
        }
    }
    if left.is_empty() {
        failed
    } else {
        io::Error::new(
            failed.kind(),
            format!("{failed}; and the keep could not be undone after it: {}", left.join("; ")),
        )
    }
}

/// A journal file's name, by its path, as a refusal names it.
fn file_name(path: &Path) -> String {
    path.file_name().unwrap_or(path.as_os_str()).to_string_lossy().into_owned()
}

#[cfg(test)]
mod tests;
