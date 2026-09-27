//! Segment files (names, listing, reclaim, directory fsync, the lock file).

use std::fs::{self, File, OpenOptions};
use std::io;
use std::path::{Path, PathBuf};

/// A journal segment file, named by its `firstSeq` (§1). Every operation over
/// a slice of these reads a neighbour's name as this segment's bound, so the
/// slice must be ascending by `first_seq` as [`list_segments`] produces it.
///
/// Both fields are read only by the operations here that own segment names —
/// [`inferred_last_seq`], [`reaches_genesis`], [`reclaim_below`], [`scan`]
/// and [`first_sync_word`], the last two reaching their segments through the
/// one skip rule, [`scanned_above`] — because a `firstSeq` read outside them
/// is a coverage inference made away from the naming rule it rests on, and
/// [`reclaim_below`] deletes files on that inference. A slice of these
/// travels; the names inside do not, and neither does the inference drawn
/// from them — the one fact about segment coverage that leaves this module is
/// [`reaches_genesis`]'s answer.
pub(crate) struct SegmentMeta {
    pub(super) first_seq: u64,
    pub(super) path: PathBuf,
}

/// The one file name a segment beginning at `first_seq` has:
/// `seg-<firstSeq>.wal` (§1).
///
/// Stated as a pair with [`parse_segment_name`], which reads it back by
/// re-emitting it, because the format and the parse are one agreement: a
/// change to either that the other does not match makes every segment on disk
/// invisible to recovery, which reads as an empty journal rather than as a
/// failure.
fn segment_name(first_seq: u64) -> String {
    format!("seg-{first_seq}.wal")
}

/// Where a segment beginning at `first_seq` lives (§1).
pub(crate) fn segment_path(dir: &Path, first_seq: u64) -> PathBuf {
    dir.join(segment_name(first_seq))
}

/// Read back the `firstSeq` [`segment_name`] wrote — and ONLY the spelling it
/// writes. `u64::from_str` accepts a leading `+` and any number of leading
/// zeros, so the round trip is what keeps `seg-01.wal` from claiming a live
/// segment's `firstSeq`: two entries at one coordinate make
/// [`inferred_last_seq`] answer `0` for the first of them, and
/// [`reclaim_below`] deletes on that inference. `None` for any other name — a
/// checkpoint, the lock file, or something foreign.
fn parse_segment_name(name: &str) -> Option<u64> {
    let first_seq: u64 = name.strip_prefix("seg-")?.strip_suffix(".wal")?.parse().ok()?;
    (name == segment_name(first_seq)).then_some(first_seq)
}

/// All segments in `dir`, ascending by `firstSeq`. Non-segment files
/// (checkpoints, the lock file) fail the name parse and are skipped.
pub(crate) fn list_segments(dir: &Path) -> io::Result<Vec<SegmentMeta>> {
    let mut segs = Vec::new();
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let name = entry.file_name();
        let Some(first_seq) = name.to_str().and_then(parse_segment_name) else {
            continue;
        };
        segs.push(SegmentMeta {
            first_seq,
            path: entry.path(),
        });
    }
    segs.sort_by_key(|seg| seg.first_seq);
    Ok(segs)
}

/// The `lastSeq` segment `i` covers, inferred from its successor's name
/// (`firstSeq` − 1). An upper bound — under `TolerateGap` burns the successor
/// starts above its predecessor's true last `Seq` — so every use of it is
/// conservative. `None` for the final (active) segment, which has no
/// successor and therefore no trusted `lastSeq`: it is always scanned, never
/// range-reclaimed (§1/§6/§7).
///
/// Private for the reason [`SegmentMeta`]'s fields are: a coverage inference
/// drawn outside this module is drawn away from the naming rule it rests on,
/// and [`reclaim_below`] deletes files on it.
pub(super) fn inferred_last_seq(segs: &[SegmentMeta], i: usize) -> Option<u64> {
    segs.get(i + 1).map(|next| next.first_seq.saturating_sub(1))
}

/// The segments a scan above `s_load` reads, each with its index in `segs`:
/// every closed segment whose inferred reach lies above the base, and the
/// active one always (§1/§7). The ONE statement of the skip rule — [`scan`]
/// walks these and [`first_sync_word`] probes the first of them, so the probe
/// looks where the scan will look by construction.
pub(super) fn scanned_above(
    segs: &[SegmentMeta],
    s_load: u64,
) -> impl Iterator<Item = (usize, &SegmentMeta)> + '_ {
    segs.iter()
        .enumerate()
        .filter(move |&(i, _)| inferred_last_seq(segs, i).is_none_or(|last| last > s_load))
}

/// Whether the surviving segments still cover `Seq(1)` — whether a fold from
/// genesis can still reach the present. True for an empty journal (nothing
/// has been reclaimed yet); false once reclamation has dropped the segment
/// that began the log, which is what makes genesis unusable as a fallback
/// base (§6/§7).
pub(crate) fn reaches_genesis(segs: &[SegmentMeta]) -> bool {
    segs.first().is_none_or(|seg| seg.first_seq == 1)
}

/// Reclaim whole *closed* segments covering nothing above `floor`: the
/// qualifying segments form a prefix, so the walk stops at the first that
/// does not qualify, and the active segment never does (§6). Space
/// reclamation only — never a correctness mechanism; recovery's
/// `Seq > S_load` filter handles a straddler's leftovers. On return the
/// directory durably reflects whatever this call removed, with no case split
/// on whether that was anything.
pub(crate) fn reclaim_below(dir: &Path, floor: u64) -> io::Result<()> {
    let segs = list_segments(dir)?;
    for (i, seg) in segs.iter().enumerate() {
        match inferred_last_seq(&segs, i) {
            Some(last) if last <= floor => fs::remove_file(&seg.path)?,
            _ => break,
        }
    }
    fsync_dir(dir)
}

/// Fsync a directory so entry creations/deletions/renames are durable. On
/// non-unix targets this is a no-op (v1 targets unix; the design's dir-fsync
/// obligations are discharged there).
pub(crate) fn fsync_dir(dir: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        File::open(dir)?.sync_all()?;
    }
    #[cfg(not(unix))]
    {
        let _ = dir;
    }
    Ok(())
}

/// Take the `open()`-held exclusive advisory lock on the journal directory
/// (Lifecycle): at most one live kernel — appender *or* recoverer — per
/// journal. flock semantics, so the lock dies with the process; a second
/// `open()` fails with the acquisition error (surfaced as `OpenError::Io`).
pub(crate) fn acquire_journal_lock(dir: &Path) -> io::Result<File> {
    let f = OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(dir.join("kernel.lock"))?;
    fs2::FileExt::try_lock_exclusive(&f)?;
    Ok(f)
}
