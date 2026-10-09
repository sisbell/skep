//! Segment files (names, listing, reclaim, directory fsync, the lock file).

use std::fs::{self, File, OpenOptions};
use std::io;
use std::path::{Path, PathBuf};

/// A journal segment file, named by its `firstSeq` (§1). Every operation over
/// a slice of these reads a neighbour's name as this segment's bound, so the
/// slice must be ascending by `first_seq` as [`list_segments`] produces it.
///
/// `first_seq` is private to this file: every coverage inference drawn from
/// segment names is drawn here — by [`inferred_last_seq`], [`scanned_above`],
/// [`reaches_genesis`] and [`reclaim_below`] — because a `firstSeq` read
/// anywhere else is an inference made away from the naming rule it rests on,
/// and [`reclaim_below`] deletes files on that inference. `path` is
/// `pub(super)`: the writer and the scan open the files. Two facts about
/// coverage leave this file — [`scanned_above`]'s yield, which the scan walks
/// and the format probe opens, and [`reaches_genesis`]'s answer — and the
/// names never do.
pub(crate) struct SegmentMeta {
    first_seq: u64,
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
/// Private for the reason [`SegmentMeta`]'s `first_seq` is: a coverage
/// inference drawn outside this file is drawn away from the naming rule it
/// rests on, and [`reclaim_below`] deletes files on it.
fn inferred_last_seq(segs: &[SegmentMeta], i: usize) -> Option<u64> {
    segs.get(i + 1).map(|next| next.first_seq.saturating_sub(1))
}

/// The segments a scan above `s_load` reads, each with its index in `segs`:
/// every closed segment whose inferred reach lies above the base, and the
/// active one always (§1/§7). The ONE statement of the skip rule — [`super::scan::scan`]
/// walks these and [`super::scan::first_sync_word`] probes the first of them, so the probe
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
///
/// Answers the bytes it removed: each qualifying segment's length, read
/// before its removal, summed — the figure a landing reports as the journal
/// bytes it reclaimed ([`crate::Kernel::last_reclaimed_bytes`]). `0` where
/// no segment qualified, so a landing that reclaims nothing says so rather
/// than nothing. A failure answers the error alone: what it removed before
/// failing is gone and uncounted, and the next landing's walk starts over.
pub(crate) fn reclaim_below(dir: &Path, floor: u64) -> io::Result<u64> {
    let segs = list_segments(dir)?;
    let mut reclaimed = 0u64;
    for (i, seg) in segs.iter().enumerate() {
        match inferred_last_seq(&segs, i) {
            Some(last) if last <= floor => {
                let len = fs::metadata(&seg.path)?.len();
                fs::remove_file(&seg.path)?;
                reclaimed = reclaimed.saturating_add(len);
            }
            _ => break,
        }
    }
    fsync_dir(dir)?;
    Ok(reclaimed)
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
/// The lock file is born `0600` on unix where this creates it, as every
/// file of the kernel's is; one that already stands keeps its mode.
pub(crate) fn acquire_journal_lock(dir: &Path) -> io::Result<File> {
    let mut opts = OpenOptions::new();
    opts.create(true).truncate(false).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let f = opts.open(dir.join("kernel.lock"))?;
    fs2::FileExt::try_lock_exclusive(&f)?;
    Ok(f)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::journal::{first_sync_word, FirstSyncWord};
    use tempfile::tempdir;

    #[test]
    fn only_the_name_the_writer_emits_is_a_segment() {
        // `seg-01.wal` and `seg-+7.wal` parse as 1 and 7 under a bare
        // `u64::from_str`, so without the round trip they alias live segments'
        // `firstSeq`s. Two entries at one coordinate sort adjacent, which
        // makes the first one's inferred `lastSeq` 0 — and `reclaim_below`
        // deletes every segment whose inference is at or below the floor.
        let dir = tempdir().unwrap();
        fs::write(segment_path(dir.path(), 1), b"").unwrap();
        fs::write(dir.path().join("seg-01.wal"), b"").unwrap();
        fs::write(dir.path().join("seg-+7.wal"), b"").unwrap();
        fs::write(dir.path().join("seg-0007.wal"), b"").unwrap();
        let segs = list_segments(dir.path()).unwrap();
        assert_eq!(segs.len(), 1, "only one spelling names a segment");
        assert_eq!(segs[0].first_seq, 1);
        assert_eq!(segs[0].path, segment_path(dir.path(), 1));
        // The active segment is never range-reclaimed, and it is the only one
        // here — so nothing is deleted, where an aliased name would have made
        // the real `seg-1.wal` a closed segment covering nothing — and the
        // answer says so: zero bytes, not nothing.
        assert_eq!(reclaim_below(dir.path(), 100).unwrap(), 0, "nothing qualified");
        assert!(segment_path(dir.path(), 1).exists(), "a live segment was reclaimed");
    }

    #[test]
    fn segments_list_in_first_seq_order_across_a_digit_boundary() {
        // A closed segment's reach is read off its SUCCESSOR's name; the scan
        // skips on that inference and `reclaim_below` deletes on it. Name
        // order and `firstSeq` order agree while names have one digit — and
        // `seg-10.wal` sorts BEFORE `seg-9.wal` by name.
        let dir = tempdir().unwrap();
        // Each file a different length, so the bytes reclaimed name WHICH
        // files went: seg-1 and seg-9 together, and neither of the others.
        for (first_seq, len) in [(10, 1_000), (1, 10), (100, 10_000), (9, 100)] {
            fs::write(segment_path(dir.path(), first_seq), vec![0u8; len]).unwrap();
        }
        let segs = list_segments(dir.path()).unwrap();
        let firsts: Vec<u64> = segs.iter().map(|seg| seg.first_seq).collect();
        assert_eq!(firsts, vec![1, 9, 10, 100]);
        assert_eq!(
            inferred_last_seq(&segs, 1),
            Some(9),
            "seg-9 ends where seg-10 begins"
        );
        // …and reclamation takes exactly the closed prefix that inference
        // admits, answering the lengths of the files it took.
        assert_eq!(reclaim_below(dir.path(), 9).unwrap(), 10 + 100, "seg-1's and seg-9's bytes");
        let left: Vec<u64> = list_segments(dir.path())
            .unwrap()
            .iter()
            .map(|seg| seg.first_seq)
            .collect();
        assert_eq!(left, vec![10, 100]);
    }

    #[test]
    fn the_skip_rule_passes_over_what_the_base_embodies_and_keeps_the_straddler_and_the_active() {
        // The one statement of which segments a scan above a base reads — the
        // scan walks them and the first-sync-word probe opens the first, so the
        // two agree by construction. A closed segment is passed over only when
        // its inferred reach lies at or below the base; one that STRADDLES the
        // base is read, and the active one always is.
        //
        // Each segment opens with a word of its own, so the probe's answer says
        // WHICH segment it opened: another format's stamp names a closed one,
        // and the empty active one is the scan's to classify.
        let dir = tempdir().unwrap();
        for (first_seq, opening) in [(1, &b"SKJ2"[..]), (5, &b"SKJ3"[..]), (9, &b""[..])] {
            fs::write(segment_path(dir.path(), first_seq), opening).unwrap();
        }
        let segs = list_segments(dir.path()).unwrap();
        let read_above = |s_load: u64| -> Vec<(usize, u64)> {
            scanned_above(&segs, s_load)
                .map(|(i, seg)| (i, seg.first_seq))
                .collect()
        };
        let probed = |s_load: u64| first_sync_word(&segs, s_load).unwrap();
        // Genesis reads every segment, and the probe opens seg-1.
        assert_eq!(read_above(0), vec![(0, 1), (1, 5), (2, 9)]);
        assert_eq!(probed(0), FirstSyncWord::Foreign(*b"SKJ2"));
        // seg-1 reaches 4, where seg-5 begins at 5: it straddles a base at 3…
        assert_eq!(read_above(3), vec![(0, 1), (1, 5), (2, 9)], "seg-1 straddles the base");
        assert_eq!(probed(3), FirstSyncWord::Foreign(*b"SKJ2"));
        // …and a base at 4 embodies it, so the scan and the probe begin at seg-5.
        assert_eq!(read_above(4), vec![(1, 5), (2, 9)], "seg-1 ends at the base");
        assert_eq!(probed(4), FirstSyncWord::Foreign(*b"SKJ3"));
        assert_eq!(read_above(8), vec![(2, 9)], "seg-5 ends at the base");
        assert_eq!(probed(8), FirstSyncWord::Scan);
        // The active segment has no successor to bound it, so it is always read.
        assert_eq!(read_above(100), vec![(2, 9)], "the active segment is always read");
        assert_eq!(probed(100), FirstSyncWord::Scan);
    }
}
