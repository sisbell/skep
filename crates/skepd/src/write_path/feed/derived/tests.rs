use super::*;

/// A file replays to exactly what was appended, torn tails end trust,
/// and coverage is the fence-or-record maximum.
///
/// The field name below is a LITERAL and not one of the per-file
/// constants, deliberately: this file's discipline is field-agnostic —
/// [`LineFile::append`] writes whatever it is given — so the test
/// that pins the discipline names a field no file's schema fixes.
#[test]
fn records_and_fences_replay_and_coverage_follows_them() {
    let dir = tempfile::tempdir().expect("tempdir");
    let head = 20;
    {
        let (mut f, replayed) =
            LineFile::open(dir.path(), MASKED_FILE, head, |_| true).expect("open");
        assert!(replayed.is_empty());
        assert_eq!(f.coverage(), 0);
        f.append(3, vec![]).expect("append");
        f.append(7, vec![("docs", Value::Array(vec![Value::String("1.0.2.0.2".into())]))])
            .expect("append");
        f.fence(9).expect("fence");
        assert_eq!(f.coverage(), 9);
        f.fence(5).expect("a fence below coverage is a no-op");
        assert_eq!(f.coverage(), 9);
    }
    let path = dir.path().join(MASKED_FILE);
    let contents = std::fs::read_to_string(&path).expect("read");
    assert_eq!(
        contents,
        "{\"at\":3}\n{\"at\":7,\"docs\":[\"1.0.2.0.2\"]}\n{\"covered\":9}\n",
        "lines are key-sorted and newline-terminated"
    );
    // A torn tail: truncated at open, coverage unaffected by it.
    std::fs::write(&path, format!("{contents}{{\"at\":11,\"do")).expect("tear");
    let (f, replayed) =
        LineFile::open(dir.path(), MASKED_FILE, head, |_| true).expect("reopen");
    assert_eq!(replayed.iter().map(|(at, _)| *at).collect::<Vec<_>>(), vec![3, 7]);
    assert_eq!(f.coverage(), 9);
    assert_eq!(std::fs::read_to_string(&path).expect("read"), contents, "the tail is cut");
    drop(f);
    // A record and a fence above the head are another journal's: dropped
    // and purged from the file.
    std::fs::write(&path, format!("{contents}{{\"at\":99}}\n{{\"covered\":999}}\n"))
        .expect("foreign lines");
    let (f, replayed) =
        LineFile::open(dir.path(), MASKED_FILE, head, |_| true).expect("reopen");
    assert_eq!(replayed.iter().map(|(at, _)| *at).collect::<Vec<_>>(), vec![3, 7]);
    assert_eq!(f.coverage(), 9, "a foreign fence does not raise coverage");
    let purged = std::fs::read_to_string(&path).expect("read");
    assert!(!purged.contains("99"), "the foreign lines are gone: {purged}");
    // Byte-identical to the file the APPENDS wrote: the purge copies this
    // journal's entry lines verbatim, drops every fence, and fences once
    // at the coverage.
    assert_eq!(purged, contents, "a purged file keeps this journal's lines as written");
}

/// A replay HOLDS only the entries its caller keeps — the attest store's
/// file is never compacted, so a replay holding every line would hold its
/// whole history at every open — while coverage still counts every
/// trusted line; and a foreign purge keeps every entry line of THIS
/// journal, verbatim, kept or not: in the attest store a line no caller
/// keeps lies below the floor and is an entry signature's only copy.
#[test]
fn a_replay_holds_only_what_its_caller_keeps_and_a_purge_drops_only_the_foreign() {
    let dir = tempfile::tempdir().expect("tempdir");
    {
        let (mut f, _) =
            LineFile::open(dir.path(), MASKED_FILE, 20, |_| true).expect("open");
        for at in [3, 7, 9] {
            f.append(at, vec![]).expect("append");
        }
    }
    let path = dir.path().join(MASKED_FILE);
    let ours = std::fs::read_to_string(&path).expect("read");
    let held = |entries: &Entries| entries.iter().map(|(at, _)| *at).collect::<Vec<_>>();
    let (f, entries) =
        LineFile::open(dir.path(), MASKED_FILE, 20, |at| at == 7).expect("reopen");
    assert_eq!(held(&entries), [7], "only the kept entry is held");
    assert_eq!(f.coverage(), 9, "coverage counts the lines no caller kept");
    drop(f);
    let unmoved = std::fs::read_to_string(&path).expect("read");
    assert_eq!(unmoved, ours, "a replay with nothing to purge writes nothing");
    std::fs::write(&path, format!("{ours}{{\"at\":99}}\n")).expect("a foreign line");
    let (f, entries) =
        LineFile::open(dir.path(), MASKED_FILE, 20, |at| at == 7).expect("purge");
    assert_eq!((held(&entries), f.coverage()), (vec![7], 9));
    assert_eq!(
        std::fs::read_to_string(&path).expect("read"),
        format!("{ours}{{\"covered\":9}}\n"),
        "the foreign line is gone, and 3 and 9, which no caller kept, survive verbatim"
    );
}

/// A file whose append FAILS takes nothing further, so its on-disk
/// coverage cannot rise past the position it lost.
///
/// Coverage is `max(fence, highest record)` and a position at or below it
/// with no record means "contributed nothing". Left running, the NEXT
/// successful append raises the claim over the gap, and the next open's
/// tail derivation starts above it and never revisits it — which for
/// `feed-index.log` classifies the position EMPTY, and an empty class is
/// a `[]`-docs entry the mask never masks: a draft write served to every
/// requester, carrying its op, its wall-clock time and the fingerprint of
/// the key that signed it, permanently.
#[test]
fn a_failed_append_stops_its_file_so_coverage_never_covers_the_gap() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut f = LineFile::over_unwritable(dir.path(), INDEX_FILE, 9);

    assert!(f.append(10, vec![]).is_err(), "a read-only handle refuses the line");
    assert_eq!(f.coverage(), 9, "and the refused position does not raise the claim");

    // The position AFTER the gap: accepted as an outcome, written
    // nowhere, and — the whole point — not counted as covered.
    f.append(11, vec![(INDEX_DOCS, Value::Array(vec![]))])
        .expect("a stopped file reports its failure once, at the append that raised it");
    assert_eq!(f.coverage(), 9, "a stopped file's coverage stays where the gap left it");
    f.fence(20).expect("a fence on a stopped file is a no-op");
    assert_eq!(f.coverage(), 9, "…and does not close the check over the gap either");
    assert_eq!(
        std::fs::read(dir.path().join(INDEX_FILE)).expect("read"),
        Vec::<u8>::new(),
        "nothing reached the file after the failure"
    );

    // What the next open therefore sees: coverage 9, so its tail
    // derivation re-covers 10 and everything above it.
    drop(f);
    let (reopened, entries) =
        LineFile::open(dir.path(), INDEX_FILE, 20, |_| true).expect("reopen");
    assert!(entries.is_empty());
    assert_eq!(reopened.coverage(), 0, "an empty file claims nothing");
}

/// The RECORD-time append swallows its failure and composes the stop rule:
/// a caller between a commit and its ack owes an ack whatever this file
/// does, so [`LineFile::append_or_report`] answers unit — a caller
/// cannot forget to handle what it is never given — and still leaves
/// coverage BELOW the position it lost, which is what the next open's
/// tail derivation reads. A version writing past [`LineFile::append`]
/// rather than through it would report and then claim the gap.
#[test]
fn the_record_time_append_swallows_its_failure_and_still_stops_the_file() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut f = LineFile::over_unwritable(dir.path(), INDEX_FILE, 9);

    f.append_or_report(10, vec![(INDEX_DOCS, Value::Array(vec![]))]);
    assert_eq!(f.coverage(), 9, "the lost position does not raise the claim");

    // The position after the gap, and the fence over it: both no-ops, so
    // the on-disk claim can never cover what was lost.
    f.append_or_report(11, vec![(INDEX_DOCS, Value::Array(vec![]))]);
    f.fence(20).expect("a fence on a stopped file is a no-op");
    assert_eq!(f.coverage(), 9, "a stopped file's coverage stays where the gap left it");
    assert_eq!(
        std::fs::read(dir.path().join(INDEX_FILE)).expect("read"),
        Vec::<u8>::new(),
        "nothing reached the file after the failure"
    );
}

/// A rewrite that fails PAST its rename — the new file in place, the
/// handle naming the replaced one — STOPS the file (P22; the settled
/// disposition for `record`: reported, never failing an op): the next
/// append and the next fence are no-ops, the on-disk file is the
/// rewritten whole one and nothing after, and the next open replays it
/// and re-derives from its fence. One that fails BEFORE its rename stops
/// nothing: the old file stands and the handle still appends to it.
#[test]
fn a_rewrite_failed_past_its_rename_stops_the_file_and_one_failed_before_it_does_not() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join(MASKED_FILE);
    let (mut f, _) = LineFile::open(dir.path(), MASKED_FILE, 20, |_| true).expect("open");
    f.append(3, vec![]).expect("append");
    f.append(7, vec![]).expect("append");

    // BEFORE the rename: a directory on the temp file's name refuses
    // the create, so nothing moved and nothing stopped.
    let tmp = dir.path().join(format!("{MASKED_FILE}.compact"));
    std::fs::create_dir(&tmp).expect("a directory on the temp's name");
    let refused = f
        .rewrite(vec![record_object(7, vec![])], 9)
        .expect_err("the temp file's create is refused");
    assert!(matches!(refused, RewriteFail::BeforeRename(_)), "{refused:?}");
    assert!(!f.is_stopped(), "the old file stands and the handle names it");
    f.append(8, vec![]).expect("…so it still takes a line");
    assert_eq!(
        std::fs::read_to_string(&path).expect("read"),
        "{\"at\":3}\n{\"at\":7}\n{\"at\":8}\n",
        "the old file, whole, with the append after the refused rewrite"
    );
    std::fs::remove_dir(&tmp).expect("clear the name");

    // PAST the rename: the seam refuses the reopen. The new file is in
    // place; the handle names the replaced one; the file stops.
    f.fail_next_rewrite_past_rename();
    let refused = f
        .rewrite(vec![record_object(7, vec![]), record_object(8, vec![])], 9)
        .expect_err("the reopen is refused");
    assert!(matches!(refused, RewriteFail::PastRename(_)), "{refused:?}");
    assert!(f.is_stopped(), "the file is stopped for the uptime");
    assert_eq!(f.coverage(), 9, "the fence the rewritten file carries");
    f.append(10, vec![]).expect("a stopped file answers Ok and writes nothing");
    f.append_or_report(11, vec![]);
    f.fence(20).expect("a fence on a stopped file is a no-op");
    assert_eq!(f.coverage(), 9, "the claim never rises past the stop");
    assert_eq!(
        std::fs::read_to_string(&path).expect("read"),
        "{\"at\":7}\n{\"at\":8}\n{\"covered\":9}\n",
        "the rewritten file, whole, and nothing after it"
    );
    drop(f);
    let (reopened, entries) =
        LineFile::open(dir.path(), MASKED_FILE, 20, |_| true).expect("reopen");
    assert_eq!(entries.iter().map(|(at, _)| *at).collect::<Vec<_>>(), vec![7, 8]);
    assert_eq!(reopened.coverage(), 9, "the next open re-derives from 10");
    assert!(!reopened.is_stopped());
}

/// The attest store's append (SO-I5 (d)) is synced through its own line,
/// ANSWERS its failure rather than reporting it, and on a stopped file
/// answers every later line an error, never `Ok`: a line the file did
/// not write is no durable line.
#[test]
fn a_synced_append_answers_its_failure_and_a_stopped_file_holds_no_line_durable() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (mut f, _) = LineFile::open(dir.path(), MASKED_FILE, 20, |_| true).expect("open");
    f.append_synced(3, vec![]).expect("a writable file takes and syncs the line");
    assert_eq!(f.synced(), 3, "the sync covers the line it follows");
    let mut f = LineFile::over_unwritable(dir.path(), INDEX_FILE, 3);
    assert!(f.append_synced(4, vec![]).is_err(), "a read-only handle refuses the line");
    assert!(f.append_synced(5, vec![]).is_err(), "a stopped file answers no later line Ok");
    assert_eq!((f.coverage(), f.synced()), (3, 0), "nothing covered past it, nothing synced");
}
