use super::*;

/// [`LineFile::open`] over a door of the test's own, what the replay cut
/// and dropped beside the entries — what every claim below reads a replay
/// through.
fn open(
    dir: &Path,
    name: &'static str,
    head: u64,
    keep: impl Fn(u64) -> bool,
) -> io::Result<(LineFile, Entries, Replayed)> {
    LineFile::open(dir, name, head, keep, &Lines::new())
}

/// A file replays to exactly what was appended, torn tails end trust —
/// the cut ANSWERED, not said: the trusted end, the length before it and
/// the last trusted position, which the file's own coverage is — and
/// coverage is the fence-or-record maximum.
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
        let (mut f, replayed, answered) =
            open(dir.path(), MASKED_FILE, head, |_| true).expect("open");
        assert!(replayed.is_empty());
        assert_eq!(
            answered,
            Replayed::default(),
            "a file read whole answers no cut, no foreign line"
        );
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
    // A torn tail: truncated at open, coverage unaffected by it, and the
    // cut answered — the bytes, the last trusted position, which is the
    // fence's 9 and not the torn line's 11, and the torn line's own 11 beside
    // it, its digits standing whole.
    std::fs::write(&path, format!("{contents}{{\"at\":11,\"do")).expect("tear");
    let (f, replayed, answered) = open(dir.path(), MASKED_FILE, head, |_| true).expect("reopen");
    assert_eq!(replayed.iter().map(|(at, _)| *at).collect::<Vec<_>>(), vec![3, 7]);
    assert_eq!(f.coverage(), 9);
    assert_eq!(std::fs::read_to_string(&path).expect("read"), contents, "the tail is cut");
    let whole = contents.len() as u64;
    assert_eq!(answered.foreign, None, "a torn line is no foreign one");
    let cut =
        Cut { valid_end: whole, len: whole + 12, trusted: 9, first: Some(11), whole_after: None };
    assert_eq!(
        answered.cut,
        Some(cut),
        "the cut names the trusted end, the length before it (the 12-byte fragment after the \
         whole lines), the last trusted position and the position the torn line names"
    );
    assert_eq!(answered.kept, None, "a crash's torn line is cut and gone, nothing kept");
    assert!(
        !dir.path().join(format!("{MASKED_FILE}.cut-{whole}")).exists(),
        "no kept file for a torn line"
    );
    drop(f);
    // A record and a fence above the head are another journal's: dropped
    // and purged from the file.
    std::fs::write(&path, format!("{contents}{{\"at\":99}}\n{{\"covered\":999}}\n"))
        .expect("foreign lines");
    let (f, replayed, answered) = open(dir.path(), MASKED_FILE, head, |_| true).expect("reopen");
    assert_eq!(replayed.iter().map(|(at, _)| *at).collect::<Vec<_>>(), vec![3, 7]);
    assert_eq!(answered.cut, None, "foreign lines are whole lines: no cut");
    assert_eq!(
        answered.foreign,
        Some(EntryLines { lines: 1, first: 99, last: 99 }),
        "the entry line past the head is answered, with its position; a fence names none"
    );
    assert_eq!(f.coverage(), 9, "a foreign fence does not raise coverage");
    let purged = std::fs::read_to_string(&path).expect("read");
    assert!(!purged.contains("99"), "the foreign lines are gone: {purged}");
    // Byte-identical to the file the APPENDS wrote: the purge copies this
    // journal's entry lines verbatim, drops every fence, and fences once
    // at the coverage.
    assert_eq!(purged, contents, "a purged file keeps this journal's lines as written");
    // THE KEEP: the entry line past the head stands beside the file, byte
    // for byte, named by the byte it began at; the fence, derived, is not
    // among the kept bytes, and a torn cut kept nothing.
    assert_eq!(
        answered.foreign_kept,
        Some(KeptName { byte: whole, k: 0 }),
        "the purge's keep, named by the first foreign line's byte"
    );
    assert_eq!(
        std::fs::read_to_string(dir.path().join(format!("{MASKED_FILE}.cut-{whole}")))
            .expect("read"),
        "{\"at\":99}\n",
        "the entry line above the head, kept whole before the purge dropped it"
    );
    assert_eq!(answered.kept, None, "no cut, nothing kept for one");
}

/// Checks that a cut names what the last trusted position cannot, and keeps
/// a damaged line's bytes.
///
/// A torn line at the file's end names its own position where its `at`
/// stands whole — a tear inside the digits, zero-fill, or a position the
/// trusted lines cover or the head does not reach names none — and is cut
/// and gone; past a damaged whole line, whose digits are no witness, the
/// whole entry lines the cut takes with it are counted, the ones at or below
/// the head alone, and every byte from the trusted end on is kept beside the
/// file first.
#[test]
fn a_cut_names_the_torn_lines_position_or_the_whole_lines_it_takes() {
    let trusted_len = "{\"at\":3}\n{\"covered\":9}\n".len() as u64;
    let kept_names = |dir: &Path| -> Vec<String> {
        let mut names: Vec<String> = std::fs::read_dir(dir)
            .expect("list")
            .map(|e| e.expect("entry").file_name().to_string_lossy().into_owned())
            .filter(|name| name.contains(".cut-"))
            .collect();
        names.sort();
        names
    };
    let cut_of = |tail: &str| {
        let case = tempfile::tempdir().expect("tempdir");
        let path = case.path().join(MASKED_FILE);
        std::fs::write(&path, format!("{{\"at\":3}}\n{{\"covered\":9}}\n{tail}")).expect("write");
        let (_, _, replayed) = open(case.path(), MASKED_FILE, 20, |_| true).expect("open");
        let cut = replayed.cut.expect("a cut");
        assert_eq!(cut.trusted, 9, "the last trusted position is the fence's");
        // THE KEEP follows the class: a torn line's cut keeps nothing; a
        // damaged line's keeps every byte from the trusted end on.
        if tail.contains('\n') {
            let kept = replayed.kept.expect("a damaged line's cut is kept");
            assert_eq!(kept, KeptName { byte: trusted_len, k: 0 }, "{tail:?}");
            let kept_file = case.path().join(kept.of(MASKED_FILE));
            assert_eq!(std::fs::read(&kept_file).expect("read"), tail.as_bytes(), "{tail:?}");
            assert_eq!(kept_names(case.path()), vec![kept.of(MASKED_FILE)]);
        } else {
            assert_eq!(replayed.kept, None, "{tail:?}: a torn line keeps nothing");
            assert!(kept_names(case.path()).is_empty(), "{tail:?}");
        }
        (cut.first, cut.whole_after)
    };
    assert_eq!(cut_of("{\"at\":12,\"do"), (Some(12), None), "its digits stand whole");
    assert_eq!(cut_of("{\"at\":12}"), (Some(12), None), "whole but for its newline");
    assert_eq!(cut_of("{\"at\":1"), (None, None), "a tear inside the digits names nothing");
    assert_eq!(cut_of("\0\0\0\0"), (None, None), "zero-fill names nothing");
    assert_eq!(cut_of("{\"at\":5,"), (None, None), "a position the trusted lines cover");
    assert_eq!(cut_of("{\"at\":21,"), (None, None), "a position past the head");
    let damaged =
        "{\"at\":1x}\n{\"at\":13}\n{\"covered\":14}\n{\"at\":15}\n{\"at\":40}\n{\"at\":16";
    assert_eq!(
        cut_of(damaged),
        (None, Some(EntryLines { lines: 2, first: 13, last: 15 })),
        "a damaged line's digits are no witness; the whole entry lines after it at or below the \
         head are counted — the fence, the line past the head and the torn tail are none"
    );
}

/// Checks that a rewrite's temp file is said at the open and taken after.
///
/// The temp file found beside a line file is said at its open, once, with
/// its size — and the file's next rewrite takes it, as the line says
/// (`operations.md` §1.1 m8).
#[test]
fn a_compact_twin_is_said_at_the_open_and_the_next_rewrite_takes_it() {
    let dir = tempfile::tempdir().expect("tempdir");
    let twin = dir.path().join(format!("{STREAMS_FILE}.compact"));
    std::fs::write(&twin, b"{\"at\":3}\n").expect("a cut-short rewrite's temp");
    let lines = Lines::new();
    let (mut f, _, _) =
        LineFile::open(dir.path(), STREAMS_FILE, 20, |_| true, &lines).expect("open");
    assert_eq!(
        lines.said().lock().as_slice(),
        ["open: feed-streams.log.compact stands (9 bytes): a rewrite cut short before its rename \
          left it, feed-streams.log as it stood before that rewrite; its next rewrite overwrites \
          it"]
    );
    f.rewrite(vec![record_object(4, vec![])], 9).expect("the rewrite");
    assert!(!twin.exists(), "the rewrite's rename took the temp");
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
        let (mut f, _, _) = open(dir.path(), MASKED_FILE, 20, |_| true).expect("open");
        for at in [3, 7, 9] {
            f.append(at, vec![]).expect("append");
        }
    }
    let path = dir.path().join(MASKED_FILE);
    let ours = std::fs::read_to_string(&path).expect("read");
    let held = |entries: &Entries| entries.iter().map(|(at, _)| *at).collect::<Vec<_>>();
    let (f, entries, _) = open(dir.path(), MASKED_FILE, 20, |at| at == 7).expect("reopen");
    assert_eq!(held(&entries), [7], "only the kept entry is held");
    assert_eq!(f.coverage(), 9, "coverage counts the lines no caller kept");
    drop(f);
    let unmoved = std::fs::read_to_string(&path).expect("read");
    assert_eq!(unmoved, ours, "a replay with nothing to purge writes nothing");
    std::fs::write(&path, format!("{ours}{{\"at\":99}}\n")).expect("a foreign line");
    let (f, entries, _) = open(dir.path(), MASKED_FILE, 20, |at| at == 7).expect("purge");
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
    let (reopened, entries, _) = open(dir.path(), INDEX_FILE, 20, |_| true).expect("reopen");
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
/// and re-derives above its fence. One that fails BEFORE its rename stops
/// nothing: the old file stands and the handle still appends to it. The
/// stop is SAID ONCE PER UPTIME (`operations.md` §1.1 row 30), under
/// `failure:`, at its transition: a second rewrite past its rename on the
/// stopped file still runs — the file rewritten whole, the stop's position
/// moved to the newest fence — and says nothing more.
#[test]
fn a_rewrite_failed_past_its_rename_stops_the_file_and_one_failed_before_it_does_not() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join(MASKED_FILE);
    let lines = Lines::new();
    let (mut f, _, _) =
        LineFile::open(dir.path(), MASKED_FILE, 20, |_| true, &lines).expect("open");
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
    assert_eq!(f.stopped_since(), Some(9), "…since the fence the rewrite carried");
    assert_eq!(f.coverage(), 9, "the fence the rewritten file carries");
    let stop_line = "failure: feed-masked.log rewrite failed past its rename: test seam: the \
                     rewritten file's reopen refused; this file takes no further line, so the \
                     next open re-derives above its fence at position 9";
    assert_eq!(lines.said().lock().as_slice(), [stop_line], "the stop, said once, as a failure");
    f.append(10, vec![]).expect("a stopped file answers Ok and writes nothing");
    f.append_or_report(11, vec![]);
    f.fence(20).expect("a fence on a stopped file is a no-op");
    assert_eq!(f.coverage(), 9, "the claim never rises past the stop");
    assert_eq!(
        std::fs::read_to_string(&path).expect("read"),
        "{\"at\":7}\n{\"at\":8}\n{\"covered\":9}\n",
        "the rewritten file, whole, and nothing after it"
    );

    // A SECOND rewrite past its rename on the stopped file: it runs — the
    // file rewritten whole behind the new fence, the stop moved to it — and
    // says nothing more; the uptime's one line stands alone.
    f.fail_next_rewrite_past_rename();
    let refused = f.rewrite(vec![record_object(8, vec![])], 12).expect_err("refused again");
    assert!(matches!(refused, RewriteFail::PastRename(_)), "{refused:?}");
    assert_eq!(
        std::fs::read_to_string(&path).expect("read"),
        "{\"at\":8}\n{\"covered\":12}\n",
        "the second rewrite still ran"
    );
    assert_eq!((f.is_stopped(), f.stopped_since()), (true, Some(12)), "the stop moved");
    // The record read ONCE into a local: a failing assertion that took the
    // lock again for its message would deadlock instead of failing.
    let said = lines.said().lock().clone();
    assert_eq!(said.len(), 1, "FINDING (row 30): a second line for one stop:\n{}", said.join("\n"));
    drop(f);
    let (reopened, entries, _) =
        LineFile::open(dir.path(), MASKED_FILE, 20, |_| true, &lines).expect("reopen");
    assert_eq!(entries.iter().map(|(at, _)| *at).collect::<Vec<_>>(), vec![8]);
    assert_eq!(reopened.coverage(), 12, "the next open re-derives from 13");
    assert!(!reopened.is_stopped());
}

/// Checks row 32 on the door: a failed append stops the file, said once.
///
/// A derived file's first failed append (`operations.md` §1.1 row 32) —
/// the handle read-only, the one condition the stop rule is about — stops
/// the file and is said once through the classed door under `failure:`,
/// naming the file, the position, the cause and, the cause no full volume,
/// the volume, its device and the quota to check before the restart whose
/// open writes the file; the next append, which the stop takes, says
/// nothing more, and the claim on disk never rises past the stop.
#[test]
fn a_failed_append_is_said_once_through_the_door_and_the_stop_is_silent_after() {
    let dir = tempfile::tempdir().expect("tempdir");
    let lines = Lines::new();
    let (mut f, _, _) =
        LineFile::open(dir.path(), MASKED_FILE, 20, |_| true, &lines).expect("open");
    f.append(3, vec![]).expect("a writable file takes a line");
    f.make_unwritable().expect("the read-only handle");
    f.append_or_report(7, vec![]);
    assert_eq!((f.is_stopped(), f.stopped_since()), (true, Some(7)), "stopped at the failure");
    let said = lines.said().lock().clone();
    assert_eq!(said.len(), 1, "one line for the stop:\n{}", said.join("\n"));
    assert!(
        said[0].starts_with("failure: feed-masked.log append failed at position 7: "),
        "the class word, the file, the position, then the cause: {}",
        said[0]
    );
    assert!(
        said[0].ends_with(
            "; this file takes no further line until a restart, whose open re-derives it — the \
             board serves from memory, and nothing is lost; check the volume, its device and the \
             board user's quota before that restart: its open writes this file"
        ),
        "the stop, what serves, that nothing is lost and the act before the restart: {}",
        said[0]
    );
    f.append_or_report(8, vec![]);
    assert_eq!(lines.said().lock().len(), 1, "the stop takes the next line in silence");
    assert_eq!(f.coverage(), 3, "the claim never rises past the stop");
}

/// Checks that an owed sync is made through the file's second handle.
///
/// The attest store's append (SO-I5 (d)) owes its sync, made through the file's
/// second handle and settled with the file; it answers its failure rather than
/// reporting it, and on a stopped file answers every later line an error, never
/// `Ok`: a line the file did not write is no durable line. An owed sync that
/// failed stops the file at the position it was owed for.
#[test]
fn an_owed_sync_is_made_through_the_files_second_handle_and_a_stopped_file_owes_none() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (mut f, _, _) = open(dir.path(), MASKED_FILE, 20, |_| true).expect("open");
    let handle = f.sync_handle().expect("a second handle on the file");
    let owed = f.append_owing_sync(3, vec![]).expect("a writable file takes the line");
    assert_eq!(f.synced(), 0, "written, and owed its sync");
    handle.sync().expect("the second handle syncs the line the first wrote");
    f.settle(owed);
    assert_eq!(f.synced(), 3, "the sync covers the line it follows");
    let owed = f.append_owing_sync(7, vec![]).expect("the next line");
    f.stop_after_a_failed_sync(owed);
    assert_eq!(f.stopped_since(), Some(7), "a failed sync stops the file where it was owed");
    assert!(f.append_owing_sync(8, vec![]).is_err(), "a stopped file owes no later line a sync");
    let mut f = LineFile::over_unwritable(dir.path(), INDEX_FILE, 3);
    assert!(f.append_owing_sync(4, vec![]).is_err(), "a read-only handle refuses the line");
    assert!(f.append_owing_sync(5, vec![]).is_err(), "a stopped file answers no later line Ok");
    assert_eq!((f.coverage(), f.synced()), (3, 0), "nothing covered past it, nothing synced");
}

/// A refused open NAMES ITS FILE, the kind kept (`operations.md` §1.1 row
/// 2): a file this process may not read refuses the replay with
/// `{name}: Permission denied (os error 13)` under `PermissionDenied` — the
/// text the daemon's `change-feed sidecar: {e}` arm carries whole.
#[test]
#[cfg(unix)]
fn a_refused_open_names_its_file_and_keeps_the_kind() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join(STREAMS_FILE);
    std::fs::write(&path, b"{\"at\":3}\n").expect("a line");
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o000)).expect("mode 000");
    if File::open(&path).is_ok() {
        // A privileged user reads a mode-000 file: nothing to prove here.
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).expect("restore");
        return;
    }
    let refused = open(dir.path(), STREAMS_FILE, 20, |_| true).err().expect("the open is refused");
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).expect("restore");
    assert_eq!(refused.kind(), io::ErrorKind::PermissionDenied, "the kind is kept");
    assert_eq!(refused.to_string(), "feed-streams.log: Permission denied (os error 13)");
}

/// A file out of position order is seen at the replay — the flag, the
/// entries in file order — and rewritten sorted on demand, every record
/// kept and the fence at its coverage; the reopen sees it in order. The
/// read by position rests on the order, so no page depends on the order a
/// file's lines happen to sit in.
#[test]
fn a_file_out_of_order_is_seen_and_rewritten_sorted_keeping_every_record() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join(STREAMS_FILE);
    std::fs::write(
        &path,
        "{\"at\":9,\"owners\":[\"1.0.2\"]}\n{\"at\":3,\"owners\":[\"1.0.3\"]}\n{\"covered\":6}\n\
         {\"at\":12,\"owners\":[\"1.0.2\"]}\n",
    )
    .expect("the file");
    let (mut f, entries, replayed) = open(dir.path(), STREAMS_FILE, 20, |_| true).expect("open");
    assert!(replayed.disordered, "position 3 after 9");
    let ats = |entries: &Entries| entries.iter().map(|(at, _)| *at).collect::<Vec<_>>();
    assert_eq!(ats(&entries), vec![9, 3, 12], "replayed in file order");
    assert_eq!(f.coverage(), 12);
    f.sort_in_place().expect("sorted");
    let text = std::fs::read_to_string(&path).expect("the file");
    assert_eq!(
        text,
        "{\"at\":3,\"owners\":[\"1.0.3\"]}\n{\"at\":9,\"owners\":[\"1.0.2\"]}\n\
         {\"at\":12,\"owners\":[\"1.0.2\"]}\n{\"covered\":12}\n",
        "every record, sorted, the fence at the coverage"
    );
    let (_, entries, replayed) = open(dir.path(), STREAMS_FILE, 20, |_| true).expect("reopen");
    assert!(!replayed.disordered, "in order now");
    assert_eq!(ats(&entries), vec![3, 9, 12]);
}
