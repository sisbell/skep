use super::*;

/// A line's bytes are fixed, key order included — the determinism
/// `/changes` inherits — and every line round-trips through the reader
/// that will replay it, each at the offset the replay reports.
#[test]
fn lines_are_key_sorted_and_replay_as_written() {
    let meta = CommitMeta::Recorded {
        op: "insert".into(),
        docs: vec!["1.0.1.0.1".into()],
        time: 1_700_000_000_000,
        key: Some("bare".into()),
    };
    assert_eq!(
        entry_line(8, &meta),
        b"{\"at\":8,\"docs\":[\"1.0.1.0.1\"],\"key\":\"bare\",\"op\":\"insert\",\"time\":1700000000000}\n"
    );
    // A pre-feature recorded line carries no `key` field at all —
    // omitted in the file, replayed as `None` below.
    let pre_feature = CommitMeta::Recorded {
        op: "insert".into(),
        docs: vec!["1.0.1.0.1".into()],
        time: 1_700_000_000_001,
        key: None,
    };
    assert_eq!(
        entry_line(9, &pre_feature),
        b"{\"at\":9,\"docs\":[\"1.0.1.0.1\"],\"op\":\"insert\",\"time\":1700000000001}\n"
    );
    assert_eq!(entry_line(3, &CommitMeta::Bare), b"{\"at\":3}\n");
    assert_eq!(min_since_line(2048), b"{\"min_since\":2048}\n");

    let mut file: Vec<u8> = Vec::new();
    file.extend_from_slice(&entry_line(8, &meta));
    let second_offset = file.len();
    file.extend_from_slice(&entry_line(9, &pre_feature));
    file.extend_from_slice(&entry_line(3, &CommitMeta::Bare));
    file.extend_from_slice(&min_since_line(2048));
    let (records, valid_end) = parse_records(&file);
    assert_eq!(valid_end, file.len(), "every whole line is trusted");
    assert_eq!(records.len(), 4);
    match &records[0] {
        (0, Record::Entry(at, CommitMeta::Recorded { op, docs, time, key })) => {
            assert_eq!((*at, op.as_str(), *time), (8, "insert", 1_700_000_000_000));
            assert_eq!(docs.as_slice(), ["1.0.1.0.1".to_string()]);
            assert_eq!(key.as_deref(), Some("bare"), "testimony replays as written");
        }
        other => panic!("first line is a recorded entry at offset 0: {other:?}"),
    }
    assert!(
        matches!(&records[1], (o, Record::Entry(9, CommitMeta::Recorded { key: None, .. })) if *o == second_offset),
        "a pre-feature line replays with no testimony, at its own offset: {:?}",
        records[1]
    );
    assert!(
        matches!(records[2], (_, Record::Entry(3, CommitMeta::Bare))),
        "third line is a bare entry: {:?}",
        records[2]
    );
    assert!(
        matches!(records[3], (_, Record::MinSince(2048))),
        "fourth line names the smallest admissible since: {:?}",
        records[3]
    );
}

/// Both spellings of the min-since record read, and reading one does
/// not end trust in the lines behind it — a data dir carrying the
/// `floor` spelling replays whole rather than truncating there.
#[test]
fn both_spellings_of_the_min_since_record_replay() {
    let mut file: Vec<u8> = Vec::new();
    file.extend_from_slice(b"{\"floor\":2048}\n");
    file.extend_from_slice(&entry_line(2049, &CommitMeta::Bare));
    let (records, valid_end) = parse_records(&file);
    assert_eq!(valid_end, file.len(), "the `floor` spelling does not end trust");
    assert!(
        matches!(records[0], (_, Record::MinSince(2048))),
        "a `floor` line is a min-since record: {:?}",
        records[0]
    );
    assert!(
        matches!(records[1], (_, Record::Entry(2049, _))),
        "the line behind it still replays: {:?}",
        records[1]
    );
}

/// A position is recorded or it is bare; a line naming some of the
/// three fields is not one this daemon wrote, so trust ends there —
/// the same treatment an unparseable line gets, and the reopen walk
/// re-covers the position as bare rather than serving half a record.
#[test]
fn a_half_recorded_line_ends_trust() {
    let mut file: Vec<u8> = Vec::new();
    file.extend_from_slice(&entry_line(1, &CommitMeta::Bare));
    file.extend_from_slice(b"{\"at\":2,\"op\":\"insert\"}\n");
    file.extend_from_slice(&entry_line(3, &CommitMeta::Bare));
    let (records, valid_end) = parse_records(&file);
    assert_eq!(records.len(), 1, "trust ends at the half-recorded line");
    assert_eq!(valid_end, entry_line(1, &CommitMeta::Bare).len(), "and truncation cuts there");
    // A `null`-valued field is absence, not a half record.
    let (records, _) = parse_records(b"{\"at\":4,\"docs\":null,\"op\":null,\"time\":null}\n");
    assert!(matches!(records.as_slice(), [(_, Record::Entry(4, CommitMeta::Bare))]));
}

/// The wire entry names every field, a bare position's as explicit
/// `null` — never invented, and never merely absent, which a client
/// could not tell from a field this daemon does not know about. The
/// file line omits what the wire nulls; both are deliberate. `key`'s
/// null is AUTH-1.52's reserved lost-metadata meaning: a pre-feature
/// record reads it exactly as a bare position does. The docs rendered
/// are the REDUCED list the feed hands in — here the whole record's.
#[test]
fn wire_entries_null_what_the_file_line_omits() {
    let meta = CommitMeta::Recorded {
        op: "insert".into(),
        docs: vec!["1.0.1.0.1".into()],
        time: 1_700_000_000_000,
        key: Some("bare".into()),
    };
    assert_eq!(
        serde_json::to_string(&meta.entry(8, vec!["1.0.1.0.1".into()])).expect("json"),
        r#"{"at":8,"docs":["1.0.1.0.1"],"key":"bare","op":"insert","time":1700000000000}"#
    );
    let pre_feature = CommitMeta::Recorded {
        op: "insert".into(),
        docs: vec!["1.0.1.0.1".into()],
        time: 1_700_000_000_000,
        key: None,
    };
    assert_eq!(
        serde_json::to_string(&pre_feature.entry(8, vec!["1.0.1.0.1".into()])).expect("json"),
        r#"{"at":8,"docs":["1.0.1.0.1"],"key":null,"op":"insert","time":1700000000000}"#
    );
    assert_eq!(
        serde_json::to_string(&CommitMeta::Bare.entry(3, vec!["1.0.1.0.1".into()]))
            .expect("json"),
        r#"{"at":3,"docs":null,"key":null,"op":null,"time":null}"#,
        "a bare entry's docs are the reserved null whatever the feed hands in"
    );
    // What renders is the REDUCED list, never `Recorded.docs`: a
    // two-document record shown to a requester who may read one of them
    // carries that one. The rows above cannot see the difference — their
    // two lists are equal — so it is pinned here, on the field wire.md
    // tells clients to dispatch on.
    let straddle = CommitMeta::Recorded {
        op: "nullify".into(),
        docs: vec!["1.0.1.0.1".into(), "1.0.2.0.1".into()],
        time: 1_700_000_000_000,
        key: Some("bare".into()),
    };
    assert_eq!(
        serde_json::to_string(&straddle.entry(9, vec!["1.0.2.0.1".into()])).expect("json"),
        r#"{"at":9,"docs":["1.0.2.0.1"],"key":"bare","op":"nullify","time":1700000000000}"#,
        "the record's own second document is not rendered to a class that cannot read it"
    );
}

/// A log whose append FAILS takes nothing further, so the next open's
/// walk starts BELOW the position it lost.
///
/// [`CommitsLog::open`] reconstructs `(low, head]` where `low` is the
/// HIGHEST surviving entry, so a position lost beneath a LATER
/// SUCCESSFUL append — the condition clearing, a quota raised or a
/// device recovered — is re-derived by nothing: absent from `entries`,
/// and every feed source is a subset of those keys, so the committed
/// write is missing from `/changes` at every class, permanently, with no
/// error anywhere. That is strictly worse than the bare entry
/// [`CommitsLog::record`]'s failure path promises, which discloses its
/// position and nothing else.
///
/// The recovery is what the test must construct, and it is why the
/// read-only seam alone cannot state this: under it BOTH appends fail
/// and the file is empty either way. So the handle is swapped for a
/// writable one between the two, which is exactly the condition
/// clearing — and the two behaviours then differ in the file's own
/// contents.
#[test]
fn a_failed_append_stops_the_log_so_the_reopen_walk_starts_below_the_gap() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join(SIDECAR_FILE);
    let lock = parking_lot::Mutex::new(());
    let serial = crate::write_path::SerialGuard::over(&lock);
    let mut log = CommitsLog::over_unwritable(dir.path(), 9);

    // The lost position: recorded in memory, refused by the file.
    let offset = log.record(&serial, 10, "insert", vec!["1.0.1.0.1".into()], "bare".into());
    assert!(offset.is_some(), "the position is recorded whatever the file does");
    assert!(log.entries.contains_key(&10), "and this uptime answers it in full");

    // The condition clears: the very next append COULD succeed.
    log.file = OpenOptions::new().append(true).open(&path).expect("a writable handle");

    // The position after the gap — the one whose line would raise the
    // walk's floor over it. Accepted as an outcome, written nowhere.
    log.record(&serial, 11, "insert", vec!["1.0.1.0.2".into()], "bare".into())
        .expect("a stopped log still records: the ack is owed either way");
    assert_eq!(
        std::fs::read(&path).expect("read"),
        Vec::<u8>::new(),
        "nothing reached the file once it stopped — not the lost line, and NOT the \
         later line that would have claimed the gap was covered"
    );

    // What a reopen therefore sees, which is the whole point: no entry,
    // so `low` is `min_since` and the walk re-covers 10 AND 11 as bare
    // entries. A file claiming 11 alone would put `low` at 11 and leave
    // 10 reachable by nothing.
    let (records, _) = parse_records(&std::fs::read(&path).expect("read"));
    let claimed: Vec<u64> = records
        .iter()
        .filter_map(|(_, r)| match r {
            Record::Entry(at, _) => Some(*at),
            Record::MinSince(_) => None,
        })
        .collect();
    assert_eq!(claimed, Vec::<u64>::new(), "the file claims no position above the gap");
}
