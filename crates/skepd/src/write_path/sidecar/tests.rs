use super::*;

/// A recorded line as every unsigned, termless write records one.
fn recorded(op: &str, docs: &[&str], time: u64, key: Option<&str>) -> CommitMeta {
    CommitMeta::Recorded {
        op: op.into(),
        docs: docs.iter().map(|d| d.to_string()).collect(),
        time,
        key: key.map(str::to_string),
        signed: None,
        terms: None,
    }
}

/// A line's bytes are fixed, key order included — the determinism
/// `/changes` inherits — and every line round-trips through the reader
/// that will replay it, each at the offset the replay reports.
#[test]
fn lines_are_key_sorted_and_replay_as_written() {
    let meta = recorded("insert", &["1.0.1.0.1"], 1_700_000_000_000, Some("bare"));
    assert_eq!(
        entry_line(8, &meta),
        b"{\"at\":8,\"docs\":[\"1.0.1.0.1\"],\"key\":\"bare\",\"op\":\"insert\",\"time\":1700000000000}\n"
    );
    // A pre-feature recorded line carries no `key` field at all —
    // omitted in the file, replayed as `None` below.
    let pre_feature = recorded("insert", &["1.0.1.0.1"], 1_700_000_000_001, None);
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
        (0, Record::Entry(at, CommitMeta::Recorded { op, docs, time, key, signed, terms })) => {
            assert_eq!((*at, op.as_str(), *time), (8, "insert", 1_700_000_000_000));
            assert_eq!(docs.as_slice(), ["1.0.1.0.1".to_string()]);
            assert_eq!(key.as_deref(), Some("bare"), "testimony replays as written");
            assert_eq!((*signed, terms), (None, &None), "unsigned, and an op carrying no terms");
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

/// The signedness and the op's own terms ride the line beside the five,
/// key-sorted, and replay as written: `signed` one of its two tokens, a
/// `delegate`'s pair, a `make_link`'s link, a `publish`'s count with its
/// extent or the birth shape's `null`. A `null` extent is the birth bit and
/// not an absence — it replays as `None` under a present `placed`.
#[test]
fn the_signedness_and_the_terms_replay_as_written() {
    let marker = CommitMeta::Recorded {
        op: "make_link".into(),
        docs: vec!["1.0.1.0.1".into()],
        time: 1_700_000_000_000,
        key: Some("ab".repeat(32)),
        signed: Some(Carrier::Marker),
        terms: Some(OpTerms::MakeLink { link: "1.0.1.0.1.0.2.3".into() }),
    };
    assert_eq!(
        String::from_utf8(entry_line(8, &marker)).expect("utf-8"),
        format!(
            "{{\"at\":8,\"docs\":[\"1.0.1.0.1\"],\"key\":\"{}\",\"link\":\"1.0.1.0.1.0.2.3\",\
             \"op\":\"make_link\",\"signed\":\"marker\",\"time\":1700000000000}}\n",
            "ab".repeat(32)
        )
    );
    let record_sig = CommitMeta::Recorded {
        op: "insert".into(),
        docs: vec!["1.0.1.0.1".into()],
        time: 1_700_000_000_001,
        key: Some("ab".repeat(32)),
        signed: Some(Carrier::RecordSig),
        terms: None,
    };
    // The credential record's `sig` carrier is spelled `record` in the file,
    // the token every such line already on disk carries — whatever the
    // variant is called.
    assert_eq!(
        String::from_utf8(entry_line(9, &record_sig)).expect("utf-8"),
        format!(
            "{{\"at\":9,\"docs\":[\"1.0.1.0.1\"],\"key\":\"{}\",\"op\":\"insert\",\
             \"signed\":\"record\",\"time\":1700000000001}}\n",
            "ab".repeat(32)
        )
    );
    let delegate = CommitMeta::Recorded {
        op: "delegate".into(),
        docs: vec![],
        time: 1_700_000_000_002,
        key: Some("bare".into()),
        signed: None,
        terms: Some(OpTerms::Delegate { new_prefix: "1.0.2".into(), new_id: 1 }),
    };
    assert_eq!(
        entry_line(9, &delegate),
        b"{\"at\":9,\"docs\":[],\"key\":\"bare\",\"new_id\":1,\"new_prefix\":\"1.0.2\",\"op\":\"delegate\",\"time\":1700000000002}\n"
    );
    let birth = CommitMeta::Recorded {
        op: "publish".into(),
        docs: vec!["1.0.1.0.1.1".into()],
        time: 1_700_000_000_003,
        key: Some("system".into()),
        signed: None,
        terms: Some(OpTerms::Publish { placed: "1".into(), base_extent: None }),
    };
    assert_eq!(
        entry_line(10, &birth),
        b"{\"at\":10,\"base_extent\":null,\"docs\":[\"1.0.1.0.1.1\"],\"key\":\"system\",\"op\":\"publish\",\"placed\":\"1\",\"time\":1700000000003}\n"
    );
    let based = CommitMeta::Recorded {
        op: "publish".into(),
        docs: vec!["1.0.1.0.1.2".into()],
        time: 1_700_000_000_004,
        key: Some("system".into()),
        signed: Some(Carrier::Marker),
        terms: Some(OpTerms::Publish { placed: "5".into(), base_extent: Some("3".into()) }),
    };

    let mut file: Vec<u8> = Vec::new();
    for (at, meta) in [(8, &marker), (9, &record_sig), (10, &delegate), (11, &birth), (12, &based)]
    {
        file.extend_from_slice(&entry_line(at, meta));
    }
    let (records, valid_end) = parse_records(&file);
    assert_eq!(valid_end, file.len(), "every whole line is trusted");
    let replayed = |i: usize| match &records[i] {
        (_, Record::Entry(_, CommitMeta::Recorded { signed, terms, .. })) => (*signed, terms.clone()),
        other => panic!("a recorded entry: {other:?}"),
    };
    assert_eq!(
        replayed(0),
        (Some(Carrier::Marker), Some(OpTerms::MakeLink { link: "1.0.1.0.1.0.2.3".into() }))
    );
    assert_eq!(replayed(1), (Some(Carrier::RecordSig), None));
    assert_eq!(
        replayed(2),
        (None, Some(OpTerms::Delegate { new_prefix: "1.0.2".into(), new_id: 1 }))
    );
    assert_eq!(
        replayed(3),
        (None, Some(OpTerms::Publish { placed: "1".into(), base_extent: None })),
        "the birth shape's null extent replays as None under a present count"
    );
    assert_eq!(
        replayed(4),
        (
            Some(Carrier::Marker),
            Some(OpTerms::Publish { placed: "5".into(), base_extent: Some("3".into()) })
        )
    );
}

/// A `signed` token no carrier spells, and a `delegate` line carrying one
/// of its pair without the other, are not lines this daemon wrote: trust
/// ends there. A term on a line of another op is an unknown key, ignored,
/// and a line written before the terms were recorded replays as an op
/// carrying none.
#[test]
fn a_torn_signedness_or_a_half_pair_ends_trust_and_foreign_terms_are_ignored() {
    let bare = entry_line(1, &CommitMeta::Bare);
    let torn_signed =
        b"{\"at\":2,\"docs\":[],\"op\":\"insert\",\"signed\":\"maybe\",\"time\":1}\n".to_vec();
    let mut file = bare.clone();
    file.extend_from_slice(&torn_signed);
    let (records, valid_end) = parse_records(&file);
    assert_eq!((records.len(), valid_end), (1, bare.len()), "an unknown carrier is torn");

    let half_pair =
        b"{\"at\":2,\"docs\":[],\"new_prefix\":\"1.0.2\",\"op\":\"delegate\",\"time\":1}\n".to_vec();
    let mut file = bare.clone();
    file.extend_from_slice(&half_pair);
    let (records, valid_end) = parse_records(&file);
    assert_eq!((records.len(), valid_end), (1, bare.len()), "half a pair is torn");

    let foreign_term = b"{\"at\":2,\"docs\":[],\"link\":\"1.0.2.0.1.0.2.1\",\"op\":\"insert\",\"time\":1}\n";
    let pre_terms = b"{\"at\":3,\"docs\":[],\"key\":\"bare\",\"op\":\"delegate\",\"time\":2}\n";
    let mut file = bare.clone();
    file.extend_from_slice(foreign_term);
    file.extend_from_slice(pre_terms);
    let (records, valid_end) = parse_records(&file);
    assert_eq!((records.len(), valid_end), (3, file.len()));
    assert!(
        matches!(&records[1], (_, Record::Entry(2, CommitMeta::Recorded { terms: None, .. }))),
        "a `link` on an insert line is ignored: {:?}",
        records[1]
    );
    assert!(
        matches!(&records[2], (_, Record::Entry(3, CommitMeta::Recorded { terms: None, signed: None, .. }))),
        "a delegate line from before the terms replays as an op carrying none: {:?}",
        records[2]
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
/// could not tell from a field this daemon does not know about; the op's
/// terms included, since a bare row's op is unknown. The file line omits
/// what the wire nulls; both are deliberate. `key`'s null is AUTH-1.52's
/// reserved lost-metadata meaning: a pre-feature record reads it exactly
/// as a bare position does. The docs rendered are the REDUCED list the
/// feed hands in — here the whole record's.
#[test]
fn wire_entries_null_what_the_file_line_omits() {
    let render = |meta: &CommitMeta, at: u64, reduced: &[&str]| -> String {
        serde_json::to_string(&meta.entry(
            at,
            reduced.iter().map(|d| d.to_string()).collect(),
            None,
        ))
        .expect("json")
    };
    let meta = recorded("insert", &["1.0.1.0.1"], 1_700_000_000_000, Some("bare"));
    assert_eq!(
        render(&meta, 8, &["1.0.1.0.1"]),
        r#"{"at":8,"docs":["1.0.1.0.1"],"key":"bare","op":"insert","time":1700000000000}"#
    );
    let pre_feature = recorded("insert", &["1.0.1.0.1"], 1_700_000_000_000, None);
    assert_eq!(
        render(&pre_feature, 8, &["1.0.1.0.1"]),
        r#"{"at":8,"docs":["1.0.1.0.1"],"key":null,"op":"insert","time":1700000000000}"#
    );
    assert_eq!(
        render(&CommitMeta::Bare, 3, &["1.0.1.0.1"]),
        r#"{"at":3,"base_extent":null,"docs":null,"key":null,"link":null,"new_id":null,"new_prefix":null,"op":null,"placed":null,"time":null}"#,
        "a bare entry's docs and terms are the reserved null whatever the feed hands in"
    );
    // What renders is the REDUCED list, never `Recorded.docs`: a
    // two-document record shown to a requester who may read one of them
    // carries that one. The rows above cannot see the difference — their
    // two lists are equal — so it is pinned here, on the field wire.md
    // tells clients to dispatch on.
    let straddle =
        recorded("nullify", &["1.0.1.0.1", "1.0.2.0.1"], 1_700_000_000_000, Some("bare"));
    assert_eq!(
        render(&straddle, 9, &["1.0.2.0.1"]),
        r#"{"at":9,"docs":["1.0.2.0.1"],"key":"bare","op":"nullify","time":1700000000000}"#,
        "the record's own second document is not rendered to a class that cannot read it"
    );
}

/// A BARE row nulls exactly the members the terms render: every variant's
/// [`OpTerms::members`] lie in [`OpTerms::MEMBER_NAMES`], and together they
/// are all of it — so a term a new op carries is nulled on a bare row, and
/// the list names no member no op renders. The match below is exhaustive
/// with no `_`, so a new variant stops this test compiling until it is named
/// here — the moment to add one of it to `one_of_each`.
#[test]
fn a_bare_row_nulls_exactly_the_members_the_terms_render() {
    let one_of_each = [
        OpTerms::Delegate { new_prefix: "1.0.2".into(), new_id: 1 },
        OpTerms::MakeLink { link: "1.0.1.0.1.0.2.1".into() },
        OpTerms::Publish { placed: "1".into(), base_extent: None },
    ];
    let mut rendered: Vec<&str> = Vec::new();
    for terms in &one_of_each {
        match terms {
            OpTerms::Delegate { .. } | OpTerms::MakeLink { .. } | OpTerms::Publish { .. } => {}
        }
        rendered.extend(terms.members().into_iter().map(|(name, _)| name));
    }
    rendered.sort_unstable();
    rendered.dedup();
    let mut nulled = OpTerms::MEMBER_NAMES.to_vec();
    nulled.sort_unstable();
    assert_eq!(rendered, nulled, "the bare row's null list is the terms' own members");
}

/// THE MEMBERS THAT ARE ABSENT RATHER THAN NULL (D12; the design record
/// §7.3 (i)): `key` is served iff the line records no carrier; `attest` is
/// the store's slot wherever one is held, `null` — LOST — where the line
/// records the marker filled and the store cannot answer, and absent
/// otherwise, a credential record deposit's row included; the op's terms are
/// present on the op that carries them and absent on every other op's row, a
/// `publish`'s birth extent rendering `null`.
#[test]
fn key_attest_and_the_terms_are_present_absent_or_null_by_the_rule() {
    let slot = Attestation::new(1, vec![0xab; 4]).expect("a slot");
    let fp = "cd".repeat(32);
    let marker = CommitMeta::Recorded {
        op: "make_link".into(),
        docs: vec!["1.0.1.0.1".into()],
        time: 1,
        key: Some(fp.clone()),
        signed: Some(Carrier::Marker),
        terms: Some(OpTerms::MakeLink { link: "1.0.1.0.1.0.2.3".into() }),
    };
    let text = |v: Value| serde_json::to_string(&v).expect("json");
    assert_eq!(
        text(marker.entry(8, vec!["1.0.1.0.1".into()], Some(&slot))),
        r#"{"at":8,"attest":{"alg":"mldsa65-ed25519","sig":"abababab"},"docs":["1.0.1.0.1"],"link":"1.0.1.0.1.0.2.3","op":"make_link","time":1}"#,
        "a marker-signed row: attest from the store, no key, the minted link"
    );
    assert_eq!(
        text(marker.entry(8, vec!["1.0.1.0.1".into()], None)),
        r#"{"at":8,"attest":null,"docs":["1.0.1.0.1"],"link":"1.0.1.0.1.0.2.3","op":"make_link","time":1}"#,
        "the marker recorded filled and the store silent: LOST, never absent"
    );
    let record_sig = CommitMeta::Recorded {
        op: "insert".into(),
        docs: vec!["1.0.1.0.1".into()],
        time: 2,
        key: Some(fp.clone()),
        signed: Some(Carrier::RecordSig),
        terms: None,
    };
    assert_eq!(
        text(record_sig.entry(9, vec!["1.0.1.0.1".into()], None)),
        r#"{"at":9,"docs":["1.0.1.0.1"],"op":"insert","time":2}"#,
        "a row its credential record's `sig` signs: neither key nor attest"
    );
    let unsigned = CommitMeta::Recorded {
        op: "delegate".into(),
        docs: vec![],
        time: 3,
        key: Some("bare".into()),
        signed: None,
        terms: Some(OpTerms::Delegate { new_prefix: "1.0.2".into(), new_id: 1 }),
    };
    assert_eq!(
        text(unsigned.entry(10, vec![], None)),
        r#"{"at":10,"docs":[],"key":"bare","new_id":1,"new_prefix":"1.0.2","op":"delegate","time":3}"#,
        "an unsigned row: key served, the pair by name, no attest"
    );
    let birth = CommitMeta::Recorded {
        op: "publish".into(),
        docs: vec!["1.1.0.1.0.2.1".into()],
        time: 4,
        key: Some("system".into()),
        signed: None,
        terms: Some(OpTerms::Publish { placed: "1".into(), base_extent: None }),
    };
    assert_eq!(
        text(birth.entry(11, vec!["1.1.0.1.0.2.1".into()], None)),
        r#"{"at":11,"base_extent":null,"docs":["1.1.0.1.0.2.1"],"key":"system","op":"publish","placed":"1","time":4}"#,
        "the head writer's birth-shape publish: system, the count, a null extent"
    );
    // A bare row the store answers: the slot is the journal's fact and is
    // served; the testimony stays lost.
    assert_eq!(
        text(CommitMeta::Bare.entry(12, vec![], Some(&slot))),
        r#"{"at":12,"attest":{"alg":"mldsa65-ed25519","sig":"abababab"},"base_extent":null,"docs":null,"key":null,"link":null,"new_id":null,"new_prefix":null,"op":null,"placed":null,"time":null}"#
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
    let serial = crate::serial::Serial::new();
    let serial = serial.lock();
    let mut log = CommitsLog::over_unwritable(dir.path(), 9);

    // The lost position: recorded in memory, refused by the file.
    let offset =
        log.record(&serial, 10, "insert", vec!["1.0.1.0.1".into()], "bare".into(), None, None);
    assert!(offset.is_some(), "the position is recorded whatever the file does");
    assert!(log.entries.contains_key(&10), "and this uptime answers it in full");

    // The condition clears: the very next append COULD succeed.
    log.file = OpenOptions::new().append(true).open(&path).expect("a writable handle");

    // The position after the gap — the one whose line would raise the
    // walk's floor over it. Accepted as an outcome, written nowhere.
    log.record(&serial, 11, "insert", vec!["1.0.1.0.2".into()], "bare".into(), None, None)
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
