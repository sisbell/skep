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
    assert_eq!(entry_line(3, &CommitMeta::bare()), b"{\"at\":3}\n");
    assert_eq!(min_since_line(2048), b"{\"min_since\":2048}\n");

    let mut file: Vec<u8> = Vec::new();
    file.extend_from_slice(&entry_line(8, &meta));
    let second_offset = file.len();
    file.extend_from_slice(&entry_line(9, &pre_feature));
    file.extend_from_slice(&entry_line(3, &CommitMeta::bare()));
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
        matches!(&records[2], (_, Record::Entry(3, CommitMeta::Bare { journal })) if journal.is_empty()),
        "third line is a bare entry the journal answered nothing for: {:?}",
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

/// THE JOURNAL'S ANSWER RIDES THE BARE LINE (as7-F3; SO-I5 (e)) under one
/// `journal` member, in the wire's own spelling of the terms, and replays as
/// written — a `delegate`'s pair with its op, a `publish`'s count with its
/// extent (`null` the birth shape), a deposited link with the op unnamed, a
/// `nullify` named with no term — while a line answering nothing is the
/// bare line as it always was. A `journal` that is no object, or one naming
/// half a pair, is torn.
#[test]
fn the_journals_answer_rides_the_bare_line_and_replays_as_written() {
    let delegate = CommitMeta::Bare {
        journal: JournalTerms {
            op: Some("delegate".into()),
            terms: Some(OpTerms::Delegate { new_prefix: "1.0.2".into(), new_id: 1 }),
        },
    };
    assert_eq!(
        entry_line(4, &delegate),
        b"{\"at\":4,\"journal\":{\"new_id\":1,\"new_prefix\":\"1.0.2\",\"op\":\"delegate\"}}\n"
    );
    let birth = CommitMeta::Bare {
        journal: JournalTerms {
            op: Some("publish".into()),
            terms: Some(OpTerms::Publish { placed: "1".into(), base_extent: None }),
        },
    };
    assert_eq!(
        entry_line(5, &birth),
        b"{\"at\":5,\"journal\":{\"base_extent\":null,\"op\":\"publish\",\"placed\":\"1\"}}\n"
    );
    let link = CommitMeta::Bare {
        journal: JournalTerms {
            op: None,
            terms: Some(OpTerms::MakeLink { link: "1.0.1.0.1.0.2.3".into() }),
        },
    };
    assert_eq!(entry_line(6, &link), b"{\"at\":6,\"journal\":{\"link\":\"1.0.1.0.1.0.2.3\"}}\n");
    let nullify =
        CommitMeta::Bare { journal: JournalTerms { op: Some("nullify".into()), terms: None } };
    assert_eq!(entry_line(7, &nullify), b"{\"at\":7,\"journal\":{\"op\":\"nullify\"}}\n");

    let mut file: Vec<u8> = Vec::new();
    for (at, meta) in [(4, &delegate), (5, &birth), (6, &link), (7, &nullify)] {
        file.extend_from_slice(&entry_line(at, meta));
    }
    let (records, valid_end) = parse_records(&file);
    assert_eq!(valid_end, file.len(), "every whole line is trusted");
    let replayed = |i: usize| match &records[i] {
        (_, Record::Entry(_, CommitMeta::Bare { journal })) => journal.clone(),
        other => panic!("a bare entry: {other:?}"),
    };
    for (i, meta) in [delegate, birth, link, nullify].iter().enumerate() {
        let CommitMeta::Bare { journal } = meta else { unreachable!() };
        assert_eq!(&replayed(i), journal, "line {i} replays as written");
    }

    let bare = entry_line(1, &CommitMeta::bare());
    for torn in [
        &b"{\"at\":2,\"journal\":\"delegate\"}\n"[..],
        &b"{\"at\":2,\"journal\":{\"new_prefix\":\"1.0.2\",\"op\":\"delegate\"}}\n"[..],
        &b"{\"at\":2,\"journal\":{\"link\":\"1.0.1.0.1.0.2.3\",\"placed\":\"1\"}}\n"[..],
    ] {
        let mut file = bare.clone();
        file.extend_from_slice(torn);
        let (records, valid_end) = parse_records(&file);
        assert_eq!((records.len(), valid_end), (1, bare.len()), "torn: {}", String::from_utf8_lossy(torn));
    }
}

/// A `signed` token no carrier spells, and a `delegate` line carrying one
/// of its pair without the other, are not lines this daemon wrote: trust
/// ends there. A term on a line of another op is an unknown key, ignored,
/// and a line written before the terms were recorded replays as an op
/// carrying none.
#[test]
fn a_torn_signedness_or_a_half_pair_ends_trust_and_foreign_terms_are_ignored() {
    let bare = entry_line(1, &CommitMeta::bare());
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
    file.extend_from_slice(&entry_line(2049, &CommitMeta::bare()));
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
    file.extend_from_slice(&entry_line(1, &CommitMeta::bare()));
    file.extend_from_slice(b"{\"at\":2,\"op\":\"insert\"}\n");
    file.extend_from_slice(&entry_line(3, &CommitMeta::bare()));
    let (records, valid_end) = parse_records(&file);
    assert_eq!(records.len(), 1, "trust ends at the half-recorded line");
    assert_eq!(valid_end, entry_line(1, &CommitMeta::bare()).len(), "and truncation cuts there");
    // A `null`-valued field is absence, not a half record.
    let (records, _) = parse_records(b"{\"at\":4,\"docs\":null,\"op\":null,\"time\":null}\n");
    assert!(matches!(records.as_slice(), [(_, Record::Entry(4, CommitMeta::Bare { .. }))]));
}

/// The wire entry names every field, a bare position's testimony as explicit
/// `null` — never invented, and never merely absent, which a client could
/// not tell from a field this daemon does not know about; the op's terms
/// included where the journal answers nothing for the row, and AS THE
/// JOURNAL ANSWERS THEM where it does (as7-F3): the op's own members where
/// the op is named, exactly as the recorded row carries them; `link` alone
/// where a link was deposited and the op left unnamed, the members no link
/// write carries absent. The file line omits what the wire nulls; both are
/// deliberate. `key`'s null is AUTH-1.52's reserved lost-metadata meaning: a
/// pre-feature record reads it exactly as a bare position does. The docs
/// rendered are the REDUCED list the feed hands in — here the whole
/// record's.
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
        render(&CommitMeta::bare(), 3, &["1.0.1.0.1"]),
        r#"{"at":3,"base_extent":null,"docs":null,"key":null,"link":null,"new_id":null,"new_prefix":null,"op":null,"placed":null,"time":null}"#,
        "a bare entry's docs and terms are the reserved null whatever the feed hands in"
    );
    // The journal's answers on a bare row: the op's own members, as the
    // recorded row carries them — a `delegate`'s pair, a `publish`'s count
    // and extent — and nothing of the other ops'; `link` alone where a link
    // was deposited and the op is unnamed; a named op carrying no term
    // renders none.
    let journaled = |op: Option<&str>, terms: Option<OpTerms>| CommitMeta::Bare {
        journal: JournalTerms { op: op.map(str::to_string), terms },
    };
    assert_eq!(
        render(
            &journaled(Some("delegate"), Some(OpTerms::Delegate { new_prefix: "1.0.2".into(), new_id: 1 })),
            4,
            &[]
        ),
        r#"{"at":4,"docs":null,"key":null,"new_id":1,"new_prefix":"1.0.2","op":"delegate","time":null}"#,
        "a bare delegate row: the journal's pair, the testimony still null"
    );
    assert_eq!(
        render(
            &journaled(Some("publish"), Some(OpTerms::Publish { placed: "5".into(), base_extent: Some("3".into()) })),
            5,
            &[]
        ),
        r#"{"at":5,"base_extent":"3","docs":null,"key":null,"op":"publish","placed":"5","time":null}"#,
        "a bare publish row: the shot's terms off the placing record"
    );
    assert_eq!(
        render(&journaled(None, Some(OpTerms::MakeLink { link: "1.0.1.0.1.0.2.3".into() })), 6, &[]),
        r#"{"at":6,"docs":null,"key":null,"link":"1.0.1.0.1.0.2.3","op":null,"time":null}"#,
        "a deposited link, the op unnamed: `link`, the members no link write carries absent"
    );
    assert_eq!(
        render(&journaled(Some("nullify"), None), 7, &[]),
        r#"{"at":7,"docs":null,"key":null,"op":"nullify","time":null}"#,
        "a named op that carries no term renders none"
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

/// A BARE row the journal answers nothing for nulls exactly the members the
/// terms render: every variant's [`OpTerms::members`] lie in
/// [`OpTerms::MEMBER_NAMES`], and together they are all of it — so a term a
/// new op carries is nulled on such a row, and the list names no member no
/// op renders. The match below is exhaustive with no `_`, so a new variant
/// stops this test compiling until it is named here — the moment to add one
/// of it to `one_of_each`.
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
        text(CommitMeta::bare().entry(12, vec![], Some(&slot))),
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
    // ROW 31 ON THE DOOR (`operations.md` §1.1 row 31): the failure said
    // ONCE through the classed door under `failure:` — the position, the
    // cause, the stop, the recovery and the act owed before it.
    let said = log.lines.said().lock().clone();
    assert_eq!(said.len(), 1, "one line for the stop:\n{}", said.join("\n"));
    assert!(
        said[0].starts_with("failure: commits.log append failed at position 10: "),
        "the class word, the file, the position, then the cause: {}",
        said[0]
    );
    assert!(
        said[0].ends_with(
            "; this file takes no further line, so the next open re-derives from 10 as bare \
             entries; every write until then is held in memory alone, its key and its time lost \
             at that open — restart soon; check the volume, its device and the board user's \
             quota before that restart: its open writes this file"
        ),
        "the stop, the recovery, what it costs until the restart and, no full volume, the \
         cause checked before it: {}",
        said[0]
    );

    // The condition clears: the very next append COULD succeed.
    log.fail_appends = false;

    // The position after the gap — the one whose line would raise the
    // walk's floor over it. Accepted as an outcome, written nowhere.
    log.record(&serial, 11, "insert", vec!["1.0.1.0.2".into()], "bare".into(), None, None)
        .expect("a stopped log still records: the ack is owed either way");
    assert_eq!(log.lines.said().lock().len(), 1, "the stop takes the next line in silence");
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

/// THE LANDING IS ONE REWRITE THAT KEEPS EVERY LINE, AND FILE ORDER IS
/// POSITION ORDER (the operations design §3.3 step 2; "file order is
/// position order"; the record of events kept forever): a log whose region
/// `(24, 30]` is pending over a file holding entries 20 and 24 — the state a
/// torn open leaves — takes a write at 31 in memory alone (HELD, no line
/// appended, `head_time` answering for the head in the region: none), and
/// LANDS three walked boundaries with the walk's own fence at 25 — the
/// journal refused below it: one rewrite, the file's two lines copied
/// verbatim first, then the `min_since` line at the walk's fence, then
/// every landed entry ascending — the walked three bare with the journal's
/// answer where it had one, the held write whole. No line is dropped: the
/// two below the fence stay in the file, served by no route, and the
/// resident entries hold what stands above the fence; the region cleared,
/// the first line held the first walked boundary above the fence.
#[test]
fn the_landing_is_one_rewrite_in_position_order_keeping_every_line() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join(SIDECAR_FILE);
    let e20 = recorded("insert", &["1.0.1.0.1"], 1, Some("bare"));
    let e24 = recorded("insert", &["1.0.1.0.1"], 2, Some("bare"));
    let old = [entry_line(20, &e20), entry_line(24, &e24)].concat();
    std::fs::write(&path, &old).expect("the torn file");
    let entries = [(20, e20), (24, e24)].into_iter().collect();
    let mut log = CommitsLog::pending_over(dir.path(), entries, 24, 30);
    assert_eq!(log.pending_region(), Some((24, 30)));
    assert_eq!(log.head_time(), None, "the head's record lies in the region");
    assert_eq!(log.floor(), Some(20), "the first line held");
    let serial = crate::serial::Serial::new();
    let serial = serial.lock();

    let held = log.record(&serial, 31, "insert", vec!["1.0.1.0.2".into()], "bare".into(), None, None);
    assert_eq!(held, Some(Recorded::Held), "a write while the region pends is held");
    assert_eq!(std::fs::read(&path).expect("read"), old, "no line appended");
    assert!(log.entries.contains_key(&31), "in memory");
    assert!(log.head_time().is_some(), "the held write is above the head: head_time is its");
    assert_eq!(log.counts(), (3, 0), "counted as held");

    let walked = vec![
        Walked { at: 26, docs: Some(vec![]), journal: JournalTerms { op: Some("version".into()), terms: None } },
        Walked { at: 28, docs: None, journal: JournalTerms::default() },
        Walked { at: 30, docs: Some(vec![]), journal: JournalTerms::default() },
    ];
    let folded = log.fold_the_walk(&walked, Some(25));
    assert_eq!((folded, log.pending_region()), (Some(((24, 30), 25)), None));
    assert_eq!(std::fs::read(&path).expect("read"), old, "the fold writes nothing");
    assert_eq!((log.min_since, log.entries.contains_key(&20)), (25, false), "the fence moved");
    assert_eq!(log.floor(), Some(26), "the first line held above the fence");
    assert_eq!(log.counts(), (4, 3), "the three walked and the held write");
    log.write_the_landing(24).expect("the landing's one rewrite");
    let bytes = std::fs::read(&path).expect("read");
    assert!(bytes.starts_with(&old), "the file's own lines first, verbatim");
    let (records, valid_end) = parse_records(&bytes);
    assert_eq!(valid_end, bytes.len(), "every line whole");
    assert!(matches!(records[2].1, Record::MinSince(25)), "the fence after them: {:?}", records[2]);
    let ats: Vec<u64> = records
        .iter()
        .filter_map(|(_, r)| match r {
            Record::Entry(at, _) => Some(*at),
            Record::MinSince(_) => None,
        })
        .collect();
    assert_eq!(ats, [20, 24, 26, 28, 30, 31], "position order; nothing dropped");
    assert!(
        matches!(&records[3].1, Record::Entry(26, CommitMeta::Bare { journal }) if journal.op.as_deref() == Some("version"))
    );
    assert!(
        matches!(&records[6].1, Record::Entry(31, CommitMeta::Recorded { .. })),
        "the held write whole"
    );
    assert!(log.entries().keys().eq([26, 28, 30, 31].iter()), "resident: above the fence");
    assert_eq!(log.len(), bytes.len() as u64, "the length the next append lands at");
}

/// Checks the words of the walk's three lines, its refusal and the landing's.
///
/// Each is a pure value: `open:` with the covered edge, the count and the
/// head; `progress:` with the position, the head, the boundary's place in
/// the list and the elapsed milliseconds; `landing:` with the file and the
/// region, the walked, the unclassified, the elapsed and the lock held, the
/// fence where it stands inside the region and `in memory alone` where the
/// rewrite was refused; the journal's refusal with its account, the fence it
/// moved and the act that re-covers the positions, said while the walk goes
/// on; and the rewrite refused before its rename, naming the edge the next
/// open walks from, what the stop costs and the act owed before the restart,
/// a full volume's and any other cause's.
#[test]
fn the_walks_three_lines_and_the_landings_refusal_render_the_ruled_words() {
    assert_eq!(
        WalkOpenLine { covered: 24, boundaries: 6, head: 30 }.to_string(),
        "commits.log covers to position 24; walking 6 boundaries to position 30"
    );
    let progress =
        WalkProgressLine { position: 26, head: 30, boundary: 2, boundaries: 6, elapsed_ms: 1_204 };
    assert_eq!(progress.to_string(), "the walk at position 26 of 30, boundary 2 of 6, 1204 ms in");
    let landing = |fence, in_memory_alone| {
        WalkLandingLine {
            low: 24,
            head: 30,
            walked: 6,
            unclassified: 1,
            elapsed_ms: 2_500,
            held_ms: 40,
            fence,
            in_memory_alone,
        }
        .to_string()
    };
    let figures = "6 boundaries walked, 1 of them unclassifiable and served to every class, in \
                   2500 ms; the landing held the change feed's lock 40 ms";
    assert_eq!(
        landing(None, false),
        format!("commits.log re-covered positions (24, 30]: {figures}")
    );
    assert_eq!(
        landing(Some(27), true),
        format!(
            "commits.log re-covered positions (24, 30] in memory alone: {figures}; the fence \
             stands at position 27: /changes answers 410 history_reclaimed for every since below it"
        )
    );
    let refusal = WalkRefusal { at: 26, list: false, account: "journal corrupt at rest".into() };
    let restore = "once the walk lands the change feed answers 410 history_reclaimed for every \
                   since below position 26; the walk goes on, and its landing writes that fence \
                   into commits.log, which a segment restored alone does not move — to re-cover \
                   the positions, stop the daemon, put back the segment the account names and \
                   commits.log from a copy taken before this open, and start again (RUNBOOK §2)";
    assert_eq!(
        WalkRefusedLine { refusal: &refusal, fence: 26 }.to_string(),
        format!(
            "commits.log's walk: the journal refused position 26 (journal corrupt at rest): \
             {restore}"
        )
    );
    let refusal = WalkRefusal { list: true, ..refusal };
    assert_eq!(
        WalkRefusedLine { refusal: &refusal, fence: 26 }.to_string(),
        format!(
            "commits.log's walk: the journal refused the boundaries above position 26 (journal \
             corrupt at rest): {restore}"
        )
    );
    let refused = |e: &io::Error| LandingRefusedLine { low: 24, error: e }.to_string();
    let lost = "the file stands as it was and takes no further line, so the next open walks again \
                from position 24; every write since this open is held in memory alone, its key and \
                its time lost at that open — restart soon";
    assert_eq!(
        refused(&io::Error::new(io::ErrorKind::StorageFull, "no room")),
        format!(
            "commits.log: the walk's landing rewrite failed before its rename: the volume is full \
             (no room); {lost}; free room before that restart: its open writes this file"
        )
    );
    assert_eq!(
        refused(&io::Error::other("Input/output error (os error 5)")),
        format!(
            "commits.log: the walk's landing rewrite failed before its rename: Input/output error \
             (os error 5); {lost}; check the volume, its device and the board user's quota before \
             that restart: its open writes this file"
        )
    );
}

/// Checks the cause's words and the foreign lines', each a pure value.
///
/// A full volume reads in the operator's words, the act a stopped file's
/// line ends with room before the restart; any other kind reads in the
/// error's own words, its act the volume, its device and the quota checked
/// before it; and the lines past the head an open dropped are counted with
/// their positions and what they carry.
#[test]
fn the_cause_and_the_foreign_lines_render_the_ruled_words() {
    let full = io::Error::new(io::ErrorKind::StorageFull, "No space left on device (os error 28)");
    let cause = IoCause(&full);
    assert_eq!(cause.to_string(), "the volume is full (No space left on device (os error 28))");
    assert_eq!(
        cause.before_the_restart(),
        "; free room before that restart: its open writes this file"
    );
    let other = io::Error::other("Input/output error (os error 5)");
    assert_eq!(IoCause(&other).to_string(), "Input/output error (os error 5)");
    assert_eq!(
        IoCause(&other).before_the_restart(),
        "; check the volume, its device and the board user's quota before that restart: its open \
         writes this file"
    );
    let foreign = [31, 29, 33].into_iter().fold(None, |held, at| Some(EntryLines::with(held, at)));
    assert_eq!(foreign, Some(EntryLines { lines: 3, first: 29, last: 33 }));
    let line = ForeignLinesLine {
        name: SIDECAR_FILE,
        foreign: foreign.expect("three"),
        head: 28,
        what: "testimony",
        kept: KeptName { byte: 4_096, k: 0 },
        journal_kept: Vec::new(),
    };
    assert_eq!(
        line.to_string(),
        "commits.log held 3 lines past the journal's head at position 28 (positions 29–33): \
         dropped and kept in commits.log.cut-4096 — a live copy taken after its journal holds \
         them; after a journal tail cut that took acknowledged commits they are the cut commits' \
         testimony",
        "the kept file named, and never a copy taken before the open"
    );
    // The attest store's: the journal's kept files are a second copy of the
    // signatures, named where the journal's open kept any at this start; a
    // standing name moved the keep to `….1`.
    let attest = ForeignLinesLine {
        name: "feed-attest.log",
        foreign: foreign.expect("three"),
        head: 28,
        what: "signatures",
        kept: KeptName { byte: 4_096, k: 1 },
        journal_kept: vec!["seg-7.wal.cut-0".to_string()],
    };
    assert_eq!(
        attest.to_string(),
        "feed-attest.log held 3 lines past the journal's head at position 28 (positions 29–33): \
         dropped and kept in feed-attest.log.cut-4096.1 — a live copy taken after its journal \
         holds them; after a journal tail cut that took acknowledged commits they are the cut \
         commits' signatures, whose markers the journal's kept file seg-7.wal.cut-0 holds too"
    );
    let two = ForeignLinesLine {
        journal_kept: vec!["seg-7.wal.cut-0".to_string(), "seg-9.wal.cut-0".to_string()],
        ..attest
    };
    assert!(
        two.to_string().ends_with(
            "signatures, whose markers the journal's kept files seg-7.wal.cut-0 and \
             seg-9.wal.cut-0 hold too"
        ),
        "{two}"
    );
    assert_eq!(KeptName { byte: 12, k: 0 }.of("commits.log"), "commits.log.cut-12");
    assert_eq!(KeptName { byte: 12, k: 2 }.of("commits.log"), "commits.log.cut-12.2");
}

/// THE KEEP: what an open drops in class B stands beside the file first
/// (`operations.md` §3.6).
///
/// The dropped bytes are written whole to `{file}.cut-{byte}` — a standing
/// name passed over for `….{k}`, never written over — born owner-only and
/// synced; the routine every line file's open shares.
#[test]
fn dropped_lines_are_kept_beside_the_file_under_the_next_free_name() {
    let dir = tempfile::tempdir().expect("tempdir");
    let kept = keep_dropped_lines(dir.path(), "x.log", 40, &b"{\"at\":4}\n{\"at\":5}\n"[..])
        .expect("the keep");
    assert_eq!(kept, KeptName { byte: 40, k: 0 });
    let path = dir.path().join("x.log.cut-40");
    assert_eq!(std::fs::read(&path).expect("read"), b"{\"at\":4}\n{\"at\":5}\n");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&path).expect("stat").permissions().mode() & 0o7777;
        assert_eq!(mode, 0o600, "born owner-only");
    }
    let again = keep_dropped_lines(dir.path(), "x.log", 40, &b"other bytes"[..]).expect("again");
    assert_eq!(again, KeptName { byte: 40, k: 1 }, "a standing name is passed over");
    assert_eq!(
        std::fs::read(&path).expect("read"),
        b"{\"at\":4}\n{\"at\":5}\n",
        "never written over"
    );
    assert_eq!(std::fs::read(dir.path().join("x.log.cut-40.1")).expect("read"), b"other bytes");
}

/// THE LINES PAST THE HEAD LEAVE THE FILE at the open that drops them, and
/// the open says so: a `commits.log` naming positions a fresh journal never
/// reached replays without them, is rewritten without them — so a later
/// commit at one of their positions cannot replay as theirs — and says the
/// count and the positions once, under `open:`.
#[test]
fn the_lines_past_the_head_leave_the_file_and_are_said_once() {
    let dir = tempfile::tempdir().expect("tempdir");
    let engine = crate::commits::tests::fsync_engine(dir.path());
    let head = engine.kernel().current_seq().0;
    let path = dir.path().join(SIDECAR_FILE);
    let past = [head + 3, head + 1];
    let lines_past: Vec<u8> = past
        .iter()
        .flat_map(|&at| entry_line(at, &recorded("insert", &["1.0.1.0.1"], 1, Some("bare"))))
        .collect();
    std::fs::write(&path, &lines_past).expect("a copy taken after its journal");
    let lines = Lines::new();
    let log = CommitsLog::open(dir.path(), &engine, &lines).expect("the open");
    assert!(log.entries().is_empty(), "never served");
    let (records, _) = parse_records(&std::fs::read(&path).expect("read"));
    assert!(
        records.iter().all(|(_, r)| !matches!(r, Record::Entry(..))),
        "the file holds none of them: {records:?}"
    );
    assert_eq!(
        lines.said().lock().as_slice(),
        [format!(
            "open: commits.log held 2 lines past the journal's head at position {head} (positions \
             {}–{}): dropped and kept in commits.log.cut-0 — a live copy taken after its journal \
             holds them; after a journal tail cut that took acknowledged commits they are the \
             cut commits' testimony",
            head + 1,
            head + 3
        )],
        "said once, with the count, the positions and the kept file"
    );
    // THE KEEP: the dropped lines stand beside the file, byte for byte as
    // they were written — testimony no marker holds a copy of.
    assert_eq!(
        std::fs::read(dir.path().join("commits.log.cut-0")).expect("the kept file"),
        lines_past,
        "the lines above the head, kept whole before the rewrite dropped them"
    );
}

/// THE WORDS of this file's open-time and once-per-open lines, each a pure
/// value: row 9's head with the last trusted position and the bytes
/// ([`CutHead`]), `commits.log`'s own case after it ([`LogCutLine`]); row
/// 11's count with the first position and the case — `commits.log`'s
/// demotion, the index's split of the positions its own testimony rescues
/// from the bare ones nothing does ([`MalformedNamesLine`]); the file absent
/// on a journal that holds commits, with the region the walk re-covers
/// ([`LogBegunAfreshLine`]); and a rewrite's temp file found at an open
/// (m8, [`CompactTwinLine`]).
#[test]
fn the_cut_and_the_malformed_names_render_the_ruled_words() {
    let cut = Cut {
        valid_end: 4_096,
        len: 4_106,
        trusted: 32,
        first: None,
        whole_after: None,
        fence_alone: false,
    };
    assert_eq!(
        CutHead { name: SIDECAR_FILE, cut }.to_string(),
        "commits.log: trust ends at position 32 (byte 4096 of 4106); the 10 bytes after it are \
         cut"
    );
    assert_eq!(
        LogCutLine { cut, kept: None }.to_string(),
        "commits.log: trust ends at position 32 (byte 4096 of 4106); the 10 bytes after it are \
         cut; the cut part is re-derived as bare entries",
        "a torn line's cut: nothing kept"
    );
    let damaged = Cut { whole_after: Some(EntryLines { lines: 2, first: 33, last: 35 }), ..cut };
    let kept = Some(KeptName { byte: 4_096, k: 0 });
    assert_eq!(
        LogCutLine { cut: damaged, kept }.to_string(),
        "commits.log: trust ends at position 32 (byte 4096 of 4106); the 10 bytes after it are \
         cut, kept in commits.log.cut-4096; the cut part is re-derived as bare entries; the cut \
         took 2 whole lines with it, positions 33–35: their keys and times are LOST to the feed \
         and stand in commits.log.cut-4096 alone",
        "a damaged line's cut names the kept file"
    );
    assert_eq!(
        LogCutLine { cut: damaged, kept: None }.to_string(),
        "commits.log: trust ends at position 32 (byte 4096 of 4106); the 10 bytes after it are \
         cut; the cut part is re-derived as bare entries; the cut took 2 whole lines with it, \
         positions 33–35: their keys and times are LOST unless the board directory's backup is \
         restored"
    );
    let malformed = |file, case| MalformedNamesLine { file, positions: 3, first: 24, case };
    assert_eq!(
        malformed(SIDECAR_FILE, MalformedCase::Demoted).to_string(),
        "commits.log: 3 positions carry malformed document names, the first at position 24; \
         those positions serve as bare entries"
    );
    assert_eq!(
        malformed("feed-index.log", MalformedCase::Index { bare: 1 }).to_string(),
        "feed-index.log: 3 positions carry malformed document names, the first at position 24; \
         2 of them answer from commits.log's testimony, and 1 bare ones stay unclassified, each \
         shown to any class that reaches it",
        "a recorded position answers from the log's own testimony; a bare one has none"
    );
    assert_eq!(
        LogBegunAfreshLine { low: 2_048, head: 2_100 }.to_string(),
        "commits.log was absent at this open and is begun afresh: every position in (2048, \
         2100] is walked from the journal as a bare entry, its op recovered where the journal \
         names it — its key and its time are LOST unless the board directory's backup is \
         restored"
    );
    assert_eq!(
        CompactTwinLine { name: SIDECAR_FILE, bytes: 812 }.to_string(),
        "commits.log.compact stands (812 bytes): a rewrite cut short before its rename left it, \
         commits.log as it stood before that rewrite; its next rewrite overwrites it"
    );
}

/// Checks that a cut past a damaged line keeps and names what it takes.
///
/// A `commits.log` whose third line is damaged — whole, ended by its
/// newline, and no record — is cut there at the open, the damaged line and
/// every line after it kept beside the file first, byte for byte, in
/// `commits.log.cut-{byte}`; the whole lines after it go with the cut: the
/// two at or below the head are counted with their positions, the one past
/// the head is not, and the line names the kept file where what they held
/// stands. A torn line at the file's end takes no whole line with it, keeps
/// nothing, and the cut line says none.
#[test]
fn a_cut_past_a_damaged_line_names_the_whole_lines_it_takes() {
    use skep_kernel::{CheckpointPolicy, Durability, KernelConfig, SaltSource};
    use skep_namespace::{system_account, SYSTEM_PRINCIPAL};

    let engine = Engine::open(KernelConfig {
        durability: Durability::InMemory,
        checkpoint: CheckpointPolicy::Manual,
        salt: SaltSource::Seeded(0),
    })
    .expect("in-memory genesis cannot fail");
    while engine.kernel().current_seq().0 < 6 {
        engine
            .namespace()
            .create_new_document(SYSTEM_PRINCIPAL, &system_account(), Some(false))
            .expect("the mint commits");
    }
    let head = engine.kernel().current_seq().0;
    let line = |at| entry_line(at, &recorded("insert", &["1.0.1.0.1"], 1, Some("bare")));
    let trusted = [line(1), line(2)].concat();
    let cut_line = |file: &[u8]| -> (Vec<String>, Option<Vec<u8>>) {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(dir.path().join(SIDECAR_FILE), file).expect("the file");
        let lines = Lines::new();
        CommitsLog::open(dir.path(), &engine, &lines).expect("the open");
        let on_disk = std::fs::read(dir.path().join(SIDECAR_FILE)).expect("read");
        assert_eq!(on_disk, trusted, "cut at the last whole record");
        let said = lines.said().lock().clone();
        let kept =
            std::fs::read(dir.path().join(format!("commits.log.cut-{}", trusted.len()))).ok();
        let others: Vec<String> = std::fs::read_dir(dir.path())
            .expect("list")
            .map(|e| e.expect("entry").file_name().to_string_lossy().into_owned())
            .filter(|name| {
                name.contains(".cut-") && *name != format!("commits.log.cut-{}", trusted.len())
            })
            .collect();
        assert!(others.is_empty(), "no other kept file: {others:?}");
        (said.into_iter().filter(|l| l.contains("trust ends at")).collect(), kept)
    };
    let head_words =
        format!("failure: commits.log: trust ends at position 2 (byte {} of ", trusted.len());
    let dropped = [b"{\"at\":3,\"docs\":[\n".to_vec(), line(4), line(5), line(head + 7)].concat();
    let damaged = [trusted.clone(), dropped.clone()].concat();
    let (said, kept) = cut_line(&damaged);
    assert_eq!(said.len(), 1, "the cut said once: {said:?}");
    assert!(said[0].starts_with(&head_words), "{}", said[0]);
    let kept_name = format!("commits.log.cut-{}", trusted.len());
    assert!(
        said[0].ends_with(&format!(
            "after it are cut, kept in {kept_name}; the cut part is re-derived as bare entries; \
             the cut took 2 whole lines with it, positions 4–5: their keys and times are LOST to \
             the feed and stand in {kept_name} alone"
        )),
        "the kept file named, the two whole lines at or below the head counted: {}",
        said[0]
    );
    assert_eq!(kept, Some(dropped), "the damaged line and every line after it, kept whole");
    let torn = [trusted.clone(), b"{\"at\":3,\"do".to_vec()].concat();
    let (said, kept) = cut_line(&torn);
    assert_eq!(said.len(), 1, "the cut said once: {said:?}");
    assert!(
        said[0].starts_with(&head_words)
            && said[0].ends_with("; the cut part is re-derived as bare entries"),
        "a torn line takes no whole line with it: {}",
        said[0]
    );
    assert_eq!(kept, None, "a crash's torn line is cut and gone, nothing kept");
}

/// Checks that a progress line is due every so many steps or so long.
///
/// Whichever comes first, counted from the last line said — the walk's and
/// the open's classification's one cadence ([`ProgressCadence`]).
#[test]
fn a_progress_line_is_due_every_so_many_steps_or_so_long() {
    let long = Duration::from_secs(3_600);
    let mut cadence = ProgressCadence::new();
    let due: Vec<usize> = (1..=7).filter(|&done| cadence.due(done, 3, long)).collect();
    assert_eq!(due, [3, 6], "every third step, counted from the last line");
    let mut cadence = ProgressCadence::new();
    assert!(cadence.due(1, 1_000, Duration::ZERO), "the interval passed: due at the first step");
    assert!(!cadence.due(2, 1_000, long), "and counted afresh from that line");
}

/// Checks that an absent log and a rewrite's temp file are said at the open.
///
/// `commits.log` absent on a journal that holds commits is said, once, with
/// the region the walk re-covers — its testimony gone, a copy that still
/// holds it worth restoring — and a rewrite's temp file beside it is said
/// with its size; the same open over a fresh journal, nothing to walk, says
/// neither.
#[test]
fn an_absent_log_and_a_compact_twin_are_said_at_the_open() {
    use skep_kernel::{CheckpointPolicy, Durability, KernelConfig, SaltSource};
    use skep_namespace::{system_account, SYSTEM_PRINCIPAL};

    let open = || {
        Engine::open(KernelConfig {
            durability: Durability::InMemory,
            checkpoint: CheckpointPolicy::Manual,
            salt: SaltSource::Seeded(0),
        })
        .expect("in-memory genesis cannot fail")
    };
    let fresh = tempfile::tempdir().expect("tempdir");
    let lines = Lines::new();
    CommitsLog::open(fresh.path(), &open(), &lines).expect("a fresh open");
    assert!(lines.said().lock().is_empty(), "a fresh journal walks nothing and says nothing");

    let engine = open();
    for _ in 0..3 {
        engine
            .namespace()
            .create_new_document(SYSTEM_PRINCIPAL, &system_account(), Some(false))
            .expect("the mint commits");
    }
    let head = engine.kernel().current_seq().0;
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::write(dir.path().join("commits.log.compact"), b"{\"at\":1}\n").expect("a temp");
    let lines = Lines::new();
    let log = CommitsLog::open(dir.path(), &engine, &lines).expect("the open");
    assert_eq!(log.pending_region(), Some((0, head)), "the whole journal to walk");
    assert_eq!(
        lines.said().lock().as_slice(),
        [
            "open: commits.log.compact stands (9 bytes): a rewrite cut short before its rename \
             left it, commits.log as it stood before that rewrite; its next rewrite overwrites it"
                .to_string(),
            format!(
                "failure: commits.log was absent at this open and is begun afresh: every position \
                 in (0, {head}] is walked from the journal as a bare entry, its op recovered \
                 where the journal names it — its key and its time are LOST unless the board \
                 directory's backup is restored"
            ),
        ],
        "the temp first, at the head of the open, then the absence"
    );
}

/// The malformed names are demoted as the open's scan reads them and SAID
/// ONCE with their count and the first position (`operations.md` §1.1 row
/// 11), under `failure:` — three half-recorded positions among five lines,
/// one line said, the file kept as written; no malformed name, no line. The
/// scan's demotion is [`demoted`]'s, which the feed's reader below the window
/// runs on each line it reads, so the two agree on every entry.
#[test]
fn malformed_names_are_said_once_with_the_count_and_the_first_position() {
    let entries = [
        (20, recorded("insert", &["1.0.1.0.1"], 1, Some("bare"))),
        (24, recorded("insert", &["1.0"], 2, Some("bare"))),
        (29, recorded("make_link", &["1.0.2.0.2", "not an address"], 3, Some("bare"))),
        (31, CommitMeta::bare()),
        (32, recorded("insert", &["1.0"], 4, Some("bare"))),
    ];
    for (at, meta) in &entries {
        let (demoted_meta, was) = demoted(meta.clone());
        let malformed = [24, 29, 32].contains(at);
        assert_eq!(was, malformed, "{at}: demoted iff a name is malformed");
        assert_eq!(matches!(demoted_meta, CommitMeta::Bare { .. }), malformed || *at == 31, "{at}");
    }
    // The same lines as a file at or below a head of 40, scanned as the open
    // scans it: the three counted with the first, every line counted, the
    // demoted held bare, the file untouched.
    let dir = tempfile::tempdir().expect("tempdir");
    let file: Vec<u8> = entries.iter().flat_map(|(at, meta)| entry_line(*at, meta)).collect();
    std::fs::write(dir.path().join(SIDECAR_FILE), &file).expect("the file");
    let said_by_scan = {
        let scanned =
            scan(&dir.path().join(SIDECAR_FILE), 40, 40).expect("the scan").expect("the file stands");
        assert_eq!(scanned.malformed, Some((3, 24)), "three demoted, the first at 24");
        assert_eq!((scanned.count, scanned.bare), (5, 4), "every line counted, the demoted bare");
        scanned
            .window
            .iter()
            .map(|(at, m)| (*at, matches!(m, CommitMeta::Bare { .. })))
            .collect::<Vec<_>>()
    };
    assert_eq!(said_by_scan, [(20, false), (24, true), (29, true), (31, true), (32, true)]);
    assert_eq!(
        std::fs::read(dir.path().join(SIDECAR_FILE)).expect("read"),
        file,
        "the file keeps the lines as written"
    );
    let line = MalformedNamesLine {
        file: SIDECAR_FILE,
        positions: 3,
        first: 24,
        case: MalformedCase::Demoted,
    };
    assert_eq!(
        line.to_string(),
        "commits.log: 3 positions carry malformed document names, the first at position 24; \
         those positions serve as bare entries"
    );
}

/// A recorded line at `at` naming `carrier` as its entry's signature.
fn carried(at: u64, carrier: Option<Carrier>) -> Vec<u8> {
    let meta = CommitMeta::Recorded {
        op: "insert".into(),
        docs: vec!["1.0.1.0.1".into()],
        time: at,
        key: Some("ab".repeat(32)),
        signed: carrier,
        terms: None,
    };
    entry_line(at, &meta)
}

/// Checks the scan's witness: the last line whose marker slot can be filled.
///
/// A line recording the `marker` carrier can name a filled slot, and so can a
/// bare line, its testimony lost, and a line demoted for a malformed name; an
/// unsigned line and one the record's own `sig` signs name an empty slot. A
/// fence makes every line before it dead to this build, a witness among
/// them, and a line past the head is another journal's.
#[test]
fn the_scan_finds_the_last_line_whose_slot_can_be_filled() {
    let witness = |lines: Vec<Vec<u8>>| {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join(SIDECAR_FILE);
        std::fs::write(&path, lines.concat()).expect("the file");
        scan(&path, 20, 20).expect("the scan").expect("the file stands").last_possibly_attested
    };
    let demoted = entry_line(10, &recorded("insert", &["1.0"], 10, Some("bare")));
    assert_eq!(
        witness(vec![
            carried(3, Some(Carrier::Marker)),
            carried(5, None),
            carried(6, Some(Carrier::RecordSig)),
            min_since_line(7),
            entry_line(8, &CommitMeta::bare()),
            carried(9, None),
            demoted,
            carried(11, Some(Carrier::RecordSig)),
            carried(25, Some(Carrier::Marker)),
        ]),
        Some(10),
        "the demoted line is the last that can name a filled slot: the record's own sig at 11 \
         names an empty one, and the marker at 25 lies past the head"
    );
    assert_eq!(
        witness(vec![carried(1, None), carried(2, Some(Carrier::Marker)), carried(3, None)]),
        Some(2),
        "the marker line"
    );
    assert_eq!(
        witness(vec![carried(1, None), carried(2, Some(Carrier::RecordSig)), carried(3, None)]),
        None,
        "no line names a filled slot: the unsigned and the record-signed alike"
    );
    assert_eq!(
        witness(vec![carried(2, Some(Carrier::Marker)), min_since_line(4), carried(5, None)]),
        None,
        "a marker below the fence is dead to this build"
    );
}

/// Checks when a filled slot can lie above a position, as the open read it.
///
/// It can below the head where a line above the position records the
/// `marker` carrier or is bare, or where the open left a region to walk —
/// every position the file does not cover can hold any slot. At the head,
/// or above every such line of a file covering the head, none can, so the
/// attest store's open asks the journal nothing.
#[test]
fn a_filled_slot_can_lie_above_a_position_only_where_the_log_says_so() {
    let engine = engine_at(6);
    let head = engine.kernel().current_seq().0;
    let asked = |lines: Vec<Vec<u8>>, positions: &[u64]| -> Vec<bool> {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(dir.path().join(SIDECAR_FILE), lines.concat()).expect("the file");
        let log = CommitsLog::open(dir.path(), &engine, &Lines::new()).expect("the open");
        positions.iter().map(|&at| log.slot_may_be_filled_above(at)).collect()
    };
    let marker_at_1 = (1..=head).map(|at| carried(at, (at == 1).then_some(Carrier::Marker)));
    assert_eq!(
        asked(marker_at_1.collect(), &[0, 1, head]),
        [true, false, false],
        "the file covers the head: a filled slot only below the marker line"
    );
    let torn = (1..=4).map(|at| carried(at, None));
    assert_eq!(
        asked(torn.collect(), &[4, 5, head]),
        [true, true, false],
        "torn back to 4: the region pends, and every position below the head can hide a slot"
    );
    let bare_at_5 = (1..=head).map(|at| {
        if at == 5 {
            entry_line(5, &CommitMeta::bare())
        } else {
            carried(at, None)
        }
    });
    assert_eq!(
        asked(bare_at_5.collect(), &[4, 5, head]),
        [true, false, false],
        "a bare line, its carrier lost with its testimony"
    );
}

/// Checks that a rewrite failed past its rename stops the log, said once.
///
/// The line (`operations.md` §1.1 row 29) names the last entry the
/// rewritten file holds — the position the next open's walk starts above —
/// and what the stop costs until the restart. A second rewrite on the
/// stopped log still runs: the file rewritten keeping every line it held,
/// the write held in memory since the stop written whole into it, the
/// stop's position moved to its last entry, and no line added.
#[test]
fn a_rewrite_failed_past_its_rename_is_said_once_and_later_ones_run_in_silence() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut log = CommitsLog::over_unwritable(dir.path(), 9);
    for at in 1..=4 {
        log.entries.insert(at, CommitMeta::bare());
    }
    log.fail_next_rewrite_past_rename();
    let refused = log.rewrite_whole(1).expect_err("the reopen is refused");
    assert!(matches!(refused, RewriteFail::PastRename(_)), "{refused:?}");
    assert_eq!(log.stopped_since(), Some(4), "stopped at the rewritten file's last entry");
    let stop_line = "failure: commits.log rewrite failed past its rename: test seam: the rewritten \
                     file's reopen refused; this file takes no further line, so the next open \
                     re-derives above position 4 as bare entries; every write until then is held \
                     in memory alone, its key and its time lost at that open — restart soon";
    assert_eq!(log.lines.said().lock().as_slice(), [stop_line]);
    assert_eq!(
        std::fs::read_to_string(dir.path().join(SIDECAR_FILE)).expect("read"),
        "{\"at\":1}\n{\"at\":2}\n{\"at\":3}\n{\"at\":4}\n",
        "the first rewrite is in place"
    );

    // A write after the stop, held in memory alone.
    let serial = crate::serial::Serial::new();
    let held = log.record(&serial.lock(), 10, "insert", vec![], "bare".into(), None, None);
    assert!(matches!(held, Some(Recorded::Appended(_))), "recorded, its line not written");
    log.fail_next_rewrite_past_rename();
    let refused = log.rewrite_whole(10).expect_err("refused again");
    assert!(matches!(refused, RewriteFail::PastRename(_)), "{refused:?}");
    assert_eq!(log.stopped_since(), Some(10), "the stop moved to the second rewrite's last entry");
    let rewritten = std::fs::read_to_string(dir.path().join(SIDECAR_FILE)).expect("read");
    let at = rewritten.find("{\"at\":10,").expect("the held write is in the rewritten file");
    let (kept, held) = rewritten.split_at(at);
    assert_eq!(
        kept, "{\"at\":1}\n{\"at\":2}\n{\"at\":3}\n{\"at\":4}\n",
        "the second rewrite kept every line"
    );
    let held: serde_json::Value = serde_json::from_str(held).expect("the file's one last line");
    assert_eq!(
        (held["op"].as_str(), held["key"].as_str()),
        (Some("insert"), Some("bare")),
        "the held write whole in it: {held}"
    );
    // The record read ONCE into a local: a failing assertion that took the
    // lock again for its message would deadlock instead of failing.
    let said = log.lines.said().lock().clone();
    assert_eq!(said.len(), 1, "FINDING (row 29): a second line for one stop:\n{}", said.join("\n"));
}

/// An in-memory engine whose journal holds `commits` committed positions.
fn engine_at(commits: u64) -> Engine {
    use skep_kernel::{CheckpointPolicy, Durability, KernelConfig, SaltSource};
    use skep_namespace::{system_account, SYSTEM_PRINCIPAL};

    let engine = Engine::open(KernelConfig {
        durability: Durability::InMemory,
        checkpoint: CheckpointPolicy::Manual,
        salt: SaltSource::Seeded(0),
    })
    .expect("in-memory genesis cannot fail");
    while engine.kernel().current_seq().0 < commits {
        engine
            .namespace()
            .create_new_document(SYSTEM_PRINCIPAL, &system_account(), Some(false))
            .expect("the mint commits");
    }
    engine
}

#[cfg(unix)]
fn set_mode(path: &Path, mode: u32) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).expect("set the mode");
}

/// Whether this process opens a directory it may write and search but not
/// read — a privileged user's, for whom the mode refuses nothing and the
/// cases below can inject nothing.
#[cfg(unix)]
fn reads_any_directory(dir: &Path) -> bool {
    set_mode(dir, 0o300);
    let readable = File::open(dir).is_ok();
    set_mode(dir, 0o700);
    readable
}

/// THE KEEP THAT FAILS PAST ITS MAKING fails the open naming the step, the
/// kept file standing: a damaged `commits.log` in a directory whose own open
/// for its sync is refused by its mode — written and searched, not read —
/// has its dropped lines kept whole at `commits.log.cut-{byte}`, the
/// directory's sync refused after, and the open fails
/// `commits.log: {kept}: fsync the directory of: {cause}`, the kind kept;
/// the file stands as found, uncut, and no cut is said — no drop runs over a
/// keep that did not (the module's keep tolerates no directory's answer, as
/// the daemon's installs do).
#[cfg(unix)]
#[test]
fn a_keep_the_directory_refuses_fails_the_open_naming_the_step_and_the_kept_file_stands() {
    let engine = engine_at(6);
    let dir = tempfile::tempdir().expect("tempdir");
    if reads_any_directory(dir.path()) {
        return;
    }
    let line = |at| entry_line(at, &recorded("insert", &["1.0.1.0.1"], 1, Some("bare")));
    let trusted = [line(1), line(2)].concat();
    let dropped = [b"{\"at\":3,\"docs\":[\n".to_vec(), line(4)].concat();
    let path = dir.path().join(SIDECAR_FILE);
    std::fs::write(&path, [trusted.clone(), dropped.clone()].concat()).expect("the file");
    set_mode(dir.path(), 0o300);
    let lines = Lines::new();
    let refused = CommitsLog::open(dir.path(), &engine, &lines).err();
    set_mode(dir.path(), 0o700);
    let refused = refused.expect("the open refuses");
    let kept = format!("commits.log.cut-{}", trusted.len());
    assert_eq!(refused.kind(), io::ErrorKind::PermissionDenied, "{refused}");
    assert_eq!(
        refused.to_string(),
        format!("commits.log: {kept}: fsync the directory of: Permission denied (os error 13)"),
        "the file, the kept file and the step"
    );
    assert_eq!(
        std::fs::read(dir.path().join(&kept)).expect("the kept file stands"),
        dropped,
        "kept whole, the directory's sync refused after"
    );
    assert_eq!(
        std::fs::read(&path).expect("read"),
        [trusted, dropped].concat(),
        "no cut runs over a keep that did not: the file stands as found"
    );
    let said = lines.said().lock().clone();
    assert!(said.iter().all(|l| !l.contains("trust ends at")), "no cut said:\n{}", said.join("\n"));
}

/// A REWRITE FAILED BEFORE ITS RENAME REMOVES ITS TWIN: with the file removed
/// from under the landing's rewrite, the raw copy's read is refused and the
/// rewrite fails before its rename — the twin it made, over a kill's twin
/// that stood at the name, is removed, nothing stands at the name, and the
/// log is not stopped by the rewrite itself (the mutant that leaves the twin
/// keeps a `.compact` the next open says and the volume pays for).
#[test]
fn a_rewrite_failed_before_its_rename_removes_its_twin() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join(SIDECAR_FILE);
    let twin = dir.path().join("commits.log.compact");
    std::fs::write(&path, entry_line(20, &CommitMeta::bare())).expect("the file");
    let entries = [(20, CommitMeta::bare()), (21, CommitMeta::bare())].into_iter().collect();
    let mut log = CommitsLog::pending_over(dir.path(), entries, 20, 21);
    std::fs::write(&twin, b"{\"half\":\"writ").expect("a kill's twin");
    std::fs::remove_file(&path).expect("the file removed from under the rewrite");
    let refused = log.rewrite_whole(21).expect_err("the copy's read is refused");
    assert!(
        matches!(&refused, RewriteFail::BeforeRename(e) if e.kind() == io::ErrorKind::NotFound),
        "{refused:?}"
    );
    assert!(!twin.exists(), "the twin is removed, the kill's twin replaced with it");
    assert!(!path.exists(), "nothing stands at the name");
    assert_eq!(log.stopped_since(), None, "a rewrite failed before its rename stops nothing itself");
    assert!(log.lines.said().lock().is_empty(), "and says nothing: the landing's caller says it");
}

/// A REWRITE WHOSE DIRECTORY SYNC IS REFUSED stands at its name and stops the
/// log: with the directory's own open for its sync refused by its mode after
/// the rename, the rewrite fails past its rename — the rewritten file whole at
/// its name, the twin gone — and the log stops at the rewritten file's last
/// entry, said once in the past-rename words with the sync's cause; a write
/// after it is recorded in memory and reaches the file nowhere, in silence;
/// and the next open reads the rewritten file and re-derives above the stop's
/// position (the mutant that swallows the sync's failure keeps appending
/// through a handle on the file the rename replaced, which no open reads).
#[cfg(unix)]
#[test]
fn a_rewrite_whose_directory_sync_is_refused_stands_at_its_name_and_stops_the_log() {
    let dir = tempfile::tempdir().expect("tempdir");
    if reads_any_directory(dir.path()) {
        return;
    }
    let path = dir.path().join(SIDECAR_FILE);
    let mut log = CommitsLog::over_unwritable(dir.path(), 9);
    log.fail_appends = false;
    for at in 1..=4 {
        log.entries.insert(at, CommitMeta::bare());
    }
    set_mode(dir.path(), 0o300);
    let refused = log.rewrite_whole(1);
    set_mode(dir.path(), 0o700);
    let refused = refused.expect_err("the directory's sync is refused");
    assert!(
        matches!(&refused, RewriteFail::PastRename(e) if e.kind() == io::ErrorKind::PermissionDenied),
        "{refused:?}"
    );
    assert_eq!(refused.to_string(), "past its rename: Permission denied (os error 13)");
    let rewritten = "{\"at\":1}\n{\"at\":2}\n{\"at\":3}\n{\"at\":4}\n";
    assert_eq!(std::fs::read_to_string(&path).expect("read"), rewritten, "whole at its name");
    assert!(!dir.path().join("commits.log.compact").exists(), "renamed, not left");
    assert_eq!(log.stopped_since(), Some(4), "stopped at the rewritten file's last entry");
    let stop_line = "failure: commits.log rewrite failed past its rename: Permission denied (os \
                     error 13); this file takes no further line, so the next open re-derives \
                     above position 4 as bare entries; every write until then is held in memory \
                     alone, its key and its time lost at that open — restart soon";
    assert_eq!(log.lines.said().lock().as_slice(), [stop_line], "the stop, said once");
    let serial = crate::serial::Serial::new();
    let held = log.record(&serial.lock(), 10, "insert", vec![], "bare".into(), None, None);
    assert!(matches!(held, Some(Recorded::Appended(_))), "recorded, its line not written");
    assert_eq!(std::fs::read_to_string(&path).expect("read"), rewritten, "a stopped log writes nothing");
    assert_eq!(log.lines.said().lock().len(), 1, "and says nothing more");
    drop(log);
    let lines = Lines::new();
    let reopened = CommitsLog::open(dir.path(), &engine_at(6), &lines).expect("the next open");
    assert_eq!(reopened.counts(), (4, 4), "the rewritten file read whole");
    assert_eq!(reopened.pending_region(), Some((4, 6)), "re-derived above the stop's position");
}

/// A LINE AT THE BOUND REPLAYS WHOLE AND ONE PAST IT IS DAMAGE: the largest
/// line this file's writer produces — a recorded entry whose documents run
/// the line to the bound, the testimony padding it to the byte — is trusted
/// and held resident, nothing cut; the same line one byte longer ends trust
/// where it begins, as a whole line that does not parse does: cut, kept whole
/// with the whole line after it at `commits.log.cut-{byte}`, and said as a
/// damaged line's cut is, the whole line counted (the mutant that reads with
/// no bound holds any line whole, however long, and trusts it).
#[test]
fn a_line_at_the_bound_replays_whole_and_one_past_it_is_damage() {
    let docs = vec!["1.0.1.0.1"; (MAX_LINE_BYTES - 256) / 12];
    let with_key = |key: &str| entry_line(2, &recorded("nullify", &docs, 1, Some(key)));
    let short = with_key("").len() - 1;
    let at_bound = with_key(&"k".repeat(MAX_LINE_BYTES - short));
    assert_eq!(at_bound.len() - 1, MAX_LINE_BYTES, "the line at the bound, its newline aside");
    let past = with_key(&"k".repeat(MAX_LINE_BYTES - short + 1));
    assert_eq!(past.len() - 1, MAX_LINE_BYTES + 1);
    let engine = engine_at(3);
    let first = entry_line(1, &CommitMeta::bare());
    let third = entry_line(3, &CommitMeta::bare());
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join(SIDECAR_FILE);
    std::fs::write(&path, [first.clone(), at_bound.clone(), third.clone()].concat()).expect("the file");
    let lines = Lines::new();
    let log = CommitsLog::open(dir.path(), &engine, &lines).expect("the open");
    assert!(lines.said().lock().is_empty(), "nothing cut:\n{}", lines.said().lock().join("\n"));
    assert!(
        matches!(log.entries().get(&2), Some(CommitMeta::Recorded { docs: d, .. }) if d.len() == docs.len()),
        "the line at the bound is trusted and held"
    );
    assert_eq!((log.counts(), log.pending_region()), ((3, 2), None));
    assert_eq!(
        std::fs::metadata(&path).expect("stat").len() as usize,
        first.len() + at_bound.len() + third.len(),
        "nothing cut"
    );
    drop(log);
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join(SIDECAR_FILE);
    std::fs::write(&path, [first.clone(), past.clone(), third.clone()].concat()).expect("the file");
    let lines = Lines::new();
    let log = CommitsLog::open(dir.path(), &engine, &lines).expect("the open");
    assert!(!log.entries().contains_key(&2), "the line past the bound is no entry");
    assert_eq!((log.counts(), log.pending_region()), ((1, 1), Some((1, 3))), "re-derived above 1");
    assert_eq!(std::fs::read(&path).expect("read"), first, "cut where the line past the bound begins");
    let kept = format!("commits.log.cut-{}", first.len());
    assert_eq!(
        std::fs::read(dir.path().join(&kept)).expect("the kept file"),
        [past.clone(), third.clone()].concat(),
        "the line past the bound and the whole line after it, kept whole"
    );
    assert_eq!(
        lines.said().lock().as_slice(),
        [format!(
            "failure: commits.log: trust ends at position 1 (byte {} of {}); the {} bytes after it \
             are cut, kept in {kept}; the cut part is re-derived as bare entries; the cut took 1 \
             whole lines with it, positions 3–3: their keys and times are LOST to the feed and \
             stand in {kept} alone",
            first.len(),
            first.len() + past.len() + third.len(),
            past.len() + third.len()
        )],
        "said as a damaged line's cut, the whole line after it counted"
    );
}
