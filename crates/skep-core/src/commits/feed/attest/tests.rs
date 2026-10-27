use super::*;

/// Checks that a recorded slot is served and replays from its line as itself.
///
/// [`attest_fields`] and [`attest_of_record`] are one spelling in both
/// directions, the line owing a sync the store's second handle makes and the
/// store settles; and a line [`attest_fields`] could not have spelled replays
/// as no slot: an uppercase blob, a tag of no signature, a tag past a byte, an
/// empty blob. A tag no `SIG_ALGS` row names is a slot all the same: the table
/// is its consumer's to ask.
#[test]
fn a_recorded_slot_is_served_and_replays_from_its_line_as_itself() {
    let dir = tempfile::tempdir().expect("tempdir");
    let lines = Lines::new();
    let slot = Attestation::new(1, vec![0xab, 0x01]).expect("tag 1 and a non-empty blob");
    {
        let (file, entries, replayed) =
            LineFile::open(dir.path(), ATTEST_FILE, 9, |_| true, &lines)
                .expect("a fresh store opens");
        assert!(entries.is_empty() && replayed.cut.is_none() && replayed.foreign.is_none());
        let sync = file.sync_handle().expect("the store's second handle");
        let mut store = AttestStore { file, served: BTreeMap::new(), lines: lines.clone() };
        let owed = store.record(5, slot.clone()).expect("a writable store takes the line");
        assert_eq!(store.synced_through(), 0, "written, its sync owed");
        sync.sync().expect("the second handle syncs the line the store wrote");
        store.settle(owed);
        assert_eq!(store.synced_through(), 5, "the sync settled with the store");
        assert_eq!(store.slot(5).as_deref(), Some(&slot), "served at once");
        assert_eq!(store.slot(4).as_deref(), None, "and only where recorded");
        assert_eq!(store.figures().slots, 1, "one slot resident");
        assert!(lines.said().lock().is_empty(), "a line that landed says nothing");
    }
    let (_file, entries, _) =
        LineFile::open(dir.path(), ATTEST_FILE, 9, |_| true, &lines).expect("reopen");
    let replayed: Vec<(u64, Option<Attestation>)> =
        entries.iter().map(|(at, m)| (*at, attest_of_record(m))).collect();
    assert_eq!(replayed, [(5, Some(slot))], "the line replays as the slot it mirrors");

    let record = |alg: Value, sig: &str| {
        let mut m = Map::new();
        m.insert(ATTEST_ALG.to_string(), alg);
        m.insert(ATTEST_SIG.to_string(), Value::String(sig.to_string()));
        m
    };
    for (alg, sig, why) in [
        (Value::from(1u64), "AB01", "hex not in the store's own lowercase"),
        (Value::from(0u64), "ab01", "the empty slot's tag signs nothing"),
        (Value::from(256u64), "ab01", "a tag past a byte"),
        (Value::from(1u64), "", "a blob of no bytes"),
    ] {
        assert_eq!(attest_of_record(&record(alg, sig)), None, "{why}");
    }
    assert_eq!(
        attest_of_record(&record(Value::from(200u64), "ab01")),
        Attestation::new(200, vec![0xab, 0x01]).ok(),
        "a tag no row names replays as the slot it spells"
    );
}

/// ROW 33 ON THE DOOR (`operations.md` §1.1 row 33; SO-I5 (d)): a line
/// the store cannot make durable — its handle read-only, the seam
/// `fail_next_write` — is answered [`AttestStoreFailed`] and said
/// through the classed door under `failure:`, in the ruled words: the
/// file, the position, the cause, what still serves and the act. The
/// slot is served this uptime all the same. ONCE by the halt above: the
/// write path refuses every later commit on the answer, so no later
/// `record` runs — the file's own refusal of a later line is the halt's
/// premise, not this card's rate.
#[test]
fn a_line_the_store_cannot_make_durable_is_said_through_the_door_and_answered() {
    let dir = tempfile::tempdir().expect("tempdir");
    let lines = Lines::new();
    let (file, _, _) =
        LineFile::open(dir.path(), ATTEST_FILE, 9, |_| true, &lines).expect("a fresh store opens");
    let mut store = AttestStore { file, served: BTreeMap::new(), lines: lines.clone() };
    store.fail_next_write();
    let slot = Attestation::new(1, vec![0xab, 0x01]).expect("a slot");
    assert!(store.record(5, slot.clone()).is_err(), "answered, so the write path halts");
    assert_eq!(store.slot(5).as_deref(), Some(&slot), "served this uptime all the same");
    let said = lines.said().lock().clone();
    assert_eq!(said.len(), 1, "one line for the failure:\n{}", said.join("\n"));
    assert!(
        said[0].starts_with("failure: feed-attest.log: position 5's line is not durable ("),
        "the class word, the file and the position: {}",
        said[0]
    );
    assert!(
        said[0].ends_with(
            "); every later write is refused until a restart, whose open rebuilds the line \
             from the journal; check the volume, its device and the board user's quota first: \
             the restart's open writes the line back and syncs it, and where its cause stands \
             it refuses and reads stop with it"
        ),
        "what still serves and the act: {}",
        said[0]
    );
}

/// Checks that a failed sync is said as a failed write is, and stops the file.
///
/// The sync is made off the feed's lock and its failure met there, so the
/// store hears of it after its record: row 33, in the ruled words, with the
/// position the sync was owed for and the cause — a full volume's act among
/// them — and the file stopped there, as a failed write stops it.
#[test]
fn a_failed_sync_is_said_through_the_door_and_stops_the_file() {
    let dir = tempfile::tempdir().expect("tempdir");
    let lines = Lines::new();
    let (file, _, _) =
        LineFile::open(dir.path(), ATTEST_FILE, 9, |_| true, &lines).expect("a fresh store opens");
    let mut store = AttestStore { file, served: BTreeMap::new(), lines: lines.clone() };
    let slot = Attestation::new(1, vec![0xab, 0x01]).expect("a slot");
    let owed = store.record(5, slot.clone()).expect("the line is written");
    store.sync_failed(owed, &io::Error::new(io::ErrorKind::StorageFull, "no room"));
    let said = lines.said().lock().clone();
    assert_eq!(
        said,
        [format!(
            "failure: {}",
            NotDurableLine { at: 5, error: &io::Error::new(io::ErrorKind::StorageFull, "no room") }
        )],
        "row 33, once, for the sync that failed"
    );
    assert!(said[0].contains("(the volume is full (no room))"), "the cause: {}", said[0]);
    assert_eq!(store.file.stopped_since(), Some(5), "the file stops where the sync was owed");
    assert_eq!(store.slot(5).as_deref(), Some(&slot), "served this uptime all the same");
}

/// Row 9's attest words, all three sides, and row 10's. With the last
/// trusted position the store's one witness — no torn position, attested
/// positions anywhere above 0 — and `commits.log` recording the position just
/// past it attested, the cut is REBUILT exactly where it stands at or above
/// the floor and the journal answered, and LOST below, a last trusted
/// position one below the floor included, since no retained base answers
/// the floor's own slot, the lost ending naming the attested commit
/// `commits.log` records there; LOST above too where the journal refused the
/// rebuild. A journal still answering genesis is the floor at 0, every cut
/// rebuilt.
#[test]
fn the_attest_cut_names_the_floor_and_its_side_and_the_unreadable_slots_their_count() {
    let cut = Cut { valid_end: 1_400, len: 2_000, trusted: 40, first: None, whole_after: None };
    let head = "feed-attest.log: trust ends at position 40 (byte 1400 of 2000); the 600 bytes \
                after it are cut";
    let attested = Attested::Above(0);
    let log =
        LogWitness { attested: Some(EntryLines { lines: 1, first: 41, last: 41 }), unnamed: None };
    let line = |floor, rebuilt| {
        AttestCutLine { cut, floor, attested, rebuilt, kept: None, log }.to_string()
    };
    let rebuilt = |floor| {
        format!(
            "{head}; every cut line lies above the reclaim floor at position {floor} and is \
             rebuilt from the journal"
        )
    };
    let lost = |floor| {
        format!(
            "{head}; the lines between position 40 and the reclaim floor at position {floor} \
             are LOST unless the board directory's backup is restored; commits.log records 1 \
             attested commits there, positions 41–41"
        )
    };
    assert_eq!(line(40, true), rebuilt(40), "coverage = floor: rebuilt");
    assert_eq!(line(0, true), rebuilt(0), "nothing reclaimed: the floor is genesis");
    assert_eq!(line(41, true), lost(41), "coverage + 1 = floor: the floor's slot is lost");
    assert_eq!(line(42, true), lost(42), "coverage + 1 < floor: lost");
    assert_eq!(
        line(40, false),
        format!(
            "{head}; every cut line lies above the reclaim floor at position 40, but the \
             journal refused their rebuild: they are LOST unless the board directory's \
             backup is restored"
        ),
        "above the floor, the rebuild refused: lost"
    );
    assert_eq!(
        UnreadableSlotsLine { count: 3, first: 17 }.to_string(),
        "feed-attest.log: 3 slots this daemon cannot read, the first at position 17; their \
         rows serve attest: null, the lines kept as written"
    );
    // A damaged line's cut names the kept file after the head, and the
    // lost arms name it as what restores the lines beside the backup.
    let kept = Some(KeptName { byte: 1_400, k: 0 });
    let kept_line =
        |floor, rebuilt| AttestCutLine { cut, floor, attested, rebuilt, kept, log }.to_string();
    let kept_head = format!("{head}, kept in feed-attest.log.cut-1400");
    assert_eq!(
        kept_line(40, true),
        format!(
            "{kept_head}; every cut line lies above the reclaim floor at position 40 and is \
             rebuilt from the journal"
        )
    );
    assert_eq!(
        kept_line(42, true),
        format!(
            "{kept_head}; the lines between position 40 and the reclaim floor at position 42 \
             are LOST unless restored from feed-attest.log.cut-1400 or the board directory's \
             backup; commits.log records 1 attested commits there, positions 41–41"
        )
    );
    assert_eq!(
        kept_line(40, false),
        format!(
            "{kept_head}; every cut line lies above the reclaim floor at position 40, but the \
             journal refused their rebuild: they are LOST unless restored from \
             feed-attest.log.cut-1400 or the board directory's backup"
        )
    );
}

/// Checks the edge's two other store witnesses, in the case a crash leaves.
///
/// The store's coverage moves at an open and at an attested commit alone,
/// so over an uptime of unattested writes the floor passes it, and a crash
/// then tears the next attested line, above the floor. A torn line whose
/// `at` stands whole names its own side — above the floor, rebuilt; at the
/// floor, the floor's own slot lost, the edge the position before it, never
/// the last trusted one, `commits.log` recording that slot attested — and the
/// board's attested positions name theirs: on an unclaimed board none lies
/// anywhere, and on a claimed one none at or below its board term's position,
/// which stays the edge where `commits.log` cannot tell of the position just
/// past it. Each lost arm names the whole lines a damaged line took with it.
#[test]
fn a_torn_line_or_the_board_term_names_the_side_the_last_trusted_position_cannot() {
    let head = "feed-attest.log: trust ends at position 40 (byte 1400 of 2000); the 600 bytes \
                after it are cut";
    let cut =
        |first, whole_after| Cut { valid_end: 1_400, len: 2_000, trusted: 40, first, whole_after };
    let line = |cut, attested, rebuilt, log| {
        AttestCutLine { cut, floor: 50, attested, rebuilt, kept: None, log }.to_string()
    };
    let rebuilt = format!(
        "{head}; every cut line lies above the reclaim floor at position 50 and is rebuilt \
         from the journal"
    );
    let anywhere = Attested::Above(0);
    let none = LogWitness::default();
    let at_the_floor =
        LogWitness { attested: Some(EntryLines { lines: 1, first: 50, last: 50 }), unnamed: None };
    assert_eq!(
        line(cut(Some(60), None), anywhere, true, none),
        rebuilt,
        "a torn line above the floor"
    );
    assert_eq!(
        line(cut(Some(50), None), anywhere, true, at_the_floor),
        format!(
            "{head}; the lines between position 49 and the reclaim floor at position 50 are \
             LOST unless the board directory's backup is restored; commits.log records 1 \
             attested commits there, positions 50–50"
        ),
        "a torn line at the floor: its own slot lost, and nothing below it"
    );
    assert_eq!(
        line(cut(None, None), Attested::Above(55), true, none),
        rebuilt,
        "the board term above"
    );
    assert_eq!(
        line(cut(None, None), Attested::Above(50), true, none),
        rebuilt,
        "…or at the floor"
    );
    assert_eq!(
        line(cut(None, None), Attested::Nowhere, true, none),
        rebuilt,
        "an unclaimed board"
    );
    let damaged = cut(None, Some(EntryLines { lines: 3, first: 44, last: 61 }));
    let past_the_term = LogWitness { attested: None, unnamed: Some((43, 50)) };
    assert_eq!(
        line(damaged, Attested::Above(42), true, past_the_term),
        format!(
            "{head}; the lines between position 42 and the reclaim floor at position 50 are \
             LOST unless the board directory's backup is restored; commits.log cannot tell \
             which commits there were attested, positions 43–50; the cut took 3 whole lines \
             with it, positions 44–61"
        ),
        "a damaged line: the board term the edge, the whole lines after it named"
    );
    assert_eq!(
        line(damaged, Attested::Above(55), false, none),
        format!(
            "{head}; every cut line lies above the reclaim floor at position 50, but the journal \
             refused their rebuild: they are LOST unless the board directory's backup is \
             restored; the cut took 3 whole lines with it, positions 44–61"
        ),
        "above the floor, the rebuild refused"
    );
    let genesis = skep_engine::Engine::open(skep_kernel::KernelConfig {
        durability: skep_kernel::Durability::InMemory,
        checkpoint: skep_kernel::CheckpointPolicy::Manual,
        salt: skep_kernel::SaltSource::Seeded(0),
    })
    .expect("in-memory genesis cannot fail");
    assert_eq!(
        Attested::of(genesis.kernel().snapshot().world()),
        Attested::Nowhere,
        "an unclaimed board holds no attested position"
    );
}

/// Checks the open's other lines and row 33's two endings, at fixed inputs.
///
/// They are the refused rebuild with the account and the region; the absent
/// store with the floor, the edge above which a signature can have been lost,
/// the count and what `commits.log` records there; the store's size and slots
/// with the positions rebuilt, with none, and with the journal not asked,
/// naming the coverage above which no line records a filled slot; and the
/// line not made durable with the act its cause adds after it, room for a
/// full volume and the volume, its device and the quota for any other.
#[test]
fn the_open_and_the_halt_say_what_the_store_holds_and_what_is_lost() {
    assert_eq!(
        RebuildRefusedLine { coverage: 12, head: 30, account: "journal corrupt at rest" }
            .to_string(),
        "feed-attest.log: the journal refused the rebuild above position 12 (journal corrupt \
         at rest): any attested commit in (12, 30] serves attest: null, its line LOST at this \
         store and not retried — restore this file and the segment the account names from a \
         copy taken before this open (RUNBOOK §2)"
    );
    let log = LogWitness {
        attested: Some(EntryLines { lines: 2, first: 1025, last: 2040 }),
        unnamed: None,
    };
    assert_eq!(
        BegunAfreshLine { above: 1024, floor: 2049, rebuilt: 3, log }.to_string(),
        "feed-attest.log was absent at this open and is begun afresh: the attested commits \
         above the reclaim floor at position 2049 are rebuilt from the journal (3 lines); \
         every signature this board kept between position 1024 and position 2049 is LOST \
         unless the board directory's backup is restored; commits.log records 2 attested \
         commits there, positions 1025–2040"
    );
    let mut rebuilt = Rebuilt::default();
    let open =
        |rebuild| AttestOpenLine { bytes: 20_700, slots: 3, rebuild, elapsed_ms: 4 }.to_string();
    assert_eq!(
        open(Rebuild::Asked(rebuilt)),
        "feed-attest.log: 20700 bytes, never compacted, 3 slots resident; 0 lines rebuilt from \
         the journal's markers, in 4 ms"
    );
    for at in [7, 9, 12] {
        rebuilt.note(at);
    }
    assert_eq!(
        open(Rebuild::Asked(rebuilt)),
        "feed-attest.log: 20700 bytes, never compacted, 3 slots resident; 3 lines rebuilt from \
         the journal's markers (positions 7–12), in 4 ms"
    );
    assert_eq!(
        open(Rebuild::NotAsked { above: 30 }),
        "feed-attest.log: 20700 bytes, never compacted, 3 slots resident; the journal not \
         asked: no line of commits.log above position 30 records a filled slot, in 4 ms",
        "the open that read no base says so, and the coverage it measured from"
    );
    let durable =
        |kind| NotDurableLine { at: 5, error: &io::Error::new(kind, "no room") }.to_string();
    let halt = "feed-attest.log: position 5's line is not durable";
    let rest = "every later write is refused until a restart, whose open rebuilds the line \
                from the journal";
    assert_eq!(
        durable(io::ErrorKind::Other),
        format!(
            "{halt} (no room); {rest}; check the volume, its device and the board user's quota \
             first: the restart's open writes the line back and syncs it, and where its cause \
             stands it refuses and reads stop with it"
        )
    );
    assert_eq!(
        durable(io::ErrorKind::StorageFull),
        format!(
            "{halt} (the volume is full (no room)); {rest}; free room on the volume first: \
             the restart's open writes the line back and syncs it, and on a full volume it \
             refuses and reads stop with it"
        )
    );
}

/// Checks the fourth witness: what `commits.log` records up to the floor.
///
/// Each of its clause's three forms rides the lost ending, after the backup
/// and before the whole lines a damaged cut took: the attested commits it
/// records, the positions it cannot tell of, and both. The edge rises to the
/// position before the first it names, so a span it names nothing in reads
/// REBUILT where the journal answered the rebuild, and above the floor where
/// the journal refused it; and never past a line the cut is known to have
/// taken, so a damaged line's first whole line after it, at or below the
/// floor, keeps the cut LOST though `commits.log` names nothing there. The
/// absent store's line carries the same clause.
#[test]
fn the_loss_lines_name_what_commits_log_records_and_read_rebuilt_where_it_records_none() {
    let head = "feed-attest.log: trust ends at position 40 (byte 1400 of 2000); the 600 bytes \
                after it are cut";
    let plain = Cut { valid_end: 1_400, len: 2_000, trusted: 40, first: None, whole_after: None };
    let line = |cut, rebuilt, log| {
        let attested = Attested::Above(0);
        AttestCutLine { cut, floor: 50, attested, rebuilt, kept: None, log }.to_string()
    };
    let lost = |edge, clause: &str| {
        format!(
            "{head}; the lines between position {edge} and the reclaim floor at position 50 are \
             LOST unless the board directory's backup is restored{clause}"
        )
    };
    let attested = Some(EntryLines { lines: 2, first: 44, last: 47 });
    assert_eq!(
        line(plain, true, LogWitness { attested, unnamed: None }),
        lost(43, "; commits.log records 2 attested commits there, positions 44–47"),
        "the attested commits it records: the edge the position before the first"
    );
    assert_eq!(
        line(plain, true, LogWitness { attested: None, unnamed: Some((45, 50)) }),
        lost(44, "; commits.log cannot tell which commits there were attested, positions 45–50"),
        "the positions it cannot tell of: the edge the position before the first"
    );
    assert_eq!(
        line(plain, true, LogWitness { attested, unnamed: Some((42, 49)) }),
        lost(
            41,
            "; commits.log records 2 attested commits there, positions 44–47, and cannot tell \
             for positions 42–49"
        ),
        "both: the edge the position before the first of either"
    );
    assert_eq!(
        line(plain, true, LogWitness::default()),
        format!(
            "{head}; every cut line lies above the reclaim floor at position 50 and is rebuilt \
             from the journal"
        ),
        "it names nothing up to the floor: no signature lay there, and the cut reads rebuilt"
    );
    assert_eq!(
        line(plain, false, LogWitness::default()),
        format!(
            "{head}; every cut line lies above the reclaim floor at position 50, but the journal \
             refused their rebuild: they are LOST unless the board directory's backup is \
             restored"
        ),
        "…and above the floor where the journal refused the rebuild"
    );
    let damaged = Cut { whole_after: Some(EntryLines { lines: 2, first: 46, last: 58 }), ..plain };
    assert_eq!(
        line(damaged, true, LogWitness::default()),
        format!("{}; the cut took 2 whole lines with it, positions 46–58", lost(45, "")),
        "a line the cut took at or below the floor bounds the raise: the store held its slot"
    );
    let cannot_tell = LogWitness { attested: None, unnamed: Some((1025, 2049)) };
    assert_eq!(
        BegunAfreshLine { above: 1024, floor: 2049, rebuilt: 0, log: cannot_tell }.to_string(),
        "feed-attest.log was absent at this open and is begun afresh: the attested commits \
         above the reclaim floor at position 2049 are rebuilt from the journal (0 lines); \
         every signature this board kept between position 1024 and position 2049 is LOST \
         unless the board directory's backup is restored; commits.log cannot tell which \
         commits there were attested, positions 1025–2049"
    );
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

/// Checks what the witness reads off `commits.log` between two positions.
///
/// The file is hand-written over a journal of twenty positions: an unsigned
/// line and a marker line under a fence, which makes both dead to this build;
/// then an unsigned line, a marker line, a record-signed line, a bare line, a
/// marker line and a marker line whose name does not parse, demoted to bare
/// as the open's scan demotes it; then an unsigned line, the file ending short
/// of the head, so its open leaves the rest to walk. A marker line counts
/// attested; a bare line, a position at or below the fence and one the open
/// did not cover are ones `commits.log` cannot tell of; the unsigned and the
/// record-signed lines name their slots empty, and a span of them alone
/// names nothing, as an empty span does.
#[test]
fn the_witness_reads_commits_log_between_two_positions_and_leaves_open_what_it_cannot_name() {
    let engine = engine_at(20);
    let dir = tempfile::tempdir().expect("tempdir");
    let line = |at: u64, signed: &str, doc: &str| {
        let signed =
            if signed.is_empty() { String::new() } else { format!(",\"signed\":\"{signed}\"") };
        format!(
            "{{\"at\":{at},\"docs\":[\"{doc}\"],\"key\":\"bare\",\"op\":\"insert\"{signed},\
             \"time\":{at}}}\n"
        )
    };
    let doc = "1.0.1.0.1";
    let file = [
        line(2, "", doc),
        line(3, "marker", doc),
        "{\"min_since\":4}\n".to_string(),
        line(5, "", doc),
        line(6, "marker", doc),
        line(7, "record", doc),
        "{\"at\":9}\n".to_string(),
        line(10, "marker", doc),
        line(11, "marker", "1.0"),
        line(12, "", doc),
    ];
    std::fs::write(dir.path().join(SIDECAR_FILE), file.concat()).expect("the file");
    let log = CommitsLog::open(dir.path(), &engine, &Lines::new()).expect("the log opens");
    assert_eq!(
        (log.fence(), log.pending_region()),
        (4, Some((12, 20))),
        "the premise: the fence at 4, and the region past 12 left to walk"
    );
    let read = |after, through| {
        LogWitness::read(dir.path(), &log, after, through).expect("commits.log reads")
    };
    let attested = |lines, first, last| Some(EntryLines { lines, first, last });
    assert_eq!(
        read(0, 20),
        LogWitness { attested: attested(2, 6, 10), unnamed: Some((1, 20)) },
        "the whole journal: the two marker lines above the fence, and every other kind"
    );
    assert_eq!(read(0, 20).first(), Some(1));
    assert_eq!(
        read(4, 8),
        LogWitness { attested: attested(1, 6, 6), unnamed: None },
        "above the fence, below the bare line: the one marker line"
    );
    assert_eq!(read(6, 8), LogWitness::default(), "a record-signed line names its slot empty");
    assert_eq!(read(6, 8).first(), None, "…so the span held no signature");
    assert_eq!(
        read(8, 12),
        LogWitness { attested: attested(1, 10, 10), unnamed: Some((9, 11)) },
        "a bare line and a demoted marker line it cannot tell of, beside a marker line"
    );
    assert_eq!(
        read(12, 15),
        LogWitness { attested: None, unnamed: Some((13, 15)) },
        "the region its open did not cover"
    );
    assert_eq!(
        read(0, 3),
        LogWitness { attested: None, unnamed: Some((1, 3)) },
        "at or below the fence: the marker line there is dead to this build"
    );
    assert_eq!(read(8, 8), LogWitness::default(), "an empty span reads nothing");
}
