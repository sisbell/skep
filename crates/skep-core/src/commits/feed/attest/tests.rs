use super::*;

/// A slot the store records is served at once and replays from its line
/// as the same slot — [`attest_fields`] and [`attest_of_record`] one
/// spelling in both directions — and a line [`attest_fields`] could not
/// have spelled replays as no slot: an uppercase blob, a tag of no
/// signature, a tag past a byte, an empty blob. A tag no `SIG_ALGS` row
/// names is a slot all the same: the table is its consumer's to ask.
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
        let mut store = AttestStore { file, served: BTreeMap::new(), lines: lines.clone() };
        store.record(5, slot.clone()).expect("a writable store takes the line");
        assert_eq!(store.synced_through(), 5, "and syncs it before answering");
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

/// Row 9's attest words, all three sides, and row 10's. With the last
/// trusted position the one witness — no torn position, attested positions
/// anywhere above 0 — the cut is REBUILT exactly where it stands at or above
/// the floor and the journal answered, and LOST below, a last trusted
/// position one below the floor included, since no retained base answers
/// the floor's own slot; LOST above too where the journal refused the
/// rebuild. A journal still answering genesis is the floor at 0, every cut
/// rebuilt.
#[test]
fn the_attest_cut_names_the_floor_and_its_side_and_the_unreadable_slots_their_count() {
    let cut = Cut { valid_end: 1_400, len: 2_000, trusted: 40, first: None, whole_after: None };
    let head = "feed-attest.log: trust ends at position 40 (byte 1400 of 2000); the 600 bytes \
                after it are cut";
    let attested = Attested::Above(0);
    let line = |floor, rebuilt| AttestCutLine { cut, floor, attested, rebuilt }.to_string();
    let rebuilt = |floor| {
        format!(
            "{head}; every cut line lies above the reclaim floor at position {floor} and is \
             rebuilt from the journal"
        )
    };
    let lost = |floor| {
        format!(
            "{head}; the lines between position 40 and the reclaim floor at position {floor} \
             are LOST unless the board directory's backup is restored"
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
}

/// Checks the edge's two other witnesses, in the case a crash leaves.
///
/// The store's coverage moves at an open and at an attested commit alone,
/// so over an uptime of unattested writes the floor passes it, and a crash
/// then tears the next attested line, above the floor. A torn line whose
/// `at` stands whole names its own side — above the floor, rebuilt; at the
/// floor, the floor's own slot lost, the edge the position before it, never
/// the last trusted one — and the board's attested positions name theirs:
/// on an unclaimed board none lies anywhere, and on a claimed one none at
/// or below its board term's position. Each lost arm names the whole lines
/// a damaged line took with it.
#[test]
fn a_torn_line_or_the_board_term_names_the_side_the_last_trusted_position_cannot() {
    let head = "feed-attest.log: trust ends at position 40 (byte 1400 of 2000); the 600 bytes \
                after it are cut";
    let cut =
        |first, whole_after| Cut { valid_end: 1_400, len: 2_000, trusted: 40, first, whole_after };
    let line =
        |cut, attested, rebuilt| AttestCutLine { cut, floor: 50, attested, rebuilt }.to_string();
    let rebuilt = format!(
        "{head}; every cut line lies above the reclaim floor at position 50 and is rebuilt \
         from the journal"
    );
    let anywhere = Attested::Above(0);
    assert_eq!(line(cut(Some(60), None), anywhere, true), rebuilt, "a torn line above the floor");
    assert_eq!(
        line(cut(Some(50), None), anywhere, true),
        format!(
            "{head}; the lines between position 49 and the reclaim floor at position 50 are \
             LOST unless the board directory's backup is restored"
        ),
        "a torn line at the floor: its own slot lost, and nothing below it"
    );
    assert_eq!(line(cut(None, None), Attested::Above(55), true), rebuilt, "the board term above");
    assert_eq!(line(cut(None, None), Attested::Above(50), true), rebuilt, "…or at the floor");
    assert_eq!(line(cut(None, None), Attested::Nowhere, true), rebuilt, "an unclaimed board");
    let damaged = cut(None, Some(EntryLines { lines: 3, first: 44, last: 61 }));
    assert_eq!(
        line(damaged, Attested::Above(42), true),
        format!(
            "{head}; the lines between position 42 and the reclaim floor at position 50 are \
             LOST unless the board directory's backup is restored; the cut took 3 whole lines \
             with it, positions 44–61"
        ),
        "a damaged line: the board term the edge, the whole lines after it named"
    );
    assert_eq!(
        line(damaged, Attested::Above(55), false),
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
/// store with the floor, the edge above which a signature can have been lost
/// and the count; the store's size and slots with the positions rebuilt, and
/// with none; and the line not made durable with the act its cause adds
/// after it, room for a full volume and the volume, its device and the
/// quota for any other.
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
    assert_eq!(
        BegunAfreshLine { above: 1024, floor: 2049, rebuilt: 3 }.to_string(),
        "feed-attest.log was absent at this open and is begun afresh: the attested commits \
         above the reclaim floor at position 2049 are rebuilt from the journal (3 lines); \
         every signature this board kept between position 1024 and position 2049 is LOST \
         unless the board directory's backup is restored"
    );
    let mut rebuilt = Rebuilt::default();
    let open =
        |rebuilt| AttestOpenLine { bytes: 20_700, slots: 3, rebuilt, elapsed_ms: 4 }.to_string();
    assert_eq!(
        open(rebuilt),
        "feed-attest.log: 20700 bytes, never compacted, 3 slots resident; 0 lines rebuilt from \
         the journal's markers, in 4 ms"
    );
    for at in [7, 9, 12] {
        rebuilt.note(at);
    }
    assert_eq!(
        open(rebuilt),
        "feed-attest.log: 20700 bytes, never compacted, 3 slots resident; 3 lines rebuilt from \
         the journal's markers (positions 7–12), in 4 ms"
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
