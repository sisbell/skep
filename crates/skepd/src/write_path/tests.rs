use super::*;
use skep_content::Val;
use skep_namespace::PrincipalId;

/// Reads are exactly the ops the change feed records nothing for —
/// M10's partition and this table's answer, agreeing on both sides.
#[test]
fn reads_are_exactly_the_ops_with_no_change_feed_entry() {
    let write = Op::Fork { published: None };
    assert!(!write.is_read(), "fork commits");
    assert!(write_meta(&write).is_some());
    let read = Op::PrincipalPrefix { id: PrincipalId(1) };
    assert!(read.is_read(), "principal_prefix reads");
    assert!(write_meta(&read).is_none());
}

/// The index's entry hint, decided off the frame in each arm: an insert
/// names the indices of its values that pass the prefix test and nothing
/// of the rest; a publish carries the shot's re-inserted count; a copy and
/// a version share identity and mint no cell, as every other write.
#[test]
fn each_write_states_which_addresses_may_hold_a_cell() {
    use skep_address::Nat;
    use skep_febe::{Deposit, Shot, VPos};

    let doc = crate::codec::wire_address("1.0.1.0.1").expect("a test address");
    let cell = format!(
        r#"{{"type":"{}","hash":"af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262","size":5}}"#,
        skep_media::cell::KIND
    );
    let insert = Op::Insert {
        doc: doc.clone(),
        at: VPos::content(Nat::from(1u32)),
        values: vec![
            Val::new(b"a".as_slice()),
            Val::new(cell.as_bytes()),
            Val::new(b"b".as_slice()),
        ],
        deposit: Deposit::Undeclared,
    };
    let minting = write_meta(&insert).expect("a write").minting;
    assert!(matches!(&minting, Minting::Insert { naming } if naming == &[1]), "{minting:?}");
    let prose = Op::Insert {
        doc: doc.clone(),
        at: VPos::content(Nat::from(1u32)),
        values: vec![Val::new(b"ab".as_slice())],
        deposit: Deposit::Undeclared,
    };
    assert!(
        matches!(write_meta(&prose).expect("a write").minting, Minting::Insert { naming } if naming.is_empty())
    );
    // A `copy` and a `version` share identity: each arm states no cell.
    let copy =
        Op::Copy { doc: doc.clone(), at: VPos::content(Nat::from(1u32)), specs: Vec::new() };
    let version = Op::Version { d_src: doc.clone(), published: None };
    for op in [copy, version] {
        assert!(matches!(write_meta(&op).expect("a write").minting, Minting::None));
    }
    let publish = Op::Publish { doc, shot: Shot { base: None, draft: None, runs: Vec::new() } };
    assert!(matches!(
        write_meta(&publish).expect("a write").minting,
        Minting::Publish { reinserted: 0 }
    ));
    assert!(matches!(
        write_meta(&Op::Fork { published: None }).expect("a write").minting,
        Minting::None
    ));
}

/// Each write's arm of the table states the terms its row carries, beside
/// its documents, and no default decides it: `delegate` carries the
/// principal it seats, from the request; `make_link` and `publish` carry
/// theirs, completed from the ack; every other write carries none —
/// `emit` and `edit_link` among them, though each mints a link (r6-2a
/// names `make_link` alone).
#[test]
fn each_write_states_the_terms_its_row_carries() {
    use skep_address::Nat;
    use skep_febe::{Deposit, Endset, Shot, SlotArg, SuccessorSpec, VPos};

    let addr = |s: &str| crate::codec::wire_address(s).expect("a test address");
    let doc = addr("1.0.1.0.1");
    let terms = |op: Op| write_meta(&op).expect("a write").terms;
    let no_slot = || SlotArg::Addrs(Vec::new());

    let delegate = Op::Delegate {
        new_prefix: crate::codec::wire_tumbler("1.0.2").expect("a tumbler"),
        new_id: PrincipalId(41),
    };
    let seated = terms(delegate);
    assert!(matches!(seated, RowTerms::Delegate { new_id: 41 }), "{seated:?}");
    let make_link = Op::MakeLink {
        home: doc.clone(),
        from: no_slot(),
        to: no_slot(),
        ty: no_slot(),
        replaces: None,
    };
    assert!(matches!(terms(make_link), RowTerms::MakeLink));
    let publish = Op::Publish {
        doc: doc.clone(),
        shot: Shot { base: None, draft: None, runs: Vec::new() },
    };
    assert!(matches!(terms(publish), RowTerms::Publish));

    let emit =
        Op::Emit { home: doc.clone(), ty: Endset::empty(), from: doc.clone(), to: Vec::new() };
    let edit_link = Op::EditLink {
        original: addr("1.0.1.0.1.0.2.1"),
        successor: SuccessorSpec { from: Vec::new(), to: Vec::new(), ty: no_slot() },
        d_s: doc.clone(),
        d_a: doc.clone(),
    };
    let insert = Op::Insert {
        doc: doc.clone(),
        at: VPos::content(Nat::from(1u32)),
        values: Vec::new(),
        deposit: Deposit::Undeclared,
    };
    for (op, name) in [
        (emit, "emit"),
        (edit_link, "edit_link"),
        (Op::Fork { published: None }, "fork"),
        (insert, "insert"),
    ] {
        let carried = terms(op);
        assert!(matches!(carried, RowTerms::Absent), "{name} carries no term: {carried:?}");
    }
}

/// The commit stream only ever moves forward, and a burst between wakes
/// coalesces onto one step — the property `next` answers "anything past
/// what I last sent" for, rather than queueing.
#[test]
fn the_commit_stream_is_monotone_and_coalesces() {
    let stream = CommitStream::at(Seq(4));
    let step = stream.next(Seq(3));
    assert!(
        matches!(step, StreamStep::Commit(Seq(4))),
        "the opening position on connect: {step:?}"
    );
    stream.announce(Seq(9));
    stream.announce(Seq(7)); // an idempotency replay's older position
    let step = stream.next(Seq(4));
    assert!(
        matches!(step, StreamStep::Commit(Seq(9))),
        "an older position never displaces the announced one, and the burst is one \
         step: {step:?}"
    );
    stream.shutdown();
    let step = stream.next(Seq(0));
    assert!(matches!(step, StreamStep::Shutdown), "shutdown outranks a commit: {step:?}");
}

/// `signal.wait()` on a detached thread, its answer on the returned channel —
/// never joined, so a mutation that leaves the waiter parked fails the
/// assertion reading the channel rather than hanging the suite.
fn waiter(signal: &Arc<CheckpointSignal>) -> std::sync::mpsc::Receiver<Woken> {
    let (tx, rx) = std::sync::mpsc::channel();
    let signal = Arc::clone(signal);
    std::thread::spawn(move || {
        let _ = tx.send(signal.wait());
    });
    rx
}

/// THE CHECKPOINT THREAD's SIGNAL, its card's four claims (jw-R2: the
/// deferred cadence's wake): a raise no wait saw is KEPT, answered at once
/// by the next wait, so a crossing is never lost to a thread that was busy;
/// two raises before one wait COALESCE into one, so the wait after that one
/// parks — the thread reads the kernel's flag, not a count; the stop WAKES
/// every parked wait; and once asked it answers every later wait, a raise
/// beside it outranked — so no thread blocks a shutdown.
#[test]
fn the_checkpoint_signal_keeps_a_raise_coalesces_a_burst_and_stops_every_wait_for_good() {
    let (long, short) = (Duration::from_secs(5), Duration::from_millis(100));
    let signal = Arc::new(CheckpointSignal::new());
    signal.raise();
    signal.raise();
    assert_eq!(
        waiter(&signal).recv_timeout(long).ok(),
        Some(Woken::Due),
        "a raise no wait saw is kept"
    );
    let first = waiter(&signal);
    assert_eq!(
        first.recv_timeout(short).ok(),
        None,
        "two raises before one wait are one: this wait parks"
    );
    let second = waiter(&signal);
    std::thread::sleep(short);
    assert!(!signal.is_stopped(), "no stop asked yet");
    signal.stop();
    assert!(signal.is_stopped(), "the stop, once asked, is read");
    assert_eq!(first.recv_timeout(long).ok(), Some(Woken::Stop), "the stop wakes every parked wait");
    assert_eq!(second.recv_timeout(long).ok(), Some(Woken::Stop), "…every one");
    signal.raise();
    assert_eq!(
        waiter(&signal).recv_timeout(long).ok(),
        Some(Woken::Stop),
        "…and a later wait answers Stop, a raise beside it outranked"
    );
}

/// THE FULL VOLUME's LINE (`operations.md` §1.1 m1), in the ruled words,
/// with the position the refused write would have taken — and the door it
/// goes through keeps it in the record under its class word.
/// THE WALK THREAD's TWO LINES at fixed inputs: the catch's consequence
/// (row 41) with the payload and the region, and the OS's refusal of the
/// thread with the cause and what runs instead.
#[test]
fn the_feed_walks_catch_and_refusal_lines_render_the_ruled_words() {
    assert_eq!(
        FeedWalkEndedLine { payload: "the test seam's fault in the feed walk".into(), low: 24, head: 30 }
            .to_string(),
        "the feed walk ended: the test seam's fault in the feed walk; positions (24, 30] stay \
         uncovered — /changes refuses pages into them until a restart, which walks again"
    );
    let e = io::Error::other("Resource temporarily unavailable");
    assert_eq!(
        FeedWalkRefusedLine { error: &e, low: 24, head: 30 }.to_string(),
        "the feed walk: the OS refused its thread (Resource temporarily unavailable); positions \
         (24, 30] are walked at the open instead, the board serving once the walk lands"
    );
}

#[test]
fn the_full_volume_line_renders_the_ruled_words_and_the_door_records_it() {
    assert_eq!(
        FullVolumeLine { at: Seq(1204) }.to_string(),
        "a write was refused at a full volume at position 1204: no write lands until room is \
         freed on the volume; reads serve; the next write succeeds by itself once room stands, \
         and no restart is owed"
    );
    let lines = Lines::new();
    let shared = lines.clone();
    lines.say(Class::Failure, FullVolumeLine { at: Seq(7) });
    assert_eq!(
        shared.said().lock().as_slice(),
        ["failure: a write was refused at a full volume at position 7: no write lands until \
          room is freed on the volume; reads serve; the next write succeeds by itself once room \
          stands, and no restart is owed"],
        "a clone shares the one record, the class word ahead of the line"
    );
}

/// ROWS 27 AND 28 ON THE DOOR, PER ATTEMPT (`operations.md` §1.1 rows 27 and
/// 28; §4 row 27's line cell; L12's door): a compaction rewrite that fails
/// BEFORE its rename — a directory standing on the temp file's name,
/// `commits.log.compact` and `feed-index.log.compact`, which no create
/// passes — is said through the classed door under `failure:`, in the
/// ruled words, one line per file that stood; and said AGAIN at the next
/// landing that compacts while the cause stands — per attempt, the rule's
/// named exception, each landing a fresh act — where every other line of
/// the feed's is once. Driven one layer below the daemon, whose pre-claim
/// gate admits no bulk write: an engine over a temp dir under the daemon's
/// own kernel config, the write path over it, six bulk inserts as the
/// system principal through the session door — each recorded in the feed
/// — rotating the journal's segment so the first checkpoint reclaims below
/// it and the compaction has a floor; the checkpoint and the compaction
/// run here as the checkpoint thread runs them.
#[test]
fn a_compaction_failed_before_its_rename_is_said_through_the_door_at_every_attempt() {
    use skep_address::Nat;
    use skep_arrangement::Caller;
    use skep_febe::{Deposit, VPos};
    use skep_kernel::{BurnedSeqPolicy, CheckpointPolicy, Durability, KernelConfig, SaltSource};
    use skep_namespace::{system_account, SYSTEM_PRINCIPAL};

    let dir = tempfile::tempdir().expect("tempdir");
    let engine = Engine::open(KernelConfig {
        durability: Durability::Fsync {
            journal_path: dir.path().to_path_buf(),
            retain_checkpoints: 2,
            burned_seq: BurnedSeqPolicy::Rollback,
        },
        checkpoint: CheckpointPolicy::Deferred(Box::new(CheckpointPolicy::EveryN(1024))),
        salt: SaltSource::Os,
    })
    .expect("a fresh engine");
    let wp = WritePath::open(dir.path(), &engine, Arc::new(CellIndex::new())).expect("open");
    let stores = engine.stores();
    // One write through the session door, as the daemon's sequences commit:
    // the meta derived from the op, the driver run inside the lock.
    let commit = |op: Op, run: &dyn Fn() -> (Address, Seq)| {
        let meta = write_meta(&op).expect("a write").attributed("bare".to_string(), None);
        let serial = wp.serial_lock();
        let resp = wp.commit_under(&serial, meta, || {
            let (addr, at) = run();
            Response::AckAddr { addr, at }
        });
        assert!(matches!(resp, Response::AckAddr { .. }), "the write is acked through the door");
    };
    // Two mints under the system account: doc 3 is the head writer's own
    // staging draft, so the second, doc 4, is the private draft the inserts
    // go into.
    let account = system_account();
    let mut minted = Vec::new();
    for _ in 0..2 {
        let op = Op::CreateNewDocument { account: account.clone(), published: Some(false) };
        let mint = || {
            stores
                .namespace()
                .create_new_document(SYSTEM_PRINCIPAL, &account, Some(false))
                .expect("the mint commits")
        };
        commit(op, &mint);
        minted.push(mint_address(&stores, minted.len() + 3));
    }
    let doc = minted[1].clone();
    // A text value as the wire's codec hands it to the store: one atom per
    // character, which is what makes an 8 KiB insert a journal's worth of
    // records.
    let insert = |value: &str| {
        let values: Vec<Val> = value.bytes().map(|b| Val::new([b])).collect();
        let op = Op::Insert {
            doc: doc.clone(),
            at: VPos::content(Nat::from(1u32)),
            values: values.clone(),
            deposit: Deposit::Undeclared,
        };
        let run = || {
            stores
                .vstream()
                .insert(
                    Caller::Principal(SYSTEM_PRINCIPAL),
                    &doc,
                    VPos::content(Nat::from(1u32)),
                    values.clone(),
                    Deposit::Undeclared,
                )
                .expect("the insert commits")
        };
        commit(op, &run);
    };
    let bulk = "z".repeat(8192);
    for _ in 0..6 {
        insert(&bulk);
    }
    // THE OBSTACLE: a directory on each temp file's name, so the rewrite's
    // create fails and nothing is renamed.
    std::fs::create_dir(dir.path().join("commits.log.compact")).expect("the obstacle");
    std::fs::create_dir(dir.path().join("feed-index.log.compact")).expect("the obstacle");
    let compaction_lines = || -> Vec<String> {
        wp.lines_said()
            .lock()
            .iter()
            .filter(|l| l.contains("compaction below the reclaim floor failed"))
            .cloned()
            .collect()
    };
    let tail = "; the file stands as it was, and the next checkpoint's compaction tries again";

    // The checkpoint thread's act: the checkpoint, then the compaction.
    engine.kernel().checkpoint().expect("the first checkpoint lands");
    let compacted = wp.compact_feed_below_reclaim_floor(&engine);
    assert!(compacted.fence.is_some(), "the floor moved: a fence to compact to");
    assert_eq!(
        compacted.standing,
        ["commits.log", "feed-index.log"],
        "the two files whose rewrite failed before its rename stood"
    );
    let first = compaction_lines();
    assert_eq!(
        first.len(),
        2,
        "one line per file that stood, through the door:\n{}",
        wp.lines_said().lock().join("\n")
    );
    assert!(
        first[0].starts_with(
            "failure: commits.log compaction below the reclaim floor failed before its rename: "
        ) && first[0].ends_with(tail),
        "row 27: {}",
        first[0]
    );
    assert!(
        first[1].starts_with(
            "failure: feed-index.log compaction below the reclaim floor failed before its rename: "
        ) && first[1].ends_with(tail),
        "row 28: {}",
        first[1]
    );

    // A SECOND LANDING THAT COMPACTS, the obstacle standing: two more
    // checkpoints move the floor past the surviving entries, and each line
    // is said AGAIN — per attempt.
    insert("q");
    engine.kernel().checkpoint().expect("the second checkpoint lands");
    insert("q");
    engine.kernel().checkpoint().expect("the third checkpoint lands");
    let compacted = wp.compact_feed_below_reclaim_floor(&engine);
    assert_eq!(compacted.standing, ["commits.log", "feed-index.log"], "stood again");
    let again = compaction_lines();
    assert_eq!(
        again.len(),
        4,
        "FINDING (rows 27/28): per attempt — two landings, two lines each:\n{}",
        again.join("\n")
    );
    assert_eq!(again[2..], first[..], "the same two lines, again");
}

/// The address of the system account's `n`th document, as the mint lands
/// it — read off the world, so the test names what the store minted and
/// not a transcription.
fn mint_address(stores: &EngineStores, n: usize) -> Address {
    use skep_address::{validate, Nat, Tumbler};
    use skep_namespace::HasM3;
    let t = Tumbler::new([1u32, 1, 0, 1, 0, n as u32].into_iter().map(Nat::from))
        .expect("a six-component sequence is nonempty");
    let addr = validate(t).expect("the system account's documents are T4-valid");
    let snap = stores.kernel().snapshot();
    assert!(
        snap.world().m3().is_registered_document(&addr),
        "doc {n} of the system account is registered: {addr}"
    );
    addr
}

/// A raise WAKES a wait already parked — the thread asleep on the signal
/// between two crossings runs the checkpoint the next crossing calls for.
#[test]
fn a_raise_wakes_a_parked_wait() {
    let signal = Arc::new(CheckpointSignal::new());
    let parked = waiter(&signal);
    std::thread::sleep(Duration::from_millis(100));
    signal.raise();
    assert_eq!(
        parked.recv_timeout(Duration::from_secs(5)).ok(),
        Some(Woken::Due),
        "the raise reached the parked wait"
    );
}

/// THE THIRD ARM's COMPARE (`operations.md` §4 row 34): `commit_recorded`
/// holds the pre-commit snapshot across `execute` and, on an unwind, records
/// the position ONLY where the kernel's seq moved. Driven here WITHOUT the
/// kernel's checkpoint seam — an `execute` closure that commits a real op and
/// then panics is the committed-then-panic case, one that panics before
/// committing the unmoved case: the committed position is recorded BARE (no
/// op/docs/time/key on its line), the unmoved one records nothing.
#[test]
fn a_panic_after_the_commit_records_the_position_bare_and_an_unmoved_one_records_nothing() {
    use std::panic::{catch_unwind, AssertUnwindSafe};

    use skep_kernel::{BurnedSeqPolicy, CheckpointPolicy, Durability, KernelConfig, SaltSource};
    use skep_namespace::{system_account, SYSTEM_PRINCIPAL};

    let dir = tempfile::tempdir().expect("tempdir");
    let engine = Engine::open(KernelConfig {
        durability: Durability::Fsync {
            journal_path: dir.path().to_path_buf(),
            retain_checkpoints: 2,
            burned_seq: BurnedSeqPolicy::Rollback,
        },
        checkpoint: CheckpointPolicy::Deferred(Box::new(CheckpointPolicy::EveryN(1024))),
        salt: SaltSource::Os,
    })
    .expect("a fresh engine");
    let wp = WritePath::open(dir.path(), &engine, Arc::new(CellIndex::new())).expect("open");
    let stores = engine.stores();
    let account = system_account();

    // COMMITTED THEN PANICKED: the closure commits a real mint, then panics —
    // the kernel's seq moves, so the catch records the position BARE.
    let op = Op::CreateNewDocument { account: account.clone(), published: Some(false) };
    let meta = write_meta(&op).expect("a write").attributed("bare".to_string(), None);
    let before = engine.kernel().current_seq().0;
    let serial = wp.serial_lock();
    let caught = catch_unwind(AssertUnwindSafe(|| {
        wp.commit_under(&serial, meta, || {
            stores
                .namespace()
                .create_new_document(SYSTEM_PRINCIPAL, &account, Some(false))
                .expect("the mint commits");
            panic!("after the commit, before the answer");
        })
    }));
    drop(serial);
    assert!(caught.is_err(), "the panic rode out of the door");
    let at = engine.kernel().current_seq().0;
    assert_eq!(at, before + 1, "the mint committed before the panic");
    assert_eq!(wp.announced().0, at, "the committed position was announced");
    assert!(wp.head_time().is_none(), "the head's record is bare, so head_time is None");
    let line = commits_log_entry(dir.path(), at).expect("the committed position has a line");
    for k in ["op", "docs", "time", "key"] {
        assert!(line.get(k).is_none(), "a bare line carries no `{k}`: {line}");
    }

    // UNMOVED: the closure panics before committing anything — the seq does
    // not move, so the catch records nothing.
    let op = Op::CreateNewDocument { account: account.clone(), published: Some(false) };
    let meta = write_meta(&op).expect("a write").attributed("bare".to_string(), None);
    let before = engine.kernel().current_seq().0;
    let serial = wp.serial_lock();
    let caught = catch_unwind(AssertUnwindSafe(|| {
        wp.commit_under(&serial, meta, || -> Response { panic!("before any commit") })
    }));
    drop(serial);
    assert!(caught.is_err());
    assert_eq!(engine.kernel().current_seq().0, before, "nothing committed");
    assert!(
        commits_log_entry(dir.path(), before + 1).is_none(),
        "no bare entry is invented for a write that committed nothing"
    );
}

/// The parsed `commits.log` line for position `at`, read off the data dir as
/// an operator would — `None` where the file holds no line for it.
fn commits_log_entry(dir: &std::path::Path, at: u64) -> Option<serde_json::Value> {
    let text = std::fs::read_to_string(dir.join("commits.log")).ok()?;
    text.lines()
        .filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
        .find(|v| v.get("at").and_then(serde_json::Value::as_u64) == Some(at))
}
