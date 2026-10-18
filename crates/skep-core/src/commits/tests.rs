use super::*;
use skep_content::Val;
use skep_namespace::PrincipalId;

/// Returns an engine over `dir` under this suite's own kernel config.
///
/// The config is an fsync journal retaining two checkpoints, its cadence a
/// deferred count of 1,024 commits that no test here crosses, so a test
/// that needs a checkpoint takes it by hand (`kernel().checkpoint()`). It
/// is not the daemon's: `skepd` bounds its cadence by journal bytes as well,
/// which no test here reaches.
pub(super) fn fsync_engine(dir: &std::path::Path) -> Engine {
    use skep_kernel::{BurnedSeqPolicy, CheckpointPolicy, Durability, KernelConfig, SaltSource};
    Engine::open(KernelConfig {
        durability: Durability::Fsync {
            journal_path: dir.to_path_buf(),
            retain_checkpoints: 2,
            burned_seq: BurnedSeqPolicy::Rollback,
        },
        checkpoint: CheckpointPolicy::Deferred(Box::new(CheckpointPolicy::EveryN(1024))),
        salt: SaltSource::Os,
    })
    .expect("a fresh engine")
}

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
    // A `copy`, a `reinstate` and a `version` share identity: each arm
    // states no cell.
    let copy =
        Op::Copy { doc: doc.clone(), at: VPos::content(Nat::from(1u32)), specs: Vec::new() };
    let reinstate =
        Op::Reinstate { doc: doc.clone(), at: VPos::content(Nat::from(1u32)), runs: Vec::new() };
    let version = Op::Version { d_src: doc.clone(), published: None };
    for op in [copy, reinstate, version] {
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

/// The write by identity's row (the replacement act's record): `op`
/// `reinstate`, `docs` its DESTINATION — never a run's origin, which the
/// row would otherwise disclose to a reader the origin is withheld from —
/// no term, no cell.
#[test]
fn a_reinstate_row_names_its_destination_and_never_a_runs_origin() {
    use skep_address::Nat;
    use skep_febe::{Run, ShotRun, VPos};

    let addr = |s: &str| crate::codec::wire_address(s).expect("a test address");
    let (doc, origin) = (addr("1.0.1.0.1"), addr("1.0.1.0.2"));
    let op = Op::Reinstate {
        doc: doc.clone(),
        at: VPos::content(Nat::from(1u32)),
        runs: vec![ShotRun {
            origin: origin.clone(),
            run: Run::new(addr("1.0.1.0.2.0.1.1"), Nat::from(1u32)).expect("a content run"),
        }],
    };
    let meta = write_meta(&op).expect("a write");
    assert_eq!(meta.kind, OpKind::Reinstate);
    assert!(
        matches!(&meta.docs, AffectedDocs::Named(docs) if docs == &vec![doc.clone()]),
        "the destination alone: {:?}",
        meta.docs
    );
    assert!(matches!(meta.terms, RowTerms::Absent), "{:?}", meta.terms);
    assert!(matches!(meta.minting, Minting::None), "{:?}", meta.minting);
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

/// Checks that wire.md's keepalive sentence names the stream's own interval.
///
/// §The commit stream tells a client how long a stream is silent before the
/// daemon writes its `:ka` comment, the figure a client times a dead stream
/// by. It is read here through [`KEEPALIVE_INTERVAL`], which no other suite
/// can reach, so an interval that moves without its sentence fails here.
#[test]
fn wire_md_names_the_keepalive_interval_the_stream_waits() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs/wire.md");
    let wire = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()));
    let wire = wire.split_whitespace().collect::<Vec<_>>().join(" ");
    let sentence = format!(
        "After {} seconds of silence the daemon writes the comment line `:ka`",
        KEEPALIVE_INTERVAL.as_secs()
    );
    assert!(wire.contains(&sentence), "wire.md says {sentence:?}");
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
        FeedWalkEndedLine { payload: "the test seam's fault in the feed walk", low: 24, head: 30 }
            .to_string(),
        "the feed walk ended: the test seam's fault in the feed walk; positions (24, 30] stay \
         uncovered — /changes refuses pages into them until a restart, which walks again; until \
         that restart commits.log takes no line: every write since this open is held in memory \
         alone, and the restart's walk re-covers each as a bare entry, its key and its time lost \
         — restart soon"
    );
    // A formatted payload's text may have been made from a record's values,
    // so only a literal rides the line.
    let literal: Box<dyn std::any::Any + Send> = Box::new("a literal the code wrote");
    let formatted: Box<dyn std::any::Any + Send> = Box::new(format!("made from {}", "a value"));
    assert_eq!(payload_text(literal.as_ref()), "a literal the code wrote");
    assert_eq!(payload_text(formatted.as_ref()), "a panic", "a formatted payload never rides");
    let e = io::Error::other("Resource temporarily unavailable");
    assert_eq!(
        FeedWalkRefusedLine { error: &e, low: 24, head: 30 }.to_string(),
        "the feed walk: the OS refused its thread (Resource temporarily unavailable); positions \
         (24, 30] are walked at the open instead, the board serving once the walk lands"
    );
}

/// m1's TWO LINES AND THEIR CLOSE (`operations.md` §1.1 m1; §4 row 1), in
/// the ruled words: a full volume's with the kernel's account after the
/// position; every other kind's with its cause and the acts that clear it;
/// the account left out where the refusal carried none; the kernel's halt
/// with its own cause, and with the three classes where it kept none; and
/// the stretch's close with the landed position, the count and the first
/// refused one. The door they go through keeps them in the record under
/// their class words.
#[test]
fn the_durability_and_halt_lines_render_the_ruled_words_and_the_door_records_them() {
    let refused = |full, detail| DurabilityRefusedLine { at: Seq(1204), full, detail }.to_string();
    let room = "no write lands until room is freed on the volume; reads serve; the next write \
                succeeds by itself once room stands, and no restart is owed";
    assert_eq!(
        refused(true, Some("seg-3.wal: append: No space left on device (os error 28)")),
        format!(
            "a write was refused at a full volume at position 1204 (seg-3.wal: append: No space \
             left on device (os error 28)): {room}"
        )
    );
    assert_eq!(
        refused(true, None),
        format!("a write was refused at a full volume at position 1204: {room}")
    );
    assert_eq!(
        refused(false, Some("seg-3.wal: append: Disk quota exceeded (os error 69)")),
        "a write was refused durability at position 1204 (seg-3.wal: append: Disk quota exceeded \
         (os error 69)): no write lands until its cause clears; reads serve; check the volume, \
         its device and the board user's quota — the next write succeeds by itself once the \
         cause clears"
    );
    let landed =
        WritesLandAgainLine { at: Seq(1206), refused: 3, elapsed_ms: 912, since: Seq(1204) };
    assert_eq!(
        landed.to_string(),
        "writes land again at position 1206, 3 refused over 912 ms since position 1204"
    );
    let halt = |cause| KernelHaltLine { at: Seq(1203), cause }.to_string();
    assert_eq!(
        halt(Some("the commit of position 1204 failed (seg-3.wal: barrier: Input/output error)")),
        "the kernel halted its write paths at position 1203: the commit of position 1204 failed \
         (seg-3.wal: barrier: Input/output error); every write is refused poisoned until a \
         restart; reads serve; check the volume and the device, then restart",
        "the kernel's own cause rides the line"
    );
    assert_eq!(
        halt(None),
        "the kernel halted its write paths at position 1203: every write is refused poisoned \
         until a restart; reads serve. The cause is one of three the kernel did not report — a \
         commit that could not be rolled back durably, an unwind past the durability barrier, or \
         the sequence order exhausted; check the volume and the device, then restart",
        "with no cause kept, the three classes"
    );
    let lines = Lines::new();
    let shared = lines.clone();
    lines.say(Class::Failure, DurabilityRefusedLine { at: Seq(7), full: true, detail: None });
    assert_eq!(
        shared.said().lock().as_slice(),
        [format!("failure: a write was refused at a full volume at position 7: {room}")],
        "a clone shares the one record, the class word ahead of the line"
    );
}

/// m1 AT THE DOOR: durability refusals through the session door — a full
/// volume, a quota, the full volume again — say each kind's line once, the
/// position the first refused write would have taken named, and nothing
/// for a kind already said in the stretch; an idempotency replay between
/// them lands nothing and closes nothing; the write that lands next closes
/// the stretch with ONE landing line counting all three; and a refusal
/// after it is news again. The refusals are M10's own lowering of
/// the kernel's `TxnError::Durability`, so `io_kind` and `detail` ride as a
/// real refusal's do.
#[test]
fn durability_refusals_are_said_once_per_kind_and_the_landing_closes_the_stretch() {
    use skep_arrangement::InsertError;
    use skep_febe::lower_txn;
    use skep_kernel::TxnError;
    use skep_namespace::{system_account, SYSTEM_PRINCIPAL};

    let dir = tempfile::tempdir().expect("tempdir");
    let engine = fsync_engine(dir.path());
    let wp = Commits::open(dir.path(), &engine, Arc::new(CellIndex::new())).expect("open");
    let stores = engine.stores();
    let account = system_account();
    let mint_meta = || {
        let op = Op::CreateNewDocument { account: account.clone(), published: Some(false) };
        write_meta(&op).expect("a write").attributed("bare".to_string(), None)
    };
    let refuse = |kind: io::ErrorKind, words: &str| {
        let serial = wp.serial_lock();
        let error = io::Error::new(kind, words.to_string());
        let refusal = lower_txn::<InsertError>(OpKind::Insert, TxnError::Durability(error));
        let resp = wp.commit_under(&serial, mint_meta(), || Response::Rejected(refusal));
        assert!(matches!(resp, Response::Rejected(_)), "the refusal is answered as it came");
    };
    let mint = || {
        let serial = wp.serial_lock();
        let resp = wp.commit_under(&serial, mint_meta(), || {
            let (addr, at) = stores
                .namespace()
                .create_new_document(SYSTEM_PRINCIPAL, &account, Some(false))
                .expect("the mint commits");
            Response::AckAddr { addr, at }
        });
        assert!(matches!(resp, Response::AckAddr { .. }), "the mint is acked");
    };
    let durability_lines = || -> Vec<String> {
        wp.lines_said()
            .lock()
            .iter()
            .filter(|l| l.contains("a write was refused") || l.contains("writes land again"))
            .cloned()
            .collect()
    };
    let first = engine.kernel().current_seq().0 + 1;
    refuse(io::ErrorKind::StorageFull, "no room");
    refuse(io::ErrorKind::QuotaExceeded, "over quota");
    // An idempotency replay's ack names an old position and lands nothing:
    // the kernel's seq, not the answer, is what closes the stretch.
    let replayed = {
        let serial = wp.serial_lock();
        let at = engine.kernel().current_seq();
        wp.commit_under(&serial, mint_meta(), || Response::AckAddr { addr: account.clone(), at })
    };
    assert!(matches!(replayed, Response::AckAddr { .. }), "the replay is answered as it came");
    refuse(io::ErrorKind::StorageFull, "no room");
    let said = durability_lines();
    let all = said.join("\n");
    assert_eq!(said.len(), 2, "one line per kind, and no landing for a replay:\n{all}");
    assert!(said[0].starts_with(&format!(
        "failure: a write was refused at a full volume at position {first} (no room): "
    )));
    assert!(said[1].starts_with(&format!(
        "failure: a write was refused durability at position {first} (over quota): "
    )));
    mint();
    let landed = engine.kernel().current_seq().0;
    let said = durability_lines();
    let all = said.join("\n");
    assert_eq!(said.len(), 3, "the stretch closes once:\n{all}");
    let (head, tail) = said[2]
        .split_once(" ms since position ")
        .unwrap_or_else(|| panic!("the stretch's length and its first position: {}", said[2]));
    let ms = head
        .strip_prefix(&format!("landing: writes land again at position {landed}, 3 refused over "))
        .unwrap_or_else(|| panic!("the landed position and every refusal counted: {}", said[2]));
    assert!(ms.parse::<u128>().is_ok(), "the stretch's length in whole ms: {}", said[2]);
    assert_eq!(tail, first.to_string(), "the first refused position: {}", said[2]);
    mint();
    assert_eq!(durability_lines().len(), 3, "a landing with no stretch standing says nothing");
    let again = engine.kernel().current_seq().0 + 1;
    refuse(io::ErrorKind::StorageFull, "no room");
    assert_eq!(
        durability_lines().last().map(String::as_str),
        Some(
            format!(
                "failure: a write was refused at a full volume at position {again} (no room): no \
                 write lands until room is freed on the volume; reads serve; the next write \
                 succeeds by itself once room stands, and no restart is owed"
            )
            .as_str()
        ),
        "a refusal after the landing is a fresh stretch, said again"
    );
}

/// Checks rows 27 and 28 on the door, said at every attempt.
///
/// A compaction rewrite that fails before its rename — a directory standing
/// on the temp file's name, `commits.log.compact` and
/// `feed-index.log.compact`, which no create passes — is said through the
/// classed door under `failure:`, in the ruled words, one line per file
/// that stood (`operations.md` §1.1 rows 27 and 28; §4 row 27's line cell;
/// L12's door); and said again at the next landing that compacts while the
/// cause stands — per attempt, the rule's named exception, each landing a
/// fresh act — where every other line of the feed's is said once. Driven
/// one layer below the daemon, whose pre-claim gate admits no bulk write:
/// an engine over a temp dir under this suite's own kernel config
/// ([`fsync_engine`]), the write path over it, six bulk inserts as the
/// system principal through the session door — each recorded in the feed —
/// rotating the journal's segment so the first checkpoint reclaims below it
/// and the compaction has a floor; the checkpoint, taken by hand, and the
/// compaction run here as the checkpoint thread runs them. The next open,
/// the obstacle gone, compacts what the landings could not and says what
/// it dropped.
#[test]
fn a_compaction_failed_before_its_rename_is_said_through_the_door_at_every_attempt() {
    use skep_address::Nat;
    use skep_arrangement::Caller;
    use skep_febe::{Deposit, VPos};
    use skep_namespace::{system_account, SYSTEM_PRINCIPAL};

    let dir = tempfile::tempdir().expect("tempdir");
    let engine = fsync_engine(dir.path());
    let wp = Commits::open(dir.path(), &engine, Arc::new(CellIndex::new())).expect("open");
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
    // A text value as the wire's codec hands it to the store: one value per
    // character, which the store writes as ONE stretch — so an insert costs
    // the journal its bytes and two records, and the segment rotates only
    // under inserts of the codec's whole cap.
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
    let bulk = "z".repeat(262_144);
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
            .filter(|l| l.contains(" compaction below the reclaim floor at position "))
            .cloned()
            .collect()
    };
    // Rows 27 and 28 as a compaction to `fence` says them: the file, the
    // reclaim floor the compaction ran to, the side of the rename, then the
    // cause and the act.
    let stood = |line: &str, file: &str, fence: u64| {
        let floor = fence + 1;
        let head = format!(
            "failure: {file} compaction below the reclaim floor at position {floor} failed before \
             its rename: "
        );
        let tail = "; the file stands as it was, and the next checkpoint's compaction tries again";
        line.starts_with(&head) && line.ends_with(tail)
    };

    // The checkpoint thread's act: the checkpoint, then the compaction.
    engine.kernel().checkpoint().expect("the first checkpoint lands");
    let compacted = wp.compact_feed_below_reclaim_floor(&engine);
    let fence = compacted.fence.expect("the floor moved: a fence to compact to");
    assert_eq!(compacted.deferred, None, "no walk pending: the rewrite is not deferred");
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
    assert!(stood(&first[0], "commits.log", fence), "row 27: {}", first[0]);
    assert!(stood(&first[1], "feed-index.log", fence), "row 28: {}", first[1]);

    // A SECOND LANDING THAT COMPACTS, the obstacle standing: two more
    // checkpoints move the floor past the surviving entries, and each line
    // is said AGAIN — per attempt, naming the floor this landing ran to.
    insert("q");
    engine.kernel().checkpoint().expect("the second checkpoint lands");
    insert("q");
    engine.kernel().checkpoint().expect("the third checkpoint lands");
    let compacted = wp.compact_feed_below_reclaim_floor(&engine);
    let fence = compacted.fence.expect("the floor moved again: a fence to compact to");
    assert_eq!(compacted.standing, ["commits.log", "feed-index.log"], "stood again");
    let again = compaction_lines();
    assert_eq!(
        again.len(),
        4,
        "FINDING (rows 27/28): per attempt — two landings, two lines each:\n{}",
        again.join("\n")
    );
    assert!(
        stood(&again[2], "commits.log", fence) && stood(&again[3], "feed-index.log", fence),
        "the same two lines again, at the floor this landing ran to:\n{}",
        again[2..].join("\n")
    );

    // THE NEXT OPEN, the obstacle gone, compacts what the two landings
    // could not, and says the floor and the entries the file still held
    // below it.
    let below = std::fs::read_to_string(dir.path().join("commits.log"))
        .expect("the log")
        .lines()
        .filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
        .filter_map(|v| v.get("at").and_then(serde_json::Value::as_u64))
        .filter(|&at| at <= fence)
        .count();
    assert!(below > 0, "the premise: the file still holds entries below the floor");
    std::fs::remove_dir(dir.path().join("commits.log.compact")).expect("the obstacle goes");
    std::fs::remove_dir(dir.path().join("feed-index.log.compact")).expect("the obstacle goes");
    drop(wp);
    let wp = Commits::open(dir.path(), &engine, Arc::new(CellIndex::new())).expect("reopen");
    let floor = fence + 1;
    let line = format!(
        "open: the change feed's files compacted below the reclaim floor at position {floor}: \
         {below} entries dropped"
    );
    let said = wp.lines_said().lock().clone();
    assert_eq!(said.iter().filter(|l| **l == line).count(), 1, "{line}\n--\n{}", said.join("\n"));
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

    use skep_namespace::{system_account, SYSTEM_PRINCIPAL};

    let dir = tempfile::tempdir().expect("tempdir");
    let engine = fsync_engine(dir.path());
    let wp = Commits::open(dir.path(), &engine, Arc::new(CellIndex::new())).expect("open");
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

/// Holds the head writer's row 40 to the classed door.
///
/// `ensure_draft`'s line — the draft minted elsewhere — goes out through
/// the door the head writer holds, under `failure:`, into the record the
/// daemon shares: a published document at the staging draft's address
/// moves the head writer's mint to the next, and the line names both.
#[test]
fn the_head_writers_row_40_goes_through_the_classed_door() {
    use skep_namespace::{system_account, SYSTEM_PRINCIPAL};

    let dir = tempfile::tempdir().expect("tempdir");
    let engine = fsync_engine(dir.path());
    let wp = Commits::open(dir.path(), &engine, Arc::new(CellIndex::new())).expect("open");
    let stores = engine.stores();
    let account = system_account();
    // Another writer takes the staging draft's address with a PUBLISHED
    // document, which the head writer's resume never takes for its draft.
    let op = Op::CreateNewDocument { account: account.clone(), published: Some(true) };
    let meta = write_meta(&op).expect("a write").attributed("bare".to_string(), None);
    let serial = wp.serial_lock();
    let resp = wp.commit_under(&serial, meta, || {
        let (addr, at) = stores
            .namespace()
            .create_new_document(SYSTEM_PRINCIPAL, &account, Some(true))
            .expect("the mint commits");
        Response::AckAddr { addr, at }
    });
    assert!(matches!(resp, Response::AckAddr { .. }), "the mint is acked");
    wp.write_first_head(&serial);
    drop(serial);
    let row_40 = "failure: head writer: the staging draft minted at 1.1.0.1.0.4, not at \
                  1.1.0.1.0.3 — another writer minted under the system account; the head goes \
                  on with the draft it minted";
    let said = wp.lines_said().lock().clone();
    assert_eq!(
        said.iter().filter(|l| l.as_str() == row_40).count(),
        1,
        "row 40 through the classed door, into the one record:\n{}",
        said.join("\n")
    );
}

/// Holds the feed's three journal reads to their refusal lines, end to end.
///
/// A kernel that keeps no journal refuses every history read, so one open
/// over commits the feed never saw meets all three: the bare positions the
/// index lost (`commits.log` holds two, `feed-index.log` nothing), the attest
/// store's rebuild above its empty file, and the walk of the region the log
/// does not cover. Each is said once in the kernel's words, the walk's where
/// it meets it, with the fence the refusal moved — and `/changes` answers 410
/// below that fence once the walk lands, as the line says. The open closes
/// with what it classified and how far back the feed answers. A second open
/// over what the first wrote has nothing uncovered and says none of the
/// three; its report names the attest store's size and its slots, the
/// figures `Commits::attest_store_figures` reads.
#[test]
fn every_journal_refusal_the_feeds_open_meets_is_said_in_the_kernels_words() {
    use skep_kernel::{CheckpointPolicy, Durability, HistoryError, KernelConfig, SaltSource};
    use skep_namespace::{system_account, SYSTEM_PRINCIPAL};

    let dir = tempfile::tempdir().expect("tempdir");
    let engine = Engine::open(KernelConfig {
        durability: Durability::InMemory,
        checkpoint: CheckpointPolicy::Manual,
        salt: SaltSource::Seeded(0),
    })
    .expect("in-memory genesis cannot fail");
    let account = system_account();
    while engine.kernel().current_seq().0 < 5 {
        engine
            .stores()
            .namespace()
            .create_new_document(SYSTEM_PRINCIPAL, &account, Some(false))
            .expect("the mint commits");
    }
    let head = engine.kernel().current_seq().0;
    std::fs::write(dir.path().join("commits.log"), "{\"at\":1}\n{\"at\":2}\n").expect("the log");
    let wp = Commits::open(dir.path(), &engine, Arc::new(CellIndex::new())).expect("open");
    let deadline = Instant::now() + Duration::from_secs(30);
    while wp.feed_pending_region().is_some() {
        assert!(Instant::now() < deadline, "the walk lands");
        thread::sleep(Duration::from_millis(5));
    }
    let refused = HistoryError::Unjournaled.to_string();
    let fence = head - 1;
    let said = wp.lines_said().lock().clone();
    let all = said.join("\n");
    for line in [
        "open: feed-index.log covers to position 0: 2 bare positions are classified from the \
         journal before the board serves, two world reconstructions each"
            .to_string(),
        format!(
            "failure: feed-index.log: the journal refused to classify 2 bare positions, the \
             first at position 1 ({refused}): each is served to every class, its position alone"
        ),
        format!(
            "failure: feed-attest.log: the journal refused the rebuild above position 0 \
             ({refused}): any attested commit in (0, {head}] serves attest: null, its line LOST \
             at this store and not retried — restore this file and the segment the account \
             names from a copy taken before this open (RUNBOOK §2)"
        ),
        format!(
            "failure: commits.log's walk: the journal refused the boundaries above position 2 \
             ({refused}): once the walk lands the change feed answers 410 history_reclaimed for \
             every since below position {fence}; the walk goes on — restore the segment the \
             account names from a copy (RUNBOOK §2)"
        ),
    ] {
        assert_eq!(said.iter().filter(|l| **l == line).count(), 1, "{line}\n--\n{all}");
    }
    // The open's own closing lines: what it classified, and how far back the
    // feed answers with the region the walk has yet to land.
    let classified = "open: feed-index.log: 0 of 2 bare positions classified from the journal in ";
    let reach = format!(
        "open: the change feed answers from position 1 to position {head}: commits.log 2 \
         entries, 2 of them bare; positions (2, {head}] wait on the walk, in "
    );
    for (prefix, what) in [(classified, "the classification"), (reach.as_str(), "the feed")] {
        let found = said.iter().filter(|l| l.starts_with(prefix) && l.ends_with(" ms")).count();
        assert_eq!(found, 1, "{what}'s closing line, once:\n{all}");
    }
    let landing = format!(
        "landing: commits.log re-covered positions (2, {head}]: 1 boundaries walked, 1 of them \
         unclassifiable and served to every class, in "
    );
    let fenced = format!(
        "; the fence stands at position {fence}: /changes answers 410 history_reclaimed for \
         every since below it"
    );
    assert!(
        said.iter().any(|l| l.starts_with(&landing) && l.ends_with(&fenced)),
        "the landing names the region and the fence:\n{all}"
    );
    let snap = engine.kernel().snapshot();
    let class = FeedClass::of(snap.world(), None);
    let query = |since| ChangesQuery {
        since,
        limit: std::num::NonZeroUsize::new(16).expect("non-zero"),
        under: None,
        drafts_only: false,
    };
    let below = wp.changes(&class, &query(0));
    assert!(
        matches!(below, ChangesAnswer::Reclaimed { floor: Some(f) } if f == head),
        "below the fence, 410: {below:?}"
    );
    let at = wp.changes(&class, &query(fence));
    assert!(
        matches!(&at, ChangesAnswer::Page { entries, .. } if entries.len() == 1),
        "at the fence, the head's row: {at:?}"
    );
    drop(wp);

    let wp = Commits::open(dir.path(), &engine, Arc::new(CellIndex::new())).expect("reopen");
    assert_eq!(wp.feed_pending_region(), None, "the log covers the head");
    let said = wp.lines_said().lock().clone();
    let all = said.join("\n");
    assert!(
        !said.iter().any(|l| l.contains("the journal refused") || l.contains("bare positions")),
        "nothing uncovered, nothing asked:\n{all}"
    );
    let figures = wp.attest_store_figures();
    let bytes = figures.bytes.expect("the store's size");
    let on_disk = std::fs::metadata(dir.path().join("feed-attest.log")).expect("the store").len();
    assert_eq!((bytes, figures.slots), (on_disk, 0), "the size is the file's; nothing attested");
    let report = format!(
        "open: feed-attest.log: {bytes} bytes, never compacted, 0 slots resident; 0 lines rebuilt \
         from the journal's markers, in "
    );
    assert!(said.iter().any(|l| l.starts_with(&report)), "the open's report:\n{all}");
    let reach = format!(
        "open: the change feed answers from position {head} to position {head}: commits.log 1 \
         entries, 1 of them bare, in "
    );
    assert!(
        said.iter().any(|l| l.starts_with(&reach)),
        "the walked head alone above the fence, nothing pending:\n{all}"
    );
}
