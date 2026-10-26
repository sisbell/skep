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
    use skep_kernel::{
        BurnedSeqPolicy, CheckpointPolicy, Durability, KernelConfig, Reclaim, SaltSource,
    };
    Engine::open(KernelConfig {
        durability: Durability::Fsync {
            journal_path: dir.to_path_buf(),
            retain_checkpoints: 2,
            reclaim: Reclaim::BelowOldestRetained,
            burned_seq: BurnedSeqPolicy::Rollback,
            cut_damaged_tail: false,
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
        successor: SuccessorSpec { from: Vec::new().into(), to: Vec::new().into(), ty: no_slot() },
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
/// (row 41) with the payload and what the walk left — the region, the bare
/// positions the index lost, or both — and the OS's refusal of the thread
/// with the cause and what runs instead.
#[test]
fn the_feed_walks_catch_and_refusal_lines_render_the_ruled_words() {
    let region = FeedPending { region: Some((24, 30)), unsorted: None };
    let set = Some(Unsorted { count: 5, first: 3, last: 19 });
    let payload = "the test seam's fault in the feed walk";
    assert_eq!(
        FeedWalkEndedLine { payload, pending: region }.to_string(),
        "the feed walk ended: the test seam's fault in the feed walk; positions (24, 30] stay \
         uncovered — /changes refuses pages into them until a restart, which walks again; until \
         that restart commits.log takes no line: every write since this open is held in memory \
         alone, and the restart's walk re-covers each as a bare entry, its key and its time lost \
         — restart soon"
    );
    assert_eq!(
        FeedWalkEndedLine {
            payload,
            pending: FeedPending { region: Some((24, 30)), unsorted: set }
        }
        .to_string(),
        "the feed walk ended: the test seam's fault in the feed walk; positions (24, 30] stay \
         uncovered and 5 bare positions the index lost stay unsorted — /changes refuses pages \
         into them until a restart, which walks again; until that restart commits.log takes no \
         line: every write since this open is held in memory alone, and the restart's walk \
         re-covers each as a bare entry, its key and its time lost — restart soon"
    );
    assert_eq!(
        FeedWalkEndedLine { payload, pending: FeedPending { region: None, unsorted: set } }
            .to_string(),
        "the feed walk ended: the test seam's fault in the feed walk; 5 bare positions the index \
         lost stay unsorted — /changes refuses pages reaching them until a restart, which sorts \
         them again; until that restart the change feed's index files take no line: every write \
         since this open enters the feed's memory alone, which the restart's open re-derives \
         from commits.log — restart soon"
    );
    // A formatted payload's text may have been made from a record's values,
    // so only a literal rides the line.
    let literal: Box<dyn std::any::Any + Send> = Box::new("a literal the code wrote");
    let formatted: Box<dyn std::any::Any + Send> = Box::new(format!("made from {}", "a value"));
    assert_eq!(payload_text(literal.as_ref()), "a literal the code wrote");
    assert_eq!(payload_text(formatted.as_ref()), "a panic", "a formatted payload never rides");
    let e = io::Error::other("Resource temporarily unavailable");
    assert_eq!(
        FeedWalkRefusedLine { error: &e, pending: region }.to_string(),
        "the feed walk: the OS refused its thread (Resource temporarily unavailable); positions \
         (24, 30] are walked at the open instead, the board serving once the walk lands"
    );
    assert_eq!(
        FeedWalkRefusedLine { error: &e, pending: FeedPending { region: None, unsorted: set } }
            .to_string(),
        "the feed walk: the OS refused its thread (Resource temporarily unavailable); 5 bare \
         positions the index lost are walked at the open instead, the board serving once the \
         walk lands"
    );
}

/// Checks m1's two lines and their close in the ruled words.
///
/// They are (`operations.md` §1.1 m1; §4 row 1) a full volume's with the
/// kernel's account after the position; every other kind's with its cause
/// and the acts that clear it; each with what a restart before the cause
/// clears meets at its open; the account left out where the refusal
/// carried none; the kernel's halt with its own cause, and with the three
/// classes where it kept none; and the stretch's close with the landed
/// position, the count and the first refused one. The door they go through
/// keeps them in the record under their class words.
#[test]
fn the_durability_and_halt_lines_render_the_ruled_words_and_the_door_records_them() {
    let refused = |full, detail| DurabilityRefusedLine { at: Seq(1204), full, detail }.to_string();
    let room = "no write lands until room is freed on the volume; reads serve; the next write \
                succeeds by itself once room stands, and no restart is owed — a restart before \
                room stands runs its open into the full volume, and where the open refuses, reads \
                stop with it";
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
         cause clears; a restart before then runs its open into the same cause, and where the \
         open refuses, reads stop with it"
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
                 succeeds by itself once room stands, and no restart is owed — a restart before \
                 room stands runs its open into the full volume, and where the open refuses, \
                 reads stop with it"
            )
            .as_str()
        ),
        "a refusal after the landing is a fresh stretch, said again"
    );
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
/// index lost (`commits.log` holds two, `feed-index.log` nothing), which the
/// walk thread sorts behind the listener, the attest store's rebuild above
/// its empty file, and the walk of the region the log does not cover — the
/// sort and the walk one pass of the one thread. Each is said once in the
/// kernel's words, the walk's where it meets it, with the fence the refusal
/// moved — and `/changes` answers 410 below that fence once the walk lands,
/// as the line says. The walk's `open:` and `landing:` lines for the set
/// bracket the sort, and the open closes with how far back the feed answers
/// and what waits on the walk. A second open over what the first wrote has
/// nothing uncovered and says none of the three; its report names the attest
/// store's size and its slots, the figures `Commits::attest_store_figures`
/// reads.
#[test]
fn every_journal_refusal_the_feeds_open_meets_is_said_in_the_kernels_words() {
    use skep_kernel::{CheckpointPolicy, Durability, HistoryError, KernelConfig, SaltSource};
    use skep_namespace::{system_account, SYSTEM_PRINCIPAL};

    let _walks = one_walk_at_a_time();
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
    while wp.feed_walk_pending() {
        assert!(Instant::now() < deadline, "the walk lands");
        thread::sleep(Duration::from_millis(5));
    }
    let refused = HistoryError::Unjournaled.to_string();
    let fence = head - 1;
    let said = wp.lines_said().lock().clone();
    let all = said.join("\n");
    for line in [
        "open: feed-index.log covers to position 0: 2 bare positions are classified from the \
         journal behind the listener, 3 world reconstructions in all"
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
             every since below position {fence}; the walk goes on, and its landing writes that \
             fence into commits.log, which a segment restored alone does not move — to \
             re-cover the positions, stop the daemon, put back the segment the account names \
             and commits.log from a copy taken before this open, and start again (RUNBOOK §2)"
        ),
    ] {
        assert_eq!(said.iter().filter(|l| **l == line).count(), 1, "{line}\n--\n{all}");
    }
    // The walk's landing line for the set — no reconstruction answered — and
    // the open's own closing line: how far back the feed answers, with the
    // region and the set the walk has yet to land.
    let classified = "landing: feed-index.log: 0 of 2 bare positions classified from the \
                      journal, 0 world reconstructions, in ";
    let reach = format!(
        "open: the change feed answers from position 1 to position {head}: commits.log 2 \
         entries, 2 of them bare; positions (2, {head}] and 2 bare positions the index lost wait \
         on the walk, in "
    );
    for (prefix, what) in [(classified, "the sort's landing"), (reach.as_str(), "the feed")] {
        let found = said.iter().filter(|l| l.starts_with(prefix) && l.ends_with(" ms")).count();
        assert_eq!(found, 1, "{what}'s closing line, once:\n{all}");
    }
    assert!(
        !all.contains("before the board serves"),
        "nothing is classified before the board serves:\n{all}"
    );
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
    let at = served(wp.changes(&class, &query(fence)));
    assert_eq!(at.keys().copied().collect::<Vec<_>>(), [head], "at the fence, the head's row");
    drop(wp);

    let wp = Commits::open(dir.path(), &engine, Arc::new(CellIndex::new())).expect("reopen");
    assert_eq!(wp.feed_pending_region(), None, "the log covers the head");
    let said = wp.lines_said().lock().clone();
    let all = said.join("\n");
    // The hole the walk's fence left is said once at the reopen, and no
    // refusal is: nothing is uncovered, nothing asked of the journal.
    let hole = format!(
        "open: the change feed's files hold no line at or below position {fence}: an earlier \
         build's compaction, or a walk the journal refused, left the fence there; /changes \
         answers 410 history_reclaimed for every since below position {head}, the first line held"
    );
    assert_eq!(said.iter().filter(|l| **l == hole).count(), 1, "the hole, said once:\n{all}");
    assert!(
        !said
            .iter()
            .filter(|l| **l != hole)
            .any(|l| l.contains("the journal refused") || l.contains("bare positions")),
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

/// The feed walk's hold and its seams are process-wide.
///
/// A test here that opens the write path over a pending region, or arms a
/// seam, takes this for its span, so under plain `cargo test` no walk parks
/// behind another test's hold or meets another test's seam.
static WALKS: Mutex<()> = Mutex::new(());

/// The walks taken for one test's span ([`WALKS`]).
///
/// Its drop releases the hold, pass or fail, so a red leaves no later walk
/// parked.
struct OneWalk(#[allow(dead_code)] parking_lot::MutexGuard<'static, ()>);

impl Drop for OneWalk {
    fn drop(&mut self) {
        FEED_WALK_HOLD.release();
    }
}

/// Takes the walks for a test's span.
fn one_walk_at_a_time() -> OneWalk {
    OneWalk(WALKS.lock())
}

/// Opens the write path over `dir`, as the daemon's open does.
///
/// # Panics
///
/// Panics where the open fails.
fn open_the_write_path(dir: &std::path::Path, engine: &Engine) -> Commits {
    Commits::open(dir, engine, Arc::new(CellIndex::new())).expect("the write path opens")
}

/// Mints one draft under the system account through the session door.
///
/// It is minted as the system principal and is one record, so the position
/// advances by one; the answer is the draft and its position.
///
/// # Panics
///
/// Panics where the mint is refused.
fn mint_a_draft(wp: &Commits, stores: &EngineStores) -> (Address, u64) {
    mint_a_draft_attested(wp, stores, None)
}

/// Mints one draft as [`mint_a_draft`] does, attested by `slot` where given.
///
/// With a slot the mint is attested as the plain sequence attests an
/// admitted write: the kernel writes `slot` into the commit's marker
/// (`Stores::namespace_attested`), and the write path records the entry
/// signed by it, its testimony a fingerprint's hex; with none it is
/// [`mint_a_draft`]'s bare mint.
///
/// # Panics
///
/// Panics where the mint is refused.
fn mint_a_draft_attested(
    wp: &Commits,
    stores: &EngineStores,
    slot: Option<&Attestation>,
) -> (Address, u64) {
    use skep_namespace::{system_account, SYSTEM_PRINCIPAL};

    let account = system_account();
    let op = Op::CreateNewDocument { account: account.clone(), published: Some(false) };
    let (testimony, signed) = match slot {
        Some(slot) => ("cd".repeat(32), Some(Signed::Marker(slot.clone()))),
        None => ("bare".to_string(), None),
    };
    let meta = write_meta(&op).expect("a write").attributed(testimony, signed);
    let serial = wp.serial_lock();
    let resp = wp.commit_under(&serial, meta, || {
        let (addr, at) = stores
            .namespace_attested(slot)
            .create_new_document(SYSTEM_PRINCIPAL, &account, Some(false))
            .expect("the mint commits");
        Response::AckAddr { addr, at }
    });
    let Response::AckAddr { addr, at } = resp else { panic!("the mint is acked") };
    (addr, at.0)
}

/// Mints four drafts and tears `commits.log` back to the first.
///
/// The answer is the four positions; the next open's region is the three
/// above the first.
///
/// # Panics
///
/// Panics where the write path does not open or a mint is refused.
fn a_torn_board(dir: &std::path::Path, engine: &Engine) -> Vec<u64> {
    let wp = open_the_write_path(dir, engine);
    let stores = engine.stores();
    let board: Vec<u64> = (0..4).map(|_| mint_a_draft(&wp, &stores).1).collect();
    drop(wp);
    tear_to(dir, board[0]);
    board
}

/// Tears `commits.log` back to the entry at `low`.
///
/// Every line whose `at` lies above `low` is dropped, so the next open's
/// region is `(low, head]`; the answer is the file's bytes after the tear.
///
/// # Panics
///
/// Panics where the file cannot be read or written, or a line is no JSON.
fn tear_to(dir: &std::path::Path, low: u64) -> Vec<u8> {
    let path = dir.join("commits.log");
    let text = std::fs::read_to_string(&path).expect("commits.log");
    let kept: String = text
        .lines()
        .filter(|line| {
            let v: serde_json::Value = serde_json::from_str(line).expect("a line is JSON");
            v.get("at").and_then(serde_json::Value::as_u64).is_none_or(|at| at <= low)
        })
        .map(|line| format!("{line}\n"))
        .collect();
    std::fs::write(&path, &kept).expect("tear the file");
    kept.into_bytes()
}

/// Polls until `done`, within a minute.
///
/// # Panics
///
/// Panics where `done` has not held within the minute, naming `what`.
fn wait_until(what: &str, mut done: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(60);
    while !done() {
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        thread::sleep(Duration::from_millis(5));
    }
}

/// Returns `class`'s page from `since`: every visible entry above it.
fn page_from(wp: &Commits, class: &FeedClass<'_>, since: u64) -> ChangesAnswer {
    let limit = std::num::NonZeroUsize::new(4096).expect("non-zero");
    wp.changes(class, &ChangesQuery { since, limit, under: None, drafts_only: false })
}

/// Returns a served page's object, parsed from the bytes the feed marshaled.
///
/// # Panics
///
/// Panics where the feed refused the page, or its body is no JSON.
fn page_object(answer: ChangesAnswer) -> serde_json::Value {
    let ChangesAnswer::Page { body } = answer else {
        panic!("the feed serves the page: {answer:?}")
    };
    serde_json::from_slice(&body).expect("the page's body is JSON")
}

/// Returns a served page's entries by position.
///
/// # Panics
///
/// Panics where the feed refused the page.
fn served(answer: ChangesAnswer) -> std::collections::BTreeMap<u64, serde_json::Value> {
    let page = page_object(answer);
    let entries = page["changes"].as_array().expect("the page's changes").clone();
    entries.into_iter().map(|e| (e["at"].as_u64().expect("at"), e)).collect()
}

/// Checks that a derived file whose landing rewrite fails takes no line.
///
/// At the walk's landing a derived file rewritten from memory carries the
/// region and every write the walk held; where its rewrite fails before the
/// rename it stands fenced at the region's lower edge without them, so it
/// stops there, as `commits.log` does on the same failure. An append after
/// the landing would raise its coverage over the region, and the next open
/// would read the region's draft writes as touching no document, which no
/// class's mask withholds (PUB-6.45). Over this suite's own kernel config
/// ([`fsync_engine`]): four draft mints with `commits.log` torn back to the
/// first, a draft minted while the walk is held, a directory on the index's
/// and the bitmap's temp names, the landing, and a draft minted after it.
/// Each refusal is said once with the fence the file stands at, and both
/// files are stopped since it; the next open pends the region's bare
/// positions, which the walk sorts behind the listener — its `open:` line
/// naming them — and, landed, the guest's page from the fence carries none
/// of the drafts and the owner's names each recorded draft by its document.
#[test]
fn a_derived_file_whose_landing_rewrite_fails_takes_no_line_after_it() {
    use skep_namespace::SYSTEM_PRINCIPAL;

    let _walks = one_walk_at_a_time();
    let dir = tempfile::tempdir().expect("tempdir");
    let engine = fsync_engine(dir.path());
    let stores = engine.stores();
    let board = a_torn_board(dir.path(), &engine);
    let (low, head) = (board[0], board[3]);
    FEED_WALK_HOLD.hold();
    let wp = open_the_write_path(dir.path(), &engine);
    assert_eq!(wp.feed_pending_region(), Some((low, head)), "the region pends");
    let (held_doc, held_at) = mint_a_draft(&wp, &stores);
    let obstacles = ["feed-index.log", "feed-masked.log"].map(|name| {
        let obstacle = dir.path().join(format!("{name}.compact"));
        std::fs::create_dir(&obstacle).expect("a directory on the temp's name");
        obstacle
    });
    FEED_WALK_HOLD.release();
    wait_until("the walk's landing", || wp.feed_pending_region().is_none());
    let said = wp.lines_said().lock().clone();
    let all = said.join("\n");
    let tail = format!(
        "; the file stands fenced at position {low}, short of what the walk landed, and takes no \
         further line, so the next open re-derives above it — the board serves from memory, and \
         nothing is lost; check the volume, its device and the board user's quota before that \
         restart: its open writes this file"
    );
    for name in ["feed-index.log", "feed-masked.log"] {
        let head =
            format!("failure: {name}: the walk's landing rewrite failed before its rename: ");
        let found = said.iter().filter(|l| l.starts_with(&head) && l.ends_with(&tail)).count();
        assert_eq!(found, 1, "{name}'s refusal, once:\n{all}");
    }
    assert_eq!(
        wp.stopped_feed_files(),
        [
            StoppedFile { name: "feed-index.log", since: low },
            StoppedFile { name: "feed-masked.log", since: low },
        ],
        "both files stopped at the fence they stand at"
    );
    let (after_doc, after_at) = mint_a_draft(&wp, &stores);
    drop(wp);
    for obstacle in &obstacles {
        std::fs::remove_dir(obstacle).expect("the obstacle goes");
    }
    let wp = open_the_write_path(dir.path(), &engine);
    assert_eq!(
        wp.feed_pending_set(),
        [board[1], board[2], board[3]],
        "the next open pends the region's bare positions, which the stopped index never took"
    );
    wait_until("the sort's landing", || !wp.feed_walk_pending());
    let classifying = format!(
        "open: feed-index.log covers to position {low}: 3 bare positions are classified from the \
         journal behind the listener, 4 world reconstructions in all"
    );
    let said = wp.lines_said().lock().clone();
    assert!(
        said.contains(&classifying),
        "the walk sorts them behind the listener:\n{}",
        said.join("\n")
    );
    let snap = engine.kernel().snapshot();
    let guest = served(page_from(&wp, &FeedClass::of(snap.world(), None), low));
    assert!(guest.is_empty(), "no draft reaches the guest: {guest:?}");
    let owner = FeedClass::of(snap.world(), Some(SYSTEM_PRINCIPAL));
    let owner = served(page_from(&wp, &owner, low));
    let positions: Vec<u64> = owner.keys().copied().collect();
    assert_eq!(positions, [board[1], board[2], board[3], held_at, after_at]);
    for (at, doc) in [(held_at, &held_doc), (after_at, &after_doc)] {
        let docs = serde_json::json!([doc.to_string()]);
        assert_eq!(owner[&at]["docs"], docs, "position {at} names its draft");
    }
}

/// Checks that `commits.log`'s landing refusal leaves the region to walk.
///
/// The landing writes the region into `commits.log` by one rewrite; where
/// that rewrite fails before its rename the file stands torn at the region's
/// lower edge and stops there, so no later write's line raises its highest
/// entry over the region and the next open walks the region again, the
/// writes held in memory since among it. Driven as the derived files' case:
/// a directory on the log's temp name during the held walk. The refusal is
/// said once, and the walk's landing says the region is re-covered in
/// memory alone; the log is stopped since the fence, a later write is served
/// from memory with its testimony and the file stands as the open found it.
/// The next open pends from the fence to the head; once it lands that write
/// is a bare entry, and the guest's page from the fence carries no draft.
#[test]
fn commits_logs_landing_refusal_leaves_the_region_to_the_next_opens_walk() {
    use skep_namespace::SYSTEM_PRINCIPAL;

    let _walks = one_walk_at_a_time();
    let dir = tempfile::tempdir().expect("tempdir");
    let engine = fsync_engine(dir.path());
    let stores = engine.stores();
    let board = a_torn_board(dir.path(), &engine);
    let (low, head) = (board[0], board[3]);
    let torn = std::fs::read(dir.path().join("commits.log")).expect("the torn file");
    FEED_WALK_HOLD.hold();
    let wp = open_the_write_path(dir.path(), &engine);
    assert_eq!(wp.feed_pending_region(), Some((low, head)), "the region pends");
    let (_, held_at) = mint_a_draft(&wp, &stores);
    let obstacle = dir.path().join("commits.log.compact");
    std::fs::create_dir(&obstacle).expect("a directory on the temp's name");
    FEED_WALK_HOLD.release();
    wait_until("the walk's landing", || wp.feed_pending_region().is_none());
    let said = wp.lines_said().lock().clone();
    let all = said.join("\n");
    let tail = format!(
        "; the file stands as it was and takes no further line, so the next open walks again from \
         position {low}; every write since this open is held in memory alone, its key and its \
         time lost at that open — restart soon; check the volume, its device and the board \
         user's quota before that restart: its open writes this file"
    );
    let head_words = "failure: commits.log: the walk's landing rewrite failed before its rename: ";
    let refused = said.iter().filter(|l| l.starts_with(head_words) && l.ends_with(&tail)).count();
    assert_eq!(refused, 1, "the landing's refusal, once:\n{all}");
    let in_memory =
        format!("landing: commits.log re-covered positions ({low}, {head}] in memory alone: ");
    assert!(said.iter().any(|l| l.starts_with(&in_memory)), "the landing's line:\n{all}");
    assert_eq!(wp.stopped_feed_files(), [StoppedFile { name: "commits.log", since: low }]);
    let (later_doc, later_at) = mint_a_draft(&wp, &stores);
    let snap = engine.kernel().snapshot();
    let owner = served(page_from(&wp, &FeedClass::of(snap.world(), Some(SYSTEM_PRINCIPAL)), low));
    assert_eq!(owner[&later_at]["key"], "bare", "served from memory with its testimony");
    assert_eq!(owner[&later_at]["docs"], serde_json::json!([later_doc.to_string()]));
    let file = std::fs::read(dir.path().join("commits.log")).expect("commits.log");
    assert_eq!(file, torn, "the file stands as the open found it");
    drop(wp);
    std::fs::remove_dir(&obstacle).expect("the obstacle goes");
    FEED_WALK_HOLD.hold();
    let wp = open_the_write_path(dir.path(), &engine);
    assert_eq!(wp.feed_pending_region(), Some((low, later_at)), "the region pends again");
    FEED_WALK_HOLD.release();
    wait_until("the walk's landing", || wp.feed_pending_region().is_none());
    let snap = engine.kernel().snapshot();
    let owner = served(page_from(&wp, &FeedClass::of(snap.world(), Some(SYSTEM_PRINCIPAL)), low));
    let positions: Vec<u64> = owner.keys().copied().collect();
    assert_eq!(positions, [board[1], board[2], board[3], held_at, later_at]);
    for field in ["key", "time", "docs"] {
        let lost = &owner[&later_at][field];
        assert_eq!(*lost, serde_json::Value::Null, "the later write comes back bare: {field}");
    }
    let guest = served(page_from(&wp, &FeedClass::of(snap.world(), None), low));
    assert!(guest.is_empty(), "the journal's classification masks every draft: {guest:?}");
}

/// Checks that a walk whose thread the OS refuses runs at the open.
///
/// The walk's thread is spawned fallibly, as the daemon's other threads
/// are: where the OS refuses it the region is walked inline before the open
/// returns, the board serving once the walk lands, and the refusal is said
/// with its cause. Over `commits.log` torn back three entries, the seam's
/// refusal: the line said once, the walk's landing said before the open
/// returns, nothing pending when it does, no thread to have ended, and the
/// region's positions served.
#[test]
fn a_walk_whose_thread_the_os_refuses_is_walked_at_the_open() {
    use skep_namespace::SYSTEM_PRINCIPAL;

    let _walks = one_walk_at_a_time();
    let dir = tempfile::tempdir().expect("tempdir");
    let engine = fsync_engine(dir.path());
    let board = a_torn_board(dir.path(), &engine);
    let (low, head) = (board[0], board[3]);
    REFUSE_THE_FEED_WALKS_THREAD.store(true, Ordering::Release);
    let wp = open_the_write_path(dir.path(), &engine);
    assert!(!REFUSE_THE_FEED_WALKS_THREAD.load(Ordering::Acquire), "the seam fired once");
    assert_eq!(wp.feed_pending_region(), None, "the open walked the region before it returned");
    let said = wp.lines_said().lock().clone();
    let all = said.join("\n");
    let refused = format!(
        "failure: the feed walk: the OS refused its thread (test seam: the walk's thread \
         refused); positions ({low}, {head}] are walked at the open instead, the board serving \
         once the walk lands"
    );
    assert_eq!(said.iter().filter(|l| **l == refused).count(), 1, "the refusal, once:\n{all}");
    let landing =
        format!("landing: commits.log re-covered positions ({low}, {head}]: 3 boundaries walked");
    assert!(said.iter().any(|l| l.starts_with(&landing)), "the walk landed at the open:\n{all}");
    assert_eq!(wp.feed_walk_gone(), None, "no thread was there to end");
    let snap = engine.kernel().snapshot();
    let owner = served(page_from(&wp, &FeedClass::of(snap.world(), Some(SYSTEM_PRINCIPAL)), low));
    let positions: Vec<u64> = owner.keys().copied().collect();
    assert_eq!(positions, board[1..]);
}

/// Checks that a panic in the walk run at the open is caught, and said.
///
/// Where the OS refuses the walk's thread the region is walked at the open,
/// and a panic there would end the process with the open. It runs under the
/// thread's own catch instead: the open returns, the walk's end is said in
/// the operator's terms with the region it left uncovered, the liveness flag
/// the standing line reads is set, and the region pends for the uptime —
/// the board serving.
#[test]
fn a_panic_in_the_walk_run_at_the_open_is_caught_and_the_open_goes_on() {
    let _walks = one_walk_at_a_time();
    let dir = tempfile::tempdir().expect("tempdir");
    let engine = fsync_engine(dir.path());
    let board = a_torn_board(dir.path(), &engine);
    let (low, head) = (board[0], board[3]);
    REFUSE_THE_FEED_WALKS_THREAD.store(true, Ordering::Release);
    arm_the_feed_walks_fault();
    let wp = open_the_write_path(dir.path(), &engine);
    assert!(!REFUSE_THE_FEED_WALKS_THREAD.load(Ordering::Acquire), "the seam fired once");
    assert_eq!(wp.feed_pending_region(), Some((low, head)), "the region pends for the uptime");
    let pending = FeedPending { region: Some((low, head)), unsorted: None };
    assert_eq!(wp.feed_walk_gone(), Some(pending), "the flag the standing line reads");
    let said = wp.lines_said().lock().clone();
    let all = said.join("\n");
    let ended = FeedWalkEndedLine { payload: "the test seam's fault in the feed walk", pending }
        .to_string();
    assert_eq!(
        said.iter().filter(|l| **l == format!("failure: {ended}")).count(),
        1,
        "the walk's end, said once in the operator's terms:\n{all}"
    );
    assert!(
        said.iter().any(|l| l.contains("the OS refused its thread")),
        "the refusal said before it:\n{all}"
    );
}

/// Checks that a landing cut between its rewrites leaves the region pending.
///
/// The landing rewrites the classified files first and `commits.log` after
/// them, so a kill between the two leaves `commits.log` as the open found it
/// and the next open walks the region again behind the listener. The other
/// order would leave the log whole over derived files fenced below the
/// region, and the next open would find every bare position of it unsorted,
/// a world reconstruction each for the walk thread. The seam ends the
/// landing between its rewrites, leaving the files as a kill there leaves
/// them; opened again with the walk held, the region pends from its lower
/// edge, no bare position is left for the sort, and the walk lands it.
#[test]
fn a_landing_cut_between_its_rewrites_leaves_the_region_to_walk_again() {
    let _walks = one_walk_at_a_time();
    let dir = tempfile::tempdir().expect("tempdir");
    let engine = fsync_engine(dir.path());
    let board = a_torn_board(dir.path(), &engine);
    let (low, head) = (board[0], board[3]);
    feed::CUT_THE_NEXT_LANDING.store(true, Ordering::Release);
    let wp = open_the_write_path(dir.path(), &engine);
    wait_until("the landing's cut", || !feed::CUT_THE_NEXT_LANDING.load(Ordering::Acquire));
    drop(wp);
    FEED_WALK_HOLD.hold();
    let wp = open_the_write_path(dir.path(), &engine);
    assert_eq!(wp.feed_pending_region(), Some((low, head)), "the region pends from its edge");
    assert!(wp.feed_pending_set().is_empty(), "no bare position is left for the sort");
    let said = wp.lines_said().lock().clone();
    assert!(
        !said.iter().any(|l| l.contains("bare positions are classified from the journal")),
        "no sort is announced:\n{}",
        said.join("\n")
    );
    FEED_WALK_HOLD.release();
    wait_until("the walk's landing", || wp.feed_pending_region().is_none());
}

/// Checks that the walk's fence over damage lifts once its two files return.
///
/// A walk the journal refuses below the head fences the feed at the
/// position below the head, and its landing writes that fence into
/// `commits.log`, which every later open reads back: the damaged segment
/// restored alone moves nothing, and `commits.log` put back beside it from
/// the copy taken before the open re-covers the region. Over this suite's
/// own kernel config ([`fsync_engine`]): a checkpoint inside the first
/// segment and one past the segment it closes, so the walk's base lies
/// below the damage and the open's start point above it; that segment
/// damaged and `commits.log` torn back below the damage. The walk's list is
/// refused and said with the act, and the landing fences the feed; the
/// segment restored alone, the feed still answers `410` below the fence;
/// `commits.log` restored too, the region pends again and, landed, the feed
/// answers every position it answered before.
#[test]
fn the_walks_fence_over_damage_lifts_once_the_segment_and_the_log_return() {
    use skep_address::Nat;
    use skep_arrangement::Caller;
    use skep_febe::{Deposit, VPos};
    use skep_namespace::SYSTEM_PRINCIPAL;

    let _walks = one_walk_at_a_time();
    let dir = tempfile::tempdir().expect("tempdir");
    let engine = fsync_engine(dir.path());
    let stores = engine.stores();
    let wp = open_the_write_path(dir.path(), &engine);
    let (doc, low) = mint_a_draft(&wp, &stores);
    engine.kernel().checkpoint().expect("the checkpoint inside the first segment");
    // Five inserts of the codec's whole cap, each one stretch: the fifth
    // rotates the journal's segment, closing the first.
    let bulk: Vec<Val> = "z".repeat(262_144).bytes().map(|b| Val::new([b])).collect();
    let at = || VPos::content(Nat::from(1u32));
    for _ in 0..5 {
        let op = Op::Insert {
            doc: doc.clone(),
            at: at(),
            values: bulk.clone(),
            deposit: Deposit::Undeclared,
        };
        let meta = write_meta(&op).expect("a write").attributed("bare".to_string(), None);
        let serial = wp.serial_lock();
        let resp = wp.commit_under(&serial, meta, || {
            let (addr, at) = stores
                .vstream()
                .insert(
                    Caller::Principal(SYSTEM_PRINCIPAL),
                    &doc,
                    at(),
                    bulk.clone(),
                    Deposit::Undeclared,
                )
                .expect("the insert commits");
            Response::AckAddr { addr, at }
        });
        assert!(matches!(resp, Response::AckAddr { .. }), "the insert is acked");
    }
    engine.kernel().checkpoint().expect("the checkpoint past the closed segment");
    let head = engine.kernel().current_seq().0;
    let snap = engine.kernel().snapshot();
    let owner = FeedClass::of(snap.world(), Some(SYSTEM_PRINCIPAL));
    let before: Vec<u64> = served(page_from(&wp, &owner, low)).into_keys().collect();
    drop(wp);
    let mut segments: Vec<(u64, std::path::PathBuf)> = std::fs::read_dir(dir.path())
        .expect("the journal directory")
        .filter_map(|entry| {
            let entry = entry.ok()?;
            let name = entry.file_name().into_string().ok()?;
            let first: u64 = name.strip_prefix("seg-")?.strip_suffix(".wal")?.parse().ok()?;
            Some((first, entry.path()))
        })
        .collect();
    segments.sort();
    assert!(segments.len() >= 2, "the fifth insert rotated the segment: {segments:?}");
    let newest = engine.kernel().newest_checkpoint().expect("a checkpoint").seq.0;
    assert!(newest >= segments[1].0, "the open's start point lies past the closed segment");
    let closed = &segments[0].1;
    let whole = std::fs::read(closed).expect("the closed segment");
    let flip = (whole.len() / 2..whole.len()).find(|&i| whole[i] == b'z').expect("a stretch byte");
    let mut damaged = whole.clone();
    damaged[flip] = b'y';
    std::fs::write(closed, &damaged).expect("damage the segment");
    let torn = tear_to(dir.path(), low);
    let fence = head - 1;
    let reclaimed = |wp: &Commits| {
        let snap = engine.kernel().snapshot();
        page_from(wp, &FeedClass::of(snap.world(), Some(SYSTEM_PRINCIPAL)), low)
    };

    // The walk's list refused: said with the act, and the fence landed.
    let wp = open_the_write_path(dir.path(), &engine);
    wait_until("the walk's landing", || wp.feed_pending_region().is_none());
    let said = wp.lines_said().lock().clone();
    let all = said.join("\n");
    let head_words = format!(
        "failure: commits.log's walk: the journal refused the boundaries above position {low} \
         (journal corrupt at rest; "
    );
    let tail = format!(
        "): once the walk lands the change feed answers 410 history_reclaimed for every since \
         below position {fence}; the walk goes on, and its landing writes that fence into \
         commits.log, which a segment restored alone does not move — to re-cover the positions, \
         stop the daemon, put back the segment the account names and commits.log from a copy \
         taken before this open, and start again (RUNBOOK §2)"
    );
    let refused = said.iter().filter(|l| l.starts_with(&head_words) && l.ends_with(&tail)).count();
    assert_eq!(refused, 1, "the walk's refusal, with the act:\n{all}");
    let answer = reclaimed(&wp);
    assert!(
        matches!(answer, ChangesAnswer::Reclaimed { floor: Some(f) } if f == head),
        "410 below the fence: {answer:?}"
    );
    drop(wp);
    // The fence is written after the lines the file held — none dropped,
    // the record of events kept whole — and ahead of what the walk landed.
    let text = std::fs::read(dir.path().join("commits.log")).expect("commits.log");
    assert!(text.starts_with(&torn), "the torn file's own lines first, verbatim");
    let fence_line = format!("{{\"min_since\":{fence}}}\n");
    assert!(
        text[torn.len()..].starts_with(fence_line.as_bytes()),
        "the fence is written right after them: {}",
        String::from_utf8_lossy(&text[torn.len()..])
    );

    // The segment restored alone: the fence the file holds stands.
    std::fs::write(closed, &whole).expect("restore the segment");
    let wp = open_the_write_path(dir.path(), &engine);
    assert_eq!(wp.feed_pending_region(), None, "the file covers the head");
    let answer = reclaimed(&wp);
    assert!(
        matches!(answer, ChangesAnswer::Reclaimed { floor: Some(f) } if f == head),
        "still 410 below the fence: {answer:?}"
    );
    drop(wp);

    // `commits.log` put back beside it: the region pends and lands again.
    std::fs::write(dir.path().join("commits.log"), &torn).expect("restore the log");
    FEED_WALK_HOLD.hold();
    let wp = open_the_write_path(dir.path(), &engine);
    assert_eq!(wp.feed_pending_region(), Some((low, head)), "the region pends again");
    FEED_WALK_HOLD.release();
    wait_until("the walk's landing", || wp.feed_pending_region().is_none());
    let after: Vec<u64> = served(reclaimed(&wp)).into_keys().collect();
    assert_eq!(after, before, "the feed answers every position it answered before");
}

/// Checks that the attest store's resident slots are bounded by the window.
///
/// The slots resident are one per attested position inside the feed's
/// resident window, so as the window rises with each record the slots
/// below it leave the twins (`Inner::drop_below_the_window`), and the
/// store's file, primary state (BW-01), keeps every line — each read back
/// by position for a row below the window. Over this suite's own kernel
/// config ([`fsync_engine`]), the window set to four positions for this
/// board alone: six attested bulk inserts into one draft, a checkpoint
/// taken by hand that moves the reclaim floor past some of them and trims
/// nothing, the slots resident those of the window alone, the file's bytes
/// and lines unchanged; the system principal's page from genesis serves
/// every row's `attest`, the ones below the window off the file; one more
/// attested write adds its slot, and the page serves that row's `attest`.
#[test]
fn the_attest_stores_resident_slots_are_bounded_by_the_window_and_its_file_kept() {
    use skep_address::Nat;
    use skep_arrangement::Caller;
    use skep_febe::{Deposit, VPos};
    use skep_namespace::SYSTEM_PRINCIPAL;

    let dir = tempfile::tempdir().expect("tempdir");
    set_feed_resident_window(dir.path(), 4);
    let engine = fsync_engine(dir.path());
    let wp = open_the_write_path(dir.path(), &engine);
    let stores = engine.stores();
    let (doc, _) = mint_a_draft(&wp, &stores);
    let slot = Attestation::new(1, vec![0xab; 8]).expect("tag 1 and a non-empty blob");
    // One attested insert through the session door, the kernel writing the
    // slot into its marker and the write path mirroring it.
    let insert = |value: &str| -> u64 {
        let values: Vec<Val> = value.bytes().map(|b| Val::new([b])).collect();
        let at = VPos::content(Nat::from(1u32));
        let op = Op::Insert {
            doc: doc.clone(),
            at: at.clone(),
            values: values.clone(),
            deposit: Deposit::Undeclared,
        };
        let signed = Some(Signed::Marker(slot.clone()));
        let meta = write_meta(&op).expect("a write").attributed("cd".repeat(32), signed);
        let serial = wp.serial_lock();
        let resp = wp.commit_under(&serial, meta, || {
            let (addr, at) = stores
                .vstream_attested(Some(&slot))
                .insert(Caller::Principal(SYSTEM_PRINCIPAL), &doc, at, values, Deposit::Undeclared)
                .expect("the insert commits");
            Response::AckAddr { addr, at }
        });
        let Response::AckAddr { at, .. } = resp else { panic!("the insert is acked") };
        at.0
    };
    let bulk = "z".repeat(262_144);
    let attested: Vec<u64> = (0..6).map(|_| insert(&bulk)).collect();
    let lines_of_the_file = || {
        std::fs::read_to_string(dir.path().join("feed-attest.log"))
            .expect("the attest store's file")
            .lines()
            .filter(|l| l.contains(r#""at":"#))
            .count()
    };
    let held = wp.attest_store_figures();
    let head = engine.kernel().current_seq().0;
    let inside = |at: u64| at + 4 > head;
    let resident = attested.iter().filter(|&&at| inside(at)).count();
    assert!(resident < attested.len(), "the premise: the window passed an attested position");
    assert_eq!(
        (held.slots, lines_of_the_file()),
        (resident, 6),
        "a slot per attested insert inside the window, a line per insert"
    );
    let expect_attest = |page: &std::collections::BTreeMap<u64, serde_json::Value>| {
        for at in &attested {
            assert_eq!(
                page[at]["attest"],
                serde_json::json!({"alg": "mldsa65-ed25519", "sig": "ab".repeat(8)}),
                "the page serves {at}'s slot, off the file below the window"
            );
        }
    };
    let snap = engine.kernel().snapshot();
    expect_attest(&served(page_from(&wp, &FeedClass::of(snap.world(), Some(SYSTEM_PRINCIPAL)), 0)));

    // The checkpoint thread's act: the checkpoint, then the feed's figures —
    // the reclaim floor moves past attested positions and trims nothing.
    engine.kernel().checkpoint().expect("the checkpoint lands");
    let figures = wp.feed_figures();
    assert_eq!(figures.first, Some(1), "the feed holds every line from its first");
    let after = wp.attest_store_figures();
    assert_eq!(after.slots, held.slots, "the floor moved and no slot left: the window bounds them");
    assert_eq!(after.bytes, held.bytes, "the file is never compacted");
    assert_eq!(lines_of_the_file(), 6, "every line kept: primary state");

    let at = insert("q");
    // The head writer takes its turn after the write, so the window's edge
    // is the head's as it then stands.
    let head = engine.kernel().current_seq().0;
    let expected = attested.iter().chain([&at]).filter(|&&p| p + 4 > head).count();
    assert_eq!(
        wp.attest_store_figures().slots,
        expected,
        "the slots inside the window as the head stands, the next attested write's among them"
    );
    let snap = engine.kernel().snapshot();
    let page = served(page_from(&wp, &FeedClass::of(snap.world(), Some(SYSTEM_PRINCIPAL)), 0));
    expect_attest(&page);
    assert_eq!(
        page[&at]["attest"],
        serde_json::json!({"alg": "mldsa65-ed25519", "sig": "ab".repeat(8)}),
        "the page from genesis serves the new slot"
    );
}

/// Checks that a principal's page merges one stream per owner account.
///
/// PUB-7.28 prices a page by the streams it merges, and PUB-7.24 rules out
/// one list per visible draft document, so the merge's width
/// ([`Feed::merge_width`]) is a function of the accounts a class opens and
/// never of how many drafts they hold. The system principal opens its own
/// account's stream beside the published walk: two sources over three
/// drafts, and two again over six, every draft on the page.
#[test]
fn a_principals_page_merges_one_stream_per_owner_account_whatever_its_drafts() {
    use skep_namespace::SYSTEM_PRINCIPAL;

    let dir = tempfile::tempdir().expect("tempdir");
    let engine = fsync_engine(dir.path());
    let wp = open_the_write_path(dir.path(), &engine);
    let stores = engine.stores();
    let limit = std::num::NonZeroUsize::new(4096).expect("non-zero");
    let query = ChangesQuery { since: 0, limit, under: None, drafts_only: false };
    let mut drafts = Vec::new();
    for _ in 0..2 {
        drafts.extend((0..3).map(|_| mint_a_draft(&wp, &stores)));
        let snap = engine.kernel().snapshot();
        let class = FeedClass::of(snap.world(), Some(SYSTEM_PRINCIPAL));
        assert_eq!(
            wp.feed.merge_width(&class, &query),
            2,
            "the published walk and the account's one stream, over {} drafts",
            drafts.len()
        );
        let page = served(page_from(&wp, &class, 0));
        for (doc, at) in &drafts {
            assert_eq!(page[at]["docs"], serde_json::json!([doc.to_string()]), "{doc} on the page");
        }
    }
}

/// Checks that an attested write's sync holds no lock a page takes.
///
/// The record step writes the attest line under the change feed's lock and
/// makes it durable once that lock is released, under the serialization
/// guard alone (SO-I5 (d); `Feed::sync_the_attest_line`). With the record
/// step held between the two by the feed's test seam, `head_time` and a page
/// answer — the page serving the held write's row and its `attest`, the
/// journal's marker already durable — and, the hold released, the line is
/// synced through the write's own position and the write path admits writes.
#[test]
fn an_attested_writes_sync_holds_no_lock_a_page_takes() {
    use skep_namespace::SYSTEM_PRINCIPAL;

    let dir = tempfile::tempdir().expect("tempdir");
    let engine = fsync_engine(dir.path());
    let wp = open_the_write_path(dir.path(), &engine);
    let stores = engine.stores();
    let slot = Attestation::new(1, vec![0xab; 8]).expect("tag 1 and a non-empty blob");
    let hold = &wp.feed.attest_sync_hold;
    hold.hold();
    let (answered, at) = thread::scope(|s| {
        let writer = s.spawn(|| mint_a_draft_attested(&wp, &stores, Some(&slot)).1);
        wait_until("the record step parks at the attest line's sync", || hold.parked());
        let (tx, rx) = std::sync::mpsc::channel();
        let (wp, engine) = (&wp, &engine);
        let reader = s.spawn(move || {
            let snap = engine.kernel().snapshot();
            let class = FeedClass::of(snap.world(), Some(SYSTEM_PRINCIPAL));
            let _ = tx.send((wp.head_time(), page_from(wp, &class, 0)));
        });
        let answered = rx.recv_timeout(Duration::from_secs(10));
        hold.release();
        reader.join().expect("the reader returns");
        (answered, writer.join().expect("the attested mint is acked"))
    });
    let (head_time, page) = answered.expect("head_time and a page answer while the sync is owed");
    assert!(head_time.is_some(), "the held write is the head, its time recorded");
    assert_eq!(
        served(page)[&at]["attest"],
        serde_json::json!({"alg": "mldsa65-ed25519", "sig": "ab".repeat(8)}),
        "the held write's row, served"
    );
    assert_eq!(wp.attest_store_synced_through(), at, "the line synced once the hold released");
    assert_eq!(wp.halted_at(), None, "and the write path admits writes");
}

/// Checks that a page is marshaled once into the bytes the wire carries.
///
/// `Feed::page` writes each row into the page object's bytes as it measures
/// it, so the body is the object `obj` would build — compact, its keys and
/// every row's sorted — and is its own parse marshaled again: a whole page
/// (`more` false, `last` its final row), a page cut at its limit (`more`
/// true), and the two empty pages, `since` at the head and at the top of the
/// range, spelled out byte for byte.
#[test]
fn a_page_is_marshaled_once_into_the_bytes_the_wire_carries() {
    use skep_namespace::SYSTEM_PRINCIPAL;

    let dir = tempfile::tempdir().expect("tempdir");
    let engine = fsync_engine(dir.path());
    let wp = open_the_write_path(dir.path(), &engine);
    let stores = engine.stores();
    let board: Vec<u64> = (0..3).map(|_| mint_a_draft(&wp, &stores).1).collect();
    let snap = engine.kernel().snapshot();
    let class = FeedClass::of(snap.world(), Some(SYSTEM_PRINCIPAL));
    let body = |since: u64, limit: usize| -> Vec<u8> {
        let limit = std::num::NonZeroUsize::new(limit).expect("non-zero");
        match wp.changes(&class, &ChangesQuery { since, limit, under: None, drafts_only: false }) {
            ChangesAnswer::Page { body } => body,
            other => panic!("the feed serves the page: {other:?}"),
        }
    };
    let canonical = |body: Vec<u8>| -> serde_json::Value {
        let page: serde_json::Value = serde_json::from_slice(&body).expect("the body is JSON");
        let again = crate::codec::to_bytes(&page);
        assert_eq!(
            String::from_utf8(again).expect("utf-8"),
            String::from_utf8(body).expect("utf-8"),
            "the body is its own parse marshaled again"
        );
        page
    };
    let at = |page: &serde_json::Value| -> Vec<u64> {
        let rows = page["changes"].as_array().expect("the page's changes");
        rows.iter().map(|row| row["at"].as_u64().expect("at")).collect()
    };
    let whole = canonical(body(0, 4096));
    assert_eq!(at(&whole), board, "every row, oldest first");
    assert_eq!((&whole["last"], &whole["more"]), (&board[2].into(), &false.into()));
    let cut = canonical(body(0, 1));
    assert_eq!(at(&cut), board[..1], "the first row alone");
    assert_eq!((&cut["last"], &cut["more"]), (&board[0].into(), &true.into()));
    let head = board[2];
    assert_eq!(
        String::from_utf8(body(head, 4096)).expect("utf-8"),
        format!(r#"{{"changes":[],"last":{head},"more":false}}"#),
        "the empty page at the head"
    );
    assert_eq!(
        String::from_utf8(body(u64::MAX, 1)).expect("utf-8"),
        format!(r#"{{"changes":[],"last":{},"more":false}}"#, u64::MAX),
        "the empty page at the top of the range"
    );
}

/// Checks that the walk loads one base per boundary it proves.
///
/// `operations.md` §3.3 step 2 prices the walk behind the listener at one
/// world reconstruction per boundary, and a reconstruction's cost is the
/// base its history read loads, which the kernel counts at its one site
/// (`Kernel::bases_loaded`). Over eight draft mints with `commits.log` torn
/// back to the second, the walk proves six boundaries, held past its `open:`
/// line, where the list's one scan is already paid: released, it loads the
/// world at the region's edge, one per boundary but the head, whose world is
/// the open's own snapshot, and the landing's floor probe — one more base
/// than the boundaries it proves.
#[test]
fn the_walk_loads_one_base_per_boundary_it_proves() {
    let _walks = one_walk_at_a_time();
    let dir = tempfile::tempdir().expect("tempdir");
    let engine = fsync_engine(dir.path());
    let stores = engine.stores();
    let wp = open_the_write_path(dir.path(), &engine);
    let board: Vec<u64> = (0..8).map(|_| mint_a_draft(&wp, &stores).1).collect();
    drop(wp);
    let (low, head) = (board[1], board[7]);
    tear_to(dir.path(), low);
    FEED_WALK_HOLD.hold();
    let wp = open_the_write_path(dir.path(), &engine);
    let walking = format!(
        "open: commits.log covers to position {low}; walking 6 boundaries to position {head}"
    );
    wait_until("the walk's open line", || wp.lines_said().lock().contains(&walking));
    let before = engine.kernel().bases_loaded();
    FEED_WALK_HOLD.release();
    wait_until("the walk's landing", || wp.feed_pending_region().is_none());
    assert_eq!(
        engine.kernel().bases_loaded() - before,
        6,
        "one base per boundary proved: the region's edge, five boundaries but the head — the \
         landing probes no floor, the feed's files being kept whole"
    );
}

/// Checks that the walk rebuilds each bare position's world once.
///
/// Where `feed-index.log` is lost, the walk thread classifies every bare
/// position from the journal behind the listener (PUB-6.45), the open
/// paying no reconstruction. A run of them is what a walk's landing writes,
/// and the world at one is the world below the next, so the sort carries it
/// forward as the region's walk does: the run costs one reconstruction a
/// position and one below its first, and the head's world is the open's
/// snapshot. Over eight draft mints with `commits.log` torn back to the
/// second, the walk lands six bare positions; with the index lost, the
/// reopen loads the floor probe's base alone and returns at once with the
/// six pending; the sort then loads six for the run — the seven the region's
/// walk loads for the same six, less the landing's probe — classifies each
/// position as the walk did, and says the six it will pay ahead of paying
/// them and the six it paid once done, the landing's probe one more base.
#[test]
fn a_lost_feed_index_reconstructs_each_bare_position_once() {
    let _walks = one_walk_at_a_time();
    let dir = tempfile::tempdir().expect("tempdir");
    let engine = fsync_engine(dir.path());
    let stores = engine.stores();
    let wp = open_the_write_path(dir.path(), &engine);
    let board: Vec<u64> = (0..8).map(|_| mint_a_draft(&wp, &stores).1).collect();
    drop(wp);
    tear_to(dir.path(), board[1]);
    let wp = open_the_write_path(dir.path(), &engine);
    wait_until("the walk's landing", || wp.feed_pending_region().is_none());
    drop(wp);
    // The index's records by position, the fence line skipped.
    let index_path = dir.path().join("feed-index.log");
    let index = || -> std::collections::BTreeMap<u64, serde_json::Value> {
        std::fs::read_to_string(&index_path)
            .expect("feed-index.log")
            .lines()
            .map(|line| serde_json::from_str::<serde_json::Value>(line).expect("a line is JSON"))
            .filter_map(|record| Some((record.get("at")?.as_u64()?, record.get("docs")?.clone())))
            .collect()
    };
    let walked = index();
    assert!(
        board[2..].iter().all(|at| walked.contains_key(at)),
        "the premise: the walk classified the six bare positions it landed: {walked:?}"
    );
    std::fs::remove_file(&index_path).expect("lose the index");
    let before = engine.kernel().bases_loaded();
    FEED_WALK_HOLD.hold();
    let wp = open_the_write_path(dir.path(), &engine);
    assert_eq!(engine.kernel().bases_loaded() - before, 1, "the open pays the floor probe alone");
    assert_eq!(wp.feed_pending_set(), board[2..], "the six pend for the walk");
    FEED_WALK_HOLD.release();
    wait_until("the sort's landing", || !wp.feed_walk_pending());
    assert_eq!(
        engine.kernel().bases_loaded() - before,
        1 + 6,
        "the open's probe; the world below the run and one a bare position but the head — the \
         landing probes no floor, the feed's files being kept whole"
    );
    assert_eq!(index(), walked, "each position classified as the walk classified it");
    let said = wp.lines_said().lock().clone();
    let all = said.join("\n");
    // The index's coverage as the open left it: rewritten fenced below the
    // first unsorted position, at the second mint.
    let planned = format!(
        "open: feed-index.log covers to position {}: 6 bare positions are classified from the \
         journal behind the listener, 6 world reconstructions in all",
        board[1]
    );
    let found = said.iter().filter(|l| **l == planned).count();
    assert_eq!(found, 1, "the reconstructions counted ahead of paying them:\n{all}");
    let paid = "landing: feed-index.log: 6 of 6 bare positions classified from the journal, 6 \
                world reconstructions, in ";
    let found = said.iter().filter(|l| l.starts_with(paid) && l.ends_with(" ms")).count();
    assert_eq!(found, 1, "the reconstructions paid:\n{all}");
}

/// Checks that a lost index is sorted behind the listener, the open serving.
///
/// Over eight draft mints with `commits.log` torn back to the second and
/// walked, the index lost: the reopen returns at once with the six bare
/// positions pending and the four files fenced below the first of them —
/// the walk held. A page that would reach an unsorted position is refused
/// as the region's pages are, naming the set; a page whose rows all lie
/// below the first unsorted position serves with `more: true`; a page from
/// the head serves. A draft minted while the set pends takes its line in
/// `commits.log` and in no index file. Released, the walk lands: the pages
/// equal a never-lost board's, the write among them, every index file
/// covering the head and agreeing with the twins.
#[test]
fn a_lost_feed_index_is_sorted_behind_the_listener_and_pages_reaching_it_wait() {
    use skep_namespace::SYSTEM_PRINCIPAL;

    let _walks = one_walk_at_a_time();
    let dir = tempfile::tempdir().expect("tempdir");
    let engine = fsync_engine(dir.path());
    let stores = engine.stores();
    let wp = open_the_write_path(dir.path(), &engine);
    let board: Vec<u64> = (0..8).map(|_| mint_a_draft(&wp, &stores).1).collect();
    drop(wp);
    tear_to(dir.path(), board[1]);
    let wp = open_the_write_path(dir.path(), &engine);
    wait_until("the walk's landing", || wp.feed_pending_region().is_none());
    let snap = engine.kernel().snapshot();
    let owner = FeedClass::of(snap.world(), Some(SYSTEM_PRINCIPAL));
    let before = page_object(page_from(&wp, &owner, 0));
    drop(wp);
    std::fs::remove_file(dir.path().join("feed-index.log")).expect("lose the index");
    let log_before = std::fs::read(dir.path().join("commits.log")).expect("commits.log");

    FEED_WALK_HOLD.hold();
    let wp = open_the_write_path(dir.path(), &engine);
    assert_eq!(wp.feed_pending_set(), board[2..], "every bare position the index lost pends");
    assert_eq!(wp.feed_pending_region(), None, "the log covers the head");
    let coverage = |name: &str| -> u64 {
        std::fs::read_to_string(dir.path().join(name))
            .expect(name)
            .lines()
            .map(|line| serde_json::from_str::<serde_json::Value>(line).expect("a line is JSON"))
            .filter_map(|r| r.get("covered").or(r.get("at"))?.as_u64())
            .max()
            .unwrap_or(0)
    };
    for name in ["feed-index.log", "feed-offsets.log", "feed-masked.log", "feed-streams.log"] {
        assert_eq!(coverage(name), board[1], "{name} is fenced below the set");
    }
    let snap = engine.kernel().snapshot();
    let owner = FeedClass::of(snap.world(), Some(SYSTEM_PRINCIPAL));
    let limit = |n: usize| std::num::NonZeroUsize::new(n).expect("non-zero");
    let page = |since: u64, n: usize| {
        wp.changes(
            &owner,
            &ChangesQuery { since, limit: limit(n), under: None, drafts_only: false },
        )
    };
    let refused = |answer: ChangesAnswer| match answer {
        ChangesAnswer::Rebuilding { pending } => pending,
        other => panic!("refused, naming the set: {other:?}"),
    };
    let pending = refused(page(board[1], 1));
    assert_eq!(
        pending,
        FeedPending {
            region: None,
            unsorted: Some(Unsorted { count: 6, first: board[2], last: board[7] }),
        },
        "a page reaching the first unsorted position is refused, the set named"
    );
    refused(page(0, 3));
    let below = page_object(page(0, 2));
    assert_eq!(
        below["changes"].as_array().expect("rows").len(),
        2,
        "a page whose rows lie below the set serves"
    );
    assert_eq!(below["more"], serde_json::Value::Bool(true), "and says more follows");
    let above = page_object(page(board[7], 4));
    assert!(above["changes"].as_array().expect("rows").is_empty(), "from the head: nothing yet");

    // A write while the set pends: the log takes its line, no index file does.
    let (held_doc, held_at) = mint_a_draft(&wp, &stores);
    let log_now = std::fs::read(dir.path().join("commits.log")).expect("commits.log");
    assert!(log_now.len() > log_before.len(), "commits.log keeps appending");
    for name in ["feed-index.log", "feed-offsets.log", "feed-masked.log", "feed-streams.log"] {
        assert_eq!(coverage(name), board[1], "{name} takes no line while the set pends");
    }
    let served = served(page(board[7], 4));
    assert_eq!(served.keys().copied().collect::<Vec<_>>(), [held_at], "served from memory");

    FEED_WALK_HOLD.release();
    wait_until("the sort's landing", || !wp.feed_walk_pending());
    let after = page_object(page(0, 4096));
    let before_rows = before["changes"].as_array().expect("rows");
    let after_rows = after["changes"].as_array().expect("rows");
    assert_eq!(&after_rows[..before_rows.len()], before_rows.as_slice(), "as never lost");
    let last = after_rows.last().expect("the write");
    assert_eq!(last["at"].as_u64(), Some(held_at));
    assert_eq!(last["docs"], serde_json::json!([held_doc.to_string()]), "the write, whole");
    for name in ["feed-index.log", "feed-offsets.log", "feed-masked.log", "feed-streams.log"] {
        assert_eq!(coverage(name), held_at, "{name} covers the head after the landing");
    }
    let said = wp.lines_said().lock().clone();
    assert!(
        said.iter().any(|l| l.starts_with("landing: feed-index.log: 6 of 6 bare positions")),
        "the landing line:\n{}",
        said.join("\n")
    );
}

/// Checks that a kill mid-sort keeps the positions sorted so far.
///
/// Over the same board, the hold armed after the third position: the walk
/// sorts three and parks, each landed and appended to the index as it was
/// sorted; the write path dropped there — the stop ends the walk with
/// nothing further written, a kill's shape — and reopened with the walk
/// held, the next open pends the three left and never the three sorted,
/// pays no reconstruction itself, and the released walk lands the rest: the
/// pages equal the never-lost board's, and each position's index record
/// stands once.
#[test]
fn a_kill_mid_sort_keeps_the_positions_sorted_so_far() {
    use skep_namespace::SYSTEM_PRINCIPAL;

    let _walks = one_walk_at_a_time();
    let dir = tempfile::tempdir().expect("tempdir");
    let engine = fsync_engine(dir.path());
    let stores = engine.stores();
    let wp = open_the_write_path(dir.path(), &engine);
    let board: Vec<u64> = (0..8).map(|_| mint_a_draft(&wp, &stores).1).collect();
    drop(wp);
    tear_to(dir.path(), board[1]);
    let wp = open_the_write_path(dir.path(), &engine);
    wait_until("the walk's landing", || wp.feed_pending_region().is_none());
    let snap = engine.kernel().snapshot();
    let owner = FeedClass::of(snap.world(), Some(SYSTEM_PRINCIPAL));
    let before = served(page_from(&wp, &owner, 0));
    drop(wp);
    let index_path = dir.path().join("feed-index.log");
    std::fs::remove_file(&index_path).expect("lose the index");

    FEED_WALK_HOLD.hold_after_sorting(3);
    let wp = open_the_write_path(dir.path(), &engine);
    wait_until("three sorted", || wp.feed_pending_set() == board[5..]);
    let index_ats = || -> Vec<u64> {
        std::fs::read_to_string(&index_path)
            .expect("feed-index.log")
            .lines()
            .map(|line| serde_json::from_str::<serde_json::Value>(line).expect("a line is JSON"))
            .filter_map(|r| r.get("at")?.as_u64())
            .collect()
    };
    assert_eq!(
        index_ats(),
        board[..5],
        "the two recorded positions the open wrote, then each sorted position appended as it \
         was sorted"
    );
    drop(wp);
    FEED_WALK_HOLD.release();

    FEED_WALK_HOLD.hold();
    let probes = engine.kernel().bases_loaded();
    let wp = open_the_write_path(dir.path(), &engine);
    assert_eq!(engine.kernel().bases_loaded() - probes, 1, "the open pays its floor probe alone");
    assert_eq!(wp.feed_pending_set(), board[5..], "the three left pend, the three sorted do not");
    FEED_WALK_HOLD.release();
    wait_until("the sort's landing", || !wp.feed_walk_pending());
    let snap = engine.kernel().snapshot();
    let owner = FeedClass::of(snap.world(), Some(SYSTEM_PRINCIPAL));
    assert_eq!(served(page_from(&wp, &owner, 0)), before, "the pages as never lost");
    let ats = index_ats();
    let mut once = ats.clone();
    once.sort_unstable();
    once.dedup();
    assert_eq!(ats, once, "each position's record stands once: {ats:?}");
    assert_eq!(ats, board, "every position classified, the bare ones among them");
    let said = wp.lines_said().lock().clone();
    assert!(
        said.iter().any(|l| l.starts_with("landing: feed-index.log: 3 of 3 bare positions")),
        "the second open's walk lands the three left:\n{}",
        said.join("\n")
    );
}

/// MEASUREMENT (#461), run by hand: the open over a lost `feed-index.log`.
///
/// Seeds `SKEP_MEASURE_N` draft mints (256 by default — the gate re-admits
/// every ignored test, so the default is a smoke run; the figures of record
/// were taken at 4,096), a checkpoint by hand every 1,024 as the daemon's
/// cadence takes one; writes every position bare into `commits.log`, as a
/// walk's landing writes them; loses the index; and times the open — which
/// returns at once — then the walk's sort behind the listener until nothing
/// pends. Prints the figures and the lines said.
#[test]
#[ignore = "measurement - run by hand"]
fn measure_the_open_over_a_lost_feed_index() {
    let _walks = one_walk_at_a_time();
    let n: usize =
        std::env::var("SKEP_MEASURE_N").ok().and_then(|s| s.parse().ok()).unwrap_or(256);
    let dir = tempfile::tempdir().expect("tempdir");
    let engine = fsync_engine(dir.path());
    let stores = engine.stores();
    let wp = open_the_write_path(dir.path(), &engine);
    let seeding = Instant::now();
    let mut positions = Vec::with_capacity(n);
    for i in 1..=n {
        positions.push(mint_a_draft(&wp, &stores).1);
        if i % 1024 == 0 {
            engine.kernel().checkpoint().expect("a checkpoint lands");
        }
    }
    let seeded = seeding.elapsed();
    drop(wp);
    let mut log = String::from("{\"min_since\":0}\n");
    for at in &positions {
        log.push_str(&format!("{{\"at\":{at}}}\n"));
    }
    std::fs::write(dir.path().join("commits.log"), log).expect("the bare log");
    let index = dir.path().join("feed-index.log");
    if index.exists() {
        std::fs::remove_file(&index).expect("lose the index");
    }
    let opening = Instant::now();
    let wp = open_the_write_path(dir.path(), &engine);
    let opened = opening.elapsed();
    let pending = wp.feed_pending_set().len();
    let walking = Instant::now();
    let deadline = Instant::now() + Duration::from_secs(7_200);
    while wp.feed_walk_pending() {
        assert!(Instant::now() < deadline, "the walk lands within two hours");
        thread::sleep(Duration::from_millis(5));
    }
    let walked = walking.elapsed();
    let said = wp.lines_said().lock().clone();
    println!(
        "MEASURE after n={n} seeded={seeded:?} ({:.2} ms per commit) open={opened:?} \
         pending_at_open={pending} walk={walked:?} ({:.2} ms per position)",
        seeded.as_secs_f64() * 1000.0 / n as f64,
        walked.as_secs_f64() * 1000.0 / pending.max(1) as f64
    );
    for l in &said {
        println!("  {l}");
    }
}
