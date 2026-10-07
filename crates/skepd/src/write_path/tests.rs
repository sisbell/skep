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
