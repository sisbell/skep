use skep_address::{validate, Address, Nat, Tumbler};
use skep_blobs::HashFunction;

use super::*;
use crate::cell::HASH_BYTES;

/// A test address from its dotted form, T4-validated.
fn addr(s: &str) -> Address {
    let comps: Vec<Nat> = s.split('.').map(|c| Nat::from(c.parse::<u32>().unwrap())).collect();
    validate(Tumbler::new(comps).expect("a tumbler")).expect("a test address")
}

/// The gate deposits under the cell schema's own designation: the two
/// spellings — the cell schema's and the store's function's — are one.
#[test]
fn the_designation_is_the_cell_schemas() {
    assert_eq!(DESIGNATION, HashFunction::Blake3.designation(), "the store files every deposit under it");
}

/// A ready index, built by hand: the walk's door, with nothing walked.
fn ready(gate: &MediaGate) {
    gate.index().complete(crate::index::Rebuild {
        values: 0,
        cells: 0,
        halts: 0,
        walk: std::time::Duration::ZERO,
        parse: std::time::Duration::ZERO,
    });
}

/// THE DAEMON's DEFAULTS (M-I6 (b), (d); the owner's ruling): a
/// per-account limit is ALWAYS in force — one part in `DEFAULT_LIMIT_SHARE`
/// of the volume's capacity as the opened store reads it, never below
/// `DEFAULT_LIMIT_FLOOR_BYTES`, the floor alone where no capacity is
/// answered — the venue total unset, the lease interval seven days, the
/// horizon thirty, the per-file cap the route's; the startup line names the
/// default and its source, THE WORDS RENDERED FROM THE TWO CONSTANTS
/// (`operations.md` §1.1 row 7; §2.3 F4: "one part in {share} of the
/// volume's capacity of {c} bytes, never below {floor} bytes", no "one
/// eighth"); an installed record overrides the default whole, its cap at
/// the route's own; and the upload setting rides the gate, open by default
/// and echoed as the `media` object.
#[test]
fn the_default_limit_is_a_share_of_the_capacity_and_an_install_overrides_it_whole() {
    assert_eq!(Limits::defaults_for(None).per_account, Some(DEFAULT_LIMIT_FLOOR_BYTES), "no capacity: the floor");
    assert_eq!(Limits::defaults_for(Some(1 << 30)).per_account, Some(DEFAULT_LIMIT_FLOOR_BYTES), "a small volume: the floor");
    let sixteen: u64 = 16 << 30;
    assert_eq!(Limits::defaults_for(Some(sixteen)).per_account, Some(sixteen / DEFAULT_LIMIT_SHARE), "one part in the share");
    assert_eq!(Limits::defaults_for(Some(sixteen)).venue_total, None, "the venue total unset");
    assert!(Limits::defaults_for(None).log_line(None).contains("the host answering no capacity"));
    // LINE 7's WORDS, from the constants: the share's divisor and the floor.
    let line = Limits::defaults_for(Some(sixteen)).log_line(Some(sixteen));
    let rendered = format!(
        "per-account {} (one part in {DEFAULT_LIMIT_SHARE} of the volume's capacity of {sixteen} \
         bytes, never below {DEFAULT_LIMIT_FLOOR_BYTES} bytes), venue total none",
        sixteen / DEFAULT_LIMIT_SHARE
    );
    assert!(line.contains(&rendered), "line 7 renders the constants: {line}");
    assert!(!line.contains("one eighth") && !line.contains("MiB"), "no word table: {line}");
    let dir = tempfile::tempdir().expect("tempdir");
    let gate = MediaGate::open_with(dir.path(), MediaOptions::default()).expect("the store opens");
    let capacity = gate.store().capacity().expect("statvfs answers");
    assert_eq!(gate.capacity(), Some(capacity), "read once at the open");
    let limit = (capacity / DEFAULT_LIMIT_SHARE).max(DEFAULT_LIMIT_FLOOR_BYTES);
    assert_eq!(gate.limits(), Limits::defaults_for(Some(capacity)));
    assert_eq!(gate.limits().per_account, Some(limit));
    assert_eq!(LEASE_INTERVAL_DEFAULT_MS, 7 * 24 * 3600 * 1000);
    assert_eq!(LEASE_HORIZON_MS, 30 * 24 * 3600 * 1000);
    assert_eq!(FLOOR_BYTES, 256 * 1024 * 1024);
    let line = gate.startup_line();
    assert!(
        line.contains(&format!("one part in {DEFAULT_LIMIT_SHARE} of the volume's capacity of {capacity} bytes"))
            && line.contains(&limit.to_string()),
        "{line}"
    );
    let now = gate.now_ms();
    let p = PrincipalId(1);
    assert_eq!(gate.admit_declared(p, limit + 1, now), Err(DepositScope::Own), "the default binds");
    assert_eq!(gate.admit_declared(p, limit, now), Ok(()));
    assert!(gate.uploads_open());
    assert_eq!(gate.health_object(), serde_json::json!({"uploads": true}));
    gate.install(Limits {
        per_account: Some(10),
        venue_total: Some(100),
        lease_interval_ms: 1_000,
        per_file_cap: MAX_BLOB_BYTES,
        address: Some("1.0.1.0.3.1".into()),
    })
    .expect("a record at the route's cap installs");
    assert_eq!(gate.limits().per_file_cap, MAX_BLOB_BYTES, "the route's cap");
    assert_eq!(gate.admit_declared(p, 11, now), Err(DepositScope::Own));
    assert_eq!(gate.admit_declared(p, 10, now), Ok(()));
    assert!(!gate.index_ready(), "an opened gate's index is not ready until the walk");
    assert_eq!(MediaGate::principal_of_key(&MediaGate::key(p)), Some(p));
    assert_eq!(MediaGate::principal_of_key("k"), None);
    assert!(gate.startup_line().contains("1.0.1.0.3.1"));
    // The hold: one stream at a time, released as its guard drops.
    let id = UploadId::parse("0123456789abcdef0123456789abcdef").unwrap();
    let hold = gate.claim(id).expect("a fresh id is claimable");
    assert!(gate.claim(id).is_none(), "held: a second stream is refused");
    drop(hold);
    assert!(gate.claim(id).is_some(), "released with its guard");
    let mut closed = MediaOptions::default();
    closed.uploads = false;
    let gate = MediaGate::open_with(tempfile::tempdir().expect("tempdir").path(), closed).expect("the store opens");
    assert!(!gate.uploads_open());
    assert_eq!(gate.health_object(), serde_json::json!({"uploads": false}));
}

/// THE HOLD ENDS WITH ITS GUARD, AN UNWIND INCLUDED (clause (5)): a stream
/// that panics while holding its upload releases it as its frame unwinds,
/// so the upload answers its next resume and the pruner's next pass, and
/// not `409 upload_held` for the rest of the uptime — the daemon
/// `Daemon::route` promises a caller that contains the panic.
#[test]
fn a_hold_is_released_by_an_unwind() {
    let dir = tempfile::tempdir().expect("tempdir");
    let gate = MediaGate::open_with(dir.path(), MediaOptions::default()).expect("the store opens");
    let id = UploadId::parse("0123456789abcdef0123456789abcdef").unwrap();
    let unwound = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _hold = gate.claim(id).expect("a fresh id is claimable");
        panic!("a stream fails while it holds its upload");
    }));
    assert!(unwound.is_err(), "the stream unwound");
    assert!(gate.claim(id).is_some(), "and its hold went with it");
}

/// THE GATE AT THE CREATION (M-I6 (b), (f); M-I5 (f); P13): the
/// standing-uploads bound, read off the principal's own records first —
/// the ninth creation refused `standing`, an end making room — then the
/// floor, read on no declared length; a creation refused at either
/// makes no partial and no record. The resume's own scope reads
/// neither. Another principal's uploads count in nothing here.
#[test]
fn the_creation_is_refused_at_the_standing_bound_and_at_the_floor_before_any_record() {
    let dir = tempfile::tempdir().expect("tempdir");
    let gate = MediaGate::open_with(dir.path(), MediaOptions::default()).expect("the store opens");
    let now = gate.now_ms();
    let (p, q) = (PrincipalId(3), PrincipalId(4));
    let store = gate.store();
    assert_eq!(MAX_STANDING_UPLOADS, 8);
    let mut standing = Vec::new();
    for _ in 0..MAX_STANDING_UPLOADS {
        assert_eq!(gate.admit_creation(p, now), Ok(()));
        standing.push(store.create_upload(&MediaGate::key(p), HashFunction::Blake3, 10, Duration::from_secs(60), now).unwrap().id);
    }
    assert_eq!(gate.admit_creation(p, now), Err(DepositScope::Standing), "the bound, off the principal's own records");
    assert_eq!(gate.admit_creation(q, now), Ok(()), "another principal's uploads count in nothing here");
    store.end_upload(&MediaGate::key(p), &standing[0], now).unwrap();
    assert_eq!(gate.admit_creation(p, now), Ok(()), "an end makes room");
    gate.set_free_space(Some(FLOOR_BYTES - 1));
    assert_eq!(gate.admit_creation(p, now), Err(DepositScope::Floor), "the floor, on no declared length");
    assert_eq!(gate.admit_declared(p, 0, now), Ok(()), "the declared total's read is the own scope's alone");
    gate.set_free_space(Some(FLOOR_BYTES));
    assert_eq!(gate.admit_creation(p, now), Ok(()));
    store.create_upload(&MediaGate::key(p), HashFunction::Blake3, 10, Duration::from_secs(60), now).unwrap();
    gate.set_free_space(Some(0));
    assert_eq!(gate.admit_creation(p, now), Err(DepositScope::Standing), "the bound is read first, the own record before the host's state");
    assert_eq!(DepositScope::Standing.token(), "standing");
}

/// THE FLOOR IN FORCE (M-I5 (f), the floor sized to keep the journal
/// writable THROUGH ITS NEXT CHECKPOINT; M-I6 (f), (h)): never below the
/// constant, and never below twice the newest checkpoint's size plus one
/// maximal segment — the constant alone with no checkpoint and under a
/// small one, the scaling half above the crossover — saturating on a
/// length no volume holds. A gate opens at the constant; the floor set
/// from a 300 MiB checkpoint refuses a creation and a chunk the constant
/// would admit, naming the scope and no figure; a landed checkpoint
/// small again moves it back. The startup line names the floor in force
/// beside the default limit.
#[test]
fn the_floor_in_force_scales_with_the_newest_checkpoint_and_never_below_the_constant() {
    let mib = 1024 * 1024;
    assert_eq!(MediaGate::floor_in_force(None), FLOOR_BYTES, "no checkpoint: the constant");
    assert_eq!(MediaGate::floor_in_force(Some(0)), FLOOR_BYTES);
    assert_eq!(MediaGate::floor_in_force(Some(16 * mib)), FLOOR_BYTES, "a small checkpoint");
    assert_eq!(MAX_SEGMENT_LEN, 128 * mib, "one maximal segment, the journal's reader ceiling");
    let crossover = (FLOOR_BYTES - MAX_SEGMENT_LEN) / 2;
    assert_eq!(MediaGate::floor_in_force(Some(crossover)), FLOOR_BYTES, "at the crossover, equal");
    assert_eq!(
        MediaGate::floor_in_force(Some(crossover + 1)),
        FLOOR_BYTES + 2,
        "one byte past it, the scaling half"
    );
    assert_eq!(
        MediaGate::floor_in_force(Some(300 * mib)),
        600 * mib + MAX_SEGMENT_LEN,
        "twice the newest checkpoint plus one maximal segment"
    );
    assert_eq!(MediaGate::floor_in_force(Some(u64::MAX)), u64::MAX, "saturating, never wrapped");

    let dir = tempfile::tempdir().expect("tempdir");
    let gate = MediaGate::open_with(dir.path(), MediaOptions::default()).expect("the store opens");
    assert_eq!(gate.floor(), FLOOR_BYTES, "a gate opens at the constant");
    let now = gate.now_ms();
    let p = PrincipalId(9);
    let id = UploadId::parse("0123456789abcdef0123456789abcdef").unwrap();
    gate.set_free_space(Some(400 * mib));
    assert_eq!(gate.admit_creation(p, now), Ok(()), "400 MiB free clears the constant");
    assert_eq!(gate.admit_bytes(p, &id, 0, 64 * 1024, now), Ok(()));
    gate.set_floor(MediaGate::floor_in_force(Some(300 * mib)));
    assert_eq!(gate.floor(), 600 * mib + MAX_SEGMENT_LEN);
    assert_eq!(gate.admit_creation(p, now), Err(DepositScope::Floor), "the floor in force refuses it");
    assert_eq!(gate.admit_bytes(p, &id, 0, 64 * 1024, now), Err(DepositScope::Floor), "…and a chunk");
    assert_eq!(DepositScope::Floor.token(), "floor", "the scope, and no figure");
    gate.set_free_space(Some(600 * mib + MAX_SEGMENT_LEN + 64 * 1024));
    assert_eq!(gate.admit_creation(p, now), Ok(()), "room above the floor in force admits");
    assert_eq!(gate.admit_bytes(p, &id, 0, 64 * 1024, now), Ok(()), "a chunk that leaves it at the floor");
    assert_eq!(gate.admit_bytes(p, &id, 0, 64 * 1024 + 1, now), Err(DepositScope::Floor), "one byte more");
    gate.set_floor(MediaGate::floor_in_force(Some(1 * mib)));
    assert_eq!(gate.floor(), FLOOR_BYTES, "a small checkpoint landed: the constant again");
    gate.set_free_space(Some(400 * mib));
    assert_eq!(gate.admit_creation(p, now), Ok(()));
    let line = gate.startup_line();
    assert!(
        line.contains("the floor in force") && line.contains(&FLOOR_BYTES.to_string()),
        "the startup line names the floor in force beside the limit: {line}"
    );
    assert!(
        line.contains(&format!("one part in {DEFAULT_LIMIT_SHARE} of the volume's capacity")),
        "…beside the default: {line}"
    );
}

/// THE FLOOR's LINE, ONCE PER BINDING (`operations.md` §1.1 m9; §4 row 7;
/// §0 THE RATES, once per condition) — the once-flag's three states on the
/// gate's own record. CLEAR → BOUND: the first refusal at the floor, a
/// creation's, says the failure line with the two figures as the gate
/// compared them; BOUND: a second creation refused and a chunk refused say
/// nothing more, and a finish while the free space stands below the floor
/// says nothing and leaves the flag set; BOUND → CLEAR: the free space back
/// above the floor, an ADMISSION alone says nothing (the next chunk may
/// re-refuse), and the first FINISH says the lift once, with the finished
/// size and the figures, clearing the flag — a second finish says nothing;
/// then a new binding says the failure again. The chunk arm's figure is the
/// free space the chunk would leave, what the gate compared. The two lines
/// are pure values, pinned by `to_string()`; neither names a principal, an
/// upload or a token.
#[test]
fn the_floors_binding_is_said_once_and_its_lift_once_at_the_first_finish_above_the_floor() {
    assert_eq!(
        FloorBoundLine { free_space: 1_000, floor: 268_435_456 }.to_string(),
        "deposits refused at the floor: the volume's free space 1000 bytes is below the floor in \
         force 268435456; every write but a deposit serves; the acts: room on the volume, a pass \
         run early"
    );
    assert_eq!(
        FloorLiftedLine { bytes: 10, free_space: 300_000_000, floor: 268_435_456 }.to_string(),
        "deposits admitted again: an upload of 10 bytes finished with the volume's free space \
         300000000 bytes above the floor in force 268435456"
    );
    let dir = tempfile::tempdir().expect("tempdir");
    let gate = MediaGate::open_with(dir.path(), MediaOptions::default()).expect("the store opens");
    let now = gate.now_ms();
    let p = PrincipalId(11);
    let id = UploadId::parse("0123456789abcdef0123456789abcdef").unwrap();
    let floor = gate.floor();
    assert!(gate.lines_said().is_empty(), "a gate opens with nothing said");
    // CLEAR → BOUND, at the first refusal.
    gate.set_free_space(Some(floor - 1));
    assert_eq!(gate.admit_creation(p, now), Err(DepositScope::Floor));
    let bound = format!(
        "failure: deposits refused at the floor: the volume's free space {} bytes is below the \
         floor in force {floor}; every write but a deposit serves; the acts: room on the volume, a \
         pass run early",
        floor - 1
    );
    assert_eq!(gate.lines_said(), [bound.clone()], "said at the first refusal");
    // BOUND: nothing more, at a creation, at a chunk, at a finish below.
    assert_eq!(gate.admit_creation(p, now), Err(DepositScope::Floor));
    assert_eq!(gate.admit_bytes(p, &id, 0, 64 * 1024, now), Err(DepositScope::Floor));
    gate.note_finish(10);
    assert_eq!(gate.lines_said().len(), 1, "a binding is said once: {:?}", gate.lines_said());
    assert!(gate.floor_said.load(Ordering::Acquire), "a finish below the floor lifts nothing");
    // BOUND → CLEAR: an admission alone says nothing; the first finish says the lift.
    let room = floor + 1_000_000;
    gate.set_free_space(Some(room));
    assert_eq!(gate.admit_creation(p, now), Ok(()));
    assert_eq!(gate.admit_bytes(p, &id, 0, 64 * 1024, now), Ok(()));
    assert_eq!(gate.lines_said().len(), 1, "an admission alone says no lift");
    gate.note_finish(4_096);
    let lifted = format!(
        "landing: deposits admitted again: an upload of 4096 bytes finished with the volume's \
         free space {room} bytes above the floor in force {floor}"
    );
    assert_eq!(gate.lines_said(), [bound.clone(), lifted.clone()], "the lift at the first finish");
    assert!(!gate.floor_said.load(Ordering::Acquire), "the flag cleared by the lift");
    gate.note_finish(4_096);
    assert_eq!(gate.lines_said().len(), 2, "a second finish says nothing");
    // A NEW BINDING, at a chunk: said again, with the figure the gate compared.
    gate.set_free_space(Some(floor + 10));
    assert_eq!(gate.admit_creation(p, now), Ok(()), "the creation reads no length");
    assert_eq!(gate.admit_bytes(p, &id, 0, 64 * 1024, now), Err(DepositScope::Floor));
    let said = gate.lines_said();
    assert_eq!(said.len(), 3, "{said:?}");
    assert_eq!(
        said[2],
        format!(
            "failure: deposits refused at the floor: the volume's free space {} bytes is below the \
             floor in force {floor}; every write but a deposit serves; the acts: room on the \
             volume, a pass run early",
            floor + 10 - 64 * 1024
        ),
        "a chunk's refusal names the free space it would leave"
    );
    for line in &said {
        assert!(!line.contains("11") || line.contains("1111"), "no principal rides a floor line: {line}");
        assert!(!line.contains(&id.to_hex()), "no upload rides a floor line: {line}");
    }
}

/// THE INSTALL's REFUSAL (op-D6 (a); `operations.md` §2.3 F10; the
/// register's `per_file_cap` row): a record naming a per-file cap above
/// the route's is REFUSED whole — the answer names the cap and the route's,
/// the limits in force stand as they were, and the refusal is said ONCE per
/// attempt, in the ruled words; a second attempt is said again. A record at
/// the route's cap, and one below it, install as before, and the hook's
/// `None` is the route's own. Never the clamp that once installed the
/// record at the route's figure.
#[test]
fn a_record_naming_a_cap_past_the_routes_is_refused_at_install_and_said_once() {
    let dir = tempfile::tempdir().expect("tempdir");
    let gate = MediaGate::open_with(dir.path(), MediaOptions::default()).expect("the store opens");
    let before = gate.limits();
    let past = Limits {
        per_account: Some(10),
        venue_total: Some(100),
        lease_interval_ms: 1_000,
        per_file_cap: MAX_BLOB_BYTES + 1,
        address: Some("1.0.1.0.3.1".into()),
    };
    let refused = LimitsRefused::PerFileCap { named: MAX_BLOB_BYTES + 1, route: MAX_BLOB_BYTES };
    assert_eq!(gate.install(past.clone()), Err(refused.clone()));
    assert_eq!(gate.limits(), before, "the limits in force stand");
    let line = format!(
        "failure: media limits refused: the record names a per-file cap of {} bytes, above the \
         route's {MAX_BLOB_BYTES}; the limits in force stand",
        MAX_BLOB_BYTES + 1
    );
    assert_eq!(refused.to_string(), line["failure: ".len()..]);
    assert_eq!(gate.lines_said(), [line.clone()], "said once per attempt");
    assert_eq!(gate.install(past), Err(refused), "refused again");
    assert_eq!(gate.lines_said(), [line.clone(), line.clone()], "…and said again");
    assert_eq!(gate.limits(), before);
    // Through the hook: a cap past the route's, at it, below it, and none.
    assert_eq!(
        gate.install_limits(Some(10), None, None, Some(MAX_BLOB_BYTES * 4), None),
        Err(LimitsRefused::PerFileCap { named: MAX_BLOB_BYTES * 4, route: MAX_BLOB_BYTES })
    );
    assert_eq!(gate.limits(), before);
    gate.install_limits(Some(10), None, None, Some(MAX_BLOB_BYTES), None).expect("at the route's cap");
    assert_eq!(gate.limits().per_file_cap, MAX_BLOB_BYTES);
    assert_eq!(gate.limits().per_account, Some(10), "installed whole");
    gate.install_limits(Some(20), None, None, Some(MAX_BLOB_BYTES - 1), None).expect("below it");
    assert_eq!(gate.limits().per_file_cap, MAX_BLOB_BYTES - 1);
    gate.install_limits(None, None, None, None, None).expect("the defaults again");
    assert_eq!(gate.limits().per_file_cap, MAX_BLOB_BYTES, "`None` is the route's own");
    assert_eq!(gate.lines_said().len(), 3, "the installs that landed said nothing");
}

/// THE REBUILD WINDOW (ms5-R; the register M-I5 (b)): while the index is not
/// ready, a cell no lease covers, one whose lease lapsed, and one whose
/// live lease stands over no file each answer REBUILDING — the index
/// arm unread may admit them — while a live lease over a whole file
/// ADMITS as at any time; the walk complete, the same cells answer their
/// permanent verdicts, and a cell the principal's own cells name is
/// admitted off the index arm.
#[test]
fn the_rebuild_window_answers_rebuilding_where_the_lease_arm_alone_would_refuse() {
    let dir = tempfile::tempdir().expect("tempdir");
    let gate = MediaGate::open_with(dir.path(), MediaOptions::default()).expect("the store opens");
    let p = PrincipalId(5);
    let bytes = b"a picture in the window";
    let hash: [u8; HASH_BYTES] = *blake3::hash(bytes).as_bytes();
    let cell = Cell { hash, size: bytes.len() as u64 };
    assert!(!gate.index_ready());
    assert_eq!(gate.binding(p, &cell), Binding::Rebuilding, "no lease, the index unread");
    let key = MediaGate::key(p);
    let store = gate.store();
    let deposit = |interval: u64| {
        let now = gate.now_ms();
        let rec = store.create_upload(&key, HashFunction::Blake3, bytes.len() as u64, Duration::from_millis(interval), now).unwrap();
        let mut stream = store.resume(&key, &rec.id, 0, now).unwrap();
        stream.append(bytes, now).unwrap();
        stream.finish(Duration::from_millis(interval), now).unwrap();
    };
    deposit(10_000);
    assert_eq!(gate.binding(p, &cell), Binding::Admitted, "a live lease over a whole file admits in the rebuild window");
    assert_eq!(gate.binding(p, &Cell { hash, size: 1 }), Binding::Rebuilding, "the size contradicted: the state, not unbound");
    gate.advance_clock_ms(10_000);
    assert_eq!(gate.binding(p, &cell), Binding::Rebuilding, "lapsed: the state, not lease_lapsed");
    deposit(10_000);
    std::fs::remove_file(store.blob_path(DESIGNATION, &hex_string(&hash)).unwrap()).unwrap();
    assert_eq!(gate.binding(p, &cell), Binding::Rebuilding, "a live lease over no file: the state");
    let at = addr("1.0.1.0.2.0.1.1");
    gate.index().enter(&at, Some(p), &cell);
    ready(&gate);
    assert_eq!(gate.binding(p, &cell), Binding::Lapsed, "named, the file gone: the permanent verdict");
    deposit(10_000);
    assert_eq!(gate.binding(p, &cell), Binding::Admitted, "named, the file whole: the index arm");
    assert_eq!(gate.binding(PrincipalId(6), &cell), Binding::Unbound, "another principal, ready: permanent");
}

/// THE FAILED INDEX AT THE DOOR (`operations.md` §4 row 26; P10): the walk
/// died — `failed` set, `ready` not — and the lease arm's verdict stands
/// as FINAL where the window answered REBUILDING: a lapsed lease is LAPSED,
/// no lease is UNBOUND, a live lease over a whole file still ADMITS; with
/// neither state set the same cells answer REBUILDING, as today; and a
/// ready index answers as today. The gate's two reads never agree.
#[test]
fn a_failed_index_answers_the_lease_arm_as_final_where_the_window_answered_rebuilding() {
    let dir = tempfile::tempdir().expect("tempdir");
    let gate = MediaGate::open_with(dir.path(), MediaOptions::default()).expect("the store opens");
    let p = PrincipalId(5);
    let bytes = b"a picture after the walk died";
    let hash: [u8; HASH_BYTES] = *blake3::hash(bytes).as_bytes();
    let cell = Cell { hash, size: bytes.len() as u64 };
    let key = MediaGate::key(p);
    let store = gate.store();
    let deposit = |interval: u64| {
        let now = gate.now_ms();
        let rec = store.create_upload(&key, HashFunction::Blake3, bytes.len() as u64, Duration::from_millis(interval), now).unwrap();
        let mut stream = store.resume(&key, &rec.id, 0, now).unwrap();
        stream.append(bytes, now).unwrap();
        stream.finish(Duration::from_millis(interval), now).unwrap();
    };
    // Neither state: the window, as today.
    assert!(!gate.index_ready() && !gate.index_failed());
    assert_eq!(gate.binding(p, &cell), Binding::Rebuilding, "no lease, the walk running: the state");
    deposit(10_000);
    gate.advance_clock_ms(10_000);
    assert_eq!(gate.binding(p, &cell), Binding::Rebuilding, "lapsed, the walk running: the state");
    // FAILED: the lease arm's verdict is final.
    let payload: Box<dyn std::any::Any + Send> = Box::new("the walk died");
    gate.index().fail(payload.as_ref());
    assert!(gate.index_failed() && !gate.index_ready(), "the two reads never agree");
    assert_eq!(gate.binding(p, &cell), Binding::Lapsed, "lapsed, the walk dead: LAPSED, not the state");
    assert_eq!(gate.binding(PrincipalId(6), &cell), Binding::Unbound, "no lease, the walk dead: UNBOUND");
    deposit(10_000);
    assert_eq!(gate.binding(p, &cell), Binding::Admitted, "a live lease over a whole file admits under FAILED as at any time");
    assert_eq!(gate.binding(p, &Cell { hash, size: 1 }), Binding::Unbound, "the size contradicted under FAILED: UNBOUND");
    // READY, on a second gate: as today.
    let dir = tempfile::tempdir().expect("tempdir");
    let gate = MediaGate::open_with(dir.path(), MediaOptions::default()).expect("the store opens");
    ready(&gate);
    assert!(gate.index_ready() && !gate.index_failed());
    assert_eq!(gate.binding(p, &cell), Binding::Unbound, "ready, no lease: permanent");
}

/// The binding's three answers off the store, the index ready and
/// holding nothing of the hash: no lease is UNBOUND; a live lease over
/// a whole file whose length the cell names is ADMITTED; the same lease
/// with the cell's size wrong is UNBOUND; the file removed under the
/// live lease is LAPSED; the lease lapsed is LAPSED within the horizon
/// and UNBOUND past it. Then THE INDEX ARM: a cell the principal's own
/// cells already name is ADMITTED past every lapse while the file is
/// whole at the cell's size, LAPSED where it is not; another principal's
/// cells admit nothing of this one's; and the own scope counts a named
/// hash in the base and not in the pending bytes.
#[test]
fn the_binding_reads_the_principals_own_lease_first_and_the_file_only_under_it() {
    let dir = tempfile::tempdir().expect("tempdir");
    let gate = MediaGate::open_with(dir.path(), MediaOptions::default()).expect("the store opens");
    ready(&gate);
    let p = PrincipalId(7);
    let bytes = b"a picture";
    let hash: [u8; HASH_BYTES] = *blake3::hash(bytes).as_bytes();
    let cell = Cell { hash, size: bytes.len() as u64 };
    assert_eq!(gate.binding(p, &cell), Binding::Unbound);
    let now = gate.now_ms();
    let store = gate.store();
    let key = MediaGate::key(p);
    let rec = store.create_upload(&key, HashFunction::Blake3, 9, Duration::from_millis(10_000), now).unwrap();
    let mut stream = store.resume(&key, &rec.id, 0, now).unwrap();
    stream.append(bytes, now).unwrap();
    let fin = stream.finish(Duration::from_millis(10_000), now).unwrap();
    assert_eq!(fin.hex, hex_string(&hash));
    assert_eq!(gate.binding(p, &cell), Binding::Admitted);
    assert_eq!(gate.binding(PrincipalId(8), &cell), Binding::Unbound, "another principal holds none");
    assert_eq!(gate.binding(p, &Cell { hash, size: 8 }), Binding::Unbound, "the size contradicts the deposit");
    gate.advance_clock_ms(10_000);
    assert_eq!(gate.binding(p, &cell), Binding::Lapsed, "lapsed within the horizon");
    gate.advance_clock_ms(LEASE_HORIZON_MS);
    assert_eq!(gate.binding(p, &cell), Binding::Unbound, "past the horizon: no lease");
    // A fresh lease, then the file removed from under it.
    let now = gate.now_ms();
    let rec = store.create_upload(&key, HashFunction::Blake3, 9, Duration::from_millis(10_000), now).unwrap();
    let mut stream = store.resume(&key, &rec.id, 0, now).unwrap();
    stream.append(bytes, now).unwrap();
    stream.finish(Duration::from_millis(10_000), now).unwrap();
    assert_eq!(gate.binding(p, &cell), Binding::Admitted);
    std::fs::remove_file(store.blob_path(DESIGNATION, &hex_string(&hash)).unwrap()).unwrap();
    assert_eq!(gate.binding(p, &cell), Binding::Lapsed, "a live lease over no file reads as lapsed");

    // THE INDEX ARM. The file re-deposited, the cell entered as p's.
    let now = gate.now_ms();
    let rec = store.create_upload(&key, HashFunction::Blake3, 9, Duration::from_millis(10_000), now).unwrap();
    let mut stream = store.resume(&key, &rec.id, 0, now).unwrap();
    stream.append(bytes, now).unwrap();
    stream.finish(Duration::from_millis(10_000), now).unwrap();
    assert_eq!(gate.own_pending(p, now), 9, "no cell names it: the lease counts as pending");
    assert_eq!(gate.own_scope(p, now), 9);
    let at = addr("1.0.1.0.2.0.1.1");
    gate.index().enter(&at, Some(p), &cell);
    assert_eq!(gate.own_pending(p, now), 0, "a named hash counts in the base, not the pending");
    assert_eq!(gate.own_scope(p, now), 9, "the own scope is one number either way");
    assert_eq!(gate.venue_total(now), 9);
    assert_eq!(gate.binding(p, &cell), Binding::Admitted, "named by p's own cell, the file whole");
    assert!(gate.index_ready());
    gate.advance_clock_ms(10_000 + LEASE_HORIZON_MS);
    assert_eq!(gate.binding(p, &cell), Binding::Admitted, "named by p's own cell: admitted past the lease's horizon");
    assert_eq!(gate.binding(p, &Cell { hash, size: 8 }), Binding::Unbound, "named, the file whole at the named size, the cell contradicting it: the size check's answer");
    assert_eq!(gate.binding(PrincipalId(8), &cell), Binding::Unbound, "another principal's cells admit nothing of this one's");
    let path = store.blob_path(DESIGNATION, &hex_string(&hash)).unwrap();
    std::fs::write(&path, b"a pictur").unwrap();
    assert_eq!(gate.binding(p, &cell), Binding::Lapsed, "named, the file not whole: the deposit is gone");
    std::fs::remove_file(&path).unwrap();
    assert_eq!(gate.binding(p, &cell), Binding::Lapsed, "named, the file gone: the deposit is gone");
    assert_eq!(gate.own_scope(p, gate.now_ms()), 9, "the base stands whatever the directory holds");
}
