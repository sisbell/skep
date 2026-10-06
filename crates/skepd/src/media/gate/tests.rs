use skep_blobs::HashFunction;

use super::*;

/// The gate deposits under the cell schema's own designation: the two
/// spellings — the cell schema's and the store's function's — are one.
#[test]
fn the_designation_is_the_cell_schemas() {
    assert_eq!(DESIGNATION, HashFunction::Blake3.designation(), "the store files every deposit under it");
}

/// A ready index, built by hand: the walk's door, with nothing walked.
fn ready(gate: &MediaGate) {
    gate.index().complete(super::super::index::Rebuild {
        values: 0,
        cells: 0,
        halts: 0,
        walk: std::time::Duration::ZERO,
        parse: std::time::Duration::ZERO,
    });
}

/// THE DAEMON's DEFAULTS (M-I6 (b), (d); the owner's ruling): a
/// per-account limit is ALWAYS in force — one eighth of the volume's
/// capacity as the opened store reads it, never below 256 MiB, the floor
/// alone where no capacity is answered — the venue total unset, the
/// lease interval seven days, the horizon thirty, the per-file cap the
/// route's; the startup line names the default and its source; an
/// installed record overrides the default whole, its cap held at the
/// route's own; and the upload setting rides the gate, open by default
/// and echoed as the `media` object.
#[test]
fn the_default_limit_is_a_share_of_the_capacity_and_an_install_overrides_it_whole() {
    assert_eq!(Limits::defaults_for(None).per_account, Some(DEFAULT_LIMIT_FLOOR_BYTES), "no capacity: the floor");
    assert_eq!(Limits::defaults_for(Some(1 << 30)).per_account, Some(DEFAULT_LIMIT_FLOOR_BYTES), "a small volume: the floor");
    assert_eq!(Limits::defaults_for(Some(16 << 30)).per_account, Some(2 << 30), "one eighth");
    assert_eq!(Limits::defaults_for(Some(16 << 30)).venue_total, None, "the venue total unset");
    assert!(Limits::defaults_for(None).log_line(None).contains("the host answering no capacity"));
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
    assert!(line.contains("one eighth of the volume's capacity") && line.contains(&limit.to_string()), "{line}");
    let now = gate.now_ms();
    let p = PrincipalId(1);
    assert_eq!(gate.admit_declared(p, limit + 1, now), Err(Scope::Own), "the default binds");
    assert_eq!(gate.admit_declared(p, limit, now), Ok(()));
    assert!(gate.uploads_open());
    assert_eq!(gate.health_object(), serde_json::json!({"uploads": true}));
    gate.install(Limits {
        per_account: Some(10),
        venue_total: Some(100),
        lease_interval_ms: 1_000,
        per_file_cap: MAX_BLOB_BYTES * 4,
        address: Some("1.0.1.0.3.1".into()),
    });
    assert_eq!(gate.limits().per_file_cap, MAX_BLOB_BYTES, "held at the route's cap");
    assert_eq!(gate.admit_declared(p, 11, now), Err(Scope::Own));
    assert_eq!(gate.admit_declared(p, 10, now), Ok(()));
    assert!(!gate.index_ready(), "an opened gate's index is not ready until the walk");
    assert_eq!(MediaGate::principal_of_key(&MediaGate::key(p)), Some(p));
    assert_eq!(MediaGate::principal_of_key("k"), None);
    assert!(gate.startup_line().contains("1.0.1.0.3.1"));
    // The hold: one stream at a time.
    let id = UploadId::parse("0123456789abcdef0123456789abcdef").unwrap();
    assert!(gate.claim(id));
    assert!(!gate.claim(id));
    gate.release(id);
    assert!(gate.claim(id));
    let mut closed = MediaOptions::default();
    closed.uploads = false;
    let gate = MediaGate::open_with(tempfile::tempdir().expect("tempdir").path(), closed).expect("the store opens");
    assert!(!gate.uploads_open());
    assert_eq!(gate.health_object(), serde_json::json!({"uploads": false}));
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
    assert_eq!(gate.admit_creation(p, now), Err(Scope::Standing), "the bound, off the principal's own records");
    assert_eq!(gate.admit_creation(q, now), Ok(()), "another principal's uploads count in nothing here");
    store.end_upload(&MediaGate::key(p), &standing[0], now).unwrap();
    assert_eq!(gate.admit_creation(p, now), Ok(()), "an end makes room");
    gate.set_free_space(Some(FLOOR_BYTES - 1));
    assert_eq!(gate.admit_creation(p, now), Err(Scope::Floor), "the floor, on no declared length");
    assert_eq!(gate.admit_declared(p, 0, now), Ok(()), "the declared total's read is the own scope's alone");
    gate.set_free_space(Some(FLOOR_BYTES));
    assert_eq!(gate.admit_creation(p, now), Ok(()));
    store.create_upload(&MediaGate::key(p), HashFunction::Blake3, 10, Duration::from_secs(60), now).unwrap();
    gate.set_free_space(Some(0));
    assert_eq!(gate.admit_creation(p, now), Err(Scope::Standing), "the bound is read first, the own record before the host's state");
    assert_eq!(Scope::Standing.token(), "standing");
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
    assert_eq!(gate.admit_creation(p, now), Err(Scope::Floor), "the floor in force refuses it");
    assert_eq!(gate.admit_bytes(p, &id, 0, 64 * 1024, now), Err(Scope::Floor), "…and a chunk");
    assert_eq!(Scope::Floor.token(), "floor", "the scope, and no figure");
    gate.set_free_space(Some(600 * mib + MAX_SEGMENT_LEN + 64 * 1024));
    assert_eq!(gate.admit_creation(p, now), Ok(()), "room above the floor in force admits");
    assert_eq!(gate.admit_bytes(p, &id, 0, 64 * 1024, now), Ok(()), "a chunk that leaves it at the floor");
    assert_eq!(gate.admit_bytes(p, &id, 0, 64 * 1024 + 1, now), Err(Scope::Floor), "one byte more");
    gate.set_floor(MediaGate::floor_in_force(Some(1 * mib)));
    assert_eq!(gate.floor(), FLOOR_BYTES, "a small checkpoint landed: the constant again");
    gate.set_free_space(Some(400 * mib));
    assert_eq!(gate.admit_creation(p, now), Ok(()));
    let line = gate.startup_line();
    assert!(
        line.contains("the floor in force") && line.contains(&FLOOR_BYTES.to_string()),
        "the startup line names the floor in force beside the limit: {line}"
    );
    assert!(line.contains("one eighth of the volume's capacity"), "…beside the default: {line}");
}

/// THE WINDOW (ms5-R; the register M-I5 (b)): while the index is not
/// ready, a cell no lease covers, one whose lease lapsed, and one whose
/// live lease stands over no file each answer REBUILDING — the index
/// arm unread may admit them — while a live lease over a whole file
/// ADMITS as at any time; the walk complete, the same cells answer their
/// permanent verdicts, and a cell the principal's own cells name is
/// admitted off the index arm.
#[test]
fn the_window_answers_rebuilding_where_the_lease_arm_alone_would_refuse() {
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
    assert_eq!(gate.binding(p, &cell), Binding::Admitted, "a live lease over a whole file admits in the window");
    assert_eq!(gate.binding(p, &Cell { hash, size: 1 }), Binding::Rebuilding, "the size contradicted: the state, not unbound");
    gate.advance_clock_ms(10_000);
    assert_eq!(gate.binding(p, &cell), Binding::Rebuilding, "lapsed: the state, not lease_lapsed");
    deposit(10_000);
    std::fs::remove_file(store.blob_path(DESIGNATION, &hex_of(&hash)).unwrap()).unwrap();
    assert_eq!(gate.binding(p, &cell), Binding::Rebuilding, "a live lease over no file: the state");
    let at = crate::codec::wire_address("1.0.1.0.2.0.1.1").unwrap();
    gate.index().enter(&at, Some(p), &cell);
    ready(&gate);
    assert_eq!(gate.binding(p, &cell), Binding::Lapsed, "named, the file gone: the permanent verdict");
    deposit(10_000);
    assert_eq!(gate.binding(p, &cell), Binding::Admitted, "named, the file whole: the index arm");
    assert_eq!(gate.binding(PrincipalId(6), &cell), Binding::Unbound, "another principal, ready: permanent");
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
    assert_eq!(fin.hex, hex_of(&hash));
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
    std::fs::remove_file(store.blob_path(DESIGNATION, &hex_of(&hash)).unwrap()).unwrap();
    assert_eq!(gate.binding(p, &cell), Binding::Lapsed, "a live lease over no file reads as lapsed");

    // THE INDEX ARM. The file re-deposited, the cell entered as p's.
    let now = gate.now_ms();
    let rec = store.create_upload(&key, HashFunction::Blake3, 9, Duration::from_millis(10_000), now).unwrap();
    let mut stream = store.resume(&key, &rec.id, 0, now).unwrap();
    stream.append(bytes, now).unwrap();
    stream.finish(Duration::from_millis(10_000), now).unwrap();
    assert_eq!(gate.own_pending(p, now), 9, "no cell names it: the lease counts as pending");
    assert_eq!(gate.own_scope(p, now), 9);
    let at = crate::codec::wire_address("1.0.1.0.2.0.1.1").unwrap();
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
    let path = store.blob_path(DESIGNATION, &hex_of(&hash)).unwrap();
    std::fs::write(&path, b"a pictur").unwrap();
    assert_eq!(gate.binding(p, &cell), Binding::Lapsed, "named, the file not whole: the deposit is gone");
    std::fs::remove_file(&path).unwrap();
    assert_eq!(gate.binding(p, &cell), Binding::Lapsed, "named, the file gone: the deposit is gone");
    assert_eq!(gate.own_scope(p, gate.now_ms()), 9, "the base stands whatever the directory holds");
}
