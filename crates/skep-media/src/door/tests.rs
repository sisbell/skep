use std::time::Duration;

use skep_address::Nat;
use skep_arrangement::{AsOf, Deposit, Run, ShotRun, VPos, MAX_REINSERTED_UNITS, MAX_REINSERTED_VALUES};
use skep_febe::{PublishDeposits, PublishTarget};
use skep_blobs::HashFunction;
use skep_kernel::{CheckpointPolicy, Durability, KernelConfig, SaltSource, Seq};
use skep_namespace::{head_document, system_account, BOOTSTRAP_PRINCIPAL, SYSTEM_PRINCIPAL};

use super::*;

const HASH: &str = "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262";

fn canonical() -> Vec<u8> {
    format!(r#"{{"type":"{}","hash":"{HASH}","size":5}}"#, cell::KIND).into_bytes()
}

fn unknown_schema() -> Vec<u8> {
    format!(r#"{{"type":"{}","hash":"{HASH}","size":5,"hash_alg":"sha256-tree"}}"#, cell::KIND)
        .into_bytes()
}

fn insert(doc: &Address, bytes: Vec<u8>) -> Op {
    Op::Insert {
        doc: doc.clone(),
        at: VPos::content(Nat::from(1u32)),
        values: vec![Val::new(bytes)],
        deposit: Deposit::Undeclared,
        as_of: Seq(7),
    }
}

/// Over the genesis world, as the system principal — the one principal
/// genesis seats with documents: the head document `H` (published, its
/// own) and a private draft it mints — the insert arms: a cell into a
/// draft `index_rebuilding` while the index's walk is not done and
/// `unbound_cell` once it is, the principal holding no lease on its
/// hash; a value under an unknown schema `unknown_cell_schema` — a body
/// past the cap opening as the kind among them — prose and a def
/// nothing; into `H` `published_target` whatever the value's form and
/// whatever the declaration; and a caller who does not own the draft
/// meets nothing here (the store's `not_owner` stands). Then the shot:
/// the owner's own shot of the draft holding a cell is refused
/// `unbound_cell` the same, a shot naming no draft meets nothing, and
/// nothing commits. Then THE BINDING MADE REAL (lane B): the bytes
/// deposited under the principal's own lease, the same insert and the
/// same shot are ADMITTED; the lease lapsed, both answer `lease_lapsed`;
/// and another principal's deposit of the same bytes admits nothing of
/// this one's.
#[test]
fn the_insert_arms_and_the_owners_shot_over_the_genesis_world() {
    let dir = tempfile::tempdir().expect("tempdir");
    let gate = MediaGate::open_with(dir.path(), crate::MediaOptions::default()).expect("the store opens");
    let engine = skep_engine::Engine::open(KernelConfig {
        durability: Durability::InMemory,
        checkpoint: CheckpointPolicy::Manual,
        salt: SaltSource::Seeded(0),
    })
    .expect("in-memory genesis cannot fail");
    let (draft, _) = engine
        .namespace()
        .create_new_document(SYSTEM_PRINCIPAL, &system_account(), Some(false))
        .expect("the system principal mints a private draft in its own account");
    let cell_at = engine
        .vstream()
        .insert(
            Caller::Principal(SYSTEM_PRINCIPAL),
            &draft,
            VPos::content(Nat::from(1u32)),
            vec![Val::new(canonical())],
            Deposit::Undeclared,
            AsOf::Typed(engine.kernel().current_seq()),
        )
        .expect("the engine, below the door, writes any bytes")
        .0;
    let snap = engine.kernel().snapshot();
    let world = snap.world();
    let h = head_document();
    let door = |op: Op, p: PrincipalId| media_door(world, &op, p, &gate);

    // THE REBUILD WINDOW: the walk not done, the lease arm alone would
    // refuse — the state, retry-class, and never the permanent token.
    assert!(!gate.index_ready());
    assert_eq!(
        door(insert(&draft, canonical()), SYSTEM_PRINCIPAL),
        Some(MediaRefusal::IndexRebuilding)
    );
    assert_eq!(MediaRefusal::IndexRebuilding.disposition(), Disposition::Retry);
    gate.index().complete(crate::index::Rebuild {
        values: 0,
        cells: 0,
        halts: 0,
        walk: Duration::ZERO,
        parse: Duration::ZERO,
    });
    assert_eq!(
        door(insert(&draft, canonical()), SYSTEM_PRINCIPAL),
        Some(MediaRefusal::UnboundCell)
    );
    assert_eq!(
        door(insert(&draft, unknown_schema()), SYSTEM_PRINCIPAL),
        Some(MediaRefusal::UnknownCellSchema)
    );
    let mut past_cap = canonical();
    past_cap.truncate(past_cap.len() - 1);
    past_cap.extend_from_slice(format!(r#","pad":"{}"}}"#, "x".repeat(crate::limits::MAX_CELL_BYTES)).as_bytes());
    assert_eq!(
        door(insert(&draft, past_cap), SYSTEM_PRINCIPAL),
        Some(MediaRefusal::UnknownCellSchema),
        "past the cap, opening as the kind: the halt"
    );
    assert_eq!(door(insert(&draft, b"prose".to_vec()), SYSTEM_PRINCIPAL), None);
    assert_eq!(door(insert(&draft, vec![0x0b, 1, 0, 1, 2]), SYSTEM_PRINCIPAL), None, "a def");
    // THE BLIND KIND's column: admitted into a draft with no store
    // consulted, `published_target` into H, the halt on its malformed body.
    let blind = crate::cell::blind::encode(&crate::cell::blind::BlindCell { commitment: [0xcd; 32] })
        .into_bytes();
    let mut blind_sized = blind.clone();
    blind_sized.splice(blind.len() - 1.., br#","size":5}"#.iter().copied());
    assert_eq!(
        door(insert(&draft, blind.clone()), SYSTEM_PRINCIPAL),
        None,
        "a blind cell: admitted, no binding asked"
    );
    assert_eq!(door(insert(&h, blind), SYSTEM_PRINCIPAL), Some(MediaRefusal::PublishedTarget));
    assert_eq!(
        door(insert(&draft, blind_sized), SYSTEM_PRINCIPAL),
        Some(MediaRefusal::UnknownCellSchema)
    );
    assert_eq!(
        door(insert(&h, canonical()), SYSTEM_PRINCIPAL),
        Some(MediaRefusal::PublishedTarget)
    );
    assert_eq!(
        door(insert(&h, unknown_schema()), SYSTEM_PRINCIPAL),
        Some(MediaRefusal::PublishedTarget)
    );
    let declared = Op::Insert {
        doc: h.clone(),
        at: VPos::content(Nat::from(1u32)),
        values: vec![Val::new(canonical())],
        deposit: Deposit::Declared(skep_engine::types::t_grant().clone()),
        as_of: Seq(7),
    };
    assert_eq!(door(declared, SYSTEM_PRINCIPAL), Some(MediaRefusal::PublishedTarget));
    assert_eq!(
        door(insert(&draft, canonical()), BOOTSTRAP_PRINCIPAL),
        None,
        "not the owner: the store's"
    );

    let shot = |draft: Option<Address>| Op::Publish {
        target: PublishTarget::Document(h.clone()),
        shot: Shot {
            base: None,
            draft: draft.clone(),
            also: vec![],
            keep_base: false,
            runs: vec![ShotRun {
                origin: draft.clone().unwrap_or_else(|| h.clone()),
                run: Run::new(cell_at.clone(), Nat::from(1u32)).expect("one position"),
            }],
            stretches: Vec::new(),
        },
        places: Vec::new(),
        also_places: Vec::new(),
        deposits: PublishDeposits::default(),
    };
    assert_eq!(
        door(shot(Some(draft.clone())), SYSTEM_PRINCIPAL),
        Some(MediaRefusal::UnboundCell)
    );
    // The same runs with no draft named: the store's `bad_run` stands
    // (the run's origin is not `H`), and this door answers nothing.
    assert_eq!(door(shot(None), SYSTEM_PRINCIPAL), None);
    assert_eq!(engine.kernel().current_seq(), snap.seq(), "the door commits nothing");
    for (refusal, token) in [
        (MediaRefusal::UnboundCell, Some("unbound_cell")),
        (MediaRefusal::UnknownCellSchema, Some("unknown_cell_schema")),
        (MediaRefusal::LeaseLapsed, Some("lease_lapsed")),
        (MediaRefusal::PublishedTarget, None),
    ] {
        assert_eq!(refusal.token(), token);
        assert_eq!(refusal.disposition(), Disposition::Permanent);
    }
    assert_eq!(MediaRefusal::IndexRebuilding.token(), Some("index_rebuilding"));

    // THE BINDING MADE REAL: five real bytes, the cell naming THEIR
    // hash — the fixture's `HASH` above is the empty input's, which no
    // five-byte deposit can carry — in a second draft the engine seeds
    // below the door, as the first was.
    let bytes = b"hello";
    let hex = blake3::hash(bytes).to_hex();
    let real =
        || format!(r#"{{"type":"{}","hash":"{hex}","size":5}}"#, cell::KIND).into_bytes();
    let (draft2, _) = engine
        .namespace()
        .create_new_document(SYSTEM_PRINCIPAL, &system_account(), Some(false))
        .expect("a second private draft");
    let real_at = engine
        .vstream()
        .insert(
            Caller::Principal(SYSTEM_PRINCIPAL),
            &draft2,
            VPos::content(Nat::from(1u32)),
            vec![Val::new(real())],
            Deposit::Undeclared,
            AsOf::Typed(engine.kernel().current_seq()),
        )
        .expect("the engine, below the door, writes any bytes")
        .0;
    let snap = engine.kernel().snapshot();
    let world = snap.world();
    let door = |op: Op, p: PrincipalId| media_door(world, &op, p, &gate);
    let shot2 = || Op::Publish {
        target: PublishTarget::Document(h.clone()),
        shot: Shot {
            base: None,
            draft: Some(draft2.clone()),
            also: vec![],
            keep_base: false,
            runs: vec![ShotRun {
                origin: draft2.clone(),
                run: Run::new(real_at.clone(), Nat::from(1u32)).expect("one position"),
            }],
            stretches: Vec::new(),
        },
        places: Vec::new(),
        also_places: Vec::new(),
        deposits: PublishDeposits::default(),
    };
    let deposit = |p: PrincipalId, interval: Duration| {
        let key = MediaGate::key(p);
        let now = gate.now_ms();
        let store = gate.store();
        let rec = store.create_upload(&key, HashFunction::Blake3, 5, interval, now).unwrap();
        let mut stream = store.resume(&key, &rec.id, 0, now).unwrap();
        stream.append(bytes, now).unwrap();
        stream.finish(interval, now).unwrap();
    };
    assert_eq!(
        door(insert(&draft2, real()), SYSTEM_PRINCIPAL),
        Some(MediaRefusal::UnboundCell)
    );
    assert_eq!(door(shot2(), SYSTEM_PRINCIPAL), Some(MediaRefusal::UnboundCell));
    deposit(BOOTSTRAP_PRINCIPAL, Duration::from_millis(1_000_000));
    assert_eq!(
        door(insert(&draft2, real()), SYSTEM_PRINCIPAL),
        Some(MediaRefusal::UnboundCell),
        "another principal's deposit admits nothing of this one's"
    );
    deposit(SYSTEM_PRINCIPAL, Duration::from_millis(1_000));
    assert_eq!(
        door(insert(&draft2, real()), SYSTEM_PRINCIPAL),
        None,
        "admitted under its own live lease"
    );
    assert_eq!(door(shot2(), SYSTEM_PRINCIPAL), None, "the owner's shot too");
    let wrong_size =
        format!(r#"{{"type":"{}","hash":"{hex}","size":4}}"#, cell::KIND).into_bytes();
    assert_eq!(
        door(insert(&draft2, wrong_size), SYSTEM_PRINCIPAL),
        Some(MediaRefusal::UnboundCell),
        "the size check"
    );
    assert_eq!(
        door(insert(&h, real()), SYSTEM_PRINCIPAL),
        Some(MediaRefusal::PublishedTarget),
        "the target first, lease or none"
    );
    gate.advance_clock_ms(1_000);
    assert_eq!(
        door(insert(&draft2, real()), SYSTEM_PRINCIPAL),
        Some(MediaRefusal::LeaseLapsed)
    );
    assert_eq!(door(shot2(), SYSTEM_PRINCIPAL), Some(MediaRefusal::LeaseLapsed));
    assert_eq!(engine.kernel().current_seq(), snap.seq(), "the door commits nothing");
}

/// An edit's values take the insert's arms, whichever change holds them.
///
/// Over the genesis world, the index's walk done: an `edit` whose second
/// change mints a cell the principal holds no lease on is refused
/// `unbound_cell`, as an insert of it is, and one under an unknown schema
/// `unknown_cell_schema`; prose alone meets nothing; into the published head
/// document a value naming the kind is `published_target`; a caller who does
/// not own the
/// draft meets nothing here, the store's `not_owner` standing. The same
/// operation under its other name, placing runs by identity, mints nothing
/// and meets no arm for a draft. Under the principal's own live lease the
/// cell is admitted; and nothing is committed by the door (the mutant that
/// gives the frame the door's no-arm branch admits the unbound cell).
#[test]
fn an_edits_values_take_the_inserts_arms_whichever_change_holds_them() {
    use skep_arrangement::{Change, Edit, Placed};
    let dir = tempfile::tempdir().expect("tempdir");
    let gate = MediaGate::open_with(dir.path(), crate::MediaOptions::default()).expect("the store opens");
    let engine = skep_engine::Engine::open(KernelConfig {
        durability: Durability::InMemory,
        checkpoint: CheckpointPolicy::Manual,
        salt: SaltSource::Seeded(0),
    })
    .expect("in-memory genesis cannot fail");
    let (draft, _) = engine
        .namespace()
        .create_new_document(SYSTEM_PRINCIPAL, &system_account(), Some(false))
        .expect("the system principal mints a private draft in its own account");
    gate.index().complete(crate::index::Rebuild { values: 0, cells: 0, halts: 0, walk: Duration::ZERO, parse: Duration::ZERO });
    let snap = engine.kernel().snapshot();
    let world = snap.world();
    let door = |op: Op, p: PrincipalId| media_door(world, &op, p, &gate);
    // An edit of two changes, each minting: prose first, `cell` second.
    let request = |cell: Vec<u8>| Edit {
        changes: vec![
            Change { at: VPos::content(Nat::from(1u32)), width: Nat::from(0u32), placed: Placed::Values(vec![Val::new(b"p".to_vec())]) },
            Change { at: VPos::content(Nat::from(1u32)), width: Nat::from(0u32), placed: Placed::Values(vec![Val::new(cell)]) },
        ],
        head: None,
        base: None,
        merge: None,
    };
    let edit = |doc: &Address, cell: Vec<u8>| Op::Edit { doc: doc.clone(), edit: request(cell), as_of: Seq(7) };
    assert_eq!(door(edit(&draft, canonical()), SYSTEM_PRINCIPAL), Some(MediaRefusal::UnboundCell), "a cell no lease binds, in the second change");
    assert_eq!(door(edit(&draft, unknown_schema()), SYSTEM_PRINCIPAL), Some(MediaRefusal::UnknownCellSchema));
    assert_eq!(door(edit(&draft, b"prose".to_vec()), SYSTEM_PRINCIPAL), None, "prose alone");
    let h = head_document();
    for cell in [canonical(), unknown_schema()] {
        assert_eq!(door(edit(&h, cell), SYSTEM_PRINCIPAL), Some(MediaRefusal::PublishedTarget), "a value naming the kind, into the published head document");
    }
    assert_eq!(door(edit(&h, b"prose".to_vec()), SYSTEM_PRINCIPAL), None, "prose into it: the store's own refusal stands");
    assert_eq!(door(edit(&draft, canonical()), BOOTSTRAP_PRINCIPAL), None, "not the owner: the store's");
    // The operation's other name, placing runs: nothing minted, no arm.
    let run = ShotRun { origin: h.clone(), run: Run::new(skep_engine::types::t_grant().clone(), Nat::from(1u32)).expect("one position") };
    let placing = Edit {
        changes: vec![Change { at: VPos::content(Nat::from(1u32)), width: Nat::from(0u32), placed: Placed::Runs(vec![run]) }],
        head: None,
        base: None,
        merge: None,
    };
    assert_eq!(door(Op::SetArrangement { doc: draft.clone(), arrangement: placing, as_of: Seq(7) }, SYSTEM_PRINCIPAL), None, "runs placed by identity mint no cell");
    assert_eq!(door(Op::SetArrangement { doc: draft.clone(), arrangement: request(canonical()), as_of: Seq(7) }, SYSTEM_PRINCIPAL), Some(MediaRefusal::UnboundCell), "the arm reads the values, whichever name carries them");
    // THE BINDING MADE REAL: five bytes under the principal's own lease.
    let bytes = b"hello";
    let hex = blake3::hash(bytes).to_hex();
    let real = || format!(r#"{{"type":"{}","hash":"{hex}","size":5}}"#, cell::KIND).into_bytes();
    assert_eq!(door(edit(&draft, real()), SYSTEM_PRINCIPAL), Some(MediaRefusal::UnboundCell));
    let key = MediaGate::key(SYSTEM_PRINCIPAL);
    let (now, store, interval) = (gate.now_ms(), gate.store(), Duration::from_millis(1_000_000));
    let rec = store.create_upload(&key, HashFunction::Blake3, 5, interval, now).unwrap();
    let mut stream = store.resume(&key, &rec.id, 0, now).unwrap();
    stream.append(bytes, now).unwrap();
    stream.finish(interval, now).unwrap();
    assert_eq!(door(edit(&draft, real()), SYSTEM_PRINCIPAL), None, "admitted under its own live lease");
    assert_eq!(engine.kernel().current_seq(), snap.seq(), "the door commits nothing");
}

/// A shot past either of the store's re-insert budgets meets no arm, and no
/// value of it is judged; one past the positions is told so with no stored
/// piece read.
///
/// The draft holds an unbound cell — a value the door refuses at any shot it
/// judges — ahead of two-byte atoms, one more value than the store's units
/// budget in all. The owner's shot of the units' budget of them, the cell
/// among them, is refused `unbound_cell`: the door judged the cell. The shot
/// of them all, one unit past the budget and far inside the positions', is a
/// shot the store refuses `too_many_values` by its own count, and the door
/// answers nothing — the cell never judged, the count stopped at the value
/// that passed the budget. A second draft holds the cell ahead of the
/// positions' budget of typed bytes: the shot of it whole is past the
/// positions by arithmetic, and the door answers nothing with NO stored
/// piece read; the shot of the budget's own number of positions, the cell
/// its first, reads the two stored pieces and is refused for the cell.
#[test]
fn a_shot_past_either_reinsert_budget_meets_no_arm_and_past_the_positions_reads_nothing() {
    let dir = tempfile::tempdir().expect("tempdir");
    let gate = MediaGate::open_with(dir.path(), crate::MediaOptions::default()).expect("the store opens");
    gate.index().complete(crate::index::Rebuild { values: 0, cells: 0, halts: 0, walk: Duration::ZERO, parse: Duration::ZERO });
    let engine = skep_engine::Engine::open(KernelConfig {
        durability: Durability::InMemory,
        checkpoint: CheckpointPolicy::Manual,
        salt: SaltSource::Seeded(0),
    })
    .expect("in-memory genesis cannot fail");
    let draft_holding = |values: Vec<Val>| {
        let (draft, _) = engine
            .namespace()
            .create_new_document(SYSTEM_PRINCIPAL, &system_account(), Some(false))
            .expect("the system principal mints a private draft in its own account");
        let first = engine
            .vstream()
            .insert(Caller::Principal(SYSTEM_PRINCIPAL), &draft, VPos::content(Nat::from(1u32)), values, Deposit::Undeclared, AsOf::Typed(engine.kernel().current_seq()))
            .expect("the engine, below the door, writes any bytes")
            .0;
        (draft, first)
    };
    let cell_then = |value: &[u8], count: usize| -> Vec<Val> {
        std::iter::once(Val::new(canonical())).chain(std::iter::repeat_n(Val::new(value), count)).collect()
    };
    let (atoms, first_atom) = draft_holding(cell_then(b"at", MAX_REINSERTED_UNITS));
    let (text, first_byte) = draft_holding(cell_then(b"x", MAX_REINSERTED_VALUES));
    let snap = engine.kernel().snapshot();
    let world = snap.world();
    let h = head_document();
    // The shot of `width` positions of `draft` from `first`, asked of the
    // door's publish arm: its answer, and the stored pieces the count read.
    let asked = |draft: &Address, first: &Address, width: usize| {
        let shot = Shot {
            base: None,
            draft: Some(draft.clone()),
            also: vec![],
            keep_base: false,
            runs: vec![ShotRun { origin: draft.clone(), run: Run::new(first.clone(), Nat::from(width)).expect("one position or more") }],
            stretches: Vec::new(),
        };
        let mut walked = 0u64;
        let answer = publish_arm(world, &PublishTarget::Document(h.clone()), &shot, SYSTEM_PRINCIPAL, &gate, &mut |pieces| walked += pieces);
        (answer, walked)
    };
    // The units: at the budget the cell is judged, past it nothing is.
    let at_the_units = MAX_REINSERTED_UNITS;
    assert_eq!(asked(&atoms, &first_atom, at_the_units), (Some(MediaRefusal::UnboundCell), at_the_units as u64));
    assert_eq!(asked(&atoms, &first_atom, at_the_units + 1), (None, at_the_units as u64 + 1), "past the units: the store's `too_many_values` stands, the cell unjudged");
    // The positions: past the budget by arithmetic, no stored piece read.
    assert_eq!(asked(&text, &first_byte, MAX_REINSERTED_VALUES + 1), (None, 0), "past the positions: nothing read");
    assert_eq!(asked(&text, &first_byte, MAX_REINSERTED_VALUES), (Some(MediaRefusal::UnboundCell), 2), "the cell and the one stretch");
    // A position holding no value is the store's `dangling_source`: nothing
    // of the shot is judged, though the cell stands ahead of the hole.
    let (short, first_short) = draft_holding(cell_then(b"x", 1));
    let snap = engine.kernel().snapshot();
    let shot = Shot {
        base: None,
        draft: Some(short.clone()),
        also: vec![],
        keep_base: false,
        runs: vec![ShotRun { origin: short.clone(), run: Run::new(first_short, Nat::from(3u32)).expect("three positions") }],
        stretches: Vec::new(),
    };
    assert_eq!(publish_arm(snap.world(), &PublishTarget::Document(h), &shot, SYSTEM_PRINCIPAL, &gate, &mut |_| {}), None);
    assert_eq!(engine.kernel().current_seq(), snap.seq(), "the door commits nothing");
}
