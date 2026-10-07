use std::time::Duration;

use skep_arrangement::{Deposit, Run, ShotRun, VPos};
use skep_blobs::HashFunction;
use skep_kernel::{CheckpointPolicy, Durability, KernelConfig, SaltSource};
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
    let blind =
        crate::blind::encode(&crate::blind::BlindCell { commitment: [0xcd; 32] }).into_bytes();
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
    };
    assert_eq!(door(declared, SYSTEM_PRINCIPAL), Some(MediaRefusal::PublishedTarget));
    assert_eq!(
        door(insert(&draft, canonical()), BOOTSTRAP_PRINCIPAL),
        None,
        "not the owner: the store's"
    );

    let shot = |draft: Option<Address>| Op::Publish {
        doc: h.clone(),
        shot: Shot {
            base: None,
            draft: draft.clone(),
            runs: vec![ShotRun {
                origin: draft.clone().unwrap_or_else(|| h.clone()),
                run: Run::new(cell_at.clone(), Nat::from(1u32)).expect("one position"),
            }],
        },
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
        (MediaRefusal::NotOwner { draft: draft.clone() }, None),
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
        )
        .expect("the engine, below the door, writes any bytes")
        .0;
    let snap = engine.kernel().snapshot();
    let world = snap.world();
    let door = |op: Op, p: PrincipalId| media_door(world, &op, p, &gate);
    let shot2 = || Op::Publish {
        doc: h.clone(),
        shot: Shot {
            base: None,
            draft: Some(draft2.clone()),
            runs: vec![ShotRun {
                origin: draft2.clone(),
                run: Run::new(real_at.clone(), Nat::from(1u32)).expect("one position"),
            }],
        },
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
