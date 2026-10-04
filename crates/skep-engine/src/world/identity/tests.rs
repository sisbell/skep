//! The identity slice's seat, held where the spec pins it: the fold hook
//! steps the slice at a credential deposit's commit and nothing else moves
//! it (AUTH-2.80, AUTH-2.66); a body written without the slice reads `None`
//! (AUTH-2.79); a slice-less base resolves to the empty table over no
//! credential deposit and is refused over any (AUTH-2.83); and over a
//! journal, M2's fallback chain steps back from such a base and replays the
//! true table (AUTH-2.84), reports what it skipped (AUTH-2.85, AUTH-2.86),
//! refuses the read below a base that cannot stand in (AUTH-2.87) and the
//! open with no start point at all (AUTH-2.88).

use std::fs;
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};
use skep_address::{Address, Nat};
use skep_arrangement::{Caller, Deposit, VPos};
use skep_content::Val;
use skep_identity::{
    encode_enroll, encode_retire, Enrollment, Fingerprint, HasIdentity, IdentityState, PublicKey,
    ALG_MLDSA65_ED25519, MLDSA65_KEY_LEN,
};
use skep_kernel::{
    BurnedSeqPolicy, CheckpointPolicy, Durability, HistoryError, KernelConfig, OpenError,
    RebuildError, SaltSource, Seq, WorldState,
};
use skep_links::SlotArg;

use crate::testkit::{delegated_account, mem_engine, USER};
use crate::types::{t_claim, t_enroll, t_grant, t_retire};
use crate::world::{FormatStamp, World};
use crate::{Engine, EngineError, Recovery};

/// A deterministic hybrid key: the tag-1 row's widths, both halves one byte.
fn key(seed: u8) -> PublicKey {
    PublicKey::from_halves(ALG_MLDSA65_ED25519, &[seed; MLDSA65_KEY_LEN], &[seed; 32])
        .expect("the tag-1 row's widths")
}

/// Deposit a credential record into `home` as `caller`: the record's atom
/// DECLARED under the kind's type at `ordinal` (PUB-2.63), then the
/// `make_link` naming it — the pair the fold folds at the link's commit.
fn deposit_record(
    engine: &Engine,
    caller: Caller,
    home: &Address,
    ordinal: u32,
    ty: &Address,
    to: &Address,
    record: String,
) {
    let (atom, _) = engine
        .vstream()
        .insert(
            caller,
            home,
            VPos::content(Nat::from(ordinal)),
            vec![Val::new(record.into_bytes())],
            Deposit::Declared(ty.clone()),
        )
        .expect("the record atom lands at the home's next position");
    engine
        .linkstore(&World::visible_to(caller))
        .makelink(
            caller,
            home,
            SlotArg::Addrs(vec![atom]),
            SlotArg::Addrs(vec![to.clone()]),
            SlotArg::Addrs(vec![ty.clone()]),
        )
        .expect("the record's link deposits into the published home");
}

/// A link of type `ty` from `from` to nothing, in `home`, as [`USER`].
fn link_to_nothing(engine: &Engine, home: &Address, from: &Address, ty: &Address) {
    let caller = Caller::Principal(USER);
    engine
        .linkstore(&World::visible_to(caller))
        .makelink(
            caller,
            home,
            SlotArg::Addrs(vec![from.clone()]),
            SlotArg::Addrs(vec![]),
            SlotArg::Addrs(vec![ty.clone()]),
        )
        .expect("a link into the owner's own published document");
}

/// The claim ceremony's shape over the engine's own drivers: an account
/// delegated from the bootstrap principal, its doc 1 (the first flagless
/// mint, published), a genesis enrolling `keys` into it, and the claim.
/// Answers the account and its doc 1.
fn claim_ceremony(engine: &Engine, keys: &[(PublicKey, bool)]) -> (Address, Address) {
    let caller = Caller::Principal(USER);
    let acct = delegated_account(engine, USER);
    let (doc1, _) =
        engine.namespace().create_new_document(USER, &acct, None).expect("the home mint");
    let entries: Vec<Enrollment> = keys
        .iter()
        .map(|(k, anchor)| Enrollment::new(k.clone(), *anchor, None).expect("no label"))
        .collect();
    deposit_record(engine, caller, &doc1, 1, t_enroll(), &acct, encode_enroll(&entries));
    link_to_nothing(engine, &doc1, &acct, t_claim());
    (acct, doc1)
}

/// The slice at the engine's head.
fn identity_of(engine: &Engine) -> IdentityState {
    engine.kernel().snapshot().world().identity().clone()
}

/// The fold hook steps the slice at each credential deposit's commit
/// (AUTH-2.80, AUTH-2.66): the genesis keys the account, the claim flips the
/// board, an own-space enrollment joins the set — and a deposit of no
/// credential kind, the grant's, takes the fast exit and moves nothing.
#[test]
fn a_credential_deposit_steps_the_slice_at_its_commit() {
    let engine = mem_engine();
    let (k1, k2) = (key(1), key(2));
    assert_eq!(identity_of(&engine), IdentityState::genesis(), "Σ₀ carries the genesis table");
    let (acct, doc1) = claim_ceremony(&engine, &[(k1.clone(), true)]);
    let after_claim = identity_of(&engine);
    assert!(after_claim.key_set(&acct).contains(&Fingerprint::of(&k1)), "the genesis keyed it");
    assert_eq!(after_claim.claimant(), Some(&acct), "the claim flipped the board");

    // A holder enrollment (AUTH-2.69) at the next position of doc 1.
    let record = encode_enroll(&[Enrollment::new(k2.clone(), false, None).expect("no label")]);
    deposit_record(&engine, Caller::Principal(USER), &doc1, 2, t_enroll(), &acct, record);
    let after_enroll = identity_of(&engine);
    let set = after_enroll.key_set(&acct);
    assert!(set.contains(&Fingerprint::of(&k1)) && set.contains(&Fingerprint::of(&k2)));

    // A grant-typed deposit is NotCredential at the hook's fast exit.
    link_to_nothing(&engine, &doc1, &doc1, t_grant());
    assert_eq!(identity_of(&engine), after_enroll, "no credential kind, no step");
}

/// The hook folds the AUDIT view, verdicts and all (AUTH-2.78): a credential
/// deposit the fold answers inert — homed in a DRAFT, `unpublished` — enters
/// the link slice and leaves the identity slice as it was, totally.
#[test]
fn an_inert_credential_deposit_enters_the_links_and_moves_the_slice_nowhere() {
    let engine = mem_engine();
    let caller = Caller::Principal(USER);
    let acct = delegated_account(&engine, USER);
    let (_home, _) =
        engine.namespace().create_new_document(USER, &acct, None).expect("the home mint");
    let (draft, _) =
        engine.namespace().create_new_document(USER, &acct, None).expect("a later mint, private");
    let record = encode_enroll(&[Enrollment::new(key(3), true, None).expect("no label")]);
    let (atom, _) = engine
        .vstream()
        .insert(
            caller,
            &draft,
            VPos::content(Nat::from(1u32)),
            vec![Val::new(record.into_bytes())],
            Deposit::Undeclared,
        )
        .expect("an ordinary insert into the owner's draft");
    engine
        .linkstore(&World::visible_to(caller))
        .makelink(
            caller,
            &draft,
            SlotArg::Addrs(vec![atom]),
            SlotArg::Addrs(vec![acct.clone()]),
            SlotArg::Addrs(vec![t_enroll().clone()]),
        )
        .expect("a link in the owner's own draft");
    assert_eq!(identity_of(&engine), IdentityState::genesis(), "an unpublished home folds inert");
}

/// The body a build before the slice wrote: the stamp and the four store
/// slices, and nothing after them.
fn body_without_the_slice(world: &World) -> Vec<u8> {
    bincode::serialize(&(
        &FormatStamp,
        &world.namespace,
        &world.content,
        &world.arrangement,
        &world.links,
    ))
    .expect("the slices serialize")
}

/// AUTH-2.79's `None`: a body that ENDS where the slice would begin — every
/// checkpoint written before it — decodes with the slice absent, where the
/// derived reading would refuse the body at its end; a body carrying the
/// slice decodes with it; and a body carrying it as an explicit `None`
/// decodes the same as an absent one. The decoded world is not yet one to
/// serve — the resolution below is what makes it one.
#[test]
fn a_body_that_ends_before_the_slice_reads_none() {
    let engine = mem_engine();
    claim_ceremony(&engine, &[(key(1), true)]);
    let world = engine.kernel().snapshot().world().clone();
    let current = bincode::serialize(&world).expect("a world serializes");
    let short = body_without_the_slice(&world);
    let slice = bincode::serialize(&world.identity).expect("the slice serializes");
    assert_eq!(current, [short.clone(), slice].concat(), "the slice is the body's tail");

    let decoded = bincode::deserialize::<World>(&short).expect("the short body decodes");
    assert!(decoded.identity.is_none(), "a body ending before the slice reads None");
    let full = bincode::deserialize::<World>(&current).expect("this build's own bytes decode");
    assert_eq!(full.identity, world.identity, "a carried slice decodes as itself");
    let explicit_none = [short, vec![0u8]].concat();
    let decoded = bincode::deserialize::<World>(&explicit_none).expect("an explicit None decodes");
    assert!(decoded.identity.is_none());
}

/// AUTH-2.83, the resolving arm: a slice-less world whose link slice holds no
/// credential deposit — none at all, or a grant-typed one, which the exact
/// filter does not count — resolves to the EMPTY table and says it resolved;
/// a world that carries its slice is carried, not resolved.
#[test]
fn a_slice_less_world_without_a_credential_deposit_resolves_to_the_empty_table() {
    let bare = World { identity: None, ..World::genesis() }
        .rebuild_derived()
        .expect("no credential deposit: a start point");
    assert_eq!(bare.identity, Some(IdentityState::genesis()));
    assert!(bare.identity_resolved, "resolved, not carried");

    let engine = mem_engine();
    let acct = delegated_account(&engine, USER);
    let (home, _) =
        engine.namespace().create_new_document(USER, &acct, None).expect("the home mint");
    link_to_nothing(&engine, &home, &home, t_grant());
    let with_a_grant = World { identity: None, ..engine.kernel().snapshot().world().clone() };
    let resolved = with_a_grant.rebuild_derived().expect("a grant is no credential deposit");
    assert_eq!(resolved.identity, Some(IdentityState::genesis()));
    assert!(resolved.identity_resolved);

    let carried = engine.kernel().snapshot().world().clone().rebuild_derived().expect("carried");
    assert!(!carried.identity_resolved, "a carried slice is carried, not resolved");
}

/// AUTH-2.83, the refusing arm: a slice-less world whose link slice holds a
/// credential deposit of any kind — an enrollment, a claim with no genesis
/// before it (inert, and a deposit all the same, AUTH-2.78), a retirement —
/// is NOT a start point: M2's slice-agnostic refusal names the slice and the
/// remedy.
#[test]
fn a_slice_less_world_carrying_a_credential_deposit_is_not_a_start_point() {
    let refused = |engine: &Engine| {
        World { identity: None, ..engine.kernel().snapshot().world().clone() }
            .rebuild_derived()
            .expect_err("a credential deposit without the slice is not a start point")
    };
    let engine = mem_engine();
    claim_ceremony(&engine, &[(key(1), true)]);
    let unresolved = refused(&engine);
    assert_eq!(unresolved, RebuildError::Unresolved { slice: "identity" });
    assert!(unresolved.to_string().contains("`identity` slice"), "{unresolved}");
    assert!(unresolved.to_string().contains("restore a checkpoint"), "{unresolved}");

    // A claim alone, folded inert (a keyless claimant) — still a deposit.
    let engine = mem_engine();
    let acct = delegated_account(&engine, USER);
    let (doc1, _) =
        engine.namespace().create_new_document(USER, &acct, None).expect("the home mint");
    link_to_nothing(&engine, &doc1, &acct, t_claim());
    assert_eq!(identity_of(&engine).claimant(), None, "keyless, the claim folded inert");
    assert_eq!(refused(&engine), RebuildError::Unresolved { slice: "identity" });

    // A retirement record alone, likewise inert over an empty set.
    let engine = mem_engine();
    let acct = delegated_account(&engine, USER);
    let (doc1, _) =
        engine.namespace().create_new_document(USER, &acct, None).expect("the home mint");
    let retire = encode_retire(&[Fingerprint::of(&key(9))]);
    deposit_record(&engine, Caller::Principal(USER), &doc1, 1, t_retire(), &acct, retire);
    assert_eq!(identity_of(&engine), IdentityState::genesis(), "folded inert");
    assert_eq!(refused(&engine), RebuildError::Unresolved { slice: "identity" });
}

// ── over a journal ────────────────────────────────────────────────────────

const TEST_SEED: u64 = 0x1D;

fn fsync_cfg(dir: &Path, retain: usize) -> KernelConfig {
    KernelConfig {
        durability: Durability::Fsync {
            journal_path: dir.to_path_buf(),
            retain_checkpoints: retain,
            burned_seq: BurnedSeqPolicy::Rollback,
        },
        checkpoint: CheckpointPolicy::Manual,
        salt: SaltSource::Seeded(TEST_SEED),
    }
}

fn open_at(dir: &Path, retain: usize) -> Result<Engine, EngineError> {
    Engine::open(fsync_cfg(dir, retain))
}

/// M2's `SKC4` header: `[magic 4][seq u64 LE][crc32c(body) u32 LE]
/// [body_len u64 LE][chain_head 32][body_hash 32]`, then the body.
const HEADER_LEN: usize = 88;

/// `checkpoint.<seq>` in `dir`, which must exist.
fn checkpoint_in(dir: &Path, seq: u64) -> PathBuf {
    let path = dir.join(format!("checkpoint.{seq}"));
    assert!(path.exists(), "no checkpoint at {seq} in {}", dir.display());
    path
}

/// Rewrite `checkpoint.<seq>`'s body under a VALID header — the seq and the
/// chain head kept, the length, checksum and hash recomputed — so the DECODE
/// and the seed, not the header's checks, are what judge the body.
fn rewrite_checkpoint_body(dir: &Path, seq: u64, body: &[u8]) {
    let path = checkpoint_in(dir, seq);
    let old = fs::read(&path).expect("read the checkpoint");
    let mut header = old[..HEADER_LEN].to_vec();
    header[12..16].copy_from_slice(&crc32c::crc32c(body).to_le_bytes());
    header[16..24].copy_from_slice(&(body.len() as u64).to_le_bytes());
    let body_hash: [u8; 32] = Sha256::digest(body).into();
    header[56..88].copy_from_slice(&body_hash);
    fs::write(&path, [header.as_slice(), body].concat()).expect("rewrite the checkpoint");
}

/// Strip the identity slice off `checkpoint.<seq>`'s body: the body a build
/// before the slice would have written of the same world. `with_explicit_none`
/// appends the `None` tag instead, the shape a body that SERIALIZED the slice
/// as absent has.
fn strip_the_slice(dir: &Path, seq: u64, slice: &IdentityState, with_explicit_none: bool) {
    let path = checkpoint_in(dir, seq);
    let body = fs::read(&path).expect("read the checkpoint")[HEADER_LEN..].to_vec();
    let suffix = bincode::serialize(&Some(slice.clone())).expect("the slice serializes");
    assert!(body.ends_with(&suffix), "the body ends with the carried slice");
    let mut stripped = body[..body.len() - suffix.len()].to_vec();
    if with_explicit_none {
        stripped.push(0);
    }
    rewrite_checkpoint_body(dir, seq, &stripped);
}

/// Bulk content into a private draft of `acct`, enough to rotate the journal
/// at `dir`: four values of 300 KiB, then one small write, which is the first
/// transaction of the second segment.
fn rotate_the_journal(engine: &Engine, dir: &Path, acct: &Address) {
    let caller = Caller::Principal(USER);
    let (draft, _) =
        engine.namespace().create_new_document(USER, acct, None).expect("a later mint, private");
    for ordinal in 1..=5u32 {
        let value = if ordinal == 5 { vec![b'.'] } else { vec![b'z'; 300 * 1024] };
        engine
            .vstream()
            .insert(
                caller,
                &draft,
                VPos::content(Nat::from(ordinal)),
                vec![Val::new(value)],
                Deposit::Undeclared,
            )
            .expect("a bulk insert into the owner's draft");
    }
    let segments = fs::read_dir(dir)
        .expect("list the journal directory")
        .filter(|entry| {
            let name = entry.as_ref().expect("entry").file_name().to_string_lossy().into_owned();
            name.starts_with("seg-") && name.ends_with(".wal")
        })
        .count();
    assert!(segments >= 2, "the fixture must rotate the segment, found {segments}");
}

/// AUTH-2.84, AUTH-2.85, AUTH-2.86: a checkpoint written without the slice
/// over a claimed board is NOT a start point — the open steps back to
/// genesis, replays, and the table is the live fold's, at the head and at
/// the checkpoint's own position alike (`world_at` runs the same chain) —
/// and the open REPORTS the checkpoint it skipped and the start point it
/// resolved from. The explicit-`None` body steps back the same way.
#[test]
fn the_load_steps_back_from_a_slice_less_checkpoint_and_replays_the_true_table() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (acct, live, at) = {
        let engine = open_at(dir.path(), 2).expect("genesis open");
        let (acct, doc1) = claim_ceremony(&engine, &[(key(1), true)]);
        let record = encode_enroll(&[Enrollment::new(key(2), false, None).expect("no label")]);
        deposit_record(&engine, Caller::Principal(USER), &doc1, 2, t_enroll(), &acct, record);
        let at = engine.kernel().checkpoint().expect("checkpoint").0;
        assert_eq!(
            engine.recovery(),
            Some(&Recovery { start_point: Seq(0), skipped: vec![], identity_resolved_empty: false })
        );
        (acct, identity_of(&engine), at)
    };
    let as_written = fs::read(checkpoint_in(dir.path(), at)).expect("the carried checkpoint");
    for explicit_none in [false, true] {
        fs::write(checkpoint_in(dir.path(), at), &as_written).expect("restore the checkpoint");
        strip_the_slice(dir.path(), at, &live, explicit_none);
        let engine = open_at(dir.path(), 2).expect("the open steps back to genesis");
        let recovery = engine.recovery().expect("journaled");
        assert_eq!(recovery.start_point, Seq(0), "genesis stood in");
        assert_eq!(recovery.skipped.len(), 1, "{recovery:?}");
        assert_eq!(recovery.skipped[0].seq, Seq(at), "the slice-less checkpoint was skipped");
        assert!(recovery.skipped[0].why.contains("`identity` slice"), "{}", recovery.skipped[0].why);
        assert!(!recovery.identity_resolved_empty);
        assert_eq!(identity_of(&engine), live, "the replayed table is the live fold's");
        let at_the_checkpoint = engine.world_at(Seq(at)).expect("the history read runs the same chain");
        assert_eq!(at_the_checkpoint.identity(), &live);
        assert_eq!(
            at_the_checkpoint.identity().key_set(&acct).enrolled().count(),
            2,
            "both keys, the genesis's and the holder's, as the live fold held them"
        );
    }
}

/// AUTH-2.83 over a journal, with the open's second warning: a checkpoint
/// written without the slice over a board that never deposited a credential
/// IS a start point — it loads as the empty table, equal to a from-genesis
/// replay — and the open says it resolved.
#[test]
fn a_slice_less_checkpoint_with_no_credential_deposit_loads_as_the_empty_table_and_says_so() {
    let dir = tempfile::tempdir().expect("tempdir");
    let at = {
        let engine = open_at(dir.path(), 2).expect("genesis open");
        let acct = delegated_account(&engine, USER);
        let (home, _) =
            engine.namespace().create_new_document(USER, &acct, None).expect("the home mint");
        // Prose declared under a member type: an atom of no record, and no
        // link over it — the link slice holds no credential deposit.
        engine
            .vstream()
            .insert(
                Caller::Principal(USER),
                &home,
                VPos::content(Nat::from(1u32)),
                vec![Val::new(b"x".to_vec())],
                Deposit::Declared(t_enroll().clone()),
            )
            .expect("prose declared under a member type lands");
        engine.kernel().checkpoint().expect("checkpoint").0
    };
    strip_the_slice(dir.path(), at, &IdentityState::genesis(), false);
    let engine = open_at(dir.path(), 2).expect("a slice-less base over no deposit is a start point");
    assert_eq!(
        engine.recovery(),
        Some(&Recovery { start_point: Seq(at), skipped: vec![], identity_resolved_empty: true })
    );
    assert_eq!(identity_of(&engine), IdentityState::genesis());
    // Equal to the from-genesis replay the same journal answers.
    assert_eq!(engine.world_at(Seq(0)).expect("genesis").identity(), &IdentityState::genesis());
}

/// AUTH-2.88: a HEAD with no start point — its one retained checkpoint
/// slice-less over credential deposits, the journal below it reclaimed —
/// refuses to open, the refusal naming the slice and the remedy.
#[test]
fn a_head_with_no_start_point_refuses_to_open_naming_the_remedy() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (live, at) = {
        let engine = open_at(dir.path(), 1).expect("genesis open");
        let (acct, _) = claim_ceremony(&engine, &[(key(1), true)]);
        rotate_the_journal(&engine, dir.path(), &acct);
        let at = engine.kernel().checkpoint().expect("checkpoint, reclaiming below").0;
        assert!(engine.world_at(Seq(0)).is_err(), "the fixture must have reclaimed genesis");
        (identity_of(&engine), at)
    };
    strip_the_slice(dir.path(), at, &live, false);
    let refused = open_at(dir.path(), 1).expect_err("no start point: the open refuses");
    let EngineError::Open(OpenError::BadCheckpoint { cause: Some(cause) }) = refused else {
        panic!("expected BadCheckpoint with the slice's cause, got {refused:?}");
    };
    let sentence = cause.to_string();
    assert!(sentence.contains("`identity` slice"), "{sentence}");
    assert!(sentence.contains("restore a checkpoint that carries the slice"), "{sentence}");
    assert!(sentence.contains("a journal that reaches one"), "{sentence}");
}

/// AUTH-2.87: where the only retained checkpoint at or below `N` is
/// slice-less over credential deposits and the journal below it is
/// reclaimed, the history read at `N` is REFUSED whole — `Reclaimed`, the
/// floor named, the cause the slice's own — while the head, which has a
/// start point above, serves; and a boundary below the floor refuses as it
/// always did.
#[test]
fn a_history_read_below_a_base_that_cannot_stand_in_is_reclaimed_with_its_cause() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (live, older, newer) = {
        let engine = open_at(dir.path(), 2).expect("genesis open");
        let (acct, doc1) = claim_ceremony(&engine, &[(key(1), true)]);
        // The rotation BEFORE the older checkpoint, so the segment below it is
        // wholly below and the checkpoint reclaims it.
        rotate_the_journal(&engine, dir.path(), &acct);
        let older = engine.kernel().checkpoint().expect("the older checkpoint").0;
        assert!(engine.world_at(Seq(0)).is_err(), "genesis reclaimed below the older base");
        let record = encode_enroll(&[Enrollment::new(key(2), false, None).expect("no label")]);
        deposit_record(&engine, Caller::Principal(USER), &doc1, 2, t_enroll(), &acct, record);
        let newer = engine.kernel().checkpoint().expect("the newer checkpoint").0;
        (identity_of(&engine), older, newer)
    };
    let before_the_holder = {
        let engine = open_at(dir.path(), 2).expect("reopen");
        engine.world_at(Seq(older)).expect("the older base, still carried").identity().clone()
    };
    assert_ne!(before_the_holder, live, "the holder's key joined after the older base");
    strip_the_slice(dir.path(), older, &before_the_holder, false);
    let engine = open_at(dir.path(), 2).expect("the head has a start point: the newer base");
    assert_eq!(engine.recovery().expect("journaled").skipped, vec![], "the newer base stood in");
    assert_eq!(identity_of(&engine), live);
    assert_eq!(engine.world_at(Seq(newer)).expect("at the newer base").identity(), &live);
    match engine.world_at(Seq(older)) {
        Err(HistoryError::Reclaimed { floor, cause: Some(cause) }) => {
            assert_eq!(floor, Some(Seq(older)), "the floor is the oldest retained checkpoint");
            assert!(cause.to_string().contains("`identity` slice"), "{cause}");
        }
        other => panic!("expected Reclaimed with the slice's cause, got {other:?}"),
    }
    match engine.world_at(Seq(older - 1)) {
        Err(HistoryError::Reclaimed { floor, cause: None }) => assert_eq!(floor, Some(Seq(older))),
        other => panic!("expected Reclaimed with nothing tried, got {other:?}"),
    }
}
