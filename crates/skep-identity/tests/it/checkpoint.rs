//! AUTH-1.40's compatibility surface, which freezes with the first checkpoint
//! a v1 board writes, pinned as BYTES rather than as round trips: the
//! `Enrolled` row, the `KeySet` frame around it and each hybrid arm's bytes,
//! the genesis checkpoint, and the order of `IdentityState`'s two fields —
//! beside the round trips of the value types and of a populated state. All
//! through `bincode`, a format that admits the non-string map keys a JSON
//! round trip cannot carry; this is the one file that uses it.

use crate::common;

use common::*;
use skep_identity::{encode_enroll, Enrolled, Fingerprint, IdentityState, PublicKey};

/// AUTH-1.1/AUTH-1.7/AUTH-1.29 — the checkpoint-facing value types
/// survive a serde round trip (the populated `IdentityState` round trip is
/// `populated_state_survives_serde`, below).
#[test]
fn value_types_survive_serde() {
    let k = key(0x11);
    let bytes = bincode::serialize(&k).expect("serialize PublicKey");
    let back: PublicKey = bincode::deserialize(&bytes).expect("deserialize PublicKey");
    assert_eq!(back, k);

    let f = fp(0x22);
    let bytes = bincode::serialize(&f).expect("serialize Fingerprint");
    let back: Fingerprint = bincode::deserialize(&bytes).expect("deserialize Fingerprint");
    assert_eq!(back, f);

    let e = Enrolled { key: k, anchor: true };
    let bytes = bincode::serialize(&e).expect("serialize Enrolled");
    let back: Enrolled = bincode::deserialize(&bytes).expect("deserialize Enrolled");
    assert_eq!(back, e);
}

/// AUTH-1.40 — the checkpointed shape, pinned as BYTES rather than as a
/// round trip. `Enrolled` rides inside `KeySet` inside `IdentityState`, so
/// its encoding is part of the compatibility surface that freezes with the
/// first checkpoint a v1 board writes; a round trip agrees with itself after
/// any field-type change and would not notice. The key opens on its arm's
/// variant index — `0` for tag 1's `mldsa65-ed25519` since the classical
/// arm's deletion renumbered the discriminant (free before the first served
/// board, AUTH-2.90's clock) — then the raw key as a tuple of its row's
/// width, no length prefix. The anchor flag is ONE byte: widening it — to an
/// enum, an integer, a struct — moves every later field of every checkpoint
/// written since, and this assertion is where that is discovered.
#[test]
fn enrolled_checkpoint_encoding_is_pinned() {
    let k = key(0x11);
    let e = Enrolled { key: k.clone(), anchor: true };

    let mut want: Vec<u8> = Vec::new();
    want.extend_from_slice(&0u32.to_le_bytes()); // the tag-1 arm's variant index
    want.extend_from_slice(k.raw()); // the raw key bytes, 1,984 of them
    want.push(1); // the anchor flag, one byte

    assert_eq!(want.len(), 4 + 1984 + 1);
    assert_eq!(bincode::serialize(&e).expect("serialize Enrolled"), want);
}

/// AUTH-1.40 — the FIRST checkpoint a v1 board writes, pinned as bytes,
/// because that is the one the shape freezes with: the empty `sets` map's
/// eight-byte length and `claimant`'s one-byte `None`, and no `Address`,
/// which is why this shape can be stated here at all. NINE bytes is the
/// claim: eight for the map's length prefix, one for the `Option`
/// discriminant. A third field, or either field's width at empty changing —
/// a `claimant` that stopped being an `Option`, a length prefix that is not
/// a `u64` — moves every later byte of every checkpoint written since, and
/// `populated_state_survives_serde` agrees with itself after all of them.
/// What this cannot see is the two fields' ORDER, because at genesis every
/// byte is zero; `identity_state_encodes_sets_before_claimant` is where that
/// half is pinned, over a state that has a row to put first.
#[test]
fn genesis_checkpoint_encoding_is_pinned() {
    let mut want: Vec<u8> = Vec::new();
    want.extend_from_slice(&0u64.to_le_bytes()); // `sets`: an empty map
    want.push(0); // `claimant`: None

    assert_eq!(
        bincode::serialize(&IdentityState::genesis()).expect("serialize IdentityState"),
        want
    );
}

/// AUTH-1.40 — the checkpointed frame AROUND `Enrolled`: `KeySet`'s two maps
/// in declaration order, each a length then its rows, a `Fingerprint` key as
/// its thirty-two raw bytes, and a RETIRED row as the ONE anchor byte
/// AUTH-1.29 fixes. `enrolled_checkpoint_encoding_is_pinned` owns the
/// `Enrolled` row; this owns everything around it. The edit it is here for is
/// the tempting one — storing the whole `Enrolled` in `retired` so the flag
/// comes along instead of being carried by hand — which keeps `retired()`'s
/// `(&Fingerprint, bool)` signature, passes every other vector, and silently
/// rewrites every checkpoint's bytes.
#[test]
fn key_set_checkpoint_encoding_is_pinned() {
    let mut fx = Fixture::new();
    // enrolled = {fp(1): anchor}, retired = {fp(2): non-anchor} — ONE row in
    // each map, so fingerprint order is not a variable in this expectation.
    let st = seeded_then_retired(&mut fx);

    let mut want: Vec<u8> = Vec::new();
    want.extend_from_slice(&1u64.to_le_bytes()); // `enrolled`: one row
    want.extend_from_slice(fp(1).as_bytes()); // the map key: 32 raw bytes
    want.extend_from_slice(&0u32.to_le_bytes()); // the value: the tag-1 arm's variant index
    want.extend_from_slice(key(1).raw()); // key(1)'s raw bytes, 1,984 of them, no length prefix
    want.push(1); // the anchor flag
    want.extend_from_slice(&1u64.to_le_bytes()); // `retired`: one row
    want.extend_from_slice(fp(2).as_bytes());
    want.push(0); // the retired row is the FLAG, one byte

    assert_eq!(
        bincode::serialize(st.key_set(&addr(ACCT_A))).expect("serialize KeySet"),
        want
    );
}

/// AUTH-1.40 — BOTH HYBRID arms' checkpoint bytes, the key kinds since the
/// classical row's deletion. An enrolled row's value opens on the arm's
/// variant index — `0` for tag 1's `mldsa65-ed25519`, `1` for tag 3's
/// `fndsa512-preview-ed25519`, RENUMBERED from `1`/`2` when the classical arm
/// went (free before the first served board, AUTH-2.90's clock; never after)
/// — then the raw key as a TUPLE of its row's width — the post-quantum key
/// then the Ed25519 key, no length prefix, the form the derive gives a
/// `[u8; 32]` — then the anchor flag; the `Box` an arm holds leaves no trace
/// in the bytes. The keys are derived deterministically from a seed
/// (`key_of`), so the expectation is a function of the test alone. The edit
/// this is here for: a hybrid arm re-encoded through a length-prefixed byte
/// form, or an arm reordered in the enum, passes every other vector and
/// silently rewrites every checkpoint holding a hybrid key.
#[test]
fn hybrid_key_set_checkpoint_encodings_are_pinned() {
    for (kind, variant) in [
        (KeyKind::MlDsa65Ed25519, 0u32),
        (KeyKind::FnDsa512PreviewEd25519, 1u32),
    ] {
        let mut fx = Fixture::new();
        // enrolled = {fp: anchor}, ONE hybrid row; retired = {} — so
        // fingerprint order is not a variable here.
        let payload = encode_enroll(&[enrollment_of(kind, 1, true)]).into_bytes();
        let dep = fx.enroll_dep(&doc1(ACCT_A), ACCT_A, &payload);
        let (st, v) = fx.step(&IdentityState::genesis(), &dep);
        assert_honored(&v);

        let key = key_of(kind, 1);
        let mut want: Vec<u8> = Vec::new();
        want.extend_from_slice(&1u64.to_le_bytes()); // `enrolled`: one row
        want.extend_from_slice(Fingerprint::of(&key).as_bytes()); // the map key: 32 raw bytes
        want.extend_from_slice(&variant.to_le_bytes()); // the value: the hybrid arm's variant index
        want.extend_from_slice(key.raw()); // the raw key, PQ half then Ed25519 half, no length prefix
        want.push(1); // the anchor flag
        want.extend_from_slice(&0u64.to_le_bytes()); // `retired`: no row

        assert_eq!(
            bincode::serialize(st.key_set(&addr(ACCT_A))).expect("serialize KeySet"),
            want,
            "{kind:?}"
        );
    }
}

/// AUTH-1.40 — `sets` encodes BEFORE `claimant`, which is the half
/// `genesis_checkpoint_encoding_is_pinned` cannot see: at genesis both fields
/// are zero bytes and swapping them changes nothing. A state with one keyed
/// account opens on that map's eight-byte length of 1, where a swapped state
/// opens on `claimant`'s one-byte `None`. Only the PREFIX is asserted — what
/// follows is an `Address`, whose encoding is M1's to pin and not this
/// crate's.
#[test]
fn identity_state_encodes_sets_before_claimant() {
    let mut fx = Fixture::new();
    let st = seeded(&mut fx); // one keyed account, unclaimed
    let bytes = bincode::serialize(&st).expect("serialize IdentityState");
    assert!(
        bytes.starts_with(&1u64.to_le_bytes()),
        "a checkpoint opens on `sets`' row count, not on `claimant`"
    );
}

/// AUTH-1.40 — a populated `IdentityState` (sets, retirements, claimant)
/// survives a serde round trip, and equals itself under `PartialEq`.
#[test]
fn populated_state_survives_serde() {
    let mut fx = Fixture::new();
    let genesis_state = IdentityState::genesis();
    let st = seed_own(
        &mut fx,
        &genesis_state,
        ACCT_A,
        &[(1, true), (2, false), (3, false)],
    );
    let dep = fx.retire_dep(&doc1(ACCT_A), ACCT_A, &retire_payload(&[3]));
    let (st, v) = fx.step(&st, &dep);
    assert_honored(&v);
    let st = seed_own(&mut fx, &st, CLAIMANT, &[(9, true)]);
    let st = claim_as(&mut fx, &st, CLAIMANT);

    let bytes = bincode::serialize(&st).expect("serialize IdentityState");
    let back: IdentityState = bincode::deserialize(&bytes).expect("deserialize IdentityState");
    assert_eq!(back, st);
    assert_eq!(back.claimant(), Some(&addr(CLAIMANT)));
    assert!(back.key_set(&addr(ACCT_A)).contains(&fp(1)));
}
