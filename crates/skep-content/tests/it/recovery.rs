//! The journaled record and the checkpointed slice: that both survive a
//! bincode round trip and M2's durable recovery across a checkpoint; that
//! the slice's serialized form is the format its readers pin; that the
//! slice's decode takes its entries in every order they can arrive; that
//! neither decode trusts a count its bytes do not carry or admits a key that
//! is no tumbler, or no T4-valid address; and that both admit every T4-valid
//! address, whatever its routing, since a release build stages each as given.

use serde::de::DeserializeOwned;
use skep_address::{content_subspace, validate, Level, Nat, T4Clause, Tumbler};
use skep_content::{stage_write, write, ContentError, ContentStore, ContentWrite, HasContent, Val};
use skep_kernel::Kernel;
use tempfile::tempdir;

use crate::common::*;

// ---- serde: the journaled record and the checkpointed slice ----

#[test]
fn the_record_and_the_slice_survive_a_bincode_round_trip() {
    // §A/§Recovery: ContentWrite is the delta M2 journals; the slice is fully
    // serialized in checkpoints. bincode is M2's actual wire format.
    let a1 = ca(1);
    let a2 = ca(2);
    let rec = stage_write(&ContentStore::default(), &a1, val(b"payload")).expect("fresh");
    let bytes = bincode::serialize(&rec).expect("record serializes");
    let back: ContentWrite = bincode::deserialize(&bytes).expect("record deserializes");
    assert_eq!(back, rec);
    // The replayed record folds to the same store effect (replay re-applies,
    // no re-derivation).
    let c = ContentStore::default().apply_write(&back);
    assert_eq!(c.value_at(a1.tumbler()).map(Val::as_bytes), Some(&b"payload"[..]));

    // The slice round-trips whole (checkpoint form; rebuild_derived identity).
    let c = c.apply_write(&stage_write(&c, &a2, val(b"more")).expect("fresh"));
    let bytes = bincode::serialize(&c).expect("slice serializes");
    let back: ContentStore = bincode::deserialize(&bytes).expect("slice deserializes");
    assert_eq!(back, c, "the slice round-trips whole");
    assert_eq!(back.len(), 2);
    assert_eq!(back.value_at(a1.tumbler()).map(Val::as_bytes), Some(&b"payload"[..]));
    assert_eq!(back.value_at(a2.tumbler()).map(Val::as_bytes), Some(&b"more"[..]));
}

#[test]
fn the_slice_serializes_as_its_map_alone_in_tumbler_order() {
    // The form is a format (store.rs, `in_tumbler_order`): M2's checkpoint
    // hashes these bytes, the engine's World lays them down as one slice of
    // its layout, and the engine's world dump renders them. So they are
    // pinned whole — the slice's one field, its map, as its
    // length then its entries (exactly a `Vec` of pairs' bytes), the entries
    // in Tumbler order, each value its length then its raw bytes (bincode's
    // form for a sequence of `u8`, which `Val` and `Vec<u8>` both serialize
    // as). Sixty-four entries over four documents, written out of order, so
    // the order of writing is not Tumbler order by accident, and five more
    // below, where Tumbler order parts from other orders.
    let mut c = ContentStore::default();
    let mut entries: Vec<(Tumbler, Vec<u8>)> = Vec::new();
    for k in 0..64u32 {
        // 37 is coprime to 64: every (document, ordinal) once, out of order.
        let i = k * 37 % 64;
        let (doc, ordinal) = (1 + i / 16, 1 + i % 16);
        let addr = a(&[1, 0, 1, 0, doc, 0, 1, ordinal]);
        let bytes = format!("{doc}.{ordinal}").into_bytes();
        c = c.apply_write(&stage_write(&c, &addr, Val::new(bytes.clone())).expect("fresh"));
        entries.push((addr.tumbler().clone(), bytes));
    }
    // Five more, where Tumbler order parts from orders that agree with it on
    // the keys above (equal lengths, one-byte components): a version
    // document's content, nine components sorting between document 1's and
    // document 2's — not shortest first; and ordinals 256, 2³² and 2⁶⁴ (one
    // `u32` digit past a byte, two digits, three), each sorting after 16 —
    // not by encoded bytes, nor by a low digit.
    let ca_under = |anchor: &[u32], ordinal: Nat| {
        let comps = anchor.iter().map(|&c| Nat::from(c)).chain(std::iter::once(ordinal));
        validate(Tumbler::new(comps).expect("nonempty")).expect("T4-valid")
    };
    for addr in [
        ca_under(&[1, 0, 1, 0, 1, 1, 0, 1], Nat::from(2u32)),
        ca_under(&[1, 0, 1, 0, 3, 0, 1], Nat::from(256u32)),
        ca_under(&[1, 0, 1, 0, 2, 0, 1], Nat::from(1u64 << 32)),
        ca_under(&[1, 0, 1, 0, 1, 1, 0, 1], Nat::from(1u32)),
        ca_under(&[1, 0, 1, 0, 4, 0, 1], Nat::from(u64::MAX) + 1u32),
    ] {
        let bytes = addr.tumbler().to_string().into_bytes();
        c = c.apply_write(&stage_write(&c, &addr, Val::new(bytes.clone())).expect("fresh"));
        entries.push((addr.tumbler().clone(), bytes));
    }
    entries.sort_by(|x, y| x.0.cmp(&y.0));
    assert!(
        bincode::serialize(&c).expect("slice serializes")
            == bincode::serialize(&entries).expect("entries serialize"),
        "M4's slice serialized as something other than its map alone, entries in Tumbler \
         order: those bytes are M2's hashed checkpoint body, a slice of the engine's World \
         layout and the engine's world dump — a change to them owes the engine's \
         WORLD_FORMAT bump and a dump-filter disposition"
    );
}

/// Decodes `bytes` as `T`, asserts the decode REFUSED them — an `Err`,
/// neither a decoded `T` nor a panic — and returns the refusal's message, for
/// a caller that pins which door refused. A panic is how a reservation sized
/// by a count the bytes do not carry shows itself when it overflows, and how
/// a decode that takes what they hold on trust, through an `expect`, shows
/// itself at all.
fn assert_refused<T: DeserializeOwned>(what: &str, bytes: &[u8]) -> String {
    match std::panic::catch_unwind(|| bincode::deserialize::<T>(bytes)) {
        Ok(Err(refusal)) => refusal.to_string(),
        Ok(Ok(_)) => panic!("{what}: decoded, though no slice or record serializes as these bytes"),
        Err(_) => panic!(
            "{what}: the decode panicked instead of refusing the bytes — a reservation sized by \
             a count they do not carry, or an `expect` that took what they hold on trust"
        ),
    }
}

#[test]
fn the_record_and_the_slice_refuse_a_count_their_bytes_do_not_carry() {
    // M2's hostile-input obligation (store.rs, `in_tumbler_order`): a
    // checkpoint body and a journal frame are bytes M2 does not trust, and
    // M2 answers one that will not decode by refusing it — a checkpoint is
    // skipped for an older base, a record is `Corruption`. So a
    // declared count the bytes do not carry (a writer/reader skew reading
    // another slice's bytes as this length, or a crafted file) must decode as
    // an `Err`, by running out of input. Reserving room for the count first
    // breaks that: past `isize::MAX` bytes the reservation panics, and short
    // of it a count the allocator cannot grant aborts the process. A count one
    // past what the bytes hold is the control, refused the ordinary way.
    let held = ContentStore::default()
        .apply_write(&stage_write(&ContentStore::default(), &ca(1), val(b"held")).expect("fresh"));
    let mut one_past = bincode::serialize(&held).expect("slice serializes");
    // The slice's bytes open with its map's count (pinned by the test above).
    one_past[..8].copy_from_slice(&2u64.to_le_bytes());
    assert_refused::<ContentStore>("a slice counting one entry past those it holds", &one_past);
    assert_refused::<ContentStore>(
        "a slice counting more entries than any body could hold",
        &u64::MAX.to_le_bytes(),
    );
    let mut long_value = bincode::serialize(ca(1).tumbler()).expect("address serializes");
    long_value.extend_from_slice(&u64::MAX.to_le_bytes());
    assert_refused::<ContentWrite>(
        "a record whose value counts more bytes than follow",
        &long_value,
    );
    assert_refused::<ContentWrite>(
        "a record whose address counts more components than follow",
        &u64::MAX.to_le_bytes(),
    );
}

#[test]
fn the_record_and_the_slice_refuse_a_key_that_is_no_tumbler() {
    // M2's hostile-input obligation, at the key: the slice's decode
    // (`entry_by_entry`) and the record's decode take each address as an
    // `Address`, whose `Deserialize` first re-enters `Tumbler`'s door
    // (`try_from` → `Tumbler::new`), and that refuses the empty component
    // sequence — no tumbler at all (T0). So a checkpoint body or a journal
    // frame laying an empty sequence where an address belongs is REFUSED,
    // never stored: M1's reads stand on T0 (`ordinal` takes the last
    // component with an `expect` that names it), and a key in `dom(C)`
    // reaches every reader of the recovered store. No constructor builds such
    // a key, so the bytes are laid through the raw shapes the types serialize
    // as — a tumbler as its `Vec<Nat>`, a value as its byte sequence, the
    // slice as a `Vec` of pairs. The same shapes carrying a real address are
    // the control: they decode to the slice and the record that hold it, so
    // the refusal is the empty key's alone.
    let slice = |key: &[Nat]| {
        bincode::serialize(&vec![(key.to_vec(), b"x".to_vec())]).expect("the raw slice serializes")
    };
    let record = |key: &[Nat]| {
        bincode::serialize(&(key.to_vec(), b"x".to_vec())).expect("the raw record serializes")
    };
    let real: Vec<Nat> = ca(1).tumbler().iter().cloned().collect();
    let rec = stage_write(&ContentStore::default(), &ca(1), val(b"x")).expect("fresh");
    assert_eq!(
        bincode::deserialize::<ContentStore>(&slice(&real)).expect("the control slice decodes"),
        ContentStore::default().apply_write(&rec)
    );
    assert_eq!(
        bincode::deserialize::<ContentWrite>(&record(&real)).expect("the control record decodes"),
        rec
    );
    assert_refused::<ContentStore>("a slice whose one key is an empty sequence", &slice(&[]));
    assert_refused::<ContentWrite>("a record whose address is an empty sequence", &record(&[]));
}

#[test]
fn the_record_and_the_slice_refuse_a_key_that_is_no_address() {
    // ASN-0093 StoreT4Validity (store.rs, `ContentStore`'s key invariants):
    // every key in `dom(C)` is T4-valid, and both decode paths re-enter M1's
    // `Address` door (`validate`) to keep it so — an `Address` journals as
    // its bare tumbler, so the door reads the bytes the record and the slice
    // already write. Each key below is nonempty, so `Tumbler`'s own door (T0,
    // the test above) admits it, and breaks exactly one T4 clause, so only
    // the `Address` door can refuse it — and the refusal is pinned as that
    // door's own, word for word. What the door admits is the next test's.
    let raw = |key: &[u32]| -> Vec<Nat> { key.iter().map(|&c| Nat::from(c)).collect() };
    let slice = |key: &[u32]| {
        bincode::serialize(&vec![(raw(key), b"x".to_vec())]).expect("the raw slice serializes")
    };
    let record = |key: &[u32]| {
        bincode::serialize(&(raw(key), b"x".to_vec())).expect("the raw record serializes")
    };
    for (clause, key) in [
        (T4Clause::LeadingZero, &[0u32, 1][..]),
        (T4Clause::TrailingZero, &[1, 0][..]),
        (T4Clause::AdjacentZeros, &[1, 0, 0, 1][..]),
        (T4Clause::OverDepth, &[1, 0, 1, 0, 1, 0, 1, 0, 1][..]),
    ] {
        let door = validate(t(key)).expect_err("each key breaks a T4 clause");
        assert_eq!(door.clauses(), [clause].as_slice(), "{key:?} breaks {clause} alone");
        let door = door.to_string();
        for (form, refusal) in [
            (
                "slice",
                assert_refused::<ContentStore>(
                    &format!("a slice whose one key breaks {clause}"),
                    &slice(key),
                ),
            ),
            (
                "record",
                assert_refused::<ContentWrite>(
                    &format!("a record whose address breaks {clause}"),
                    &record(key),
                ),
            ),
        ] {
            assert_eq!(
                refusal, door,
                "the {form} refused a key breaking {clause} for another reason"
            );
        }
    }
}

#[test]
fn the_record_and_the_slice_admit_every_address_a_release_build_can_stage() {
    // store.rs, `ContentStore`'s second key invariant: a content-subspace
    // element address — ASN-0093 C1, the element LEVEL, and L0, the content
    // SUBSPACE — is the stage door's caller to guarantee, checked in debug
    // builds only; a release build stages a violator of either half as given
    // (`write_trusts_a_document_level_address_in_release_and_panics_on_it_in_debug`
    // commits one). So both decode paths take it on journal and checkpoint
    // integrity: a decode that refused one would leave that build unable to
    // replay its own journal. The decode therefore admits every address T4
    // admits, whatever its routing — here one of each shape the routing
    // assertion stops in a debug build: each level short of an element, and
    // an element in a subspace other than content's, each checked first to
    // be T4-valid and no content-subspace element address. The bytes are the
    // raw shapes the refusal tests above lay down.
    let raw = |key: &[u32]| -> Vec<Nat> { key.iter().map(|&c| Nat::from(c)).collect() };
    let slice = |key: &[u32]| {
        bincode::serialize(&vec![(raw(key), b"x".to_vec())]).expect("the raw slice serializes")
    };
    let record = |key: &[u32]| {
        bincode::serialize(&(raw(key), b"x".to_vec())).expect("the raw record serializes")
    };
    for (shape, key) in [
        ("a node address", &[1u32][..]),
        ("an account address", &[1, 0, 1][..]),
        ("a document address", &[1, 0, 1, 0, 1][..]),
        ("a link-subspace element address", &[1, 0, 1, 0, 1, 0, 2, 1][..]),
        ("a subspace-3 element address", &[1, 0, 1, 0, 1, 0, 3, 1][..]),
    ] {
        let addr = validate(t(key)).expect("T4-valid, so a release stage door admits it");
        assert!(
            addr.level() != Level::Element || addr.subspace() != Some(&content_subspace()),
            "{shape} is routed to content, so routing would not stop it"
        );
        let decoded = bincode::deserialize::<ContentStore>(&slice(key))
            .unwrap_or_else(|refusal| panic!("a slice holding {shape} was refused: {refusal}"));
        assert_eq!(
            decoded.value_at(addr.tumbler()).map(Val::as_bytes),
            Some(&b"x"[..]),
            "the slice decoded from {shape} does not hold it"
        );
        let decoded = bincode::deserialize::<ContentWrite>(&record(key))
            .unwrap_or_else(|refusal| panic!("a record at {shape} was refused: {refusal}"));
        assert_eq!(
            decoded.addr(),
            addr.tumbler(),
            "the record decoded from {shape} carries another address"
        );
    }
}

/// Every ordering of `items`, each once: each item first, followed by every
/// ordering of the rest — `n!` vectors for `n` items.
fn every_order<T: Clone>(items: &[T]) -> Vec<Vec<T>> {
    if items.is_empty() {
        return vec![Vec::new()];
    }
    let mut orders = Vec::new();
    for (i, first) in items.iter().enumerate() {
        let mut rest = items.to_vec();
        rest.remove(i);
        for tail in every_order(&rest) {
            let mut order = vec![first.clone()];
            order.extend(tail);
            orders.push(order);
        }
    }
    orders
}

#[test]
fn the_slice_decodes_its_entries_in_whatever_order_they_arrive() {
    // store.rs (`entry_by_entry`) and M4's interface: `Serialize` writes the
    // entries in Tumbler order, and `Deserialize` takes them in any order —
    // the map is rebuilt from whatever arrives, one entry at a time. "Any
    // order" is a law over every arrival order, and one chosen order stands
    // for none of the others: a decode can admit the sorted and the reversed
    // body alike and still refuse one sorted but for its last two entries. So
    // six entries arrive in each of their 720 orders, and each decodes to the
    // slice holding them.
    let mut c = ContentStore::default();
    let mut entries: Vec<(Tumbler, Vec<u8>)> = Vec::new();
    for ordinal in 1..=6u32 {
        let addr = ca(ordinal);
        let bytes = vec![b'0' + ordinal as u8];
        c = c.apply_write(&stage_write(&c, &addr, Val::new(bytes.clone())).expect("fresh"));
        entries.push((addr.tumbler().clone(), bytes));
    }
    let orders = every_order(&entries);
    assert_eq!(
        orders.iter().collect::<std::collections::BTreeSet<_>>().len(),
        720,
        "the generator did not yield each of the 720 orders of six entries once"
    );
    for order in &orders {
        let arrival: Vec<String> =
            order.iter().map(|(addr, _)| skep_address::ordinal(addr).to_string()).collect();
        let back: ContentStore =
            bincode::deserialize(&bincode::serialize(order).expect("entries serialize"))
                .unwrap_or_else(|refusal| {
                    panic!("entries arriving as ordinals {arrival:?} were refused: {refusal}")
                });
        assert_eq!(
            back, c,
            "decoded from entries arriving as ordinals {arrival:?}, the slice is not the one \
             holding them"
        );
    }
}

// ---- M2-driven recovery across a checkpoint ----

#[test]
fn content_survives_durable_recovery_across_a_checkpoint() {
    // §Recovery: M4 owns no recovery machinery — M2's open loads the latest
    // checkpoint (deserializing the slice) and replays the tail by folding
    // ContentWrite records through apply → apply_write: a1 is written before
    // the checkpoint, a2 after it. Which base M2 chose this test cannot see —
    // with the journal still reaching genesis, a checkpoint that failed to
    // load would be skipped for a full replay with the same answer — so the
    // checkpoint form itself is held by the round trip and the pinned bytes.
    let dir = tempdir().expect("tempdir");
    let a1 = ca(1);
    let a2 = ca(2);
    {
        let k = Kernel::<World>::open(cfg_fsync(dir.path()), genesis()).expect("open");
        write(&k, &a1, val(b"alpha")).expect("first write");
        k.checkpoint().expect("checkpoint");
        write(&k, &a2, val(b"beta")).expect("second write");
    }
    let k = Kernel::<World>::open(cfg_fsync(dir.path()), genesis()).expect("reopen");
    let s = k.snapshot();
    let c = s.world().content();
    assert_eq!(c.len(), 2);
    assert_eq!(c.value_at(a1.tumbler()).map(Val::as_bytes), Some(&b"alpha"[..]));
    assert_eq!(c.value_at(a2.tumbler()).map(Val::as_bytes), Some(&b"beta"[..]));
    // The recovered dom(C) still feeds `stage_write`'s already-stored check.
    drop(s);
    assert_eq!(
        rejected(write(&k, &a1, val(b"again"))),
        ContentError::AlreadyStored(a1.tumbler().clone())
    );
}
