//! The journaled record and the checkpointed slice: that both survive a
//! bincode round trip and M2's durable recovery by checkpoint and replay, the
//! reopen starting from the checkpoint; that the slice's serialized form is
//! the format its readers pin; that the slice's decode takes its entries in
//! every order they can arrive, and refuses a body naming one address twice,
//! however its digits spell it and wherever its two namings stand, while
//! admitting every body that names none twice, the empty one included; that
//! neither decode trusts a count its bytes do not carry — the slice's
//! entries, an address's components, a component's digits, a value's bytes —
//! or admits a key that is no tumbler, or no T4-valid address; that both
//! admit every T4-valid address, whatever its routing, since a release build
//! stages each as given; and that a decode holding several faults is refused
//! for the first it reads, within an entry as across entries.

use serde::de::DeserializeOwned;
use skep_address::{content_subspace, validate, Level, Nat, T4Clause, Tumbler};
use skep_content::{stage_write, write, ContentError, ContentStore, ContentWrite, HasContent, Val};
use skep_kernel::{Kernel, Recovery};
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
/// itself at all. `#[track_caller]`, so a decode that did not refuse is
/// reported at the line that expected it to.
#[track_caller]
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
    // an `Err`, by running out of input — at each count the form carries: the
    // slice's entries, an address's components, a component's digits and a
    // value's bytes. Reserving room for the count first breaks that: past
    // `isize::MAX` bytes the reservation panics, and short of it a count the
    // allocator cannot grant aborts the process. A count one past what the
    // bytes hold is the control, refused the ordinary way.
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
    let mut overlong_value = bincode::serialize(ca(1).tumbler()).expect("address serializes");
    overlong_value.extend_from_slice(&u64::MAX.to_le_bytes());
    assert_refused::<ContentWrite>(
        "a record whose value counts more bytes than follow",
        &overlong_value,
    );
    assert_refused::<ContentWrite>(
        "a record whose address counts more components than follow",
        &u64::MAX.to_le_bytes(),
    );
    // One component, which counts more `u32` digits than follow.
    let mut overlong_digits = 1u64.to_le_bytes().to_vec();
    overlong_digits.extend_from_slice(&u64::MAX.to_le_bytes());
    assert_refused::<ContentWrite>(
        "a record whose address's one component counts more digits than follow",
        &overlong_digits,
    );
}

/// `comps` in the shape a tumbler serializes as, its components' `Vec<Nat>`,
/// built without M1's doors — so a test can lay any key where an address
/// belongs, one no door admits (empty, or breaking T4) as readily as one it
/// does.
fn raw_key(comps: &[u32]) -> Vec<Nat> {
    comps.iter().map(|&c| Nat::from(c)).collect()
}

/// A slice body naming each of `keys`, in the order given and repeats kept,
/// with the value `x` at each: a `Vec` of (key, value) pairs, each key in
/// `raw_key`'s shape and each value its byte sequence. That is a slice's own
/// shape — `the_slice_serializes_as_its_map_alone_in_tumbler_order` pins a
/// slice's bytes as exactly a `Vec` of pairs', and the control in
/// `the_record_and_the_slice_refuse_a_key_that_is_no_tumbler` decodes
/// `raw_slice(&[CA1])` to the slice `stage_write` builds at `ca(1)` — so a
/// test can lay down a body no slice serializes as: keys out of order, named
/// twice, or no address at all.
fn raw_slice(keys: &[&[u32]]) -> Vec<u8> {
    let entries: Vec<_> = keys.iter().map(|&key| (raw_key(key), b"x".to_vec())).collect();
    bincode::serialize(&entries).expect("the raw slice serializes")
}

/// The bytes of a record writing the value `x` at `key` — what a journal
/// frame carries, never the frame itself: the address in `raw_key`'s shape,
/// then the value's byte sequence. That is a record's own shape, as the same
/// control holds of `raw_record(CA1)`.
fn raw_record(key: &[u32]) -> Vec<u8> {
    bincode::serialize(&(raw_key(key), b"x".to_vec())).expect("the raw record serializes")
}

/// `ca(1)`'s components, for the raw shapes. The control in
/// `the_record_and_the_slice_refuse_a_key_that_is_no_tumbler` decodes them to
/// the slice and the record `stage_write` builds at `ca(1)`, so the two
/// cannot part unseen.
const CA1: &[u32] = &[1, 0, 1, 0, 1, 0, 1, 1];

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
    // a key, so the bytes are laid through the raw shapes, `raw_slice` and
    // `raw_record`. The same shapes carrying `ca(1)` are the control: they
    // decode to the slice and the record `stage_write` builds there — which
    // is what makes the raw shapes the types' own bytes for every test that
    // lays one down — so the refusal is the empty key's alone.
    let rec = stage_write(&ContentStore::default(), &ca(1), val(b"x")).expect("fresh");
    assert_eq!(
        bincode::deserialize::<ContentStore>(&raw_slice(&[CA1]))
            .expect("the control slice decodes"),
        ContentStore::default().apply_write(&rec)
    );
    assert_eq!(
        bincode::deserialize::<ContentWrite>(&raw_record(CA1)).expect("the control record decodes"),
        rec
    );
    let no_tumbler: &[u32] = &[];
    assert_refused::<ContentStore>(
        "a slice whose one key is an empty sequence",
        &raw_slice(&[no_tumbler]),
    );
    assert_refused::<ContentWrite>(
        "a record whose address is an empty sequence",
        &raw_record(no_tumbler),
    );
}

#[test]
fn the_record_and_the_slice_refuse_a_key_that_is_no_address() {
    // ASN-0093 StoreT4Validity (store.rs, `ContentStore`'s key invariants):
    // every key in `dom(C)` is T4-valid, and both decode paths re-enter M1's
    // `Address` door (`validate`) to keep it so — an `Address` journals as
    // its bare tumbler, so the door reads the bytes the record and the slice
    // already serialize as. Each key below is nonempty, so `Tumbler`'s own
    // door (T0, the test above) admits it, and breaks exactly one T4 clause,
    // so only the `Address` door can refuse it — and the refusal is pinned as
    // that door's own, word for word. What the door admits is the next test's.
    for (clause, key) in [
        (T4Clause::LeadingZero, &[0u32, 1][..]),
        (T4Clause::TrailingZero, &[1, 0][..]),
        (T4Clause::AdjacentZeros, &[1, 0, 0, 1][..]),
        (T4Clause::OverDepth, &[1, 0, 1, 0, 1, 0, 1, 0, 1][..]),
    ] {
        let door_refusal = validate(t(key)).expect_err("each key breaks a T4 clause");
        assert_eq!(door_refusal.clauses(), [clause].as_slice(), "{key:?} breaks {clause} alone");
        let door_refusal = door_refusal.to_string();
        for (form, refusal) in [
            (
                "slice",
                assert_refused::<ContentStore>(
                    &format!("a slice whose one key breaks {clause}"),
                    &raw_slice(&[key]),
                ),
            ),
            (
                "record",
                assert_refused::<ContentWrite>(
                    &format!("a record whose address breaks {clause}"),
                    &raw_record(key),
                ),
            ),
        ] {
            assert_eq!(
                refusal, door_refusal,
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
    // (store.rs's `stage_write_stages_every_mis_routed_address_as_given_in_release`
    // stages each shape in `MIS_ROUTED`). So both decode paths take it on
    // journal and checkpoint integrity: a decode that refused one would leave
    // that build unable to replay its own journal. The decode therefore admits
    // every address T4 admits, whatever its routing — here each shape in
    // `MIS_ROUTED`, each checked first to be T4-valid and no content-subspace
    // element address. The bytes are `raw_slice`'s and `raw_record`'s.
    for &(shape, key) in MIS_ROUTED {
        let addr = validate(t(key)).expect("T4-valid, so a release stage door admits it");
        assert!(
            addr.level() != Level::Element || addr.subspace() != Some(&content_subspace()),
            "{shape} is routed to content, so routing would not stop it"
        );
        let decoded = bincode::deserialize::<ContentStore>(&raw_slice(&[key]))
            .unwrap_or_else(|refusal| panic!("a slice holding {shape} was refused: {refusal}"));
        assert_eq!(
            decoded.value_at(addr.tumbler()).map(Val::as_bytes),
            Some(&b"x"[..]),
            "the slice decoded from {shape} does not hold it"
        );
        let decoded = bincode::deserialize::<ContentWrite>(&raw_record(key))
            .unwrap_or_else(|refusal| panic!("a record at {shape} was refused: {refusal}"));
        assert_eq!(
            decoded.addr(),
            &addr,
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

/// Every sequence of exactly `len` picks from `0..choices`, repeats allowed:
/// each sequence one shorter, followed by each pick — `choices^len` vectors.
fn every_sequence(choices: usize, len: usize) -> Vec<Vec<usize>> {
    if len == 0 {
        return vec![Vec::new()];
    }
    let mut sequences = Vec::new();
    for shorter in every_sequence(choices, len - 1) {
        for pick in 0..choices {
            let mut sequence = shorter.clone();
            sequence.push(pick);
            sequences.push(sequence);
        }
    }
    sequences
}

#[test]
fn the_slice_decodes_its_entries_in_whatever_order_they_arrive() {
    // store.rs (`entry_by_entry`) and M4's interface: `Serialize` emits the
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

#[test]
fn the_slice_refuses_a_body_naming_one_address_twice() {
    // store.rs (`entry_by_entry`): a body names one state, and a state holds
    // one value at an address (S0). No build serializes a body naming an
    // address twice — its encoder walks a map whose keys are unique — and a
    // decode that took one would have to choose which value stands, where the
    // fold keeps the stored one (S0(b)) and `OrdMap::insert` would keep the
    // later. So the body is refused, by the decode's own message, and "one
    // address" is the DECODED address: ca(1) twice as serialized, then ca(1)
    // twice spelled two ways — its ordinal's `u32` digits with and without a
    // trailing zero digit, which num-bigint reads as one number. The bytes
    // are laid as `raw_slice` lays a body, but each key is spelled as the
    // `u32` digits its components serialize as and each value is its own; the
    // same shape naming two addresses is the control, decoding to the slice
    // that holds both values.
    let digits = |key: &Tumbler| -> Vec<Vec<u32>> { key.iter().map(Nat::to_u32_digits).collect() };
    assert_eq!(
        bincode::serialize(&digits(ca(1).tumbler())).expect("the digits serialize"),
        bincode::serialize(ca(1).tumbler()).expect("the address serializes"),
        "a tumbler's bytes are not its components' `u32` digits"
    );
    let body = |first: Vec<Vec<u32>>, second: Vec<Vec<u32>>| {
        bincode::serialize(&vec![(first, b"first".to_vec()), (second, b"second".to_vec())])
            .expect("the raw slice serializes")
    };
    let both: ContentStore =
        bincode::deserialize(&body(digits(ca(1).tumbler()), digits(ca(2).tumbler())))
            .expect("a body naming two addresses decodes");
    assert_eq!(both.value_at(ca(1).tumbler()).map(Val::as_bytes), Some(&b"first"[..]));
    assert_eq!(both.value_at(ca(2).tumbler()).map(Val::as_bytes), Some(&b"second"[..]));
    // ca(1) as serialized, and again with its ordinal `[1]` spelled `[1, 0]`:
    // a trailing zero digit, which num-bigint drops, so that key decodes to
    // ca(1) itself.
    let as_serialized = digits(ca(1).tumbler());
    let mut respelled = as_serialized.clone();
    respelled.last_mut().expect("a tumbler is nonempty").push(0);
    for (how, second) in [("as serialized", as_serialized.clone()), ("spelled two ways", respelled)]
    {
        assert_eq!(
            assert_refused::<ContentStore>(
                &format!("a slice naming ca(1) twice, {how}"),
                &body(as_serialized.clone(), second),
            ),
            "a content address named twice in one slice",
            "a slice naming ca(1) twice, {how}, was refused for another reason"
        );
    }
}

#[test]
fn the_slice_admits_a_body_exactly_when_it_names_no_address_twice() {
    // store.rs (`entry_by_entry`): a body naming one address twice is
    // refused, and every body the decode admits names one state, whatever
    // order its entries take. Both are laws over every body, and the test
    // above names ca(1) twice only side by side — which a check against the
    // entry just before would refuse as well, while admitting ca(1), ca(2),
    // ca(1) with the later value standing. Nor does any other test decode
    // the empty body, the slice a world holds before any content is written.
    // So every body of up to three entries over ca(1), ca(2) and ca(3) is
    // laid down — 40, each entry with a value no other entry carries: one
    // naming an address twice is refused by the decode's own message,
    // wherever its two namings stand; every other, the empty body included,
    // decodes to the slice holding its entries.
    let keys = [ca(1), ca(2), ca(3)];
    let bodies: Vec<Vec<usize>> = (0..=3).flat_map(|len| every_sequence(keys.len(), len)).collect();
    assert_eq!(
        bodies.iter().collect::<std::collections::BTreeSet<_>>().len(),
        1 + 3 + 9 + 27,
        "the generator did not yield each body of up to three entries over three addresses once"
    );
    for body in &bodies {
        let named: Vec<usize> = body.iter().map(|&k| k + 1).collect();
        // Each entry's value is its position in the body, so no two entries
        // carry one value.
        let entries: Vec<(Tumbler, Vec<u8>)> = body
            .iter()
            .enumerate()
            .map(|(at, &k)| (keys[k].tumbler().clone(), vec![b'a' + at as u8]))
            .collect();
        let bytes = bincode::serialize(&entries).expect("the raw slice serializes");
        let names_an_address_twice =
            body.iter().collect::<std::collections::BTreeSet<_>>().len() < body.len();
        if names_an_address_twice {
            assert_eq!(
                assert_refused::<ContentStore>(
                    &format!("a body naming ordinals {named:?}"),
                    &bytes
                ),
                "a content address named twice in one slice",
                "a body naming ordinals {named:?} was refused for another reason"
            );
        } else {
            let mut holding = ContentStore::default();
            for (&k, (_, value)) in body.iter().zip(&entries) {
                let rec = stage_write(&holding, &keys[k], val(value))
                    .expect("fresh: the body names no address twice");
                holding = holding.apply_write(&rec);
            }
            let decoded: ContentStore = bincode::deserialize(&bytes).unwrap_or_else(|refusal| {
                panic!("a body naming ordinals {named:?}, none twice, was refused: {refusal}")
            });
            assert_eq!(
                decoded, holding,
                "a body naming ordinals {named:?}, none twice, decoded to a slice other than the \
                 one holding its entries"
            );
        }
    }
}

#[test]
fn the_record_and_the_slice_refuse_for_the_first_fault_they_read() {
    // store.rs (`entry_by_entry`'s REFUSAL PRECEDENCE, and `ContentWrite`):
    // where several refusals hold of one body, the first fault in reading
    // order speaks, and that is what M2 keeps — a refused base's reason, a
    // refused record's `Corruption` cause. So each body below carries two
    // faults and is refused for the one it reads first: a key breaking T4
    // and a second naming of ca(1), in each order; a second naming of ca(1)
    // whose value counts more bytes than follow, refused for the value,
    // because the key is checked against the entries before it only once its
    // value is read; a key breaking T4 under a count no body could carry,
    // refused for the key, because a count is no fault until the body runs
    // out; and one entry whose key breaks T4 and whose value counts more
    // bytes than follow, refused for the key in the slice as in the record,
    // because within an entry the key is read, and refused at M1's door,
    // before its value is.
    let no_address: &[u32] = &[1, 0, 0, 1];
    let past_its_bytes = u64::MAX.to_le_bytes();
    let door_refusal = validate(t(no_address)).expect_err("the key breaks T4").to_string();
    let named_twice_refusal = "a content address named twice in one slice".to_owned();
    let value_refusal = bincode::deserialize::<Val>(&past_its_bytes)
        .expect_err("a value counting more bytes than follow is refused")
        .to_string();
    // Two entries counted: ca(1) whole, then ca(1) again, its value counting
    // more bytes than follow.
    let mut overlong_value = raw_slice(&[CA1]);
    overlong_value[..8].copy_from_slice(&2u64.to_le_bytes());
    overlong_value.extend(bincode::serialize(&raw_key(CA1)).expect("the raw key serializes"));
    overlong_value.extend_from_slice(&past_its_bytes);
    // ca(1), then a key breaking T4, under a count no body could carry.
    let mut overlong_count = raw_slice(&[CA1, no_address]);
    overlong_count[..8].copy_from_slice(&past_its_bytes);
    // One entry whose key breaks T4 and whose value counts more bytes than
    // follow: a record's bytes, and with a count of one before them, a
    // slice's.
    let mut both_fail = bincode::serialize(&raw_key(no_address)).expect("the raw key serializes");
    both_fail.extend_from_slice(&past_its_bytes);
    let mut one_entry_both_fail = 1u64.to_le_bytes().to_vec();
    one_entry_both_fail.extend_from_slice(&both_fail);
    for (what, body, speaks) in [
        (
            "a key breaking T4 before a second naming of ca(1)",
            raw_slice(&[CA1, no_address, CA1]),
            &door_refusal,
        ),
        (
            "a second naming of ca(1) before a key breaking T4",
            raw_slice(&[CA1, CA1, no_address]),
            &named_twice_refusal,
        ),
        (
            "a second naming of ca(1) whose value counts more bytes than follow",
            overlong_value,
            &value_refusal,
        ),
        ("a key breaking T4 under a count no body could carry", overlong_count, &door_refusal),
        (
            "one entry whose key breaks T4 and whose value counts more bytes than follow",
            one_entry_both_fail,
            &door_refusal,
        ),
    ] {
        assert_eq!(
            &assert_refused::<ContentStore>(&format!("a slice with {what}"), &body),
            speaks,
            "a slice with {what} was refused for a fault it reads later"
        );
    }
    assert_eq!(
        assert_refused::<ContentWrite>("a record whose address and value both fail", &both_fail),
        door_refusal,
        "a record whose address and value both fail was refused for its value"
    );
}

// ---- M2-driven recovery by checkpoint and replay ----

#[test]
fn content_survives_durable_recovery_by_checkpoint_and_replay() {
    // §Recovery: M4 owns no recovery machinery — M2's open loads the latest
    // checkpoint (deserializing the slice) and replays the tail by folding
    // ContentWrite records through apply → apply_write: a1 is written before
    // the checkpoint, a2 after it. The contents alone cannot say which base
    // M2 chose — with the journal still reaching genesis, a checkpoint passed
    // over would leave a full replay with the same answer — so the test asks
    // M2's own report (`Kernel::recovery`): the reopen started from that
    // checkpoint and passed nothing over, so the slice came back through M2's
    // codec and load, and not only through the round trip above.
    let dir = tempdir().expect("tempdir");
    let a1 = ca(1);
    let a2 = ca(2);
    let checkpointed_at = {
        let k = Kernel::<World>::open(cfg_fsync(dir.path()), genesis()).expect("open");
        write(&k, &a1, val(b"alpha")).expect("first write");
        let at = k.checkpoint().expect("checkpoint");
        write(&k, &a2, val(b"beta")).expect("second write");
        at
    };
    let k = Kernel::<World>::open(cfg_fsync(dir.path()), genesis()).expect("reopen");
    assert_eq!(
        k.recovery(),
        Some(&Recovery { start_point: checkpointed_at, skipped: vec![], replayed: 1, tail_cut: 0 }),
        "the reopen did not start from the checkpoint taken after a1, passing nothing over and \
         replaying the one write above it — where M2 passed a base over, its `skipped` entry \
         says why"
    );
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
