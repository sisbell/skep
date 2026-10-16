//! The journaled records and the checkpointed slice: that both records and
//! the slice survive a bincode round trip and M2's durable recovery by
//! checkpoint and replay, the reopen starting from the checkpoint; that the
//! slice's serialized form is the format its readers pin, each entry a key
//! and a tagged value or stretch; that the slice's decode takes its entries in
//! every order they can arrive, and refuses a body naming one address twice,
//! however its digits spell it and wherever its two namings stand, a body
//! holding a key inside a stretch's reach or a stretch of no bytes, while
//! admitting every body that names none twice, the empty one included; that
//! no decode trusts a count its bytes do not carry — the slice's entries, an
//! address's components, a component's digits, a value's or a stretch's bytes
//! — or admits a key that is no tumbler, or no T4-valid address; that both
//! admit every T4-valid address, whatever its routing, since a release build
//! stages each as given, and lend each as it was decoded; that a decode
//! holding several faults is refused for the first it reads, within an entry
//! as across entries; and that the slice's OLD form — a bare value per entry
//! — fails to decode under the current form on a one-byte entry and on an
//! atom, and decodes to the empty map where it holds no entry.

use serde::de::DeserializeOwned;
use serde::Serialize;
use skep_address::{content_subspace, validate, Level, Nat, T4Clause, Tumbler};
use skep_content::{
    stage_stretch, stage_write, write, write_stretch, ContentError, ContentStore, ContentStretch,
    ContentWrite, HasContent, Val,
};
use skep_kernel::{Kernel, Recovery};
use tempfile::tempdir;

use crate::common::*;

/// A slice entry's value in the form the slice serializes it — the crate's
/// private `Stored` twin: a `u32` tag, `Value = 0` and `Stretch = 1`, then
/// the bytes as their length and themselves. Built without the crate's doors,
/// so a test can lay any entry where one belongs.
#[derive(Clone, Serialize)]
enum RawStored {
    Value(Vec<u8>),
    Stretch(Vec<u8>),
}

// ---- serde: the journaled records and the checkpointed slice ----

#[test]
fn the_records_and_the_slice_survive_a_bincode_round_trip() {
    // §A/§Recovery: ContentWrite and ContentStretch are the deltas M2
    // journals; the slice is fully serialized in checkpoints. bincode is M2's
    // actual wire format.
    let a1 = ca(1);
    let a2 = ca(2);
    let rec = stage_write(&ContentStore::default(), a1.clone(), val(b"payload")).expect("fresh");
    let bytes_of = bincode::serialize(&rec).expect("record serializes");
    let back: ContentWrite = bincode::deserialize(&bytes_of).expect("record deserializes");
    assert_eq!(back, rec);
    // The replayed record folds to the same store effect (replay re-applies,
    // no re-derivation).
    let c = ContentStore::default().apply_write(&back);
    assert_eq!(read(&c, a1.tumbler()), Some(b"payload".to_vec()));

    // The stretch record the same way: the first address, then the bytes.
    let stretch = stage_stretch(&c, a2.clone(), bytes(b"more")).expect("fresh");
    let bytes_of = bincode::serialize(&stretch).expect("record serializes");
    assert_eq!(
        bytes_of,
        bincode::serialize(&(a2.tumbler(), b"more".to_vec())).expect("pair serializes"),
        "a stretch serializes as its first address, then its bytes"
    );
    let back: ContentStretch = bincode::deserialize(&bytes_of).expect("record deserializes");
    assert_eq!(back, stretch);
    let c = c.apply_stretch(&back);
    for (ordinal, byte) in (2..).zip(b"more") {
        assert_eq!(read(&c, ca(ordinal).tumbler()), Some(vec![*byte]));
    }

    // The slice round-trips whole (checkpoint form; rebuild_derived identity).
    let bytes_of = bincode::serialize(&c).expect("slice serializes");
    let back: ContentStore = bincode::deserialize(&bytes_of).expect("slice deserializes");
    assert_eq!(back, c, "the slice round-trips whole");
    assert_eq!(back.len(), 2, "two entries: a value and a stretch");
    assert_eq!(read(&back, a1.tumbler()), Some(b"payload".to_vec()));
    assert_eq!(read(&back, ca(5).tumbler()), Some(b"e".to_vec()));
}

#[test]
fn the_slice_serializes_as_its_map_alone_in_tumbler_order() {
    // The form is a format (store.rs, `in_tumbler_order`): M2's checkpoint
    // hashes these bytes, the engine's World lays them down as one slice of
    // its layout, and the engine's world dump renders them. So they are
    // pinned whole — the slice's one field, its map, as its length then its
    // entries (exactly a `Vec` of pairs' bytes), the entries in Tumbler
    // order, each entry its key then a `u32` tag — `Value = 0`, `Stretch = 1`
    // — then its bytes as their length and the raw bytes (bincode's form for
    // a sequence of `u8`, which `Val`, a stretch and `Vec<u8>` all serialize
    // as). Sixty-four entries over four documents, written out of order, so
    // the order of writing is not Tumbler order by accident — every fourth a
    // stretch — and five more below, where Tumbler order parts from other
    // orders.
    let mut c = ContentStore::default();
    let mut entries: Vec<(Tumbler, RawStored)> = Vec::new();
    for k in 0..64u32 {
        // 37 is coprime to 64: every (document, ordinal) once, out of order.
        let i = k * 37 % 64;
        let (doc, ordinal) = (1 + i / 16, 1 + i % 16);
        // Ordinals 1, 5, 9 and 13 of each document are stretches of one byte;
        // a longer one would reach over the next ordinal's entry.
        let addr = a(&[1, 0, 1, 0, doc, 0, 1, ordinal]);
        let payload = format!("{doc}.{ordinal}").into_bytes();
        if ordinal % 4 == 1 {
            let b = vec![payload[0]];
            c = c.apply_stretch(&stage_stretch(&c, addr.clone(), bytes(&b)).expect("fresh"));
            entries.push((addr.tumbler().clone(), RawStored::Stretch(b)));
        } else {
            c = c.apply_write(&stage_write(&c, addr.clone(), Val::new(payload.clone())).expect("fresh"));
            entries.push((addr.tumbler().clone(), RawStored::Value(payload)));
        }
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
        let payload = addr.tumbler().to_string().into_bytes();
        c = c.apply_write(&stage_write(&c, addr.clone(), Val::new(payload.clone())).expect("fresh"));
        entries.push((addr.tumbler().clone(), RawStored::Value(payload)));
    }
    entries.sort_by(|x, y| x.0.cmp(&y.0));
    assert!(
        bincode::serialize(&c).expect("slice serializes")
            == bincode::serialize(&entries).expect("entries serialize"),
        "M4's slice serialized as something other than its map alone, entries in Tumbler \
         order, each a key and a tagged value or stretch: those bytes are M2's hashed checkpoint \
         body, a slice of the engine's World layout and the engine's world dump — a change to \
         them owes the engine's WORLD_FORMAT bump (or the owner's no-stamp ruling) and a \
         dump-filter disposition"
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
fn the_records_and_the_slice_refuse_a_count_their_bytes_do_not_carry() {
    // M2's hostile-input obligation (store.rs, `in_tumbler_order`): a
    // checkpoint body and a journal frame are bytes M2 does not trust, and
    // M2 answers one that will not decode by refusing it — a checkpoint is
    // skipped for an older base, a record is `Corruption`. So a
    // declared count the bytes do not carry (a writer/reader skew reading
    // another slice's bytes as this length, or a crafted file) must decode as
    // an `Err`, by running out of input — at each count the form carries: the
    // slice's entries, an address's components, a component's digits, a
    // value's bytes and a stretch's bytes. Reserving room for the count first
    // breaks that: past `isize::MAX` bytes the reservation panics, and short
    // of it a count the allocator cannot grant aborts the process. A count
    // one past what the bytes hold is the control, refused the ordinary way.
    let held = ContentStore::default()
        .apply_write(&stage_write(&ContentStore::default(), ca(1), val(b"held")).expect("fresh"));
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
    assert_refused::<ContentStretch>(
        "a stretch whose bytes count more than follow",
        &overlong_value,
    );
    // A slice entry whose stretch counts more bytes than follow: the count,
    // the key, the `Stretch` tag, then the overlong length.
    let mut overlong_stretch = 1u64.to_le_bytes().to_vec();
    overlong_stretch.extend(bincode::serialize(ca(1).tumbler()).expect("address serializes"));
    overlong_stretch.extend_from_slice(&1u32.to_le_bytes());
    overlong_stretch.extend_from_slice(&u64::MAX.to_le_bytes());
    assert_refused::<ContentStore>(
        "a slice whose one stretch counts more bytes than follow",
        &overlong_stretch,
    );
    for what in ["a record", "a stretch"] {
        let refused = |bytes: &[u8], msg: &str| {
            if what == "a record" {
                assert_refused::<ContentWrite>(msg, bytes)
            } else {
                assert_refused::<ContentStretch>(msg, bytes)
            }
        };
        refused(
            &u64::MAX.to_le_bytes(),
            &format!("{what} whose address counts more components than follow"),
        );
        // One component, which counts more `u32` digits than follow.
        let mut overlong_digits = 1u64.to_le_bytes().to_vec();
        overlong_digits.extend_from_slice(&u64::MAX.to_le_bytes());
        refused(
            &overlong_digits,
            &format!("{what} whose address's one component counts more digits than follow"),
        );
    }
}

/// `comps` in the form a tumbler serializes as, its components' `Vec<Nat>`,
/// built without M1's doors — so a test can lay any key where an address
/// belongs, one no door admits (empty, or breaking T4) as readily as one it
/// does.
fn raw_key(comps: &[u32]) -> Vec<Nat> {
    comps.iter().map(|&c| Nat::from(c)).collect()
}

/// A slice body naming each of `keys`, in the order given and repeats kept,
/// with the value `x` at each: a `Vec` of (key, entry) pairs, each key in
/// `raw_key`'s form and each entry the `Value` tag then its byte sequence.
/// That is a slice's own form — `the_slice_serializes_as_its_map_alone_in_tumbler_order`
/// pins a slice's bytes as exactly a `Vec` of such pairs', and the control in
/// `the_records_and_the_slice_refuse_a_key_that_is_no_tumbler` decodes
/// `raw_slice(&[CA1])` to the slice `stage_write` builds at `ca(1)` — so a
/// test can lay down a body no slice serializes as: keys out of order, named
/// twice, or no address at all.
fn raw_slice(keys: &[&[u32]]) -> Vec<u8> {
    let entries: Vec<_> =
        keys.iter().map(|&key| (raw_key(key), RawStored::Value(b"x".to_vec()))).collect();
    bincode::serialize(&entries).expect("the raw slice serializes")
}

/// A slice body of `entries` as given — each a key in `raw_key`'s form and a
/// `RawStored` — for the bodies that hold a stretch.
fn raw_slice_of(entries: &[(&[u32], RawStored)]) -> Vec<u8> {
    let entries: Vec<_> =
        entries.iter().map(|(key, stored)| (raw_key(key), stored.clone())).collect();
    bincode::serialize(&entries).expect("the raw slice serializes")
}

/// The bytes of a record writing the value `x` at `key` — what a journal
/// frame carries, never the frame itself: the address in `raw_key`'s form,
/// then the value's byte sequence. That is a record's own form, as the same
/// control holds of `raw_record(CA1)`.
fn raw_record(key: &[u32]) -> Vec<u8> {
    bincode::serialize(&(raw_key(key), b"x".to_vec())).expect("the raw record serializes")
}

/// The bytes of a stretch record writing `bytes` at `key` — the address in
/// `raw_key`'s form, then the bytes as their sequence: a `ContentStretch`'s
/// own form, the twin of `raw_record`, which the same control holds of.
fn raw_stretch(key: &[u32], bytes: &[u8]) -> Vec<u8> {
    bincode::serialize(&(raw_key(key), bytes.to_vec())).expect("the raw stretch serializes")
}

/// `ca(1)`'s components, for the raw forms. The control in
/// `the_records_and_the_slice_refuse_a_key_that_is_no_tumbler` decodes them to
/// the slice and the records `stage_write` and `stage_stretch` build at
/// `ca(1)`, so the forms cannot part unseen.
const CA1: &[u32] = &[1, 0, 1, 0, 1, 0, 1, 1];

#[test]
fn the_records_and_the_slice_refuse_a_key_that_is_no_tumbler() {
    // M2's hostile-input obligation, at the key: the slice's decode
    // (`entry_by_entry`) and the records' decodes take each address as an
    // `Address`, whose `Deserialize` first re-enters `Tumbler`'s door
    // (`try_from` → `Tumbler::new`), and that refuses the empty component
    // sequence — no tumbler at all (T0). So a checkpoint body or a journal
    // frame laying an empty sequence where an address belongs is REFUSED,
    // never stored: M1's reads stand on T0 (`ordinal` takes the last
    // component with an `expect` that names it), and a key in `dom(C)`
    // reaches every reader of the recovered store. No constructor builds such
    // a key, so the bytes are laid through the raw forms, `raw_slice`,
    // `raw_record` and `raw_stretch`. The same forms carrying `ca(1)` are the
    // control: they decode to the slice and the records the stage doors build
    // there — which is what makes the raw forms the types' own bytes for every
    // test that lays one down — so the refusal is the empty key's alone.
    let rec = stage_write(&ContentStore::default(), ca(1), val(b"x")).expect("fresh");
    assert_eq!(
        bincode::deserialize::<ContentStore>(&raw_slice(&[CA1]))
            .expect("the control slice decodes"),
        ContentStore::default().apply_write(&rec)
    );
    assert_eq!(
        bincode::deserialize::<ContentWrite>(&raw_record(CA1)).expect("the control record decodes"),
        rec
    );
    let stretch = stage_stretch(&ContentStore::default(), ca(1), bytes(b"xy")).expect("fresh");
    assert_eq!(
        bincode::deserialize::<ContentStretch>(&raw_stretch(CA1, b"xy"))
            .expect("the control stretch decodes"),
        stretch
    );
    assert_eq!(
        bincode::deserialize::<ContentStore>(&raw_slice_of(&[(CA1, RawStored::Stretch(b"xy".to_vec()))]))
            .expect("the control slice with a stretch decodes"),
        ContentStore::default().apply_stretch(&stretch)
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
    assert_refused::<ContentStretch>(
        "a stretch whose first address is an empty sequence",
        &raw_stretch(no_tumbler, b"x"),
    );
}

#[test]
fn the_records_and_the_slice_refuse_a_key_that_is_no_address() {
    // ASN-0093 StoreT4Validity (store.rs, `ContentStore`'s first key invariant):
    // every key in `dom(C)` is T4-valid, and every decode path re-enters M1's
    // `Address` door (`validate`) to keep it so — an `Address` journals as
    // its bare tumbler, so the door reads the bytes the records and the slice
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
            (
                "stretch",
                assert_refused::<ContentStretch>(
                    &format!("a stretch whose first address breaks {clause}"),
                    &raw_stretch(key, b"x"),
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
fn the_records_and_the_slice_admit_every_address_a_release_build_can_stage() {
    // store.rs, `ContentStore`'s second key invariant: a content-subspace
    // element address — ASN-0093 C1, the element LEVEL, and L0, the content
    // SUBSPACE — is the stage doors' caller to guarantee, checked in debug
    // builds only; a release build stages a violator of either half as given
    // (store.rs's `stage_write_stages_every_mis_routed_address_as_given_in_release`
    // stages each shape in `MIS_ROUTED` through both doors). So every decode
    // path takes it on journal and checkpoint integrity: a decode that refused
    // one would leave that build unable to replay its own journal. The decode
    // therefore admits every address T4 admits, whatever its routing, and the
    // walk and the records lend each as it was decoded, so no reader of M4's
    // keys may assume the invariant either — here each shape in `MIS_ROUTED`,
    // each checked first to be T4-valid and no content-subspace element
    // address. The bytes are `raw_slice`'s, `raw_record`'s and `raw_stretch`'s.
    for &(shape, key) in MIS_ROUTED {
        let addr = validate(t(key)).expect("T4-valid, so a release stage door admits it");
        assert!(
            addr.level() != Level::Element || addr.subspace() != Some(&content_subspace()),
            "{shape} is routed to content, so routing would not stop it"
        );
        let decoded = bincode::deserialize::<ContentStore>(&raw_slice(&[key]))
            .unwrap_or_else(|refusal| panic!("a slice holding {shape} was refused: {refusal}"));
        assert_eq!(
            read(&decoded, addr.tumbler()),
            Some(b"x".to_vec()),
            "the slice decoded from {shape} does not hold it"
        );
        assert!(
            decoded.iter().map(|(at, _)| at).eq([&addr]),
            "the walk does not lend {shape} as it was decoded"
        );
        let decoded = bincode::deserialize::<ContentWrite>(&raw_record(key))
            .unwrap_or_else(|refusal| panic!("a record at {shape} was refused: {refusal}"));
        assert_eq!(
            decoded.addr(),
            &addr,
            "the record decoded from {shape} carries another address"
        );
        let decoded = bincode::deserialize::<ContentStretch>(&raw_stretch(key, b"xy"))
            .unwrap_or_else(|refusal| panic!("a stretch at {shape} was refused: {refusal}"));
        assert_eq!(
            decoded.addr(),
            &addr,
            "the stretch decoded from {shape} carries another address"
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
    // the map is rebuilt from whatever arrives, one entry at a time, and the
    // ordered pass that checks stretches against their neighbours runs over
    // the finished map, so its verdict is the same whatever the arrival
    // order. "Any order" is a law over every arrival order, and one chosen
    // order stands for none of the others: a decode can admit the sorted and
    // the reversed body alike and still refuse one sorted but for its last two
    // entries. So six entries — four values and two stretches, one of two
    // bytes — arrive in each of their 720 orders, and each decodes to the
    // slice holding them.
    let mut c = ContentStore::default();
    let mut entries: Vec<(Tumbler, RawStored)> = Vec::new();
    for ordinal in [1u32, 2, 3, 5, 6, 7] {
        let addr = ca(ordinal);
        let payload = vec![b'0' + ordinal as u8];
        if ordinal == 3 {
            // A stretch of two bytes at 3..=4, then the value at 5.
            let b = b"34".to_vec();
            c = c.apply_stretch(&stage_stretch(&c, addr.clone(), bytes(&b)).expect("fresh"));
            entries.push((addr.tumbler().clone(), RawStored::Stretch(b)));
        } else if ordinal == 6 {
            c = c.apply_stretch(&stage_stretch(&c, addr.clone(), bytes(&payload)).expect("fresh"));
            entries.push((addr.tumbler().clone(), RawStored::Stretch(payload)));
        } else {
            c = c.apply_write(&stage_write(&c, addr.clone(), Val::new(payload.clone())).expect("fresh"));
            entries.push((addr.tumbler().clone(), RawStored::Value(payload)));
        }
    }
    let orders = every_order(&entries);
    assert_eq!(orders.len(), 720, "the generator did not yield each of the 720 orders");
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
    // same form naming two addresses is the control, decoding to the slice
    // that holds both values.
    let digits = |key: &Tumbler| -> Vec<Vec<u32>> { key.iter().map(Nat::to_u32_digits).collect() };
    assert_eq!(
        bincode::serialize(&digits(ca(1).tumbler())).expect("the digits serialize"),
        bincode::serialize(ca(1).tumbler()).expect("the address serializes"),
        "a tumbler's bytes are not its components' `u32` digits"
    );
    let body = |first: Vec<Vec<u32>>, second: Vec<Vec<u32>>| {
        bincode::serialize(&vec![
            (first, RawStored::Value(b"first".to_vec())),
            (second, RawStored::Value(b"second".to_vec())),
        ])
        .expect("the raw slice serializes")
    };
    let both: ContentStore =
        bincode::deserialize(&body(digits(ca(1).tumbler()), digits(ca(2).tumbler())))
            .expect("a body naming two addresses decodes");
    assert_eq!(read(&both, ca(1).tumbler()), Some(b"first".to_vec()));
    assert_eq!(read(&both, ca(2).tumbler()), Some(b"second".to_vec()));
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
fn the_slice_refuses_a_body_holding_a_key_inside_a_stretch_or_a_stretch_of_no_bytes() {
    // store.rs (`entry_by_entry`'s ordered pass): after the entries are
    // inserted, every consecutive pair by tumbler order is checked — where an
    // entry is a stretch of N bytes the next key must be at or past its reach
    // — so a body in which any key lies inside a stretch's reach, whatever
    // the key's chain or length, or in which two stretches overlap, is
    // refused "a content stretch overlapping its neighbour", and a stretch of
    // zero bytes is refused wherever it stands. The pass runs over the
    // finished map, so the verdict is the same whichever order the two
    // entries arrive in; and a key AT the reach, the first address the
    // stretch does not hold, is admitted.
    let ca3 = &[1u32, 0, 1, 0, 1, 0, 1, 3][..];
    let ca4 = &[1u32, 0, 1, 0, 1, 0, 1, 4][..];
    let ca5 = &[1u32, 0, 1, 0, 1, 0, 1, 5][..];
    let ca6 = &[1u32, 0, 1, 0, 1, 0, 1, 6][..];
    let interloper = &[1u32, 0, 1, 0, 1, 0, 1, 3, 7][..];
    let stretch = |b: &[u8]| RawStored::Stretch(b.to_vec());
    let value = |b: &[u8]| RawStored::Value(b.to_vec());
    let overlap = "a content stretch overlapping its neighbour in one slice";
    for (what, entries) in [
        ("a value inside a stretch's reach", vec![(ca3, stretch(b"abc")), (ca4, value(b"x"))]),
        ("the same, arriving first", vec![(ca4, value(b"x")), (ca3, stretch(b"abc"))]),
        ("a stretch inside a stretch's reach", vec![(ca3, stretch(b"abc")), (ca5, stretch(b"yz"))]),
        ("the interloper key beneath a stretch", vec![(ca3, stretch(b"abc")), (interloper, value(b"i"))]),
        ("the interloper arriving first", vec![(interloper, value(b"i")), (ca3, stretch(b"abc"))]),
    ] {
        assert_eq!(
            assert_refused::<ContentStore>(&format!("a slice with {what}"), &raw_slice_of(&entries)),
            overlap,
            "a slice with {what} was refused for another reason"
        );
    }
    for (what, entries) in [
        ("a stretch of no bytes alone", vec![(ca3, stretch(b""))]),
        ("a stretch of no bytes before a value", vec![(ca3, stretch(b"")), (ca4, value(b"x"))]),
        ("a stretch of no bytes last", vec![(ca3, value(b"x")), (ca4, stretch(b""))]),
    ] {
        assert_eq!(
            assert_refused::<ContentStore>(&format!("a slice with {what}"), &raw_slice_of(&entries)),
            "a content stretch of zero bytes in one slice",
            "a slice with {what} was refused for another reason"
        );
    }
    // The control: a key at the reach, and the interloper under a VALUE (a
    // value's reach is itself alone), both decode.
    let admitted: ContentStore = bincode::deserialize(&raw_slice_of(&[
        (ca3, stretch(b"abc")),
        (ca6, value(b"x")),
    ]))
    .expect("a key at the reach is admitted");
    assert_eq!(admitted.len(), 2);
    let admitted: ContentStore = bincode::deserialize(&raw_slice_of(&[
        (ca3, value(b"v")),
        (interloper, value(b"i")),
    ]))
    .expect("a longer key under a value is admitted");
    assert_eq!(admitted.len(), 2);
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
        let entries: Vec<(Tumbler, RawStored)> = body
            .iter()
            .enumerate()
            .map(|(at, &k)| (keys[k].tumbler().clone(), RawStored::Value(vec![b'a' + at as u8])))
            .collect();
        let bytes_of = bincode::serialize(&entries).expect("the raw slice serializes");
        let names_an_address_twice =
            body.iter().collect::<std::collections::BTreeSet<_>>().len() < body.len();
        if names_an_address_twice {
            assert_eq!(
                assert_refused::<ContentStore>(
                    &format!("a body naming ordinals {named:?}"),
                    &bytes_of
                ),
                "a content address named twice in one slice",
                "a body naming ordinals {named:?} was refused for another reason"
            );
        } else {
            let mut holding = ContentStore::default();
            for (&k, (_, stored)) in body.iter().zip(&entries) {
                let RawStored::Value(value) = stored else { unreachable!("values only") };
                let rec = stage_write(&holding, keys[k].clone(), val(value))
                    .expect("fresh: the body names no address twice");
                holding = holding.apply_write(&rec);
            }
            let decoded: ContentStore = bincode::deserialize(&bytes_of).unwrap_or_else(|refusal| {
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
fn the_records_and_the_slice_refuse_for_the_first_fault_they_read() {
    // store.rs (`entry_by_entry`'s REFUSAL PRECEDENCE, and the two records):
    // where several refusals hold of one body, the first fault in reading
    // order speaks, and that is what M2 keeps — a refused base's reason, a
    // refused record's `Corruption` cause. So each body below carries two
    // faults and is refused for the one it reads first: a key breaking T4
    // and a second naming of ca(1), in each order; a second naming of ca(1)
    // whose value counts more bytes than follow, refused for the value,
    // because the key is checked against the entries before it only once its
    // value is read; a key breaking T4 under a count no body could carry,
    // refused for the key, because a count is no fault until the body runs
    // out; one entry whose key breaks T4 and whose value counts more bytes
    // than follow, refused for the key in the slice as in the record, because
    // within an entry the key is read, and refused at M1's door, before its
    // value is; and a stretch overlapping its neighbour beside a second
    // naming, refused for the naming, because the ordered pass runs last.
    let no_address: &[u32] = &[1, 0, 0, 1];
    let past_its_bytes = u64::MAX.to_le_bytes();
    let door_refusal = validate(t(no_address)).expect_err("the key breaks T4").to_string();
    let named_twice_refusal = "a content address named twice in one slice".to_owned();
    let value_refusal = bincode::deserialize::<Val>(&past_its_bytes)
        .expect_err("a value counting more bytes than follow is refused")
        .to_string();
    // A `Value` entry whose bytes count more than follow: the tag, then the
    // overlong length.
    let mut past_its_value = 0u32.to_le_bytes().to_vec();
    past_its_value.extend_from_slice(&past_its_bytes);
    // Two entries counted: ca(1) whole, then ca(1) again, its value counting
    // more bytes than follow.
    let mut overlong_value = raw_slice(&[CA1]);
    overlong_value[..8].copy_from_slice(&2u64.to_le_bytes());
    overlong_value.extend(bincode::serialize(&raw_key(CA1)).expect("the raw key serializes"));
    overlong_value.extend_from_slice(&past_its_value);
    // ca(1), then a key breaking T4, under a count no body could carry.
    let mut overlong_count = raw_slice(&[CA1, no_address]);
    overlong_count[..8].copy_from_slice(&past_its_bytes);
    // One entry whose key breaks T4 and whose value counts more bytes than
    // follow: a record's bytes, and with a count of one before them, a
    // slice's.
    let mut both_fail = bincode::serialize(&raw_key(no_address)).expect("the raw key serializes");
    both_fail.extend_from_slice(&past_its_bytes);
    let mut one_entry_both_fail = 1u64.to_le_bytes().to_vec();
    one_entry_both_fail.extend(bincode::serialize(&raw_key(no_address)).expect("the raw key serializes"));
    one_entry_both_fail.extend_from_slice(&past_its_value);
    // A stretch at ca(1) over ca(2), and ca(2) named twice.
    let ca2 = &[1u32, 0, 1, 0, 1, 0, 1, 2][..];
    let overlap_and_twice = raw_slice_of(&[
        (CA1, RawStored::Stretch(b"ab".to_vec())),
        (ca2, RawStored::Value(b"x".to_vec())),
        (ca2, RawStored::Value(b"y".to_vec())),
    ]);
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
        (
            "a stretch overlapping its neighbour beside a second naming",
            overlap_and_twice,
            &named_twice_refusal,
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
    assert_eq!(
        assert_refused::<ContentStretch>("a stretch whose address and bytes both fail", &both_fail),
        door_refusal,
        "a stretch whose address and bytes both fail was refused for its bytes"
    );
}

#[test]
fn the_old_form_slice_fails_to_decode_on_a_value_and_decodes_empty_where_it_holds_none() {
    // The OLD form of the slice — each entry a key and a BARE value, no tag —
    // under the current decoder: a one-byte value's length prefix, `01 00 00
    // 00`, reads as the `Stretch` tag, and the stretch's length is then taken
    // from the next eight bytes — the rest of the old length prefix, the byte
    // itself and whatever follows — at least `2³²` times a nonzero byte, past
    // any body; a multi-byte atom's length reads as a tag naming no variant.
    // Either way the body is refused, never misread into a slice — a
    // checkpoint written before the stretch is a skipped base, and its board
    // opens from genesis where its journal still reaches it. An empty old-form
    // map is the same eight zero bytes under both forms, and decodes to the
    // empty slice. The old form is pinned first against the current one, so
    // the hand-built bytes are the old ones and not a strawman.
    let old_form = |entries: &[(&[u32], &[u8])]| -> Vec<u8> {
        let entries: Vec<(Vec<Nat>, Vec<u8>)> =
            entries.iter().map(|(key, b)| (raw_key(key), b.to_vec())).collect();
        bincode::serialize(&entries).expect("the old-form slice serializes")
    };
    let current = raw_slice(&[CA1]);
    let old = old_form(&[(CA1, b"x")]);
    assert_eq!(
        current.len(),
        old.len() + 4,
        "the current form adds the four-byte tag to each entry and nothing else"
    );
    assert_eq!(&current[..8 + 92], &old[..8 + 92], "the count and the key are as they were");
    assert_refused::<ContentStore>("an old-form slice holding a one-byte value", &old);
    assert_refused::<ContentStore>(
        "an old-form slice holding a multi-byte atom",
        &old_form(&[(CA1, b"atom")]),
    );
    assert_refused::<ContentStore>(
        "an old-form slice holding a value and an atom",
        &old_form(&[(CA1, b"x"), (&[1, 0, 1, 0, 1, 0, 1, 2], b"atom")]),
    );
    let empty: ContentStore =
        bincode::deserialize(&old_form(&[])).expect("an empty old-form map decodes");
    assert!(empty.is_empty(), "the empty map under both forms is eight zero bytes");
    assert_eq!(old_form(&[]), bincode::serialize(&ContentStore::default()).expect("serializes"));
}

// ---- M2-driven recovery by checkpoint and replay ----

#[test]
fn content_survives_durable_recovery_by_checkpoint_and_replay() {
    // §Recovery: M4 owns no recovery machinery — M2's open loads the latest
    // checkpoint (deserializing the slice) and replays the tail by folding
    // ContentWrite and ContentStretch records through apply → apply_write and
    // apply_stretch: a value and a stretch are written before the checkpoint,
    // a value and a stretch after it. The contents alone cannot say which
    // base M2 chose — with the journal still reaching genesis, a checkpoint
    // passed over would leave a full replay with the same answer — so the
    // test asks M2's own report (`Kernel::recovery`): the reopen started from
    // that checkpoint and passed nothing over, so the slice came back through
    // M2's codec and load, and not only through the round trip above.
    let dir = tempdir().expect("tempdir");
    let a1 = ca(1);
    let s1 = ca(2); // a stretch at 2..=4
    let a2 = ca(5);
    let s2 = ca(6); // a stretch at 6..=7
    let checkpointed_at = {
        let k = Kernel::<World>::open(cfg_fsync(dir.path()), genesis()).expect("open");
        write(&k, &a1, val(b"alpha")).expect("first write");
        write_stretch(&k, &s1, bytes(b"xyz")).expect("first stretch");
        let at = k.checkpoint().expect("checkpoint");
        write(&k, &a2, val(b"beta")).expect("second write");
        write_stretch(&k, &s2, bytes(b"pq")).expect("second stretch");
        at
    };
    let k = Kernel::<World>::open(cfg_fsync(dir.path()), genesis()).expect("reopen");
    assert_eq!(
        k.recovery(),
        Some(&Recovery {
            start_point: checkpointed_at,
            skipped: vec![],
            replayed: 2,
            tail_cut: 0,
            tail_cut_intact: 0,
            tail_cut_from: None,
            tail_cut_claimed: None,
            began: false,
            runs_passed_over: 0,
            first_run_passed_over: None,
        }),
        "the reopen did not start from the checkpoint taken after the first two writes, passing \
         nothing over and replaying the two above it — where M2 passed a base over, its `skipped` \
         entry says why"
    );
    let s = k.snapshot();
    let c = s.world().content();
    assert_eq!(c.len(), 4, "two values and two stretches");
    assert_eq!(read(c, a1.tumbler()), Some(b"alpha".to_vec()));
    for (ordinal, byte) in (2..).zip(b"xyz") {
        assert_eq!(read_arm(c, ca(ordinal).tumbler()), Some((true, vec![*byte])));
    }
    assert_eq!(read(c, a2.tumbler()), Some(b"beta".to_vec()));
    for (ordinal, byte) in (6..).zip(b"pq") {
        assert_eq!(read_arm(c, ca(ordinal).tumbler()), Some((true, vec![*byte])));
    }
    // The recovered dom(C) still feeds both doors' already-stored checks: a
    // value's key, and an address inside a recovered stretch.
    drop(s);
    assert_eq!(
        rejected(write(&k, &a1, val(b"again"))),
        ContentError::AlreadyStored(a1.tumbler().clone())
    );
    assert_eq!(
        rejected(write(&k, &ca(3), val(b"inside"))),
        ContentError::AlreadyStored(ca(3).tumbler().clone())
    );
    assert_eq!(
        rejected(write_stretch(&k, &ca(4), bytes(b"over"))),
        ContentError::AlreadyStored(ca(4).tumbler().clone())
    );
}
