//! Integration tests for M4's public surface. Each test states a claim the
//! design/interface actually makes (§-references inline): what the duplicate
//! check admits and rejects, that the fold never replaces a stored value
//! (S0(b)) — it leaves the whole slice as it was — and panics on the attempt
//! in debug builds, that the fold is pure and insert-only, that identity is
//! by address and never by value and `Val` implements no `Hash` (S4), that a
//! point query matches its address exactly, never a prefix or an extension,
//! that any byte string is a value and comes back exactly as written, that
//! the record and the slice survive a serde round trip (and M2's durable
//! recovery across a checkpoint), that the slice's decode takes its entries
//! in any order and neither the record's decode nor the slice's trusts a
//! count its bytes do not carry or admits a key that is no tumbler, or no
//! T4-valid address, that the slice's serialized form is the format its
//! readers pin, that a debug build panics on a non-content address before it
//! looks at what is stored there, at the line that passed it in, while a
//! release build writes one with a document as given, that a value renders
//! into `Debug` as its byte length and never a byte, and that each part of
//! the interface does its ordinary job on an ordinary input.
//! Where a debug build's assertion panics, release does something else, and
//! those tests say what each build does; the gate runs the suite in both.
//! The toy `World`/`Rec` pair is the minimal engine assembly the composition
//! contract prescribes: `HasContent` read accessor, `From<ContentWrite>`
//! record lift, `apply` dispatching into `ContentStore::apply_write`.

use std::path::Path;

use serde::{de::DeserializeOwned, Deserialize, Serialize};
use skep_address::{validate, Address, Nat, T4Clause, Tumbler};
use skep_content::{stage_write, write, ContentError, ContentStore, ContentWrite, HasContent, Val};
use skep_kernel::{
    BurnedSeqPolicy, CheckpointPolicy, Durability, Kernel, KernelConfig, SaltSource, TxnError,
    WorldState,
};
use skep_namespace::M3State;
use tempfile::tempdir;

// ---- the minimal engine assembly (composition contract) ----

#[derive(Clone, Serialize, Deserialize)]
struct World {
    content: ContentStore,
}

#[derive(Clone, Serialize, Deserialize)]
struct Rec(ContentWrite);

impl From<ContentWrite> for Rec {
    fn from(r: ContentWrite) -> Rec {
        Rec(r)
    }
}

impl HasContent for World {
    fn content(&self) -> &ContentStore {
        &self.content
    }
}

impl WorldState for World {
    type Record = Rec;
    fn apply(&self, r: &Rec) -> World {
        World {
            content: self.content.apply_write(&r.0),
        }
    }
}

// ---- helpers ----

fn t(comps: &[u32]) -> Tumbler {
    Tumbler::new(comps.iter().map(|&c| Nat::from(c))).expect("test tumblers are nonempty")
}

fn a(comps: &[u32]) -> Address {
    validate(t(comps)).expect("test addresses are T4-valid")
}

/// A content element address in M3's minted shape: doc `[1,0,1,0,1]`,
/// element field `[s_C = 1, ordinal]`.
fn ca(ordinal: u32) -> Address {
    a(&[1, 0, 1, 0, 1, 0, 1, ordinal])
}

fn val(b: &[u8]) -> Val {
    Val::new(b)
}

fn genesis() -> World {
    World {
        content: ContentStore::default(),
    }
}

fn mem_kernel() -> Kernel<World> {
    let cfg = KernelConfig {
        durability: Durability::InMemory,
        checkpoint: CheckpointPolicy::Manual,
        salt: SaltSource::Seeded(0),
    };
    Kernel::open(cfg, genesis()).expect("in-memory open")
}

fn cfg_fsync(dir: &Path) -> KernelConfig {
    KernelConfig {
        durability: Durability::Fsync {
            journal_path: dir.to_path_buf(),
            retain_checkpoints: 1,
            burned_seq: BurnedSeqPolicy::Rollback,
        },
        checkpoint: CheckpointPolicy::Manual,
        salt: SaltSource::Seeded(0),
    }
}

/// Unwrap an op's typed rejection (`TxnError::Rejected(E)` — surfaced
/// verbatim, per M2's transact contract).
fn rejected<T: std::fmt::Debug, E: std::fmt::Debug>(r: Result<T, TxnError<E>>) -> E {
    match r {
        Err(TxnError::Rejected(e)) => e,
        other => panic!("expected TxnError::Rejected, got {other:?}"),
    }
}

// ---- §C stage_write: the pure step ----

#[test]
fn stage_write_admits_a_fresh_address_and_commits_nothing() {
    // §C: reads off a supplied slice, returns the record, commits nothing.
    let c = ContentStore::default();
    let a1 = ca(1);
    let rec = stage_write(&c, &a1, val(b"alpha")).expect("fresh address is admitted");
    // Read-public accessors report the staged pair (§A).
    assert_eq!(rec.addr(), a1.tumbler());
    assert_eq!(rec.val().as_bytes(), b"alpha");
    // Nothing committed: the supplied slice is untouched, so a second stage
    // of the same address against the SAME slice is admitted again — folding
    // between stages (working()) is the caller's obligation.
    assert!(!c.contains(a1.tumbler()));
    assert!(stage_write(&c, &a1, val(b"alpha")).is_ok());
}

#[test]
fn stage_write_rejects_an_address_already_stored() {
    // The duplicate check (§Invariants): an address with a value already
    // stored is a typed rejection.
    let c = ContentStore::default();
    let a1 = ca(1);
    let c = c.apply_write(&stage_write(&c, &a1, val(b"first")).expect("fresh"));
    let err = stage_write(&c, &a1, val(b"second")).unwrap_err();
    assert_eq!(err, ContentError::AlreadyStored(a1.tumbler().clone()));
    // The message names the address dotted, as M1 renders one, and leaves
    // "rejected" to whichever wrapper carries it.
    assert_eq!(err.to_string(), "a value is already stored at 1.0.1.0.1.0.1.1 (S0 no-overwrite)");
    // The check is per-address: a different fresh address is still admitted.
    assert!(stage_write(&c, &ca(2), val(b"second")).is_ok());
}

// ---- §A apply_write: the fold ----

#[test]
fn apply_write_is_a_pure_insert_only_fold() {
    // §A: pure — the receiver is untouched, a NEW slice is returned; S0(a)/S1
    // — the domain only grows.
    let c0 = ContentStore::default();
    assert!(c0.is_empty());
    assert_eq!(c0.len(), 0);
    let a1 = ca(1);
    let rec = stage_write(&c0, &a1, val(b"alpha")).expect("fresh");
    let c1 = c0.apply_write(&rec);
    // The prior slice still exists unchanged (persistent structural sharing —
    // this is what lets snapshots pin old Worlds).
    assert!(c0.is_empty());
    assert!(!c0.contains(a1.tumbler()));
    // The new slice holds the entry.
    assert!(c1.contains(a1.tumbler()));
    assert_eq!(c1.value_at(a1.tumbler()).map(Val::as_bytes), Some(&b"alpha"[..]));
    assert_eq!(c1.len(), 1);
    assert!(!c1.is_empty());
}

#[test]
#[cfg_attr(
    debug_assertions,
    should_panic(expected = "already stored in the slice it is folded into")
)]
fn apply_write_never_replaces_a_stored_value_and_panics_on_the_attempt_in_debug() {
    // §A/§C: S0(b) is the fold's own — the stored value wins. Staging against
    // the slice the record is folded into only decides whether a duplicate is
    // refused or dropped: two records for one address, both staged against
    // the unchanged c0, each pass the duplicate check; folding the second
    // panics in a debug build and, in release, leaves the slice as it was —
    // every entry, not only the one it collided with, so c0 holds others.
    let mut c0 = ContentStore::default();
    for ordinal in 2..=6 {
        c0 = c0.apply_write(&stage_write(&c0, &ca(ordinal), val(b"other")).expect("fresh"));
    }
    let a1 = ca(1);
    let first = stage_write(&c0, &a1, val(b"first")).expect("fresh in c0");
    let second = stage_write(&c0, &a1, val(b"second")).expect("still fresh in c0");
    let c1 = c0.apply_write(&first);
    let c2 = c1.apply_write(&second);
    assert_eq!(c2, c1, "a record for a stored address changed the slice it was folded into");
    assert_eq!(c2.value_at(a1.tumbler()).map(Val::as_bytes), Some(&b"first"[..]));
}

// ---- §B point queries ----

#[test]
fn point_queries_report_content_presence_only() {
    // §B: contains/value_at answer content-presence — whether content is
    // stored at an address (`a ∈ dom(C)`) — and nothing else. An address
    // with nothing stored ⇒ false/None, on the empty (Default) slice and next
    // to a live entry alike.
    let c = ContentStore::default();
    let a1 = ca(1);
    let a2 = ca(2);
    assert!(!c.contains(a1.tumbler()));
    assert!(c.value_at(a1.tumbler()).is_none());
    let c = c.apply_write(&stage_write(&c, &a1, val(b"alpha")).expect("fresh"));
    assert!(c.contains(a1.tumbler()));
    assert!(!c.contains(a2.tumbler()));
    assert!(c.value_at(a2.tumbler()).is_none());
}

#[test]
fn point_queries_match_the_stored_address_exactly_never_a_prefix_or_an_extension() {
    // §B / lib.rs §Boundary: `contains` and `value_at` are point queries over
    // `dom(C)` — exact membership; M4 offers no prefix or range read. So
    // beside content stored at 1.0.1.0.1.0.1.1, its document, its content
    // anchor, an element beneath it and the link element beside it all answer
    // false/None: content is stored at none of them.
    let stored = ca(1);
    let c = ContentStore::default().apply_write(
        &stage_write(&ContentStore::default(), &stored, val(b"alpha")).expect("fresh"),
    );
    assert!(c.contains(stored.tumbler()));
    for (what, near) in [
        ("its document", t(&[1, 0, 1, 0, 1])),
        ("its content anchor", t(&[1, 0, 1, 0, 1, 0, 1])),
        ("an element beneath it", t(&[1, 0, 1, 0, 1, 0, 1, 1, 1])),
        ("the link element beside it", t(&[1, 0, 1, 0, 1, 0, 2, 1])),
    ] {
        assert!(!c.contains(&near), "{what}, {near}, answered stored");
        assert!(c.value_at(&near).is_none(), "{what}, {near}, answered a value");
    }
}

#[test]
fn identity_is_by_address_never_by_value() {
    // S4: two equal values at two addresses are simply two entries — no
    // content-addressed collapse.
    let c = ContentStore::default();
    let a1 = ca(1);
    let a2 = ca(2);
    let c = c.apply_write(&stage_write(&c, &a1, val(b"same bytes")).expect("fresh"));
    let c = c.apply_write(&stage_write(&c, &a2, val(b"same bytes")).expect("fresh"));
    assert_eq!(c.len(), 2);
    assert_eq!(c.value_at(a1.tumbler()).map(Val::as_bytes), Some(&b"same bytes"[..]));
    assert_eq!(c.value_at(a2.tumbler()).map(Val::as_bytes), Some(&b"same bytes"[..]));
}

#[test]
fn slices_are_equal_when_they_store_the_same_values_at_the_same_addresses() {
    // §A: a slice's equality is its contents' — `dom(C)` and `C(a)` — in
    // whatever order its records were folded; a record's is its address and
    // its value.
    let c0 = ContentStore::default();
    let r1 = stage_write(&c0, &ca(1), val(b"one")).expect("fresh");
    let r2 = stage_write(&c0, &ca(2), val(b"two")).expect("fresh");
    assert_eq!(c0.apply_write(&r1).apply_write(&r2), c0.apply_write(&r2).apply_write(&r1));
    assert_ne!(c0.apply_write(&r1), c0.apply_write(&r2));
    let other = stage_write(&c0, &ca(1), val(b"uno")).expect("fresh");
    assert_ne!(r1, other, "one address, two values: two records");
    assert_ne!(c0.apply_write(&r1), c0.apply_write(&other));
}

// ---- §B the one enumeration ----

#[test]
fn iter_visits_every_entry_exactly_once_and_promises_no_order() {
    // The one enumeration beside the point reads: every pair once, its
    // count the slice's, over a pinned slice while a later slice grows —
    // the daemon's cell-index rebuild walks a snapshot this way while
    // commits proceed. The order is the map's own, so the test asserts the
    // SET and the count, never a sequence.
    let c0 = ContentStore::default();
    assert_eq!(c0.iter().len(), 0);
    assert!(c0.iter().next().is_none());
    let mut c = c0.clone();
    let n = 257u32; // past one B-tree node, so the walk crosses levels
    for i in 1..=n {
        let rec = stage_write(&c, &ca(i), val(format!("v{i}").as_bytes())).expect("fresh");
        c = c.apply_write(&rec);
    }
    let later = c.apply_write(&stage_write(&c, &ca(n + 1), val(b"later")).expect("fresh"));
    let walk = c.iter();
    assert_eq!(walk.len(), n as usize, "exact-size: the slice's count");
    let mut seen = std::collections::BTreeSet::new();
    for (addr, v) in walk {
        let ordinal: u32 = addr.iter().last().expect("an ordinal").to_string().parse().expect("small");
        assert_eq!(v.as_bytes(), format!("v{ordinal}").as_bytes(), "the pair is the stored one");
        assert!(seen.insert(ordinal), "an entry is visited once");
        assert!(c.contains(addr), "every address walked is in the slice");
    }
    assert_eq!(seen.len(), n as usize, "every entry is visited");
    assert_eq!(later.iter().len(), n as usize + 1, "a later slice walks its own entry too");
    assert_eq!(c.iter().len(), n as usize, "and the pinned slice is untouched by it");
}

// ---- §Types: Val, and Debug over the types that hold one ----

#[test]
fn val_wraps_bytes_and_compares_by_content_value() {
    let from_slice = Val::new(b"payload".as_slice());
    let from_vec = Val::new(b"payload".to_vec());
    assert_eq!(from_slice.as_bytes(), b"payload");
    let generic: &[u8] = from_slice.as_ref();
    assert_eq!(generic, b"payload");
    assert_eq!(from_slice.len(), 7);
    assert!(!from_slice.is_empty());
    assert_eq!(from_slice, from_vec);
    assert_eq!(Val::new(*b"payload"), from_vec, "an array wraps as the same value");
    assert_ne!(from_slice, Val::new(b"other".as_slice()));
    // A zero-length value is legal.
    assert_eq!(Val::new(Vec::<u8>::new()).len(), 0);
    assert!(Val::new(Vec::<u8>::new()).is_empty());
}

#[test]
#[allow(clippy::assertions_on_constants)] // the probe's answer is a constant by design
fn val_implements_no_hash_so_no_map_can_key_on_a_value() {
    // value.rs, S4: identity is by address, never by value, and `Val` keeps it
    // so by implementing no `Hash` — no map, this crate's or a caller's, can
    // key on a value. `Probe::<T>::HASH` resolves to the inherent `true` where
    // `T: Hash` and to the fallback trait's `false` elsewhere; `Tumbler`, the
    // key M4 hashes, is the control that the probe can read `true` at all.
    #[allow(dead_code)] // a type to resolve paths on; never built
    struct Probe<T>(std::marker::PhantomData<T>);
    trait Fallback {
        const HASH: bool = false;
    }
    impl<T> Fallback for Probe<T> {}
    impl<T: std::hash::Hash> Probe<T> {
        const HASH: bool = true;
    }
    assert!(<Probe<Tumbler>>::HASH, "the probe reads `false` even for a type that implements Hash");
    assert!(
        !<Probe<Val>>::HASH,
        "Val implements Hash: a map can key on a value, where S4 keys content by its address"
    );
}

#[test]
fn a_value_is_stored_and_read_back_exactly_as_written_whatever_its_bytes() {
    // value.rs: M4 is value-oblivious — it never inspects a value's bytes, so
    // any byte string is a value and comes back exactly as written: the
    // zero-length one, a single byte (the shape INSERT stores, one byte per
    // content address), and bytes that are no text at all. Each folds from its
    // journaled record and reads back from the slice and from its checkpoint
    // form; a zero-length value is content stored like any other.
    let written: [&[u8]; 3] = [b"", &[0x00], &[0xff, 0xfe, 0x80]];
    let mut c = ContentStore::default();
    for (ordinal, bytes) in (1..).zip(written) {
        let rec = stage_write(&c, &ca(ordinal), val(bytes)).expect("fresh");
        let replayed: ContentWrite =
            bincode::deserialize(&bincode::serialize(&rec).expect("record serializes"))
                .expect("record decodes");
        c = c.apply_write(&replayed);
    }
    let checkpointed: ContentStore =
        bincode::deserialize(&bincode::serialize(&c).expect("slice serializes"))
            .expect("slice decodes");
    for (ordinal, bytes) in (1..).zip(written) {
        let at = ca(ordinal);
        for (form, slice) in [("folded", &c), ("checkpointed", &checkpointed)] {
            assert!(
                slice.contains(at.tumbler()),
                "{form}: a {}-byte value is not stored",
                bytes.len()
            );
            assert_eq!(
                slice.value_at(at.tumbler()).map(Val::as_bytes),
                Some(bytes),
                "{form}: a {}-byte value came back changed",
                bytes.len()
            );
        }
    }
}

#[test]
fn debug_renders_a_value_by_its_byte_length_never_its_bytes() {
    // §Types/§A: `Val`'s `Debug` is its byte length, so the record and the
    // slice, deriving theirs, render addresses and lengths and never a byte.
    assert_eq!(format!("{:?}", val(b"secret")), "6 bytes");
    let rec = stage_write(&ContentStore::default(), &ca(7), val(b"abc")).expect("fresh");
    assert_eq!(
        format!("{rec:?}"),
        "ContentWrite { addr: Tumbler([1, 0, 1, 0, 1, 0, 1, 7]), val: 3 bytes }"
    );
    let c = ContentStore::default().apply_write(&rec);
    assert_eq!(
        format!("{c:?}"),
        "ContentStore { map: {Tumbler([1, 0, 1, 0, 1, 0, 1, 7]): 3 bytes} }"
    );
}

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
    // The form is a format (store.rs, `impl Serialize for ContentStore`):
    // M2's checkpoint hashes these bytes, the engine's World lays them down
    // as one slice of its layout, and the engine's world dump renders them.
    // So they are pinned whole — the slice's one field, its map, as its
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
/// neither a value nor a panic — and returns the refusal's message, for a
/// caller that pins which door refused. A panic is how a reservation sized by
/// a count the bytes do not carry shows itself when it overflows, and how a
/// decode that takes what they hold on trust, through an `expect`, shows
/// itself at all.
fn assert_refused<T: DeserializeOwned>(what: &str, bytes: &[u8]) -> String {
    match std::panic::catch_unwind(|| bincode::deserialize::<T>(bytes)) {
        Ok(Err(refusal)) => refusal.to_string(),
        Ok(Ok(_)) => panic!("{what}: decoded, though no value serializes as these bytes"),
        Err(_) => panic!(
            "{what}: the decode panicked instead of refusing the bytes — a reservation sized by \
             a count they do not carry, or an `expect` that took what they hold on trust"
        ),
    }
}

#[test]
fn the_record_and_the_slice_refuse_a_count_their_bytes_do_not_carry() {
    // M2's hostile-input obligation (store.rs, `impl Serialize for
    // ContentStore`): a checkpoint body and a journal frame are bytes M2 does
    // not trust, and M2 answers one that will not decode by refusing it — a
    // checkpoint is skipped for an older base, a record is `Corruption`. So a
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
    // door's own, word for word. The door's other edge is pinned too: a
    // link-subspace element address is T4-valid, and a release build — its
    // routing assertion compiled out — can journal one, so the decode admits
    // it; a door that refused it would leave that build unable to replay its
    // own journal.
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
    let link_elem = [1, 0, 1, 0, 1, 0, 2, 1]; // subspace s_L = 2
    let decoded = bincode::deserialize::<ContentStore>(&slice(&link_elem))
        .expect("a mis-routed, T4-valid key is the stage door's to check, not the decode's");
    assert!(decoded.contains(&t(&link_elem)), "the decoded slice holds the key it carried");
    let decoded = bincode::deserialize::<ContentWrite>(&record(&link_elem))
        .expect("a mis-routed, T4-valid address is the stage door's to check, not the decode's");
    assert_eq!(
        decoded.addr(),
        &t(&link_elem),
        "the decoded record carries the address it was given"
    );
}

#[test]
fn the_slice_decodes_its_entries_in_whatever_order_they_arrive() {
    // store.rs and M4's interface: `Serialize` writes the entries in Tumbler
    // order, and `Deserialize` takes them in any order — the map is rebuilt
    // from whatever arrives, one entry at a time, so a body whose entries
    // come in any order loads. Bytes carrying the entries in REVERSE Tumbler
    // order decode to the slice that holds them.
    let mut c = ContentStore::default();
    let mut reversed: Vec<(Tumbler, Vec<u8>)> = Vec::new();
    for ordinal in 1..=8u32 {
        let addr = ca(ordinal);
        let bytes = vec![b'0' + ordinal as u8];
        c = c.apply_write(&stage_write(&c, &addr, Val::new(bytes.clone())).expect("fresh"));
        reversed.push((addr.tumbler().clone(), bytes));
    }
    reversed.sort_by(|x, y| y.0.cmp(&x.0));
    let back: ContentStore =
        bincode::deserialize(&bincode::serialize(&reversed).expect("entries serialize"))
            .expect("entries out of Tumbler order decode");
    assert_eq!(
        back, c,
        "decoded from its entries in reverse order, the slice is not the one holding them"
    );
}

// ---- §C the standalone op over M2 ----

#[test]
fn standalone_write_commits_and_reads_back_through_a_snapshot() {
    let k = mem_kernel();
    let a1 = ca(1);
    let (stored, seq) = write(&k, &a1, val(b"alpha")).expect("fresh write commits");
    assert_eq!(stored, *a1.tumbler());
    assert_eq!(k.current_seq(), seq);
    // Bind the snapshot first; the &Val borrows THROUGH it (§B).
    let s = k.snapshot();
    assert_eq!(s.seq(), seq);
    let c = s.world().content();
    assert!(c.contains(a1.tumbler()));
    assert_eq!(c.value_at(a1.tumbler()).map(Val::as_bytes), Some(&b"alpha"[..]));
    assert_eq!(c.len(), 1);
}

#[test]
fn standalone_write_rejects_a_double_write_and_preserves_the_first_value() {
    // S0(b) through the composite: the second write is a clean typed
    // rejection (surfaced verbatim per M2), nothing committed, the stored
    // value untouched.
    let k = mem_kernel();
    let a1 = ca(1);
    write(&k, &a1, val(b"first")).expect("fresh write commits");
    let seq_before = k.current_seq();
    let err = rejected(write(&k, &a1, val(b"second")));
    assert_eq!(err, ContentError::AlreadyStored(a1.tumbler().clone()));
    assert_eq!(k.current_seq(), seq_before);
    let s = k.snapshot();
    let c = s.world().content();
    assert_eq!(c.len(), 1);
    assert_eq!(c.value_at(a1.tumbler()).map(Val::as_bytes), Some(&b"first"[..]));
}

#[test]
fn stage_write_composes_into_one_transaction_off_the_working_slice() {
    // The M5-shape composite (§Dependencies & seams): m records staged via
    // stage_write against stg.working().content() in ONE transact, committed
    // under one marker; the working slice reflects each push, so an
    // intra-composite double-stage is rejected.
    let k = mem_kernel();
    let d = a(&[1, 0, 1, 0, 1]);
    let a1 = ca(1);
    let a2 = ca(2);
    let (_, seq) = k
        .transact(&[M3State::content_lock_key(&d)], |stg| {
            let r1 = stage_write(stg.working().content(), &a1, val(b"one"))?;
            stg.push(r1.into());
            // working() reflects the push: re-staging a1 here is rejected.
            assert!(matches!(
                stage_write(stg.working().content(), &a1, val(b"dup")),
                Err(ContentError::AlreadyStored(t)) if t == *a1.tumbler()
            ));
            let r2 = stage_write(stg.working().content(), &a2, val(b"two"))?;
            stg.push(r2.into());
            // Pins the closure's error parameter: `?` on stage_write only
            // constrains `E: From<ContentError>`, which infers nothing.
            Ok::<(), ContentError>(())
        })
        .expect("composite commits");
    let s = k.snapshot();
    assert_eq!(s.seq(), seq);
    let c = s.world().content();
    assert_eq!(c.len(), 2);
    assert_eq!(c.value_at(a1.tumbler()).map(Val::as_bytes), Some(&b"one"[..]));
    assert_eq!(c.value_at(a2.tumbler()).map(Val::as_bytes), Some(&b"two"[..]));
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
    // The recovered dom(C) still feeds `stage_write`'s duplicate check.
    drop(s);
    assert_eq!(
        rejected(write(&k, &a1, val(b"again"))),
        ContentError::AlreadyStored(a1.tumbler().clone())
    );
}

// ---- Open build decision #4: the routing assertion ----

#[test]
#[cfg_attr(debug_assertions, should_panic(expected = "content routing: write"))]
#[cfg_attr(not(debug_assertions), should_panic(expected = "content address ⇒ zeros = 3"))]
fn write_panics_on_a_non_content_address_routing_first() {
    // §C: a zeros = 1 input is an internal invariant violation, never a
    // domain rejection. A debug build's routing assertion fires BEFORE key
    // derivation (its message, not the `.expect`'s); in release it is
    // compiled out and the `document_of` `.expect` — the trusted-address
    // contract — fires.
    let k = mem_kernel();
    let account = a(&[1, 0, 1]);
    let _ = write(&k, &account, val(b"x"));
}

#[test]
#[cfg_attr(debug_assertions, should_panic(expected = "content routing: write"))]
fn write_trusts_a_document_level_address_in_release_and_panics_on_it_in_debug() {
    // §C: `write`'s `.expect` catches only an address with no document
    // (zeros < 2). A document-level address has one — itself — so it passes
    // the `.expect`: a debug build's routing assertion is what stops it, and
    // a release build, that assertion compiled out, writes it as given. The
    // trusted-address contract is the caller's, checked whole in debug builds
    // only.
    let k = mem_kernel();
    let doc = a(&[1, 0, 1, 0, 1]);
    let (stored, _) = write(&k, &doc, val(b"x")).expect("release trusts the caller's address");
    assert_eq!(stored, *doc.tumbler());
    let s = k.snapshot();
    assert!(s.world().content().contains(doc.tumbler()), "release writes the address as given");
}

/// The source file a panic inside `f` is located at, read by a hook set for
/// this call alone, the previous hook put back after it.
fn panic_file(f: impl FnOnce()) -> String {
    use std::cell::RefCell;
    use std::panic::{self, AssertUnwindSafe};
    thread_local! {
        static FILE: RefCell<Option<String>> = const { RefCell::new(None) };
    }
    let previous = panic::take_hook();
    panic::set_hook(Box::new(|info| {
        let file = info.location().map(|l| l.file().to_owned());
        FILE.with(|slot| *slot.borrow_mut() = file);
    }));
    let outcome = panic::catch_unwind(AssertUnwindSafe(f));
    panic::set_hook(previous);
    assert!(outcome.is_err(), "the call was expected to panic");
    FILE.with(|slot| slot.borrow_mut().take()).expect("a panic has a location")
}

#[test]
fn a_routing_panic_is_located_at_the_line_that_passed_the_address_in() {
    // §C: both doors are `#[track_caller]`, so a mis-routed address panics
    // at the caller's line — in this file — and not inside M4. A debug
    // build's routing assertion fires through either door; in release it is
    // compiled out, `stage_write` admits the address, and `write`'s
    // `.expect` fires at the caller's line instead.
    let k = mem_kernel();
    let account = a(&[1, 0, 1]);
    let through_write = panic_file(|| {
        let _ = write(&k, &account, val(b"x"));
    });
    assert_eq!(through_write, file!());
    if cfg!(debug_assertions) {
        let through_stage = panic_file(|| {
            let _ = stage_write(&ContentStore::default(), &account, val(b"x"));
        });
        assert_eq!(through_stage, file!());
    }
}

// A debug_assert!: it fires only in debug builds.
#[cfg(debug_assertions)]
mod routing {
    use super::*;

    #[test]
    #[should_panic(expected = "content routing: stage_write")]
    fn stage_write_asserts_against_a_link_subspace_address() {
        let link_elem = a(&[1, 0, 1, 0, 1, 0, 2, 1]); // subspace s_L = 2
        let _ = stage_write(&ContentStore::default(), &link_elem, val(b"x"));
    }

    #[test]
    #[should_panic(expected = "content routing: stage_write")]
    fn stage_write_asserts_against_a_subspace_neither_content_nor_link() {
        // Routing admits s_C = 1 alone — not "every subspace but s_L = 2".
        let elem = a(&[1, 0, 1, 0, 1, 0, 3, 1]); // subspace 3
        let _ = stage_write(&ContentStore::default(), &elem, val(b"x"));
    }

    #[test]
    #[should_panic(expected = "content routing: stage_write")]
    fn stage_write_asserts_against_a_non_element_address() {
        let doc = a(&[1, 0, 1, 0, 1]);
        let _ = stage_write(&ContentStore::default(), &doc, val(b"x"));
    }

    #[test]
    #[should_panic(expected = "content routing: stage_write")]
    fn stage_write_asserts_routing_before_it_checks_what_is_stored() {
        // §C: the routing assertion runs BEFORE the already-stored check, so a
        // mis-routed address panics on its own terms even where a value is
        // stored at it — never an `AlreadyStored`, which reads as a duplicate
        // mint and sends its reader to M3. A debug build cannot stage such a
        // value, so it arrives as M2's replay hands one over: a record decoded
        // from bytes, as a release build — its assertion compiled out —
        // journaled it.
        let link_elem = a(&[1, 0, 1, 0, 1, 0, 2, 1]); // subspace s_L = 2
        let replayed: ContentWrite = bincode::deserialize(
            &bincode::serialize(&(link_elem.tumbler(), b"x".to_vec())).expect("pair serializes"),
        )
        .expect("a record's bytes are its address, then its value");
        let c = ContentStore::default().apply_write(&replayed);
        assert!(c.contains(link_elem.tumbler()), "the replayed record's value is stored");
        let _ = stage_write(&c, &link_elem, val(b"y"));
    }
}
