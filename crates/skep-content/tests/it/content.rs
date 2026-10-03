//! Integration tests for M4's public surface. Each test states a claim the
//! design/interface actually makes (§-references inline): what the duplicate
//! check admits and rejects, that the fold never replaces a stored value
//! (S0(b)) and panics on the attempt in debug builds, that the fold is pure
//! and insert-only, that identity is by address and never by value (S4),
//! that the journaled types survive a serde round trip (and M2's real
//! checkpoint-plus-replay recovery), that the slice's serialized form is the
//! format its readers pin, that a debug build panics on a non-content
//! address before writing it, at the line that passed it in, that a value
//! renders into `Debug` as its byte length and never a byte, and that each
//! part of the interface does its ordinary job on an ordinary input. Where a
//! debug build's assertion panics, release does something else, and those
//! tests say what each build does; the gate runs the suite in both. The toy
//! `World`/`Rec` pair is the minimal engine assembly the composition contract
//! prescribes: `HasContent` read accessor, `From<ContentWrite>` record lift,
//! `apply` dispatching into `ContentStore::apply_write`.

use std::path::Path;

use serde::{Deserialize, Serialize};
use skep_address::{validate, Address, Nat, Tumbler};
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
fn apply_write_never_replaces_a_stored_value_and_nets_the_attempt_in_debug() {
    // §A/§C: S0(b) is the fold's own — the stored value wins. Staging against
    // the slice the record is folded into only decides whether a duplicate is
    // refused or dropped: two records for one address, both staged against
    // the unchanged c0, each pass the duplicate check; folding the second
    // panics in a debug build and, in release, leaves the first value where
    // it was.
    let c0 = ContentStore::default();
    let a1 = ca(1);
    let first = stage_write(&c0, &a1, val(b"first")).expect("fresh in c0");
    let second = stage_write(&c0, &a1, val(b"second")).expect("still fresh in c0");
    let c2 = c0.apply_write(&first).apply_write(&second);
    assert_eq!(c2.len(), 1);
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
    let n = 257u32; // past one HAMT node, so the walk crosses levels
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

// ---- serde: the journaled types ----

#[test]
fn journaled_types_survive_a_bincode_round_trip() {
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
    // as). Sixty-four entries over four documents, so the HAMT's own
    // iteration order is not Tumbler order by accident.
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

// ---- M2-driven recovery: checkpoint load + tail replay ----

#[test]
fn content_survives_durable_recovery_by_checkpoint_and_replay() {
    // §Recovery: M4 owns no recovery machinery — M2's open loads the latest
    // checkpoint (deserializing the slice) and replays the tail by folding
    // ContentWrite records through apply → apply_write. a1 rides the
    // checkpoint path, a2 the replay path.
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
    fn stage_write_asserts_against_a_non_element_address() {
        let doc = a(&[1, 0, 1, 0, 1]);
        let _ = stage_write(&ContentStore::default(), &doc, val(b"x"));
    }
}
