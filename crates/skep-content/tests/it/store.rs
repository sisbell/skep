//! The slice and its write steps, with no kernel: what the already-stored
//! check admits and rejects at both doors, and that staging keeps the address
//! it is handed in the memory it had; that the two folds are pure and
//! insert-only, keep every stored address and value in the memory they had
//! and put the written ones in the memory their record holds them in, and
//! never replace a stored entry — they leave the whole slice as it was, and
//! panic on the attempt in debug builds; that a point query matches a value's
//! address exactly, never a prefix or an extension, and answers every address
//! inside a stretch by its byte, across a B-tree leaf boundary, and never
//! another chain's address whose predecessor is a stretch; that "inside a
//! stretch" is tumbler-interval containment — an address inside one is
//! refused at both doors and the interloper key beneath one is refused by the
//! doors and the decoder while every byte still answers; that the one run
//! read walks an extent piece by piece, across the seam between a stretch and
//! a value, and says whether the extent is covered; that identity is by
//! address, never by value, and `Val` implements no `Hash` (S4); that a
//! slice's equality is its contents', address and value each counting; that
//! the one enumeration visits every entry once, through `iter` and through a
//! `for` loop over the slice alike, as a walk a caller can name, which knows
//! exactly what remains at every step, shows no entry in its `Debug`, and
//! offers no walk from the far end; that any byte string is a value, shares
//! its bytes with every clone, comes back exactly as written, and renders
//! into `Debug` as its byte length, never a byte; and that the stage doors
//! panic on a non-content address in debug builds, before they look at what
//! is stored there, and stage every such address as given in release.

use skep_address::{Address, Nat};
use skep_content::{
    stage_stretch, stage_write, ContentError, ContentStore, ContentStretch, ContentWrite, Iter,
    Piece, Val,
};

use crate::common::*;

/// Whether the type before the colon implements the trait after it, read at
/// compile time: the inherent `IMPLEMENTS`, which path resolution prefers,
/// exists only where the bound holds, and the fallback trait's `false`
/// answers everywhere else. A probe that could only ever say `false` would
/// pass every "implements no X" claim, so each claim pairs it with a control
/// type that does implement the trait and must read `true`.
macro_rules! implements {
    ($ty:ty: $($bound:tt)+) => {{
        // Each probe reads one `IMPLEMENTS` of the two — the inherent one
        // where the bound holds, the fallback's elsewhere — so the other is
        // dead by design, and `Probe` is a type to resolve paths on, never
        // built.
        #[allow(dead_code)]
        struct Probe<T>(std::marker::PhantomData<T>);
        #[allow(dead_code)]
        trait Fallback {
            const IMPLEMENTS: bool = false;
        }
        impl<T> Fallback for Probe<T> {}
        #[allow(dead_code)]
        impl<T: $($bound)+> Probe<T> {
            const IMPLEMENTS: bool = true;
        }
        <Probe<$ty>>::IMPLEMENTS
    }};
}

/// The memory an address's components occupy, named by its first. A move,
/// or a second view through the `Arc` that holds it, leaves the answer as it
/// was; a clone rebuilds the components elsewhere and changes it.
fn component_memory(addr: &Address) -> *const Nat {
    std::ptr::from_ref(addr.tumbler().iter().next().expect("a tumbler is nonempty"))
}

/// The memory a value's bytes occupy, named by their first. A clone that
/// shares the bytes leaves the answer as it was; a copy puts them elsewhere
/// and changes it — while the original lives, and for a value of at least one
/// byte: an empty value's bytes can sit at a placeholder address every copy
/// shares.
fn value_memory(bytes: &[u8]) -> *const u8 {
    bytes.as_ptr()
}

/// `c` with a stretch of `bytes` at `ca(first)` folded in.
fn with_stretch(c: &ContentStore, first: u32, b: &[u8]) -> ContentStore {
    c.apply_stretch(&stage_stretch(c, ca(first), bytes(b)).expect("fresh"))
}

/// `c` with the value `bytes` at `ca(ordinal)` folded in.
fn with_value(c: &ContentStore, ordinal: u32, b: &[u8]) -> ContentStore {
    c.apply_write(&stage_write(c, ca(ordinal), val(b)).expect("fresh"))
}

// ---- §C stage_write: the pure step ----

#[test]
fn stage_write_admits_a_fresh_address_and_commits_nothing() {
    // §C: reads off a supplied slice, returns the record, commits nothing.
    let c = ContentStore::default();
    let a1 = ca(1);
    let rec = stage_write(&c, a1.clone(), val(b"alpha")).expect("fresh address is admitted");
    // Read-public accessors report the staged pair (§A).
    assert_eq!(rec.addr(), &a1);
    assert_eq!(rec.val().as_bytes(), b"alpha");
    // Nothing committed: the supplied slice is untouched, so a second stage
    // of the same address against the SAME slice is admitted again — folding
    // between stages (working()) is the caller's obligation.
    assert!(!c.contains(a1.tumbler()));
    assert!(stage_write(&c, a1, val(b"alpha")).is_ok());
}

#[test]
fn stage_write_keeps_the_address_it_is_handed_in_the_memory_it_had() {
    // store.rs (`stage_write`): the record keeps the address its caller hands
    // over, moved in whole and never cloned component by component — a clone,
    // where one is needed, is the caller's to make at its own call
    // (C-CALLER-CONTROL). So the address the record lends occupies the very
    // memory the one handed in did.
    let addr = ca(1);
    let handed = component_memory(&addr);
    let rec = stage_write(&ContentStore::default(), addr, val(b"v")).expect("fresh");
    assert!(
        std::ptr::eq(handed, component_memory(rec.addr())),
        "stage_write rebuilt the address it was handed, {}, in new memory",
        rec.addr()
    );
}

#[test]
fn stage_write_rejects_an_address_already_stored() {
    // The already-stored check (§Invariants): an address with a value already
    // stored is a typed rejection.
    let c = ContentStore::default();
    let a1 = ca(1);
    let c = c.apply_write(&stage_write(&c, a1.clone(), val(b"first")).expect("fresh"));
    let err = stage_write(&c, a1.clone(), val(b"second")).unwrap_err();
    assert_eq!(err, ContentError::AlreadyStored(a1.tumbler().clone()));
    // The message names the address dotted, as M1 renders one, and leaves
    // "rejected" to whichever wrapper carries it.
    assert_eq!(
        err.to_string(),
        "a value is already stored at 1.0.1.0.1.0.1.1 (S0 content immutability)"
    );
    // The check is per-address: a different fresh address is still admitted.
    assert!(stage_write(&c, ca(2), val(b"second")).is_ok());
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
    let rec = stage_write(&c0, a1.clone(), val(b"alpha")).expect("fresh");
    let c1 = c0.apply_write(&rec);
    // The prior slice still exists unchanged (persistent structural sharing —
    // this is what lets snapshots pin old Worlds).
    assert!(c0.is_empty());
    assert!(!c0.contains(a1.tumbler()));
    // The new slice holds the entry.
    assert!(c1.contains(a1.tumbler()));
    assert_eq!(read(&c1, a1.tumbler()), Some(b"alpha".to_vec()));
    assert_eq!(c1.len(), 1);
    assert!(!c1.is_empty());
}

#[test]
fn apply_write_keeps_every_stored_address_in_the_memory_it_had() {
    // store.rs (`Key`): a fold copies the tree nodes on its path, up to 64
    // entries each, and leaves every address where it is in memory, those in
    // the copied nodes included; and it puts the address its record carries
    // into the map by the record's own `Arc` — "neither staging a write nor
    // folding it clones its address component by component", on commit and
    // on every replay. A node copy that cloned each of those addresses
    // component by component would make every write pay for up to 64
    // addresses per level of the tree, a cost set by the longest addresses
    // stored near it, which an INSERT multiplies by its value count under
    // M2's applier lock and every replay pays again; a fold that rebuilt the
    // address its record carries would add one more to every commit and every
    // replay. So each address the old slice stores keeps, in the new slice,
    // the very memory its components had, and the written address sits in
    // the memory its record holds it in. 257 entries put the tree past one
    // node, so the fold copies an inner node as well as a leaf. The record
    // lives through the fold, so no rebuilt address can take its memory.
    let mut c0 = ContentStore::default();
    for ordinal in 1..=257u32 {
        c0 = c0.apply_write(&stage_write(&c0, ca(ordinal), val(b"v")).expect("fresh"));
    }
    let stored: std::collections::BTreeMap<&Address, *const Nat> =
        c0.iter().map(|(addr, _)| (addr, component_memory(addr))).collect();
    let rec = stage_write(&c0, ca(258), val(b"v")).expect("fresh");
    let written = component_memory(rec.addr());
    let c1 = c0.apply_write(&rec);
    let (mut kept, mut added) = (0, 0);
    for (addr, _) in &c1 {
        match stored.get(addr) {
            Some(&before) => {
                assert!(
                    std::ptr::eq(before, component_memory(addr)),
                    "the fold rebuilt {addr}, an address the slice already stored, in new memory"
                );
                kept += 1;
            }
            None => {
                assert!(
                    std::ptr::eq(written, component_memory(addr)),
                    "the fold rebuilt {addr}, the address its record carries, in new memory"
                );
                added += 1;
            }
        }
    }
    assert_eq!(
        (kept, added),
        (257, 1),
        "the new slice holds every address the old one stored, and the written one"
    );
}

#[test]
fn apply_write_keeps_every_stored_value_in_the_memory_it_had() {
    // value.rs and store.rs (`Key`, `ContentStore`): a value's clone shares
    // its bytes and never copies them — each value's bytes sit behind an
    // `Arc`, as each address does — so the tree nodes a fold copies clone the
    // values they hold by that `Arc`, and the value its record carries goes
    // into the map the same way. A value that owned its bytes would make
    // every write copy the bytes of up to 64 values per level of the tree —
    // an atom runs to megabytes — under M2's applier lock, every replay pay
    // it again, and every M5 re-insert, which hands a draft's value over by a
    // clone, hold a second copy. So each value the old slice stores keeps, in
    // the new slice, the very memory its bytes had, and the written value
    // sits in the memory its record holds it in. 257 entries put the tree
    // past one node, so the fold copies an inner node as well as a leaf; the
    // old slice and the record live through the fold, so no copied value can
    // take their memory. The walk lends each entry as a borrowed piece, whose
    // bytes ARE the stored allocation's.
    let mut c0 = ContentStore::default();
    for ordinal in 1..=257u32 {
        c0 = c0.apply_write(&stage_write(&c0, ca(ordinal), val(b"v")).expect("fresh"));
    }
    let stored: std::collections::BTreeMap<&Address, *const u8> =
        c0.iter().map(|(addr, piece)| (addr, value_memory(piece.as_bytes()))).collect();
    let rec = stage_write(&c0, ca(258), val(b"v")).expect("fresh");
    let written = value_memory(rec.val().as_bytes());
    let c1 = c0.apply_write(&rec);
    let (mut kept, mut added) = (0, 0);
    for (addr, piece) in &c1 {
        match stored.get(addr) {
            Some(&before) => {
                assert!(
                    std::ptr::eq(before, value_memory(piece.as_bytes())),
                    "the fold put the value at {addr}, already stored, in new memory"
                );
                kept += 1;
            }
            None => {
                assert!(
                    std::ptr::eq(written, value_memory(piece.as_bytes())),
                    "the fold put the value its record carries, at {addr}, in new memory"
                );
                added += 1;
            }
        }
    }
    assert_eq!(
        (kept, added),
        (257, 1),
        "the new slice holds every value the old one stored, and the written one"
    );
}

#[test]
#[cfg_attr(
    debug_assertions,
    should_panic(expected = "already stored in the slice it is folded into")
)]
fn apply_write_never_replaces_a_stored_value_and_panics_on_the_attempt_in_debug() {
    // §A/§C: S0(b) is the fold's own — the stored value wins. Staging against
    // the slice the record is folded into only decides whether a second
    // write at one address is refused or dropped: two records for one
    // address, both staged against the unchanged c0, each pass the
    // already-stored check; folding the second panics in a debug build and,
    // in release, leaves the slice as it was — every entry, not only the one
    // it collided with, so c0 holds others.
    let mut c0 = ContentStore::default();
    for ordinal in 2..=6 {
        c0 = c0.apply_write(&stage_write(&c0, ca(ordinal), val(b"other")).expect("fresh"));
    }
    let a1 = ca(1);
    let first = stage_write(&c0, a1.clone(), val(b"first")).expect("fresh in c0");
    let second = stage_write(&c0, a1.clone(), val(b"second")).expect("still fresh in c0");
    let c1 = c0.apply_write(&first);
    let c2 = c1.apply_write(&second);
    assert_eq!(c2, c1, "a record for a stored address changed the slice it was folded into");
    assert_eq!(read(&c2, a1.tumbler()), Some(b"first".to_vec()));
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
    let c = c.apply_write(&stage_write(&c, a1.clone(), val(b"alpha")).expect("fresh"));
    assert!(c.contains(a1.tumbler()));
    assert!(!c.contains(a2.tumbler()));
    assert!(c.value_at(a2.tumbler()).is_none());
}

#[test]
fn point_queries_match_the_stored_address_exactly_never_a_prefix_or_an_extension() {
    // §B / lib.rs §Boundary: `contains` and `value_at` are point queries over
    // `dom(C)` — exact membership for a VALUE's key, whose reach is itself
    // alone; M4 offers no prefix read. So beside content stored at
    // 1.0.1.0.1.0.1.1, its document, its content anchor, an element beneath
    // it and the link element beside it all answer false/None: content is
    // stored at none of them. (An element beneath a STRETCH's key is the
    // interloper case below, where containment answers otherwise.)
    let stored = ca(1);
    let c = ContentStore::default().apply_write(
        &stage_write(&ContentStore::default(), stored.clone(), val(b"alpha")).expect("fresh"),
    );
    assert!(c.contains(stored.tumbler()));
    for (what, near) in [
        ("its document", t(&[1, 0, 1, 0, 1])),
        ("its content anchor", t(&[1, 0, 1, 0, 1, 0, 1])),
        ("an element beneath it", t(&[1, 0, 1, 0, 1, 0, 1, 1, 1])),
        ("the link element beside it", t(&[1, 0, 1, 0, 2, 0, 2, 1])),
        ("the next ordinal", t(&[1, 0, 1, 0, 1, 0, 1, 2])),
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
    let c = c.apply_write(&stage_write(&c, a1.clone(), val(b"same bytes")).expect("fresh"));
    let c = c.apply_write(&stage_write(&c, a2.clone(), val(b"same bytes")).expect("fresh"));
    assert_eq!(c.len(), 2);
    assert_eq!(read(&c, a1.tumbler()), Some(b"same bytes".to_vec()));
    assert_eq!(read(&c, a2.tumbler()), Some(b"same bytes".to_vec()));
}

#[test]
fn slices_are_equal_when_they_store_the_same_values_at_the_same_addresses() {
    // §A: a slice's equality is its contents' — `dom(C)` and `C(a)` — in
    // whatever order its records were folded; a record's is its address and
    // its value. Each half counts on its own: one address holding two values,
    // and one value at two addresses, are two records and two slices. And the
    // KIND of an entry counts: one byte stored as a value and the same byte
    // as a stretch of one are two slices, since the checkpoint's bytes part.
    let c0 = ContentStore::default();
    let r1 = stage_write(&c0, ca(1), val(b"one")).expect("fresh");
    let r2 = stage_write(&c0, ca(2), val(b"two")).expect("fresh");
    assert_eq!(c0.apply_write(&r1).apply_write(&r2), c0.apply_write(&r2).apply_write(&r1));
    assert_ne!(c0.apply_write(&r1), c0.apply_write(&r2));
    let other = stage_write(&c0, ca(1), val(b"uno")).expect("fresh");
    assert_ne!(r1, other, "one address, two values: two records");
    assert_ne!(c0.apply_write(&r1), c0.apply_write(&other));
    let elsewhere = stage_write(&c0, ca(2), val(b"one")).expect("fresh");
    assert_ne!(r1, elsewhere, "one value at two addresses: two records");
    assert_ne!(
        c0.apply_write(&r1),
        c0.apply_write(&elsewhere),
        "one value at two addresses: two slices (S4)"
    );
    let as_value = with_value(&c0, 3, b"x");
    let as_stretch = with_stretch(&c0, 3, b"x");
    assert_eq!(read(&as_value, ca(3).tumbler()), read(&as_stretch, ca(3).tumbler()));
    assert_ne!(as_value, as_stretch, "one byte as a value and as a stretch: two slices");
}

// ---- §B the one enumeration ----

#[test]
fn iter_visits_every_entry_of_a_pinned_slice_exactly_once() {
    // The one enumeration beside the point queries: every ENTRY once, its
    // count the slice's — a stretch lent whole as one `Bytes` piece — over a
    // pinned slice while a later slice grows — the cell index's walk reads a
    // snapshot this way while commits proceed — and a `for` loop over `&c`
    // reads the same walk. The order is no part of its promise (store.rs,
    // `iter`) — `iter_offers_no_walk_from_the_far_end_so_it_promises_no_order`
    // defends that — so this test asserts the SET and the count, never a
    // sequence.
    let c0 = ContentStore::default();
    assert_eq!(c0.iter().len(), 0);
    assert!(c0.iter().next().is_none());
    let mut c = c0.clone();
    let n = 257u32; // past one B-tree node, so the walk crosses levels
    for ordinal in 1..=n {
        let rec =
            stage_write(&c, ca(ordinal), val(format!("v{ordinal}").as_bytes())).expect("fresh");
        c = c.apply_write(&rec);
    }
    // One stretch past the values, lent as one entry of three addresses.
    let c = with_stretch(&c, n + 1, b"xyz");
    let later = c.apply_write(&stage_write(&c, ca(n + 4), val(b"later")).expect("fresh"));
    let walk = c.iter();
    assert_eq!(walk.len(), n as usize + 1, "exact-size: the slice's entry count");
    let mut seen = std::collections::BTreeSet::new();
    for (addr, piece) in walk {
        let ordinal =
            u32::try_from(skep_address::ordinal(addr.tumbler())).expect("ca's ordinal is a u32");
        match piece {
            Piece::Value(v) => {
                assert_eq!(v.as_bytes(), format!("v{ordinal}").as_bytes(), "the pair is the stored one")
            }
            Piece::Bytes(b) => {
                assert_eq!((ordinal, b), (n + 1, &b"xyz"[..]), "the stretch is lent whole, once")
            }
        }
        assert!(seen.insert(ordinal), "an entry is visited once");
        assert!(c.contains(addr.tumbler()), "every address walked is in the slice");
    }
    assert_eq!(seen.len(), n as usize + 1, "every entry is visited");
    let mut looped = std::collections::BTreeSet::new();
    for (addr, piece) in &c {
        // The point read at the entry's key: a value whole, a stretch's first
        // byte.
        let at_key = match piece {
            Piece::Value(v) => v.as_bytes().to_vec(),
            Piece::Bytes(b) => b[..1].to_vec(),
        };
        assert_eq!(
            read(&c, addr.tumbler()),
            Some(at_key),
            "a loop over `&c` yields the entry stored at its key"
        );
        assert!(looped.insert(addr), "a loop over `&c` visits an entry once");
    }
    assert_eq!(looped.len(), n as usize + 1, "a loop over `&c` visits every entry");
    assert_eq!(later.iter().len(), n as usize + 2, "a later slice walks its own entry too");
    assert_eq!(c.iter().len(), n as usize + 1, "and the pinned slice is untouched by it");
}

#[test]
fn iter_lends_a_named_walk_that_knows_its_length_and_shows_no_entry() {
    // store.rs, `Iter`: `iter` lends an `Iter`, whose backing is hidden and
    // to which a foreign crate can add no trait — so what the loan promises
    // is witnessed from one: a type a caller can name, the exact length,
    // `Debug`, and `Send + Sync`, which the type has because of what it
    // borrows and which a caller handing a walk to another thread depends on
    // without any signature saying so. `&ContentStore` yields the same type,
    // and its `Debug` names the walk, never an entry. The run read's walk,
    // `Pieces`, promises the same of itself.
    fn lends<'a, I>(walk: I) -> usize
    where
        I: ExactSizeIterator<Item = (&'a Address, Piece<'a>)> + std::fmt::Debug + Send + Sync,
    {
        walk.len()
    }
    let c0 = ContentStore::default();
    let c = c0.apply_write(&stage_write(&c0, ca(1), val(b"secret")).expect("fresh"));
    let walk: Iter<'_> = c.iter();
    assert_eq!(format!("{walk:?}"), "Iter { .. }", "the walk, never an entry");
    assert_eq!(lends(walk), 1);
    let loop_walk: Iter<'_> = IntoIterator::into_iter(&c);
    assert_eq!(lends(loop_walk), 1, "`&ContentStore` lends the same walk");
    fn run_read<'a, I>(walk: I) -> usize
    where
        I: Iterator<Item = Piece<'a>> + std::fmt::Debug + Send + Sync,
    {
        walk.count()
    }
    let pieces = c.pieces(ca(1).tumbler(), &Nat::from(1u32));
    assert_eq!(format!("{pieces:?}"), "Pieces { .. }", "the walk, never a piece");
    assert_eq!(run_read(pieces), 1);
}

#[test]
fn iter_knows_exactly_what_remains_at_every_step_through_len_and_size_hint_alike() {
    // store.rs, `iter` and `Iter`: the walk is exact-size and "the exact
    // length is forwarded" — a promise about every step, not only the first,
    // and about every slice — here the empty one, one pair, and 257 (past one
    // B-tree node, as in the walk test above). After `k` of `n` pairs,
    // `len()` is `n - k` and `size_hint()` is `(n - k, Some(n - k))`, the
    // exact form `ExactSizeIterator` requires, down to the `None` that ends
    // the walk after exactly `n`. The two faces are forwarded separately, and
    // std's `Skip` takes `len()` from `size_hint` and asserts it exact: a walk
    // whose `size_hint` fell back to `(0, None)` would answer `len()` and
    // panic in `skip(1).len()`.
    for n in [0u32, 1, 257] {
        let mut c = ContentStore::default();
        for ordinal in 1..=n {
            c = c.apply_write(&stage_write(&c, ca(ordinal), val(b"v")).expect("fresh"));
        }
        let n = n as usize;
        let mut walk = c.iter();
        for step in 0..=n {
            let left = n - step;
            assert_eq!(walk.len(), left, "len() after {step} of {n} steps");
            assert_eq!(
                walk.size_hint(),
                (left, Some(left)),
                "size_hint() after {step} of {n} steps"
            );
            match walk.next() {
                Some(_) => assert!(step < n, "the walk yielded a pair past its {n}"),
                None => assert_eq!(step, n, "the walk ended after {step} of its {n} pairs"),
            }
        }
        assert_eq!(
            c.iter().skip(1).len(),
            n.saturating_sub(1),
            "skip(1)'s len() over {n} pairs, which std reads off size_hint()"
        );
    }
}

#[test]
fn iter_offers_no_walk_from_the_far_end_so_it_promises_no_order() {
    // store.rs, `Iter`: the reverse walk is withheld though `im`'s map
    // iterator has one — the order is no part of `iter`'s promise, and a walk
    // from the far end would make one: `iter().rev().next()` reads as "the
    // highest address stored", an ordered read M4 does not offer, true only
    // while the map behind the slice is ordered. So `Iter` implements no
    // `DoubleEndedIterator`, which `implements!` reads; `std::slice::Iter`,
    // which does walk from either end, is the control that it can read `true`
    // at all.
    assert!(
        implements!(std::slice::Iter<'static, u8>: DoubleEndedIterator),
        "the probe reads `false` even for an iterator that walks from either end"
    );
    assert!(
        !implements!(Iter<'static>: DoubleEndedIterator),
        "Iter walks from the far end: `rev()` hands its callers an order `iter` disclaims"
    );
}

// ---- §2 stretches: the second record, the predecessor read, the run read ----

#[test]
fn stage_stretch_admits_a_fresh_range_and_the_fold_answers_every_byte() {
    // store.rs (`stage_stretch`, `apply_stretch`, `value_at`): one record for
    // N consecutive single-byte values — the first address and the bytes, the
    // record's accessors reporting both and its `Debug` the length alone —
    // and after the fold every address inside it answers its byte as a
    // borrowed one-byte piece, the address past it nothing, and `len` counts
    // the one entry.
    let c = ContentStore::default();
    let rec = stage_stretch(&c, ca(1), bytes(b"hello")).expect("fresh");
    assert_eq!(rec.addr(), &ca(1));
    assert_eq!(rec.bytes(), b"hello");
    assert_eq!(rec.len(), 5);
    assert_eq!(
        format!("{rec:?}"),
        "ContentStretch { first: Tumbler([1, 0, 1, 0, 1, 0, 1, 1]), bytes: 5 bytes }"
    );
    assert!(!c.contains(ca(1).tumbler()), "staging commits nothing");
    let c = c.apply_stretch(&rec);
    assert_eq!(c.len(), 1, "one entry for five addresses");
    for (k, byte) in b"hello".iter().enumerate() {
        let at = ca(1 + k as u32);
        assert!(c.contains(at.tumbler()), "{at} is inside the stretch");
        assert_eq!(
            read_arm(&c, at.tumbler()),
            Some((true, vec![*byte])),
            "{at} answers its byte as a one-byte piece of the stretch"
        );
    }
    assert!(!c.contains(ca(6).tumbler()), "the reach is the first address NOT held");
    assert!(c.value_at(ca(6).tumbler()).is_none());
    assert_eq!(
        format!("{c:?}"),
        "ContentStore { map: {Tumbler([1, 0, 1, 0, 1, 0, 1, 1]): Stretch(5 bytes)} }"
    );
}

#[test]
fn the_predecessor_read_is_sound_across_a_b_tree_leaf_boundary() {
    // store.rs (`at_or_below`): the point read finds the greatest key at or
    // below an address by `range(..=t).next_back()`, which `im` answers by a
    // descent that climbs back to the parent's separator when the child it
    // reached holds no key below the probe — never `get_prev`, whose
    // `lookup_prev` returns such a child's `None` as-is once the map outgrows
    // one 64-key leaf (the false `None` skep-namespace's `query.rs` warns of).
    // So 300 stretches of three bytes put the map several leaves deep, and
    // EVERY address of every stretch — the ones whose predecessor key is the
    // last key of a left leaf included, wherever the leaf edges fall — must
    // answer its byte, and every address between two stretches nothing.
    let mut c = ContentStore::default();
    for k in 0..300u32 {
        // Stretches at ordinals 1, 5, 9, …: three bytes each, a gap of one.
        let first = 1 + 4 * k;
        let b = [b'a' + (k % 26) as u8, b'A' + (k % 26) as u8, b'0' + (k % 10) as u8];
        c = with_stretch(&c, first, &b);
    }
    assert_eq!(c.len(), 300);
    for k in 0..300u32 {
        let first = 1 + 4 * k;
        let b = [b'a' + (k % 26) as u8, b'A' + (k % 26) as u8, b'0' + (k % 10) as u8];
        for (offset, byte) in b.iter().enumerate() {
            let at = ca(first + offset as u32);
            assert_eq!(
                read(&c, at.tumbler()),
                Some(vec![*byte]),
                "a false None (or a wrong byte) at {at}: the predecessor read lost a leaf's last key"
            );
            assert!(c.contains(at.tumbler()), "{at} is covered");
        }
        let gap = ca(first + 3);
        assert_eq!(read(&c, gap.tumbler()), None, "the gap at {gap} holds nothing");
        assert!(!c.contains(gap.tumbler()));
    }
    // And the run read, which stands on the same primitive, covers each
    // stretch from its start and from its interior.
    for k in 0..300u32 {
        let first = 1 + 4 * k;
        assert!(c.pieces(ca(first).tumbler(), &Nat::from(3u32)).covered(), "stretch {k} whole");
        assert!(c.pieces(ca(first + 1).tumbler(), &Nat::from(2u32)).covered(), "stretch {k} tail");
        assert!(!c.pieces(ca(first).tumbler(), &Nat::from(4u32)).covered(), "past stretch {k}");
    }
}

#[test]
fn pieces_walks_an_extent_piece_by_piece_and_says_whether_it_is_covered() {
    // store.rs (`pieces`, `Pieces::covered`): the one run read lends the
    // maximal pieces of `[start, start ⊕ width)` in I-order, each one entry
    // clipped to the window — a stretch entered in its interior clipped at
    // the front, one left at the window's end clipped at the back — stops at
    // the first address no entry covers, and `covered` says whether the width
    // was reached. A zero width is reached at once, and a window starting at
    // an uncovered address yields nothing.
    let c = ContentStore::default();
    let c = with_stretch(&c, 1, b"abcdef"); // 1..=6
    let c = with_value(&c, 7, b"atom"); // 7
    let c = with_stretch(&c, 8, b"xyz"); // 8..=10
    // Entered in the first stretch's interior, out past the third's start.
    assert_eq!(
        pieces_of(&c, ca(2).tumbler(), 8),
        (
            vec![(true, b"bcdef".to_vec()), (false, b"atom".to_vec()), (true, b"xy".to_vec())],
            true
        )
    );
    // Exactly the three entries.
    assert_eq!(
        pieces_of(&c, ca(1).tumbler(), 10),
        (
            vec![(true, b"abcdef".to_vec()), (false, b"atom".to_vec()), (true, b"xyz".to_vec())],
            true
        )
    );
    // One byte inside a stretch; one value alone.
    assert_eq!(pieces_of(&c, ca(4).tumbler(), 1), (vec![(true, b"d".to_vec())], true));
    assert_eq!(pieces_of(&c, ca(7).tumbler(), 1), (vec![(false, b"atom".to_vec())], true));
    // Past the last entry: the pieces up to it, then not covered.
    assert_eq!(
        pieces_of(&c, ca(9).tumbler(), 5),
        (vec![(true, b"yz".to_vec())], false),
        "the walk stops at the first address no entry covers"
    );
    // Starting at an uncovered address: nothing, not covered.
    assert_eq!(pieces_of(&c, ca(11).tumbler(), 1), (vec![], false));
    assert_eq!(pieces_of(&ContentStore::default(), ca(1).tumbler(), 1), (vec![], false));
    // A zero width is reached at once.
    assert_eq!(pieces_of(&c, ca(11).tumbler(), 0), (vec![], true));
    // The pieces are borrowed from the stored allocations, never copied.
    let mut walk = c.pieces(ca(1).tumbler(), &Nat::from(6u32));
    let Some(Piece::Bytes(first)) = walk.next() else { panic!("the first piece is the stretch") };
    let stored = c.iter().find(|(at, _)| **at == ca(1)).map(|(_, p)| p.as_bytes().as_ptr());
    assert_eq!(stored, Some(first.as_ptr()), "the piece lends the stretch's own bytes");
}

#[test]
fn pieces_crosses_the_seam_between_stretch_value_and_stretch_inside_one_run() {
    // THE SEAM: the mixed insert `["abc", {"atom":"X"}, "def"]` — one run by
    // I-adjacency, three entries — read as one extent: three pieces of widths
    // 3, 1 and 3, each beginning where the last reached, and covered. The
    // place a stop condition's off-by-one would hide, at both grains: the
    // whole run, and each seam crossed from one byte before it.
    let c = ContentStore::default();
    let c = with_stretch(&c, 1, b"abc");
    let c = with_value(&c, 4, b"X");
    let c = with_stretch(&c, 5, b"def");
    let (parts, covered) = pieces_of(&c, ca(1).tumbler(), 7);
    assert!(covered);
    assert_eq!(
        parts,
        vec![(true, b"abc".to_vec()), (false, b"X".to_vec()), (true, b"def".to_vec())]
    );
    assert_eq!(parts.iter().map(|(_, b)| b.len()).collect::<Vec<_>>(), [3, 1, 3]);
    assert_eq!(
        pieces_of(&c, ca(3).tumbler(), 3),
        (vec![(true, b"c".to_vec()), (false, b"X".to_vec()), (true, b"d".to_vec())], true),
        "both seams crossed from one byte before the first"
    );
    assert_eq!(
        pieces_of(&c, ca(4).tumbler(), 2),
        (vec![(false, b"X".to_vec()), (true, b"d".to_vec())], true),
        "the value, then the stretch's first byte"
    );
    assert_eq!(
        pieces_of(&c, ca(3).tumbler(), 2),
        (vec![(true, b"c".to_vec()), (false, b"X".to_vec())], true),
        "the stretch's last byte, then the value"
    );
}

#[test]
fn stage_stretch_refuses_an_empty_stretch_then_a_covered_first_address_then_an_overlap() {
    // store.rs (`stage_stretch`'s `# Errors`): three refusals in order. An
    // empty stretch is refused before anything is read, even at a stored
    // address; a first address that is covered — a stored key, or an address
    // inside a stored stretch's reach — is `AlreadyStored`; a window reaching
    // over a stored key — a value's or a stretch's — is `Overlap`, naming the
    // first address and the reach.
    let c = ContentStore::default();
    let c = with_stretch(&c, 1, b"abc"); // 1..=3
    let c = with_value(&c, 10, b"atom"); // 10
    let c = with_stretch(&c, 20, b"xyz"); // 20..=22
    assert_eq!(stage_stretch(&c, ca(50), bytes(b"")).unwrap_err(), ContentError::EmptyStretch);
    assert_eq!(
        stage_stretch(&c, ca(1), bytes(b"")).unwrap_err(),
        ContentError::EmptyStretch,
        "the empty check speaks before the stored one"
    );
    assert_eq!(ContentError::EmptyStretch.to_string(), "a content stretch of zero bytes");
    for (what, first) in [("a stored key", 1), ("an address inside a stretch", 2), ("a value", 10)]
    {
        assert_eq!(
            stage_stretch(&c, ca(first), bytes(b"q")).unwrap_err(),
            ContentError::AlreadyStored(ca(first).tumbler().clone()),
            "{what} is already stored"
        );
    }
    // Windows reaching over the value at 10 and over the stretch at 20.
    for (what, first, b) in [
        ("over the value", 8, &b"abcd"[..]), // 8..=11 holds 10
        ("up to the value", 9, &b"ab"[..]),  // 9..=10 holds 10
        ("over the stretch's start", 18, &b"abc"[..]), // 18..=20 holds 20
    ] {
        let err = stage_stretch(&c, ca(first), bytes(b)).unwrap_err();
        let reach = skep_address::shift(ca(first).tumbler(), &Nat::from(b.len()));
        assert_eq!(
            err,
            ContentError::Overlap { first: ca(first).tumbler().clone(), reach: reach.clone() },
            "{what}"
        );
        assert_eq!(
            err.to_string(),
            format!(
                "a content stretch from {} up to {reach} overlaps a stored entry (S0 content \
                 immutability)",
                ca(first).tumbler()
            )
        );
    }
    // A window ending exactly at a stored key is admitted: the reach is the
    // first address the stretch does NOT hold.
    assert!(stage_stretch(&c, ca(4), bytes(b"abcdef")).is_ok(), "4..=9 touches 10 and no more");
    assert!(stage_stretch(&c, ca(11), bytes(b"abcdefghi")).is_ok(), "11..=19 stops short of 20");
}

#[test]
#[cfg_attr(
    debug_assertions,
    should_panic(expected = "already stored in the slice it is folded into")
)]
fn apply_stretch_never_replaces_a_stored_entry_and_panics_on_the_attempt_in_debug() {
    // S0(b) generalized (store.rs, `apply_stretch`): two stretches staged
    // against one slice overlap — the second's first address is covered by
    // the first — so folding the second after the first panics in a debug
    // build and, in release, leaves the slice equal to the receiver: no
    // stored byte changes on any build, the stored stretch wins. The same for
    // a stretch whose window reaches over a stored value — staged against the
    // empty slice, since the door refuses it against one holding the value:
    // the release fold drops it whole.
    let c0 = with_value(&ContentStore::default(), 9, b"atom");
    let first = stage_stretch(&c0, ca(1), bytes(b"abcd")).expect("fresh in c0");
    let second = stage_stretch(&c0, ca(3), bytes(b"xyz")).expect("still fresh in c0");
    let over = stage_stretch(&ContentStore::default(), ca(6), bytes(b"pqrstu"))
        .expect("fresh in the empty slice: 6..=11, over the value at 9 in c0");
    let c1 = c0.apply_stretch(&first);
    let c2 = c1.apply_stretch(&second);
    assert_eq!(c2, c1, "a stretch at a covered address changed the slice it was folded into");
    let c3 = c2.apply_stretch(&over);
    assert_eq!(c3, c2, "a stretch reaching over a stored value changed the slice");
    for (ordinal, byte) in (1..).zip(b"abcd") {
        assert_eq!(read(&c3, ca(ordinal).tumbler()), Some(vec![*byte]));
    }
    assert_eq!(read(&c3, ca(9).tumbler()), Some(b"atom".to_vec()));
    assert_eq!(read(&c3, ca(6).tumbler()), None);
}

#[test]
fn another_chains_address_whose_predecessor_is_a_stretch_answers_nothing() {
    // THE CROSS-CHAIN CASE (store.rs, `value_at`'s chain test): the greatest
    // key at or below document 2's first content address is document 1's
    // stretch, and the stretch answers for its own chain alone — equal
    // component counts, every component but the last equal — so `value_at`
    // answers `None`, `contains` `false`, and `pieces` stops uncovered; the
    // same at a version document's content address beneath the stretch's
    // document, which sorts between its content keys and document 2's.
    let c = with_stretch(&ContentStore::default(), 1, b"abcdefgh");
    for (what, other) in [
        ("document 2's first content address", a(&[1, 0, 1, 0, 2, 0, 1, 1])),
        ("a version document's content address", a(&[1, 0, 1, 0, 1, 1, 0, 1, 2])),
        ("document 1's first link address", a(&[1, 0, 1, 0, 1, 0, 2, 1])),
    ] {
        assert_eq!(c.value_at(other.tumbler()), None, "{what} answered a byte of the stretch");
        assert!(!c.contains(other.tumbler()), "{what} is not covered");
        assert_eq!(
            pieces_of(&c, other.tumbler(), 1),
            (vec![], false),
            "the run read at {what} stops at once"
        );
    }
    // And the stretch itself still answers every byte.
    for (ordinal, byte) in (1..).zip(b"abcdefgh") {
        assert_eq!(read(&c, ca(ordinal).tumbler()), Some(vec![*byte]));
    }
}

#[test]
fn an_address_inside_a_stretch_is_already_stored_at_both_doors_and_contains_answers_true() {
    // THE INTERIOR DOOR (S3★'s moved meaning): `contains` is coverage, so an
    // address inside a stored stretch's reach is "already stored" — refused
    // `AlreadyStored` by `stage_write` and by `stage_stretch`, as a key is —
    // and `contains` answers `true` there while `value_at` answers the byte.
    let c = with_stretch(&ContentStore::default(), 3, b"abcd"); // 3..=6
    for ordinal in 3..=6u32 {
        let at = ca(ordinal);
        assert!(c.contains(at.tumbler()), "{at} is covered");
        assert_eq!(
            stage_write(&c, at.clone(), val(b"x")).unwrap_err(),
            ContentError::AlreadyStored(at.tumbler().clone())
        );
        assert_eq!(
            stage_stretch(&c, at.clone(), bytes(b"x")).unwrap_err(),
            ContentError::AlreadyStored(at.tumbler().clone())
        );
    }
    for ordinal in [2u32, 7] {
        let at = ca(ordinal);
        assert!(!c.contains(at.tumbler()), "{at} is outside the reach");
        assert!(stage_write(&c, at.clone(), val(b"x")).is_ok());
    }
}

#[test]
fn the_interloper_key_inside_a_stretchs_reach_is_refused_at_both_doors_and_by_the_decoder() {
    // THE INTERLOPER: the nine-component key `D·0·1·3·7` — T4-valid, minted
    // by nothing — sorts between `D·0·1·3` and `D·0·1·4`, so inside a stretch
    // at `D·0·1·3` of four bytes it would be the predecessor of every later
    // byte and shadow them. "Inside a stretch" is tumbler-interval containment
    // whatever the key's length or chain, so it is refused at `stage_write`
    // (`AlreadyStored`, coverage), at `stage_stretch` (`AlreadyStored` at it;
    // `Overlap` for a stretch below it reaching past it, where it stands
    // alone), and by the slice's decoder (a body holding both refused) —
    // while `value_at` at every address of the stretch answers its byte,
    // `contains` of the interloper answers `true` (covered, no value of its
    // own: coverage and presence part here, off the chain) and `pieces` over
    // the stretch covers.
    let interloper = a(&[1, 0, 1, 0, 1, 0, 1, 3, 7]);
    let c = with_stretch(&ContentStore::default(), 3, b"abcd"); // 3..=6
    assert_eq!(
        stage_write(&c, interloper.clone(), val(b"x")).unwrap_err(),
        ContentError::AlreadyStored(interloper.tumbler().clone())
    );
    assert_eq!(
        stage_stretch(&c, interloper.clone(), bytes(b"xy")).unwrap_err(),
        ContentError::AlreadyStored(interloper.tumbler().clone())
    );
    assert!(c.contains(interloper.tumbler()), "covered by the reach");
    assert_eq!(c.value_at(interloper.tumbler()), None, "off the chain: no value of its own");
    for (ordinal, byte) in (3..).zip(b"abcd") {
        assert_eq!(read(&c, ca(ordinal).tumbler()), Some(vec![*byte]));
    }
    assert!(c.pieces(ca(3).tumbler(), &Nat::from(4u32)).covered());
    // Standing alone as a value — admitted, nothing covers it — the interloper
    // refuses a stretch below it whose window reaches past it, by tumbler
    // order: `D·0·1·3 ≤ D·0·1·3·7 < D·0·1·7`.
    let alone = ContentStore::default()
        .apply_write(&stage_write(&ContentStore::default(), interloper.clone(), val(b"i")).expect("fresh"));
    assert_eq!(
        stage_stretch(&alone, ca(3), bytes(b"abcd")).unwrap_err(),
        ContentError::Overlap {
            first: ca(3).tumbler().clone(),
            reach: ca(7).tumbler().clone(),
        }
    );
    assert!(stage_stretch(&alone, ca(1), bytes(b"ab")).is_ok(), "1..=2 stops short of it");
    // The decoder: a body holding the stretch and the interloper beneath it
    // is refused for the overlap, whichever order the two arrive in — and
    // the release fold of a stretch over an interloper drops the stretch.
    #[derive(serde::Serialize)]
    enum RawStored {
        Value(Vec<u8>),
        Stretch(Vec<u8>),
    }
    let key = |addr: &Address| -> Vec<Nat> { addr.tumbler().iter().cloned().collect() };
    for order in [
        vec![(key(&ca(3)), RawStored::Stretch(b"abcd".to_vec())), (key(&interloper), RawStored::Value(b"i".to_vec()))],
        vec![(key(&interloper), RawStored::Value(b"i".to_vec())), (key(&ca(3)), RawStored::Stretch(b"abcd".to_vec()))],
    ] {
        let body = bincode::serialize(&order).expect("the raw slice serializes");
        let refusal = bincode::deserialize::<ContentStore>(&body)
            .expect_err("a body holding a key inside a stretch's reach is refused")
            .to_string();
        assert_eq!(refusal, "a content stretch overlapping its neighbour in one slice");
    }
}

#[test]
#[cfg_attr(debug_assertions, should_panic(expected = "or inside a stored stretch"))]
fn apply_write_drops_an_on_chain_write_inside_a_stored_stretch_and_the_bytes_above_still_answer() {
    // The fold's "already stored" is the predecessor read, the same test as
    // its door: a `ContentWrite` at an ON-CHAIN address inside a stored
    // stretch's reach — built by hand in the shape `raw_record` pins, since
    // the door never admits one — folded through `apply_write` in a release
    // build leaves the slice equal to the receiver, and `value_at` at every
    // LATER byte of the stretch still answers its byte. An exact-key fold
    // would land the value at the interior key, where it would be the
    // predecessor of every later byte and answer `None` for each — the bytes
    // shadowed, which "no stored byte changes" does not cover. A debug build
    // fail-stops on the fold's own message.
    let c0 = with_stretch(&ContentStore::default(), 3, b"abcdef"); // 3..=8
    let key: Vec<Nat> = ca(5).tumbler().iter().cloned().collect();
    let interior: ContentWrite = bincode::deserialize(
        &bincode::serialize(&(key, b"X".to_vec())).expect("the raw record serializes"),
    )
    .expect("a record's bytes are its address, then its value");
    assert_eq!(interior.addr(), &ca(5));
    let c1 = c0.apply_write(&interior);
    assert_eq!(c1, c0, "a write inside a stored stretch changed the slice it was folded into");
    for (ordinal, byte) in (3..).zip(b"abcdef") {
        assert_eq!(
            read_arm(&c1, ca(ordinal).tumbler()),
            Some((true, vec![*byte])),
            "the byte at ordinal {ordinal} is shadowed"
        );
    }
    assert!(c1.pieces(ca(3).tumbler(), &Nat::from(6u32)).covered());
}

// ---- §Types: Val, Piece, and Debug over the types that hold one ----

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
fn val_shares_its_bytes_with_every_clone_and_never_copies_them() {
    // value.rs: "a clone shares the bytes and never copies them, so it is
    // O(1) however long the value" — what a fold's node copies, M5's
    // re-inserts and M6's delivery, which hands a value out once per position
    // it is arranged at, all rest on. So a clone's bytes sit in the very
    // memory its original's do, for one byte — the value INSERT stores per
    // address — as for a megabyte, an atom's size. Not for zero bytes: an
    // empty buffer's address can be a placeholder a copy shares, so there
    // the test could not fail.
    for len in [1usize, 1 << 20] {
        let v = Val::new(vec![0x5au8; len]);
        assert!(
            std::ptr::eq(value_memory(v.as_bytes()), value_memory(v.clone().as_bytes())),
            "a clone of a {len}-byte value copied its bytes"
        );
    }
}

#[test]
fn val_implements_no_hash_so_no_map_can_key_on_a_value() {
    // value.rs, S4: identity is by address, never by value, and `Val` keeps it
    // so by implementing no `Hash` — no map, this crate's or a caller's, can
    // key on a value. `implements!` reads that; `Address`, what M4 keys
    // content by, which does implement `Hash`, is the control that it can read
    // `true` at all.
    assert!(
        implements!(Address: std::hash::Hash),
        "the probe reads `false` even for a type that implements Hash"
    );
    assert!(
        !implements!(Val: std::hash::Hash),
        "Val implements Hash: a map can key on a value, where S4 keys content by its address"
    );
}

#[test]
fn a_value_is_stored_and_read_back_exactly_as_written_whatever_its_bytes() {
    // value.rs: M4 is value-oblivious — it never inspects a value's bytes, so
    // any byte string is a value and comes back exactly as written: the
    // zero-length one, a single byte, and bytes that are no text at all; and
    // a stretch's bytes come back the same way, byte by byte. Each folds from
    // its journaled record and reads back from the slice and from its
    // checkpoint form; a zero-length value is content stored like any other.
    let written: [&[u8]; 3] = [b"", &[0x00], &[0xff, 0xfe, 0x80]];
    let mut c = ContentStore::default();
    for (ordinal, bytes) in (1..).zip(written) {
        let rec = stage_write(&c, ca(ordinal), val(bytes)).expect("fresh");
        let replayed: ContentWrite =
            bincode::deserialize(&bincode::serialize(&rec).expect("record serializes"))
                .expect("record decodes");
        c = c.apply_write(&replayed);
    }
    let run: &[u8] = &[0x00, 0xff, b'a', 0x80];
    let stretch = stage_stretch(&c, ca(4), bytes(run)).expect("fresh");
    let replayed: ContentStretch =
        bincode::deserialize(&bincode::serialize(&stretch).expect("record serializes"))
            .expect("record decodes");
    assert_eq!(replayed, stretch);
    c = c.apply_stretch(&replayed);
    let checkpointed: ContentStore =
        bincode::deserialize(&bincode::serialize(&c).expect("slice serializes"))
            .expect("slice decodes");
    for (ordinal, bytes) in (1..).zip(written) {
        let addr = ca(ordinal);
        for (form, slice) in [("folded", &c), ("checkpointed", &checkpointed)] {
            assert!(
                slice.contains(addr.tumbler()),
                "{form}: a {}-byte value is not stored",
                bytes.len()
            );
            assert_eq!(
                read(slice, addr.tumbler()),
                Some(bytes.to_vec()),
                "{form}: a {}-byte value came back changed",
                bytes.len()
            );
        }
    }
    for (offset, byte) in run.iter().enumerate() {
        let addr = ca(4 + offset as u32);
        for (form, slice) in [("folded", &c), ("checkpointed", &checkpointed)] {
            assert_eq!(read(slice, addr.tumbler()), Some(vec![*byte]), "{form}: a stretch byte");
        }
    }
    assert_eq!(checkpointed, c);
}

#[test]
fn a_stretch_of_zero_bytes_is_refused_at_the_records_decode() {
    // store.rs (`ContentStretch`'s decode shadow): a stretch of no bytes is
    // refused where it is decoded, as the door refuses it — a frame M2
    // reports as corruption rather than an entry the slice's own decoder
    // would refuse at the next checkpoint. The control, one byte, decodes.
    let key: Vec<Nat> = ca(1).tumbler().iter().cloned().collect();
    let empty = bincode::serialize(&(key.clone(), Vec::<u8>::new())).expect("serializes");
    let refusal = bincode::deserialize::<ContentStretch>(&empty)
        .expect_err("a stretch of zero bytes is refused")
        .to_string();
    assert_eq!(refusal, "a content stretch of zero bytes");
    let one = bincode::serialize(&(key, b"x".to_vec())).expect("serializes");
    let decoded: ContentStretch = bincode::deserialize(&one).expect("one byte decodes");
    assert_eq!((decoded.addr(), decoded.bytes()), (&ca(1), &b"x"[..]));
}

#[test]
fn a_piece_lends_its_bytes_and_owns_a_value_only_when_asked() {
    // store.rs (`Piece`): the one borrowed answer of every read — `as_bytes`
    // lends the stored bytes, a stretch's one byte or a value's whole; `to_val`
    // owns them, a refcount bump for a value (the same allocation) and a new
    // allocation for a run of bytes; `Debug` renders the kind and the length,
    // never a byte.
    let c = with_stretch(&ContentStore::default(), 1, b"ab");
    let c = with_value(&c, 3, b"secret");
    let inside = c.value_at(ca(2).tumbler()).expect("inside the stretch");
    assert_eq!(inside.as_bytes(), b"b");
    assert_eq!(inside.to_val(), Val::new(b"b".as_slice()));
    assert_eq!(format!("{inside:?}"), "Bytes(1 bytes)");
    let whole = c.value_at(ca(3).tumbler()).expect("the value");
    assert_eq!(whole.as_bytes(), b"secret");
    assert!(
        std::ptr::eq(whole.to_val().as_bytes().as_ptr(), whole.as_bytes().as_ptr()),
        "to_val of a value shares the stored allocation"
    );
    assert_eq!(format!("{whole:?}"), "Value(6 bytes)");
    assert_eq!(
        format!("{:?}", c.pieces(ca(1).tumbler(), &Nat::from(2u32)).next()),
        "Some(Bytes(2 bytes))"
    );
}

#[test]
fn debug_renders_a_value_by_its_byte_length_never_its_bytes() {
    // §Types/§A: `Val`'s `Debug` is its byte length, so the records and the
    // slice, deriving or writing theirs, render addresses and lengths and
    // never a byte — a value entry as `Value(n bytes)`, a stretch as
    // `Stretch(n bytes)`.
    assert_eq!(format!("{:?}", val(b"secret")), "6 bytes");
    let rec = stage_write(&ContentStore::default(), ca(7), val(b"abc")).expect("fresh");
    assert_eq!(
        format!("{rec:?}"),
        "ContentWrite { addr: Tumbler([1, 0, 1, 0, 1, 0, 1, 7]), val: 3 bytes }"
    );
    let c = ContentStore::default().apply_write(&rec);
    assert_eq!(
        format!("{c:?}"),
        "ContentStore { map: {Tumbler([1, 0, 1, 0, 1, 0, 1, 7]): Value(3 bytes)} }"
    );
    let c = with_stretch(&c, 1, b"ab");
    assert_eq!(
        format!("{c:?}"),
        "ContentStore { map: {Tumbler([1, 0, 1, 0, 1, 0, 1, 1]): Stretch(2 bytes), \
         Tumbler([1, 0, 1, 0, 1, 0, 1, 7]): Value(3 bytes)} }"
    );
}

// The routing assertion at the stage doors (Open build decision #4) is a
// debug_assert!: it fires only in debug builds.
#[cfg(debug_assertions)]
mod routing {
    use super::*;

    #[test]
    #[should_panic(expected = "content routing: stage_write")]
    fn stage_write_asserts_against_a_link_subspace_address() {
        let link_elem = a(&[1, 0, 1, 0, 1, 0, 2, 1]); // subspace s_L = 2
        let _ = stage_write(&ContentStore::default(), link_elem, val(b"x"));
    }

    #[test]
    #[should_panic(expected = "content routing: stage_write")]
    fn stage_write_asserts_against_a_subspace_neither_content_nor_link() {
        // Routing admits s_C = 1 alone — not "every subspace but s_L = 2".
        let elem = a(&[1, 0, 1, 0, 1, 0, 3, 1]); // subspace 3
        let _ = stage_write(&ContentStore::default(), elem, val(b"x"));
    }

    #[test]
    #[should_panic(expected = "content routing: stage_write")]
    fn stage_write_asserts_against_a_non_element_address() {
        let doc = a(&[1, 0, 1, 0, 1]);
        let _ = stage_write(&ContentStore::default(), doc, val(b"x"));
    }

    #[test]
    #[should_panic(expected = "content routing: stage_write")]
    fn stage_write_asserts_routing_before_it_checks_what_is_stored() {
        // §C: the routing assertion runs BEFORE the already-stored check, so a
        // mis-routed address panics on its own terms even where a value is
        // stored at it — never an `AlreadyStored`, which reads as an address
        // minted twice and sends its reader to M3. A debug build cannot stage
        // such a value, so it arrives as M2's replay hands one over: a record
        // decoded from bytes, as a release build — its assertion compiled
        // out — journaled it.
        let link_elem = a(&[1, 0, 1, 0, 1, 0, 2, 1]); // subspace s_L = 2
        let replayed: ContentWrite = bincode::deserialize(
            &bincode::serialize(&(link_elem.tumbler(), b"x".to_vec())).expect("pair serializes"),
        )
        .expect("a record's bytes are its address, then its value");
        let c = ContentStore::default().apply_write(&replayed);
        assert!(c.contains(link_elem.tumbler()), "the replayed record's value is stored");
        let _ = stage_write(&c, link_elem, val(b"y"));
    }

    #[test]
    #[should_panic(expected = "content routing: stage_stretch")]
    fn stage_stretch_asserts_routing_after_the_empty_check_and_before_the_stored_ones() {
        // store.rs (`stage_stretch`'s `# Panics`): the routing assertion runs
        // after the zero-length check — an empty stretch at a mis-routed
        // address is `EmptyStretch`, read first — and before the two stored
        // checks, so a mis-routed first address panics on its own terms.
        let link_elem = a(&[1, 0, 1, 0, 1, 0, 2, 1]); // subspace s_L = 2
        assert_eq!(
            stage_stretch(&ContentStore::default(), link_elem.clone(), bytes(b"")).unwrap_err(),
            ContentError::EmptyStretch
        );
        let _ = stage_stretch(&ContentStore::default(), link_elem, bytes(b"x"));
    }
}

// The assertion's other edge: release compiles it out and trusts the
// caller's routing, so a release build stages every address it stops in a
// debug build as given — the stage doors' twin of the decode admitting every
// one (recovery.rs).
#[cfg(not(debug_assertions))]
#[test]
fn stage_write_stages_every_mis_routed_address_as_given_in_release() {
    // store.rs (`stage_write`, `stage_stretch`, and `ContentStore`'s second
    // key invariant): a content-subspace element address — C1's element LEVEL
    // and L0's content SUBSPACE — is the caller's to guarantee, and a release
    // build stages a violator of either half as given. `write`'s release test
    // commits a document address, the level half through `write`'s door; here
    // each shape in `MIS_ROUTED` goes through both stage doors: its record
    // carries the address it was handed, and the fold stores the bytes there.
    for &(shape, key) in MIS_ROUTED {
        let addr = a(key);
        let rec = stage_write(&ContentStore::default(), addr.clone(), val(b"x")).unwrap_or_else(
            |refusal| panic!("a release build refused to stage {shape}: {refusal}"),
        );
        assert_eq!(rec.addr(), &addr, "a release build staged {shape} at another address");
        assert_eq!(
            read(&ContentStore::default().apply_write(&rec), addr.tumbler()),
            Some(b"x".to_vec()),
            "a release build did not store the value staged at {shape}"
        );
        let stretch = stage_stretch(&ContentStore::default(), addr.clone(), bytes(b"yz"))
            .unwrap_or_else(|refusal| panic!("a release build refused a stretch at {shape}: {refusal}"));
        assert_eq!(stretch.addr(), &addr, "a release build staged a stretch at another address");
        assert_eq!(
            read(&ContentStore::default().apply_stretch(&stretch), addr.tumbler()),
            Some(b"y".to_vec()),
            "a release build did not store the stretch staged at {shape}"
        );
    }
}
