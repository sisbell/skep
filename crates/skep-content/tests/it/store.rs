//! The slice and its write step, with no kernel: what the already-stored
//! check admits and rejects; that the fold is pure and insert-only, shares
//! every address the slice already stores, and never replaces a stored
//! value — it leaves the whole slice as it was, and panics on the attempt in
//! debug builds; that a point query matches its address exactly, never a
//! prefix or an extension; that identity is by address, never by value, and
//! `Val` implements no `Hash` (S4); that a slice's equality is its contents',
//! address and value each counting; that the one enumeration visits every
//! entry once, through `iter` and through a `for` loop over the slice alike,
//! as a walk a caller can name, which knows exactly what remains at every
//! step, shows no entry in its `Debug`, and offers no walk from the far end;
//! that any byte string is a value, comes back exactly as written, and
//! renders into `Debug` as its byte length, never a byte; and that
//! `stage_write` panics on a non-content address in debug builds, before it
//! looks at what is stored there, and stages every such address as given in
//! release.

use skep_address::{Nat, Tumbler};
use skep_content::{stage_write, ContentError, ContentStore, ContentWrite, Iter, Val};

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
    // The already-stored check (§Invariants): an address with a value already
    // stored is a typed rejection.
    let c = ContentStore::default();
    let a1 = ca(1);
    let c = c.apply_write(&stage_write(&c, &a1, val(b"first")).expect("fresh"));
    let err = stage_write(&c, &a1, val(b"second")).unwrap_err();
    assert_eq!(err, ContentError::AlreadyStored(a1.tumbler().clone()));
    // The message names the address dotted, as M1 renders one, and leaves
    // "rejected" to whichever wrapper carries it.
    assert_eq!(
        err.to_string(),
        "a value is already stored at 1.0.1.0.1.0.1.1 (S0 content immutability)"
    );
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
fn apply_write_shares_every_address_the_slice_already_stores() {
    // store.rs (`ContentStore`, the `map` field): a fold copies the tree
    // nodes on its path, up to 64 entries each, and shares everything else —
    // the addresses in the copied nodes included. A copy that cloned each of
    // those addresses component by component would make every write pay for
    // up to 64 addresses per level of the tree, a cost set by the longest
    // addresses stored near it, which an INSERT multiplies by its value count
    // under M2's applier lock and every replay pays again. So each address
    // the old slice stores keeps, in the new slice, the very components it
    // had — one storage, not a copy. 257 entries put the tree past one node,
    // so the fold copies an inner node as well as a leaf.
    let components = |addr: &Tumbler| -> *const Nat {
        std::ptr::from_ref(addr.iter().next().expect("a tumbler is nonempty"))
    };
    let mut c0 = ContentStore::default();
    for ordinal in 1..=257u32 {
        c0 = c0.apply_write(&stage_write(&c0, &ca(ordinal), val(b"v")).expect("fresh"));
    }
    let stored: std::collections::BTreeMap<&Tumbler, *const Nat> =
        c0.iter().map(|(addr, _)| (addr, components(addr))).collect();
    let c1 = c0.apply_write(&stage_write(&c0, &ca(258), val(b"v")).expect("fresh"));
    let mut shared = 0;
    for (addr, _) in &c1 {
        if let Some(&before) = stored.get(addr) {
            assert!(
                std::ptr::eq(before, components(addr)),
                "the fold copied {addr}, an address the slice already stored"
            );
            shared += 1;
        }
    }
    assert_eq!(shared, 257, "the new slice holds every address the old one stored");
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
    // its value. Each half counts on its own: one address holding two values,
    // and one value at two addresses, are two records and two slices.
    let c0 = ContentStore::default();
    let r1 = stage_write(&c0, &ca(1), val(b"one")).expect("fresh");
    let r2 = stage_write(&c0, &ca(2), val(b"two")).expect("fresh");
    assert_eq!(c0.apply_write(&r1).apply_write(&r2), c0.apply_write(&r2).apply_write(&r1));
    assert_ne!(c0.apply_write(&r1), c0.apply_write(&r2));
    let other = stage_write(&c0, &ca(1), val(b"uno")).expect("fresh");
    assert_ne!(r1, other, "one address, two values: two records");
    assert_ne!(c0.apply_write(&r1), c0.apply_write(&other));
    let elsewhere = stage_write(&c0, &ca(2), val(b"one")).expect("fresh");
    assert_ne!(r1, elsewhere, "one value at two addresses: two records");
    assert_ne!(
        c0.apply_write(&r1),
        c0.apply_write(&elsewhere),
        "one value at two addresses: two slices (S4)"
    );
}

// ---- §B the one enumeration ----

#[test]
fn iter_visits_every_entry_of_a_pinned_slice_exactly_once() {
    // The one enumeration beside the point queries: every pair once, its
    // count the slice's, over a pinned slice while a later slice grows —
    // the cell index's walk reads a snapshot this way while commits
    // proceed — and a `for` loop over `&c` reads the same walk. The order is
    // no part of its promise (store.rs, `iter`) —
    // `iter_offers_no_walk_from_the_far_end_so_it_promises_no_order` defends
    // that — so this test asserts the SET and the count, never a sequence.
    let c0 = ContentStore::default();
    assert_eq!(c0.iter().len(), 0);
    assert!(c0.iter().next().is_none());
    let mut c = c0.clone();
    let n = 257u32; // past one B-tree node, so the walk crosses levels
    for ordinal in 1..=n {
        let rec =
            stage_write(&c, &ca(ordinal), val(format!("v{ordinal}").as_bytes())).expect("fresh");
        c = c.apply_write(&rec);
    }
    let later = c.apply_write(&stage_write(&c, &ca(n + 1), val(b"later")).expect("fresh"));
    let walk = c.iter();
    assert_eq!(walk.len(), n as usize, "exact-size: the slice's count");
    let mut seen = std::collections::BTreeSet::new();
    for (addr, v) in walk {
        let ordinal = u32::try_from(skep_address::ordinal(addr)).expect("ca's ordinal is a u32");
        assert_eq!(v.as_bytes(), format!("v{ordinal}").as_bytes(), "the pair is the stored one");
        assert!(seen.insert(ordinal), "an entry is visited once");
        assert!(c.contains(addr), "every address walked is in the slice");
    }
    assert_eq!(seen.len(), n as usize, "every entry is visited");
    let mut looped = std::collections::BTreeSet::new();
    for (addr, v) in &c {
        assert_eq!(
            c.value_at(addr).map(Val::as_bytes),
            Some(v.as_bytes()),
            "a loop over `&c` yields the stored pair"
        );
        assert!(looped.insert(addr), "a loop over `&c` visits an entry once");
    }
    assert_eq!(looped.len(), n as usize, "a loop over `&c` visits every entry");
    assert_eq!(later.iter().len(), n as usize + 1, "a later slice walks its own entry too");
    assert_eq!(c.iter().len(), n as usize, "and the pinned slice is untouched by it");
}

#[test]
fn iter_lends_a_named_walk_that_knows_its_length_and_shows_no_entry() {
    // store.rs, `Iter`: `iter` lends an `Iter`, whose backing is hidden and
    // to which a foreign crate can add no trait — so what the loan promises
    // is witnessed from one: a type a caller can name, the exact length,
    // `Debug`, and `Send + Sync`, which the type has because of what it
    // borrows and which a caller handing a walk to another thread depends on
    // without any signature saying so. `&ContentStore` yields the same type,
    // and its `Debug` names the walk, never an entry.
    fn lends<'a, I>(walk: I) -> usize
    where
        I: ExactSizeIterator<Item = (&'a Tumbler, &'a Val)> + std::fmt::Debug + Send + Sync,
    {
        walk.len()
    }
    let c0 = ContentStore::default();
    let c = c0.apply_write(&stage_write(&c0, &ca(1), val(b"secret")).expect("fresh"));
    let walk: Iter<'_> = c.iter();
    assert_eq!(format!("{walk:?}"), "Iter { .. }", "the walk, never an entry");
    assert_eq!(lends(walk), 1);
    let loop_walk: Iter<'_> = IntoIterator::into_iter(&c);
    assert_eq!(lends(loop_walk), 1, "`&ContentStore` lends the same walk");
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
            c = c.apply_write(&stage_write(&c, &ca(ordinal), val(b"v")).expect("fresh"));
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
fn val_implements_no_hash_so_no_map_can_key_on_a_value() {
    // value.rs, S4: identity is by address, never by value, and `Val` keeps it
    // so by implementing no `Hash` — no map, this crate's or a caller's, can
    // key on a value. `implements!` reads that; `Tumbler`, M4's key, which
    // does implement `Hash`, is the control that it can read `true` at all.
    assert!(
        implements!(Tumbler: std::hash::Hash),
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
        let addr = ca(ordinal);
        for (form, slice) in [("folded", &c), ("checkpointed", &checkpointed)] {
            assert!(
                slice.contains(addr.tumbler()),
                "{form}: a {}-byte value is not stored",
                bytes.len()
            );
            assert_eq!(
                slice.value_at(addr.tumbler()).map(Val::as_bytes),
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

// The routing assertion at stage_write's door (Open build decision #4) is a
// debug_assert!: it fires only in debug builds.
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
        let _ = stage_write(&c, &link_elem, val(b"y"));
    }
}

// The assertion's other edge: release compiles it out and trusts the
// caller's routing, so a release build stages every address it stops in a
// debug build as given — the stage door's twin of the decode admitting every
// one (recovery.rs).
#[cfg(not(debug_assertions))]
#[test]
fn stage_write_stages_every_mis_routed_address_as_given_in_release() {
    // store.rs (`stage_write`, and `ContentStore`'s second key invariant): a
    // content-subspace element address — C1's element LEVEL and L0's content
    // SUBSPACE — is the caller's to guarantee, and a release build stages a
    // violator of either half as given. `write`'s release test commits a
    // document address, the level half through `write`'s door; here each
    // shape the debug routing tests stop goes through `stage_write`: its
    // record carries the address it was handed, and the fold stores the
    // value there.
    for (shape, key) in [
        ("a node address", &[1u32][..]),
        ("an account address", &[1, 0, 1][..]),
        ("a document address", &[1, 0, 1, 0, 1][..]),
        ("a link-subspace element address", &[1, 0, 1, 0, 1, 0, 2, 1][..]),
        ("a subspace-3 element address", &[1, 0, 1, 0, 1, 0, 3, 1][..]),
    ] {
        let addr = a(key);
        let rec =
            stage_write(&ContentStore::default(), &addr, val(b"x")).unwrap_or_else(|refusal| {
                panic!("a release build refused to stage {shape}: {refusal}")
            });
        assert_eq!(rec.addr(), addr.tumbler(), "a release build staged {shape} at another address");
        assert_eq!(
            ContentStore::default().apply_write(&rec).value_at(addr.tumbler()).map(Val::as_bytes),
            Some(&b"x"[..]),
            "a release build did not store the value staged at {shape}"
        );
    }
}
