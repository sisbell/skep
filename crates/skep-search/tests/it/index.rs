//! THE WRITE SIDE under the design's fence (`search.md` §1.4): the class
//! check (§2.1), one class per index (§5.2 D7), the ceiling at the real
//! constant (§7.4), replacement and the tombstone (§5.1), prepare under no
//! lock and install by one swap under the embedder's lock (§5.6), the join
//! of a document of twice `MAX_DELIVERY_ITEMS` positions with a character
//! across the parts' edge (§2.1), and the range across a `Gap` and a `hex`
//! stretch with the item found by binary search (§2.3).

use std::sync::{Arc, RwLock, TryLockError};

use skep_search::{
    tokenize, Class, GapKind, Index, IndexError, Item, Kind, Stats, Unit, CEILING_BYTES, REVISION,
};

use crate::{addr, key, text_unit};

/// `MAX_DELIVERY_ITEMS`, the delivery budget one `retrieve_v` is bounded by
/// (`crates/skep-retrieval/src/budget.rs`, `1 << 17`): a document past it is
/// read in parts (§2.1). The number alone is mirrored here; the crate does
/// not depend on the retrieval crate (§1.3).
const MAX_DELIVERY_ITEMS: usize = 1 << 17;

fn guest(n: u32, text: &str) -> Unit {
    text_unit(Class::Guest, n, text.as_bytes())
}

fn terms(index: &Index) -> Vec<String> {
    index.terms().map(str::to_string).collect()
}

/// §2.1 THE CLASS CHECK, STRUCTURAL: a published index refuses a unit read
/// under a principal's session, and a supplement refuses a guest-class unit
/// and another principal's, each refusal naming both classes; the refused
/// unit leaves no trace, not even in `seen`.
#[test]
fn the_class_check_refuses_a_unit_of_another_class_naming_both() {
    let mut published = Index::new(Class::Guest);
    assert_eq!(
        published.index(text_unit(Class::Principal(7), 1, b"a draft's words")),
        Err(IndexError::ClassMismatch { index: Class::Guest, unit: Class::Principal(7) })
    );
    let fresh = Stats {
        units: 0,
        terms: 0,
        postings: 0,
        bytes: 0,
        tombstones: 0,
        dead_postings: 0,
        ceiling: CEILING_BYTES,
        seen: 0,
    };
    assert_eq!(published.stats(), fresh, "nothing entered");
    published.index(guest(1, "published words")).expect("the index's own class is admitted");

    let mut supplement = Index::new(Class::Principal(3));
    assert_eq!(
        supplement.index(guest(2, "published words")),
        Err(IndexError::ClassMismatch { index: Class::Principal(3), unit: Class::Guest })
    );
    assert_eq!(
        supplement.index(text_unit(Class::Principal(4), 2, b"another principal's draft")),
        Err(IndexError::ClassMismatch { index: Class::Principal(3), unit: Class::Principal(4) })
    );
    assert_eq!(supplement.stats(), fresh);
    supplement
        .index(text_unit(Class::Principal(3), 2, b"this principal's draft"))
        .expect("its own class");
    assert_eq!(supplement.stats().units, 1);
}

/// §5.2 D7, ONE CLASS PER INDEX: an index carries exactly one class from
/// `new`, reads it back after every write-side call, and no call of the
/// surface takes a class — the published index and a supplement are two
/// values, never one value with a filter.
#[test]
fn an_index_carries_one_class_from_new_and_no_call_changes_it() {
    for class in [Class::Guest, Class::Principal(1), Class::Principal(u64::MAX)] {
        let mut index = Index::new(class);
        assert_eq!(index.class(), class);
        assert_eq!(index.revision(), REVISION, "cut under the running crate's revision");
        index.merge(Index::prepare(text_unit(class, 1, b"alpha beta"))).expect("admitted");
        assert_eq!(index.class(), class);
        index.index(text_unit(class, 1, b"beta")).expect("replaced");
        assert_eq!(index.class(), class);
        let compacted = index.compacted();
        index.install(compacted);
        assert_eq!(index.class(), class);
        let other = match class {
            Class::Guest => Class::Principal(1),
            Class::Principal(_) => Class::Guest,
        };
        assert!(matches!(
            index.index(text_unit(other, 2, b"x")),
            Err(IndexError::ClassMismatch { index, unit }) if index == class && unit == other
        ));
        assert_eq!(index.class(), class);
    }
}

/// §7.4 THE CEILING, CUT ONCE AT `merge`, at the real constant: a unit that
/// would carry the index past `CEILING_BYTES` is not indexed and nothing
/// changes — the unit it would have replaced is KEPT, its terms still the
/// dictionary's — the error names the bytes held and the limit with the
/// units beside them, and the offer is counted in `seen`; a unit of exactly
/// the ceiling's bytes is at the ceiling, not past it, and is admitted.
#[test]
fn past_the_ceiling_the_unit_is_not_indexed_and_the_unit_it_would_replace_is_kept() {
    let mut index = Index::new(Class::Guest);
    index.index(guest(1, "alpha beta")).expect("admitted");
    index.index(guest(2, "gamma")).expect("admitted");
    let before = index.stats();
    assert_eq!(before.bytes, 15);

    // A replacement of unit 1 past the ceiling: 15 - 10 + (CEILING + 1) > CEILING.
    let oversized = vec![b' '; usize::try_from(CEILING_BYTES).expect("fits") + 1];
    assert_eq!(
        index.index(text_unit(Class::Guest, 1, &oversized)),
        Err(IndexError::PastTheCeiling { held: 15, limit: CEILING_BYTES, units: 2 })
    );
    assert_eq!(
        index.stats(),
        Stats { seen: 1, ..before },
        "nothing indexed, nothing changed but `seen`"
    );
    assert_eq!(
        terms(&index),
        ["alpha", "beta", "gamma"],
        "the unit it would have replaced is kept"
    );
    drop(oversized);

    // At the ceiling exactly, into a fresh index: admitted; one byte more is refused.
    let mut full = Index::new(Class::Guest);
    let at_ceiling = vec![b' '; usize::try_from(CEILING_BYTES).expect("fits")];
    full.index(text_unit(Class::Guest, 1, &at_ceiling)).expect("at the ceiling, not past it");
    drop(at_ceiling);
    assert_eq!(full.stats().bytes, CEILING_BYTES);
    assert_eq!(
        full.index(guest(2, "x")),
        Err(IndexError::PastTheCeiling { held: CEILING_BYTES, limit: CEILING_BYTES, units: 1 })
    );
    assert_eq!(full.stats().seen, 1);
    assert_eq!(full.stats().units, 1);
}

/// §5.1 REPLACEMENT: a key already held is replaced and the replaced unit
/// tombstoned inside `merge` — every statistic and the term list change at
/// once: the unit count holds, the old-only terms leave the dictionary, the
/// new ones enter, the bytes and postings are the new unit's, the tombstone
/// and its dead postings are counted; and compaction then drops the dead
/// with the live counts unmoved.
#[test]
fn a_held_key_is_replaced_and_the_replaced_unit_tombstoned_every_statistic_at_once() {
    let mut index = Index::new(Class::Guest);
    index.index(guest(1, "alpha beta gamma gamma")).expect("admitted");
    index.index(guest(2, "beta")).expect("admitted");
    assert_eq!(terms(&index), ["alpha", "beta", "gamma"]);
    assert_eq!(index.stats().units, 2);
    assert_eq!(index.stats().postings, 5);

    index.index(guest(1, "beta delta")).expect("the re-read's one call");
    assert_eq!(
        index.stats(),
        Stats {
            units: 2,
            terms: 2,
            postings: 3,
            bytes: 14,
            tombstones: 1,
            dead_postings: 4,
            ceiling: CEILING_BYTES,
            seen: 0,
        }
    );
    assert_eq!(terms(&index), ["beta", "delta"], "the term list changed with the statistics");

    let compacted = index.compacted();
    index.install(compacted);
    assert_eq!(
        index.stats(),
        Stats {
            units: 2,
            terms: 2,
            postings: 3,
            bytes: 14,
            tombstones: 0,
            dead_postings: 0,
            ceiling: CEILING_BYTES,
            seen: 0,
        }
    );
    assert_eq!(terms(&index), ["beta", "delta"]);
}

/// §5.6 PREPARE UNDER NO LOCK / INSTALL BY ONE SWAP, the lock modelled as
/// the embedder's `RwLock`, the crate holding none: `prepare` takes no index
/// — it runs before any lock is taken, on a unit alone — and `install`
/// replaces the body by one assignment, so a clone held across it is
/// unchanged, a reader holding the old value under the read side sees it
/// whole until it drops it, and the write side cannot begin while it does.
#[test]
fn prepare_takes_no_index_and_install_is_one_swap_a_clone_held_across_it_unchanged() {
    // Prepared before any index exists.
    let prepared = Index::prepare(guest(1, "alpha beta"));
    assert_eq!((prepared.class(), prepared.bytes()), (Class::Guest, 10));
    let replacement = Index::prepare(guest(1, "beta"));

    let lock = Arc::new(RwLock::new(Index::new(Class::Guest)));
    {
        let mut writer = lock.write().expect("the write side");
        writer.merge(prepared).expect("admitted");
        writer.merge(replacement).expect("replaced");
    }
    let old = lock.read().expect("the read side").clone();
    assert_eq!(old.stats().tombstones, 1);

    // Compaction built under the read side, from the snapshot.
    let compacted = lock.read().expect("the read side").compacted();

    // A reader holding the old value: install cannot begin, and the reader
    // sees the old value whole.
    let reader = lock.read().expect("the read side");
    assert!(matches!(lock.try_write(), Err(TryLockError::WouldBlock)));
    assert_eq!(reader.stats().tombstones, 1);
    assert_eq!(reader.stats().dead_postings, 2);
    drop(reader);

    // The swap, under the write side.
    lock.write().expect("the write side").install(compacted);
    let now = lock.read().expect("the read side");
    assert_eq!((now.stats().tombstones, now.stats().dead_postings), (0, 0));
    assert_eq!(now.stats().units, 1);
    assert_eq!(terms(&now), ["beta"]);

    // The clone held across the install is the old value, unchanged.
    assert_eq!((old.stats().tombstones, old.stats().dead_postings), (1, 2));
    assert_eq!(terms(&old), ["beta"]);
}

/// §2.1 THE JOIN: a document of twice `MAX_DELIVERY_ITEMS` positions, read
/// in two parts with a multi-byte character across the parts' edge, is
/// joined whole — one text item, the character rejoined, the token holding
/// it cut whole with its range across the edge — and indexed as one unit.
#[test]
fn a_document_of_twice_the_delivery_budget_with_a_character_across_the_edge_is_joined_whole() {
    let n = MAX_DELIVERY_ITEMS;
    // The first part: a run of `a`, a space, then `caf` and the FIRST byte of
    // `é` (`c3`); the second: the SECOND byte (`a9`), a space, a run of `b`.
    let mut first = vec![b'a'; n];
    first[n - 5] = b' ';
    first[n - 4..].copy_from_slice(b"caf\xC3");
    let mut second = vec![b'b'; n];
    second[0] = 0xA9;
    second[1] = b' ';
    assert!(std::str::from_utf8(&first).is_err(), "the first part alone is not UTF-8");
    assert!(std::str::from_utf8(&second).is_err(), "nor the second");

    let parts = vec![
        Item::Text { start: 1, bytes: first },
        Item::Text { start: 1 + n as u64, bytes: second },
    ];
    let unit =
        Unit::new(key(1), Some(addr(&[1, 0, 1, 0, 1, 1])), Kind::Edition, Class::Guest, 9, parts)
            .expect("one extent");
    assert_eq!(unit.items().len(), 1, "the parts are one item");
    assert_eq!(unit.positions(), 2 * n as u64);
    assert_eq!(unit.bytes(), 2 * n as u64);
    let Item::Text { bytes, .. } = &unit.items()[0] else { unreachable!() };
    assert!(
        std::str::from_utf8(bytes).is_ok(),
        "joined, the character is whole and the text valid"
    );

    let tokens = tokenize(&unit);
    assert_eq!(tokens.len(), 3, "the run of `a`, the word across the edge, the run of `b`");
    let cafe = &tokens[1];
    assert_eq!(cafe.term, "cafe", "cut whole and folded, never two stretches");
    assert_eq!(
        (cafe.ordinal, cafe.offset, cafe.len),
        (1, (n - 4) as u64, 5),
        "its range crosses the edge"
    );
    assert_eq!((tokens[2].offset, tokens[2].len), ((n + 2) as u64, (n - 2) as u32));

    let mut index = Index::new(Class::Guest);
    index.index(unit).expect("admitted: one unit, under the ceiling");
    assert_eq!(index.stats().units, 1);
    assert!(terms(&index).contains(&"cafe".to_string()));
}

/// §2.3 THE RANGE across a `Gap` and a `hex` stretch: each occurrence's
/// offset runs from the unit's start — the gap counted at its width, the
/// invalid byte at its own ordinal — and the item it lies in is found by a
/// binary search over the item table's start ordinals.
#[test]
fn an_occurrences_range_runs_across_a_gap_and_a_hex_stretch_its_item_found_by_binary_search() {
    let origin = addr(&[1, 0, 1, 0, 2]);
    let items = vec![
        Item::Text { start: 1, bytes: b"alpha beta".to_vec() },
        Item::Gap { start: 11, width: 5, kind: GapKind::Withheld { origin } },
        Item::Text { start: 16, bytes: b"gam\xFFma delta".to_vec() },
    ];
    let unit = Unit::new(key(1), None, Kind::Draft, Class::Guest, 1, items).expect("one extent");
    let cut: Vec<_> =
        tokenize(&unit).into_iter().map(|t| (t.term, t.ordinal, t.offset, t.len)).collect();
    let tok = |term: &str, ordinal, offset, len| (term.to_string(), ordinal, offset, len);
    assert_eq!(
        cut,
        vec![
            tok("alpha", 0, 0, 5),
            tok("beta", 1, 6, 4),
            tok("gam", 3, 15, 3),
            tok("ma", 5, 19, 2),
            tok("delta", 6, 22, 5),
        ]
    );
    for (expected_item, (_, _, offset, len)) in [0, 0, 2, 2, 2].into_iter().zip(&cut) {
        assert_eq!(unit.item_at(*offset), Some(expected_item), "the occurrence at {offset}");
        assert_eq!(
            unit.item_at(offset + u64::from(*len) - 1),
            Some(expected_item),
            "its last byte too"
        );
    }
    assert_eq!(unit.item_at(12), Some(1), "a position inside the withheld run");
    assert_eq!(unit.item_at(27), None, "past the extent");
}
