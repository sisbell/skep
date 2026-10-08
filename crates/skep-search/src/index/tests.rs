use super::*;
use crate::unit::{GapKind, Item, Kind};
use skep_address::{validate, Nat, Tumbler};

/// The document `1.0.1.0.n`.
fn key(n: u32) -> UnitKey {
    let t = Tumbler::new([1u32, 0, 1, 0, n].map(Nat::from)).expect("nonempty");
    UnitKey::new(validate(t).expect("a T4-valid address"))
}

fn text(start: u64, bytes: &[u8]) -> Item {
    Item::Text { start, bytes: bytes.to_vec() }
}

/// A unit of one text item at ordinal 1.
fn unit(class: Class, n: u32, s: &str) -> Unit {
    Unit::new(key(n), None, Kind::Edition, class, 1, vec![text(1, s.as_bytes())])
        .expect("one extent")
}

fn guest(n: u32, s: &str) -> Unit {
    unit(Class::Guest, n, s)
}

/// The live postings of `term`: `(key, occurrences)` per live unit.
fn postings_of(index: &Index, term: &str) -> Vec<(UnitKey, Vec<Occurrence>)> {
    let Some(&id) = index.body.dictionary.get(term) else {
        return Vec::new();
    };
    index.body.terms[id]
        .postings
        .iter()
        .filter_map(|p| match &index.body.units[p.unit] {
            Record::Live { unit, .. } => Some((unit.key().clone(), p.occurrences.clone())),
            Record::Dead => None,
        })
        .collect()
}

fn occ(ordinal: u32, offset: u64, len: u32) -> Occurrence {
    Occurrence { ordinal, offset, len }
}

/// `prepare` groups the unit's occurrences by term, each term's in ordinal
/// order, and counts what it would add.
#[test]
fn prepare_groups_a_units_occurrences_by_term_in_ordinal_order() {
    let p = Index::prepare(guest(1, "beta alpha beta"));
    assert_eq!(p.terms(), 2);
    assert_eq!(p.entries(), 3);
    assert_eq!(p.postings["alpha"], vec![occ(1, 5, 5)]);
    assert_eq!(p.postings["beta"], vec![occ(0, 0, 4), occ(2, 11, 4)]);
    assert_eq!(p.class(), Class::Guest);
    assert_eq!(p.bytes(), 15);
    assert_eq!(p.key(), &key(1));
    assert_eq!(p.unit().positions(), 15);
}

/// §2.3, §5.1: the postings hold each occurrence's ordinal and its range
/// from the unit's start — across a `Gap` and a `hex` stretch, the gap at
/// its width and the invalid byte at its own ordinal — so a span is read off
/// them with no re-tokenizing.
#[test]
fn the_postings_hold_each_occurrences_ordinal_and_range_across_a_gap_and_a_hex_stretch() {
    let items = vec![
        text(1, b"alpha beta"),
        Item::Gap { start: 11, width: 5, kind: GapKind::Atom },
        text(16, b"gam\xFFma alpha"),
    ];
    let u = Unit::new(key(1), None, Kind::Edition, Class::Guest, 1, items).expect("one extent");
    let mut index = Index::new(Class::Guest);
    index.index(u).expect("admitted");
    assert_eq!(postings_of(&index, "alpha"), vec![(key(1), vec![occ(0, 0, 5), occ(6, 22, 5)])]);
    assert_eq!(postings_of(&index, "beta"), vec![(key(1), vec![occ(1, 6, 4)])]);
    assert_eq!(postings_of(&index, "gam"), vec![(key(1), vec![occ(3, 15, 3)])]);
    assert_eq!(postings_of(&index, "ma"), vec![(key(1), vec![occ(5, 19, 2)])]);
    assert_eq!(index.terms().collect::<Vec<_>>(), ["alpha", "beta", "gam", "ma"]);
}

/// §5.1: a replacement tombstones the old record where it stands — its
/// postings resident, counted dead — while every live count and each term's
/// live count move at once from the unit's own term list.
#[test]
fn a_replacement_tombstones_the_old_unit_and_every_live_count_moves_at_once() {
    let mut index = Index::new(Class::Guest);
    index.index(guest(1, "alpha beta gamma gamma")).expect("admitted");
    index.index(guest(2, "beta")).expect("admitted");
    index.index(guest(1, "beta delta")).expect("the replacement");
    assert_eq!(index.body.units.len(), 3, "the tombstone stands where the old record stood");
    assert!(matches!(index.body.units[0], Record::Dead));
    assert_eq!(index.body.keys[&key(1)], 2, "the key names the new record");
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
    let gamma = index.body.dictionary["gamma"];
    assert_eq!(index.body.terms[gamma].live_units, 0, "held by the dead unit alone");
    assert_eq!(index.body.terms[gamma].postings.len(), 1, "its dead posting is resident");
    let beta = index.body.dictionary["beta"];
    assert_eq!(index.body.terms[beta].live_units, 2);
    assert_eq!(
        index.body.terms[beta].postings.len(),
        3,
        "old, unit 2's, new — the dead one among them"
    );
    assert_eq!(
        postings_of(&index, "beta"),
        vec![(key(2), vec![occ(0, 0, 4)]), (key(1), vec![occ(0, 0, 4)])]
    );
}

/// §5.1: a term held only by dead units is no term — absent from the live
/// dictionary while its postings are resident, and gone from the structure
/// once compaction drops them.
#[test]
fn a_term_held_only_by_dead_units_is_no_term_until_compaction_drops_it() {
    let mut index = Index::new(Class::Guest);
    index.index(guest(1, "alpha gamma")).expect("admitted");
    index.index(guest(1, "alpha")).expect("the replacement");
    assert_eq!(index.terms().collect::<Vec<_>>(), ["alpha"]);
    assert!(index.body.dictionary.contains_key("gamma"), "resident until the compaction");
    let compacted = index.compacted();
    index.install(compacted);
    assert!(!index.body.dictionary.contains_key("gamma"));
    assert_eq!(index.terms().collect::<Vec<_>>(), ["alpha"]);
}

/// §5.1, §5.6: compaction drops the dead postings and the tombstones,
/// re-numbers the live units densely and re-points every term list and key;
/// the live counts are unchanged and the postings read the same.
#[test]
fn compaction_drops_the_dead_postings_and_remaps_the_ids() {
    let mut index = Index::new(Class::Guest);
    index.index(guest(1, "alpha beta")).expect("admitted");
    index.index(guest(2, "beta gamma")).expect("admitted");
    index.index(guest(3, "gamma alpha")).expect("admitted");
    index.index(guest(2, "delta")).expect("the replacement");
    index.index(guest(1, "alpha")).expect("the replacement");
    let before = index.stats();
    assert_eq!((before.tombstones, before.dead_postings), (2, 4));
    let live_before: Vec<_> =
        ["alpha", "beta", "delta", "gamma"].iter().map(|t| postings_of(&index, t)).collect();
    let compacted = index.compacted();
    index.install(compacted);
    let after = index.stats();
    assert_eq!(after, Stats { tombstones: 0, dead_postings: 0, ..before });
    assert_eq!(index.body.units.len(), 3, "dense again");
    assert!(index.body.units.iter().all(|r| matches!(r, Record::Live { .. })));
    assert_eq!(index.body.terms.iter().map(|t| t.postings.len()).sum::<usize>(), after.postings);
    assert_eq!(index.body.terms.len(), after.terms, "no dead term entry remains");
    for (id, record) in index.body.units.iter().enumerate() {
        let Record::Live { unit, terms, .. } = record else { unreachable!() };
        assert_eq!(index.body.keys[unit.key()], id);
        for &term in terms {
            assert!(
                index.body.terms[term].postings.iter().any(|p| p.unit == id),
                "the term list points at a term holding this unit"
            );
        }
    }
    let live_after: Vec<_> =
        ["alpha", "beta", "delta", "gamma"].iter().map(|t| postings_of(&index, t)).collect();
    assert_eq!(live_after, live_before, "the live postings read the same");
}

/// §5.1, §7.1: compaction is due once the dead postings exceed one eighth of
/// the live ones — at the eighth itself it is not.
#[test]
fn compaction_is_due_past_an_eighth_of_dead_postings() {
    let mut index = Index::new(Class::Guest);
    index.index(guest(1, "a b c d e f g h")).expect("admitted");
    index.index(guest(2, "x")).expect("admitted");
    assert!(!index.compaction_due(), "nothing dead");
    index.index(guest(2, "y")).expect("the replacement: one dead against eight live");
    assert!(!index.compaction_due(), "one of eight is the eighth, not past it");
    index.index(guest(2, "z")).expect("the replacement: two dead against eight live");
    assert!(index.compaction_due());
    let compacted = index.compacted();
    index.install(compacted);
    assert!(!index.compaction_due());
}

/// §7.4: `seen` counts the ceiling's refusals alone — not a class refusal,
/// not an admission — and the index's class check runs before the ceiling.
#[test]
fn seen_counts_the_ceilings_refusals_alone() {
    let mut index = Index::with_ceiling(Class::Guest, 10);
    assert_eq!(index.stats().ceiling, 10);
    index.index(guest(1, "abc")).expect("under the ceiling");
    assert_eq!(index.stats().seen, 0);
    assert_eq!(
        index.index(unit(Class::Principal(2), 2, "x")),
        Err(IndexError::ClassMismatch { index: Class::Guest, unit: Class::Principal(2) })
    );
    assert_eq!(index.stats().seen, 0, "a class refusal is not an offer past the ceiling");
    assert_eq!(
        index.index(guest(2, "twelve bytes")),
        Err(IndexError::PastTheCeiling { held: 3, limit: 10, units: 1 })
    );
    assert!(index.index(guest(3, "a lot of bytes")).is_err());
    assert_eq!(index.stats().seen, 2);
    assert_eq!(index.stats().units, 1);
}

/// §7.4, at a small ceiling: the refused REPLACEMENT keeps the unit it would
/// have replaced — its terms, its bytes, its key — and the replaced unit's
/// bytes are not counted twice when a replacement fits.
#[test]
fn a_ceiling_refusal_keeps_the_unit_it_would_replace() {
    let mut index = Index::with_ceiling(Class::Guest, 10);
    index.index(guest(1, "alpha")).expect("5 of 10");
    index.index(guest(2, "beta")).expect("9 of 10");
    let before = index.stats();
    assert_eq!(
        index.index(guest(1, "gamma delta")),
        Err(IndexError::PastTheCeiling { held: 9, limit: 10, units: 2 })
    );
    assert_eq!(index.stats(), Stats { seen: 1, ..before });
    assert_eq!(
        index.terms().collect::<Vec<_>>(),
        ["alpha", "beta"],
        "the unit it would replace is kept"
    );
    assert_eq!(index.body.keys[&key(1)], 0);
    index
        .index(guest(1, "abcdef"))
        .expect("a replacement that fits: 9 - 5 + 6 = 10, at the ceiling");
    assert_eq!(index.stats().bytes, 10);
    assert_eq!(index.terms().collect::<Vec<_>>(), ["abcdef", "beta"]);
}

/// §5.2 D7: the class is set at `new` and the revision is the running
/// crate's; a fresh index holds nothing.
#[test]
fn a_fresh_index_holds_its_class_and_the_running_revision_and_nothing_else() {
    let index = Index::new(Class::Principal(9));
    assert_eq!(index.class(), Class::Principal(9));
    assert_eq!(index.revision(), REVISION);
    assert_eq!(
        index.stats(),
        Stats {
            units: 0,
            terms: 0,
            postings: 0,
            bytes: 0,
            tombstones: 0,
            dead_postings: 0,
            ceiling: CEILING_BYTES,
            seen: 0,
        }
    );
    assert_eq!(index.terms().count(), 0);
    assert!(!index.compaction_due());
}

/// §1.4 THE ONE READ, RULED (b): the keys under a range — an account's
/// prefix, a document's own, the node's for the whole board — in the address
/// order, one contiguous scan; a tombstoned unit's key is not among them,
/// and the postings and the stored text are never read.
#[test]
fn keys_by_range_scans_the_keys_under_a_prefix_in_address_order() {
    let a = |n: u32| {
        let t = Tumbler::new([1u32, 0, 1, 0, n].map(Nat::from)).expect("nonempty");
        UnitKey::new(validate(t).expect("a T4-valid address"))
    };
    let b = |n: u32| {
        let t = Tumbler::new([1u32, 0, 2, 0, n].map(Nat::from)).expect("nonempty");
        UnitKey::new(validate(t).expect("a T4-valid address"))
    };
    let of = |key: &UnitKey| {
        Unit::new(key.clone(), None, Kind::Edition, Class::Guest, 1, vec![text(1, b"x")])
            .expect("one extent")
    };
    let mut index = Index::new(Class::Guest);
    for key in [b(2), a(3), a(1), b(1), a(2)] {
        index.index(of(&key)).expect("admitted");
    }
    index.index(of(&a(2))).expect("replaced: its old record a tombstone");
    let prefix = |comps: &[u32]| {
        let t = Tumbler::new(comps.iter().map(|&c| Nat::from(c))).expect("nonempty");
        Prefix::new(validate(t).expect("a T4-valid address"))
    };
    let under = |index: &Index, p: &Prefix| index.keys_by_range(p).cloned().collect::<Vec<_>>();
    assert_eq!(
        under(&index, &prefix(&[1, 0, 1])),
        [a(1), a(2), a(3)],
        "account 1's documents, in order"
    );
    assert_eq!(under(&index, &prefix(&[1, 0, 2])), [b(1), b(2)]);
    assert_eq!(under(&index, &prefix(&[1, 0, 1, 0, 2])), [a(2)], "a document's own prefix: itself");
    assert_eq!(under(&index, &prefix(&[1, 0, 3])), [], "an account holding nothing");
    assert_eq!(under(&index, &prefix(&[1])), [a(1), a(2), a(3), b(1), b(2)], "the node: every key");
    assert!(prefix(&[1, 0, 1]).admits(a(3).doc()) && !prefix(&[1, 0, 1]).admits(b(1).doc()));
    index.index(of(&a(3))).expect("replaced");
    let compacted = index.compacted();
    index.install(compacted);
    assert_eq!(
        under(&index, &prefix(&[1, 0, 1])),
        [a(1), a(2), a(3)],
        "the same keys after compaction"
    );
}

/// The refusals render what the design says they name.
#[test]
fn the_refusals_display_both_classes_and_the_bytes_held_against_the_limit() {
    let class = IndexError::ClassMismatch { index: Class::Guest, unit: Class::Principal(7) };
    assert_eq!(class.to_string(), "an index of class guest refuses a unit read at principal 7");
    let ceiling = IndexError::PastTheCeiling { held: 12, limit: 10, units: 3 };
    assert_eq!(
        ceiling.to_string(),
        "past the ceiling: the index holds 12 bytes of text in 3 units and its ceiling is 10 bytes"
    );
}
