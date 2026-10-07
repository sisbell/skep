use super::*;
use skep_address::{validate, Nat, Tumbler};

fn addr(comps: &[u32]) -> Address {
    let t = Tumbler::new(comps.iter().map(|&c| Nat::from(c))).expect("nonempty");
    validate(t).expect("a T4-valid address")
}

/// The document `1.0.1.0.1`: node 1, account 1, document 1.
fn doc() -> Address {
    addr(&[1, 0, 1, 0, 1])
}

fn key() -> UnitKey {
    UnitKey::new(doc())
}

fn text(start: u64, bytes: &[u8]) -> Item {
    Item::Text { start, bytes: bytes.to_vec() }
}

fn gap(start: u64, width: u64) -> Item {
    Item::Gap { start, width, kind: GapKind::Atom }
}

fn unit(items: Vec<Item>) -> Result<Unit, UnitError> {
    Unit::new(key(), None, Kind::Edition, Class::Guest, 7, items)
}

/// §2.1: the parts are joined in order into one unit, and a character split
/// at the parts' edge is rejoined — the two text items become one, valid
/// UTF-8 again, at the first item's start.
#[test]
fn adjacent_text_items_are_joined_into_one_whole_character_included() {
    let u = unit(vec![text(1, b"caf\xC3"), text(5, b"\xA9 au lait")]).expect("one extent");
    assert_eq!(u.items().len(), 1, "{:?}", u.items());
    assert_eq!(
        u.items()[0],
        text(1, "café au lait".as_bytes()),
        "joined whole at the first item's start"
    );
    assert_eq!(u.start(), 1);
    assert_eq!(u.bytes(), 13);
    assert_eq!(u.positions(), 13);
}

/// A gap between two text items keeps them apart: three rows of the item
/// table, each at its own start.
#[test]
fn a_gap_between_text_items_keeps_them_apart() {
    let u = unit(vec![text(1, b"alpha"), gap(6, 1), text(7, b"beta")]).expect("one extent");
    assert_eq!(u.items().len(), 3);
    assert_eq!(u.items()[1], gap(6, 1));
    assert_eq!(u.items()[2].start(), 7);
}

/// §2.1: the parts are consecutive sub-spans of one extent, so a sequence
/// whose items are not contiguous is refused, the refusal naming the item,
/// the ordinal reached and the ordinal found.
#[test]
fn the_items_must_be_one_contiguous_extent() {
    assert_eq!(
        unit(vec![text(1, b"abcd"), text(6, b"e")]),
        Err(UnitError::Discontiguous { index: 1, expected: 5, found: 6 })
    );
    assert_eq!(
        unit(vec![text(1, b"abcd"), gap(4, 1)]),
        Err(UnitError::Discontiguous { index: 1, expected: 5, found: 4 })
    );
}

/// A width that reaches past the ordinal space is refused rather than
/// wrapped: a hostile board's width is a wire value the shell parsed.
#[test]
fn an_item_past_the_ordinal_space_is_refused() {
    assert_eq!(unit(vec![gap(u64::MAX - 1, 5)]), Err(UnitError::Overflow { index: 0 }));
}

/// §7.4: the live bytes are the bytes of text; a gap adds positions and no
/// bytes.
#[test]
fn live_bytes_count_the_text_alone() {
    let u = unit(vec![text(1, b"alpha"), gap(6, 40), text(46, b"beta")]).expect("one extent");
    assert_eq!(u.bytes(), 9);
    assert_eq!(u.positions(), 49);
}

/// §2.3: an occurrence's item is found by a binary search over the item
/// table's start ordinals — at every boundary of a three-item unit, and
/// `None` past the extent.
#[test]
fn the_item_of_an_occurrence_is_found_by_binary_search_over_the_starts() {
    let u = unit(vec![text(1, b"alpha beta"), gap(11, 5), text(16, b"gamma delta")])
        .expect("one extent");
    assert_eq!(u.item_at(0), Some(0));
    assert_eq!(u.item_at(9), Some(0), "the text item's last byte");
    assert_eq!(u.item_at(10), Some(1), "the gap's first position");
    assert_eq!(u.item_at(14), Some(1), "the gap's last position");
    assert_eq!(u.item_at(15), Some(2));
    assert_eq!(u.item_at(25), Some(2), "the extent's last position");
    assert_eq!(u.item_at(26), None, "past the extent");
    assert_eq!(u.item_at(u64::MAX), None);
}

/// A unit of no items starts at zero, holds no bytes and places nothing.
#[test]
fn an_empty_unit_starts_at_zero_and_holds_nothing() {
    let u = unit(Vec::new()).expect("empty is an extent");
    assert_eq!(u.start(), 0);
    assert_eq!(u.bytes(), 0);
    assert_eq!(u.positions(), 0);
    assert_eq!(u.item_at(0), None);
}

/// What rides beside the key (§2.1, §3.1) is read back as given.
#[test]
fn the_facts_beside_the_key_ride_with_the_unit() {
    let member = addr(&[1, 0, 1, 0, 1, 3]);
    let u =
        Unit::new(key(), Some(member.clone()), Kind::Edition, Class::Principal(7), 42, Vec::new())
            .expect("empty is an extent");
    assert_eq!(u.key(), &key());
    assert_eq!(u.member(), Some(&member));
    assert_eq!(u.kind(), Kind::Edition);
    assert_eq!(u.class(), Class::Principal(7));
    assert_eq!(u.as_of(), 42);
}

/// The class and the key render as the refusals name them.
#[test]
fn the_class_and_the_key_display_as_the_design_names_them() {
    assert_eq!(Class::Guest.to_string(), "guest");
    assert_eq!(Class::Principal(7).to_string(), "principal 7");
    assert_eq!(key().to_string(), "1.0.1.0.1");
}

/// §2.4: a DAUGHTER's `publish` row — a member more than one component past
/// the document, `1.0.1.0.1.1.1` — moves no head; "Daughters never float".
#[test]
fn a_daughters_publish_row_moves_no_head() {
    let head = addr(&[1, 0, 1, 0, 1, 1]);
    let daughter = addr(&[1, 0, 1, 0, 1, 1, 1]);
    assert_eq!(moved_head(&doc(), Some(&head), &daughter), None);
    assert_eq!(moved_head(&doc(), None, &daughter), None, "nor where no head stands yet");
}

/// §2.4: an owner's `version` row mints the trunk's next member,
/// `1.0.1.0.1.2`, and moves the head to it — as a `publish` row on the trunk
/// does.
#[test]
fn an_owners_version_row_moves_the_head() {
    let head = addr(&[1, 0, 1, 0, 1, 1]);
    let next = addr(&[1, 0, 1, 0, 1, 2]);
    assert_eq!(moved_head(&doc(), Some(&head), &next), Some(next.clone()));
    assert_eq!(moved_head(&doc(), None, &next), Some(next), "the first head seen");
}

/// §2.4: a row naming another document is not this document's, and a row
/// naming a member at or below the head — a replayed page — moves nothing.
#[test]
fn a_row_naming_another_document_or_an_earlier_member_moves_no_head() {
    let head = addr(&[1, 0, 1, 0, 1, 2]);
    let other = addr(&[1, 0, 2, 0, 1]);
    assert_eq!(
        moved_head(&doc(), Some(&head), &other),
        None,
        "a cross-owner version's fresh document"
    );
    let earlier = addr(&[1, 0, 1, 0, 1, 1]);
    assert_eq!(moved_head(&doc(), Some(&head), &earlier), None);
    assert_eq!(moved_head(&doc(), Some(&head), &head), None, "the head itself");
}
