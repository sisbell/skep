//! The entry frame's LAWS, stated through the public surface a signer and a
//! verifier both call (signed ops; the design record §2.5). The byte pins
//! beside the rows (`src/entry.rs`) fix each row at a chosen instance; what
//! is stated here holds over a whole family no pin enumerates.

use crate::common;

use std::collections::BTreeMap;

use common::{addr, tum};
use skep_address::{Address, Span};
use skep_identity::{entry_body_make_link, EntrySlot, LinkSlots};

/// Every sequence of at most two elements drawn from `elements` — the empty
/// sequence, each element alone, and every ordered pair, repeats included:
/// `1 + n + n²` sequences, generated rather than chosen.
fn sequences_of<T: Clone>(elements: &[T]) -> Vec<Vec<T>> {
    let mut out = vec![Vec::new()];
    out.extend(elements.iter().map(|e| vec![e.clone()]));
    for first in elements {
        for second in elements {
            out.push(vec![first.clone(), second.clone()]);
        }
    }
    out
}

/// The entry module's closing claim, as a LAW over an exhaustive family: the
/// composition is injective — two distinct inputs never spell one preimage.
/// An endset is a verbatim span sequence (M7; the design record §2.5), so a
/// slot's elements, their ORDER and their REPEATS are all part of what a link
/// deposits; two links whose bodies spelled alike would share every signature
/// over either, and a reader beside the table could not tell the link that
/// was signed from its twin. The family is every slot of at most two elements
/// over two addresses, in both forms — the empty slot, each element alone,
/// and every ordered pair, repeats included — in each of a `make_link`'s
/// three slots: 14³ bodies, all distinct.
///
/// Why a law and not a pin: the row pins spell a slot of one element or of
/// two distinct ones. A `push_slot` that deduplicated its elements, sorted a
/// resolve slot's, or wrote nothing for an empty slot keeps every one of them
/// green. The first two keep every signed-ops cell in skepd green too, whose
/// signer and verifier both spell through it; the third is caught otherwise
/// only a crate away, by skepd's hand-spelled frame pin and the goldens signed
/// over the same frames.
#[test]
fn no_two_distinct_slot_triples_spell_one_make_link_body() {
    // DESCENDING in address order and in spelled order alike, so a row that
    // sorted its elements by either comparison reorders every mixed pair.
    let addrs = [addr(&[1, 0, 30]), addr(&[1, 0, 2])];
    let span = |start: &[u32], width: &[u32]| Span::new(tum(start), tum(width)).expect("T12-valid");
    let specs: [(Address, Span); 2] =
        [(addrs[0].clone(), span(&[1, 1], &[0, 2])), (addrs[1].clone(), span(&[1, 3], &[0, 1]))];
    let (addr_slots, spec_slots) = (sequences_of(&addrs), sequences_of(&specs));
    let family: Vec<EntrySlot<'_>> = addr_slots
        .iter()
        .map(|s| EntrySlot::Addrs(s))
        .chain(spec_slots.iter().map(|s| EntrySlot::Resolve(s)))
        .collect();
    assert_eq!(family.len(), 14, "seven slots of each form");

    let mut spelled: BTreeMap<Vec<u8>, LinkSlots<'_>> = BTreeMap::new();
    for &ty in &family {
        for &from in &family {
            for &to in &family {
                let slots = LinkSlots { from, to, ty };
                let body = entry_body_make_link(slots).as_bytes().to_vec();
                if let Some(earlier) = spelled.insert(body, slots) {
                    panic!(
                        "two distinct slot triples spell one make_link body:\n  {earlier:?}\n  {slots:?}"
                    );
                }
            }
        }
    }
    assert_eq!(spelled.len(), family.len().pow(3), "every triple spelled a body of its own");
}
