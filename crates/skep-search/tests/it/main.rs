//! The crate's one integration-test target: every suite below is a module of
//! this binary, not a target of its own. `cases` — §7.2's twenty-two
//! tokenizer cases, each asserting its tokens AND its byte range (the two
//! grammar cases there are lane SR-3's); `index` — the write side's surface
//! under the design's fence: the class check (§2.1), one class per index
//! (§5.2 D7), the ceiling at the real constant (§7.4), replacement (§5.1),
//! prepare under no lock and install by one swap (§5.6), the join across the
//! parts' edge (§2.1) and the range across a `Gap` and a `hex` stretch
//! (§2.3). Nothing but module declarations and the fixtures they share
//! belongs here.

mod cases;
mod index;

use skep_address::{validate, Address, Nat, Tumbler};
use skep_search::{Class, Item, Kind, Unit, UnitKey};

/// A T4-valid address from its components.
pub fn addr(comps: &[u32]) -> Address {
    let t = Tumbler::new(comps.iter().map(|&c| Nat::from(c))).expect("nonempty");
    validate(t).expect("a T4-valid address")
}

/// The key of document `1.0.1.0.n`.
pub fn key(n: u32) -> UnitKey {
    UnitKey::new(addr(&[1, 0, 1, 0, n]))
}

/// A unit of one text item at ordinal 1, read at `class`.
pub fn text_unit(class: Class, n: u32, bytes: &[u8]) -> Unit {
    let item = Item::Text { start: 1, bytes: bytes.to_vec() };
    Unit::new(key(n), None, Kind::Edition, class, 1, vec![item]).expect("one extent")
}
