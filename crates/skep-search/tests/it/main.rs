//! The crate's one integration-test target: every suite below is a module of
//! this binary, not a target of its own. `cases` — §7.2's twenty-two
//! tokenizer cases, each asserting its tokens AND its byte range; `grammar` —
//! §3.2's forms at the public surface, §7.2's two grammar cases with their
//! byte ranges (fact 11), and every bound met at its real constant with its
//! flag set; `ranking` — §3.3's vectors: the pinned idf's order, the first
//! keystroke's union near zero and never below, the tie set, the pair's
//! merged statistics counting the published member once, determinism; `hits`
//! — §3.1's standing across a restart off the range's record, the span's
//! V-ordinals, and §6's snippet cases; `separation` — §2.1's class
//! separation by construction, the investigation §4.10 item 15's vector set;
//! `index` — the write side's surface under the design's fence: the class
//! check (§2.1), one class per index (§5.2 D7), the ceiling at the real
//! constant (§7.4), replacement (§5.1), prepare under no lock and install by
//! one swap (§5.6), the join across the parts' edge (§2.1) and the range
//! across a `Gap` and a `hex` stretch (§2.3); `file` — the file's
//! dispositions at the public surface, §8.3's list one by one (§5.1, §5.4);
//! `resume` — the open's judgment over a loaded header and the wire's
//! answers (§5.4); `budgets` — §7's pins, each MEASURED over §7.3's corpus
//! fed through a dev board as the shell feeds it and REPORTED beside its pin
//! (§7.1–§7.4), the timing partition that skips without the corpus. Nothing
//! but module declarations and the fixtures they share belongs here.

mod budgets;
mod cases;
mod file;
mod grammar;
mod hits;
mod index;
mod ranking;
mod resume;
mod separation;

use skep_address::{validate, Address, Nat, Tumbler};
use skep_search::{Chain, ChainAt, Class, Item, Kind, Unit, UnitKey};

/// A T4-valid address from its components.
pub fn addr(comps: &[u32]) -> Address {
    let t = Tumbler::new(comps.iter().map(|&c| Nat::from(c))).expect("nonempty");
    validate(t).expect("a T4-valid address")
}

/// The document `1.0.1.0.n`.
pub fn doc(n: u32) -> Address {
    addr(&[1, 0, 1, 0, n])
}

/// The key of document `1.0.1.0.n`.
pub fn key(n: u32) -> UnitKey {
    UnitKey::new(doc(n))
}

/// A unit of one text item at ordinal 1, read at `class`.
pub fn text_unit(class: Class, n: u32, bytes: &[u8]) -> Unit {
    let item = Item::Text { start: 1, bytes: bytes.to_vec() };
    Unit::new(key(n), None, Kind::Edition, class, 1, vec![item]).expect("one extent")
}

/// A draft of one text item at ordinal 1, the document `doc`, read at
/// `class`, its member its own address.
pub fn draft(class: Class, doc: &Address, bytes: &[u8]) -> Unit {
    let item = Item::Text { start: 1, bytes: bytes.to_vec() };
    Unit::new(UnitKey::new(doc.clone()), Some(doc.clone()), Kind::Draft, class, 1, vec![item])
        .expect("one extent")
}

/// A chain of one repeated byte.
pub fn chain(fill: u8) -> Chain {
    Chain::from_bytes([fill; 32])
}

/// A `(position, chain)` pair over `chain(fill)`.
pub fn at(position: u64, fill: u8) -> ChainAt {
    ChainAt { position, chain: chain(fill) }
}
