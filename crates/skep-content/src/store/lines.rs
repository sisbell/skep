//! The line-break counts the slice keeps beside its content.
//!
//! A line break is a content position whose value is the single byte `0x0A`:
//! one byte of a stretch, or a one-byte value. Nothing else is one — not
//! `\r`, not the pair `\r\n`, not U+2028 — and a value of any other length is
//! an atom, which holds no line break whatever its bytes. One byte at one
//! permanent address, so no seam between two runs can split, make or remove
//! one, and an arrangement's line breaks are the sum of its runs'. Content is
//! written once (S0), so an entry's line breaks are counted once, as the
//! entry joins the slice, and hold for every arrangement of it.
//!
//! [`Lines`] keeps, for each entry that holds a line break, the entry's own
//! count and its chain's running sum, the line breaks on the chain below the
//! entry's key. A chain is the addresses that share all their components but
//! the last, as those M3 mints one document's content at do. Two maps hold
//! the same entries. By address, the line breaks before an address are one
//! lookup; by chain and running sum, the address of a chain's n-th line
//! break is one lookup too, never a walk of the chain's entries. An entry
//! that holds no line break is in neither map, so counting one moves
//! neither.
//!
//! The maps are a function of the entries counted into them, in whatever
//! order they are counted: an entry counted below a chain's highest raises
//! the running sum of each entry above it. They are derived and never
//! serialized, and the slice's decode counts its entries again, so nothing
//! a checkpoint holds can disagree with the bytes beside it. Both figures
//! are `u64`s that cannot overflow: each line break counted is a byte the
//! slice holds in memory.
//!
//! Inside one entry a count or a search scans at most one block of
//! [`BLOCK`] bytes: a stretch longer than that keeps its running count at
//! each whole block (SP-23).

use std::borrow::Cow;
use std::sync::Arc;

use skep_address::{ordinal, shift, Nat, Tumbler};

use super::{same_chain, Key, Stored};

/// The byte a line break is.
const LINE_BREAK: u8 = 0x0A;

/// The bytes of a stretch that one running count stands for.
///
/// It bounds what a count or a search scans inside one entry, and a stretch
/// longer than it pays one `u64` for each whole block it holds. The one
/// spelling of the figure (SP-25).
const BLOCK: usize = 4096;

/// Returns how many of `bytes` are the line break's byte.
fn breaks_in(bytes: &[u8]) -> u64 {
    bytes.iter().map(|&byte| u64::from(byte == LINE_BREAK)).sum()
}

/// Returns the bytes of `stored` that are each the value at one position.
///
/// They are a stretch's bytes, or a one-byte value's byte. Any other value
/// is an atom, one position whose value is no single byte, and answers
/// `None`: it holds no line break.
fn positions(stored: &Stored) -> Option<&Arc<[u8]>> {
    match stored {
        Stored::Stretch(bytes) => Some(bytes),
        Stored::Value(val) if val.len() == 1 => Some(val.shared()),
        Stored::Value(_) => None,
    }
}

/// Returns how far `t` lies past `key` on the chain they share, in positions.
///
/// A distance no `usize` holds lies past every entry's bytes, and answers
/// the greatest.
///
/// # Panics
///
/// Panics where `key` lies above `t`.
fn distance(key: &Tumbler, t: &Tumbler) -> usize {
    usize::try_from(ordinal(t) - ordinal(key)).unwrap_or(usize::MAX)
}

/// A chain's name: the components its addresses share, all but the last.
///
/// They are none for a one-component address, a sequence no `Tumbler` holds.
/// An entry counted above another on its chain takes that entry's reference,
/// so a chain minted in order holds its name once, however many of its
/// entries are counted.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
struct Chain(Arc<[Nat]>);

impl Chain {
    /// Returns the chain `t` lies on.
    fn of(t: &Tumbler) -> Chain {
        Chain(t.iter().take(t.len() - 1).cloned().collect())
    }
}

/// One entry's own line breaks: how many, and where each is found.
#[derive(Clone, PartialEq, Eq)]
struct Breaks {
    // How many of `bytes` are the line break's byte: at least one.
    count: u64,
    // The entry's bytes, each the value at one position: the entry's own
    // allocation, shared.
    bytes: Arc<[u8]>,
    // The count in `bytes[..(i + 1) * BLOCK]` at each whole block `i`, kept
    // where the bytes are longer than one block.
    marks: Option<Arc<[u64]>>,
}

impl Breaks {
    /// Counts `bytes` in one pass, answering `None` where they hold none.
    fn of(bytes: &Arc<[u8]>) -> Option<Breaks> {
        let (count, marks) = if bytes.len() > BLOCK {
            let (blocks, tail) = bytes.as_chunks::<BLOCK>();
            let mut counted = 0;
            let marks: Arc<[u64]> = blocks
                .iter()
                .map(|block| {
                    counted += breaks_in(block);
                    counted
                })
                .collect();
            (counted + breaks_in(tail), Some(marks))
        } else {
            (breaks_in(bytes), None)
        };
        (count > 0).then(|| Breaks { count, bytes: Arc::clone(bytes), marks })
    }

    /// Returns the line breaks in the entry's first `blocks` whole blocks.
    fn marked(&self, blocks: usize) -> u64 {
        blocks.checked_sub(1).map_or(0, |last| self.marks.as_deref().unwrap_or_default()[last])
    }

    /// Returns the line breaks among the entry's first `offset` bytes.
    ///
    /// That is every one it holds where `offset` reaches past its bytes.
    fn before(&self, offset: usize) -> u64 {
        if offset >= self.bytes.len() {
            return self.count;
        }
        let whole = offset / BLOCK;
        self.marked(whole) + breaks_in(&self.bytes[whole * BLOCK..offset])
    }

    /// Returns the offset of the entry's `nth` line break, counted from zero.
    ///
    /// `None` where the entry holds no more than `nth`.
    fn nth(&self, nth: u64) -> Option<usize> {
        // The first whole block whose running count passes `nth` holds the
        // line break, and the scan ends at it, inside that block; past every
        // whole block, the bytes after the last hold it or nothing, and they
        // are no more than one block.
        let block =
            self.marks.as_deref().unwrap_or_default().partition_point(|&counted| counted <= nth);
        let skipped = usize::try_from(nth - self.marked(block)).ok()?;
        let start = block * BLOCK;
        self.bytes[start..]
            .iter()
            .enumerate()
            .filter(|(_, &byte)| byte == LINE_BREAK)
            .nth(skipped)
            .map(|(at, _)| start + at)
    }
}

/// One entry that holds a line break, as the by-address map keeps it.
#[derive(Clone, PartialEq, Eq)]
struct Counted {
    // The chain the entry's key lies on.
    chain: Chain,
    // The chain's running sum: its line breaks below the entry's key.
    before: u64,
    // The entry's own line breaks.
    breaks: Breaks,
}

/// The line-break counts of one slice: a function of its entries.
///
/// Cheap to keep many of, as the slice is: `clone` is O(1), and a count
/// copies the path it writes in each map and shares the rest.
#[derive(Clone, Default, PartialEq, Eq)]
pub(super) struct Lines {
    // Each entry that holds a line break, under its key, in the slice's own
    // key order, so a probe is the `&Tumbler` a read is handed and builds
    // nothing. A key off a chain sorts among the chain's keys in that
    // order, which `floor` passes over.
    by_address: im::OrdMap<Key, Counted>,
    // The same entries under their chain and running sum. A chain's entries
    // are consecutive here, and each holds at least one line break, so
    // their sums are distinct and rise with their keys: the chain's n-th
    // line break lies in the entry at the greatest sum at or below n, and
    // the entries above a key are those at its sum or past it.
    by_sum: im::OrdMap<(Chain, u64), (Key, Breaks)>,
}

impl Lines {
    /// Counts `stored`, the entry about to stand at `key`, into both maps.
    ///
    /// An entry that holds no line break moves neither. One that does takes
    /// the running sum the chain has reached below `key`, and raises by its
    /// own count the sum of each counted entry above `key` on the chain —
    /// none where the chain is counted in order, as a mint and the decode's
    /// pass count it.
    ///
    /// **Precondition.** No entry counted so far covers `key` or lies inside
    /// `stored`'s reach: the folds' domain, and what the decode's ordered
    /// pass has checked of every entry it counts.
    pub(super) fn count(&mut self, key: &Key, stored: &Stored) {
        let Some(breaks) = positions(stored).and_then(Breaks::of) else {
            return;
        };
        let below = self.floor(key.tumbler());
        let before = below.map_or(0, |(_, counted)| counted.before + counted.breaks.count);
        let chain =
            below.map_or_else(|| Chain::of(key.tumbler()), |(_, counted)| counted.chain.clone());
        // Every entry above is taken out before any is put back, so a raised
        // sum never lands on an entry still standing at it.
        let above: Vec<(u64, Key, Breaks)> = self
            .by_sum
            .range::<_, (Chain, u64)>((chain.clone(), before)..)
            .take_while(|((on, _), _)| *on == chain)
            .map(|((_, sum), (above, breaks))| (*sum, above.clone(), breaks.clone()))
            .collect();
        for (sum, ..) in &above {
            self.by_sum.remove(&(chain.clone(), *sum));
        }
        for (sum, entry, own) in above {
            let raised = sum + breaks.count;
            self.by_sum.insert((chain.clone(), raised), (entry.clone(), own.clone()));
            self.by_address
                .insert(entry, Counted { chain: chain.clone(), before: raised, breaks: own });
        }
        self.by_sum.insert((chain.clone(), before), (key.clone(), breaks.clone()));
        self.by_address.insert(key.clone(), Counted { chain, before, breaks });
    }

    /// Returns the line breaks on `a`'s chain below `a`.
    pub(super) fn before(&self, a: &Tumbler) -> u64 {
        self.below(a).0
    }

    /// Returns the address of the `n`-th line break at or above `a`.
    ///
    /// It is searched on `a`'s chain, `n` counted from zero. `None` where the
    /// chain holds no more than `n` at or above `a`, a count past `u64`
    /// included.
    pub(super) fn nth_from(&self, a: &Tumbler, n: u64) -> Option<Tumbler> {
        let (before, chain) = self.below(a);
        let chain = chain.cloned().unwrap_or_else(|| Chain::of(a));
        // The chain's line breaks are numbered from zero in address order,
        // and `before` of them lie below `a`.
        let nth = (chain, before.checked_add(n)?);
        let ((on, sum), (key, breaks)) =
            self.by_sum.range::<_, (Chain, u64)>(..=&nth).next_back()?;
        if *on != nth.0 {
            return None;
        }
        let offset = breaks.nth(nth.1 - sum)?;
        Some(shift(key.tumbler(), &Nat::from(offset)))
    }

    /// Returns the line breaks below `a` on its chain, and the chain's name.
    ///
    /// The name is the one a counted entry at or below `a` holds, and `None`
    /// where the chain has none there.
    fn below(&self, a: &Tumbler) -> (u64, Option<&Chain>) {
        match self.floor(a) {
            Some((key, counted)) => {
                let inside = counted.breaks.before(distance(key.tumbler(), a));
                (counted.before + inside, Some(&counted.chain))
            }
            None => (0, None),
        }
    }

    /// Returns the highest counted entry of `t`'s chain at or below `t`.
    ///
    /// The greatest key at or below `t` need not lie on `t`'s chain. A key
    /// that extends a chain address by a component or more — `D·0·1·3·7`
    /// beside `D·0·1·3` — sorts above that address and below the next, and
    /// counts for a chain of its own; the search moves to the address it
    /// extends, passing every key beneath that address at once. Any other
    /// key off the chain sorts below every address of the chain, and ends
    /// the search with nothing. One lookup, and one more for each chain
    /// address so passed: none in a slice built from M3's mints, whose
    /// content keys lie on their documents' chains (ASN-0093
    /// ChainMembershipForOrigin). Each is `range(..=t).next_back()`, sound
    /// across leaves, as the slice's own predecessor read is.
    fn floor(&self, t: &Tumbler) -> Option<(&Key, &Counted)> {
        let mut probe = Cow::Borrowed(t);
        loop {
            let (key, counted) = self.by_address.range::<_, Tumbler>(..=&*probe).next_back()?;
            let found = key.tumbler();
            if same_chain(found, t) {
                return Some((key, counted));
            }
            let extends_a_chain_address = found.len() > t.len()
                && found.iter().zip(t.iter()).take(t.len() - 1).all(|(a, b)| a == b);
            if !extends_a_chain_address {
                return None;
            }
            probe = Cow::Owned(Tumbler::new(found.iter().take(t.len()).cloned()).ok()?);
        }
    }
}

#[cfg(test)]
mod tests {
    use skep_address::validate;

    use super::*;
    use crate::{stage_stretch, ContentStore};

    /// `len` bytes with a line break at every fifth, and at the first two
    /// and the last of each block, so a count or a search off by one at a
    /// block's edge lands on a byte that tells.
    fn patterned(len: usize) -> Arc<[u8]> {
        (0..len)
            .map(|at| match at % BLOCK {
                edge if edge <= 1 || edge == BLOCK - 1 || at % 5 == 0 => LINE_BREAK,
                _ => b'x',
            })
            .collect()
    }

    /// The offsets of `bytes`' line breaks, and the count below each offset
    /// from zero to one past the bytes: what a walk of the bytes finds.
    fn walked(bytes: &[u8]) -> (Vec<usize>, Vec<u64>) {
        let found: Vec<usize> =
            (0..bytes.len()).filter(|&offset| bytes[offset] == LINE_BREAK).collect();
        let mut below = vec![0; bytes.len() + 2];
        for offset in 0..=bytes.len() {
            let here = bytes.get(offset).is_some_and(|&byte| byte == LINE_BREAK);
            below[offset + 1] = below[offset] + u64::from(here);
        }
        (found, below)
    }

    /// The tumbler at `ordinal` of one document's content chain.
    fn at(ordinal: usize) -> Tumbler {
        let chain = [1u32, 0, 1, 0, 1, 0, 1].map(Nat::from);
        Tumbler::new(chain.into_iter().chain([Nat::from(ordinal)])).expect("nonempty")
    }

    #[test]
    fn an_entry_counts_and_finds_at_every_offset_as_its_bytes_do_whatever_its_blocks() {
        // `Breaks`: a stretch longer than one block keeps its running count
        // at each whole block, and `before` and `nth` read the count there
        // and scan one block at most. So at every length about a block's
        // edge — one byte, one short of a block, a block, one past it, two
        // blocks whole, three and a part — every offset's count and every
        // line break's offset are the ones a walk of the bytes finds; a mark
        // stands for each whole block exactly where the bytes pass one
        // block; and bytes with no line break are not kept at all.
        for len in [1, BLOCK - 1, BLOCK, BLOCK + 1, 2 * BLOCK, 3 * BLOCK + 17] {
            let bytes = patterned(len);
            let (found, below) = walked(&bytes);
            let breaks = Breaks::of(&bytes).expect("the pattern opens with a line break");
            assert_eq!(breaks.count, found.len() as u64, "the count of {len} bytes");
            assert_eq!(
                breaks.marks.as_deref().map(<[u64]>::len),
                (len > BLOCK).then_some(len / BLOCK),
                "one mark for each whole block of {len} bytes, and none at one block or under"
            );
            for (offset, &below) in below.iter().enumerate() {
                assert_eq!(breaks.before(offset), below, "before offset {offset} of {len} bytes");
            }
            for nth in 0..=found.len() {
                assert_eq!(
                    breaks.nth(nth as u64),
                    found.get(nth).copied(),
                    "line break {nth} of {len} bytes"
                );
            }
        }
        assert!(Breaks::of(&Arc::from(vec![b'x'; 2 * BLOCK])).is_none(), "no line break, no entry");
    }

    #[test]
    fn the_two_reads_answer_inside_a_stretch_of_many_blocks_as_its_bytes_do() {
        // The same law through the slice's two reads, over one stretch of
        // three blocks and a part standing at ordinal 9: the line breaks
        // before every address of it and the two past it; and the address of
        // every line break, asked from the stretch's first address and from
        // a block below the line break's own, the line breaks between
        // counted off.
        let bytes = patterned(3 * BLOCK + 17);
        let (found, below) = walked(&bytes);
        let c = ContentStore::default();
        let first = validate(at(9)).expect("a content element address");
        let c = c.apply_stretch(&stage_stretch(&c, first, Arc::clone(&bytes)).expect("fresh"));
        for (offset, &below) in below.iter().enumerate() {
            assert_eq!(c.line_breaks_before(&at(9 + offset)), below, "before offset {offset}");
        }
        for (nth, &offset) in found.iter().enumerate() {
            assert_eq!(c.nth_line_break_from(&at(9), nth as u64), Some(at(9 + offset)));
            let from = offset.saturating_sub(BLOCK);
            assert_eq!(
                c.nth_line_break_from(&at(9 + from), below[offset] - below[from]),
                Some(at(9 + offset)),
                "the line break at offset {offset}, asked from offset {from}"
            );
        }
        assert_eq!(c.nth_line_break_from(&at(9), found.len() as u64), None, "past the last");
    }
}
