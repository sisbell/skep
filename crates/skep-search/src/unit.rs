//! The document model (`search.md` §2.1, §2.4): ONE UNIT PER DOCUMENT
//! VERSION's ARRANGED CONTENT, read by `retrieve_v` over the document's whole
//! content-subspace extent — in one delivery where it holds no more than
//! `MAX_DELIVERY_ITEMS` positions, in consecutive parts where it holds more
//! — and handed to this crate TYPED, as the shell parsed it: a sequence of
//! [`Item`]s, each an [`Item::Text`] — one `content` item's bytes, or a
//! `hex` run's — or an [`Item::Gap`] for every item that is not text (an
//! atom, a withheld run, a kind the shell does not know), at its width. The
//! parts are JOINED in order into one [`Unit`]: adjacent text items become
//! one, so a character split at a part's edge is rejoined and never a `hex`
//! run, and the tokenizer runs over the joined text, so no token and no
//! phrase is cut at an edge (§2.1). The unit keeps the ITEM TABLE — each
//! item's start ordinal, width and kind — so a term found at byte `b` of
//! text item `i` is at V-position `1.(start_i + b)`, byte-exact by the
//! wire's one-value-per-byte discipline (§0 fact 11), and the item an
//! occurrence lies in is found by a binary search over the starts
//! ([`Unit::item_at`]; §2.3).
//!
//! THE UNIT KEY is the bare document address ALONE ([`UnitKey`]; §2.1): every
//! re-read of a document, a `publish`'s included, enters under the same key
//! and REPLACES. The pinned member the unit was read at, its `as_of`, its
//! kind and the CLASS it was read at ride beside the key (§2.1, §3.1).
//! Which member is read is §2.4's head rule, [`moved_head`]: the trunk head
//! alone per published document — a daughter's row moves no head, an
//! owner's `version` row moves it.
//!
//! What a unit does NOT hold (§2.2): un-arranged values, links (subspace 2
//! never appears in a content delivery), an atom's interior bytes, a media
//! cell's bytes, a withheld run's text. A unit's LIVE BYTES ([`Unit::bytes`])
//! are its bytes of text — what the ceiling counts (§7.4) and what
//! `Prepared` carries to `merge` (§1.4).

use std::error::Error;
use std::fmt;

use skep_address::{is_prefix, Address};

/// The class a read was made at, and so the class an index holds (`search.md`
/// §1.4, §2.1; §5.2 D7): token-free reads are `Guest`, the published index's
/// class; reads under principal `n`'s session are `Principal(n)`, the class
/// of `n`'s supplement. A [`Unit`] carries the class it was read at — the
/// embedder's word — and an index refuses a unit of any other class at
/// `merge`, so §4's invariants (i) and (ii) hold in the crate whatever the
/// embedder hands it; the tag guards the file-choice bug and proves nothing
/// more.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Class {
    /// A token-free read: the published index's class.
    Guest,
    /// A read under this principal's session: its supplement's class.
    Principal(u64),
}

impl fmt::Display for Class {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Class::Guest => f.write_str("guest"),
            Class::Principal(n) => write!(f, "principal {n}"),
        }
    }
}

/// Edition or draft (`search.md` §2.1, §3.1): a function of the document,
/// publication being fixed at its birth — no op publishes a draft in place.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Kind {
    /// A published chain; the unit is read at a pinned member (§2.4).
    Edition,
    /// A draft; the unit is read at the draft's own address.
    Draft,
}

/// The unit's key: the bare document address ALONE (`search.md` §2.1), so
/// every re-read of a document enters under the same key and replaces, and
/// so the keys sort in the address order, under which every document below
/// a prefix is one contiguous range — the order THE ENUMERATOR's one read
/// over the keys (RULED (b); lane SR-3) walks.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct UnitKey(Address);

impl UnitKey {
    /// The key of the document at `doc` — its bare address, the chain's
    /// prefix, never a member's.
    pub fn new(doc: Address) -> UnitKey {
        UnitKey(doc)
    }

    /// The document's bare address.
    pub fn doc(&self) -> &Address {
        &self.0
    }
}

impl fmt::Display for UnitKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

/// What an item that is not text is (`search.md` §2.1, §2.2; wire.md §Value
/// encodings). Each occupies its positions and indexes nothing; the
/// tokenizer advances its ordinal by one across it, so no phrase crosses it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GapKind {
    /// An `atom` or `atom_hex`: one position holding a composite value whose
    /// interior bytes are permanently unaddressable (§2.2).
    Atom,
    /// A `withheld` run, never delivered to this reader (§2.2): its origin
    /// DOCUMENT kept for the `Gap` mark the snippet carries (§6).
    Withheld {
        /// The run's origin document, as the wire names it.
        origin: Address,
    },
    /// An item kind the shell does not know, which carries its width by the
    /// wire's forward rule and is kept at its place.
    Unknown,
}

/// One item of a delivery, typed (`search.md` §2.1) — a row of the item
/// table, at `start`, its first V-ordinal: the extent's start plus the widths
/// of the items before it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Item {
    /// One `content` item's bytes, or a `hex` run's: the crate judges UTF-8
    /// over the JOINED parts, indexing the valid stretches as text at their
    /// own ordinals and taking each invalid byte as a token break (§2.2).
    Text {
        /// The first byte's V-ordinal.
        start: u64,
        /// The bytes, one per position.
        bytes: Vec<u8>,
    },
    /// Every item that is not text, at its width.
    Gap {
        /// The first position's V-ordinal.
        start: u64,
        /// The positions it occupies: one for an atom, the run's count for a
        /// withheld run, whatever width an unknown kind carries.
        width: u64,
        /// What it is.
        kind: GapKind,
    },
}

impl Item {
    /// The item's first V-ordinal.
    pub fn start(&self) -> u64 {
        match self {
            Item::Text { start, .. } | Item::Gap { start, .. } => *start,
        }
    }

    /// The positions the item occupies: a text item's byte count, a gap's
    /// width.
    pub fn width(&self) -> u64 {
        match self {
            Item::Text { bytes, .. } => bytes.len() as u64,
            Item::Gap { width, .. } => *width,
        }
    }
}

/// Why [`Unit::new`] refused the items (`search.md` §2.1): the parts are
/// consecutive sub-spans of one extent, so their items are one contiguous
/// sequence of ordinals. A sequence that is not is the shell's bug — a part
/// dropped or re-ordered — and never a unit.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum UnitError {
    /// Item `index` starts at `found` where the items before it reach
    /// `expected`.
    Discontiguous {
        /// The offending item's index in the sequence handed in.
        index: usize,
        /// The ordinal the items before it reach.
        expected: u64,
        /// The ordinal it starts at.
        found: u64,
    },
    /// Item `index` reaches past the ordinal space this crate counts in.
    Overflow {
        /// The offending item's index in the sequence handed in.
        index: usize,
    },
}

impl fmt::Display for UnitError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            UnitError::Discontiguous { index, expected, found } => write!(
                f,
                "item {index} starts at ordinal {found} where the items before it reach {expected}"
            ),
            UnitError::Overflow { index } => {
                write!(f, "item {index} reaches past the ordinal space")
            }
        }
    }
}

impl Error for UnitError {}

/// One document version's arranged content, delivered in parts and joined
/// (`search.md` §2.1): the key, what rides beside it, and the item table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Unit {
    key: UnitKey,
    member: Option<Address>,
    kind: Kind,
    class: Class,
    as_of: u64,
    start: u64,
    items: Vec<Item>,
    bytes: u64,
}

impl Unit {
    /// The unit from its parts' items in order — a part's edge is where one
    /// text item meets the next, and the join makes them one, so a character
    /// split there is whole again (§2.1). `member` is the pinned member an
    /// edition was read at, the draft's own address for a draft, absent for
    /// a published document without a member; `as_of` the last part's
    /// position; `class` the class the reads were made at. Refused where the
    /// items are not one contiguous extent.
    pub fn new(
        key: UnitKey,
        member: Option<Address>,
        kind: Kind,
        class: Class,
        as_of: u64,
        items: impl IntoIterator<Item = Item>,
    ) -> Result<Unit, UnitError> {
        let mut joined: Vec<Item> = Vec::new();
        let mut reach: Option<u64> = None;
        let mut bytes = 0u64;
        for (index, item) in items.into_iter().enumerate() {
            if let Some(expected) = reach {
                if item.start() != expected {
                    return Err(UnitError::Discontiguous { index, expected, found: item.start() });
                }
            }
            reach =
                Some(item.start().checked_add(item.width()).ok_or(UnitError::Overflow { index })?);
            if let Item::Text { bytes: more, .. } = &item {
                bytes += more.len() as u64;
            }
            let merged = match (joined.last_mut(), &item) {
                (Some(Item::Text { bytes: prev, .. }), Item::Text { bytes: more, .. }) => {
                    prev.extend_from_slice(more);
                    true
                }
                _ => false,
            };
            if !merged {
                joined.push(item);
            }
        }
        let start = joined.first().map_or(0, Item::start);
        Ok(Unit { key, member, kind, class, as_of, start, items: joined, bytes })
    }

    /// The key: the bare document address.
    pub fn key(&self) -> &UnitKey {
        &self.key
    }

    /// The member the unit was read at (§2.1): the pinned member for an
    /// edition, the draft's own address for a draft, absent for a published
    /// document without a member.
    pub fn member(&self) -> Option<&Address> {
        self.member.as_ref()
    }

    /// Edition or draft.
    pub fn kind(&self) -> Kind {
        self.kind
    }

    /// The class the unit was read at (§2.1's class check reads it).
    pub fn class(&self) -> Class {
        self.class
    }

    /// The board position the unit's read was made at — the last part's.
    pub fn as_of(&self) -> u64 {
        self.as_of
    }

    /// The extent's start: the first item's ordinal, the one every
    /// occurrence's offset is counted from (§2.3). Zero for a unit of no
    /// items.
    pub fn start(&self) -> u64 {
        self.start
    }

    /// The item table, joined: each item at its start ordinal, in order and
    /// contiguous.
    pub fn items(&self) -> &[Item] {
        &self.items
    }

    /// The unit's LIVE BYTES: its bytes of text, what the ceiling counts
    /// (§7.4). A gap adds none.
    pub fn bytes(&self) -> u64 {
        self.bytes
    }

    /// The extent's width in positions: every text byte and every gap's
    /// width.
    pub fn positions(&self) -> u64 {
        self.items.iter().map(Item::width).sum()
    }

    /// The item holding the position at `offset` from the unit's start —
    /// the occurrence's item, where the snippet needs it (§2.3) — by a
    /// binary search over the item table's start ordinals. `None` past the
    /// extent.
    pub fn item_at(&self, offset: u64) -> Option<usize> {
        let ordinal = self.start.checked_add(offset)?;
        let after = self.items.partition_point(|item| item.start() <= ordinal);
        let index = after.checked_sub(1)?;
        let item = &self.items[index];
        (ordinal - item.start() < item.width()).then_some(index)
    }
}

/// §2.4's head rule, as a function of one minting row: `minted` is the row's
/// `docs` member — the minted member for `publish`, the minted document or
/// member for `version` — and the answer is the new head of `doc`, or `None`
/// where the row moves no head. The head is the LATEST TRUNK MEMBER any
/// minting row names: a member one version component past the document
/// (`D.k`), which an owner's `version` of a published document mints as a
/// `publish` does; a DAUGHTER — more than one component past the document,
/// which a shot whose base the trunk had passed mints in the nested form
/// (`D.k.j`) — never floats and moves no head; a row naming another
/// document is not this document's (a cross-owner `version` mints a fresh
/// document, indexed as its own). Later is the tumbler order: trunk members
/// are minted densely and in order, so the greater `k` is the row seen
/// later. One component count per row, no read.
pub fn moved_head(doc: &Address, head: Option<&Address>, minted: &Address) -> Option<Address> {
    let on_trunk = is_prefix(doc.tumbler(), minted.tumbler())
        && minted.tumbler().len() == doc.tumbler().len() + 1;
    if !on_trunk {
        return None;
    }
    match head {
        Some(held) if held >= minted => None,
        _ => Some(minted.clone()),
    }
}

#[cfg(test)]
mod tests;
