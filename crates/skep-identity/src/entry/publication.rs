//! The `publish` body's deposit rows: the rows a publication's PUBLIC
//! deposits add behind today's shot body (the link-sets design §5.7, THE
//! SIGNED ENTRY — the signed-ops record's D25 delta).
//!
//! The body of a publication that carries deposits is today's `publish` body
//! — `be64(placed)`, the segments, the base group, which the child module
//! `publish` builds and which is UNCHANGED for a request carrying none —
//! followed by one group per public deposit, in the one order the signer
//! and every verifier compute (the design's: the homes member first, then
//! a minted edition, then every other home in address order; inside a home
//! the edition claim, then the copies, then the retractions, then the
//! read-withs, each list in declared order), each group:
//!
//! * **the home row** — the deposit's home, one length-delimited element:
//!   the tag `member` or `edition` where the commit mints the home, else
//!   the home's address in the address row's spelling ([`DepositHome`]);
//! * **the kind byte** — `0x01` the edition claim, `0x02` a copy, `0x03` a
//!   retraction, `0x04` a read-with ([`DepositKind`]): the token the
//!   deposit's own op would carry, as one byte, so two deposits of one
//!   shape under different acts spell different bodies;
//! * **the four rows its own op signs** — the type slot, the `from` slot,
//!   the `to` slot, then the `replaces` row EMPTY (`be32(0)`; no deposit of
//!   a publication carries the member) — a copy's and a read-with's the
//!   `make_link` body's, a retraction's `nullify`'s, the edition claim's a
//!   `make_link` body's — each slot one of two rows:
//!   - **the slot row as stored** (the parent's `0x03` row) over elements
//!     ([`SlotElement`]): a span as the parent spells it, its start and its
//!     width each length-delimited; or a TAG standing for an address the
//!     commit mints — `member`, `edition` — spelled as the tag's token where
//!     a start goes and the EMPTY element where a width goes, which no span
//!     spells (a tumbler's spelling is never empty), so a tag element and a
//!     span element are told apart by the second element alone;
//!   - **the member-position row** (`0x04`): `be64(n)` then each span of
//!     the member's positions as `be64(ordinal) ‖ be64(width)`
//!     ([`MemberPositions`]) — THE MEMBER-POSITION END FORM, an end on the
//!     shot's own words signed as its span of the member's positions inside
//!     `[1, placed]`, never the fresh I-span the commit mints.
//!
//! No count leads the groups: a request carrying no deposit spells today's
//! body byte for byte, which is what keeps every signer and golden of the
//! shot alone standing. The body stays uniquely decodable from its front:
//! today's body ends where its base group ends (the child module states
//! why), and what follows is the groups, each self-delimiting — a delimited
//! home, one kind byte, three self-delimiting slot rows and one delimited
//! group.

use skep_address::{Address, Span};

use super::{address_bytes, push_delimited, push_optional_address, EntryBody, Grammar};

/// The home a deposit's rows are prefixed by.
///
/// A home the commit mints is named by tag — the member always, the edition
/// where the request mints one — since no signer holds its address before
/// the commit (the design's M2); every other home by its address.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DepositHome<'a> {
    /// The member the commit mints: the tag `member`.
    Member,
    /// The edition the commit mints: the tag `edition`.
    Edition,
    /// A home standing before the commit, by its address.
    Address(&'a Address),
}

/// The kind of one public deposit: the body's kind byte.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DepositKind {
    /// The edition claim (R20), homed in the edition the commit mints.
    EditionClaim,
    /// An accepted link's public copy, a `links` entry.
    Copy,
    /// A held removal's retraction, a `retract` entry.
    Retraction,
    /// A read-with, a `read_with` entry.
    ReadWith,
}

impl DepositKind {
    /// Returns the kind byte.
    fn byte(self) -> u8 {
        match self {
            DepositKind::EditionClaim => 0x01,
            DepositKind::Copy => 0x02,
            DepositKind::Retraction => 0x03,
            DepositKind::ReadWith => 0x04,
        }
    }
}

/// One element of a slot row as stored.
///
/// A span as the store holds it, or a tag standing for an address the
/// commit mints, which the store will hold as that address's unit span and
/// a verifier spells back as the tag.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SlotElement<'a> {
    /// A stored span.
    Span(&'a Span),
    /// The member the commit mints, by tag.
    Member,
    /// The edition the commit mints, by tag.
    Edition,
}

/// One span of the member's positions, the member-position end form.
///
/// `ordinal` is the first position, 1-based, and `width` the count, at
/// least one; the span lies inside `[1, placed]`. Which positions a request
/// may spell — the lowest holding each value, the design's canonical rule —
/// is the request's door's to decide; this row spells what it is handed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct MemberPositions {
    /// The first position, 1-based.
    pub ordinal: u64,
    /// The count of positions, at least one.
    pub width: u64,
}

/// A deposit's slot as the body spells it: as stored, or by the member's
/// positions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DepositSlot<'a> {
    /// The slot row as stored, over its elements.
    Stored(Vec<SlotElement<'a>>),
    /// The member-position row.
    MemberPositions(Vec<MemberPositions>),
}

/// One public deposit's rows: its home, its kind and its three slots.
///
/// The `replaces` row is no field: it is EMPTY for every deposit of a
/// publication, as the builder spells it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DepositRow<'a> {
    /// The home the deposit lands in.
    pub home: DepositHome<'a>,
    /// Which act's rows these are.
    pub kind: DepositKind,
    /// The type slot.
    pub ty: DepositSlot<'a>,
    /// The `from` slot.
    pub from: DepositSlot<'a>,
    /// The `to` slot.
    pub to: DepositSlot<'a>,
}

/// The member-position row's form byte.
const MEMBER_POSITIONS_FORM: u8 = 0x04;

/// The slot row's form byte, the parent's `0x03`, spelled here for the
/// tagged elements this module adds to it.
const SLOT_FORM_STORED: u8 = 0x03;

/// The tags' tokens, as the home row and a tag element spell them.
const MEMBER_TAG: &[u8] = b"member";
const EDITION_TAG: &[u8] = b"edition";

/// Returns the `publish` body of a publication: `shot`, today's body, then
/// the groups of `deposits` in the order given.
///
/// `shot` is the body [`entry_body_publish`](super::entry_body_publish) or
/// [`PublishBody::finish`](super::PublishBody::finish) returned — the shot's
/// own rows, unchanged. With no deposit the body is `shot` byte for byte.
/// The order of `deposits` is the caller's, which is the design's one order
/// (the module doc); this builder spells what it is handed.
///
/// # Panics
///
/// Panics where `shot` is not a `publish` body, naming the obligation: the
/// deposit rows extend one grammar alone. And where an address's or a
/// tumbler's spelling is 2^32 bytes or longer, as every row does.
pub fn entry_body_publication(shot: EntryBody, deposits: &[DepositRow<'_>]) -> EntryBody {
    assert!(
        shot.grammar == Grammar::Publish,
        "entry_body_publication: the deposit rows extend the `publish` body alone, and this \
         `{}` body was handed in",
        shot.op()
    );
    let EntryBody { grammar, mut bytes } = shot;
    for deposit in deposits {
        push_deposit(&mut bytes, deposit);
    }
    EntryBody { grammar, bytes }
}

/// Writes one deposit's group onto `out`: the home row, the kind byte, the
/// three slot rows, the EMPTY `replaces` row.
fn push_deposit(out: &mut Vec<u8>, deposit: &DepositRow<'_>) {
    match deposit.home {
        DepositHome::Member => push_delimited(out, MEMBER_TAG),
        DepositHome::Edition => push_delimited(out, EDITION_TAG),
        DepositHome::Address(a) => push_delimited(out, &address_bytes(a)),
    }
    out.push(deposit.kind.byte());
    push_deposit_slot(out, &deposit.ty);
    push_deposit_slot(out, &deposit.from);
    push_deposit_slot(out, &deposit.to);
    push_optional_address(out, None);
}

/// Writes one deposit slot's row onto `out`: the slot row as stored over its
/// elements, or the member-position row.
fn push_deposit_slot(out: &mut Vec<u8>, slot: &DepositSlot<'_>) {
    match slot {
        DepositSlot::Stored(elements) => {
            out.push(SLOT_FORM_STORED);
            out.extend_from_slice(&(elements.len() as u64).to_be_bytes());
            for element in elements {
                match element {
                    SlotElement::Span(span) => {
                        push_delimited(out, span.start().to_string().as_bytes());
                        push_delimited(out, span.width().to_string().as_bytes());
                    }
                    SlotElement::Member => {
                        push_delimited(out, MEMBER_TAG);
                        push_delimited(out, &[]);
                    }
                    SlotElement::Edition => {
                        push_delimited(out, EDITION_TAG);
                        push_delimited(out, &[]);
                    }
                }
            }
        }
        DepositSlot::MemberPositions(spans) => {
            out.push(MEMBER_POSITIONS_FORM);
            out.extend_from_slice(&(spans.len() as u64).to_be_bytes());
            for span in spans {
                out.extend_from_slice(&span.ordinal.to_be_bytes());
                out.extend_from_slice(&span.width.to_be_bytes());
            }
        }
    }
}

#[cfg(test)]
mod tests;
