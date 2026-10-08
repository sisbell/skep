//! The entry frame's LAWS, stated through the public surface a signer and a
//! verifier both call (signed ops; the design record §2.5). The byte pins
//! beside the rows (`src/entry/tests.rs`) fix each row at a chosen instance;
//! what is stated here holds over a whole family no pin enumerates.

use crate::common;

use std::collections::BTreeMap;
use std::num::NonZeroU64;

use common::{addr, tum};
use skep_address::Span;
use skep_identity::{
    entry_body_assert_sup, entry_body_edit_link, entry_body_emit, entry_body_make_link,
    entry_body_make_link_replacing, entry_body_nullify, entry_body_publish, unit_span, EntrySlot,
    LinkSlots, PublishBody, PublishRefusal, ShotBase, ShotSegmentPiece,
};

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
/// slot's spans, their ORDER and their REPEATS are all part of what a link
/// deposits; two links whose bodies spelled alike would share every signature
/// over either, and a reader beside the table could not tell the link that
/// was signed from its twin. The family is every slot of at most two spans
/// over two stored spans — a unit span, as an address named stores, and a
/// resolved content extent — the empty slot, each span alone, and every
/// ordered pair, repeats included — in each of a `make_link`'s three slots:
/// 7³ bodies, all distinct; and an `edit_link` body over each of those
/// triples under each of two originals, 2 × 7³ more, distinct among
/// themselves and from every `make_link` body.
///
/// Why a law and not a pin: the row pins spell a slot of one span or of two
/// distinct ones. A `push_slot` that deduplicated its spans, sorted them, or
/// wrote nothing for an empty slot keeps every one of them green. The first
/// two keep every signed-ops cell in skepd green too, whose signer and
/// verifier both spell through it; the third is caught otherwise only a
/// crate away, by skepd's hand-spelled frame pin and the goldens signed over
/// the same frames.
#[test]
fn no_two_distinct_slot_triples_spell_one_make_link_body() {
    // DESCENDING in address order and in spelled order alike, so a row that
    // sorted its spans by either comparison reorders every mixed pair.
    let span = |start: &[u32], width: &[u32]| Span::new(tum(start), tum(width)).expect("T12-valid");
    let spans = [span(&[1, 0, 30, 0, 1, 0, 1, 1], &[0, 0, 0, 0, 0, 0, 0, 2]), unit_span(&addr(&[1, 0, 2]))];
    let slot_spans = sequences_of(&spans);
    let family: Vec<EntrySlot<'_>> = slot_spans.iter().map(|s| EntrySlot(s)).collect();
    assert_eq!(family.len(), 7, "the empty slot, each span alone, every ordered pair");

    let originals = [unit_span(&addr(&[1, 0, 2, 0, 1, 0, 2, 1])), unit_span(&addr(&[1, 0, 2, 0, 1, 0, 2, 2]))];
    let mut spelled: BTreeMap<Vec<u8>, String> = BTreeMap::new();
    for &ty in &family {
        for &from in &family {
            for &to in &family {
                let slots = LinkSlots { from, to, ty };
                let body = entry_body_make_link(slots).as_bytes().to_vec();
                if let Some(earlier) = spelled.insert(body, format!("make_link {slots:?}")) {
                    panic!("two distinct inputs spell one body:\n  {earlier}\n  make_link {slots:?}");
                }
                for original in &originals {
                    let body = entry_body_edit_link(slots, original).as_bytes().to_vec();
                    let named = format!("edit_link {slots:?} of {original:?}");
                    if let Some(earlier) = spelled.insert(body, named.clone()) {
                        panic!("two distinct inputs spell one body:\n  {earlier}\n  {named}");
                    }
                }
            }
        }
    }
    assert_eq!(spelled.len(), 3 * family.len().pow(3), "every input spelled a body of its own");
}

/// A walk of a slot's spans that CLAIMS NOTHING of its length — its
/// `size_hint` the default, `(0, None)`, what `std::iter::from_fn` claims,
/// and no `ExactSizeIterator` — so only the spans it yields say how many
/// there are.
struct ClaimsNoLength<'a>(std::slice::Iter<'a, Span>);

impl<'a> Iterator for ClaimsNoLength<'a> {
    type Item = &'a Span;

    fn next(&mut self) -> Option<&'a Span> {
        self.0.next()
    }
}

/// A link-write body reads each slot as a WALK of its spans as stored, so
/// the store's own slot frames in place: M7 keeps an endset in an
/// `im::Vector`, with no slice to borrow, and a composer holding the stored
/// link hands its `&Endset`s over as they lie. The law, over every slot
/// triple of the family above and under each link-write builder: the body
/// over borrowed persistent vectors of the spans, and the body over walks
/// that claim nothing of their length ([`ClaimsNoLength`]), IS the body over
/// slices of them — neither the container the spans are kept in nor the
/// length a walk claims moves a byte, the slot row's count being the spans
/// walked (`push_slot`'s card: "never a length the walk claims").
///
/// Why a law and not a pin: the row pins, the goldens and every signer in the
/// workspace frame slices, and the daemon's composer — the verifier at the
/// commit — frames M7's endsets in place, so the two meet only here: the
/// signer's preimage and the daemon's are one only if the container moves no
/// byte. A slot type narrowed back to slices stops this law's build, and the
/// composer's in-place framing with it. And every walk the workspace frames
/// knows its length exactly — a slice, an `im::Vector`, M7's `Spans` — so a
/// slot row that wrote its count from the walk's `size_hint`, or builders
/// narrowed to `ExactSizeIterator` walks, kept every other pin, the goldens
/// and skepd's cells green; only a walk that claims nothing tells them apart.
#[test]
fn a_link_write_body_is_the_same_over_any_walk_of_its_slots() {
    let span = |start: &[u32], width: &[u32]| Span::new(tum(start), tum(width)).expect("T12-valid");
    let spans =
        [span(&[1, 0, 30, 0, 1, 0, 1, 1], &[0, 0, 0, 0, 0, 0, 0, 2]), unit_span(&addr(&[1, 0, 2]))];
    let slices = sequences_of(&spans);
    let vectors: Vec<im::Vector<Span>> =
        slices.iter().map(|s| s.iter().cloned().collect()).collect();
    let family: Vec<(EntrySlot<'_>, &im::Vector<Span>)> =
        slices.iter().map(|s| EntrySlot(s)).zip(&vectors).collect();
    assert_eq!(family.len(), 7, "the empty slot, each span alone, every ordered pair");
    let original = unit_span(&addr(&[1, 0, 2, 0, 1, 0, 2, 1]));
    let replaces = addr(&[1, 0, 1, 0, 1, 0, 2, 9]);
    for &(ty, ty_vector) in &family {
        for &(from, from_vector) in &family {
            for &(to, to_vector) in &family {
                let over_slices = LinkSlots { from, to, ty };
                let over_vectors = LinkSlots { from: from_vector, to: to_vector, ty: ty_vector };
                // A fresh walk per body: a `ClaimsNoLength` is spent by the
                // body it is framed into.
                let claiming_nothing = || LinkSlots {
                    from: ClaimsNoLength(from.0.iter()),
                    to: ClaimsNoLength(to.0.iter()),
                    ty: ClaimsNoLength(ty.0.iter()),
                };
                for (by_vector, by_claiming_nothing, by_slice, builder) in [
                    (
                        entry_body_make_link(over_vectors),
                        entry_body_make_link(claiming_nothing()),
                        entry_body_make_link(over_slices),
                        "make_link",
                    ),
                    (
                        entry_body_make_link_replacing(over_vectors, &replaces),
                        entry_body_make_link_replacing(claiming_nothing(), &replaces),
                        entry_body_make_link_replacing(over_slices, &replaces),
                        "make_link replacing",
                    ),
                    (
                        entry_body_emit(over_vectors),
                        entry_body_emit(claiming_nothing()),
                        entry_body_emit(over_slices),
                        "emit",
                    ),
                    (
                        entry_body_nullify(over_vectors),
                        entry_body_nullify(claiming_nothing()),
                        entry_body_nullify(over_slices),
                        "nullify",
                    ),
                    (
                        entry_body_assert_sup(over_vectors),
                        entry_body_assert_sup(claiming_nothing()),
                        entry_body_assert_sup(over_slices),
                        "assert_sup",
                    ),
                    (
                        entry_body_edit_link(over_vectors, &original),
                        entry_body_edit_link(claiming_nothing(), &original),
                        entry_body_edit_link(over_slices, &original),
                        "edit_link",
                    ),
                ] {
                    assert_eq!(
                        by_vector, by_slice,
                        "{builder} over {over_slices:?}: persistent vectors"
                    );
                    assert_eq!(
                        by_claiming_nothing, by_slice,
                        "{builder} over {over_slices:?}: walks that claim no length"
                    );
                }
            }
        }
    }
}

/// [`PublishBody`]'s budget is TIGHT, whatever piece crosses it — the
/// builder's card: the budget bounds the FINISHED body, and a push or window
/// refuses `PastBudget` exactly where that body would pass it. A piece's cost
/// depends on its shape: a value OPENING a stretch pays the class byte and the
/// count besides its length prefix, a value JOINING one its prefix and bytes
/// alone, and a window its class byte, start and width whether or not it
/// CLOSES a stretch, the stretch's count being written back in place. Every
/// sequence of one or two pieces over an empty value, a value and two windows
/// ends in each of those shapes, so the family is every crossing there is;
/// for each, under either shape of the base group, a budget of the
/// finished body's own length takes every piece and finishes to
/// [`entry_body_publish`]'s body, and one byte less refuses it.
///
/// Why a law and not a pin: the budget pins in `src/entry/tests.rs` cross
/// their budgets with a value that opens a stretch and a window that opens
/// the body, and skepd's wire cell with values that join a stretch. A builder
/// that over-charged a joining value kept every pin here green, and one that
/// over-charged a window closing a stretch kept skepd's cell green too —
/// refusing, PERMANENT, `frame_too_large`, an honest attested publish whose
/// body sat within its budget.
#[test]
fn every_publish_body_lands_exactly_on_a_budget_of_its_own_length() {
    let (start, other) = (addr(&[1, 0, 2, 0, 1, 4]), addr(&[1, 0, 30, 0, 1, 1]));
    let nonzero = |n: u64| NonZeroU64::new(n).expect("a window holds at least one position");
    let alphabet = [
        ShotSegmentPiece::Value(b""),
        ShotSegmentPiece::Value(b"ab"),
        ShotSegmentPiece::Window { start: &start, width: nonzero(1) },
        ShotSegmentPiece::Window { start: &other, width: nonzero(2) },
    ];
    let fed = |budget: usize, base: Option<ShotBase<'_>>, pieces: &[ShotSegmentPiece<'_>]| {
        let empty = PublishBody::within(budget, base);
        pieces.iter().try_fold(empty, |body, piece| match *piece {
            ShotSegmentPiece::Value(value) => body.push(value),
            ShotSegmentPiece::Window { start, width } => body.window(start, width),
        })
    };
    let sequences = sequences_of(&alphabet);
    assert_eq!(sequences.len(), 21, "the empty sequence, four alone, sixteen pairs");
    let base_member = addr(&[1, 0, 1, 0, 1, 2]);
    for base in [None, Some(ShotBase { member: &base_member, extent: 5 })] {
        for pieces in sequences.iter().filter(|pieces| !pieces.is_empty()) {
            let whole = entry_body_publish(pieces.iter().copied(), base);
            let budget = whole.as_bytes().len();
            assert_eq!(
                fed(budget, base, pieces).map(PublishBody::finish),
                Ok(whole),
                "{pieces:?} under {base:?}: exactly on its budget"
            );
            assert_eq!(
                fed(budget - 1, base, pieces).err(),
                Some(PublishRefusal::PastBudget),
                "{pieces:?} under {base:?}: one byte short"
            );
        }
    }
}
