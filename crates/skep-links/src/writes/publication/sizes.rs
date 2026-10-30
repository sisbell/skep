//! THE WORST-CASE TABLE (the link-sets design §5.6, M6): the bytes the
//! kernel prices each kind of record a publication stages at, one constant
//! per entry kind; the price of a request's staged bytes from it
//! ([`price_staged_bytes`], the fifth term of the pre-lock price); and two
//! sums against the transaction budget — the maximal request's, a product
//! of caps, and the reachable request's, what a body within the frame
//! routes' cap can command.
//!
//! Every figure is the staged bytes AS THE KERNEL PRICES THEM: the journal
//! frame per record — its 12-byte header and the 28 bytes the frame payload
//! wraps around the record's encoding — summed over the records the kind
//! stages, the commit marker (one per transaction, outside every figure
//! here) aside. Each is measured by `tests/it/publication.rs` on a journaled
//! kernel as the difference two transactions' bytes make, and held equal to
//! its constant there, so the table moves when the record encodings do and
//! a figure that drifts is a red test, not a stale number. The depth every
//! figure is measured at is THE SHALLOW END: a top-level document of an
//! account (`1.0.1.0.3`, five components), its content elements at eight,
//! its links at eight, its members at six — the depth `budget.rs`'s span
//! argument prices from. A span's own bytes are not a constant but a
//! function of its depth and its components' magnitudes
//! ([`stored_span_bytes`]: the kernel's bincode fixint layout, an 8-byte
//! length before every sequence and 4 bytes per 32-bit digit of a
//! component), measured too, so a slot is priced at the spans the request
//! spells and never at a depth it does not have.
//!
//! What a panel prices from it (M6), and what [`price_staged_bytes`]
//! prices: a correspondence record per piece the shot mints
//! ([`CORRESPONDENCE_RECORD_BYTES`]), a copy and its claim per `links` entry
//! ([`COPY_FIXED_BYTES`] with its slots' spans at their own bytes —
//! [`COPY_BYTES`] is the copy with every slot at `MAX_SLOT_SPANS` spans of
//! the shallow depth — and [`CLAIM_BYTES`]), a retraction per `retract`
//! entry ([`RETRACTION_BYTES`]), a read-with per `read_with` entry
//! ([`READ_WITH_BYTES`]), the re-window per piece at a kept place
//! ([`KEPT_PLACE_BYTES`], a placement and a removal), the shot's own
//! placement per run ([`PLACED_RUN_BYTES`]) and its re-insert per value
//! ([`REINSERTED_VALUE_BYTES`], the value's own bytes on top), the shot's
//! fixed records ([`SHOT_BYTES`]), at the mint form the edition's mint
//! ([`EDITION_MINT_BYTES`]) and, where the deposits claim at either form,
//! the edition claim ([`EDITION_CLAIM_BYTES`]). THE
//! MAXIMAL REQUEST — every wire list at its cap, every placed run and every
//! re-inserted value at M5's, every slot at its cap — sums to
//! [`MAXIMAL_PUBLICATION_BYTES`]; THE REACHABLE REQUEST, bounded by the
//! request body ([`REQUEST_BODY_BYTES`]) as well as the caps, to
//! [`REACHABLE_PUBLICATION_BYTES`]; `tests` below holds both against
//! `MAX_TXN_BYTES`.

use skep_address::{document_of, subtree_of, Nat, Span, Tumbler};
use skep_arrangement::{trunk_of, Run, Shot, VPos, MAX_PLACED_RUNS, MAX_REINSERTED_VALUES};

use super::plan::{EndArg, NamedAddress, PublishDeposits, PublishTarget};
use super::correspondence_type;
use crate::budget::MAX_SLOT_SPANS;
use crate::endset::enc;
use crate::state::{View, TO, TYPE};
use crate::LinkWorld;

/// The bytes one correspondence record stages: the link's mint, its deposit
/// — `from` one I-span, `to` one I-span, the correspondence type's unit span
/// — and its seat in the link subspace of the named draft whose identity
/// the piece was. One per piece of draft identity the shot mints; a record's
/// bytes do not depend on its home, so the rendering draft's and an `also`
/// draft's cost alike.
pub const CORRESPONDENCE_RECORD_BYTES: u64 = 1_057;

/// The bytes one `links` entry's copy stages at the worst case: the link's
/// mint, its deposit with EACH of the three slots at `MAX_SLOT_SPANS`
/// spans — `from` and `to` as content I-spans of the shallow depth, the type
/// as unit spans of ten-component commons addresses — and its seat in its
/// home's link subspace. [`COPY_FIXED_BYTES`] plus the spans' own bytes.
pub const COPY_BYTES: u64 = 2_228_785;

/// The bytes one `links` entry's copy stages past its spans: the link's
/// mint, its deposit's three empty slots and its seat. A copy is this plus
/// [`stored_span_bytes`] of every span of its three slots, so a slot is
/// priced at the spans the request spells; [`COPY_BYTES`] is this at every
/// slot's cap.
pub const COPY_FIXED_BYTES: u64 = 561;

/// The bytes one `links` entry's claim stages where the entry names an
/// original: the link's mint and its deposit — `from` the original's unit
/// span, `to` the copy's, the supersession class — unseated, as every claim
/// is.
pub const CLAIM_BYTES: u64 = 857;

/// The bytes one `retract` entry stages: the retraction tuple's mint and
/// deposit — `from` the home's unit span, `to` the target's, the retraction
/// class — unseated, as `nullify` leaves it. (Pinned at 841 by lane S4,
/// whose measurement subtracted a shot of another base extent, four bytes
/// longer; measured against a shot of the same shape it is this.)
pub const RETRACTION_BYTES: u64 = 845;

/// The bytes one `read_with` entry stages: the link's mint, its deposit —
/// `from` the edition's unit span, `to` the set's, the read-with type — and
/// its seat in the set's link subspace. (921 by S4's measurement, four
/// bytes low for the reason [`RETRACTION_BYTES`] states.)
pub const READ_WITH_BYTES: u64 = 925;

/// The bytes the re-window stages per piece at a kept place: the published
/// piece's placement (`ContentPlace`) and the draft-native piece's removal
/// (`ContentRemove`), each over one run.
pub const KEPT_PLACE_BYTES: u64 = 364;

/// The bytes one run of the member's placement adds to the shot's
/// `ShotPlace` record: a run's start and width.
pub const PLACED_RUN_BYTES: u64 = 104;

/// The bytes the re-insert stages per value at the worst case — a value
/// that is an atom, two bytes or more, its own mint and its own content
/// write, measured at a two-byte atom — the value's bytes past two on top
/// of this figure. A run of single-byte values stages one range mint and
/// one stretch for the whole run instead, 301 bytes for a run of one byte
/// and one more per byte, so a byte of prose costs a fraction of this.
pub const REINSERTED_VALUE_BYTES: u64 = 287;

/// The bytes the shot stages whatever it places: the member's mint and the
/// `ShotPlace` record holding no run, its terms carrying a base extent; the
/// birth shape, with no extent to carry, is 258.
pub const SHOT_BYTES: u64 = 270;

/// The bytes the mint form adds: the edition's mint under the account.
pub const EDITION_MINT_BYTES: u64 = 109;

/// The bytes the edition claim stages: its mint, its deposit — `from` the
/// edition's unit span, `to` the draft's, the edition class — and its seat.
/// One figure for either form: the edition the mint form mints and the
/// edition the document form names lie at one depth under the account, so
/// the claim's rows weigh the same (measured at both by
/// `tests/it/publication.rs`).
pub const EDITION_CLAIM_BYTES: u64 = 925;

/// The request-body cap of the frame routes, 8 MiB, as this crate states it
/// for [`REACHABLE_PUBLICATION_BYTES`]: the daemon's core owns the cap
/// (`skep_core::limits::MAX_REQUEST_BODY`, wire.md §Transport, "8 MiB on
/// the frame routes") and pins the two equal.
pub const REQUEST_BODY_BYTES: u64 = 8 * 1024 * 1024;

/// The wire list cap, as the codec reuses `MAX_SLOT_SPANS` for it.
const MAX_WIRE_LIST: u64 = MAX_SLOT_SPANS as u64;

/// The bytes a content I-span of the shallow depth stores — eight
/// components a tumbler, every component under 2³² — as
/// [`stored_span_bytes`] prices it; `tests` holds the two equal.
const SHALLOW_CONTENT_SPAN_BYTES: u64 = 168;

/// The bytes a ten-component commons address's unit span stores, the type
/// slot's span at the shallow end, as [`stored_span_bytes`] prices it.
const SHALLOW_TYPE_SPAN_BYTES: u64 = 208;

/// The bytes the maximal request stages, by the table — A PRODUCT OF CAPS,
/// not a request any body can carry: every wire list at its cap
/// (`MAX_WIRE_LIST`, the codec's, equal to `MAX_SLOT_SPANS`) — 4096 `links`
/// entries each with a copy at full slots and a claim, 4096 `retract`
/// entries, 4096 `read_with` entries, 4096 runs each minting a record and
/// re-windowed at a place as one piece — the placement at `MAX_PLACED_RUNS`
/// runs, the re-insert at `MAX_REINSERTED_VALUES` values every one an atom,
/// the shot's fixed records and the mint form's two: 9,190,118,680 bytes,
/// which DOES NOT FIT `MAX_TXN_BYTES` (64 MiB) — by two orders, the copies
/// at full slots being 9,132,613,632 of it. With the copies at one span a
/// slot (1,029 bytes apiece: the fixed part, a content span, a document's
/// unit span and a nine-component type's) every other cap at once sums to
/// 65,230,104 bytes, INSIDE the budget by 1,878,760 — the re-inserted
/// atoms' 37,617,664 the largest term. What a body within the frame routes'
/// cap can command is [`REACHABLE_PUBLICATION_BYTES`]. The caps are the
/// design's to move; `tests` pins the figures.
pub const MAXIMAL_PUBLICATION_BYTES: u64 = SHOT_BYTES
    + EDITION_MINT_BYTES
    + EDITION_CLAIM_BYTES
    + MAX_WIRE_LIST * (COPY_BYTES + CLAIM_BYTES)
    + MAX_WIRE_LIST * RETRACTION_BYTES
    + MAX_WIRE_LIST * READ_WITH_BYTES
    + MAX_WIRE_LIST * (CORRESPONDENCE_RECORD_BYTES + KEPT_PLACE_BYTES)
    + MAX_PLACED_RUNS as u64 * PLACED_RUN_BYTES
    + MAX_REINSERTED_VALUES as u64 * REINSERTED_VALUE_BYTES;

/// The pieces a request of `MAX_WIRE_LIST` draft-native runs can have the
/// re-window stage, with every run placed: the first half of the runs each
/// minting one position, in position order, the second half each
/// re-supplying every one of those positions — placed by reference, piece
/// by piece, "each draft identity once per shot" — so each of the second
/// half is as many pieces as the first half has runs, the placement
/// merging them (the fresh identity being I-adjacent) under
/// `MAX_PLACED_RUNS` while the pairing, and the re-window's two records per
/// piece, do not: `2048 + 2048 × 2048`.
const REACHABLE_PIECES: u64 = MAX_WIRE_LIST / 2 + (MAX_WIRE_LIST / 2) * (MAX_WIRE_LIST / 2);

/// A bound on the bytes a request within [`REQUEST_BODY_BYTES`] can have
/// the commit stage — THE REACHABLE MAXIMUM, each term at the most a body
/// of 8 MiB commands of it, where the product of caps
/// ([`MAXIMAL_PUBLICATION_BYTES`]) counts what no body can spell.
///
/// The lane's arithmetic. A request's lists at their caps cost about
/// 1,060,000 bytes of body in their cheapest spellings — a run `{"origin":
/// "1.0.1.0.1","i_start":"1.0.1.0.1.0.1.1","width":1},` 61 bytes, a place
/// `{"subspace":1,"ordinal":1},` 27, a `links` entry in the member-position
/// form about 140, a `retract` address 18 and a `read_with` address 12,
/// 4096 of each — so EVERY list stands at its cap inside the body, and what
/// the body bounds is not the entries but the spans a slot spells. Three
/// kinds of term then stand whole, bounded by the caps and not the body:
///
/// * THE VALUES: `MAX_REINSERTED_VALUES` atoms, 37,617,664 bytes — a run's
///   width is a number in the request, not bytes, and the values are read
///   off the draft, so a run of six characters commands them all.
/// * THE RE-WINDOW's PIECES: `REACHABLE_PIECES` × [`KEPT_PLACE_BYTES`],
///   1,527,472,128 bytes from 4096 runs and 4096 places (360 KB of body),
///   the placement under its cap; and the placement itself at
///   `MAX_PLACED_RUNS` runs, the shot's records per minting run.
/// * THE COPIES' SLOTS: a `links` entry's `from` and `to` in the
///   member-position form resolve to the member's runs over the positions
///   they name — `{"member":[{"ordinal":1,"width":4096}]}`, 36 bytes, is
///   up to `MAX_SLOT_SPANS` stored spans over a member of 4096 runs — so
///   4096 entries command 2 × 4096 × 4096 shallow content spans, 5,637
///   MB, from under 600 KB of body; and a span spelled in the request
///   stores at ABOUT TEN TIMES its spelling (an eight-component address,
///   `"1.0.1.0.1.0.1.1",` 18 bytes, is a 168-byte stored span), so the
///   `addrs` and `spans` forms command 10 bytes per body byte besides.
///
/// Summed with the shot's fixed records, the mint form's two, a record per
/// minting run of the first half, a claim per entry and the retractions and
/// read-withs at their caps, the figure is 7,225,126,168 bytes: PAST
/// `MAX_TXN_BYTES` by two orders, each of the two large terms past it
/// alone. So a request within the body cap can command more staged bytes
/// than one transaction holds, and the kernel's `txn_over_budget` is met
/// by an honest request unless it is priced ahead of the lock — which
/// [`price_staged_bytes`] does, from this table, per span the request
/// spells. The caps are the design's to move; `tests` pins the figure and
/// its side of the budget.
pub const REACHABLE_PUBLICATION_BYTES: u64 = SHOT_BYTES
    + EDITION_MINT_BYTES
    + EDITION_CLAIM_BYTES
    + MAX_REINSERTED_VALUES as u64 * REINSERTED_VALUE_BYTES
    + REACHABLE_PIECES * KEPT_PLACE_BYTES
    + MAX_PLACED_RUNS as u64 * PLACED_RUN_BYTES
    + (MAX_WIRE_LIST / 2) * CORRESPONDENCE_RECORD_BYTES
    + MAX_WIRE_LIST
        * (COPY_FIXED_BYTES
            + 2 * MAX_SLOT_SPANS as u64 * SHALLOW_CONTENT_SPAN_BYTES
            + SHALLOW_TYPE_SPAN_BYTES
            + CLAIM_BYTES)
    + MAX_WIRE_LIST * (RETRACTION_BYTES + READ_WITH_BYTES);

/// The bytes one component of a tumbler stores: bincode fixint's 8-byte
/// length before the magnitude's 32-bit digits, 4 bytes each, zero having
/// none.
fn nat_bytes(n: &Nat) -> u64 {
    8 + 4 * n.bits().div_ceil(32)
}

/// Returns the bytes `t` stores as the kernel encodes it: an 8-byte length
/// and, per component, `nat_bytes` — an 8-byte length and 4 bytes per
/// 32-bit digit of the magnitude.
pub fn stored_tumbler_bytes(t: &Tumbler) -> u64 {
    8 + t.iter().map(nat_bytes).sum::<u64>()
}

/// Returns the bytes `span` stores as the kernel encodes it: its start and
/// its width, each a tumbler ([`stored_tumbler_bytes`]).
///
/// The one spelling of a span's stored cost, which `tests/it/publication.rs`
/// holds to the journal's growth at two depths; the table's per-kind
/// figures carry their spans at this price, and a slot is priced at the
/// spans the request spells.
pub fn stored_span_bytes(span: &Span) -> u64 {
    stored_tumbler_bytes(span.start()) + stored_tumbler_bytes(span.width())
}

/// Prices the bytes a publication would stage, from the table: an UPPER
/// bound on what the kernel charges the transaction, read off the request
/// and one stab of the rendering draft's records per stray place.
///
/// The terms, each at the table's figure:
///
/// * the shot's fixed records ([`SHOT_BYTES`]), the edition's mint at the
///   mint form, and the edition claim where the deposits claim, at either
///   form;
/// * per draft-native run — of any named draft, the rendering `draft`'s or
///   an `also` draft's, a record costing the same in either home — its PIECES × ([`PLACED_RUN_BYTES`] +
///   [`CORRESPONDENCE_RECORD_BYTES`]), and × [`KEPT_PLACE_BYTES`] beside
///   where the entry carries a place — the pieces bounded off the request
///   as one more than the endpoints of other draft-native runs lying
///   strictly inside the run's extent, since the pairing cuts a run only
///   where an earlier run's minted piece begins or ends; a run overlapping
///   no other is one piece;
/// * the re-inserted values, the DISTINCT positions the draft-native runs
///   name ([`Shot::reinserted_values`]) × [`REINSERTED_VALUE_BYTES`] — an
///   atom's bytes past two ride the draft's content, which the price does
///   not read;
/// * per run of any other origin [`PLACED_RUN_BYTES`], and where it carries
///   a place — a STRAY run of the document's own identity — one stab of the
///   draft's TO slot by its span, the records overlapping it ×
///   [`KEPT_PLACE_BYTES`], one piece per record (a window of another
///   origin, which the codec refuses a place on, is priced as one);
/// * per `links` entry [`COPY_FIXED_BYTES`] + [`stored_span_bytes`] of
///   every span its three slots spell — an `addrs` element as its unit
///   span, a tag as a unit span at the member's depth, a `spans` element as
///   itself, and a member-position span as the fewer of its width, the
///   request's runs and `MAX_SLOT_SPANS` content spans of the edition's
///   chain — and [`CLAIM_BYTES`] where it names an original;
/// * per `retract` entry [`RETRACTION_BYTES`], per `read_with` entry
///   [`READ_WITH_BYTES`].
///
/// An upper bound: the twin fence refuses before anything is staged, the
/// plan's skips (a retracted target, a standing read-with) stage less, a
/// run named twice stages its identity once, a member-position end's
/// pieces merge where the member's runs are I-adjacent, and a byte of prose
/// costs a fraction of an atom. Request arithmetic — `O(n log n)` in the
/// draft-native runs for the endpoints' sort, linear in the lists — plus
/// the stray stabs; saturating, so an absurd request prices at `u64::MAX`.
pub fn price_staged_bytes<W: LinkWorld>(world: &W, target: &PublishTarget, shot: &Shot, places: &[Option<VPos>], deposits: &PublishDeposits) -> u64 {
    let (trunk, draft) = (target.term(), shot.draft_document());
    let mut bytes = SHOT_BYTES;
    if target.mints() {
        bytes += EDITION_MINT_BYTES;
    }
    if deposits.claim {
        bytes += EDITION_CLAIM_BYTES;
    }
    // The draft-native runs' endpoints, sorted: the pieces bound reads them.
    let mut ends: Vec<Tumbler> = shot.reinserted_runs().flat_map(|run| [run.i_start().tumbler().clone(), run.reach()]).collect();
    ends.sort();
    let pieces_bound = |run: &Run| -> u64 {
        let (start, reach) = (run.i_start().tumbler(), run.reach());
        let first = ends.partition_point(|end| end <= start);
        let past = ends.partition_point(|end| *end < reach);
        1 + past.saturating_sub(first) as u64
    };
    let ty = enc([correspondence_type()]);
    for (index, entry) in shot.runs.iter().enumerate() {
        let placed = places.get(index).is_some_and(Option::is_some);
        let origin = document_of(entry.run.i_start()).map(|d| trunk_of(&d));
        if draft.is_some() && origin == draft {
            let pieces = pieces_bound(&entry.run);
            bytes = bytes.saturating_add(pieces.saturating_mul(PLACED_RUN_BYTES + CORRESPONDENCE_RECORD_BYTES));
            if placed {
                bytes = bytes.saturating_add(pieces.saturating_mul(KEPT_PLACE_BYTES));
            }
        } else {
            bytes = bytes.saturating_add(PLACED_RUN_BYTES);
            if placed {
                let records = match &draft {
                    Some(draft) if origin.as_ref() == Some(&trunk) => {
                        let span = entry.run.iextent();
                        world.links().match_links_in(draft, (TO, [&span]), &[(TYPE, &ty)], View::Active).len() as u64
                    }
                    _ => 0,
                };
                bytes = bytes.saturating_add(records.max(1).saturating_mul(KEPT_PLACE_BYTES));
            }
        }
    }
    let values = u64::try_from(shot.reinserted_values()).unwrap_or(u64::MAX);
    bytes = bytes.saturating_add(values.saturating_mul(REINSERTED_VALUE_BYTES));
    // The copies: their spans at the depth the request spells them at.
    let content_span = stored_span_bytes(&content_span_of(target));
    let tag_span = stored_span_bytes(&subtree_of(&tag_depth_of(target)));
    let runs = shot.runs.len() as u64;
    let end_bytes = |end: &EndArg| -> u64 {
        match end {
            EndArg::Addrs(list) => list
                .iter()
                .map(|named| match named {
                    NamedAddress::Address(a) => stored_span_bytes(&subtree_of(a.tumbler())),
                    NamedAddress::Member | NamedAddress::Edition => tag_span,
                })
                .fold(0u64, u64::saturating_add),
            EndArg::Spans(list) => list.iter().map(stored_span_bytes).fold(0u64, u64::saturating_add),
            EndArg::Member(list) => list
                .iter()
                .map(|span| span.width.min(runs).min(MAX_SLOT_SPANS as u64).saturating_mul(content_span))
                .fold(0u64, u64::saturating_add),
        }
    };
    for entry in &deposits.links {
        bytes = bytes
            .saturating_add(COPY_FIXED_BYTES)
            .saturating_add(end_bytes(&entry.from))
            .saturating_add(end_bytes(&entry.to))
            .saturating_add(end_bytes(&entry.ty));
        if entry.old.is_some() {
            bytes = bytes.saturating_add(CLAIM_BYTES);
        }
    }
    bytes = bytes.saturating_add((deposits.retract.len() as u64).saturating_mul(RETRACTION_BYTES));
    bytes.saturating_add((deposits.read_with.len() as u64).saturating_mul(READ_WITH_BYTES))
}

/// Returns a content I-span of the edition's chain, one position wide at a
/// small ordinal, as the member-position form resolves to: the trunk's
/// components then `0 · 1 · k` at the document form, the account's then
/// `0 · d · 0 · 1 · k` at the mint form — the depth the span's bytes turn
/// on, each component priced under 2³².
fn content_span_of(target: &PublishTarget) -> Span {
    let one = Nat::from(1u32);
    let tail: &[u32] = match target {
        PublishTarget::Document(_) => &[0, 1, 1],
        PublishTarget::Mint { .. } => &[0, 1, 0, 1, 1],
    };
    let start = Tumbler::new(target.term().tumbler().iter().cloned().chain(tail.iter().map(|&c| Nat::from(c))))
        .expect("a term is nonempty");
    let width = Tumbler::new(std::iter::repeat_n(Nat::from(0u32), start.len() - 1).chain([one])).expect("nonempty");
    Span::new(start, width).expect("a unit displacement at the start's depth is T12-valid")
}

/// Returns a tumbler at the depth a tag resolves to: the member's address,
/// the trunk's components and one ordinal at the document form, the
/// account's and `0 · d · k` at the mint form — the edition's own address,
/// one shorter, priced at the member's.
fn tag_depth_of(target: &PublishTarget) -> Tumbler {
    let tail: &[u32] = match target {
        PublishTarget::Document(_) => &[1],
        PublishTarget::Mint { .. } => &[0, 1, 1],
    };
    Tumbler::new(target.term().tumbler().iter().cloned().chain(tail.iter().map(|&c| Nat::from(c)))).expect("a term is nonempty")
}

#[cfg(test)]
mod tests {
    use skep_kernel::MAX_TXN_BYTES;

    use super::*;

    /// THE ARITHMETIC (M6): the maximal request's bytes against the
    /// transaction budget — a product of caps. At full slots it does not
    /// fit; at one span a slot every other cap at once does, narrowly. Both
    /// figures are pinned so a cap or an encoding that moves either is a
    /// visible decision here.
    #[test]
    fn the_maximal_request_is_priced_against_the_transaction_budget() {
        assert_eq!(MAXIMAL_PUBLICATION_BYTES, 9_190_118_680, "the table's sum");
        assert!(
            MAXIMAL_PUBLICATION_BYTES > MAX_TXN_BYTES,
            "the maximal request at the table's figures does not fit the budget: {MAXIMAL_PUBLICATION_BYTES} bytes against {MAX_TXN_BYTES}"
        );
        let one_span_a_slot = MAXIMAL_PUBLICATION_BYTES - MAX_WIRE_LIST * (COPY_BYTES - 1_029);
        assert_eq!(one_span_a_slot, 65_230_104, "every other cap at once, the copies at one span a slot");
        assert!(
            one_span_a_slot <= MAX_TXN_BYTES,
            "…fits the budget, by {} bytes",
            MAX_TXN_BYTES.saturating_sub(one_span_a_slot)
        );
        // The copy at full slots is the fixed part plus its spans at the
        // shallow depth: two content spans and one type span per span index.
        assert_eq!(
            COPY_BYTES,
            COPY_FIXED_BYTES + MAX_SLOT_SPANS as u64 * (2 * SHALLOW_CONTENT_SPAN_BYTES + SHALLOW_TYPE_SPAN_BYTES),
            "the full copy is the fixed part and its spans"
        );
    }

    /// THE REACHABLE MAXIMUM (lane F4): what a body within the frame routes'
    /// cap can command is PAST the budget — by two orders — and each of its
    /// two large terms is past it alone: the re-window's pieces from 4096
    /// runs and places, and the copies' member-position slots from 4096
    /// entries; the lists at their caps cost about an eighth of the body.
    /// Pinned, with the side of the budget it falls on, so the figure and
    /// the verdict are a visible decision here.
    #[test]
    fn the_reachable_request_is_priced_against_the_transaction_budget() {
        assert_eq!(REACHABLE_PIECES, 2_048 + 2_048 * 2_048);
        assert_eq!(REACHABLE_PUBLICATION_BYTES, 7_225_126_168, "the lane's arithmetic");
        assert!(
            REACHABLE_PUBLICATION_BYTES > MAX_TXN_BYTES,
            "the reachable request is past the budget: {REACHABLE_PUBLICATION_BYTES} against {MAX_TXN_BYTES}"
        );
        assert!(REACHABLE_PUBLICATION_BYTES / MAX_TXN_BYTES >= 100, "by two orders");
        assert!(REACHABLE_PIECES * KEPT_PLACE_BYTES > MAX_TXN_BYTES, "the re-window's pieces alone");
        assert!(MAX_WIRE_LIST * 2 * MAX_SLOT_SPANS as u64 * SHALLOW_CONTENT_SPAN_BYTES > MAX_TXN_BYTES, "the copies' slots alone");
        assert!(REACHABLE_PUBLICATION_BYTES < MAXIMAL_PUBLICATION_BYTES, "and under the product of caps");
        // The body the division costs: every list at its cap in its cheapest
        // spelling, about an eighth of the cap.
        let body = MAX_WIRE_LIST * (61 + 27 + 140 + 18 + 12);
        assert!(body < REQUEST_BODY_BYTES / 7, "{body} bytes of body for every list at its cap");
    }

    /// THE SPAN's BYTES: the kernel's fixint layout — an 8-byte length
    /// before every sequence, 4 bytes per 32-bit digit, zero having none —
    /// over the shallow content span, the type slot's span and a span whose
    /// ordinal needs two digits; and the two shallow constants the reachable
    /// figure uses are what the function prices.
    #[test]
    fn a_spans_stored_bytes_follow_the_kernels_layout() {
        let t = |comps: &[u32]| Tumbler::new(comps.iter().map(|&c| Nat::from(c))).expect("nonempty");
        let content = Span::new(t(&[1, 0, 1, 0, 3, 0, 1, 1]), t(&[0, 0, 0, 0, 0, 0, 0, 1])).expect("a span");
        assert_eq!(stored_span_bytes(&content), (8 + 5 * 12 + 3 * 8) + (8 + 7 * 8 + 12));
        assert_eq!(stored_span_bytes(&content), SHALLOW_CONTENT_SPAN_BYTES);
        assert_eq!(stored_span_bytes(&subtree_of(&t(&[1, 1, 0, 1, 0, 1, 0, 3, 23, 1]))), SHALLOW_TYPE_SPAN_BYTES);
        let wide = Span::new(t(&[1, 0, 1, 0, 3, 0, 1, 1]), t(&[0, 0, 0, 0, 0, 0, 0, 70_000])).expect("a span");
        assert_eq!(stored_span_bytes(&wide), SHALLOW_CONTENT_SPAN_BYTES, "one digit still");
        let deep = Tumbler::new(std::iter::repeat_n(Nat::from(1u64 << 40), 8)).expect("nonempty");
        assert_eq!(stored_tumbler_bytes(&deep), 8 + 8 * 16, "two digits a component");
    }
}
