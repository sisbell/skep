//! THE WORST-CASE TABLE (the link-sets design §5.6, M6): the bytes the
//! kernel prices each kind of record a publication stages at, one constant
//! per entry kind, and the maximal request's sum against the transaction
//! budget.
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
//! argument prices from; a span encodes a component in a fixed-width
//! length-prefixed `Nat`, so a deeper home's figures grow linearly with its
//! depth and the deep end (256 components) is order thirty times these.
//!
//! What a panel prices from it (M6): a correspondence record per run the
//! shot mints ([`CORRESPONDENCE_RECORD_BYTES`]), a copy and its claim per
//! `links` entry ([`COPY_BYTES`] with every slot at `MAX_SLOT_SPANS` spans,
//! [`CLAIM_BYTES`]), a retraction per `retract` entry ([`RETRACTION_BYTES`]),
//! a read-with per `read_with` entry ([`READ_WITH_BYTES`]), the re-window per
//! kept place ([`KEPT_PLACE_BYTES`], a placement and a removal per piece),
//! the shot's own placement per run ([`PLACED_RUN_BYTES`]) and its re-insert
//! per value ([`REINSERTED_VALUE_BYTES`], the value's own bytes on top), the
//! shot's fixed records ([`SHOT_BYTES`]) and, at the mint form, the edition's
//! mint and its claim ([`EDITION_MINT_BYTES`], [`EDITION_CLAIM_BYTES`]). THE
//! MAXIMAL REQUEST — every wire list at its cap, every placed run and every
//! re-inserted value at M5's — sums to [`MAXIMAL_PUBLICATION_BYTES`], which
//! `tests` below holds against `MAX_TXN_BYTES`.

use skep_arrangement::{MAX_PLACED_RUNS, MAX_REINSERTED_VALUES};

use crate::budget::MAX_SLOT_SPANS;

/// The bytes one correspondence record stages: the link's mint, its deposit
/// — `from` one I-span, `to` one I-span, the correspondence type's unit span
/// — and its seat in the draft's link subspace. One per piece of draft
/// identity the shot mints.
pub const CORRESPONDENCE_RECORD_BYTES: u64 = 1_057;

/// The bytes one `links` entry's copy stages at the worst case: the link's
/// mint, its deposit with EACH of the three slots at `MAX_SLOT_SPANS`
/// spans — `from` and `to` as content I-spans of the shallow depth, the type
/// as unit spans of ten-component commons addresses — and its seat in its
/// home's link subspace.
pub const COPY_BYTES: u64 = 2_228_785;

/// The bytes one `links` entry's claim stages where the entry names an
/// original: the link's mint and its deposit — `from` the original's unit
/// span, `to` the copy's, the supersession class — unseated, as every claim
/// is.
pub const CLAIM_BYTES: u64 = 857;

/// The bytes one `retract` entry stages: the retraction tuple's mint and
/// deposit — `from` the home's unit span, `to` the target's, the retraction
/// class — unseated, as `nullify` leaves it.
pub const RETRACTION_BYTES: u64 = 841;

/// The bytes one `read_with` entry stages: the link's mint, its deposit —
/// `from` the edition's unit span, `to` the set's, the read-with type — and
/// its seat in the set's link subspace.
pub const READ_WITH_BYTES: u64 = 921;

/// The bytes the re-window stages per piece at a kept place: the fresh
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
pub const EDITION_CLAIM_BYTES: u64 = 925;

/// The bytes the maximal request stages, by the table: every wire list at
/// its cap (`MAX_WIRE_LIST`, the codec's, equal to `MAX_SLOT_SPANS`) — 4096
/// `links` entries each with a copy at full slots and a claim, 4096 `retract`
/// entries, 4096 `read_with` entries, 4096 runs each minting a record and
/// re-windowed at a place — the placement at `MAX_PLACED_RUNS` runs, the
/// re-insert at `MAX_REINSERTED_VALUES` values every one an atom, the shot's
/// fixed records and the mint form's two: 9,190,085,912 bytes, which DOES
/// NOT FIT `MAX_TXN_BYTES` (64 MiB) — by two orders, the copies at full
/// slots being 9,132,613,632 of it. The request body's cap, 8 MiB on the
/// frame routes, bounds what a request can spell well inside that term;
/// and with the copies at one span a slot (1,025 bytes apiece) every other
/// cap at once sums to 65,180,952 bytes, INSIDE the budget by 1,927,912 —
/// the re-inserted atoms' 37,617,664 the largest term — so a request at
/// every list's cap fits where its slots are narrow and is refused
/// `txn_over_budget` by the kernel where they are wide, and the panel that
/// prices from this table refuses the second ahead of the act. The caps
/// are the design's to move; `tests` pins both figures.
pub const MAXIMAL_PUBLICATION_BYTES: u64 = SHOT_BYTES
    + EDITION_MINT_BYTES
    + EDITION_CLAIM_BYTES
    + MAX_SLOT_SPANS as u64 * (COPY_BYTES + CLAIM_BYTES)
    + MAX_SLOT_SPANS as u64 * RETRACTION_BYTES
    + MAX_SLOT_SPANS as u64 * READ_WITH_BYTES
    + MAX_SLOT_SPANS as u64 * (CORRESPONDENCE_RECORD_BYTES + KEPT_PLACE_BYTES)
    + MAX_PLACED_RUNS as u64 * PLACED_RUN_BYTES
    + MAX_REINSERTED_VALUES as u64 * REINSERTED_VALUE_BYTES;

#[cfg(test)]
mod tests {
    use skep_kernel::MAX_TXN_BYTES;

    use super::*;

    /// THE ARITHMETIC (M6): the maximal request's bytes against the
    /// transaction budget — the figure the panel refuses at ahead of the
    /// act, so that `txn_over_budget` is met only by a bug or a race. At
    /// full slots it does not fit; at one span a slot every other cap at
    /// once does, narrowly. Both figures are pinned so a cap or an encoding
    /// that moves either is a visible decision here.
    #[test]
    fn the_maximal_request_is_priced_against_the_transaction_budget() {
        assert_eq!(MAXIMAL_PUBLICATION_BYTES, 9_190_085_912, "the table's sum");
        assert!(
            MAXIMAL_PUBLICATION_BYTES > MAX_TXN_BYTES,
            "the maximal request at the table's figures does not fit the budget: {MAXIMAL_PUBLICATION_BYTES} bytes against {MAX_TXN_BYTES}"
        );
        let one_span_a_slot = MAXIMAL_PUBLICATION_BYTES - MAX_SLOT_SPANS as u64 * (COPY_BYTES - 1_025);
        assert_eq!(one_span_a_slot, 65_180_952, "every other cap at once, the copies at one span a slot");
        assert!(
            one_span_a_slot <= MAX_TXN_BYTES,
            "…fits the budget, by {} bytes",
            MAX_TXN_BYTES.saturating_sub(one_span_a_slot)
        );
    }
}
