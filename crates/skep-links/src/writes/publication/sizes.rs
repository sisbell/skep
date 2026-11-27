//! THE WORST-CASE TABLE (the link-sets design §5.6, M6): the bytes the
//! kernel prices each kind of record a publication stages at, one constant
//! per entry kind; and the price of a request's staged bytes from it
//! ([`price_staged_bytes`], the fifth term of the pre-lock price), over THE
//! PIECES each run is cut into ([`run_pieces`]), which the reads' price
//! prices the re-window's pieces by too.
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
//! account (`1.0.1.0.65`, five components), its content elements at eight,
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
//! ([`READ_WITH_BYTES`]), a claim per `supersede` entry ([`CLAIM_BYTES`]
//! again — a claim over two version members spells shorter spans than one
//! over two links, so the link-ended figure bounds it), per `originals`
//! entry a retraction ([`RETRACTION_BYTES`]) and, over a rest, the fresh
//! mark — a copy's fixed part ([`COPY_FIXED_BYTES`]) with the rest's spans
//! and the original's stored type slot at their own bytes, the type read
//! only where the caller's visibility class admits the original's home and
//! priced as an absent link's where it does not — the re-window
//! per piece at a kept place ([`KEPT_PLACE_BYTES`], a change of one run in
//! the draft's one record) and once for each draft it re-windows
//! ([`REWINDOWED_DRAFT_BYTES`], that record past its changes, the draft's
//! address at its own bytes beside it), the shot's own
//! placement per run ([`PLACED_RUN_BYTES`]) and its re-insert per unit — an
//! atom, or a whole run of single bytes ([`REINSERTED_UNIT_BYTES`], the
//! unit's own bytes on top) — the shot's
//! fixed records ([`SHOT_BYTES`]), at the mint form the edition's mint
//! ([`EDITION_MINT_BYTES`]) and, where the deposits claim at either form,
//! the edition claim ([`EDITION_CLAIM_BYTES`]).

use skep_address::{document_of, subtree_of, Address, Nat, Span, Tumbler};
use skep_arrangement::{trunk_of, ReinsertWorld, Run, Shot, UnitTally, VPos};

use super::plan::{EndArg, NamedAddress, PublishDeposits, PublishTarget};
use super::{also_places_by_draft, rewindows, stray, AlsoPlaces, Rewindow};
use crate::budget::MAX_SLOT_SPANS;
use crate::writes::Visibility;
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

/// The bytes the re-window stages per piece at a kept place: one change of
/// the draft's one record (`ContentEdit`) — its ordinal, the width it
/// removes and its run count — placing one run, the published piece. A
/// place of several pieces is one change of as many runs, so each piece
/// past a place's first stages a run's bytes ([`PLACED_RUN_BYTES`]) and is
/// priced at this figure all the same: an upper bound.
pub const KEPT_PLACE_BYTES: u64 = 136;

/// The bytes the re-window stages once for each draft it re-windows,
/// whatever its places hold: its one record (`ContentEdit`) holding no
/// change. The draft's own address rides the record and is priced beside
/// this figure, at [`stored_tumbler_bytes`] of it.
pub const REWINDOWED_DRAFT_BYTES: u64 = 56;

/// The bytes one run of the member's placement adds to the shot's
/// `ShotPlace` record: a run's start and width.
pub const PLACED_RUN_BYTES: u64 = 104;

/// The bytes the re-insert stages per UNIT, past the unit's own bytes: a
/// unit is what the commit stages as one mint and one content write
/// (M5's `Shot::reinserted_units` counts them) — a maximal run of
/// single-byte values, its range mint and its stretch, or an atom, its mint
/// and its write. The figure is measured at a shot's one unit, a run of
/// single bytes — of one byte and of four, a byte a position on top — and
/// bounds every other: an atom stages eleven bytes fewer, its mint carrying
/// no count, and each unit after a shot's first four fewer again. So a unit
/// holding `n` bytes is priced `this + n`: exact for a shot of one run of
/// typed text, an upper bound within a few bytes a unit for every other,
/// and a megabyte of typed text in one run costs this once.
pub const REINSERTED_UNIT_BYTES: u64 = 300;

/// The bytes the shot stages whatever it places: the member's mint and the
/// `ShotPlace` record holding no run, its terms carrying a base extent and
/// a base, and its rendering-draft slot empty; the base's own address is
/// priced beside them, at [`stored_tumbler_bytes`] of it (skep #1111), and
/// the birth shape, with no base and no extent to carry, is 260. A shot
/// naming its rendering draft stages the draft's address in that slot
/// beside them, priced the same way.
pub const SHOT_BYTES: u64 = 272;

/// The bytes the mint form adds: the edition's mint under the account.
pub const EDITION_MINT_BYTES: u64 = 109;

/// The bytes the edition claim stages: its mint, its deposit — `from` the
/// edition's unit span, `to` the draft's, the edition class — and its seat.
/// One figure for either form: the edition the mint form mints and the
/// edition the document form names lie at one depth under the account, so
/// the claim's rows weigh the same (measured at both by
/// `tests/it/publication.rs`).
pub const EDITION_CLAIM_BYTES: u64 = 925;

/// The request-body cap of the frame routes, 8 MiB, as this crate states
/// it: the daemon's core owns the cap (`skep_core::limits::MAX_REQUEST_BODY`,
/// wire.md §Transport, "8 MiB on the frame routes") and pins the two equal.
/// No sum here reads it: a request well inside it can ask more staged bytes
/// than one transaction holds, which is why the bytes are priced
/// ([`price_staged_bytes`]) and never bounded by the body.
pub const REQUEST_BODY_BYTES: u64 = 8 * 1024 * 1024;

/// The bytes a ten-component commons address's unit span stores, the type
/// slot's span at the shallow end, as [`stored_span_bytes`] prices it.
const SHALLOW_TYPE_SPAN_BYTES: u64 = 208;

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

/// One run of a shot as the two prices read it (THE PIECES): the pieces the
/// commit can cut it into, by the family it lies in.
///
/// [`run_pieces`] answers it per run; [`price_staged_bytes`] prices each
/// piece's records from it, and the reads' price
/// (`price_publication_reads`) the re-window's splices, so the two read one
/// bound off one stab.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum RunPieces {
    /// A draft-native run, of any named draft's identity, cut into at most
    /// this many pieces: one more than the endpoints of other draft-native
    /// runs lying strictly inside its extent, since the pairing cuts a run
    /// only where an earlier run's minted piece begins or ends.
    Native(u64),
    /// A run of no named draft's identity that some list places — a STRAY,
    /// re-windowed through the records: one piece per correspondence record
    /// overlapping it that the caller may read, wherever homed, at least
    /// one.
    Stray(u64),
    /// A run of no named draft's identity that no list places: placed by
    /// reference, cut nowhere and re-windowed nowhere.
    Unplaced,
}

impl RunPieces {
    /// Returns the pieces a list that places the run re-windows; none for a
    /// run no list places.
    pub(super) fn pieces(self) -> u64 {
        match self {
            RunPieces::Native(pieces) | RunPieces::Stray(pieces) => pieces,
            RunPieces::Unplaced => 0,
        }
    }
}

/// Returns how many lists carry a place at `index`: the rendering draft's
/// `places` and each `also_places` entry — one re-window per list that
/// places the run.
pub(super) fn placed_in(places: &[Option<VPos>], also_places: &[AlsoPlaces], index: usize) -> u64 {
    let rendering = u64::from(places.get(index).is_some_and(Option::is_some));
    let also = also_places.iter().filter(|entry| entry.places.get(index).is_some_and(Option::is_some)).count() as u64;
    rendering.saturating_add(also)
}

/// Returns each run of `shot`, in `runs`' order, as [`RunPieces`]: a
/// draft-native run's pieces bounded off the request, a stray's counted by
/// one stab at the caller's visibility class — `placed` answering whether
/// any list carries a place at an index.
///
/// A draft-native run is one whose origin is a named draft's
/// ([`Shot::is_draft_native`] of its origin, the one test the commit's
/// placement asks); its pieces are bounded by the draft-native runs'
/// endpoints, sorted — `O(n log n)` in them. A run of any other origin that
/// a list places is a stray, re-windowed through the records: one stab of
/// the TO slot by its span across every home, the correspondence records
/// overlapping it wherever homed that `readable` admits the home of
/// (`stray::readable_record_count` — the stab and the filter the commit's
/// own stray read makes), at least one. THE CLASS IS THE COMMIT's: a record
/// homed in a document the caller may not read is one the commit will not
/// read, so it is no piece — and counted, it would tell the caller how many
/// records in drafts it cannot read name a published span. Every other run
/// is [`RunPieces::Unplaced`], and is read no further.
pub(super) fn run_pieces<W: LinkWorld>(
    world: &W,
    readable: &Visibility<'_, W>,
    shot: &Shot,
    placed: impl Fn(usize) -> bool,
) -> Vec<RunPieces> {
    // The draft-native runs' endpoints, sorted: the pieces bound reads them.
    let mut ends: Vec<Tumbler> = shot.reinserted_runs().flat_map(|run| [run.i_start().tumbler().clone(), run.reach()]).collect();
    ends.sort();
    let pieces_bound = |run: &Run| -> u64 {
        let (start, reach) = (run.i_start().tumbler(), run.reach());
        let first = ends.partition_point(|end| end <= start);
        let past = ends.partition_point(|end| *end < reach);
        1 + past.saturating_sub(first) as u64
    };
    shot.runs
        .iter()
        .enumerate()
        .map(|(index, entry)| {
            let origin = document_of(entry.run.i_start()).map(|d| trunk_of(&d));
            if origin.is_some_and(|origin| shot.is_draft_native(&origin)) {
                RunPieces::Native(pieces_bound(&entry.run))
            } else if placed(index) {
                // The stray stab, across every home and at the caller's
                // visibility class: the records the commit may read, and
                // none it may not.
                RunPieces::Stray(stray::readable_record_count(world, readable, &entry.run).max(1))
            } else {
                RunPieces::Unplaced
            }
        })
        .collect()
}

/// Returns the units of `shot`'s re-insert as a price counts them: M5's
/// one count ([`Shot::reinserted_units`]) over `world`'s stored content
/// where `readable` admits EVERY draft the shot names, and nothing — no
/// unit, no byte, no stored piece read — where it does not admit one.
///
/// THE CLASS, for the count's reads. The count walks the stored pieces of
/// the named drafts' runs, and what it answers says how each draft's
/// content is held: how many atoms, how many bytes, where a position holds
/// no value. A price is answered ahead of every other judgment of the
/// request — a transport's refusal ahead of its lock states its bytes before
/// the store has asked who owns a draft — so the count is asked only at the
/// caller's own class: of a draft the caller may not read it is told
/// nothing, whatever that draft holds. Nothing where one draft of several
/// is not admitted, the readable ones included, since the count is one walk
/// over all of them and such a shot stages nothing: the store refuses it at
/// its admission, ω of every named draft — an owner reads its own — ahead
/// of its count. So the price stays a bound on what the commit stages.
/// `steps` is the count's.
pub(super) fn reinsert_tally<W: ReinsertWorld>(
    world: &W,
    readable: &Visibility<'_, W>,
    shot: &Shot,
    steps: &mut impl FnMut(u64),
) -> UnitTally {
    if !shot.named_drafts().all(|draft| readable(world, &draft)) {
        return UnitTally::default();
    }
    shot.reinserted_units(world, steps).tally()
}

/// Prices the bytes a publication would stage, from the table: an UPPER
/// bound on what the kernel charges the transaction, read off the request,
/// one stab of every home's records per stray place, at the caller's
/// visibility class `readable`, one walk of the stored pieces its
/// re-insert reads (M5's count of its units), made only where that class
/// admits every draft the shot names, and one read of the stored type of
/// each original a rest is named of, made only where that class admits the
/// original's home.
///
/// The terms, each at the table's figure:
///
/// * the shot's fixed records ([`SHOT_BYTES`]), the address of the base the
///   shot names where it names one ([`stored_tumbler_bytes`] of its member,
///   in the terms' own slot), the address of the draft whose base the shot
///   moves where it moves one ([`stored_tumbler_bytes`] of
///   [`Shot::moves_base_of`], in the placing record's own slot), the
///   edition's mint at the mint form,
///   and the edition claim where the deposits claim, at either form;
/// * per draft the commit re-windows — the rendering draft where `places`
///   carries a place, each `also` draft where its `also_places` entry does
///   — [`REWINDOWED_DRAFT_BYTES`] and [`stored_tumbler_bytes`] of the
///   draft's address: its one record, past the places it holds;
/// * per draft-native run — of any named draft, the rendering `draft`'s or
///   an `also` draft's, a record costing the same in either home — its
///   PIECES (`RunPieces::Native`) × ([`PLACED_RUN_BYTES`] +
///   [`CORRESPONDENCE_RECORD_BYTES`]), and × [`KEPT_PLACE_BYTES`] beside
///   PER LIST THAT PLACES IT — the rendering draft's `places`, and each
///   `also_places` entry whose list carries a place at the entry, every such
///   list re-windowing its own draft at the run; a run overlapping no other
///   is one piece;
/// * the re-insert, per UNIT the commit would stage
///   ([`Shot::reinserted_units`], M5's one count of them over this world's
///   stored content — an atom, or a maximal run of single-byte values of an
///   unminted portion) [`REINSERTED_UNIT_BYTES`] and the unit's own bytes: a
///   byte-run's its width, an atom's its length. A megabyte of typed text
///   in one run is one unit and its bytes; an atom of any length is priced
///   at its own. Where the store would refuse the re-insert the term prices
///   what the count counted to there, and the shot stages nothing: no unit
///   past the positions' budget, which the count reads nothing for; the
///   units' budget plus one, and the bytes of the units inside it, past the
///   units'; the units ahead of a position holding no value; and no unit
///   where `readable` does not admit a draft the shot names
///   (`reinsert_tally`), no stored piece of any draft read;
/// * per run of any other origin [`PLACED_RUN_BYTES`], and per list that
///   places it — a STRAY run of published identity, the document's own or
///   another document's, re-windowed through the records in each draft
///   whose list carries a place at it — its pieces, one per record
///   overlapping it that the caller may read (`RunPieces::Stray`, one
///   stab), × [`KEPT_PLACE_BYTES`];
/// * per `links` entry [`COPY_FIXED_BYTES`] + [`stored_span_bytes`] of
///   every span its three slots spell — an `addrs` element as its unit
///   span, a tag as a unit span at the member's depth, a `spans` element as
///   itself, and a member-position span as the fewer of its width, the
///   request's runs and `MAX_SLOT_SPANS` content spans of the edition's
///   chain — and [`CLAIM_BYTES`] where it names an original;
/// * per `retract` entry [`RETRACTION_BYTES`], per `read_with` entry
///   [`READ_WITH_BYTES`], per `supersede` entry [`CLAIM_BYTES`] — the
///   daughter's claim, its two member-ended spans shorter than the
///   link-ended figure's;
/// * per `originals` entry [`RETRACTION_BYTES`] and, where it names a rest,
///   the fresh mark: [`COPY_FIXED_BYTES`] + [`stored_span_bytes`] of every
///   rest span the request spells + [`stored_span_bytes`] of every span of
///   the original's type slot as stored, read by one `readlink` where
///   `readable` admits the original's home (`original_type_bytes`) — and
///   the shallow type span where it does not, as where no link stands at
///   the address: entries the plan refuses, priced alike, so the bytes do
///   not tell a link the caller may not read from no link at all.
///
/// An upper bound: the twin fence refuses before anything is staged, the
/// plan's skips (a retracted target, a standing read-with, a daughter
/// already claimed, an original already retracted) stage less, a
/// run named twice stages its identity once, a member-position end's
/// pieces merge where the member's runs are I-adjacent, a place's pieces
/// past its first share its one change, and a unit past a shot's first, or
/// an atom, stages a few bytes under the unit's figure. Request arithmetic — `run_pieces`'s,
/// and linear in the lists — plus the stray stabs, one `readlink` per rest
/// whose original's home the class admits and the count's walk of the
/// draft-native runs' stored pieces, at most
/// M5's `MAX_REINSERTED_VALUES` of them and none past that budget;
/// saturating, so an absurd request prices at `u64::MAX`.
///
/// The caps alone do not bound these bytes — every list at its cap, and a
/// request well inside the body cap, can ask more than one transaction
/// holds — so this price, read ahead of the lock, and no sum of caps, is
/// what keeps a publication inside the transaction budget.
pub fn price_staged_bytes<W: LinkWorld + ReinsertWorld>(
    world: &W,
    readable: &Visibility<'_, W>,
    target: &PublishTarget,
    shot: &Shot,
    places: &[Option<VPos>],
    also_places: &[AlsoPlaces],
    deposits: &PublishDeposits,
) -> u64 {
    let pieces = run_pieces(world, readable, shot, |index| placed_in(places, also_places, index) > 0);
    let by_draft = also_places_by_draft(also_places);
    let units = reinsert_tally(world, readable, shot, &mut |_| {});
    staged_bytes(world, readable, target, shot, places, also_places, deposits, &pieces, &rewindows(shot, places, &by_draft), units)
}

/// Returns the bytes the type slot of the fresh mark over a rest of the
/// original at `old` is priced at: the original's type slot as stored, read
/// at the class `readable`, and the shallow type span wherever that read is
/// not made or finds no link.
///
/// THE CLASS, for the rider's one read. A link's stored type says what kind
/// of link stands at an address, and a price is answered ahead of the plan's
/// own judgment of whose the original is, so the type is read only where
/// `readable` admits the original's home — the home read off the address by
/// [`document_of`], the link element's document, as the plan and the stray
/// read find a link's home. Where the class does not admit the home, where
/// the address derives no document, and where no link stands at it, the
/// figure is one, `SHALLOW_TYPE_SPAN_BYTES`: a link homed where the caller
/// may not read is priced as no link is, so the bytes answered do not tell
/// the two apart, and nothing of that link is read. The price stays a bound
/// on what the commit stages, since the plan refuses each of the three
/// (`plan_deposits`' (4′)): an address where no link stands is `Absent`,
/// and a link homed where the caller's class does not read is not the
/// caller's own — a principal's class admits every home it owns — and is
/// `NotOwner`; `Caller::System`, which passes ω, owns no home a claim onto
/// a mark could stand in, and is refused `Unclaimed`.
fn original_type_bytes<W: LinkWorld>(world: &W, readable: &Visibility<'_, W>, old: &Address) -> u64 {
    document_of(old)
        .filter(|home| readable(world, home))
        .and_then(|_| world.links().readlink(old))
        .map_or(SHALLOW_TYPE_SPAN_BYTES, |original| {
            original.type_slot().spans().map(stored_span_bytes).fold(0u64, u64::saturating_add)
        })
}

/// Returns [`price_staged_bytes`]'s figure over `pieces`, the shot's runs
/// as [`run_pieces`] read them, `rewindows`, the documents the commit
/// re-windows, and `units`, the re-insert as M5's count tallied it — the
/// one body both prices share, so the reads' price stabs each stray once,
/// groups the lists once for its two terms and walks the draft's stored
/// pieces once for its units figure and these bytes. `readable` is the
/// class the rider's read is made at (`original_type_bytes`): the one read
/// of `world` this body makes, an original's stored type, is made only
/// where it admits the original's home.
#[allow(clippy::too_many_arguments)]
pub(super) fn staged_bytes<W: LinkWorld>(
    world: &W,
    readable: &Visibility<'_, W>,
    target: &PublishTarget,
    shot: &Shot,
    places: &[Option<VPos>],
    also_places: &[AlsoPlaces],
    deposits: &PublishDeposits,
    pieces: &[RunPieces],
    rewindows: &[Rewindow<'_>],
    units: UnitTally,
) -> u64 {
    let mut bytes = SHOT_BYTES;
    if let Some(base) = &shot.base {
        bytes = bytes.saturating_add(stored_tumbler_bytes(base.member.tumbler()));
    }
    if let Some(rendering) = shot.moves_base_of() {
        bytes = bytes.saturating_add(stored_tumbler_bytes(rendering.tumbler()));
    }
    if target.mints() {
        bytes += EDITION_MINT_BYTES;
    }
    if deposits.claim {
        bytes += EDITION_CLAIM_BYTES;
    }
    // Per re-windowed draft its one record, past its places.
    for (draft, _) in rewindows {
        bytes = bytes.saturating_add(REWINDOWED_DRAFT_BYTES).saturating_add(stored_tumbler_bytes(draft.tumbler()));
    }
    // Per run its pieces' records, and a kept place's change per piece per
    // list that places it: the rendering draft's, and each `also` draft's.
    for (index, run) in pieces.iter().enumerate() {
        let placed = placed_in(places, also_places, index);
        match *run {
            RunPieces::Native(cut) => {
                bytes = bytes.saturating_add(cut.saturating_mul(PLACED_RUN_BYTES + CORRESPONDENCE_RECORD_BYTES));
                bytes = bytes.saturating_add(placed.saturating_mul(cut.saturating_mul(KEPT_PLACE_BYTES)));
            }
            RunPieces::Stray(cut) => {
                bytes = bytes.saturating_add(PLACED_RUN_BYTES);
                bytes = bytes.saturating_add(placed.saturating_mul(cut.saturating_mul(KEPT_PLACE_BYTES)));
            }
            RunPieces::Unplaced => bytes = bytes.saturating_add(PLACED_RUN_BYTES),
        }
    }
    // The re-insert: each unit's two records, and its own bytes.
    bytes = bytes.saturating_add(units.units.saturating_mul(REINSERTED_UNIT_BYTES)).saturating_add(units.bytes);
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
    bytes = bytes.saturating_add((deposits.read_with.len() as u64).saturating_mul(READ_WITH_BYTES));
    bytes = bytes.saturating_add((deposits.supersede.len() as u64).saturating_mul(CLAIM_BYTES));
    // The rider: a retraction per original and, over a rest, the fresh mark
    // — the rest's spans as spelled and the original's type as stored, read
    // at the caller's class and priced as an absent link's where that class
    // does not admit the original's home.
    for entry in &deposits.originals {
        bytes = bytes.saturating_add(RETRACTION_BYTES);
        if entry.rest.is_empty() {
            continue;
        }
        bytes = bytes
            .saturating_add(COPY_FIXED_BYTES)
            .saturating_add(entry.rest.iter().map(stored_span_bytes).fold(0u64, u64::saturating_add))
            .saturating_add(original_type_bytes(world, readable, &entry.old));
    }
    bytes
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
    use super::*;

    /// THE SPAN's BYTES: the kernel's fixint layout — an 8-byte length
    /// before every sequence, 4 bytes per 32-bit digit, zero having none —
    /// over the shallow content span, the type slot's span and a span whose
    /// ordinal needs two digits; and the shallow type span the price falls
    /// back to is what the function prices.
    #[test]
    fn a_spans_stored_bytes_follow_the_kernels_layout() {
        let t = |comps: &[u32]| Tumbler::new(comps.iter().map(|&c| Nat::from(c))).expect("nonempty");
        let content = Span::new(t(&[1, 0, 1, 0, 65, 0, 1, 1]), t(&[0, 0, 0, 0, 0, 0, 0, 1])).expect("a span");
        assert_eq!(stored_span_bytes(&content), (8 + 5 * 12 + 3 * 8) + (8 + 7 * 8 + 12));
        assert_eq!(stored_span_bytes(&content), 168);
        assert_eq!(stored_span_bytes(&subtree_of(&t(&[1, 1, 0, 1, 0, 1, 0, 3, 23, 1]))), SHALLOW_TYPE_SPAN_BYTES);
        let wide = Span::new(t(&[1, 0, 1, 0, 65, 0, 1, 1]), t(&[0, 0, 0, 0, 0, 0, 0, 70_000])).expect("a span");
        assert_eq!(stored_span_bytes(&wide), 168, "one digit still");
        let deep = Tumbler::new(std::iter::repeat_n(Nat::from(1u64 << 40), 8)).expect("nonempty");
        assert_eq!(stored_tumbler_bytes(&deep), 8 + 8 * 16, "two digits a component");
    }
}
