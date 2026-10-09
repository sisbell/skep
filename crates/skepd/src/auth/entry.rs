//! THE ENTRY FRAME AS THE DAEMON COMPOSES IT (signed ops; the seam
//! placement investigation §3.2): the verifier's side of
//! [`skep_identity::entry_frame`] — every member rebuilt from the op and the
//! locked snapshot the write's gates read, which under the serialization
//! guard IS the transaction's base. Nothing here is served or derived from
//! the daemon's own state beyond what the design record §2.5 names:
//!
//! * `alg` — the `attest.alg` token as the request carried it — the one
//!   member the snapshot does not supply, so it is applied last
//!   ([`EntryFrame::to_bytes`]);
//! * `board` — the BOARD TERM ([`BoardTerm`]), `H.1`'s committed pair (D13,
//!   RULED), read off the snapshot by [`crate::write_path::board_term`] — by
//!   the check, ahead of the member, and handed to [`compose`]; by
//!   [`compose_record`] itself;
//! * `account` — the act's principal's account in the board's local form,
//!   M3's `principal_prefix`;
//! * `doc` — per op cell ([`DocTerm`]): the TRUNK of the op's `doc` for
//!   `insert` and `publish` (M5's one truncation, PUB-2.15); the op's `home`
//!   for `make_link`, `emit`, `nullify` and `assert_sup`; the PAIR of homes
//!   `(d_s, d_a)` for `edit_link`; the PARENT ACCOUNT the minted document
//!   lands in for the three mints — the request's `account` at
//!   `create_new_document`, the principal's own at `fork` and at `version`
//!   (d24-3: never the trunk of `d_src`, which would put ω(`doc`) off
//!   `account` at a cross-owner version);
//! * `op` — the op-kind token as the wire spells it, which the body's
//!   [`EntryBody`] carries (`each_body_carries_the_wire_name_of_its_op`
//!   holds it to the codec's own `op_name`) — and, at a credential deposit's
//!   `make_link`, the RECORD grade's `record` ([`compose_record`]: the frame
//!   the record's own `sig` is made over, `account` the HOME's account and
//!   `doc` the home, both the fold's own reading of the link's address);
//! * `body` — per op cell: EMPTY for the three mints; the declared type and
//!   the values for `insert`; for the LINK WRITES the stored link's slots AS
//!   THE TRANSACTION WILL DEPOSIT THEM (the design record §2.5's slot row as
//!   ruled, ap6-3 and d24-2): a `make_link`'s three slots resolved through
//!   M7's own [`slot_endset`] over this snapshot — an address-form slot's
//!   unit spans, a V-spec slot's I-extents — with its `replaces` member,
//!   absent or the address it names; an `emit`'s, a `nullify`'s and an
//!   `assert_sup`'s tuple as M7's own [`emit_tuple`], [`retraction_tuple`]
//!   and [`supersession_claim`] build it; an `edit_link`'s successor as
//!   M10's own [`successor_link`] builds it over this snapshot, then
//!   `original`'s unit span — the composer and the dispatch building through
//!   ONE function each, under the daemon's serialization lock, over the base
//!   the transaction opens on, so the signed row and the stored endset agree
//!   by construction; and for `publish` THE COUNT, THE RUNS THE CLIENT PLACED
//!   IN THE ADDRESS FORM AND THE BASE (the design record §2.5's cell as
//!   ruled — V, l6-A4, D25; the base MEMBER in the group since round 7,
//!   bu7-E2 ARM (a)): the runs as the commit will place them, M5's own
//!   classing (`Shot::address_form`) — a run the commit COPIES IN (the
//!   trunk's own I-space, the staging draft's) by its values, read off the
//!   snapshot by M4's `value_at` in run order; a WINDOW onto another
//!   document by its address and width, read from nowhere — within
//!   [`MAX_SHOT_BODY_BYTES`]; the base the shot's own, `Shot::base`'s member
//!   and extent as the request named them, EMPTY in the birth shape — the
//!   member's address read off the request and never minted here, so the
//!   frame stays position-free.
//!
//! Eight bodies the daemon does not compose. Each is answered as the
//! [`ComposeFault`] that names its reason, and no more: what the write is
//! then OWED — passed through to the store's or the door's own refusal, or
//! refused as its own cause — is the check's to decide, and is stated there
//! alone (`policy/attestation.rs`'s `attestation_check`, its doc item 6).
//!
//! * a `publish` body whose values it does not hold — a copied run naming an
//!   address M4 has no value at ([`ComposeFault::MissingValue`]). (A window's
//!   addresses are never walked here: the body spells them.)
//! * a `publish` body over a value the principal may NOT READ — a COPIED run
//!   onto a staging draft the read predicate withholds from it
//!   ([`ComposeFault::UnreadableCopiedRunOrigin`]). Those values are never read
//!   here: a verdict composed over them answers BY them —
//!   `attestation_required` telling that an address holds a value,
//!   `signature` whether a guessed value is the one it holds — where the
//!   store's source gate promises `withheld` before any existence answer
//!   (PUB-8.4). A WINDOW is no such case since the address form (l6-A4): it
//!   is signed by its address, which its author holds whatever it may read,
//!   so it is composed unread — and an author whose grant lapsed re-signs a
//!   re-shoot that keeps a window (fam2-Q's (c), closed by arm A).
//! * a `publish` body past [`MAX_SHOT_BODY_BYTES`]
//!   ([`ComposeFault::PastBodyBudget`]), answered before it is built past the
//!   budget.
//! * a `publish` body with a term the frame's fixed-width rows cannot spell
//!   — a width, an extent or a placed count past 2^64 − 1
//!   ([`ComposeFault::Unspellable`]): a shot naming positions or a base
//!   extent no store holds.
//! * a `publish` body whose STAGING-DRAFT runs re-insert more values than
//!   the store's own re-insert budget ([`ComposeFault::PastReinsertBudget`]),
//!   answered off the runs' widths before a value is read.
//! * a link write's slot over either of M7's per-slot budgets — the spans a
//!   slot keeps, the run-list steps its resolution walks
//!   ([`ComposeFault::SlotTooLarge`]): the same two budgets M7 charges
//!   inside the write, charged here as there, so the composer walks no
//!   further than the transaction would (SO-I9); a slot past either is a
//!   slot M7 refuses `slot_too_large`.
//! * a `make_link`'s or an `edit_link`'s V-spec naming a source the
//!   principal may NOT READ ([`ComposeFault::UnreadableSlotSource`]): no
//!   arrangement the read predicate withholds is resolved here, since a
//!   verdict composed over its I-extents would answer by them — `signature`
//!   whether a guess at a private draft's I-space is right — where the write
//!   door promises `withheld` naming the source; the door judges every
//!   write that reaches this composer, both homes being registered and the
//!   principal's own, so that refusal follows.
//! * an `edit_link` whose successor M10's own build refuses — an ill-formed
//!   spec, an unregistered source, a slot past a budget
//!   ([`ComposeFault::SuccessorRefused`]): the dispatch refuses the same
//!   request by the same function.

use std::num::NonZeroU64;

use skep_address::{document_of, Address, Nat, Span};
use skep_arrangement::{trunk_of, Deposit, HasM5, SegmentRun, Shot, MAX_REINSERTED_VALUES};
use skep_content::HasContent;
use skep_febe::{successor_link, Judgment, Op};
use skep_identity::{
    entry_body_assert_sup, entry_body_edit_link, entry_body_emit, entry_body_empty,
    entry_body_insert, entry_body_make_link, entry_body_make_link_replacing, entry_body_nullify,
    entry_body_record, entry_frame, unit_span, BoardTerm, ContentFreeOp, DocTerm, EntryBody,
    EntrySlot, LinkSlots, PublishBody, PublishRefusal, RecordRows, ShotBase,
};
use skep_links::{
    emit_tuple, retraction_tuple, slot_endset, supersession_claim, Endset, Link, SlotArg,
};
use skep_namespace::{HasM3, PrincipalId};

use crate::write_path::board_term;
use crate::World;

/// The most bytes a `publish`'s entry-frame BODY may reach — PARITY with the
/// request-body cap, [`crate::limits::MAX_REQUEST_BODY`]. The other two ops
/// of the checked set compose their bodies out of the request itself —
/// `insert`'s values and `make_link`'s slots ride in the frame — so the
/// transport's cap bounds them already. A shot's body is read off the
/// STORE, one value per position its COPIED runs name (a window costs its
/// address row alone, whatever its width), and a run may name one stored
/// value as often as the wire's run list admits, at a width no codec cap
/// sees. Parity makes the largest body the check reads, frames and verifies
/// — against every candidate key of the attestation's row — the largest an
/// `insert` could already hand it.
///
/// Measured by [`PublishBody`], in the body's own layout, as the walk reads
/// each value, so an over-budget shot is refused before its body is built
/// past the budget, and the walk over the copied runs' Σ width stops at it:
/// every value costs at least its four-byte length prefix, so the walk
/// visits at most a quarter of the budget in positions, whatever the values
/// hold. Over the STAGING DRAFT's runs the store's own re-insert budget stops
/// the walk first ([`ComposeFault::PastReinsertBudget`]): a quarter of this
/// budget is sixteen times the most the store ever re-inserts.
const MAX_SHOT_BODY_BYTES: usize = crate::limits::MAX_REQUEST_BODY;

/// Why the daemon could not compose the entry frame for a write —
/// [`compose`]'s reasons alone, the record frame's one refusal being
/// [`compose_record`]'s `None`; what the write is owed is the check's to
/// answer (`policy/attestation.rs`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ComposeFault {
    /// The principal has no account prefix — no `account` term.
    NoAccount,
    /// A `publish`'s COPIED run names an address the snapshot holds no value
    /// at — a shot the store's own existence walk refuses `dangling_source`.
    MissingValue,
    /// A `publish`'s COPIED run — a staging draft's, re-inserted by value —
    /// names an origin document the principal may not read, so no value of
    /// the shot is read: a verdict composed over such a value would answer BY
    /// it. What the write is OWED is not the composer's to know: the check
    /// asks M5's own admission of the shot (`policy/attestation.rs`'s
    /// `refused_at_or_before_the_source_gate`). A window raises this never:
    /// it is spelled by address and read from nowhere.
    UnreadableCopiedRunOrigin,
    /// A `publish`'s body would pass [`MAX_SHOT_BODY_BYTES`].
    PastBodyBudget,
    /// A `publish` term the frame's fixed-width rows cannot spell — a run's
    /// width, the base extent or the placed count past 2^64 − 1 — naming
    /// positions or a base extent no store holds: a shot the store refuses
    /// (`base_extent_too_large`, `too_many_values`, `dangling_source`).
    Unspellable,
    /// A `publish` whose STAGING-DRAFT runs — re-inserted by the commit value
    /// by value — name more values than M5's re-insert budget
    /// (`Shot::reinserted_values` past
    /// `skep_arrangement::MAX_REINSERTED_VALUES`): a shot the store refuses
    /// `too_many_values` by request arithmetic before it probes an address,
    /// so one whose values this composer never walks.
    PastReinsertBudget,
    /// A link write's slot over either of M7's per-slot budgets —
    /// `MAX_SLOT_SPANS` spans in whichever form, or a V-spec slot commanding
    /// more than `MAX_SLOT_RESOLVE_STEPS` run-list steps — charged here as
    /// M7 charges them inside the write, by M7's own `slot_endset` for a
    /// `make_link`, by M10's own `successor_link` for an `edit_link`, and by
    /// M7's own `emit_tuple` for an `emit`: a slot the store refuses
    /// `slot_too_large`.
    SlotTooLarge,
    /// A `make_link`'s or an `edit_link`'s V-spec names a source document
    /// the principal may not read, so no slot is resolved: the write door
    /// refuses it `withheld` naming the source, ahead of the store
    /// (`consult_write`'s source consult, which judges every write that
    /// reaches here).
    UnreadableSlotSource,
    /// An `edit_link` whose successor M10's own build refuses — an ill-formed
    /// spec, an unregistered source — so no frame is composed: the dispatch
    /// refuses the same request by the same function, before any driver.
    SuccessorRefused,
}

/// The entry frame's `doc` TERM (the design record §2.5) as the composer
/// holds it, owned: one document, or an `edit_link`'s pair of homes —
/// [`DocTerm`]'s owning twin, spelled by [`EntryFrame::to_bytes`] through
/// [`skep_identity::entry_frame`].
enum FrameDocTerm {
    One(Address),
    Pair { d_s: Address, d_a: Address },
}

impl FrameDocTerm {
    fn term(&self) -> DocTerm<'_> {
        match self {
            FrameDocTerm::One(a) => DocTerm::One(a),
            FrameDocTerm::Pair { d_s, d_a } => DocTerm::Pair { d_s, d_a },
        }
    }
}

/// An endset's spans, owned — the slot row's input, as M7 stores the slot.
fn spans_of(endset: &Endset) -> Vec<Span> {
    endset.spans().cloned().collect()
}

/// A stored link's three slot rows, owned, in slot order — what an entry
/// body's [`LinkSlots`] borrows, read off the link as M7 or M10 builds it.
fn slot_rows(link: &Link) -> (Vec<Span>, Vec<Span>, Vec<Span>) {
    (spans_of(link.from_slot()), spans_of(link.to_slot()), spans_of(link.type_slot()))
}

/// ONE `make_link` slot AS THE TRANSACTION WILL STORE IT: M7's own
/// [`slot_endset`] over this snapshot's M5 — an address-form slot's unit
/// spans, a V-spec slot's I-extents — under M7's two per-slot budgets
/// ([`ComposeFault::SlotTooLarge`] past either); a V-spec naming a source the
/// principal may not read is never resolved
/// ([`ComposeFault::UnreadableSlotSource`]): the door withholds the write
/// before the store sees it, and a verdict composed over the source's
/// I-extents would answer by them.
fn stored_slot(world: &World, principal: PrincipalId, arg: &SlotArg) -> Result<Vec<Span>, ComposeFault> {
    if let SlotArg::Resolve(specs) = arg {
        let reader = world.reader_class(Some(principal));
        if specs.iter().any(|spec| !reader.readable(&spec.source)) {
            return Err(ComposeFault::UnreadableSlotSource);
        }
    }
    let endset = slot_endset(world.m5(), arg).ok_or(ComposeFault::SlotTooLarge)?;
    Ok(spans_of(&endset))
}

/// THE ENTRY FRAME for `op` by `principal` on `world`, over the board term
/// `board` the check read — every member the op and the snapshot supply,
/// composed once — or why it cannot be composed. `alg` is not among them: it
/// is the presented attestation's own, applied last ([`EntryFrame::to_bytes`]).
/// The check asks this for a write that PRESENTS a member alone — the board
/// term and (1)'s missing-member refusal stand ahead of the composition (the
/// design record §4.5's ratified order) — so no unsigned write pays the walk
/// a shot's body costs.
///
/// PRECONDITION: `op` is of the checked set ([`crate::codec::in_checked_set`]),
/// and every op of that set has an arm below. The first half is
/// `policy/attestation.rs`'s `attestation_check`'s to discharge — its step 1,
/// the one membership check, which this function does not repeat; the
/// second half is this function's own. Either broken — an op outside the
/// set, or the set widened without its arm — is never answered as a fault:
/// once the account is read it STOPS LOUDLY in every build, because no
/// refusal the check can give is true of a build whose two tables disagree,
/// and passing the write through would commit it with its marker slot empty
/// — the silent drop the checked set's card rules out. The check runs before
/// the transaction, under locks that do not poison, so under [`crate::serve`]
/// the stop is a `500 internal_panic` that commits nothing.
pub(super) fn compose(
    world: &World,
    op: &Op,
    principal: PrincipalId,
    board: BoardTerm,
) -> Result<EntryFrame, ComposeFault> {
    let account = world.m3().principal_prefix(principal).ok_or(ComposeFault::NoAccount)?.clone();
    let (doc, body) = match op {
        // THE THREE MINTS (D24's cells (1)–(3)): the EMPTY body over the
        // parent account — the request's at `create_new_document`, the
        // principal's own at `fork` and `version` (d24-3). No minted address
        // enters: the frame stays position-free.
        Op::CreateNewDocument { account: parent, .. } => (
            FrameDocTerm::One(parent.clone()),
            entry_body_empty(ContentFreeOp::CreateNewDocument),
        ),
        Op::Fork { .. } => {
            (FrameDocTerm::One(account.clone()), entry_body_empty(ContentFreeOp::Fork))
        }
        Op::Version { .. } => {
            (FrameDocTerm::One(account.clone()), entry_body_empty(ContentFreeOp::Version))
        }
        Op::Insert { doc, values, deposit, .. } => {
            let declared = match deposit {
                Deposit::Declared(ty) => Some(ty),
                Deposit::Undeclared => None,
            };
            let values = values.iter().map(|v| v.as_bytes());
            (FrameDocTerm::One(trunk_of(doc)), entry_body_insert(declared, values))
        }
        Op::MakeLink { home, from, to, ty, replaces } => {
            // Every slot AS STORED: M7's own resolution over this snapshot,
            // which under the serialization lock is the transaction's base.
            let (from, to, ty) = (
                stored_slot(world, principal, from)?,
                stored_slot(world, principal, to)?,
                stored_slot(world, principal, ty)?,
            );
            let slots = LinkSlots { from: EntrySlot(&from), to: EntrySlot(&to), ty: EntrySlot(&ty) };
            // The `replaces` member rides the signed body (PUB-5.15): the
            // EMPTY group where the op carries none, else the state named —
            // so a copy of the request carries the one state its signer named.
            let body = match replaces {
                None => entry_body_make_link(slots),
                Some(named) => entry_body_make_link_replacing(slots, named),
            };
            (FrameDocTerm::One(home.clone()), body)
        }
        // THE OTHER LINK WRITES (D24's cells (4)–(6)): the stored tuple's
        // rows, as M7's own `emit_tuple`, `retraction_tuple` and
        // `supersession_claim` build the tuple each op deposits — so, as a
        // `make_link`'s slots through `slot_endset`, the signed row and the
        // stored link agree by construction.
        Op::Emit { home, ty, from, to } => {
            // `None` is M7's own budget on the two caller-sized slots.
            let tuple = emit_tuple(ty, from, to).ok_or(ComposeFault::SlotTooLarge)?;
            let (from, to, ty) = slot_rows(&tuple);
            let slots = LinkSlots { from: EntrySlot(&from), to: EntrySlot(&to), ty: EntrySlot(&ty) };
            (FrameDocTerm::One(home.clone()), entry_body_emit(slots))
        }
        Op::Nullify { home, target } => {
            let (from, to, ty) = slot_rows(&retraction_tuple(home, target));
            let slots = LinkSlots { from: EntrySlot(&from), to: EntrySlot(&to), ty: EntrySlot(&ty) };
            (FrameDocTerm::One(home.clone()), entry_body_nullify(slots))
        }
        Op::AssertSup { home, old, new } => {
            let (from, to, ty) = slot_rows(&supersession_claim(old, new));
            let slots = LinkSlots { from: EntrySlot(&from), to: EntrySlot(&to), ty: EntrySlot(&ty) };
            (FrameDocTerm::One(home.clone()), entry_body_assert_sup(slots))
        }
        // THE EDIT (D24's cell (7)): the successor as M10's own build makes
        // it over this snapshot — the door judges every write that reaches
        // here, so `Judged`, which answers a spec's faults as the dispatch
        // will — then the claim's `from`, `original`'s unit span; the pair
        // of homes as the frame's `doc`.
        Op::EditLink { original, successor, d_s, d_a } => {
            let reader = world.reader_class(Some(principal));
            let resolve_ty = match &successor.ty {
                SlotArg::Resolve(specs) => specs.as_slice(),
                SlotArg::Addrs(_) => &[],
            };
            if successor.from.iter().chain(&successor.to).chain(resolve_ty).any(|spec| !reader.readable(&spec.source)) {
                return Err(ComposeFault::UnreadableSlotSource);
            }
            let link = successor_link(world.m3(), world.m5(), successor, Judgment::Judged)
                .map_err(|_| ComposeFault::SuccessorRefused)?;
            let (from, to, ty) = slot_rows(&link);
            let slots = LinkSlots { from: EntrySlot(&from), to: EntrySlot(&to), ty: EntrySlot(&ty) };
            (
                FrameDocTerm::Pair { d_s: d_s.clone(), d_a: d_a.clone() },
                entry_body_edit_link(slots, &unit_span(original)),
            )
        }
        Op::Publish { doc, shot } => {
            let trunk = trunk_of(doc);
            // The runs as the commit will place them — M5's classing, the
            // one place a run's family is decided (l6-A4), asked with the
            // address the shot names, as `publish` is.
            let segments = shot.address_form(doc);
            // No value the principal may not read is ever read here: a
            // copied run's origin must be readable to it; a window is spelled
            // by address and read from nowhere.
            if !every_copied_run_origin_readable(world, &trunk, &segments, principal) {
                return Err(ComposeFault::UnreadableCopiedRunOrigin);
            }
            (FrameDocTerm::One(trunk), publish_body(world, shot, &segments)?)
        }
        _ => unreachable!(
            "compose's precondition: {:?} is outside the checked set, or the set was \
             widened without its entry-frame arm here",
            op.kind()
        ),
    };
    Ok(EntryFrame { board, account, doc, body })
}

/// Whether the principal may read every value the shot COPIES IN — each
/// copied segment's ORIGIN DOCUMENT, the trunk of the document its start was
/// minted under (`document_of`, then `trunk_of`: the derivation M5's source
/// gate asks about, PUB-2.15), being `trunk`, the shot document's own
/// I-space, which the gate never consults, or one the read predicate admits
/// at the principal's class, which is what M10 lends the gate, on the
/// premise `policy/attestation.rs`'s `refused_at_or_before_the_source_gate`
/// states. A window's origin is not asked about: no value of it is read.
fn every_copied_run_origin_readable(
    world: &World,
    trunk: &Address,
    segments: &[SegmentRun],
    principal: PrincipalId,
) -> bool {
    let reader = world.reader_class(Some(principal));
    segments.iter().all(|segment| match segment {
        SegmentRun::Value(run) => document_of(run.i_start())
            .map(|d| trunk_of(&d))
            .is_some_and(|origin| origin == *trunk || reader.readable(&origin)),
        SegmentRun::Window(_) => true,
    })
}

/// A shot's body — its segments in placement order, a copied run's values
/// pushed one by one and a window pushed as its address and width, onto a
/// [`PublishBody`] held to [`MAX_SHOT_BODY_BYTES`] over the shot's base —
/// the member and the extent the request named, `Shot::base`, which the
/// signer composed from the same request (V; bu7-E2) — or why it cannot be
/// built: an address M4 holds no value at, a
/// segment that would carry the body past the budget, a term the frame's
/// fixed-width rows cannot spell, or staging-draft runs re-inserting more
/// values than the store will. The budget is measured in the body's own
/// layout as each value is read, so nothing is collected ahead of the build
/// and no body is held past it; a refused push takes the builder with it, so
/// the shot is refused whole and no body is finished over the segments before
/// the refusal — the preimage of a shorter publish. PRECONDITION: the
/// principal may read every value the shot copies in
/// ([`every_copied_run_origin_readable`]).
fn publish_body(
    world: &World,
    shot: &Shot,
    segments: &[SegmentRun],
) -> Result<EntryBody, ComposeFault> {
    let content = world.content();
    let spelled = |n: &Nat| u64::try_from(n).map_err(|_| ComposeFault::Unspellable);
    // THE BASE, both members (V; bu7-E2): the member the request named — a
    // client-named address, never one minted here — and the extent spelled
    // into its eight bytes.
    let base = shot
        .base
        .as_ref()
        .map(|base| Ok::<_, ComposeFault>(ShotBase { member: &base.member, extent: spelled(&base.extent)? }))
        .transpose()?;
    // The count must fit its eight bytes for the body to exist at all —
    // summed off the runs' widths before a value is read, so a shot naming
    // positions no count can spell is told so whatever its values would cost;
    // past this, the builder names each refusal itself (`refused`).
    segments.iter().try_fold(0u64, |placed, segment| {
        placed.checked_add(spelled(segment.run().width())?).ok_or(ComposeFault::Unspellable)
    })?;
    // THE STORE'S RE-INSERT BUDGET, asked of the store's own count before a
    // value is read. The staging draft's runs are re-inserted value by value,
    // and M5 refuses a shot re-inserting more than `MAX_REINSERTED_VALUES` by
    // request arithmetic before it probes an address: walked here past it,
    // they would cost the check up to the body budget's worth of positions
    // under the serialization lock, for a shot nothing commits. The check
    // passes this answer through UNATTESTED, which is safe only because every
    // shot refused here is one the store refuses too — and it is: the count
    // is M5's own (`Shot::reinserted_values`, the one `publish` holds to the
    // same constant with the same `>`).
    if shot.reinserted_values() > Nat::from(MAX_REINSERTED_VALUES) {
        return Err(ComposeFault::PastReinsertBudget);
    }
    let mut body = PublishBody::within(MAX_SHOT_BODY_BYTES, base);
    for segment in segments {
        match segment {
            SegmentRun::Value(run) => {
                for a in run.addrs() {
                    let v = content.value_at(a.tumbler()).ok_or(ComposeFault::MissingValue)?;
                    body = body.push(v.as_bytes()).map_err(refused)?;
                }
            }
            SegmentRun::Window(run) => {
                // A window here is a `Run`, whose width is at least one
                // (`RunError::ZeroWidth`): a zero is a broken premise, and
                // STOPS LOUDLY, as `compose`'s precondition does.
                let width = NonZeroU64::new(spelled(run.width())?).expect(
                    "publish_body's premise: a window here is a Run, whose width is at least one",
                );
                body = body.window(run.i_start(), width).map_err(refused)?;
            }
        }
    }
    Ok(body.finish())
}

/// The composer's answer for a segment [`PublishBody`] refused, by the cause
/// the builder names: past its budget, [`ComposeFault::PastBodyBudget`]; a
/// count past `be64`, [`ComposeFault::Unspellable`] (which the up-front sum
/// has already answered for every shot that reaches the walk).
fn refused(refusal: PublishRefusal) -> ComposeFault {
    match refusal {
        PublishRefusal::PastBudget => ComposeFault::PastBodyBudget,
        PublishRefusal::Unspellable => ComposeFault::Unspellable,
    }
}

/// THE RECORD FRAME for a credential deposit's `make_link` (signed ops, the
/// record grade, 2a; the frame merge, fm-I: the entry frame under the
/// `record` grammar, [`skep_identity::entry_body_record`]) — every member but
/// `alg`, which is each candidate key's own ([`EntryFrame::to_bytes`]):
///
/// * `board` — the board term, `H.1`'s pair (D13), off the snapshot;
/// * `account` — `home_account`, the HOME's account: the fold's own H, ω
///   over the link's home (AUTH-2.35), which the caller has read — the
///   DELEGATOR's for a genesis, the subject's for a holder act (the design
///   record §4.5's clause (a)); never the acting principal's, which is the
///   entry grade's member and enters no record frame;
/// * `doc` — `home`, the link's home: the account's doc 1 (AUTH-2.127);
/// * the body's five rows — `ty`, the link's type address; `to`, the link's
///   target address where the kind names one (none at a targetless kind);
///   the `replaces` row EMPTY (BW-04: a credential deposit carries no member,
///   `op_shape_refusal` refuses one); the LINEAGE row EMPTY (D2, l6-A5: at 2a
///   no lineage has forked, so every kind writes the empty group); and
///   `canonical`, the SIG-LESS CANONICAL RECORD
///   (`canonical_record(entries, None)`) the caller projected off the atom.
///
/// Every member is a value the link's address, the atom's bytes and `H.1`
/// supply, which is what lets a mirror compose the same bytes from
/// `find_links` and `retrieve` (the design record §4.2 (C)). `None` only
/// where the board has no `H.1` (the states [`board_term`] names): the one
/// member the snapshot may lack, and so the one refusal this composer meets —
/// and the type says so. No fault of [`compose`]'s can reach this function's
/// caller, and a second refusal added here changes this signature, which
/// sends its author to the caller that must answer it.
pub(super) fn compose_record(
    world: &World,
    home_account: &Address,
    home: &Address,
    ty: &Address,
    to: &[Address],
    canonical: &[u8],
) -> Option<EntryFrame> {
    let board = board_term(world)?;
    let body = entry_body_record(RecordRows {
        ty,
        to,
        replaces: None,
        lineage_fork_point: None,
        sigless_canonical_record: canonical,
    });
    Some(EntryFrame {
        board,
        account: home_account.clone(),
        doc: FrameDocTerm::One(home.clone()),
        body,
    })
}

/// An ENTRY frame composed but for its `alg` member — [`compose`]'s answer,
/// or [`compose_record`]'s — every other member as the value
/// [`skep_identity::entry_frame`] spells: the board term, the account, the
/// document term, and the body with its grammar's token.
pub(super) struct EntryFrame {
    board: BoardTerm,
    account: Address,
    doc: FrameDocTerm,
    body: EntryBody,
}

impl EntryFrame {
    /// The entry frame's bytes under `alg`, the token the presented
    /// attestation's MARKER tag names — [`skep_identity::entry_frame`]'s
    /// layout, `framed(ENTRY_TAG, [alg, board, account, doc, op, body])`,
    /// `ENTRY_TAG` its framing tag. `to_` as C-CONV spells a rendering from a
    /// borrow, as `write_path/head.rs`'s `HeadRecord::to_bytes` is; the free
    /// borrow is `EntryBody::as_bytes`.
    pub(super) fn to_bytes(&self, alg: &str) -> Vec<u8> {
        entry_frame(alg, self.board, &self.account, self.doc.term(), &self.body)
    }
}

#[cfg(test)]
mod tests {
    use skep_febe::{Codec, OpKind};
    use skep_identity::{entry_body_publish, entry_body_record};
    use skep_links::{enc, registry, ShippedType};

    use super::*;
    use crate::codec::op_name;
    use crate::JsonCodec;

    /// The frame's `op` member is the op-kind token AS THE WIRE SPELLS IT
    /// (the design record §2.5): each entry-grade body `skep_identity` builds
    /// — one per kind of the checked set — carries the codec's own name for
    /// its op, so a wire rename meets this test before it can move a signed
    /// preimage. ONE EXCEPTION, the frame merge's (fm-I, 2026-09-29):
    /// `record` names the record grade's body and no wire op — the codec
    /// parses no such op, and the body's token says which grammar a `sig`
    /// was made over.
    #[test]
    fn each_body_carries_the_wire_name_of_its_op() {
        let empty = EntrySlot(&[]);
        let slots = LinkSlots { from: empty, to: empty, ty: empty };
        let original = skep_address::validate(
            skep_address::Tumbler::new([1u32, 0, 1, 0, 1, 0, 2, 1].map(skep_address::Nat::from))
                .expect("a tumbler"),
        )
        .expect("an address");
        for (body, kind) in [
            (entry_body_empty(ContentFreeOp::CreateNewDocument), OpKind::CreateNewDocument),
            (entry_body_empty(ContentFreeOp::Fork), OpKind::Fork),
            (entry_body_empty(ContentFreeOp::Version), OpKind::Version),
            (entry_body_insert(None, std::iter::empty()), OpKind::Insert),
            (entry_body_make_link(slots), OpKind::MakeLink),
            (entry_body_emit(slots), OpKind::Emit),
            (entry_body_nullify(slots), OpKind::Nullify),
            (entry_body_assert_sup(slots), OpKind::AssertSup),
            (entry_body_edit_link(slots, &unit_span(&original)), OpKind::EditLink),
            (entry_body_publish(std::iter::empty(), None), OpKind::Publish),
        ] {
            assert_eq!(body.op(), op_name(kind), "{kind:?}");
            assert!(crate::codec::in_checked_set(kind), "{kind:?}: every body's kind is of the checked set");
        }
        let ty = skep_address::validate(
            skep_address::Tumbler::new([1u32, 1, 0, 1, 0, 1, 0, 3, 1].map(skep_address::Nat::from))
                .expect("a tumbler"),
        )
        .expect("an address");
        let record = entry_body_record(RecordRows {
            ty: &ty,
            to: &[],
            replaces: None,
            lineage_fork_point: None,
            sigless_canonical_record: b"",
        });
        assert_eq!(record.op(), "record", "the record grade's grammar token");
        assert!(
            JsonCodec.parse(br#"{"op":"record"}"#).is_err(),
            "`record` is a grammar token with no wire op: the codec parses none by that name"
        );
    }

    /// THE UNIT SPAN IS M7's OWN SPELLING: the span the frame's `unit_span`
    /// gives an address — the start the address, the width the unit at its
    /// length — is the span M7's `enc` stores for a slot that names it, at
    /// every depth an address takes, and over a list the two agree span for
    /// span and in order. So a slot row composed from addresses alone — a
    /// `nullify`'s, an `assert_sup`'s, an `emit`'s, the `edit_link` claim's
    /// `from` — is the row a verifier composes from `read_link`.
    #[test]
    fn the_unit_span_is_the_span_enc_stores() {
        let addr = |comps: &[u32]| {
            skep_address::validate(
                skep_address::Tumbler::new(comps.iter().map(|&c| skep_address::Nat::from(c)))
                    .expect("a tumbler"),
            )
            .expect("an address")
        };
        let addrs = [
            addr(&[1, 0, 1]),
            addr(&[1, 0, 1, 0, 1]),
            addr(&[1, 0, 1, 0, 1, 0, 2, 1]),
            addr(&[1, 1, 0, 1, 0, 1, 0, 1, 5]),
            addr(&[1, 0, 1, 0, 1, 2, 0, 1, 7]),
        ];
        for a in &addrs {
            assert_eq!(enc([a]).spans().cloned().collect::<Vec<_>>(), vec![unit_span(a)], "{a}");
        }
        assert_eq!(
            spans_of(&enc(addrs.iter())),
            addrs.iter().map(unit_span).collect::<Vec<_>>(),
            "over a list, span for span and in order"
        );
        assert_eq!(
            spans_of(registry().reserved_type(ShippedType::Retraction)),
            vec![unit_span(&addr(&[1, 1, 0, 1, 0, 1, 0, 1, 5]))],
            "the retraction class's type slot is its ghost address's one unit span"
        );
        assert_eq!(
            spans_of(registry().reserved_type(ShippedType::Supersedes)),
            vec![unit_span(&addr(&[1, 1, 0, 1, 0, 1, 0, 1, 4]))],
            "the supersedes class's type slot is its ghost address's one unit span"
        );
    }

    /// COMPOSE'S PRECONDITION IS NEVER ANSWERED AS A FAULT: for a principal
    /// with a prefix — the account term read ahead of the op — an op outside
    /// the checked set STOPS LOUDLY. A fault here would be one the check
    /// passes through, committing the write with its marker slot empty — the
    /// silent drop the checked set's card rules out — and no refusal the check
    /// could give is true of a build whose two tables disagree.
    #[test]
    #[should_panic(expected = "compose's precondition")]
    fn an_op_outside_the_checked_set_stops_compose_loudly() {
        use skep_arrangement::VPos;
        use skep_kernel::{CheckpointPolicy, Durability, KernelConfig, SaltSource};
        use skep_namespace::{head_document, BOOTSTRAP_PRINCIPAL};

        let engine = skep_engine::Engine::open(KernelConfig {
            durability: Durability::InMemory,
            checkpoint: CheckpointPolicy::Manual,
            salt: SaltSource::Seeded(0),
        })
        .expect("in-memory genesis cannot fail");
        let snap = engine.kernel().snapshot();
        let world = snap.world();
        assert!(
            world.m3().principal_prefix(BOOTSTRAP_PRINCIPAL).is_some(),
            "the premise: genesis seats principal 0, so its account term is read"
        );
        let board = BoardTerm { log_position: 1, chain: [0; 32] };
        let delete = Op::Delete {
            doc: head_document(),
            p: VPos::content(Nat::from(1u32)),
            width: Nat::from(1u32),
        };
        let _ = compose(world, &delete, BOOTSTRAP_PRINCIPAL, board);
    }
}
