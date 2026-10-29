//! The entry frame as the daemon composes it.
//!
//! It is the verifier's side of [`skep_identity::entry_frame`] (signed ops;
//! the seam placement investigation §3.2) — every member rebuilt from the op
//! and the locked snapshot the write's gates read, which under the
//! serialization guard *is* the transaction's base. Nothing here is served
//! or derived from the daemon's own state beyond what the design record
//! §2.5 names:
//!
//! * `alg` — the `attest.alg` token as the request carried it — the one
//!   member the snapshot does not supply, so it is applied last
//!   ([`EntryFrame::to_bytes`]);
//! * `board` — the board term ([`BoardTerm`]), `H.1`'s committed pair
//!   (signed-ops D13), read off the snapshot by
//!   [`crate::commits::board_term`] — by the check, ahead of the member,
//!   and handed to [`compose`]; by [`compose_record`] itself;
//! * `account` — the act's principal's account in the board's local form,
//!   M3's `principal_prefix`;
//! * `doc` — per op cell ([`DocTerm`]): the trunk of the op's `doc` for
//!   `insert` and `publish` (M5's one truncation, PUB-2.15); the op's `home`
//!   for `make_link`, `emit`, `nullify` and `assert_sup`; the pair of homes
//!   `(d_s, d_a)` for `edit_link`; the parent account the minted document
//!   lands in for the three mints — the request's `account` at
//!   `create_new_document`, the principal's own at `fork` and at `version`
//!   (never the trunk of `d_src`, which would put ω(`doc`) off `account` at
//!   a cross-owner version);
//! * `op` — the op-kind token as the wire spells it, which the body's
//!   [`EntryBody`] carries (`each_body_carries_the_wire_name_of_its_op`
//!   holds it to the codec's own `op_name`) — and, at a credential or
//!   registry record's `make_link`, the record grade's `record`
//!   ([`compose_record`]: skep-identity's [`RecordFrame`] over the fold's
//!   own reading of the link's address — its home, and the home's account
//!   by ω);
//! * `body` — per op cell: empty for the three mints; the declared type and
//!   the values for `insert`; for the link writes the stored link's slots as
//!   the transaction will deposit them (the design record §2.5's slot row):
//!   a `make_link`'s three slots resolved through M7's own [`slot_endset`]
//!   over this snapshot — an address-form slot's unit spans, a V-spec slot's
//!   I-extents — with its `replaces` member, absent or the address it names;
//!   an `emit`'s, a `nullify`'s and an `assert_sup`'s tuple as M7's own
//!   [`emit_tuple`], [`retraction_tuple`] and [`supersession_claim`] build
//!   it; an `edit_link`'s successor as M10's own [`successor_link`] builds it
//!   over this snapshot, then `original`'s unit span — the composer and the
//!   dispatch building through one function each, under the daemon's
//!   serialization lock, over the base the transaction opens on, so the
//!   signed row and the stored endset agree by construction; and for
//!   `publish` the count, the runs the client placed in the address form and
//!   the base (the design record §2.5's cell; signed-ops D25): the runs as
//!   the commit will place them, M5's own classing (`Shot::address_form`) —
//!   a run the commit copies in (the trunk's own I-space, the staging
//!   draft's) by its values, read off the snapshot by M4's run read
//!   (`pieces`) in run order; a window onto another document by its address
//!   and width, read from nowhere — within [`MAX_SHOT_BODY_BYTES`]; the base
//!   the shot's own, `Shot::base`'s member and extent as the request named
//!   them, empty in the birth shape — the member's address read off the
//!   request and never minted here, so the frame stays position-free; the
//!   kept places a `publish` carries beside its shot (`Op::Publish`'s
//!   `places`, the link-sets design §5.7) are no part of it, outside the
//!   preimage as `draft` is, so a shot with places verifies as the same
//!   shot without them; and, behind the shot's rows, THE DEPOSIT ROWS of a
//!   publication that carries `links`, `retract` or `read_with` entries
//!   (the link-sets design §5.7's signed entry; the signed-ops record's D25
//!   delta): M7's own [`plan_deposits`] over this snapshot — the one
//!   function the composite stages from, under the serialization lock the
//!   transaction's base — answers the public deposits per home in the
//!   signed order, and each is spelled by skep-identity's one builder
//!   ([`entry_body_publication`]) as the rows its own act would sign: the
//!   home by tag or address, the kind, the three slots as the store will
//!   hold them — a tag where a slot names the member or the edition the
//!   commit mints, the member-position row where the request spelled an
//!   end as the member's positions — and the `replaces` row empty. A
//!   request carrying no deposit spells today's body byte for byte.
//!
//! Nine bodies the daemon does not compose. Each is answered as the
//! [`ComposeFault`] that names its reason, and no more: what the write is
//! then owed — passed through to the store's or the door's own refusal, or
//! refused as its own cause — is the check's to decide, and is stated there
//! alone (`policy/attestation.rs`'s `attestation_check`, its doc item 6).
//!
//! * a `publish` body whose values it does not hold — a copied run naming an
//!   address M4 has no value at ([`ComposeFault::MissingValue`]). (A window's
//!   addresses are never walked here: the body spells them.)
//! * a `publish` body over a value the principal may not read — a copied run
//!   onto a staging draft the read predicate withholds from it
//!   ([`ComposeFault::UnreadableCopiedRunOrigin`]). Those values are never read
//!   here: a verdict composed over them answers *by* them —
//!   `attestation_required` telling that an address holds a value,
//!   `signature` whether a guessed value is the one it holds — where the
//!   store's source gate promises `withheld` before any existence answer
//!   (PUB-8.4). A window is no such case in the address form: it is signed
//!   by its address, which its author holds whatever it may read, so it is
//!   composed unread — and an author whose grant lapsed re-signs a re-shoot
//!   that keeps a window.
//! * a `publish` body past [`MAX_SHOT_BODY_BYTES`]
//!   ([`ComposeFault::PastBodyBudget`]), answered before it is built past the
//!   budget.
//! * a `publish` body with a term the frame's fixed-width rows cannot spell
//!   — a width, an extent or a placed count past 2^64 − 1
//!   ([`ComposeFault::Unspellable`]): a shot naming positions or a base
//!   extent no store holds.
//! * a `publish` body whose staging-draft runs re-insert more values than
//!   the store's own re-insert budget ([`ComposeFault::PastReinsertBudget`]),
//!   answered off the runs' widths before a value is read.
//! * a `make_link`'s or an `emit`'s slot over either of M7's per-slot
//!   budgets — the spans a slot keeps, the run-list steps its resolution
//!   walks ([`ComposeFault::SlotTooLarge`]): the same two budgets M7 charges
//!   inside the write, charged here as there, so the composer walks no
//!   further than the transaction would (SO-I9); a slot past either is a
//!   slot M7 refuses `slot_too_large`.
//! * a `make_link`'s or an `edit_link`'s V-spec naming a source the
//!   principal may not read ([`ComposeFault::UnreadableSlotSource`]): no
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
//! * a `publish` whose deposits M7's plan refuses
//!   ([`ComposeFault::DepositRefused`]): a `links`, `retract` or `read_with`
//!   entry the design's validation (3)–(5) refuses over this snapshot — the
//!   store refuses the same request by the same function, with the same
//!   fault, and answers it as the typed rejection naming the entry.

use std::num::NonZeroU64;

use skep_address::{document_of, Address, Nat, Span};
use skep_arrangement::{
    trunk_of, Caller, Deposit, HasM5, SegmentRun, Shot, MAX_REINSERTED_VALUES,
};
use skep_content::{HasContent, Piece};
use skep_febe::{successor_link, Judgment, Op};
use skep_identity::{
    entry_body_assert_sup, entry_body_edit_link, entry_body_emit, entry_body_empty,
    entry_body_insert, entry_body_make_link, entry_body_make_link_replacing, entry_body_nullify,
    entry_body_publication, entry_frame, unit_span, BoardTerm, ContentFreeOp, DepositHome,
    DepositKind, DepositRow, DepositSlot, DocTerm, EntryBody, LinkSlots, MemberPositions,
    PublishBody, PublishRefusal, RecordFrame, RecordRows, ShotBase, SlotElement,
};
use skep_links::{
    edition_type, emit_tuple, plan_deposits, read_with_type, retraction_tuple, slot_endset,
    supersession_claim, DepositPlan, Endset, Link, NamedAddress, PlanFault, PlannedDeposit,
    PlannedEnd, PlannedHome, PublishDeposits, PublishTarget, SlotArg,
};
use skep_namespace::{HasM3, PrincipalId};

use crate::commits::board_term;
use skep_engine::World;

/// The most bytes a `publish`'s entry-frame body may reach.
///
/// It is parity with the request-body cap,
/// [`crate::limits::MAX_REQUEST_BODY`]. The checked set's other ops compose
/// their bodies out of the request: the three mints' are empty, `insert`'s
/// values and the link writes' slot arguments ride in the frame, so the
/// transport's cap bounds them already, and the slots a `make_link`, an
/// `emit` and an `edit_link` build from them are held to the per-slot
/// budgets ([`ComposeFault::SlotTooLarge`],
/// [`ComposeFault::SuccessorRefused`]). A shot's body is read off the
/// store, one value per position its copied runs name (a window costs its
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
/// hold. Over the staging draft's runs the store's own re-insert budget stops
/// the walk first ([`ComposeFault::PastReinsertBudget`]): a quarter of this
/// budget is sixteen times the most the store ever re-inserts.
const MAX_SHOT_BODY_BYTES: usize = crate::limits::MAX_REQUEST_BODY;

/// Why the daemon could not compose the entry frame for a write.
///
/// These are [`compose`]'s reasons alone, the record frame's one refusal
/// being [`compose_record`]'s `None`; what the write is owed is the check's
/// to answer (`policy/attestation.rs`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum ComposeFault {
    /// The principal has no account prefix — no `account` term.
    NoAccount,
    /// A `publish`'s copied run names an address with no value in the snapshot.
    ///
    /// It is a shot the store's own existence walk refuses `dangling_source`.
    MissingValue,
    /// A `publish` copies a run from a document the principal may not read.
    ///
    /// The run is a staging draft's, re-inserted by value, and no value of
    /// the shot is read: a verdict composed over such a value would answer
    /// *by* it. What the write is owed is not the composer's to know: the
    /// check asks M5's own admission of the shot (`policy/attestation.rs`'s
    /// `refused_at_or_before_the_source_gate`). A window raises this never:
    /// it is spelled by address and read from nowhere.
    UnreadableCopiedRunOrigin,
    /// A `publish`'s body would pass [`MAX_SHOT_BODY_BYTES`].
    PastBodyBudget,
    /// A `publish` term the frame's fixed-width rows cannot spell.
    ///
    /// It is a run's width, the base extent or the placed count past
    /// 2^64 − 1 — naming positions or a base extent no store holds: a shot
    /// the store refuses (`base_extent_too_large`, `too_many_values`,
    /// `dangling_source`).
    Unspellable,
    /// A `publish` whose staging-draft runs pass M5's re-insert budget.
    ///
    /// The commit re-inserts those runs value by value
    /// (`Shot::reinserted_values` past
    /// `skep_arrangement::MAX_REINSERTED_VALUES`): a shot the store refuses
    /// `too_many_values` by request arithmetic before it probes an address,
    /// so one whose values this composer never walks.
    PastReinsertBudget,
    /// A `make_link`'s or `emit`'s slot over either of M7's per-slot budgets.
    ///
    /// The budgets are `MAX_SLOT_SPANS` spans in whichever form, or a V-spec
    /// slot commanding more than `MAX_SLOT_RESOLVE_STEPS` run-list steps —
    /// charged here as M7 charges them inside the write, by M7's own
    /// `slot_endset` for a `make_link` and by M7's own `emit_tuple` for an
    /// `emit`: a slot the store refuses `slot_too_large`. An `edit_link`'s
    /// slot past a budget is M10's own build refusing it,
    /// [`ComposeFault::SuccessorRefused`].
    SlotTooLarge,
    /// A V-spec names a source document the principal may not read.
    ///
    /// The V-spec is a `make_link`'s or an `edit_link`'s, and the slot that
    /// names it is never resolved: the write door refuses it `withheld`
    /// naming the source, ahead of the store (`consult_write`'s source
    /// consult, which judges every write that reaches here).
    UnreadableSlotSource,
    /// An `edit_link` whose successor M10's own build refuses.
    ///
    /// The build refuses an ill-formed spec, an unregistered source, a slot
    /// past a budget — so no frame is composed: the dispatch refuses the same
    /// request by the same function, before any driver.
    SuccessorRefused,
    /// A `publish` whose deposits M7's plan refuses (the link-sets design
    /// §5.7's validation (3)–(5)).
    ///
    /// The plan is a pure function of the world and the request, run here
    /// over the snapshot that is, under the serialization lock, the base the
    /// transaction opens on — so the store's own plan, inside the
    /// transaction, refuses the same request with this same fault, lowered
    /// to the typed rejection naming the entry (`link_home_refused`,
    /// `old_refused`, … with `site.index`), which is the answer owed; no
    /// frame is composed.
    DepositRefused(PlanFault),
}

/// The entry frame's `doc` term, owned, as the composer holds it.
///
/// It is the design record §2.5's term: one document, or an `edit_link`'s
/// pair of homes — [`DocTerm`]'s owning twin, spelled by
/// [`EntryFrame::to_bytes`] through [`skep_identity::entry_frame`].
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

/// Returns a stored link's three slots, by name, as M7 holds them.
///
/// They are its own endsets, borrowed where they lie: what an entry body's
/// [`LinkSlots`] walks, so no span is copied out of the link to be framed.
fn link_slots(link: &Link) -> LinkSlots<&Endset> {
    LinkSlots { from: link.from_slot(), to: link.to_slot(), ty: link.type_slot() }
}

/// Returns one `make_link` slot as the transaction will store it.
///
/// It is M7's own [`slot_endset`] over this snapshot's M5 — an address-form
/// slot's unit spans, a V-spec slot's I-extents, an I-span slot's spans
/// verbatim — under M7's two per-slot budgets. The two name forms consult
/// nothing: the I-span form's row is the request's own spans, so the
/// preimage of a write naming positions the principal cannot read is a
/// function of the request and the home alone (the read check's
/// composition channel, W6 (a)).
///
/// # Errors
///
/// [`ComposeFault::SlotTooLarge`] past either budget, and
/// [`ComposeFault::UnreadableSlotSource`] for a V-spec naming a source the
/// principal may not read, which is never resolved: the door withholds the
/// write before the store sees it, and a verdict composed over the source's
/// I-extents would answer by them.
fn stored_slot(
    world: &World,
    principal: PrincipalId,
    arg: &SlotArg,
) -> Result<Endset, ComposeFault> {
    if let SlotArg::Resolve(specs) = arg {
        let reader = world.reader_class(Some(principal));
        if specs.iter().any(|spec| !reader.readable(&spec.source)) {
            return Err(ComposeFault::UnreadableSlotSource);
        }
    }
    slot_endset(world.m5(), arg).ok_or(ComposeFault::SlotTooLarge)
}

/// Composes the entry frame for `op` by `principal` on `world`.
///
/// It is composed over the board term `board` the check read — every member
/// the op and the snapshot supply, composed once. `alg` is not among them:
/// it is the presented attestation's own, applied last
/// ([`EntryFrame::to_bytes`]). The check asks this for a write that
/// *presents* a member alone — the board term and (1)'s missing-member
/// refusal stand ahead of the composition (the design record §4.5's order)
/// — so no unsigned write pays the walk a shot's body costs.
///
/// # Errors
///
/// Why the frame cannot be composed: [`ComposeFault::NoAccount`] where the
/// principal has no account prefix, read first; then a `make_link`'s slot
/// faults ([`stored_slot`]), an `emit`'s [`ComposeFault::SlotTooLarge`], an
/// `edit_link`'s [`ComposeFault::UnreadableSlotSource`] or
/// [`ComposeFault::SuccessorRefused`], and a `publish`'s
/// [`ComposeFault::UnreadableCopiedRunOrigin`], its body's faults
/// ([`publish_body`]) or its deposits' ([`publication_body`]:
/// [`ComposeFault::DepositRefused`], and [`ComposeFault::PastBodyBudget`]
/// for the rows past the budget).
///
/// # Panics
///
/// Panics where the precondition fails: `op` is of the checked set
/// ([`crate::codec::in_checked_set`]), and every op of that set has an arm
/// below. The first half is `policy/attestation.rs`'s `attestation_check`'s
/// to discharge — its step 1, the one membership check, which this function
/// does not repeat; the second half is this function's own. Either broken —
/// an op outside the set, or the set widened without its arm — is never
/// answered as a fault: once the account is read it stops loudly in every
/// build, because no refusal the check can give is true of a build whose
/// two tables disagree, and passing the write through would commit it with
/// its marker slot empty — the silent drop the checked set's card rules
/// out. The check runs before the transaction, under locks that do not
/// poison, so under `skepd::serve` the stop is a `500 internal_panic` that
/// commits nothing.
pub(super) fn compose(
    world: &World,
    op: &Op,
    principal: PrincipalId,
    board: BoardTerm,
) -> Result<EntryFrame, ComposeFault> {
    let account = world.m3().principal_prefix(principal).ok_or(ComposeFault::NoAccount)?.clone();
    let (doc, body) = match op {
        // The three mints (signed-ops D24's cells (1)–(3)): the empty body
        // over the parent account — the request's at `create_new_document`,
        // the principal's own at `fork` and `version`. No minted address
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
            // Every slot as stored: M7's own resolution over this snapshot,
            // which under the serialization lock is the transaction's base.
            let (from, to, ty) = (
                stored_slot(world, principal, from)?,
                stored_slot(world, principal, to)?,
                stored_slot(world, principal, ty)?,
            );
            let slots = LinkSlots { from: &from, to: &to, ty: &ty };
            // The `replaces` member rides the signed body (PUB-5.15): the
            // empty group where the op carries none, else the state named —
            // so a copy of the request carries the one state its signer named.
            let body = match replaces {
                None => entry_body_make_link(slots),
                Some(named) => entry_body_make_link_replacing(slots, named),
            };
            (FrameDocTerm::One(home.clone()), body)
        }
        // The other link writes (signed-ops D24's cells (4)–(6)): the
        // stored tuple's rows, as M7's own `emit_tuple`, `retraction_tuple`
        // and `supersession_claim` build the tuple each op deposits — so, as
        // a `make_link`'s slots through `slot_endset`, the signed row and the
        // stored link agree by construction.
        Op::Emit { home, ty, from, to } => {
            // `None` is M7's own budget on the two caller-sized slots.
            let tuple = emit_tuple(ty, from, to).ok_or(ComposeFault::SlotTooLarge)?;
            (FrameDocTerm::One(home.clone()), entry_body_emit(link_slots(&tuple)))
        }
        Op::Nullify { home, target } => {
            let tuple = retraction_tuple(home, target);
            (FrameDocTerm::One(home.clone()), entry_body_nullify(link_slots(&tuple)))
        }
        Op::AssertSup { home, old, new } => {
            let tuple = supersession_claim(old, new);
            (FrameDocTerm::One(home.clone()), entry_body_assert_sup(link_slots(&tuple)))
        }
        // The edit (signed-ops D24's cell (7)): the successor as M10's own
        // build makes it over this snapshot — the door judges every write
        // that reaches here, so `Judged`, which answers a spec's faults as
        // the dispatch will — then the claim's `from`, `original`'s unit
        // span; the pair of homes as the frame's `doc`.
        Op::EditLink { original, successor, d_s, d_a } => {
            let reader = world.reader_class(Some(principal));
            // The `Resolve` form's sources, slot by slot; the two name forms
            // have none to consult (`SlotArg::specs`).
            let mut sources = [&successor.from, &successor.to, &successor.ty]
                .into_iter()
                .flat_map(|slot| slot.specs().iter());
            if sources.any(|spec| !reader.readable(&spec.source)) {
                return Err(ComposeFault::UnreadableSlotSource);
            }
            let link = successor_link(world.m3(), world.m5(), successor, Judgment::Judged)
                .map_err(|_| ComposeFault::SuccessorRefused)?;
            (
                FrameDocTerm::Pair { d_s: d_s.clone(), d_a: d_a.clone() },
                entry_body_edit_link(link_slots(&link), &unit_span(original)),
            )
        }
        // The kept places the request carries beside the shot (the
        // link-sets design §5.7) are outside the preimage, as `draft` is:
        // the shot alone is read here, and a shot with places signs as the
        // same shot without them. The deposits beside it are IN the
        // preimage, behind the shot's rows (`publication_body`).
        Op::Publish { target, shot, deposits, .. } => {
            // The frame's `doc`: the trunk at the document form, the parent
            // account at the mint form — the term M5's classing takes too
            // (`PublishTarget::term`), so at a mint every run of another
            // document is a window, as the commit will keep it.
            let term = target.term();
            // The runs as the commit will place them — M5's classing, the
            // one place a run's family is decided, asked with the address
            // the shot names, as `publish` is.
            let segments = shot.address_form(&term);
            // No value the principal may not read is ever read here: a
            // copied run's origin must be readable to it; a window is spelled
            // by address and read from nowhere.
            if !every_copied_run_origin_readable(world, &term, &segments, principal) {
                return Err(ComposeFault::UnreadableCopiedRunOrigin);
            }
            let shot_body = publish_body(world, shot, &segments)?;
            let body = publication_body(world, principal, target, shot, deposits, shot_body)?;
            (FrameDocTerm::One(term), body)
        }
        _ => unreachable!(
            "compose's precondition: {:?} is outside the checked set, or the set was \
             widened without its entry-frame arm here",
            op.kind()
        ),
    };
    Ok(EntryFrame { board, account, doc, body })
}

/// Returns whether the principal may read every value the shot copies in.
///
/// That is each copied segment's origin document — the trunk of the
/// document its start was minted under (`document_of`, then `trunk_of`: the
/// derivation M5's source gate asks about, PUB-2.15) — being `trunk`, the
/// shot document's own I-space, which the gate never consults, or one the
/// read predicate admits at the principal's class, which is what M10 lends
/// the gate, on the premise `policy/attestation.rs`'s
/// `refused_at_or_before_the_source_gate` states. A window's origin is not
/// asked about: no value of it is read.
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

/// Builds a shot's body, its segments in placement order.
///
/// A copied run's values are pushed one by one and a window as its address
/// and width, onto a [`PublishBody`] held to [`MAX_SHOT_BODY_BYTES`] over
/// the shot's base — the member and the extent the request named,
/// `Shot::base`, which the signer composed from the same request.
///
/// **The body's grain stays per value.** The values are read by M4's run
/// read, one lookup per piece, and a piece of a stretch — a run of
/// single-byte values — pushes *one row per byte*, since the body is the
/// entry frame's signed preimage, composed by the client from the values it
/// inserted and by a later verifier from the member's runs; a row per piece
/// would spell one N-byte value where the client spelled N one-byte values,
/// and every attested per-byte publish would be refused for its signature.
///
/// The budget is measured in the body's own layout as each value is read,
/// so nothing is collected ahead of the build and no body is held past it;
/// a refused push takes the builder with it, so the shot is refused whole
/// and no body is finished over the segments before the refusal — the
/// preimage of a shorter publish.
///
/// **Precondition.** The principal may read every value the shot copies in
/// ([`every_copied_run_origin_readable`]).
///
/// # Errors
///
/// Why the body cannot be built: an address M4 holds no value at
/// ([`ComposeFault::MissingValue`]), a base group or a segment that would
/// carry the body past the budget ([`ComposeFault::PastBodyBudget`]), a
/// term the frame's fixed-width rows cannot spell
/// ([`ComposeFault::Unspellable`]), or staging-draft runs re-inserting more
/// values than the store will ([`ComposeFault::PastReinsertBudget`]).
///
/// # Panics
///
/// Panics where a window's width is zero, which a `Run`'s never is.
fn publish_body(
    world: &World,
    shot: &Shot,
    segments: &[SegmentRun],
) -> Result<EntryBody, ComposeFault> {
    let content = world.content();
    let spelled = |n: &Nat| u64::try_from(n).map_err(|_| ComposeFault::Unspellable);
    // The base, both members: the member the request named — a
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
    // The store's re-insert budget, asked of the store's own count before a
    // value is read. The staging draft's runs are re-inserted value by value,
    // and M5 refuses a shot re-inserting more than `MAX_REINSERTED_VALUES` by
    // request arithmetic before it probes an address: walked here past it,
    // they would cost the check up to the body budget's worth of positions
    // under the serialization lock, for a shot nothing commits. The check
    // passes this answer through unattested, which is safe only because every
    // shot refused here is one the store refuses too — and it is: the count
    // is M5's own (`Shot::reinserted_values`, the one `publish` holds to the
    // same constant with the same `>`).
    if shot.reinserted_values() > Nat::from(MAX_REINSERTED_VALUES) {
        return Err(ComposeFault::PastReinsertBudget);
    }
    let mut body = PublishBody::within(MAX_SHOT_BODY_BYTES, base).map_err(refused)?;
    for segment in segments {
        match segment {
            SegmentRun::Value(run) => {
                // One row per *value* (the function's doc): a stretch's piece
                // one row per byte, a one-byte slice apiece; a value one row.
                // `covered`, asked after the walk, is the missing value.
                let mut pieces = content.pieces(run.i_start().tumbler(), run.width());
                for piece in pieces.by_ref() {
                    match piece {
                        Piece::Bytes(bytes) => {
                            for byte in bytes {
                                body = body.push(std::slice::from_ref(byte)).map_err(refused)?;
                            }
                        }
                        Piece::Value(v) => body = body.push(v.as_bytes()).map_err(refused)?,
                    }
                }
                if !pieces.covered() {
                    return Err(ComposeFault::MissingValue);
                }
            }
            SegmentRun::Window(run) => {
                // A window here is a `Run`, whose width is at least one
                // (`RunError::ZeroWidth`): a zero is a broken premise, and
                // stops loudly, as `compose`'s precondition does.
                let width = NonZeroU64::new(spelled(run.width())?).expect(
                    "publish_body's premise: a window here is a Run, whose width is at least one",
                );
                body = body.window(run.i_start(), width).map_err(refused)?;
            }
        }
    }
    Ok(body.finish())
}

/// Returns the composer's answer for what [`PublishBody`] refused.
///
/// The refusal is the shot's base at its mint or a segment after it, and
/// the answer goes by the cause the builder names: past its budget,
/// [`ComposeFault::PastBodyBudget`]; a count past `be64`,
/// [`ComposeFault::Unspellable`] (which the up-front sum has already answered
/// for every shot that reaches the walk).
fn refused(refusal: PublishRefusal) -> ComposeFault {
    match refusal {
        PublishRefusal::PastBudget => ComposeFault::PastBodyBudget,
        PublishRefusal::Unspellable => ComposeFault::Unspellable,
    }
}

/// Builds a publication's body: `shot_body`, the shot's own rows, then the
/// deposit rows of its public deposits (the link-sets design §5.7's signed
/// entry; the signed-ops record's D25 delta).
///
/// The deposits are M7's own plan over this snapshot ([`plan_deposits`]) —
/// the function the composite stages from inside the transaction, over the
/// base this snapshot is under the serialization lock, so the rows signed
/// here and the links stored agree by construction — spelled per home in
/// the plan's order by skep-identity's one builder
/// ([`entry_body_publication`]), each deposit the rows its own act would
/// sign ([`deposit_rows`]). A request carrying no deposit is `shot_body`
/// byte for byte; the plan is not asked for it, so a shot alone costs what
/// it cost before.
///
/// # Errors
///
/// [`ComposeFault::DepositRefused`] with the plan's fault — the store
/// refuses the same request by the same function — and
/// [`ComposeFault::PastBodyBudget`] where the rows carry the body past
/// [`MAX_SHOT_BODY_BYTES`].
fn publication_body(
    world: &World,
    principal: PrincipalId,
    target: &PublishTarget,
    shot: &Shot,
    deposits: &PublishDeposits,
    shot_body: EntryBody,
) -> Result<EntryBody, ComposeFault> {
    if deposits.is_empty() {
        return Ok(shot_body);
    }
    let plan = plan_deposits(world, Caller::Principal(principal), target, shot, deposits)
        .map_err(ComposeFault::DepositRefused)?;
    // The edition the read-withs are `from`: the document's trunk at the
    // document form, read off the request; at the mint form the edition the
    // commit mints, which no signer holds, spelled by tag.
    let owned = deposit_rows(&plan, target.document().map(trunk_of).as_ref());
    let rows: Vec<DepositRow<'_>> = owned.iter().map(OwnedRow::borrow).collect();
    let body = entry_body_publication(shot_body, &rows);
    if body.as_bytes().len() > MAX_SHOT_BODY_BYTES {
        return Err(ComposeFault::PastBodyBudget);
    }
    Ok(body)
}

/// One element of a deposit's slot row, owned ahead of the borrow the
/// builder takes ([`SlotElement`]'s owning twin).
enum OwnedElement {
    Span(Span),
    Member,
    Edition,
}

/// One slot of a deposit's rows, owned ([`DepositSlot`]'s owning twin).
enum OwnedSlot {
    Stored(Vec<OwnedElement>),
    Member(Vec<MemberPositions>),
}

/// One deposit's rows, owned ([`DepositRow`]'s owning twin): the builder
/// borrows every span and address, and the plan holds them in its own
/// shapes, so the rows are built once here and borrowed from.
struct OwnedRow {
    home: NamedAddress,
    kind: DepositKind,
    ty: OwnedSlot,
    from: OwnedSlot,
    to: OwnedSlot,
}

impl OwnedSlot {
    /// Returns a stored slot over `spans`, each its own element.
    fn spans<'a>(spans: impl IntoIterator<Item = &'a Span>) -> OwnedSlot {
        OwnedSlot::Stored(spans.into_iter().cloned().map(OwnedElement::Span).collect())
    }

    /// Returns a stored slot of one unit span, `a`'s.
    fn unit(a: &Address) -> OwnedSlot {
        OwnedSlot::Stored(vec![OwnedElement::Span(unit_span(a))])
    }

    /// Returns a planned end as its slot: a stored end's spans; a named end's
    /// elements, each tag as the tag and each address as its unit span, the
    /// span M7's `enc` stores for it; a member-position end's row.
    fn of(end: &PlannedEnd) -> OwnedSlot {
        match end {
            PlannedEnd::Stored(endset) => OwnedSlot::spans(endset.spans()),
            PlannedEnd::Named(named) => OwnedSlot::Stored(
                named
                    .iter()
                    .map(|n| match n {
                        NamedAddress::Member => OwnedElement::Member,
                        NamedAddress::Edition => OwnedElement::Edition,
                        NamedAddress::Address(a) => OwnedElement::Span(unit_span(a)),
                    })
                    .collect(),
            ),
            PlannedEnd::Member(spans) => OwnedSlot::Member(
                spans.iter().map(|s| MemberPositions { ordinal: s.ordinal, width: s.width }).collect(),
            ),
        }
    }

    fn borrow(&self) -> DepositSlot<'_> {
        match self {
            OwnedSlot::Stored(elements) => DepositSlot::Stored(
                elements
                    .iter()
                    .map(|e| match e {
                        OwnedElement::Span(s) => SlotElement::Span(s),
                        OwnedElement::Member => SlotElement::Member,
                        OwnedElement::Edition => SlotElement::Edition,
                    })
                    .collect(),
            ),
            OwnedSlot::Member(spans) => DepositSlot::MemberPositions(spans.clone()),
        }
    }
}

impl OwnedRow {
    fn borrow(&self) -> DepositRow<'_> {
        let home = match &self.home {
            NamedAddress::Member => DepositHome::Member,
            NamedAddress::Edition => DepositHome::Edition,
            NamedAddress::Address(a) => DepositHome::Address(a),
        };
        DepositRow { home, kind: self.kind, ty: self.ty.borrow(), from: self.from.borrow(), to: self.to.borrow() }
    }
}

/// Returns the deposit rows of `plan`, per home in the plan's order — the
/// signed entry's — each deposit as the rows its own act would sign over
/// the link the composite stages (`skep_links`'s `stage_deposits`, the one
/// other reader of the plan):
///
/// * the edition claim: the edition type's unit span, `from` the edition —
///   by tag where the commit mints it, its unit span where `doc` names it,
///   as the plan homes the row — `to` the staging draft's unit span;
/// * a copy: the plan's type slot as stored, its ends as planned —
///   stored, named (a tag, or an address's unit span) or by the member's
///   positions; its private claim is in no row, outside the signed set;
/// * a retraction: M7's own [`retraction_tuple`] over the home and the
///   target, as a `nullify` signs it;
/// * a read-with: the read-with type's unit span, `from` the edition —
///   `edition`'s unit span at the document form, the tag at the mint form —
///   `to` the set's unit span.
fn deposit_rows(plan: &DepositPlan, edition: Option<&Address>) -> Vec<OwnedRow> {
    let mut rows = Vec::new();
    for PlannedHome { home, deposits } in &plan.homes {
        for deposit in deposits {
            let row = |kind, ty, from, to| OwnedRow { home: home.clone(), kind, ty, from, to };
            rows.push(match deposit {
                PlannedDeposit::EditionClaim { origin } => row(
                    DepositKind::EditionClaim,
                    OwnedSlot::unit(edition_type()),
                    match home {
                        NamedAddress::Address(edition) => OwnedSlot::unit(edition),
                        NamedAddress::Member | NamedAddress::Edition => {
                            OwnedSlot::Stored(vec![OwnedElement::Edition])
                        }
                    },
                    OwnedSlot::unit(origin),
                ),
                PlannedDeposit::Copy { ty, from, to, .. } => {
                    row(DepositKind::Copy, OwnedSlot::spans(ty.spans()), OwnedSlot::of(from), OwnedSlot::of(to))
                }
                PlannedDeposit::Retraction { target, .. } => {
                    // The plan homes a retraction at its target's home, by
                    // address; a tag here is a broken premise, spelled as
                    // the tuple over the target alone would never be.
                    let NamedAddress::Address(at) = home else {
                        unreachable!("the plan homes a retraction in its target's home, by address")
                    };
                    let tuple = retraction_tuple(at, target);
                    let slots = link_slots(&tuple);
                    row(
                        DepositKind::Retraction,
                        OwnedSlot::spans(slots.ty.spans()),
                        OwnedSlot::spans(slots.from.spans()),
                        OwnedSlot::spans(slots.to.spans()),
                    )
                }
                PlannedDeposit::ReadWith { set, .. } => row(
                    DepositKind::ReadWith,
                    OwnedSlot::unit(read_with_type()),
                    match edition {
                        Some(edition) => OwnedSlot::unit(edition),
                        None => OwnedSlot::Stored(vec![OwnedElement::Edition]),
                    },
                    OwnedSlot::unit(set),
                ),
            });
        }
    }
    rows
}

/// Composes the record frame for a credential or registry record's `make_link`.
///
/// It is skep-identity's [`RecordFrame`] (signed ops, the record grade, 2a;
/// the frame merge), every member but `alg`, which is each candidate key's
/// own ([`RecordFrame::to_bytes`]), read here:
///
/// * `board` — the board term, `H.1`'s pair (signed-ops D13), off the
///   snapshot;
/// * `account` — `home_account`, the home's account: the fold's own H, ω
///   over the link's home (AUTH-2.35), which the caller has read — the
///   delegator's for a genesis, the subject's for a holder act (the design
///   record §4.5's clause (a)); never the acting principal's, which is the
///   entry grade's member and enters no record frame;
/// * `doc` — `home`, the link's home: the account's doc 1 (AUTH-2.127);
/// * the body's five rows — `ty`, the link's type address; `to`, the link's
///   target address where the kind names one (none at a targetless kind);
///   the `replaces` row empty (a credential deposit carries no member,
///   `op_shape_refusal` refuses one); the lineage row empty (signed-ops D2:
///   at 2a no lineage has forked, so every kind writes the empty group); and
///   `canonical`, the sig-less canonical record the caller projected off the
///   atom (`canonical_record(entries, None)` for a credential record).
///
/// Every member is a value the link's address, the atom's bytes and `H.1`
/// supply, which is what lets a mirror compose the same bytes from
/// `find_links` and `retrieve` (the design record §4.2 (C)). `None` only
/// where the board has no `H.1` (the states [`board_term`] names): the one
/// member the snapshot may lack, and so the one refusal this composer meets —
/// and the type says so. No fault of [`compose`]'s can reach this function's
/// caller, and a second refusal added here changes this signature, which
/// sends its author to the caller that must answer it.
pub(super) fn compose_record<'a>(
    world: &World,
    home_account: &'a Address,
    home: &'a Address,
    ty: &'a Address,
    to: &'a [Address],
    canonical: &'a [u8],
) -> Option<RecordFrame<'a>> {
    let board = board_term(world)?;
    let rows = RecordRows {
        ty,
        to,
        replaces: None,
        lineage_fork_point: None,
        sigless_canonical_record: canonical,
    };
    Some(RecordFrame { board, home_account, home, rows })
}

/// An entry frame composed but for its `alg` member — [`compose`]'s answer.
///
/// Every other member is held as the value [`skep_identity::entry_frame`]
/// spells: the board term, the account, the document term, and the body
/// with its grammar's token.
pub(super) struct EntryFrame {
    board: BoardTerm,
    account: Address,
    doc: FrameDocTerm,
    body: EntryBody,
}

impl EntryFrame {
    /// Returns the entry frame's bytes under `alg`.
    ///
    /// `alg` is the token the presented attestation's marker tag names; the
    /// layout is [`skep_identity::entry_frame`]'s,
    /// `framed(ENTRY_TAG, [alg, board, account, doc, op, body])`, `ENTRY_TAG`
    /// its framing tag. `to_` as C-CONV spells a rendering from a borrow, as
    /// `commits/head.rs`'s `HeadRecord::to_bytes` is; the free borrow is
    /// `EntryBody::as_bytes`.
    pub(super) fn to_bytes(&self, alg: &str) -> Vec<u8> {
        entry_frame(alg, self.board, &self.account, self.doc.term(), &self.body)
    }
}

#[cfg(test)]
mod tests;
