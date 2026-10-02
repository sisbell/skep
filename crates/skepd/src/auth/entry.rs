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
//! * `doc` — per op cell: the TRUNK of the op's `doc` for `insert` and
//!   `publish` (M5's one truncation, PUB-2.15), the op's `home` for
//!   `make_link`;
//! * `op` — the op-kind token as the wire spells it, which the body's
//!   [`EntryBody`] carries (`each_body_carries_the_wire_name_of_its_op`
//!   holds it to the codec's own `op_name`) — and, at a credential deposit's
//!   `make_link`, the RECORD grade's `record` ([`compose_record`]: the frame
//!   the record's own `sig` is made over, `account` the HOME's account and
//!   `doc` the home, both the fold's own reading of the link's address);
//! * `body` — per op cell: the declared type and the values for `insert`,
//!   the three slots as the client sent them and its `replaces` member —
//!   absent, or the address it names — for `make_link`, and for `publish`
//!   THE COUNT, THE RUNS THE CLIENT PLACED IN THE ADDRESS FORM AND THE BASE
//!   EXTENT (the design record §2.5's cell as ruled — V, l6-A4, D25): the
//!   runs as the commit will place them, M5's own classing
//!   (`Shot::address_form`) — a run the commit COPIES IN (the trunk's own
//!   I-space, the staging draft's) by its values, read off the snapshot by
//!   M4's `value_at` in run order; a WINDOW onto another document by its
//!   address and width, read from nowhere — within [`MAX_SHOT_BODY_BYTES`];
//!   `base_extent` the shot's own, EMPTY in the birth shape.
//!
//! Five `publish` bodies the daemon does not compose. Each is answered as the
//! [`ComposeFault`] that names its reason, and no more: what the write is
//! then OWED — passed through to the store's own refusal, or refused as its
//! own cause — is the check's to decide, and is stated there alone
//! (`policy/attestation.rs`'s `attestation_check`, its doc item 6).
//!
//! * a body whose values it does not hold — a copied run naming an address
//!   M4 has no value at ([`ComposeFault::MissingValue`]). (A window's
//!   addresses are never walked here: the body spells them.)
//! * a body over a value the principal may NOT READ — a COPIED run onto a
//!   staging draft the read predicate withholds from it
//!   ([`ComposeFault::UnreadableCopiedRunOrigin`]). Those values are never read
//!   here: a verdict composed over them answers BY them —
//!   `attestation_required` telling that an address holds a value,
//!   `signature` whether a guessed value is the one it holds — where the
//!   store's source gate promises `withheld` before any existence answer
//!   (PUB-8.4). A WINDOW is no such case since the address form (l6-A4): it
//!   is signed by its address, which its author holds whatever it may read,
//!   so it is composed unread — and an author whose grant lapsed re-signs a
//!   re-shoot that keeps a window (fam2-Q's (c), closed by arm A).
//! * a body past [`MAX_SHOT_BODY_BYTES`] ([`ComposeFault::PastBodyBudget`]),
//!   answered before it is built past the budget.
//! * a body with a term the frame's fixed-width rows cannot spell — a width,
//!   an extent or a placed count past 2^64 − 1 ([`ComposeFault::Unspellable`]):
//!   a shot naming positions or a base extent no store holds.
//! * a body whose STAGING-DRAFT runs re-insert more values than the store's
//!   own re-insert budget ([`ComposeFault::PastReinsertBudget`]), answered off
//!   the runs' widths before a value is read.

use std::num::NonZeroU64;

use skep_address::{document_of, Address, Nat, Span};
use skep_arrangement::{trunk_of, Deposit, PlacedSegment, Shot, MAX_REINSERTED_VALUES};
use skep_content::HasContent;
use skep_febe::Op;
use skep_identity::{
    entry_body_insert, entry_body_make_link, entry_body_make_link_replacing, entry_body_record,
    entry_frame, BoardTerm, EntryBody, EntrySlot, LinkSlots, PublishBody, PublishRefusal,
    RecordRows,
};
use skep_links::SlotArg;
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
}

/// A link slot as the entry frame's slot row takes it — the resolve form's
/// V-specs re-paired as `(source, span)`.
enum Slot<'a> {
    Addrs(&'a [Address]),
    Resolve(Vec<(Address, Span)>),
}

impl<'a> Slot<'a> {
    fn of(arg: &'a SlotArg) -> Slot<'a> {
        match arg {
            SlotArg::Addrs(addrs) => Slot::Addrs(addrs),
            SlotArg::Resolve(specs) => Slot::Resolve(
                specs.iter().map(|s| (s.source.clone(), s.span.clone())).collect(),
            ),
        }
    }

    fn as_entry(&self) -> EntrySlot<'_> {
        match self {
            Slot::Addrs(a) => EntrySlot::Addrs(a),
            Slot::Resolve(v) => EntrySlot::Resolve(v),
        }
    }
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
        Op::Insert { doc, values, deposit, .. } => {
            let declared = match deposit {
                Deposit::Declared(ty) => Some(ty),
                Deposit::Undeclared => None,
            };
            let values = values.iter().map(|v| v.as_bytes());
            (trunk_of(doc), entry_body_insert(declared, values))
        }
        Op::MakeLink { home, from, to, ty, replaces } => {
            let (from, to, ty) = (Slot::of(from), Slot::of(to), Slot::of(ty));
            let slots = LinkSlots { from: from.as_entry(), to: to.as_entry(), ty: ty.as_entry() };
            // The `replaces` member rides the signed body (PUB-5.15): the
            // EMPTY group where the op carries none, else the state named —
            // so a copy of the request carries the one state its signer named.
            let body = match replaces {
                None => entry_body_make_link(slots),
                Some(named) => entry_body_make_link_replacing(slots, named),
            };
            (home.clone(), body)
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
            (trunk, publish_body(world, shot, &segments)?)
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
    segments: &[PlacedSegment],
    principal: PrincipalId,
) -> bool {
    let reader = world.reader_class(Some(principal));
    segments.iter().all(|segment| match segment {
        PlacedSegment::Value(run) => document_of(run.i_start())
            .map(|d| trunk_of(&d))
            .is_some_and(|origin| origin == *trunk || reader.readable(&origin)),
        PlacedSegment::Window(_) => true,
    })
}

/// A shot's body — its segments in placement order, a copied run's values
/// pushed one by one and a window pushed as its address and width, onto a
/// [`PublishBody`] held to [`MAX_SHOT_BODY_BYTES`] over the shot's base
/// extent — or why it cannot be built: an address M4 holds no value at, a
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
    segments: &[PlacedSegment],
) -> Result<EntryBody, ComposeFault> {
    let content = world.content();
    let spelled = |n: &Nat| u64::try_from(n).map_err(|_| ComposeFault::Unspellable);
    let base_extent = shot.base.as_ref().map(|base| spelled(&base.extent)).transpose()?;
    // The count must fit its eight bytes for the body to exist at all —
    // summed off the runs' widths before a value is read, so a shot naming
    // positions no count can spell is told so whatever its values would cost;
    // past this, the builder names each refusal itself (`refused`).
    segments.iter().try_fold(0u64, |placed, segment| {
        let run = match segment {
            PlacedSegment::Value(run) | PlacedSegment::Window(run) => run,
        };
        placed.checked_add(spelled(run.width())?).ok_or(ComposeFault::Unspellable)
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
    let mut body = PublishBody::within(MAX_SHOT_BODY_BYTES, base_extent);
    for segment in segments {
        match segment {
            PlacedSegment::Value(run) => {
                for a in run.addrs() {
                    let v = content.value_at(a.tumbler()).ok_or(ComposeFault::MissingValue)?;
                    body = body.push(v.as_bytes()).map_err(refused)?;
                }
            }
            PlacedSegment::Window(run) => {
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
    Some(EntryFrame { board, account: home_account.clone(), doc: home.clone(), body })
}

/// An ENTRY frame composed but for its `alg` member — [`compose`]'s answer,
/// or [`compose_record`]'s — every other member as the value
/// [`skep_identity::entry_frame`] spells: the board term, the account, the
/// document, and the body with its grammar's token.
pub(super) struct EntryFrame {
    board: BoardTerm,
    account: Address,
    doc: Address,
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
        entry_frame(alg, self.board, &self.account, &self.doc, &self.body)
    }
}

#[cfg(test)]
mod tests {
    use skep_febe::{Codec, OpKind};
    use skep_identity::{entry_body_publish, entry_body_record};

    use super::*;
    use crate::codec::op_name;
    use crate::JsonCodec;

    /// The frame's `op` member is the op-kind token AS THE WIRE SPELLS IT
    /// (the design record §2.5): each entry-grade body `skep_identity` builds
    /// carries the codec's own name for its op, so a wire rename meets this
    /// test before it can move a signed preimage. ONE EXCEPTION, the frame
    /// merge's (fm-I, 2026-09-29): `record` names the record grade's body
    /// and no wire op — the codec parses no such op, and the body's token
    /// says which grammar a `sig` was made over.
    #[test]
    fn each_body_carries_the_wire_name_of_its_op() {
        let empty = EntrySlot::Addrs(&[]);
        let slots = LinkSlots { from: empty, to: empty, ty: empty };
        assert_eq!(entry_body_insert(None, std::iter::empty()).op(), op_name(OpKind::Insert));
        assert_eq!(entry_body_make_link(slots).op(), op_name(OpKind::MakeLink));
        assert_eq!(entry_body_publish(std::iter::empty(), None).op(), op_name(OpKind::Publish));
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
