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
//!   RULED), read off the snapshot by [`crate::write_path::board_term`];
//! * `account` — the act's principal's account in the board's local form,
//!   M3's `principal_prefix`;
//! * `doc` — per op cell: the TRUNK of the op's `doc` for `insert` and
//!   `publish` (M5's one truncation, PUB-2.15), the op's `home` for
//!   `make_link`;
//! * `op` — the op-kind token as the wire spells it, which the body's
//!   [`EntryBody`] carries (`each_body_carries_the_wire_name_of_its_op`
//!   holds it to the codec's own `op_name`);
//! * `body` — per op cell: the declared type and the values for `insert`,
//!   the three slots as the client sent them for `make_link`, and for
//!   `publish` THE RUNS THE CLIENT PLACED, their values read off the
//!   snapshot by M4's `value_at` in run order (the record §2.5; the
//!   investigation §3.3: the count is Σ width of the supplied runs), within
//!   [`MAX_SHOT_BODY_BYTES`].
//!
//! Three `publish` bodies the daemon does not compose:
//!
//! * a body whose values it does not hold — a run naming an address M4 has
//!   no value at. That write cannot commit: the store's own existence walk
//!   refuses it `dangling_source`, so the check passes it through
//!   UNATTESTED and lets the store answer.
//! * a body over a value the principal may NOT READ — a run onto an origin
//!   document the read predicate withholds from it. Those values are never
//!   read here: a verdict composed over them answers BY them —
//!   `attestation_required` telling that an address holds a value,
//!   `signature` whether a guessed value is the one it holds — where the
//!   store's source gate promises `withheld` before any existence answer
//!   (PUB-8.4). The composer answers [`ComposeFault::UnreadableRunOrigin`] and
//!   no more. What such a shot is OWED is the check's to decide, by asking
//!   the store's own gates (`policy/attestation.rs`): their own refusal,
//!   passed through UNATTESTED, where they refuse it; and
//!   `attestation_invalid:withheld` where the base CARRIES every such run
//!   (PUB-6.24), a value no signature of its author's can attest — as a
//!   cross-owner `version` of a published member hands a principal runs whose
//!   origin it never could read.
//! * a body past [`MAX_SHOT_BODY_BYTES`], refused
//!   `attestation_invalid:frame_too_large` before it is built.

use skep_address::{document_of, Address, Span};
use skep_arrangement::{trunk_of, Deposit, Shot};
use skep_content::HasContent;
use skep_febe::Op;
use skep_identity::{
    entry_body_insert, entry_body_make_link, entry_body_publish, entry_frame, BoardTerm, EntryBody,
    EntrySlot, LinkSlots,
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
/// STORE, one value per position its runs name, and a run may name one
/// stored value as often as the wire's run list admits, at a width no codec
/// cap sees. Parity makes the largest body the check reads, frames and
/// verifies — against every candidate key of the attestation's row — the
/// largest an `insert` could already hand it.
///
/// Measured in [`entry_body_publish`]'s own layout — a be64 count, then a
/// be32 length and the bytes per value ([`VALUE_COUNT_BYTES`],
/// [`VALUE_LENGTH_BYTES`]) — as the walk reads each value, so an
/// over-budget shot is refused before its body is built, and the walk over
/// the runs' Σ width stops at the budget: every value is at least one byte
/// (M5 refuses an empty one), so the walk visits at most a fifth of the
/// budget in positions.
const MAX_SHOT_BODY_BYTES: usize = crate::limits::MAX_REQUEST_BODY;

/// The value sequence's leading be64 count.
const VALUE_COUNT_BYTES: usize = 8;

/// The be32 length each value of the sequence is delimited by.
const VALUE_LENGTH_BYTES: usize = 4;

/// Why the daemon could not compose the entry frame for a write — the reason
/// the composer met; what the write is owed is the check's to answer
/// (`policy/attestation.rs`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ComposeFault {
    /// The entry frame's `board` term (D13) has no value: the board has no
    /// `H.1` — on a claimed board, one of the two states [`board_term`]
    /// names.
    NoBoardTerm,
    /// The principal has no account prefix — no `account` term.
    NoAccount,
    /// A `publish` run names an address the snapshot holds no value at — a
    /// shot the store's own existence walk refuses `dangling_source`.
    MissingValue,
    /// A `publish` run names an origin document the principal may not read,
    /// so no value of the shot is read: a verdict composed over such a value
    /// would answer BY it. What the write is OWED — the store's own refusal,
    /// or `attestation_invalid:withheld` where the base CARRIES every such
    /// run (PUB-6.24) — is not the composer's to know: the check asks the
    /// store's own gates (`policy/attestation.rs`'s
    /// `refused_at_or_before_the_source_gate`).
    UnreadableRunOrigin,
    /// A `publish`'s body would pass [`MAX_SHOT_BODY_BYTES`].
    OverBudget,
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

/// THE ENTRY FRAME for `op` by `principal` on `world` — every member the op
/// and the snapshot supply, composed once — or why it cannot be composed.
/// `alg` is not among them: it is the presented attestation's own, applied
/// last ([`EntryFrame::to_bytes`]), so the check learns whether an entry frame
/// CAN be composed before it asks for the member, and names no token for a
/// write that presents none.
///
/// PRECONDITION: `op` is of the checked set ([`crate::codec::in_checked_set`]),
/// and every op of that set has an arm below. The first half is
/// `policy/attestation.rs`'s `attestation_check`'s to discharge — its step 1,
/// the one membership check, which this function does not repeat; the
/// second half is this function's own. Either broken — an op outside the
/// set, or the set widened without its arm — is never answered as a fault:
/// once the board term and the account are read it STOPS LOUDLY in every
/// build, because no refusal the check can give is true of a build whose two
/// tables disagree, and passing the write through would commit it with its
/// marker slot empty — the silent drop the checked set's card rules out. The
/// check runs before the transaction, under locks that do not poison, so
/// under [`crate::serve`] the stop is a `500 internal_panic` that commits
/// nothing.
pub(super) fn compose(
    world: &World,
    op: &Op,
    principal: PrincipalId,
) -> Result<EntryFrame, ComposeFault> {
    let board = board_term(world).ok_or(ComposeFault::NoBoardTerm)?;
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
        Op::MakeLink { home, from, to, ty } => {
            let (from, to, ty) = (Slot::of(from), Slot::of(to), Slot::of(ty));
            let slots = LinkSlots { from: from.as_entry(), to: to.as_entry(), ty: ty.as_entry() };
            (home.clone(), entry_body_make_link(slots))
        }
        Op::Publish { doc, shot } => {
            let trunk = trunk_of(doc);
            // No value the principal may not read is ever read here.
            if !every_run_origin_readable(world, &trunk, shot, principal) {
                return Err(ComposeFault::UnreadableRunOrigin);
            }
            (trunk, publish_body(world, shot)?)
        }
        _ => unreachable!(
            "compose's precondition: {:?} is outside the checked set, or the set was \
             widened without its entry-frame arm here",
            op.kind()
        ),
    };
    Ok(EntryFrame { board, account, doc, body })
}

/// Whether the principal may read every value `shot` places — each run's
/// ORIGIN DOCUMENT, the trunk of the document its start was minted under
/// (`document_of`, then `trunk_of`: the derivation M5's source gate asks
/// about, PUB-2.15), being `trunk`, the shot document's own I-space, which
/// the gate never consults, or one the read predicate admits at the
/// principal's class, which is what M10 lends the gate, on the premise
/// `policy/attestation.rs`'s `refused_at_or_before_the_source_gate` states.
/// A run whose start names no document counts as unreadable: the store
/// refuses it `bad_run`, and nothing is read to learn so.
fn every_run_origin_readable(
    world: &World,
    trunk: &Address,
    shot: &Shot,
    principal: PrincipalId,
) -> bool {
    let reader = world.reader_class(Some(principal));
    shot.runs.iter().all(|placed| {
        document_of(placed.run.i_start())
            .map(|d| trunk_of(&d))
            .is_some_and(|origin| origin == *trunk || reader.readable(&origin))
    })
}

/// A shot's body — its runs' values in run order, as [`entry_body_publish`]'s
/// value sequence — or why it cannot be built: an address M4 holds no value
/// at, or a body past [`MAX_SHOT_BODY_BYTES`], measured in the sequence's
/// own layout as each value is read. PRECONDITION: the principal may read
/// every value the shot places ([`every_run_origin_readable`]).
fn publish_body(world: &World, shot: &Shot) -> Result<EntryBody, ComposeFault> {
    let content = world.content();
    let mut values: Vec<&[u8]> = Vec::new();
    let mut body_len = VALUE_COUNT_BYTES;
    for placed in &shot.runs {
        for a in placed.run.addrs() {
            let v = content.value_at(a.tumbler()).ok_or(ComposeFault::MissingValue)?;
            body_len = body_len.saturating_add(VALUE_LENGTH_BYTES).saturating_add(v.len());
            if body_len > MAX_SHOT_BODY_BYTES {
                return Err(ComposeFault::OverBudget);
            }
            values.push(v.as_bytes());
        }
    }
    Ok(entry_body_publish(values))
}

/// An ENTRY frame composed but for its `alg` member — [`compose`]'s answer,
/// every other member as the value [`skep_identity::entry_frame`] spells: the
/// board term, the principal's account, the op's document, and the body with
/// its op's token.
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
    use skep_febe::OpKind;

    use super::*;
    use crate::codec::op_name;

    /// The budget is measured in the body's OWN layout: the two constants
    /// [`publish_body`] sums are the ones `entry_body_publish` lays out — a
    /// count, then a length and the bytes per value — so the shot refused
    /// past [`MAX_SHOT_BODY_BYTES`] is one whose built body would pass it,
    /// and the one admitted at it builds no more.
    #[test]
    fn the_budget_is_measured_in_the_value_sequence_s_own_layout() {
        assert_eq!(entry_body_publish(std::iter::empty()).as_bytes().len(), VALUE_COUNT_BYTES);
        let values: [&[u8]; 3] = [b"ab", b"c", b"defg"];
        assert_eq!(
            entry_body_publish(values).as_bytes().len(),
            VALUE_COUNT_BYTES + 3 * VALUE_LENGTH_BYTES + 2 + 1 + 4
        );
    }

    /// The frame's `op` member is the op-kind token AS THE WIRE SPELLS IT
    /// (the design record §2.5): each body `skep_identity` builds carries the
    /// codec's own name for its op, so a wire rename meets this test before it
    /// can move a signed preimage.
    #[test]
    fn each_body_carries_the_wire_name_of_its_op() {
        let empty = EntrySlot::Addrs(&[]);
        let slots = LinkSlots { from: empty, to: empty, ty: empty };
        assert_eq!(entry_body_insert(None, std::iter::empty()).op(), op_name(OpKind::Insert));
        assert_eq!(entry_body_make_link(slots).op(), op_name(OpKind::MakeLink));
        assert_eq!(entry_body_publish(std::iter::empty()).op(), op_name(OpKind::Publish));
    }

    /// COMPOSE'S PRECONDITION IS NEVER ANSWERED AS A FAULT: on a board whose
    /// `H.1` stands, for a principal with a prefix — the two terms read ahead
    /// of the op — an op outside the checked set STOPS LOUDLY. A fault here
    /// would be one the check passes through, committing the write with its
    /// marker slot empty — the silent drop the checked set's card rules out —
    /// and no refusal the check could give is true of a build whose two tables
    /// disagree.
    #[test]
    #[should_panic(expected = "compose's precondition")]
    fn an_op_outside_the_checked_set_stops_compose_loudly() {
        use skep_address::{Nat, Tumbler};
        use skep_arrangement::VPos;
        use skep_kernel::{CheckpointPolicy, Durability, KernelConfig, SaltSource};
        use skep_namespace::{head_document, BOOTSTRAP_PRINCIPAL};

        use crate::write_path::WritePath;

        let engine = skep_engine::Engine::open(KernelConfig {
            durability: Durability::InMemory,
            checkpoint: CheckpointPolicy::Manual,
            salt: SaltSource::Seeded(0),
        })
        .expect("in-memory genesis cannot fail");
        let dir = tempfile::tempdir().expect("tempdir");
        let writes = WritePath::open(dir.path(), &engine).expect("the change feed opens");
        // One commit, so the first head has a position to name; then `H.1`.
        let node = Tumbler::new([1u32, 9001].map(Nat::from)).expect("a two-component tumbler");
        engine.namespace().register_node(node).expect("a fresh node registers");
        assert!(writes.write_first_head(&writes.serial_lock()), "H.1 lands");
        let snap = engine.kernel().snapshot();
        let world = snap.world();
        assert!(board_term(world).is_some(), "the board term stands");
        let delete = Op::Delete {
            doc: head_document(),
            p: VPos::content(Nat::from(1u32)),
            width: Nat::from(1u32),
        };
        let _ = compose(world, &delete, BOOTSTRAP_PRINCIPAL);
    }
}
