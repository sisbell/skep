//! THE ENTRY FRAME AS THE DAEMON COMPOSES IT (signed ops; the seam
//! placement investigation §3.2): the verifier's side of
//! [`skep_identity::entry_frame`] — every member rebuilt from the op and the
//! locked snapshot the write's gates read, which under the serialization
//! guard IS the transaction's base. Nothing here is served or derived from
//! the daemon's own state beyond what the design record §2.5 names:
//!
//! * `alg` — the `attest.alg` token as the request carried it — the one
//!   member the snapshot does not supply, so it is applied last
//!   ([`EntryFrame::bytes`]);
//! * `board` — the BOARD TERM, `H.1`'s committed pair (D13, RULED), read off
//!   the snapshot by [`crate::write_path::board_term`];
//! * `account` — the act's principal's account in the board's local form,
//!   M3's `principal_prefix`;
//! * `doc` — per op cell: the TRUNK of the op's `doc` for `insert` and
//!   `publish` (M5's one truncation, PUB-2.15), the op's `home` for
//!   `make_link`;
//! * `op` — the op-kind token as the wire spells it;
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
//!   (PUB-8.4). The STORE's own gates judge such a shot, asked on a detached
//!   kernel ([`refused_at_or_before_the_source_gate`]): a shot they refuse
//!   passes through UNATTESTED for their own answer. A shot they admit — the
//!   base CARRYING every such run (PUB-6.24), as a cross-owner `version` of a
//!   published member hands a principal runs whose origin it never could
//!   read — places a value no signature of its author's can attest, and is
//!   refused `attestation_invalid:withheld` without a byte of it read.
//! * a body past [`MAX_SHOT_BODY_BYTES`], refused
//!   `attestation_invalid:frame_too_large` before it is built.

use skep_address::{document_of, Address, Nat, Span};
use skep_arrangement::{trunk_of, Caller, Deposit, PublishError, Run, Shot, ShotRun, Vstream};
use skep_content::HasContent;
use skep_febe::{Op, OpKind};
use skep_identity::{
    address_bytes, board_bytes, entry_body_insert, entry_body_link, entry_body_publish,
    entry_frame, EntrySlot,
};
use skep_kernel::TxnError;
use skep_links::SlotArg;
use skep_namespace::{HasM3, PrincipalId};

use crate::codec::op_name;
use crate::history::detached_kernel;
use crate::write_path::board_term;
use crate::World;

/// The most bytes a `publish`'s entry-frame BODY may reach — PARITY with the
/// request-body cap, [`crate::server::MAX_REQUEST_BODY`]. The other two ops
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
pub(crate) const MAX_SHOT_BODY_BYTES: usize = crate::server::MAX_REQUEST_BODY;

/// The value sequence's leading be64 count.
const VALUE_COUNT_BYTES: usize = 8;

/// The be32 length each value of the sequence is delimited by.
const VALUE_LENGTH_BYTES: usize = 4;

/// Why the daemon could not compose the entry frame for a write.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ComposeFault {
    /// The entry frame's `board` term (D13) has no value: the board has no
    /// `H.1`. Since s1 (RULED 2026-09-25) the claim writes `H.1` in its own
    /// step and the open writes it where a crash split the two, so on a
    /// claimed board this names one of the two states [`board_term`] states:
    /// a first head the head writer's driver refused (surfaced on the operator
    /// stream, and written by the next head or the next open), or a journal
    /// damaged below `H.1`.
    NoBoardTerm,
    /// The principal has no account prefix — no `account` term.
    NoAccount,
    /// A `publish` run names an address the snapshot holds no value at; the
    /// store's `dangling_source` is the answer this write is owed.
    MissingValue,
    /// A `publish` run names an origin document the principal may not read,
    /// and the STORE refuses the shot at or before its source gate — the run
    /// `withheld` there, or the shot refused ahead of it (M5 `publish`'s
    /// slots 1–6, PUB-6.36). That refusal reads no value, and it is the
    /// answer this write is owed.
    StoreRefuses,
    /// A `publish` run names an origin document the principal may not read,
    /// and the store's source gate would admit the shot all the same: the
    /// base CARRIES every such run (PUB-6.24). The entry frame would carry a
    /// value withheld from its own author, which no signature of theirs can
    /// attest and which the check does not read for them.
    CarriedUnreadable,
    /// A `publish`'s body would pass [`MAX_SHOT_BODY_BYTES`].
    OverBudget,
    /// The op kind is outside the checked set [`in_checked_set`] states.
    OutsideCheckedSet,
}

/// THE CHECKED SET — the op kinds the write-path check reaches, and so the
/// ops an ENTRY frame is composed for: `insert`, `make_link`, `publish` (the
/// owner's term, m2, the design record's round 5 rulings 2026-09-26; the
/// seam build's three — the record's thirteen publish-class-capable inputs
/// are the WIDENING lane's). The ONE statement of it: the codec admits a
/// request's `attest` member exactly on these, the check demands and
/// verifies one exactly on these, and [`compose`] has an arm exactly for
/// these. The acting hand ATTESTS; the check admits or refuses, and signs
/// nothing. The three must agree in both directions — a member the codec
/// admits and the check never demands is a signature parsed and silently
/// DROPPED, the commit landing with its marker slot empty; one the check
/// demands and the codec refuses is a write no signed session can make on a
/// claimed board — so a widening is one edit here and one arm in
/// [`compose`], whose wildcard asserts it.
pub(crate) fn in_checked_set(kind: OpKind) -> bool {
    matches!(kind, OpKind::Insert | OpKind::MakeLink | OpKind::Publish)
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
/// last ([`EntryFrame::bytes`]), so the check learns whether an entry frame
/// CAN be composed before it asks for the member, and names no token for a
/// write that presents none.
pub(crate) fn compose(
    world: &World,
    op: &Op,
    principal: PrincipalId,
) -> Result<EntryFrame, ComposeFault> {
    let (position, chain) = board_term(world).ok_or(ComposeFault::NoBoardTerm)?;
    let board = board_bytes(position, &chain);
    let account = world.m3().principal_prefix(principal).ok_or(ComposeFault::NoAccount)?;
    let account = address_bytes(account);
    let (doc, body) = match op {
        Op::Insert { doc, values, deposit, .. } => {
            let declared = match deposit {
                Deposit::Declared(ty) => Some(ty),
                Deposit::Undeclared => None,
            };
            let values = values.iter().map(|v| v.as_bytes());
            (address_bytes(&trunk_of(doc)), entry_body_insert(declared, values))
        }
        Op::MakeLink { home, from, to, ty } => {
            let (ty, from, to) = (Slot::of(ty), Slot::of(from), Slot::of(to));
            (address_bytes(home), entry_body_link(&ty.as_entry(), &from.as_entry(), &to.as_entry()))
        }
        Op::Publish { doc, shot } => {
            let trunk = trunk_of(doc);
            // No value the principal may not read is ever read here: such a
            // shot is the store's gates' to judge, before any value is.
            if !every_origin_readable(world, &trunk, shot, principal) {
                return Err(
                    if refused_at_or_before_the_source_gate(world, doc, &trunk, shot, principal) {
                        ComposeFault::StoreRefuses
                    } else {
                        ComposeFault::CarriedUnreadable
                    },
                );
            }
            (address_bytes(&trunk), publish_body(world, shot)?)
        }
        _ => {
            // An op kind added to the checked set with no arm here would have
            // its `attest` dropped unverified — the silent direction — so the
            // premise is made loud.
            debug_assert!(
                !in_checked_set(op.kind()),
                "an op kind in the checked set with no entry frame: {:?}",
                op.kind()
            );
            return Err(ComposeFault::OutsideCheckedSet);
        }
    };
    Ok(EntryFrame { board, account, doc, op: op_name(op.kind()), body })
}

/// Whether the principal may read every value `shot` places — each run's
/// ORIGIN DOCUMENT, the trunk of the document its start was minted under
/// (`document_of`, then `trunk_of`: the derivation M5's source gate asks
/// about, PUB-2.15), being `trunk`, the shot document's own I-space, which
/// the gate never consults, or one the read predicate admits at the
/// principal's class, which is what M10 lends the gate, on the premise
/// [`refused_at_or_before_the_source_gate`] states. A run whose start names
/// no document counts as unreadable: the store refuses it `bad_run`, and the
/// check reads nothing to learn so.
fn every_origin_readable(
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

/// Whether the STORE refuses `shot` at or before its source gate (M5
/// `publish`'s slots 1–6, PUB-6.36) — asked of the store ITSELF, on a
/// detached kernel over this snapshot ([`detached_kernel`]), so the base's
/// chain and shape, the carried-run test (PUB-6.24) and the gate's own skips
/// are M5's answers and never a second statement of them here. Under the
/// serialization guard this snapshot IS the base the real transaction opens
/// on, and the predicate handed the gate — [`World::visible_to`] at the
/// principal — answers what M10 lends it on the real write: M10's
/// `visible_to` asks its front door's `readable`, which is `World::readable`
/// at the principal wherever that door carries NO read consult, and the
/// daemon's live door carries none (`Daemon::open_under` builds it so). That
/// premise is this dry run's to rely on and the open's to keep: a consult on
/// the live door would make the two gates two predicates, and one MORE
/// lenient than `World::readable` would pass through UNATTESTED a shot the
/// real store then admits. So a refusal here is the refusal the real shot
/// meets.
///
/// The dry shot is `shot` behind one SENTINEL run: the shot document's next
/// content address, which M3's mint only PEEKS (it moves nothing) and which
/// therefore holds no value. The sentinel passes every check ahead of the
/// source gate — its origin is the document's own trunk, registered, stated
/// as itself — and the gate skips it as the document's own I-space, so the
/// store's answer through the source gate is the real shot's own. Then the
/// existence walk, which asks the runs in order, stops at the sentinel's one
/// address: the dry run never pays for the real runs' Σ width or the
/// placement.
///
/// `false` wherever a refusal at or before the source gate cannot be shown:
/// a dry run that gets past it — every run the principal may not read then
/// CARRIED by the base — and any answer this does not recognize. The caller
/// REFUSES the write on `false`, which is safe whether or not the store
/// would have; it passes the shot through UNATTESTED on `true` alone, which
/// is safe because the real shot is then refused with the same answer. The
/// match over M5's refusals is exhaustive so that a new one is placed on
/// one side of the gate or the other before this compiles.
fn refused_at_or_before_the_source_gate(
    world: &World,
    doc: &Address,
    trunk: &Address,
    shot: &Shot,
    principal: PrincipalId,
) -> bool {
    let sentinel = world
        .m3()
        .mint_content(trunk)
        .ok()
        .and_then(|(next, _)| Run::new(next, Nat::from(1u32)).ok());
    let Some(sentinel) = sentinel else {
        return false;
    };
    let mut runs = Vec::with_capacity(shot.runs.len() + 1);
    runs.push(ShotRun { origin: trunk.clone(), run: sentinel });
    runs.extend(shot.runs.iter().cloned());
    let dry = Shot { base: shot.base.clone(), draft: shot.draft.clone(), runs };
    let kernel = detached_kernel(world.clone());
    let caller = Caller::Principal(principal);
    let visibility = World::visible_to(caller);
    match Vstream::new(&kernel).publish(caller, doc, dry, &visibility) {
        Err(TxnError::Rejected(refusal)) => match refusal {
            // At or before the source gate: the real shot — the same runs,
            // without the sentinel every one of these checks passes — is
            // refused with the same answer.
            PublishError::DocNotRegistered
            | PublishError::NotOwner(_)
            | PublishError::SourceNotRegistered
            | PublishError::BadRun
            | PublishError::PrivateSourceVersionless
            | PublishError::BaseNotInChain
            | PublishError::BaseSuperseded
            | PublishError::BaseExtentTooLarge
            | PublishError::Withheld(_) => true,
            // Past the source gate: every run it asks about was admitted.
            PublishError::TooManyValues
            | PublishError::DanglingSource
            | PublishError::TooManyRuns
            | PublishError::Mint(_)
            | PublishError::Content(_) => false,
        },
        Ok(_) | Err(_) => false,
    }
}

/// A shot's body — its runs' values in run order, as [`entry_body_publish`]'s
/// value sequence — or why it cannot be built: an address M4 holds no value
/// at, or a body past [`MAX_SHOT_BODY_BYTES`], measured in the sequence's
/// own layout as each value is read. PRECONDITION: the principal may read
/// every value the shot places ([`every_origin_readable`]).
fn publish_body(world: &World, shot: &Shot) -> Result<Vec<u8>, ComposeFault> {
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
/// every other member in its byte form.
pub(crate) struct EntryFrame {
    board: [u8; 40],
    account: Vec<u8>,
    doc: Vec<u8>,
    op: &'static str,
    body: Vec<u8>,
}

impl EntryFrame {
    /// The entry frame's bytes under `alg`, the token the presented
    /// attestation's MARKER tag names — [`skep_identity::entry_frame`]'s
    /// layout, `framed(ENTRY_TAG, [alg, board, account, doc, op, body])`,
    /// `ENTRY_TAG` its framing tag.
    pub(crate) fn bytes(&self, alg: &str) -> Vec<u8> {
        entry_frame(alg, &self.board, &self.account, &self.doc, self.op, &self.body)
    }
}

#[cfg(test)]
mod tests {
    use skep_arrangement::Base;
    use skep_engine::Engine;
    use skep_kernel::{CheckpointPolicy, Durability, KernelConfig, SaltSource};
    use skep_namespace::{ghost_home_doc, head_document, SYSTEM_PRINCIPAL};

    use super::*;

    /// The budget is measured in the body's OWN layout: the two constants
    /// [`publish_body`] sums are the ones `entry_body_publish` lays out — a
    /// count, then a length and the bytes per value — so the shot refused
    /// past [`MAX_SHOT_BODY_BYTES`] is one whose built body would pass it,
    /// and the one admitted at it builds no more.
    #[test]
    fn the_budget_is_measured_in_the_value_sequence_s_own_layout() {
        assert_eq!(entry_body_publish(std::iter::empty()).len(), VALUE_COUNT_BYTES);
        let values: [&[u8]; 3] = [b"ab", b"c", b"defg"];
        assert_eq!(
            entry_body_publish(values).len(),
            VALUE_COUNT_BYTES + 3 * VALUE_LENGTH_BYTES + 2 + 1 + 4
        );
    }

    /// The dry run asks the STORE, and its SENTINEL is invisible to every
    /// check ahead of the source gate — the premise that makes a pass-through
    /// safe, since a sentinel some earlier check refused would make every
    /// dry run a refusal and pass through shots the store then admits. Over
    /// genesis, the system principal's shot into the head document `H`
    /// (published, memberless, its own): with no base the dry run gets past
    /// the gate — the sentinel alone answering the existence walk, so `false`
    /// — and with a base outside `H`'s chain the store refuses
    /// `base_not_in_chain` ahead of the gate, so `true`.
    #[test]
    fn the_dry_run_answers_the_store_s_own_gates_and_its_sentinel_passes_them() {
        let engine = Engine::open(KernelConfig {
            durability: Durability::InMemory,
            checkpoint: CheckpointPolicy::Manual,
            salt: SaltSource::Seeded(0),
        })
        .expect("in-memory genesis cannot fail");
        let snap = engine.kernel().snapshot();
        let world = snap.world();
        let h = head_document();
        let empty = Shot { base: None, draft: None, runs: Vec::new() };
        assert!(
            !refused_at_or_before_the_source_gate(world, &h, &h, &empty, SYSTEM_PRINCIPAL),
            "a shot the store admits through its gate is not refused there"
        );
        let foreign_base = Shot {
            base: Some(Base { member: ghost_home_doc(), extent: Nat::from(0u32) }),
            ..empty
        };
        assert!(
            refused_at_or_before_the_source_gate(world, &h, &h, &foreign_base, SYSTEM_PRINCIPAL),
            "a base outside the document's chain is refused ahead of the gate"
        );
        assert_eq!(
            engine.kernel().current_seq(),
            snap.seq(),
            "a dry run commits nothing to the live kernel"
        );
    }
}
