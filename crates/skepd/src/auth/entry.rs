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
//!   investigation §3.3: the count is Σ width of the supplied runs).
//!
//! The one thing the daemon cannot compose is a body whose values it does
//! not hold: a `publish` run naming an address M4 has no value at. That
//! write cannot commit — the store's own existence walk refuses it
//! `dangling_source` — so the check passes it through UNATTESTED and lets
//! the store answer, which keeps the store's refusal ahead of a signature
//! verdict over bytes nobody could have signed.

use skep_address::{Address, Span};
use skep_arrangement::{trunk_of, Deposit};
use skep_content::HasContent;
use skep_febe::{Op, OpKind};
use skep_identity::{
    address_bytes, board_bytes, entry_body_insert, entry_body_link, entry_body_publish,
    entry_frame, EntrySlot,
};
use skep_links::SlotArg;
use skep_namespace::{HasM3, PrincipalId};

use crate::codec::op_name;
use crate::write_path::board_term;
use crate::World;

/// Why the daemon could not compose the entry frame for a write.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ComposeFault {
    /// The entry frame's `board` term (D13) has no value: the board has no
    /// `H.1`. Since s1 (RULED 2026-09-25) the claim writes `H.1` in its own
    /// step and the open writes it where a crash split the two, so on a
    /// claimed board this names a journal damaged below `H.1`, nothing a
    /// healthy board answers.
    NoBoardTerm,
    /// The principal has no account prefix — no `account` term.
    NoAccount,
    /// A `publish` run names an address the snapshot holds no value at; the
    /// store's `dangling_source` is the answer this write is owed.
    MissingValue,
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
            let content = world.content();
            let mut values: Vec<&[u8]> = Vec::new();
            for run in &shot.runs {
                for a in run.run.addrs() {
                    let v = content.value_at(a.tumbler()).ok_or(ComposeFault::MissingValue)?;
                    values.push(v.as_bytes());
                }
            }
            (address_bytes(&trunk_of(doc)), entry_body_publish(values))
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
