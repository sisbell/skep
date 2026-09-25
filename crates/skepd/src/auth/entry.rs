//! THE ENTRY FRAME AS THE DAEMON COMPOSES IT (signed ops; the seam
//! placement investigation §3.2): the verifier's side of
//! [`skep_identity::entry_frame`] — every member rebuilt from the op and the
//! locked snapshot the write's gates read, which under the serialization
//! guard IS the transaction's base. Nothing here is served or derived from
//! the daemon's own state beyond what the design record §2.5 names:
//!
//! * `alg` — the `attest.alg` token as the frame carried it;
//! * `board` — `H.1`'s committed pair (D13, RULED), read off the snapshot
//!   by [`crate::write_path::board_pair`];
//! * `account` — the act's principal's account in the board's local form,
//!   M3's `principal_prefix`;
//! * `doc` — per op cell: the TRUNK of the frame's `doc` for `insert` and
//!   `publish` (M5's one truncation, PUB-2.15), the `home` for `make_link`;
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

use skep_arrangement::trunk_of;
use skep_content::HasContent;
use skep_febe::Op;
use skep_identity::{
    address_bytes, board_bytes, entry_body_insert, entry_body_link, entry_body_publish,
    entry_frame, EntrySlot,
};
use skep_links::SlotArg;
use skep_namespace::{HasM3, PrincipalId};

use crate::codec::op_name;
use crate::write_path::board_pair;
use crate::World;

/// Why the daemon could not compose the frame for a write.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ComposeFault {
    /// The board has no `H.1`, so the `board` term D13 rules has no value on
    /// this board. Since s1 (RULED 2026-09-25) the claim writes `H.1` in its
    /// own step and the open writes it where a crash split the two, so on a
    /// claimed board this names a journal damaged below `H.1`, nothing a
    /// healthy board answers.
    NoBoard,
    /// The principal has no account prefix — no `account` term.
    NoAccount,
    /// A `publish` run names an address the snapshot holds no value at; the
    /// store's `dangling_source` is the answer this write is owed.
    MissingValue,
    /// The op is none of the three the slice attests.
    NotAttestable,
}

/// A link slot as the frame's slot row takes it — the resolve form's V-specs
/// re-paired as `(source, span)`.
enum Slot<'a> {
    Addrs(&'a [skep_address::Address]),
    Resolve(Vec<(skep_address::Address, skep_address::Span)>),
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

/// THE FRAME for `op` by `principal` on `world`, under the `alg` token the
/// attestation names — or why it cannot be composed.
pub(crate) fn compose(
    world: &World,
    op: &Op,
    principal: PrincipalId,
    alg: &str,
) -> Result<Vec<u8>, ComposeFault> {
    let (position, chain) = board_pair(world).ok_or(ComposeFault::NoBoard)?;
    let board = board_bytes(position, &chain);
    let account = world.m3().principal_prefix(principal).ok_or(ComposeFault::NoAccount)?;
    let account = address_bytes(account);
    let (doc, body) = match op {
        Op::Insert { doc, values, deposit, .. } => {
            let declared = match deposit {
                skep_arrangement::Deposit::Declared(ty) => Some(ty),
                skep_arrangement::Deposit::Undeclared => None,
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
        _ => return Err(ComposeFault::NotAttestable),
    };
    Ok(entry_frame(alg, &board, &account, &doc, op_name(op.kind()), &body))
}
