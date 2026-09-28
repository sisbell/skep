//! THE ENTRY FRAME (signed ops; the design record §2.5, §4.2 (C)'s ENTRY row)
//! — the bytes a publish-class entry's signature is made over — and THE BYTE
//! FORMS of its members (D24's interim pins, the seam build's own, 2026-09-25):
//! stated ONCE here, by encoding and not by member, so the signer (a client,
//! the test signer) and the verifier (the daemon's check, a mirror beside the
//! table) compose one preimage from one description. Values in, bytes out:
//! this crate reads no world and holds no key (AUTH-2.1); what it fixes is
//! how a value the caller already holds is spelled into the frame, and
//! [`entry_frame`] spells EVERY member itself, so no caller spells one.
//!
//! THE FRAME. `framed(ENTRY_TAG, [alg, board, account, doc, op, body])`
//! (AUTH-1.12's framing: the tag, then each member — a FIELD, in AUTH-1.12's
//! word — as `be32(len) ‖ bytes`), every member a compiled constant, a
//! client-named address, a client-composed byte string or the board's
//! [`BoardTerm`], fixed from the claim on — no fact the daemon assigns at the
//! entry's own commit (a minted address, a position, a seq) enters it, which
//! is what lets a client sign BEFORE the commit with no round trip and the
//! daemon verify AT the commit with no lookup, and what makes the signature
//! POSITION-FREE, in the design record's word: free of the entry's own LOG
//! position, so two identical writes sign identical bytes wherever in the
//! journal the commit lands them.
//!
//! THE ROWS, by encoding:
//!
//! * THE TOKEN ROW — `alg` (the `ALGS` token of the signing key) and `op`
//!   (the op-kind token as the wire spells it — `insert`, `make_link`,
//!   `publish` — which each body's [`EntryBody`] carries beside it): the
//!   token's ASCII bytes, bare.
//! * THE ADDRESS ROW — `account` (the act's principal's account in the
//!   board's local form), `doc` (the target or home document's bare address),
//!   and every address inside a body: the dotted-decimal ASCII rendering M1's
//!   `Display` gives a tumbler (`1.0.1.0.1`) — lossless by T3, and the ONE
//!   spelling of the address among the several a string can carry: a
//!   component written with a leading zero (`1.01.0.1`) names the same
//!   address (`1.1.0.1`). So the frame spells the ADDRESS and never a string
//!   — [`entry_frame`], the insert's declared type and the slots all take
//!   `Address` values — and a signer holding the address it named signs the
//!   bytes the verifier composes, whichever spelling carried it on the wire.
//! * THE BOARD ROW — `board`, the BOARD TERM ([`BoardTerm`]), `H.1`'s
//!   committed `(position, chain)` pair (D13, RULED) — its position a LOG
//!   position, never an element position: eight big-endian bytes, then the
//!   chain's thirty-two raw bytes — forty bytes, [`board_bytes`].
//! * THE VALUE-SEQUENCE ROW — content values in V-order WITH THEIR COUNT:
//!   `be64(count)` then, per value, `be32(len) ‖ bytes` —
//!   [`push_value_sequence`]. The count leads so a verifier holding a CHAIN
//!   member that has GROWN past the signed prefix (the record §2.5's `publish`
//!   cell, D25) knows how many of its values the signature covers before
//!   reading one.
//! * THE SLOT ROW — a link slot in the form the client sent it: one form
//!   byte (`0x01` the address form, `0x02` the resolve form), `be64(n)`, then
//!   each element — an address as the address row, a V-spec as its source
//!   address, its span's start and its span's width, each length-delimited —
//!   [`push_slot`]. A `Resolve` slot's V-specs are the client's own; the
//!   endsets the transaction resolves them to are the transaction's and
//!   enter no frame.
//!
//! THE BODIES, per op of this slice — each an [`EntryBody`], the op's token
//! paired with its body, so a body is never framed under another op's token:
//!
//! * `insert` — [`entry_body_insert`]: the DECLARED TYPE ADDRESS (the address
//!   row, length-delimited; empty where the insert declares none) then the
//!   values placed as a value sequence.
//! * `make_link` — [`entry_body_make_link`] over a [`LinkSlots`]: the type
//!   slot, then the `from` slot, then the `to` slot, each a slot row — the
//!   slots taken by name, so this order is spelled here and nowhere else.
//! * `publish` — [`entry_body_publish`]: THE RUNS THE CLIENT PLACED, their
//!   values in V-order as one value sequence — a PREFIX of the CHAIN member
//!   the commit mints, never the whole member (the base's carried tail past
//!   `base_extent` and every later deposit into the head member fall outside
//!   it).
//!
//! Every length-delimited element is written by [`push_delimited`], the one
//! function [`framed`] delimits its own fields with, and every row is written
//! the same way — onto the one buffer its body builds ([`push_value_sequence`],
//! [`push_slot`]), never built apart and copied in — so the composition is
//! injective at every level: two distinct inputs never spell one preimage.

use skep_address::{Address, Span};

use crate::framing::{framed, push_delimited, ENTRY_TAG};

/// THE ENTRY FRAME: `framed(ENTRY_TAG, [alg, board, account, doc, op, body])`
/// (AUTH-1.12's framing), EVERY member spelled here from the value the caller
/// holds, so a signer and a verifier holding the same values compose the same
/// bytes and no caller spells a member for itself:
///
/// * `alg` — the signing key's `ALGS` token, its ASCII bytes;
/// * `board` — the [`BoardTerm`] (D13): `be64(log_position) ‖ chain`, forty
///   bytes;
/// * `account`, `doc` — each ADDRESS in its dotted-decimal spelling
///   (`1.0.1.0.1`), the one spelling of the address whatever string named it;
/// * `op`, `body` — the [`EntryBody`]'s token and bytes, which its builder
///   ([`entry_body_insert`], [`entry_body_make_link`], [`entry_body_publish`])
///   pairs.
pub fn entry_frame(
    alg: &str,
    board: BoardTerm,
    account: &Address,
    doc: &Address,
    body: &EntryBody,
) -> Vec<u8> {
    framed(
        ENTRY_TAG,
        &[
            alg.as_bytes(),
            &board_bytes(&board),
            &address_bytes(account),
            &address_bytes(doc),
            body.op.as_bytes(),
            &body.bytes,
        ],
    )
}

/// THE BOARD TERM (signed ops; the design record §2.5, D13, RULED): the
/// committed `(position, chain)` pair `H.1` — the head document's first chain
/// member — NAMES, fixed from the claim on for the life of the board. It is
/// the ENTRY frame's `board` member ([`entry_frame`]), and the design
/// record's RECORD-grade frame names it too (§4.2 (C)) — one term, both
/// grades. It is NEVER the live pair `/health` serves, nor the pair any later
/// head names: a signature framed over either is refused
/// `attestation_invalid:signature`. A value: two terms are equal iff both
/// halves are.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct BoardTerm {
    /// The LOG position `H.1` names — a point in the journal, M2's `Seq` and
    /// the axis the wire serves as `/health`'s `log_position` — never an
    /// element position, which is what bare "position" means everywhere else
    /// in this crate ([`Values`](crate::Values)).
    pub log_position: u64,
    /// The whole-log chain value at that position, thirty-two raw bytes.
    pub chain: [u8; 32],
}

/// ONE publish-class entry's `op` and `body` members, held together because
/// they are one fact: each op's body has its own grammar, and the `op` token
/// names which. Built only by [`entry_body_insert`], [`entry_body_make_link`]
/// and [`entry_body_publish`], so a body cannot be framed under another op's
/// token. The tokens are the op-kind names as the wire spells them —
/// `insert`, `make_link`, `publish` — spelled HERE, beside the grammar each
/// selects, because they are members of a signed preimage that a reader
/// beside the table recomposes from this crate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EntryBody {
    op: &'static str,
    bytes: Vec<u8>,
}

impl EntryBody {
    /// The frame's `op` member: the op-kind token as the wire spells it.
    pub fn op(&self) -> &'static str {
        self.op
    }

    /// The frame's `body` member: the op's body in its grammar's bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

/// THE BOARD ROW: `be64(log_position) ‖ chain` — forty bytes.
fn board_bytes(board: &BoardTerm) -> [u8; 40] {
    let mut out = [0u8; 40];
    out[..8].copy_from_slice(&board.log_position.to_be_bytes());
    out[8..].copy_from_slice(&board.chain);
    out
}

/// THE ADDRESS ROW: the dotted-decimal ASCII of the address.
fn address_bytes(a: &Address) -> Vec<u8> {
    a.to_string().into_bytes()
}

/// THE VALUE-SEQUENCE ROW, onto `out`: `be64(count)` then each value
/// length-delimited, in the order given. The count LEADS but is known only
/// once the values are down, so its eight bytes are held and written back:
/// the values are walked once, as they come, and never collected.
fn push_value_sequence<'a>(out: &mut Vec<u8>, values: impl IntoIterator<Item = &'a [u8]>) {
    let at = out.len();
    out.extend_from_slice(&[0; 8]);
    let mut count: u64 = 0;
    for v in values {
        push_delimited(out, v);
        count += 1;
    }
    out[at..at + 8].copy_from_slice(&count.to_be_bytes());
}

/// A link slot as the client composed it — the two wire forms. `Copy`, as the
/// slices it borrows are: a view of the caller's slot, never an owner of it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntrySlot<'a> {
    /// `{"addrs": [...]}` — address names, deposited verbatim.
    Addrs(&'a [Address]),
    /// A V-spec array — `(source document, span)` per spec, resolved by the
    /// store against the transaction's base.
    Resolve(&'a [(Address, Span)]),
}

/// A `make_link`'s three link slots, BY NAME. They are three values of one
/// type, and the body lays them out in an order of its own — the TYPE slot
/// first (the design record §2.5) — while every other place the workspace
/// names a link's slots names them `from`, `to`, `ty`: M7's `Link::triple`
/// and `LinkWriter::makelink`, M10's `Op::MakeLink` and `SuccessorSpec`, this
/// crate's own [`LinkDeposit`](crate::LinkDeposit). Taken positionally, the
/// natural transcription of any of those would compile, frame the slots out
/// of order, and have every attested `make_link` its signer made refused
/// `attestation_invalid:signature`, with nothing naming the order. By field,
/// the call site says which slot is which, and the order is spelled once, in
/// [`entry_body_make_link`].
///
/// Not `#[non_exhaustive]`: every caller builds one, and a `make_link` body
/// has exactly these three slots — a fourth would be a new body grammar, not
/// a new field of this one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LinkSlots<'a> {
    /// The `from` slot.
    pub from: EntrySlot<'a>,
    /// The `to` slot.
    pub to: EntrySlot<'a>,
    /// The type slot.
    pub ty: EntrySlot<'a>,
}

/// The slot row's form bytes.
const SLOT_FORM_ADDRS: u8 = 0x01;
const SLOT_FORM_RESOLVE: u8 = 0x02;

/// THE SLOT ROW, onto `out`: the form byte, `be64(n)`, then each element as
/// the module doc states it.
fn push_slot(out: &mut Vec<u8>, slot: EntrySlot<'_>) {
    match slot {
        EntrySlot::Addrs(addrs) => {
            out.push(SLOT_FORM_ADDRS);
            out.extend_from_slice(&(addrs.len() as u64).to_be_bytes());
            for a in addrs {
                push_delimited(out, &address_bytes(a));
            }
        }
        EntrySlot::Resolve(specs) => {
            out.push(SLOT_FORM_RESOLVE);
            out.extend_from_slice(&(specs.len() as u64).to_be_bytes());
            for (source, span) in specs {
                push_delimited(out, &address_bytes(source));
                push_delimited(out, span.start().to_string().as_bytes());
                push_delimited(out, span.width().to_string().as_bytes());
            }
        }
    }
}

/// THE `insert` BODY, under the `insert` token: the declared type address in
/// its dotted-decimal spelling, length-delimited (empty where undeclared),
/// then the values placed as a value sequence — `be64(count)`, then each
/// value as `be32(len) ‖ bytes`.
pub fn entry_body_insert<'a>(
    declared_type: Option<&Address>,
    values: impl IntoIterator<Item = &'a [u8]>,
) -> EntryBody {
    let mut out = Vec::new();
    match declared_type {
        Some(ty) => push_delimited(&mut out, &address_bytes(ty)),
        None => push_delimited(&mut out, &[]),
    }
    push_value_sequence(&mut out, values);
    EntryBody { op: "insert", bytes: out }
}

/// THE `make_link` BODY, under the `make_link` token: the TYPE slot, then the
/// `from` slot, then the `to` slot — the body's order, whatever order the
/// caller names them in — each as its form byte (`0x01` the address form,
/// `0x02` the resolve form), `be64(n)`, then each element length-delimited —
/// an address in its dotted-decimal spelling, a V-spec as its source address,
/// its span's start and its span's width.
pub fn entry_body_make_link(slots: LinkSlots<'_>) -> EntryBody {
    let mut out = Vec::new();
    push_slot(&mut out, slots.ty);
    push_slot(&mut out, slots.from);
    push_slot(&mut out, slots.to);
    EntryBody { op: "make_link", bytes: out }
}

/// THE `publish` BODY, under the `publish` token: the client's runs' values
/// in V-order, as one value sequence with their count — `be64(count)`, then
/// each value as `be32(len) ‖ bytes`.
pub fn entry_body_publish<'a>(values: impl IntoIterator<Item = &'a [u8]>) -> EntryBody {
    let mut out = Vec::new();
    push_value_sequence(&mut out, values);
    EntryBody { op: "publish", bytes: out }
}

#[cfg(test)]
mod tests {
    use skep_address::{validate, Nat, Tumbler};

    use super::*;

    fn addr(comps: &[u32]) -> Address {
        validate(Tumbler::new(comps.iter().map(|&c| Nat::from(c))).unwrap()).unwrap()
    }

    /// The value-sequence row alone, as the pins below state it.
    fn value_sequence<'a>(values: impl IntoIterator<Item = &'a [u8]>) -> Vec<u8> {
        let mut out = Vec::new();
        push_value_sequence(&mut out, values);
        out
    }

    /// The slot row alone, as the pins below state it.
    fn slot_bytes(slot: EntrySlot<'_>) -> Vec<u8> {
        let mut out = Vec::new();
        push_slot(&mut out, slot);
        out
    }

    /// The rows, byte for byte, at one small instance each — the pins a
    /// second implementation composes against — and the token each body
    /// carries into the frame's `op` member. The two insert pins put the
    /// value sequence after a prefix, so a count written back anywhere but
    /// where its row began is caught.
    #[test]
    fn the_rows_spell_as_the_module_doc_states() {
        assert_eq!(
            board_bytes(&BoardTerm { log_position: 12, chain: [0xAB; 32] })[..],
            [&[0u8, 0, 0, 0, 0, 0, 0, 12][..], &[0xAB; 32][..]].concat()[..]
        );
        assert_eq!(address_bytes(&addr(&[1, 0, 1, 0, 1])), b"1.0.1.0.1");
        assert_eq!(
            value_sequence([&b"ab"[..], &b""[..], &b"c"[..]]),
            [
                &[0u8, 0, 0, 0, 0, 0, 0, 3][..],
                &[0, 0, 0, 2, b'a', b'b'][..],
                &[0, 0, 0, 0][..],
                &[0, 0, 0, 1, b'c'][..],
            ]
            .concat()
        );
        let a = addr(&[1, 0, 1, 0, 1, 0, 1, 1]);
        assert_eq!(
            slot_bytes(EntrySlot::Addrs(std::slice::from_ref(&a))),
            [&[0x01u8, 0, 0, 0, 0, 0, 0, 0, 1][..], &[0, 0, 0, 15][..], b"1.0.1.0.1.0.1.1"].concat()
        );
        let span = Span::new(
            Tumbler::new([1u32, 1].map(Nat::from)).unwrap(),
            Tumbler::new([0u32, 2].map(Nat::from)).unwrap(),
        )
        .unwrap();
        assert_eq!(
            slot_bytes(EntrySlot::Resolve(&[(addr(&[1, 0, 1, 0, 1]), span)])),
            [
                &[0x02u8, 0, 0, 0, 0, 0, 0, 0, 1][..],
                &[0, 0, 0, 9][..],
                b"1.0.1.0.1",
                &[0, 0, 0, 3][..],
                b"1.1",
                &[0, 0, 0, 3][..],
                b"0.2",
            ]
            .concat()
        );
        assert_eq!(
            entry_body_insert(None, [&b"x"[..]]).as_bytes(),
            [&[0u8, 0, 0, 0][..], &value_sequence([&b"x"[..]])[..]].concat()
        );
        assert_eq!(
            entry_body_insert(Some(&addr(&[1, 1, 0, 1, 0, 1, 0, 3, 1])), []).as_bytes(),
            [&[0u8, 0, 0, 17][..], b"1.1.0.1.0.1.0.3.1", &[0u8; 8][..]].concat()
        );
        assert_eq!(entry_body_publish([&b"q"[..]]).as_bytes(), value_sequence([&b"q"[..]]));
        // Three DISTINCT slots, named in the workspace's `from, to, ty` order:
        // the body lays out the type slot first whatever order they are named
        // in, and a builder that wrote them in any other order spells other
        // bytes here.
        let (ty, from) = ([a], [addr(&[1, 0, 1])]);
        let empty = EntrySlot::Addrs(&[]);
        let slots =
            LinkSlots { from: EntrySlot::Addrs(&from), to: empty, ty: EntrySlot::Addrs(&ty) };
        assert_eq!(
            entry_body_make_link(slots).as_bytes(),
            [slot_bytes(slots.ty), slot_bytes(slots.from), slot_bytes(slots.to)].concat(),
            "the type slot, then from, then to"
        );
        assert_eq!(
            [
                entry_body_insert(None, []).op(),
                entry_body_make_link(LinkSlots { from: empty, to: empty, ty: empty }).op(),
                entry_body_publish([]).op(),
            ],
            ["insert", "make_link", "publish"],
            "each body carries its own op's token"
        );
    }

    /// The frame is `framed(ENTRY_TAG, …)` over the six members in order and
    /// nothing else: the tag, then each member length-delimited — the board
    /// term as the board row, the two addresses as the address row, the op
    /// and body the [`EntryBody`]'s own.
    #[test]
    fn the_frame_is_framed_under_the_entry_tag_over_six_members() {
        let body = EntryBody { op: "insert", bytes: b"B".to_vec() };
        let term = BoardTerm { log_position: 1, chain: [0; 32] };
        let frame = entry_frame(
            "mldsa65-ed25519",
            term,
            &addr(&[1, 0, 1]),
            &addr(&[1, 0, 1, 0, 1]),
            &body,
        );
        let board = board_bytes(&term);
        let mut expected = b"skep-entry-v1".to_vec();
        for m in [
            &b"mldsa65-ed25519"[..],
            &board[..],
            b"1.0.1",
            b"1.0.1.0.1",
            b"insert",
            b"B",
        ] {
            expected.extend_from_slice(&(m.len() as u32).to_be_bytes());
            expected.extend_from_slice(m);
        }
        assert_eq!(frame, expected);
    }
}
