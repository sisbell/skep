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
//! (AUTH-1.12's framing: the tag, then each member as `be32(len) ‖ bytes`),
//! every member a compiled constant, a client-named address or a
//! client-composed byte string — no daemon-assigned fact (a minted address, a
//! position, a seq) enters it, which is what lets a client sign BEFORE the
//! commit with no round trip and the daemon verify AT the commit with no
//! lookup, and what makes the signature position-free.
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
//! * THE BOARD ROW — `board`, the BOARD TERM, `H.1`'s committed
//!   `(position, chain)` pair (D13, RULED): the position as eight big-endian
//!   bytes, then the chain's thirty-two raw bytes — forty bytes,
//!   [`board_bytes`].
//! * THE VALUE-SEQUENCE ROW — a run of content values in V-order WITH THEIR
//!   COUNT: `be64(count)` then, per value, `be32(len) ‖ bytes` —
//!   [`value_sequence`]. The count leads so a verifier holding a member that
//!   has GROWN past the signed prefix (the record §2.5's `publish` cell, D25)
//!   knows how many values the signature covers before reading one.
//! * THE SLOT ROW — a link slot in the form the client sent it: one form
//!   byte (`0x01` the address form, `0x02` the resolve form), `be64(n)`, then
//!   each element — an address as the address row, a V-spec as its source
//!   address, its span's start and its span's width, each length-delimited —
//!   [`slot_bytes`]. A `Resolve` slot's V-specs are the client's own; the
//!   endsets the transaction resolves them to are the transaction's and
//!   enter no frame.
//!
//! THE BODIES, per op of this slice — each an [`EntryBody`], the op's token
//! paired with its body, so a body is never framed under another op's token:
//!
//! * `insert` — [`entry_body_insert`]: the DECLARED TYPE ADDRESS (the address
//!   row, length-delimited; empty where the insert declares none) then the
//!   values placed as a value sequence.
//! * `make_link` — [`entry_body_link`]: the type slot, then the `from` slot,
//!   then the `to` slot, each a slot row.
//! * `publish` — [`entry_body_publish`]: THE RUNS THE CLIENT PLACED, their
//!   values in V-order as one value sequence — a PREFIX of the member the
//!   commit mints, never the member (the base's carried tail past
//!   `base_extent` and every later deposit into the head member fall outside
//!   it).
//!
//! Every length-delimited element is written by [`push_delimited`], the one
//! function [`framed`] delimits its own members with, so the composition is
//! injective at every level: two distinct inputs never spell one preimage.

use skep_address::{Address, Span};

use crate::framing::{framed, push_delimited, ENTRY_TAG};

/// THE ENTRY FRAME: `framed(ENTRY_TAG, [alg, board, account, doc, op, body])`
/// (AUTH-1.12's framing), EVERY member spelled here from the value the caller
/// holds, so a signer and a verifier holding the same values compose the same
/// bytes and no caller spells a member for itself:
///
/// * `alg` — the signing key's `ALGS` token, its ASCII bytes;
/// * `board` — the BOARD TERM, `H.1`'s committed `(position, chain)` pair
///   (D13): `be64(position) ‖ chain`, forty bytes;
/// * `account`, `doc` — each ADDRESS in its dotted-decimal spelling
///   (`1.0.1.0.1`), the one spelling of the address whatever string named it;
/// * `op`, `body` — the [`EntryBody`]'s token and bytes, which its builder
///   ([`entry_body_insert`], [`entry_body_link`], [`entry_body_publish`])
///   pairs.
pub fn entry_frame(
    alg: &str,
    board: (u64, [u8; 32]),
    account: &Address,
    doc: &Address,
    body: &EntryBody,
) -> Vec<u8> {
    let (position, chain) = board;
    framed(
        ENTRY_TAG,
        &[
            alg.as_bytes(),
            &board_bytes(position, &chain),
            &address_bytes(account),
            &address_bytes(doc),
            body.op.as_bytes(),
            &body.bytes,
        ],
    )
}

/// ONE publish-class entry's `op` and `body` members, held together because
/// they are one fact: each op's body has its own grammar, and the `op` token
/// names which. Built only by [`entry_body_insert`], [`entry_body_link`] and
/// [`entry_body_publish`], so a body cannot be framed under another op's
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

/// THE BOARD ROW: `be64(position) ‖ chain` — forty bytes.
fn board_bytes(position: u64, chain: &[u8; 32]) -> [u8; 40] {
    let mut out = [0u8; 40];
    out[..8].copy_from_slice(&position.to_be_bytes());
    out[8..].copy_from_slice(chain);
    out
}

/// THE ADDRESS ROW: the dotted-decimal ASCII of the address.
fn address_bytes(a: &Address) -> Vec<u8> {
    a.to_string().into_bytes()
}

/// THE VALUE-SEQUENCE ROW: `be64(count)` then each value length-delimited,
/// in the order given.
fn value_sequence<'a>(values: impl IntoIterator<Item = &'a [u8]>) -> Vec<u8> {
    let values: Vec<&[u8]> = values.into_iter().collect();
    let mut out = Vec::with_capacity(8 + values.iter().map(|v| 4 + v.len()).sum::<usize>());
    out.extend_from_slice(&(values.len() as u64).to_be_bytes());
    for v in values {
        push_delimited(&mut out, v);
    }
    out
}

/// A link slot as the client composed it — the two wire forms.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EntrySlot<'a> {
    /// `{"addrs": [...]}` — address names, deposited verbatim.
    Addrs(&'a [Address]),
    /// A V-spec array — `(source document, span)` per spec, resolved by the
    /// store against the transaction's base.
    Resolve(&'a [(Address, Span)]),
}

/// The slot row's form bytes.
const SLOT_FORM_ADDRS: u8 = 0x01;
const SLOT_FORM_RESOLVE: u8 = 0x02;

/// THE SLOT ROW: the form byte, `be64(n)`, then each element as the module
/// doc states it.
fn slot_bytes(slot: &EntrySlot<'_>) -> Vec<u8> {
    let mut out = Vec::new();
    match slot {
        EntrySlot::Addrs(addrs) => {
            out.push(SLOT_FORM_ADDRS);
            out.extend_from_slice(&(addrs.len() as u64).to_be_bytes());
            for a in *addrs {
                push_delimited(&mut out, &address_bytes(a));
            }
        }
        EntrySlot::Resolve(specs) => {
            out.push(SLOT_FORM_RESOLVE);
            out.extend_from_slice(&(specs.len() as u64).to_be_bytes());
            for (source, span) in *specs {
                push_delimited(&mut out, &address_bytes(source));
                push_delimited(&mut out, span.start().to_string().as_bytes());
                push_delimited(&mut out, span.width().to_string().as_bytes());
            }
        }
    }
    out
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
    out.extend_from_slice(&value_sequence(values));
    EntryBody { op: "insert", bytes: out }
}

/// THE `make_link` BODY, under the `make_link` token: the type slot, the
/// `from` slot, the `to` slot, each as its form byte (`0x01` the address
/// form, `0x02` the resolve form), `be64(n)`, then each element
/// length-delimited — an address in its dotted-decimal spelling, a V-spec as
/// its source address, its span's start and its span's width.
pub fn entry_body_link(ty: &EntrySlot<'_>, from: &EntrySlot<'_>, to: &EntrySlot<'_>) -> EntryBody {
    let mut out = slot_bytes(ty);
    out.extend_from_slice(&slot_bytes(from));
    out.extend_from_slice(&slot_bytes(to));
    EntryBody { op: "make_link", bytes: out }
}

/// THE `publish` BODY, under the `publish` token: the client's runs' values
/// in V-order, as one value sequence with their count — `be64(count)`, then
/// each value as `be32(len) ‖ bytes`.
pub fn entry_body_publish<'a>(values: impl IntoIterator<Item = &'a [u8]>) -> EntryBody {
    EntryBody { op: "publish", bytes: value_sequence(values) }
}

#[cfg(test)]
mod tests {
    use skep_address::{validate, Nat, Tumbler};

    use super::*;

    fn addr(comps: &[u32]) -> Address {
        validate(Tumbler::new(comps.iter().map(|&c| Nat::from(c))).unwrap()).unwrap()
    }

    /// The rows, byte for byte, at one small instance each — the pins a
    /// second implementation composes against — and the token each body
    /// carries into the frame's `op` member.
    #[test]
    fn the_rows_spell_as_the_module_doc_states() {
        assert_eq!(
            board_bytes(12, &[0xAB; 32])[..],
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
            slot_bytes(&EntrySlot::Addrs(std::slice::from_ref(&a))),
            [&[0x01u8, 0, 0, 0, 0, 0, 0, 0, 1][..], &[0, 0, 0, 15][..], b"1.0.1.0.1.0.1.1"].concat()
        );
        let span = Span::new(
            Tumbler::new([1u32, 1].map(Nat::from)).unwrap(),
            Tumbler::new([0u32, 2].map(Nat::from)).unwrap(),
        )
        .unwrap();
        assert_eq!(
            slot_bytes(&EntrySlot::Resolve(&[(addr(&[1, 0, 1, 0, 1]), span)])),
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
        let empty = EntrySlot::Addrs(&[]);
        assert_eq!(
            entry_body_link(&EntrySlot::Addrs(&[a]), &empty, &empty).as_bytes(),
            [
                &slot_bytes(&EntrySlot::Addrs(&[addr(&[1, 0, 1, 0, 1, 0, 1, 1])]))[..],
                &slot_bytes(&empty)[..],
                &slot_bytes(&empty)[..],
            ]
            .concat()
        );
        assert_eq!(
            [
                entry_body_insert(None, []).op(),
                entry_body_link(&empty, &empty, &empty).op(),
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
        let frame = entry_frame(
            "mldsa65-ed25519",
            (1, [0; 32]),
            &addr(&[1, 0, 1]),
            &addr(&[1, 0, 1, 0, 1]),
            &body,
        );
        let board = board_bytes(1, &[0; 32]);
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
