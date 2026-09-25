//! THE ENTRY FRAME (signed ops; the design record §2.5, §4.2 (C)'s ENTRY row)
//! — the bytes a publish-class entry's signature is made over — and THE BYTE
//! FORMS of its members (D24's interim pins, the seam build's own, 2026-09-25):
//! stated ONCE here, by encoding and not by member, so the signer (a client,
//! the test signer) and the verifier (the daemon's check, a mirror beside the
//! table) compose one preimage from one description. Bytes in, bytes out:
//! this crate reads no world and holds no key (AUTH-2.1); what it fixes is
//! how a value the caller already holds is spelled into the frame.
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
//!   (the op-kind token as the wire spells it: `insert`, `make_link`,
//!   `publish`): the token's ASCII bytes, bare.
//! * THE ADDRESS ROW — `account` (the act's principal's account in the
//!   board's local form), `doc` (the target or home document's bare address),
//!   and every address inside a body: the dotted-decimal ASCII rendering M1's
//!   `Display` gives a tumbler (`1.0.1.0.1`) — lossless by T3, and the
//!   spelling the wire already carries, so a client signs the string it sent.
//! * THE BOARD ROW — `board`, `H.1`'s committed pair (D13, RULED): the
//!   position as eight big-endian bytes, then the chain's thirty-two raw
//!   bytes — forty bytes, [`board_bytes`].
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
//! THE BODIES, per op of this slice:
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
//! Every length-delimited element is framed the way [`framed`] frames a
//! member, so the composition is injective at every level: two distinct
//! inputs never spell one preimage.

use skep_address::{Address, Span};

use crate::framing::{framed, ENTRY_TAG};

/// The whole ENTRY frame over members already in their byte forms:
/// `framed(ENTRY_TAG, [alg, board, account, doc, op, body])`.
pub fn entry_frame(
    alg: &str,
    board: &[u8],
    account: &[u8],
    doc: &[u8],
    op: &str,
    body: &[u8],
) -> Vec<u8> {
    framed(ENTRY_TAG, &[alg.as_bytes(), board, account, doc, op.as_bytes(), body])
}

/// THE BOARD ROW: `be64(position) ‖ chain` — forty bytes.
pub fn board_bytes(position: u64, chain: &[u8; 32]) -> [u8; 40] {
    let mut out = [0u8; 40];
    out[..8].copy_from_slice(&position.to_be_bytes());
    out[8..].copy_from_slice(chain);
    out
}

/// THE ADDRESS ROW: the dotted-decimal ASCII of the address.
pub fn address_bytes(a: &Address) -> Vec<u8> {
    a.to_string().into_bytes()
}

/// One length-delimited element — `be32(len) ‖ bytes`, [`framed`]'s own
/// member rule at the element level. PRECONDITION as `framed`'s: the element
/// is shorter than 2^32 bytes.
fn push_delimited(out: &mut Vec<u8>, bytes: &[u8]) {
    let len = u32::try_from(bytes.len()).expect("entry frame element length exceeds be32");
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(bytes);
}

/// THE VALUE-SEQUENCE ROW: `be64(count)` then each value length-delimited,
/// in the order given.
pub fn value_sequence<'a>(values: impl IntoIterator<Item = &'a [u8]>) -> Vec<u8> {
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
pub fn slot_bytes(slot: &EntrySlot<'_>) -> Vec<u8> {
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

/// THE `insert` BODY: the declared type address, length-delimited (empty
/// where undeclared), then the values placed as a value sequence.
pub fn entry_body_insert<'a>(
    declared_type: Option<&Address>,
    values: impl IntoIterator<Item = &'a [u8]>,
) -> Vec<u8> {
    let mut out = Vec::new();
    match declared_type {
        Some(ty) => push_delimited(&mut out, &address_bytes(ty)),
        None => push_delimited(&mut out, &[]),
    }
    out.extend_from_slice(&value_sequence(values));
    out
}

/// THE `make_link` BODY: the type slot, the `from` slot, the `to` slot.
pub fn entry_body_link(ty: &EntrySlot<'_>, from: &EntrySlot<'_>, to: &EntrySlot<'_>) -> Vec<u8> {
    let mut out = slot_bytes(ty);
    out.extend_from_slice(&slot_bytes(from));
    out.extend_from_slice(&slot_bytes(to));
    out
}

/// THE `publish` BODY: the client's runs' values in V-order, as one value
/// sequence with their count.
pub fn entry_body_publish<'a>(values: impl IntoIterator<Item = &'a [u8]>) -> Vec<u8> {
    value_sequence(values)
}

#[cfg(test)]
mod tests {
    use skep_address::{validate, Nat, Tumbler};

    use super::*;

    fn addr(comps: &[u32]) -> Address {
        validate(Tumbler::new(comps.iter().map(|&c| Nat::from(c))).unwrap()).unwrap()
    }

    /// The rows, byte for byte, at one small instance each — the pins a
    /// second implementation composes against.
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
            entry_body_insert(None, [&b"x"[..]]),
            [&[0u8, 0, 0, 0][..], &value_sequence([&b"x"[..]])[..]].concat()
        );
        assert_eq!(
            entry_body_insert(Some(&addr(&[1, 1, 0, 1, 0, 1, 0, 3, 1])), []),
            [&[0u8, 0, 0, 17][..], b"1.1.0.1.0.1.0.3.1", &[0u8; 8][..]].concat()
        );
        assert_eq!(entry_body_publish([&b"q"[..]]), value_sequence([&b"q"[..]]));
        let empty = EntrySlot::Addrs(&[]);
        assert_eq!(
            entry_body_link(&EntrySlot::Addrs(&[a]), &empty, &empty),
            [
                &slot_bytes(&EntrySlot::Addrs(&[addr(&[1, 0, 1, 0, 1, 0, 1, 1])]))[..],
                &slot_bytes(&empty)[..],
                &slot_bytes(&empty)[..],
            ]
            .concat()
        );
    }

    /// The frame is `framed(ENTRY_TAG, …)` over the six members in order and
    /// nothing else: the tag, then each member length-delimited.
    #[test]
    fn the_frame_is_framed_under_the_entry_tag_over_six_members() {
        let board = board_bytes(1, &[0; 32]);
        let frame = entry_frame("mldsa65-ed25519", &board, b"1.0.1", b"1.0.1.0.1", "insert", b"B");
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
