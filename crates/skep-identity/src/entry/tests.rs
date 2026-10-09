use core::num::NonZeroU64;

use skep_address::{validate, Nat, Tumbler};

use super::*;

fn addr(comps: &[u32]) -> Address {
    validate(Tumbler::new(comps.iter().map(|&c| Nat::from(c))).unwrap()).unwrap()
}

/// The value-sequence row alone, as the pins below state it.
fn value_sequence_bytes<'a>(values: impl IntoIterator<Item = &'a [u8]>) -> Vec<u8> {
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

/// The address-list row alone, as the pins below state it.
fn address_list_bytes(addrs: &[Address]) -> Vec<u8> {
    let mut out = Vec::new();
    push_address_list(&mut out, addrs);
    out
}

/// The optional-address row alone, as the pins below state it.
fn optional_address_bytes(named: Option<&Address>) -> Vec<u8> {
    let mut out = Vec::new();
    push_optional_address(&mut out, named);
    out
}

/// A span from its two tumblers' components, as a pin spells one.
fn span(start: &[u32], width: &[u32]) -> Span {
    Span::new(
        Tumbler::new(start.iter().map(|&c| Nat::from(c))).unwrap(),
        Tumbler::new(width.iter().map(|&c| Nat::from(c))).unwrap(),
    )
    .unwrap()
}

/// The window row alone, as the pins below state it.
fn window_bytes(start: &Address, width: u64) -> Vec<u8> {
    let mut out = Vec::new();
    push_window(&mut out, &address_bytes(start), width);
    out
}

/// A window's width as a pin spells it — at least one, as every run's is.
fn nonzero(width: u64) -> NonZeroU64 {
    NonZeroU64::new(width).expect("a pinned window's width is at least one")
}

/// A link write's four rows as the pins compose them: the type slot, then
/// `from`, then `to`, each the slot row its own pin spells, then the
/// `replaces` row's EMPTY group.
fn four_rows(slots: LinkSlots<EntrySlot<'_>>) -> Vec<u8> {
    [
        slot_bytes(slots.ty),
        slot_bytes(slots.from),
        slot_bytes(slots.to),
        optional_address_bytes(None),
    ]
    .concat()
}

/// The `replaces` member the pins name.
fn revocation() -> Address {
    addr(&[1, 0, 1, 0, 1, 0, 2, 9])
}

/// [`revocation`]'s optional-address row as the pins spell it — group length
/// 28: the form byte, `be64(1)`, then `be32(15)` and the fifteen bytes of the
/// address's spelling.
fn replaces_group() -> Vec<u8> {
    [
        &[0u8, 0, 0, 28][..],
        &[0x01, 0, 0, 0, 0, 0, 0, 0, 1][..],
        &[0, 0, 0, 15][..],
        b"1.0.1.0.1.0.2.9",
    ]
    .concat()
}

/// The base group over the member `1.0.1.0.1.2` at `extent`, as the pins
/// spell it: its length, 32, then the member as an address-list row of one
/// element and `be64(extent)`.
fn base_group(extent: u64) -> Vec<u8> {
    [
        &[0u8, 0, 0, 32][..],
        &[0x01, 0, 0, 0, 0, 0, 0, 0, 1][..],
        &[0, 0, 0, 11][..],
        b"1.0.1.0.1.2",
        &extent.to_be_bytes()[..],
    ]
    .concat()
}

// THE ROWS AND THE BODIES, byte for byte, at one small instance each — the
// pins a second implementation composes against — one promise to a test, so
// a failure names the row or the body whose spelling moved.

/// THE BOARD ROW: `be64(log_position) ‖ chain`, forty bytes.
#[test]
fn the_board_row_is_the_log_position_then_the_chain() {
    assert_eq!(
        board_bytes(&BoardTerm { log_position: 12, chain: [0xAB; 32] })[..],
        [&[0u8, 0, 0, 0, 0, 0, 0, 12][..], &[0xAB; 32][..]].concat()[..]
    );
}

/// THE ADDRESS ROW: the address's dotted-decimal ASCII.
#[test]
fn the_address_row_is_the_dotted_decimal_spelling() {
    assert_eq!(address_bytes(&addr(&[1, 0, 1, 0, 1])), b"1.0.1.0.1");
}

/// THE VALUE-SEQUENCE ROW: `be64(count)`, then each value delimited, in the
/// order given — an empty value its length prefix alone.
#[test]
fn the_value_sequence_row_is_its_count_then_each_value_delimited() {
    assert_eq!(
        value_sequence_bytes([&b"ab"[..], &b""[..], &b"c"[..]]),
        [
            &[0u8, 0, 0, 0, 0, 0, 0, 3][..],
            &[0, 0, 0, 2, b'a', b'b'][..],
            &[0, 0, 0, 0][..],
            &[0, 0, 0, 1, b'c'][..],
        ]
        .concat()
    );
}

/// THE UNIT SPAN an address names: the address as its start, the unit at the
/// address's own length as its width.
#[test]
fn the_unit_span_is_the_address_over_the_unit_at_its_own_length() {
    let element = addr(&[1, 0, 1, 0, 1, 0, 1, 1]);
    assert_eq!(
        unit_span(&element),
        span(&[1, 0, 1, 0, 1, 0, 1, 1], &[0, 0, 0, 0, 0, 0, 0, 1]),
        "the unit span: the address as the start, the unit at its length as the width"
    );
}

/// THE SLOT ROW as stored, pinned at one span, at TWO — since only a second
/// span can show the ORDER the row keeps — and at its one EMPTY spelling.
#[test]
fn the_slot_row_spells_the_stored_spans_in_the_order_given() {
    // One unit span — the span an address named stores as, its start the
    // address and its width the unit at the address's own length — then its
    // start and width, each delimited.
    let element = addr(&[1, 0, 1, 0, 1, 0, 1, 1]);
    assert_eq!(
        slot_bytes(EntrySlot(&[unit_span(&element)])),
        [
            &[0x03u8, 0, 0, 0, 0, 0, 0, 0, 1][..],
            &[0, 0, 0, 15][..],
            b"1.0.1.0.1.0.1.1",
            &[0, 0, 0, 15][..],
            b"0.0.0.0.0.0.0.1",
        ]
        .concat()
    );
    // …at TWO spans, in the order given — a resolved content extent of two
    // positions, then a unit span — DESCENDING both in address order
    // (30 > 2) and in spelled order ("1.0.30…" > "1.0.2"), so a row that
    // sorted its spans by either comparison spells other bytes. `30` is a
    // component only base ten spells `30`, so the row's DECIMAL shows too.
    let extent = span(&[1, 0, 30, 0, 1, 0, 1, 4], &[0, 0, 0, 0, 0, 0, 0, 2]);
    assert_eq!(
        slot_bytes(EntrySlot(&[extent.clone(), unit_span(&addr(&[1, 0, 2]))])),
        [
            &[0x03u8, 0, 0, 0, 0, 0, 0, 0, 2][..],
            &[0, 0, 0, 16][..],
            b"1.0.30.0.1.0.1.4",
            &[0, 0, 0, 15][..],
            b"0.0.0.0.0.0.0.2",
            &[0, 0, 0, 5][..],
            b"1.0.2",
            &[0, 0, 0, 5][..],
            b"0.0.1",
        ]
        .concat(),
        "the slot row keeps its spans in the order given"
    );
    // …and EMPTY: one spelling, the form byte and a zero count.
    assert_eq!(slot_bytes(EntrySlot(&[])), [0x03u8, 0, 0, 0, 0, 0, 0, 0, 0], "the EMPTY slot");
}

/// THE ADDRESS-LIST ROW: `0x01`, `be64(n)`, each address delimited — pinned
/// at one address and at TWO, since only a second can show the ORDER the row
/// keeps.
#[test]
fn the_address_list_row_keeps_its_addresses_in_the_order_given() {
    let element = addr(&[1, 0, 1, 0, 1, 0, 1, 1]);
    assert_eq!(
        address_list_bytes(std::slice::from_ref(&element)),
        [&[0x01u8, 0, 0, 0, 0, 0, 0, 0, 1][..], &[0, 0, 0, 15][..], b"1.0.1.0.1.0.1.1"].concat()
    );
    let descending = [addr(&[1, 0, 30]), addr(&[1, 0, 2])];
    assert_eq!(
        address_list_bytes(&descending),
        [
            &[0x01u8, 0, 0, 0, 0, 0, 0, 0, 2][..],
            &[0, 0, 0, 6][..],
            b"1.0.30",
            &[0, 0, 0, 5][..],
            b"1.0.2",
        ]
        .concat(),
        "the address-list row keeps its elements in the order given"
    );
}

/// THE PAIR'S ROW, pinned beside the address-list row it is one of: an
/// `edit_link`'s two homes as an address-list row of two, the successor's
/// home FIRST — and the one-address term the address row.
#[test]
fn the_pairs_row_is_the_successors_home_then_the_supersession_claims() {
    let (d_s, d_a) = (addr(&[1, 0, 1, 0, 2]), addr(&[1, 0, 1, 0, 1]));
    assert_eq!(
        doc_bytes(DocTerm::Pair { d_s: &d_s, d_a: &d_a }),
        [
            &[0x01u8, 0, 0, 0, 0, 0, 0, 0, 2][..],
            &[0, 0, 0, 9][..],
            b"1.0.1.0.2",
            &[0, 0, 0, 9][..],
            b"1.0.1.0.1",
        ]
        .concat(),
        "the pair's row: d_s then d_a"
    );
    assert_eq!(doc_bytes(DocTerm::One(&d_a)), b"1.0.1.0.1", "one address: the address row");
    assert_ne!(
        doc_bytes(DocTerm::Pair { d_s: &d_s, d_a: &d_a }),
        doc_bytes(DocTerm::Pair { d_s: &d_a, d_a: &d_s }),
        "the two homes swapped spell another term"
    );
}

/// THE OPTIONAL-ADDRESS ROW: ONE length-delimited group, EMPTY where no
/// address is named, else the one address named as an address-list row of
/// one element — and a present group naming nothing is still never the
/// absent one.
#[test]
fn the_optional_address_row_is_one_group_empty_or_naming_one_address() {
    assert_eq!(optional_address_bytes(None), [0u8, 0, 0, 0], "absent: the EMPTY group");
    assert_eq!(optional_address_bytes(Some(&revocation())), replaces_group(), "present: one group");
    // A PRESENT group holding an EMPTY address-list row — a spelling no op
    // makes, the wire's `replaces` member being one address — is still not
    // the absent bytes: the group's length tells the two apart.
    let mut present_and_empty = Vec::new();
    push_delimited(&mut present_and_empty, &address_list_bytes(&[]));
    assert_eq!(present_and_empty, [&[0u8, 0, 0, 9][..], &address_list_bytes(&[])[..]].concat());
    assert_ne!(
        present_and_empty,
        optional_address_bytes(None),
        "present-and-empty is never absent"
    );
}

/// THE WINDOW ROW: the run's start in its dotted-decimal spelling, delimited,
/// then `be64(width)`.
#[test]
fn the_window_row_is_the_start_delimited_then_the_width() {
    let window_start = addr(&[1, 0, 2, 0, 1, 4]);
    assert_eq!(
        window_bytes(&window_start, 3),
        [&[0u8, 0, 0, 11][..], b"1.0.2.0.1.4", &[0, 0, 0, 0, 0, 0, 0, 3][..]].concat()
    );
}

/// THE EMPTY BODY: the three mints sign no bytes, each under its own op's
/// token.
#[test]
fn the_mints_share_the_empty_body_under_each_ops_own_token() {
    for (op, token) in [
        (ContentFreeOp::CreateNewDocument, "create_new_document"),
        (ContentFreeOp::Fork, "fork"),
        (ContentFreeOp::Version, "version"),
    ] {
        let body = entry_body_empty(op);
        assert!(body.as_bytes().is_empty(), "{token}: the EMPTY body");
        assert_eq!(body.op(), token);
    }
}

/// THE `insert` BODY: the declared type's spelling, delimited — empty where
/// none is declared — then the value sequence. Both pins put the value
/// sequence after a prefix, so a count written back anywhere but where its
/// row began is caught.
#[test]
fn the_insert_body_is_the_declared_type_then_the_value_sequence() {
    assert_eq!(
        entry_body_insert(None, [&b"x"[..]]).as_bytes(),
        [&[0u8, 0, 0, 0][..], &value_sequence_bytes([&b"x"[..]])[..]].concat()
    );
    assert_eq!(
        entry_body_insert(Some(&addr(&[1, 1, 0, 1, 0, 1, 0, 3, 1])), []).as_bytes(),
        [&[0u8, 0, 0, 17][..], b"1.1.0.1.0.1.0.3.1", &[0u8; 8][..]].concat()
    );
}

/// THE `make_link` BODY: the type slot first, whatever order the slots are
/// named in, then `from`, then `to`, then the `replaces` row — the EMPTY
/// group where the op carries no `replaces` member, the member's group where
/// it names one.
#[test]
fn the_make_link_body_is_its_type_from_and_to_slots_then_the_replaces_row() {
    let element = addr(&[1, 0, 1, 0, 1, 0, 1, 1]);
    // Three DISTINCT slots, named in the workspace's `from, to, ty` order:
    // the body lays out the type slot first whatever order they are named
    // in, and a builder that wrote them in any other order spells other
    // bytes here. Then the `replaces` row: EMPTY where the op carries no
    // `replaces` member, so such a body is never the three slots alone.
    let (ty, from) = ([unit_span(&element)], [unit_span(&addr(&[1, 0, 1]))]);
    let empty = EntrySlot(&[]);
    let slots = LinkSlots { from: EntrySlot(&from), to: empty, ty: EntrySlot(&ty) };
    assert_eq!(
        entry_body_make_link(slots).as_bytes(),
        four_rows(slots),
        "the type slot, then from, then to, then the `replaces` row's EMPTY group"
    );
    // …and a `replaces` member PRESENT: the one address as an address-list
    // row, the whole row one group, length-delimited.
    assert_eq!(
        entry_body_make_link_replacing(slots, &revocation()).as_bytes(),
        [slot_bytes(slots.ty), slot_bytes(slots.from), slot_bytes(slots.to), replaces_group()]
            .concat(),
        "the three slots, then the `replaces` row's group"
    );
}

/// THE OTHER LINK WRITES — `emit`, `nullify`, `assert_sup` — are the
/// `make_link` body's four rows over the stored link, each under its own op's
/// token.
#[test]
fn the_other_link_writes_are_the_make_link_body_under_their_own_tokens() {
    let element = addr(&[1, 0, 1, 0, 1, 0, 1, 1]);
    let (ty, from) = ([unit_span(&element)], [unit_span(&addr(&[1, 0, 1]))]);
    let empty = EntrySlot(&[]);
    let slots = LinkSlots { from: EntrySlot(&from), to: empty, ty: EntrySlot(&ty) };
    // `emit` with its `to` EMPTY, as a Unary class stores it; `nullify` over
    // the home's and the target's unit spans under the retraction's;
    // `assert_sup` over the two links' under the supersedes constant's. Each
    // body is bytes-equal to a `make_link`'s over the same slots and differs
    // in its token alone.
    for (body, token) in [
        (entry_body_emit(slots), "emit"),
        (entry_body_nullify(slots), "nullify"),
        (entry_body_assert_sup(slots), "assert_sup"),
    ] {
        assert_eq!(body.as_bytes(), four_rows(slots), "{token}: the make_link body's four rows");
        assert_eq!(body.op(), token);
    }
}

/// THE `edit_link` BODY: the successor's four rows, then the supersession
/// claim's `from` slot row — the original's one unit span — and nothing after
/// it, under the op's own token.
#[test]
fn the_edit_link_body_is_the_successors_four_rows_then_the_originals_unit_span() {
    let element = addr(&[1, 0, 1, 0, 1, 0, 1, 1]);
    let (ty, from) = ([unit_span(&element)], [unit_span(&addr(&[1, 0, 1]))]);
    let empty = EntrySlot(&[]);
    let slots = LinkSlots { from: EntrySlot(&from), to: empty, ty: EntrySlot(&ty) };
    let original = addr(&[1, 0, 1, 0, 1, 0, 2, 1]);
    let edit = entry_body_edit_link(slots, &unit_span(&original));
    assert_eq!(
        edit.as_bytes(),
        [four_rows(slots), slot_bytes(EntrySlot(&[unit_span(&original)]))].concat(),
        "the successor's four rows, then the supersession claim's from: the original's unit span"
    );
    assert_eq!(edit.op(), "edit_link");
}

/// THE `publish` BODY: the count of positions placed, then the segments, each
/// behind its class byte, then the base group.
#[test]
fn the_publish_body_is_its_count_then_its_segments_then_the_base_group() {
    // One value in the birth shape: the count, one stretch — its class byte
    // and a value-sequence row of one — and the EMPTY base group. The class
    // bytes are spelled as the bytes they are — `0x02` a value stretch,
    // `0x01` a window — never as the constants that spell them: a pin
    // composed from those agrees with whatever value they hold, so a class
    // byte that moved — and every `publish` preimage with it — would pass it.
    assert_eq!(
        entry_body_publish([ShotSegmentPiece::Value(b"q")], None).as_bytes(),
        [
            &[0u8, 0, 0, 0, 0, 0, 0, 1][..],
            &[0x02][..],
            &value_sequence_bytes([&b"q"[..]])[..],
            &[0, 0, 0, 0][..],
        ]
        .concat(),
        "one value, no base: count 1, one stretch, the EMPTY group"
    );
    // Both classes, and a base: two values (one stretch), a window
    // of three positions, one more value (a SECOND stretch, since the
    // window parted them), the base `1.0.1.0.1.2` at extent 5 — six
    // positions in all. The count is the positions, not the segments; the
    // class byte precedes each segment; the group closes the body: its
    // length, the member as an address-list row of one element — the
    // optional-address row's spelling of a present address, the form byte,
    // `be64(1)`, the eleven bytes of the address delimited — then be64(5).
    // Group length 32: 1 + 8 + (4 + 11) + 8.
    let window_start = addr(&[1, 0, 2, 0, 1, 4]);
    let base_member = addr(&[1, 0, 1, 0, 1, 2]);
    let base_at = |extent: u64| Some(ShotBase { member: &base_member, extent });
    let mixed = entry_body_publish(
        [
            ShotSegmentPiece::Value(b"a"),
            ShotSegmentPiece::Value(b"b"),
            ShotSegmentPiece::Window { start: &window_start, width: nonzero(3) },
            ShotSegmentPiece::Value(b"c"),
        ],
        base_at(5),
    );
    assert_eq!(
        mixed.as_bytes(),
        [
            &[0u8, 0, 0, 0, 0, 0, 0, 6][..],
            &[0x02][..],
            &value_sequence_bytes([&b"a"[..], &b"b"[..]])[..],
            &[0x01][..],
            &window_bytes(&window_start, 3)[..],
            &[0x02][..],
            &value_sequence_bytes([&b"c"[..]])[..],
            &base_group(5)[..],
        ]
        .concat(),
        "values, a window, a value, then the base group: the member's address-list row and extent"
    );
    // Two windows in a row stay two segments: the builder merges no
    // addresses — the minted member's arrangement did, before they got here.
    let second_start = addr(&[1, 0, 3, 0, 1, 1]);
    assert_eq!(
        entry_body_publish(
            [
                ShotSegmentPiece::Window { start: &window_start, width: nonzero(3) },
                ShotSegmentPiece::Window { start: &second_start, width: nonzero(1) },
            ],
            base_at(0),
        )
        .as_bytes(),
        [
            &[0u8, 0, 0, 0, 0, 0, 0, 4][..],
            &[0x01][..],
            &window_bytes(&window_start, 3)[..],
            &[0x01][..],
            &window_bytes(&second_start, 1)[..],
            &base_group(0)[..],
        ]
        .concat()
    );
    // The empty shot: the count zero, no segment, the group — a count of
    // zero positions is what says no segment stands before the group.
    assert_eq!(entry_body_publish([], None).as_bytes(), [0u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
}

/// THE BASE GROUP is the member's address-list row and the extent, and
/// NOTHING ELSE spells it: the same shot over another member of the trunk, or
/// over the same member at another extent, or in the birth shape, is another
/// body (V, bu7-E2).
#[test]
fn the_base_group_signs_its_member_and_its_extent_both() {
    let base_member = addr(&[1, 0, 1, 0, 1, 2]);
    let base_at = |extent: u64| Some(ShotBase { member: &base_member, extent });
    let other_member = addr(&[1, 0, 1, 0, 1, 3]);
    let over = |base: Option<ShotBase<'_>>| {
        entry_body_publish([ShotSegmentPiece::Value(b"a")], base).as_bytes().to_vec()
    };
    assert_ne!(
        over(base_at(5)),
        over(Some(ShotBase { member: &other_member, extent: 5 })),
        "another member"
    );
    assert_ne!(over(base_at(5)), over(base_at(4)), "another extent");
    assert_ne!(over(base_at(5)), over(None), "the birth shape");
}

/// THE `record` BODY: its five rows in order — the type slot row, the `to`
/// slot row, the `replaces` row, the lineage row, the sig-less record's
/// bytes — pinned with neither optional row named and with both.
#[test]
fn the_record_body_is_its_five_rows_in_order() {
    // The type slot row and the `to` slot row are address-list rows both —
    // here a targeted kind with neither optional row named…
    let (record_ty, subject) = (addr(&[1, 1, 0, 1, 0, 1, 0, 3, 1]), [addr(&[1, 0, 2])]);
    assert_eq!(
        entry_body_record(RecordRows {
            ty: &record_ty,
            to: &subject,
            replaces: None,
            lineage_fork_point: None,
            sigless_canonical_record: b"{}",
        })
        .as_bytes(),
        [
            address_list_bytes(std::slice::from_ref(&record_ty)),
            address_list_bytes(&subject),
            vec![0, 0, 0, 0],
            vec![0, 0, 0, 0],
            vec![0, 0, 0, 2, b'{', b'}'],
        ]
        .concat(),
        "type, to, the EMPTY replaces group, the EMPTY lineage group, the bytes"
    );
    // …and a targetless kind naming both: the `to` row is the EMPTY
    // address-list row (nine bytes, never absent), each optional row its one
    // address in the `replaces` row's own spelling, and `from` is nowhere.
    let fork_point = addr(&[1, 0, 1, 0, 1, 3]);
    let lineage_group = [
        &[0u8, 0, 0, 24][..],
        &[0x01, 0, 0, 0, 0, 0, 0, 0, 1][..],
        &[0, 0, 0, 11][..],
        b"1.0.1.0.1.3",
    ]
    .concat();
    assert_eq!(
        entry_body_record(RecordRows {
            ty: &record_ty,
            to: &[],
            replaces: Some(&revocation()),
            lineage_fork_point: Some(&fork_point),
            sigless_canonical_record: b"r",
        })
        .as_bytes(),
        [
            address_list_bytes(std::slice::from_ref(&record_ty)),
            address_list_bytes(&[]),
            replaces_group(),
            lineage_group,
            vec![0, 0, 0, 1, b'r'],
        ]
        .concat()
    );
}

/// Each body carries its own grammar's token into the frame's `op` member.
#[test]
fn each_body_carries_its_own_grammars_token() {
    let empty = EntrySlot(&[]);
    let record_ty = addr(&[1, 1, 0, 1, 0, 1, 0, 3, 1]);
    assert_eq!(
        [
            entry_body_insert(None, []).op(),
            entry_body_make_link(LinkSlots { from: empty, to: empty, ty: empty }).op(),
            entry_body_make_link_replacing(
                LinkSlots { from: empty, to: empty, ty: empty },
                &revocation()
            )
            .op(),
            entry_body_publish([], None).op(),
            entry_body_record(RecordRows {
                ty: &record_ty,
                to: &[],
                replaces: None,
                lineage_fork_point: None,
                sigless_canonical_record: b"",
            })
            .op(),
        ],
        ["insert", "make_link", "make_link", "publish", "record"],
        "each body carries its own grammar's token"
    );
}

/// [`PublishBody`] under its budget: it finishes to [`entry_body_publish`]'s
/// body over the pieces it took, and the budget is the FINISHED body's
/// length, the base group included — a value landing the body exactly on
/// it is taken, one byte more is refused, at the budget not even an empty
/// value fits (its length prefix costs four bytes), and a window is refused
/// by the same measure. A refusal CONSUMES the builder, so no body is
/// finished over a sequence that skipped a piece or stopped short of one:
/// the third row offers `cd` between the window and `c`, and a builder that
/// let the walk go on past its refusal would finish to `[ab, window, c]`'s
/// body — `whole` itself, the preimage of another publish, whose signature
/// verifies over it.
#[test]
fn a_publish_body_within_its_budget_finishes_to_the_body_of_all_its_pieces() {
    let start = addr(&[1, 0, 2, 0, 1, 4]);
    let base_member = addr(&[1, 0, 1, 0, 1, 2]);
    let base = Some(ShotBase { member: &base_member, extent: 7 });
    let whole = entry_body_publish(
        [
            ShotSegmentPiece::Value(b"ab"),
            ShotSegmentPiece::Window { start: &start, width: nonzero(2) },
            ShotSegmentPiece::Value(b"c"),
        ],
        base,
    );
    let budget = whole.as_bytes().len();
    let fed = |pieces: &[ShotSegmentPiece<'_>]| {
        PublishBody::within(budget, base).and_then(|empty| {
            pieces.iter().try_fold(empty, |body, piece| match *piece {
                ShotSegmentPiece::Value(value) => body.push(value),
                ShotSegmentPiece::Window { start, width } => body.window(start, width),
            })
        })
    };
    let window = ShotSegmentPiece::Window { start: &start, width: nonzero(2) };
    let past = Some(PublishRefusal::PastBudget);
    assert_eq!(
        fed(&[ShotSegmentPiece::Value(b"ab"), window, ShotSegmentPiece::Value(b"cd")]).err(),
        past,
        "one byte past the budget"
    );
    assert_eq!(
        fed(&[
            ShotSegmentPiece::Value(b"ab"),
            window,
            ShotSegmentPiece::Value(b"c"),
            ShotSegmentPiece::Value(b"")
        ])
        .err(),
        past,
        "an empty value costs its length prefix"
    );
    assert_eq!(
        fed(&[
            ShotSegmentPiece::Value(b"ab"),
            window,
            ShotSegmentPiece::Value(b"cd"),
            ShotSegmentPiece::Value(b"c")
        ])
        .err(),
        past,
        "a refusal ends the body: nothing finishes over the pieces around it"
    );
    assert_eq!(
        fed(&[ShotSegmentPiece::Value(b"ab"), window, ShotSegmentPiece::Value(b"c"), window]).err(),
        past,
        "a window is measured by the same budget"
    );
    assert_eq!(
        fed(&[ShotSegmentPiece::Value(b"ab"), window, ShotSegmentPiece::Value(b"c")])
            .map(PublishBody::finish),
        Ok(whole),
        "exactly on it"
    );
    // The base group is counted from the start: `ab`'s body with the base
    // present is thirty-two bytes longer than in the birth shape — the
    // member's address-list row (1 + 8 + 4 + 11) and the extent (8) — and
    // one byte short of that budget `ab` is refused at its push, not at
    // `finish`.
    let birth_budget = entry_body_publish([ShotSegmentPiece::Value(b"ab")], None).as_bytes().len();
    let based_budget = entry_body_publish([ShotSegmentPiece::Value(b"ab")], base).as_bytes().len();
    assert_eq!(based_budget, birth_budget + 32, "the present group's cost over the EMPTY one");
    assert_eq!(
        PublishBody::within(based_budget - 1, base).and_then(|body| body.push(b"ab")).err(),
        past,
        "a present group costs the member's address-list row and the extent more than the EMPTY one"
    );
}

/// `PublishBody`'s budget bounds the FINISHED body, its leading count and its
/// base group included, so the least budget a builder can keep is the body
/// of no segments — in either shape of the group: exactly there it finishes
/// to that body and admits no value (an empty one costs its length prefix,
/// and the first of a stretch its class byte and count besides) and no
/// window.
#[test]
fn a_publish_budget_of_the_empty_body_finishes_to_it_and_admits_nothing() {
    let base_member = addr(&[1, 0, 1, 0, 1, 2]);
    for base in [None, Some(ShotBase { member: &base_member, extent: 3 })] {
        let empty = entry_body_publish([], base);
        let floor = empty.as_bytes().len();
        assert_eq!(PublishBody::within(floor, base).map(PublishBody::finish), Ok(empty));
        assert_eq!(
            PublishBody::within(floor, base).and_then(|body| body.push(b"")).err(),
            Some(PublishRefusal::PastBudget),
            "an empty value costs its length prefix"
        );
        assert_eq!(
            PublishBody::within(floor, base)
                .and_then(|body| body.window(&addr(&[1, 0, 2, 0, 1, 1]), nonzero(1)))
                .err(),
            Some(PublishRefusal::PastBudget),
            "a window costs its start and its width"
        );
    }
}

/// …and below it `within` REFUSES, naming the cause, in either shape of the
/// group as at it: a builder constructed past its own budget would finish to
/// the over-budget body the type exists to refuse rather than build, with no
/// push to refuse it. The PRESENT group is the shape a floor fixed at the
/// birth shape's twelve bytes would pass — the member's address-list row and
/// the extent are thirty-two bytes more — so each shape is asked one byte
/// below its own floor. Then the case the refusal exists for: ONE budget, a
/// kilobyte, that holds the body of no segments over an ordinary base, and a
/// base member deep enough that its group alone passes it. The group holds
/// the member's address, which the shot's author names (bu7-E2), so a budget
/// the body of no segments passes is an input's doing, answered as a refusal
/// and never a panic.
#[test]
fn a_publish_budget_below_the_empty_body_is_refused_at_within() {
    let base_member = addr(&[1, 0, 1, 0, 1, 2]);
    for base in [None, Some(ShotBase { member: &base_member, extent: 3 })] {
        let below = entry_body_publish([], base).as_bytes().len() - 1;
        assert_eq!(
            PublishBody::within(below, base).err(),
            Some(PublishRefusal::PastBudget),
            "{base:?}: one byte below the body of no segments"
        );
    }
    // A node address of 256 components, each `u32::MAX` — T4-valid, spelled
    // in 2,815 bytes — makes a body of no segments 2,848 bytes long.
    let deep_member = addr(&[u32::MAX; 256]);
    let ordinary_base = Some(ShotBase { member: &base_member, extent: 3 });
    assert!(PublishBody::within(1024, ordinary_base).is_ok(), "an ordinary base fits a kilobyte");
    assert_eq!(
        PublishBody::within(1024, Some(ShotBase { member: &deep_member, extent: 3 })).err(),
        Some(PublishRefusal::PastBudget),
        "a base member spelled past the budget is refused at construction"
    );
}

/// [`PublishBody`] NAMES what it refuses, because a caller answers the causes
/// differently: a body past its budget is the one the builder exists to
/// refuse, and a count past 2^64 − 1 names positions no store holds. Where a
/// piece meets both, the answer is the count. A body holding a full count and
/// standing exactly on its budget is passed by its next piece on BOTH the
/// count and the budget, and is told the count; one byte short of that
/// budget, the full count's own window is told the budget alone.
#[test]
fn each_refusal_names_its_cause() {
    let start = addr(&[1, 0, 2, 0, 1, 4]);
    let full = [ShotSegmentPiece::Window { start: &start, width: NonZeroU64::MAX }];
    let budget = entry_body_publish(full, None).as_bytes().len();
    let at_full =
        || PublishBody::within(budget, None).and_then(|body| body.window(&start, NonZeroU64::MAX));
    assert_eq!(
        at_full().and_then(|body| body.window(&start, nonzero(1))).err(),
        Some(PublishRefusal::Unspellable),
        "a window past the count and the budget is told the count"
    );
    assert_eq!(
        at_full().and_then(|body| body.push(b"x")).err(),
        Some(PublishRefusal::Unspellable),
        "a value past the count and the budget is told the count"
    );
    assert_eq!(
        PublishBody::within(budget - 1, None)
            .and_then(|body| body.window(&start, NonZeroU64::MAX))
            .err(),
        Some(PublishRefusal::PastBudget),
        "a spellable count past the budget is told the budget"
    );
}

/// The frame is `framed(ENTRY_TAG, …)` over the six members in order and
/// nothing else: the tag, then each member length-delimited — the board
/// term as the board row, the account as the address row, the `doc` term
/// as the address row or the pair's row, the op and body the
/// [`EntryBody`]'s own — over EVERY body, each under the `doc` term its own
/// grammar takes: each builder's token is the frame's fifth member and its
/// bytes the sixth, the EMPTY body framed as `be32(0)` with the member
/// present, and an `edit_link`'s pair's row the fourth member whole.
#[test]
fn the_frame_is_framed_under_the_entry_tag_over_six_members() {
    let term = BoardTerm { log_position: 1, chain: [0; 32] };
    let board = board_bytes(&term);
    let (account, doc) = (addr(&[1, 0, 1]), addr(&[1, 0, 1, 0, 1]));
    let framed_members = |members: [&[u8]; 6]| {
        let mut want = b"skep-entry-v1".to_vec();
        for m in members {
            want.extend_from_slice(&(m.len() as u32).to_be_bytes());
            want.extend_from_slice(m);
        }
        want
    };
    let body = EntryBody { grammar: Grammar::Insert, bytes: b"B".to_vec() };
    assert_eq!(
        entry_frame("mldsa65-ed25519", term, &account, DocTerm::One(&doc), &body),
        framed_members([b"mldsa65-ed25519", &board, b"1.0.1", b"1.0.1.0.1", b"insert", b"B"])
    );
    // Every body, under its own token, each over the `doc` term its grammar
    // takes: the pair's row for the edit, the parent account for a mint, a
    // document for every other.
    let unit = [unit_span(&addr(&[1, 0, 1, 0, 1, 0, 2, 1]))];
    let slots = LinkSlots { from: EntrySlot(&unit), to: EntrySlot(&[]), ty: EntrySlot(&unit) };
    let ty = addr(&[1, 1, 0, 1, 0, 1, 0, 3, 1]);
    let bodies = [
        entry_body_empty(ContentFreeOp::CreateNewDocument),
        entry_body_empty(ContentFreeOp::Fork),
        entry_body_empty(ContentFreeOp::Version),
        entry_body_insert(None, [&b"a"[..]]),
        entry_body_make_link(slots),
        entry_body_make_link_replacing(slots, &doc),
        entry_body_emit(slots),
        entry_body_nullify(slots),
        entry_body_assert_sup(slots),
        entry_body_edit_link(slots, &unit[0]),
        entry_body_publish([ShotSegmentPiece::Value(b"q")], None),
        entry_body_record(RecordRows {
            ty: &ty,
            to: &[],
            replaces: None,
            lineage_fork_point: None,
            sigless_canonical_record: b"",
        }),
    ];
    // The pair's row as the `doc` member, whole, where the op names two homes.
    let d_s = addr(&[1, 0, 1, 0, 2]);
    let pair = DocTerm::Pair { d_s: &d_s, d_a: &doc };
    for body in &bodies {
        let (doc_term, doc_member) = match body.op() {
            "edit_link" => (pair, doc_bytes(pair)),
            // A mint's `doc` is the PARENT ACCOUNT its document lands in.
            "create_new_document" | "fork" | "version" => {
                (DocTerm::One(&account), b"1.0.1".to_vec())
            }
            _ => (DocTerm::One(&doc), b"1.0.1.0.1".to_vec()),
        };
        assert_eq!(
            entry_frame("mldsa65-ed25519", term, &account, doc_term, body),
            framed_members([
                b"mldsa65-ed25519",
                &board,
                b"1.0.1",
                &doc_member,
                body.op().as_bytes(),
                body.as_bytes()
            ]),
            "{}: the frame's fifth and sixth members are the body's token and bytes",
            body.op()
        );
    }
}

/// …and each body over the `doc` term its own grammar takes: an `edit_link`
/// body under one address — the term every other link write takes, its
/// successor's home the address a `make_link`'s would be — is a frame no
/// verifier composes, and [`entry_frame`] stops, naming the obligation
/// (d24-1).
#[test]
#[should_panic(expected = "this `edit_link` body was framed under one address")]
fn an_edit_link_body_under_one_address_is_refused_at_the_frame() {
    let (account, d_s) = (addr(&[1, 0, 1]), addr(&[1, 0, 1, 0, 2]));
    let empty = EntrySlot(&[]);
    let edit = entry_body_edit_link(
        LinkSlots { from: empty, to: empty, ty: empty },
        &unit_span(&addr(&[1, 0, 1, 0, 1, 0, 2, 1])),
    );
    let term = BoardTerm { log_position: 1, chain: [0; 32] };
    let _ = entry_frame("mldsa65-ed25519", term, &account, DocTerm::One(&d_s), &edit);
}

/// …and the pair's row under any other body, as a `make_link`'s, is the same
/// refusal.
#[test]
#[should_panic(expected = "this `make_link` body was framed under the pair's row")]
fn any_other_body_under_the_pairs_row_is_refused_at_the_frame() {
    let (account, d_s, d_a) = (addr(&[1, 0, 1]), addr(&[1, 0, 1, 0, 2]), addr(&[1, 0, 1, 0, 1]));
    let empty = EntrySlot(&[]);
    let body = entry_body_make_link(LinkSlots { from: empty, to: empty, ty: empty });
    let term = BoardTerm { log_position: 1, chain: [0; 32] };
    let pair = DocTerm::Pair { d_s: &d_s, d_a: &d_a };
    let _ = entry_frame("mldsa65-ed25519", term, &account, pair, &body);
}

/// THE RECORD FRAME is the entry frame under the `record` grammar with its two
/// address members fixed by the grade: `account` the home's account and `doc`
/// the home, one address — under whichever token signs it, each member in its
/// place. The home and its account are two addresses of one type, and traded
/// they spell another preimage.
#[test]
fn the_record_frame_is_the_entry_frame_over_the_home_and_its_account() {
    let term = BoardTerm { log_position: 12, chain: [0xAB; 32] };
    let board = board_bytes(&term);
    let (home_account, home) = (addr(&[1, 0, 1]), addr(&[1, 0, 1, 0, 1]));
    let (ty, subject) = (addr(&[1, 1, 0, 1, 0, 1, 0, 3, 1]), [addr(&[1, 0, 2])]);
    let rows = RecordRows {
        ty: &ty,
        to: &subject,
        replaces: None,
        lineage_fork_point: None,
        sigless_canonical_record: b"{}",
    };
    let body = entry_body_record(rows);
    let frame = RecordFrame { board: term, home_account: &home_account, home: &home, rows };
    for alg in ["mldsa65-ed25519", "fndsa512-preview-ed25519"] {
        let members: [&[u8]; 6] =
            [alg.as_bytes(), &board, b"1.0.1", b"1.0.1.0.1", b"record", body.as_bytes()];
        let mut want = b"skep-entry-v1".to_vec();
        for m in members {
            want.extend_from_slice(&(m.len() as u32).to_be_bytes());
            want.extend_from_slice(m);
        }
        assert_eq!(
            frame.to_bytes(alg),
            want,
            "{alg}: the record body over the home's account, the home"
        );
    }
    let traded = RecordFrame { home_account: &home, home: &home_account, ..frame };
    assert_ne!(traded.to_bytes("mldsa65-ed25519"), frame.to_bytes("mldsa65-ed25519"), "traded");
}
