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

/// The optional-address row alone, as the pins below state it.
fn optional_address_bytes(named: Option<&Address>) -> Vec<u8> {
    let mut out = Vec::new();
    push_optional_address(&mut out, named);
    out
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

/// The rows, byte for byte, at one small instance each — the pins a
/// second implementation composes against — and the token each body
/// carries into the frame's `op` member. The two insert pins put the
/// value sequence after a prefix, so a count written back anywhere but
/// where its row began is caught; the slot row is pinned at TWO elements
/// as well as one, since only a second element can show the ORDER the row
/// keeps.
#[test]
fn the_rows_spell_as_the_module_doc_states() {
    assert_eq!(
        board_bytes(&BoardTerm { log_position: 12, chain: [0xAB; 32] })[..],
        [&[0u8, 0, 0, 0, 0, 0, 0, 12][..], &[0xAB; 32][..]].concat()[..]
    );
    assert_eq!(address_bytes(&addr(&[1, 0, 1, 0, 1])), b"1.0.1.0.1");
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
    let element = addr(&[1, 0, 1, 0, 1, 0, 1, 1]);
    assert_eq!(
        slot_bytes(EntrySlot::Addrs(std::slice::from_ref(&element))),
        [&[0x01u8, 0, 0, 0, 0, 0, 0, 0, 1][..], &[0, 0, 0, 15][..], b"1.0.1.0.1.0.1.1"].concat()
    );
    // …and at TWO elements, in the order given: DESCENDING both in address
    // order (30 > 2) and in spelled order ("1.0.30" > "1.0.2"), so a row
    // that sorted its elements by either comparison spells other bytes.
    // `30` is a component only base ten spells `30`, so the row's DECIMAL
    // shows here too.
    let pair = [addr(&[1, 0, 30]), addr(&[1, 0, 2])];
    assert_eq!(
        slot_bytes(EntrySlot::Addrs(&pair)),
        [
            &[0x01u8, 0, 0, 0, 0, 0, 0, 0, 2][..],
            &[0, 0, 0, 6][..],
            b"1.0.30",
            &[0, 0, 0, 5][..],
            b"1.0.2",
        ]
        .concat(),
        "the slot row keeps its elements in the order given"
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
        [&[0u8, 0, 0, 0][..], &value_sequence_bytes([&b"x"[..]])[..]].concat()
    );
    assert_eq!(
        entry_body_insert(Some(&addr(&[1, 1, 0, 1, 0, 1, 0, 3, 1])), []).as_bytes(),
        [&[0u8, 0, 0, 17][..], b"1.1.0.1.0.1.0.3.1", &[0u8; 8][..]].concat()
    );
    // THE PUBLISH BODY. One value in the birth shape: the count, one
    // stretch — its class byte and a value-sequence row of one — and the
    // EMPTY base-extent group. The class bytes are spelled as the bytes they
    // are — `0x02` a value stretch, `0x01` a window — never as the constants
    // that spell them: a pin composed from those agrees with whatever value
    // they hold, even the zero that opens the base-extent group, which no
    // class byte may be if the body is to read back from its front.
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
    // The window row: the start's spelling, delimited, then be64(width).
    let window_start = addr(&[1, 0, 2, 0, 1, 4]);
    assert_eq!(
        window_bytes(&window_start, 3),
        [&[0u8, 0, 0, 11][..], b"1.0.2.0.1.4", &[0, 0, 0, 0, 0, 0, 0, 3][..]].concat()
    );
    // All three classes with a base: two values (one stretch), a window
    // of three positions, one more value (a SECOND stretch, since the
    // window parted them), base extent 5 — six positions in all. The
    // count is the positions, not the segments; the class byte precedes
    // each segment; the group closes the body.
    let mixed = entry_body_publish(
        [
            ShotSegmentPiece::Value(b"a"),
            ShotSegmentPiece::Value(b"b"),
            ShotSegmentPiece::Window { start: &window_start, width: nonzero(3) },
            ShotSegmentPiece::Value(b"c"),
        ],
        Some(5),
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
            &[0, 0, 0, 8, 0, 0, 0, 0, 0, 0, 0, 5][..],
        ]
        .concat(),
        "values, a window, a value, then the base-extent group"
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
            Some(0),
        )
        .as_bytes(),
        [
            &[0u8, 0, 0, 0, 0, 0, 0, 4][..],
            &[0x01][..],
            &window_bytes(&window_start, 3)[..],
            &[0x01][..],
            &window_bytes(&second_start, 1)[..],
            &[0, 0, 0, 8, 0, 0, 0, 0, 0, 0, 0, 0][..],
        ]
        .concat()
    );
    // The empty shot: the count zero, no segment, the group — the group's
    // leading zero byte is what tells it from a segment.
    assert_eq!(entry_body_publish([], None).as_bytes(), [0u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    // Three DISTINCT slots, named in the workspace's `from, to, ty` order:
    // the body lays out the type slot first whatever order they are named
    // in, and a builder that wrote them in any other order spells other
    // bytes here. Then the `replaces` row: EMPTY where the op carries no
    // `replaces` member, so such a body is never the three slots alone.
    let (ty, from) = ([element], [addr(&[1, 0, 1])]);
    let empty = EntrySlot::Addrs(&[]);
    let slots = LinkSlots { from: EntrySlot::Addrs(&from), to: empty, ty: EntrySlot::Addrs(&ty) };
    assert_eq!(optional_address_bytes(None), [0u8, 0, 0, 0], "absent: the EMPTY group");
    assert_eq!(
        entry_body_make_link(slots).as_bytes(),
        [
            slot_bytes(slots.ty),
            slot_bytes(slots.from),
            slot_bytes(slots.to),
            optional_address_bytes(None)
        ]
        .concat(),
        "the type slot, then from, then to, then the `replaces` row's EMPTY group"
    );
    // …and a `replaces` member PRESENT: the one address as an address-form
    // slot row, the whole row one group, length-delimited.
    let revocation = addr(&[1, 0, 1, 0, 1, 0, 2, 9]);
    // Group length 28: the form byte, `be64(1)`, then `be32(15)` and the
    // fifteen bytes of the address's spelling.
    let replaces_group = [
        &[0u8, 0, 0, 28][..],
        &[0x01, 0, 0, 0, 0, 0, 0, 0, 1][..],
        &[0, 0, 0, 15][..],
        b"1.0.1.0.1.0.2.9",
    ]
    .concat();
    assert_eq!(optional_address_bytes(Some(&revocation)), replaces_group, "present: one group");
    assert_eq!(
        entry_body_make_link_replacing(slots, &revocation).as_bytes(),
        [
            slot_bytes(slots.ty),
            slot_bytes(slots.from),
            slot_bytes(slots.to),
            replaces_group.clone()
        ]
        .concat(),
        "the three slots, then the `replaces` row's group"
    );
    // A PRESENT group holding an EMPTY slot row — a spelling no op makes,
    // the wire's `replaces` member being one address — is still not the
    // absent bytes: the group's length tells the two apart.
    let mut present_and_empty = Vec::new();
    push_delimited(&mut present_and_empty, &slot_bytes(empty));
    assert_eq!(present_and_empty, [&[0u8, 0, 0, 9][..], &slot_bytes(empty)[..]].concat());
    assert_ne!(
        present_and_empty,
        optional_address_bytes(None),
        "present-and-empty is never absent"
    );
    // THE RECORD BODY: the type slot row, the `to` slot row, the
    // `replaces` row, the lineage row, the sig-less record's bytes — here a
    // targeted kind with neither optional row named…
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
            slot_bytes(EntrySlot::Addrs(std::slice::from_ref(&record_ty))),
            slot_bytes(EntrySlot::Addrs(&subject)),
            vec![0, 0, 0, 0],
            vec![0, 0, 0, 0],
            vec![0, 0, 0, 2, b'{', b'}'],
        ]
        .concat(),
        "type, to, the EMPTY replaces group, the EMPTY lineage group, the bytes"
    );
    // …and a targetless kind naming both: the `to` row is the EMPTY slot
    // (nine bytes, never absent), each optional row its one address in
    // the `replaces` row's own spelling, and `from` is nowhere.
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
            replaces: Some(&revocation),
            lineage_fork_point: Some(&fork_point),
            sigless_canonical_record: b"r",
        })
        .as_bytes(),
        [
            slot_bytes(EntrySlot::Addrs(std::slice::from_ref(&record_ty))),
            slot_bytes(empty),
            replaces_group,
            lineage_group,
            vec![0, 0, 0, 1, b'r'],
        ]
        .concat()
    );
    assert_eq!(
        [
            entry_body_insert(None, []).op(),
            entry_body_make_link(LinkSlots { from: empty, to: empty, ty: empty }).op(),
            entry_body_make_link_replacing(
                LinkSlots { from: empty, to: empty, ty: empty },
                &revocation
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
/// length, the base-extent group included — a value landing the body
/// exactly on it is taken, one byte more is refused, at the budget not
/// even an empty value fits (its length prefix costs four bytes), and a
/// window is refused by the same measure. A refusal CONSUMES the builder,
/// so no body is finished over a sequence that skipped a piece or stopped
/// short of one: the third row offers `cd` between the window and `c`, and a
/// builder that let the walk go on past its refusal would finish to
/// `[ab, window, c]`'s body — `whole` itself, the preimage of another publish,
/// whose signature verifies over it.
#[test]
fn a_publish_body_within_its_budget_finishes_to_the_body_of_all_its_pieces() {
    let start = addr(&[1, 0, 2, 0, 1, 4]);
    let whole = entry_body_publish(
        [
            ShotSegmentPiece::Value(b"ab"),
            ShotSegmentPiece::Window { start: &start, width: nonzero(2) },
            ShotSegmentPiece::Value(b"c"),
        ],
        Some(7),
    );
    let budget = whole.as_bytes().len();
    let fed = |pieces: &[ShotSegmentPiece<'_>]| {
        pieces.iter().try_fold(PublishBody::within(budget, Some(7)), |body, piece| match *piece {
            ShotSegmentPiece::Value(value) => body.push(value),
            ShotSegmentPiece::Window { start, width } => body.window(start, width),
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
    // The base-extent group is counted from the start: under a budget of
    // `ab`'s body in the birth shape — eight bytes short of that body with
    // the group present — `ab` is refused at its push, not at `finish`.
    let birth_budget = entry_body_publish([ShotSegmentPiece::Value(b"ab")], None).as_bytes().len();
    assert_eq!(
        PublishBody::within(birth_budget, Some(7)).push(b"ab").err(),
        past,
        "a present group costs eight bytes more than the EMPTY one"
    );
}

/// `PublishBody`'s budget bounds the FINISHED body, its leading count and its
/// base-extent group included, so the least budget a builder can keep is the
/// body of no segments — in either shape of the group: exactly there it
/// finishes to that body and admits no value (an empty one costs its length
/// prefix, and the first of a stretch its class byte and count besides) and
/// no window.
#[test]
fn a_publish_budget_of_the_empty_body_finishes_to_it_and_admits_nothing() {
    for base_extent in [None, Some(3)] {
        let empty = entry_body_publish([], base_extent);
        let floor = empty.as_bytes().len();
        assert_eq!(PublishBody::within(floor, base_extent).finish(), empty);
        assert_eq!(
            PublishBody::within(floor, base_extent).push(b"").err(),
            Some(PublishRefusal::PastBudget),
            "an empty value costs its length prefix"
        );
        assert_eq!(
            PublishBody::within(floor, base_extent)
                .window(&addr(&[1, 0, 2, 0, 1, 1]), nonzero(1))
                .err(),
            Some(PublishRefusal::PastBudget),
            "a window costs its start and its width"
        );
    }
}

/// …and below it `within` stops, naming the obligation: a builder minted past
/// its own budget would finish to the over-budget body the type exists to
/// refuse rather than build, with no push to refuse it.
#[test]
#[should_panic(expected = "cannot hold the body of no segments")]
fn a_publish_budget_below_the_empty_body_is_refused_at_within() {
    let floor = entry_body_publish([], None).as_bytes().len();
    let _ = PublishBody::within(floor - 1, None);
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
    let at_full = || PublishBody::within(budget, None).window(&start, NonZeroU64::MAX);
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
        PublishBody::within(budget - 1, None).window(&start, NonZeroU64::MAX).err(),
        Some(PublishRefusal::PastBudget),
        "a spellable count past the budget is told the budget"
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
    let frame =
        entry_frame("mldsa65-ed25519", term, &addr(&[1, 0, 1]), &addr(&[1, 0, 1, 0, 1]), &body);
    let board = board_bytes(&term);
    let mut want = b"skep-entry-v1".to_vec();
    for m in [&b"mldsa65-ed25519"[..], &board[..], b"1.0.1", b"1.0.1.0.1", b"insert", b"B"] {
        want.extend_from_slice(&(m.len() as u32).to_be_bytes());
        want.extend_from_slice(m);
    }
    assert_eq!(frame, want);
}
