use skep_address::{validate, Nat, Tumbler};

use super::super::{entry_body_publish, unit_span, ShotSegmentPiece};
use super::*;

fn addr(comps: &[u32]) -> Address {
    validate(Tumbler::new(comps.iter().map(|&c| Nat::from(c))).unwrap()).unwrap()
}

/// A length-delimited element as every row spells one.
fn delimited(bytes: &[u8]) -> Vec<u8> {
    [&(bytes.len() as u32).to_be_bytes()[..], bytes].concat()
}

/// The slot row as stored over spans alone, as the parent's pin spells it.
fn stored(spans: &[&Span]) -> Vec<u8> {
    let mut out = vec![0x03u8];
    out.extend((spans.len() as u64).to_be_bytes());
    for span in spans {
        out.extend(delimited(span.start().to_string().as_bytes()));
        out.extend(delimited(span.width().to_string().as_bytes()));
    }
    out
}

/// Today's shot body at one value in the birth shape: the count, one
/// stretch, the EMPTY base group.
fn shot() -> EntryBody {
    entry_body_publish([ShotSegmentPiece::Value(b"q")], None)
}

/// A slot as stored over spans.
fn spans<'a>(spans: &[&'a Span]) -> DepositSlot<'a> {
    DepositSlot::Stored(spans.iter().map(|s| SlotElement::Span(s)).collect())
}

/// NO DEPOSIT, TODAY'S BODY: a publication carrying no deposit spells the
/// shot's body byte for byte — no count, no group — so every signer and
/// golden of the shot alone stands.
#[test]
fn a_publication_with_no_deposit_is_todays_body_byte_for_byte() {
    let body = entry_body_publication(shot(), &[]);
    assert_eq!(body, shot());
    assert_eq!(body.op(), "publish");
}

/// THE DEPOSIT GROUP, byte for byte: a copy homed in the member — the home
/// row the tag `member` delimited, the kind byte `0x02`, the type slot as
/// stored, the `from` slot as stored, the `to` slot as stored, the EMPTY
/// `replaces` row — appended behind today's body.
#[test]
fn a_copys_group_is_its_home_its_kind_and_the_make_link_bodys_four_rows() {
    let ty = unit_span(&addr(&[1, 1, 0, 1, 0, 1, 0, 3, 13]));
    let from = Span::new(
        Tumbler::new([1u32, 0, 1, 0, 2, 0, 1, 1].map(Nat::from)).unwrap(),
        Tumbler::new([0u32, 0, 0, 0, 0, 0, 0, 5].map(Nat::from)).unwrap(),
    )
    .unwrap();
    let to = unit_span(&addr(&[1, 0, 1, 0, 3, 0, 2, 1]));
    let row = DepositRow {
        home: DepositHome::Member,
        kind: DepositKind::Copy,
        ty: spans(&[&ty]),
        from: spans(&[&from]),
        to: spans(&[&to]),
    };
    let body = entry_body_publication(shot(), &[row]);
    let want = [
        shot().as_bytes().to_vec(),
        delimited(b"member"),
        vec![0x02],
        stored(&[&ty]),
        stored(&[&from]),
        stored(&[&to]),
        vec![0, 0, 0, 0],
    ]
    .concat();
    assert_eq!(body.as_bytes(), &want[..]);
}

/// THE HOME ROW AND THE KIND BYTE tell the groups apart: the same four rows
/// homed by address, by the `edition` tag, or under another kind each spell
/// another body — a retraction's kind byte `0x03`, a read-with's `0x04`, the
/// claim's `0x01` — and two groups in the other order spell another body.
#[test]
fn the_home_row_and_the_kind_byte_part_the_groups() {
    let ty = unit_span(&addr(&[1, 1, 0, 1, 0, 1, 0, 3, 71]));
    let from = unit_span(&addr(&[1, 0, 1, 0, 2]));
    let to = unit_span(&addr(&[1, 0, 1, 0, 4]));
    let home = addr(&[1, 0, 1, 0, 4]);
    fn row<'a>(
        home: DepositHome<'a>,
        kind: DepositKind,
        slots: [&'a Span; 3],
    ) -> DepositRow<'a> {
        let [ty, from, to] = slots;
        DepositRow { home, kind, ty: spans(&[ty]), from: spans(&[from]), to: spans(&[to]) }
    }
    let slots = [&ty, &from, &to];
    let bodies = [
        row(DepositHome::Member, DepositKind::Copy, slots),
        row(DepositHome::Edition, DepositKind::Copy, slots),
        row(DepositHome::Address(&home), DepositKind::Copy, slots),
        row(DepositHome::Address(&home), DepositKind::ReadWith, slots),
        row(DepositHome::Address(&home), DepositKind::Retraction, slots),
        row(DepositHome::Edition, DepositKind::EditionClaim, slots),
    ];
    let spelled: Vec<Vec<u8>> =
        bodies.iter().map(|r| entry_body_publication(shot(), std::slice::from_ref(r)).as_bytes().to_vec()).collect();
    for (i, a) in spelled.iter().enumerate() {
        for (j, b) in spelled.iter().enumerate() {
            assert_eq!(a == b, i == j, "groups {i} and {j}");
        }
    }
    // The kind bytes, each where the home row ends.
    let kind_byte = |r: &DepositRow<'_>| {
        let bytes = entry_body_publication(shot(), std::slice::from_ref(r)).as_bytes().to_vec();
        let home = match r.home {
            DepositHome::Member => delimited(b"member"),
            DepositHome::Edition => delimited(b"edition"),
            DepositHome::Address(a) => delimited(a.to_string().as_bytes()),
        };
        bytes[shot().as_bytes().len() + home.len()]
    };
    assert_eq!(kind_byte(&bodies[0]), 0x02, "a copy");
    assert_eq!(kind_byte(&bodies[3]), 0x04, "a read-with");
    assert_eq!(kind_byte(&bodies[4]), 0x03, "a retraction");
    assert_eq!(kind_byte(&bodies[5]), 0x01, "the edition claim");
    // The order of the groups is signed.
    let ab = entry_body_publication(shot(), &[bodies[0].clone(), bodies[3].clone()]);
    let ba = entry_body_publication(shot(), &[bodies[3].clone(), bodies[0].clone()]);
    assert_ne!(ab, ba, "the groups' order is part of the body");
    assert_eq!(
        ab.as_bytes().len(),
        shot().as_bytes().len()
            + (entry_body_publication(shot(), std::slice::from_ref(&bodies[0])).as_bytes().len() - shot().as_bytes().len())
            + (entry_body_publication(shot(), std::slice::from_ref(&bodies[3])).as_bytes().len() - shot().as_bytes().len()),
        "two groups are the two groups' bytes"
    );
}

/// A TAG ELEMENT in a slot row as stored: the tag's token where a start
/// goes and the EMPTY element where a width goes — which no span spells —
/// so a `from` naming the edition by tag and one naming an address spell
/// different rows under the same `0x03` form byte, and a tag element beside
/// a span counts as one element.
#[test]
fn a_tag_element_spells_its_token_and_an_empty_width() {
    let ty = unit_span(&addr(&[1, 1, 0, 1, 0, 1, 0, 3, 71]));
    let set = unit_span(&addr(&[1, 0, 1, 0, 4]));
    let row = DepositRow {
        home: DepositHome::Address(&addr(&[1, 0, 1, 0, 4])),
        kind: DepositKind::ReadWith,
        ty: spans(&[&ty]),
        from: DepositSlot::Stored(vec![SlotElement::Edition]),
        to: spans(&[&set]),
    };
    let body = entry_body_publication(shot(), &[row.clone()]);
    let from_row = [vec![0x03u8], 1u64.to_be_bytes().to_vec(), delimited(b"edition"), delimited(b"")].concat();
    let want = [
        shot().as_bytes().to_vec(),
        delimited(b"1.0.1.0.4"),
        vec![0x04],
        stored(&[&ty]),
        from_row,
        stored(&[&set]),
        vec![0, 0, 0, 0],
    ]
    .concat();
    assert_eq!(body.as_bytes(), &want[..]);
    // The member's tag, and a tag beside a span.
    let member = DepositRow { from: DepositSlot::Stored(vec![SlotElement::Member]), ..row.clone() };
    assert_ne!(entry_body_publication(shot(), &[member]), body, "another tag, another body");
    let beside = DepositRow {
        from: DepositSlot::Stored(vec![SlotElement::Edition, SlotElement::Span(&set)]),
        ..row.clone()
    };
    let bytes = entry_body_publication(shot(), &[beside]).as_bytes().to_vec();
    let at = shot().as_bytes().len() + delimited(b"1.0.1.0.4").len() + 1 + stored(&[&ty]).len();
    assert_eq!(bytes[at], 0x03);
    assert_eq!(&bytes[at + 1..at + 9], &2u64.to_be_bytes(), "two elements: the tag and the span");
}

/// THE MEMBER-POSITION ROW: `0x04`, `be64(n)`, then each span's ordinal and
/// width as `be64`s — and it is told from a stored slot of any content at
/// its first byte.
#[test]
fn the_member_position_row_is_its_count_then_each_spans_ordinal_and_width() {
    let ty = unit_span(&addr(&[1, 1, 0, 1, 0, 1, 0, 3, 13]));
    let to = unit_span(&addr(&[1, 0, 1, 0, 3, 0, 2, 1]));
    let row = DepositRow {
        home: DepositHome::Member,
        kind: DepositKind::Copy,
        ty: spans(&[&ty]),
        from: DepositSlot::MemberPositions(vec![
            MemberPositions { ordinal: 2, width: 3 },
            MemberPositions { ordinal: 7, width: 1 },
        ]),
        to: spans(&[&to]),
    };
    let body = entry_body_publication(shot(), &[row]);
    let from_row = [
        vec![0x04u8],
        2u64.to_be_bytes().to_vec(),
        2u64.to_be_bytes().to_vec(),
        3u64.to_be_bytes().to_vec(),
        7u64.to_be_bytes().to_vec(),
        1u64.to_be_bytes().to_vec(),
    ]
    .concat();
    let want = [
        shot().as_bytes().to_vec(),
        delimited(b"member"),
        vec![0x02],
        stored(&[&ty]),
        from_row,
        stored(&[&to]),
        vec![0, 0, 0, 0],
    ]
    .concat();
    assert_eq!(body.as_bytes(), &want[..]);
    // An empty member-position row is nine bytes, as an empty stored slot
    // is, and the two differ at their form byte.
    let empty = DepositRow {
        home: DepositHome::Member,
        kind: DepositKind::Copy,
        ty: spans(&[&ty]),
        from: DepositSlot::MemberPositions(Vec::new()),
        to: spans(&[]),
    };
    let stored_empty = DepositRow { from: spans(&[]), ..empty.clone() };
    let (a, b) = (entry_body_publication(shot(), &[empty]), entry_body_publication(shot(), &[stored_empty]));
    assert_eq!(a.as_bytes().len(), b.as_bytes().len());
    assert_ne!(a, b, "the form byte parts them");
}

/// The deposit rows extend the `publish` body alone: any other grammar is
/// refused at the builder, naming the obligation.
#[test]
#[should_panic(expected = "the deposit rows extend the `publish` body alone")]
fn another_bodys_grammar_is_refused_at_the_builder() {
    let body = super::super::entry_body_empty(super::super::ContentFreeOp::Fork);
    let _ = entry_body_publication(body, &[]);
}
