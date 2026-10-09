//! THE FIXED FRAMES the suites sign and pin: the thirteen entry frames at
//! fixed instances (`fixed_frames`), each under its name, and the two
//! helpers that spell their addresses and extents.
//!
//! TWINS: `addr`, `extent` and `fixed_frames` are copies of the three in
//! skepd's `tests/it/signed_ops.rs`, whose
//! `the_entry_frames_bytes_per_op_are_pinned` pins the frames' bytes;
//! `golden.rs` pins their signatures and preimages, so a copy that drifts
//! from its twin fails a golden there.

use skep_identity::{
    entry_body_assert_sup, entry_body_edit_link, entry_body_emit, entry_body_empty,
    entry_body_insert, entry_body_make_link, entry_body_nullify, entry_body_publish,
    entry_body_record, entry_frame, unit_span, BoardTerm, ContentFreeOp, DocTerm, EntrySlot,
    LinkSlots, RecordRows, ShotBase, ShotSegmentPiece,
};

pub fn addr(s: &str) -> skep_address::Address {
    let comps: Vec<skep_address::Nat> =
        s.split('.').map(|c| skep_address::Nat::from(c.parse::<u64>().unwrap())).collect();
    skep_address::validate(skep_address::Tumbler::new(comps).unwrap()).unwrap()
}

/// A stored content extent — a resolved slot's span — from its I-start and
/// its width in positions, as a run's `iextent` spells one.
pub fn extent(start: &str, width: u64) -> skep_address::Span {
    let start = addr(start);
    let depth = start.tumbler().len();
    let mut comps = vec![skep_address::Nat::from(0u64); depth];
    comps[depth - 1] = skep_address::Nat::from(width);
    skep_address::Span::new(start.tumbler().clone(), skep_address::Tumbler::new(comps).unwrap())
        .unwrap()
}

/// The thirteen fixed instances every golden signs, on a board whose `H.1`
/// pair is `(12, 0xAB…)`, by account `1.0.1`: the frames of an `insert`
/// (undeclared, two values), a `make_link` (three slots as stored: a unit
/// type span, a unit `from`, the `to` EMPTY), a `publish` (three values
/// copied in, one window of two positions onto another document, the base
/// `1.0.1.0.1.1` taken at three — the address form, l6-A4; the base member
/// in the group since round 7, bu7-E2) and three `record`s (the frame
/// merge, fm-I; the record grade, 2a): an enrol's kind — its type slot, one
/// subject, neither optional row named, a short canonical body — a retire's
/// kind beside it over the same subject, and the claim's — its type slot,
/// the EMPTY target slot, no record at all (a claim carries none,
/// AUTH-2.48), the body-bytes row empty; then the seven cells D24 pinned: a
/// `create_new_document`, a `fork` and a `version`, each the EMPTY body
/// over the parent account `1.0.1`; a `nullify` of the link `…0.2.1` from
/// its home, a `assert_sup` of that link by `…0.2.2`, an `emit` of the
/// retired class over `1.0.1.0.2` with its `to` EMPTY (Unary), each the
/// stored link's rows; and an `edit_link` of `…0.2.1` whose successor is
/// homed in `1.0.1.0.2` with two resolved content extents and a named
/// type, its claim homed in `1.0.1.0.1` — the pair's row as its `doc`. Each
/// comes under its NAME — its op and, after a comma, what marks the instance
/// out (`insert, undeclared`; `record, enroll`) — the one label both goldens
/// report it by.
pub fn fixed_frames(alg: &str) -> [(&'static str, Vec<u8>); 13] {
    let (account, doc, other) = (addr("1.0.1"), addr("1.0.1.0.1"), addr("1.0.1.0.2"));
    let board = BoardTerm { log_position: 12, chain: [0xAB; 32] };
    let insert = entry_body_insert(None, [&b"a"[..], &b"b"[..]]);
    let ty = [unit_span(&addr("1.1.0.1.0.1.0.3.90"))];
    let from = [unit_span(&addr("1.0.1"))];
    let link = entry_body_make_link(LinkSlots {
        from: EntrySlot(&from),
        to: EntrySlot(&[]),
        ty: EntrySlot(&ty),
    });
    let window = addr("1.0.1.0.2.0.1.1");
    let base_member = addr("1.0.1.0.1.1");
    let publish = entry_body_publish(
        [
            ShotSegmentPiece::Value(b"x"),
            ShotSegmentPiece::Value(b"y"),
            ShotSegmentPiece::Value(b"z"),
            ShotSegmentPiece::Window {
                start: &window,
                width: std::num::NonZeroU64::new(2).expect("2 is not zero"),
            },
        ],
        Some(ShotBase { member: &base_member, extent: 3 }),
    );
    let subject = [addr("1.0.2")];
    let enrol = entry_body_record(RecordRows {
        ty: &addr("1.1.0.1.0.1.0.3.1"),
        to: &subject,
        replaces: None,
        lineage_fork_point: None,
        sigless_canonical_record: br#"{"type":"skep-enroll"}"#,
    });
    let retire = entry_body_record(RecordRows {
        ty: &addr("1.1.0.1.0.1.0.3.2"),
        to: &subject,
        replaces: None,
        lineage_fork_point: None,
        sigless_canonical_record: br#"{"type":"skep-retire"}"#,
    });
    let claim = entry_body_record(RecordRows {
        ty: &addr("1.1.0.1.0.1.0.3.3"),
        to: &[],
        replaces: None,
        lineage_fork_point: None,
        sigless_canonical_record: b"",
    });
    // The other link writes, over the stored link's unit spans: the link
    // `1.0.1.0.1.0.2.1` retracted from its home, superseded by `…0.2.2`; a
    // retired-class tuple over `1.0.1.0.2`, its `to` EMPTY.
    let (l1, l2) = (unit_span(&addr("1.0.1.0.1.0.2.1")), unit_span(&addr("1.0.1.0.1.0.2.2")));
    let (home, retraction) = (unit_span(&doc), unit_span(&addr("1.1.0.1.0.1.0.1.5")));
    let supersedes = unit_span(&addr("1.1.0.1.0.1.0.1.4"));
    let (retired, retired_doc) = (unit_span(&addr("1.1.0.1.0.1.0.1.3")), unit_span(&other));
    let nullify = entry_body_nullify(LinkSlots {
        from: EntrySlot(std::slice::from_ref(&home)),
        to: EntrySlot(std::slice::from_ref(&l1)),
        ty: EntrySlot(std::slice::from_ref(&retraction)),
    });
    let assert_sup = entry_body_assert_sup(LinkSlots {
        from: EntrySlot(std::slice::from_ref(&l1)),
        to: EntrySlot(std::slice::from_ref(&l2)),
        ty: EntrySlot(std::slice::from_ref(&supersedes)),
    });
    let emit = entry_body_emit(LinkSlots {
        from: EntrySlot(std::slice::from_ref(&retired_doc)),
        to: EntrySlot(&[]),
        ty: EntrySlot(std::slice::from_ref(&retired)),
    });
    // The edit: the successor's `from` and `to` resolved to content extents
    // of `1.0.1.0.2` (five positions from its first, two from its sixth),
    // its type a ghost name, the original `…0.2.1`'s unit span the fifth row.
    let (s_from, s_to) = (extent("1.0.1.0.2.0.1.1", 5), extent("1.0.1.0.2.0.1.6", 2));
    let s_ty = unit_span(&addr("1.0.1.0.3.0.2.1"));
    let edit = entry_body_edit_link(
        LinkSlots {
            from: EntrySlot(std::slice::from_ref(&s_from)),
            to: EntrySlot(std::slice::from_ref(&s_to)),
            ty: EntrySlot(std::slice::from_ref(&s_ty)),
        },
        &l1,
    );
    let (create, fork, version) = (
        entry_body_empty(ContentFreeOp::CreateNewDocument),
        entry_body_empty(ContentFreeOp::Fork),
        entry_body_empty(ContentFreeOp::Version),
    );
    let frame = |name: &'static str, body: &skep_identity::EntryBody, term: DocTerm<'_>| {
        (name, entry_frame(alg, board, &account, term, body))
    };
    [
        frame("insert, undeclared", &insert, DocTerm::One(&doc)),
        frame("make_link, no replaces", &link, DocTerm::One(&doc)),
        frame("publish, the base filled", &publish, DocTerm::One(&doc)),
        frame("record, enroll", &enrol, DocTerm::One(&doc)),
        frame("record, retire", &retire, DocTerm::One(&doc)),
        frame("record, claim", &claim, DocTerm::One(&doc)),
        frame("create_new_document, the empty body", &create, DocTerm::One(&account)),
        frame("fork, the empty body", &fork, DocTerm::One(&account)),
        frame("version, the empty body", &version, DocTerm::One(&account)),
        frame("nullify", &nullify, DocTerm::One(&doc)),
        frame("assert_sup", &assert_sup, DocTerm::One(&doc)),
        frame("emit, the to empty", &emit, DocTerm::One(&doc)),
        frame("edit_link, the pair row", &edit, DocTerm::Pair { d_s: &other, d_a: &doc }),
    ]
}
