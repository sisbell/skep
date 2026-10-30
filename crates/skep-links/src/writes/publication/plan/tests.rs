use skep_address::{validate, Nat, Tumbler};
use skep_arrangement::{head_lock_key, MintedRun, ShotRun, VPos};
use skep_kernel::LockKey;
use skep_namespace::M3State;

use super::super::publication_lock_keys;
use super::*;

fn a(comps: &[u32]) -> Address {
    validate(Tumbler::new(comps.iter().map(|&c| Nat::from(c))).unwrap()).unwrap()
}

/// doc1's content element `k`.
fn ca(k: u32) -> Address {
    a(&[1, 0, 1, 0, 1, 0, 1, k])
}

/// The edition's content element `k`.
fn pca(k: u32) -> Address {
    a(&[1, 0, 1, 0, 3, 0, 1, k])
}

fn run(start: &Address, width: u32) -> Run {
    Run::new(start.clone(), Nat::from(width)).unwrap()
}

fn span(ordinal: u64, width: u64) -> MemberSpan {
    MemberSpan { ordinal, width }
}

/// The I-span `width` positions from `start`.
fn ispan(start: &Address, width: u32) -> Span {
    run(start, width).iextent()
}

/// THE ONE FUNCTION, both halves: over an image of the edition's own run
/// `pca(1..=3)` then the draft's `ca(1..=2)`, a span of member positions
/// resolves to the I-spans the image holds there, a span crossing the two
/// runs to two pieces; the canonical spelling of each stored endset maps
/// back to the request's spans; and a request's spelling that is not the
/// canonical one — a span split at no run boundary, or a span over the
/// SECOND holding of a repeated identity — is not what the one function
/// answers.
#[test]
fn a_member_position_end_resolves_to_the_images_spans_and_maps_back() {
    let image = [run(&pca(1), 3), run(&ca(1), 2)];
    let end = member_end(&image, &[span(2, 3)]).expect("inside [1, 5]");
    assert_eq!(end.stored, Endset::from_spans([ispan(&pca(2), 2), ispan(&ca(1), 1)]), "two pieces, one per run");
    assert_eq!(end.canonical, vec![span(2, 3)], "the request's own spelling");
    assert_eq!(canonical_member_spans(&image, &end.stored), Some(end.canonical.clone()), "the verifier's half");
    // Two adjacent request spans resolve to one I-adjacent piece, whose
    // canonical spelling is ONE span: the split spelling is not canonical.
    let split = member_end(&image, &[span(1, 2), span(3, 1)]).expect("inside");
    assert_eq!(split.stored, Endset::from_spans([ispan(&pca(1), 3)]));
    assert_eq!(split.canonical, vec![span(1, 3)]);
    // Out of order stays out of order: two spans, as the endset is verbatim.
    let reversed = member_end(&image, &[span(4, 1), span(1, 1)]).expect("inside");
    assert_eq!(reversed.stored, Endset::from_spans([ispan(&ca(1), 1), ispan(&pca(1), 1)]));
    assert_eq!(reversed.canonical, vec![span(4, 1), span(1, 1)]);
    // Outside [1, placed], or a zero width: no end.
    assert!(member_end(&image, &[span(5, 2)]).is_none());
    assert!(member_end(&image, &[span(0, 1)]).is_none());
    assert!(member_end(&image, &[span(1, 0)]).is_none());
    assert_eq!(member_end(&image, &[]).map(|e| e.stored), Some(Endset::empty()), "the empty end");
}

/// THE LOWEST POSITIONS RULE (the design's W3 (a)): a run the request
/// names twice holds one identity at two places — `ca(1..=2)` at positions
/// 1–2 and again at 4–5 — and a span over the second holding spells, in
/// the canonical row, the FIRST; a span straddling the repeat and fresh
/// words spells each value at its lowest position.
#[test]
fn an_end_on_a_repeated_identity_spells_the_lowest_positions() {
    let image = [run(&ca(1), 2), run(&pca(1), 1), run(&ca(1), 2)];
    let second = member_end(&image, &[span(4, 2)]).expect("inside");
    assert_eq!(second.stored, Endset::from_spans([ispan(&ca(1), 2)]));
    assert_eq!(second.canonical, vec![span(1, 2)], "the lowest positions holding the values");
    let straddle = member_end(&image, &[span(3, 3)]).expect("inside");
    assert_eq!(straddle.stored, Endset::from_spans([ispan(&pca(1), 1), ispan(&ca(1), 2)]));
    assert_eq!(straddle.canonical, vec![span(3, 1), span(1, 2)]);
    // A partial overlap: `ca(2..=3)` at 6–7 repeats `ca(2)` from position 2.
    let image = [run(&ca(1), 2), run(&pca(1), 3), run(&ca(2), 2)];
    let partial = member_end(&image, &[span(6, 2)]).expect("inside");
    assert_eq!(partial.stored, Endset::from_spans([ispan(&ca(2), 2)]));
    assert_eq!(partial.canonical, vec![span(2, 1), span(7, 1)], "ca(2) at 2, ca(3) first at 7");
}

/// THE REQUEST'S IMAGE AND THE MEMBER'S agree on the canonical row: the
/// keys a draft-native position holds before the commit (the draft's
/// addresses) part and repeat exactly where the fresh addresses part and
/// repeat after it, so the row the signer composes over its runs is the row
/// the verifier composes over the member — while the stored endsets differ,
/// the draft's addresses before and the fresh ones after.
#[test]
fn the_request_image_and_the_member_image_spell_one_canonical_row() {
    let draft = a(&[1, 0, 1, 0, 1]);
    let shot = Shot {
        base: None,
        draft: Some(draft.clone()),
        also: vec![],
        runs: vec![
            ShotRun { origin: draft.clone(), run: run(&ca(1), 2) },
            ShotRun { origin: a(&[1, 0, 1, 0, 3]), run: run(&pca(1), 1) },
            ShotRun { origin: draft.clone(), run: run(&ca(1), 2) },
        ],
    };
    // The pairing `stage_publish` returns: the first entry minted, the
    // third placed by reference to its fresh run.
    let fresh = run(&pca(2), 2);
    let pairing: Pairing = vec![
        MintedRun { from: run(&ca(1), 2), to: fresh.clone(), home: draft.clone(), index: 0, minted: true },
        MintedRun { from: run(&ca(1), 2), to: fresh.clone(), home: draft.clone(), index: 2, minted: false },
    ];
    let before = request_image(&shot);
    let after = member_image(&shot, &pairing);
    assert_eq!(before, vec![run(&ca(1), 2), run(&pca(1), 1), run(&ca(1), 2)]);
    assert_eq!(after, vec![fresh.clone(), run(&pca(1), 1), fresh.clone()]);
    for spans in [vec![span(1, 5)], vec![span(4, 2)], vec![span(3, 3)], vec![span(2, 1)]] {
        let (b, a) = (member_end(&before, &spans).unwrap(), member_end(&after, &spans).unwrap());
        assert_eq!(b.canonical, a.canonical, "{spans:?}: one row before and after the commit");
        assert_eq!(canonical_member_spans(&after, &a.stored), Some(a.canonical), "{spans:?}: the verifier's read");
    }
    assert_eq!(
        member_end(&after, &[span(4, 2)]).unwrap().stored,
        Endset::from_spans([ispan(&pca(2), 2)]),
        "stored as the fresh I-span, on its characters at every place"
    );
}

/// `resolve_end` over the three forms once the member is minted: a stored
/// end as it is, a named end's tags to the member and the edition, a
/// member-position end through the member's image.
#[test]
fn resolve_end_resolves_the_tags_and_the_member_positions_at_the_commit() {
    let (member, edition) = (a(&[1, 0, 1, 0, 3, 1]), a(&[1, 0, 1, 0, 3]));
    let image = [run(&pca(1), 3)];
    let stored = PlannedEnd::Stored(enc([&edition]));
    assert_eq!(resolve_end(&stored, &member, Some(&edition), &image), Some(enc([&edition])));
    let named = PlannedEnd::Named(vec![NamedAddress::Member, NamedAddress::Edition, NamedAddress::Address(a(&[1, 0, 2]))]);
    assert_eq!(
        resolve_end(&named, &member, Some(&edition), &image),
        Some(enc([&member, &edition, &a(&[1, 0, 2])]))
    );
    let positions = PlannedEnd::Member(vec![span(2, 2)]);
    assert_eq!(resolve_end(&positions, &member, None, &image), Some(Endset::from_spans([ispan(&pca(2), 2)])));
    assert_eq!(resolve_end(&PlannedEnd::Member(vec![span(4, 1)]), &member, None, &image), None, "past the image");
}

/// THE LOCK SET of a family publication (the link-sets design §5.7; the card
/// on `LinkWriter::publication`): each named draft's link key where a run
/// of its identity is re-inserted — the rendering draft's and the `also`
/// draft's alike — and the rendering draft's content key alone where a
/// place is carried, never an `also` draft's content key; an `also` draft
/// with no run of its identity takes no key; the set sorted and deduped.
#[test]
fn a_family_publication_takes_each_also_drafts_link_key_and_no_content_key_for_it() {
    let (edition, draft, other) = (a(&[1, 0, 1, 0, 3]), a(&[1, 0, 1, 0, 1]), a(&[1, 0, 1, 0, 2]));
    let other_ca = |k: u32| a(&[1, 0, 1, 0, 2, 0, 1, k]);
    let shot = |also: Vec<Address>, runs: Vec<ShotRun>| Shot { base: None, draft: Some(draft.clone()), also, runs };
    let target = PublishTarget::Document(edition.clone());
    let none = PublishDeposits::default();
    let place = Some(VPos::content(Nat::from(1u32)));
    // Both drafts re-inserted, a place beside the rendering draft's run.
    let both = shot(
        vec![other.clone()],
        vec![ShotRun { origin: draft.clone(), run: run(&ca(1), 2) }, ShotRun { origin: other.clone(), run: run(&other_ca(1), 1) }],
    );
    let keys: Vec<LockKey> = publication_lock_keys(&target, &both, &[place.clone(), None], &none);
    assert!(keys.contains(&head_lock_key(&edition)) && keys.contains(&M3State::content_lock_key(&edition)), "the shot's own: {keys:?}");
    assert!(keys.contains(&M3State::link_lock_key(&draft)) && keys.contains(&M3State::link_lock_key(&other)), "each named draft's link key: {keys:?}");
    assert!(keys.contains(&M3State::content_lock_key(&draft)), "the rendering draft's content key, a place carried: {keys:?}");
    assert!(!keys.contains(&M3State::content_lock_key(&other)), "no content key for the `also` draft, never re-windowed: {keys:?}");
    let mut sorted = keys.clone();
    sorted.sort();
    sorted.dedup();
    assert_eq!(keys, sorted, "M2's order, duplicates collapsed");
    // No run of the `also` draft: no key of its; no place: no content key.
    let draft_alone = shot(vec![other.clone()], vec![ShotRun { origin: draft.clone(), run: run(&ca(1), 2) }]);
    let keys = publication_lock_keys(&target, &draft_alone, &[None], &none);
    assert!(keys.contains(&M3State::link_lock_key(&draft)) && !keys.contains(&M3State::link_lock_key(&other)), "{keys:?}");
    assert!(!keys.contains(&M3State::content_lock_key(&draft)), "{keys:?}");
    // The `also` draft's run alone: its link key and not the rendering draft's.
    let other_alone = shot(vec![other.clone()], vec![ShotRun { origin: other.clone(), run: run(&other_ca(1), 1) }]);
    let keys = publication_lock_keys(&target, &other_alone, &[None], &none);
    assert!(keys.contains(&M3State::link_lock_key(&other)) && !keys.contains(&M3State::link_lock_key(&draft)), "{keys:?}");
}

/// The two commons values M7 spells for the plan, and the read-with test:
/// the type itself, a subtype beneath it, and the type beside another each
/// name the read-with; the parent tier and a sibling do not.
#[test]
fn the_read_with_and_edition_types_are_the_commons_rows_and_the_test_is_by_prefix() {
    assert_eq!(read_with_type().to_string(), "1.1.0.1.0.1.0.3.71");
    assert_eq!(edition_type().to_string(), "1.1.0.1.0.1.0.3.14");
    assert!(names_read_with(&enc([read_with_type()])));
    assert!(names_read_with(&enc([&a(&[1, 1, 0, 1, 0, 1, 0, 3, 71, 2])])), "a subtype");
    assert!(names_read_with(&enc([edition_type(), read_with_type()])), "beside another");
    assert!(!names_read_with(&enc([edition_type()])));
    assert!(!names_read_with(&enc([&a(&[1, 1, 0, 1, 0, 1, 0, 3, 70])])), "a sibling");
    assert!(!names_read_with(&Endset::empty()));
}
