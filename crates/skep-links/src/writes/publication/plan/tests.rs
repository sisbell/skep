use skep_address::{validate, Nat, Tumbler};
use skep_arrangement::{head_lock_key, Base, MintedRun, ShotRun, ShotStretch, VPos};
use skep_kernel::LockKey;
use skep_namespace::{M3State, FIRST_ORDINARY_DOCUMENT};

use super::super::{publication_lock_keys, AlsoPlaces};
use super::*;

fn a(comps: &[u32]) -> Address {
    validate(Tumbler::new(comps.iter().map(|&c| Nat::from(c))).unwrap()).unwrap()
}

/// The number of the owner's account's `k`-th document: its home page is 1,
/// and its documents past it are numbered from `FIRST_ORDINARY_DOCUMENT` on,
/// past the reserved block of well-known slots. Its second is the private
/// draft beside doc1, and the edition `E` and the set `S` are its third and
/// fourth; every address these cells spell at or below one of them reads
/// its number here, worked out from that constant and never spelled.
fn nth_doc(k: u32) -> u32 {
    assert_ne!(k, 0, "an account has no 0th document");
    if k == 1 {
        1
    } else {
        FIRST_ORDINARY_DOCUMENT + k - 2
    }
}

/// doc1's content element `k`.
fn ca(k: u32) -> Address {
    a(&[1, 0, 1, 0, 1, 0, 1, k])
}

/// The edition's content element `k`.
fn pca(k: u32) -> Address {
    a(&[1, 0, 1, 0, nth_doc(3), 0, 1, k])
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
        keep_base: false,
        runs: vec![
            ShotRun { origin: draft.clone(), run: run(&ca(1), 2) },
            ShotRun { origin: a(&[1, 0, 1, 0, nth_doc(3)]), run: run(&pca(1), 1) },
            ShotRun { origin: draft.clone(), run: run(&ca(1), 2) },
        ],
        stretches: Vec::new(),
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

/// THE PAIRING's PIECES BY INDEX: `pieces_at` answers exactly the entries a
/// scan for the index would, over a pairing whose indices hold several
/// pieces each and skip a run no draft holds — the first run's three, none
/// for the edition's run, one placed by reference, two — and nothing past
/// the last index; so the member's image replaces each draft-native run by
/// its own fresh runs, in order, and keeps the edition's run as it is.
#[test]
fn the_pairings_pieces_at_an_index_are_the_entries_a_scan_finds() {
    let draft = a(&[1, 0, 1, 0, 1]);
    let piece = |from: u32, to: u32, index: usize, minted: bool| MintedRun { from: run(&ca(from), 1), to: run(&pca(to), 1), home: draft.clone(), index, minted };
    let shot = Shot {
        base: None,
        draft: Some(draft.clone()),
        also: vec![],
        keep_base: false,
        runs: vec![
            ShotRun { origin: draft.clone(), run: run(&ca(1), 3) },
            ShotRun { origin: a(&[1, 0, 1, 0, nth_doc(3)]), run: run(&pca(1), 1) },
            ShotRun { origin: draft.clone(), run: run(&ca(2), 1) },
            ShotRun { origin: draft.clone(), run: run(&ca(5), 2) },
        ],
        stretches: Vec::new(),
    };
    let pairing: Pairing = vec![
        piece(1, 2, 0, true),
        piece(2, 3, 0, true),
        piece(3, 4, 0, true),
        piece(2, 3, 2, false),
        piece(5, 5, 3, true),
        piece(6, 6, 3, true),
    ];
    for index in 0..6 {
        let scanned: Vec<&MintedRun> = pairing.iter().filter(|p| p.index == index).collect();
        assert_eq!(pieces_at(&pairing, index).iter().collect::<Vec<_>>(), scanned, "index {index}");
    }
    assert!(pieces_at(&[], 0).is_empty(), "an empty pairing holds no piece");
    assert_eq!(
        member_image(&shot, &pairing),
        vec![run(&pca(2), 1), run(&pca(3), 1), run(&pca(4), 1), run(&pca(1), 1), run(&pca(3), 1), run(&pca(5), 1), run(&pca(6), 1)],
        "each draft-native run by its own pieces' fresh runs, the edition's run as it is"
    );
}

/// `resolve_end` over the three forms once the member is minted: a stored
/// end as it is, a named end's tags to the member and the edition, a
/// member-position end through the member's image.
#[test]
fn resolve_end_resolves_the_tags_and_the_member_positions_at_the_commit() {
    let (member, edition) = (a(&[1, 0, 1, 0, nth_doc(3), 1]), a(&[1, 0, 1, 0, nth_doc(3)]));
    let image = PositionImage::of(vec![run(&pca(1), 3)]);
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
/// draft's alike — and each RE-WINDOWED draft's content key: the rendering
/// draft's where `places` carries a place, the `also` draft's where its
/// `also_places` entry carries one, neither's where its list carries none;
/// an `also` draft with no run of its identity takes no link key; the set
/// sorted and deduped.
#[test]
fn a_family_publication_takes_each_also_drafts_link_key_and_its_content_key_where_its_entry_carries_a_place() {
    let (edition, draft, other) = (a(&[1, 0, 1, 0, nth_doc(3)]), a(&[1, 0, 1, 0, 1]), a(&[1, 0, 1, 0, nth_doc(2)]));
    let other_ca = |k: u32| a(&[1, 0, 1, 0, nth_doc(2), 0, 1, k]);
    let shot = |also: Vec<Address>, runs: Vec<ShotRun>| Shot { base: None, draft: Some(draft.clone()), also, keep_base: false, runs, stretches: Vec::new() };
    let target = PublishTarget::Document(edition.clone());
    let none = PublishDeposits::default();
    let place = Some(VPos::content(Nat::from(1u32)));
    // Both drafts re-inserted, a place beside the rendering draft's run in
    // `places` and none in any `also_places` entry.
    let both = shot(
        vec![other.clone()],
        vec![ShotRun { origin: draft.clone(), run: run(&ca(1), 2) }, ShotRun { origin: other.clone(), run: run(&other_ca(1), 1) }],
    );
    let keys: Vec<LockKey> = publication_lock_keys(&target, &both, &[place.clone(), None], &[], &none);
    assert!(keys.contains(&head_lock_key(&edition)) && keys.contains(&M3State::content_lock_key(&edition)), "the shot's own: {keys:?}");
    assert!(keys.contains(&M3State::link_lock_key(&draft)) && keys.contains(&M3State::link_lock_key(&other)), "each named draft's link key: {keys:?}");
    assert!(keys.contains(&M3State::content_lock_key(&draft)), "the rendering draft's content key, a place carried: {keys:?}");
    assert!(!keys.contains(&M3State::content_lock_key(&other)), "no content key for the `also` draft where no entry places it: {keys:?}");
    let mut sorted = keys.clone();
    sorted.sort();
    sorted.dedup();
    assert_eq!(keys, sorted, "M2's order, duplicates collapsed");
    // The `also` draft's entry carrying a place: its content key, and not
    // the rendering draft's where `places` carries none; an entry with no
    // place takes none; both lists placing, both keys.
    let other_places = [AlsoPlaces { draft: other.clone(), places: vec![None, place.clone()] }];
    let keys = publication_lock_keys(&target, &both, &[None, None], &other_places, &none);
    assert!(keys.contains(&M3State::content_lock_key(&other)), "the `also` draft's content key where its entry carries a place: {keys:?}");
    assert!(!keys.contains(&M3State::content_lock_key(&draft)), "and not the rendering draft's where `places` carries none: {keys:?}");
    let empty_entry = [AlsoPlaces { draft: other.clone(), places: vec![None, None] }];
    let keys = publication_lock_keys(&target, &both, &[None, None], &empty_entry, &none);
    assert!(!keys.contains(&M3State::content_lock_key(&other)) && !keys.contains(&M3State::content_lock_key(&draft)), "an entry with no place re-windows nothing: {keys:?}");
    let keys = publication_lock_keys(&target, &both, &[place.clone(), None], &other_places, &none);
    assert!(keys.contains(&M3State::content_lock_key(&draft)) && keys.contains(&M3State::content_lock_key(&other)), "both lists place: both content keys: {keys:?}");
    let mut sorted = keys.clone();
    sorted.sort();
    sorted.dedup();
    assert_eq!(keys, sorted, "M2's order, duplicates collapsed");
    // No run of the `also` draft: no key of its; no place: no content key.
    let draft_alone = shot(vec![other.clone()], vec![ShotRun { origin: draft.clone(), run: run(&ca(1), 2) }]);
    let keys = publication_lock_keys(&target, &draft_alone, &[None], &[], &none);
    assert!(keys.contains(&M3State::link_lock_key(&draft)) && !keys.contains(&M3State::link_lock_key(&other)), "{keys:?}");
    assert!(!keys.contains(&M3State::content_lock_key(&draft)), "{keys:?}");
    // The `also` draft's run alone: its link key and not the rendering draft's.
    let other_alone = shot(vec![other.clone()], vec![ShotRun { origin: other.clone(), run: run(&other_ca(1), 1) }]);
    let keys = publication_lock_keys(&target, &other_alone, &[None], &[], &none);
    assert!(keys.contains(&M3State::link_lock_key(&other)) && !keys.contains(&M3State::link_lock_key(&draft)), "{keys:?}");
}

/// THE LOCK SET AT THE WIRE's CAPS, IN ONE PASS: a shot naming 4,097 drafts
/// — the rendering draft and 4,096 `also` — and 4,096 runs of the last
/// one's identity, that draft's `also_places` entry placing one, takes the
/// last draft's link key and its content key and no other named draft's,
/// inside the house's two seconds: the runs grouped by draft once and the
/// entry looked up once, where asking each draft for its runs would test
/// the named drafts once per run per draft.
#[test]
fn the_lock_set_of_four_thousand_drafts_groups_their_runs_in_one_pass() {
    let edition = a(&[1, 0, 1, 0, nth_doc(3)]);
    let draft = a(&[1, 0, 2, 0, 1]);
    let also: Vec<Address> = (2..=4097u32).map(|k| a(&[1, 0, 2, 0, k])).collect();
    let last = also.last().cloned().expect("the drafts");
    let runs: Vec<ShotRun> = (1..=4096u32).map(|j| ShotRun { origin: last.clone(), run: run(&a(&[1, 0, 2, 0, 4097, 0, 1, j]), 1) }).collect();
    let shot = Shot { base: None, draft: Some(draft.clone()), also, keep_base: false, runs, stretches: Vec::new() };
    let mut placed = vec![None; 4096];
    placed[0] = Some(VPos::content(Nat::from(1u32)));
    let entry = [AlsoPlaces { draft: last.clone(), places: placed }];
    let started = std::time::Instant::now();
    let keys = publication_lock_keys(&PublishTarget::Document(edition.clone()), &shot, &[], &entry, &PublishDeposits::default());
    let elapsed = started.elapsed();
    assert!(keys.contains(&M3State::link_lock_key(&last)) && keys.contains(&M3State::content_lock_key(&last)), "the last draft's two keys");
    assert!(!keys.contains(&M3State::link_lock_key(&draft)) && !keys.contains(&M3State::content_lock_key(&draft)), "no run, no place: none of the rendering draft's");
    assert_eq!(keys.len(), 4, "the shot's two, and the last draft's two: {keys:?}");
    assert!(elapsed < std::time::Duration::from_secs(2), "one pass over 4,097 drafts and 4,096 runs: {elapsed:?}");
}

/// THE LOCK SET's VERSION KEY: a member base takes its own `version_lock_key`
/// — the daughter chain's frontier — and the BARE DOCUMENT as the base takes
/// the FIRST member's, `D.1`'s, whether or not the chain holds a member yet:
/// once one stands the shot mints `D.1`'s daughter, and while none does the
/// shot mints `D.1` itself under the head key every shot takes, which the
/// set holds in either case; the birth shape, no base, takes neither.
#[test]
fn a_bare_base_takes_the_first_members_version_key_and_a_member_base_its_own() {
    let (edition, draft) = (a(&[1, 0, 1, 0, nth_doc(3)]), a(&[1, 0, 1, 0, 1]));
    let (first, second) = (a(&[1, 0, 1, 0, nth_doc(3), 1]), a(&[1, 0, 1, 0, nth_doc(3), 2]));
    let target = PublishTarget::Document(edition.clone());
    let none = PublishDeposits::default();
    let shot = |base: Option<Base>| Shot { base, draft: Some(draft.clone()), also: vec![], keep_base: false, runs: vec![ShotRun { origin: draft.clone(), run: run(&ca(1), 2) }], stretches: Vec::new() };
    let bare = publication_lock_keys(&target, &shot(Some(Base { member: edition.clone(), extent: Nat::from(0u32) })), &[None], &[], &none);
    assert!(bare.contains(&head_lock_key(&edition)) && bare.contains(&M3State::content_lock_key(&edition)), "the shot's own: {bare:?}");
    assert!(bare.contains(&M3State::version_lock_key(&first)), "the bare document's base takes the first member's version key: {bare:?}");
    assert!(!bare.contains(&M3State::version_lock_key(&second)), "never the trunk's second member's: {bare:?}");
    let member = publication_lock_keys(&target, &shot(Some(Base { member: second.clone(), extent: Nat::from(3u32) })), &[None], &[], &none);
    assert!(member.contains(&M3State::version_lock_key(&second)) && !member.contains(&M3State::version_lock_key(&first)), "a member base takes its own: {member:?}");
    let birth = publication_lock_keys(&target, &shot(None), &[None], &[], &none);
    assert!(!birth.contains(&M3State::version_lock_key(&first)) && !birth.contains(&M3State::version_lock_key(&second)), "the birth shape takes no member's key: {birth:?}");
    assert!(birth.contains(&head_lock_key(&edition)), "{birth:?}");
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

// ──────────── THE VALIDATION's (6): the daughters superseded ────────────
//
// The merge bridge lane, brief A (skep #805): a publication's `supersede`
// entries, planned over a world of M3, M7 and an empty M5 and no kernel —
// the plan being a pure function of the world and the request. The world
// lends an empty content store too, which the plan never reads: the price
// asked beside the plan counts a shot's re-insert off it.

use serde::{Deserialize, Serialize};
use skep_arrangement::M5State;
use skep_content::{ContentStore, HasContent};
use skep_kernel::{RebuildError, Seq, WorldState};
use skep_namespace::{HasM3, M3Rec, PrincipalId};

use super::super::super::nullify::retraction_tuple;
use super::super::super::supersession::supersession_claim;
// The root's accessor trait, named by its path from this module (the crate's
// tidy rule lets a module reach the root for `LinkWorld` alone): the test
// world below must implement it to be a `LinkWorld`.
use super::super::super::super::HasLinks;
use crate::error::SupersedeCause;
use crate::state::LinkRec;

/// The owner of the chain, principal 1 of the account `1.0.1`.
const P1: Caller = Caller::Principal(PrincipalId(1));

/// The plan's world: M3's registrations, M7's links, M5 at genesis, and
/// no content.
#[derive(Clone, Serialize, Deserialize)]
struct World {
    m3: M3State,
    links: LinkState,
    m5: M5State,
    content: ContentStore,
}

impl WorldState for World {
    type Record = LinkRec;
    fn apply(&self, _at: Seq, r: &LinkRec) -> World {
        World { links: self.links.apply_link(r), ..self.clone() }
    }
    fn rebuild_derived(self) -> Result<World, RebuildError> {
        Ok(self)
    }
}
impl HasM3 for World {
    fn m3(&self) -> &M3State {
        &self.m3
    }
}
impl HasLinks for World {
    fn links(&self) -> &LinkState {
        &self.links
    }
}
impl HasM5 for World {
    fn m5(&self) -> &M5State {
        &self.m5
    }
}
impl HasContent for World {
    fn content(&self) -> &ContentStore {
        &self.content
    }
}

/// The edition `E`, the owner's third document, published.
fn trunk() -> Address {
    a(&[1, 0, 1, 0, nth_doc(3)])
}

/// `E.k`, a trunk member.
fn member(k: u32) -> Address {
    a(&[1, 0, 1, 0, nth_doc(3), k])
}

/// `E.k.m`, a daughter of `E.k`.
fn daughter(k: u32, m: u32) -> Address {
    a(&[1, 0, 1, 0, nth_doc(3), k, m])
}

/// The owner's other published document, the set `S`.
fn set() -> Address {
    a(&[1, 0, 1, 0, nth_doc(4)])
}

/// The sibling account's published document.
fn theirs() -> Address {
    a(&[1, 0, 2, 0, 1])
}

/// Link element `k` of `home`.
fn link_in(home: &Address, k: u32) -> Address {
    let comps: Vec<u32> = home.tumbler().iter().map(|c| u32::try_from(c).expect("small")).chain([0, 2, k]).collect();
    a(&comps)
}

/// The chain's world: the owner's account and a sibling's, the owner's two
/// private drafts, `E` and `S` published, the sibling's document, and `E`'s
/// members `E.1`, `E.2` (the head) and the daughter `E.1.1` — each
/// allocated at its chain's next ordinal, as M3's fold requires.
fn chain_world() -> World {
    let at = Seq(0);
    let m3 = M3State::genesis()
        .apply_m3(at, &M3Rec::allocate(a(&[1, 0, 1]), false))
        .apply_m3(at, &M3Rec::register_principal(a(&[1, 0, 1]), PrincipalId(1)))
        .apply_m3(at, &M3Rec::allocate(a(&[1, 0, 2]), false))
        .apply_m3(at, &M3Rec::register_principal(a(&[1, 0, 2]), PrincipalId(2)))
        .apply_m3(at, &M3Rec::allocate(a(&[1, 0, 1, 0, 1]), false))
        .apply_m3(at, &M3Rec::allocate(a(&[1, 0, 1, 0, nth_doc(2)]), false))
        .apply_m3(at, &M3Rec::allocate(trunk(), true))
        .apply_m3(at, &M3Rec::allocate(set(), true))
        .apply_m3(at, &M3Rec::allocate(theirs(), true))
        .apply_m3(at, &M3Rec::allocate(member(1), true))
        .apply_m3(at, &M3Rec::allocate(member(2), true))
        .apply_m3(at, &M3Rec::allocate(daughter(1, 1), true));
    World { m3, links: LinkState::genesis(), m5: M5State::genesis(), content: ContentStore::default() }
}

/// `world` with the claim `old → new` deposited at link `k` of `home`.
fn with_claim(world: World, home: &Address, k: u32, old: &Address, new: &Address) -> World {
    let rec = LinkRec::Deposit { addr: link_in(home, k).tumbler().clone(), value: supersession_claim(old, new) };
    world.apply(Seq(1), &rec)
}

/// A records-less shot off `base`, the whole arrangement empty.
fn off(base: &Address) -> Shot {
    Shot { base: Some(Base { member: base.clone(), extent: Nat::from(0u32) }), draft: None, also: vec![], keep_base: false, runs: vec![], stretches: Vec::new() }
}

/// The deposits of `supersede` alone.
fn supersede(daughters: Vec<Address>) -> PublishDeposits {
    PublishDeposits { supersede: daughters, ..PublishDeposits::default() }
}

/// THE PLAN's (6): each `supersede` entry plans one claim — `old` the
/// daughter, homed in the TRUNK by address — in declared order, BEHIND the
/// other kinds inside the trunk's home (a copy homed in `E` ahead of it); a
/// trunk member other than the base is a member of the chain and is
/// admitted; the price's entry term counts the entries; and a request
/// naming no daughter plans as before.
#[test]
fn a_supersede_entry_plans_the_daughters_claim_in_the_trunk_behind_the_other_kinds() {
    let world = chain_world();
    let target = PublishTarget::Document(trunk());
    let shot = off(&member(2));
    let copy = LinkEntry {
        home: NamedAddress::Address(trunk()),
        from: EndArg::Addrs(vec![]),
        to: EndArg::Addrs(vec![]),
        ty: EndArg::Addrs(vec![NamedAddress::Address(a(&[1, 0, 1, 0, nth_doc(3), 0, 3, 6, 1]))]),
        old: None,
    };
    let deposits = PublishDeposits { links: vec![copy], supersede: vec![daughter(1, 1), member(1)], ..PublishDeposits::default() };
    let plan = plan_deposits(&world, P1, &target, &shot, &deposits).expect("planned");
    assert_eq!(plan.homes.len(), 1, "one home, the trunk: {plan:?}");
    assert_eq!(plan.homes[0].home, NamedAddress::Address(trunk()));
    assert_eq!(plan.homes[0].deposits.len(), 3);
    assert!(matches!(plan.homes[0].deposits[0], PlannedDeposit::Copy { index: 0, .. }), "the copy first: {plan:?}");
    assert_eq!(plan.homes[0].deposits[1], PlannedDeposit::Supersede { index: 0, old: daughter(1, 1) });
    assert_eq!(plan.homes[0].deposits[2], PlannedDeposit::Supersede { index: 1, old: member(1) }, "a trunk member that is not the base");
    let everything = |_: &World, _: &Address| true;
    let price = super::super::price_publication_reads(&world, P1, &everything, &target, &shot, &[], &[], &deposits, &mut |_| {});
    assert_eq!(price.entries, 3, "one links entry and two supersede entries read over the caller's homes");
    assert!(plan_deposits(&world, P1, &target, &shot, &PublishDeposits::default()).expect("planned").is_empty(), "no entry: the plan as before");
}

/// THE REFUSALS, each naming its entry and its cause: the trunk itself, a
/// document outside the chain, a member not yet minted, an element address
/// and another account's document are `not_member`; the shot's base is
/// `base`; a repeat is `duplicate` at the second; every entry at the mint
/// form is `not_member`; and the plan's order — a read-with fault speaks
/// ahead of a supersede fault.
#[test]
fn each_supersede_refusal_names_its_entry_and_its_cause() {
    let world = chain_world();
    let target = PublishTarget::Document(trunk());
    let shot = off(&member(2));
    let refused = |deposits: PublishDeposits| plan_deposits(&world, P1, &target, &shot, &deposits).expect_err("refused");
    let not_member = |index| PlanFault::Supersede { index, cause: SupersedeCause::NotMember };
    assert_eq!(refused(supersede(vec![trunk()])), not_member(0), "the trunk itself");
    assert_eq!(refused(supersede(vec![set()])), not_member(0), "a document outside the chain");
    assert_eq!(refused(supersede(vec![member(3)])), not_member(0), "a member not yet minted");
    assert_eq!(refused(supersede(vec![a(&[1, 0, 1, 0, nth_doc(3), 0, 1, 1])])), not_member(0), "an element address");
    assert_eq!(refused(supersede(vec![theirs()])), not_member(0), "another account's document");
    assert_eq!(refused(supersede(vec![daughter(1, 1), member(2)])), PlanFault::Supersede { index: 1, cause: SupersedeCause::Base }, "the base");
    assert_eq!(
        refused(supersede(vec![daughter(1, 1), member(1), daughter(1, 1)])),
        PlanFault::Supersede { index: 2, cause: SupersedeCause::Duplicate },
        "a repeat, at the second"
    );
    let mint = PublishTarget::Mint { account: a(&[1, 0, 1]) };
    let birth = Shot { base: None, draft: None, also: vec![], keep_base: false, runs: vec![], stretches: Vec::new() };
    assert_eq!(
        plan_deposits(&world, P1, &mint, &birth, &supersede(vec![daughter(1, 1)])).expect_err("refused"),
        not_member(0),
        "the mint form has no chain before the commit"
    );
    let both = PublishDeposits { read_with: vec![a(&[1, 0, 1, 0, nth_doc(2)])], supersede: vec![trunk()], ..PublishDeposits::default() };
    assert!(matches!(refused(both), PlanFault::ReadWith { index: 0, .. }), "(5) speaks ahead of (6)");
}

/// THE MOVED HEAD (skep #806): beside a shot whose base is not the trunk's
/// head `E.2` — the older member `E.1`, the bare document, the daughter
/// `E.1.1`, or no base at all — the `supersede` list is refused whole at its
/// first entry, `head_moved` naming the head, ahead of every entry's own
/// check: a later entry's `not_member`, the base named, and the skip of a
/// daughter the caller's own claim names. (5) still speaks ahead of it; a
/// request naming no daughter plans at a moved head as before; and a chain
/// with no member has no head to move, every entry there `not_member`.
#[test]
fn a_supersede_list_beside_a_base_the_trunk_moved_past_is_refused_whole_as_head_moved() {
    let world = chain_world();
    let target = PublishTarget::Document(trunk());
    let head_moved = PlanFault::Supersede { index: 0, cause: SupersedeCause::HeadMoved(member(2)) };
    let unbased = Shot { base: None, draft: None, also: vec![], keep_base: false, runs: vec![], stretches: Vec::new() };
    for (shot, name) in [(off(&member(1)), "an older member"), (off(&trunk()), "the bare document"), (off(&daughter(1, 1)), "a daughter"), (unbased, "no base")] {
        let refused = |deposits: PublishDeposits| plan_deposits(&world, P1, &target, &shot, &deposits).expect_err("refused");
        assert_eq!(refused(supersede(vec![daughter(1, 1)])), head_moved, "{name}");
        assert_eq!(refused(supersede(vec![daughter(1, 1), trunk()])), head_moved, "{name}: ahead of the second entry's `not_member`");
        assert_eq!(refused(supersede(vec![trunk()])), head_moved, "{name}: ahead of the first entry's own `not_member`");
        let rw = PublishDeposits { read_with: vec![a(&[1, 0, 1, 0, nth_doc(2)])], supersede: vec![daughter(1, 1)], ..PublishDeposits::default() };
        assert!(matches!(refused(rw), PlanFault::ReadWith { index: 0, .. }), "{name}: (5) speaks ahead of (6)");
        assert!(plan_deposits(&world, P1, &target, &shot, &PublishDeposits::default()).expect("planned").is_empty(), "{name}: no daughter, no refusal");
    }
    let off_daughter = off(&daughter(1, 1));
    let named_base = plan_deposits(&world, P1, &target, &off_daughter, &supersede(vec![daughter(1, 1)])).expect_err("refused");
    assert_eq!(named_base, head_moved, "the base named: the moved head speaks, not `base`");
    let own = with_claim(chain_world(), &trunk(), 1, &daughter(1, 1), &member(2));
    let claimed = plan_deposits(&own, P1, &target, &off(&member(1)), &supersede(vec![daughter(1, 1)])).expect_err("refused");
    assert_eq!(claimed, head_moved, "a daughter the caller's own claim names is refused here, never skipped");
    // A chain with no member: the set `S`, published and memberless, off its
    // bare document and in the birth shape — no head, so each entry's own
    // check speaks.
    let memberless = PublishTarget::Document(set());
    let s1 = a(&[1, 0, 1, 0, nth_doc(4), 1]);
    let birth = Shot { base: None, draft: None, also: vec![], keep_base: false, runs: vec![], stretches: Vec::new() };
    for shot in [off(&set()), birth] {
        let refused = plan_deposits(&world, P1, &memberless, &shot, &supersede(vec![s1.clone()])).expect_err("refused");
        assert_eq!(refused, PlanFault::Supersede { index: 0, cause: SupersedeCause::NotMember }, "no member stands: no head moved");
    }
}

/// THE SKIP: a daughter an ACTIVE claim of the caller's own already names
/// is skipped — nothing planned, never refused — whatever the claim's `new`
/// and wherever among the caller's homes it lies; another account's claim
/// naming it skips nothing, nor does the caller's own claim once
/// retracted; and a skipped entry leaves the next planned at its own index.
#[test]
fn a_daughter_a_claim_of_the_callers_own_names_is_skipped_and_anothers_or_a_retracted_one_is_not() {
    let target = PublishTarget::Document(trunk());
    let shot = off(&member(2));
    let plan_of = |world: &World, daughters: Vec<Address>| plan_deposits(world, P1, &target, &shot, &supersede(daughters)).expect("planned");
    let own = with_claim(chain_world(), &trunk(), 1, &daughter(1, 1), &member(2));
    assert!(plan_of(&own, vec![daughter(1, 1)]).is_empty(), "the caller's own claim in the trunk: skipped");
    let elsewhere = with_claim(chain_world(), &a(&[1, 0, 1, 0, nth_doc(2)]), 1, &daughter(1, 1), &a(&[1, 0, 1, 0, nth_doc(2), 0, 2, 9]));
    assert!(plan_of(&elsewhere, vec![daughter(1, 1)]).is_empty(), "a claim in the caller's draft onto a link: skipped all the same");
    let not_mine = with_claim(chain_world(), &theirs(), 1, &daughter(1, 1), &member(2));
    assert_eq!(
        plan_of(&not_mine, vec![daughter(1, 1)]).homes[0].deposits,
        vec![PlannedDeposit::Supersede { index: 0, old: daughter(1, 1) }],
        "another account's claim is not the caller's: planned"
    );
    let retracted = own.apply(
        Seq(2),
        &LinkRec::Deposit { addr: link_in(&trunk(), 2).tumbler().clone(), value: retraction_tuple(&trunk(), &link_in(&trunk(), 1)) },
    );
    assert_eq!(
        plan_of(&retracted, vec![daughter(1, 1)]).homes[0].deposits,
        vec![PlannedDeposit::Supersede { index: 0, old: daughter(1, 1) }],
        "the caller's own claim, retracted, is no longer active: planned"
    );
    assert_eq!(
        plan_of(&own, vec![daughter(1, 1), member(1)]).homes[0].deposits,
        vec![PlannedDeposit::Supersede { index: 1, old: member(1) }],
        "the skipped entry leaves the next at its own index"
    );
}

/// The node's principal: seated at the node, above every account.
const NODE: Caller = Caller::Principal(skep_namespace::BOOTSTRAP_PRINCIPAL);

/// The sibling account's principal.
const P2: Caller = Caller::Principal(PrincipalId(2));

/// The sub-account under the owner's account, and its one document.
fn sub_account() -> Address {
    a(&[1, 0, 1, 1])
}
fn sub_doc() -> Address {
    a(&[1, 0, 1, 1, 0, 1])
}

/// The sibling account's `k`-th document, private.
fn sibling_doc(k: u32) -> Address {
    a(&[1, 0, 2, 0, nth_doc(k)])
}

/// The chain's world, plus a sub-account under the owner's account (its
/// own principal, one private document) and `n` private documents of the
/// sibling account; one citation link homed in the owner's draft, in the
/// trunk, in the sub-account's document and in each of the sibling's `n`.
/// So `n + 3` homes hold a link, `n` of them the sibling's.
fn homes_world(n: u32) -> World {
    let at = Seq(0);
    let mut world = chain_world();
    world.m3 = world
        .m3
        .apply_m3(at, &M3Rec::allocate(sub_account(), false))
        .apply_m3(at, &M3Rec::register_principal(sub_account(), PrincipalId(3)))
        .apply_m3(at, &M3Rec::allocate(sub_doc(), false));
    for k in 2..n + 2 {
        world.m3 = world.m3.apply_m3(at, &M3Rec::allocate(sibling_doc(k), false));
    }
    let homes: Vec<Address> =
        [a(&[1, 0, 1, 0, 1]), trunk(), sub_doc()].into_iter().chain((2..n + 2).map(sibling_doc)).collect();
    for home in &homes {
        world = with_link(world, home, 1, Link::triple(enc([home]), Endset::empty(), enc([&citation()])));
    }
    world
}

/// The caller's own homes and the homes its walk visited.
fn walked(world: &World, caller: Caller) -> (Vec<Address>, u64) {
    let mut visited = 0;
    let homes = own_homes_counted(world.m3(), world.links(), caller, &mut |k| visited += k);
    (homes, visited)
}

/// A caller seated at no account walks no home: the node's principal owns
/// no link home, so its walk is skipped whatever the board holds, where the
/// walk would visit every link-holding home on the board. An account's
/// principal walks its account's homes as before, the sub-account's
/// visited and not kept; the system caller visits none.
#[test]
fn a_caller_seated_at_no_account_walks_no_home() {
    for n in [0, 2, 16] {
        let world = homes_world(n);
        let seat = world.m3().principal_prefix(skep_namespace::BOOTSTRAP_PRINCIPAL).expect("the node's principal is seated");
        assert_eq!(*seat, a(&[1]), "seated at the node");
        assert_eq!(world.links().homes_under(&enc([seat])).len(), n as usize + 3, "n = {n}: every link home lies under the node");
        assert_eq!(walked(&world, NODE), (vec![], 0), "n = {n}: the node's principal walks nothing and owns nothing");
        assert_eq!(walked(&world, Caller::System), (vec![], 0), "n = {n}: the system caller walks nothing");
        assert_eq!(
            walked(&world, P1),
            (vec![a(&[1, 0, 1, 0, 1]), trunk()], 3),
            "n = {n}: the account's three homes visited, the sub-account's not kept"
        );
        let (theirs_homes, theirs_visited) = walked(&world, P2);
        assert_eq!((theirs_homes.len(), theirs_visited), (n as usize, u64::from(n)), "n = {n}: the sibling walks its own");
    }
}

/// The node's principal plans as it did: an original of another's is
/// refused as not its own, and a supersede entry plans as the owner's does.
#[test]
fn the_node_principals_plan_answers_as_before_the_walk_was_skipped() {
    let world = homes_world(16);
    let (target, shot) = (PublishTarget::Document(trunk()), off(&member(2)));
    let draft = a(&[1, 0, 1, 0, 1]);
    let original =
        PublishDeposits { originals: vec![OriginalEntry { old: link_in(&draft, 1), rest: vec![] }], ..PublishDeposits::default() };
    assert_eq!(
        plan_deposits(&world, NODE, &target, &shot, &original).expect_err("refused"),
        PlanFault::Original { index: 0, cause: OriginalCause::NotOwner },
        "an original in another's home: not the caller's"
    );
    let node = plan_deposits(&world, NODE, &target, &shot, &supersede(vec![daughter(1, 1)])).expect("planned");
    let owner = plan_deposits(&world, P1, &target, &shot, &supersede(vec![daughter(1, 1)])).expect("planned");
    assert_eq!(node.homes[0].deposits, vec![PlannedDeposit::Supersede { index: 0, old: daughter(1, 1) }]);
    assert_eq!(format!("{node:?}"), format!("{owner:?}"), "the supersede entry plans as the owner's does");
}

/// THE FEED ROW's TEST: `supersession_claim_in` finds the claim `old → new`
/// homed in `home` — exactly that pair, in that home — and no other.
#[test]
fn supersession_claim_in_finds_the_claim_onto_the_member_and_no_other() {
    let world = with_claim(chain_world(), &trunk(), 1, &daughter(1, 1), &member(2));
    assert!(supersession_claim_in(&world.links, &trunk(), &daughter(1, 1), &member(2)));
    assert!(!supersession_claim_in(&world.links, &trunk(), &daughter(1, 1), &member(1)), "another `new`");
    assert!(!supersession_claim_in(&world.links, &trunk(), &member(1), &member(2)), "another `old`");
    assert!(!supersession_claim_in(&world.links, &set(), &daughter(1, 1), &member(2)), "another home");
    assert!(!supersession_claim_in(&chain_world().links, &trunk(), &daughter(1, 1), &member(2)), "no claim");
}

/// THE LOCK SET gains the trunk's link key where a daughter is named, as it
/// does where the deposits claim at the document form: the claims are
/// minted in the trunk's link subspace, a home that stands before the
/// commit.
#[test]
fn a_publication_naming_a_daughter_takes_the_trunks_link_key() {
    let target = PublishTarget::Document(trunk());
    let shot = off(&member(2));
    let keys = publication_lock_keys(&target, &shot, &[], &[], &PublishDeposits::default());
    assert!(!keys.contains(&M3State::link_lock_key(&trunk())), "no deposit in the trunk: no key: {keys:?}");
    let keys = publication_lock_keys(&target, &shot, &[], &[], &supersede(vec![daughter(1, 1)]));
    assert!(keys.contains(&M3State::link_lock_key(&trunk())), "a daughter named: the trunk's link key: {keys:?}");
    let mut sorted = keys.clone();
    sorted.sort();
    sorted.dedup();
    assert_eq!(keys, sorted, "M2's order, duplicates collapsed");
}

// ──────────── THE VALIDATION's (4′): the originals the rider ends ────────────
//
// The private rider (the link-sets design §5.7 (vi′)), planned over a world
// of M3, M7 and an empty M5 and no kernel, as the daughters are above: the
// cells the kernel suite cannot build — an original of a fenced class behind
// a hand-written claim — and the lock set; `tests/it/publication.rs` holds
// the step's refusals and its writes over a kernel.

use super::super::super::correspondence_type;
use crate::error::OriginalCause;

/// `world` with `value` deposited at link `k` of `home`.
fn with_link(world: World, home: &Address, k: u32, value: Link) -> World {
    world.apply(Seq(1), &LinkRec::Deposit { addr: link_in(home, k).tumbler().clone(), value })
}

/// The rider naming `old` with `rest`, beside the retraction of `copy`.
fn take_off(copy: &Address, old: &Address, rest: Vec<Span>) -> PublishDeposits {
    PublishDeposits { retract: vec![copy.clone()], originals: vec![OriginalEntry { old: old.clone(), rest }], ..PublishDeposits::default() }
}

/// THE FENCED TYPE: an original whose stored type is a class the open
/// surface never writes — here a correspondence record in the owner's draft,
/// behind a claim onto a copy in `E` the request retracts — is refused
/// `fenced_type` where the entry names a rest, no fresh mark of that class
/// being a `make_link`'s to write; with no rest the entry passes the step
/// and is planned, the daemon's class cell being where the record's
/// retraction is refused. A plain original of the same shape plans its
/// fresh mark over the rest in the end that holds it.
#[test]
fn an_original_of_a_fenced_class_takes_no_fresh_mark_and_a_plain_one_does() {
    let (draft, draft_word, trunk_word) = (a(&[1, 0, 1, 0, 1]), a(&[1, 0, 1, 0, 1, 0, 1, 1]), a(&[1, 0, 1, 0, nth_doc(3), 0, 1, 1]));
    let span = |start: &Address, width: u32| Run::new(start.clone(), Nat::from(width)).unwrap().iextent();
    let copy = link_in(&trunk(), 1);
    let plain_ty = a(&[1, 1, 0, 1, 0, 1, 0, 3, 23, 2]);
    let world = with_link(chain_world(), &trunk(), 1, Link::triple(Endset::from_spans([span(&trunk_word, 3)]), Endset::empty(), enc([&plain_ty])));
    // The record, and the plain mark, each over the draft's three words, each claimed onto the copy.
    let record = Link::triple(Endset::from_spans([span(&draft_word, 3)]), Endset::from_spans([span(&trunk_word, 3)]), enc([correspondence_type()]));
    let mark = Link::triple(Endset::empty(), Endset::from_spans([span(&draft_word, 3)]), enc([&plain_ty]));
    let world = with_link(world, &draft, 1, record);
    let world = with_link(world, &draft, 2, mark);
    let world = with_claim(world, &draft, 3, &link_in(&draft, 1), &copy);
    let world = with_claim(world, &draft, 4, &link_in(&draft, 2), &copy);
    let (target, shot) = (PublishTarget::Document(trunk()), off(&member(2)));
    let plan = |deposits: PublishDeposits| plan_deposits(&world, P1, &target, &shot, &deposits);
    let rest = span(&a(&[1, 0, 1, 0, 1, 0, 1, 3]), 1);
    assert_eq!(
        plan(take_off(&copy, &link_in(&draft, 1), vec![rest.clone()])).expect_err("refused"),
        PlanFault::Original { index: 0, cause: OriginalCause::FencedType },
        "a rest over a correspondence record: no fresh record is made"
    );
    let planned = plan(take_off(&copy, &link_in(&draft, 1), vec![])).expect("planned");
    assert_eq!((planned.originals.len(), planned.originals[0].rest.as_ref()), (1, None), "no rest: the record's retraction alone is planned");
    let planned = plan(take_off(&copy, &link_in(&draft, 2), vec![rest.clone()])).expect("planned");
    assert_eq!(
        planned.originals[0].rest,
        Some(Link::triple(Endset::empty(), Endset::from_spans([rest]), enc([&plain_ty]))),
        "the plain mark's rest in the end that holds it, its type kept"
    );
    assert_eq!(planned.homes.len(), 1, "the copy's retraction alone is homed: {planned:?}");
    assert_eq!(planned.homes[0].home, NamedAddress::Address(trunk()));
    assert!(!planned.is_empty());
}

/// THE LOCK SET gains the link key of each original's home where the rider
/// names one: its retraction and its rest's fresh mark are minted there, a
/// home that stands before the commit, the home key covering the
/// retraction's dedup as it does a `retract` target's.
#[test]
fn a_publication_naming_an_original_takes_its_homes_link_key() {
    let (target, shot) = (PublishTarget::Document(trunk()), off(&member(2)));
    let draft = a(&[1, 0, 1, 0, nth_doc(2)]);
    let keys = publication_lock_keys(&target, &shot, &[], &[], &PublishDeposits::default());
    assert!(!keys.contains(&M3State::link_lock_key(&draft)), "no original: no key: {keys:?}");
    let keys = publication_lock_keys(&target, &shot, &[], &[], &take_off(&link_in(&trunk(), 1), &link_in(&draft, 1), vec![]));
    assert!(keys.contains(&M3State::link_lock_key(&draft)), "an original named: its home's link key: {keys:?}");
    assert!(keys.contains(&M3State::link_lock_key(&trunk())), "and the copy's home's: {keys:?}");
    let mut sorted = keys.clone();
    sorted.sort();
    sorted.dedup();
    assert_eq!(keys, sorted, "M2's order, duplicates collapsed");
}

/// The citation type, a commons row: what the cells below type their links.
fn citation() -> Address {
    a(&[1, 1, 0, 1, 0, 1, 0, 3, 13])
}

/// THE BASE'S WORDS, subtracted by identity: the base's runs merged — two
/// overlapping, one apart — and a published span cut where they hold part
/// of it, the rest kept in order; a span they hold whole leaves nothing; a
/// span on another chain, or at another depth, is kept whole; no base word
/// leaves every span.
#[test]
fn the_bases_words_leave_the_published_positions_it_did_not_hold() {
    let base = BaseWords::of(&[run(&pca(3), 2), run(&pca(9), 1), run(&pca(4), 3)]);
    assert_eq!(base.unheld(&[ispan(&pca(1), 10)]), vec![ispan(&pca(1), 2), ispan(&pca(7), 2), ispan(&pca(10), 1)]);
    assert!(base.unheld(&[ispan(&pca(3), 4), ispan(&pca(9), 1)]).is_empty(), "every position held");
    assert_eq!(base.unheld(&[ispan(&ca(1), 5)]), vec![ispan(&ca(1), 5)], "another chain");
    let document = subtree_of(trunk().tumbler());
    assert_eq!(base.unheld(&[document.clone()]), vec![document], "another depth");
    assert_eq!(BaseWords::of(&[]).unheld(&[ispan(&pca(1), 3)]), vec![ispan(&pca(1), 3)], "no base word");
}

/// THE VALIDATION's (3) against the base (§5.1's key (iii) as E4 2.1
/// re-says it): an original on the edition's words 1..5, claimed onto a
/// public copy over 1..2 alone. With no base word read the copy covers too
/// little and the entry is planned; with the base holding every published
/// word none is left to cover and it is refused `superseded`; holding 3..5
/// the copy covers what is left and it is refused; holding 1..3, the words
/// 4..5 are left uncovered and it is planned; base words of another chain
/// change nothing. A revision of the original, judged by the original's
/// copy over the entry's spans whole (W17), is planned whatever the base
/// holds.
#[test]
fn an_entrys_original_is_superseded_over_the_published_words_its_base_does_not_hold() {
    let draft = a(&[1, 0, 1, 0, 1]);
    let ty = citation();
    let on = |start: &Address, width: u32| Endset::from_spans([ispan(start, width)]);
    let world = with_link(chain_world(), &draft, 1, Link::triple(on(&pca(1), 5), Endset::empty(), enc([&ty])));
    let world = with_link(world, &trunk(), 1, Link::triple(on(&pca(1), 2), Endset::empty(), enc([&ty])));
    let world = with_claim(world, &draft, 2, &link_in(&draft, 1), &link_in(&trunk(), 1));
    let world = with_link(world, &draft, 3, Link::triple(on(&pca(1), 5), Endset::empty(), enc([&a(&[1, 1, 0, 1, 0, 1, 0, 3, 20])])));
    let world = with_claim(world, &draft, 4, &link_in(&draft, 1), &link_in(&draft, 3));
    let (target, shot) = (PublishTarget::Document(trunk()), off(&member(2)));
    let plan = |old: Address, base_runs: Vec<Run>| {
        let entry = LinkEntry { home: NamedAddress::Member, from: EndArg::Spans(vec![ispan(&pca(1), 5)]), to: EndArg::Addrs(vec![]), ty: EndArg::Addrs(vec![NamedAddress::Address(ty.clone())]), old: Some(old) };
        plan_deposits(&world, P1, &target, &shot, &PublishDeposits { links: vec![entry], base_runs, ..PublishDeposits::default() }).map(|_| ())
    };
    let superseded: Result<(), PlanFault> = Err(PlanFault::Old { index: 0, cause: OldCause::Superseded });
    let original = link_in(&draft, 1);
    assert_eq!(plan(original.clone(), vec![]), Ok(()), "no base word: the copy covers 1..2 of 1..5");
    assert_eq!(plan(original.clone(), vec![run(&pca(1), 5)]), superseded, "every published word the base's: none left to cover");
    assert_eq!(plan(original.clone(), vec![run(&pca(3), 3)]), superseded, "the copy covers what the base left");
    assert_eq!(plan(original.clone(), vec![run(&pca(1), 3)]), Ok(()), "4..5 left, which no copy covers");
    assert_eq!(plan(original, vec![run(&ca(1), 5)]), Ok(()), "the base's words on another chain");
    assert_eq!(plan(link_in(&draft, 3), vec![run(&pca(1), 5)]), Ok(()), "a revision: its original's copy over the spans whole");
}

// ──────────── the member-position end: the one pass against the scan ────────────
//
// The member-position check as it was first spelled, kept here as the
// oracle the prepared image is held to, answer for answer, and counted in
// the unit the prepared image's own passes are counted in.

/// The check's first spelling: every row of the image for each span, every
/// row for each piece, every holding row for each cut. Kept word for word
/// but for the `steps` each loop charges — one for a row built, one for a
/// row a span's walk or a piece's filter looks at, one for a piece cut, one
/// for a holding row a piece's cuts are read off, one for a cut window made
/// and one for a holding row a window's scan looks at. The sum that counts
/// the placed positions charges nothing.
mod oracle {
    use std::collections::BTreeSet;

    use skep_address::{Nat, Span, Tumbler};
    use skep_arrangement::Run;

    use super::super::{MemberEnd, MemberSpan};
    use crate::endset::Endset;

    pub(super) fn member_end(image: &[Run], spans: &[MemberSpan], steps: &mut impl FnMut(u64)) -> Option<MemberEnd> {
        let rows = rows_of(image, steps)?;
        let placed: u64 = rows.iter().map(|r| r.width).sum();
        let mut pieces: Vec<Piece> = Vec::new();
        for span in spans {
            if span.width == 0 || span.ordinal == 0 {
                return None;
            }
            let reach = span.ordinal.checked_add(span.width)?;
            if reach - 1 > placed {
                return None;
            }
            for row in &rows {
                steps(1);
                let row_reach = row.position + row.width;
                let lo = span.ordinal.max(row.position);
                let hi = reach.min(row_reach);
                if lo >= hi {
                    continue;
                }
                steps(1);
                let piece = Piece { chain: row.chain.clone(), first: row.first + (lo - row.position), width: hi - lo };
                match pieces.last_mut() {
                    Some(last) if last.chain == piece.chain && last.first + last.width == piece.first => {
                        last.width += piece.width;
                    }
                    _ => pieces.push(piece),
                }
            }
        }
        let stored = Endset::from_spans(pieces.iter().map(Piece::span));
        let canonical = canonical_over(&rows, &pieces, steps)?;
        Some(MemberEnd { canonical, stored })
    }

    pub(super) fn canonical_member_spans(image: &[Run], stored: &Endset, steps: &mut impl FnMut(u64)) -> Option<Vec<MemberSpan>> {
        let rows = rows_of(image, steps)?;
        let pieces: Vec<Piece> = stored.spans().map(Piece::of_span).collect::<Option<_>>()?;
        canonical_over(&rows, &pieces, steps)
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    struct Row {
        chain: Vec<Nat>,
        first: u64,
        width: u64,
        position: u64,
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    struct Piece {
        chain: Vec<Nat>,
        first: u64,
        width: u64,
    }

    impl Piece {
        fn span(&self) -> Span {
            let tumbler = |ordinal: u64| {
                Tumbler::new(self.chain.iter().cloned().chain([Nat::from(ordinal)]))
                    .expect("a content address has a chain and an ordinal")
            };
            Span::from_endpoints(tumbler(self.first), &tumbler(self.first + self.width))
                .expect("width ≥ 1 and one length: the span is well-formed")
        }

        fn of_span(span: &Span) -> Option<Piece> {
            let start = span.start();
            let width = span.width();
            if start.len() != width.len() || start.len() < 2 {
                return None;
            }
            if width.iter().take(width.len() - 1).any(|c| *c != Nat::from(0u32)) {
                return None;
            }
            let (chain, first) = split(start)?;
            let count = u64::try_from(width.get(width.len())?).ok()?;
            (count > 0).then_some(Piece { chain, first, width: count })
        }
    }

    fn split(t: &Tumbler) -> Option<(Vec<Nat>, u64)> {
        let mut chain: Vec<Nat> = t.iter().cloned().collect();
        let ordinal = chain.pop()?;
        Some((chain, u64::try_from(&ordinal).ok()?))
    }

    fn rows_of(image: &[Run], steps: &mut impl FnMut(u64)) -> Option<Vec<Row>> {
        let mut rows = Vec::with_capacity(image.len());
        let mut position: u64 = 1;
        for run in image {
            steps(1);
            let (chain, first) = split(run.i_start().tumbler())?;
            let width = u64::try_from(run.width()).ok()?;
            rows.push(Row { chain, first, width, position });
            position = position.checked_add(width)?;
        }
        Some(rows)
    }

    fn canonical_over(rows: &[Row], pieces: &[Piece], steps: &mut impl FnMut(u64)) -> Option<Vec<MemberSpan>> {
        let mut out: Vec<MemberSpan> = Vec::new();
        for piece in pieces {
            let reach = piece.first + piece.width;
            let holding: Vec<&Row> = rows
                .iter()
                .filter(|r| {
                    steps(1);
                    r.chain == piece.chain && r.first < reach && r.first + r.width > piece.first
                })
                .collect();
            let mut cuts: BTreeSet<u64> = BTreeSet::from([piece.first, reach]);
            for r in &holding {
                steps(1);
                for c in [r.first, r.first + r.width] {
                    if c > piece.first && c < reach {
                        cuts.insert(c);
                    }
                }
            }
            let cuts: Vec<u64> = cuts.into_iter().collect();
            for pair in cuts.windows(2) {
                steps(1);
                let (x, y) = (pair[0], pair[1]);
                let best = holding
                    .iter()
                    .filter(|r| {
                        steps(1);
                        r.first <= x && x < r.first + r.width
                    })
                    .min_by_key(|r| r.position + (x - r.first))?;
                let ordinal = best.position + (x - best.first);
                match out.last_mut() {
                    Some(last) if last.ordinal + last.width == ordinal => last.width += y - x,
                    _ => out.push(MemberSpan { ordinal, width: y - x }),
                }
            }
        }
        Some(out)
    }
}

/// `count` runs of one position each, every one on doc1's first content
/// address: one identity at every position.
fn one_address(count: u32) -> Vec<Run> {
    (0..count).map(|_| run(&ca(1), 1)).collect()
}

/// `count` runs of one position each on `count` addresses of doc1's content,
/// the highest first: no run continues the one before it, and no address is
/// held twice.
fn descending(count: u32) -> Vec<Run> {
    (0..count).map(|k| run(&ca(count - k), 1)).collect()
}

/// `short` runs of one position each on doc1's even content addresses
/// `2, 4, …`, then ONE run over the addresses `1 ..= 2 × short + 1`: the wide
/// run holds every even address a second time, at a higher position, so its
/// values' lowest positions alternate between a short run and itself.
fn striped(short: u32) -> Vec<Run> {
    (1..=short).map(|k| run(&ca(2 * k), 1)).chain([run(&ca(1), 2 * short + 1)]).collect()
}

/// The card's `L` for an image of `runs` runs: `⌈log₂(runs + 2)⌉`.
fn log_of(runs: usize) -> u64 {
    u64::from(64 - (runs as u64 + 1).leading_zeros())
}

/// The steps the card allows the preparation of an image of `runs` runs.
fn prepared_within(runs: usize) -> u64 {
    8 * (runs as u64 + 1) * log_of(runs)
}

/// The steps the card allows `is_canonical` of `spans` spans.
fn canonical_within(runs: usize, spans: usize) -> u64 {
    (spans as u64 + 1) * (log_of(runs) + 3)
}

/// The steps the card allows `canonical_row` of `spans` spans asked for at
/// most `most` spans of the row.
fn row_within(runs: usize, spans: usize, most: usize) -> u64 {
    4 * (spans as u64 + most as u64 + 1) * (log_of(runs) + 3)
}

/// The steps the card allows `stored` of `spans` spans resolving to
/// `pieces` pieces.
fn stored_within(runs: usize, spans: usize, pieces: usize) -> u64 {
    (spans as u64 + 1) * (log_of(runs) + 3) + 2 * (pieces as u64 + spans as u64)
}

/// The steps the card allows `canonical_spans` of `pieces` stored spans
/// whose row has `row` spans.
fn spans_within(runs: usize, pieces: usize, row: usize) -> u64 {
    2 * (pieces as u64 + 1) * (log_of(runs) + 3) + row as u64 + pieces as u64
}

/// A seeded sequence (xorshift64*): the same shapes on every run, and no
/// dependency taken for them.
struct Seeded(u64);

impl Seeded {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    /// A number under `n`, which is not zero.
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }

    fn one_in(&mut self, n: u64) -> bool {
        self.below(n) == 0
    }
}

/// Element `k` of one of six chains: doc1's content, the edition's, doc1's
/// links (a chain apart from its content by the subspace alone), a member's
/// content and a sub-account's document's (each a component longer), and
/// the sibling account's.
fn on(chain: u64, k: u32) -> Address {
    match chain {
        0 => ca(k),
        1 => pca(k),
        2 => a(&[1, 0, 1, 0, 1, 0, 2, k]),
        3 => a(&[1, 0, 1, 0, nth_doc(3), 1, 0, 1, k]),
        4 => a(&[1, 0, 1, 2, 0, 1, 0, 1, k]),
        _ => a(&[1, 0, 2, 0, 1, 0, 1, k]),
    }
}

/// An image of up to twelve runs over one, two, three or six chains, their
/// addresses drawn from a dozen so that runs repeat, overlap and nest; one
/// run in four continues the run before it, one in six repeats it, one in
/// six stands one address below it, and one in eight is wide.
fn seeded_image(seed: &mut Seeded) -> Vec<Run> {
    let chains = [1, 1, 2, 3, 6][seed.below(5) as usize];
    let mut rows: Vec<(u64, u32, u32)> = Vec::new();
    for _ in 0..seed.below(13) {
        let fresh = |seed: &mut Seeded| {
            let width = 1 + if seed.one_in(8) { seed.below(30) } else { seed.below(5) };
            (seed.below(chains), 1 + seed.below(12) as u32, width as u32)
        };
        let row = match (rows.last().copied(), seed.below(12)) {
            (Some((chain, first, width)), 0..=2) => (chain, first + width, 1 + seed.below(4) as u32),
            (Some(before), 3..=4) => before,
            (Some((chain, first, _)), 5..=6) if first > 1 => (chain, first - 1, 1),
            _ => fresh(seed),
        };
        rows.push(row);
    }
    rows.into_iter().map(|(chain, first, width)| run(&on(chain, first), width)).collect()
}

/// A request of up to six spans over `placed` positions: most inside them,
/// one in three beginning where the span before it ends, and one in forty
/// no span at all — a zero ordinal, a zero width, a start or a reach past
/// the positions, or a reach past `u64`.
fn seeded_spans(seed: &mut Seeded, placed: u64) -> Vec<MemberSpan> {
    let mut spans: Vec<MemberSpan> = Vec::new();
    for _ in 0..seed.below(7) {
        let next = if placed == 0 || seed.one_in(40) {
            match seed.below(5) {
                0 => span(0, 1),
                1 => span(1, 0),
                2 => span(placed + 1, 1),
                3 => span(placed.max(1), 2),
                _ => span(u64::MAX, 2),
            }
        } else {
            let touching = spans.last().map(|last| last.ordinal.saturating_add(last.width)).filter(|at| *at <= placed);
            let ordinal = match touching {
                Some(at) if seed.one_in(3) => at,
                _ => 1 + seed.below(placed),
            };
            let room = placed - ordinal + 1;
            span(ordinal, 1 + if seed.one_in(3) { seed.below(room) } else { seed.below(room.min(3)) })
        };
        spans.push(next);
    }
    spans
}

/// A stored endset of up to three spans, as a verifier might hand one:
/// content spans on `chains` chains at a dozen addresses — some held whole
/// by an image over those chains, some in part, some in no run — and, one
/// in six, a span that is no I-span: an address's own span, a span whose
/// width is not at its start's depth, or one a tier wide.
fn seeded_endset(seed: &mut Seeded, chains: u64) -> Endset {
    let t = |comps: &[u32]| Tumbler::new(comps.iter().map(|&c| Nat::from(c))).unwrap();
    Endset::from_spans((0..seed.below(4)).filter_map(|_| match seed.below(18) {
        0 => Some(subtree_of(a(&[1, 0, 1, 0, 1]).tumbler())),
        1 => Span::new(t(&[5, 3]), t(&[0, 2, 7])).ok(),
        2 => Span::new(ca(1 + seed.below(12) as u32).tumbler().clone(), t(&[0, 0, 0, 0, 0, 1, 0, 0])).ok(),
        _ => Some(ispan(&on(seed.below(chains), 1 + seed.below(14) as u32), 1 + seed.below(8) as u32)),
    }))
}

/// What the equality fence asked, by answer: the ends, those the first
/// spelling answers no end for, those whose request is its own canonical
/// row, and the stored endsets read back, with those no row holds whole.
#[derive(Debug, Default, PartialEq, Eq)]
struct Asked {
    ends: usize,
    none: usize,
    canonical: usize,
    endsets: usize,
    unheld: usize,
}

/// Holds every answer the prepared image gives for `spans` over `image` to
/// the first spelling's, and every count to the card's bound; answers the
/// first spelling's end.
fn held_to_the_first_spelling(image: &[Run], spans: &[MemberSpan], asked: &mut Asked) -> Option<MemberEnd> {
    let first = oracle::member_end(image, spans, &mut |_| {});
    let (runs, count) = (image.len(), spans.len());
    asked.ends += 1;
    asked.none += usize::from(first.is_none());
    assert_eq!(member_end(image, spans), first, "the one function: {image:?} {spans:?}");
    let prepared = PositionImage::of(image.to_vec());
    let mut steps = 0u64;
    prepared.rows(&mut |n| steps += n);
    assert!(steps <= prepared_within(runs), "the preparation, {steps} steps: {image:?}");
    let (mut steps, mut again) = (0u64, 0u64);
    assert_eq!(prepared.end_counted(spans, &mut |n| steps += n), first, "the end, the image prepared once: {image:?} {spans:?}");
    prepared.rows(&mut |n| again += n);
    assert_eq!(again, 0, "prepared once: a second ask charges nothing");
    let (pieces, row) = first.as_ref().map_or((0, 0), |end| (end.stored.len(), end.canonical.len()));
    assert!(steps <= stored_within(runs, count, pieces) + row_within(runs, count, row), "the end, {steps} steps: {image:?} {spans:?}");
    let mut steps = 0u64;
    assert_eq!(prepared.stored_counted(spans, &mut |n| steps += n), first.as_ref().map(|end| end.stored.clone()), "the stored endset alone: {image:?} {spans:?}");
    assert!(steps <= stored_within(runs, count, pieces), "the stored endset, {steps} steps: {image:?} {spans:?}");
    let mut steps = 0u64;
    let verdict = first.as_ref().map(|end| end.canonical == spans);
    asked.canonical += usize::from(verdict == Some(true));
    assert_eq!(prepared.is_canonical_counted(spans, &mut |n| steps += n), verdict, "whether the request is its own row: {image:?} {spans:?}");
    assert!(steps <= canonical_within(runs, count), "the verdict, {steps} steps: {image:?} {spans:?}");
    for most in [0, 1, 2, 3, usize::MAX] {
        let mut steps = 0u64;
        let head = first.as_ref().map(|end| (end.canonical[..most.min(row)].to_vec(), row > most));
        assert_eq!(prepared.canonical_row_counted(spans, most, &mut |n| steps += n), head, "the row's first {most} spans: {image:?} {spans:?}");
        assert!(steps <= row_within(runs, count, most.min(row)), "the row's first {most} spans, {steps} steps: {image:?} {spans:?}");
    }
    if let Some(end) = &first {
        read_back_as_the_first_spelling_reads(image, &end.stored, asked);
    }
    first
}

/// Holds the prepared image's reading of `stored` back to its row to the
/// first spelling's, and its count to the card's bound.
fn read_back_as_the_first_spelling_reads(image: &[Run], stored: &Endset, asked: &mut Asked) {
    let first = oracle::canonical_member_spans(image, stored, &mut |_| {});
    asked.endsets += 1;
    asked.unheld += usize::from(first.is_none());
    assert_eq!(canonical_member_spans(image, stored), first, "the verifier's half: {image:?} {stored:?}");
    let prepared = PositionImage::of(image.to_vec());
    prepared.rows(&mut |_| {});
    let mut steps = 0u64;
    assert_eq!(prepared.canonical_spans_counted(stored, &mut |n| steps += n), first, "the verifier's half, the image prepared once: {image:?} {stored:?}");
    let row = first.as_ref().map_or(0, Vec::len);
    assert!(steps <= spans_within(image.len(), stored.len(), row), "the verifier's half, {steps} steps: {image:?} {stored:?}");
}

/// THE ONE PASS ANSWERS AS THE SCAN DID, over every shape a seeded sequence
/// makes — four thousand images of up to twelve runs on one chain and on
/// several, their runs repeating one identity at several positions,
/// overlapping, nesting and continuing one another; over each, four
/// requests of up to six spans — inside one run, across many, touching the
/// span before them, of zero ordinal or width, past the positions and past
/// `u64` — and the empty request; each request's own canonical row sent
/// back as a request; and three stored endsets a verifier might read back,
/// held whole, in part or in no run, or no I-span at all. Then the shapes
/// at `u64`'s top, and the two images of one shot — the request's and the
/// minted member's — of a shot naming its whole arrangement and of a shot
/// naming its change by a stretch list. Every answer is the first
/// spelling's: the end's stored endset and its row, the stored endset
/// alone, whether the request is its own row, the row's first spans up to
/// a count and whether it runs on, and the verifier's reading of an endset
/// back to its row — `None` for `None`. And every one is counted inside the
/// bound the prepared image's card states.
#[test]
fn the_prepared_image_answers_as_the_first_spelling_does_over_every_shape() {
    let mut seed = Seeded(0x05EE_D0FA_5EED);
    let mut asked = Asked::default();
    for _ in 0..4_000 {
        let image = seeded_image(&mut seed);
        let placed: u64 = image.iter().map(|run| u64::try_from(run.width()).expect("a small width")).sum();
        let chains = 1 + seed.below(6);
        held_to_the_first_spelling(&image, &[], &mut asked).expect("the empty request is the empty end");
        for _ in 0..4 {
            let spans = seeded_spans(&mut seed, placed);
            if let Some(end) = held_to_the_first_spelling(&image, &spans, &mut asked) {
                // The row is its own canonical spelling: asked again as one.
                let again = held_to_the_first_spelling(&image, &end.canonical, &mut asked).expect("a row is a request");
                assert_eq!(again.canonical, end.canonical, "a row spells itself: {image:?} {spans:?}");
            }
        }
        for _ in 0..3 {
            read_back_as_the_first_spelling_reads(&image, &seeded_endset(&mut seed, chains), &mut asked);
        }
    }
    assert_eq!(
        asked,
        Asked { ends: 33_919, none: 2_081, canonical: 22_710, endsets: 43_838, unheld: 8_534 },
        "the seeded shapes, by answer"
    );
    // The top of `u64`: one run over all but the last two positions a
    // `u64` counts, and spans at its edge.
    let top = [Run::new(ca(1), Nat::from(u64::MAX - 1)).unwrap()];
    let mut edge = Asked::default();
    for spans in [
        vec![span(1, u64::MAX - 1)],
        vec![span(u64::MAX - 1, 1)],
        vec![span(u64::MAX - 2, 2)],
        vec![span(u64::MAX - 1, 2)],
        vec![span(u64::MAX, 1)],
        vec![span(u64::MAX, u64::MAX)],
        vec![span(1, 1), span(2, u64::MAX - 2)],
        vec![span(7, 3), span(u64::MAX - 5, 4), span(1, 6)],
    ] {
        held_to_the_first_spelling(&top, &spans, &mut edge);
    }
    assert_eq!((edge.ends, edge.none, edge.canonical), (8, 3, 4), "at the top of `u64`: a reach past it is no span");
    // An image no end is read over: a run as wide as `u64` counts, whose
    // positions pass it; a width past `u64`; an ordinal past it; and two
    // runs whose positions together pass it.
    let mut unread = Asked::default();
    let past = Nat::from(u64::MAX) + Nat::from(1u32);
    let beyond = validate(Tumbler::new([1u32, 0, 1, 0, 1, 0, 1].into_iter().map(Nat::from).chain([past.clone()])).unwrap()).unwrap();
    for image in [
        vec![Run::new(ca(1), Nat::from(u64::MAX)).unwrap()],
        vec![run(&ca(1), 2), Run::new(ca(9), past.clone()).unwrap()],
        vec![Run::new(beyond, Nat::from(1u32)).unwrap(), run(&ca(1), 2)],
        vec![Run::new(ca(1), Nat::from(u64::MAX / 2 + 1)).unwrap(), Run::new(pca(1), Nat::from(u64::MAX / 2)).unwrap()],
    ] {
        for spans in [vec![], vec![span(1, 1)]] {
            assert_eq!(held_to_the_first_spelling(&image, &spans, &mut unread), None, "no end over such an image, the empty one included: {spans:?}");
        }
        read_back_as_the_first_spelling_reads(&image, &Endset::from_spans([ispan(&ca(1), 1)]), &mut unread);
    }
    assert_eq!(unread, Asked { ends: 8, none: 8, canonical: 0, endsets: 4, unheld: 4 }, "no end, and no row read back");
    // One shot, two images: the request's, and the member's once minted.
    let draft = a(&[1, 0, 1, 0, 1]);
    let mut shots = Asked::default();
    for form in 0..400 {
        // The shot's runs: the draft's own words and words placed by
        // reference; and the pairing a mint would return for them, each
        // draft address given one fresh address at its first placing.
        let mut fresh: BTreeMap<u32, u32> = BTreeMap::new();
        let (mut runs, mut pairing): (Vec<ShotRun>, Pairing) = (Vec::new(), Vec::new());
        for index in 0..1 + seed.below(8) as usize {
            if seed.one_in(3) {
                let chain = [1, 5][seed.below(2) as usize];
                let origin = document_of(&on(chain, 1)).expect("an element lies in a document");
                runs.push(ShotRun { origin, run: run(&on(chain, 1 + seed.below(12) as u32), 1 + seed.below(4) as u32) });
                continue;
            }
            let (first, width) = (1 + seed.below(10) as u32, 1 + seed.below(4) as u32);
            runs.push(ShotRun { origin: draft.clone(), run: run(&ca(first), width) });
            let mut k = first;
            while k < first + width {
                let minted = !fresh.contains_key(&k);
                let next = 1_000 + fresh.len() as u32;
                let to = *fresh.entry(k).or_insert(next);
                let mut len = 1;
                while k + len < first + width {
                    let held = fresh.get(&(k + len)).copied();
                    let runs_on = match held {
                        Some(at) => !minted && at == to + len,
                        None => minted,
                    };
                    if !runs_on {
                        break;
                    }
                    fresh.entry(k + len).or_insert(to + len);
                    len += 1;
                }
                pairing.push(MintedRun { from: run(&ca(k), len), to: run(&pca(to), len), home: draft.clone(), index, minted });
                k += len;
            }
        }
        let by_stretches = form % 2 == 1;
        let shot = Shot {
            base: by_stretches.then(|| Base { member: member(2), extent: Nat::from(40u32) }),
            draft: Some(draft.clone()),
            also: vec![],
            keep_base: false,
            stretches: if by_stretches { vec![ShotStretch { start: Nat::from(3u32), width: Nat::from(2u32), count: runs.len() }] } else { Vec::new() },
            runs,
        };
        let (before, after) = (request_image(&shot), member_image(&shot, &pairing));
        let placed: u64 = before.iter().map(|run| u64::try_from(run.width()).expect("a small width")).sum();
        for _ in 0..4 {
            let spans = seeded_spans(&mut seed, placed);
            let (b, a) = (held_to_the_first_spelling(&before, &spans, &mut shots), held_to_the_first_spelling(&after, &spans, &mut shots));
            assert_eq!(b.map(|end| end.canonical), a.map(|end| end.canonical), "one row over the request's image and the member's: {shot:?} {spans:?}");
        }
    }
    assert_eq!(shots, Asked { ends: 3_200, none: 244, canonical: 1_210, endsets: 2_956, unheld: 0 }, "the shots' two images, by answer");
}

/// WHERE THE FIRST SPELLING OVERFLOWED: a run whose addresses pass `u64` —
/// its ordinal and its width each within it, their sum not. The first
/// spelling added the two in `u64` wherever a span reached such a run, and
/// so had no answer for it (its arithmetic overflowed); the prepared image
/// reads a reach wider than `u64` and answers by the same rule as for any
/// run. Beside a run on another chain that no span reaches, such a run
/// changes nothing, and there the two spellings agree.
#[test]
fn a_run_whose_addresses_pass_u64_is_read_by_the_same_rule() {
    let last = validate(Tumbler::new([1u32, 0, 1, 0, 1, 0, 1].into_iter().map(Nat::from).chain([Nat::from(u64::MAX)])).unwrap()).unwrap();
    let image = vec![run(&pca(1), 2), Run::new(last.clone(), Nat::from(2u32)).unwrap(), Run::new(last.clone(), Nat::from(2u32)).unwrap()];
    let prepared = PositionImage::of(image.clone());
    let past = Run::new(last, Nat::from(2u32)).unwrap().iextent();
    let end = prepared.end(&[span(2, 3)]).expect("inside the positions");
    assert_eq!(end.stored, Endset::from_spans([ispan(&pca(2), 1), past.clone()]), "the run's two addresses, the second past `u64`");
    assert_eq!(end.canonical, vec![span(2, 3)]);
    assert_eq!(prepared.is_canonical(&[span(2, 3)]), Some(true));
    assert_eq!(prepared.is_canonical(&[span(5, 2)]), Some(false), "the same two addresses a second time");
    assert_eq!(prepared.canonical_row(&[span(5, 2)], 4), Some((vec![span(3, 2)], false)), "their lowest positions");
    assert_eq!(prepared.canonical_spans(&Endset::from_spans([past])), Some(vec![span(3, 2)]), "and read back");
    // No span on the far run: the two spellings agree.
    let mut asked = Asked::default();
    held_to_the_first_spelling(&image, &[span(1, 2)], &mut asked).expect("the edition's two words");
}

/// Runs `call` over a count of the steps it charges and answers both. The
/// count may not pass `within`: one that does stops the call where it
/// passes, so a spelling that rescans is refused at its first rescan and
/// never run out.
fn counted<T>(within: u64, what: &str, call: impl FnOnce(&mut dyn FnMut(u64)) -> T) -> (T, u64) {
    let mut steps = 0u64;
    let out = call(&mut |n| {
        steps += n;
        assert!(steps <= within, "{what}: {steps} steps, past the {within} the card allows");
    });
    (out, steps)
}

/// The first spelling's steps for one end over `rows` runs holding ONE
/// address, the end one span over all of them: every row for the span,
/// then, for each of the `rows` pieces, every row filtered, every row
/// holding it read for its cuts and scanned for its one cut.
fn first_over_one_address(rows: u64) -> u64 {
    3 * rows * rows + 4 * rows
}

/// The first spelling's steps for one end over those runs, the end `spans`
/// spans of the first position.
fn first_over_one_position(rows: u64, spans: u64) -> u64 {
    rows + spans * (4 * rows + 2)
}

/// The first spelling's steps for one end over `rows` runs on descending
/// addresses, the end `spans` spans over all of them: `spans × rows`
/// pieces, every row filtered for each.
fn first_over_descending(rows: u64, spans: u64) -> u64 {
    rows + spans * rows * (rows + 5)
}

/// The first spelling's steps for one end over `rows − 1` runs on even
/// addresses and the wide run after them, the end `spans` spans over the
/// wide run: each piece cut `2 × rows − 1` times, every row scanned a cut.
fn first_over_striped(rows: u64, spans: u64) -> u64 {
    rows + spans * (2 * rows * rows + 4 * rows)
}

/// THE WORST SHAPES AT THE CAPS, COUNTED: images of 4,096 runs (one list's
/// cap, a shot's runs before they took the store's number), 16,384, and
/// 65,536 (the store's number, which a shot's runs take now), and over
/// each the ends that cost the first spelling most — the count of every
/// answer inside the bound the prepared image's card states, the
/// preparation charged ONCE an image however many ends are asked of it.
///
/// * One address at every position, the end one span over all of them: not
///   canonical, its row a span a position. The verdict is one search, and
///   the row owed is read to one list's 4,096 spans and no further.
/// * The same image, the end a full list of spans of the first position:
///   canonical, a search a span; stored, a piece a span.
/// * Runs on descending addresses, the end one span over all of them:
///   canonical by one search, whatever the runs; stored, a piece a run; and
///   those pieces read back to the one span they spell.
/// * The same image, the end a full list of such spans: canonical, a search
///   a span — where the spans resolve to `4,096 × runs` pieces, none of
///   which the verdict builds. Their walk is counted where they number a
///   sixteenth of that.
/// * Short runs on even addresses and one wide run over them all, the end a
///   full list of spans over the wide run: not canonical at its first span,
///   where the search stops, its row `4,096 × (2 × runs − 1)` spans long
///   and read to 4,096.
///
/// Beside each stands what the first spelling charged the same end, by the
/// formulas `the_first_spelling_looks_at_every_row_for_every_piece_of_an_end`
/// holds it to by count: past the prepared image's whole allowance at every
/// shape and size — the preparation included — and never run here. At
/// 65,536 runs it is 12,885,164,032 steps for the first end,
/// 1,073,815,552 for the second, 4,295,360,512 for the third, about
/// 1.76 × 10¹³ for the fourth and about 3.52 × 10¹³ for the fifth.
#[test]
fn the_prepared_image_reads_the_worst_shapes_inside_its_bounds_at_the_caps() {
    const LIST: usize = MAX_SLOT_SPANS;
    assert_eq!(
        (first_over_one_address(65_536), first_over_one_position(65_536, 4_096), first_over_descending(65_536, 1)),
        (12_885_164_032, 1_073_815_552, 4_295_360_512),
        "the first spelling at the store's number, by its formulas"
    );
    assert_eq!((first_over_descending(65_536, 4_096), first_over_striped(65_536, 4_096)), (17_593_528_287_232, 35_185_445_896_192));
    for rows in [4_096u32, 16_384, 65_536] {
        let (r, n) = (u64::from(rows), rows as usize);
        let (whole, list) = ([span(1, r)], LIST as u64);
        // One address at every position.
        let image = PositionImage::of(one_address(rows));
        counted(prepared_within(n), "the preparation", |mut steps| image.rows(&mut steps).is_some());
        let (verdict, _) = counted(canonical_within(n, 1), "one span over one address", |mut steps| image.is_canonical_counted(&whole, &mut steps));
        assert_eq!(verdict, Some(false), "{rows}: the positions past the first hold the first's value");
        let (owed, _) = counted(row_within(n, 1, LIST), "the row owed", |mut steps| image.canonical_row_counted(&whole, LIST, &mut steps));
        let (owed, more) = owed.expect("an end");
        assert_eq!((owed.len(), more), (LIST, n > LIST), "{rows}: the row read to one list's spans, and whether it runs on");
        assert!(owed.iter().all(|spelled| *spelled == span(1, 1)), "{rows}: a span a position, each the first");
        assert!(first_over_one_address(r) > (prepared_within(n) + canonical_within(n, 1) + row_within(n, 1, LIST)), "{rows}: the first spelling's steps");
        let ones: Vec<MemberSpan> = (0..LIST).map(|_| span(1, 1)).collect();
        let (verdict, _) = counted(canonical_within(n, LIST), "a list of the first position", |mut steps| image.is_canonical_counted(&ones, &mut steps));
        assert_eq!(verdict, Some(true), "{rows}");
        let (stored, _) = counted(stored_within(n, LIST, LIST), "a list of the first position, stored", |mut steps| image.stored_counted(&ones, &mut steps));
        let stored = stored.expect("an end");
        assert_eq!(stored.len(), LIST, "{rows}: a piece a span");
        let (back, _) = counted(spans_within(n, LIST, LIST), "those pieces read back", |mut steps| image.canonical_spans_counted(&stored, &mut steps));
        assert_eq!(back, Some(ones.clone()), "{rows}");
        assert!(first_over_one_position(r, list) > (prepared_within(n) + canonical_within(n, LIST) + stored_within(n, LIST, LIST)), "{rows}: the first spelling's steps");
        // Runs on descending addresses.
        let image = PositionImage::of(descending(rows));
        counted(prepared_within(n), "the preparation", |mut steps| image.rows(&mut steps).is_some());
        let (verdict, _) = counted(canonical_within(n, 1), "one span over descending runs", |mut steps| image.is_canonical_counted(&whole, &mut steps));
        assert_eq!(verdict, Some(true), "{rows}");
        let (stored, _) = counted(stored_within(n, 1, n), "one span over descending runs, stored", |mut steps| image.stored_counted(&whole, &mut steps));
        let stored = stored.expect("an end");
        assert_eq!(stored.len(), n, "{rows}: a piece a run");
        let (back, _) = counted(spans_within(n, n, 1), "those pieces read back", |mut steps| image.canonical_spans_counted(&stored, &mut steps));
        assert_eq!(back, Some(whole.to_vec()), "{rows}: the one span they spell");
        assert!(first_over_descending(r, 1) > (prepared_within(n) + canonical_within(n, 1) + stored_within(n, 1, n)), "{rows}: the first spelling's steps");
        let wide: Vec<MemberSpan> = (0..LIST).map(|_| span(1, r)).collect();
        let (verdict, _) = counted(canonical_within(n, LIST), "a list of spans over descending runs", |mut steps| image.is_canonical_counted(&wide, &mut steps));
        assert_eq!(verdict, Some(true), "{rows}: no piece built for the verdict");
        let sixteenth = &wide[..LIST / 16];
        let within = stored_within(n, sixteenth.len(), sixteenth.len() * n);
        let (pieces, _) = counted(within, "a sixteenth of those spans, walked", |mut steps| {
            let rows = image.rows(&mut steps).expect("an image");
            assert!(rows.holds(sixteenth, &mut steps));
            rows.pieces(sixteenth, &mut steps).len()
        });
        assert_eq!(pieces, sixteenth.len() * n, "{rows}: a piece a run a span");
        assert!(first_over_descending(r, list) > (prepared_within(n) + canonical_within(n, LIST)), "{rows}: the first spelling's steps");
        // A FRAME's ends: the `from` and the `to` of a full `links` list,
        // each one span over the image — prepared once for all of them.
        let ends = 2 * list;
        let (_, frame) = counted(prepared_within(n) + ends * canonical_within(n, 1), "a frame's ends over one image", |mut steps| {
            let image = PositionImage::of(descending(rows));
            for _ in 0..ends {
                assert_eq!(image.is_canonical_counted(&whole, &mut steps), Some(true));
                assert_eq!(image.stored_counted(&[span(1, 1)], &mut steps).map(|stored| stored.len()), Some(1));
            }
        });
        assert!(ends * first_over_descending(r, 1) > frame, "{rows}: the first spelling's steps for the same ends");
        // Short runs on even addresses, and the wide run over them.
        let image = PositionImage::of(striped(rows - 1));
        counted(prepared_within(n), "the preparation", |mut steps| image.rows(&mut steps).is_some());
        let over: Vec<MemberSpan> = (0..LIST).map(|_| span(r, 2 * r - 1)).collect();
        let (verdict, judged_striped) = counted(canonical_within(n, LIST), "a list of spans over the wide run", |mut steps| image.is_canonical_counted(&over, &mut steps));
        assert_eq!(verdict, Some(false), "{rows}: the wide run's even addresses stand lower");
        assert!(judged_striped <= list + canonical_within(n, 1), "{rows}: every span held to the positions, a step each, and the search stopped at the first span");
        let (owed, _) = counted(row_within(n, LIST, LIST), "the row owed", |mut steps| image.canonical_row_counted(&over, LIST, &mut steps));
        let (owed, more) = owed.expect("an end");
        assert_eq!((owed.len(), more, &owed[..4]), (LIST, true, &[span(r, 1), span(1, 1), span(r + 2, 1), span(2, 1)][..]), "{rows}: the wide run's own position, then the short run's, by turns");
        let (stored, _) = counted(stored_within(n, LIST, LIST), "a list of spans over the wide run, stored", |mut steps| image.stored_counted(&over, &mut steps));
        assert_eq!(stored.map(|stored| stored.len()), Some(LIST), "{rows}: a piece a span");
        assert!(first_over_striped(r, list) > (prepared_within(n) + canonical_within(n, LIST) + row_within(n, LIST, LIST)), "{rows}: the first spelling's steps");
    }
}

/// THE FIRST SPELLING, COUNTED, where it can be run: over 4,096 runs — one
/// list's cap, a shot's runs before they took the store's number — one end
/// of each of the three shapes that fit there, and over 256 runs the two
/// whose pieces or rows outgrow any run of it. Its count is the formula's,
/// step for step, at every shape; its answer is the prepared image's; and
/// its count is past the prepared image's whole allowance for the same end,
/// the preparation included — 50,348,032 steps against 688,392 for one
/// span over one address at 4,096 runs.
///
/// Past these sizes the first spelling is not run: at the store's 65,536
/// runs its steps are the formulas' (the fence beside this one states
/// them), 256 times these and more.
#[test]
fn the_first_spelling_looks_at_every_row_for_every_piece_of_an_end() {
    let first = |image: &[Run], spans: &[MemberSpan]| {
        let mut steps = 0u64;
        let end = oracle::member_end(image, spans, &mut |n| steps += n);
        assert_eq!(PositionImage::of(image.to_vec()).end(spans), end, "one answer");
        (end.expect("an end"), steps)
    };
    let (rows, r, n) = (4_096u32, 4_096u64, 4_096usize);
    let (end, steps) = first(&one_address(rows), &[span(1, r)]);
    assert_eq!((steps, end.stored.len(), end.canonical.len()), (first_over_one_address(r), n, n), "one span over one address: a piece and a span a position");
    assert_eq!(steps, 50_348_032);
    let allowed = prepared_within(n) + canonical_within(n, 1) + row_within(n, 1, MAX_SLOT_SPANS);
    assert_eq!(allowed, 688_392, "what the prepared image is allowed for the same end: prepared, judged, its row read");
    assert!(steps > allowed);
    let ones: Vec<MemberSpan> = (0..1_024).map(|_| span(1, 1)).collect();
    let (end, steps) = first(&one_address(rows), &ones);
    assert_eq!((steps, end.stored.len(), end.canonical == ones), (first_over_one_position(r, 1_024), 1_024, true), "a quarter of a list of the first position");
    assert!(steps > (prepared_within(n) + canonical_within(n, 1_024) + stored_within(n, 1_024, 1_024)));
    let (end, steps) = first(&descending(rows), &[span(1, r)]);
    assert_eq!((steps, end.stored.len(), end.canonical), (first_over_descending(r, 1), n, vec![span(1, r)]), "one span over descending runs: a piece a run, one span");
    assert_eq!(steps, 16_801_792);
    assert!(steps > (prepared_within(n) + canonical_within(n, 1) + stored_within(n, 1, n)));
    // The two shapes that outgrow it, where they are small.
    let (rows, r, n) = (256u32, 256u64, 256usize);
    let wide: Vec<MemberSpan> = (0..16).map(|_| span(1, r)).collect();
    let (end, steps) = first(&descending(rows), &wide);
    assert_eq!((steps, end.stored.len(), end.canonical == wide), (first_over_descending(r, 16), 16 * n, true), "sixteen spans over descending runs: a piece a run a span");
    assert!(steps > (prepared_within(n) + canonical_within(n, 16) + stored_within(n, 16, 16 * n)));
    let over: Vec<MemberSpan> = (0..16).map(|_| span(r, 2 * r - 1)).collect();
    let (end, steps) = first(&striped(rows - 1), &over);
    assert_eq!((steps, end.stored.len(), end.canonical.len()), (first_over_striped(r, 16), 16, 16 * (2 * n - 1)), "sixteen spans over the wide run: a piece a span, a span a cut");
    assert!(steps > (prepared_within(n) + canonical_within(n, 16) + row_within(n, 16, 16 * (2 * n - 1))));
}
