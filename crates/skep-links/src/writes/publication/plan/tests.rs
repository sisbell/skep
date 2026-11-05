use skep_address::{validate, Nat, Tumbler};
use skep_arrangement::{head_lock_key, Base, MintedRun, ShotRun, VPos};
use skep_kernel::LockKey;
use skep_namespace::M3State;

use super::super::{publication_lock_keys, AlsoPlaces};
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
/// draft's alike — and each RE-WINDOWED draft's content key: the rendering
/// draft's where `places` carries a place, the `also` draft's where its
/// `also_places` entry carries one, neither's where its list carries none;
/// an `also` draft with no run of its identity takes no link key; the set
/// sorted and deduped.
#[test]
fn a_family_publication_takes_each_also_drafts_link_key_and_its_content_key_where_its_entry_carries_a_place() {
    let (edition, draft, other) = (a(&[1, 0, 1, 0, 3]), a(&[1, 0, 1, 0, 1]), a(&[1, 0, 1, 0, 2]));
    let other_ca = |k: u32| a(&[1, 0, 1, 0, 2, 0, 1, k]);
    let shot = |also: Vec<Address>, runs: Vec<ShotRun>| Shot { base: None, draft: Some(draft.clone()), also, runs };
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

/// THE LOCK SET's VERSION KEY: a member base takes its own `version_lock_key`
/// — the daughter chain's frontier — and the BARE DOCUMENT as the base takes
/// the FIRST member's, `D.1`'s, whether or not the chain holds a member yet:
/// once one stands the shot mints `D.1`'s daughter, and while none does the
/// shot mints `D.1` itself under the head key every shot takes, which the
/// set holds in either case; the birth shape, no base, takes neither.
#[test]
fn a_bare_base_takes_the_first_members_version_key_and_a_member_base_its_own() {
    let (edition, draft) = (a(&[1, 0, 1, 0, 3]), a(&[1, 0, 1, 0, 1]));
    let (first, second) = (a(&[1, 0, 1, 0, 3, 1]), a(&[1, 0, 1, 0, 3, 2]));
    let target = PublishTarget::Document(edition.clone());
    let none = PublishDeposits::default();
    let shot = |base: Option<Base>| Shot { base, draft: Some(draft.clone()), also: vec![], runs: vec![ShotRun { origin: draft.clone(), run: run(&ca(1), 2) }] };
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
// the plan being a pure function of the world and the request.

use serde::{Deserialize, Serialize};
use skep_arrangement::M5State;
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

/// The plan's world: M3's registrations, M7's links, M5 at genesis.
#[derive(Clone, Serialize, Deserialize)]
struct World {
    m3: M3State,
    links: LinkState,
    m5: M5State,
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

/// The edition `E`, the owner's third document, published.
fn trunk() -> Address {
    a(&[1, 0, 1, 0, 3])
}

/// `E.k`, a trunk member.
fn member(k: u32) -> Address {
    a(&[1, 0, 1, 0, 3, k])
}

/// `E.k.m`, a daughter of `E.k`.
fn daughter(k: u32, m: u32) -> Address {
    a(&[1, 0, 1, 0, 3, k, m])
}

/// The owner's other published document, the set `S`.
fn set() -> Address {
    a(&[1, 0, 1, 0, 4])
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
        .apply_m3(at, &M3Rec::allocate(a(&[1, 0, 1, 0, 2]), false))
        .apply_m3(at, &M3Rec::allocate(trunk(), true))
        .apply_m3(at, &M3Rec::allocate(set(), true))
        .apply_m3(at, &M3Rec::allocate(theirs(), true))
        .apply_m3(at, &M3Rec::allocate(member(1), true))
        .apply_m3(at, &M3Rec::allocate(member(2), true))
        .apply_m3(at, &M3Rec::allocate(daughter(1, 1), true));
    World { m3, links: LinkState::genesis(), m5: M5State::genesis() }
}

/// `world` with the claim `old → new` deposited at link `k` of `home`.
fn with_claim(world: World, home: &Address, k: u32, old: &Address, new: &Address) -> World {
    let rec = LinkRec::Deposit { addr: link_in(home, k).tumbler().clone(), value: supersession_claim(old, new) };
    world.apply(Seq(1), &rec)
}

/// A records-less shot off `base`, the whole arrangement empty.
fn off(base: &Address) -> Shot {
    Shot { base: Some(Base { member: base.clone(), extent: Nat::from(0u32) }), draft: None, also: vec![], runs: vec![] }
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
        ty: EndArg::Addrs(vec![NamedAddress::Address(a(&[1, 0, 1, 0, 3, 0, 3, 6, 1]))]),
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
    let price = super::super::price_publication_reads(&world, P1, &target, &shot, &[], &[], &deposits);
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
    assert_eq!(refused(supersede(vec![a(&[1, 0, 1, 0, 3, 0, 1, 1])])), not_member(0), "an element address");
    assert_eq!(refused(supersede(vec![theirs()])), not_member(0), "another account's document");
    assert_eq!(refused(supersede(vec![daughter(1, 1), member(2)])), PlanFault::Supersede { index: 1, cause: SupersedeCause::Base }, "the base");
    assert_eq!(
        refused(supersede(vec![daughter(1, 1), member(1), daughter(1, 1)])),
        PlanFault::Supersede { index: 2, cause: SupersedeCause::Duplicate },
        "a repeat, at the second"
    );
    let mint = PublishTarget::Mint { account: a(&[1, 0, 1]) };
    let birth = Shot { base: None, draft: None, also: vec![], runs: vec![] };
    assert_eq!(
        plan_deposits(&world, P1, &mint, &birth, &supersede(vec![daughter(1, 1)])).expect_err("refused"),
        not_member(0),
        "the mint form has no chain before the commit"
    );
    let both = PublishDeposits { read_with: vec![a(&[1, 0, 1, 0, 2])], supersede: vec![trunk()], ..PublishDeposits::default() };
    assert!(matches!(refused(both), PlanFault::ReadWith { index: 0, .. }), "(5) speaks ahead of (6)");
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
    let elsewhere = with_claim(chain_world(), &a(&[1, 0, 1, 0, 2]), 1, &daughter(1, 1), &a(&[1, 0, 1, 0, 2, 0, 2, 9]));
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
