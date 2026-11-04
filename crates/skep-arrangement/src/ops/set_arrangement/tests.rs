//! SET_ARRANGEMENT's in-crate claims, in a world assembled from the four
//! slices the op and its fixtures touch — M3 for the mints, M4 for the
//! bytes, M5 for the arrangement — a state built by the ops themselves
//! (`version`, `stage`, `insert`) over a seeded edition: the refusal order
//! the op states, each refusal writing nothing; the base's extent judged
//! against its own member's count, refused past it and recorded at it; a
//! head or a base naming a chain address no mint has made refused, and the
//! base recorded once a mint makes it; the landing's one commit — the
//! arrangement set, the base moved, the marker stamped — and the tell of a
//! moved head; a base absent moving nothing and a base without a merge
//! clearing the marker; the empty draft and the empty `runs`; the fork
//! gate's two answers and the free-standing draft admitted with nothing
//! moved, its head unchecked.

use serde::{Deserialize, Serialize};
use skep_content::{stage_write, ContentStore, ContentStretch, ContentWrite, Val};
use skep_kernel::{Kernel, Seq};
use skep_namespace::{M3Rec, PrincipalId};

use super::*;
use crate::error::SetArrangementError as E;
use crate::ops::MAX_PLACED_RUNS;
use crate::run::Run;
use crate::state::{DraftBase, M5State, Marker};
use crate::testutil::{a, ca, doc1, doc2, la, mem_kernel_of, n, pca, pdoc, rejected, run, seeded_m3, vca, vp};
use crate::Deposit;

#[derive(Clone, Serialize, Deserialize)]
struct LandWorld {
    m3: M3State,
    content: ContentStore,
    m5: M5State,
}

#[derive(Clone, Serialize, Deserialize)]
enum Rec {
    M3(M3Rec),
    Content(ContentWrite),
    Stretch(ContentStretch),
    M5(M5Rec),
}

impl From<M3Rec> for Rec {
    fn from(r: M3Rec) -> Rec {
        Rec::M3(r)
    }
}
impl From<ContentWrite> for Rec {
    fn from(r: ContentWrite) -> Rec {
        Rec::Content(r)
    }
}
impl From<ContentStretch> for Rec {
    fn from(r: ContentStretch) -> Rec {
        Rec::Stretch(r)
    }
}
impl From<M5Rec> for Rec {
    fn from(r: M5Rec) -> Rec {
        Rec::M5(r)
    }
}

impl WorldState for LandWorld {
    type Record = Rec;
    fn apply(&self, at: Seq, r: &Rec) -> LandWorld {
        match r {
            Rec::M3(x) => LandWorld { m3: self.m3.apply_m3(at, x), ..self.clone() },
            Rec::Content(x) => LandWorld { content: self.content.apply_write(x), ..self.clone() },
            Rec::Stretch(x) => LandWorld { content: self.content.apply_stretch(x), ..self.clone() },
            Rec::M5(x) => LandWorld { m5: self.m5.apply_m5(at, x), ..self.clone() },
        }
    }
}
impl HasM3 for LandWorld {
    fn m3(&self) -> &M3State {
        &self.m3
    }
}
impl HasContent for LandWorld {
    fn content(&self) -> &ContentStore {
        &self.content
    }
}
impl HasM5 for LandWorld {
    fn m5(&self) -> &M5State {
        &self.m5
    }
}

const P1: Caller = Caller::Principal(PrincipalId(1));
const P2: Caller = Caller::Principal(PrincipalId(2));

/// The seeded world: the published edition `pdoc` holding `a b c` at its
/// first three addresses, and the private draft `doc1` holding `x y` at its
/// own — a plain draft, never staged, the board recording no base for it.
fn seeded() -> Kernel<LandWorld> {
    let mut content = ContentStore::default();
    for (k, byte) in [(1u32, b'a'), (2, b'b'), (3, b'c')] {
        let cw = stage_write(&content, pca(k), Val::new(&[byte][..])).expect("written once");
        content = content.apply_write(&cw);
    }
    for (k, byte) in [(1u32, b'x'), (2, b'y')] {
        let cw = stage_write(&content, ca(k), Val::new(&[byte][..])).expect("written once");
        content = content.apply_write(&cw);
    }
    let m5 = M5State::genesis()
        .apply_m5(Seq(0), &M5Rec::ContentPlace { doc: pdoc(), at: n(1), runs: vec![run(&pca(1), 3)] })
        .apply_m5(Seq(0), &M5Rec::ContentPlace { doc: doc1(), at: n(1), runs: vec![run(&ca(1), 2)] });
    mem_kernel_of(LandWorld { m3: seeded_m3(), content, m5 })
}

/// The edition's first member, minted by `version`, and the staging draft of
/// it: `(member, draft)`, the draft holding the member's `a b c` by identity
/// with the member as its recorded base at three.
fn staged(k: &Kernel<LandWorld>) -> (Address, Address) {
    let vs = Vstream::new(k);
    let (member, _) = vs.version(PrincipalId(1), &pdoc(), None).expect("the edition's first member");
    assert_eq!(member, a(&[1, 0, 1, 0, 3, 1]));
    let (draft, _) = vs.stage(PrincipalId(1), &member).expect("the staging draft");
    assert_eq!(draft, a(&[1, 0, 1, 0, 4]));
    (member, draft)
}

fn now(k: &Kernel<LandWorld>) -> AsOf {
    AsOf::Typed(k.current_seq())
}

fn pair(member: &Address, extent: u32) -> Base {
    Base { member: member.clone(), extent: n(extent) }
}

/// A run of the edition's own words, `width` positions from `pca(start)`.
fn of_edition(start: u32, width: u32) -> ShotRun {
    ShotRun { origin: pdoc(), run: run(&pca(start), width) }
}

fn request(
    runs: Vec<ShotRun>,
    head: Option<Base>,
    base: Option<Base>,
    merge: Option<Vec<Address>>,
) -> SetArrangement {
    SetArrangement { runs, head, base, merge }
}

fn runs_of(k: &Kernel<LandWorld>, doc: &Address) -> Vec<Run> {
    k.snapshot().world().m5().content_runs(doc).cloned().collect()
}

fn base_of(k: &Kernel<LandWorld>, doc: &Address) -> Option<DraftBase> {
    k.snapshot().world().m5().draft_base(doc).cloned()
}

/// THE REFUSAL ORDER, each refusal writing nothing: the destination's own
/// four, then the head's three, the fork gate, the base's four, then the
/// runs — each pinned against the next by a request defective in both ways,
/// so a later verdict never speaks ahead of an earlier one; a defective run
/// is refused past the staged removal with nothing of the transaction kept.
#[test]
fn the_refusals_come_in_the_stated_order_and_each_writes_nothing() {
    let k = seeded();
    let (member, draft) = staged(&k);
    let vs = Vstream::new(&k);
    let fork = {
        let (fork, _) = vs.version(PrincipalId(2), &member, Some(false)).expect("a private fork of the member, the stranger's");
        fork
    };
    let before = k.current_seq();
    let good = || vec![of_edition(2, 2)];
    let bad_run = || vec![ShotRun { origin: doc1(), run: run(&pca(9), 1) }];
    // A document no mint has made, and an address in the edition's chain
    // that no mint has made either.
    let ghost = a(&[1, 0, 1, 0, 9]);
    let unminted = a(&[1, 0, 1, 0, 3, 9]);
    let unchanged = |what: &str| {
        assert_eq!(k.current_seq(), before, "{what}: a refusal commits nothing");
        assert_eq!(runs_of(&k, &draft), vec![run(&pca(1), 3)], "{what}: the draft's arrangement stands");
        assert_eq!(base_of(&k, &draft), Some(DraftBase { base: member.clone(), extent: n(3), source: member.clone(), merge: None }), "{what}: the record stands");
        assert_eq!(runs_of(&k, &doc1()), vec![run(&ca(1), 2)], "{what}: the plain draft stands");
        assert_eq!(runs_of(&k, &fork), vec![run(&pca(1), 3)], "{what}: the fork stands");
    };
    // Registration, then ω, then publication — with a bad run behind each.
    assert!(matches!(
        rejected(vs.set_arrangement(P1, &a(&[1, 0, 1, 0, 9]), &request(bad_run(), None, None, None), now(&k))),
        E::DocNotRegistered
    ));
    assert!(matches!(
        rejected(vs.set_arrangement(P2, &draft, &request(bad_run(), None, None, None), now(&k))),
        E::NotOwner(d) if d == draft
    ));
    assert!(matches!(
        rejected(vs.set_arrangement(P1, &pdoc(), &request(bad_run(), None, None, None), now(&k))),
        E::PublishedTarget
    ));
    // The typed state, ahead of the head's checks and the runs: typed
    // against the state before the stage, with a head off the chain.
    assert!(matches!(
        rejected(vs.set_arrangement(P1, &draft, &request(bad_run(), Some(pair(&doc1(), 1)), None, None), AsOf::Typed(Seq(0)))),
        E::ArrangementMoved { as_of: Seq(0), current } if current > Seq(0)
    ));
    unchanged("the destination's four");
    // The head: naming no registered document, ahead of its chain and its
    // extent; off the chain the recorded base lies in, ahead of its extent;
    // its extent past the head's count, ahead of the fork gate and of a base
    // off the chain.
    assert!(matches!(
        rejected(vs.set_arrangement(P1, &draft, &request(bad_run(), Some(pair(&ghost, 99)), None, None), now(&k))),
        E::SourceNotRegistered
    ));
    assert!(matches!(
        rejected(vs.set_arrangement(P1, &draft, &request(bad_run(), Some(pair(&doc1(), 99)), None, None), now(&k))),
        E::BaseNotInChain
    ));
    assert!(matches!(
        rejected(vs.set_arrangement(P1, &draft, &request(bad_run(), Some(pair(&member, 4)), Some(pair(&doc1(), 1)), None), now(&k))),
        E::BaseExtentTooLarge
    ));
    // The fork gate: the fork's source is the member, the head the trunk —
    // in the chain, under its count, not the source — ahead of the base's
    // and the runs' verdicts.
    assert!(matches!(
        rejected(vs.set_arrangement(P2, &fork, &request(bad_run(), Some(pair(&pdoc(), 3)), Some(pair(&pdoc(), 3)), None), now(&k))),
        E::ForkBaseMoved(source) if source == member
    ));
    assert!(matches!(
        rejected(vs.set_arrangement(P2, &fork, &request(bad_run(), Some(pair(&pdoc(), 99)), None, None), now(&k))),
        E::BaseExtentTooLarge
    ), "the extent ahead of the gate");
    // A head in the fork's chain that no mint has made: its registration
    // ahead of the gate, which would name the source.
    assert!(matches!(
        rejected(vs.set_arrangement(P2, &fork, &request(bad_run(), Some(pair(&unminted, 0)), None, None), now(&k))),
        E::SourceNotRegistered
    ), "the registration ahead of the gate");
    unchanged("the head's three");
    // The base to record: none recorded, ahead of its extent and of its
    // registration; naming no registered document, ahead of its chain, its
    // extent and the runs; off the chain, ahead of its extent — `doc1` holds
    // two; its extent past its member's count, the head passing, ahead of
    // the runs.
    assert!(matches!(
        rejected(vs.set_arrangement(P1, &doc1(), &request(bad_run(), Some(pair(&member, 3)), Some(pair(&member, 99)), None), now(&k))),
        E::NoBaseToRecord
    ));
    assert!(matches!(
        rejected(vs.set_arrangement(P1, &doc1(), &request(bad_run(), None, Some(pair(&ghost, 99)), None), now(&k))),
        E::NoBaseToRecord
    ), "nothing to record, ahead of the registration");
    assert!(matches!(
        rejected(vs.set_arrangement(P1, &draft, &request(bad_run(), None, Some(pair(&ghost, 99)), None), now(&k))),
        E::SourceNotRegistered
    ));
    assert!(matches!(
        rejected(vs.set_arrangement(P1, &draft, &request(bad_run(), None, Some(pair(&unminted, 0)), None), now(&k))),
        E::SourceNotRegistered
    ), "a base in the chain that no mint has made, ahead of the runs");
    assert!(matches!(
        rejected(vs.set_arrangement(P1, &draft, &request(bad_run(), None, Some(pair(&doc1(), 99)), None), now(&k))),
        E::BaseNotInChain
    ));
    assert!(matches!(
        rejected(vs.set_arrangement(P1, &draft, &request(bad_run(), Some(pair(&member, 3)), Some(pair(&member, 4)), Some(vec![])), now(&k))),
        E::BaseExtentTooLarge
    ));
    unchanged("the base's four");
    // The runs, as REINSTATE judges them — each refused past the removal
    // the body staged first, the transaction discarded whole.
    assert!(matches!(
        rejected(vs.set_arrangement(P1, &draft, &request(bad_run(), None, None, None), now(&k))),
        E::BadRun
    ));
    assert!(matches!(
        rejected(vs.set_arrangement(P1, &draft, &request(vec![ShotRun { origin: ghost.clone(), run: run(&a(&[1, 0, 1, 0, 9, 0, 1, 1]), 1) }], None, None, None), now(&k))),
        E::SourceNotRegistered
    ));
    assert!(matches!(
        rejected(vs.set_arrangement(P1, &draft, &request(vec![of_edition(3, 2)], None, None, None), now(&k))),
        E::DanglingSource
    ), "every address probed: the fourth holds nothing");
    let same: Vec<ShotRun> = std::iter::repeat_with(|| of_edition(1, 1)).take(MAX_PLACED_RUNS + 1).collect();
    assert!(matches!(
        rejected(vs.set_arrangement(P1, &draft, &request(same, None, None, None), now(&k))),
        E::TooManyRuns
    ));
    unchanged("the runs' four");
    // The control: the same draft takes a sound request.
    vs.set_arrangement(P1, &draft, &request(good(), None, None, None), now(&k)).expect("a sound request lands");
    assert_eq!(runs_of(&k, &draft), vec![run(&pca(2), 2)]);
}

/// THE BASE IS JUDGED AS THE HEAD IS (the owner's ruling N4): a base to
/// record whose extent passes its member's count is refused
/// `BaseExtentTooLarge` with nothing written — beside a head that passes,
/// the landing's shape, and alone, the undo's — judged against the base
/// member's count and never the draft's, which holds one more; an extent
/// AT the count records, the marker beside it.
#[test]
fn a_base_extent_past_its_members_count_is_refused_and_one_at_the_count_records() {
    let k = seeded();
    let (member, draft) = staged(&k);
    let vs = Vstream::new(&k);
    vs.insert(P1, &draft, vp(1, 4), vec![Val::new(&b"z"[..])], Deposit::Undeclared, now(&k)).expect("the draft's own word");
    assert_eq!(k.snapshot().world().m5().content_count(&draft), n(4), "the draft one past its base");
    let before = k.current_seq();
    let recorded = Some(DraftBase { base: member.clone(), extent: n(3), source: member.clone(), merge: None });
    assert!(matches!(
        rejected(vs.set_arrangement(P1, &draft, &request(vec![of_edition(2, 2)], Some(pair(&member, 3)), Some(pair(&member, 4)), Some(vec![vca(1)])), now(&k))),
        E::BaseExtentTooLarge
    ), "the landing's shape: the head at its count, the base past it");
    assert!(matches!(
        rejected(vs.set_arrangement(P1, &draft, &request(vec![of_edition(1, 3)], None, Some(pair(&member, 4)), None), now(&k))),
        E::BaseExtentTooLarge
    ), "the undo's shape: the base alone, past its count");
    assert_eq!(k.current_seq(), before, "a refusal commits nothing");
    assert_eq!(base_of(&k, &draft), recorded, "the record stands");
    assert_eq!(k.snapshot().world().m5().content_count(&draft), n(4), "the arrangement stands");
    let (at, _) = vs
        .set_arrangement(P1, &draft, &request(vec![of_edition(2, 2)], Some(pair(&member, 3)), Some(pair(&member, 3)), Some(vec![vca(1)])), now(&k))
        .expect("an extent at the count");
    assert_eq!(
        base_of(&k, &draft),
        Some(DraftBase {
            base: member.clone(),
            extent: n(3),
            source: member.clone(),
            merge: Some(Marker { sides: vec![vca(1)], head: member.clone(), head_copied: n(3), at }),
        }),
        "recorded at the count, the marker beside it"
    );
}

/// A HEAD OR A BASE NAMING NO MEMBER (PUB-6.37): an address of the draft's
/// chain that no mint has made — the trunk's next member, or a daughter of
/// the base — lies in the chain by its address and passes an extent of
/// zero, `content_count` answering zero for an address nothing arranges,
/// yet is refused `SourceNotRegistered` as the head beside a base that
/// passes and as the base to record, with nothing written; once `version`
/// mints the trunk's next member, the same base frame records it — the
/// reorder that refusal tells.
#[test]
fn a_head_or_base_naming_no_member_is_refused_and_one_minted_since_records() {
    let k = seeded();
    let (member, draft) = staged(&k);
    let vs = Vstream::new(&k);
    let next = a(&[1, 0, 1, 0, 3, 2]);
    let daughter = a(&[1, 0, 1, 0, 3, 1, 1]);
    let recorded = Some(DraftBase { base: member.clone(), extent: n(3), source: member.clone(), merge: None });
    let before = k.current_seq();
    for unminted in [&next, &daughter] {
        assert!(!k.snapshot().world().m3().is_registered_document(unminted), "{unminted:?}: no mint has made it");
        assert_eq!(trunk_of(unminted), pdoc(), "{unminted:?}: in the chain by its address");
        assert!(matches!(
            rejected(vs.set_arrangement(P1, &draft, &request(vec![of_edition(2, 2)], Some(pair(unminted, 0)), Some(pair(&member, 3)), Some(vec![])), now(&k))),
            E::SourceNotRegistered
        ), "{unminted:?} as the head, the base passing");
        assert!(matches!(
            rejected(vs.set_arrangement(P1, &draft, &request(vec![of_edition(2, 2)], None, Some(pair(unminted, 0)), None), now(&k))),
            E::SourceNotRegistered
        ), "{unminted:?} as the base to record");
    }
    assert_eq!(k.current_seq(), before, "a refusal commits nothing");
    assert_eq!(base_of(&k, &draft), recorded, "the record stands");
    assert_eq!(runs_of(&k, &draft), vec![run(&pca(1), 3)], "the arrangement stands");
    // The trunk's next member minted: the same base frame records it.
    let (second, _) = vs.version(PrincipalId(1), &pdoc(), None).expect("the second member");
    assert_eq!(second, next);
    vs.set_arrangement(P1, &draft, &request(vec![of_edition(2, 2)], None, Some(pair(&next, 0)), None), now(&k))
        .expect("the member a mint has made since");
    assert_eq!(
        base_of(&k, &draft),
        Some(DraftBase { base: next, extent: n(0), source: member, merge: None }),
        "the base recorded, the source kept"
    );
}

/// THE LANDING IS ONE COMMIT: the whole arrangement set by identity, the
/// base moved to the head told and the marker stamped with the commit's own
/// position — and THE TELL: a version published since the compose refuses
/// nothing, the base is recorded on the head used, and the answer names the
/// trunk's current head; a head that is the trunk's answers none.
#[test]
fn a_landing_sets_the_arrangement_moves_the_base_marks_the_merge_and_tells_a_moved_head() {
    let k = seeded();
    let (member, draft) = staged(&k);
    let vs = Vstream::new(&k);
    vs.insert(P1, &draft, vp(1, 4), vec![Val::new(&b"z"[..])], Deposit::Undeclared, now(&k)).expect("the draft's own word");
    assert_eq!(k.snapshot().world().m5().content_count(&draft), n(4));
    let before = k.current_seq();
    let (at, head_moved) = vs
        .set_arrangement(
            P1,
            &draft,
            &request(vec![of_edition(2, 2)], Some(pair(&member, 3)), Some(pair(&member, 3)), Some(vec![vca(1)])),
            now(&k),
        )
        .expect("the landing");
    assert_eq!(head_moved, None, "the head used is the trunk's head");
    assert_eq!(at, k.current_seq(), "one commit, the ack's position");
    assert!(at > before);
    assert_eq!(runs_of(&k, &draft), vec![run(&pca(2), 2)], "the whole arrangement, by identity");
    // The three records — the removal, the placement, the base record —
    // fold at the one commit's position: the arranged-at entry and the
    // marker's position are the ack's.
    assert_eq!(k.snapshot().world().m5().arranged_at(&draft), Some(at), "the typed state moves to the landing");
    assert_eq!(
        base_of(&k, &draft),
        Some(DraftBase {
            base: member.clone(),
            extent: n(3),
            source: member.clone(),
            merge: Some(Marker { sides: vec![vca(1)], head: member.clone(), head_copied: n(3), at }),
        }),
        "the base as told, the source kept, the marker stamped at the commit"
    );
    // The removed word's bytes stand in the store (NonDestruction).
    assert!(k.snapshot().world().m5().deletions(&draft).iter().next().is_some(), "the draft's own word is a deletion, its bytes kept");
    // A second member stands: the trunk moved past the head the merge was
    // composed on. The landing lands and tells.
    let (second, _) = vs.version(PrincipalId(1), &pdoc(), None).expect("the second member");
    assert_eq!(second, a(&[1, 0, 1, 0, 3, 2]));
    let (at2, head_moved) = vs
        .set_arrangement(P1, &draft, &request(vec![of_edition(1, 3)], Some(pair(&member, 3)), Some(pair(&member, 3)), Some(vec![])), now(&k))
        .expect("land and tell");
    assert_eq!(head_moved, Some(second.clone()), "the trunk's current head, told");
    assert_eq!(
        base_of(&k, &draft).and_then(|b| b.merge),
        Some(Marker { sides: vec![], head: member.clone(), head_copied: n(3), at: at2 }),
        "recorded on the head used, the sides empty for the draft-side shape"
    );
    assert_eq!(base_of(&k, &draft).map(|b| b.base), Some(member.clone()));
    // Composed on the trunk's head: nothing to tell.
    let (_, head_moved) = vs
        .set_arrangement(P1, &draft, &request(vec![of_edition(1, 3)], Some(pair(&second, 3)), Some(pair(&second, 3)), Some(vec![])), now(&k))
        .expect("on the head");
    assert_eq!(head_moved, None);
    assert_eq!(base_of(&k, &draft).map(|b| b.base), Some(second));
}

/// THE MARKER TRAVELS WITH THE BASE (the owner's ruling N3): where the
/// request names no base, nothing of the record moves — a plain
/// re-arrangement of a marked draft keeps base and marker, and a head with
/// a merge but no base records nothing; where it names a base and no
/// merge, the base moves and the marker is cleared — the undo's shape.
#[test]
fn a_base_absent_moves_nothing_and_a_base_without_a_merge_clears_the_marker() {
    let k = seeded();
    let (member, draft) = staged(&k);
    let vs = Vstream::new(&k);
    let (landed_at, _) = vs
        .set_arrangement(P1, &draft, &request(vec![of_edition(2, 2)], Some(pair(&member, 3)), Some(pair(&member, 3)), Some(vec![vca(1)])), now(&k))
        .expect("the landing");
    let marked = base_of(&k, &draft);
    assert!(marked.as_ref().is_some_and(|b| b.merge.as_ref().is_some_and(|m| m.at == landed_at)));
    // A plain re-arrangement: the arrangement moves, the record does not.
    vs.set_arrangement(P1, &draft, &request(vec![of_edition(1, 1)], None, None, None), now(&k)).expect("a plain re-arrangement");
    assert_eq!(runs_of(&k, &draft), vec![run(&pca(1), 1)]);
    assert_eq!(base_of(&k, &draft), marked, "base and marker stand");
    // A head and a merge with no base: admitted, nothing recorded.
    vs.set_arrangement(P1, &draft, &request(vec![of_edition(3, 1)], Some(pair(&member, 3)), None, Some(vec![])), now(&k)).expect("a head told, no base to record");
    assert_eq!(base_of(&k, &draft), marked, "the marker stands as it was: nothing moved");
    // The undo's shape: the old base, no merge — the marker cleared.
    let (undone_at, _) = vs
        .set_arrangement(P1, &draft, &request(vec![of_edition(1, 3)], None, Some(pair(&member, 3)), None), now(&k))
        .expect("the undo");
    assert_eq!(
        base_of(&k, &draft),
        Some(DraftBase { base: member.clone(), extent: n(3), source: member.clone(), merge: None }),
        "the base as told, the marker cleared"
    );
    assert_eq!(k.snapshot().world().m5().arranged_at(&draft), Some(undone_at));
    assert_eq!(runs_of(&k, &draft), vec![run(&pca(1), 3)]);
}

/// THE EMPTY COUNT AND THE EMPTY `runs`: a draft arranging nothing takes a
/// placement with no removal staged; an empty `runs` sets an empty
/// arrangement, admitted — the draft emptied, its typed state moved.
#[test]
fn an_empty_draft_takes_a_placement_and_an_empty_runs_empties_the_draft() {
    let k = seeded();
    let vs = Vstream::new(&k);
    assert_eq!(k.snapshot().world().m5().content_count(&doc2()), n(0));
    let (at, head_moved) = vs.set_arrangement(P1, &doc2(), &request(vec![of_edition(1, 2)], None, None, None), now(&k)).expect("into the empty draft");
    assert_eq!(head_moved, None);
    assert_eq!(runs_of(&k, &doc2()), vec![run(&pca(1), 2)]);
    assert_eq!(k.snapshot().world().m5().arranged_at(&doc2()), Some(at));
    let (emptied_at, _) = vs.set_arrangement(P1, &doc2(), &request(vec![], None, None, None), now(&k)).expect("the empty arrangement is admitted");
    assert_eq!(k.snapshot().world().m5().content_count(&doc2()), n(0));
    assert!(runs_of(&k, &doc2()).is_empty());
    assert_eq!(k.snapshot().world().m5().arranged_at(&doc2()), Some(emptied_at), "the removal moved the typed state");
    assert!(emptied_at > at);
    // Typed against the state before the emptying: refused, nothing wiped.
    assert!(matches!(
        rejected(vs.set_arrangement(P1, &doc2(), &request(vec![of_edition(3, 1)], None, None, None), AsOf::Typed(at))),
        E::ArrangementMoved { as_of, current } if as_of == at && current == emptied_at
    ));
    assert!(runs_of(&k, &doc2()).is_empty());
}

/// THE FORK GATE'S TWO ANSWERS AND THE FREE-STANDING DRAFT (the owner's
/// ruling N4, its precision P5): a fork whose source IS the head named is
/// admitted, gaining no base and no marker; a document with neither a
/// recorded base nor a published source — a plain draft, an alternative of
/// one — is admitted with its head unchecked and nothing moved.
#[test]
fn a_fork_is_admitted_where_its_source_is_the_head_and_a_free_standing_draft_gains_nothing() {
    let k = seeded();
    let (member, _) = staged(&k);
    let vs = Vstream::new(&k);
    let (fork, _) = vs.version(PrincipalId(2), &member, Some(false)).expect("the stranger's private fork");
    assert_eq!(k.snapshot().world().m5().fork_source(&fork), Some(&member));
    assert_eq!(base_of(&k, &fork), None);
    let (at, head_moved) = vs
        .set_arrangement(P2, &fork, &request(vec![of_edition(3, 1)], Some(pair(&member, 3)), None, Some(vec![vca(1)])), now(&k))
        .expect("the source is the head: admitted");
    assert_eq!(head_moved, None);
    assert_eq!(runs_of(&k, &fork), vec![run(&pca(3), 1)]);
    assert_eq!(base_of(&k, &fork), None, "no base, no marker");
    assert_eq!(k.snapshot().world().m5().fork_source(&fork), Some(&member), "the source stands, true");
    assert_eq!(k.snapshot().world().m5().arranged_at(&fork), Some(at));
    // The plain draft: no base, no source — the head unchecked.
    vs.set_arrangement(P1, &doc1(), &request(vec![of_edition(1, 1)], Some(pair(&member, 3)), None, Some(vec![])), now(&k)).expect("free-standing: admitted");
    assert_eq!(runs_of(&k, &doc1()), vec![run(&pca(1), 1)]);
    assert_eq!(base_of(&k, &doc1()), None);
    // A head no mint has made is unchecked there too: no chain to judge it
    // against, and nothing recorded of it.
    vs.set_arrangement(P1, &doc1(), &request(vec![of_edition(2, 1)], Some(pair(&a(&[1, 0, 1, 0, 3, 9]), 0)), None, None), now(&k))
        .expect("free-standing: the head unchecked");
    assert_eq!(runs_of(&k, &doc1()), vec![run(&pca(2), 1)]);
    assert_eq!(base_of(&k, &doc1()), None);
    // An alternative of the plain draft: its source a draft, so no fork —
    // a head off any chain is unchecked, and nothing moves.
    let (alternative, _) = vs.stage(PrincipalId(1), &doc1()).expect("an alternative of the plain draft");
    assert_eq!(k.snapshot().world().m5().fork_source(&alternative), Some(&doc1()));
    vs.set_arrangement(P1, &alternative, &request(vec![ShotRun { origin: doc1(), run: run(&ca(2), 1) }], Some(pair(&member, 3)), None, None), now(&k))
        .expect("free-standing: admitted");
    assert_eq!(runs_of(&k, &alternative), vec![run(&ca(2), 1)]);
    assert_eq!(base_of(&k, &alternative), None);
    // A link-subspace start is a bad run here as everywhere.
    assert!(matches!(
        rejected(vs.set_arrangement(P1, &alternative, &request(vec![ShotRun { origin: doc1(), run: run(&la(1), 1) }], None, None, None), now(&k))),
        E::BadRun
    ));
}
