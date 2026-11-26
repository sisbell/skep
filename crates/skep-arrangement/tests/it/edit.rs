//! EDIT (the one write a text edit and a merge's landing are both sent as):
//! a list of positional changes to one draft in one commit — what it admits
//! and refuses through the engine's world, that a call lands whole or not
//! at all, that the same arrangement reached by a change naming only what
//! differs and by one change over the draft's whole content is one state,
//! and that the record replays. Its in-crate suite pins the lock hold and
//! the refusal order (`src/ops/edit/tests.rs`).
//!
//! The helper [`set_whole`] says a draft's whole arrangement as one change
//! over `[1, n_C]`, which the suites that land a merge in a draft use.

use skep_address::Address;
use skep_arrangement::{
    AsOf, Base, Change, Deposit, Edit, EditError, HasM5, Placed, SetMerge, ShotRun, Vstream,
};
use skep_kernel::{Kernel, Seq, TxnError};
use skep_namespace::PrincipalId;
use tempfile::tempdir;

use crate::common::*;

/// A draft's whole arrangement and a landing's three terms.
#[derive(Clone)]
pub struct Whole {
    pub runs: Vec<ShotRun>,
    pub head: Option<Base>,
    pub base: Option<Base>,
    pub merge: Option<SetMerge>,
}

/// Sets `doc`'s whole arrangement to `whole.runs` by one edit of one change
/// over `[1, n_C]`, `n_C` the count the draft holds as the call is made, and
/// of no change where the draft is empty and so is the list. Answers the
/// commit position and the trunk's head where the head named is not it.
pub fn set_whole(
    k: &Kernel<World>,
    caller: skep_arrangement::Caller,
    doc: &Address,
    whole: &Whole,
    as_of: AsOf,
) -> Result<(Seq, Option<Address>), TxnError<EditError>> {
    let count = k.snapshot().world().m5().content_count(doc);
    let changes = if count == n(0) && whole.runs.is_empty() {
        Vec::new()
    } else {
        vec![Change { at: vp(1, 1), width: count, placed: Placed::Runs(whole.runs.clone()) }]
    };
    let request = Edit { changes, head: whole.head.clone(), base: whole.base.clone(), merge: whole.merge.clone() };
    Vstream::new(k).edit(caller, doc, request, as_of).map(|edited| (edited.at, edited.head_moved))
}

fn text(s: &str) -> Placed {
    Placed::Values(s.bytes().map(|b| val(&[b])).collect())
}

fn change(at: u32, width: u32, placed: Placed) -> Change {
    Change { at: vp(1, at), width: n(width), placed }
}

fn plain(changes: Vec<Change>) -> Edit {
    Edit { changes, head: None, base: None, merge: None }
}

/// A call of several changes lands as one commit, each change at its
/// position of the state the call was typed against: the text reads as
/// every change made, the minted bytes stand at consecutive addresses in
/// the request's order, and one refused change leaves the draft as it was.
#[test]
fn a_call_of_several_changes_lands_whole_or_not_at_all() {
    let k = mem_kernel();
    let vs = insert_abc(&k);
    let before = k.current_seq();
    // a b c → X a Y c Z: a placement at 1, b replaced, a placement at the end.
    let request = plain(vec![change(1, 0, text("X")), change(2, 1, text("Y")), change(4, 0, text("Z"))]);
    let refused = plain(vec![change(1, 0, text("X")), change(2, 1, text("Y")), change(5, 0, text("Z"))]);
    assert_eq!(rejected(vs.edit(P1, &doc1(), refused, now(&k))), EditError::OutOfBounds { change: 2 });
    assert_eq!(k.current_seq(), before, "nothing of the refused call stands");
    assert_eq!(bytes_of(&k.snapshot(), &doc1()), vec![b"a".to_vec(), b"b".to_vec(), b"c".to_vec()]);
    let edited = vs.edit(P1, &doc1(), request, now(&k)).expect("the call lands");
    let snap = k.snapshot();
    assert_eq!(edited.at, snap.seq(), "one commit");
    assert_eq!(
        bytes_of(&snap, &doc1()),
        [&b"X"[..], b"a", b"Y", b"c", b"Z"].map(<[u8]>::to_vec).to_vec()
    );
    assert_eq!(edited.minted, Some(ca(4)), "the first address minted, past the three the draft held");
    assert_eq!(
        content_runs_of(&snap, &doc1()),
        vec![
            skep_arrangement::Run::new(ca(4), n(1)).unwrap(),
            skep_arrangement::Run::new(ca(1), n(1)).unwrap(),
            skep_arrangement::Run::new(ca(5), n(1)).unwrap(),
            skep_arrangement::Run::new(ca(3), n(1)).unwrap(),
            skep_arrangement::Run::new(ca(6), n(1)).unwrap(),
        ],
        "X, Y and Z minted in the request's order"
    );
    // The removed `b` reads as deleted, and the draft still holds it in R.
    assert!(!snap.world().m5().deletions(&doc1()).is_empty());
    // A call typed before that commit is refused, nothing written.
    assert!(matches!(
        rejected(vs.edit(P1, &doc1(), plain(vec![change(1, 1, Placed::Runs(vec![]))]), AsOf::Typed(before))),
        EditError::ArrangementMoved { as_of, current } if as_of == before && current == edited.at
    ));
}

/// The same arrangement, reached two ways, is one state: a change that
/// names only the stretch that differs, and one change over the draft's
/// whole content placing every run. The list, what R answers, the base, the
/// marker and the position each agree.
#[test]
fn a_change_naming_what_differs_leaves_the_state_one_change_over_the_whole_leaves() {
    // Each world: the edition `a b c`, its first member, a draft staged
    // from it, and a second draft of words the landing brings in.
    let world = || {
        let k = mem_kernel();
        let vs = deposit_abc(&k);
        vs.insert(P1, &doc1(), vp(1, 1), vec![val(b"x"), val(b"y")], Deposit::Undeclared, now(&k)).expect("the side's words");
        let (member, _) = vs.version(PrincipalId(1), &pdoc(), None).expect("the first member");
        let (draft, _) = vs.stage(PrincipalId(1), &member).expect("the staging draft");
        (k, member, draft)
    };
    let terms = |member: &Address| {
        let head = base(member, 3);
        (Some(head.clone()), Some(head), Some(SetMerge { sides: vec![doc1()], at: None }))
    };
    // The merged text: a x y c — the draft's `b` replaced by the side's two.
    let (whole, member, draft) = world();
    let (head, base_, merge) = terms(&member);
    let merged = vec![shot_run(&pdoc(), &pca(1), 1), shot_run(&doc1(), &ca(1), 2), shot_run(&pdoc(), &pca(3), 1)];
    let (whole_at, _) = set_whole(&whole, P1, &draft, &Whole { runs: merged, head, base: base_, merge }, now(&whole)).expect("the whole list");
    let (net, member, draft_net) = world();
    assert_eq!(draft_net, draft, "the two worlds are built alike");
    let (head, base_, merge) = terms(&member);
    let one = Edit { changes: vec![change(2, 1, Placed::Runs(vec![shot_run(&doc1(), &ca(1), 2)]))], head, base: base_, merge };
    let edited = Vstream::new(&net).edit(P1, &draft, one, now(&net)).expect("the stretch that differs");
    assert_eq!(edited.at, whole_at, "the same position in each world");
    let (a, b) = (whole.snapshot(), net.snapshot());
    let (a5, b5) = (a.world().m5(), b.world().m5());
    assert!(a5.content_runs(&draft).eq(b5.content_runs(&draft)), "one list");
    assert_eq!(a5.draft_base(&draft), b5.draft_base(&draft), "one base and one marker");
    assert_eq!(a5.arranged_at(&draft), b5.arranged_at(&draft));
    assert_eq!(a5.deletions(&draft), b5.deletions(&draft), "what R answers of the draft");
    for placed in [pca(1), pca(2), pca(3), ca(1), ca(2)] {
        let coverage = coverage_of(&skep_arrangement::Run::new(placed, n(1)).unwrap());
        assert_eq!(a5.docs_ever_containing(&coverage), b5.docs_ever_containing(&coverage));
        assert!(b5.docs_ever_containing(&coverage).contains(&draft));
    }
    // The whole list re-placed every run and appended a span for each; the
    // change appended the one run it placed.
    assert!(a5.recorded_span_count(&draft) > b5.recorded_span_count(&draft));
}

/// The record replays: a journal holding edits of both kinds, a landing
/// that changes no position among them, reopens to the state the live
/// kernel held.
#[test]
fn the_edits_record_survives_a_journal_replay() {
    let dir = tempdir().expect("a scratch directory");
    let (live, draft) = {
        let k = Kernel::open(cfg_fsync(dir.path()), genesis()).expect("open");
        let vs = deposit_abc(&k);
        let (member, _) = vs.version(PrincipalId(1), &pdoc(), None).expect("the first member");
        let (draft, _) = vs.stage(PrincipalId(1), &member).expect("the staging draft");
        vs.edit(P1, &draft, plain(vec![change(1, 0, text("pq")), change(2, 1, text("r")), change(4, 0, Placed::Runs(vec![shot_run(&pdoc(), &pca(1), 1)]))]), now(&k))
            .expect("values and runs");
        let head = base(&member, 3);
        let landing = Edit { changes: vec![], head: Some(head.clone()), base: Some(head), merge: Some(SetMerge { sides: vec![], at: None }) };
        vs.edit(P1, &draft, landing, now(&k)).expect("a landing of no change");
        (k.snapshot().world().m5().clone(), draft)
    };
    let reopened = Kernel::open(cfg_fsync(dir.path()), genesis()).expect("reopen");
    let snap = reopened.snapshot();
    assert_eq!(snap.world().m5(), &live, "replay re-derives the slice");
    assert_eq!(snap.world().m5().content_count(&draft), n(6), "p q a r c and the edition's a");
}
