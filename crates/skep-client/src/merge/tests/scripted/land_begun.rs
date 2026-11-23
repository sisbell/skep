//! A landing begun and never recorded, over the scripted board (skep #1103).
//!
//! The suite checks that a landing cut off before its record is named,
//! never landed twice, and recorded by a `resume` naming its draft; that
//! one begun before a take-back elsewhere, in a draft its record's
//! take-back left, or in a draft with no recorded base re-arranged since,
//! is named, and one undone since stages afresh; and that
//! a landing of other sides, one in another account's draft, one recorded
//! in another state and a merge landed in its own side are no landing
//! begun of the merge at hand.

use super::*;

/// The draft landing's world, its head minted where its row says.
///
/// `D.2` is registered from the position its `publish` row names, the
/// `at` its `doc_metadata` serves, which a walk for a landing begun
/// starts past.
fn minted_head_world() -> World {
    let mut w = draft_landing_world();
    let head = format!("{D}.2");
    let minted = w
        .rows
        .iter()
        .find(|r| r.op == "publish" && r.docs[0] == head)
        .expect("the head's mint")
        .at;
    let d = w.docs.get_mut(&head).unwrap();
    let runs = d.history.remove(&0).expect("the head as planted");
    d.history.insert(minted, runs);
    w
}

/// Returns the position the head `D.2`'s `publish` row names.
fn head_minted(dialer: &Scripted) -> u64 {
    dialer
        .world()
        .rows
        .iter()
        .find(|r| r.op == "publish" && r.docs[0] == format!("{D}.2"))
        .expect("the head's mint")
        .at
}

/// Lands `inputs`' merge in `into`, or a fresh draft where `None`, cut off
/// before its record.
///
/// Over `world`, the session dies at the record's atom (wire.md
/// §Sessions), its place among the requests read off the same landing
/// made whole: the stage, where one is sent, and the one write stand, no
/// record. The death is then undone and the session's memo dropped, as a
/// fresh session finds the board. Answers the dialer, the board and the
/// hand, with the draft landed in and the landing's position.
fn cut_off_before_the_record(
    world: fn() -> World,
    inputs: &Inputs,
    into: Option<&str>,
) -> (Arc<Scripted>, Board, HybridSigner, Address, u64) {
    let atom = {
        let (dialer, board, signer) = open(world());
        let session = sign_in(&board, &signer);
        let merged = compose(&board, Some(session.token()), inputs).expect("composed");
        dialer.clear();
        land(&board, &merged, draft_landing(&session, &signer, into.map(a)))
            .expect("the premise: landed whole");
        1 + dialer
            .requests()
            .iter()
            .position(|(line, _)| line == "insert")
            .expect("the record's atom")
    };
    let (dialer, board, signer) = open(world());
    {
        let session = sign_in(&board, &signer);
        let merged = compose(&board, Some(session.token()), inputs).expect("composed");
        dialer.clear();
        dialer.world().die_at = Some(atom);
        let err = land(&board, &merged, draft_landing(&session, &signer, into.map(a)))
            .expect_err("the session ended");
        let Refusal::SessionEnded(Halt::Halt(face)) = &err else {
            panic!("the death at the atom: {err:?}")
        };
        assert_eq!(face.act, OnEnd::Resume.act(), "a landing's way on");
    }
    let mut w = dialer.world();
    w.die_at = None;
    w.memo.clear();
    let row = w
        .rows
        .iter()
        .rev()
        .find(|r| r.op == "set_arrangement")
        .expect("the landing's one write");
    let (fresh, at) = (a(&row.docs[0]), row.at);
    assert!(w.links.iter().all(|l| l.ty != K), "the premise: no record linked");
    drop(w);
    (dialer, board, signer, fresh, at)
}

/// A landing cut off before its record is named, never landed twice.
///
/// The draft landing's merge lands in a fresh draft `L` and the session
/// dies at the record's atom, the stage and the one write standing with
/// no record. In a fresh session the merge is composed again, past the
/// landing's position, and `resume` and `land` with no draft named each
/// answer `Refusal::LandingBegun` naming `L` and the landing's position,
/// nothing staged or written — a landing naming a published journal too,
/// the landing begun answered before the journal is checked — the
/// merger's drafts' rows walked on the supplement past the head's mint,
/// never past the composition's position (the mutant that walks past
/// `as_of` stages a second draft), the refusal's words naming the ways
/// on. Landed naming `L`, the
/// composition made again runs every check again — one `set_arrangement`
/// typed at its own position and one record, nothing staged — and a
/// fresh landing then finds it standing.
#[test]
fn a_landing_cut_off_before_its_record_is_named_never_landed_twice() {
    let (dialer, board, signer, l, at) =
        cut_off_before_the_record(minted_head_world, &draft_inputs(), None);
    let session = sign_in(&board, &signer);
    let fresh = || draft_landing(&session, &signer, None);
    let again =
        compose(&board, Some(session.token()), &draft_inputs()).expect("composed again");
    assert!(again.as_of > at, "the premise: composed past the landing");
    let begun = Refusal::LandingBegun { draft: l.clone(), position: at };
    let rows = dialer.world().rows.len();
    dialer.clear();
    assert_eq!(resume(&board, &again, fresh()), Err(begun.clone()), "the resume names it");
    assert_eq!(land(&board, &again, fresh()), Err(begun.clone()), "the landing names it");
    let published_journal = Landing::Draft {
        merger: merger(&session, &signer),
        into: None,
        journal: Some(a(DOC1)),
    };
    assert_eq!(
        land(&board, &again, published_journal),
        Err(begun.clone()),
        "named before a journal named is checked"
    );
    let ops = dialer.ops();
    let writes = ["stage", "set_arrangement", "create_new_document", "insert", "make_link"];
    assert!(
        ops.iter().all(|o| !writes.contains(&o.as_str())),
        "nothing staged or written: {ops:?}"
    );
    assert_eq!(dialer.world().rows.len(), rows, "nothing committed");
    let walk =
        format!("GET /changes?since={}&under={ACCOUNT}&drafts=true", head_minted(&dialer));
    let walks: Vec<&String> = ops.iter().filter(|o| o.starts_with("GET /changes?")).collect();
    assert_eq!(
        walks,
        [&walk, &walk, &walk],
        "the merger's drafts walked past the head's mint, at each call"
    );
    let words = begun.to_string();
    for said in [
        format!("this merge already landed in {l} at position {at}, and its record is not written"),
        "nothing was staged or written, so the merge does not land twice".to_string(),
        format!("land it naming {l} (the command's --into {l}), which runs every check again and writes its record"),
        format!("resume naming {l}, which writes the record alone"),
        format!("undo it naming {l} (the command's --undo {l})"),
    ] {
        assert!(words.contains(&said), "the words say {said:?}: {words}");
    }
    // The way on: landed naming L, every check run again.
    dialer.clear();
    let landed = land(&board, &again, draft_landing(&session, &signer, Some(l.clone())))
        .expect("landed naming L");
    let Landed::Draft { into, position, staged, .. } = &landed else { panic!("{landed:?}") };
    assert_eq!((into, *staged), (&l, false), "{landed:?}");
    let wrote: Vec<String> = dialer
        .ops()
        .into_iter()
        .filter(|o| ["stage", "set_arrangement", "insert", "make_link"].contains(&o.as_str()))
        .collect();
    assert_eq!(
        wrote,
        ["set_arrangement", "insert", "make_link"],
        "one write and one record, nothing staged"
    );
    assert_eq!(
        dialer.frames("set_arrangement")[0]["as_of"].as_u64(),
        Some(again.as_of),
        "typed against the composition made again"
    );
    assert_eq!(
        appended_record(&dialer)["landed"],
        json!({"draft": l.to_string(), "position": position})
    );
    dialer.clear();
    assert_eq!(land(&board, &again, fresh()), Ok(as_found(&landed)), "found standing");
    assert!(dialer.frames("stage").is_empty(), "nothing staged: {:?}", dialer.ops());
}

/// A landing begun and undone since stages afresh.
///
/// After the cut-off, `L`'s landing is taken back, the undo's one write
/// clearing its marker and writing no record, none standing for the
/// landing. Its landing's row still names the merge, but the board marks
/// no landing of it in `L` as `L` stands, so none is begun: `resume`
/// with no draft named answers none, and `land` stages a draft of its
/// own (the mutant that takes a draft its row names without reading its
/// mark answers `LandingBegun`).
#[test]
fn a_landing_begun_and_undone_since_stages_afresh() {
    let (dialer, board, signer, l, _) =
        cut_off_before_the_record(minted_head_world, &draft_inputs(), None);
    let session = sign_in(&board, &signer);
    let undone =
        undo(&board, merger(&session, &signer), &l, &a(K), None, None).expect("undone");
    assert_eq!(
        (undone.record, dialer.world().standing(&l.to_string()).1),
        (None, None),
        "the premise: the marker cleared, no record"
    );
    let again =
        compose(&board, Some(session.token()), &draft_inputs()).expect("composed again");
    assert_eq!(
        resume(&board, &again, draft_landing(&session, &signer, None)),
        Ok(None),
        "nothing landed"
    );
    let landed = land(&board, &again, draft_landing(&session, &signer, None)).expect("landed");
    let Landed::Draft { into, staged, .. } = &landed else { panic!("{landed:?}") };
    assert!(*staged && *into != l, "a draft of its own: {landed:?}");
}

/// A landing begun of other sides is not this merge's.
///
/// A merge of the draft `T` on the same head lands in a fresh draft and
/// is cut off before its record. The draft landing's merge of `S`,
/// composed on that head, finds no landing of its own begun: the row of
/// `T`'s landing names other sides, so its draft is never read, and the
/// landing stages a draft of its own (the mutant that matches a row by
/// its head alone reads that draft).
#[test]
fn a_landing_begun_of_other_sides_is_not_this_merges() {
    const T: &str = "1.0.1.0.67";
    let world = || {
        let mut w = minted_head_world();
        w.text(T, 1, "??");
        w.doc(T, false, ACCOUNT, vec![run(D, 1, 11), run(T, 1, 2)]);
        w.staged(T, &format!("{D}.1"), 11);
        w
    };
    let of_t =
        Inputs { sides: vec![Side::Draft { at: a(T), position: None }], ..draft_inputs() };
    let (dialer, board, signer, theirs, _) = cut_off_before_the_record(world, &of_t, None);
    let session = sign_in(&board, &signer);
    let merged =
        compose(&board, Some(session.token()), &draft_inputs()).expect("the merge of S");
    dialer.clear();
    let landed = land(&board, &merged, draft_landing(&session, &signer, None)).expect("landed");
    let Landed::Draft { into, staged, .. } = &landed else { panic!("{landed:?}") };
    assert!(*staged && *into != theirs, "a draft of its own: {landed:?}");
    let read: Vec<Value> =
        dialer.frames("doc_metadata").iter().map(|f| f["doc"].clone()).collect();
    assert!(
        !read.contains(&json!(theirs.to_string())),
        "the other merge's draft never read: {read:?}"
    );
}

/// A cut-off landing is recorded by a `resume` naming its draft.
///
/// After the cut-off, the merge composed again in a fresh session and
/// resumed naming `L` finds the landing the board marks there, `L`
/// holding M, and writes its one record — no stage and no
/// `set_arrangement` — answering the landing at its position: the
/// record-only completion, which no search for a landing begun stands
/// before (the mutant that searches on a draft named answers
/// `LandingBegun`). A fresh landing then finds it standing, and the
/// `resume` again writes nothing.
#[test]
fn a_landing_cut_off_before_its_record_is_completed_by_resume_naming_it() {
    let (dialer, board, signer, l, at) =
        cut_off_before_the_record(minted_head_world, &draft_inputs(), None);
    let session = sign_in(&board, &signer);
    let into_l = || draft_landing(&session, &signer, Some(l.clone()));
    let again =
        compose(&board, Some(session.token()), &draft_inputs()).expect("composed again");
    dialer.clear();
    let resumed = resume(&board, &again, into_l()).expect("resumed").expect("the landing");
    let Landed::Draft { into, position, staged, head_moved, .. } = &resumed else {
        panic!("{resumed:?}")
    };
    assert_eq!((into, *position, *staged, head_moved), (&l, at, false, &None), "{resumed:?}");
    let wrote: Vec<String> = dialer
        .ops()
        .into_iter()
        .filter(|o| ["stage", "set_arrangement", "insert", "make_link"].contains(&o.as_str()))
        .collect();
    assert_eq!(wrote, ["insert", "make_link"], "the record alone");
    assert_eq!(
        appended_record(&dialer)["landed"],
        json!({"draft": l.to_string(), "position": at})
    );
    assert_eq!(
        land(&board, &again, draft_landing(&session, &signer, None)),
        Ok(resumed.clone()),
        "found standing"
    );
    dialer.clear();
    assert_eq!(resume(&board, &again, into_l()), Ok(Some(resumed)), "the same landing");
    assert!(
        dialer.frames("insert").is_empty() && dialer.frames("make_link").is_empty(),
        "nothing written twice: {:?}",
        dialer.ops()
    );
}

/// A landing begun in another account's draft is not the merger's.
///
/// A draft of a sub-account of the merger's, which the merger's
/// supplement carries beside its own account's, holds this merge's
/// landing, marked with its head and sides, and no record names it. A
/// fresh landing of the merge keeps the rows of drafts of the merger's
/// own account, exactly, so that draft is never read and the landing
/// stages a draft of its own (the mutant that keeps every row under the
/// account's prefix answers `LandingBegun` naming it).
#[test]
fn a_landing_begun_in_another_accounts_draft_is_not_the_mergers() {
    const THEIRS: &str = "1.0.1.1.0.5";
    let head = format!("{D}.2");
    let mut w = minted_head_world();
    w.doc(THEIRS, false, "1.0.1.1", draft_m());
    w.docs.get_mut(THEIRS).unwrap().staged.insert(0, (head.clone(), 15));
    let at = w.commit_records("set_arrangement", vec![THEIRS.to_string()], 3);
    let marker = Marker { sides: vec![S.to_string()], head: head.clone(), head_copied: 15, at };
    let d = w.docs.get_mut(THEIRS).unwrap();
    d.history.insert(at, draft_m());
    d.markers.insert(at, Some(marker.clone()));
    d.stamped.push(marker);
    w.rows.last_mut().unwrap().terms =
        Some((Some(head.clone()), Some(json!({"sides": [S], "head": head}))));
    let (dialer, board, signer) = open(w);
    let session = sign_in(&board, &signer);
    let merged = compose(&board, Some(session.token()), &draft_inputs()).expect("composed");
    dialer.clear();
    let landed = land(&board, &merged, draft_landing(&session, &signer, None)).expect("landed");
    let Landed::Draft { into, staged, .. } = &landed else { panic!("{landed:?}") };
    assert!(*staged && into.to_string() != THEIRS, "a draft of its own: {landed:?}");
    let read: Vec<Value> =
        dialer.frames("doc_metadata").iter().map(|f| f["doc"].clone()).collect();
    assert!(!read.contains(&json!(THEIRS)), "the sub-account's draft never read: {read:?}");
}

/// A landing recorded in another state is no landing begun.
///
/// Case (j)'s fork `F` lands in a fresh draft `L` with its record, and
/// the forker edits the fork: the merge composed again is another key,
/// no record of it standing, while `L` still carries the merge as the
/// board marks it. The merger's record of the merge in its first state
/// names `L`, so `L` holds no landing begun: `resume` with no draft named
/// answers none, and a fresh landing of the new key stages a draft of its
/// own (the mutant that passes over only the drafts the newest record of
/// the key names answers `LandingBegun` naming `L`).
#[test]
fn a_landing_recorded_in_another_state_is_no_landing_begun() {
    let mut w = World::race();
    w.fork(F, "1.0.2", &format!("{D}.1"), vec![run(D, 1, 7)]);
    let (dialer, board, signer) = open(w);
    let session = sign_in(&board, &signer);
    let inputs = Inputs { sides: vec![Side::Fork(a(F))], ..race_inputs() };
    let merged = compose(&board, Some(session.token()), &inputs).expect("composed");
    let first = land(&board, &merged, draft_landing(&session, &signer, None)).expect("landed");
    let Landed::Draft { into: l, position, .. } = first else { panic!("{first:?}") };
    dialer.world().change(F, vec![run(D, 5, 3)]);
    let again = compose(&board, Some(session.token()), &inputs).expect("composed again");
    assert_ne!(again.key, merged.key, "the premise: another key");
    assert_eq!(
        dialer.world().standing(&l.to_string()).1.map(|m| m.at),
        Some(position),
        "the premise: L carries the merge"
    );
    assert_eq!(
        resume(&board, &again, draft_landing(&session, &signer, None)),
        Ok(None),
        "nothing of the new key landed"
    );
    let landed = land(&board, &again, draft_landing(&session, &signer, None)).expect("landed");
    let Landed::Draft { into, staged, .. } = &landed else { panic!("{landed:?}") };
    assert!(*staged && *into != l, "a draft of its own: {landed:?}");
}

/// A landing begun before a take-back elsewhere is named.
///
/// The merge lands in the draft `X`, named, the board too busy to find
/// the account's journal, so no record names it; then in `Y`, named, with
/// its record, and `Y`'s landing is taken back, the undo's record
/// replacing `Y`'s. Composed again, the merge's newest record is the
/// undo's, which names no landing, and a fresh landing walks the
/// merger's drafts past the head's mint whatever record stands: `X`'s
/// landing is named at the position its marker names, at a `resume` and
/// a landing alike, nothing staged (the mutant that walks only past the
/// newest record stages a second landing).
#[test]
fn a_landing_begun_before_a_take_back_elsewhere_is_named() {
    const X: &str = "1.0.1.0.67";
    const Y: &str = "1.0.1.0.68";
    let mut w = minted_head_world();
    for draft in [X, Y] {
        w.doc(draft, false, ACCOUNT, vec![run(D, 1, 11)]);
        w.staged(draft, &format!("{D}.1"), 11);
    }
    let (dialer, board, signer) = open(w);
    let session = sign_in(&board, &signer);
    let into = |draft: &str| draft_landing(&session, &signer, Some(a(draft)));
    let merged = compose(&board, Some(session.token()), &draft_inputs()).expect("composed");
    too_busy_for_the_find(&mut dialer.world());
    let err = land(&board, &merged, into(X)).expect_err("X's record unwritten");
    let Refusal::Halt(Halt::Halt(face)) = &err else { panic!("{err:?}") };
    assert!(face.state.contains(&format!("the merge stands at {X}")), "the premise: {face}");
    let x_at = dialer.world().standing(X).1.expect("the premise: X marked").at;
    land(&board, &merged, into(Y)).expect("landed in Y");
    let undone = undo(&board, merger(&session, &signer), &a(Y), &a(K), None, None)
        .expect("Y's landing undone");
    assert!(undone.record.is_some(), "the premise: the undo's record replaces Y's");
    let again =
        compose(&board, Some(session.token()), &draft_inputs()).expect("composed again");
    let begun = Refusal::LandingBegun { draft: a(X), position: x_at };
    assert_eq!(
        resume(&board, &again, draft_landing(&session, &signer, None)),
        Err(begun.clone()),
        "the resume names X"
    );
    dialer.clear();
    assert_eq!(
        land(&board, &again, draft_landing(&session, &signer, None)),
        Err(begun),
        "the landing names X"
    );
    assert!(dialer.frames("stage").is_empty(), "nothing staged: {:?}", dialer.ops());
}

/// A landing begun in a draft its record's take-back left is named.
///
/// The merge lands in the draft `X`, named, with its record, and that
/// landing is undone, the undo's record replacing the landing's. The
/// merge composed again lands in `X` once more, a write of its own, and
/// the board is too busy to find the account's journal, so no record
/// names this landing: the first one's record names `X` but a take-back
/// replaced it, so it stands for no landing there. Composed again, a
/// fresh landing names `X`'s landing begun at the second write's
/// position, nothing staged (the mutant that counts every record naming
/// a draft stages a second landing).
#[test]
fn a_landing_begun_in_a_draft_its_records_take_back_left_is_named() {
    const X: &str = "1.0.1.0.67";
    let mut w = minted_head_world();
    w.doc(X, false, ACCOUNT, vec![run(D, 1, 11)]);
    w.staged(X, &format!("{D}.1"), 11);
    let (dialer, board, signer) = open(w);
    let session = sign_in(&board, &signer);
    let into_x = || draft_landing(&session, &signer, Some(a(X)));
    let merged = compose(&board, Some(session.token()), &draft_inputs()).expect("composed");
    land(&board, &merged, into_x()).expect("landed in X");
    let undone =
        undo(&board, merger(&session, &signer), &a(X), &a(K), None, None).expect("undone");
    assert!(undone.record.is_some(), "the premise: the undo's record replaces the landing's");
    let again =
        compose(&board, Some(session.token()), &draft_inputs()).expect("composed again");
    too_busy_for_the_find(&mut dialer.world());
    let err = land(&board, &again, into_x()).expect_err("the record unwritten");
    let Refusal::Halt(Halt::Halt(face)) = &err else { panic!("{err:?}") };
    assert!(face.state.contains(&format!("the merge stands at {X}")), "the premise: {face}");
    let at = dialer.world().standing(X).1.expect("the premise: X marked").at;
    let third =
        compose(&board, Some(session.token()), &draft_inputs()).expect("composed a third time");
    dialer.clear();
    assert_eq!(
        land(&board, &third, draft_landing(&session, &signer, None)),
        Err(Refusal::LandingBegun { draft: a(X), position: at }),
        "the landing since the take-back named"
    );
    assert!(dialer.frames("stage").is_empty(), "nothing staged: {:?}", dialer.ops());
}

/// A merge landed in its own side is no landing begun of a later one.
///
/// The draft landing's merge lands in `S`, its own draft side, with its
/// record. That landing moves `S`'s base to the head and its text to M,
/// so the merge composed again reads another `S` over another base: a
/// key of its own, with no record. `S` carries the first landing's mark,
/// naming the head and no side, as a landing of the new composition in
/// `S` would; but a side of the merge is the draft the composition
/// reads, never one a landing of it was begun in, so a fresh landing
/// stages a draft of its own (the mutant that keeps a side among the
/// drafts read answers `LandingBegun` naming `S`).
#[test]
fn a_merge_landed_in_its_own_side_is_no_landing_begun_of_a_later_one() {
    let (dialer, board, signer) = open(minted_head_world());
    let session = sign_in(&board, &signer);
    let (merged, _) = landed_in_s(&board, &session, &signer);
    let inputs = Inputs { base: None, ..draft_inputs() };
    let again = compose(&board, Some(session.token()), &inputs).expect("composed again");
    assert_ne!(again.key.stateless(), merged.key.stateless(), "the premise: another merge");
    let marker = dialer.world().standing(S).1.expect("the premise: S marked");
    assert!(marker.sides.is_empty() && marker.head == format!("{D}.2"), "{marker:?}");
    let landed = land(&board, &again, draft_landing(&session, &signer, None)).expect("landed");
    let Landed::Draft { into, staged, .. } = &landed else { panic!("{landed:?}") };
    assert!(*staged && into.to_string() != S, "a draft of its own: {landed:?}");
}

/// A landing begun in a baseless draft re-arranged since is named.
///
/// Skep #914: the draft landing's merge lands in `P`, named, a draft the
/// board records no base for that held another list before, and is cut off
/// before its record; `P` is then re-arranged by hand to the merge's words
/// again, a row naming no merge, which leaves the landing standing. The
/// merge composed again, a `resume` and a landing with no draft named each
/// answer `Refusal::LandingBegun` naming `P` at the landing's position,
/// nothing staged or written (the mutant that reads `P`'s latest row of any
/// kind stages a second draft).
#[test]
fn a_landing_begun_in_a_baseless_draft_re_arranged_since_is_named() {
    const P: &str = "1.0.1.0.67";
    let world = || {
        let mut w = minted_head_world();
        w.doc(P, false, ACCOUNT, vec![run(D, 1, 11)]);
        w
    };
    let (dialer, board, signer, p, at) =
        cut_off_before_the_record(world, &draft_inputs(), Some(P));
    assert_eq!(p, a(P), "the premise: landed in P");
    assert_eq!(dialer.world().standing(P), (None, None), "the premise: no base, no marker");
    let typed = dialer.world().position;
    let frame = frames::set_arrangement(P, &shot_runs(&draft_m()), typed, None, None, None, None);
    dialer.world().apply(&frame)["at"].as_u64().expect("the re-arrangement's ack");
    let session = sign_in(&board, &signer);
    let again =
        compose(&board, Some(session.token()), &draft_inputs()).expect("composed again");
    let begun = Refusal::LandingBegun { draft: a(P), position: at };
    let rows = dialer.world().rows.len();
    dialer.clear();
    assert_eq!(
        resume(&board, &again, draft_landing(&session, &signer, None)),
        Err(begun.clone()),
        "the resume names P"
    );
    assert_eq!(
        land(&board, &again, draft_landing(&session, &signer, None)),
        Err(begun),
        "the landing names P"
    );
    let ops = dialer.ops();
    let writes = ["stage", "set_arrangement", "create_new_document", "insert", "make_link"];
    assert!(
        ops.iter().all(|o| !writes.contains(&o.as_str())),
        "nothing staged or written: {ops:?}"
    );
    assert_eq!(dialer.world().rows.len(), rows, "nothing committed");
}
