//! Landing again after a take-back, over the scripted board.
//!
//! The suite checks that a landing after a take-back is a write and a
//! record of its own, in one session or a fresh one, the same composition
//! landed again judged by the board, a fresh one staging a draft of its
//! own; that a resume finds a draft landing by its mark, never by the
//! draft's words or a marker it was staged with; that the standing record
//! is the merger's own newest for the key, read as a fresh landing lands
//! and replaced by its record; that a second landing of one key into one
//! draft is the same landing; that merges landed one over another are taken
//! back a landing at a time, each by its own record, a marker a stage
//! copied put back inherited; the take-backs' refusals, each mapped; and a
//! merge taken back unsigned where a claimed board's head is owed.

use super::*;

/// A landing after a take-back writes its own record.
///
/// The merge record's §1.5 (ii) and §4's currency, newest per key: a
/// merge of the draft side `S` landed in `S` and undone is composed
/// again: the undo restored the base, but the landing and the undo each
/// arranged `S`, so the draft side's state, a term of the key, is
/// another, and no record of that key stands (skep #770). Landed in `S`
/// in a fresh session, the memo cleared, it writes one record of its
/// own: `landed` the draft at the write's position, replacing none,
/// linked to the draft, current for its key, the undo's record current
/// for the first. A re-run and a `resume` over that composition write
/// nothing, and the next undo replaces the new record. After a
/// withdrawal, over the race shape landed in a staged draft `T`, the key
/// of member sides outlives the withdrawal, and the landing's record
/// replaces the withdrawal's.
#[test]
fn a_landing_after_a_take_back_writes_its_own_record() {
    // The undo.
    let (dialer, board, signer) = open(draft_landing_world());
    let session = sign_in(&board, &signer);
    let m = merger(&session, &signer);
    let into_s = || draft_landing(&session, &signer, Some(a(S)));
    let (merged, landed) = landed_in_s(&board, &session, &signer);
    let (_, first) = landing_of(&landed);
    let undone = undo(&board, m, &a(S), &a(K), None, None).expect("undone").record.expect("the undo's record");
    dialer.world().memo.clear();
    let again =
        compose(&board, Some(session.token()), &draft_inputs()).expect("composed again");
    assert_eq!(
        again.key.stateless(),
        merged.key.stateless(),
        "the premise: the undo restored the base, so the composition is the first landing's"
    );
    assert_ne!(
        again.key, merged.key,
        "the premise: the landing and the undo arranged S, so its state is another"
    );
    assert_eq!(again.prior, None, "the premise: no record of that key stands");
    dialer.clear();
    let relanded = land(&board, &again, into_s()).expect("landed again");
    let (at, link) = landing_of(&relanded);
    assert!(link != first && link != undone, "a record of its own: {link}");
    let atom = appended_record(&dialer);
    assert_eq!(atom["landed"], json!({"draft": S, "position": at}));
    assert_eq!(atom["replaces"], Value::Null, "a key of its own replaces nothing");
    assert_eq!(dialer.frames("make_link")[0]["to"]["addrs"], json!([S]));
    assert_eq!(dialer.world().docs.get(S).unwrap().runs, draft_m(), "S holds M again");
    let found = current(&board, Some(session.token()), &a(K), &again.key)
        .expect("the lookup")
        .expect("a record");
    assert_eq!(found.link, Some(link.clone()), "the landing's record is current for its key");
    let first_key = current(&board, Some(session.token()), &a(K), &merged.key)
        .expect("the lookup")
        .expect("a record");
    assert_eq!(
        first_key.link,
        Some(undone.clone()),
        "the undo's record current for the first key"
    );
    // A re-run and a resume over the composition: nothing written.
    let rows = dialer.world().rows.len();
    dialer.clear();
    assert_eq!(land(&board, &again, into_s()).expect("landed again"), relanded);
    assert_eq!(resume(&board, &again, into_s()).expect("resumed"), Some(relanded.clone()));
    assert!(dialer.frames("insert").is_empty() && dialer.frames("make_link").is_empty(), "{:?}", dialer.ops());
    assert_eq!(dialer.world().rows.len(), rows, "nothing written twice");
    // The next undo replaces the new record.
    dialer.clear();
    undo(&board, m, &a(S), &a(K), None, None).expect("undone again");
    assert_eq!(appended_record(&dialer)["replaces"].as_str(), Some(link.to_string().as_str()));

    // The withdrawal: the race shape landed in `T`, staged from `D.1`.
    let t = "1.0.1.0.67";
    let mut w = World::race();
    w.doc(t, false, ACCOUNT, vec![run(D, 1, 11)]);
    w.staged(t, &format!("{D}.1"), 11);
    let (dialer, board, signer) = open(w);
    let session = sign_in(&board, &signer);
    let m = merger(&session, &signer);
    let into_t = || draft_landing(&session, &signer, Some(a(t)));
    let merged = compose(&board, Some(session.token()), &race_inputs()).expect("composed");
    let (_, first) = landing_of(&land(&board, &merged, into_t()).expect("landed"));
    let withdrawn = withdraw(&board, m, &a(t), &a(K), None).expect("withdrawn").record.expect("the withdrawal's record");
    dialer.world().memo.clear();
    let again = compose(&board, Some(session.token()), &race_inputs()).expect("composed again");
    assert_eq!(
        (again.key.clone(), again.prior.as_ref().and_then(|p| p.link.clone())),
        (merged.key.clone(), Some(withdrawn.clone())),
        "the premise: the key outlives the withdrawal, whose record is the prior"
    );
    dialer.clear();
    let (at, link) = landing_of(&land(&board, &again, into_t()).expect("landed again"));
    assert!(link != first && link != withdrawn, "a record of its own: {link}");
    let atom = appended_record(&dialer);
    assert_eq!(atom["landed"], json!({"draft": t, "position": at}));
    assert_eq!(atom["replaces"].as_str(), Some(withdrawn.to_string().as_str()), "the withdrawal's record replaced");
    assert_eq!(dialer.frames("make_link")[0]["to"]["addrs"], json!([t, format!("{D}.1.1")]));
    let found = current(&board, Some(session.token()), &a(K), &merged.key).expect("the lookup").expect("a record");
    assert_eq!(found.link, Some(link), "the landing's record is current for the key");
}

/// A landing after a take-back in one session is a write of its own.
///
/// The draft landing's ids are spelled over the key, the draft, the
/// position its write is typed against and the record it follows — the
/// undo's — so a merge composed again after an undo, the same key at a
/// later position, is never answered by the board's memo with the first
/// landing's acknowledgment. The race shape landed in a staged draft
/// `T`, its key of member sides, keeps its key across the undo. The
/// write commits, `T` holds M again with the marker at the new position,
/// and the record's two writes carry ids of the same stem. The draft
/// side `S` landed in itself and undone is another key (skep #770), its
/// ids spelled over the draft's new state and following no record.
#[test]
fn a_landing_after_a_take_back_in_one_session_is_a_write_of_its_own() {
    let t = "1.0.1.0.67";
    let mut w = World::race();
    w.doc(t, false, ACCOUNT, vec![run(D, 1, 11)]);
    w.staged(t, &format!("{D}.1"), 11);
    let (dialer, board, signer) = open(w);
    let session = sign_in(&board, &signer);
    let into_t = || draft_landing(&session, &signer, Some(a(t)));
    let merged = compose(&board, Some(session.token()), &race_inputs()).expect("composed");
    let (first_at, _) = landing_of(&land(&board, &merged, into_t()).expect("landed"));
    let undone = undo(&board, merger(&session, &signer), &a(t), &a(K), None, None)
        .expect("undone")
        .record
        .expect("the undo's record");
    let again = compose(&board, Some(session.token()), &race_inputs()).expect("composed again");
    assert_eq!(again.key, merged.key, "the premise: the same key");
    assert!(again.as_of > merged.as_of, "the premise: a later position");
    let rows = dialer.world().rows.len();
    dialer.clear();
    let relanded = land(&board, &again, into_t()).expect("landed again");
    let (at, _) = landing_of(&relanded);
    assert!(at > first_at, "a commit of its own, never the first landing's acknowledgment: {relanded:?}");
    let stem = Stem::of(&format!("{}:{t}@{}~{undone}", again.key.text(), again.as_of));
    assert_eq!(dialer.frames("set_arrangement")[0]["id"].as_str(), Some(stem.id("draft").as_str()));
    assert_eq!(dialer.frames("insert")[0]["id"].as_str(), Some(stem.id("record").as_str()));
    assert_eq!(dialer.frames("make_link")[0]["id"].as_str(), Some(stem.id("link").as_str()));
    {
        let w = dialer.world();
        assert!(w.rows.len() > rows, "committed");
        assert_eq!(
            w.docs.get(t).unwrap().runs,
            vec![run(D, 1, 4), run(D, 12, 4), run(D, 5, 3)],
            "T holds M again: the big cat"
        );
        assert_eq!(w.standing(t).1.map(|m| m.at), Some(at), "the marker at the new landing");
    }

    // The draft side landed in itself: another key after the undo.
    let (dialer, board, signer) = open(draft_landing_world());
    let session = sign_in(&board, &signer);
    let (merged, landed) = landed_in_s(&board, &session, &signer);
    let (first_at, _) = landing_of(&landed);
    undo(&board, merger(&session, &signer), &a(S), &a(K), None, None).expect("undone");
    let again =
        compose(&board, Some(session.token()), &draft_inputs()).expect("composed again");
    assert_eq!(
        again.key.stateless(),
        merged.key.stateless(),
        "the premise: the same composition"
    );
    assert_ne!(again.key, merged.key, "the premise: S, the draft side, arranged since");
    dialer.clear();
    let relanded = land(&board, &again, draft_landing(&session, &signer, Some(a(S))))
        .expect("landed again");
    let (at, _) = landing_of(&relanded);
    assert!(at > first_at, "a commit of its own: {relanded:?}");
    let stem = Stem::of(&format!("{}:{S}@{}", again.key.text(), again.as_of));
    let SideAt::Draft { arranged: SideState::At(state), .. } = again.record.sides[1] else {
        panic!("{:?}", again.record.sides)
    };
    assert!(state > first_at, "the undo arranged S after the landing: {state}");
    assert!(
        again.key.text().ends_with(&format!(":{S}@{state}")),
        "the key's text spells S's state: {}",
        again.key.text()
    );
    assert_eq!(
        dialer.frames("set_arrangement")[0]["id"].as_str(),
        Some(stem.id("draft").as_str())
    );
    assert_eq!(dialer.world().docs.get(S).unwrap().runs, draft_m(), "S holds M again");
}

/// THE SAME COMPOSITION LANDED AGAIN INTO ITS DRAFT AFTER A TAKE-BACK IS
/// JUDGED BY THE BOARD: the landing's ids name the record it follows, so
/// the composition that landed in `S`, kept across an undo or a
/// withdrawal of that landing, each recorded, and landed into `S` again
/// in the same session is never answered by the board's memo with the
/// landing taken back. Its one write, under ids naming the take-back's
/// record and typed against the composition's position, is refused
/// `arrangement_moved` — the landing moved `S` past that position —
/// nothing written, `S` as the take-back left it with no marker, and the
/// take-back's record current; the memo cleared, the same refusal. A
/// retry over a lost acknowledgment, no record yet written, spells its
/// first call's ids: the board answers the one write, and the record is
/// written once.
#[test]
fn the_same_composition_landed_again_into_its_draft_after_a_take_back_is_judged_by_the_board() {
    for act in ["undo", "withdraw"] {
        let (dialer, board, signer) = open(draft_landing_world());
        let session = sign_in(&board, &signer);
        let m = merger(&session, &signer);
        let (merged, _) = landed_in_s(&board, &session, &signer);
        let (taken_back, left) = match act {
            "undo" => {
                (undo(&board, m, &a(S), &a(K), None, None).expect("undone").record, draft_c())
            }
            _ => {
                (withdraw(&board, m, &a(S), &a(K), None).expect("withdrawn").record, draft_m())
            }
        };
        let taken_back = taken_back.expect("the take-back's record");
        let id = landing_id(
            &format!("{}:{S}@{}~{taken_back}", merged.key.text(), merged.as_of),
            "draft",
        );
        assert_eq!(
            dialer.world().docs.get(S).unwrap().runs,
            left,
            "{act}: the premise, S as the take-back left it"
        );
        assert_eq!(dialer.world().standing(S).1, None, "{act}: the premise, no marker");
        let rows = dialer.world().rows.len();
        for memo in ["kept", "cleared"] {
            if memo == "cleared" {
                dialer.world().memo.clear();
            }
            let cell = format!("{act}, the memo {memo}");
            dialer.clear();
            let err = land(&board, &merged, draft_landing(&session, &signer, Some(a(S))))
                .expect_err("the landing was taken back");
            let Refusal::Halt(Halt::Refused(refused)) = &err else { panic!("{cell}: {err:?}") };
            assert_eq!(refused.code, "arrangement_moved", "{cell}: {refused:?}");
            let detail = refused.detail.as_deref().expect("the person's words");
            assert!(
                detail.contains("nothing was merged") && !detail.contains("resume"),
                "{cell}: the take-back's change, no landing of this merge standing: {detail}"
            );
            let frames = dialer.frames("set_arrangement");
            assert_eq!(frames.len(), 1, "{cell}: one write sent: {:?}", dialer.ops());
            assert_eq!(
                frames[0]["as_of"].as_u64(),
                Some(merged.as_of),
                "{cell}: typed against the composition's position"
            );
            assert_eq!(
                frames[0]["id"].as_str(),
                Some(id.as_str()),
                "{cell}: the ids name the take-back's record"
            );
            assert!(
                dialer.frames("insert").is_empty() && dialer.frames("make_link").is_empty(),
                "{cell}: no record: {:?}",
                dialer.ops()
            );
            let w = dialer.world();
            assert_eq!(w.rows.len(), rows, "{cell}: nothing written");
            assert_eq!(w.docs.get(S).unwrap().runs, left, "{cell}: S as the take-back left it");
            assert_eq!(w.standing(S).1, None, "{cell}: no marker");
            drop(w);
            let found = current(&board, Some(session.token()), &a(K), &merged.key)
                .expect("the lookup")
                .expect("a record");
            assert_eq!(
                found.link,
                Some(taken_back.clone()),
                "{cell}: the take-back's record current"
            );
        }
    }
    // A retry over a lost acknowledgment, no record written yet: no
    // record to follow, the same ids, the one write answered again.
    let (dialer, board, signer) = open(draft_landing_world());
    let session = sign_in(&board, &signer);
    let merged = compose(&board, Some(session.token()), &draft_inputs()).expect("composed");
    let rows = dialer.world().rows.len();
    dialer.clear();
    dialer.world().drop_acks = 1;
    let lost = land(&board, &merged, draft_landing(&session, &signer, Some(a(S))));
    assert!(
        matches!(lost, Err(Refusal::Halt(Halt::Dial(_)))),
        "the premise: the write's acknowledgment lost: {lost:?}"
    );
    let landed = land(&board, &merged, draft_landing(&session, &signer, Some(a(S))))
        .expect("landed on the retry");
    let Landed::Draft { into, .. } = &landed else { panic!("{landed:?}") };
    assert_eq!(*into, a(S));
    let frames = dialer.frames("set_arrangement");
    assert_eq!(frames.len(), 2, "the write and its retry: {:?}", dialer.ops());
    let id = landing_id(&format!("{}:{S}@{}", merged.key.text(), merged.as_of), "draft");
    assert_eq!(frames[0]["id"].as_str(), Some(id.as_str()), "no record to follow");
    assert_eq!(frames[1]["id"], frames[0]["id"], "the retry's id is its first call's");
    let w = dialer.world();
    assert_eq!(
        w.rows.iter().skip(rows).filter(|r| r.op == "set_arrangement").count(),
        1,
        "one write committed"
    );
    drop(w);
    assert_eq!(
        (dialer.frames("insert").len(), dialer.frames("make_link").len()),
        (1, 1),
        "the record written once"
    );
}

/// A resume finds a draft landing by its mark, never by the draft's words.
///
/// The mark is the marker naming the merge, or on a draft with no
/// recorded base its latest `set_arrangement` row naming it; a take-back
/// clears it, and a draft holding M without it holds no landing to resume
/// (skep #888). (a) The landing withdrawn, the withdrawal recorded:
/// `resume` naming the draft, which still holds M, answers none and
/// writes nothing, the withdrawal's record current. (b) The landing's
/// record unwritten, the board too busy to find its journal, then the
/// landing withdrawn: none, nothing written, no record of the key. (c) The
/// withdrawal's record unwritten: none, nothing written, the landing's
/// record current. (d) A draft with no recorded base, holding M's list
/// before the landing, the landing undone: the undo's row names no merge,
/// so none, nothing written. (e) A composition made after its landing,
/// the marker standing: the landing at the marker's position, nothing
/// written.
#[test]
fn a_resume_finds_a_draft_landing_by_its_mark_never_by_the_drafts_words() {
    let writes = ["stage", "set_arrangement", "create_new_document", "insert", "make_link"];
    let wrote = |dialer: &Scripted| {
        dialer.ops().into_iter().filter(|o| writes.contains(&o.as_str())).collect::<Vec<_>>()
    };

    // (a) The landing withdrawn, the withdrawal recorded.
    let (dialer, board, signer) = open(draft_landing_world());
    let session = sign_in(&board, &signer);
    let into_s = || draft_landing(&session, &signer, Some(a(S)));
    let (merged, _) = landed_in_s(&board, &session, &signer);
    let withdrawn = withdraw(&board, merger(&session, &signer), &a(S), &a(K), None)
        .expect("withdrawn")
        .record
        .expect("(a): the premise, the withdrawal's record");
    {
        let w = dialer.world();
        assert_eq!(w.docs.get(S).unwrap().runs, draft_m(), "(a): the premise, S holds M");
        assert_eq!(w.standing(S).1, None, "(a): the premise, no marker");
    }
    let rows = dialer.world().rows.len();
    dialer.clear();
    assert_eq!(resume(&board, &merged, into_s()), Ok(None), "(a): the landing withdrawn");
    assert!(wrote(&dialer).is_empty(), "(a): nothing written: {:?}", dialer.ops());
    assert_eq!(dialer.world().rows.len(), rows, "(a): nothing committed");
    let found = current(&board, Some(session.token()), &a(K), &merged.key)
        .expect("the lookup")
        .expect("a record");
    assert_eq!(
        (found.link, found.landed),
        (Some(withdrawn), None),
        "(a): the withdrawal's record current"
    );

    // (b) The landing's record unwritten, the board too busy to find its
    // journal, then the landing withdrawn with no record to replace.
    let (dialer, board, signer) = open(draft_landing_world());
    let session = sign_in(&board, &signer);
    let into_s = || draft_landing(&session, &signer, Some(a(S)));
    let merged = compose(&board, Some(session.token()), &draft_inputs()).expect("composed");
    too_busy_for_the_find(&mut dialer.world());
    let err = land(&board, &merged, into_s()).expect_err("the record unwritten");
    let Refusal::Halt(Halt::Halt(face)) = &err else { panic!("(b): {err:?}") };
    assert!(
        face.state.contains(&format!("the merge stands at {S}")),
        "(b): the premise: {face}"
    );
    let withdrawn =
        withdraw(&board, merger(&session, &signer), &a(S), &a(K), None).expect("withdrawn");
    assert_eq!(withdrawn.record, None, "(b): the premise, no record stood to replace");
    assert_eq!(dialer.world().docs.get(S).unwrap().runs, draft_m(), "(b): the premise");
    let rows = dialer.world().rows.len();
    dialer.clear();
    assert_eq!(resume(&board, &merged, into_s()), Ok(None), "(b): the landing withdrawn");
    assert!(wrote(&dialer).is_empty(), "(b): nothing written: {:?}", dialer.ops());
    assert_eq!(dialer.world().rows.len(), rows, "(b): nothing committed");
    assert!(
        current(&board, Some(session.token()), &a(K), &merged.key)
            .expect("the lookup")
            .is_none(),
        "(b): no record of the key"
    );

    // (c) The withdrawal's record unwritten, the board too busy to find
    // its journal past the withdrawal's write.
    let (dialer, board, signer) = open(draft_landing_world());
    let session = sign_in(&board, &signer);
    let into_s = || draft_landing(&session, &signer, Some(a(S)));
    let (merged, landed) = landed_in_s(&board, &session, &signer);
    let (_, link) = landing_of(&landed);
    too_busy_for_the_find(&mut dialer.world());
    let err = withdraw(&board, merger(&session, &signer), &a(S), &a(K), None)
        .expect_err("the withdrawal's record unwritten");
    let Refusal::Halt(Halt::Halt(face)) = &err else { panic!("(c): {err:?}") };
    assert!(
        face.state.contains("the record of the withdrawal is not written"),
        "(c): the premise: {face}"
    );
    {
        let w = dialer.world();
        assert_eq!(w.docs.get(S).unwrap().runs, draft_m(), "(c): the premise, S holds M");
        assert_eq!(w.standing(S).1, None, "(c): the premise, the marker cleared");
    }
    let rows = dialer.world().rows.len();
    dialer.clear();
    assert_eq!(resume(&board, &merged, into_s()), Ok(None), "(c): the landing withdrawn");
    assert!(wrote(&dialer).is_empty(), "(c): nothing written: {:?}", dialer.ops());
    assert_eq!(dialer.world().rows.len(), rows, "(c): nothing committed");
    let found = current(&board, Some(session.token()), &a(K), &merged.key)
        .expect("the lookup")
        .expect("a record");
    assert_eq!(found.link, Some(link), "(c): the landing's record current");

    // (d) A draft with no recorded base that held M's list before the
    // landing, the landing undone and the undo recorded.
    let plain = "1.0.1.0.67";
    let mut w = draft_landing_world();
    w.doc(plain, false, ACCOUNT, draft_m());
    let (dialer, board, signer) = open(w);
    let session = sign_in(&board, &signer);
    let into_plain = || draft_landing(&session, &signer, Some(a(plain)));
    let merged = compose(&board, Some(session.token()), &draft_inputs()).expect("composed");
    land(&board, &merged, into_plain()).expect("landed");
    let undone = undo(&board, merger(&session, &signer), &a(plain), &a(K), None, None)
        .expect("undone")
        .record
        .expect("(d): the premise, the undo's record");
    {
        let w = dialer.world();
        assert_eq!(w.docs.get(plain).unwrap().runs, draft_m(), "(d): the premise, M's list");
        assert_eq!(w.standing(plain), (None, None), "(d): the premise, no base, no marker");
    }
    let rows = dialer.world().rows.len();
    dialer.clear();
    assert_eq!(resume(&board, &merged, into_plain()), Ok(None), "(d): the landing undone");
    let ops = dialer.ops();
    assert!(
        ops.iter().any(|o| o.starts_with("GET /changes?")
            && o.contains(&format!("under={plain}"))
            && o.contains("drafts=true")),
        "(d): the draft's own rows read on the supplement: {ops:?}"
    );
    assert!(wrote(&dialer).is_empty(), "(d): nothing written: {ops:?}");
    assert_eq!(dialer.world().rows.len(), rows, "(d): nothing committed");
    let found = current(&board, Some(session.token()), &a(K), &merged.key)
        .expect("the lookup")
        .expect("a record");
    assert_eq!(found.link, Some(undone), "(d): the undo's record current");

    // (e) A composition made after its landing, the marker standing.
    let t = "1.0.1.0.67";
    let mut w = World::race();
    w.doc(t, false, ACCOUNT, vec![run(D, 1, 11)]);
    w.staged(t, &format!("{D}.1"), 11);
    let (dialer, board, signer) = open(w);
    let session = sign_in(&board, &signer);
    let into_t = || draft_landing(&session, &signer, Some(a(t)));
    let merged = compose(&board, Some(session.token()), &race_inputs()).expect("composed");
    let (at, link) = landing_of(&land(&board, &merged, into_t()).expect("landed"));
    let again = compose(&board, Some(session.token()), &race_inputs()).expect("composed again");
    assert!(again.as_of > at, "(e): the premise, composed after the landing");
    dialer.clear();
    assert_eq!(
        resume(&board, &again, into_t()),
        Ok(Some(Landed::Draft { into: a(t), position: at, record: link, head_moved: None, staged: false })),
        "(e): the landing, at the marker's position"
    );
    assert!(wrote(&dialer).is_empty(), "(e): nothing written: {:?}", dialer.ops());
}

/// A resume never finds a landing by a marker its draft was staged with.
///
/// A stage of a draft the merge landed in copies its words and its
/// marker, the marker stamped at the stage's own commit, the copy's mint
/// (P2): the copy holds M and a marker naming the merge, and no landing
/// of it (skep #913). The race shape is landed in `T`, a draft no side
/// names, and `T′` is staged from `T`. (a) `resume` naming `T′` answers
/// none, reading nothing at a position and writing nothing, `T`'s record
/// current. (b) `resume` naming `T` answers `T`'s landing. (c) The
/// journal reclaimed past the landing and the stage: (a) and (b) answer
/// as they did. (d) The merge composed again and landed in `T′`: that
/// landing's marker stands past the mint, and `resume` answers it,
/// writing nothing. (e) `T″` staged from `T′`: none, nothing written.
#[test]
fn a_resume_never_finds_a_landing_by_a_marker_its_draft_was_staged_with() {
    let writes = ["stage", "set_arrangement", "create_new_document", "insert", "make_link"];
    let wrote = |dialer: &Scripted| {
        dialer.ops().into_iter().filter(|o| writes.contains(&o.as_str())).collect::<Vec<_>>()
    };
    let t = "1.0.1.0.67";
    let mut w = World::race();
    w.doc(t, false, ACCOUNT, vec![run(D, 1, 11)]);
    w.staged(t, &format!("{D}.1"), 11);
    let (dialer, board, signer) = open(w);
    let session = sign_in(&board, &signer);
    let into = |draft: &str| draft_landing(&session, &signer, Some(a(draft)));
    let stage = |from: &str| -> (String, u64) {
        let frame = frames::stage(from, None);
        let Answer::Document(ack) = board.op(Some(session.token()), &frame).expect("the stage")
        else {
            panic!("closed")
        };
        (acked_addr(&ack).expect("the copy").to_string(), acked_at(&ack).expect("its position"))
    };
    let merged = compose(&board, Some(session.token()), &race_inputs()).expect("composed");
    let landed = land(&board, &merged, into(t)).expect("landed in T");
    let (landed_at, link) = landing_of(&landed);
    let (copy, staged_at) = stage(t);
    {
        let w = dialer.world();
        assert_eq!(w.docs.get(&copy).unwrap().runs, m_runs(&merged), "the premise: T′ holds M");
        let marker = w.standing(&copy).1.expect("the premise: T′'s marker");
        assert_eq!(
            (marker.head, marker.sides, marker.at),
            (format!("{D}.2"), vec![format!("{D}.1.1")], staged_at),
            "the premise: the merge's marker, stamped at T′'s mint"
        );
    }
    let rows = dialer.world().rows.len();
    let t_record = |cell: &str| {
        let found = current(&board, Some(session.token()), &a(K), &merged.key)
            .expect("the lookup")
            .expect("a record");
        let in_t = RecordLanding::Draft { draft: a(t), position: landed_at };
        assert_eq!(
            (found.link, found.landed),
            (Some(link.clone()), Some(in_t)),
            "{cell}: T's record current"
        );
    };

    // (a) The copy: no landing.
    dialer.clear();
    assert_eq!(resume(&board, &merged, into(&copy)), Ok(None), "(a): no landing in T′");
    assert!(wrote(&dialer).is_empty(), "(a): nothing written: {:?}", dialer.ops());
    assert!(
        dialer.ops().iter().all(|o| !o.starts_with("at:")),
        "(a): nothing read at a position: {:?}",
        dialer.ops()
    );
    assert_eq!(dialer.world().rows.len(), rows, "(a): nothing committed");
    t_record("(a)");

    // (b) The draft the merge landed in: its landing.
    dialer.clear();
    assert_eq!(resume(&board, &merged, into(t)), Ok(Some(as_found(&landed))), "(b)");
    assert!(wrote(&dialer).is_empty(), "(b): nothing written: {:?}", dialer.ops());

    // (c) The journal reclaimed past the landing and the stage.
    let floor = dialer.world().position;
    dialer.world().floor = Some(floor);
    assert_eq!(resume(&board, &merged, into(&copy)), Ok(None), "(c): no landing in T′");
    assert_eq!(resume(&board, &merged, into(t)), Ok(Some(as_found(&landed))), "(c): T's");
    assert_eq!(dialer.world().rows.len(), rows, "(c): nothing committed");
    t_record("(c)");

    // (d) Composed again and landed in the copy: a landing of its own.
    let again = compose(&board, Some(session.token()), &race_inputs()).expect("composed again");
    let relanded = land(&board, &again, into(&copy)).expect("landed in T′");
    let (again_at, _) = landing_of(&relanded);
    assert!(again_at > staged_at, "(d): the premise, a write past T′'s mint");
    dialer.clear();
    assert_eq!(resume(&board, &again, into(&copy)), Ok(Some(as_found(&relanded))), "(d)");
    assert!(wrote(&dialer).is_empty(), "(d): nothing written: {:?}", dialer.ops());

    // (e) A copy of the copy: no landing.
    let (copy2, _) = stage(&copy);
    let rows = dialer.world().rows.len();
    dialer.clear();
    assert_eq!(resume(&board, &again, into(&copy2)), Ok(None), "(e): no landing in T″");
    assert!(wrote(&dialer).is_empty(), "(e): nothing written: {:?}", dialer.ops());
    assert_eq!(dialer.world().rows.len(), rows, "(e): nothing committed");
}

/// A composition landed again in a fresh session names its own landing.
///
/// The fresh session holds no memo of the first call's write (skep #852):
/// typed against the composition's position, which the landing moved the
/// draft past, the one write is refused `arrangement_moved` and nothing
/// is written; the memo is cleared to stand for the fresh session. (a)
/// The landing recorded: the words name the draft, the landing's position
/// and its record, never that nothing was merged, with `resume` the way
/// on, which answers the landing writing nothing. (b) Its record
/// unwritten, the board too busy to find its journal: the words say so,
/// and `resume` writes it at the marker's position. (c) The draft edited
/// since: the words name the landing and the other list the draft holds,
/// never `resume`, which answers none. (d) A composition made after the
/// landing, raced by another hand's edit: the marker predates it, so the
/// words are the race's. (e) Another merge landed over the draft after
/// the composition: its marker names other sides, so the words are the
/// race's. (f) A draft with no recorded base, its record unwritten: the
/// landing's row on the supplement names it, and `resume` writes the
/// record at that row's position. (g) The same draft once the landing is
/// undone: the undo's row names no merge, so the words are the race's.
/// (h) One key landed twice in a draft, the same landing (skep #790),
/// then a third time in a fresh session: the words name the record that
/// stands, the first landing's, at the marker's position, the second
/// write's (skep #964).
#[test]
fn a_composition_landed_again_in_a_fresh_session_names_its_own_landing() {
    let writes = ["stage", "set_arrangement", "create_new_document", "insert", "make_link"];
    let wrote = |dialer: &Scripted| {
        dialer.ops().into_iter().filter(|o| writes.contains(&o.as_str())).collect::<Vec<_>>()
    };
    let refused_words = |err: &Refusal, cell: &str| -> String {
        let Refusal::Halt(Halt::Refused(refused)) = err else { panic!("{cell}: {err:?}") };
        assert_eq!(refused.code, "arrangement_moved", "{cell}: {refused:?}");
        refused.detail.clone().expect("the person's words")
    };

    // (a) The landing recorded.
    let (dialer, board, signer) = open(draft_landing_world());
    let session = sign_in(&board, &signer);
    let into_s = || draft_landing(&session, &signer, Some(a(S)));
    let (merged, landed) = landed_in_s(&board, &session, &signer);
    let (at, link) = landing_of(&landed);
    dialer.world().memo.clear();
    let rows = dialer.world().rows.len();
    dialer.clear();
    let err = land(&board, &merged, into_s()).expect_err("its own landing moved S");
    let detail = refused_words(&err, "(a)");
    assert!(
        detail.contains(&format!(
            "{S} already holds this merge: it landed there at position {at}"
        )) && detail.contains(&format!("its record is {link}"))
            && detail.contains("resume answers that landing"),
        "(a): {detail}"
    );
    assert!(
        !detail.contains("nothing was merged") && !detail.contains("writes its record"),
        "(a): {detail}"
    );
    let frames = dialer.frames("set_arrangement");
    assert_eq!(frames.len(), 1, "(a): one write sent: {:?}", dialer.ops());
    assert_eq!(
        frames[0]["as_of"].as_u64(),
        Some(merged.as_of),
        "(a): typed against the composition's position"
    );
    assert_eq!(
        wrote(&dialer),
        ["set_arrangement"],
        "(a): nothing of a record: {:?}",
        dialer.ops()
    );
    let w = dialer.world();
    assert_eq!(w.rows.len(), rows, "(a): nothing written");
    assert_eq!(w.docs.get(S).unwrap().runs, draft_m(), "(a): S holds M");
    assert_eq!(w.standing(S).1.map(|m| m.at), Some(at), "(a): the marker at the landing");
    drop(w);
    dialer.clear();
    assert_eq!(
        resume(&board, &merged, into_s()).expect("resumed"),
        Some(landed),
        "(a): the way on answers the landing"
    );
    assert!(wrote(&dialer).is_empty(), "(a): a resume writes nothing: {:?}", dialer.ops());

    // (b) The record unwritten: the board too busy to find the account's
    // journal past the landing's write.
    let (dialer, board, signer) = open(draft_landing_world());
    let session = sign_in(&board, &signer);
    let into_s = || draft_landing(&session, &signer, Some(a(S)));
    let merged = compose(&board, Some(session.token()), &draft_inputs()).expect("composed");
    too_busy_for_the_find(&mut dialer.world());
    let err = land(&board, &merged, into_s()).expect_err("the record unwritten");
    let Refusal::Halt(Halt::Halt(face)) = &err else { panic!("(b): {err:?}") };
    assert!(
        face.state.contains(&format!("the merge stands at {S}")),
        "(b): the premise: {face}"
    );
    let at = dialer.world().standing(S).1.expect("(b): the premise, the marker").at;
    dialer.world().memo.clear();
    dialer.clear();
    let err = land(&board, &merged, into_s()).expect_err("its own landing moved S");
    let detail = refused_words(&err, "(b)");
    assert!(
        detail.contains(&format!(
            "{S} already holds this merge: it landed there at position {at}"
        )) && detail.contains("its record is not written")
            && detail.contains("resume answers that landing and writes its record"),
        "(b): {detail}"
    );
    assert!(!detail.contains("nothing was merged"), "(b): {detail}");
    assert_eq!(
        wrote(&dialer),
        ["set_arrangement"],
        "(b): nothing of a record: {:?}",
        dialer.ops()
    );
    dialer.clear();
    let resumed = resume(&board, &merged, into_s()).expect("resumed");
    let Some(Landed::Draft { into, position, .. }) = &resumed else {
        panic!("(b): {resumed:?}")
    };
    assert_eq!(
        (into.clone(), *position),
        (a(S), at),
        "(b): the landing, at the marker's position"
    );
    assert_eq!(
        dialer.frames("make_link").len(),
        1,
        "(b): the record written: {:?}",
        dialer.ops()
    );
    assert!(dialer.frames("set_arrangement").is_empty(), "(b): {:?}", dialer.ops());

    // (c) S edited since its landing.
    let (dialer, board, signer) = open(draft_landing_world());
    let session = sign_in(&board, &signer);
    let into_s = || draft_landing(&session, &signer, Some(a(S)));
    let (merged, landed) = landed_in_s(&board, &session, &signer);
    let (at, link) = landing_of(&landed);
    dialer.world().change(S, vec![run(D, 1, 11)]);
    dialer.world().memo.clear();
    dialer.clear();
    let err = land(&board, &merged, into_s()).expect_err("S moved");
    let detail = refused_words(&err, "(c)");
    assert!(
        detail.contains(&format!("this merge landed in {S} at position {at}"))
            && detail.contains(&format!("its record is {link}"))
            && detail.contains(&format!("{S} holds another list now")),
        "(c): {detail}"
    );
    assert!(
        !detail.contains("resume") && !detail.contains("nothing was merged"),
        "(c): {detail}"
    );
    assert_eq!(wrote(&dialer), ["set_arrangement"], "(c): {:?}", dialer.ops());
    assert_eq!(
        resume(&board, &merged, into_s()).expect("resumed"),
        None,
        "(c): nothing to resume"
    );

    // (d) A composition made after the landing, raced.
    let t = "1.0.1.0.67";
    let mut w = World::race();
    w.doc(t, false, ACCOUNT, vec![run(D, 1, 11)]);
    w.staged(t, &format!("{D}.1"), 11);
    let (dialer, board, signer) = open(w);
    let session = sign_in(&board, &signer);
    let into_t = || draft_landing(&session, &signer, Some(a(t)));
    let merged = compose(&board, Some(session.token()), &race_inputs()).expect("composed");
    let (landed_at, _) = landing_of(&land(&board, &merged, into_t()).expect("landed"));
    let again = compose(&board, Some(session.token()), &race_inputs()).expect("composed again");
    assert!(again.as_of > landed_at, "(d): the premise, composed after the landing");
    let edit_at = dialer.world().change(t, vec![run(D, 1, 4), run(D, 12, 4)]);
    dialer.world().memo.clear();
    dialer.clear();
    let err = land(&board, &again, into_t()).expect_err("another hand's edit");
    let detail = refused_words(&err, "(d)");
    assert!(
        detail.contains(&format!("{t} changed after the merge was composed (composed at position {}, the draft changed at {edit_at})", again.as_of))
            && detail.contains("nothing was merged"),
        "(d): {detail}"
    );
    assert!(!detail.contains("resume") && !detail.contains("already holds"), "(d): {detail}");

    // (e) Another merge landed over the draft after the composition: its
    // marker names the head but other sides, so the words are the race's.
    let mut w = World::race();
    w.doc(t, false, ACCOUNT, vec![run(D, 1, 11)]);
    w.staged(t, &format!("{D}.1"), 11);
    let (dialer, board, signer) = open(w);
    let session = sign_in(&board, &signer);
    let into_t = || draft_landing(&session, &signer, Some(a(t)));
    let merged = compose(&board, Some(session.token()), &race_inputs()).expect("composed");
    let other =
        Inputs { sides: vec![Side::Draft { at: a(t), position: None }], ..race_inputs() };
    let other = compose(&board, Some(session.token()), &other).expect("another merge composed");
    land(&board, &other, into_t()).expect("another merge landed");
    let marker =
        dialer.world().standing(t).1.expect("(e): the premise, the other merge's marker");
    assert!(
        marker.head == format!("{D}.2") && marker.sides.is_empty() && marker.at > merged.as_of,
        "(e): the premise: {marker:?}"
    );
    dialer.world().memo.clear();
    dialer.clear();
    let err = land(&board, &merged, into_t()).expect_err("another merge moved T");
    let detail = refused_words(&err, "(e)");
    assert!(
        detail.contains(&format!("{t} changed after the merge was composed"))
            && detail.contains("nothing was merged"),
        "(e): {detail}"
    );
    assert!(
        !detail.contains("resume") && !detail.contains("this merge landed"),
        "(e): {detail}"
    );

    // (f) A draft with no recorded base, its record unwritten.
    let plain = "1.0.1.0.67";
    let baseless = || {
        let mut w = draft_landing_world();
        w.doc(plain, false, ACCOUNT, vec![run(D, 1, 11)]);
        w
    };
    let (dialer, board, signer) = open(baseless());
    let session = sign_in(&board, &signer);
    let into_plain = || draft_landing(&session, &signer, Some(a(plain)));
    let merged = compose(&board, Some(session.token()), &draft_inputs()).expect("composed");
    too_busy_for_the_find(&mut dialer.world());
    let err = land(&board, &merged, into_plain()).expect_err("the record unwritten");
    let Refusal::Halt(Halt::Halt(face)) = &err else { panic!("(f): {err:?}") };
    assert!(
        face.state.contains(&format!("the merge stands at {plain}")),
        "(f): the premise: {face}"
    );
    let at = dialer
        .world()
        .rows
        .iter()
        .rev()
        .find(|r| r.op == "set_arrangement")
        .expect("(f): the landing's row")
        .at;
    assert_eq!(
        dialer.world().standing(plain),
        (None, None),
        "(f): the premise, no base and no marker"
    );
    dialer.world().memo.clear();
    dialer.clear();
    let err = land(&board, &merged, into_plain()).expect_err("its own landing moved the draft");
    let detail = refused_words(&err, "(f)");
    assert!(
        detail.contains(&format!(
            "{plain} already holds this merge: it landed there at position {at}"
        )) && detail.contains("its record is not written")
            && detail.contains("resume answers that landing and writes its record"),
        "(f): {detail}"
    );
    let ops = dialer.ops();
    assert!(
        ops.iter().any(|o| o.starts_with("GET /changes?")
            && o.contains(&format!("under={plain}"))
            && o.contains("drafts=true")),
        "(f): the landing off the draft's own rows on the supplement: {ops:?}"
    );
    assert_eq!(wrote(&dialer), ["set_arrangement"], "(f): {ops:?}");
    dialer.clear();
    let resumed = resume(&board, &merged, into_plain()).expect("resumed");
    assert!(
        matches!(&resumed, Some(Landed::Draft { into, position, .. })
            if into.to_string() == plain && *position == at),
        "(f): the landing, at its row's position: {resumed:?}"
    );
    assert_eq!(
        dialer.frames("make_link").len(),
        1,
        "(f): the record written: {:?}",
        dialer.ops()
    );
    assert_eq!(
        appended_record(&dialer)["landed"],
        json!({"draft": plain, "position": at}),
        "(f): the record names the row's position"
    );

    // (g) The same draft, its landing undone, the undo recorded.
    let (dialer, board, signer) = open(baseless());
    let session = sign_in(&board, &signer);
    let into_plain = || draft_landing(&session, &signer, Some(a(plain)));
    let merged = compose(&board, Some(session.token()), &draft_inputs()).expect("composed");
    land(&board, &merged, into_plain()).expect("landed");
    let undone =
        undo(&board, merger(&session, &signer), &a(plain), &a(K), None, None).expect("undone");
    assert!(undone.record.is_some(), "(g): the premise, the undo recorded");
    dialer.world().memo.clear();
    dialer.clear();
    let err = land(&board, &merged, into_plain()).expect_err("the undo moved the draft");
    let detail = refused_words(&err, "(g)");
    assert!(
        detail.contains(&format!("{plain} changed after the merge was composed"))
            && detail.contains("nothing was merged"),
        "(g): {detail}"
    );
    assert!(
        !detail.contains("resume") && !detail.contains("this merge landed"),
        "(g): {detail}"
    );
    assert_eq!(wrote(&dialer), ["set_arrangement"], "(g): {:?}", dialer.ops());

    // (h) One key landed twice in `T`, the same landing, then a third
    // time in a fresh session.
    let mut w = World::race();
    w.doc(t, false, ACCOUNT, vec![run(D, 1, 11)]);
    w.staged(t, &format!("{D}.1"), 11);
    let (dialer, board, signer) = open(w);
    let session = sign_in(&board, &signer);
    let into_t = || draft_landing(&session, &signer, Some(a(t)));
    let merged = compose(&board, Some(session.token()), &race_inputs()).expect("composed");
    let (_, first) = landing_of(&land(&board, &merged, into_t()).expect("landed"));
    let again = compose(&board, Some(session.token()), &race_inputs()).expect("composed again");
    let (second_at, record) =
        landing_of(&land(&board, &again, into_t()).expect("landed again"));
    assert_eq!(record, first, "(h): the premise, the same landing");
    dialer.world().memo.clear();
    dialer.clear();
    let err = land(&board, &again, into_t()).expect_err("its own landing moved T");
    let detail = refused_words(&err, "(h)");
    assert!(
        detail.contains(&format!(
            "{t} already holds this merge: it landed there at position {second_at}"
        )) && detail.contains(&format!("its record is {first}"))
            && detail.contains("resume answers that landing"),
        "(h): {detail}"
    );
    assert!(!detail.contains("not written"), "(h): {detail}");
    assert_eq!(wrote(&dialer), ["set_arrangement"], "(h): {:?}", dialer.ops());
}

/// THE STANDING RECORD IS THE MERGER's OWN NEWEST FOR THE KEY. A newer
/// record of the key in another account's home, one that sorts above
/// every link of the merger's doc 1, never stands for the merger's
/// landing and never replaces its record: a `resume` after it finds the
/// landing's own record standing and writes nothing. A landing of the
/// key into another draft replaces the first landing's record, though
/// its link reaches no part of the first draft: a landing into the first
/// draft again writes a record of its own, replacing it.
#[test]
fn the_standing_record_is_the_mergers_own_newest_for_the_key() {
    // Another account's record.
    let (dialer, board, signer) = open(draft_landing_world());
    let session = sign_in(&board, &signer);
    let (merged, landed) = landed_in_s(&board, &session, &signer);
    let (at, link) = landing_of(&landed);
    let planted = {
        let mut w = dialer.world();
        w.doc("1.0.2.0.67", false, "1.0.2", Vec::new());
        file(&mut w, "1.0.2.0.67", &merged.record, &[S], None)
    };
    let comps = crate::merge::reads::comps;
    assert!(comps(&a(&planted)) > comps(&link), "the premise: another home's link sorts above the merger's");
    dialer.world().memo.clear();
    dialer.clear();
    assert_eq!(
        resume(&board, &merged, draft_landing(&session, &signer, Some(a(S)))).expect("resumed"),
        Some(Landed::Draft { into: a(S), position: at, record: link, head_moved: None, staged: false })
    );
    assert!(dialer.frames("insert").is_empty() && dialer.frames("make_link").is_empty(), "{:?}", dialer.ops());

    // A landing of the key elsewhere: the race shape landed in `T`, then
    // in `U`, then in `T` again.
    let (t, u) = ("1.0.1.0.67", "1.0.1.0.68");
    let mut w = World::race();
    for draft in [t, u] {
        w.doc(draft, false, ACCOUNT, vec![run(D, 1, 11)]);
        w.staged(draft, &format!("{D}.1"), 11);
    }
    let (dialer, board, signer) = open(w);
    let session = sign_in(&board, &signer);
    let into = |draft: &str| draft_landing(&session, &signer, Some(a(draft)));
    let merged = compose(&board, Some(session.token()), &race_inputs()).expect("composed");
    let (_, in_t) = landing_of(&land(&board, &merged, into(t)).expect("landed in T"));
    let elsewhere = compose(&board, Some(session.token()), &race_inputs()).expect("composed again");
    dialer.clear();
    let (_, in_u) = landing_of(&land(&board, &elsewhere, into(u)).expect("landed in U"));
    assert_eq!(appended_record(&dialer)["replaces"].as_str(), Some(in_t.to_string().as_str()), "the premise: U's record replaces T's");
    assert!(!dialer.frames("make_link")[0]["to"]["addrs"].as_array().unwrap().contains(&json!(t)), "the premise: U's record links nowhere near T");
    let back = compose(&board, Some(session.token()), &race_inputs()).expect("composed a third time");
    dialer.clear();
    let (at, link) = landing_of(&land(&board, &back, into(t)).expect("landed in T again"));
    assert!(link != in_t && link != in_u, "a record of its own: {link}");
    let atom = appended_record(&dialer);
    assert_eq!(atom["landed"], json!({"draft": t, "position": at}));
    assert_eq!(atom["replaces"].as_str(), Some(in_u.to_string().as_str()), "U's record replaced");
}

/// A second landing of one key into one draft is the same landing.
///
/// Skep #790: where the merger's newest record for the key names the
/// draft, a landing into it sends its one `set_arrangement` and writes
/// no record, the record keeping the first landing's position. (i) An
/// edit between: the race shape landed in `T`, `T` edited, the merge
/// composed again — the same key, the first record its prior — and
/// landed in `T`. The write lands after the edit with the marker at it,
/// nothing is appended or linked, and the answer is the write's position
/// with the first record, which stays current for the key naming the
/// first position and verifies equal there; a `resume` answers the same,
/// writing nothing, and so does a fresh landing over either composition,
/// in a landing and a resume alike, the draft read as it stands (skep
/// #980); the undo is typed against the second write — the marker's,
/// never the record's — puts the edit back with the first landing's
/// marker, its own position kept (skep #964), and writes no record, the
/// first one standing for that marker; the undo after it, the edit since
/// the first landing standing in the words at that put-back, is typed
/// against the first landing and refused with no `own_ack`, and typed at
/// the first undo's write puts `T` back as staged, replacing the first
/// record. (ii) A take-back whose record went unwritten, the board too
/// busy to find the account's journal: the merge composed again and
/// landed in `T` is the same landing, the first record standing for it
/// and current, and the next undo is typed against the second write, its
/// record replacing the first. (iii) `T` with no recorded base, landed in
/// twice: a fresh landing finds it standing at the second write's
/// `set_arrangement` row, read off the supplement, beside the first
/// record.
#[test]
fn a_second_landing_of_one_key_into_one_draft_is_the_same_landing() {
    let t = "1.0.1.0.67";
    let world = || {
        let mut w = World::race();
        w.doc(t, false, ACCOUNT, vec![run(D, 1, 11)]);
        w.staged(t, &format!("{D}.1"), 11);
        w
    };
    let writes = ["stage", "set_arrangement", "create_new_document", "insert", "make_link"];
    let wrote = |dialer: &Scripted| dialer.ops().into_iter().filter(|o| writes.contains(&o.as_str())).collect::<Vec<_>>();

    // (i) An edit between.
    let (dialer, board, signer) = open(world());
    let session = sign_in(&board, &signer);
    let m = merger(&session, &signer);
    let into_t = || draft_landing(&session, &signer, Some(a(t)));
    let merged = compose(&board, Some(session.token()), &race_inputs()).expect("composed");
    let (first_at, first) = landing_of(&land(&board, &merged, into_t()).expect("landed"));
    let edited = vec![run(D, 1, 4), run(D, 12, 4)];
    let edit_at = dialer.world().change(t, edited.clone());
    let again = compose(&board, Some(session.token()), &race_inputs()).expect("composed again");
    assert_eq!(again.key, merged.key, "the premise: the same key");
    assert_eq!(again.prior.as_ref().and_then(|p| p.link.clone()), Some(first.clone()), "the premise: the first landing's record is the prior");
    dialer.clear();
    let relanded = land(&board, &again, into_t()).expect("landed again");
    let (at, _) = landing_of(&relanded);
    assert!(at > edit_at, "the write lands after the edit: {relanded:?}");
    assert_eq!(
        relanded,
        Landed::Draft { into: a(t), position: at, record: first.clone(), head_moved: None, staged: false },
        "the write's position, the first landing's record"
    );
    assert_eq!(wrote(&dialer), ["set_arrangement"], "one write, nothing of a record: {:?}", dialer.ops());
    let w = dialer.world();
    assert_eq!(w.docs.get(t).unwrap().runs, m_runs(&again), "T holds M");
    assert_eq!(w.standing(t).1.map(|m| m.at), Some(at), "the marker at the second write");
    drop(w);
    let found = current(&board, Some(session.token()), &a(K), &merged.key).expect("the lookup").expect("a record");
    assert_eq!(
        (found.link.clone(), found.landed.clone()),
        (Some(first.clone()), Some(RecordLanding::Draft { draft: a(t), position: first_at })),
        "one record for the key, naming the first landing's position"
    );
    assert_eq!(verify(&board, Some(session.token()), &found), Ok(Verdict::Equal), "T held M at the first landing's position");
    dialer.clear();
    assert_eq!(resume(&board, &again, into_t()).expect("resumed"), Some(relanded.clone()), "the marker's position, the first record");
    assert!(wrote(&dialer).is_empty(), "a resume writes nothing: {:?}", dialer.ops());
    // A fresh landing finds it standing where the marker names it, over
    // either composition, in a landing and a resume alike.
    let fresh = || draft_landing(&session, &signer, None);
    for composed in [&again, &merged] {
        dialer.clear();
        assert_eq!(land(&board, composed, fresh()).expect("found standing"), relanded);
        assert!(wrote(&dialer).is_empty(), "nothing staged or written: {:?}", dialer.ops());
        let read: Vec<Value> =
            dialer.frames("doc_metadata").iter().map(|f| f["doc"].clone()).collect();
        assert_eq!(
            (read, dialer.positions("doc_metadata")),
            (vec![json!(t)], vec![]),
            "the draft read as it stands: {:?}",
            dialer.ops()
        );
    }
    assert_eq!(resume(&board, &again, fresh()).expect("resumed"), Some(relanded.clone()));
    dialer.clear();
    let undone = undo(&board, m, &a(t), &a(K), None, None).expect("undone");
    let frame = dialer.frames("set_arrangement")[0].clone();
    assert_eq!(
        frame["as_of"].as_u64(),
        Some(at),
        "typed against the marker's position, never the record's"
    );
    assert_eq!(
        (&frame["merge"], &frame["head"]),
        (
            &json!({"sides": [format!("{D}.1.1")], "at": first_at}),
            &json!({"at": format!("{D}.2"), "extent": "15"})
        ),
        "the first landing's marker put back with its own position: {frame}"
    );
    let w = dialer.world();
    assert_eq!(
        w.docs.get(t).unwrap().runs,
        edited,
        "T as it stood before the second write: the edit"
    );
    assert_eq!(
        w.standing(t).1.map(|m| m.at),
        Some(first_at),
        "the first landing's marker standing again"
    );
    drop(w);
    assert_eq!(
        (undone.record, undone.marker.and_then(|m| m.at)),
        (None, Some(first_at)),
        "no record written, the first landing's standing for the marker put back"
    );
    assert!(
        dialer.frames("insert").is_empty() && dialer.frames("make_link").is_empty(),
        "nothing of a record: {:?}",
        dialer.ops()
    );
    let found = current(&board, Some(session.token()), &a(K), &merged.key)
        .expect("the lookup")
        .expect("a record");
    assert_eq!(
        (found.link, found.landed),
        (Some(first.clone()), Some(RecordLanding::Draft { draft: a(t), position: first_at })),
        "the first landing's record current"
    );
    // The undo after it: the edit since the first landing stands in the
    // words at the put-back, so with no `own_ack` it is typed against
    // the first landing and refused, the edit kept.
    let rows = dialer.world().rows.len();
    dialer.clear();
    let err = undo(&board, m, &a(t), &a(K), None, None)
        .expect_err("the edit since the first landing");
    let Refusal::Halt(Halt::Refused(refused)) = &err else { panic!("{err:?}") };
    assert_eq!(
        (refused.code.as_str(), dialer.frames("set_arrangement")[0]["as_of"].as_u64()),
        ("arrangement_moved", Some(first_at)),
        "typed against the first landing"
    );
    assert!(
        refused
            .detail
            .as_deref()
            .is_some_and(|d| d.contains(&format!("put back at position {}", undone.position))),
        "{refused:?}"
    );
    let w = dialer.world();
    assert_eq!(
        (&w.docs.get(t).unwrap().runs, w.rows.len()),
        (&edited, rows),
        "the edit stands, nothing committed"
    );
    drop(w);
    // Typed at the caller's own last ack, the first undo's write: T as
    // staged, the first landing's record replaced.
    dialer.clear();
    let staged = undo(&board, m, &a(t), &a(K), Some(undone.position), None)
        .expect("typed at the caller's own last ack");
    assert_eq!(staged.marker, None, "no marker before the first landing");
    assert_eq!(dialer.world().docs.get(t).unwrap().runs, vec![run(D, 1, 11)], "T as staged");
    assert_eq!(
        dialer.world().standing(t),
        (Some((format!("{D}.1"), 11)), None),
        "the base as staged, no marker"
    );
    assert_eq!(
        appended_record(&dialer)["replaces"].as_str(),
        Some(first.to_string().as_str()),
        "the first landing's record replaced"
    );

    // (ii) A take-back whose record went unwritten: the board too busy
    // to find the account's journal past the undo's write.
    let (dialer, board, signer) = open(world());
    let session = sign_in(&board, &signer);
    let m = merger(&session, &signer);
    let into_t = || draft_landing(&session, &signer, Some(a(t)));
    let merged = compose(&board, Some(session.token()), &race_inputs()).expect("composed");
    let (first_at, first) = landing_of(&land(&board, &merged, into_t()).expect("landed"));
    too_busy_for_the_find(&mut dialer.world());
    let err =
        undo(&board, m, &a(t), &a(K), None, None).expect_err("the undo's record unwritten");
    let Refusal::Halt(Halt::Halt(face)) = &err else { panic!("{err:?}") };
    assert!(face.state.contains("the record of the undo is not written: the board was too busy to find the account's merge journal"), "{face}");
    assert_eq!(
        dialer.world().docs.get(t).unwrap().runs,
        vec![run(D, 1, 11)],
        "the premise: the undo stands"
    );
    let again = compose(&board, Some(session.token()), &race_inputs()).expect("composed again");
    assert_eq!(
        again.prior.as_ref().and_then(|p| p.link.clone()),
        Some(first.clone()),
        "the premise: the undo's record unlinked, the first landing's is the prior"
    );
    dialer.clear();
    let relanded = land(&board, &again, into_t()).expect("landed again");
    let (at, record) = landing_of(&relanded);
    assert_eq!(record, first, "the same landing: {relanded:?}");
    assert!(at > first_at, "a write of its own: {relanded:?}");
    assert_eq!(wrote(&dialer), ["set_arrangement"], "one write, nothing of a record: {:?}", dialer.ops());
    let found = current(&board, Some(session.token()), &a(K), &merged.key).expect("the lookup").expect("a record");
    assert_eq!(
        (found.link, found.landed),
        (Some(first.clone()), Some(RecordLanding::Draft { draft: a(t), position: first_at })),
        "the first landing's record current, its position kept"
    );
    dialer.clear();
    undo(&board, m, &a(t), &a(K), None, None).expect("undone");
    assert_eq!(dialer.frames("set_arrangement")[0]["as_of"].as_u64(), Some(at), "typed against the second write");
    assert_eq!(dialer.world().docs.get(t).unwrap().runs, vec![run(D, 1, 11)], "T as it stood before the second write");
    assert_eq!(appended_record(&dialer)["replaces"].as_str(), Some(first.to_string().as_str()), "the first landing's record replaced");

    // (iii) `T` with no recorded base, landed in twice: a fresh landing
    // finds it standing at the second write's row on the supplement.
    let mut w = World::race();
    w.doc(t, false, ACCOUNT, vec![run(D, 1, 11)]);
    let (dialer, board, signer) = open(w);
    let session = sign_in(&board, &signer);
    let into_t = || draft_landing(&session, &signer, Some(a(t)));
    let merged = compose(&board, Some(session.token()), &race_inputs()).expect("composed");
    let (first_at, first) = landing_of(&land(&board, &merged, into_t()).expect("landed"));
    let again = compose(&board, Some(session.token()), &race_inputs()).expect("composed again");
    let (at, record) = landing_of(&land(&board, &again, into_t()).expect("landed again"));
    assert!(record == first && at > first_at, "the premise: the same landing");
    assert_eq!(dialer.world().standing(t), (None, None), "the premise: no base, no marker");
    dialer.clear();
    assert_eq!(
        land(&board, &again, draft_landing(&session, &signer, None)).expect("found standing"),
        Landed::Draft {
            into: a(t),
            position: at,
            record: first,
            head_moved: None,
            staged: false,
        },
        "the second write's row, the first landing's record"
    );
    assert!(wrote(&dialer).is_empty(), "nothing staged or written: {:?}", dialer.ops());
    assert!(
        dialer.ops().iter().any(|o| o.starts_with("GET /changes?")
            && o.contains(&format!("under={t}"))
            && o.contains("drafts=true")),
        "the draft's own rows read on the supplement: {:?}",
        dialer.ops()
    );
}

/// One merge landed twice in a draft is taken back a landing at a time.
///
/// Skep #964 with #790: the race shape landed in `T`, composed again and
/// landed again with nothing between — the same landing, its record the
/// first's. A publication landing between the first undo's read and its
/// write, the board's `marker_not_restorable`, is said in the person's
/// words, nothing changed. The first undo, with no `own_ack`, puts the
/// first landing's marker back with its own position, writes no record
/// and answers that marker; the second, with no `own_ack`, finds that
/// put-back on `T`'s rows, `T`'s words there those at the first landing,
/// and is typed against it, putting `T` back as staged and replacing the
/// record; a third has nothing to undo.
#[test]
fn one_merge_landed_twice_is_taken_back_one_landing_at_a_time() {
    let t = "1.0.1.0.67";
    let mut w = World::race();
    w.doc(t, false, ACCOUNT, vec![run(D, 1, 11)]);
    w.staged(t, &format!("{D}.1"), 11);
    let (dialer, board, signer) = open(w);
    let session = sign_in(&board, &signer);
    let m = merger(&session, &signer);
    let into_t = || draft_landing(&session, &signer, Some(a(t)));
    let merged = compose(&board, Some(session.token()), &race_inputs()).expect("composed");
    let (first_at, first) = landing_of(&land(&board, &merged, into_t()).expect("landed"));
    let again = compose(&board, Some(session.token()), &race_inputs()).expect("composed again");
    let (second_at, record) =
        landing_of(&land(&board, &again, into_t()).expect("landed again"));
    assert!(
        record == first && second_at > first_at,
        "the premise: the same landing, a write of its own"
    );
    // A publication raced past the read: the put-back refused.
    let id = format!("undo:{t}:{second_at}.arrangement");
    dialer
        .world()
        .memo
        .insert(id.clone(), permanent("set_arrangement", "marker_not_restorable", Value::Null));
    let err = undo(&board, m, &a(t), &a(K), None, None).expect_err("the put-back refused");
    let Refusal::Halt(Halt::Refused(refused)) = &err else { panic!("{err:?}") };
    let detail = refused.detail.as_deref().unwrap_or_default();
    assert!(
        refused.code == "marker_not_restorable"
            && detail.contains("was published since it was read")
            && detail.contains("nothing was changed"),
        "{refused:?}"
    );
    dialer.world().memo.remove(&id);
    // The first undo: the first landing's marker back, no record.
    dialer.clear();
    let undone =
        undo(&board, m, &a(t), &a(K), None, None).expect("the second landing taken back");
    let frame = dialer.frames("set_arrangement")[0].clone();
    assert_eq!(
        (frame["as_of"].as_u64(), &frame["merge"]),
        (Some(second_at), &json!({"sides": [format!("{D}.1.1")], "at": first_at})),
        "{frame}"
    );
    assert_eq!(
        (undone.record.clone(), undone.marker.as_ref().and_then(|m| m.at)),
        (None, Some(first_at))
    );
    assert!(dialer.frames("insert").is_empty(), "no record: {:?}", dialer.ops());
    let w = dialer.world();
    assert_eq!(w.standing(t).1.map(|m| m.at), Some(first_at), "the first landing's marker");
    assert_eq!(
        w.docs.get(t).unwrap().runs,
        m_runs(&merged),
        "T holds M, as the first landing left it"
    );
    drop(w);
    // The second undo: typed against the first undo's write.
    dialer.clear();
    let staged =
        undo(&board, m, &a(t), &a(K), None, None).expect("the first landing taken back");
    assert_eq!(
        dialer.frames("set_arrangement")[0]["as_of"],
        json!(undone.position),
        "typed against the put-back"
    );
    assert_eq!(staged.marker, None);
    assert_eq!(dialer.world().docs.get(t).unwrap().runs, vec![run(D, 1, 11)], "T as staged");
    assert_eq!(
        dialer.world().standing(t),
        (Some((format!("{D}.1"), 11)), None),
        "the base as staged, no marker"
    );
    assert_eq!(
        appended_record(&dialer)["replaces"].as_str(),
        Some(first.to_string().as_str()),
        "the first landing's record replaced"
    );
    // A third: nothing to undo.
    assert_eq!(
        undo(&board, m, &a(t), &a(K), None, None),
        Err(Refusal::NothingToUndo { draft: a(t), why: NoUndo::TakenBack })
    );
}

/// An undo of a merge landed over another puts that one's marker back.
///
/// Skep #964: the race shape landed in `T` — merge A — then the
/// draft-side merge of `T` landed over it — merge B — its record left
/// unwritten, the board too busy to find the journal. The undo of B puts
/// A's marker back as it stood and answers it, and writes no record: A's
/// record names no landing of B's, and stays current for A's key. The
/// undo after it takes A back, typed against the first undo's write, and
/// replaces A's record.
#[test]
fn an_undo_of_a_merge_landed_over_another_puts_its_marker_back_and_leaves_its_record() {
    let t = "1.0.1.0.67";
    let mut w = World::race();
    w.doc(t, false, ACCOUNT, vec![run(D, 1, 11)]);
    w.staged(t, &format!("{D}.1"), 11);
    let (dialer, board, signer) = open(w);
    let session = sign_in(&board, &signer);
    let m = merger(&session, &signer);
    let into_t = || draft_landing(&session, &signer, Some(a(t)));
    let merge_a = compose(&board, Some(session.token()), &race_inputs()).expect("A composed");
    let (a_at, a_record) = landing_of(&land(&board, &merge_a, into_t()).expect("A landed"));
    let b_inputs =
        Inputs { sides: vec![Side::Draft { at: a(t), position: None }], ..race_inputs() };
    let merge_b = compose(&board, Some(session.token()), &b_inputs).expect("B composed");
    too_busy_for_the_find(&mut dialer.world());
    let err = land(&board, &merge_b, into_t()).expect_err("B's record unwritten");
    assert!(
        matches!(&err, Refusal::Halt(Halt::Halt(face)) if face.state.contains(&format!("the merge stands at {t}"))),
        "the premise: {err:?}"
    );
    let b_marker = dialer.world().standing(t).1.expect("the premise: B's marker");
    assert!(b_marker.sides.is_empty() && b_marker.at > a_at, "the premise: {b_marker:?}");
    dialer.clear();
    let undone = undo(&board, m, &a(t), &a(K), None, None).expect("B taken back");
    assert_eq!(
        dialer.frames("set_arrangement")[0]["merge"],
        json!({"sides": [format!("{D}.1.1")], "at": a_at}),
        "A's marker put back"
    );
    assert_eq!(
        (undone.record.clone(), undone.marker.as_ref().and_then(|m| m.at)),
        (None, Some(a_at)),
        "no record of B's landing stood"
    );
    assert!(
        dialer.frames("insert").is_empty() && dialer.frames("make_link").is_empty(),
        "nothing of a record: {:?}",
        dialer.ops()
    );
    assert_eq!(dialer.world().docs.get(t).unwrap().runs, m_runs(&merge_a), "T as A left it");
    let found = current(&board, Some(session.token()), &a(K), &merge_a.key)
        .expect("the lookup")
        .expect("a record");
    assert_eq!(
        (found.link, found.landed),
        (Some(a_record.clone()), Some(RecordLanding::Draft { draft: a(t), position: a_at })),
        "A's record current"
    );
    dialer.clear();
    undo(&board, m, &a(t), &a(K), None, None).expect("A taken back");
    assert_eq!(
        dialer.frames("set_arrangement")[0]["as_of"],
        json!(undone.position),
        "typed against the first undo's write"
    );
    assert_eq!(
        dialer.world().standing(t),
        (Some((format!("{D}.1"), 11)), None),
        "T's base as staged, no marker"
    );
    assert_eq!(
        appended_record(&dialer)["replaces"].as_str(),
        Some(a_record.to_string().as_str()),
        "A's record replaced"
    );
}

/// Two merges of one head and sides in a draft are each taken back by
/// their own record.
///
/// Skep #964: the draft-side merge of `T` landed in it, `T`'s base
/// moving to the head, then composed again — another key, the same head
/// and sides — and landed again, its record of its own. The undo takes
/// the second back and replaces its record, the first landing's marker
/// put back. Composed a third time and landed with its record unwritten,
/// then undone: the first landing's record stands for the marker put
/// back, and the second's, replaced, is never taken back again — nothing
/// is written. The last undo, typed against the latest put-back, takes
/// the first landing back and replaces its record. And where the second
/// landing's undo left its record unwritten, the second's record, naming
/// a landing made since the first, is never the first landing's: a fresh
/// landing of the second merge finds it standing at its own position,
/// never at the first merge's marker below it, and the undo of the first
/// replaces the first's.
#[test]
fn two_merges_of_one_head_and_sides_are_each_taken_back_by_their_own_record() {
    let t = "1.0.1.0.67";
    let mut w = World::race();
    w.doc(t, false, ACCOUNT, vec![run(D, 1, 11)]);
    w.staged(t, &format!("{D}.1"), 11);
    let (dialer, board, signer) = open(w);
    let session = sign_in(&board, &signer);
    let m = merger(&session, &signer);
    let into_t = || draft_landing(&session, &signer, Some(a(t)));
    let inputs =
        Inputs { sides: vec![Side::Draft { at: a(t), position: None }], ..race_inputs() };
    let first = compose(&board, Some(session.token()), &inputs).expect("composed");
    let (first_at, first_record) = landing_of(&land(&board, &first, into_t()).expect("landed"));
    let second = compose(&board, Some(session.token()), &inputs).expect("composed again");
    assert_ne!(second.key, first.key, "the premise: T's base moved, another key");
    let (_, second_record) =
        landing_of(&land(&board, &second, into_t()).expect("landed again"));
    assert_ne!(second_record, first_record, "the premise: a record of its own");
    dialer.clear();
    let undone = undo(&board, m, &a(t), &a(K), None, None).expect("the second taken back");
    assert_eq!(
        undone.marker.as_ref().and_then(|m| m.at),
        Some(first_at),
        "the first landing's marker put back"
    );
    assert_eq!(
        appended_record(&dialer)["replaces"].as_str(),
        Some(second_record.to_string().as_str()),
        "the second landing's record replaced"
    );
    let third = compose(&board, Some(session.token()), &inputs).expect("composed a third time");
    too_busy_for_the_find(&mut dialer.world());
    assert!(
        matches!(land(&board, &third, into_t()), Err(Refusal::Halt(Halt::Halt(_)))),
        "the premise: landed, its record unwritten"
    );
    dialer.clear();
    let undone = undo(&board, m, &a(t), &a(K), None, None).expect("the third taken back");
    assert_eq!(
        (undone.record, undone.marker.and_then(|m| m.at)),
        (None, Some(first_at)),
        "the first landing's record stands for the marker put back"
    );
    assert!(
        dialer.frames("insert").is_empty() && dialer.frames("make_link").is_empty(),
        "no record written: {:?}",
        dialer.ops()
    );
    dialer.clear();
    let staged = undo(&board, m, &a(t), &a(K), None, None).expect("the first taken back");
    assert_eq!(
        dialer.frames("set_arrangement")[0]["as_of"],
        json!(undone.position),
        "typed against the latest put-back"
    );
    assert_eq!(staged.marker, None);
    assert_eq!(
        dialer.world().standing(t),
        (Some((format!("{D}.1"), 11)), None),
        "T's base as staged, no marker"
    );
    assert_eq!(
        appended_record(&dialer)["replaces"].as_str(),
        Some(first_record.to_string().as_str()),
        "the first landing's record replaced"
    );

    // The second landing's undo with its record unwritten.
    let mut w = World::race();
    w.doc(t, false, ACCOUNT, vec![run(D, 1, 11)]);
    w.staged(t, &format!("{D}.1"), 11);
    let (dialer, board, signer) = open(w);
    let session = sign_in(&board, &signer);
    let m = merger(&session, &signer);
    let into_t = || draft_landing(&session, &signer, Some(a(t)));
    let first = compose(&board, Some(session.token()), &inputs).expect("composed");
    let (_, first_record) = landing_of(&land(&board, &first, into_t()).expect("landed"));
    let second = compose(&board, Some(session.token()), &inputs).expect("composed again");
    let (second_at, second_record) =
        landing_of(&land(&board, &second, into_t()).expect("landed again"));
    too_busy_for_the_find(&mut dialer.world());
    let err =
        undo(&board, m, &a(t), &a(K), None, None).expect_err("the undo's record unwritten");
    assert!(
        matches!(&err, Refusal::Halt(Halt::Halt(face)) if face.state.contains("the merge landed before it standing again")),
        "the premise, the earlier merge back: {err:?}"
    );
    // A fresh landing of the second merge finds its record standing while
    // `T` marks the first merge's landing, below the record's position:
    // the record's position, never the earlier merge's.
    dialer.clear();
    assert_eq!(
        land(&board, &second, draft_landing(&session, &signer, None)).expect("found standing"),
        Landed::Draft {
            into: a(t),
            position: second_at,
            record: second_record,
            head_moved: None,
            staged: false,
        }
    );
    assert!(
        dialer.frames("stage").is_empty() && dialer.frames("set_arrangement").is_empty(),
        "nothing staged or written: {:?}",
        dialer.ops()
    );
    dialer.clear();
    undo(&board, m, &a(t), &a(K), None, None).expect("the first taken back");
    assert_eq!(
        appended_record(&dialer)["replaces"].as_str(),
        Some(first_record.to_string().as_str()),
        "the first landing's record replaced, never the second's"
    );
}

/// An undo over the marker a stage copied puts it back, inherited still.
///
/// Skep #964, P2: the race shape landed in `T0`, `T` staged from it — the
/// marker copied, stamped at `T`'s mint — and the same merge landed in
/// `T`, a landing of its own with a record of its own. The undo puts the
/// copied marker back with its mint position, the head and the sides the
/// landing's own, and replaces `T`'s record: a copied marker marks no
/// landing, so no record stands for it. The undo after it answers
/// `Inherited`, nothing sent. With the record left unwritten, the face
/// is a plain take-back's, a re-run finding no merge to take out, never
/// an earlier landing's merge standing again.
#[test]
fn an_undo_over_the_marker_a_stage_copied_puts_it_back_and_the_next_answers_inherited() {
    let t0 = "1.0.1.0.67";
    let world = || {
        let mut w = World::race();
        w.doc(t0, false, ACCOUNT, vec![run(D, 1, 11)]);
        w.staged(t0, &format!("{D}.1"), 11);
        w
    };
    let (dialer, board, signer) = open(world());
    let session = sign_in(&board, &signer);
    let m = merger(&session, &signer);
    let into = |draft: &str| draft_landing(&session, &signer, Some(a(draft)));
    let merged = compose(&board, Some(session.token()), &race_inputs()).expect("composed");
    land(&board, &merged, into(t0)).expect("landed in T0");
    let Answer::Document(ack) =
        board.op(Some(session.token()), &frames::stage(t0, None)).expect("the stage")
    else {
        panic!("closed")
    };
    let t = acked_addr(&ack).expect("T").to_string();
    let minted = acked_at(&ack).expect("its position");
    let again = compose(&board, Some(session.token()), &race_inputs()).expect("composed again");
    let (at, link) = landing_of(&land(&board, &again, into(&t)).expect("landed in T"));
    assert!(at > minted, "the premise: a landing of its own");
    dialer.clear();
    let undone = undo(&board, m, &a(&t), &a(K), None, None).expect("T's landing taken back");
    assert_eq!(
        dialer.frames("set_arrangement")[0]["merge"],
        json!({"sides": [format!("{D}.1.1")], "at": minted}),
        "the copied marker put back at T's mint"
    );
    assert_eq!(undone.marker.as_ref().and_then(|m| m.at), Some(minted));
    assert_eq!(
        dialer.world().standing(&t).1.map(|m| m.at),
        Some(minted),
        "the copied marker standing"
    );
    assert!(undone.record.is_some(), "a copied marker marks no landing: T's record replaced");
    assert_eq!(appended_record(&dialer)["replaces"].as_str(), Some(link.to_string().as_str()));
    dialer.clear();
    assert_eq!(
        undo(&board, m, &a(&t), &a(K), None, None),
        Err(Refusal::NothingToUndo { draft: a(&t), why: NoUndo::Inherited })
    );
    assert!(
        dialer.frames("set_arrangement").is_empty() && dialer.frames("insert").is_empty(),
        "nothing sent: {:?}",
        dialer.ops()
    );

    // The same undo, its record left unwritten.
    let (dialer, board, signer) = open(world());
    let session = sign_in(&board, &signer);
    let m = merger(&session, &signer);
    let into = |draft: &str| draft_landing(&session, &signer, Some(a(draft)));
    let merged = compose(&board, Some(session.token()), &race_inputs()).expect("composed");
    land(&board, &merged, into(t0)).expect("landed in T0");
    let Answer::Document(ack) =
        board.op(Some(session.token()), &frames::stage(t0, None)).expect("the stage")
    else {
        panic!("closed")
    };
    let t = acked_addr(&ack).expect("T").to_string();
    let again = compose(&board, Some(session.token()), &race_inputs()).expect("composed again");
    land(&board, &again, into(&t)).expect("landed in T");
    too_busy_for_the_find(&mut dialer.world());
    let err = undo(&board, m, &a(&t), &a(K), None, None).expect_err("the record unwritten");
    let Refusal::Halt(Halt::Halt(face)) = &err else { panic!("{err:?}") };
    assert!(
        face.state.starts_with(&format!(
            "the merge is out of {t}, and the record of the undo is not written"
        )),
        "{face}"
    );
    assert_eq!(face.act, OnEnd::TakenOut.act(), "a plain take-back's way on: {face}");
}

/// A fresh landing reads the standing record as it lands, never `prior`.
///
/// The merge record's §1.5 (ii) and §4's currency read it so. (a) A
/// composition kept from after a fresh landing in `F`, its `prior` naming
/// that landing, landed once `F` is undone: the undo's record is the
/// merger's newest for the key, so a `resume` answers none and the landing
/// stages a draft of its own holding M, its record replacing the undo's and
/// current for the key, `staged`; a re-run and a `resume` answer that
/// landing found standing, `staged` false, and write nothing. (a′) The same
/// after a withdrawal. (b) Another account's record of the key, naming that
/// account's draft, is the composition's `prior` where the merger's home
/// holds none: it is never the merger's landing — a `resume` answers none,
/// and the landing stages its own, `staged`, its record replacing nothing
/// (P20); landed again, that composition — its `prior` still the other
/// account's — is answered the merger's own landing, `staged` false,
/// nothing staged or written. (c) The composition that landed fresh, its
/// `prior` none, in a fresh session: the landing's own record answers it,
/// `staged` false, nothing staged or written.
#[test]
fn a_fresh_landing_reads_the_standing_record_when_it_lands_never_the_compositions() {
    let writes = ["stage", "set_arrangement", "create_new_document", "insert", "make_link"];
    let wrote = |dialer: &Scripted| dialer.ops().into_iter().filter(|o| writes.contains(&o.as_str())).collect::<Vec<_>>();
    // (a), (a′): a composition kept across an undo and a withdrawal.
    for act in ["undo", "withdraw"] {
        let (dialer, board, signer) = open(draft_landing_world());
        let session = sign_in(&board, &signer);
        let m = merger(&session, &signer);
        let fresh_landing = || draft_landing(&session, &signer, None);
        let merged = compose(&board, Some(session.token()), &draft_inputs()).expect("composed");
        let landed = land(&board, &merged, fresh_landing()).expect("landed fresh");
        let Landed::Draft { into: f, record: first, .. } = landed.clone() else { panic!("{landed:?}") };
        let kept = compose(&board, Some(session.token()), &draft_inputs()).expect("composed after the landing");
        assert_eq!(kept.prior.as_ref().and_then(|p| p.link.clone()), Some(first.clone()), "{act}: the premise: the kept composition's prior names the landing");
        let taken_back = match act {
            "undo" => undo(&board, m, &f, &a(K), None, None).expect("undone").record,
            _ => withdraw(&board, m, &f, &a(K), None).expect("withdrawn").record,
        }
        .expect("the take-back's record");
        dialer.clear();
        assert_eq!(resume(&board, &kept, fresh_landing()).expect("resumed"), None, "{act}: nothing stands for the key");
        assert!(wrote(&dialer).is_empty(), "{act}: a resume writes nothing: {:?}", dialer.ops());
        dialer.clear();
        let relanded = land(&board, &kept, fresh_landing()).expect("landed again");
        let Landed::Draft { into: f2, position: at, record: link, head_moved, staged } = relanded.clone() else { panic!("{relanded:?}") };
        assert!(f2 != f && link != first && link != taken_back, "{act}: a draft and a record of its own: {relanded:?}");
        assert_eq!((head_moved, staged), (None, true), "{act}: staged by this call");
        assert_eq!(dialer.frames("stage").len(), 1, "{act}: one stage: {:?}", dialer.ops());
        assert_eq!(dialer.world().docs.get(&f2.to_string()).unwrap().runs, draft_m(), "{act}: the fresh draft holds M");
        let atom = appended_record(&dialer);
        assert_eq!(atom["landed"], json!({"draft": f2.to_string(), "position": at}));
        assert_eq!(atom["replaces"].as_str(), Some(taken_back.to_string().as_str()), "{act}: the take-back's record replaced, never the composition's prior");
        let found = current(&board, Some(session.token()), &a(K), &kept.key).expect("the lookup").expect("a record");
        assert_eq!(found.link, Some(link.clone()), "{act}: the landing's record is current for the key");
        let rows = dialer.world().rows.len();
        dialer.clear();
        assert_eq!(land(&board, &kept, fresh_landing()).expect("landed a third time"), as_found(&relanded));
        assert_eq!(resume(&board, &kept, fresh_landing()).expect("resumed"), Some(as_found(&relanded)));
        assert!(wrote(&dialer).is_empty(), "{act}: nothing staged, nothing written: {:?}", dialer.ops());
        assert_eq!(dialer.world().rows.len(), rows, "{act}: nothing written twice");
    }

    // (b) Another account's record of the key, the composition's prior.
    let (dialer, board, signer) = open(draft_landing_world());
    let session = sign_in(&board, &signer);
    let fresh_landing = || draft_landing(&session, &signer, None);
    let theirs = "1.0.2.0.68";
    let mut record = compose(&board, Some(session.token()), &draft_inputs()).expect("composed").record;
    record.landed = Some(RecordLanding::Draft { draft: a(theirs), position: 5 });
    let planted = {
        let mut w = dialer.world();
        w.doc("1.0.2.0.67", false, "1.0.2", Vec::new());
        file(&mut w, "1.0.2.0.67", &record, &[theirs, S], None)
    };
    let merged = compose(&board, Some(session.token()), &draft_inputs()).expect("composed after it");
    assert_eq!(merged.prior.as_ref().and_then(|p| p.link.as_ref()).map(ToString::to_string), Some(planted), "the premise: another home's record is the prior");
    assert_eq!(resume(&board, &merged, fresh_landing()).expect("resumed"), None, "another account's landing is never the merger's");
    dialer.clear();
    let landed = land(&board, &merged, fresh_landing()).expect("landed");
    let Landed::Draft { into: f, staged, .. } = &landed else { panic!("{landed:?}") };
    assert_ne!(f.to_string(), theirs, "a draft of its own: {landed:?}");
    assert!(*staged, "staged by this call: {landed:?}");
    assert_eq!(dialer.frames("stage").len(), 1, "{:?}", dialer.ops());
    assert!(appended_record(&dialer)["replaces"].is_null(), "no record stood in the merger's home");
    // Landed again, its `prior` still the other account's: the merger's
    // own landing, read at the landing, found standing.
    let rows = dialer.world().rows.len();
    dialer.clear();
    assert_eq!(land(&board, &merged, fresh_landing()).expect("landed again"), as_found(&landed));
    assert!(wrote(&dialer).is_empty(), "nothing staged, nothing written: {:?}", dialer.ops());
    assert_eq!(dialer.world().rows.len(), rows);

    // (c) The composition that landed fresh, in a fresh session.
    let (dialer, board, signer) = open(draft_landing_world());
    let session = sign_in(&board, &signer);
    let fresh_landing = || draft_landing(&session, &signer, None);
    let merged = compose(&board, Some(session.token()), &draft_inputs()).expect("composed");
    let landed = land(&board, &merged, fresh_landing()).expect("landed fresh");
    assert!(matches!(landed, Landed::Draft { staged: true, .. }), "staged by this call: {landed:?}");
    assert_eq!(merged.prior, None, "the premise: composed before its landing");
    dialer.world().memo.clear();
    let rows = dialer.world().rows.len();
    dialer.clear();
    assert_eq!(resume(&board, &merged, fresh_landing()).expect("resumed"), Some(as_found(&landed)));
    assert_eq!(land(&board, &merged, fresh_landing()).expect("landed again"), as_found(&landed));
    assert!(wrote(&dialer).is_empty(), "nothing staged, nothing written: {:?}", dialer.ops());
    assert_eq!(dialer.world().rows.len(), rows);
}

/// A FRESH LANDING AFTER ITS TAKE-BACK, IN ONE SESSION, STAGES A DRAFT OF
/// ITS OWN (wire.md §Correlation and idempotency: the memo answers a
/// repeat of the identical request). The composition landed fresh in
/// `F`, `F` undone, the same composition landed again with no draft
/// named: the undo's record is the merger's newest for the key, so the
/// stage's id names it — its stem over `<key>@<P>~<link>` — and the
/// board's memo never answers it with `F`. A stage and a landing commit,
/// the new draft holding M with its marker while `F` keeps the head's
/// text the undo restored; the record's ids carry the new draft's stem
/// and its `replaces` names the undo's record. A call after it answers
/// that landing, nothing written.
#[test]
fn a_fresh_landing_after_its_take_back_in_one_session_stages_a_draft_of_its_own() {
    let (dialer, board, signer) = open(draft_landing_world());
    let session = sign_in(&board, &signer);
    let fresh_landing = || draft_landing(&session, &signer, None);
    let merged = compose(&board, Some(session.token()), &draft_inputs()).expect("composed");
    let landed = land(&board, &merged, fresh_landing()).expect("landed fresh");
    let Landed::Draft { into: f, .. } = landed.clone() else { panic!("{landed:?}") };
    let undone = undo(&board, merger(&session, &signer), &f, &a(K), None, None).expect("undone").record.expect("the undo's record");
    let head = vec![run(D, 1, 4), run(D, 12, 4), run(D, 5, 7)];
    assert_eq!(dialer.world().docs.get(&f.to_string()).unwrap().runs, head, "the premise: the undo restored the head's text");
    let rows = dialer.world().rows.len();
    dialer.clear();
    let relanded = land(&board, &merged, fresh_landing()).expect("landed again");
    let Landed::Draft { into: f2, position: at, record: link, staged, .. } = relanded.clone() else { panic!("{relanded:?}") };
    assert!(staged, "staged by this call: {relanded:?}");
    assert_eq!(
        dialer.frames("stage")[0]["id"].as_str(),
        Some(landing_id(&format!("{}@{}~{undone}", merged.key.text(), merged.as_of), "stage").as_str()),
        "the stage's id names the record the landing follows"
    );
    let stage_at = dialer.world().rows.iter().rev().find(|r| r.op == "stage").unwrap().at;
    let stem = Stem::of(&format!("{}:{f2}@{stage_at}", merged.key.text()));
    assert_eq!(dialer.frames("set_arrangement")[0]["id"].as_str(), Some(stem.id("draft").as_str()));
    assert_eq!(dialer.frames("insert")[0]["id"].as_str(), Some(stem.id("record").as_str()));
    assert_eq!(dialer.frames("make_link")[0]["id"].as_str(), Some(stem.id("link").as_str()));
    let w = dialer.world();
    assert!(w.rows.len() > rows, "committed, never the memo's answers to the first landing");
    assert_ne!(f2, f, "a draft of its own: {relanded:?}");
    assert_eq!(w.docs.get(&f2.to_string()).unwrap().runs, draft_m(), "the new draft holds M");
    assert_eq!(w.docs.get(&f.to_string()).unwrap().runs, head, "F keeps what the undo restored");
    assert_eq!(w.standing(&f2.to_string()).1.map(|m| m.at), Some(at), "the marker at the new landing");
    drop(w);
    assert_ne!(link, undone);
    assert_eq!(appended_record(&dialer)["replaces"].as_str(), Some(undone.to_string().as_str()), "the undo's record replaced");
    // Again: the new landing's record answers it, nothing written twice.
    let rows = dialer.world().rows.len();
    dialer.clear();
    assert_eq!(land(&board, &merged, fresh_landing()).expect("landed a third time"), as_found(&relanded));
    assert!(dialer.frames("stage").is_empty(), "nothing staged: {:?}", dialer.ops());
    assert_eq!(dialer.world().rows.len(), rows, "nothing written twice");
}

/// A LANDING's RECORD REPLACES THE MERGER's NEWEST RECORD AS IT LANDS (the
/// merge record's §4, `replaces`; P20: a later record from the same home
/// naming the one it replaces), never the composition's. One composition
/// of the race shape landed in `T`, `T` withdrawn, then the same
/// composition landed in `U`: its record replaces the withdrawal's, which
/// the composition never saw. The trunk owner's shot, composed while
/// another account's record of the key stood and its own home held none,
/// replaces nothing.
#[test]
fn a_landings_record_replaces_the_mergers_newest_record_as_it_lands() {
    // A composition kept across a withdrawal, landed into another draft.
    let (t, u) = ("1.0.1.0.67", "1.0.1.0.68");
    let mut w = World::race();
    for draft in [t, u] {
        w.doc(draft, false, ACCOUNT, vec![run(D, 1, 11)]);
        w.staged(draft, &format!("{D}.1"), 11);
    }
    let (dialer, board, signer) = open(w);
    let session = sign_in(&board, &signer);
    let into = |draft: &str| draft_landing(&session, &signer, Some(a(draft)));
    let merged = compose(&board, Some(session.token()), &race_inputs()).expect("composed");
    assert_eq!(merged.record.replaces, None, "the premise: no record stood when it was composed");
    land(&board, &merged, into(t)).expect("landed in T");
    let withdrawn = withdraw(&board, merger(&session, &signer), &a(t), &a(K), None).expect("withdrawn").record.expect("the withdrawal's record");
    dialer.clear();
    let (_, link) = landing_of(&land(&board, &merged, into(u)).expect("landed in U"));
    assert_eq!(appended_record(&dialer)["replaces"].as_str(), Some(withdrawn.to_string().as_str()), "the withdrawal's record replaced");
    let found = current(&board, Some(session.token()), &a(K), &merged.key).expect("the lookup").expect("a record");
    assert_eq!((found.link, found.replaces), (Some(link), Some(withdrawn)), "current for the key, naming what it replaces");

    // The owner's shot over another account's record of the key.
    let (dialer, board, signer) = open(World::race());
    let session = sign_in(&board, &signer);
    let daughter = format!("{D}.1.1");
    let mut theirs = compose(&board, Some(session.token()), &race_inputs()).expect("composed").record;
    theirs.landed = Some(RecordLanding::Draft { draft: a(F), position: 5 });
    let planted = {
        let mut w = dialer.world();
        w.doc("1.0.2.0.67", false, "1.0.2", Vec::new());
        file(&mut w, "1.0.2.0.67", &theirs, &[F, &daughter], None)
    };
    let merged = compose(&board, Some(session.token()), &race_inputs()).expect("composed after it");
    assert_eq!(merged.record.replaces.as_ref().map(ToString::to_string), Some(planted), "the premise: the composition names another home's record");
    dialer.clear();
    let landed = land(&board, &merged, shot(&session, &signer)).expect("landed");
    assert!(matches!(landed, Landed::Member { .. }), "{landed:?}");
    assert!(appended_record(&dialer)["replaces"].is_null(), "the merger's home held no record of the key, so the record replaces none");
}

/// Every refusal the one write can answer, each mapped (item 4):
/// `not_owner` naming the draft, `published_target`, `withheld` naming
/// the origin and its words in C as the write sends it — none for `Z`,
/// which no run windows; `D`'s eleven at 1–11, `S`'s three after them left
/// out — and with no site the draft and no words (the mutant that counts
/// the draft's own run in the site's place names `S`'s at 12–14),
/// `signed_session_required`, `doc_not_registered` naming
/// the draft; `source_not_registered`, `no_base_to_record`,
/// `base_not_in_chain`, `base_extent_too_large` and the runs' codes as
/// the library's own faults, since it sends only the base and the runs
/// it read; the board's others verbatim — and nothing after the
/// refusal. A published document is refused at the metadata read, before
/// any position is read.
#[test]
fn the_take_backs_refusals_are_mapped() {
    let (dialer, board, signer) = open(draft_landing_world());
    let session = sign_in(&board, &signer);
    let m = merger(&session, &signer);
    let (_, landed) = landed_in_s(&board, &session, &signer);
    let (at, _) = landing_of(&landed);
    let rows = dialer.world().rows.len();
    let id = format!("undo:{S}:{at}.arrangement");
    let refused = |code: &str, site: Option<&str>| -> Refusal {
        let site = site.map_or(Value::Null, |s| json!({"addr": s}));
        dialer.world().memo.insert(id.clone(), permanent("set_arrangement", code, site));
        dialer.clear();
        let err = undo(&board, m, &a(S), &a(K), None, None).expect_err(code);
        assert_eq!(dialer.ops().last().map(String::as_str), Some("set_arrangement"), "{code}: nothing after the refusal: {:?}", dialer.ops());
        assert_eq!(dialer.world().rows.len(), rows, "{code}: nothing committed");
        err
    };
    assert_eq!(refused("not_owner", Some(S)), Refusal::NotOwner { draft: a(S) });
    assert_eq!(refused("published_target", None), Refusal::Published { doc: a(S) });
    assert_eq!(
        refused("withheld", Some(Z)),
        Refusal::WindowWithheld { origin: a(Z), positions: Vec::new() }
    );
    assert_eq!(
        dialer.frames("set_arrangement")[0]["runs"],
        frame_runs(&draft_c()),
        "the premise: C as the write sends it"
    );
    assert_eq!(
        refused("withheld", Some(D)),
        Refusal::WindowWithheld { origin: a(D), positions: vec![(1, 11)] }
    );
    let unsited = refused("withheld", None);
    assert!(
        matches!(&unsited, Refusal::WindowWithheld { positions, .. } if positions.is_empty()),
        "{unsited:?}"
    );
    assert_eq!(refused("signed_session_required", None), Refusal::NeedsSignedSession);
    assert_eq!(refused("doc_not_registered", None), Refusal::NoSuchDocument(a(S)));
    for code in ["source_not_registered", "no_base_to_record", "base_not_in_chain", "base_extent_too_large", "fork_base_moved", "bad_run", "dangling_source", "too_many_runs", "malformed"] {
        let err = refused(code, None);
        let Refusal::Halt(Halt::Halt(face)) = &err else { panic!("{code}: {err:?}") };
        assert!(face.cause.contains(code) && face.act.contains("fault in this library"), "{code}: {face}");
    }
    let err = refused("txn_over_budget", None);
    let Refusal::Halt(Halt::Refused(verbatim)) = &err else { panic!("{err:?}") };
    assert_eq!(verbatim.code, "txn_over_budget");
    let said = Refusal::NotOwner { draft: a(S) }.to_string();
    assert!(said.contains("not_owner") && said.contains("nothing was changed"), "{said}");
    // A published document: refused at the metadata read.
    dialer.world().docs.get_mut(S).unwrap().published = true;
    dialer.clear();
    assert_eq!(undo(&board, m, &a(S), &a(K), None, None), Err(Refusal::Published { doc: a(S) }));
    assert_eq!(withdraw(&board, m, &a(S), &a(K), None), Err(Refusal::Published { doc: a(S) }));
    assert_eq!(dialer.ops(), ["doc_metadata", "doc_metadata"], "the one read each, nothing sent");
}

/// A CLAIMED BOARD WHOSE HEAD IS OWED TAKES A MERGE BACK UNSIGNED:
/// `/health` names a claimant and `H.1` serves no record — read afresh,
/// since a board keeps the head it read — and neither take-back signs a
/// write, so the undo and the withdrawal each read no head, send their
/// one `set_arrangement` and the record's two writes with no `attest`,
/// and replace the landing's record.
#[test]
fn a_claimed_board_serving_no_head_record_takes_a_merge_back_unsigned() {
    for name in ["the undo", "the withdrawal"] {
        let (dialer, board, signer) = open(draft_landing_world());
        let session = sign_in(&board, &signer);
        let (_, landed) = landed_in_s(&board, &session, &signer);
        let (_, link) = landing_of(&landed);
        dialer.world().head = false;
        let afresh =
            Board::new(Origin::parse("http://127.0.0.1:8642").unwrap(), dialer.clone());
        let session = sign_in(&afresh, &signer);
        let m = merger(&session, &signer);
        dialer.clear();
        let record = match name {
            "the undo" => undo(&afresh, m, &a(S), &a(K), None, None).map(|u| u.record),
            _ => withdraw(&afresh, m, &a(S), &a(K), None).map(|w| w.record),
        };
        let record = record.unwrap_or_else(|e| panic!("{name}: {e}"));
        assert!(record.is_some(), "{name}: the replacing record");
        assert!(
            dialer.frames("retrieve_v").iter().all(|f| f["specs"][0]["doc"] != HEAD_MEMBER_1),
            "{name}: no head read: {:?}",
            dialer.ops()
        );
        for op in ["set_arrangement", "insert", "make_link"] {
            let frames = dialer.frames(op);
            assert_eq!(frames.len(), 1, "{name}: one `{op}`: {:?}", dialer.ops());
            assert!(frames[0].get("attest").is_none(), "{name}: unsigned: {}", frames[0]);
        }
        assert!(dialer.world().standing(S).1.is_none(), "{name}: the marker cleared");
        assert_eq!(
            appended_record(&dialer)["replaces"].as_str(),
            Some(link.to_string().as_str()),
            "{name}: the landing's record replaced"
        );
    }
}
