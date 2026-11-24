//! Landing again after a take-back, over the scripted board.
//!
//! The suite checks that a landing after a take-back is a write and a
//! record of its own, in one session or a fresh one, the same composition
//! landed again judged by the board, a fresh one staging a draft of its
//! own; that a resume finds a draft landing by its mark, never by the
//! draft's words or a marker it was staged with; that the standing record
//! is the merger's own newest for the key, read as a fresh landing lands
//! and replaced by its record; that a fresh landing finds its own landing
//! standing in any draft the merger's records of the key name, whatever
//! landed or was taken back in another since — a take-back's record written
//! late among them — and never another composition's landing of the key,
//! which stages a draft of its own; that a second landing of one key into one
//! draft is the same landing; that merges landed one over another are taken
//! back a landing at a time, each by its own record — a merge landed again
//! over another leaving its first landing's record standing beneath — a
//! marker a stage copied put back inherited; that a withdrawal and its undo
//! go by the marker's own record — the withdrawal after an undo put an
//! earlier merge back replacing that merge's, the withdrawal's undo writing
//! the landing's again after another merge, or the same one landed again,
//! was undone since, and writing back none taken back before its landing;
//! the take-backs' refusals, each mapped; and a merge taken back unsigned
//! where a claimed board's head is owed.

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
    // record to follow, the same ids, the one write answered again. The
    // write's re-ask is lost too, so the first call halts.
    let (dialer, board, signer) = open(draft_landing_world());
    let session = sign_in(&board, &signer);
    let merged = compose(&board, Some(session.token()), &draft_inputs()).expect("composed");
    let rows = dialer.world().rows.len();
    dialer.clear();
    dialer.world().drop_acks = 2;
    let lost = land(&board, &merged, draft_landing(&session, &signer, Some(a(S))));
    assert!(
        matches!(lost, Err(Refusal::Halt(Halt::Dial(_)))),
        "the premise: the write's acknowledgment lost, and its re-ask's: {lost:?}"
    );
    let landed = land(&board, &merged, draft_landing(&session, &signer, Some(a(S))))
        .expect("landed on the retry");
    let Landed::Draft { into, .. } = &landed else { panic!("{landed:?}") };
    assert_eq!(*into, a(S));
    let frames = dialer.frames("set_arrangement");
    assert_eq!(frames.len(), 3, "the write, its re-ask and its retry: {:?}", dialer.ops());
    let id = landing_id(&format!("{}:{S}@{}", merged.key.text(), merged.as_of), "draft");
    assert_eq!(frames[0]["id"].as_str(), Some(id.as_str()), "no record to follow");
    assert!(frames.iter().all(|f| f["id"] == frames[0]["id"]), "the re-ask's and the retry's id are the first call's");
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
/// recorded base the landing standing by its `set_arrangement` rows where
/// it names the merge; a take-back clears it, and a draft holding M
/// without it holds no landing to resume (skep #888). (a) The landing
/// withdrawn, the withdrawal recorded: `resume` naming the draft, which
/// still holds M, answers none and writes nothing, the withdrawal's record
/// current. (b) The landing's record unwritten, the board too busy to find
/// its journal, then the landing withdrawn: none, nothing written, no
/// record of the key. (c) The
/// withdrawal's record unwritten: none, nothing written, the landing's
/// record current. (d) A draft with no recorded base, holding M's list
/// before the landing, the landing undone: the undo's row names no merge,
/// so none, nothing written. (e) A composition made after its landing,
/// the marker standing: the landing at the marker's position, nothing
/// written. Skep #914, on a draft with no recorded base holding another
/// list before the landing: (f) a plain re-arrangement since that leaves
/// M's words leaves the landing standing, and `resume` answers it at its
/// row's position, nothing written (the mutant that reads the latest row
/// of any kind answers none); (g) the landing undone, then the same
/// re-arrangement: taken back for good, none, nothing written.
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

    // (f) and (g): a draft with no recorded base, holding another list
    // before the landing, re-arranged to M's words by hand since, a
    // `set_arrangement` naming no merge — (g) after the landing's undo.
    for undone in [false, true] {
        let plain = "1.0.1.0.67";
        let mut w = draft_landing_world();
        w.doc(plain, false, ACCOUNT, vec![run(D, 1, 11)]);
        let (dialer, board, signer) = open(w);
        let session = sign_in(&board, &signer);
        let into_plain = || draft_landing(&session, &signer, Some(a(plain)));
        let merged = compose(&board, Some(session.token()), &draft_inputs()).expect("composed");
        let landed = land(&board, &merged, into_plain()).expect("landed");
        if undone {
            undo(&board, merger(&session, &signer), &a(plain), &a(K), None, None).expect("undone");
        }
        let typed = dialer.world().position;
        let frame =
            frames::set_arrangement(plain, &shot_runs(&draft_m()), typed, None, None, None, None);
        dialer.world().apply(&frame)["at"].as_u64().expect("the re-arrangement's ack");
        assert_eq!(dialer.world().docs.get(plain).unwrap().runs, draft_m(), "the premise, M");
        let rows = dialer.world().rows.len();
        dialer.clear();
        let found = resume(&board, &merged, into_plain());
        if undone {
            assert_eq!(found, Ok(None), "(g): taken back for good");
        } else {
            assert_eq!(found, Ok(Some(as_found(&landed))), "(f): the landing standing, at its row");
        }
        assert!(wrote(&dialer).is_empty(), "undone {undone}: nothing written: {:?}", dialer.ops());
        assert_eq!(dialer.world().rows.len(), rows, "undone {undone}: nothing committed");
    }
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
/// since: the landing stands, so the words name it, its record and
/// `resume`, which answers it, writing nothing (the mutant that reads the
/// draft at the head names no `resume`). (c″) The draft edited since and
/// the board's history reclaimed past the landing: the words name the
/// landing, its record and that the list it placed cannot be read back,
/// never another list, with `resume` the way on, which answers it by its
/// record, writing nothing (the mutant that reads the draft as it stands in
/// the reclaimed state's place says another list and resumes none). (c′) A
/// landing of the same head and sides that placed another list, made by
/// hand: the words name it and
/// that it placed another list, never `resume`, which answers none (the
/// mutant that takes any marked landing as this composition's answers it).
/// (d) A composition made after the
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
        detail.contains(&format!("{S} already holds this merge: it landed there at position {at}"))
            && detail.contains(&format!("its record is {link}"))
            && detail.contains("resume answers that landing"),
        "(c): {detail}"
    );
    assert!(
        !detail.contains("another list") && !detail.contains("nothing was merged"),
        "(c): {detail}"
    );
    assert_eq!(wrote(&dialer), ["set_arrangement"], "(c): {:?}", dialer.ops());
    dialer.clear();
    assert_eq!(
        resume(&board, &merged, into_s()).expect("resumed"),
        Some(landed),
        "(c): the landing, the edit since it beside"
    );
    assert!(wrote(&dialer).is_empty(), "(c): a resume writes nothing: {:?}", dialer.ops());

    // (c″) S edited since its landing, the board's history reclaimed past
    // it: the list the landing placed cannot be read back.
    let (dialer, board, signer) = open(draft_landing_world());
    let session = sign_in(&board, &signer);
    let into_s = || draft_landing(&session, &signer, Some(a(S)));
    let (merged, landed) = landed_in_s(&board, &session, &signer);
    let (at, link) = landing_of(&landed);
    {
        let mut w = dialer.world();
        let edited = w.change(S, vec![run(D, 1, 11)]);
        w.floor = Some(edited);
        w.memo.clear();
    }
    dialer.clear();
    let err = land(&board, &merged, into_s()).expect_err("S moved");
    let detail = refused_words(&err, "(c″)");
    assert!(
        detail.contains(&format!("{S} holds a landing of this merge: it landed there at position {at}"))
            && detail.contains(&format!("its record is {link}"))
            && detail.contains(&format!("the list that landing placed cannot be read back, the board having reclaimed position {at}"))
            && detail.contains("resume answers that landing"),
        "(c″): {detail}"
    );
    assert!(
        !detail.contains("another list") && !detail.contains("nothing was merged"),
        "(c″): {detail}"
    );
    assert_eq!(wrote(&dialer), ["set_arrangement"], "(c″): {:?}", dialer.ops());
    dialer.clear();
    assert_eq!(
        resume(&board, &merged, into_s()).expect("resumed"),
        Some(landed),
        "(c″): the landing its record stands for"
    );
    assert!(wrote(&dialer).is_empty(), "(c″): a resume writes nothing: {:?}", dialer.ops());

    // (c′) A landing of the same head and sides that placed another list.
    let (dialer, board, signer) = open(draft_landing_world());
    let session = sign_in(&board, &signer);
    let into_s = || draft_landing(&session, &signer, Some(a(S)));
    let merged = compose(&board, Some(session.token()), &draft_inputs()).expect("composed");
    let other = landed_by_hand(&board, &session, &dialer, &[run(D, 1, 11)]);
    assert_eq!(
        dialer.world().standing(S).1.map(|m| (m.head, m.sides, m.at)),
        Some((format!("{D}.2"), Vec::new(), other)),
        "(c′): the premise, the merge's head and sides marked"
    );
    dialer.clear();
    let err = land(&board, &merged, into_s()).expect_err("the landing by hand moved S");
    let detail = refused_words(&err, "(c′)");
    assert!(
        detail.contains(&format!("this merge landed in {S} at position {other}"))
            && detail.contains("its record is not written")
            && detail.contains("placing another list than this composition's"),
        "(c′): {detail}"
    );
    assert!(!detail.contains("resume"), "(c′): {detail}");
    assert_eq!(
        resume(&board, &merged, into_s()).expect("resumed"),
        None,
        "(c′): no landing of this composition to resume"
    );
    assert!(wrote(&dialer).iter().all(|o| o == "set_arrangement"), "(c′): no record: {:?}", dialer.ops());

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
/// in a landing and a resume alike, the draft's marker read as it stands
/// and its words as of that mark (skep #980); the undo is typed against the
/// second write — the marker's,
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
            (vec![json!(t), json!(t)], vec![]),
            "the draft's marker read as it stands, and read again around its words, read at the head while it stands as its landing left it: {:?}",
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

/// A take-back's lost answer is asked again, then read back.
///
/// The setup of [`one_merge_landed_twice_is_taken_back_one_landing_at_a_time`]:
/// one merge landed twice in `T`. The undo's write lands and its answer is
/// lost: asked again once under the same id, the board's memo answers it,
/// and the undo answers the first landing's marker put back, one row
/// committed (cell 1). Its re-ask's answer lost too, the undo reads `T`'s
/// own row past the landing — a `set_arrangement` carrying the frame's
/// terms, `T` there holding the frame's words — and answers that row's
/// position, the first landing's marker standing, so a second undo is not
/// needed to learn the first landed and never takes the first landing back
/// (cell 2). A fresh landing's stage, its answer lost, is asked again under
/// its id, one draft minted (cell 3); the journal's mint, lost before it
/// landed, is sent again and lands once (cell 4). The mutant that never
/// re-asks reddens cells 1, 3 and 4; the one that never reads back, cell 2.
#[test]
fn a_take_backs_lost_answer_is_asked_again_then_read_back() {
    let t = "1.0.1.0.67";
    for lost in [1usize, 2] {
        let mut w = World::race();
        w.doc(t, false, ACCOUNT, vec![run(D, 1, 11)]);
        w.staged(t, &format!("{D}.1"), 11);
        let (dialer, board, signer) = open(w);
        let session = sign_in(&board, &signer);
        let into_t = || draft_landing(&session, &signer, Some(a(t)));
        let merged = compose(&board, Some(session.token()), &race_inputs()).expect("composed");
        let (first_at, _) = landing_of(&land(&board, &merged, into_t()).expect("landed"));
        let again = compose(&board, Some(session.token()), &race_inputs()).expect("composed again");
        let (second_at, _) = landing_of(&land(&board, &again, into_t()).expect("landed again"));
        let rows = dialer.world().rows.len();
        dialer.clear();
        dialer.world().drop_acks = lost;
        let undone = undo(&board, merger(&session, &signer), &a(t), &a(K), None, None)
            .unwrap_or_else(|e| panic!("cell {lost}: the second landing taken back: {e:?}"));
        let frames = dialer.frames("set_arrangement");
        assert!(frames.len() == 2 && frames[0]["id"] == frames[1]["id"], "cell {lost}: one re-ask under the same id: {frames:?}");
        assert_eq!(frames[0]["as_of"], json!(second_at), "cell {lost}: typed at the second landing");
        let w = dialer.world();
        let committed: Vec<u64> = w.rows[rows..].iter().filter(|r| r.op == "set_arrangement").map(|r| r.at).collect();
        assert_eq!(committed, vec![undone.position], "cell {lost}: one row, its position answered");
        assert_eq!(w.standing(t).1.map(|m| m.at), Some(first_at), "cell {lost}: the first landing's marker stands");
        assert_eq!(w.docs.get(t).unwrap().runs, m_runs(&merged), "cell {lost}: T as the first landing left it");
        drop(w);
        assert_eq!(undone.marker.and_then(|m| m.at), Some(first_at), "cell {lost}: the marker put back answered");
    }
    // Cell 3: a fresh landing's stage, its answer lost.
    let (dialer, board, signer) = open(draft_landing_world());
    let session = sign_in(&board, &signer);
    let merged = compose(&board, Some(session.token()), &draft_inputs()).expect("composed");
    dialer.world().drop_acks = 1;
    let landed = land(&board, &merged, draft_landing(&session, &signer, None)).expect("cell 3: landed");
    let Landed::Draft { staged: true, .. } = landed else { panic!("cell 3: {landed:?}") };
    let stages = dialer.frames("stage");
    assert!(stages.len() == 2 && stages[0]["id"] == stages[1]["id"], "cell 3: one re-ask under the same id: {stages:?}");
    assert_eq!(dialer.world().rows.iter().filter(|r| r.op == "stage").count(), 1, "cell 3: one draft staged");
    // Cell 4: the journal's mint lost before it landed.
    let (dialer, board, signer) = open(draft_landing_world());
    let session = sign_in(&board, &signer);
    let merged = compose(&board, Some(session.token()), &draft_inputs()).expect("composed");
    dialer.world().lose_before = Some(("create_new_document", 1));
    land(&board, &merged, draft_landing(&session, &signer, Some(a(S)))).expect("cell 4: landed with its record");
    let mints = dialer.frames("create_new_document");
    assert!(mints.len() == 2 && mints[0]["id"] == mints[1]["id"], "cell 4: one re-ask under the same id: {mints:?}");
    assert_eq!(dialer.world().rows.iter().filter(|r| r.op == "create_new_document").count(), 1, "cell 4: one journal minted");
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

/// An undo of a merge landed again over another leaves the first landing's
/// record standing beneath.
///
/// Skep #790 under skep #914's one rule: the race shape — merge A — landed
/// in `T` with its record, the draft-side merge of `T` — merge B — landed
/// over it with its own, and A composed again and landed in `T` over B, the
/// same landing as A's first: A's record is its key's newest and names
/// `T`, so no record is written. The undo takes A's later write back and
/// puts B's marker back, writing no record: A's record names A's first
/// landing, below B's, and that landing stands on beneath B (the mutant
/// that judges by the record standing for B's marker alone replaces A's
/// record). The undo after it takes B back, A's marker back, and replaces
/// B's record; A's record is current for its key, and a fresh landing of A
/// finds A standing in `T` at its first landing, nothing staged or written
/// (with A's record replaced, it answers `LandingBegun`).
#[test]
fn an_undo_of_a_merge_landed_again_over_another_leaves_its_first_landings_record() {
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
    let (b_at, b_record) = landing_of(&land(&board, &merge_b, into_t()).expect("B landed"));
    let again = compose(&board, Some(session.token()), &race_inputs()).expect("A composed again");
    assert_eq!(again.key, merge_a.key, "the premise: A's key");
    dialer.clear();
    let (again_at, again_record) =
        landing_of(&land(&board, &again, into_t()).expect("A landed again"));
    assert!(a_at < b_at && b_at < again_at, "the premise: A, B, then A again");
    assert_eq!(again_record, a_record, "the premise: the same landing, A's record");
    assert!(
        dialer.frames("insert").is_empty() && dialer.frames("make_link").is_empty(),
        "the premise: no record written: {:?}",
        dialer.ops()
    );
    dialer.clear();
    let undone = undo(&board, m, &a(t), &a(K), None, None).expect("A's later write taken back");
    assert_eq!(undone.marker.as_ref().and_then(|m| m.at), Some(b_at), "B's marker put back");
    assert_eq!(undone.record, None, "A's record stands for its first landing, beneath B");
    assert!(
        dialer.frames("insert").is_empty() && dialer.frames("make_link").is_empty(),
        "nothing of a record: {:?}",
        dialer.ops()
    );
    dialer.clear();
    let undone = undo(&board, m, &a(t), &a(K), None, None).expect("B taken back");
    assert_eq!(undone.marker.as_ref().and_then(|m| m.at), Some(a_at), "A's marker put back");
    assert_eq!(
        appended_record(&dialer)["replaces"].as_str(),
        Some(b_record.to_string().as_str()),
        "B's record replaced"
    );
    let found = current(&board, Some(session.token()), &a(K), &merge_a.key)
        .expect("the lookup")
        .expect("a record");
    assert_eq!(
        (found.link, found.landed),
        (Some(a_record.clone()), Some(RecordLanding::Draft { draft: a(t), position: a_at })),
        "A's record current"
    );
    dialer.clear();
    let fresh = land(&board, &merge_a, draft_landing(&session, &signer, None))
        .expect("A's landing found standing");
    assert_eq!(
        fresh,
        Landed::Draft { into: a(t), position: a_at, record: a_record, head_moved: None, staged: false },
        "A standing in T at its first landing"
    );
    assert!(
        dialer.frames("stage").is_empty() && dialer.frames("set_arrangement").is_empty(),
        "nothing staged or written: {:?}",
        dialer.ops()
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
/// a landing made since the first, is never the first landing's: `T`
/// marks the first merge below the second's record, so a fresh landing of
/// the second merge finds none of it standing, stages a draft of its own
/// and replaces the second's record — never answers the first merge's
/// landing, nor the one taken back (the mutant that answers the record's
/// position where the draft marks none stages nothing) — and the undo of
/// the first replaces the first's.
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
    // A fresh landing of the second merge finds none of it standing: `T`
    // marks the first merge's landing, below the record's position, the
    // second taken back though its take-back's record went unwritten — so it
    // stages a draft of its own, its record replacing the second's, and
    // never answers the earlier merge's landing as its own.
    dialer.clear();
    let fresh = land(&board, &second, draft_landing(&session, &signer, None)).expect("landed afresh");
    let Landed::Draft { into, position, staged, .. } = &fresh else { panic!("{fresh:?}") };
    assert!(*staged && *into != a(t) && *position > second_at, "a draft of its own: {fresh:?}");
    assert_eq!(dialer.frames("stage").len(), 1, "one stage: {:?}", dialer.ops());
    assert_eq!(dialer.world().docs.get(&into.to_string()).unwrap().runs, m_runs(&second), "the fresh draft holds the second merge");
    assert_eq!(
        appended_record(&dialer)["replaces"].as_str(),
        Some(second_record.to_string().as_str()),
        "the second landing's record replaced"
    );
    dialer.clear();
    undo(&board, m, &a(t), &a(K), None, None).expect("the first taken back");
    assert_eq!(
        appended_record(&dialer)["replaces"].as_str(),
        Some(first_record.to_string().as_str()),
        "the first landing's record replaced, never the second's"
    );
}

/// Returns the marker `doc` carries, as `doc_metadata` serves it at the head.
fn marker_of(
    board: &Board,
    session: &Session<'_>,
    doc: &str,
) -> crate::board::answers::MergeMarker {
    let frame = frames::doc_metadata(doc);
    let Answer::Document(v) = board.op(Some(session.token()), &frame).expect("the read") else {
        panic!("closed")
    };
    crate::board::answers::merge_marker(&v).flatten().expect("the draft's marker")
}

/// A withdrawal after an undo put a merge back replaces that merge's record.
///
/// Skep #1154, over skep #964's shape: the draft-side merge of `T` landed
/// in it, then composed again — another key, the same head and sides — and
/// landed again, its record of its own; the undo takes the second back, the
/// first landing's marker put back. The withdrawal replaces the record
/// standing for the marker it takes out, the first landing's, never the
/// second's, already replaced (the mutant that replaces the newest record
/// naming the draft as landed in replaces the second's again). The
/// withdrawal's undo writes the first landing's record again — `landed` `T`
/// at the first landing's position, `replaces` the withdrawal's record —
/// which `landing_record` answers by the marker (the mutant that bounds no
/// position writes the second landing's record).
#[test]
fn a_withdrawal_after_an_undo_put_an_earlier_merge_back_replaces_that_merges_record() {
    let t = "1.0.1.0.67";
    let mut w = World::race();
    w.doc(t, false, ACCOUNT, vec![run(D, 1, 11)]);
    w.staged(t, &format!("{D}.1"), 11);
    let (dialer, board, signer) = open(w);
    let session = sign_in(&board, &signer);
    let m = merger(&session, &signer);
    let into_t = || draft_landing(&session, &signer, Some(a(t)));
    let inputs = Inputs { sides: vec![Side::Draft { at: a(t), position: None }], ..race_inputs() };
    let first = compose(&board, Some(session.token()), &inputs).expect("composed");
    let (first_at, first_record) = landing_of(&land(&board, &first, into_t()).expect("landed"));
    let second = compose(&board, Some(session.token()), &inputs).expect("composed again");
    let (_, second_record) = landing_of(&land(&board, &second, into_t()).expect("landed again"));
    assert_ne!(second_record, first_record, "the premise: a record of its own");
    let undone = undo(&board, m, &a(t), &a(K), None, None).expect("the second taken back");
    let marker = undone.marker.clone().expect("the premise: the first landing's marker put back");
    assert_eq!(marker.at, Some(first_at), "the premise: {marker:?}");
    dialer.clear();
    let withdrawn = withdraw(&board, m, &a(t), &a(K), None).expect("withdrawn");
    let taken = withdrawn.record.clone().expect("the first landing's record replaced");
    assert_eq!(
        appended_record(&dialer)["replaces"].as_str(),
        Some(first_record.to_string().as_str()),
        "the record standing for the marker taken out"
    );
    dialer.clear();
    let unwithdrawn = unwithdraw(&board, m, &a(t), &a(K), withdrawn.position, None, None)
        .expect("the withdrawal taken back");
    let atom = appended_record(&dialer);
    assert_eq!(
        atom["landed"],
        json!({"draft": t, "position": first_at}),
        "the first landing's record again: {atom}"
    );
    assert_eq!(atom["replaces"].as_str(), Some(taken.to_string().as_str()));
    let standing = landing_record(&board, Some(session.token()), &a(K), &a(t), &marker, ACCOUNT)
        .expect("the lookup")
        .and_then(|r| r.link);
    assert_eq!(standing, unwithdrawn.record, "the record a re-open of T goes by");
}

/// A withdrawal's undo writes its record past another merge's undone landing.
///
/// Skep #1154, the editor's own stack (P3): the race shape — merge A —
/// landed in `T` and withdrawn; the draft-side merge of `T` — merge B —
/// landed in it and undone, its record replaced; then the withdrawal's
/// undo, typed at the caller's own last ack, B's undo. The newest record
/// linked to `T` is B's take-back, of another merge, so the record is
/// judged by the marker put back: A's landing record is written again,
/// `landed` `T` at A's position, `replaces` the withdrawal's record, and
/// `landing_record` answers it by the marker (the mutant that judges the
/// newest record linked to the draft writes none).
#[test]
fn a_withdrawals_undo_after_another_merge_landed_and_was_undone_writes_the_landings_record_again() {
    let t = "1.0.1.0.67";
    let mut w = World::race();
    w.doc(t, false, ACCOUNT, vec![run(D, 1, 11)]);
    w.staged(t, &format!("{D}.1"), 11);
    let (dialer, board, signer) = open(w);
    let session = sign_in(&board, &signer);
    let m = merger(&session, &signer);
    let into_t = || draft_landing(&session, &signer, Some(a(t)));
    let merge_a = compose(&board, Some(session.token()), &race_inputs()).expect("A composed");
    let (a_at, _) = landing_of(&land(&board, &merge_a, into_t()).expect("A landed"));
    let marker = marker_of(&board, &session, t);
    let withdrawn = withdraw(&board, m, &a(t), &a(K), None).expect("A withdrawn");
    let taken = withdrawn.record.clone().expect("the premise: A's record replaced");
    let b_inputs =
        Inputs { sides: vec![Side::Draft { at: a(t), position: None }], ..race_inputs() };
    let merge_b = compose(&board, Some(session.token()), &b_inputs).expect("B composed");
    land(&board, &merge_b, into_t()).expect("B landed");
    let undone_b = undo(&board, m, &a(t), &a(K), None, None).expect("B taken back");
    assert!(
        undone_b.record.is_some() && undone_b.marker.is_none(),
        "the premise: B's record replaced, no marker before B: {undone_b:?}"
    );
    dialer.clear();
    let unwithdrawn =
        unwithdraw(&board, m, &a(t), &a(K), withdrawn.position, Some(undone_b.position), None)
            .expect("A's withdrawal taken back");
    assert_eq!(marker_of(&board, &session, t), marker, "the premise: A's marker back");
    let atom = appended_record(&dialer);
    assert_eq!(
        atom["landed"],
        json!({"draft": t, "position": a_at}),
        "A's landing record again: {atom}"
    );
    assert_eq!(
        atom["replaces"].as_str(),
        Some(taken.to_string().as_str()),
        "the withdrawal's record replaced"
    );
    let standing = landing_record(&board, Some(session.token()), &a(K), &a(t), &marker, ACCOUNT)
        .expect("the lookup")
        .and_then(|r| r.link);
    assert_eq!(standing, unwithdrawn.record, "the record a re-open of T goes by");
}

/// A withdrawal's undo writes back no record taken back before its landing.
///
/// Skep #1154: the race shape landed in `T` and undone, its record
/// replaced, then landed in `T` again — a write of its own — with its
/// record unwritten, the board too busy to find the journal, so no record
/// of the merger's stands for the marker. The withdrawal writes no record:
/// the first landing's, below the marker's position, was replaced by the
/// undo (the mutant that replaces the newest record naming the draft as
/// landed in replaces it again). Its undo puts the marker back and writes
/// none either: the first landing's record was taken back before the
/// marker's landing was made, never since (the mutant that bounds the
/// take-back by no position writes the first landing's record again).
#[test]
fn a_withdrawals_undo_writes_back_no_record_taken_back_before_its_landing() {
    let t = "1.0.1.0.67";
    let mut w = World::race();
    w.doc(t, false, ACCOUNT, vec![run(D, 1, 11)]);
    w.staged(t, &format!("{D}.1"), 11);
    let (dialer, board, signer) = open(w);
    let session = sign_in(&board, &signer);
    let m = merger(&session, &signer);
    let into_t = || draft_landing(&session, &signer, Some(a(t)));
    let merged = compose(&board, Some(session.token()), &race_inputs()).expect("composed");
    let (first_at, _) = landing_of(&land(&board, &merged, into_t()).expect("landed"));
    let undone = undo(&board, m, &a(t), &a(K), None, None).expect("undone");
    assert!(undone.record.is_some(), "the premise: the first landing's record replaced");
    let again = compose(&board, Some(session.token()), &race_inputs()).expect("composed again");
    too_busy_for_the_find(&mut dialer.world());
    assert!(
        matches!(land(&board, &again, into_t()), Err(Refusal::Halt(Halt::Halt(_)))),
        "the premise: landed, its record unwritten"
    );
    let marker = dialer.world().standing(t).1.expect("the premise: the marker");
    assert!(marker.at > first_at, "the premise: a landing of its own: {marker:?}");
    dialer.clear();
    let withdrawn = withdraw(&board, m, &a(t), &a(K), None).expect("withdrawn");
    assert_eq!(withdrawn.record, None, "no record stands for the marker taken out");
    dialer.clear();
    let unwithdrawn = unwithdraw(&board, m, &a(t), &a(K), withdrawn.position, None, None)
        .expect("the withdrawal taken back");
    assert_eq!(dialer.world().standing(t).1, Some(marker), "the marker put back");
    assert_eq!(unwithdrawn.record, None, "the first landing's record stays replaced");
    assert!(
        dialer.frames("insert").is_empty() && dialer.frames("make_link").is_empty(),
        "nothing of a record: {:?}",
        dialer.ops()
    );
}

/// A withdrawal's undo writes its record after a later landing is undone.
///
/// Skep #1154: the race shape landed in `T` and withdrawn; composed again
/// — its key the same, the withdrawal's record its newest — and landed in
/// `T` again, a write of its own whose record replaces the withdrawal's;
/// that landing undone, the marker cleared, `T` as the withdrawal left it.
/// Typed at the caller's own last ack, the withdrawal's undo puts the first
/// landing's marker back and writes its record again, `replaces` the
/// withdrawal's, which `landing_record` answers by the marker: the
/// withdrawal's record is still the take-back of the first landing,
/// whatever replaces it since (the mutant that takes no take-back another
/// record replaces writes none; the one that judges the newest record
/// linked to the draft writes the second landing's).
#[test]
fn a_withdrawals_undo_writes_the_landings_record_again_after_the_merge_landed_again_and_was_undone()
{
    let t = "1.0.1.0.67";
    let mut w = World::race();
    w.doc(t, false, ACCOUNT, vec![run(D, 1, 11)]);
    w.staged(t, &format!("{D}.1"), 11);
    let (dialer, board, signer) = open(w);
    let session = sign_in(&board, &signer);
    let m = merger(&session, &signer);
    let into_t = || draft_landing(&session, &signer, Some(a(t)));
    let merged = compose(&board, Some(session.token()), &race_inputs()).expect("composed");
    let (first_at, _) = landing_of(&land(&board, &merged, into_t()).expect("landed"));
    let marker = marker_of(&board, &session, t);
    let withdrawn = withdraw(&board, m, &a(t), &a(K), None).expect("withdrawn");
    let taken = withdrawn.record.clone().expect("the premise: the landing's record replaced");
    let again = compose(&board, Some(session.token()), &race_inputs()).expect("composed again");
    let (_, second) = landing_of(&land(&board, &again, into_t()).expect("landed again"));
    let found = current(&board, Some(session.token()), &a(K), &again.key)
        .expect("the lookup")
        .expect("a record");
    assert_eq!(
        (found.link, found.replaces),
        (Some(second), Some(taken.clone())),
        "the premise: the second landing's record replaces the withdrawal's"
    );
    let undone = undo(&board, m, &a(t), &a(K), None, None).expect("the second taken back");
    assert_eq!(undone.marker, None, "the premise: no marker before the second landing");
    dialer.clear();
    let unwithdrawn =
        unwithdraw(&board, m, &a(t), &a(K), withdrawn.position, Some(undone.position), None)
            .expect("the withdrawal taken back");
    assert_eq!(marker_of(&board, &session, t), marker, "the first landing's marker back");
    let atom = appended_record(&dialer);
    assert_eq!(
        atom["landed"],
        json!({"draft": t, "position": first_at}),
        "the first landing's record again: {atom}"
    );
    assert_eq!(
        atom["replaces"].as_str(),
        Some(taken.to_string().as_str()),
        "the withdrawal's record replaced"
    );
    let standing = landing_record(&board, Some(session.token()), &a(K), &a(t), &marker, ACCOUNT)
        .expect("the lookup")
        .and_then(|r| r.link);
    assert_eq!(standing, unwithdrawn.record, "the record a re-open of T goes by");
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

/// A LANDING TAKEN BACK STANDS NO MORE, ITS TAKE-BACK's RECORD UNWRITTEN
/// (the owner's ruling on skep #914: a landing stands until it is taken
/// back; the record is testimony, the board's state the fact). The
/// composition landed fresh in `F`, then taken back — by an undo, and in a
/// world of its own by a withdrawal — while the board was too busy to find
/// the journal: `F` carries no marker, and the landing's record `R` stands
/// unreplaced. A `resume` with no draft named answers none, nothing
/// written; a landing with no draft named stages a draft of its own holding
/// M with its marker, its record replacing `R`.
#[test]
fn a_fresh_landing_taken_back_with_its_record_unwritten_stands_no_more() {
    let wrote = |dialer: &Scripted| {
        dialer.ops().into_iter().filter(|o| ["stage", "set_arrangement", "insert", "make_link"].contains(&o.as_str())).collect::<Vec<_>>()
    };
    for withdrawal in [false, true] {
        let (dialer, board, signer) = open(draft_landing_world());
        let session = sign_in(&board, &signer);
        let m = merger(&session, &signer);
        let fresh_landing = || draft_landing(&session, &signer, None);
        let merged = compose(&board, Some(session.token()), &draft_inputs()).expect("composed");
        let landed = land(&board, &merged, fresh_landing()).expect("landed fresh");
        let Landed::Draft { into: f, record: r, .. } = landed else { panic!("{landed:?}") };
        too_busy_for_the_find(&mut dialer.world());
        let taken = if withdrawal { withdraw(&board, m, &f, &a(K), None).map(|_| ()) } else { undo(&board, m, &f, &a(K), None, None).map(|_| ()) };
        assert!(matches!(taken, Err(Refusal::Halt(Halt::Halt(_)))), "{withdrawal}: the take-back's record unwritten: {taken:?}");
        dialer.world().scan_busy = 0;
        assert_eq!(dialer.world().standing(&f.to_string()).1, None, "{withdrawal}: the premise, no marker on F");
        let found = current(&board, Some(session.token()), &a(K), &merged.key).expect("the lookup").expect("a record");
        assert_eq!(found.link, Some(r.clone()), "{withdrawal}: the premise, R unreplaced");
        dialer.clear();
        assert_eq!(resume(&board, &merged, fresh_landing()), Ok(None), "{withdrawal}: no landing standing");
        assert!(wrote(&dialer).is_empty(), "{withdrawal}: nothing written: {:?}", dialer.ops());
        let relanded = land(&board, &merged, fresh_landing()).expect("landed again");
        let Landed::Draft { into: g, position, staged, .. } = relanded.clone() else { panic!("{relanded:?}") };
        assert!(staged && g != f, "{withdrawal}: a draft of its own, staged by this call: {relanded:?}");
        assert_eq!(dialer.frames("stage").len(), 1, "{withdrawal}: one stage: {:?}", dialer.ops());
        let w = dialer.world();
        assert_eq!(w.docs.get(&g.to_string()).unwrap().runs, draft_m(), "{withdrawal}: the new draft holds M");
        assert_eq!(w.standing(&g.to_string()).1.map(|m| m.at), Some(position), "{withdrawal}: its marker");
        drop(w);
        assert_eq!(appended_record(&dialer)["replaces"].as_str(), Some(r.to_string().as_str()), "{withdrawal}: R replaced");
    }
}

/// A FRESH LANDING FINDS ITS LANDING STANDING IN ANY DRAFT ITS RECORDS NAME
/// (P20: a record stands for its landing until a take-back replaces it; the
/// board's mark the fact). (a) One actor: the race shape landed in `T`, then
/// in `U`, its record replacing `T`'s, then `U` undone, the undo's record the
/// newest of the key. A `resume` and a landing with no draft named each
/// answer the landing standing in `T` at its marker with `T`'s record,
/// nothing staged or written, and `landed_draft` names `T`'s record. (b) Two
/// writers: the merge landed fresh in `F1`, then undone with its record
/// unwritten, the board too busy to find the journal; landed fresh again in
/// `F2`, its record replacing `F1`'s; then the undo's record of `F1` lands
/// late, minted past `F2`'s. A landing with no draft named answers `F2`'s
/// landing, nothing staged (the mutant that reads the merger's newest record
/// of the key alone finds no landing standing in either, so a landing stages
/// a fresh draft and the merge lands twice; the one whose `landed_draft`
/// answers the newest record, whatever a take-back replaced, names none in
/// (a)).
#[test]
fn a_fresh_landing_finds_its_landing_standing_in_any_draft_its_records_name() {
    let writes = ["stage", "set_arrangement", "create_new_document", "insert", "make_link"];
    let wrote = |dialer: &Scripted| {
        dialer.ops().into_iter().filter(|o| writes.contains(&o.as_str())).collect::<Vec<_>>()
    };
    // (a) One actor: landed in T, then in U, U undone.
    let (t, u) = ("1.0.1.0.67", "1.0.1.0.68");
    let mut w = World::race();
    for draft in [t, u] {
        w.doc(draft, false, ACCOUNT, vec![run(D, 1, 11)]);
        w.staged(draft, &format!("{D}.1"), 11);
    }
    let (dialer, board, signer) = open(w);
    let session = sign_in(&board, &signer);
    let into = |draft: &str| draft_landing(&session, &signer, Some(a(draft)));
    let fresh = || draft_landing(&session, &signer, None);
    let merged = compose(&board, Some(session.token()), &race_inputs()).expect("composed");
    let (in_t_at, in_t) = landing_of(&land(&board, &merged, into(t)).expect("landed in T"));
    let (_, in_u) = landing_of(&land(&board, &merged, into(u)).expect("landed in U"));
    let undone = undo(&board, merger(&session, &signer), &a(u), &a(K), None, None)
        .expect("U undone")
        .record
        .expect("the undo's record");
    let newest = current(&board, Some(session.token()), &a(K), &merged.key)
        .expect("the lookup")
        .expect("a record");
    assert_eq!(
        (newest.link, newest.replaces),
        (Some(undone), Some(in_u)),
        "the premise: the undo's record, the newest of the key"
    );
    assert_eq!(
        dialer.world().standing(t).1.map(|m| m.at),
        Some(in_t_at),
        "the premise: T marks its landing"
    );
    let standing = Landed::Draft {
        into: a(t),
        position: in_t_at,
        record: in_t.clone(),
        head_moved: None,
        staged: false,
    };
    dialer.clear();
    assert_eq!(
        resume(&board, &merged, fresh()),
        Ok(Some(standing.clone())),
        "(a): the landing standing in T"
    );
    assert_eq!(land(&board, &merged, fresh()), Ok(standing), "(a): found, nothing staged");
    assert!(wrote(&dialer).is_empty(), "(a): nothing staged or written: {:?}", dialer.ops());
    assert_eq!(
        landed_draft(&board, Some(session.token()), &a(K), &merged.key, ACCOUNT)
            .expect("the lookup")
            .and_then(|r| r.link),
        Some(in_t),
        "(a): T's record, U's taken back"
    );

    // (b) Two writers: F1's undo recorded late, past F2's landing.
    let (dialer, board, signer) = open(World::race());
    let session = sign_in(&board, &signer);
    let fresh = || draft_landing(&session, &signer, None);
    let merged = compose(&board, Some(session.token()), &race_inputs()).expect("composed");
    let first = land(&board, &merged, fresh()).expect("landed in F1");
    let Landed::Draft { into: f1, record: r1, .. } = first else { panic!("{first:?}") };
    too_busy_for_the_find(&mut dialer.world());
    let taken = undo(&board, merger(&session, &signer), &f1, &a(K), None, None);
    assert!(
        matches!(taken, Err(Refusal::Halt(Halt::Halt(_)))),
        "the premise: F1 undone, its record unwritten: {taken:?}"
    );
    dialer.world().scan_busy = 0;
    let second = land(&board, &merged, fresh()).expect("landed in F2");
    let Landed::Draft { into: f2, position: in_f2_at, .. } = second.clone() else {
        panic!("{second:?}")
    };
    assert_ne!(f2, f1, "the premise: a draft of its own");
    let journal = crate::address::document_of(&r1.to_string()).expect("R1's journal");
    let late = {
        let mut w = dialer.world();
        w.position += 1;
        let minted = w.position;
        let take_back =
            Record { landed: None, replaces: Some(r1.clone()), ..merged.record.clone() };
        file(&mut w, &journal, &take_back, &[&f1.to_string(), &format!("{D}.1.1")], Some(minted))
    };
    let newest = current(&board, Some(session.token()), &a(K), &merged.key)
        .expect("the lookup")
        .expect("a record");
    assert_eq!(
        (newest.link.map(|l| l.to_string()), newest.replaces),
        (Some(late), Some(r1)),
        "the premise: F1's take-back, recorded late, the newest of the key"
    );
    assert_eq!(
        dialer.world().standing(&f2.to_string()).1.map(|m| m.at),
        Some(in_f2_at),
        "the premise: F2 marks its landing"
    );
    dialer.clear();
    assert_eq!(
        land(&board, &merged, fresh()),
        Ok(as_found(&second)),
        "(b): F2's landing, standing"
    );
    assert!(wrote(&dialer).is_empty(), "(b): nothing staged or written: {:?}", dialer.ops());
}

/// A RESUME ANSWERS BY THE RECORD STANDING FOR ITS LANDING. (a) The race
/// shape landed in `T`, then in `U`: `U`'s record replaces `T`'s as the
/// newest of the key while both landings stand, no take-back recorded
/// (skep #914). A `resume` naming `T` answers `T`'s landing with `T`'s
/// record and one naming `U` answers `U`'s, nothing written, the newest
/// record of the key `U`'s still. (b) A shot landed with its record, then
/// the same composition landed in `T`, its record the newest of the key: a
/// `resume` of the shot and `record_published` of its member each answer the
/// shot's record, nothing written. The mutant that judges the residue walk
/// by the newest record of the key alone writes a second record of `T`'s
/// landing at (a), the newest flipping to it; the one that looks for a
/// member's record among the other states' alone writes a second record of
/// the member at (b).
#[test]
fn a_resume_answers_by_the_record_standing_for_its_landing() {
    let writes = ["stage", "set_arrangement", "create_new_document", "insert", "make_link"];
    let wrote = |dialer: &Scripted| {
        dialer.ops().into_iter().filter(|o| writes.contains(&o.as_str())).collect::<Vec<_>>()
    };
    let (t, u) = ("1.0.1.0.67", "1.0.1.0.68");
    let world = || {
        let mut w = World::race();
        for draft in [t, u] {
            w.doc(draft, false, ACCOUNT, vec![run(D, 1, 11)]);
            w.staged(draft, &format!("{D}.1"), 11);
        }
        w
    };
    // (a) Landed in T, then in U.
    let (dialer, board, signer) = open(world());
    let session = sign_in(&board, &signer);
    let into = |draft: &str| draft_landing(&session, &signer, Some(a(draft)));
    let merged = compose(&board, Some(session.token()), &race_inputs()).expect("composed");
    let in_t = land(&board, &merged, into(t)).expect("landed in T");
    let in_u = land(&board, &merged, into(u)).expect("landed in U");
    let newest = || {
        current(&board, Some(session.token()), &a(K), &merged.key)
            .expect("the lookup")
            .and_then(|r| r.link)
    };
    let (_, r_u) = landing_of(&in_u);
    assert_eq!(newest(), Some(r_u.clone()), "(a): the premise, U's record the newest");
    let rows = dialer.world().rows.len();
    dialer.clear();
    assert_eq!(resume(&board, &merged, into(t)), Ok(Some(in_t)), "(a): T's landing, T's record");
    assert_eq!(resume(&board, &merged, into(u)), Ok(Some(in_u)), "(a): U's landing, U's record");
    assert!(wrote(&dialer).is_empty(), "(a): nothing written: {:?}", dialer.ops());
    assert_eq!(dialer.world().rows.len(), rows, "(a): nothing committed");
    assert_eq!(newest(), Some(r_u), "(a): U's record the newest still");

    // (b) A shot landed, then the same composition landed in T.
    let (dialer, board, signer) = open(world());
    let session = sign_in(&board, &signer);
    let merged = compose(&board, Some(session.token()), &race_inputs()).expect("composed");
    let shot_landed = land(&board, &merged, shot(&session, &signer)).expect("the shot landed");
    let Landed::Member { address: member, position, record, .. } = &shot_landed else {
        panic!("{shot_landed:?}")
    };
    let (_, r_t) = landing_of(
        &land(&board, &merged, draft_landing(&session, &signer, Some(a(t)))).expect("landed in T"),
    );
    let newest = current(&board, Some(session.token()), &a(K), &merged.key)
        .expect("the lookup")
        .and_then(|r| r.link);
    assert_eq!(newest, Some(r_t), "(b): the premise, T's record the newest");
    let rows = dialer.world().rows.len();
    dialer.clear();
    assert_eq!(resume(&board, &merged, shot(&session, &signer)), Ok(Some(shot_landed.clone())), "(b): the shot's member, its record");
    let recorded = record_published(&board, &merged, merger(&session, &signer), member, *position, None, &[]).expect("recorded");
    let Landed::Member { record: answered, .. } = &recorded else { panic!("{recorded:?}") };
    assert_eq!(answered, record, "(b): the shot's record answered");
    assert!(wrote(&dialer).is_empty(), "(b): nothing written: {:?}", dialer.ops());
    assert_eq!(dialer.world().rows.len(), rows, "(b): nothing committed");
}

/// A take-back's answer lost past its re-ask is named unconfirmed.
///
/// The setup of [`one_merge_landed_twice_is_taken_back_one_landing_at_a_time`]:
/// one merge landed twice in `T`, the undo putting the first landing's
/// marker back. Cell 1: the undo's write lands and its answer is lost, and
/// the session dies at its re-ask — a daemon restarted between the two asks
/// kills every token and its memo. The undo answers the session's end with
/// the way on of a write unconfirmed, naming the marker its write puts back
/// and the second landing's, nothing more sent; `T` carries the first
/// landing's marker, the undo landed. Run again in a session of its own, the
/// undo takes the first landing back too — the step that way on warns of.
/// Cell 2: the re-ask's answer lost too, the session dies at the read back
/// of `T`'s rows, answered alike. The mutant that faces a death at the
/// re-ask as one at the first ask, to run the act again, reddens cell 1; the
/// one that answers the read back's death as itself, cell 2.
#[test]
fn a_take_backs_answer_lost_past_its_re_ask_is_unconfirmed() {
    let t = "1.0.1.0.67";
    // The requests an undo with `lost` answers lost serves, made whole.
    let served = |lost: usize| {
        let (dialer, board, signer, ..) = landed_twice_in(t);
        let session = sign_in(&board, &signer);
        dialer.clear();
        dialer.world().drop_acks = lost;
        undo(&board, merger(&session, &signer), &a(t), &a(K), None, None)
            .expect("the premise: undone whole");
        dialer.requests()
    };
    let reask = |requests: &[(String, bool)]| {
        requests
            .iter()
            .enumerate()
            .filter(|(_, (line, _))| line == "set_arrangement")
            .nth(1)
            .expect("the re-ask")
            .0
    };
    let unconfirmed = |cell: &str, err: &Refusal, first_at: u64, second_at: u64| {
        let Refusal::SessionEnded(Halt::Halt(face)) = err else { panic!("{cell}: {err:?}") };
        let lost = LostTakeBack::Undo { landing: second_at, earlier: Some(first_at) };
        assert!(face.state.starts_with("the write may have landed, and its record is not written"), "{cell}: {face:?}");
        assert_eq!(face.act, OnEnd::Unconfirmed(lost).act(), "{cell}");
        assert!(
            face.act.contains(&format!("the merge marked at position {first_at}"))
                && face.act.contains(&format!("the merge marked at position {second_at}"))
                && face.act.contains("a re-run takes that merge back too"),
            "{cell}: {face:?}"
        );
    };
    // Cell 1: the death at the re-ask.
    let at = 1 + reask(&served(1));
    let (dialer, board, signer, first_at, second_at) = landed_twice_in(t);
    let session = sign_in(&board, &signer);
    dialer.clear();
    {
        let mut w = dialer.world();
        w.drop_acks = 1;
        w.die_at = Some(at);
    }
    let err = undo(&board, merger(&session, &signer), &a(t), &a(K), None, None)
        .expect_err("cell 1: the session ended");
    unconfirmed("cell 1", &err, first_at, second_at);
    assert_eq!(dialer.requests().len(), at, "cell 1: nothing asked past the death");
    assert_eq!(dialer.world().standing(t).1.map(|m| m.at), Some(first_at), "cell 1: the undo landed");
    {
        let mut w = dialer.world();
        w.die_at = None;
        w.memo.clear();
    }
    let session = sign_in(&board, &signer);
    let again = undo(&board, merger(&session, &signer), &a(t), &a(K), None, None)
        .expect("cell 1: run again");
    assert_eq!(again.marker, None, "cell 1: the first landing taken back too");
    assert_eq!(dialer.world().docs.get(t).unwrap().runs, vec![run(D, 1, 11)], "cell 1: T as staged");
    // Cell 2: the death at the read back.
    let requests = served(2);
    let past = reask(&requests);
    let at = 1 + past
        + requests[past..].iter().position(|(line, _)| line.starts_with("GET /changes")).expect("the read back");
    let (dialer, board, signer, first_at, second_at) = landed_twice_in(t);
    let session = sign_in(&board, &signer);
    dialer.clear();
    {
        let mut w = dialer.world();
        w.drop_acks = 2;
        w.die_at = Some(at);
    }
    let err = undo(&board, merger(&session, &signer), &a(t), &a(K), None, None)
        .expect_err("cell 2: the session ended");
    unconfirmed("cell 2", &err, first_at, second_at);
    assert_eq!(dialer.world().standing(t).1.map(|m| m.at), Some(first_at), "cell 2: the undo landed");
}

/// One merge landed twice in `draft`, composed again between.
///
/// It is the setup of
/// [`one_merge_landed_twice_is_taken_back_one_landing_at_a_time`] over the
/// race shape, `draft` staged from `D.1`. Answers the dialer, the board, the
/// hand and the two landings' positions.
fn landed_twice_in(draft: &str) -> (Arc<Scripted>, Board, HybridSigner, u64, u64) {
    let mut w = World::race();
    w.doc(draft, false, ACCOUNT, vec![run(D, 1, 11)]);
    w.staged(draft, &format!("{D}.1"), 11);
    let (dialer, board, signer) = open(w);
    let (first_at, second_at) = {
        let session = sign_in(&board, &signer);
        let into = || draft_landing(&session, &signer, Some(a(draft)));
        let merged = compose(&board, Some(session.token()), &race_inputs()).expect("composed");
        let (first_at, _) = landing_of(&land(&board, &merged, into()).expect("landed"));
        let again =
            compose(&board, Some(session.token()), &race_inputs()).expect("composed again");
        let (second_at, _) = landing_of(&land(&board, &again, into()).expect("landed again"));
        (first_at, second_at)
    };
    (dialer, board, signer, first_at, second_at)
}

/// A take-back answered `500 internal_panic` reads its write back.
///
/// The board's `500 internal_panic` is no verdict on a write: it may have
/// committed, its acknowledgment never memoized (wire.md §HTTP status
/// codes). Cell 1: the undo of a recorded landing in `S`, its one write
/// applied and answered so, is asked nowhere again — `S`'s own row past the
/// landing, carrying the frame's terms and `S` there holding the frame's
/// words, is the write's — and the undo answers that row's position and
/// writes its record. Cell 2: the write and its re-ask lost before the board
/// saw either, no row is the write's: the undo answers the write unconfirmed,
/// a face saying it may have landed and how the draft tells, never the
/// dialer's halt, nothing committed. The mutant that answers the `500` as
/// the board's refusal reddens cell 1; the one that answers a write no row
/// confirms with the dialer's halt, cell 2.
#[test]
fn a_take_back_answered_internal_panic_reads_its_write_back() {
    // Cell 1: applied, answered `500 internal_panic`.
    let (dialer, board, signer) = open(draft_landing_world());
    let session = sign_in(&board, &signer);
    let (_, landed) = landed_in_s(&board, &session, &signer);
    let (_, link) = landing_of(&landed);
    dialer.clear();
    dialer.world().panic_after = Some("set_arrangement");
    let undone = undo(&board, merger(&session, &signer), &a(S), &a(K), None, None)
        .expect("cell 1: the undo read back");
    let row = dialer.world().rows.iter().rev().find(|r| r.op == "set_arrangement").expect("cell 1: the undo's row").at;
    assert_eq!(undone.position, row, "cell 1: the position its row names");
    assert_eq!(dialer.frames("set_arrangement").len(), 1, "cell 1: never asked again: {:?}", dialer.ops());
    assert_eq!(dialer.world().standing(S).1, None, "cell 1: the marker cleared");
    assert_eq!(
        appended_record(&dialer)["replaces"].as_str(),
        Some(link.to_string().as_str()),
        "cell 1: the undo's record written"
    );
    // Cell 2: the write and its re-ask lost before the board saw them.
    let (dialer, board, signer) = open(draft_landing_world());
    let session = sign_in(&board, &signer);
    let (_, landed) = landed_in_s(&board, &session, &signer);
    let (at, _) = landing_of(&landed);
    let rows = dialer.world().rows.len();
    dialer.clear();
    dialer.world().lose_before = Some(("set_arrangement", 2));
    let err = undo(&board, merger(&session, &signer), &a(S), &a(K), None, None)
        .expect_err("cell 2: unconfirmed");
    let Refusal::Halt(Halt::Halt(face)) = &err else { panic!("cell 2: {err:?}") };
    assert!(
        face.state.starts_with("the write may have landed, and its record is not written: its answer was lost while taking the merge back out of the draft")
            && face.cause.starts_with("transport:"),
        "cell 2: {face:?}"
    );
    assert_eq!(face.act, LostTakeBack::Undo { landing: at, earlier: None }.way_on(), "cell 2");
    assert_eq!(dialer.frames("set_arrangement").len(), 2, "cell 2: the write and its re-ask: {:?}", dialer.ops());
    let w = dialer.world();
    assert_eq!(w.rows.len(), rows, "cell 2: nothing committed");
    assert_eq!(w.standing(S).1.map(|m| m.at), Some(at), "cell 2: the landing stands");
}

/// A take-back whose record's step is stopped stands with its record
/// unwritten.
///
/// After each take-back's one write lands, the record's link is lost at the
/// transport and lost again at its re-ask, never applied: the undo of a
/// recorded landing in `S`, its withdrawal, the withdrawal's undo after a
/// recorded withdrawal, and the undo of a merge landed over another in
/// `OVER`, the earlier merge back in it (skep #964). Each answers a face
/// saying the act stands and its record is not written, the refusal its
/// cause, with the way on of a take-back whose record went unwritten —
/// `TakenOut`, `PutBack`, `EarlierBack` — never the dialer's halt, the
/// act's write standing and no link written (the mutant that passes the
/// record step's refusals up as themselves reddens every cell).
#[test]
fn a_take_back_whose_record_is_stopped_stands_with_its_record_unwritten() {
    let stopped = |cell: &str, err: Refusal, state: &str, on_end: OnEnd| {
        let Refusal::Halt(Halt::Halt(face)) = &err else { panic!("{cell}: {err:?}") };
        assert!(
            face.state.starts_with(state)
                && face.state.ends_with("is not written: a read or a write of the record went unanswered, or was refused")
                && face.cause.starts_with("transport:"),
            "{cell}: {face:?}"
        );
        assert_eq!(face.act, on_end.act(), "{cell}");
    };
    let links = |dialer: &Scripted| dialer.world().links.iter().filter(|l| l.ty == K).count();
    let lose_the_link = |dialer: &Scripted| dialer.world().lose_before = Some(("make_link", 2));
    // The undo.
    let (dialer, board, signer) = open(draft_landing_world());
    let session = sign_in(&board, &signer);
    landed_in_s(&board, &session, &signer);
    let linked = links(&dialer);
    lose_the_link(&dialer);
    let err = undo(&board, merger(&session, &signer), &a(S), &a(K), None, None).expect_err("the undo");
    stopped("the undo", err, &format!("the merge is out of {S}, and the record of the undo"), OnEnd::TakenOut);
    let marker = dialer.world().standing(S).1;
    assert_eq!((marker, links(&dialer)), (None, linked), "the undo stands, no link");
    // The withdrawal.
    let (dialer, board, signer) = open(draft_landing_world());
    let session = sign_in(&board, &signer);
    landed_in_s(&board, &session, &signer);
    lose_the_link(&dialer);
    let err = withdraw(&board, merger(&session, &signer), &a(S), &a(K), None).expect_err("the withdrawal");
    stopped("the withdrawal", err, &format!("the merge is out of {S}, and the record of the withdrawal"), OnEnd::TakenOut);
    assert_eq!(dialer.world().standing(S).1, None, "the withdrawal stands");
    // The withdrawal's undo, after a recorded withdrawal.
    let (dialer, board, signer) = open(draft_landing_world());
    let session = sign_in(&board, &signer);
    let (_, landed) = landed_in_s(&board, &session, &signer);
    let (at, _) = landing_of(&landed);
    let withdrawn = withdraw(&board, merger(&session, &signer), &a(S), &a(K), None).expect("withdrawn");
    assert!(withdrawn.record.is_some(), "the premise: the withdrawal recorded");
    lose_the_link(&dialer);
    let err = unwithdraw(&board, merger(&session, &signer), &a(S), &a(K), withdrawn.position, None, None)
        .expect_err("the withdrawal's undo");
    stopped("the withdrawal's undo", err, &format!("the merge is back in {S}, and the record of the withdrawal's undo"), OnEnd::PutBack);
    assert_eq!(dialer.world().standing(S).1.map(|m| m.at), Some(at), "the merge back in S");
    // The undo of a merge landed over another.
    const OVER: &str = "1.0.1.0.67";
    let mut w = World::race();
    w.doc(OVER, false, ACCOUNT, vec![run(D, 1, 11)]);
    w.staged(OVER, &format!("{D}.1"), 11);
    let (dialer, board, signer) = open(w);
    let session = sign_in(&board, &signer);
    let into = || draft_landing(&session, &signer, Some(a(OVER)));
    let first = compose(&board, Some(session.token()), &race_inputs()).expect("composed");
    let (first_at, _) = landing_of(&land(&board, &first, into()).expect("landed"));
    let over = Inputs { sides: vec![Side::Draft { at: a(OVER), position: None }], ..race_inputs() };
    let over = compose(&board, Some(session.token()), &over).expect("composed over it");
    land(&board, &over, into()).expect("landed over it");
    lose_the_link(&dialer);
    let err = undo(&board, merger(&session, &signer), &a(OVER), &a(K), None, None).expect_err("the undo over an earlier landing");
    stopped(
        "the undo over an earlier landing",
        err,
        &format!("the merge is out of {OVER}, the merge landed before it standing again, and the record of the undo"),
        OnEnd::EarlierBack,
    );
    assert_eq!(dialer.world().standing(OVER).1.map(|m| m.at), Some(first_at), "the earlier merge back");
}

/// A FRESH LANDING OF ANOTHER COMPOSITION OF THE KEY STAGES A DRAFT OF ITS
/// OWN. The key holds no choice: the race shape with a second daughter
/// `D.1.2` adding "fat " where the head added "big " is one `order` gap,
/// and the merge composed at its default order and composed with the order
/// swapped are one key with two lists. The default landed fresh in `F`: a
/// `resume` and a landing with no draft named of the swapped one find no
/// landing of it in `F`, whose landing placed the default list, read as of
/// its mark — the resume answers none, nothing written, and the landing
/// stages a draft of its own holding the swapped list, its record replacing
/// `F`'s. The default composed again then finds its own landing in `F`, the
/// swapped one in its own draft, each nothing written (the mutant that judges
/// a draft by its mark alone answers `F` for the swapped composition, the
/// merger's choice reported landed and never written; the one that reads the
/// newest record alone stages a third draft for the default).
#[test]
fn a_fresh_landing_of_another_composition_of_the_key_stages_a_draft_of_its_own() {
    let writes = ["stage", "set_arrangement", "create_new_document", "insert", "make_link"];
    let wrote = |dialer: &Scripted| {
        dialer.ops().into_iter().filter(|o| writes.contains(&o.as_str())).collect::<Vec<_>>()
    };
    let mut w = World::race();
    w.text(D, 16, "fat ");
    w.member(&format!("{D}.1.2"), vec![run(D, 1, 4), run(D, 16, 4), run(D, 5, 7)], Some(11));
    let (dialer, board, signer) = open(w);
    let session = sign_in(&board, &signer);
    let fresh = || draft_landing(&session, &signer, None);
    let inputs = Inputs { sides: vec![Side::Member(a(&format!("{D}.1.2")))], ..race_inputs() };
    let defaults = compose(&board, Some(session.token()), &inputs).expect("composed");
    let swap = Resolution {
        gap: GapId(1),
        choice: Choice::Order(vec![SideIx(1), SideIx(0)]),
        by: ResolvedBy::Agent,
    };
    let options = Options { resolutions: vec![swap], ..Options::default() };
    let swapped = compose(&board, Some(session.token()), &Inputs { options, ..inputs })
        .expect("composed swapped");
    assert_eq!(swapped.key, defaults.key, "the premise: one key, which holds no choice");
    assert_eq!(
        (m_runs(&defaults), m_runs(&swapped)),
        (
            vec![run(D, 1, 4), run(D, 12, 8), run(D, 5, 7)],
            vec![run(D, 1, 4), run(D, 16, 4), run(D, 12, 4), run(D, 5, 7)]
        ),
        "the premise: two lists"
    );
    let first = land(&board, &defaults, fresh()).expect("the default landed");
    let Landed::Draft { into: f, record: r1, .. } = first.clone() else { panic!("{first:?}") };
    dialer.clear();
    assert_eq!(
        resume(&board, &swapped, fresh()),
        Ok(None),
        "no landing of the swapped list stands in F"
    );
    assert!(wrote(&dialer).is_empty(), "a resume writes nothing: {:?}", dialer.ops());
    let second = land(&board, &swapped, fresh()).expect("the swapped landed");
    let Landed::Draft { into: g, position, staged, .. } = second.clone() else {
        panic!("{second:?}")
    };
    assert!(staged && g != f, "a draft of its own, staged by this call: {second:?}");
    assert_eq!(dialer.frames("stage").len(), 1, "one stage: {:?}", dialer.ops());
    let w = dialer.world();
    assert_eq!(
        w.docs.get(&g.to_string()).unwrap().runs,
        m_runs(&swapped),
        "the new draft holds the swapped list"
    );
    assert_eq!(
        w.docs.get(&f.to_string()).unwrap().runs,
        m_runs(&defaults),
        "F keeps the default list"
    );
    assert_eq!(w.standing(&g.to_string()).1.map(|m| m.at), Some(position), "its marker");
    drop(w);
    assert_eq!(
        appended_record(&dialer)["replaces"].as_str(),
        Some(r1.to_string().as_str()),
        "F's record replaced"
    );
    dialer.clear();
    assert_eq!(
        land(&board, &defaults, fresh()),
        Ok(as_found(&first)),
        "the default's own landing, in F"
    );
    assert_eq!(
        land(&board, &swapped, fresh()),
        Ok(as_found(&second)),
        "the swapped one's own, in its draft"
    );
    assert!(wrote(&dialer).is_empty(), "nothing staged or written: {:?}", dialer.ops());
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
    assert_eq!(
        (merged.prior.as_ref().and_then(|p| p.link.as_ref()).map(ToString::to_string), merged.record.replaces.clone()),
        (Some(planted), None),
        "the premise: the composition's prior another home's record, its own record replacing nothing"
    );
    dialer.clear();
    let landed = land(&board, &merged, shot(&session, &signer)).expect("landed");
    assert!(matches!(landed, Landed::Member { .. }), "{landed:?}");
    assert!(appended_record(&dialer)["replaces"].is_null(), "the merger's home held no record of the key, so the record replaces none");
}

/// Every refusal the one write can answer, each mapped (item 4):
/// `not_owner` naming the draft, `published_target`, `withheld` naming
/// the origin and its words in C as the write sends it — none for `Z`,
/// which no run windows; `D`'s eleven at 1–11, `S`'s three after them left
/// out — and with no site, or one naming no document, the board's refusal
/// verbatim, never the draft named in the board's place (the mutant that
/// names it answers `WindowWithheld` naming `S`),
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
    for site in [None, Some("x")] {
        let err = refused("withheld", site);
        let Refusal::Halt(Halt::Refused(verbatim)) = &err else {
            panic!("{site:?}: {err:?}")
        };
        assert_eq!(
            (verbatim.code.as_str(), verbatim.detail.as_deref()),
            ("withheld", None),
            "{site:?}"
        );
    }
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
