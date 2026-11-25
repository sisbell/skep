//! The landing's refusals over the scripted board, each mapped.
//!
//! The suite checks every refusal the shot and the draft landing's one
//! write can answer, a `withheld` naming the words refused, those the head
//! carries never among them at the shot, and one naming no document the
//! board's refusal verbatim; a shot too large for one request refused with
//! its size, before any value is read where its positions alone pass the
//! budget; a draft word a record names, sent
//! by reference, a
//! retry keeping its ids, and `already_published` at the shot read again
//! and sent once more, never a second member or atom; a draft the merger
//! may not read, refused before any write; an edit past the draft's
//! closing fence, past P, refused at the draft landing; a claimed board whose head is
//! owed landing nothing, a landing that stands writing its record unsigned,
//! and a claim past the head's read met by one signed send (SP-14); a
//! journal the act cannot write into leaving the act standing, checked
//! before the act's first write where named, `journal::check` the
//! landing's check alone; and a landing write's id, its stem the digest of
//! its text, admitted by the wire however many sides.

use super::*;

/// Every refusal the shot can answer, each mapped: `withheld` naming the
/// origin and its words the head does not carry — none of a run of the
/// race's list, each of which the head `D.2` holds whole (the mutant that
/// lists a carried run names 1–11) — `signed_session_required`,
/// `doc_not_registered`, the library's own faults as halts, the board's
/// `board_unavailable` as the head it owes — and nothing after the
/// refusal; `attestation_required` at the signed shot the library's own
/// fault, never sent again.
#[test]
fn the_shots_refusals_are_mapped() {
    let (dialer, board, signer) = open(World::race());
    let session = sign_in(&board, &signer);
    let merged = compose(&board, Some(session.token()), &race_inputs()).expect("composed");
    let refuse = |code: &str, site: Option<&str>| {
        let mut rej = json!({"resp": "rejected", "code": code, "disposition": "permanent", "op": "publish"});
        if let Some(s) = site {
            rej["site"] = json!({"addr": s});
        }
        dialer.world().memo.insert(landing_id(&merged.key.text(), "publish"), rej);
    };
    refuse("withheld", Some(Z));
    assert_eq!(
        land(&board, &merged, shot(&session, &signer)),
        Err(Refusal::WindowWithheld { origin: a(Z), positions: Vec::new() })
    );
    refuse("withheld", Some(D));
    assert_eq!(
        land(&board, &merged, shot(&session, &signer)),
        Err(Refusal::WindowWithheld { origin: a(D), positions: Vec::new() }),
        "every run of the list carried by the head"
    );
    refuse("signed_session_required", None);
    assert_eq!(
        land(&board, &merged, shot(&session, &signer)),
        Err(Refusal::NeedsSignedSession)
    );
    refuse("doc_not_registered", None);
    assert_eq!(
        land(&board, &merged, shot(&session, &signer)),
        Err(Refusal::NoSuchDocument(a(D)))
    );
    refuse("base_superseded", None);
    let err = land(&board, &merged, shot(&session, &signer)).expect_err("own fault");
    assert!(
        matches!(&err, Refusal::Halt(h) if h.exit_code() == 3 && h.to_string().contains("base_superseded")),
        "{err}"
    );
    // The daughters' refusal, typed with its entry and cause —
    // `head_moved` carrying the trunk's head — never the library's
    // fault; a detail this client does not know the board's verbatim.
    let refuse_entry = |detail: &str, site: Value| {
        dialer.world().memo.insert(
            landing_id(&merged.key.text(), "publish"),
            json!({"resp": "rejected", "code": "supersede_refused", "detail": detail, "disposition": "permanent", "op": "publish", "site": site}),
        );
    };
    refuse_entry("head_moved", json!({"index": 0, "addr": format!("{D}.2")}));
    assert_eq!(
        land(&board, &merged, shot(&session, &signer)),
        Err(Refusal::SupersedeRefused {
            index: 0,
            cause: SupersedeCause::HeadMoved { head: Some(a(&format!("{D}.2"))) }
        })
    );
    for (detail, cause) in [
        ("not_member", SupersedeCause::NotMember),
        ("base", SupersedeCause::Base),
        ("duplicate", SupersedeCause::Duplicate),
    ] {
        refuse_entry(detail, json!({"index": 1}));
        assert_eq!(
            land(&board, &merged, shot(&session, &signer)),
            Err(Refusal::SupersedeRefused { index: 1, cause }),
            "{detail}"
        );
    }
    refuse_entry("later_cause", json!({"index": 0}));
    let err = land(&board, &merged, shot(&session, &signer)).expect_err("verbatim");
    assert!(
        matches!(&err, Refusal::Halt(Halt::Refused(r)) if r.code == "supersede_refused"),
        "{err}"
    );
    // The publication family's arms: `not_owner` naming the DRAFT side is
    // the unowned draft, named — never the library's own fault — while
    // naming `doc` is the own fault; the twin fence met again past the
    // one re-read is typed, naming the draft and the member; the budget's
    // detail rides verbatim; `kept_place_moved`, the draft changed since
    // the merge was composed, the board's verdict and no fault of the
    // library's; a place the records do not name, which only the
    // library's own arithmetic sends, the library's own fault.
    let drafted = || Landing::Shot { merger: merger(&session, &signer), draft: Some(a(S)), answers: Answers::default(), journal: None };
    let verbatim = |err: Refusal, code: &str| -> crate::halt::Refused {
        match err {
            Refusal::Halt(Halt::Refused(r)) if r.code == code => r,
            other => panic!("not the board's {code} verbatim: {other:?}"),
        }
    };
    refuse("not_owner", Some(S));
    assert_eq!(land(&board, &merged, drafted()).unwrap_err(), Refusal::UnownedDraft { draft: a(S) }, "the draft side named");
    refuse("not_owner", Some(D));
    let err = land(&board, &merged, drafted()).expect_err("own fault");
    assert!(matches!(&err, Refusal::Halt(Halt::Halt(_))), "{err}");
    assert!(err.to_string().contains("not_owner"), "{err}");
    refuse("already_published", Some(&format!("{D}.3")));
    let twin = land(&board, &merged, drafted()).unwrap_err();
    assert_eq!(twin, Refusal::AlreadyPublished { draft: a(S), member: a(&format!("{D}.3")) }, "{twin}");
    assert!(twin.to_string().contains("nothing was published") && twin.to_string().contains("run the merge again"), "{twin}");
    dialer.world().memo.insert(
        landing_id(&merged.key.text(), "publish"),
        json!({"resp": "rejected", "code": "publication_over_budget", "detail": "70000 in-lock reads priced over the budget of 65536", "disposition": "permanent", "op": "publish"}),
    );
    let budget = verbatim(land(&board, &merged, drafted()).unwrap_err(), "publication_over_budget");
    assert_eq!(budget.detail.as_deref(), Some("70000 in-lock reads priced over the budget of 65536"));
    refuse("kept_place_moved", Some(S));
    let moved = verbatim(land(&board, &merged, drafted()).unwrap_err(), "kept_place_moved");
    assert_eq!(moved.detail, Some(format!("{S} changed after the merge was composed at position {} — nothing was published; run the merge again, which reads the draft as it stands", merged.as_of)), "{moved:?}");
    refuse("stray_place_unrecorded", Some(S));
    let err = land(&board, &merged, drafted()).expect_err("own fault");
    assert!(matches!(&err, Refusal::Halt(Halt::Halt(_))) && err.to_string().contains("stray_place_unrecorded"), "{err}");
    // The head the board owes past the landing's read of it: the board's
    // state, a retry its act — never this library's fault.
    dialer.world().memo.insert(
        landing_id(&merged.key.text(), "publish"),
        json!({"resp": "rejected", "code": "credential_refused", "detail": "attestation_invalid:board_unavailable", "disposition": "reorder", "op": "publish"}),
    );
    let err = land(&board, &merged, shot(&session, &signer)).expect_err("the head owed");
    let Refusal::Halt(Halt::Halt(face)) = &err else { panic!("{err:?}") };
    assert!(
        face.state.contains("H.1")
            && face.cause.contains("attestation_invalid:board_unavailable"),
        "{face}"
    );
    assert!(
        face.act.contains("retry once the board has written its head")
            && !face.act.contains("fault in this library"),
        "{face}"
    );
    assert!(
        dialer.frames("insert").is_empty() && dialer.frames("make_link").is_empty(),
        "nothing after a refused shot"
    );
    // A signed shot refused `attestation_required`: the library's own
    // fault, never sent again.
    dialer.world().memo.insert(
        landing_id(&merged.key.text(), "publish"),
        json!({"resp": "rejected", "code": "credential_refused", "detail": "attestation_required", "disposition": "reorder", "op": "publish"}),
    );
    let shots = dialer.frames("publish").len();
    let err = land(&board, &merged, shot(&session, &signer)).expect_err("own fault");
    let Refusal::Halt(Halt::Halt(face)) = &err else { panic!("{err:?}") };
    assert!(
        face.state.contains("the shot's attest") && face.cause.contains("attestation_required"),
        "{face}"
    );
    assert_eq!(dialer.frames("publish").len(), shots + 1, "one signed shot, never sent again");
}

/// The shot's `withheld` names the words of the list the shot places whose
/// origin the board names, those the head carries never among them.
///
/// From the draft side M is the head's three runs and `S`'s "!!!", which
/// the head does not hold: naming `S`, the refusal names 16–18, counted
/// from 1 past the head's fifteen words. A daughter adding "!" past the
/// head's words, `D·20`, puts at 16 a word of `D` the head does not hold:
/// naming `D`, the refusal names it alone, the head's runs before it
/// carried. With no site, or one naming no document, it is the board's
/// refusal verbatim, never the trunk named in the board's place (the
/// mutant that names it answers `WindowWithheld` naming `D`).
#[test]
fn the_shots_withheld_names_the_words_the_head_does_not_carry() {
    let (dialer, board, signer) = open(draft_landing_world());
    let session = sign_in(&board, &signer);
    let merged = compose(&board, Some(session.token()), &draft_inputs()).expect("composed");
    assert_eq!(m_runs(&merged), draft_m(), "the premise: M");
    dialer.world().memo.insert(
        landing_id(&merged.key.text(), "publish"),
        permanent("publish", "withheld", json!({"addr": S})),
    );
    assert_eq!(
        land(&board, &merged, shot(&session, &signer)),
        Err(Refusal::WindowWithheld { origin: a(S), positions: vec![(16, 3)] })
    );
    let mut w = World::race();
    w.text(D, 20, "!");
    w.member(&format!("{D}.1.2"), vec![run(D, 1, 11), run(D, 20, 1)], Some(11));
    let (dialer, board, signer) = open(w);
    let session = sign_in(&board, &signer);
    let inputs = Inputs { sides: vec![Side::Member(a(&format!("{D}.1.2")))], ..race_inputs() };
    let merged = compose(&board, Some(session.token()), &inputs).expect("composed");
    assert_eq!(
        m_runs(&merged),
        vec![run(D, 1, 4), run(D, 12, 4), run(D, 5, 7), run(D, 20, 1)],
        "the premise: M"
    );
    let refuse = |site: Value| {
        dialer.world().memo.insert(
            landing_id(&merged.key.text(), "publish"),
            permanent("publish", "withheld", site),
        );
    };
    refuse(json!({"addr": D}));
    assert_eq!(
        land(&board, &merged, shot(&session, &signer)),
        Err(Refusal::WindowWithheld { origin: a(D), positions: vec![(16, 1)] })
    );
    for site in [Value::Null, json!({"addr": "x"})] {
        refuse(site.clone());
        let err = land(&board, &merged, shot(&session, &signer)).expect_err("withheld");
        let Refusal::Halt(Halt::Refused(verbatim)) = &err else {
            panic!("{site}: {err:?}")
        };
        assert_eq!(
            (verbatim.code.as_str(), verbatim.detail.as_deref()),
            ("withheld", None),
            "{site}"
        );
    }
}

/// A SHOT TOO LARGE FOR ONE REQUEST IS REFUSED WITH ITS SIZE (decision 13),
/// never as this library's fault. Every copied word costs the signed body
/// its four-byte length at least, past the body's eight-byte count, so a
/// draft side whose words alone pass `SHOT_BODY_BUDGET` so counted is
/// refused that least size before any value is read — no `retrieve_v`, no
/// `retrieve_i`, nothing sent; and one whose three atoms, three mebibytes
/// each, pass it once read is refused with the body's whole size, nothing
/// sent. The mutant that reads first meets the scripted board's panic at a
/// value never planted; the one that keeps the library's own fault answers
/// the second as a halt.
#[test]
fn a_shot_too_large_for_one_request_is_refused_with_its_size() {
    let wide = (SHOT_BODY_BUDGET as u64 - 8) / 4 + 1;
    let mut w = draft_landing_world();
    w.doc(S, false, ACCOUNT, vec![run(D, 1, 11), run(S, 1, wide)]);
    w.staged(S, &format!("{D}.1"), 11);
    let (dialer, board, signer) = open(w);
    let session = sign_in(&board, &signer);
    let merged = compose(&board, Some(session.token()), &draft_inputs()).expect("composed");
    dialer.clear();
    let least = 8 + 4 * (4 + 4 + 7 + wide);
    assert_eq!(
        land(&board, &merged, shot(&session, &signer)),
        Err(Refusal::BodyOverBudget {
            bytes: least,
            budget: SHOT_BODY_BUDGET
        })
    );
    let read = dialer.names();
    assert!(
        !read.iter().any(|o| ["retrieve_v", "retrieve_i", "publish"].contains(&o.as_str())),
        "{read:?}"
    );
    let mut w = draft_landing_world();
    for k in 1..=3 {
        w.values.insert((S.to_string(), k), Val::Atom("x".repeat(3 << 20)));
    }
    let (dialer, board, signer) = open(w);
    let session = sign_in(&board, &signer);
    let merged = compose(&board, Some(session.token()), &draft_inputs()).expect("composed");
    dialer.clear();
    let err = land(&board, &merged, shot(&session, &signer)).expect_err("too large");
    assert!(
        matches!(err, Refusal::BodyOverBudget { bytes, budget } if bytes > 9 << 20 && budget == SHOT_BODY_BUDGET),
        "{err:?}"
    );
    assert!(dialer.frames("publish").is_empty(), "nothing sent: {:?}", dialer.ops());
}

/// Returns the answer the record keeps for "!!!", by reference to `to`.
fn twin_answer(to: &str) -> Value {
    json!([{"from": {"i_start": format!("{S}.0.1.1"), "width": "3"}, "answer": "window", "to": {"i_start": to, "width": "3"}}])
}

/// Returns the shot's fourth run, the draft's "!!!".
fn tail_of(shot: &Value) -> Value {
    shot["runs"][3].clone()
}

/// Checks that a draft word a record names as published goes by reference.
///
/// The word goes to the record's `to`, the draft's own place beside it and
/// the draft named, so the board has nothing to refuse (the `windows`
/// module's doc, the twins; skep #939); the id is the key's, the twins no
/// part of it. The member holds the words by reference, the record keeps
/// them among its answers so `verify` reads the member as sent, the
/// acknowledgment names no answer of the caller's, and a second `land`
/// writes nothing.
#[test]
fn a_draft_word_a_record_names_goes_by_reference_with_its_place_and_lands_once() {
    let (dialer, board, signer) = open(draft_landing_world());
    let session = sign_in(&board, &signer);
    let merged = compose(&board, Some(session.token()), &draft_inputs()).expect("composed");
    assert_eq!(m_runs(&merged), draft_m(), "the premise: S's typed words are M's last run");
    {
        let mut w = dialer.world();
        w.text(D, 19, "!!!");
        plant_record(&mut w, 1, 19, 3);
    }
    dialer.clear();
    let landed = land(&board, &merged, shot(&session, &signer)).expect("landed");
    let Landed::Member { address, answers, .. } = &landed else { panic!("{landed:?}") };
    assert_eq!(address.to_string(), format!("{D}.3"));
    assert!(answers.is_empty(), "the caller answered nothing: {answers:?}");
    let shots = dialer.frames("publish");
    assert_eq!(shots.len(), 1, "{:?}", dialer.ops());
    assert_eq!(shots[0]["id"].as_str(), Some(landing_id(&merged.key.text(), "publish").as_str()), "the id is the key's alone");
    assert_eq!(shots[0]["draft"].as_str(), Some(S), "the draft named, so the commit re-windows it");
    assert_eq!(tail_of(&shots[0]), frames::shot_run(D, &format!("{D}.0.1.19"), 3), "by reference");
    assert_eq!(shots[0]["places"], json!([null, null, null, {"subspace": "1", "ordinal": "12"}]), "the draft's own place beside it: {:?}", shots[0]);
    // The words by reference, in the trunk's own chain, are signed by
    // value, read through the draft that holds them.
    let values: Vec<[u8; 1]> = b"the big cat sat!!!".iter().map(|b| [*b]).collect();
    let head = a(&format!("{D}.2"));
    let body = entry_body_publish(values.iter().map(|v| ShotSegmentPiece::Value(v)), Some(ShotBase { member: &head, extent: 15 }));
    let term = board.board_term().unwrap().unwrap();
    let alg = Signer::public_key(&signer).alg();
    let sig = crate::hex::decode(shots[0]["attest"]["sig"].as_str().unwrap()).unwrap();
    let expected = entry_frame(alg, term, &a(ACCOUNT), DocTerm::One(&a(D)), &body);
    assert_eq!(skep_signature::verify(Signer::tag(&signer), Signer::public_key(&signer), &expected, &sig), Ok(()), "the attest signs the body the pieces spell");
    assert_eq!(dialer.world().docs.get(&format!("{D}.3")).unwrap().runs.last(), Some(&run(D, 19, 3)), "the member holds the published words");
    assert_eq!(appended_record(&dialer)["answers"], twin_answer(&format!("{D}.0.1.19")), "the record keeps the words as sent");
    let record = current(&board, Some(&token()), &a(K), &merged.key).expect("the lookup").expect("a record");
    assert_eq!(verify(&board, Some(&token()), &record), Ok(Verdict::Equal));
    dialer.clear();
    assert_eq!(land(&board, &merged, shot(&session, &signer)).as_ref(), Ok(&landed), "the same landing");
    assert!(dialer.frames("publish").is_empty() && dialer.frames("insert").is_empty() && dialer.frames("make_link").is_empty(), "{:?}", dialer.ops());
}

/// Checks that a retry reading the shot's own records keeps its ids.
///
/// The first call read no record, its shot and its atom landed, and the
/// link's send was lost with its re-ask; the retry over the one composition reads the
/// shot's own record and so sends by reference. The read-first finds the
/// member, and the record is written under the first call's ids — the
/// twins, which only this call read, no part of them, whether or not a
/// window part was answered beside them — so the journal keeps the one
/// atom.
#[test]
fn a_retry_that_reads_the_shots_own_records_keeps_its_ids_and_writes_no_second_atom() {
    fn retry(world: World, answers: Answers) {
        let (dialer, board, signer) = open(world);
        let session = sign_in(&board, &signer);
        let merged = compose(&board, Some(session.token()), &draft_inputs()).expect("composed");
        let landing = || Landing::Shot { merger: merger(&session, &signer), draft: None, answers: answers.clone(), journal: None };
        dialer.world().lose_before = Some(("make_link", 2));
        let lost = land(&board, &merged, landing());
        assert!(matches!(lost, Err(Refusal::Halt(Halt::Dial(_)))), "the link's send lost, and its re-ask: {lost:?}");
        let member = format!("{D}.3");
        let minted = dialer.world().docs.get(&member).expect("the premise: the shot landed").runs.iter().find(|r| r.origin == a(D) && r.width == 3).expect("the premise: the words re-minted under the trunk").clone();
        plant_record(&mut dialer.world(), 1, minted.i_start, 3);
        dialer.clear();
        let landed = land(&board, &merged, landing()).expect("the retry lands");
        assert!(matches!(&landed, Landed::Member { address, .. } if address.to_string() == member), "{landed:?}");
        assert!(dialer.frames("publish").is_empty(), "the member found, no second shot: {:?}", dialer.ops());
        let links = dialer.frames("make_link");
        assert_eq!(links.len(), 1, "{:?}", dialer.ops());
        let journal = links[0]["home"].as_str().expect("the journal").to_string();
        let held: u64 = dialer.world().docs.get(&journal).expect("the journal").runs.iter().map(|r| r.width).sum();
        assert_eq!(held, 1, "one atom in the journal, under the first call's id");
    }
    retry(draft_landing_world(), Answers::default());
    // A window part answered beside them: the answers name the ids, the
    // twins never do.
    let mut world = draft_landing_world();
    world.text(O, 1, "hello");
    world.doc(O, false, ACCOUNT, vec![run(O, 1, 5)]);
    world.change(S, vec![run(D, 1, 11), run(S, 1, 3), run(O, 1, 5)]);
    retry(world, Answers { keep_private: vec![a(O)], ..Answers::default() });
}

/// Checks that `already_published` at the shot reads again and re-sends.
///
/// A publication of the draft's words lands between the records' read and
/// the send, the board refusing the shot, nothing committed (skep #939).
/// The records are read again, and the shot goes once more under its own
/// id, the words by address onto the member the record names with the
/// draft's place beside them, signed afresh over the body that makes; the
/// record keeps the list as sent.
#[test]
fn already_published_at_the_shot_reads_again_and_sends_once_by_reference() {
    let (dialer, board, signer) = open(draft_landing_world());
    let session = sign_in(&board, &signer);
    let merged = compose(&board, Some(session.token()), &draft_inputs()).expect("composed");
    let to = format!("{E}.0.1.3");
    {
        let mut w = dialer.world();
        w.refuse_signed = Some(permanent("publish", "already_published", json!({"addr": format!("{E}.2")})));
        let to = to.clone();
        w.on_refused = Some(Box::new(move |w| {
            w.links.push(LinkRow { addr: format!("{S}.0.2.90"), home: S.into(), from: vec![format!("{S}.0.1.1")], to: vec![to], ty: frames::T_CORRESPONDENCE.into(), width: 3, at: None });
        }));
    }
    dialer.clear();
    let landed = land(&board, &merged, shot(&session, &signer)).expect("landed");
    assert!(matches!(&landed, Landed::Member { address, .. } if address.to_string() == format!("{D}.3")), "{landed:?}");
    let shots = dialer.frames("publish");
    assert_eq!(shots.len(), 2, "one re-send: {:?}", dialer.ops());
    assert_eq!(shots[0]["id"], shots[1]["id"], "under its own id");
    assert_ne!(shots[0]["attest"]["sig"], shots[1]["attest"]["sig"], "signed afresh over the new body");
    assert_eq!(tail_of(&shots[0]), frames::shot_run(S, &format!("{S}.0.1.1"), 3), "first sent as the draft's words");
    assert_eq!(tail_of(&shots[1]), frames::shot_run(E, &to, 3), "then by address onto the published words");
    assert_eq!(shots[1]["places"], json!([null, null, null, {"subspace": "1", "ordinal": "12"}]), "{:?}", shots[1]);
    assert_eq!(appended_record(&dialer)["answers"], twin_answer(&to));
}

/// Checks that `already_published` past the one re-read is the typed arm.
///
/// It names the draft and the member; nothing is sent a third time and
/// nothing of the record written.
#[test]
fn already_published_again_is_the_typed_refusal_and_no_third_frame() {
    let (dialer, board, signer) = open(draft_landing_world());
    let session = sign_in(&board, &signer);
    let merged = compose(&board, Some(session.token()), &draft_inputs()).expect("composed");
    let member = format!("{D}.9");
    dialer.world().memo.insert(landing_id(&merged.key.text(), "publish"), permanent("publish", "already_published", json!({"addr": member})));
    dialer.clear();
    assert_eq!(land(&board, &merged, shot(&session, &signer)), Err(Refusal::AlreadyPublished { draft: a(S), member: a(&member) }));
    assert_eq!(dialer.frames("publish").len(), 2, "one re-send, never a third: {:?}", dialer.ops());
    assert!(dialer.frames("insert").is_empty() && dialer.frames("make_link").is_empty(), "{:?}", dialer.ops());
}

/// Checks that a member found after the refusal is this landing.
///
/// Another process landed this merge between the records' read and the
/// send, so the list recomposed from the records is a member the head's
/// next already holds: no second frame, the record written beside it,
/// keeping the list as the member holds it.
#[test]
fn a_member_found_after_already_published_is_the_landing_with_no_second_shot() {
    let (dialer, board, signer) = open(draft_landing_world());
    let session = sign_in(&board, &signer);
    let merged = compose(&board, Some(session.token()), &draft_inputs()).expect("composed");
    let member = format!("{D}.3");
    {
        let mut w = dialer.world();
        w.refuse_signed = Some(permanent("publish", "already_published", json!({"addr": member})));
        let (member, runs) = (member.clone(), vec![run(D, 1, 4), run(D, 12, 4), run(D, 5, 7), run(D, 19, 3)]);
        w.on_refused = Some(Box::new(move |w| {
            w.text(D, 19, "!!!");
            plant_record(w, 1, 19, 3);
            w.member(&member, runs, Some(15));
            w.trunk_head.insert(D.to_string(), member.clone());
        }));
    }
    dialer.clear();
    let landed = land(&board, &merged, shot(&session, &signer)).expect("landed");
    assert!(matches!(&landed, Landed::Member { address, .. } if address.to_string() == member), "{landed:?}");
    assert_eq!(dialer.frames("publish").len(), 1, "no second shot: {:?}", dialer.ops());
    assert_eq!(appended_record(&dialer)["answers"], twin_answer(&format!("{D}.0.1.19")), "the record reads the member as it stands");
}

/// Every refusal the draft landing's one write can answer is mapped.
///
/// A draft staged from another document's member meets the board's own
/// `base_not_in_chain` as `Refusal::BaseNotInChain`. Planted under the
/// write's id, `withheld` names the origin and its words in M — none for
/// `Z`, which no run of M windows; for `D`, its three runs back to back at
/// 1–15, `S`'s run after them left out — and `withheld` and
/// `fork_base_moved` with no site, or one naming no document, are the
/// board's refusals verbatim, never the draft named in the board's place
/// (the mutant that names it answers `WindowWithheld` naming `S`, and
/// `ForkBaseMoved` naming `S` its own source); `signed_session_required`
/// and `doc_not_registered` answer theirs, every refusal of the frame's
/// substance is the library's own fault and any other code rides
/// verbatim. Each leaves the feed as it stood, the refused write the
/// last frame sent: no journal and no record.
#[test]
fn the_draft_landings_refusals_are_mapped() {
    // `T`, a draft staged from `Z`'s first member: its chain is `Z`'s.
    let t = "1.0.1.0.67";
    let mut w = draft_landing_world();
    w.member(&format!("{Z}.1"), vec![run(Z, 1, 5)], None);
    w.doc(t, false, ACCOUNT, vec![run(Z, 1, 5)]);
    w.staged(t, &format!("{Z}.1"), 5);
    let (dialer, board, signer) = open(w);
    let session = sign_in(&board, &signer);
    let merged = compose(&board, Some(session.token()), &draft_inputs()).expect("composed");
    let rows = dialer.world().rows.len();
    let stopped = |cell: &str| {
        let ops = dialer.ops();
        assert_eq!(ops.last().map(String::as_str), Some("set_arrangement"), "{cell}: {ops:?}");
        assert_eq!(dialer.world().rows.len(), rows, "{cell}: nothing committed");
    };
    dialer.clear();
    assert_eq!(
        land(&board, &merged, draft_landing(&session, &signer, Some(a(t)))),
        Err(Refusal::BaseNotInChain { into: a(t), head: a(&format!("{D}.2")) })
    );
    assert_eq!(
        dialer.frames("set_arrangement")[0]["base"],
        json!({"at": format!("{D}.2"), "extent": "15"}),
        "the head's pair, the base to record: the board records one for T"
    );
    stopped("base_not_in_chain");
    assert_eq!(
        dialer.world().standing(t),
        (Some((format!("{Z}.1"), 5)), None),
        "T's base as it stood"
    );
    // The codes planted under the write's id, each answered to a landing
    // into `S`.
    let id = landing_id(&format!("{}:{S}@{}", merged.key.text(), merged.as_of), "draft");
    let refused = |code: &str, site: Option<&str>| -> Refusal {
        let site = site.map_or(Value::Null, |s| json!({"addr": s}));
        dialer.world().memo.insert(id.clone(), permanent("set_arrangement", code, site));
        dialer.clear();
        let err = land(&board, &merged, draft_landing(&session, &signer, Some(a(S))))
            .expect_err(code);
        stopped(code);
        err
    };
    assert_eq!(m_runs(&merged), draft_m(), "the premise: M");
    assert_eq!(
        refused("withheld", Some(Z)),
        Refusal::WindowWithheld { origin: a(Z), positions: Vec::new() }
    );
    assert_eq!(
        refused("withheld", Some(D)),
        Refusal::WindowWithheld { origin: a(D), positions: vec![(1, 15)] }
    );
    for code in ["withheld", "fork_base_moved"] {
        for site in [None, Some("x")] {
            let err = refused(code, site);
            let Refusal::Halt(Halt::Refused(verbatim)) = &err else {
                panic!("{code}, {site:?}: {err:?}")
            };
            assert_eq!(
                (verbatim.code.as_str(), verbatim.detail.as_deref()),
                (code, None),
                "{site:?}"
            );
        }
    }
    assert_eq!(refused("signed_session_required", None), Refusal::NeedsSignedSession);
    assert_eq!(refused("doc_not_registered", None), Refusal::NoSuchDocument(a(S)));
    for code in [
        "source_not_registered",
        "no_base_to_record",
        "base_extent_too_large",
        "published_target",
        "not_owner",
        "bad_run",
        "dangling_source",
        "too_many_runs",
        "malformed",
    ] {
        let err = refused(code, None);
        let Refusal::Halt(halt) = &err else { panic!("{code}: {err:?}") };
        assert_eq!(halt.exit_code(), 3, "{code}: {err:?}");
        let Halt::Halt(face) = halt else { panic!("{code}: {err:?}") };
        assert!(
            face.cause.contains(code) && face.act.contains("fault in this library"),
            "{code}: {face}"
        );
    }
    let err = refused("txn_over_budget", None);
    let Refusal::Halt(Halt::Refused(verbatim)) = &err else { panic!("{err:?}") };
    assert_eq!(verbatim.code, "txn_over_budget");
}

/// A draft the merger may not read is refused before any write, naming it.
///
/// `X` is another account's private draft, withheld. A landing into `X`
/// meets `withheld` at its one read of `X`'s metadata as it stands, after
/// the merger's newest record for the key, the undo and the withdrawal of
/// `X` at theirs, all at the head — each
/// [`Refusal::Unreadable`] naming `X`, with no `stage`,
/// `set_arrangement`, journal mint, `insert` or `make_link` sent and no
/// commit made. A fresh landing whose standing record names a draft
/// withheld since, `S`, meets `withheld` at its read of `S` as it
/// stands, in a landing and a resume alike, never answered as standing
/// (SP-14), nothing staged or written.
#[test]
fn a_draft_the_merger_may_not_read_is_refused_unreadable_before_any_write() {
    let x = "1.0.2.0.70";
    let mut w = draft_landing_world();
    w.doc(x, false, "1.0.2", vec![run(D, 1, 11)]);
    w.withheld.insert(x.to_string());
    let (dialer, board, signer) = open(w);
    let session = sign_in(&board, &signer);
    let m = merger(&session, &signer);
    let merged = compose(&board, Some(session.token()), &draft_inputs()).expect("composed");
    let rows = dialer.world().rows.len();
    let nothing_sent = |cell: &str| {
        for op in ["publish", "stage", "set_arrangement", "create_new_document", "insert", "make_link"] {
            assert!(dialer.frames(op).is_empty(), "{cell}: no `{op}`: {:?}", dialer.ops());
        }
        assert_eq!(dialer.world().rows.len(), rows, "{cell}: no commit");
    };
    dialer.clear();
    assert_eq!(
        land(&board, &merged, draft_landing(&session, &signer, Some(a(x)))),
        Err(Refusal::Unreadable(a(x)))
    );
    assert_eq!(
        dialer.ops(),
        ["find_links_ftt", "doc_metadata"],
        "the merger's newest record for the key, by the links of the kind to the daughter, the one side but the head, then the one read of X, as it stands"
    );
    nothing_sent("a landing into X");
    dialer.clear();
    assert_eq!(undo(&board, m, &a(x), &a(K), None, None), Err(Refusal::Unreadable(a(x))));
    assert_eq!(dialer.ops(), ["doc_metadata"]);
    nothing_sent("the undo");
    dialer.clear();
    assert_eq!(withdraw(&board, m, &a(x), &a(K), None), Err(Refusal::Unreadable(a(x))));
    assert_eq!(dialer.ops(), ["doc_metadata"]);
    nothing_sent("the withdrawal");
    // A fresh landing whose standing record names `S`, withheld since.
    land(&board, &merged, draft_landing(&session, &signer, Some(a(S)))).expect("landed in S");
    dialer.world().withheld.insert(S.to_string());
    let rows = dialer.world().rows.len();
    dialer.clear();
    let fresh = || draft_landing(&session, &signer, None);
    assert_eq!(land(&board, &merged, fresh()), Err(Refusal::Unreadable(a(S))));
    assert_eq!(resume(&board, &merged, fresh()), Err(Refusal::Unreadable(a(S))));
    let read: Vec<Value> =
        dialer.frames("doc_metadata").iter().map(|f| f["doc"].clone()).collect();
    assert_eq!(read, [json!(S), json!(S)], "S read as it stands, each: {:?}", dialer.ops());
    assert!(
        dialer.frames("stage").is_empty() && dialer.frames("set_arrangement").is_empty(),
        "nothing staged or written: {:?}",
        dialer.ops()
    );
    assert_eq!(dialer.world().rows.len(), rows, "no commit");
}

/// A fresh landing whose M windows a document withheld since is refused
/// before its stage (P13).
///
/// M windows "hello" from `Z`, readable when the merge was composed and
/// withheld before the landing. The one write's source gate would refuse
/// it past the stage, leaving the staged draft standing with nothing in
/// it, so the landing reads each origin M windows first and is refused
/// [`Refusal::WindowWithheld`] naming `Z` and its words in M, positions 5
/// to 9: no `stage`, no `set_arrangement`, no commit (the mutant that
/// reads no window first stages a draft).
#[test]
fn a_fresh_landing_over_a_window_withheld_since_is_refused_before_its_stage() {
    let (dialer, board, signer) = open(World::window_and_draft());
    let session = sign_in(&board, &signer);
    let merged = compose(&board, Some(session.token()), &draft_inputs()).expect("composed");
    assert!(merged.families.contains(&Family::Window), "the premise: M windows Z");
    dialer.world().withheld.insert(Z.to_string());
    let rows = dialer.world().rows.len();
    dialer.clear();
    assert_eq!(
        land(&board, &merged, draft_landing(&session, &signer, None)),
        Err(Refusal::WindowWithheld { origin: a(Z), positions: vec![(5, 5)] })
    );
    assert!(
        dialer.frames("stage").is_empty() && dialer.frames("set_arrangement").is_empty(),
        "nothing staged or written: {:?}",
        dialer.ops()
    );
    assert_eq!(dialer.world().rows.len(), rows, "no commit");
}

/// P IS WHERE THE OPENING FENCES STAND (skep #1144): another hand's edit
/// to the draft after the composition read it — after the draft's
/// closing fence and before the head's, or after every closing fence and
/// before the prior records' read — leaves the draft unchanged across its
/// fences, so the composition answers, and P, where the opening fences
/// stood, is before the edit: the draft landing typed against P is
/// refused `arrangement_moved`, nothing written and the edit kept (the
/// mutants taking P from the last closing fence, or from the reader's
/// highest `as_of`, type the write past the edit and lose it).
#[test]
fn an_edit_past_the_drafts_closing_fence_is_past_p_and_the_draft_landing_refuses_it() {
    // The frames of a composition no hand edits, counted from 1.
    let (dialer, board, _) = open(draft_landing_world());
    compose(&board, Some(&token()), &draft_inputs()).expect("composed untouched");
    let first_find = dialer.served_index("find_links_ftt");
    let head = format!("{D}.2");
    {
        let served = dialer.served.lock().unwrap();
        let fence = |k: usize| served[k - 1].1["doc"].as_str().map(str::to_string);
        assert_eq!(
            (fence(first_find - 2), fence(first_find - 1)),
            (Some(S.to_string()), Some(head)),
            "the premise: the draft's closing fence, then the head's, then the prior records"
        );
    }
    for (cell, before) in [
        ("after the draft's closing fence, before the head's", first_find - 1),
        ("after every closing fence, before the prior records", first_find),
    ] {
        let (dialer, board, signer) = open(draft_landing_world());
        let session = sign_in(&board, &signer);
        let p = dialer.world().position;
        dialer.clear();
        dialer.world().interleave = Some((before, S.to_string(), vec![run(D, 1, 11)]));
        let merged = compose(&board, Some(session.token()), &draft_inputs())
            .unwrap_or_else(|e| panic!("{cell}: the draft unchanged across its fences: {e:?}"));
        assert!(dialer.world().interleave.is_none(), "{cell}: the edit landed mid-walk");
        assert_eq!(merged.as_of, p, "{cell}: P where the opening fences stood, before the edit");
        assert_eq!(m_runs(&merged), draft_m(), "{cell}: M as the draft was read, \"!!!\" in it");
        let rows = dialer.world().rows.len();
        let err = land(&board, &merged, draft_landing(&session, &signer, Some(a(S))))
            .expect_err("the draft changed past P");
        let Refusal::Halt(Halt::Refused(refused)) = &err else { panic!("{cell}: {err:?}") };
        assert_eq!(refused.code, "arrangement_moved", "{cell}");
        let w = dialer.world();
        assert_eq!(w.docs[S].runs, vec![run(D, 1, 11)], "{cell}: the edit kept");
        assert_eq!(w.rows.len(), rows, "{cell}: nothing written");
    }
}

/// A CLAIMED BOARD WHOSE HEAD IS OWED LANDS NO SHOT (SP-14): `/health`
/// names a claimant and `H.1` serves no record, so the shot halts naming
/// `H.1` before its first write — no `publish`, journal mint, `insert` or
/// `make_link` sent, no commit made — and a `resume` that finds nothing
/// landed answers none with no head read. The same board unclaimed lands
/// it, carrying no `attest`, and the record's link carries none on either
/// board. A draft landing signs nothing — its stage, its one write and
/// its record's two writes go to private drafts — so it lands on the
/// claimed board whose head is owed, reading no head and sending no
/// `attest`.
#[test]
fn a_claimed_board_serving_no_head_record_lands_nothing_and_an_unclaimed_one_lands_unsigned() {
    let head_read = |dialer: &Scripted| {
        dialer.frames("retrieve_v").iter().any(|f| f["specs"][0]["doc"] == HEAD_MEMBER_1)
    };
    let mut world = World::race();
    world.head = false;
    let (dialer, board, signer) = open(world);
    let session = sign_in(&board, &signer);
    let merged = compose(&board, Some(session.token()), &race_inputs()).expect("composed");
    let rows = dialer.world().rows.len();
    dialer.clear();
    let err = land(&board, &merged, shot(&session, &signer)).expect_err("the head is owed");
    let Refusal::Halt(Halt::Halt(face)) = &err else { panic!("{err:?}") };
    assert!(face.state.contains("H.1") && face.state.contains("cannot land"), "{face}");
    assert!(face.cause.contains(&format!("names {ACCOUNT} its claimant")), "{face}");
    assert!(face.act.contains("nothing was written"), "{face}");
    for op in ["publish", "create_new_document", "insert", "make_link"] {
        assert!(dialer.frames(op).is_empty(), "no `{op}`: {:?}", dialer.ops());
    }
    assert_eq!(dialer.world().rows.len(), rows, "no commit");
    dialer.clear();
    assert_eq!(resume(&board, &merged, shot(&session, &signer)), Ok(None), "nothing landed");
    assert!(
        !head_read(&dialer),
        "a resume with nothing to write reads no head: {:?}",
        dialer.ops()
    );
    // The same board, no one its claimant: landed, unsigned.
    dialer.world().claimed = false;
    dialer.clear();
    land(&board, &merged, shot(&session, &signer)).expect("landed");
    let links = dialer.frames("make_link");
    assert_eq!(links.len(), 1, "the record's link: {:?}", dialer.ops());
    for frame in dialer.frames("publish").iter().chain(&links) {
        assert!(frame.get("attest").is_none(), "unsigned: {frame}");
    }

    // The draft landings, on the claimed board whose head is owed.
    for cell in ["a landing into S", "a fresh draft"] {
        let mut world = draft_landing_world();
        world.head = false;
        let (dialer, board, signer) = open(world);
        let session = sign_in(&board, &signer);
        let merged = compose(&board, Some(session.token()), &draft_inputs()).expect("composed");
        let (landing, writes) = match cell {
            "a landing into S" => (
                draft_landing(&session, &signer, Some(a(S))),
                vec!["set_arrangement", "insert", "make_link"],
            ),
            _ => (
                draft_landing(&session, &signer, None),
                vec!["stage", "set_arrangement", "insert", "make_link"],
            ),
        };
        dialer.clear();
        let landed = land(&board, &merged, landing).unwrap_or_else(|e| panic!("{cell}: {e}"));
        assert!(matches!(landed, Landed::Draft { .. }), "{cell}: {landed:?}");
        assert!(!head_read(&dialer), "{cell}: no head read: {:?}", dialer.ops());
        for op in writes {
            let frames = dialer.frames(op);
            assert_eq!(frames.len(), 1, "{cell}: one `{op}`: {:?}", dialer.ops());
            assert!(frames[0].get("attest").is_none(), "{cell}: unsigned: {}", frames[0]);
        }
    }
}

/// A LANDING THAT STANDS WRITES ITS RECORD UNSIGNED, WHATEVER THE HEAD
/// (SP-14): the shot lands and the record's step meets the board too
/// busy to find the account's journal — the merge standing with its
/// record unwritten, `resume` its act, never the library's fault — and,
/// read afresh with the head owed, the residue walk writes the record:
/// no head read, the atom and the link unsigned, no second shot.
#[test]
fn a_landing_that_stands_writes_its_record_unsigned_while_the_head_is_owed() {
    let (dialer, board, signer) = open(World::race());
    let session = sign_in(&board, &signer);
    let merged = compose(&board, Some(session.token()), &race_inputs()).expect("composed");
    too_busy_for_the_find(&mut dialer.world());
    let member = format!("{D}.3");
    let err = land(&board, &merged, shot(&session, &signer)).expect_err("the record unwritten");
    let Refusal::Halt(Halt::Halt(face)) = &err else { panic!("{err:?}") };
    assert!(
        face.state.contains(&format!("the merge stands at {member}, and its record is not written: the board was too busy to find the account's merge journal")),
        "{face}"
    );
    assert!(face.cause.starts_with("scan_busy:"), "{face}");
    assert!(
        face.act.starts_with("resume") && !face.act.contains("fault in this library"),
        "{face}"
    );
    assert!(dialer.world().docs.contains_key(&member), "the premise: the shot landed");
    assert!(
        dialer.frames("insert").is_empty() && dialer.frames("make_link").is_empty(),
        "nothing of the record: {:?}",
        dialer.ops()
    );
    // A board read afresh, its head owed: the record written, unsigned.
    dialer.world().head = false;
    let afresh = Board::new(Origin::parse("http://127.0.0.1:8642").unwrap(), dialer.clone());
    dialer.clear();
    let resumed = resume(&afresh, &merged, shot(&session, &signer)).expect("resumed");
    assert!(
        matches!(&resumed, Some(Landed::Member { address, .. }) if address.to_string() == member),
        "{resumed:?}"
    );
    assert!(
        dialer.frames("retrieve_v").iter().all(|f| f["specs"][0]["doc"] != HEAD_MEMBER_1),
        "no head read: {:?}",
        dialer.ops()
    );
    for op in ["insert", "make_link"] {
        let frames = dialer.frames(op);
        assert_eq!(frames.len(), 1, "one `{op}`: {:?}", dialer.ops());
        assert!(frames[0].get("attest").is_none(), "unsigned: {}", frames[0]);
    }
    assert!(dialer.frames("publish").is_empty(), "no second shot: {:?}", dialer.ops());
}

/// A CLAIM PAST THE HEAD'S READ IS MET BY ONE SIGNED SEND OF THE SHOT
/// UNDER ITS OWN ID: the landing reads a board no one has claimed and
/// sends the shot unsigned; a claim lands ahead of it with its head
/// written, and the board refuses it `attestation_required` before its
/// transaction. The head is read again and the same shot sent once more,
/// signed, under the same id, which the refusal left unmemoized, and the
/// landing completes, the member minted once and the record linked
/// once. The record's link is a private journal's, so a claim landing
/// ahead of it — after the shot, or after a landing into `S` — changes
/// nothing: it is sent once, unsigned, and lands; a second `land` meets
/// it, writing nothing. The signed send's answer is a signed frame's:
/// `attestation_required` again this library's own fault, never a third
/// shot. Where the head read again serves none, the shot's refusal is
/// the head the board owes, one frame sent and nothing after it.
#[test]
fn a_claim_past_the_head_read_re_sends_the_shot_once_signed() {
    let unclaimed = |mut world: World, claim_before: Option<&'static str>| {
        world.claimed = false;
        world.head = false;
        world.claim_before = claim_before;
        open(world)
    };
    // The frame sent unsigned, then the same frame signed, under `id`.
    let resent = |frames: &[Value], id: &str| {
        assert_eq!(frames.len(), 2, "one signed send after the unsigned one: {frames:?}");
        assert!(frames[0].get("attest").is_none(), "the first went unsigned: {}", frames[0]);
        let mut signed = frames[1].clone();
        let attest =
            signed.as_object_mut().unwrap().remove("attest").expect("the second signed");
        assert!(attest["sig"].is_string(), "{attest}");
        assert_eq!(signed, frames[0], "the same frame, signed");
        assert_eq!(frames[0]["id"].as_str(), Some(id), "under the frame's own id");
    };
    let record_links = |w: &World| w.links.iter().filter(|l| l.ty == K).count();
    let minted = |w: &World| w.rows.iter().filter(|r| r.op == "publish").count();

    // The shot.
    let (dialer, board, signer) = unclaimed(World::race(), Some("publish"));
    let session = sign_in(&board, &signer);
    let merged = compose(&board, Some(session.token()), &race_inputs()).expect("composed");
    let shots = minted(&dialer.world());
    dialer.clear();
    let landed = land(&board, &merged, shot(&session, &signer)).expect("landed");
    assert!(
        matches!(&landed, Landed::Member { address, .. } if address.to_string() == format!("{D}.3")),
        "{landed:?}"
    );
    resent(&dialer.frames("publish"), &landing_id(&merged.key.text(), "publish"));
    let links = dialer.frames("make_link");
    assert_eq!(links.len(), 1, "the record's link, once: {:?}", dialer.ops());
    assert!(
        links[0].get("attest").is_none(),
        "a private journal's link, unsigned: {}",
        links[0]
    );
    let w = dialer.world();
    assert_eq!(minted(&w), shots + 1, "one shot committed");
    assert!(
        !w.docs.contains_key(&format!("{D}.2.1")),
        "never applied again as the head's daughter"
    );
    drop(w);

    // A claim ahead of the record's link, after the shot and after a
    // landing into `S`: the link sent once, unsigned.
    for cell in ["the shot", "a landing into S"] {
        let (world, inputs) = match cell {
            "the shot" => (World::race(), race_inputs()),
            _ => (draft_landing_world(), draft_inputs()),
        };
        let (dialer, board, signer) = unclaimed(world, Some("make_link"));
        let session = sign_in(&board, &signer);
        let merged = compose(&board, Some(session.token()), &inputs).expect("composed");
        let (landing, stem) = match cell {
            "the shot" => (shot(&session, &signer), merged.key.text()),
            _ => (
                draft_landing(&session, &signer, Some(a(S))),
                format!("{}:{S}@{}", merged.key.text(), merged.as_of),
            ),
        };
        dialer.clear();
        let landed = land(&board, &merged, landing).unwrap_or_else(|e| panic!("{cell}: {e}"));
        let record = match &landed {
            Landed::Member { address, record, .. }
                if address.to_string() == format!("{D}.3") =>
            {
                record.clone()
            }
            Landed::Draft { into, record, .. } if *into == a(S) => record.clone(),
            other => panic!("{cell}: {other:?}"),
        };
        assert!(
            dialer.frames("publish").iter().all(|f| f.get("attest").is_none()),
            "{cell}: the shot went before the claim, unsigned"
        );
        let links = dialer.frames("make_link");
        assert_eq!(links.len(), 1, "{cell}: one link: {:?}", dialer.ops());
        assert!(links[0].get("attest").is_none(), "{cell}: unsigned: {}", links[0]);
        assert_eq!(
            links[0]["id"].as_str(),
            Some(landing_id(&stem, "link").as_str()),
            "{cell}: under its own id"
        );
        assert!(dialer.world().claimed, "{cell}: the premise, the claim landed ahead of it");
        assert_eq!(dialer.frames("insert").len(), 1, "{cell}: one atom: {:?}", dialer.ops());
        assert_eq!(record_links(&dialer.world()), 1, "{cell}: one record linked");
        let again = match cell {
            "the shot" => shot(&session, &signer),
            _ => draft_landing(&session, &signer, Some(a(S))),
        };
        dialer.clear();
        let second = land(&board, &merged, again).unwrap_or_else(|e| panic!("{cell}: {e}"));
        assert!(
            matches!(&second, Landed::Member { record: r, .. } | Landed::Draft { record: r, .. } if *r == record),
            "{cell}: the same record: {second:?}"
        );
        for op in ["publish", "create_new_document", "insert", "make_link"] {
            assert!(
                dialer.frames(op).is_empty(),
                "{cell}: no `{op}` again: {:?}",
                dialer.ops()
            );
        }
    }

    // The signed send's answer is a signed frame's.
    let required = |op: &str| json!({"resp": "rejected", "code": "credential_refused", "detail": "attestation_required", "disposition": "reorder", "op": op});
    let (dialer, board, signer) = unclaimed(World::race(), Some("publish"));
    dialer.world().refuse_signed = Some(required("publish"));
    let session = sign_in(&board, &signer);
    let merged = compose(&board, Some(session.token()), &race_inputs()).expect("composed");
    let rows = dialer.world().rows.len();
    dialer.clear();
    let err =
        land(&board, &merged, shot(&session, &signer)).expect_err("the library's own fault");
    let Refusal::Halt(Halt::Halt(face)) = &err else { panic!("{err:?}") };
    assert!(
        face.state.contains("the shot's attest") && face.act.contains("fault in this library"),
        "{face}"
    );
    assert_eq!(dialer.frames("publish").len(), 2, "never a third shot: {:?}", dialer.ops());
    assert!(
        dialer.frames("insert").is_empty() && dialer.frames("make_link").is_empty(),
        "nothing after the shot"
    );
    assert_eq!(dialer.world().rows.len(), rows, "nothing committed");

    // No head the second read finds: the head the board owes.
    let (dialer, board, signer) = unclaimed(World::race(), None);
    let session = sign_in(&board, &signer);
    let merged = compose(&board, Some(session.token()), &race_inputs()).expect("composed");
    dialer.world().memo.insert(landing_id(&merged.key.text(), "publish"), required("publish"));
    dialer.clear();
    let err = land(&board, &merged, shot(&session, &signer)).expect_err("the head is owed");
    let Refusal::Halt(Halt::Halt(face)) = &err else { panic!("{err:?}") };
    assert!(face.state.contains("H.1") && face.state.contains("cannot land"), "{face}");
    assert!(
        face.cause.contains("attestation_required")
            && !face.act.contains("fault in this library"),
        "{face}"
    );
    assert_eq!(
        dialer.frames("publish").len(),
        1,
        "nothing sent after the second read: {:?}",
        dialer.ops()
    );
    assert!(
        dialer.frames("insert").is_empty() && dialer.frames("make_link").is_empty(),
        "nothing after the shot"
    );
}

/// A journal that fails a check at the record leaves the act standing.
///
/// Where the record is the call's first write — a `resume` after the
/// act's acknowledgment was lost — no journal is checked before it, so a
/// journal named that this merger may not read (`J`, another account's
/// private document, withheld) or that this board does not register
/// (`U`) is met at the record's first read, its extent: faced as the act
/// standing with its record unwritten, exit 3 and never a refusal of the
/// act, nothing of the record sent. Over the shot and a landing into `S`:
/// the member minted, the draft holding M; a `resume` naming no journal
/// then writes the record into the account's own, once, landing nothing
/// twice. The undo of `S` checks its journal `G`, a draft of the
/// merger's own, before its write; with `G` withheld from the next frame
/// on, the draft is back to C, the record of the undo unwritten, and a
/// re-run finds the merge taken back.
#[test]
fn a_journal_the_act_cannot_write_into_leaves_the_act_standing_with_its_record_unwritten() {
    let (j, u, g) = ("1.0.2.0.70", "1.0.2.0.71", "1.0.1.0.70");
    let world = |mut w: World| {
        w.doc(j, false, "1.0.2", Vec::new());
        w.withheld.insert(j.to_string());
        w.doc(g, false, ACCOUNT, Vec::new());
        w
    };
    let checks = [
        (j, "is not readable to this merger (withheld)"),
        (u, "is not registered at this board (doc_not_registered)"),
    ];
    let unwritten = |err: &Refusal, journal: &str, why: &str, cell: &str| -> crate::halt::Face {
        let Refusal::Halt(halt) = err else { panic!("{cell}: {err:?}") };
        assert_eq!(halt.exit_code(), 3, "{cell}: a halt, never the board's refusal: {err:?}");
        let Halt::Halt(face) = halt else { panic!("{cell}: {err:?}") };
        assert!(face.state.ends_with(&format!("is not written: the journal {journal} {why}")), "{cell}: {face}");
        assert!(face.cause.contains(&format!("{journal}'s extent")), "{cell}: {face}");
        assert!(!face.act.contains("fault in this library"), "{cell}: {face}");
        face.clone()
    };
    let no_record = |dialer: &Scripted, cell: &str| {
        assert!(
            dialer.frames("insert").is_empty() && dialer.frames("make_link").is_empty(),
            "{cell}: nothing of the record sent: {:?}",
            dialer.ops()
        );
    };

    // The shot, its acknowledgment lost: the member minted, no record.
    let (dialer, board, signer) = open(world(World::race()));
    let session = sign_in(&board, &signer);
    let merged = compose(&board, Some(session.token()), &race_inputs()).expect("composed");
    let shot_into = |journal: Option<&str>| Landing::Shot { merger: merger(&session, &signer), draft: None, answers: Answers::default(), journal: journal.map(a) };
    dialer.world().drop_acks = 2;
    let lost = land(&board, &merged, shot_into(None));
    assert!(matches!(lost, Err(Refusal::Halt(Halt::Dial(_)))), "the ack lost: {lost:?}");
    let member = format!("{D}.3");
    assert!(dialer.world().docs.contains_key(&member), "the premise: the shot landed");
    for (journal, why) in checks {
        dialer.clear();
        let err = resume(&board, &merged, shot_into(Some(journal))).expect_err("the record unwritten");
        let face = unwritten(&err, journal, why, "the shot");
        assert!(face.state.starts_with(&format!("the merge stands at {member}, and its record is")), "{face}");
        assert!(face.act.starts_with("resume with a journal this account can write"), "{face}");
        no_record(&dialer, "the shot");
    }
    dialer.clear();
    let resumed = resume(&board, &merged, shot_into(None)).expect("resumed");
    assert!(matches!(&resumed, Some(Landed::Member { address, .. }) if address.to_string() == member), "{resumed:?}");
    assert_eq!((dialer.frames("insert").len(), dialer.frames("make_link").len()), (1, 1), "the record, once: {:?}", dialer.ops());
    assert!(dialer.frames("publish").is_empty(), "nothing landed twice");

    // A landing into `S`, its acknowledgment lost and its re-ask's: the
    // draft holding M, no record.
    let (dialer, board, signer) = open(world(draft_landing_world()));
    let session = sign_in(&board, &signer);
    let merged = compose(&board, Some(session.token()), &draft_inputs()).expect("composed");
    let into_s = |journal: Option<&str>| Landing::Draft { merger: merger(&session, &signer), into: Some(a(S)), journal: journal.map(a) };
    dialer.world().drop_acks = 2;
    let lost = land(&board, &merged, into_s(None));
    assert!(matches!(lost, Err(Refusal::Halt(Halt::Dial(_)))), "the ack lost: {lost:?}");
    assert_eq!(dialer.world().docs.get(S).unwrap().runs, draft_m(), "the premise: the draft holds M");
    for (journal, why) in checks {
        dialer.clear();
        let err = resume(&board, &merged, into_s(Some(journal))).expect_err("the record unwritten");
        let face = unwritten(&err, journal, why, "a landing into S");
        assert!(face.state.starts_with(&format!("the merge stands at {S}, and its record is")), "{face}");
        assert!(face.act.starts_with(&format!("resume naming {S} with a journal this account can write")), "{face}");
        no_record(&dialer, "a landing into S");
    }
    dialer.clear();
    let resumed = resume(&board, &merged, into_s(None)).expect("resumed");
    assert!(matches!(&resumed, Some(Landed::Draft { into, .. }) if *into == a(S)), "{resumed:?}");
    assert_eq!((dialer.frames("insert").len(), dialer.frames("make_link").len()), (1, 1), "the record, once: {:?}", dialer.ops());
    assert!(dialer.frames("set_arrangement").is_empty(), "nothing landed twice");

    // The undo of `S` naming `G`: refused at the check while `G` is
    // withheld; then, `G` passing it and withheld from the next frame
    // on, the draft back to C and the record of the undo unwritten.
    let (dialer, board, signer) = open(world(draft_landing_world()));
    let session = sign_in(&board, &signer);
    let m = merger(&session, &signer);
    landed_in_s(&board, &session, &signer);
    dialer.world().withheld.insert(g.to_string());
    dialer.clear();
    undo(&board, m, &a(S), &a(K), None, Some(&a(g))).expect_err("withheld at the check");
    let checked = dialer.requests().len();
    assert_eq!(dialer.ops().last().map(String::as_str), Some("doc_metadata"), "the check, the last read: {:?}", dialer.ops());
    assert_eq!(dialer.frames("doc_metadata").last().map(|f| f["doc"].clone()), Some(json!(g)), "the check reads `G`");
    {
        let mut w = dialer.world();
        w.withheld.remove(g);
        w.withhold = Some((checked + 1, g.to_string()));
    }
    dialer.clear();
    let err = undo(&board, m, &a(S), &a(K), None, Some(&a(g))).expect_err("the record unwritten");
    let face = unwritten(&err, g, "is not readable to this merger (withheld)", "the undo");
    assert!(face.state.starts_with(&format!("the merge is out of {S}, and the record of the undo is")), "{face}");
    assert_eq!(dialer.world().docs.get(S).unwrap().runs, draft_c(), "the draft back to C");
    assert_eq!(dialer.frames("set_arrangement").len(), 1, "the undo's one write");
    no_record(&dialer, "the undo");
    assert_eq!(
        undo(&board, m, &a(S), &a(K), None, None),
        Err(Refusal::NothingToUndo { draft: a(S), why: NoUndo::TakenBack }),
        "a re-run finds the merge taken back"
    );
}

/// A named journal is checked before the act's first write (P13).
///
/// The check is one `doc_metadata` of the journal at the head, after the
/// act's reads and before its first write — the shot, the stage, a named
/// draft's one write, an undo's or a withdrawal's. A journal this merger
/// may not read (`J`, withheld), one this board does not register (`U`),
/// or another account's draft it may read (`O`) or published document
/// refuses the act with a face naming the journal and the check it fails,
/// exit 3 and never this library's fault; a published document of its
/// own — `D`, the trunk, and its doc 1, born published — is the typed
/// refusal naming it, `PublishedJournal`: each with nothing written, no
/// commit, the journal read once and nothing after it. A draft of the
/// merger's own (`G`) passes, and the record's atom goes into it.
#[test]
fn a_named_journal_is_checked_before_the_acts_first_write() {
    let (j, u, o, g) = ("1.0.2.0.70", "1.0.2.0.71", "1.0.2.0.68", "1.0.1.0.70");
    let world = |mut w: World| {
        w.doc(j, false, "1.0.2", Vec::new());
        w.withheld.insert(j.to_string());
        w.doc(o, false, "1.0.2", Vec::new());
        w.doc(g, false, ACCOUNT, Vec::new());
        w
    };
    // `None`: the typed refusal of a published journal of the merger's.
    let checks = [
        (j, Some("is not readable to this merger (withheld)")),
        (u, Some("is not registered at this board (doc_not_registered)")),
        (o, Some("is another account's")),
        (D, None),
        (DOC1, None),
        // Another account's published document: the owner is judged
        // before the published bit, as the board judges the atom.
        (OTHER_DOC1, Some("is another account's")),
    ];
    let writes = ["publish", "stage", "set_arrangement", "create_new_document", "insert", "make_link"];
    for cell in ["the shot", "a landing into S", "a fresh draft", "the undo", "the withdrawal"] {
        let (w, inputs) = match cell {
            "the shot" => (World::race(), race_inputs()),
            _ => (draft_landing_world(), draft_inputs()),
        };
        let (dialer, board, signer) = open(world(w));
        let session = sign_in(&board, &signer);
        let m = merger(&session, &signer);
        let merged = match cell {
            "the undo" | "the withdrawal" => landed_in_s(&board, &session, &signer).0,
            _ => compose(&board, Some(session.token()), &inputs).expect("composed"),
        };
        let act = |journal: &str| -> Result<(), Refusal> {
            let journal = Some(a(journal));
            match cell {
                "the shot" => land(&board, &merged, Landing::Shot { merger: m, draft: None, answers: Answers::default(), journal }).map(drop),
                "a landing into S" => land(&board, &merged, Landing::Draft { merger: m, into: Some(a(S)), journal }).map(drop),
                "a fresh draft" => land(&board, &merged, Landing::Draft { merger: m, into: None, journal }).map(drop),
                "the undo" => undo(&board, m, &a(S), &a(K), None, journal.as_ref()).map(drop),
                _ => withdraw(&board, m, &a(S), &a(K), journal.as_ref()).map(drop),
            }
        };
        let blocked = match cell {
            "the undo" | "the withdrawal" => format!("so the merge cannot be taken out of {S}"),
            _ => "so the merge cannot land".to_string(),
        };
        let rows = dialer.world().rows.len();
        for (journal, why) in checks {
            dialer.clear();
            let err = act(journal).expect_err(journal);
            match why {
                None => assert_eq!(err, Refusal::PublishedJournal { journal: a(journal) }, "{cell}: a published journal of the merger's own"),
                Some(why) => {
                    let Refusal::Halt(halt) = &err else { panic!("{cell}: {journal}: {err:?}") };
                    assert_eq!(halt.exit_code(), 3, "{cell}: {journal}: {err:?}");
                    let Halt::Halt(face) = halt else { panic!("{cell}: {journal}: {err:?}") };
                    assert_eq!(face.state, format!("the journal {journal} {why}, {blocked}"), "{cell}");
                    assert!(face.cause.contains("its `doc_metadata`"), "{cell}: {face}");
                    assert!(face.act.contains("nothing was written") && !face.act.contains("fault in this library"), "{cell}: {face}");
                }
            }
            for op in writes {
                assert!(dialer.frames(op).is_empty(), "{cell}: {journal}: no `{op}`: {:?}", dialer.ops());
            }
            assert_eq!(dialer.world().rows.len(), rows, "{cell}: {journal}: no commit");
            let read = dialer.frames("doc_metadata").into_iter().filter(|f| f["doc"] == journal).count();
            assert_eq!(read, 1, "{cell}: {journal}: the journal read once: {:?}", dialer.ops());
            assert_eq!(dialer.ops().last().map(String::as_str), Some("doc_metadata"), "{cell}: {journal}: nothing after the check: {:?}", dialer.ops());
        }
        // A draft of the merger's own passes, and takes the record.
        dialer.clear();
        act(g).unwrap_or_else(|e| panic!("{cell}: {e}"));
        assert_eq!(dialer.frames("doc_metadata").into_iter().filter(|f| f["doc"] == g).count(), 1, "{cell}: the journal read once");
        let inserts = dialer.frames("insert");
        assert_eq!(inserts.len(), 1, "{cell}: one atom: {:?}", dialer.ops());
        assert_eq!(inserts[0]["doc"], g, "{cell}: the record into the journal named");
    }
}

/// `journal::check` is the landing's check alone, nothing written.
///
/// It answers each journal as an act's check does — a published one of
/// the merger's own (`D`) the typed refusal naming it, another account's
/// draft (`O`) the halt naming the check, a draft of the merger's own
/// (`G`) nothing — one `doc_metadata` of each and no other frame.
#[test]
fn the_journal_check_is_the_landings_check_alone() {
    let (o, g) = ("1.0.2.0.68", "1.0.1.0.70");
    let mut world = World::race();
    world.doc(o, false, "1.0.2", Vec::new());
    world.doc(g, false, ACCOUNT, Vec::new());
    let (dialer, board, signer) = open(world);
    let session = sign_in(&board, &signer);
    let m = merger(&session, &signer);
    let rows = dialer.world().rows.len();
    dialer.clear();
    assert_eq!(journal::check(&board, &m, &a(D)), Err(Refusal::PublishedJournal { journal: a(D) }));
    let Err(Refusal::Halt(Halt::Halt(face))) = journal::check(&board, &m, &a(o)) else { panic!("another account's draft is a halt") };
    assert_eq!(face.state, format!("the journal {o} is another account's, so the merge cannot land"));
    assert_eq!(journal::check(&board, &m, &a(g)), Ok(()));
    assert_eq!(dialer.ops(), ["doc_metadata"; 3], "one read of each journal and nothing else");
    assert_eq!(dialer.world().rows.len(), rows, "nothing committed");
}

/// A named journal that refuses the atom leaves the member standing.
///
/// Where the record is the call's first write — a `resume` after the
/// shot's acknowledgment was lost, or `record_published` — no journal is
/// checked before it, so a journal named that is published (`D`, the
/// trunk) or another account's draft this merger may read (`O`) passes
/// the extent read and is refused at the atom's insert,
/// `published_target` or `not_owner`: faced as the merge standing at the
/// member with its record unwritten, exit 3 and never this library's
/// fault, no link sent and nothing committed. The account's own journal
/// is read before the library takes it: a published document its first
/// record's link points into is passed over, a private journal minted,
/// and the record goes into that, once.
#[test]
fn a_named_journal_that_refuses_the_atom_leaves_the_member_standing() {
    let (o, p) = ("1.0.2.0.68", "1.0.1.0.70");
    let mut world = World::race();
    world.doc(o, false, "1.0.2", Vec::new());
    let (dialer, board, signer) = open(world);
    let session = sign_in(&board, &signer);
    let merged = compose(&board, Some(session.token()), &race_inputs()).expect("composed");
    let shot_into = |journal: Option<&str>| Landing::Shot { merger: merger(&session, &signer), draft: None, answers: Answers::default(), journal: journal.map(a) };
    dialer.world().drop_acks = 2;
    let lost = land(&board, &merged, shot_into(None));
    assert!(matches!(lost, Err(Refusal::Halt(Halt::Dial(_)))), "the ack lost: {lost:?}");
    let member = a(&format!("{D}.3"));
    let at = dialer.world().rows.iter().find(|r| r.docs[0] == member.to_string()).expect("the shot's row").at;
    let rows = dialer.world().rows.len();
    for (journal, why, code) in [(D, "is published", "published_target"), (o, "is another account's", "not_owner")] {
        for call in ["resume", "record_published"] {
            dialer.clear();
            let err = match call {
                "resume" => resume(&board, &merged, shot_into(Some(journal))).map(drop),
                _ => record_published(&board, &merged, merger(&session, &signer), &member, at, Some(&a(journal)), &[]).map(drop),
            }
            .expect_err(code);
            let Refusal::Halt(halt) = &err else { panic!("{call}: {journal}: {err:?}") };
            assert_eq!(halt.exit_code(), 3, "{call}: {journal}: {err:?}");
            let Halt::Halt(face) = halt else { panic!("{call}: {journal}: {err:?}") };
            assert_eq!(face.state, format!("the merge stands at {member}, and its record is not written: the journal {journal} {why}"), "{call}");
            assert!(face.cause.starts_with(&format!("{code}: the board refused the record's atom into {journal}")), "{call}: {face}");
            assert!(face.act.contains("with a journal this account can write") && !face.act.contains("fault in this library"), "{call}: {face}");
            assert_eq!(dialer.frames("insert").len(), 1, "{call}: {journal}: the atom sent once: {:?}", dialer.ops());
            assert!(dialer.frames("make_link").is_empty(), "{call}: {journal}: no link: {:?}", dialer.ops());
            assert_eq!(dialer.world().rows.len(), rows, "{call}: {journal}: nothing committed");
        }
    }
    // The account's own journal is read before it is taken: a published
    // document its first link of the kind from doc 1 points into is
    // passed over, and a private journal minted takes the record, once.
    {
        let mut w = dialer.world();
        w.doc(p, true, ACCOUNT, Vec::new());
        file(&mut w, p, &merged.record, &["1.0.1.0.67"], None);
    }
    dialer.clear();
    let resumed = resume(&board, &merged, shot_into(None)).expect("resumed, never the library's own fault");
    assert!(matches!(&resumed, Some(Landed::Member { address, .. }) if *address == member), "{resumed:?}");
    assert_eq!(dialer.frames("doc_metadata").into_iter().filter(|f| f["doc"] == p).count(), 1, "the published journal read once and passed over: {:?}", dialer.ops());
    let minted = dialer.frames("create_new_document");
    assert_eq!(minted.len(), 1, "the account's own journal minted: {:?}", dialer.ops());
    assert_eq!(minted[0]["published"], json!(false), "minted private");
    let inserts = dialer.frames("insert");
    assert_eq!((inserts.len(), dialer.frames("make_link").len()), (1, 1), "the record, once: {:?}", dialer.ops());
    assert_ne!(inserts[0]["doc"], json!(p), "no record into the published document");
    assert!(dialer.frames("publish").is_empty(), "nothing landed twice");
}

/// A LANDING WRITE's ID IS ITS STEM AND ITS FRAME (skep #792): the stem
/// is `merge:` and the SHA-256 of the text naming the write in lowercase
/// hex — the empty text's the digest every SHA-256 gives it — 70 bytes
/// for ten bytes of text or ten thousand; one text gives one stem, and
/// another text another.
#[test]
fn a_landing_writes_stem_is_the_digest_of_its_text_at_one_width() {
    assert_eq!(
        Stem::of("").id("publish"),
        "merge:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855.publish"
    );
    let width = |text: &str| Stem::of(text).id("stage").len();
    assert_eq!((width("0123456789"), width(&"0123456789".repeat(1000))), (76, 76));
    let key = format!("merge:{D}:{D}.1:{D}.2+{D}.1.1");
    assert_eq!(Stem::of(&key).id("draft"), Stem::of(&key.clone()).id("draft"));
    assert_ne!(Stem::of(&key).id("draft"), Stem::of(&format!("{key}@11")).id("draft"));
}

/// A MERGE OF MANY SIDES LANDS IN EVERY ARM (skep #792). The head and
/// sixteen daughters of the base, each removing " sat", spell a record
/// key whose text alone passes the 256-byte id cap the scripted board
/// holds every frame to, as skepd's parse does — an id one byte past it
/// refused `malformed` with nothing applied, one at it admitted. Every
/// write of every arm carries `merge:`, sixty-four hex digits, a dot and
/// its frame: the shot lands the trunk's next member, a landing into `T`
/// and a fresh one each land M with its record, and a second call over
/// each writes nothing; the fresh draft undone, the fresh arm stages a
/// draft of its own under the id naming the undo's record and the landing
/// taken back.
#[test]
fn a_many_sided_merge_lands_in_every_arm_under_ids_the_wire_admits() {
    // The premise: the cap, held at parse.
    {
        let (dialer, board, signer) = open(World::race());
        let session = sign_in(&board, &signer);
        let stage = |id: String| {
            let frame = json!({"op": "stage", "from": format!("{D}.2"), "id": id});
            match board.op(Some(session.token()), &frame).expect("answered") {
                Answer::Document(v) => v,
                Answer::Closed => panic!("closed"),
            }
        };
        let rows = dialer.world().rows.len();
        let past = stage("k".repeat(MAX_REQ_ID_BYTES + 1));
        assert_eq!((past["code"].as_str(), past["op"].as_str()), (Some("malformed"), Some("unparseable")), "{past}");
        assert_eq!(dialer.world().rows.len(), rows, "nothing applied");
        assert_eq!(stage("k".repeat(MAX_REQ_ID_BYTES))["resp"].as_str(), Some("ack_addr"));
    }
    let t = "1.0.1.0.67";
    let world = || {
        let mut w = World::race();
        for k in 2..=16 {
            w.member(&format!("{D}.1.{k}"), vec![run(D, 1, 7)], Some(11));
        }
        w.doc(t, false, ACCOUNT, vec![run(D, 1, 11)]);
        w.staged(t, &format!("{D}.1"), 11);
        w
    };
    let sides = (1..=16).map(|k| Side::Member(a(&format!("{D}.1.{k}")))).collect();
    let inputs = Inputs { sides, ..race_inputs() };
    // Every id a landing write sent: its stem, a dot and its frame.
    let fixed_width = |dialer: &Scripted, cell: &str| {
        let mut seen = 0;
        for (op, frame) in [("publish", "publish"), ("stage", "stage"), ("set_arrangement", "draft"), ("insert", "record"), ("make_link", "link")] {
            for f in dialer.frames(op) {
                let id = f["id"].as_str().unwrap_or_else(|| panic!("{cell}: `{op}` carries an id: {f}"));
                let hex = id.strip_prefix("merge:").and_then(|rest| rest.strip_suffix(&format!(".{frame}")));
                assert!(
                    hex.is_some_and(|h| h.len() == 64 && h.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))),
                    "{cell}: {id}"
                );
                seen += 1;
            }
        }
        assert!(seen >= 3, "{cell}: the landing's writes: {:?}", dialer.ops());
    };
    for cell in ["the shot", "into T", "a fresh draft"] {
        let (dialer, board, signer) = open(world());
        let session = sign_in(&board, &signer);
        let merged = compose(&board, Some(session.token()), &inputs).expect("composed");
        let text = merged.key.text();
        assert!(text.len() > MAX_REQ_ID_BYTES, "the premise: the key's text alone passes the cap, {} bytes", text.len());
        let landing = || match cell {
            "the shot" => shot(&session, &signer),
            "into T" => draft_landing(&session, &signer, Some(a(t))),
            _ => draft_landing(&session, &signer, None),
        };
        dialer.clear();
        let landed = land(&board, &merged, landing()).unwrap_or_else(|e| panic!("{cell}: {e}"));
        match (&landed, cell) {
            (Landed::Member { address, .. }, "the shot") => assert_eq!(address.to_string(), format!("{D}.3")),
            (Landed::Draft { into, staged, .. }, "into T") => assert_eq!((into.to_string(), *staged), (t.to_string(), false)),
            (Landed::Draft { staged, .. }, "a fresh draft") => assert_eq!((dialer.frames("stage").len(), *staged), (1, true)),
            other => panic!("{cell}: {other:?}"),
        }
        assert_eq!((dialer.frames("insert").len(), dialer.frames("make_link").len()), (1, 1), "{cell}: the record and its link");
        fixed_width(&dialer, cell);
        let rows = dialer.world().rows.len();
        dialer.clear();
        assert_eq!(land(&board, &merged, landing()).expect("landed again"), as_found(&landed), "{cell}");
        assert_eq!(dialer.world().rows.len(), rows, "{cell}: nothing written twice");
        if let (Landed::Draft { into: f, position: first, .. }, "a fresh draft") = (&landed, cell) {
            let undone = undo(&board, merger(&session, &signer), f, &a(K), None, None).expect("undone").record.expect("the undo's record");
            dialer.clear();
            let relanded = land(&board, &merged, landing()).expect("landed fresh again");
            let Landed::Draft { into: f2, .. } = &relanded else { panic!("{relanded:?}") };
            assert_ne!(f2, f, "a draft of its own");
            assert_eq!(
                dialer.frames("stage")[0]["id"].as_str(),
                Some(landing_id(&format!("{text}@{}~{undone}^{first}", merged.as_of), "stage").as_str()),
                "the stage's id names the undo's record and the latest landing of the merge"
            );
            fixed_width(&dialer, "fresh again");
        }
    }
}
