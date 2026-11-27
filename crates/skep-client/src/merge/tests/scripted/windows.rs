//! The shot's window parts over the scripted board (skep #932).
//!
//! The suite checks a part unanswered refusing the shot with nothing sent,
//! naming it alone or with its pair; each answer — the counterpart by
//! reference, a leave-out, a keep-private — composing its part and nothing
//! else, a counterpart in the trunk's own chain signed by value; answers
//! that fit nothing refused, a part named since its answer refused again at
//! the shot; another account's words asked naming their owner; the answered
//! list found by the read-first, never answered none by a resume, verified,
//! held to the cap and named in the shot's id; a run the draft holds at two
//! places sent at both, the list they cut held to the cap, a part answered
//! by its counterpart at the draft's place; a passage's words returned as
//! text for the embedder to render; and a window origin's records read once,
//! its parts' words together.

use super::*;

/// A shot under no answers; a landing over `answers`.
fn answered<'s>(session: &'s Session<'_>, signer: &'s HybridSigner, answers: Answers) -> Landing<'s> {
    Landing::Shot { merger: merger(session, signer), draft: None, answers, journal: None }
}

/// Returns the landing's refusal's members, panicking on any other
/// outcome.
fn owed(err: Refusal) -> (Vec<WindowPart>, Vec<Misfit>, Vec<WindowPart>) {
    match err {
        Refusal::WindowPartsOwed { parts, misfits, given } => (parts, misfits, given),
        other => panic!("the shot's refusal of its own: {other}"),
    }
}

/// Asserts the walk sent no write: no `publish`, no record.
fn nothing_sent(dialer: &Scripted) {
    let ops = dialer.ops();
    assert!(!ops.iter().any(|o| ["publish", "insert", "make_link", "create_new_document"].contains(&o.as_str())), "nothing sent: {ops:?}");
}

/// A part no record names, unanswered, refuses the shot with nothing
/// sent, the refusal naming the part: its first words and those before
/// it in the merged text, the origin (the merger's own, so no owner),
/// the published side showing the placeholder (the head, which windows
/// `O`, and not the daughter, which does not), and the answers the part
/// admits — the landing composes no answer the caller did not give.
#[test]
fn a_part_no_record_names_unanswered_refuses_the_shot_naming_it_and_sends_nothing() {
    let (dialer, board, signer) = open(World::windowed());
    let session = sign_in(&board, &signer);
    let merged = compose(&board, Some(session.token()), &race_inputs()).expect("composed");
    dialer.clear();
    let err = land(&board, &merged, shot(&session, &signer)).expect_err("owed");
    let (parts, misfits, given) = owed(err);
    assert_eq!((misfits, given), (Vec::new(), Vec::new()));
    assert_eq!(parts.len(), 1, "{parts:?}");
    let part = &parts[0];
    assert_eq!((part.words.as_deref(), part.after.as_deref(), part.ordinal), (Some("hello"), Some("the"), 5));
    assert_eq!((part.origin.to_string(), part.owner.clone()), (O.to_string(), None), "the merger's own: no owner said");
    assert_eq!((part.record.clone(), part.counterpart.clone(), part.version.clone()), (None, None, None));
    assert_eq!(part.sides, vec![a(&format!("{D}.2"))], "the head shows the placeholder");
    assert_eq!(part.admits, vec![OriginAnswer::PublishFirst, OriginAnswer::Drop, OriginAnswer::KeepPrivate]);
    assert!(part.answer.is_none() && !part.named_since);
    nothing_sent(&dialer);
}

/// A part a record names refuses the same, naming the pair: the
/// counterpart's span and ⟨E.j⟩, the member the record's commit minted,
/// read off the feed, and the two answers a named part admits.
#[test]
fn a_part_a_record_names_unanswered_refuses_naming_its_pair_and_sends_nothing() {
    let mut world = World::windowed();
    let record = world.record_of_o(1, 5, 40);
    let (dialer, board, signer) = open(world);
    let session = sign_in(&board, &signer);
    let merged = compose(&board, Some(session.token()), &race_inputs()).expect("composed");
    dialer.clear();
    let err = land(&board, &merged, shot(&session, &signer)).expect_err("owed");
    let (parts, misfits, _) = owed(err);
    assert!(misfits.is_empty(), "{misfits:?}");
    let part = &parts[0];
    assert_eq!(part.record.as_ref().map(ToString::to_string), Some(record));
    assert_eq!(part.counterpart.as_ref().map(|c| (c.chain.clone(), c.first, c.width)), Some((format!("{E}.0.1"), 3, 5)));
    assert_eq!(part.version.as_ref().map(ToString::to_string), Some(format!("{E}.2")), "the member its commit minted");
    assert_eq!(part.admits, vec![OriginAnswer::Counterpart, OriginAnswer::Drop], "no placeholder over published words");
    nothing_sent(&dialer);
}

/// `--window ⟨E.j⟩` publishes the counterpart by reference: the frame
/// names the published words where the window stood, by address — a
/// window onto another document, signed by address — no place beside
/// it, the record carrying the answer; and the member lands. The same
/// shot's composition is the core's ([`compose_part`](crate::publication::compose_part)).
#[test]
fn a_window_answer_publishes_the_counterpart_by_reference() {
    let mut world = World::windowed();
    let record = world.record_of_o(1, 5, 40);
    let (dialer, board, signer) = open(world.whole_form_due());
    let session = sign_in(&board, &signer);
    let merged = compose(&board, Some(session.token()), &race_inputs()).expect("composed");
    dialer.clear();
    let landed = land(&board, &merged, answered(&session, &signer, Answers { window: vec![a(&format!("{E}.2"))], ..Answers::default() })).expect("landed");
    let frame = &dialer.frames("publish")[0];
    let runs: Vec<(String, String, String)> = frame["runs"].as_array().unwrap().iter().map(|r| (r["origin"].as_str().unwrap().into(), r["i_start"].as_str().unwrap().into(), r["width"].as_str().unwrap().into())).collect();
    assert_eq!(runs, [(D.into(), format!("{D}.0.1.1"), "4".into()), (E.into(), format!("{E}.0.1.3"), "5".into()), (D.into(), format!("{D}.0.1.5"), "3".into())]);
    assert!(frame["places"].is_null(), "no place beside the part: {frame}");
    let Landed::Member { answers, record: record_link, .. } = &landed else { panic!("{landed:?}") };
    assert_eq!(answers.len(), 1, "{answers:?}");
    assert_eq!((answers[0].answer, answers[0].words.as_deref()), (Some(OriginAnswer::Counterpart), Some("hello")));
    assert_eq!(answers[0].record.as_ref().map(ToString::to_string), Some(record));
    let appended = serde_json::from_str::<Value>(dialer.frames("insert")[0]["values"][0]["atom"].as_str().unwrap()).unwrap();
    assert_eq!(appended["answers"], json!([{"from": {"i_start": format!("{O}.0.1.1"), "width": "5"}, "answer": "window", "to": {"i_start": format!("{E}.0.1.3"), "width": "5"}}]), "{appended}");
    let _ = record_link;
}

/// `--leave-out ⟨E.j⟩` publishes without the words; `--keep-private` on
/// an unnamed part keeps the window — no answer composed for the part
/// beside it.
#[test]
fn a_leave_out_and_a_keep_private_compose_their_parts_and_nothing_else() {
    let mut world = World::windowed();
    world.record_of_o(1, 5, 40);
    let (dialer, board, signer) = open(world.whole_form_due());
    let session = sign_in(&board, &signer);
    let merged = compose(&board, Some(session.token()), &race_inputs()).expect("composed");
    dialer.clear();
    let landed = land(&board, &merged, answered(&session, &signer, Answers { leave_out: vec![a(&format!("{E}.2"))], ..Answers::default() })).expect("landed");
    let runs = dialer.frames("publish")[0]["runs"].clone();
    assert_eq!(runs.as_array().unwrap().len(), 2, "the part left out: {runs}");
    assert_eq!(dialer.world().docs.get(&format!("{D}.3")).unwrap().runs, vec![run(D, 1, 7)], "the member holds no window");
    let Landed::Member { answers, .. } = &landed else { panic!("{landed:?}") };
    assert_eq!(answers[0].answer, Some(OriginAnswer::Drop));

    let (dialer, board, signer) = open(World::windowed().whole_form_due());
    let session = sign_in(&board, &signer);
    let merged = compose(&board, Some(session.token()), &race_inputs()).expect("composed");
    dialer.clear();
    land(&board, &merged, answered(&session, &signer, Answers { keep_private: vec![a(O)], ..Answers::default() })).expect("landed");
    let frame = &dialer.frames("publish")[0];
    assert_eq!(frame["runs"][1]["i_start"], format!("{O}.0.1.1"), "the window itself: {frame}");
    assert!(frame["places"].is_null(), "a window with no place: {frame}");
    let atom = serde_json::from_str::<Value>(dialer.frames("insert")[0]["values"][0]["atom"].as_str().unwrap()).unwrap();
    assert_eq!(atom["answers"][0]["answer"], "keep_private", "{atom}");
}

/// A counterpart in the trunk's own chain is the document's own
/// words: signed by value, read through the window's own span, since no
/// side's image holds the published words — never a window onto the
/// document itself. The draft side here keeps the body the plain shot's,
/// its attest verifying over the values alone.
#[test]
fn a_counterpart_in_the_trunks_own_chain_is_signed_by_value_through_the_windows_span() {
    let mut world = World::windowed();
    world.text(D, 20, "hello");
    world.text(S, 1, "!!!");
    world.doc(S, false, ACCOUNT, vec![run(D, 1, 11), run(S, 1, 3)]);
    world.staged(S, &format!("{D}.1"), 11);
    world.position += 1;
    let at = world.position;
    world.docs.get_mut(S).unwrap().history.insert(at, vec![run(D, 1, 11), run(S, 1, 3)]);
    world.links.push(LinkRow { addr: format!("{O}.0.2.1"), home: O.to_string(), from: vec![format!("{O}.0.1.1")], to: vec![format!("{D}.0.1.20")], ty: crate::board::frames::T_CORRESPONDENCE.to_string(), width: 5, at: Some(40) });
    world.rows.push(FeedRow { at: 40, op: "publish", docs: vec![format!("{D}.1")], terms: None });
    let (dialer, board, signer) = open(world.whole_form_due());
    let session = sign_in(&board, &signer);
    let inputs = Inputs { sides: vec![Side::Draft { at: a(S), position: None }], base: Some(a(&format!("{D}.1"))), ..race_inputs() };
    let merged = compose(&board, Some(session.token()), &inputs).expect("composed");
    dialer.clear();
    land(&board, &merged, answered(&session, &signer, Answers { window: vec![a(&format!("{D}.1"))], ..Answers::default() })).expect("landed");
    let frame = &dialer.frames("publish")[0];
    assert_eq!(frame["runs"][1], json!({"origin": D, "i_start": format!("{D}.0.1.20"), "width": "5"}), "{frame}");
    // The values were read through the window's own span in the head.
    let reads: Vec<(String, u64, u64)> = dialer.frames("retrieve_v").iter().filter(|f| f["specs"][0]["doc"] != HEAD_MEMBER_1).map(|f| {
        let (from, width) = span(&f["specs"][0]["span"]);
        (f["specs"][0]["doc"].as_str().unwrap().to_string(), from, width)
    }).collect();
    assert!(reads.contains(&(format!("{D}.2"), 5, 5)), "read through the window's span in the head: {reads:?}");
    // Every position by value, the draft side's and the counterpart's.
    let values: Vec<[u8; 1]> = b"the hellocat sat!!!".iter().map(|b| [*b]).collect();
    let pieces: Vec<ShotSegmentPiece<'_>> = values.iter().map(|v| ShotSegmentPiece::Value(v)).collect();
    let head = a(&format!("{D}.2"));
    let body = entry_body_publish(pieces, Some(ShotBase { member: &head, extent: merged.head_extent }));
    let term = board.board_term().unwrap().unwrap();
    let alg = Signer::public_key(&signer).alg();
    let sig = crate::hex::decode(frame["attest"]["sig"].as_str().unwrap()).unwrap();
    let expected = entry_frame(alg, term, &a(ACCOUNT), DocTerm::One(&a(D)), &body);
    assert_eq!(skep_signature::verify(Signer::tag(&signer), Signer::public_key(&signer), &expected, &sig), Ok(()), "the attest signs the counterpart's words by value");
}

/// Answers that fit nothing are refused with nothing sent: a version
/// that publishes no word here, an origin answered keep-private whose
/// words are published (named in its line), a key this merge asks
/// nothing about, and two answers for one part.
#[test]
fn an_answer_that_fits_nothing_or_two_answers_for_one_part_are_refused() {
    let check = |answers: Answers, named: bool, expect: Vec<Misfit>| {
        let mut world = World::windowed();
        if named {
            world.record_of_o(1, 5, 40);
        }
        let (dialer, board, signer) = open(world);
        let session = sign_in(&board, &signer);
        let merged = compose(&board, Some(session.token()), &race_inputs()).expect("composed");
        dialer.clear();
        let err = land(&board, &merged, answered(&session, &signer, answers)).expect_err("refused");
        let (_, misfits, _) = owed(err);
        assert_eq!(misfits, expect);
        nothing_sent(&dialer);
    };
    let other = a("1.0.1.0.99.1");
    check(Answers { window: vec![other.clone()], ..Answers::default() }, false, vec![Misfit::FitsNothing { flag: Flag::Window, key: other.clone(), published_in: vec![] }]);
    check(Answers { keep_private: vec![a(O)], ..Answers::default() }, true, vec![Misfit::FitsNothing { flag: Flag::KeepPrivate, key: a(O), published_in: vec![a(&format!("{E}.2"))] }]);
    check(Answers { leave_out: vec![a(Z)], ..Answers::default() }, false, vec![Misfit::FitsNothing { flag: Flag::LeaveOut, key: a(Z), published_in: vec![] }]);
    check(Answers { keep_private: vec![a(O)], leave_out: vec![a(O)], ..Answers::default() }, false, vec![Misfit::TwoAnswers { first: Flag::KeepPrivate, second: Flag::LeaveOut, key: a(O) }]);
    let version = a(&format!("{E}.2"));
    check(Answers { window: vec![version.clone()], leave_out: vec![version.clone()], ..Answers::default() }, true, vec![Misfit::TwoAnswers { first: Flag::Window, second: Flag::LeaveOut, key: version }]);
}

/// A part a record names after the step's reads is refused again just
/// before the send, nothing published (PUB-3.108): keep-private does not
/// carry onto words published since, a leave-out does.
#[test]
fn a_part_named_since_its_answer_is_refused_again_at_the_shot_and_a_leave_out_stands() {
    let (link, row) = o_record(1, 5, 40);
    let (dialer, board, signer) = open(World::windowed());
    let session = sign_in(&board, &signer);
    let merged = compose(&board, Some(session.token()), &race_inputs()).expect("composed");
    dialer.clear();
    dialer.world().link_before = Some((2, link.clone(), row.clone()));
    let err = land(&board, &merged, answered(&session, &signer, Answers { keep_private: vec![a(O)], ..Answers::default() })).expect_err("named since");
    let (parts, _, given) = owed(err);
    assert_eq!(parts.len(), 1, "{parts:?}");
    assert!(parts[0].named_since, "{:?}", parts[0]);
    assert_eq!(parts[0].version.as_ref().map(ToString::to_string), Some(format!("{E}.2")));
    assert_eq!(given.len(), 1, "the answer that stood: {given:?}");
    nothing_sent(&dialer);

    let (dialer, board, signer) = open(World::windowed());
    let session = sign_in(&board, &signer);
    let merged = compose(&board, Some(session.token()), &race_inputs()).expect("composed");
    dialer.clear();
    dialer.world().link_before = Some((2, link, row));
    land(&board, &merged, answered(&session, &signer, Answers { leave_out: vec![a(O)], ..Answers::default() })).expect("the leave-out carries");
    assert_eq!(dialer.frames("publish").len(), 1, "sent");
}

/// A fork's words that readers cannot read are asked, naming the owner,
/// with the answers the part admits — never publish-first — and
/// `--keep-private ⟨F⟩` publishes the placeholder knowingly; a withheld
/// origin is asked with no words and no records read.
#[test]
fn another_accounts_words_are_asked_naming_their_owner_and_withheld_ones_with_no_reads() {
    let f2 = "1.0.2.0.70";
    let fork_world = || {
        let mut w = World::race();
        w.text(f2, 1, "fat ");
        w.fork(f2, "1.0.2", &format!("{D}.1"), vec![run(D, 1, 4), run(f2, 1, 4), run(D, 5, 7)]);
        w
    };
    let (dialer, board, signer) = open(fork_world().whole_form_due());
    let session = sign_in(&board, &signer);
    let inputs = Inputs { sides: vec![Side::Fork(a(f2))], ..race_inputs() };
    let merged = compose(&board, Some(session.token()), &inputs).expect("composed");
    dialer.clear();
    let err = land(&board, &merged, shot(&session, &signer)).expect_err("asked");
    let (parts, _, _) = owed(err);
    assert_eq!((parts[0].words.as_deref(), parts[0].owner.as_deref(), parts[0].origin.to_string()), (Some("fat"), Some("1.0.2"), f2.to_string()));
    assert_eq!(parts[0].admits, vec![OriginAnswer::Drop, OriginAnswer::KeepPrivate], "not the merger's to publish");
    assert!(parts[0].sides.is_empty(), "no published version shows the fork's words");
    nothing_sent(&dialer);
    land(&board, &merged, answered(&session, &signer, Answers { keep_private: vec![a(f2)], ..Answers::default() })).expect("the placeholder, knowingly");
    assert_eq!(dialer.frames("publish")[0]["runs"][2]["origin"], f2, "the fork's words as a window");

    // A document this merger may not read: asked with no words and no
    // records read; M holds its words only as the head's window.
    let private = "1.0.2.0.71";
    let mut world = World::new();
    world.text(D, 1, "the cat sat");
    world.text(private, 1, "hidden");
    world.doc(private, false, "1.0.2", vec![run(private, 1, 6)]);
    let head = vec![run(D, 1, 4), run(private, 1, 6), run(D, 5, 7)];
    world.doc(D, true, ACCOUNT, head.clone());
    world.member(&format!("{D}.1"), vec![run(D, 1, 11)], None);
    world.member(&format!("{D}.2"), head, Some(11));
    world.member(&format!("{D}.1.1"), vec![run(D, 1, 7)], Some(11));
    world.trunk_head.insert(D.to_string(), format!("{D}.2"));
    world.withheld.insert(private.to_string());
    let (dialer, board, signer) = open(world);
    let session = sign_in(&board, &signer);
    let merged = compose(&board, Some(session.token()), &race_inputs()).expect("composed");
    dialer.clear();
    let err = land(&board, &merged, shot(&session, &signer)).expect_err("asked");
    let (parts, _, _) = owed(err);
    let part = parts.iter().find(|p| p.origin.to_string() == private).expect("the withheld origin is asked");
    assert_eq!((part.words.as_deref(), part.owner.as_deref(), part.record.clone()), (None, Some("1.0.2"), None));
    assert!(!dialer.frames("find_links_ftt").iter().any(|f| f["q"]["home"][0]["start"] == private), "no records read of a withheld origin");
    nothing_sent(&dialer);
}

/// A lost acknowledgment is found by the read-first in the answered
/// list, so a re-run in a new session lands no second member (the
/// answered list, never the unanswered M, is what the member holds).
#[test]
fn a_landing_lost_past_its_ack_is_found_by_the_answered_list_and_lands_no_second_member() {
    let mut world = World::windowed();
    world.record_of_o(1, 5, 40);
    world.drop_acks = 2;
    let (dialer, board, signer) = open(world);
    let session = sign_in(&board, &signer);
    let merged = compose(&board, Some(session.token()), &race_inputs()).expect("composed");
    dialer.clear();
    let answers = || Answers { window: vec![a(&format!("{E}.2"))], ..Answers::default() };
    let err = land(&board, &merged, answered(&session, &signer, answers())).expect_err("the ack was lost");
    assert!(matches!(err, Refusal::Halt(Halt::Dial(_))), "{err}");
    assert!(dialer.world().docs.contains_key(&format!("{D}.3")), "the write applied");
    dialer.clear();
    let landed = land(&board, &merged, answered(&session, &signer, answers())).expect("found");
    assert!(matches!(&landed, Landed::Member { address, .. } if address.to_string() == format!("{D}.3")), "{landed:?}");
    assert!(dialer.frames("publish").is_empty(), "no second shot: {:?}", dialer.ops());
}

/// A resume naming no answers at a shot with parts owed is the refusal,
/// never "nothing landed" (SP-14): a landing is compared by the list its
/// answers make.
#[test]
fn a_resume_with_parts_owed_refuses_rather_than_answering_none() {
    let (_dialer, board, signer) = open(World::windowed());
    let session = sign_in(&board, &signer);
    let merged = compose(&board, Some(session.token()), &race_inputs()).expect("composed");
    let err = resume(&board, &merged, shot(&session, &signer)).expect_err("owed");
    assert!(matches!(err, Refusal::WindowPartsOwed { .. }), "{err}");
}

/// A landed shot with answers verifies `Equal` (the answers applied to
/// M), and a record that dropped them is the one that differs.
#[test]
fn an_answered_shot_verifies_equal_and_differs_without_its_answers() {
    let mut world = World::windowed();
    world.record_of_o(1, 5, 40);
    let (_dialer, board, signer) = open(world);
    let session = sign_in(&board, &signer);
    let merged = compose(&board, Some(session.token()), &race_inputs()).expect("composed");
    land(&board, &merged, answered(&session, &signer, Answers { window: vec![a(&format!("{E}.2"))], ..Answers::default() })).expect("landed");
    let record = current(&board, Some(session.token()), &merged.inputs.kind, &merged.key).expect("the lookup").expect("a record");
    assert_eq!(record.answers.len(), 1, "the answer kept: {record:?}");
    assert_eq!(verify(&board, Some(session.token()), &record), Ok(Verdict::Equal));
    let mut bare = record.clone();
    bare.answers.clear();
    assert!(matches!(verify(&board, Some(session.token()), &bare), Ok(Verdict::Differs { .. })), "the answer is what makes it Equal");
}

/// The answered list past the run cap is refused with the count before
/// any frame: answers can cut a run into more runs than M held.
#[test]
fn an_answered_list_past_the_cap_is_refused_with_its_count() {
    let mut world = World::windowed();
    world.record_of_o(1, 2, 40);
    let (dialer, board, signer) = open(world.whole_form_due());
    let session = sign_in(&board, &signer);
    let mut merged = compose(&board, Some(session.token()), &race_inputs()).expect("composed");
    merged.cap = merged.composed.counts.m;
    dialer.clear();
    let err = land(&board, &merged, answered(&session, &signer, Answers { window: vec![a(&format!("{E}.2"))], keep_private: vec![a(O)], ..Answers::default() })).expect_err("over");
    assert_eq!(err, Refusal::OverCap { runs: 4, cap: 3 });
    nothing_sent(&dialer);
}

/// The shot's id names its answers: the same composition with other
/// answers is a write of its own, never met by the first's memo; with
/// no window part it is the key's text alone.
#[test]
fn the_shots_id_names_its_answers_where_any_was_given() {
    let mut world = World::windowed();
    world.record_of_o(1, 5, 40);
    let (dialer, board, signer) = open(world);
    let session = sign_in(&board, &signer);
    let merged = compose(&board, Some(session.token()), &race_inputs()).expect("composed");
    dialer.clear();
    land(&board, &merged, answered(&session, &signer, Answers { window: vec![a(&format!("{E}.2"))], ..Answers::default() })).expect("landed");
    let id = dialer.frames("publish")[0]["id"].as_str().unwrap().to_string();
    assert_ne!(id, landing_id(&merged.key.text(), "publish"), "the key's text alone is every other shot's");
}

/// The `X abc Y def` shape: the draft `S`, staged from the base `D.1`
/// "abcdef", with `X` typed before "abc" and `Y` typed after it — `S·1`
/// and `S·2`, I-adjacent — and the head `D.2` having removed "abc". M
/// coalesces the two typed words into one run the draft holds at two
/// places.
fn cut_by_the_draft_world() -> World {
    let mut w = World::new();
    w.text(D, 1, "abcdef");
    w.text(S, 1, "XY");
    let head = vec![run(D, 4, 3)];
    w.doc(D, true, ACCOUNT, head.clone());
    w.member(&format!("{D}.1"), vec![run(D, 1, 6)], None);
    w.member(&format!("{D}.2"), head, Some(6));
    w.trunk_head.insert(D.to_string(), format!("{D}.2"));
    let draft = vec![run(S, 1, 1), run(D, 1, 3), run(S, 2, 1), run(D, 4, 3)];
    w.doc(S, false, ACCOUNT, draft.clone());
    w.staged(S, &format!("{D}.1"), 6);
    w.position += 1;
    let at = w.position;
    w.docs.get_mut(S).unwrap().history.insert(at, draft);
    w
}

/// One run of M the draft holds at two places goes out as two runs, each
/// beside its own place: the board checks a place against the whole
/// entry beside it (`kept_place_moved`), so one place beside the coalesced
/// run would refuse a merge the draft has done nothing to.
#[test]
fn a_run_of_m_the_draft_holds_at_two_places_is_sent_as_two_at_their_places() {
    let (dialer, board, signer) = open(cut_by_the_draft_world().whole_form_due());
    let session = sign_in(&board, &signer);
    let merged = compose(&board, Some(session.token()), &draft_inputs()).expect("composed");
    assert_eq!(
        m_runs(&merged),
        vec![run(S, 1, 2), run(D, 4, 3)],
        "the premise: M coalesced the two typed words"
    );
    dialer.clear();
    land(&board, &merged, shot(&session, &signer)).expect("landed");
    let frame = &dialer.frames("publish")[0];
    assert_eq!(
        frame["runs"],
        json!([
            {"origin": S, "i_start": format!("{S}.0.1.1"), "width": "1"},
            {"origin": S, "i_start": format!("{S}.0.1.2"), "width": "1"},
            {"origin": D, "i_start": format!("{D}.0.1.4"), "width": "3"},
        ]),
        "{frame}"
    );
    assert_eq!(
        frame["places"],
        json!([{"subspace": "1", "ordinal": "1"}, {"subspace": "1", "ordinal": "5"}, null]),
        "{frame}"
    );
    assert_eq!(frame["draft"].as_str(), Some(S), "{frame}");
}

/// The list a draft's places cut is held to the shot's run cap too,
/// refused with its count before the head is read or anything sent.
#[test]
fn a_list_the_kept_places_cut_past_the_cap_is_refused_before_anything_is_sent() {
    let (dialer, board, signer) = open(cut_by_the_draft_world().whole_form_due());
    let session = sign_in(&board, &signer);
    let mut merged = compose(&board, Some(session.token()), &draft_inputs()).expect("composed");
    merged.cap = merged.composed.counts.m;
    dialer.clear();
    let err = land(&board, &merged, shot(&session, &signer)).expect_err("over");
    assert_eq!(err, Refusal::OverCap { runs: 3, cap: 2 });
    nothing_sent(&dialer);
    assert!(
        dialer.frames("retrieve_v").iter().all(|f| f["specs"][0]["doc"] != HEAD_MEMBER_1),
        "the head was not read: {:?}",
        dialer.ops()
    );
}

/// The draft's own window onto its private origin `O`: "hello" between
/// the base's words, and "!!!" typed at its end, the head unchanged.
fn window_in_the_draft_world() -> World {
    let mut w = World::new();
    w.text(D, 1, "the cat sat");
    w.text(O, 1, "hello");
    w.text(E, 1, "xxhello world");
    w.text(S, 1, "!!!");
    w.doc(O, false, ACCOUNT, vec![run(O, 1, 5)]);
    w.doc(E, true, ACCOUNT, vec![run(E, 1, 13)]);
    let head = vec![run(D, 1, 11)];
    w.doc(D, true, ACCOUNT, head.clone());
    w.member(&format!("{D}.1"), head.clone(), None);
    w.member(&format!("{D}.2"), head, Some(11));
    w.trunk_head.insert(D.to_string(), format!("{D}.2"));
    let draft = vec![run(D, 1, 4), run(O, 1, 5), run(D, 5, 7), run(S, 1, 3)];
    w.doc(S, false, ACCOUNT, draft.clone());
    w.staged(S, &format!("{D}.1"), 11);
    w.position += 1;
    let at = w.position;
    w.docs.get_mut(S).unwrap().history.insert(at, draft);
    w
}

/// A part the draft holds as a window, answered by its counterpart,
/// takes the draft's place of the window — the commit re-windows the
/// draft there through the record; a part kept private takes none, the
/// words staying the window it was, and the draft's own words take theirs.
#[test]
fn a_part_answered_by_its_counterpart_takes_the_drafts_place_and_a_kept_private_one_none() {
    let mut world = window_in_the_draft_world();
    world.record_of_o(1, 5, 40);
    let (dialer, board, signer) = open(world.whole_form_due());
    let session = sign_in(&board, &signer);
    let merged = compose(&board, Some(session.token()), &draft_inputs()).expect("composed");
    dialer.clear();
    land(
        &board,
        &merged,
        answered(
            &session,
            &signer,
            Answers { window: vec![a(&format!("{E}.2"))], ..Answers::default() },
        ),
    )
    .expect("landed");
    let frame = &dialer.frames("publish")[0];
    assert_eq!(
        frame["runs"][1],
        json!({"origin": E, "i_start": format!("{E}.0.1.3"), "width": "5"}),
        "the part by its counterpart: {frame}"
    );
    assert_eq!(
        frame["places"],
        json!([null, {"subspace": "1", "ordinal": "5"}, null, {"subspace": "1", "ordinal": "17"}]),
        "the window's own place in the draft, and the draft's own words': {frame}"
    );

    let (dialer, board, signer) = open(window_in_the_draft_world().whole_form_due());
    let session = sign_in(&board, &signer);
    let merged = compose(&board, Some(session.token()), &draft_inputs()).expect("composed");
    dialer.clear();
    land(
        &board,
        &merged,
        answered(&session, &signer, Answers { keep_private: vec![a(O)], ..Answers::default() }),
    )
    .expect("landed");
    let frame = &dialer.frames("publish")[0];
    assert_eq!(frame["runs"][1]["i_start"], format!("{O}.0.1.1"), "the window itself: {frame}");
    assert_eq!(
        frame["places"],
        json!([null, null, null, {"subspace": "1", "ordinal": "17"}]),
        "no place beside the part kept private: {frame}"
    );
}

/// A word whose control characters could forge a line comes back as
/// plain text; the program renders it (F9's data half, the CLI's
/// `render_inert`) and a preceding unreadable run empties `after`.
#[test]
fn a_passages_words_are_returned_as_text_for_the_embedder_to_render() {
    let mut world = World::windowed();
    world.text(O, 1, "he\nl\x1b");
    let (_dialer, board, signer) = open(world);
    let session = sign_in(&board, &signer);
    let merged = compose(&board, Some(session.token()), &race_inputs()).expect("composed");
    let err = land(&board, &merged, shot(&session, &signer)).expect_err("owed");
    let (parts, ..) = owed(err);
    assert_eq!(parts[0].words.as_deref(), Some("he l\u{1b}"), "the whitespace collapsed and the bytes as text: {parts:?}");
}

/// A WINDOW ORIGIN'S RECORDS ARE READ ONCE AND THE PARTS' WORDS TOGETHER:
/// a fork whose owner wrote p one-byte words into the base at p spots gives
/// M p windows onto it, and a shot answering them `--keep-private ⟨F⟩`
/// reads the fork's records in one find homed in it at the step and one at
/// the re-read before the send, and every part's first words in one
/// `retrieve_i` through the fork, at p = 2 and at p = 6 alike — never a find
/// a window run, nor a read a part. The parts answer each its own word, and
/// the shot sends M as composed, each window kept private. Unanswered, the
/// refusal names each part with its word and the merged text before it,
/// read in one read through each holding side (the mutant reading a run's
/// records alone sends 2p finds; the one reading a part's words alone, p
/// reads).
#[test]
fn a_window_origins_records_are_read_once_and_its_parts_words_together() {
    let f2 = "1.0.2.0.70";
    for p in [2u64, 6] {
        let fork_world = || {
            let mut w = World::new();
            w.text(D, 1, "0123456789x");
            let base = vec![run(D, 1, 11)];
            w.doc(D, true, ACCOUNT, base.clone());
            w.member(&format!("{D}.1"), base.clone(), None);
            w.member(&format!("{D}.2"), base, Some(11));
            w.trunk_head.insert(D.to_string(), format!("{D}.2"));
            let words: String = (0..p).map(|k| char::from(b'A' + k as u8)).collect();
            w.text(f2, 1, &words);
            let mut fork = Vec::new();
            for k in 1..=p {
                fork.extend([run(D, k, 1), run(f2, k, 1)]);
            }
            fork.push(run(D, p + 1, 11 - p));
            w.fork(f2, "1.0.2", &format!("{D}.1"), fork);
            w
        };
        let words: Vec<String> = (0..p).map(|k| char::from(b'A' + k as u8).to_string()).collect();
        let homed_in_f = |dialer: &Scripted| dialer.frames("find_links_ftt").iter().filter(|f| f["q"]["home"][0]["start"] == f2).count();
        let inputs = Inputs {
            sides: vec![Side::Fork(a(f2))],
            ..race_inputs()
        };
        // Answered: the step and the re-read, one find each; the words, one
        // read.
        let (dialer, board, signer) = open(fork_world().whole_form_due());
        let session = sign_in(&board, &signer);
        let merged = compose(&board, Some(session.token()), &inputs).expect("composed");
        assert_eq!(merged.families.iter().filter(|f| **f == Family::Window).count() as u64, p, "the premise: p windows");
        dialer.clear();
        let landed = land(
            &board,
            &merged,
            answered(
                &session,
                &signer,
                Answers {
                    keep_private: vec![a(f2)],
                    ..Answers::default()
                },
            ),
        )
        .expect("landed");
        let Landed::Member { answers, .. } = &landed else { panic!("{landed:?}") };
        assert_eq!(
            (homed_in_f(&dialer), dialer.frames("retrieve_i").len()),
            (2, 1),
            "p = {p}: a find at the step and at the re-read, one read of every part's words: {:?}",
            dialer.ops()
        );
        assert_eq!(
            answers.iter().map(|part| part.words.clone()).collect::<Vec<_>>(),
            words.iter().map(|w| Some(w.clone())).collect::<Vec<_>>(),
            "p = {p}: each part its own word"
        );
        assert_eq!(
            dialer.frames("publish")[0]["runs"],
            json!(shot_runs(&m_runs(&merged))),
            "p = {p}: M as composed, each window kept private"
        );
        // Unanswered: each part's word and the merged text before it.
        let (dialer, board, signer) = open(fork_world().whole_form_due());
        let session = sign_in(&board, &signer);
        let merged = compose(&board, Some(session.token()), &inputs).expect("composed");
        dialer.clear();
        let (parts, _, _) = owed(land(&board, &merged, shot(&session, &signer)).expect_err("asked"));
        let text: String = (1..=p).map(|k| format!("{}{}", k - 1, words[k as usize - 1])).collect();
        assert_eq!(
            parts.iter().map(|part| (part.words.clone(), part.after.clone())).collect::<Vec<_>>(),
            (1..=p as usize).map(|k| (Some(words[k - 1].clone()), Some(text[..2 * k - 1].to_string()))).collect::<Vec<_>>(),
            "p = {p}: each part's word, and the merged text before it"
        );
        assert_eq!(
            (homed_in_f(&dialer), dialer.frames("retrieve_v").len(), dialer.frames("retrieve_i").len()),
            (1, 1, 1),
            "p = {p}: one find, and the words read through the head and the fork once each: {:?}",
            dialer.ops()
        );
        nothing_sent(&dialer);
    }
}
