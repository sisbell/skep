//! The landing over the scripted board: the shot and the draft landing.
//!
//! The suite checks the shot: its frame and body, byte-checked; its values
//! read at the head in parts past the delivery budget, and asked again in
//! halves where a read is too large; the claim's and the record's reads
//! after it; a lost ack completed by `resume`; a daughter reported at
//! once; a shot naming a daughter at a moved head refused whole; the member
//! sides named `supersede`, never a draft side; the record written after
//! the merger's own publication; and the run cap, before any frame. It
//! checks the draft landing: one `set_arrangement` typed at the
//! composition, refused whole after an edit between compose and land, and
//! a race on a draft that is no side; a draft edited while the composition
//! reads it refused, and one edited before read as it stands; a position
//! reclaimed, past the head or inside a commit, and a withheld draft side,
//! each refused or withholding the verdict; a newer head told while the
//! landing stands; a baseless draft sent no base; the fork gate; a side's
//! state and the key's text, a fork arranged or edited since its state
//! answering `SideMoved`, read at a draft side's position, and arranged
//! since its landing another key; what a landing replaces, read at the
//! head and held to the composition's position; the scripted board judging
//! `set_arrangement` as the store does; and a fresh draft staged from the
//! head.

use super::*;

/// THE SHOT and its body, byte-checked: the three families — the
/// document's own runs by reference, a window onto `Z`, a draft side's
/// fresh text — in one frame from the head with `base`, `base_extent`,
/// the `draft` named without asking and `keep_base` beside it, the
/// draft's recorded base standing, the runs in V-order, the id; and
/// the `attest` verifying over the entry frame whose body is the one
/// `entry_body_publish` spells from the same pieces.
#[test]
fn the_shot_frame_and_its_body_are_byte_checked() {
    let (dialer, board, signer) = open(World::window_and_draft());
    let session = sign_in(&board, &signer);
    let inputs = Inputs {
        sides: vec![Side::Draft { at: a(S), position: None }],
        base: Some(a(&format!("{D}.1"))),
        ..race_inputs()
    };
    let merged = compose(&board, Some(session.token()), &inputs).expect("composed");
    dialer.clear();
    let landed = land(&board, &merged, shot(&session, &signer)).expect("landed");
    let Landed::Member { address, position, claims, record, retries, .. } = &landed else {
        panic!("{landed:?}")
    };
    assert_eq!((address.to_string(), *retries, claims.len()), (format!("{D}.3"), 0, 0));
    assert!(
        record.to_string().starts_with("1.0.1.0.72.0.2."),
        "the record's link is homed in the journal minted: {record}"
    );
    let frames = dialer.frames("publish");
    assert_eq!(frames.len(), 1);
    let frame = &frames[0];
    assert_eq!(frame["doc"], D);
    assert_eq!(
        (frame["base"].as_str(), frame["base_extent"].as_str(), frame["draft"].as_str()),
        (Some(format!("{D}.2").as_str()), Some("16"), Some(S))
    );
    assert_eq!(frame["keep_base"], json!(true), "the merge's shot keeps the draft's base (skep #944)");
    assert_eq!(dialer.world().standing(S).0, Some((format!("{D}.1"), 11)), "the draft's base stands at the version it was staged from");
    assert_eq!(frame["id"].as_str(), Some(landing_id(&merged.key.text(), "publish").as_str()));
    let runs: Vec<(String, String, String)> = frame["runs"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| {
            (
                r["origin"].as_str().unwrap().into(),
                r["i_start"].as_str().unwrap().into(),
                r["width"].as_str().unwrap().into(),
            )
        })
        .collect();
    assert_eq!(
        runs,
        [
            (D.into(), format!("{D}.0.1.1"), "4".into()),
            (Z.into(), format!("{Z}.0.1.1"), "5".into()),
            (D.into(), format!("{D}.0.1.5"), "7".into()),
            (S.into(), format!("{S}.0.1.1"), "3".into())
        ]
    );
    // The draft side's own words take its place in the draft, read off
    // its image (the draft arranges "!!!" at 12); the trunk's words and
    // the window take none.
    assert_eq!(
        frame["places"],
        json!([null, null, null, {"subspace": "1", "ordinal": "12"}]),
        "{frame}"
    );
    // The body, hand-built from the same pieces, verifies the attest.
    signs_the_cat_sat(&board, &signer, frame);
    // The values were read at the head through the sides that hold them:
    // D's through the head by its V-ordinals, both stretches in one read;
    // the draft's by the I-addresses its image served.
    assert_eq!(value_reads(&dialer), [vec![(format!("{D}.2"), 1, 4), (format!("{D}.2"), 10, 7)]]);
    assert_eq!(dialer.frames("retrieve_i"), [crate::board::frames::retrieve_i(&[(&format!("{S}.0.1.1"), 3)])]);
    assert!(dialer.ops().iter().all(|o| !o.starts_with("at:")), "nothing read at a position: {:?}", dialer.ops());
    assert_eq!(
        *position,
        dialer
            .world()
            .rows
            .iter()
            .find(|r| r.op == "publish" && r.docs[0] == format!("{D}.3"))
            .unwrap()
            .at
    );
    let member = dialer.world().docs.get(&format!("{D}.3")).unwrap().clone();
    assert_eq!(member.runs, vec![run(D, 1, 4), run(Z, 1, 5), run(D, 5, 10)], "the draft's text re-minted under D at D·12, I-adjacent to D·5–11 and so one run with it");
    assert_eq!((member.placed, member.base_extent), (Some(19), Some(16)));
}

/// Asserts the shot `frame`'s `attest` verifies over the body `pieces`
/// spell, its base the head `D.2` at `extent`.
fn signs(board: &Board, signer: &HybridSigner, frame: &Value, pieces: Vec<ShotSegmentPiece<'_>>, extent: u64) {
    let head = a(&format!("{D}.2"));
    let body = entry_body_publish(pieces, Some(ShotBase { member: &head, extent }));
    let term = board.board_term().unwrap().unwrap();
    let alg = Signer::public_key(signer).alg();
    assert_eq!(frame["attest"]["alg"].as_str(), Some(alg));
    let sig = crate::hex::decode(frame["attest"]["sig"].as_str().unwrap()).unwrap();
    let expected = entry_frame(alg, term, &a(ACCOUNT), DocTerm::One(&a(D)), &body);
    assert_eq!(
        skep_signature::verify(Signer::tag(signer), Signer::public_key(signer), &expected, &sig),
        Ok(()),
        "the attest signs the body the pieces spell"
    );
}

/// Asserts the shot `frame` of the shot's byte-checked shape signs "the
/// cat sat!!!" by value, the window onto `Z`'s "hello" after "the ".
fn signs_the_cat_sat(board: &Board, signer: &HybridSigner, frame: &Value) {
    let window = a(&format!("{Z}.0.1.1"));
    let values: Vec<[u8; 1]> = b"the cat sat!!!".iter().map(|b| [*b]).collect();
    let pieces: Vec<ShotSegmentPiece<'_>> = values[..4]
        .iter()
        .map(|v| ShotSegmentPiece::Value(v))
        .chain(std::iter::once(ShotSegmentPiece::Window {
            start: &window,
            width: std::num::NonZeroU64::new(5).unwrap(),
        }))
        .chain(values[4..].iter().map(|v| ShotSegmentPiece::Value(v)))
        .collect();
    signs(board, signer, frame, pieces, 16);
}

/// The specs of each `retrieve_v` a dialer served but `H.1`'s, as `(doc,
/// from, width)`.
fn value_reads(dialer: &Scripted) -> Vec<Vec<(String, u64, u64)>> {
    dialer
        .frames("retrieve_v")
        .iter()
        .filter(|f| f["specs"][0]["doc"] != HEAD_MEMBER_1)
        .map(|f| {
            f["specs"]
                .as_array()
                .unwrap()
                .iter()
                .map(|spec| {
                    let (from, width) = span(&spec["span"]);
                    (spec["doc"].as_str().unwrap().to_string(), from, width)
                })
                .collect()
        })
        .collect()
}

/// THE SHOT READS EACH HOLDER'S VALUES IN AS FEW READS AS ITS BUDGETS ALLOW
/// (skep #1144): the head's own words, read at the head by its V-ordinals,
/// go out in one `retrieve_v` while they fit the delivery budget and in
/// parts past it — 131,074 positions in two, the first the budget's
/// 131,072 — and the attest signs every value they deliver (the mutant
/// that reads past the budget is refused `too_many_items` whole, and the
/// one that splits a part back to the wrong stretch signs other words).
/// The side is a draft staged from `D.1` that removed the base's last word,
/// "c", which the head keeps, so the merge is no copy of the head's list
/// (P13) while the shot claims no daughter and renders no draft: its body
/// is the values alone.
#[test]
fn the_shot_reads_a_holders_values_in_parts_past_the_delivery_budget() {
    let budget = crate::merge::reads::MAX_DELIVERY_ITEMS;
    let n = budget + 1;
    let mut w = World::new();
    w.text(D, 1, &"a".repeat(n as usize));
    w.text(D, n + 1, "b");
    w.text(D, n + 2, "c");
    let base = vec![run(D, 1, n), run(D, n + 2, 1)];
    let head = vec![run(D, 1, n), run(D, n + 1, 1), run(D, n + 2, 1)];
    w.doc(D, true, ACCOUNT, head.clone());
    w.member(&format!("{D}.1"), base.clone(), None);
    w.member(&format!("{D}.2"), head, Some(n + 1));
    w.trunk_head.insert(D.to_string(), format!("{D}.2"));
    w.doc(S, false, ACCOUNT, vec![run(D, 1, n)]);
    w.staged(S, &format!("{D}.1"), n + 1);
    let (dialer, board, signer) = open(w);
    let session = sign_in(&board, &signer);
    let inputs = Inputs { sides: vec![Side::Draft { at: a(S), position: None }], ..race_inputs() };
    let merged = compose(&board, Some(session.token()), &inputs).expect("composed");
    assert_eq!(m_runs(&merged), vec![run(D, 1, n + 1)], "the premise: the head's words but \"c\", one run");
    dialer.clear();
    land(&board, &merged, shot(&session, &signer)).expect("landed");
    let member = format!("{D}.2");
    assert_eq!(
        value_reads(&dialer),
        [vec![(member.clone(), 1, budget)], vec![(member.clone(), budget + 1, 1), (member, budget + 2, 1)]],
        "the budget's positions, then the rest of the first stretch and the second, at the head"
    );
    let values: Vec<[u8; 1]> = (0..=n).map(|k| [if k < n { b'a' } else { b'b' }]).collect();
    signs(&board, &signer, &dialer.frames("publish")[0], values.iter().map(|v| ShotSegmentPiece::Value(v)).collect(), n + 2);
}

/// A VALUE READ TOO LARGE IS ASKED AGAIN IN HALVES (skep #1144): the shot
/// reads the head's two stretches in one `retrieve_v`. Refused
/// `too_many_items`, it goes again one read a stretch, and a stretch still
/// refused in halves of its width; and where its answer passes the
/// dialer's cap — a composite value's item is as long as the value, so a
/// read within the budget can pass it where each stretch alone fits — it
/// goes again one read a stretch. Each lands, the attest signing the body
/// the whole read would have spelled (the mutant that halves on
/// `too_many_items` alone halts on the dialer's `TooLarge`).
#[test]
fn a_value_read_too_large_is_asked_again_in_halves() {
    let head = format!("{D}.2");
    let whole = vec![(head.clone(), 1, 4), (head.clone(), 10, 7)];
    // The answer the whole read would carry, and each stretch's.
    let answer = |specs: &[(u64, u64)]| World::window_and_draft().op(&crate::board::frames::retrieve_v_of(&head, specs), None).expect("an answer").body.len();
    let (both, first, second) = (answer(&[(1, 4), (10, 7)]), answer(&[(1, 4)]), answer(&[(10, 7)]));
    assert!(first.max(second) < both, "the premise: each stretch's answer is shorter than the whole read's");
    // The shot over a board `refusing` sizes as it does: the value reads it
    // made, the attest checked.
    let landed = |refusing: &dyn Fn(&mut World)| {
        let mut w = World::window_and_draft();
        refusing(&mut w);
        let (dialer, board, signer) = open(w);
        let session = sign_in(&board, &signer);
        let inputs = Inputs { sides: vec![Side::Draft { at: a(S), position: None }], ..race_inputs() };
        let merged = compose(&board, Some(session.token()), &inputs).expect("composed");
        dialer.clear();
        land(&board, &merged, shot(&session, &signer)).expect("landed");
        signs_the_cat_sat(&board, &signer, &dialer.frames("publish")[0]);
        value_reads(&dialer)
    };
    let (first_four, last_seven) = (vec![(head.clone(), 1, 4)], vec![(head.clone(), 10, 7)]);
    assert_eq!(
        landed(&|w| w.delivery_cap = 4),
        [whole.clone(), first_four.clone(), last_seven.clone(), vec![(head.clone(), 10, 3)], vec![(head.clone(), 13, 4)]],
        "too_many_items: one read a stretch, then a stretch in halves"
    );
    assert_eq!(
        landed(&move |w| w.value_answer_cap = Some(both - 1)),
        [whole, first_four, last_seven],
        "past the dialer's cap: one read a stretch"
    );
}

/// WHAT A LANDING REPLACES IS READ AT THE HEAD, HELD TO THE COMPOSITION'S
/// POSITION (skep #1144, F4): `replaced` reads the draft's image at the
/// head between two `doc_metadata` reads, nothing at a position, and
/// answers its stretches where the draft is unchanged since the
/// composition. A draft another hand edits between the two reads refuses
/// `SideMoved` with its two states; one edited after the composition
/// refuses it with `before` and `after` the edit's position, past `at`, its
/// words saying the draft changed after the merge was composed — never that
/// a base moved — as the landing typed against `at` would be refused
/// `arrangement_moved`; and one minted after the composition is
/// `NoSuchDocument`, as it was at that position.
#[test]
fn what_a_landing_replaces_is_read_at_the_head_and_held_to_the_compositions_position() {
    let (dialer, board, signer) = open(draft_landing_world());
    let session = sign_in(&board, &signer);
    let merged = compose(&board, Some(session.token()), &draft_inputs()).expect("composed");
    let p = merged.as_of;
    dialer.clear();
    assert_eq!(replaced(&board, Some(session.token()), &a(S), &merged), Ok(vec![]), "M carries every word S holds");
    assert_eq!(
        dialer.ops(),
        ["doc_metadata", "retrieve_doc_v_span_set", "image", "doc_metadata"],
        "the draft's two reads around its image, at the head"
    );
    // Edited between the two reads: before the fourth frame.
    dialer.clear();
    dialer.world().interleave = Some((4, S.to_string(), vec![run(D, 1, 11)]));
    let edited = p + 1;
    assert_eq!(
        replaced(&board, Some(session.token()), &a(S), &merged),
        Err(Refusal::SideMoved { side: a(S), at: p, before: Some(p), after: Some(edited) })
    );
    // Read again, the draft stands as edited after the composition.
    let refused = replaced(&board, Some(session.token()), &a(S), &merged);
    assert_eq!(refused, Err(Refusal::SideMoved { side: a(S), at: p, before: Some(edited), after: Some(edited) }));
    let said = refused.unwrap_err().to_string();
    assert!(
        said.contains(&format!("{S} changed at position {edited}, after this merge was composed at position {p}"))
            && !said.contains("base")
            && said.contains("nothing was merged"),
        "{said}"
    );
    // Minted after the composition.
    let x = "1.0.1.0.79";
    {
        let mut w = dialer.world();
        let minted = w.commit("create_new_document", vec![x.to_string()]);
        w.doc(x, false, ACCOUNT, Vec::new());
        w.docs.get_mut(x).unwrap().history = BTreeMap::from([(minted, Vec::new())]);
    }
    assert_eq!(replaced(&board, Some(session.token()), &a(x), &merged), Err(Refusal::NoSuchDocument(a(x))));
}

/// After the shot, in order: the claim's read at the daughter (and no
/// `assert_sup` — the scripted board panics on one), the record's read
/// by the links of the kind to the daughter — a record links every side
/// but the head — the journal found by the account's own links of the
/// kind, one `window_ftt` page with `home` the account finding none, then
/// MINTED private, the atom appended as a PLAIN insert at the
/// journal's end, the link homed in the journal beside it, from the atom
/// to the member and the daughter under the kind, unsigned. A second
/// `land` reads each of the three writes standing and writes nothing.
#[test]
fn the_claim_is_read_and_the_record_is_written_after_the_shot_each_read_first() {
    let (dialer, board, signer) = open(World::race());
    let session = sign_in(&board, &signer);
    let merged = compose(&board, Some(session.token()), &race_inputs()).expect("composed");
    dialer.clear();
    let landed = land(&board, &merged, shot(&session, &signer)).expect("landed");
    let Landed::Member { address, position, claims, record, .. } = &landed else {
        panic!("{landed:?}")
    };
    assert_eq!(address.to_string(), format!("{D}.3"));
    let own_claim = a(&format!("{D}.0.2.1"));
    assert_eq!(claims, &vec![own_claim.clone()], "the claim the shot deposited, read back");
    let ops = dialer.ops();
    let after_values: Vec<&str> =
        ops.iter().map(String::as_str).skip_while(|o| *o != "publish").collect();
    assert_eq!(
        after_values,
        [
            "publish",
            "in_claims",
            "find_links_ftt",
            "window_ftt",
            "create_new_document",
            "retrieve_doc_v_span_set",
            "insert",
            "make_link"
        ]
    );
    assert_eq!(ops[0], "doc_metadata", "the shot reads the trunk's next member first: {ops:?}");
    assert_eq!(dialer.frames("doc_metadata")[0]["doc"], format!("{D}.3"));
    assert_eq!(
        dialer.frames("in_claims")[0],
        json!({"op": "in_claims", "view": "active", "y": format!("{D}.1.1")})
    );
    let links = dialer.frames("find_links_ftt");
    assert_eq!(
        links.iter().map(|f| f["q"]["to"][0]["start"].clone()).collect::<Vec<_>>(),
        [json!(format!("{D}.1.1"))],
        "the record's read-first: the links of the kind to the daughter, the side but the head"
    );
    let page = &dialer.frames("window_ftt")[0];
    assert_eq!(
        (
            page["q"]["home"][0]["start"].as_str(),
            page["q"]["to"].as_str(),
            &page["cur"],
            page["n"].as_u64()
        ),
        (Some(ACCOUNT), Some("any"), &Value::Null, Some(1)),
        "the journal's find: the account's own links of the kind, a page of one"
    );
    assert_eq!(
        dialer.frames("create_new_document")[0],
        json!({"op": "create_new_document", "account": ACCOUNT, "published": false, "id": format!("merge.journal:{ACCOUNT}")})
    );
    let insert = &dialer.frames("insert")[0];
    let journal = insert["doc"].as_str().unwrap().to_string();
    assert_eq!(journal, "1.0.1.0.72", "the minted journal");
    assert_eq!((insert["at"]["ordinal"].as_str(), insert.get("deposit")), (Some("1"), None));
    let atom: Value =
        serde_json::from_str(insert["values"][0]["atom"].as_str().unwrap()).unwrap();
    assert_eq!(atom["type"], "merge");
    assert_eq!(atom["landed"], json!({"member": format!("{D}.3"), "position": position}));
    assert_eq!(atom["claims"], json!([own_claim.to_string()]), "the record carries the shot's claim");
    let written = Record::from_value(&atom).expect("a record");
    assert_eq!((written.key(), written.landed.is_some()), (merged.key.clone(), true));
    let link = &dialer.frames("make_link")[0];
    assert_eq!(link["home"], journal, "the link homed in the journal, beside the record");
    assert_eq!(link["from"]["addrs"], json!([format!("{journal}.0.1.1")]));
    assert_eq!(link["to"]["addrs"], json!([format!("{D}.3"), format!("{D}.1.1")]));
    assert_eq!(link["ty"]["addrs"], json!([K]));
    assert!(link.get("attest").is_none(), "a private journal's link is unsigned: {link}");
    assert_eq!(record.to_string(), format!("{journal}.0.2.1"));
    // The claim's read records a claim another writer filed.
    dialer.world().claims.push(ClaimRow {
        claim: format!("{DOC1}.0.2.9"),
        home: DOC1.into(),
        old: format!("{D}.1.1"),
        new: format!("{D}.3"),
    });
    // A second landing: every write standing, nothing written.
    dialer.clear();
    let rows = dialer.world().rows.len();
    let again = land(&board, &merged, shot(&session, &signer)).expect("landed again");
    let Landed::Member { claims, record: again_record, .. } = &again else {
        panic!("{again:?}")
    };
    assert_eq!((claims.clone(), again_record), (vec![own_claim, a(&format!("{DOC1}.0.2.9"))], record));
    assert_eq!(dialer.world().rows.len(), rows, "nothing written twice");
    let ops = dialer.ops();
    assert!(
        !ops.iter()
            .any(|o| ["publish", "insert", "make_link", "create_new_document"]
                .contains(&o.as_str())),
        "{ops:?}"
    );
    assert_eq!(ops.iter().filter(|o| *o == "in_claims").count(), 1);
}

/// THE LOST ACK: the dialer drops the shot's acknowledgment and the one
/// re-ask's under the same id — the write applied once, the memo
/// answering the re-ask — so `land` halts at the transport; `resume`
/// finds the member whose first `placed` positions equal M, with the
/// position it was minted at off its own `doc_metadata` and no walk of the
/// feed, AND THE CLAIM WITH IT — a landed shot carried its claim — and
/// completes the record; a second `resume` writes nothing.
#[test]
fn a_lost_ack_is_completed_by_resume_and_nothing_is_written_twice() {
    let (dialer, board, signer) = open(World::race());
    let session = sign_in(&board, &signer);
    let merged = compose(&board, Some(session.token()), &race_inputs()).expect("composed");
    dialer.clear();
    dialer.world().drop_acks = 2;
    let err = land(&board, &merged, shot(&session, &signer)).expect_err("the ack was lost");
    assert!(matches!(err, Refusal::Halt(Halt::Dial(_))), "{err}");
    let publishes = dialer.frames("publish");
    assert_eq!(publishes.len(), 2, "one re-ask under the same id");
    assert_eq!(publishes[0]["id"], publishes[1]["id"]);
    assert!(dialer.world().docs.contains_key(&format!("{D}.3")), "the write applied once");
    assert_eq!(dialer.world().rows.iter().filter(|r| r.op == "publish").count(), 4);
    assert!(dialer.frames("insert").is_empty() && dialer.frames("make_link").is_empty());
    dialer.clear();
    let resumed = resume(&board, &merged, shot(&session, &signer)).expect("resumed");
    let Some(Landed::Member { address, position, claims, record, .. }) = &resumed else {
        panic!("{resumed:?}")
    };
    assert_eq!(address.to_string(), format!("{D}.3"));
    assert_eq!(claims, &vec![a(&format!("{D}.0.2.1"))], "the claim found with the member");
    assert_eq!(
        *position,
        dialer.world().rows.iter().find(|r| r.docs[0] == format!("{D}.3")).unwrap().at,
        "the position the shot minted the member at"
    );
    let ops = dialer.ops();
    assert!(!ops.iter().any(|o| o == "publish"), "the shot is not re-sent: {ops:?}");
    assert_eq!(ops.iter().filter(|o| *o == "insert").count(), 1);
    assert_eq!(ops.iter().filter(|o| *o == "make_link").count(), 1);
    assert!(
        !ops.iter().any(|o| o.starts_with("GET /changes?")),
        "the member's position off its own doc_metadata, no walk of the feed: {ops:?}"
    );
    dialer.clear();
    let twice = resume(&board, &merged, shot(&session, &signer)).expect("resumed again");
    assert_eq!(
        twice.as_ref().map(|l| match l {
            Landed::Member { record, .. } => record.clone(),
            _ => unreachable!(),
        }),
        Some(record.clone())
    );
    assert!(
        !dialer
            .ops()
            .iter()
            .any(|o| ["publish", "insert", "make_link", "create_new_document"]
                .contains(&o.as_str())),
        "{:?}",
        dialer.ops()
    );
    // Where nothing landed, resume writes nothing and answers none.
    let (dialer, board, signer) = open(World::race());
    let session = sign_in(&board, &signer);
    let merged = compose(&board, Some(session.token()), &race_inputs()).expect("composed");
    dialer.clear();
    assert_eq!(resume(&board, &merged, shot(&session, &signer)), Ok(None));
    assert_eq!(dialer.ops(), ["doc_metadata"]);
}

/// A version found standing answers the position it was minted at.
///
/// The shot lands `D.3` and both its answers are lost; the feed then holds
/// no row of `D.3`'s mint, and a write elsewhere commits past it. `resume`
/// finds `D.3` holding M and answers the position its own `doc_metadata`
/// serves as its `at`, and the record it writes keeps that position — never
/// the reads' highest `as_of`, past the mint, which a run that finds the
/// version would take for a version published now (the mutant that reads
/// the position off the feed alone answers that `as_of`).
#[test]
fn a_version_found_standing_answers_the_position_it_was_minted_at() {
    let (dialer, board, signer) = open(World::race());
    let session = sign_in(&board, &signer);
    let merged = compose(&board, Some(session.token()), &race_inputs()).expect("composed");
    dialer.world().drop_acks = 2;
    land(&board, &merged, shot(&session, &signer)).expect_err("both answers lost");
    let member = format!("{D}.3");
    let minted = {
        let mut w = dialer.world();
        let row = w.rows.iter().position(|r| r.op == "publish" && r.docs[0] == member);
        let minted = w.rows.remove(row.expect("the shot's row")).at;
        // A write elsewhere: the board's position moves past the mint.
        w.position += 1;
        minted
    };
    dialer.clear();
    let resumed = resume(&board, &merged, shot(&session, &signer)).expect("resumed");
    let Some(Landed::Member { address, position, .. }) = &resumed else { panic!("{resumed:?}") };
    assert_eq!(address.to_string(), member);
    assert!(minted < dialer.world().position, "the premise: the board moved past the mint");
    assert_eq!(*position, minted, "the mint, off the member's own doc_metadata");
    assert_eq!(
        appended_record(&dialer)["landed"],
        json!({"member": member, "position": minted}),
        "the record keeps the mint"
    );
}

/// THE HEAD HOLDS THE MERGE (P13): the shot landed and both its answers
/// were lost, so the merger runs the merge again from the head the feed
/// names, `D.3` — the version the shot minted, whose claim already names
/// the daughter. Composed on it, M is `D.3`'s own list and the shot
/// supersedes no daughter left, so the landing is refused naming `D.3`
/// before anything is sent: no `publish`, no record, no `D.4`. The
/// composition the first shot was made from still resumes on its own head,
/// finding `D.3` and writing its record once.
#[test]
fn a_merge_run_again_on_the_head_it_published_is_refused_and_resumes_on_its_own() {
    let (dialer, board, signer) = open(World::race());
    let session = sign_in(&board, &signer);
    let merged = compose(&board, Some(session.token()), &race_inputs()).expect("composed");
    dialer.world().drop_acks = 2;
    let lost = land(&board, &merged, shot(&session, &signer));
    assert!(matches!(lost, Err(Refusal::Halt(Halt::Dial(_)))), "both answers lost: {lost:?}");
    // The run again, in a session of its own: no memo stands.
    dialer.world().memo.clear();
    let head = head_of(&board, Some(session.token()), &a(D)).expect("the feed").expect("a head");
    assert_eq!(head, a(&format!("{D}.3")), "the premise: the head is the version the shot minted");
    let again = compose(&board, Some(session.token()), &Inputs { head: head.clone(), ..race_inputs() })
        .expect("composed again");
    dialer.clear();
    assert_eq!(land(&board, &again, shot(&session, &signer)), Err(Refusal::HeadHolds { head }));
    let ops = dialer.ops();
    assert!(!ops.iter().any(|o| ["publish", "insert", "make_link", "create_new_document"].contains(&o.as_str())), "nothing sent: {ops:?}");
    assert!(!dialer.world().docs.contains_key(&format!("{D}.4")), "no second version");
    dialer.clear();
    let resumed = resume(&board, &merged, shot(&session, &signer)).expect("resumed");
    let Some(Landed::Member { address, .. }) = &resumed else { panic!("{resumed:?}") };
    assert_eq!(address.to_string(), format!("{D}.3"), "the member the first shot minted");
    assert_eq!(dialer.frames("insert").len(), 1, "its record written once: {:?}", dialer.ops());
    assert!(dialer.frames("publish").is_empty(), "no shot: {:?}", dialer.ops());
}

/// A VERSION OF OTHER WORDS IS NO LANDING OF THE MERGE: a draft side's words
/// are re-minted by the shot, so a member's addresses match M's draft-native
/// runs by their widths alone, and the words decide. The merge of `S` lands
/// as `D.3`, "!!!" re-minted, both its answers lost; `resume` finds it, its
/// words `S`'s own. Then the person writes "???" in `S` in their place and
/// runs the merge again on `D.2`, as the command's halt says to: `D.3` holds
/// the same widths and other words, so `resume` answers no landing, `verify`
/// of a record claiming `D.3` for this composition answers `Differs` at the
/// first re-minted word, and `land` publishes "???" from `D.2`, answered as
/// its daughter — never `D.3` reported as this merge's landing with "???"
/// published nowhere. The mutant comparing the addresses alone answers `D.3`
/// at the second `resume`, `Equal` at `verify` and `D.3` at `land`.
#[test]
fn a_version_of_other_words_of_the_draft_sides_widths_is_no_landing_of_the_merge() {
    let (dialer, board, signer) = open(draft_landing_world());
    let session = sign_in(&board, &signer);
    let merged = compose(&board, Some(session.token()), &draft_inputs()).expect("composed");
    dialer.world().drop_acks = 2;
    let lost = land(&board, &merged, shot(&session, &signer));
    assert!(matches!(lost, Err(Refusal::Halt(Halt::Dial(_)))), "both answers lost: {lost:?}");
    let member = a(&format!("{D}.3"));
    let found = resume(&board, &merged, shot(&session, &signer)).expect("resumed");
    assert!(
        matches!(&found, Some(Landed::Member { address, .. }) if *address == member),
        "{found:?}"
    );
    {
        let mut w = dialer.world();
        w.text(S, 4, "???");
        w.change(S, vec![run(D, 1, 11), run(S, 4, 3)]);
    }
    let again = compose(&board, Some(session.token()), &draft_inputs()).expect("composed again");
    assert_eq!(m_runs(&again)[3], run(S, 4, 3), "the premise: the same widths, other words");
    dialer.clear();
    assert_eq!(resume(&board, &again, shot(&session, &signer)), Ok(None));
    let mut claimed = again.record.clone();
    let minted = dialer.world().rows.iter().find(|r| r.docs[0] == member.to_string()).unwrap().at;
    claimed.landed = Some(RecordLanding::Member {
        member: member.clone(),
        position: minted,
    });
    assert_eq!(verify(&board, Some(session.token()), &claimed), Ok(Verdict::Differs { at: 16 }));
    dialer.clear();
    let landed = land(&board, &again, shot(&session, &signer)).expect("landed");
    assert!(
        matches!(&landed, Landed::AsDaughter { address, .. } if address.to_string() == format!("{D}.2.1")),
        "{landed:?}"
    );
    assert_eq!(dialer.frames("publish").len(), 1, "\"???\" published: {:?}", dialer.ops());
}

/// Another draft's merge of the same widths records no landing it did not
/// make: `S2`, staged from `D.1` with "???" after the base's text, is merged
/// onto `D.2` once `S`'s merge stands as `D.3`, "!!!" re-minted. `D.3`
/// matches `S2`'s list by its widths and holds other words, so the
/// read-first answers no landing, the shot lands as `D.2`'s daughter, and no
/// record of `S2`'s key names `D.3` (the mutant comparing addresses alone
/// writes one).
#[test]
fn another_drafts_merge_of_the_same_widths_records_no_landing_it_did_not_make() {
    const S2: &str = "1.0.1.0.67";
    let mut w = draft_landing_world();
    w.text(S2, 1, "???");
    w.doc(S2, false, ACCOUNT, vec![run(D, 1, 11), run(S2, 1, 3)]);
    w.staged(S2, &format!("{D}.1"), 11);
    let (dialer, board, signer) = open(w);
    let session = sign_in(&board, &signer);
    let merged = compose(&board, Some(session.token()), &draft_inputs()).expect("composed");
    let first = land(&board, &merged, shot(&session, &signer)).expect("S's merge landed");
    assert!(
        matches!(&first, Landed::Member { address, .. } if address.to_string() == format!("{D}.3")),
        "{first:?}"
    );
    let other = Inputs {
        sides: vec![Side::Draft { at: a(S2), position: None }],
        ..draft_inputs()
    };
    let merged = compose(&board, Some(session.token()), &other).expect("S2's merge composed");
    dialer.clear();
    let landed = land(&board, &merged, shot(&session, &signer)).expect("S2's merge landed");
    assert!(
        matches!(&landed, Landed::AsDaughter { address, .. } if address.to_string() == format!("{D}.2.1")),
        "{landed:?}"
    );
    assert_eq!(dialer.frames("publish").len(), 1, "{:?}", dialer.ops());
    assert!(
        dialer.frames("insert").is_empty(),
        "no record of a landing it did not make: {:?}",
        dialer.ops()
    );
}

/// A member of another width is no landing, and its image is not read: the
/// read-first takes `placed` for the list's width first. Beside the race's
/// composition, eleven positions wide, stand another hand's `D.3` and the
/// head's daughters `D.2.1` and `D.2.2`, five, six and seven wide: `resume`
/// answers none having read the metadata of each and of the absent `D.2.3`,
/// and no image (the mutant reading the image first reads three).
#[test]
fn a_member_of_another_width_is_no_landing_and_its_image_is_not_read() {
    let mut w = World::race();
    w.member(&format!("{D}.3"), vec![run(D, 1, 5)], Some(15));
    w.member(&format!("{D}.2.1"), vec![run(D, 1, 6)], Some(15));
    w.member(&format!("{D}.2.2"), vec![run(D, 1, 7)], Some(15));
    let (dialer, board, signer) = open(w);
    let session = sign_in(&board, &signer);
    let merged = compose(&board, Some(session.token()), &race_inputs()).expect("composed");
    let width: u64 = m_runs(&merged).iter().map(|r| r.width).sum();
    assert_eq!(width, 11, "the premise: {:?}", m_runs(&merged));
    dialer.clear();
    assert_eq!(resume(&board, &merged, shot(&session, &signer)), Ok(None));
    assert_eq!(dialer.ops(), ["doc_metadata"; 4], "the metadata of four members alone");
}

/// A DAUGHTER in the acknowledgment — the head moved under a merge whose
/// shot names NO daughter, a draft side's — is reported at once with its
/// position: ONE `publish`, no second, no claim read, no record; a
/// standing daughter holding M is found by the read-first too, once the
/// trunk has moved on by another's shot.
#[test]
fn a_daughter_is_reported_at_once_and_never_retried() {
    let (dialer, board, signer) = open(draft_landing_world());
    let session = sign_in(&board, &signer);
    let merged = compose(&board, Some(session.token()), &draft_inputs()).expect("composed");
    dialer.world().head_moved = true;
    dialer.clear();
    let landed = land(&board, &merged, shot(&session, &signer)).expect("landed");
    assert!(
        matches!(&landed, Landed::AsDaughter { address, .. } if address.to_string() == format!("{D}.2.1")),
        "{landed:?}"
    );
    let ops = dialer.ops();
    assert_eq!(ops.iter().filter(|o| *o == "publish").count(), 1);
    assert_eq!(ops.last().map(String::as_str), Some("publish"), "the library stops: {ops:?}");
    assert!(dialer.frames("publish")[0].get("supersede").is_none(), "a draft side names no daughter");
    assert!(!ops.iter().any(|o| o == "in_claims"), "no claim read: {ops:?}");
    // A standing daughter holding M is found by the read-first too: the
    // trunk moved on by another's shot (which is why ours landed under
    // the head), so the trunk's next is another's and the daughter ours.
    {
        let mut w = dialer.world();
        w.text(D, 19, "!");
        w.member(
            &format!("{D}.3"),
            vec![run(D, 1, 4), run(D, 12, 4), run(D, 5, 7), run(D, 19, 1)],
            Some(15),
        );
        w.trunk_head.insert(D.to_string(), format!("{D}.3"));
        w.head_moved = false;
    }
    dialer.clear();
    let found = land(&board, &merged, shot(&session, &signer)).expect("landed");
    assert!(
        matches!(&found, Landed::AsDaughter { address, .. } if address.to_string() == format!("{D}.2.1")),
        "{found:?}"
    );
    assert!(!dialer.ops().iter().any(|o| o == "publish"), "{:?}", dialer.ops());
}

/// A SHOT NAMING A DAUGHTER AT A MOVED HEAD IS REFUSED WHOLE (skep #806;
/// the merge bridge lane): the head moved under the merge, so the shot
/// would have landed as a daughter with a claim naming a side version
/// for good — the board refuses it `supersede_refused` / `head_moved`,
/// answered typed with the trunk's head, ONE `publish` and nothing after
/// it, nothing committed, no claim at the daughter, no record; `resume`
/// finds nothing landed. The embedder composes again on the head the
/// refusal names with `retries` one higher, and that shot lands on the
/// trunk with its claim, the count in its record.
#[test]
fn a_shot_naming_a_daughter_at_a_moved_head_is_refused_whole_and_typed() {
    let (dialer, board, signer) = open(World::race());
    let session = sign_in(&board, &signer);
    let merged = compose(&board, Some(session.token()), &race_inputs()).expect("composed");
    dialer.world().head_moved = true;
    let rows = dialer.world().rows.len();
    dialer.clear();
    let err = land(&board, &merged, shot(&session, &signer)).expect_err("refused");
    assert_eq!(
        err,
        Refusal::SupersedeRefused {
            index: 0,
            cause: SupersedeCause::HeadMoved { head: Some(a(&format!("{D}.2"))) },
        }
    );
    let ops = dialer.ops();
    assert_eq!(ops.iter().filter(|o| *o == "publish").count(), 1);
    assert_eq!(ops.last().map(String::as_str), Some("publish"), "nothing after it: {ops:?}");
    {
        let w = dialer.world();
        assert!(!w.docs.contains_key(&format!("{D}.2.1")), "nothing committed");
        assert_eq!(w.rows.len(), rows, "nothing committed");
        assert!(w.claims.is_empty(), "no claim at the daughter");
    }
    dialer.clear();
    assert_eq!(resume(&board, &merged, shot(&session, &signer)), Ok(None), "nothing to find");
    assert!(!dialer.ops().iter().any(|o| o == "publish"), "{:?}", dialer.ops());
    // THE RE-RUN on the head the refusal names: another's shot stands as
    // `D.3`; composed on it with `retries` one higher, the merge lands
    // as `D.4` with its claim, the count in its record.
    {
        let mut w = dialer.world();
        w.text(D, 16, "!");
        w.member(
            &format!("{D}.3"),
            vec![run(D, 1, 4), run(D, 12, 4), run(D, 5, 7), run(D, 16, 1)],
            Some(15),
        );
        w.trunk_head.insert(D.to_string(), format!("{D}.3"));
        w.head_moved = false;
    }
    let again = Inputs {
        head: a(&format!("{D}.3")),
        options: Options { retries: 1, ..Options::default() },
        ..race_inputs()
    };
    let merged = compose(&board, Some(session.token()), &again).expect("composed again");
    assert_eq!(
        (merged.record.retries, merged.record.to_value()["retries"].as_u64()),
        (1, Some(1))
    );
    let landed = land(&board, &merged, shot(&session, &signer)).expect("landed");
    let Landed::Member { address, claims, retries, .. } = &landed else {
        panic!("{landed:?}")
    };
    assert_eq!(
        (address.to_string(), claims.clone(), *retries),
        (format!("{D}.4"), vec![a(&format!("{D}.0.2.1"))], 1)
    );
}

/// THE SHOT NAMES THE MEMBER SIDES AS `supersede` AND NEVER A DRAFT SIDE
/// (the merge bridge lane): the race shape's shot carries `supersede`
/// `[D.1.1]`, the skip read at the daughter before it, its `attest`
/// verifying over the entry frame whose body is the shot's rows then the
/// one group the daemon's verifier spells for the daughter — the trunk
/// by address, the supersedes class, `from` the daughter's unit span,
/// `to` the tag `member`; a daughter an active claim of the merger's own
/// already names, whatever its `new`, is dropped from the list and the
/// body alike, the frame then naming no `supersede` and the body
/// today's; a draft side beside a member side is named as `draft`, never
/// in `supersede`; and a draft side alone names none.
#[test]
fn the_shot_names_the_member_sides_as_supersede_and_never_a_draft_side() {
    let values: Vec<[u8; 1]> = b"the big cat".iter().map(|b| [*b]).collect();
    let head = a(&format!("{D}.2"));
    let shot_body = || {
        entry_body_publish(
            values.iter().map(|v| ShotSegmentPiece::Value(v)),
            Some(ShotBase { member: &head, extent: 15 }),
        )
    };
    let verifies = |frame: &Value, body: &skep_identity::EntryBody, board: &Board, signer: &HybridSigner| {
        let term = board.board_term().unwrap().unwrap();
        let alg = Signer::public_key(signer).alg();
        assert_eq!(frame["attest"]["alg"].as_str(), Some(alg));
        let sig = crate::hex::decode(frame["attest"]["sig"].as_str().unwrap()).unwrap();
        let expected = entry_frame(alg, term, &a(ACCOUNT), DocTerm::One(&a(D)), body);
        skep_signature::verify(Signer::tag(signer), Signer::public_key(signer), &expected, &sig)
    };
    // The member side: the group, byte-checked through the attest.
    let (dialer, board, signer) = open(World::race());
    let session = sign_in(&board, &signer);
    let merged = compose(&board, Some(session.token()), &race_inputs()).expect("composed");
    dialer.clear();
    let landed = land(&board, &merged, shot(&session, &signer)).expect("landed");
    assert!(
        matches!(&landed, Landed::Member { address, claims, .. } if address.to_string() == format!("{D}.3") && *claims == vec![a(&format!("{D}.0.2.1"))]),
        "{landed:?}"
    );
    let ops = dialer.ops();
    assert!(
        ops.iter().position(|o| o == "in_claims") < ops.iter().position(|o| o == "publish"),
        "the skip read before the shot: {ops:?}"
    );
    let frame = &dialer.frames("publish")[0];
    assert_eq!(frame["supersede"], json!([format!("{D}.1.1")]));
    assert!(frame.get("draft").is_none());
    let (trunk, sup_ty, daughter) =
        (a(D), unit_span(&a(T_SUPERSEDES)), unit_span(&a(&format!("{D}.1.1"))));
    let group = DepositRow {
        home: DepositHome::Address(&trunk),
        kind: DepositKind::Supersede,
        ty: DepositSlot::Stored(vec![SlotElement::Span(&sup_ty)]),
        from: DepositSlot::Stored(vec![SlotElement::Span(&daughter)]),
        to: DepositSlot::Stored(vec![SlotElement::Member]),
    };
    assert_eq!(
        verifies(frame, &entry_body_publication(shot_body(), &[group]), &board, &signer),
        Ok(()),
        "the attest signs the body the board composes: the shot's rows then the daughter's group"
    );
    // THE SKIP: an own claim already names the daughter, its `new` a side
    // version — dropped from the list and the body, no second claim.
    let (dialer, board, signer) = open(World::race());
    let session = sign_in(&board, &signer);
    dialer.world().claims.push(ClaimRow {
        claim: format!("{DOC1}.0.2.7"),
        home: DOC1.into(),
        old: format!("{D}.1.1"),
        new: format!("{D}.1.1.1"),
    });
    let merged = compose(&board, Some(session.token()), &race_inputs()).expect("composed");
    dialer.clear();
    let landed = land(&board, &merged, shot(&session, &signer)).expect("landed");
    assert!(
        matches!(&landed, Landed::Member { address, claims, .. } if address.to_string() == format!("{D}.3") && claims.is_empty()),
        "{landed:?}"
    );
    let frame = &dialer.frames("publish")[0];
    assert!(frame.get("supersede").is_none(), "the daughter dropped: {frame}");
    assert_eq!(
        verifies(frame, &entry_body_publication(shot_body(), &[]), &board, &signer),
        Ok(()),
        "today's body, no group"
    );
    assert_eq!(dialer.world().claims.len(), 1, "no second claim deposited");
    // A draft side beside a member side: `draft`, never `supersede`.
    let mut w = draft_landing_world();
    w.member(&format!("{D}.1.1"), vec![run(D, 1, 7)], Some(11));
    let (dialer, board, signer) = open(w);
    let session = sign_in(&board, &signer);
    let both = Inputs {
        sides: vec![
            Side::Member(a(&format!("{D}.1.1"))),
            Side::Draft { at: a(S), position: None },
        ],
        ..draft_inputs()
    };
    let merged = compose(&board, Some(session.token()), &both).expect("composed");
    dialer.clear();
    land(&board, &merged, shot(&session, &signer)).expect("landed");
    let frame = &dialer.frames("publish")[0];
    assert_eq!(
        (frame["supersede"].clone(), frame["draft"].as_str()),
        (json!([format!("{D}.1.1")]), Some(S))
    );
    // A draft side alone names none.
    let (dialer, board, signer) = open(draft_landing_world());
    let session = sign_in(&board, &signer);
    let merged = compose(&board, Some(session.token()), &draft_inputs()).expect("composed");
    dialer.clear();
    land(&board, &merged, shot(&session, &signer)).expect("landed");
    assert!(dialer.frames("publish")[0].get("supersede").is_none());
}

/// THE RECORD AFTER THE MERGER's OWN PUBLICATION (the merge bridge
/// lane): the person publishes the merged draft themselves — here the
/// world's `D.3` holding M with an edit, "!" typed before the shot, and
/// the claim at the daughter as that shot deposited it — and
/// `record_published`, handed the member and the position acknowledged,
/// sends NO `publish`: it reads the claims at the daughter and the
/// merger's newest record for the key, writes the record — `landed` the
/// member at that position, `claims` the shot's — in the journal with
/// its link beside it, under the shot's own ids, reading no head: it
/// signs nothing — and answers the landing; a second call answers the
/// same record and writes nothing.
/// The shot landing's read-first would not find the edited member
/// (`resume` answers none), which is why the entry exists; a member
/// outside the document's chain is the library's own fault, nothing
/// read.
#[test]
fn the_record_is_written_after_the_mergers_own_publication_and_never_a_second_shot() {
    let (dialer, board, signer) = open(World::race());
    let session = sign_in(&board, &signer);
    let merged = compose(&board, Some(session.token()), &race_inputs()).expect("composed");
    let (member, at) = {
        let mut w = dialer.world();
        w.text(D, 16, "!");
        w.member(
            &format!("{D}.3"),
            vec![run(D, 1, 4), run(D, 12, 4), run(D, 5, 3), run(D, 16, 1)],
            Some(15),
        );
        w.trunk_head.insert(D.to_string(), format!("{D}.3"));
        w.claims.push(ClaimRow {
            claim: format!("{D}.0.2.1"),
            home: D.into(),
            old: format!("{D}.1.1"),
            new: format!("{D}.3"),
        });
        (a(&format!("{D}.3")), w.position)
    };
    dialer.clear();
    let landed =
        record_published(&board, &merged, merger(&session, &signer), &member, at, None, &[])
            .expect("recorded");
    let Landed::Member { address, position, claims, record, retries, .. } = &landed else {
        panic!("{landed:?}")
    };
    assert_eq!(
        (address, *position, claims.clone(), record.to_string(), *retries),
        (&member, at, vec![a(&format!("{D}.0.2.1"))], "1.0.1.0.72.0.2.1".to_string(), 0)
    );
    assert_eq!(
        dialer.ops(),
        [
            "in_claims",
            "find_links_ftt",
            "window_ftt",
            "create_new_document",
            "retrieve_doc_v_span_set",
            "insert",
            "make_link"
        ],
        "the claims' read, the record's read-first, the journal's find and mint, the two writes — no head read, no publish, no shot read-first"
    );
    let insert = &dialer.frames("insert")[0];
    let atom: Value =
        serde_json::from_str(insert["values"][0]["atom"].as_str().unwrap()).unwrap();
    assert_eq!(atom["landed"], json!({"member": format!("{D}.3"), "position": at}));
    assert_eq!(atom["claims"], json!([format!("{D}.0.2.1")]));
    assert_eq!(atom["replaces"], Value::Null);
    assert_eq!(
        insert["id"].as_str(),
        Some(landing_id(&merged.key.text(), "record").as_str()),
        "the shot's own ids"
    );
    let link = &dialer.frames("make_link")[0];
    assert_eq!(link["to"]["addrs"], json!([format!("{D}.3"), format!("{D}.1.1")]));
    // A second call: the standing record, nothing written.
    dialer.clear();
    let rows = dialer.world().rows.len();
    assert_eq!(
        record_published(&board, &merged, merger(&session, &signer), &member, at, None, &[]),
        Ok(landed.clone())
    );
    assert_eq!(dialer.world().rows.len(), rows, "nothing written twice");
    assert!(
        !dialer
            .ops()
            .iter()
            .any(|o| ["publish", "insert", "make_link", "create_new_document"]
                .contains(&o.as_str())),
        "{:?}",
        dialer.ops()
    );
    // The shot landing's read-first finds no member holding M: the edit.
    dialer.clear();
    assert_eq!(resume(&board, &merged, shot(&session, &signer)), Ok(None));
    assert!(!dialer.ops().iter().any(|o| o == "publish"), "{:?}", dialer.ops());
    // A member outside the chain: the library's own fault, nothing read.
    dialer.clear();
    let err = record_published(&board, &merged, merger(&session, &signer), &a(Z), at, None, &[])
        .expect_err("own fault");
    assert!(matches!(&err, Refusal::Halt(h) if h.exit_code() == 3), "{err}");
    assert!(dialer.ops().is_empty(), "{:?}", dialer.ops());
}

/// OVER THE CAP: a merged list past the shot's run cap is refused with
/// the count before ANY frame — no read, no write.
#[test]
fn over_the_cap_refuses_with_the_count_before_any_frame() {
    let (dialer, board, signer) = open(World::race());
    let session = sign_in(&board, &signer);
    let mut merged = compose(&board, Some(session.token()), &race_inputs()).expect("composed");
    assert_eq!(merged.cap, 1 << 12);
    merged.cap = 2;
    dialer.clear();
    assert_eq!(
        land(&board, &merged, shot(&session, &signer)),
        Err(Refusal::OverCap { runs: 3, cap: 2 })
    );
    assert_eq!(
        resume(&board, &merged, shot(&session, &signer)),
        Err(Refusal::OverCap { runs: 3, cap: 2 })
    );
    assert!(dialer.ops().is_empty(), "{:?}", dialer.ops());
}

/// THE DRAFT LANDING IS ONE WRITE (the landing lane's rulings R1, R4,
/// R5; skep #764): the merger's newest record for the key read first,
/// then the draft's base as it stands, at the head, then one
/// `set_arrangement` of M into the draft — its runs, `as_of` the ONE
/// position the merge was composed at, `head` the head and its extent as
/// read, `base` the same pair since the board records a base for the
/// draft, `merge` the sides but the draft itself (none: the draft was
/// the side), the id `<stem>.draft`, its stem over `<key>:<draft>@<P>` —
/// the key, the draft and the position typed against, no record standing
/// to follow — no `delete`, no `reinstate`, no `publish`, no claim read;
/// the draft holds M, its base re-recorded on the head and the marker
/// beside it at the write's position; the record with `landed` the draft
/// and THE WRITE's position. A second landing over the same `merged` in
/// the session follows the record the first one followed, so the board's
/// memo answers its id: the same landing, nothing written twice. `resume`
/// answers the landing, writing nothing, and again after an edit of the
/// draft, which it reads as of the marker's position (the mutant that reads
/// the draft at the head answers none).
#[test]
fn the_draft_landing_is_one_set_arrangement_typed_at_the_composition_and_writes_the_record() {
    let (dialer, board, signer) = open(draft_landing_world());
    let session = sign_in(&board, &signer);
    let merged = compose(&board, Some(session.token()), &draft_inputs()).expect("composed");
    assert_eq!(m_runs(&merged), draft_m());
    let p = merged.as_of;
    assert_eq!(p, dialer.world().position, "the one position: the head when the composition began");
    dialer.clear();
    let landed = land(&board, &merged, draft_landing(&session, &signer, Some(a(S)))).expect("landed");
    let Landed::Draft { into, position, record, head_moved, staged } = &landed else { panic!("{landed:?}") };
    assert_eq!((into.to_string(), head_moved.clone(), *staged), (S.to_string(), None, false), "a draft named is never staged");
    let frames = dialer.frames("set_arrangement");
    assert_eq!(frames.len(), 1, "one write: {:?}", dialer.ops());
    let frame = &frames[0];
    assert_eq!(frame["doc"], S);
    assert_eq!(frame["as_of"].as_u64(), Some(p), "typed against the composition's position: {frame}");
    assert_eq!(frame["runs"], frame_runs(&draft_m()));
    assert_eq!(frame["head"], json!({"at": format!("{D}.2"), "extent": "15"}), "the head and its extent as read");
    assert_eq!(frame["base"], json!({"at": format!("{D}.2"), "extent": "15"}), "the base to record: the head's pair");
    assert_eq!(frame["merge"], json!({"sides": []}), "every side but the draft itself");
    assert_eq!(frame["id"].as_str(), Some(landing_id(&format!("{}:{S}@{p}", merged.key.text()), "draft").as_str()));
    let ops = dialer.ops();
    assert!(
        !ops.iter().any(|o| ["publish", "in_claims", "delete", "reinstate", "stage"].contains(&o.as_str())),
        "{ops:?}"
    );
    assert_eq!(
        ops[..3],
        ["find_links_ftt", "doc_metadata", "set_arrangement"],
        "the merger's newest record for the key — the links of the kind to the draft, the one side but the head, none standing — then the draft's base, read as it stands, then the one write: {ops:?}"
    );
    assert!(ops.iter().all(|o| !o.starts_with("at:")), "nothing read at a position: {ops:?}");
    // The draft holds M; the base re-recorded on the head at the extent
    // read; the marker beside it, at the write's position.
    let w = dialer.world();
    assert_eq!(w.docs.get(S).unwrap().runs, draft_m());
    assert_eq!(
        w.standing(S),
        (Some((format!("{D}.2"), 15)), Some(Marker { sides: vec![], head: format!("{D}.2"), head_copied: 15, at: *position }))
    );
    assert_eq!(*position, w.rows.iter().find(|r| r.op == "set_arrangement").unwrap().at, "the write's `at`");
    drop(w);
    // The record: the draft and the write's position.
    let atom: Value =
        serde_json::from_str(dialer.frames("insert")[0]["values"][0]["atom"].as_str().unwrap())
            .unwrap();
    assert_eq!(atom["landed"], json!({"draft": S, "position": position}));
    assert_eq!(dialer.frames("make_link")[0]["to"]["addrs"], json!([S]));
    // Again over the same `merged`: the memo answers the id, nothing
    // written twice, the same landing.
    dialer.clear();
    let rows = dialer.world().rows.len();
    assert_eq!(
        land(&board, &merged, draft_landing(&session, &signer, Some(a(S)))).expect("landed again"),
        Landed::Draft { into: a(S), position: *position, record: record.clone(), head_moved: None, staged: false }
    );
    assert_eq!(dialer.world().rows.len(), rows, "nothing written twice");
    assert!(dialer.frames("insert").is_empty() && dialer.frames("make_link").is_empty());
    // `resume` finds the draft holding M and answers the marker's
    // position, the record standing; an edit since the landing changes
    // nothing, the draft read as of the marker's position, where the landing
    // placed M (skep #914: a landing stands until it is taken back).
    let landed_s = Some(Landed::Draft { into: a(S), position: *position, record: record.clone(), head_moved: None, staged: false });
    dialer.clear();
    assert_eq!(resume(&board, &merged, draft_landing(&session, &signer, Some(a(S)))).expect("resumed"), landed_s);
    assert!(dialer.frames("set_arrangement").is_empty(), "a resume sends nothing: {:?}", dialer.ops());
    dialer.world().change(S, vec![run(D, 1, 11)]);
    dialer.clear();
    assert_eq!(resume(&board, &merged, draft_landing(&session, &signer, Some(a(S)))).expect("resumed"), landed_s, "the landing stands, the edit since it beside");
    assert_eq!(dialer.positions("image"), vec![*position], "the draft imaged as of the marker's position: {:?}", dialer.ops());
    assert!(dialer.frames("insert").is_empty() && dialer.frames("make_link").is_empty(), "the record stands: {:?}", dialer.ops());
}

/// AN EDIT TO THE DRAFT BETWEEN COMPOSE AND LAND IS REFUSED WHOLE (THE
/// PROVENANCE, skep #762's landing half): the merge composed at P;
/// another hand deletes the draft's "!!!" after it; the one write, typed
/// against P, is refused `arrangement_moved` — the board's verdict, its
/// detail naming the draft that changed after the merge was composed
/// and that nothing was merged — the draft left as the other hand left
/// it, nothing written, no record. The hole this closes: a landing typed
/// against a fresh read of the draft lands M over the edit and deletes
/// it as absent from M.
#[test]
fn an_edit_to_the_draft_between_compose_and_land_is_refused_whole() {
    let (dialer, board, signer) = open(draft_landing_world());
    let session = sign_in(&board, &signer);
    let merged = compose(&board, Some(session.token()), &draft_inputs()).expect("composed");
    let p = merged.as_of;
    // Another hand's edit: the draft's "!!!" deleted.
    let typed = dialer.world().position;
    match board.op(Some(session.token()), &frames::delete(S, 12, 3, typed, None)) {
        Ok(Answer::Document(v)) => assert_eq!(v["resp"], "ack", "{v}"),
        other => panic!("{other:?}"),
    }
    let edited = dialer.world().docs.get(S).unwrap().runs.clone();
    assert_eq!(edited, vec![run(D, 1, 11)]);
    let rows = dialer.world().rows.len();
    dialer.clear();
    let err = land(&board, &merged, draft_landing(&session, &signer, Some(a(S)))).expect_err("the draft changed");
    let Refusal::Halt(Halt::Refused(refused)) = &err else { panic!("{err:?}") };
    assert_eq!(refused.code, "arrangement_moved");
    let detail = refused.detail.as_deref().expect("the person's words");
    assert!(detail.contains(S) && detail.contains("changed after the merge was composed") && detail.contains("nothing was merged"), "{detail}");
    assert!(detail.contains(&format!("composed at position {p}")), "{detail}");
    assert!(detail.contains("run the merge again, which reads the draft as it stands"), "S is the merge's side, which a run again reads: {detail}");
    assert_eq!(dialer.frames("set_arrangement")[0]["as_of"].as_u64(), Some(p), "typed against the composition's position, never a fresh read");
    let w = dialer.world();
    assert_eq!(w.docs.get(S).unwrap().runs, edited, "the other hand's edit stands: nothing wiped");
    assert_eq!(w.rows.len(), rows, "nothing written");
    assert_eq!(w.standing(S), (Some((format!("{D}.1"), 11)), None), "the base and no marker, as they stood");
    drop(w);
    assert!(dialer.frames("insert").is_empty() && dialer.frames("make_link").is_empty(), "no record");
}

/// A race on a draft that is no side says what landing there again does.
///
/// The race shape is composed to land in `T`, a draft staged from `D.1`
/// that the merge never reads, and another hand edits `T` after the
/// composition (skep #852). The one write is refused `arrangement_moved`,
/// nothing written and the edit kept, and its words say that nothing was
/// merged and that `T`, no side of the merge, has the change replaced by
/// the merged list were the merge landed there again — never that a run
/// again reads the draft as it stands.
#[test]
fn a_race_on_a_draft_that_is_no_side_says_landing_there_again_replaces_the_change() {
    let t = "1.0.1.0.67";
    let mut w = World::race();
    w.doc(t, false, ACCOUNT, vec![run(D, 1, 11)]);
    w.staged(t, &format!("{D}.1"), 11);
    let (dialer, board, signer) = open(w);
    let session = sign_in(&board, &signer);
    let merged = compose(&board, Some(session.token()), &race_inputs()).expect("composed");
    let edited = vec![run(D, 1, 4), run(D, 12, 4)];
    let edit_at = dialer.world().change(t, edited.clone());
    let rows = dialer.world().rows.len();
    dialer.clear();
    let err = land(&board, &merged, draft_landing(&session, &signer, Some(a(t))))
        .expect_err("another hand's edit");
    let Refusal::Halt(Halt::Refused(refused)) = &err else { panic!("{err:?}") };
    assert_eq!(refused.code, "arrangement_moved", "{refused:?}");
    let detail = refused.detail.as_deref().expect("the person's words");
    assert!(
        detail.contains(&format!("{t} changed after the merge was composed (composed at position {}, the draft changed at {edit_at})", merged.as_of))
            && detail.contains("nothing was merged"),
        "{detail}"
    );
    assert!(
        detail.contains(&format!("{t} is no side of this merge"))
            && detail.contains(
                "landing the merge there again replaces the change with the merged list"
            ),
        "{detail}"
    );
    assert!(
        !detail.contains("reads the draft as it stands") && !detail.contains("resume"),
        "{detail}"
    );
    let w = dialer.world();
    assert_eq!(w.rows.len(), rows, "nothing written");
    assert_eq!(w.docs.get(t).unwrap().runs, edited, "the edit kept");
}

/// A DRAFT EDITED WHILE THE COMPOSITION READS IT IS REFUSED (skep #1144):
/// another hand deletes the draft's "!!!" after the draft's opening fence
/// and before its closing one, and the composition refuses `SideMoved`
/// naming the draft — `before` its state at the opening fence, `after` the
/// edit's position, `at` the position the composition stood at — with no
/// read at a position and nothing written. The same edit landed before
/// the draft's opening fence is read as it stands: M holds no "!!!", and
/// P, past the edit, is the result's `as_of` and the record's draft
/// side's position, the draft's state the edit's. Read with no fence,
/// the composition would pair the draft's base and state from one moment
/// with an image from the next.
#[test]
fn a_draft_edited_while_the_composition_reads_it_is_refused_and_one_edited_before_is_read_as_it_stands() {
    // After the draft's opening fence: before the head's, the third frame.
    let mut w = draft_landing_world();
    w.interleave = Some((3, S.to_string(), vec![run(D, 1, 11)]));
    let (dialer, board, _) = open(w);
    let p = dialer.world().position;
    let refused = compose(&board, Some(&token()), &draft_inputs());
    assert!(dialer.world().interleave.is_none(), "the edit landed mid-walk");
    let edited = p + 1;
    assert_eq!(dialer.world().docs.get(S).unwrap().history.keys().next_back(), Some(&edited), "the premise: the edit's position");
    assert_eq!(refused, Err(Refusal::SideMoved { side: a(S), at: edited, before: Some(p), after: Some(edited) }));
    let said = refused.unwrap_err().to_string();
    assert!(said.contains(&format!("{S} changed while this merge was reading it")) && said.contains("nothing was merged") && said.contains("compose the merge again"), "{said}");
    let ops = dialer.ops();
    assert!(ops.iter().all(|o| !o.starts_with("at:")), "no read at a position: {ops:?}");
    assert!(!ops.iter().any(|o| ["set_arrangement", "publish", "insert", "make_link", "stage"].contains(&o.as_str())), "nothing written: {ops:?}");
    // Before the draft's opening fence: the second frame.
    let mut w = draft_landing_world();
    w.interleave = Some((2, S.to_string(), vec![run(D, 1, 11)]));
    let (dialer, board, _) = open(w);
    let edited = dialer.world().position + 1;
    let merged = compose(&board, Some(&token()), &draft_inputs()).expect("composed");
    assert!(dialer.world().interleave.is_none(), "the edit landed mid-walk");
    assert_eq!(m_runs(&merged), vec![run(D, 1, 4), run(D, 12, 4), run(D, 5, 7)], "the draft as the other hand left it: no \"!!!\"");
    assert_eq!(merged.as_of, edited, "P past the edit");
    assert_eq!(
        merged.record.sides[1],
        SideAt::Draft { at: a(S), position: Some(edited), arranged: SideState::At(edited) },
        "the draft's state as it was read"
    );
}

/// A POSITION THE BOARD HAS RECLAIMED is refused by name and never read
/// at the head instead (skep #762): a draft side naming a position below
/// the journal's floor refuses `HistoryReclaimed` at the first read, the
/// position and the floor named, with no read at the head.
#[test]
fn a_reclaimed_position_is_refused_and_never_read_at_the_head() {
    let mut w = draft_landing_world();
    let p = w.position - 2;
    w.floor = Some(w.position);
    let (dialer, board, _) = open(w);
    let inputs = Inputs { sides: vec![Side::Draft { at: a(S), position: Some(p) }], ..draft_inputs() };
    let floor = dialer.world().floor;
    assert_eq!(compose(&board, Some(&token()), &inputs), Err(Refusal::HistoryReclaimed { at: p, floor }));
    assert_eq!(dialer.ops(), ["at:doc_metadata"], "the one read, at the position; nothing at the head");
    let said = Refusal::HistoryReclaimed { at: p, floor }.to_string();
    assert!(said.contains(&format!("position {p}")) && said.contains("nothing was read at another"), "{said}");
}

/// A named position the board never answered is refused as the caller's.
///
/// A draft side named past the board's head refuses `BeyondHead` with
/// the head, and one inside a commit `NotAPosition` with the nearest
/// position, each at the first read with no record named, nothing read
/// at the head, and the face advising a position the board has answered
/// (skep #761).
#[test]
fn a_named_position_past_the_head_or_inside_a_commit_is_refused_as_the_callers() {
    let (dialer, board, _) = open(draft_landing_world());
    let head = dialer.world().position;
    let named = |p: u64| Inputs {
        sides: vec![Side::Draft { at: a(S), position: Some(p) }],
        ..draft_inputs()
    };
    let refused = compose(&board, Some(&token()), &named(head + 5));
    assert_eq!(
        refused,
        Err(Refusal::BeyondHead { at: head + 5, head: Some(head), recorded: None })
    );
    assert_eq!(
        dialer.ops(),
        ["at:doc_metadata"],
        "the one read, at the position; nothing at the head"
    );
    let said = refused.unwrap_err().to_string();
    assert!(
        said.contains(&format!("position {}", head + 5))
            && said.contains(&format!("head at position {head}")),
        "{said}"
    );
    assert!(
        said.contains("beyond_head") && said.contains("or at the head"),
        "the caller's advice: {said}"
    );
    dialer.world().inside_commits.insert(head - 1);
    dialer.clear();
    let refused = compose(&board, Some(&token()), &named(head - 1));
    assert_eq!(
        refused,
        Err(Refusal::NotAPosition { at: head - 1, nearest: Some(head - 2), recorded: None })
    );
    assert_eq!(dialer.ops(), ["at:doc_metadata"]);
    let said = refused.unwrap_err().to_string();
    assert!(
        said.contains(&format!("position {}", head - 1))
            && said.contains(&format!("at or below it is {}", head - 2)),
        "{said}"
    );
    assert!(said.contains("not_a_position") && said.contains("or at the head"), "{said}");
}

/// Returns the draft side's record and the position its side names.
///
/// `S` is read at the composition's first position, and the merge is
/// landed as the shot and its record read back.
fn landed_draft_side_record(
    dialer: &Scripted,
    board: &Board,
    signer: &HybridSigner,
) -> (Record, u64) {
    let session = sign_in(board, signer);
    let read_at = dialer.world().position;
    let inputs =
        Inputs { sides: vec![Side::Draft { at: a(S), position: None }], ..race_inputs() };
    let merged = compose(board, Some(session.token()), &inputs).expect("composed");
    land(board, &merged, shot(&session, signer)).expect("landed");
    let record = current(board, Some(&token()), &a(K), &merged.key)
        .expect("the lookup")
        .expect("the record");
    assert_eq!(
        record.sides[1],
        SideAt::Draft { at: a(S), position: Some(read_at), arranged: SideState::At(read_at) }
    );
    (record, read_at)
}

/// A reclaimed position a record names withholds the verdict.
///
/// The draft side's record verifies Equal as of the position it names;
/// once the journal's floor passes that position, `verify` answers
/// Unreadable naming the draft — never the composition's refusal, whose
/// advice is to compose again — after the one refused read, with
/// nothing read at the head or at another position in its place (skep
/// #761; D14).
#[test]
fn a_reclaimed_position_a_record_names_withholds_the_verdict() {
    let (dialer, board, signer) = open(World::window_and_draft());
    let (record, read_at) = landed_draft_side_record(&dialer, &board, &signer);
    assert_eq!(verify(&board, Some(&token()), &record), Ok(Verdict::Equal), "the premise");
    dialer.world().floor = Some(read_at + 1);
    dialer.clear();
    assert_eq!(verify(&board, Some(&token()), &record), Ok(Verdict::Unreadable(a(S))));
    assert_eq!(dialer.ops(), ["at:doc_metadata"], "the one read, at the record's position");
    assert_eq!(dialer.positions("doc_metadata"), [read_at]);
}

/// A draft side the reader may not read withholds the verdict.
///
/// The draft side's record verifies Equal; once the draft is withheld
/// from the reader, `verify` answers Unreadable naming the draft — never
/// the composition's refusal — after the trunk's metadata and the
/// draft's own, each at the record's position, with nothing read past
/// the refused one (merge record §4, testimony; D14).
#[test]
fn a_withheld_draft_side_withholds_the_verdict() {
    let (dialer, board, signer) = open(World::window_and_draft());
    let (record, read_at) = landed_draft_side_record(&dialer, &board, &signer);
    assert_eq!(verify(&board, Some(&token()), &record), Ok(Verdict::Equal), "the premise");
    dialer.world().withheld.insert(S.to_string());
    dialer.clear();
    assert_eq!(verify(&board, Some(&token()), &record), Ok(Verdict::Unreadable(a(S))));
    assert_eq!(
        dialer.ops(),
        ["at:doc_metadata", "at:doc_metadata"],
        "the trunk's metadata, then the draft's, refused"
    );
    let read: Vec<String> = dialer
        .frames("doc_metadata")
        .iter()
        .map(|f| f["doc"].as_str().unwrap().to_string())
        .collect();
    assert_eq!(read, [D, S]);
    assert_eq!(dialer.positions("doc_metadata"), [read_at, read_at]);
}

/// A reclaimed draft landing position withholds the verdict.
///
/// The race shape landed into a fresh draft verifies Equal by identity
/// as of the landing's position. Once the journal's floor passes that
/// position — the recomputation's own reads, at the head, still answered
/// — `verify` answers Unreadable naming the draft, the draft read no
/// further than the refused read; and so it does where the floor passes
/// the position between the draft's extent and its image (skep #761;
/// D14).
#[test]
fn a_reclaimed_draft_landing_position_withholds_the_verdict() {
    let (dialer, board, signer) = open(World::race());
    let session = sign_in(&board, &signer);
    let merged = compose(&board, Some(session.token()), &race_inputs()).expect("composed");
    let landed = land(&board, &merged, draft_landing(&session, &signer, None)).expect("landed");
    let Landed::Draft { into: fresh, position, .. } = &landed else { panic!("{landed:?}") };
    let record = current(&board, Some(&token()), &a(K), &merged.key)
        .expect("the lookup")
        .expect("the record");
    assert_eq!(
        record.landed,
        Some(RecordLanding::Draft { draft: fresh.clone(), position: *position })
    );
    assert_eq!(verify(&board, Some(&token()), &record), Ok(Verdict::Equal), "the premise");
    assert!(
        *position < dialer.world().position,
        "the premise: the head the recomputation reads at stands above the floor"
    );
    dialer.world().floor = Some(position + 1);
    dialer.clear();
    assert_eq!(verify(&board, Some(&token()), &record), Ok(Verdict::Unreadable(fresh.clone())));
    let ops = dialer.ops();
    assert_eq!(
        ops.last().map(String::as_str),
        Some("at:retrieve_doc_v_span_set"),
        "the refused read is the last: {ops:?}"
    );
    assert_eq!(dialer.positions("retrieve_doc_v_span_set").last(), Some(position));
    let fresh_text = fresh.to_string();
    assert!(
        dialer.frames("image").iter().all(|f| f["d"].as_str() != Some(fresh_text.as_str())),
        "no image of the draft: {ops:?}"
    );
    // The floor passing the landing's position after the draft's extent
    // was read there and before its image: the image's refusal withholds
    // the verdict too.
    dialer.world().floor = None;
    dialer.clear();
    assert_eq!(verify(&board, Some(&token()), &record), Ok(Verdict::Equal));
    let image_at = dialer
        .served
        .lock()
        .unwrap()
        .iter()
        .position(|(line, f)| {
            line == "at:image" && f["frame"]["d"].as_str() == Some(fresh_text.as_str())
        })
        .expect("the draft's image");
    dialer.world().reclaim = Some((image_at + 1, position + 1));
    dialer.clear();
    assert_eq!(verify(&board, Some(&token()), &record), Ok(Verdict::Unreadable(fresh.clone())));
    assert!(dialer.world().reclaim.is_none(), "the journal reclaimed mid-walk");
    let ops = dialer.ops();
    assert_eq!(
        ops.last().map(String::as_str),
        Some("at:image"),
        "the refused image is the last read: {ops:?}"
    );
    assert_eq!(
        dialer.positions("retrieve_doc_v_span_set").last(),
        Some(position),
        "the extent answered at the landing's position"
    );
    assert_eq!(dialer.positions("image").last(), Some(position));
}

/// A position a record names that the board never answered is refused.
///
/// A draft side's record naming a position past the board's head
/// refuses `BeyondHead`, and one naming a number inside one commit
/// `NotAPosition`, each carrying the board's head or nearest position
/// and naming the draft as the record's. The face says the record
/// cannot be checked here and advises no read elsewhere; after the one
/// refused read nothing is read at another position (skep #761).
#[test]
fn a_position_a_record_names_past_the_head_or_inside_a_commit_is_refused_as_the_records() {
    let (dialer, board, signer) = open(World::window_and_draft());
    let (record, _) = landed_draft_side_record(&dialer, &board, &signer);
    let head = dialer.world().position;
    let naming = |p: u64| {
        let mut r = record.clone();
        let SideAt::Draft { position, .. } = &mut r.sides[1] else { panic!("the draft side") };
        *position = Some(p);
        r
    };
    dialer.clear();
    let refused = verify(&board, Some(&token()), &naming(head + 5));
    assert_eq!(
        refused,
        Err(Refusal::BeyondHead { at: head + 5, head: Some(head), recorded: Some(a(S)) })
    );
    assert_eq!(dialer.ops(), ["at:doc_metadata"], "the one read, at the record's position");
    let said = refused.unwrap_err().to_string();
    assert!(
        said.contains(&format!("position {} for {S}", head + 5))
            && said.contains(&format!("head at position {head}")),
        "{said}"
    );
    assert!(said.contains("beyond_head") && said.contains("cannot be checked here"), "{said}");
    assert!(!said.contains("or at the head"), "no read elsewhere advised: {said}");
    dialer.world().inside_commits.insert(head - 1);
    dialer.clear();
    let refused = verify(&board, Some(&token()), &naming(head - 1));
    assert_eq!(
        refused,
        Err(Refusal::NotAPosition {
            at: head - 1,
            nearest: Some(head - 2),
            recorded: Some(a(S))
        })
    );
    assert_eq!(dialer.ops(), ["at:doc_metadata"]);
    let said = refused.unwrap_err().to_string();
    assert!(
        said.contains(&format!("position {} for {S}", head - 1))
            && said.contains(&format!("at or below it is {}", head - 2)),
        "{said}"
    );
    assert!(
        said.contains("not_a_position") && said.contains("cannot be checked here"),
        "{said}"
    );
    assert!(!said.contains("or at the head"), "no read elsewhere advised: {said}");
}

/// LAND AND TELL (R5, P1): version 3 published after the merge was
/// composed on version 2 refuses nothing — the write lands, the base is
/// recorded on the head USED at the extent read, the marker names that
/// head, and the landing carries the trunk's current head as
/// `head_moved`.
#[test]
fn a_newer_head_published_since_the_compose_is_told_and_the_landing_stands() {
    let (dialer, board, signer) = open(draft_landing_world());
    let session = sign_in(&board, &signer);
    let merged = compose(&board, Some(session.token()), &draft_inputs()).expect("composed");
    {
        let mut w = dialer.world();
        w.text(D, 16, "?");
        w.member(&format!("{D}.3"), vec![run(D, 1, 4), run(D, 12, 4), run(D, 5, 7), run(D, 16, 1)], Some(15));
        w.trunk_head.insert(D.to_string(), format!("{D}.3"));
    }
    let landed = land(&board, &merged, draft_landing(&session, &signer, Some(a(S)))).expect("landed");
    let Landed::Draft { into, position, head_moved, .. } = &landed else { panic!("{landed:?}") };
    assert_eq!((into.to_string(), head_moved.as_ref().map(ToString::to_string)), (S.to_string(), Some(format!("{D}.3"))));
    let w = dialer.world();
    assert_eq!(w.docs.get(S).unwrap().runs, draft_m());
    assert_eq!(
        w.standing(S),
        (Some((format!("{D}.2"), 15)), Some(Marker { sides: vec![], head: format!("{D}.2"), head_copied: 15, at: *position })),
        "recorded on the head used"
    );
}

/// A BASELESS DRAFT (N4): landing into a plain draft the board records
/// no base for — never staged — sends `head` and `merge` and NO `base`,
/// so the board admits it with nothing moved: the draft holds M, no
/// base, no marker. A `resume` after another write has moved the board
/// finds the landing by its `set_arrangement` row on the supplement, the
/// draft carrying no marker, and answers that row's position, never the
/// board's, with the landing's record standing: nothing is written.
#[test]
fn a_landing_into_a_baseless_draft_sends_no_base() {
    let plain = "1.0.1.0.67";
    let mut w = draft_landing_world();
    w.doc(plain, false, ACCOUNT, Vec::new());
    let (dialer, board, signer) = open(w);
    let session = sign_in(&board, &signer);
    let merged = compose(&board, Some(session.token()), &draft_inputs()).expect("composed");
    dialer.clear();
    let landed = land(&board, &merged, draft_landing(&session, &signer, Some(a(plain)))).expect("landed");
    let Landed::Draft { into, position, record, head_moved, staged } = &landed else { panic!("{landed:?}") };
    assert_eq!((into.to_string(), head_moved.clone(), *staged), (plain.to_string(), None, false));
    let frame = &dialer.frames("set_arrangement")[0];
    assert_eq!(frame["doc"], plain);
    assert!(frame.get("base").is_none(), "no base the board must refuse `no_base_to_record`: {frame}");
    assert_eq!(frame["head"], json!({"at": format!("{D}.2"), "extent": "15"}));
    assert_eq!(frame["merge"], json!({"sides": [S]}), "the side, which is not the draft landed into");
    let w = dialer.world();
    assert_eq!(w.docs.get(plain).unwrap().runs, draft_m());
    assert_eq!(w.standing(plain), (None, None), "nothing moved");
    drop(w);
    let moved = dialer.world().commit("insert", vec![Z.to_string()]);
    assert!(moved > *position, "the premise: the board moved past the landing");
    dialer.clear();
    let resumed = resume(&board, &merged, draft_landing(&session, &signer, Some(a(plain)))).expect("resumed");
    assert_eq!(resumed, Some(Landed::Draft { into: a(plain), position: *position, record: record.clone(), head_moved: None, staged: false }), "the landing's row's position and its own record");
    assert!(dialer.frames("insert").is_empty() && dialer.frames("make_link").is_empty(), "{:?}", dialer.ops());
}

/// THE FORK GATE (N4, P5): a fork — a document the board records no base
/// for, born sharing a published version, its `source` — takes a landing
/// composed on another head than its source as `fork_base_moved`,
/// refused by name with the source, the head and the way out, nothing
/// written; a fork whose source IS the head is admitted, gaining no base
/// and no marker. The forks are the merger's, landed into by their
/// owner, and the trunk `T` another account's: a fork is another
/// account's document, and one of the trunk owner's own account is
/// refused `ForkOfOwner` (skep #1107).
#[test]
fn a_fork_is_refused_fork_base_moved_and_admitted_where_its_source_is_the_head() {
    let (t, moved, fresh) = ("1.0.2.0.64", "1.0.1.0.69", "1.0.1.0.70");
    let (v1, v2) = (format!("{t}.1"), format!("{t}.2"));
    // Another account's trunk in the race's shape — the base `T.1` "the
    // cat sat", the head `T.2` adding "big " at `T·4|T·5` — and the
    // merger's two forks of it: one of version 1 that removed " sat",
    // and one of version 2 that did the same.
    let mut w = World::new();
    w.text(t, 1, "the cat sat");
    w.text(t, 12, "big ");
    let head = vec![run(t, 1, 4), run(t, 12, 4), run(t, 5, 7)];
    w.doc(t, true, "1.0.2", head.clone());
    w.member(&v1, vec![run(t, 1, 11)], None);
    w.member(&v2, head, Some(11));
    w.trunk_head.insert(t.to_string(), v2.clone());
    w.fork(moved, ACCOUNT, &v1, vec![run(t, 1, 7)]);
    w.fork(fresh, ACCOUNT, &v2, vec![run(t, 1, 4), run(t, 12, 4), run(t, 5, 3)]);
    let (dialer, board, signer) = open(w);
    let session = sign_in(&board, &signer);
    let inputs = |fork: &str| Inputs { doc: a(t), head: a(&v2), sides: vec![Side::Fork(a(fork))], ..race_inputs() };
    let merged = compose(&board, Some(session.token()), &inputs(moved)).expect("composed");
    assert_eq!(m_runs(&merged), vec![run(t, 1, 4), run(t, 12, 4), run(t, 5, 3)], "the big cat");
    let rows = dialer.world().rows.len();
    dialer.clear();
    assert_eq!(
        land(&board, &merged, draft_landing(&session, &signer, Some(a(moved)))),
        Err(Refusal::ForkBaseMoved { fork: a(moved), source: a(&v1), head: a(&v2) })
    );
    let frame = &dialer.frames("set_arrangement")[0];
    assert!(frame.get("base").is_none(), "a fork records no base: {frame}");
    assert_eq!(frame["merge"], json!({"sides": []}));
    assert_eq!(dialer.world().docs.get(moved).unwrap().runs, vec![run(t, 1, 7)], "nothing written");
    assert_eq!(dialer.world().rows.len(), rows);
    assert!(dialer.frames("insert").is_empty(), "no record");
    let said = Refusal::ForkBaseMoved { fork: a(moved), source: a(&v1), head: a(&v2) }.to_string();
    assert!(said.contains(&format!("forked from {v1}")) && said.contains(&format!("fork {v2} afresh")), "{said}");
    // The fork of the head: admitted, nothing moved.
    let merged = compose(&board, Some(session.token()), &inputs(fresh)).expect("composed");
    assert_eq!(merged.key.base, a(&v2), "the fork's source is the head, so the base is the head");
    dialer.clear();
    let landed = land(&board, &merged, draft_landing(&session, &signer, Some(a(fresh)))).expect("landed");
    let Landed::Draft { into, head_moved, .. } = &landed else { panic!("{landed:?}") };
    assert_eq!((into.to_string(), head_moved.clone()), (fresh.to_string(), None));
    let frame = &dialer.frames("set_arrangement")[0];
    assert_eq!(frame["head"], json!({"at": v2, "extent": "15"}));
    assert!(frame.get("base").is_none());
    assert_eq!(dialer.world().standing(fresh), (None, None), "no base, no marker gained");
}

/// A record whose fork a landing has moved since answers `SideMoved`.
///
/// The merger's draft `Y`, staged from `T.1` of another account's trunk
/// `T` — a fork from `T`'s side, never arranged since the world planted
/// it — composes over its recorded base `T.1`, its state `Unarranged`,
/// and is landed into itself, the landing moving its recorded base to the
/// head `T.2` and its `arranged_at` to the landing's position in the same
/// commit. `verify` answers `SideMoved` naming `Y`, before any read of
/// the recomputation (skep #770). The same record with its fork's
/// `arranged` stripped — a record written before the states were kept —
/// meets a fork arranged at the landing's position, not after it, so it
/// is read as it stands and faced, naming both bases and that
/// the record names no state for its fork, never verified; the mutant
/// that reads the fork's source first derives `T.1` again and answers
/// `Equal`.
#[test]
fn verify_faces_a_record_whose_fork_a_landing_has_moved_since() {
    let (t, y) = ("1.0.2.0.64", "1.0.1.0.69");
    let (v1, v2) = (format!("{t}.1"), format!("{t}.2"));
    let mut w = World::new();
    w.text(t, 1, "the cat sat");
    w.text(t, 12, "big ");
    let head = vec![run(t, 1, 4), run(t, 12, 4), run(t, 5, 7)];
    w.doc(t, true, "1.0.2", head.clone());
    w.member(&v1, vec![run(t, 1, 11)], None);
    w.member(&v2, head, Some(11));
    w.trunk_head.insert(t.to_string(), v2.clone());
    w.doc(y, false, ACCOUNT, vec![run(t, 1, 7)]);
    w.staged(y, &v1, 11);
    let (dialer, board, signer) = open(w);
    let session = sign_in(&board, &signer);
    let inputs =
        Inputs { doc: a(t), head: a(&v2), sides: vec![Side::Fork(a(y))], ..race_inputs() };
    let merged = compose(&board, Some(session.token()), &inputs).expect("composed");
    assert_eq!(merged.key.base, a(&v1), "the base the board records for the fork");
    assert_eq!(m_runs(&merged), vec![run(t, 1, 4), run(t, 12, 4), run(t, 5, 3)], "the big cat");
    assert_eq!(
        merged.record.sides[1],
        SideAt::Fork { at: a(y), arranged: SideState::Unarranged },
        "never arranged since its mint"
    );
    let landed =
        land(&board, &merged, draft_landing(&session, &signer, Some(a(y)))).expect("landed");
    let Landed::Draft { into, position, .. } = &landed else { panic!("{landed:?}") };
    assert_eq!(into, &a(y), "landed into the fork itself");
    let world = dialer.world();
    assert_eq!(
        (world.standing(y).0, world.docs[y].source.clone()),
        (Some((v2.clone(), 15)), Some(v1.clone())),
        "the landing moved the fork's base to the head and kept its source"
    );
    drop(world);
    let record = current(&board, Some(&token()), &a(K), &merged.key)
        .expect("the lookup")
        .expect("a current record");
    assert_eq!(record.base, a(&v1));
    dialer.clear();
    assert_eq!(
        verify(&board, Some(&token()), &record),
        Ok(Verdict::SideMoved {
            side: a(y),
            recorded: SideState::Unarranged,
            now: Some(*position)
        })
    );
    assert_eq!(dialer.ops(), ["doc_metadata"], "the fork's state alone, read at the head");
    let mut body = record.to_value();
    body["sides"][1].as_object_mut().expect("the fork side").remove("arranged");
    let stripped = Record::from_value(&body).expect("a record");
    assert_eq!(stripped.sides[1], SideAt::Fork { at: a(y), arranged: SideState::Unrecorded });
    let err = verify(&board, Some(&token()), &stripped).expect_err("faced");
    let Refusal::Halt(Halt::Halt(face)) = &err else { panic!("{err:?}") };
    assert!(
        face.state.contains(&format!("names the base {v1}"))
            && face.state.contains(&format!("now derive {v2}")),
        "{face:?}"
    );
    assert!(
        face.cause.contains("written before a fork side's state was kept, names none"),
        "{face:?}"
    );
    assert!(face.act.contains("cannot be checked against its fork as it stands"), "{face:?}");
}

/// A side's state round-trips through the record's JSON (skep #770).
///
/// A fork side's and a draft side's `"arranged": 7`, `"arranged": null`
/// and no member read as `At(7)`, `Unarranged` and `Unrecorded`, and are
/// written back the same: no member for a state never recorded. An
/// `arranged` of another kind is no record.
#[test]
fn a_sides_state_reads_and_writes_back_as_the_record_spells_it() {
    let (_, board, _) = open(World::race());
    let mut record = compose(&board, Some(&token()), &race_inputs()).expect("composed").record;
    let fork = |n: u64| a(&format!("1.0.2.0.{n}"));
    record.sides.extend([
        SideAt::Fork { at: fork(70), arranged: SideState::At(7) },
        SideAt::Fork { at: fork(71), arranged: SideState::Unarranged },
        SideAt::Fork { at: fork(72), arranged: SideState::Unrecorded },
        SideAt::Draft { at: a(S), position: Some(7), arranged: SideState::Unarranged },
    ]);
    let v = record.to_value();
    assert_eq!(v["sides"][2], json!({"at": "1.0.2.0.70", "role": "fork", "arranged": 7}));
    assert_eq!(v["sides"][3], json!({"at": "1.0.2.0.71", "role": "fork", "arranged": null}));
    assert_eq!(
        v["sides"][4],
        json!({"at": "1.0.2.0.72", "role": "fork"}),
        "no member for a state never recorded"
    );
    assert_eq!(
        v["sides"][5],
        json!({"at": {"draft": S, "position": 7}, "role": "draft", "arranged": null})
    );
    assert_eq!(
        v["sides"][1],
        json!({"at": format!("{D}.1.1"), "role": "alternative"}),
        "a member carries no state"
    );
    let back = Record::from_value(&v).expect("a record");
    assert_eq!(back.sides, record.sides);
    assert_eq!(back.to_value(), v, "written back the same");
    let mut odd = v.clone();
    odd["sides"][2]["arranged"] = json!("7");
    assert_eq!(Record::from_value(&odd), None, "a state of another kind");
}

/// The key's text spells each state, and its equality is exact.
///
/// `RecordKey::text` appends `:<side>@<q>` per state in address order,
/// `@null` for `Unarranged`, and leaves an `Unrecorded` state out, so a
/// record written before the states were kept spells today's text. A key
/// with an `Unrecorded` state equals none with `Unarranged` or `At`, and
/// `stateless` drops the states (skep #770).
#[test]
fn the_keys_text_spells_each_state_and_an_unrecorded_one_equals_no_other() {
    let key = |states: Vec<(Address, SideState)>| {
        RecordKey::new(a(D), a(&format!("{D}.1")), [a(F), a(S), a(&format!("{D}.2"))], states)
    };
    let bare = format!("merge:{D}:{D}.1:{D}.2+{S}+{F}");
    assert_eq!(key(vec![]).text(), bare, "the sides in address order");
    assert_eq!(
        key(vec![(a(F), SideState::At(7)), (a(S), SideState::Unarranged)]).text(),
        format!("{bare}:{S}@null:{F}@7"),
        "each state in address order"
    );
    let unrecorded = key(vec![(a(F), SideState::Unrecorded)]);
    assert_eq!(unrecorded.text(), bare, "an unrecorded state spells nothing");
    assert_ne!(unrecorded, key(vec![(a(F), SideState::Unarranged)]));
    assert_ne!(unrecorded, key(vec![(a(F), SideState::At(7))]));
    assert_eq!(unrecorded.stateless(), key(vec![(a(F), SideState::At(7))]).stateless());
    assert_eq!(unrecorded.stateless(), key(vec![]));
}

/// A fork recorded `Unarranged` answers `SideMoved` once it is arranged.
///
/// Case (j)'s fork `F`, never arranged since the world planted it,
/// composes as `Unarranged` and lands as the shot: its record verifies
/// `Equal` while the board still serves `null`. Re-arranged in place,
/// its words unchanged, the record answers `SideMoved` naming the fork,
/// the recorded `Unarranged` and the position served now — the mutant
/// matching `Unarranged` to any position answers `Equal` — and so does
/// the record with its fork's `arranged` stripped, `Unrecorded`, the
/// fork arranged after its landing, where before it verified `Equal`. A
/// record composed over the fork in that state, `At` its position — a
/// shot of it refused `HeadHolds`, the head already holding the fork's
/// words, so landed in a fresh draft — answers `SideMoved` once the forker
/// edits it again, never `Differs`.
#[test]
fn a_fork_recorded_unarranged_answers_side_moved_once_it_is_arranged() {
    let mut w = World::race();
    w.fork(F, "1.0.2", &format!("{D}.1"), vec![run(D, 1, 7)]);
    let (dialer, board, signer) = open(w);
    let session = sign_in(&board, &signer);
    let inputs = Inputs { sides: vec![Side::Fork(a(F))], ..race_inputs() };
    let merged = compose(&board, Some(session.token()), &inputs).expect("composed");
    assert_eq!(
        merged.record.sides[1],
        SideAt::Fork { at: a(F), arranged: SideState::Unarranged }
    );
    land(&board, &merged, shot(&session, &signer)).expect("landed");
    let record = current(&board, Some(&token()), &a(K), &merged.key)
        .expect("the lookup")
        .expect("the record");
    assert_eq!(
        verify(&board, Some(&token()), &record),
        Ok(Verdict::Equal),
        "still served null"
    );
    let mut body = record.to_value();
    body["sides"][1].as_object_mut().expect("the fork side").remove("arranged");
    let stripped = Record::from_value(&body).expect("a record");
    assert_eq!(
        verify(&board, Some(&token()), &stripped),
        Ok(Verdict::Equal),
        "a record before the states, the fork unarranged since"
    );
    let arranged = dialer.world().change(F, vec![run(D, 1, 7)]);
    assert_eq!(
        verify(&board, Some(&token()), &record),
        Ok(Verdict::SideMoved {
            side: a(F),
            recorded: SideState::Unarranged,
            now: Some(arranged)
        })
    );
    assert_eq!(
        verify(&board, Some(&token()), &stripped),
        Ok(Verdict::SideMoved {
            side: a(F),
            recorded: SideState::Unrecorded,
            now: Some(arranged)
        }),
        "arranged after the landing"
    );
    // Composed over the fork as it stands now, and landed again.
    let head = format!("{D}.3");
    let again = compose(
        &board,
        Some(session.token()),
        &Inputs { head: a(&head), sides: vec![Side::Fork(a(F))], ..race_inputs() },
    )
    .expect("composed again");
    assert_eq!(
        again.record.sides[1],
        SideAt::Fork { at: a(F), arranged: SideState::At(arranged) }
    );
    assert_eq!(
        land(&board, &again, shot(&session, &signer)),
        Err(Refusal::HeadHolds { head: a(&head) }),
        "no version identical to the head"
    );
    land(&board, &again, draft_landing(&session, &signer, None)).expect("landed again");
    let second = current(&board, Some(&token()), &a(K), &again.key)
        .expect("the lookup")
        .expect("the record");
    assert_eq!(verify(&board, Some(&token()), &second), Ok(Verdict::Equal));
    let edited = dialer.world().change(F, vec![run(D, 1, 4)]);
    assert_eq!(
        verify(&board, Some(&token()), &second),
        Ok(Verdict::SideMoved {
            side: a(F),
            recorded: SideState::At(arranged),
            now: Some(edited)
        }),
        "the fork's text changed: never `Differs`"
    );
}

/// A fork edited after its state's check answers `SideMoved`.
///
/// Case (j)'s fork, landed as the shot, its record `Unarranged`: another
/// hand's edit of the fork lands after `verify`'s first read, the fork's
/// state checked at the head, and before the recomputation's first, so
/// the recomputation reads the fork at a position past the edit. The
/// fork's state the readings carry is compared again: `SideMoved`, never
/// the `Differs` the mutant without that second comparison answers.
#[test]
fn a_fork_edited_between_the_state_check_and_the_recomputation_answers_side_moved() {
    let mut w = World::race();
    w.fork(F, "1.0.2", &format!("{D}.1"), vec![run(D, 1, 7)]);
    let (dialer, board, signer) = open(w);
    let session = sign_in(&board, &signer);
    let inputs = Inputs { sides: vec![Side::Fork(a(F))], ..race_inputs() };
    let merged = compose(&board, Some(session.token()), &inputs).expect("composed");
    land(&board, &merged, shot(&session, &signer)).expect("landed");
    let record = current(&board, Some(&token()), &a(K), &merged.key)
        .expect("the lookup")
        .expect("the record");
    dialer.clear();
    dialer.world().interleave = Some((2, F.to_string(), vec![run(D, 1, 4)]));
    let verdict = verify(&board, Some(&token()), &record);
    let w = dialer.world();
    assert!(w.interleave.is_none(), "the premise: the edit landed after the state check");
    let edited = *w.docs[F].history.keys().next_back().expect("the edit");
    drop(w);
    assert_eq!(
        verdict,
        Ok(Verdict::SideMoved {
            side: a(F),
            recorded: SideState::Unarranged,
            now: Some(edited)
        })
    );
    assert_eq!(dialer.frames("doc_metadata")[0]["doc"], F, "the state checked first");
}

/// A fork beside a draft side is read at the draft side's position.
///
/// The draft `S` and another account's version fork `F` compose and land
/// in a fresh draft, the record naming `S`'s position. The forker then
/// re-arranges `F`: `verify` reads the fork's state at that position, as
/// every read of the recomputation is made, so the record verifies
/// `Equal` — the mutant reading the fork's state at the head answers
/// `SideMoved` for a record the board can still check.
#[test]
fn a_forks_state_beside_a_draft_side_is_read_at_the_draft_sides_position() {
    let mut w = draft_landing_world();
    w.fork(F, "1.0.2", &format!("{D}.1"), vec![run(D, 1, 11)]);
    let (dialer, board, signer) = open(w);
    let session = sign_in(&board, &signer);
    let inputs = Inputs {
        sides: vec![Side::Draft { at: a(S), position: None }, Side::Fork(a(F))],
        ..race_inputs()
    };
    let merged = compose(&board, Some(session.token()), &inputs).expect("composed");
    assert_eq!(m_runs(&merged), draft_m(), "the big cat sat!!!, the fork unchanged");
    land(&board, &merged, draft_landing(&session, &signer, None)).expect("landed");
    let record = current(&board, Some(&token()), &a(K), &merged.key)
        .expect("the lookup")
        .expect("the record");
    assert_eq!(record.sides[2], SideAt::Fork { at: a(F), arranged: SideState::Unarranged });
    dialer.world().change(F, vec![run(D, 1, 7)]);
    dialer.clear();
    assert_eq!(verify(&board, Some(&token()), &record), Ok(Verdict::Equal));
    let read = dialer
        .frames("doc_metadata")
        .into_iter()
        .position(|f| f["doc"] == F)
        .expect("the fork's state read");
    assert_eq!(
        dialer.positions("doc_metadata")[read],
        merged.as_of,
        "the fork's state read at the record's position"
    );
}

/// What a landing replaces is each stretch M does not carry.
///
/// The pure comparison: a draft holding words M does not carry at two
/// places answers two stretches, in order, with their ordinals and
/// widths; words M carries at another place are not replaced; two
/// stretches meeting across a run boundary are one; a run M carries in
/// part answers the rest; an image M carries whole answers none.
#[test]
fn what_a_landing_replaces_is_each_stretch_m_does_not_carry() {
    use crate::merge::land::replaced_stretches;
    let l = "1.0.1.0.72";
    let x = "1.0.1.0.73";
    // "zz the yy cat sat!!!": L·1–3 and L·4–5 M does not carry; S·1–3
    // M carries after "the ".
    let held = vec![run(l, 1, 3), run(D, 1, 4), run(l, 4, 2), run(D, 5, 7), run(S, 1, 3)];
    let m = vec![run(D, 1, 4), run(S, 1, 3), run(D, 5, 7)];
    let stretch = |ordinal, width, origin: &str, i_start| Replaced {
        ordinal,
        width,
        origin: a(origin),
        i_start,
    };
    assert_eq!(replaced_stretches(&held, &m), vec![stretch(1, 3, l, 1), stretch(8, 2, l, 4)]);
    assert_eq!(
        replaced_stretches(&[run(l, 1, 2), run(x, 5, 3)], &m),
        vec![stretch(1, 5, l, 1)],
        "one stretch across the boundary"
    );
    assert_eq!(
        replaced_stretches(&[run(D, 1, 11)], &[run(D, 1, 4), run(D, 8, 4)]),
        vec![stretch(5, 3, D, 5)],
        "the run's middle"
    );
    assert_eq!(
        replaced_stretches(&[run(D, 1, 11)], &[run(D, 1, 11)]),
        Vec::<Replaced>::new(),
        "carried whole"
    );
    assert_eq!(replaced_stretches(&[], &m), Vec::<Replaced>::new(), "an empty draft");
}

/// A fork arranged since its draft landing is another key.
///
/// Case (j)'s fork `F` composes and lands in a fresh draft `L`. The
/// forker edits the fork, and the merge composed again differs from the
/// first in its key's states alone, no record of it standing; the
/// person's own landing is found by `landed_draft`, the states ignored —
/// the mutant matching the key exactly finds none — and `replaced` names
/// the stretch of `L` the new M does not carry. Landed in `L`, the merge
/// writes a record of its own replacing none, never the same landing
/// (skep #790); it verifies `Equal`, and the first `SideMoved`. Taken back
/// by an undo, which puts the first landing's marker back in `L` (skep
/// #964), the first landing stands again: `landed_draft` names its record,
/// the undo's record replacing the second's alone (the mutant that answers
/// the newest record whatever a take-back replaced answers none). Taken back
/// by a second undo, the key is open again: `landed_draft` answers none.
#[test]
fn a_fork_arranged_since_its_draft_landing_is_another_key_landed_with_a_record_of_its_own() {
    let mut w = World::race();
    w.fork(F, "1.0.2", &format!("{D}.1"), vec![run(D, 1, 7)]);
    let (dialer, board, signer) = open(w);
    let session = sign_in(&board, &signer);
    let inputs = Inputs { sides: vec![Side::Fork(a(F))], ..race_inputs() };
    let merged = compose(&board, Some(session.token()), &inputs).expect("composed");
    let first = land(&board, &merged, draft_landing(&session, &signer, None)).expect("landed");
    let Landed::Draft { into: l, record: first_link, .. } = first else { panic!("{first:?}") };
    let first_record = current(&board, Some(&token()), &a(K), &merged.key)
        .expect("the lookup")
        .expect("the record");
    assert_eq!(
        dialer.world().docs[&l.to_string()].runs,
        vec![run(D, 1, 4), run(D, 12, 4), run(D, 5, 3)],
        "L holds the big cat"
    );
    // The forker removes "the " too.
    let edited = dialer.world().change(F, vec![run(D, 5, 3)]);
    let again = compose(&board, Some(session.token()), &inputs).expect("composed again");
    assert_eq!(again.key.stateless(), merged.key.stateless(), "the same composition");
    assert_eq!(
        (merged.key.states.clone(), again.key.states.clone()),
        (vec![(a(F), SideState::Unarranged)], vec![(a(F), SideState::At(edited))]),
        "its states alone differ"
    );
    assert_eq!(again.prior, None, "no record of the new key");
    assert_eq!(m_runs(&again), vec![run(D, 12, 4), run(D, 5, 3)], "big cat");
    let found = landed_draft(&board, Some(session.token()), &a(K), &again.key, ACCOUNT)
        .expect("the lookup");
    assert_eq!(
        found.map(|r| r.link),
        Some(Some(first_link.clone())),
        "the person's own landing, the states ignored"
    );
    assert_eq!(
        replaced(&board, Some(session.token()), &l, &again),
        Ok(vec![Replaced { ordinal: 1, width: 4, origin: a(D), i_start: 1 }]),
        "\"the \", which the new M does not carry"
    );
    dialer.clear();
    let second = land(&board, &again, draft_landing(&session, &signer, Some(l.clone())))
        .expect("landed again");
    let Landed::Draft { into, record: second_link, .. } = second else { panic!("{second:?}") };
    assert_eq!(into, l);
    assert_ne!(second_link, first_link, "a record of its own, never the same landing");
    assert_eq!(appended_record(&dialer)["replaces"], Value::Null, "replacing none");
    let second_record = current(&board, Some(&token()), &a(K), &again.key)
        .expect("the lookup")
        .expect("the record");
    assert_eq!(second_record.link, Some(second_link.clone()));
    assert_eq!(verify(&board, Some(&token()), &second_record), Ok(Verdict::Equal));
    assert_eq!(
        verify(&board, Some(&token()), &first_record),
        Ok(Verdict::SideMoved {
            side: a(F),
            recorded: SideState::Unarranged,
            now: Some(edited)
        })
    );
    assert_eq!(
        landed_draft(&board, Some(session.token()), &a(K), &merged.key, ACCOUNT)
            .expect("the lookup")
            .and_then(|r| r.link),
        Some(second_link),
        "the newest, whatever key it is looked up by"
    );
    let undone = undo(&board, merger(&session, &signer), &l, &a(K), None, None).expect("undone");
    assert_eq!(
        undone.marker.and_then(|m| m.at),
        first_record.landed.as_ref().and_then(|landed| match landed {
            RecordLanding::Draft { position, .. } => Some(*position),
            RecordLanding::Member { .. } => None,
        }),
        "the premise: the first landing's marker put back in L"
    );
    assert_eq!(
        landed_draft(&board, Some(session.token()), &a(K), &again.key, ACCOUNT)
            .expect("the lookup")
            .and_then(|r| r.link),
        Some(first_link),
        "the first landing standing again, its record named"
    );
    undo(&board, merger(&session, &signer), &l, &a(K), None, None).expect("undone again");
    assert_eq!(
        landed_draft(&board, Some(session.token()), &a(K), &again.key, ACCOUNT),
        Ok(None),
        "both taken back: the key open"
    );
}

/// The scripted board judges `set_arrangement` in the store's order.
///
/// A head's registration is asked on every draft, ahead of its chain,
/// its extent and the fork gate, and is all a plain draft's head meets;
/// a base's follows `no_base_to_record`, ahead of its chain and its
/// extent (wire.md §Arrangement) — cell by cell over the staged draft
/// `S`, the merger's fork of `D.1` and a plain draft. Every refused
/// frame carries a run of no value, so `dangling_source` answers where
/// no judgment ahead of the runs spoke, and leaves the feed, the draft
/// and its base as they stood; the admitted frames, last, commit once
/// each and record no base.
#[test]
fn the_scripted_board_judges_set_arrangement_as_the_store_does() {
    let (plain, fork) = ("1.0.1.0.67", "1.0.1.0.69");
    let mut w = draft_landing_world();
    w.doc(plain, false, ACCOUNT, Vec::new());
    w.fork(fork, ACCOUNT, &format!("{D}.1"), vec![run(D, 1, 7)]);
    let v1: &str = &format!("{D}.1");
    let v2: &str = &format!("{D}.2");
    // Addresses no mint made: a member, a daughter and a document.
    let no_member: &str = &format!("{D}.9");
    let no_daughter: &str = &format!("{D}.1.9");
    let no_document = "1.0.1.0.99";
    let cells = [
        // `S`, whose chain is `D`'s: the head's three checks, then the
        // base's.
        (S, Some((no_member, 0)), Some((v1, 11)), "source_not_registered"),
        (S, Some((no_document, 99)), None, "source_not_registered"),
        (S, Some((Z, 5)), None, "base_not_in_chain"),
        (S, Some((v2, 16)), None, "base_extent_too_large"),
        (S, None, Some((no_daughter, 0)), "source_not_registered"),
        (S, None, Some((no_document, 99)), "source_not_registered"),
        (S, None, Some((Z, 5)), "base_not_in_chain"),
        (S, None, Some((v1, 12)), "base_extent_too_large"),
        // The fork, whose chain is its source's: the head judged ahead
        // of the gate.
        (fork, Some((no_member, 0)), None, "source_not_registered"),
        (fork, Some((D, 99)), None, "base_extent_too_large"),
        (fork, Some((v2, 15)), None, "fork_base_moved"),
        // The plain draft, with no chain: the head's registration
        // alone, ahead of the base's `no_base_to_record`.
        (plain, Some((no_member, 5)), None, "source_not_registered"),
        (plain, Some((no_document, 99)), Some((v2, 15)), "source_not_registered"),
        (plain, Some((v2, 99)), None, "dangling_source"),
        (plain, None, Some((no_document, 99)), "no_base_to_record"),
    ];
    let dangling = [frames::shot_run(D, &i_addr(&a(D), 99), 1)];
    for (doc, head, base, code) in cells {
        let cell = format!("{doc}, head {head:?}, base {base:?}");
        let before = (w.rows.len(), w.docs[doc].runs.clone(), w.standing(doc));
        let frame = frames::set_arrangement(doc, &dangling, w.position, head, base, None, None);
        let answer = w.set_arrangement(&frame);
        assert_eq!(answer["code"].as_str(), Some(code), "{cell}: {answer}");
        assert_eq!(
            (w.rows.len(), w.docs[doc].runs.clone(), w.standing(doc)),
            before,
            "{cell}: nothing written"
        );
    }
    // Admitted: the trunk's head told where the head named is not it,
    // and no base or marker recorded for a draft that records none.
    let whole = [frames::shot_run(D, &i_addr(&a(D), 1), 11)];
    for (doc, head, told) in
        [(plain, (v2, 99), None), (plain, (v1, 11), Some(v2)), (fork, (v1, 11), Some(v2))]
    {
        let cell = format!("{doc}, head {head:?}");
        let rows = w.rows.len();
        let frame =
            frames::set_arrangement(doc, &whole, w.position, Some(head), None, None, None);
        let answer = w.set_arrangement(&frame);
        assert_eq!(
            (answer["resp"].as_str(), answer["head_moved"].as_str()),
            (Some("ack"), told),
            "{cell}: {answer}"
        );
        assert_eq!(w.rows.len(), rows + 1, "{cell}: one commit");
        assert_eq!(
            (w.docs[doc].runs.clone(), w.standing(doc)),
            (vec![run(D, 1, 11)], (None, None)),
            "{cell}: the runs placed, nothing recorded"
        );
    }
}

/// A fresh draft is staged and landed in, and a re-run stages nothing.
///
/// With no draft named (R3 (i)), `stage {from: the head}` goes under the
/// id `<stem>.stage`, its stem over `<key>@<P>`, then the one write into
/// the staged draft typed against the stage's position, the base sent —
/// the stage recorded one — and the merge's side; two commits, the state
/// between a plain staged draft, the landing `staged`. Over the same
/// `merged` the landing's own record, read at the landing before any
/// stage, answers it: nothing twice, nothing staged, `staged` false.
/// Composed again, the merger's newest record for the key, read at the
/// landing, names the landing: it is reported, and nothing is staged or
/// written; and the same record answers a `resume` over the composition
/// that landed it, whose `prior` predates it.
#[test]
fn a_fresh_draft_is_staged_from_the_head_then_landed_in_and_a_re_run_stages_nothing() {
    let (dialer, board, signer) = open(draft_landing_world());
    let session = sign_in(&board, &signer);
    let merged = compose(&board, Some(session.token()), &draft_inputs()).expect("composed");
    dialer.clear();
    let landed = land(&board, &merged, draft_landing(&session, &signer, None)).expect("landed");
    let Landed::Draft { into: fresh, position, record, head_moved, staged } = &landed else { panic!("{landed:?}") };
    assert_eq!((fresh.to_string(), head_moved.clone(), *staged), ("1.0.1.0.72".to_string(), None, true), "the fresh draft minted");
    let ops = dialer.ops();
    let writes: Vec<&str> = ops.iter().map(String::as_str).filter(|o| ["stage", "set_arrangement", "insert", "make_link", "create_new_document"].contains(o)).collect();
    assert_eq!(writes, ["stage", "set_arrangement", "create_new_document", "insert", "make_link"], "{ops:?}");
    let stage = &dialer.frames("stage")[0];
    assert_eq!(stage, &json!({"op": "stage", "from": format!("{D}.2"), "id": landing_id(&format!("{}@{}", merged.key.text(), merged.as_of), "stage")}));
    let stage_at = dialer.world().rows.iter().find(|r| r.op == "stage").unwrap().at;
    let frame = &dialer.frames("set_arrangement")[0];
    assert_eq!(frame["doc"].as_str(), Some(fresh.to_string().as_str()));
    assert_eq!(frame["as_of"].as_u64(), Some(stage_at), "typed against the stage's position: {frame}");
    assert_eq!(frame["id"].as_str(), Some(landing_id(&format!("{}:{fresh}@{stage_at}", merged.key.text()), "draft").as_str()), "the fresh draft and the stage's position");
    assert_eq!(frame["base"], json!({"at": format!("{D}.2"), "extent": "15"}), "the stage recorded a base, so it is re-recorded");
    assert_eq!(frame["merge"], json!({"sides": [S]}));
    assert!(
        dialer.frames("doc_metadata").iter().any(|f| f["doc"] == fresh.to_string()) && ops.iter().all(|o| !o.starts_with("at:")),
        "the fresh draft's base read as it stands, nothing at a position: {ops:?}"
    );
    let w = dialer.world();
    assert_eq!(w.docs.get(&fresh.to_string()).unwrap().runs, draft_m());
    assert_eq!(
        w.standing(&fresh.to_string()),
        (Some((format!("{D}.2"), 15)), Some(Marker { sides: vec![S.to_string()], head: format!("{D}.2"), head_copied: 15, at: *position }))
    );
    assert_eq!(*position, w.rows.iter().find(|r| r.op == "set_arrangement").unwrap().at);
    let rows = w.rows.len();
    drop(w);
    // The same `merged` again: the landing's own record answers it before
    // any stage, nothing twice and nothing staged.
    dialer.clear();
    assert_eq!(land(&board, &merged, draft_landing(&session, &signer, None)).expect("landed again"), as_found(&landed));
    assert!(dialer.frames("stage").is_empty(), "nothing staged: {:?}", dialer.ops());
    assert_eq!(dialer.world().rows.len(), rows, "nothing written twice");
    // Composed again: the merger's newest record, read at the landing,
    // names the landing — reported, nothing staged, nothing written.
    let again = compose(&board, Some(session.token()), &draft_inputs()).expect("composed again");
    assert_eq!(again.prior.as_ref().and_then(|p| p.link.clone()), Some(record.clone()));
    dialer.clear();
    assert_eq!(
        land(&board, &again, draft_landing(&session, &signer, None)).expect("landed"),
        Landed::Draft { into: fresh.clone(), position: *position, record: record.clone(), head_moved: None, staged: false }
    );
    let ops = dialer.ops();
    assert!(ops.iter().all(|o| !["stage", "set_arrangement", "create_new_document", "insert", "make_link"].contains(&o.as_str())), "nothing staged, nothing written: {ops:?}");
    assert!(ops.contains(&"find_links_ftt".to_string()), "the record read at the landing: {ops:?}");
    assert_eq!(dialer.world().rows.len(), rows);
    assert_eq!(resume(&board, &again, draft_landing(&session, &signer, None)).expect("resumed"), Some(as_found(&landed)));
    // The composition that landed it: its `prior` predates the landing,
    // and the record read at the landing answers it.
    assert_eq!(merged.prior, None, "the premise: composed before its landing");
    assert_eq!(resume(&board, &merged, draft_landing(&session, &signer, None)).expect("resumed"), Some(as_found(&landed)));
}

/// A landing found standing is read at the head while its draft is unchanged
/// since it: the draft's `arranged_at` is the landing's own position, so its
/// image at the head is the state the landing left, kept where the draft's
/// `doc_metadata`, read again after the image, still names that position —
/// no past state rebuilt, no `/op-at` read. An edit landing in the draft just
/// before that head image moves `arranged_at`, so the draft is read as of the
/// landing through `/op-at` and the landing is still found; and every read
/// after the edit reads it so. The mutant that never reads at the head sends
/// an `/op-at` read at the first `resume`; the one that keeps the head image
/// without the second `doc_metadata` answers no landing at the second.
#[test]
fn a_landing_found_standing_is_read_at_the_head_while_its_draft_is_unchanged() {
    let (dialer, board, signer) = open(draft_landing_world());
    let session = sign_in(&board, &signer);
    let merged = compose(&board, Some(session.token()), &draft_inputs()).expect("composed");
    let landed = land(&board, &merged, draft_landing(&session, &signer, None)).expect("landed");
    let Landed::Draft { into, position, .. } = &landed else {
        panic!("{landed:?}")
    };
    let fresh = into.to_string();
    dialer.clear();
    assert_eq!(
        resume(&board, &merged, draft_landing(&session, &signer, None)),
        Ok(Some(as_found(&landed)))
    );
    assert!(
        dialer.ops().iter().all(|o| !o.starts_with("at:")),
        "no past state rebuilt: {:?}",
        dialer.ops()
    );
    let head_image = {
        let served = dialer.served.lock().unwrap();
        1 + served
            .iter()
            .position(|(line, f)| line == "retrieve_doc_v_span_set" && f["doc"] == fresh)
            .expect("the draft read at the head")
    };
    dialer.world().interleave = Some((head_image, fresh.clone(), vec![run(D, 1, 4), run(D, 12, 4), run(D, 5, 7)]));
    dialer.clear();
    assert_eq!(
        resume(&board, &merged, draft_landing(&session, &signer, None)),
        Ok(Some(as_found(&landed)))
    );
    assert_eq!(dialer.positions("image"), [*position], "read as of the landing: {:?}", dialer.ops());
    dialer.clear();
    assert_eq!(
        resume(&board, &merged, draft_landing(&session, &signer, None)),
        Ok(Some(as_found(&landed)))
    );
    assert_eq!(
        dialer.positions("image"),
        [*position],
        "read as of the landing again: {:?}",
        dialer.ops()
    );
}

/// A landing whose list cannot be read back is never made a second time.
///
/// The draft landing's merge lands in a fresh draft `N`, its record
/// written; `N` is edited and the board reclaims its history past the
/// landing. The list the landing placed cannot be read back, and `N` as it
/// stands holds other words, which tell nothing of it. (a) A fresh landing
/// of the same composition answers that landing at its mark, and so does a
/// `resume` naming no draft; (b) a `resume` naming `N` answers it with its
/// record — each nothing staged or written (the `land` module's doc, **A
/// fresh landing found standing**). The mutant that reads `N` as it stands
/// in the reclaimed state's place stages a second draft at (a) and answers
/// no landing at (b).
#[test]
fn a_landing_whose_list_cannot_be_read_back_is_never_made_a_second_time() {
    let writes = ["stage", "set_arrangement", "create_new_document", "insert", "make_link"];
    let (dialer, board, signer) = open(draft_landing_world());
    let session = sign_in(&board, &signer);
    let merged = compose(&board, Some(session.token()), &draft_inputs()).expect("composed");
    let landed = land(&board, &merged, draft_landing(&session, &signer, None)).expect("landed");
    let Landed::Draft { into, position, .. } = &landed else { panic!("{landed:?}") };
    {
        let mut w = dialer.world();
        let edited = w.change(&into.to_string(), vec![run(D, 1, 4), run(D, 12, 4)]);
        w.floor = Some(edited);
    }
    let rows = dialer.world().rows.len();
    dialer.clear();
    let fresh = || draft_landing(&session, &signer, None);
    assert_eq!(land(&board, &merged, fresh()), Ok(as_found(&landed)), "(a): the landing");
    assert_eq!(resume(&board, &merged, fresh()), Ok(Some(as_found(&landed))), "(a): resumed");
    assert_eq!(
        resume(&board, &merged, draft_landing(&session, &signer, Some(into.clone()))),
        Ok(Some(as_found(&landed))),
        "(b): resumed naming N"
    );
    let ops = dialer.ops();
    assert!(ops.iter().all(|o| !writes.contains(&o.as_str())), "nothing staged or written: {ops:?}");
    assert_eq!(dialer.world().rows.len(), rows, "nothing committed");
    assert!(
        dialer.positions("retrieve_doc_v_span_set").contains(position),
        "the premise: N asked as of the landing, and refused: {ops:?}"
    );
}
