//! The withdrawal over the scripted board, and either take-back's record.
//!
//! The suite checks `withdraw`: the marker cleared and the runs and the base
//! kept in one frame, the draft read at the head; refused after an edit
//! since its read; read again as of its read where the draft changed while
//! it was imaged; nothing to take out at no marker. It checks the
//! `replaces` record each take-back writes where a record stands, and none
//! where none stands; a re-run of either writing nothing twice; and a
//! withdrawal taken back — the marker put back and the next undo taking the
//! landing back, typed at the landing or refused where another hand edited
//! after it, and nothing to undo past a landing, a publication, or a
//! put-back taken out again. And it checks the words a withdrawal and its
//! undo keep: a member's own word sent under the member's chain, no
//! correspondence record read by the withdrawal, another account's words
//! sent by its undo as their owner published them, a write that changed a
//! member's word for the trunk's naming no withdrawal and leaving the next
//! undo typed at the landing, and both refused at the cap counted on the
//! runs they would write. And it checks the withdrawal's undo writing the
//! landing's record again past newer records naming the draft as a side, a
//! sub-account's and the merger's own.

use super::*;

/// THE WITHDRAWAL (ruled 1 (a); skep #783): the draft's `doc_metadata`
/// read live, its image read at the head and held to that read's position
/// by its `arranged_at`, read again after the image — nothing read through
/// `/op-at` — and ONE `set_arrangement` — no change named, the draft's
/// words standing as read, `as_of` the read's position, the recorded base
/// re-sent unmoved (address and extent as read), no `head`, no `merge`, the
/// id naming the draft and the position — so the marker is cleared and the
/// draft's words and base stay as they are; the replacing record follows
/// (the mutant that sends the image back as one change over every position
/// names four runs).
#[test]
fn the_withdrawal_clears_the_marker_and_keeps_the_runs_and_the_base_in_one_frame() {
    let (dialer, board, signer) = open(draft_landing_world());
    let session = sign_in(&board, &signer);
    let (_, landed) = landed_in_s(&board, &session, &signer);
    let (at, link) = landing_of(&landed);
    let read_at = dialer.world().position;
    dialer.clear();
    let withdrawn = withdraw(&board, merger(&session, &signer), &a(S), &a(K), None).expect("withdrawn");
    assert_eq!(withdrawn.draft, a(S));
    assert!(withdrawn.position > at);
    let replacing = withdrawn.record.clone().expect("a record stood, so one replaces it");
    assert_ne!(replacing, link);
    let ops = dialer.ops();
    let write = ops.iter().position(|o| o == "set_arrangement").expect("the write");
    assert_eq!(
        ops[..write],
        ["doc_metadata", "retrieve_doc_v_span_set", "image", "doc_metadata"],
        "the metadata, the image and the metadata again, every one at the head"
    );
    let frames = dialer.frames("set_arrangement");
    assert_eq!(frames.len(), 1, "one write: {:?}", dialer.ops());
    let frame = &frames[0];
    assert_eq!(frame["doc"], S);
    assert_eq!(frame["as_of"].as_u64(), Some(read_at), "typed against the read's position: {frame}");
    assert_eq!(frame["changes"], json!([]), "no change named: the words stand as read, and the frame names no run of them: {frame}");
    assert!(frame.get("runs").is_none(), "no whole list beside the changes: {frame}");
    assert_eq!(frame["base"], json!({"at": format!("{D}.2"), "extent": "15"}), "the recorded base re-sent unmoved");
    assert!(frame.get("head").is_none() && frame.get("merge").is_none(), "no head, no merge: {frame}");
    assert_eq!(frame["id"].as_str(), Some(format!("withdraw:{S}:{read_at}.arrangement").as_str()));
    let w = dialer.world();
    assert_eq!(w.docs.get(S).unwrap().runs, draft_m(), "the words stay");
    assert_eq!(w.standing(S), (Some((format!("{D}.2"), 15)), None), "the base stays, the marker cleared");
    let row = w.rows.iter().rev().find(|r| r.op == "set_arrangement").expect("the withdrawal's row");
    assert_eq!((row.at, &row.terms), (withdrawn.position, &Some((Some(format!("{D}.2")), None))));
    drop(w);
    let atom = appended_record(&dialer);
    assert!(atom["landed"].is_null());
    assert_eq!(atom["replaces"].as_str(), Some(link.to_string().as_str()));
    assert_eq!(dialer.frames("insert")[0]["id"].as_str(), Some(format!("withdraw:{S}:{read_at}.record").as_str()));
    assert_eq!(dialer.frames("make_link")[0]["to"]["addrs"], json!([S]));
}

/// AN EDIT BETWEEN THE WITHDRAWAL's READ AND ITS WRITE: another hand's
/// edit lands before the one write is answered, so the write, typed
/// against the read's position, is refused `arrangement_moved` — its
/// words saying to run it again, since a re-run reads first — the
/// draft as the other hand left it, the marker standing, nothing
/// committed but the edit, no record.
#[test]
fn the_withdrawal_is_refused_arrangement_moved_after_an_edit_since_its_read() {
    // The place of the one write among a withdrawal's requests, off one
    // that lands.
    let n = {
        let (dialer, board, signer) = open(draft_landing_world());
        let session = sign_in(&board, &signer);
        landed_in_s(&board, &session, &signer);
        dialer.clear();
        withdraw(&board, merger(&session, &signer), &a(S), &a(K), None).expect("withdrawn");
        dialer.served_index("set_arrangement")
    };
    let (dialer, board, signer) = open(draft_landing_world());
    let session = sign_in(&board, &signer);
    let (_, landed) = landed_in_s(&board, &session, &signer);
    let (at, _) = landing_of(&landed);
    let edited = vec![run(D, 1, 4), run(D, 12, 4), run(D, 5, 7)];
    let (rows, read_at) = {
        let w = dialer.world();
        (w.rows.len(), w.position)
    };
    dialer.clear();
    dialer.world().interleave = Some((n, S.to_string(), edited.clone()));
    let err = withdraw(&board, merger(&session, &signer), &a(S), &a(K), None).expect_err("the draft changed since the read");
    assert!(dialer.world().interleave.is_none(), "the premise: the edit landed before the write was answered");
    let Refusal::Halt(Halt::Refused(refused)) = &err else { panic!("{err:?}") };
    assert_eq!(refused.code, "arrangement_moved");
    let detail = refused.detail.as_deref().expect("the person's words");
    assert!(detail.contains(S) && detail.contains("changed since it was read") && detail.contains("nothing was changed"), "{detail}");
    assert!(detail.contains("run this again, which reads the draft as it stands"), "{detail}");
    let frame = &dialer.frames("set_arrangement")[0];
    assert_eq!(frame["as_of"].as_u64(), Some(read_at), "typed against the read's position: {frame}");
    assert_eq!(frame["changes"], json!([]), "no change named: {frame}");
    let w = dialer.world();
    assert_eq!(w.docs.get(S).unwrap().runs, edited, "the other hand's edit stands");
    assert_eq!(w.rows.len(), rows + 1, "the edit's commit alone");
    assert_eq!(w.standing(S), (Some((format!("{D}.2"), 15)), Some(Marker { sides: vec![], head: format!("{D}.2"), head_copied: 15, at })), "the marker stands");
    drop(w);
    assert!(dialer.frames("insert").is_empty() && dialer.frames("make_link").is_empty(), "no record");
}

/// THE WITHDRAWAL READS AT THE HEAD, AND FALLS BACK WHERE THE DRAFT
/// CHANGED: another hand's edit — one run past the cap — lands just before
/// the head image is answered, so the `doc_metadata` read after the image
/// names another `arranged_at`, and the draft is read again as of the first
/// read's position through `/op-at`: the one frame names the image as it
/// stood there, M, typed against that position, and the board refuses it
/// `arrangement_moved`, the edit standing, the marker standing, no record.
/// The mutant keeping the head image without the second read reads nothing
/// at the position.
#[test]
fn a_withdrawal_reads_at_the_head_and_falls_back_where_the_draft_changed() {
    // The place of the head image among a withdrawal's requests, off one
    // that lands.
    let n = {
        let (dialer, board, signer) = open(draft_landing_world());
        let session = sign_in(&board, &signer);
        landed_in_s(&board, &session, &signer);
        dialer.clear();
        withdraw(&board, merger(&session, &signer), &a(S), &a(K), None).expect("withdrawn");
        dialer.served_index("image")
    };
    let (dialer, board, signer) = open(draft_landing_world());
    let session = sign_in(&board, &signer);
    let (_, landed) = landed_in_s(&board, &session, &signer);
    let (at, _) = landing_of(&landed);
    let read_at = dialer.world().position;
    dialer.clear();
    dialer.world().interleave = Some((n, S.to_string(), alternating()));
    let err = withdraw(&board, merger(&session, &signer), &a(S), &a(K), None).expect_err("the draft changed after the read");
    assert!(dialer.world().interleave.is_none(), "the premise: the edit landed before the head image was answered");
    let Refusal::Halt(Halt::Refused(refused)) = &err else { panic!("{err:?}") };
    assert_eq!(refused.code, "arrangement_moved");
    assert_eq!(dialer.positions("image"), [read_at], "the draft read again as of the first read: {:?}", dialer.ops());
    let frame = &dialer.frames("set_arrangement")[0];
    assert_eq!(frame["as_of"].as_u64(), Some(read_at), "typed against the read's position: {frame}");
    assert_eq!(frame["changes"], json!([]), "no change named, whatever the draft holds since: {frame}");
    let w = dialer.world();
    assert_eq!(w.docs.get(S).unwrap().runs, alternating(), "the other hand's edit stands");
    assert_eq!(w.standing(S).1.map(|m| m.at), Some(at), "the marker stands");
    drop(w);
    assert!(dialer.frames("insert").is_empty() && dialer.frames("make_link").is_empty(), "no record");
}

/// NO MARKER: a withdrawal of a draft carrying no merge has nothing to
/// take out, with nothing sent — the one read is the draft's metadata.
#[test]
fn the_withdrawal_at_no_marker_answers_nothing_to_take_out() {
    let (dialer, board, signer) = open(draft_landing_world());
    let session = sign_in(&board, &signer);
    let rows = dialer.world().rows.len();
    dialer.clear();
    let err = withdraw(&board, merger(&session, &signer), &a(S), &a(K), None).expect_err("no merge");
    assert_eq!(err, Refusal::NoMerge { draft: a(S) });
    assert_eq!(err.to_string(), format!("{S} carries no merge: nothing to undo, nothing to take out"));
    assert_eq!(dialer.ops(), ["doc_metadata"], "the one read, at the head; nothing sent");
    assert_eq!(dialer.world().rows.len(), rows);
}

/// THE RECORD (the operator's choice): each call writes a record
/// composed from the current one naming the draft as landed in —
/// `landed` none, `replaces` its link, the sides and the base the
/// landing's — and writes none where none stands, the act standing all
/// the same: a landing made by hand with no record is undone and
/// withdrawn with no `insert` and no `make_link`, the links of the kind
/// to the draft read first.
#[test]
fn each_call_writes_the_replaces_record_where_a_record_stands_and_none_where_none_stands() {
    let (dialer, board, signer) = open(draft_landing_world());
    let session = sign_in(&board, &signer);
    let m = merger(&session, &signer);
    let (merged, landed) = landed_in_s(&board, &session, &signer);
    let (_, link) = landing_of(&landed);
    dialer.clear();
    let withdrawn = withdraw(&board, m, &a(S), &a(K), None).expect("withdrawn");
    let atom = appended_record(&dialer);
    let landing_record = merged.record.to_value();
    assert!(atom["landed"].is_null() && landing_record["landed"].is_null(), "{atom}");
    assert_eq!(atom["replaces"].as_str(), Some(link.to_string().as_str()), "the landing's link replaced");
    for member in ["type", "v", "doc", "base", "sides", "runs", "gaps", "values"] {
        assert_eq!(atom[member], landing_record[member], "`{member}` the landing's: {atom}");
    }
    let links = dialer.frames("make_link");
    assert_eq!(links[0]["to"]["addrs"], json!([S]), "linked to the draft");
    assert!(withdrawn.record.is_some(), "the link written is answered");
    assert_eq!(
        links[0]["home"],
        dialer.frames("insert")[0]["doc"],
        "homed in the journal beside the atom"
    );
    assert!(
        links[0].get("attest").is_none(),
        "a private journal's link, unsigned: {}",
        links[0]
    );
    // A landing by hand on a board holding no record of the kind: the
    // undo and the withdrawal write none, the links of the kind to the
    // draft read first.
    let (dialer, board, signer) = open(draft_landing_world());
    let session = sign_in(&board, &signer);
    let m = merger(&session, &signer);
    let head = format!("{D}.2");
    for (act, name) in [("undo", "the undo"), ("withdraw", "the withdrawal")] {
        let typed = dialer.world().position;
        let frame = frames::set_arrangement(S, &whole_of(&dialer, S, &draft_m()), typed, Some((&head, 15)), Some((&head, 15)), Some((&[], None)), None);
        let Answer::Document(ack) = board.op(Some(session.token()), &frame).expect("the landing by hand") else { panic!("closed") };
        assert_eq!(ack["resp"], "ack", "{name}: {ack}");
        assert!(dialer.world().standing(S).1.is_some(), "{name}: the premise, the marker stands");
        let rows = dialer.world().rows.len();
        dialer.clear();
        let record = match act {
            "undo" => undo(&board, m, &a(S), &a(K), None, None).expect("undone").record,
            _ => withdraw(&board, m, &a(S), &a(K), None).expect("withdrawn").record,
        };
        assert_eq!(record, None, "{name}: no record stood, none written");
        assert!(dialer.frames("set_arrangement").len() == 1, "{name}: the act stands: {:?}", dialer.ops());
        assert!(dialer.ops().contains(&"find_links_ftt".to_string()), "{name}: the links of the kind to the draft read: {:?}", dialer.ops());
        assert!(dialer.frames("insert").is_empty() && dialer.frames("make_link").is_empty() && dialer.frames("create_new_document").is_empty(), "{name}: nothing of a record: {:?}", dialer.ops());
        assert_eq!(dialer.world().rows.len(), rows + 1, "{name}: the one write alone");
        assert!(dialer.world().standing(S).1.is_none(), "{name}: the marker cleared");
    }
}

/// A RE-RUN OF EITHER WRITES NOTHING TWICE: after an undo the draft
/// records a base and no marker, and its latest marker-ending row is
/// the undo's — nothing to undo, the merge already taken back; after a
/// withdrawal the draft carries no marker — nothing to take out. Each
/// re-run sends nothing and commits nothing.
#[test]
fn a_re_run_of_either_take_back_writes_nothing_twice() {
    let (dialer, board, signer) = open(draft_landing_world());
    let session = sign_in(&board, &signer);
    let m = merger(&session, &signer);
    landed_in_s(&board, &session, &signer);
    undo(&board, m, &a(S), &a(K), None, None).expect("undone");
    let rows = dialer.world().rows.len();
    dialer.clear();
    let err = undo(&board, m, &a(S), &a(K), None, None).expect_err("already taken back");
    assert_eq!(err, Refusal::NothingToUndo { draft: a(S), why: NoUndo::TakenBack });
    assert_eq!(err.to_string(), format!("nothing to undo: the merge in {S} was already taken back"));
    assert!(dialer.frames("set_arrangement").is_empty() && dialer.frames("insert").is_empty(), "nothing sent: {:?}", dialer.ops());
    assert!(dialer.positions("doc_metadata").is_empty(), "no read of history");
    assert_eq!(dialer.world().rows.len(), rows, "nothing written twice");
    // Landed again in this session — a landing of its own — and
    // withdrawn: a second withdrawal finds no merge.
    landed_in_s(&board, &session, &signer);
    withdraw(&board, m, &a(S), &a(K), None).expect("withdrawn");
    let rows = dialer.world().rows.len();
    dialer.clear();
    assert_eq!(withdraw(&board, m, &a(S), &a(K), None), Err(Refusal::NoMerge { draft: a(S) }));
    assert_eq!(undo(&board, m, &a(S), &a(K), None, None), Err(Refusal::NothingToUndo { draft: a(S), why: NoUndo::TakenBack }), "an undo after a withdrawal: taken back");
    assert!(dialer.frames("set_arrangement").is_empty() && dialer.frames("insert").is_empty(), "{:?}", dialer.ops());
    assert_eq!(dialer.world().rows.len(), rows, "nothing written twice");
}

/// A withdrawal taken back puts the marker back (skep #870).
///
/// B3-S11, D6 BM-36: after a landing and its withdrawal, the landing's
/// position named as a
/// withdrawal is refused `NoWithdrawal`, nothing sent; the withdrawal's
/// position takes it back — the draft's rows walked from the withdrawal,
/// never from the floor (the mutant walking from 0 asks `since=0`), then
/// ONE `set_arrangement` of the draft's words,
/// its base re-sent, the head pair and the marker's sides with the
/// landing's own `at`, typed against the withdrawal — and the draft's
/// base and marker stand as the landing left them, the landing's record
/// written again; a second run sends nothing; and the undo after it,
/// with no `own_ack` as the command's (skep #964), finds the put-back on
/// the draft's feed rows past the landing, reads the draft at the two
/// writes, and is typed against the put-back: ONE frame of C with the
/// old base and no merge, the draft holding C, its base as it stood
/// before the merge and no marker, the record replacing the landing's.
#[test]
fn a_withdrawal_taken_back_puts_the_marker_back_and_the_next_undo_takes_the_landing_back() {
    let (dialer, board, signer) = open(draft_landing_world());
    let session = sign_in(&board, &signer);
    let m = merger(&session, &signer);
    let staged = dialer.world().standing(S);
    landed_in_s(&board, &session, &signer);
    let landed = dialer.world().standing(S);
    let marker = landed.1.clone().expect("the premise: the landing's marker");
    let withdrawn = withdraw(&board, m, &a(S), &a(K), None).expect("withdrawn");
    assert!(dialer.world().standing(S).1.is_none(), "the premise: the marker cleared");
    dialer.clear();
    assert_eq!(
        unwithdraw(&board, m, &a(S), &a(K), marker.at, None, None),
        Err(Refusal::NoWithdrawal { draft: a(S), at: marker.at }),
        "the landing's position is no withdrawal"
    );
    assert!(dialer.frames("set_arrangement").is_empty(), "nothing sent: {:?}", dialer.ops());
    dialer.clear();
    let read_at = dialer.world().position;
    let unwithdrawn = unwithdraw(&board, m, &a(S), &a(K), withdrawn.position, None, None).expect("the withdrawal taken back");
    let past = dialer.positions("image");
    assert!(
        past.len() == 2 && !past.contains(&read_at),
        "the draft at the withdrawal and before it alone, its words as they stand read at the head: {:?}",
        dialer.ops()
    );
    let walks: Vec<String> = dialer
        .ops()
        .into_iter()
        .filter(|o| o.starts_with("GET /changes?") && o.contains(&format!("under={S}&")))
        .collect();
    assert!(
        !walks.is_empty()
            && walks.iter().all(|o| o.contains(&format!("?since={}&", withdrawn.position - 1))),
        "the draft's rows walked from the withdrawal, never from the floor: {walks:?}"
    );
    let sent = dialer.frames("set_arrangement");
    assert_eq!(sent.len(), 1, "one write: {:?}", dialer.ops());
    assert_eq!(sent[0]["merge"], json!({"sides": [], "at": marker.at}), "the marker's sides and its own position: {}", sent[0]);
    assert_eq!(sent[0]["head"], json!({"at": marker.head, "extent": marker.head_copied.to_string()}));
    assert_eq!(sent[0]["as_of"], json!(withdrawn.position), "typed against the withdrawal");
    assert_eq!(dialer.world().standing(S), landed, "the base and the marker as the landing left them");
    assert!(unwithdrawn.record.is_some(), "the landing's record written again");
    let atom = appended_record(&dialer);
    assert_eq!(atom["landed"]["draft"], json!(S), "the record names the draft as landed in: {atom}");
    dialer.clear();
    assert_eq!(
        unwithdraw(&board, m, &a(S), &a(K), withdrawn.position, None, None),
        Err(Refusal::NothingToUndo { draft: a(S), why: NoUndo::Remarked }),
        "a second run finds the merge standing"
    );
    assert!(dialer.frames("set_arrangement").is_empty() && dialer.frames("insert").is_empty(), "nothing sent: {:?}", dialer.ops());
    dialer.clear();
    let undone = undo(&board, m, &a(S), &a(K), None, None).expect("the landing taken back");
    let ops = dialer.ops();
    assert!(
        ops.iter().any(|o| o.starts_with("GET /changes?")
            && o.contains(&format!("?since={}&", marker.at))
            && o.contains(&format!("under={S}"))),
        "the put-back off the draft's own rows past the landing: {ops:?}"
    );
    assert_eq!(
        dialer.positions("image"),
        [marker.at - 2, marker.at, unwithdrawn.position],
        "C, then the draft at the landing and at the put-back: {ops:?}"
    );
    let sent = dialer.frames("set_arrangement");
    assert_eq!(sent.len(), 1, "one write: {ops:?}");
    assert_eq!(
        sent[0]["as_of"],
        json!(unwithdrawn.position),
        "typed against the put-back: {}",
        sent[0]
    );
    assert_eq!(sent[0]["changes"], whole_changes(width_of(&draft_m()), &draft_c()), "C, read before the landing, over every position the draft holds");
    assert!(
        sent[0].get("head").is_none() && sent[0].get("merge").is_none(),
        "no marker before the landing, none put back: {}",
        sent[0]
    );
    assert_eq!(
        (undone.position, undone.marker),
        (
            dialer.world().rows.iter().rev().find(|r| r.op == "set_arrangement").unwrap().at,
            None
        )
    );
    assert_eq!(dialer.world().docs.get(S).unwrap().runs, draft_c(), "C again");
    assert_eq!(dialer.world().standing(S), staged, "the draft's base as before the merge, no marker");
    assert_eq!(
        appended_record(&dialer)["replaces"].as_str(),
        unwithdrawn.record.as_ref().map(|r| r.to_string()).as_deref(),
        "the landing's record written again, replaced"
    );
}

/// An undo after a withdrawal's undo meets another hand's edit past it.
///
/// Skep #964: the undo, with no `own_ack`, is typed against the
/// put-back, so another hand's edit after it refuses the undo
/// `arrangement_moved` — its words naming the put-back, the edit's
/// position and the landing's — and nothing is changed, the edit, the
/// base and the marker standing, no record written.
#[test]
fn an_undo_typed_past_a_put_back_is_refused_where_another_hand_edited_after_it() {
    let (dialer, board, signer) = open(draft_landing_world());
    let session = sign_in(&board, &signer);
    let m = merger(&session, &signer);
    let (_, landed) = landed_in_s(&board, &session, &signer);
    let (at, _) = landing_of(&landed);
    let withdrawn = withdraw(&board, m, &a(S), &a(K), None).expect("withdrawn");
    let back = unwithdraw(&board, m, &a(S), &a(K), withdrawn.position, None, None)
        .expect("put back")
        .position;
    let edited = vec![run(D, 1, 4), run(D, 12, 4), run(D, 5, 7)];
    let edit_at = dialer.world().change(S, edited.clone());
    let (rows, standing) = {
        let w = dialer.world();
        (w.rows.len(), w.standing(S))
    };
    dialer.clear();
    let err = undo(&board, m, &a(S), &a(K), None, None)
        .expect_err("another hand's edit past the put-back");
    let Refusal::Halt(Halt::Refused(refused)) = &err else { panic!("{err:?}") };
    assert_eq!(refused.code, "arrangement_moved");
    assert_eq!(
        dialer.frames("set_arrangement")[0]["as_of"],
        json!(back),
        "typed against the put-back"
    );
    let detail = refused.detail.as_deref().expect("the person's words");
    assert!(detail.contains(&format!("{S} changed since the merge was put back (the merge was put back at position {back}, the draft changed at {edit_at}), after it landed at position {at}")), "{detail}");
    assert!(
        detail.contains("nothing was changed")
            && detail.contains("an undo typed against the merge's put-back can no longer land")
            && detail.contains("edit the draft as it stands"),
        "{detail}"
    );
    let w = dialer.world();
    assert_eq!(w.docs.get(S).unwrap().runs, edited, "the other hand's edit stands");
    assert_eq!(
        (w.rows.len(), w.standing(S)),
        (rows, standing),
        "nothing committed, the base and the marker as they stood"
    );
    drop(w);
    assert!(
        dialer.frames("insert").is_empty() && dialer.frames("make_link").is_empty(),
        "no record"
    );
}

/// An undo after a withdrawal's undo stays typed at the landing where an
/// edit made before the withdrawal stands in the words.
///
/// Skep #964, P3: another hand edits the landed draft, then the merge is
/// withdrawn and put back, the edit kept in the words. The draft's words
/// at the put-back are not those at the landing, so the undo, with no
/// `own_ack`, is typed against the landing and refused
/// `arrangement_moved`, its words naming the put-back — the edit is
/// never wiped. Typed at the caller's own last ack, the put-back, it
/// lands: the editor's rule.
#[test]
fn an_undo_after_a_put_back_is_typed_at_the_landing_where_an_earlier_edit_stands() {
    let (dialer, board, signer) = open(draft_landing_world());
    let session = sign_in(&board, &signer);
    let m = merger(&session, &signer);
    let (_, landed) = landed_in_s(&board, &session, &signer);
    let (at, _) = landing_of(&landed);
    let edited = vec![run(D, 1, 4), run(D, 12, 4), run(D, 5, 7)];
    dialer.world().change(S, edited.clone());
    let withdrawn = withdraw(&board, m, &a(S), &a(K), None).expect("withdrawn");
    let back = unwithdraw(&board, m, &a(S), &a(K), withdrawn.position, None, None)
        .expect("put back")
        .position;
    assert_eq!(
        dialer.world().docs.get(S).unwrap().runs,
        edited,
        "the premise: the edit kept in the words"
    );
    let rows = dialer.world().rows.len();
    dialer.clear();
    let err =
        undo(&board, m, &a(S), &a(K), None, None).expect_err("the edit stands in the words");
    let Refusal::Halt(Halt::Refused(refused)) = &err else { panic!("{err:?}") };
    assert_eq!(refused.code, "arrangement_moved");
    assert_eq!(
        dialer.frames("set_arrangement")[0]["as_of"],
        json!(at),
        "typed against the landing, never the put-back"
    );
    let detail = refused.detail.as_deref().expect("the person's words");
    assert!(detail.contains(&format!("{S} changed since the merge landed (the merge landed at position {at}, the draft changed at {back}): its words changed before the merge was put back at position {back}")), "{detail}");
    assert!(
        detail.contains("an undo typed against the landing can no longer land"),
        "{detail}"
    );
    assert_eq!(dialer.world().docs.get(S).unwrap().runs, edited, "the edit stands");
    assert_eq!(dialer.world().rows.len(), rows, "nothing committed");
    undo(&board, m, &a(S), &a(K), Some(back), None)
        .expect("typed at the caller's own last ack");
    assert_eq!(dialer.world().docs.get(S).unwrap().runs, draft_c(), "C again");
}

/// A withdrawal's undo past a landing or a publication sends nothing.
///
/// Skep #870, BM-37: the same merge landed again after the withdrawal
/// carries a
/// marker of its own, `Remarked`; a publication of the draft after the
/// withdrawal moved its base, `Published` naming the member the row
/// names first, with the publication's words; and a position the draft's
/// history no longer answers is `HistoryReclaimed`.
#[test]
fn a_withdrawals_undo_finds_nothing_to_undo_past_a_landing_or_a_publication() {
    let (dialer, board, signer) = open(draft_landing_world());
    let session = sign_in(&board, &signer);
    let m = merger(&session, &signer);
    landed_in_s(&board, &session, &signer);
    let withdrawn = withdraw(&board, m, &a(S), &a(K), None).expect("withdrawn");
    // The same merge landed again by hand, a marker of its own.
    let head = format!("{D}.2");
    let typed = dialer.world().position;
    let frame = frames::set_arrangement(S, &whole_of(&dialer, S, &draft_m()), typed, Some((&head, 15)), Some((&head, 15)), Some((&[], None)), None);
    let Answer::Document(ack) = board.op(Some(session.token()), &frame).expect("the landing by hand") else { panic!("closed") };
    assert_eq!(ack["resp"], "ack", "{ack}");
    dialer.clear();
    assert_eq!(
        unwithdraw(&board, m, &a(S), &a(K), withdrawn.position, None, None),
        Err(Refusal::NothingToUndo { draft: a(S), why: NoUndo::Remarked }),
        "landed again since"
    );
    assert!(dialer.frames("set_arrangement").is_empty(), "nothing sent: {:?}", dialer.ops());
    let again = withdraw(&board, m, &a(S), &a(K), None).expect("withdrawn again");
    let runs = shot_runs(&draft_m());
    let frame = frames::publication(&frames::PublishFrame { doc: Some(D), base: Some((&head, 15)), draft: Some(S), runs: &runs, ..frames::PublishFrame::default() });
    let ack = dialer.world().apply(&frame);
    assert_eq!(acked_addr(&ack), Some(format!("{D}.3").as_str()), "{ack}");
    dialer.clear();
    let err = unwithdraw(&board, m, &a(S), &a(K), again.position, None, None).expect_err("published since");
    assert_eq!(err, Refusal::NothingToUndo { draft: a(S), why: NoUndo::Published { version: a(&format!("{D}.3")) } });
    assert_eq!(err.to_string(), format!("nothing to undo: {S} was published as version {D}.3 since, and a version stands — the way back is to publish the older text again"));
    assert!(dialer.frames("set_arrangement").is_empty(), "nothing sent: {:?}", dialer.ops());
}

/// A withdrawal's undo run again after its put-back was taken out sends
/// nothing (the `undo` module's doc, **Nothing to undo**).
///
/// `T`, staged from the head `D.2`, takes the race merge, which re-records
/// the base pair `T` was staged with; the merge is withdrawn, the
/// withdrawal taken back and the landing undone, so `T` holds the head's
/// words again with no marker and the base pair it held at the withdrawal.
/// The withdrawal's undo run again — typed at the caller's own last ack,
/// the undo's write, and with none — is `Remarked`, nothing sent: the row
/// that put the cleared marker back stands past the withdrawal (the mutant
/// without that row check puts the marker back over the head's words at
/// the caller's ack, and sends a frame the board refuses with none; the one
/// that takes any row naming a merge as a put-back refuses the withdrawal's
/// undo past another merge's landing and undo, which skep #1154's suite
/// pins).
#[test]
fn a_withdrawals_undo_run_again_after_its_put_back_was_taken_out_sends_nothing() {
    let t = "1.0.1.0.67";
    let head = format!("{D}.2");
    let words = vec![run(D, 1, 4), run(D, 12, 4), run(D, 5, 7)];
    let mut w = World::race();
    w.doc(t, false, ACCOUNT, words.clone());
    w.staged(t, &head, 15);
    let (dialer, board, signer) = open(w);
    let session = sign_in(&board, &signer);
    let m = merger(&session, &signer);
    let merged = compose(&board, Some(session.token()), &race_inputs()).expect("composed");
    land(&board, &merged, draft_landing(&session, &signer, Some(a(t)))).expect("landed");
    assert_eq!(dialer.world().standing(t).0, Some((head.clone(), 15)), "the premise: the landing re-recorded the pair T was staged with");
    let withdrawn = withdraw(&board, m, &a(t), &a(K), None).expect("withdrawn");
    unwithdraw(&board, m, &a(t), &a(K), withdrawn.position, None, None).expect("the withdrawal taken back");
    let undone = undo(&board, m, &a(t), &a(K), None, None).expect("the landing taken back");
    assert_eq!(dialer.world().docs.get(t).unwrap().runs, words, "the premise: T holds the head's words again");
    assert_eq!(dialer.world().standing(t), (Some((head.clone(), 15)), None), "the premise: the base pair as at the withdrawal, no marker");
    for own_ack in [Some(undone.position), None] {
        dialer.clear();
        assert_eq!(
            unwithdraw(&board, m, &a(t), &a(K), withdrawn.position, own_ack, None),
            Err(Refusal::NothingToUndo { draft: a(t), why: NoUndo::Remarked }),
            "own_ack {own_ack:?}: the put-back taken out again since"
        );
        assert!(dialer.frames("set_arrangement").is_empty(), "own_ack {own_ack:?}: nothing sent: {:?}", dialer.ops());
    }
    assert_eq!(dialer.world().docs.get(t).unwrap().runs, words, "T's words stand");
    assert_eq!(dialer.world().standing(t), (Some((head, 15)), None), "no marker put back");
}

/// A withdrawal and its undo keep a member's own word (skep #1121).
///
/// The draft holds M and, after it, one word a deposit naming `D.2` minted
/// under the member's chain, whose ordinal is the trunk's first word's. The
/// withdrawal names no change, reading no correspondence record, and the
/// withdrawal's undo, whose mapping moves no word, names none either, the
/// marker put back beside it; the draft holds the member's word throughout
/// (the mutants that send the core's runs back whole send the trunk's first
/// word in its place).
#[test]
fn a_withdrawal_and_its_undo_keep_a_members_own_word_under_the_members_chain() {
    let (dialer, board, signer) = open(draft_landing_world());
    let session = sign_in(&board, &signer);
    let m = merger(&session, &signer);
    landed_in_s(&board, &session, &signer);
    let held: Vec<Run> = draft_m().into_iter().chain([run(&member(), 1, 1)]).collect();
    {
        let mut w = dialer.world();
        w.text(&member(), 1, "z");
        w.change(S, held.clone());
    }
    let correspondence = frames::unit_span(frames::T_CORRESPONDENCE);
    dialer.clear();
    let withdrawn = withdraw(&board, m, &a(S), &a(K), None).expect("withdrawn");
    let sent = dialer.frames("set_arrangement");
    assert_eq!(sent.len(), 1, "one write: {:?}", dialer.ops());
    assert_eq!(sent[0]["changes"], json!([]), "no change named: every word stands on the chain that minted it: {}", sent[0]);
    assert!(dialer.frames("find_links_ftt").iter().all(|f| f["q"]["ty"] != correspondence), "no correspondence record is read: {:?}", dialer.ops());
    assert_eq!(dialer.world().docs.get(S).unwrap().runs, held, "the words stay, each its own");
    dialer.clear();
    unwithdraw(&board, m, &a(S), &a(K), withdrawn.position, None, None).expect("the withdrawal taken back");
    let sent = dialer.frames("set_arrangement");
    assert_eq!(sent.len(), 1, "one write: {:?}", dialer.ops());
    assert_eq!(sent[0]["changes"], json!([]), "no word moved by the mapping, none named, the marker put back beside none: {}", sent[0]);
    assert_eq!(dialer.world().docs.get(S).unwrap().runs, held, "the words stay, each its own");
    assert!(dialer.world().standing(S).1.is_some(), "the marker back");
}

/// A withdrawal reads no correspondence record and maps nothing.
///
/// A record of the merger's names `S`'s own words in M as the trunk's
/// `D·19–21` they became. The withdrawal keeps the draft's words as they
/// stand: it never asks for the record, and names no change of `S·1–3`
/// (the mutant that maps the image through the records places the trunk's
/// words in their stead).
#[test]
fn the_withdrawal_reads_no_correspondence_record_and_leaves_the_words_as_read() {
    let (dialer, board, signer) = open(draft_landing_world());
    let session = sign_in(&board, &signer);
    landed_in_s(&board, &session, &signer);
    let record = {
        let mut w = dialer.world();
        w.text(D, 19, "!!!");
        plant_record(&mut w, 1, 19, 3)
    };
    let correspondence = frames::unit_span(frames::T_CORRESPONDENCE);
    dialer.clear();
    withdraw(&board, merger(&session, &signer), &a(S), &a(K), None).expect("withdrawn");
    assert!(dialer.frames("find_links_ftt").iter().all(|f| f["q"]["ty"] != correspondence), "no records' read: {:?}", dialer.ops());
    assert!(dialer.frames("read_link").iter().all(|f| f["a"] != record), "the record is never read: {:?}", dialer.ops());
    assert_eq!(dialer.frames("set_arrangement")[0]["changes"], json!([]), "no change named, S's own words its own");
    assert_eq!(dialer.world().docs.get(S).unwrap().runs, draft_m(), "the words stay");
}

/// A withdrawal's undo sends another account's words as their owner
/// published them.
///
/// M holds "abc", words of `THEIR_DRAFT`, a draft of the account `1.0.2`
/// whose owner published them into `THEIR_EDITION`, the record homed in
/// the draft. The withdrawal names no change, the draft's words standing;
/// its undo reads the records of the draft's origins at the head, the
/// draft's in its own account, and names the one stretch its mapping moved
/// — the edition's three words in place of the draft's, positions 16 to
/// 18, no run of the fifteen positions before them — the marker put back
/// (the mutant that reads the merger's own origins alone names no change,
/// and the one that sends the mapped words whole names four runs from
/// position 1).
#[test]
fn a_withdrawals_undo_sends_another_accounts_words_as_their_owner_published_them() {
    let mut w = draft_landing_world();
    let record = their_publication(&mut w);
    let (dialer, board, signer) = open(w);
    let session = sign_in(&board, &signer);
    let m = merger(&session, &signer);
    let held = vec![run(D, 1, 4), run(D, 12, 4), run(D, 5, 7), run(THEIR_DRAFT, 1, 3)];
    landed_by_hand(&board, &session, &dialer, &held);
    dialer.clear();
    let withdrawn = withdraw(&board, m, &a(S), &a(K), None).expect("withdrawn");
    assert_eq!(dialer.frames("set_arrangement")[0]["changes"], json!([]), "the premise: the withdrawal names no change");
    dialer.clear();
    unwithdraw(&board, m, &a(S), &a(K), withdrawn.position, None, None).expect("the withdrawal taken back");
    assert_eq!(dialer.frames("read_link").iter().filter(|f| f["a"] == record).count(), 1, "the draft's record read once: {:?}", dialer.ops());
    let mapped = vec![run(D, 1, 4), run(D, 12, 4), run(D, 5, 7), run(THEIR_EDITION, 1, 3)];
    let sent = dialer.frames("set_arrangement");
    assert_eq!(sent.len(), 1, "one write: {:?}", dialer.ops());
    assert_eq!(sent[0]["changes"], json!([frames::placed(16, 3, &shot_runs(&[run(THEIR_EDITION, 1, 3)]))]), "the one stretch the mapping moved: the edition's words where the draft's stood");
    let w = dialer.world();
    assert_eq!(w.docs.get(S).unwrap().runs, mapped);
    assert!(w.standing(S).1.is_some(), "the marker back");
}

/// A write that changed a member's word for the trunk's is no withdrawal.
///
/// The state before the write holds a word minted under `D.2`'s chain; the
/// write, by hand, has a withdrawal's shape — the base re-sent, no merge —
/// and leaves the trunk's word of the same ordinal in its place. The words
/// at it are not those before it, so the position names no withdrawal:
/// `NoWithdrawal`, nothing sent, the marker staying out (the mutant that
/// compares the core's runs puts the marker back over the other word).
#[test]
fn a_write_that_changed_a_members_word_for_the_trunks_names_no_withdrawal() {
    let (dialer, board, signer) = open(draft_landing_world());
    let session = sign_in(&board, &signer);
    landed_in_s(&board, &session, &signer);
    let held: Vec<Run> = draft_m().into_iter().chain([run(&member(), 1, 1)]).collect();
    let swapped: Vec<Run> = draft_m().into_iter().chain([run(D, 1, 1)]).collect();
    {
        let mut w = dialer.world();
        w.text(&member(), 1, "z");
        w.change(S, held);
    }
    let head = format!("{D}.2");
    let typed = dialer.world().position;
    let frame = frames::set_arrangement(S, &whole_of(&dialer, S, &swapped), typed, None, Some((&head, 15)), None, None);
    let at = dialer.world().apply(&frame)["at"].as_u64().expect("the write's ack");
    assert_eq!(dialer.world().standing(S), (Some((head, 15)), None), "the premise: the base re-sent, the marker cleared");
    let rows = dialer.world().rows.len();
    dialer.clear();
    assert_eq!(unwithdraw(&board, merger(&session, &signer), &a(S), &a(K), at, None, None), Err(Refusal::NoWithdrawal { draft: a(S), at }));
    assert_eq!(dialer.positions("image"), [at, typed], "the premise: the words read at the write and before it: {:?}", dialer.ops());
    assert!(dialer.frames("set_arrangement").is_empty() && dialer.frames("insert").is_empty(), "nothing sent: {:?}", dialer.ops());
    assert_eq!(dialer.world().rows.len(), rows, "nothing committed");
    assert!(dialer.world().standing(S).1.is_none(), "the marker stays out");
    assert_eq!(dialer.world().docs.get(S).unwrap().runs, swapped, "the draft as the write left it");
}

/// A member's word changed for the trunk's keeps an undo at the landing.
///
/// Skep #1121 with #964, P3: the undo after a put-back is typed past it
/// only where the words there are the landing's by identity. The landing
/// leaves a word minted under `D.2`'s chain in the draft, and another hand
/// then puts the trunk's word of the same ordinal in its place; the merge
/// is withdrawn and put back, that change kept. The words at the put-back
/// are not the landing's, so the undo, with no `own_ack`, is typed against
/// the landing and refused `arrangement_moved`, its words naming the
/// put-back, the change standing (the mutant that compares the core's runs
/// types it past the put-back, and it lands over the change).
#[test]
fn an_undo_after_a_put_back_is_typed_at_the_landing_where_a_members_word_became_the_trunks() {
    let (dialer, board, signer) = open(draft_landing_world());
    let session = sign_in(&board, &signer);
    let m = merger(&session, &signer);
    let landed: Vec<Run> = draft_m().into_iter().chain([run(&member(), 1, 1)]).collect();
    let swapped: Vec<Run> = draft_m().into_iter().chain([run(D, 1, 1)]).collect();
    dialer.world().text(&member(), 1, "z");
    let at = landed_by_hand(&board, &session, &dialer, &landed);
    dialer.world().change(S, swapped.clone());
    let withdrawn = withdraw(&board, m, &a(S), &a(K), None).expect("withdrawn");
    let back = unwithdraw(&board, m, &a(S), &a(K), withdrawn.position, None, None).expect("put back").position;
    assert_eq!(dialer.world().docs.get(S).unwrap().runs, swapped, "the premise: the change kept in the words");
    let rows = dialer.world().rows.len();
    dialer.clear();
    let err = undo(&board, m, &a(S), &a(K), None, None).expect_err("the change stands in the words");
    let Refusal::Halt(Halt::Refused(refused)) = &err else { panic!("{err:?}") };
    assert_eq!(refused.code, "arrangement_moved");
    assert_eq!(dialer.frames("set_arrangement")[0]["as_of"], json!(at), "typed against the landing, never the put-back");
    let detail = refused.detail.as_deref().expect("the person's words");
    assert!(detail.contains(&format!("{S} changed since the merge landed (the merge landed at position {at}, the draft changed at {back}): its words changed before the merge was put back at position {back}")), "{detail}");
    assert!(detail.contains("an undo typed against the landing can no longer land"), "{detail}");
    assert_eq!(dialer.world().docs.get(S).unwrap().runs, swapped, "the change stands");
    assert_eq!(dialer.world().rows.len(), rows, "nothing committed");
}

/// The cap is counted on the runs a write places, never on the draft's.
///
/// The draft holds the trunk's words and a member's by turns at adjoining
/// ordinals, one run more than a write may place as the board serves and
/// takes them and one run of `D` as the core joins them. (a) The withdrawal
/// lands: it names no change, so no run of the draft is sent or counted, the
/// image still read, in pages past the board's run budget, the marker
/// cleared and every word standing (the mutant that sends the image back
/// whole answers `OverCap`). (b) Its undo lands the same way, no record
/// moving a word: the marker back, no run named. (c) A draft whose first and
/// last words are `S`'s own, each named by a record as the trunk's word it
/// became, the cap's runs less one between: the one stretch the undo's
/// mapping moves reaches from the first word to the last, so the write would
/// place one run more than the cap and is refused `OverCap` with that count
/// after the records' read, nothing sent and the marker staying out (the
/// mutant that counts none sends a frame of that many runs). (d) The same
/// undo over a draft of 5,000 runs places them all in one frame.
#[test]
fn a_take_back_is_held_to_the_cap_on_the_runs_its_write_places() {
    let wrote = |dialer: &Scripted| !(dialer.frames("set_arrangement").is_empty() && dialer.frames("insert").is_empty() && dialer.frames("make_link").is_empty());
    // (a) The withdrawal of a draft in more runs than a write may name.
    let (dialer, board, signer) = open(draft_landing_world());
    let session = sign_in(&board, &signer);
    let m = merger(&session, &signer);
    landed_in_s(&board, &session, &signer);
    dialer.world().change(S, alternating());
    dialer.clear();
    let withdrawn = withdraw(&board, m, &a(S), &a(K), None).expect("(a): withdrawn");
    let names = dialer.names();
    let write = names.iter().position(|n| n == "set_arrangement").expect("(a): the write");
    assert_eq!(names[..write].iter().filter(|n| *n == "image").count(), (SHOT_RUN_CAP + 1).div_ceil(1 << 12), "(a): the premise: the image read in pages past the board's run budget, 4,096 runs a page: {names:?}");
    let sent = dialer.frames("set_arrangement");
    assert_eq!((sent.len(), &sent[0]["changes"]), (1, &json!([])), "(a): one write, naming no change");
    assert_eq!(dialer.world().docs.get(S).unwrap().runs, alternating(), "(a): every word stands");
    assert!(dialer.world().standing(S).1.is_none(), "(a): the marker cleared");
    // (b) Its undo, no record moving a word.
    dialer.clear();
    unwithdraw(&board, m, &a(S), &a(K), withdrawn.position, None, None).expect("(b): the withdrawal taken back");
    let sent = dialer.frames("set_arrangement");
    assert_eq!((sent.len(), &sent[0]["changes"]), (1, &json!([])), "(b): one write, naming no change");
    assert_eq!(dialer.world().docs.get(S).unwrap().runs, alternating(), "(b): every word stands");
    assert!(dialer.world().standing(S).1.is_some(), "(b): the marker back");
    // (c) The undo whose mapping moves the first word and the last.
    let (dialer, board, signer) = open(draft_landing_world());
    let session = sign_in(&board, &signer);
    let m = merger(&session, &signer);
    landed_in_s(&board, &session, &signer);
    let withdrawn = withdraw(&board, m, &a(S), &a(K), None).expect("withdrawn");
    let between = alternating().into_iter().take(SHOT_RUN_CAP - 1);
    let held: Vec<Run> = [run(S, 1, 1)].into_iter().chain(between).chain([run(S, 3, 1)]).collect();
    let (own, records) = {
        let mut w = dialer.world();
        let own = w.change(S, held);
        (own, [plant_record(&mut w, 1, 9_000, 1), plant_record(&mut w, 3, 9_500, 1)])
    };
    let rows = dialer.world().rows.len();
    dialer.clear();
    assert_eq!(
        unwithdraw(&board, m, &a(S), &a(K), withdrawn.position, Some(own), None).map(drop),
        Err(Refusal::OverCap { runs: SHOT_RUN_CAP + 1, cap: SHOT_RUN_CAP }),
        "(c): the two words mapped and the runs between them"
    );
    for record in &records {
        assert!(dialer.frames("read_link").iter().any(|f| f["a"] == *record), "(c): the records read first: {:?}", dialer.names());
    }
    assert!(!wrote(&dialer), "(c): nothing sent: {:?}", dialer.names());
    assert_eq!(dialer.world().rows.len(), rows, "(c): nothing committed");
    assert!(dialer.world().standing(S).1.is_none(), "(c): the marker stays out");
    // (d) The same undo over a draft of 5,000 runs: the stretch its mapping
    // moves places every one of them, past what one wire list holds and
    // inside the cap, so it lands in ONE frame and one row, the marker back
    // (the mutant that holds a write to 4,096 runs refuses it `OverCap`).
    let (dialer, board, signer) = open(draft_landing_world());
    let session = sign_in(&board, &signer);
    let m = merger(&session, &signer);
    landed_in_s(&board, &session, &signer);
    let withdrawn = withdraw(&board, m, &a(S), &a(K), None).expect("withdrawn");
    let between = alternating().into_iter().take(4_998);
    let held: Vec<Run> = [run(S, 1, 1)].into_iter().chain(between).chain([run(S, 3, 1)]).collect();
    let own = {
        let mut w = dialer.world();
        // Every word the draft names is a stored one.
        w.text(D, 16, &"x".repeat(10_000));
        w.text(&member(), 1, &"x".repeat(5_000));
        let own = w.change(S, held);
        plant_record(&mut w, 1, 9_000, 1);
        plant_record(&mut w, 3, 9_500, 1);
        own
    };
    let rows = dialer.world().rows.iter().filter(|r| r.op == "set_arrangement").count();
    dialer.clear();
    unwithdraw(&board, m, &a(S), &a(K), withdrawn.position, Some(own), None).expect("(d): the withdrawal taken back in one write");
    let sent = dialer.frames("set_arrangement");
    assert_eq!(sent.len(), 1, "(d): one frame: {:?}", dialer.names());
    let placed: usize = sent[0]["changes"].as_array().expect("changes").iter().map(|change| change["runs"].as_array().map_or(0, Vec::len)).sum();
    assert_eq!(placed, 5_000, "(d): the two words mapped and the 4,998 runs between them, in the one frame");
    assert_eq!(dialer.world().rows.iter().filter(|r| r.op == "set_arrangement").count(), rows + 1, "(d): one row");
    assert!(dialer.world().standing(S).1.is_some(), "(d): the marker back");
}

/// A withdrawal's undo looks past records naming the draft as a side.
///
/// Skep #1154: after a landing in `S` and its withdrawal, a newer record
/// linked to `S` stands, landed elsewhere, `S` one of its sides: (a) a
/// sub-account's, landed in a draft of its own; (b) the merger's own,
/// landed in another draft of theirs. At each, the withdrawal's undo writes
/// the landing's record again — `landed` `S` at the landing's position,
/// `replaces` the withdrawal's record — judged by the marker it puts back
/// (judged by the newest of every account's records linked to the draft,
/// none is written at either; by the newest of the merger's own, none at
/// (b)).
#[test]
fn a_withdrawals_undo_writes_the_landings_record_again_past_records_naming_the_draft_as_a_side() {
    for (case, journal, landed_in) in [("(a)", "1.0.1.2.0.65", "1.0.1.2.0.66"), ("(b)", "1.0.1.0.90", "1.0.1.0.91")] {
        let (dialer, board, signer) = open(draft_landing_world());
        let session = sign_in(&board, &signer);
        let m = merger(&session, &signer);
        let (merged, landed) = landed_in_s(&board, &session, &signer);
        let (at, _) = landing_of(&landed);
        let withdrawn = withdraw(&board, m, &a(S), &a(K), None).expect("withdrawn");
        let taken = withdrawn.record.clone().expect("the premise: the landing's record replaced");
        {
            let mut w = dialer.world();
            w.position += 1;
            let minted = w.position;
            let elsewhere = RecordLanding::Draft { draft: a(landed_in), position: minted };
            file(&mut w, journal, &Record { landed: Some(elsewhere), ..merged.record.clone() }, &[landed_in, S], Some(minted));
        }
        dialer.clear();
        let unwithdrawn = unwithdraw(&board, m, &a(S), &a(K), withdrawn.position, None, None).expect("the withdrawal taken back");
        assert!(unwithdrawn.record.is_some(), "{case}: the landing's record written again");
        let atom = appended_record(&dialer);
        assert_eq!(atom["landed"], json!({"draft": S, "position": at}), "{case}: the landing's: {atom}");
        assert_eq!(atom["replaces"].as_str(), Some(taken.to_string().as_str()), "{case}: the withdrawal's record replaced");
    }
}

/// A take-back's write is read back off its own row, whatever its changes
/// named.
///
/// Each act's answer is lost, and its re-ask's: the act reads the draft's
/// own row past the position it typed, a `set_arrangement` carrying its
/// frame's terms, and the draft there holding the whole state the act meant
/// to leave — never the runs its changes place, which are not that state.
/// (a) A withdrawal, whose frame names no change. (b) Its undo, whose frame
/// names the one stretch its mapping moved, three positions of eighteen.
/// (c) The undo of the landing, whose frame replaces every position. Each
/// answers its own row's position, one row committed (the mutant that
/// compares the state at the row with the runs the frame's changes place
/// finds no write of the withdrawal's or of its undo's, and halts).
#[test]
fn a_take_backs_lost_answer_is_read_back_whatever_its_changes_named() {
    let mut w = draft_landing_world();
    their_publication(&mut w);
    let (dialer, board, signer) = open(w);
    let session = sign_in(&board, &signer);
    let m = merger(&session, &signer);
    let c = vec![run(D, 1, 11), run(THEIR_DRAFT, 1, 3)];
    dialer.world().change(S, c);
    let held = vec![run(D, 1, 4), run(D, 12, 4), run(D, 5, 7), run(THEIR_DRAFT, 1, 3)];
    let mapped = vec![run(D, 1, 4), run(D, 12, 4), run(D, 5, 7), run(THEIR_EDITION, 1, 3)];
    landed_by_hand(&board, &session, &dialer, &held);
    // One act with its answer and its re-ask's lost: the frames it sent,
    // and the rows it committed.
    let lost = |act: &dyn Fn() -> u64| {
        let rows = dialer.world().rows.len();
        dialer.clear();
        dialer.world().drop_acks = 2;
        let position = act();
        let frames = dialer.frames("set_arrangement");
        assert!(frames.len() == 2 && frames[0] == frames[1], "the write and its one re-ask, the same frame: {frames:?}");
        let committed: Vec<u64> = dialer.world().rows[rows..].iter().filter(|r| r.op == "set_arrangement").map(|r| r.at).collect();
        assert_eq!(committed, [position], "one row, its position answered");
        (position, frames[0]["changes"].clone())
    };
    // (a) The withdrawal.
    let (withdrawal, changes) = lost(&|| withdraw(&board, m, &a(S), &a(K), None).expect("(a): the withdrawal read back").position);
    assert_eq!(changes, json!([]), "(a): no change named");
    assert_eq!(dialer.world().standing(S).1, None, "(a): the marker cleared");
    // (b) Its undo.
    let (_, changes) = lost(&|| unwithdraw(&board, m, &a(S), &a(K), withdrawal, None, None).expect("(b): the put-back read back").position);
    assert_eq!(changes, json!([frames::placed(16, 3, &shot_runs(&[run(THEIR_EDITION, 1, 3)]))]), "(b): the one stretch the mapping moved");
    assert_eq!(dialer.world().docs.get(S).unwrap().runs, mapped, "(b): the draft holds the words mapped");
    assert!(dialer.world().standing(S).1.is_some(), "(b): the marker back");
    // (c) The undo of the landing.
    let (_, changes) = lost(&|| undo(&board, m, &a(S), &a(K), None, None).expect("(c): the undo read back").position);
    assert_eq!(changes[0]["at"], frames::place(1), "(c): one change from the first position");
    assert_eq!(changes[0]["width"], json!(width_of(&mapped).to_string()), "(c): over every position the draft held");
    assert_eq!(dialer.world().standing(S).1, None, "(c): the marker cleared");
}
