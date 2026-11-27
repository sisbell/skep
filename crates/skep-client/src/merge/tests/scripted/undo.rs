//! The undo over the scripted board.
//!
//! The suite checks `undo` after a landing: C and the old base restored and
//! the marker cleared in one frame; refused past another hand's edit; typed
//! at the editor's own last ack, or at the landing where that ack is
//! earlier, advising a take-back, and refused past the head or past another
//! hand's change; C mapped through the records of its origins, each read in
//! its owner's account — another account's words sent as the words its
//! owner published — refused past the cap, and faced where a record maps it
//! past the largest ordinal; the put-back judged on the states at the
//! landing and at it mapped through one read of the records, another
//! account's word re-windowed onto its published word one word; a member's
//! own word in C sent under the member's chain, told from the trunk's word
//! of its ordinal where a baseless landing is judged taken back, and
//! counted as a run of its own at the cap; nothing to undo after a
//! publication, or after a merge's shot, its words naming the merge's
//! version; an inherited marker; a baseless landing undone by its feed row,
//! and run again — another account's words sent mapped among them, and a
//! restore of the merge's words since bringing none back — and taken back
//! where its re-arrangement holds words a record maps onto C's; one merge
//! landed twice in a baseless draft undone a landing at a time, and a
//! baseless landing with no record replacing no other merge's; the state
//! before the landing read at `nearest`, refused where
//! reclaimed; and the record an undo and a withdrawal replace, the
//! merger's own whatever another account files — a newer record of the
//! landing, never read, or a take-back of the merger's record.

use super::*;

/// THE UNDO (the landing lane's R6; P1, P3, P4; skep #783): after a
/// landing into `S`, `undo` reads the draft's `doc_metadata` live — a
/// base and a marker — then the state before the landing at ONE
/// position, `/op-at`'s `nearest` for the marker's `at − 1`: a landing
/// with a base is one commit of two records, the changes' and the base's,
/// so `at − 1` lies inside it and the board answers `not_a_position`;
/// `doc_metadata` there for the old base, address and extent, and `image`
/// for C. ONE `set_arrangement` follows — one change, C over every
/// position the draft holds, `as_of` the landing's position (P3), `base`
/// the old pair (P1), no `head`, no `merge`, the id naming the draft and
/// the position — so the draft holds C again, its base is `D.1` at
/// eleven and the marker is cleared; the replacing record, `landed`
/// none and `replaces` the landing's link, is appended and linked to
/// the draft.
#[test]
fn undo_after_a_landing_restores_c_and_the_old_base_and_clears_the_marker_in_one_frame() {
    let (dialer, board, signer) = open(draft_landing_world());
    let session = sign_in(&board, &signer);
    let before = dialer.world().position;
    let (_, landed) = landed_in_s(&board, &session, &signer);
    let (at, link) = landing_of(&landed);
    assert_eq!(at, before + 2, "the premise: one commit of two records, the changes' and the base's");
    assert_eq!(dialer.world().standing(S).1.map(|m| m.at), Some(at), "the premise: the marker at the landing");
    dialer.clear();
    let undone = undo(&board, merger(&session, &signer), &a(S), &a(K), None, None).expect("undone");
    assert_eq!(undone.draft, a(S));
    assert_eq!(undone.restored, Some((a(&format!("{D}.1")), 11)), "the pair read before the landing");
    let replacing = undone.record.clone().expect("a record stood, so one replaces it");
    assert_ne!(replacing, link);
    // The pre-landing read: `at − 1` refused `not_a_position`, then the
    // one position `nearest` for the metadata and the image.
    assert_eq!(dialer.positions("doc_metadata"), [at - 1, before], "at − 1 asked, then nearest: {:?}", dialer.ops());
    assert_eq!(dialer.positions("retrieve_doc_v_span_set"), [before]);
    assert_eq!(dialer.positions("image"), [before]);
    // The one write.
    let frames = dialer.frames("set_arrangement");
    assert_eq!(frames.len(), 1, "one write: {:?}", dialer.ops());
    let frame = &frames[0];
    assert_eq!(frame["doc"], S);
    assert_eq!(frame["as_of"].as_u64(), Some(at), "typed against the landing's position: {frame}");
    assert_eq!(frame["changes"], whole_changes(width_of(&draft_m()), &draft_c()), "C, read before the landing, over every position the draft holds");
    assert_eq!(frame["base"], json!({"at": format!("{D}.1"), "extent": "11"}), "the old base, address and extent");
    assert!(frame.get("head").is_none() && frame.get("merge").is_none(), "no head, no merge: {frame}");
    assert_eq!(frame["id"].as_str(), Some(format!("undo:{S}:{at}.arrangement").as_str()));
    let w = dialer.world();
    assert_eq!(w.docs.get(S).unwrap().runs, draft_c(), "C again");
    assert_eq!(w.standing(S), (Some((format!("{D}.1"), 11)), None), "the base restored, the marker cleared");
    let row = w.rows.iter().rev().find(|r| r.op == "set_arrangement").expect("the undo's row");
    assert_eq!((row.at, &row.terms), (undone.position, &Some((Some(format!("{D}.1")), None))), "the write's `at`; its row names the base restored and no merge");
    drop(w);
    // The record: the landing's with `landed` none and `replaces` its
    // link, under the act's stem, linked to the draft.
    let atom = appended_record(&dialer);
    assert!(atom["landed"].is_null(), "{atom}");
    assert_eq!(atom["replaces"].as_str(), Some(link.to_string().as_str()));
    assert_eq!((atom["doc"].as_str(), atom["base"].as_str()), (Some(D), Some(format!("{D}.1").as_str())));
    assert_eq!(dialer.frames("insert")[0]["id"].as_str(), Some(format!("undo:{S}:{at}.record").as_str()));
    assert_eq!(dialer.frames("make_link")[0]["to"]["addrs"], json!([S]));
}

/// An undo past another hand's edit since the landing is refused whole.
///
/// Typed against the landing's position, `own_ack` none, the undo is
/// refused `arrangement_moved` by the board, its words the person's: the
/// draft, that nothing was changed, and that an undo typed against the
/// landing can no longer land, never to undo the later changes first
/// (P3). The edit stands, nothing is committed, the base and the marker
/// stand as they did, and no record is written.
#[test]
fn undo_after_another_hands_edit_is_refused_arrangement_moved_with_nothing_committed() {
    let (dialer, board, signer) = open(draft_landing_world());
    let session = sign_in(&board, &signer);
    let (_, landed) = landed_in_s(&board, &session, &signer);
    let (at, _) = landing_of(&landed);
    // Another hand's edit after the landing: the "!!!" deleted.
    let edited = vec![run(D, 1, 4), run(D, 12, 4), run(D, 5, 7)];
    let edit_at = dialer.world().change(S, edited.clone());
    let (rows, standing) = {
        let w = dialer.world();
        (w.rows.len(), w.standing(S))
    };
    dialer.clear();
    let err = undo(&board, merger(&session, &signer), &a(S), &a(K), None, None).expect_err("the draft changed since");
    let Refusal::Halt(Halt::Refused(refused)) = &err else { panic!("{err:?}") };
    assert_eq!(refused.code, "arrangement_moved");
    let detail = refused.detail.as_deref().expect("the person's words");
    assert!(detail.contains(S) && detail.contains("changed since the merge landed") && detail.contains("nothing was changed"), "{detail}");
    assert!(detail.contains(&format!("position {at}")) && detail.contains(&format!("changed at {edit_at}")), "{detail}");
    assert!(detail.contains("can no longer land") && detail.contains("edit the draft as it stands"), "{detail}");
    assert!(!detail.contains("undo the later changes first"), "no take-back lands an undo typed at the landing: {detail}");
    assert_eq!(dialer.frames("set_arrangement")[0]["as_of"].as_u64(), Some(at), "typed against the landing's position, never a fresh read");
    let w = dialer.world();
    assert_eq!(w.docs.get(S).unwrap().runs, edited, "the other hand's edit stands: nothing wiped");
    assert_eq!(w.rows.len(), rows, "nothing committed");
    assert_eq!(w.standing(S), standing, "the base and the marker as they stood");
    drop(w);
    assert!(dialer.frames("insert").is_empty() && dialer.frames("make_link").is_empty(), "no record");
}

/// An undo typed at the editor's last ack lands past an edit taken back.
///
/// After the landing the person edits `S` and takes the edit back: two
/// commits, `S` holding M again with its arrangement moved past the
/// landing (P3; skep #811). Typed against the landing, `own_ack` none,
/// the undo is refused `arrangement_moved`, its words saying it can no
/// longer land and never to undo the later changes first. Typed against
/// the editor's own last acknowledgment, the taking-back's position `r`,
/// it lands: one frame, `as_of` `r`, C as the runs, the old base, no head
/// and no merge, the id naming the draft and `r`; the draft holds C, its
/// base `D.1` at eleven, the marker cleared, and the replacing record is
/// written under the same stem.
#[test]
fn undo_typed_at_the_editors_own_last_ack_lands_after_its_later_edit_was_taken_back() {
    let (dialer, board, signer) = open(draft_landing_world());
    let session = sign_in(&board, &signer);
    let (_, landed) = landed_in_s(&board, &session, &signer);
    let (at, link) = landing_of(&landed);
    // The person's own edit after the landing — the "!!!" deleted — and
    // its taking back.
    let edit = dialer.world().change(S, vec![run(D, 1, 4), run(D, 12, 4), run(D, 5, 7)]);
    let r = dialer.world().change(S, draft_m());
    assert!(at < edit && edit < r, "the premise: two commits past the landing");
    let err = undo(&board, merger(&session, &signer), &a(S), &a(K), None, None).expect_err("typed at the landing");
    let Refusal::Halt(Halt::Refused(refused)) = &err else { panic!("{err:?}") };
    assert_eq!(refused.code, "arrangement_moved", "the premise: the landing's typing is refused once the arrangement moved, M again or not");
    let detail = refused.detail.as_deref().expect("the person's words");
    assert!(detail.contains("can no longer land") && detail.contains("edit the draft as it stands"), "{detail}");
    assert!(!detail.contains("undo the later changes first"), "taking the edit back left it refused: {detail}");
    dialer.clear();
    let undone = undo(&board, merger(&session, &signer), &a(S), &a(K), Some(r), None).expect("undone at the editor's own last ack");
    assert_eq!(undone.restored, Some((a(&format!("{D}.1")), 11)), "the pair read before the landing");
    let frames = dialer.frames("set_arrangement");
    assert_eq!(frames.len(), 1, "one write: {:?}", dialer.ops());
    let frame = &frames[0];
    assert_eq!(frame["as_of"].as_u64(), Some(r), "typed against the editor's own last ack: {frame}");
    assert_eq!(frame["changes"], whole_changes(width_of(&draft_m()), &draft_c()), "C, read before the landing, over every position the draft holds");
    assert_eq!(frame["base"], json!({"at": format!("{D}.1"), "extent": "11"}), "the old base, address and extent");
    assert!(frame.get("head").is_none() && frame.get("merge").is_none(), "no head, no merge: {frame}");
    assert_eq!(frame["id"].as_str(), Some(format!("undo:{S}:{r}.arrangement").as_str()), "the id names the draft and the typed position");
    let w = dialer.world();
    assert_eq!(w.docs.get(S).unwrap().runs, draft_c(), "C again");
    assert_eq!(w.standing(S), (Some((format!("{D}.1"), 11)), None), "the base restored, the marker cleared");
    drop(w);
    let atom = appended_record(&dialer);
    assert_eq!(atom["replaces"].as_str(), Some(link.to_string().as_str()), "the landing's record replaced");
    assert_eq!(dialer.frames("insert")[0]["id"].as_str(), Some(format!("undo:{S}:{r}.record").as_str()));
}

/// AN OWN ACK BEFORE THE LANDING: the editor's last acknowledgment on the
/// draft names a write before the landing — the library's landing being
/// no write the editor was answered for — so the undo is typed against
/// the landing's position, the later of the two, and lands: no position
/// below the landing's would.
#[test]
fn undo_typed_at_an_own_ack_before_the_landing_is_typed_at_the_landing() {
    let (dialer, board, signer) = open(draft_landing_world());
    let session = sign_in(&board, &signer);
    let before = dialer.world().position;
    let (_, landed) = landed_in_s(&board, &session, &signer);
    let (at, _) = landing_of(&landed);
    dialer.clear();
    undo(&board, merger(&session, &signer), &a(S), &a(K), Some(before), None).expect("undone");
    let frame = &dialer.frames("set_arrangement")[0];
    assert_eq!(frame["as_of"].as_u64(), Some(at), "the landing's position, the later: {frame}");
    assert_eq!(frame["id"].as_str(), Some(format!("undo:{S}:{at}.arrangement").as_str()));
    assert_eq!(dialer.world().docs.get(S).unwrap().runs, draft_c(), "C again");
}

/// An undo typed at the landing for an earlier own ack advises a take-back.
///
/// The editor's last acknowledgment on `S` names a write before the
/// landing, and another hand edits `S` after the landing, so the undo,
/// typed against the landing's position, is refused `arrangement_moved`,
/// its words saying to undo the later changes first, or edit, and never
/// that it can no longer land (P3). The editor taking the edit back makes
/// a write of its own past the landing, and the undo typed at it lands C.
#[test]
fn undo_typed_at_an_own_ack_before_the_landing_advises_taking_a_later_change_back() {
    let (dialer, board, signer) = open(draft_landing_world());
    let session = sign_in(&board, &signer);
    let before = dialer.world().position;
    let (_, landed) = landed_in_s(&board, &session, &signer);
    let (at, _) = landing_of(&landed);
    // Another hand's edit after the landing: the "!!!" deleted.
    dialer.world().change(S, vec![run(D, 1, 4), run(D, 12, 4), run(D, 5, 7)]);
    dialer.clear();
    let err = undo(&board, merger(&session, &signer), &a(S), &a(K), Some(before), None).expect_err("another hand's edit since the landing");
    let Refusal::Halt(Halt::Refused(refused)) = &err else { panic!("{err:?}") };
    assert_eq!(refused.code, "arrangement_moved");
    assert_eq!(dialer.frames("set_arrangement")[0]["as_of"].as_u64(), Some(at), "typed against the landing's position, the later");
    let detail = refused.detail.as_deref().expect("the person's words");
    assert!(detail.contains("changed since the merge landed") && detail.contains("undo the later changes first, or edit"), "{detail}");
    assert!(!detail.contains("can no longer land"), "{detail}");
    // The editor takes the edit back: a write of its own past the landing.
    let r = dialer.world().change(S, draft_m());
    undo(&board, merger(&session, &signer), &a(S), &a(K), Some(r), None).expect("undone at the editor's own last ack");
    assert_eq!(dialer.world().docs.get(S).unwrap().runs, draft_c(), "C again");
}

/// AN OWN ACK PAST THE HEAD: no acknowledgment names a position the
/// board has not reached, and the board refuses no typed state past its
/// head — so the undo refuses it after its first read, the draft's
/// `doc_metadata` at the head, before any other: nothing sent, nothing
/// committed, the marker standing.
#[test]
fn undo_typed_at_a_position_past_the_head_is_refused_with_nothing_sent() {
    let (dialer, board, signer) = open(draft_landing_world());
    let session = sign_in(&board, &signer);
    landed_in_s(&board, &session, &signer);
    let (head, rows) = {
        let w = dialer.world();
        (w.position, w.rows.len())
    };
    dialer.clear();
    let err = undo(&board, merger(&session, &signer), &a(S), &a(K), Some(head + 5), None).expect_err("past the head");
    let Refusal::Halt(Halt::Halt(face)) = &err else { panic!("{err:?}") };
    assert!(face.state.contains(&format!("position {}", head + 5)) && face.cause.contains(&format!("position {head}")), "{face:?}");
    assert_eq!(dialer.ops(), ["doc_metadata"], "the one read, at the head; nothing sent");
    assert_eq!(dialer.world().rows.len(), rows, "nothing committed");
    assert!(dialer.world().standing(S).1.is_some(), "the marker stands");
}

/// ANOTHER HAND's CHANGE PAST THE EDITOR's LAST ACK: the editor's own
/// change at `q`, then another hand's at `t` — the undo typed against
/// `q` is refused `arrangement_moved` by the board, its words naming `q`
/// as the editor's last write, the other hand's change, and the
/// landing's own position beside them, never `q` as the landing's; the
/// other hand's change stands, nothing committed, the base and the
/// marker as they stood, no record.
#[test]
fn undo_typed_at_an_own_ack_is_refused_past_another_hands_change_naming_both_positions() {
    let (dialer, board, signer) = open(draft_landing_world());
    let session = sign_in(&board, &signer);
    let (_, landed) = landed_in_s(&board, &session, &signer);
    let (at, _) = landing_of(&landed);
    let q = dialer.world().change(S, vec![run(D, 1, 4), run(D, 12, 4), run(D, 5, 7), run(S, 1, 2)]);
    let theirs = vec![run(D, 1, 4), run(D, 12, 4), run(D, 5, 7)];
    let t = dialer.world().change(S, theirs.clone());
    let (rows, standing) = {
        let w = dialer.world();
        (w.rows.len(), w.standing(S))
    };
    dialer.clear();
    let err = undo(&board, merger(&session, &signer), &a(S), &a(K), Some(q), None).expect_err("another hand's change since");
    let Refusal::Halt(Halt::Refused(refused)) = &err else { panic!("{err:?}") };
    assert_eq!(refused.code, "arrangement_moved");
    assert_eq!(dialer.frames("set_arrangement")[0]["as_of"].as_u64(), Some(q), "typed against the editor's own last ack");
    let detail = refused.detail.as_deref().expect("the person's words");
    assert!(detail.contains(S) && detail.contains("since your last write") && detail.contains("another hand's") && detail.contains("nothing was changed"), "{detail}");
    assert!(detail.contains(&format!("position {q}")) && detail.contains(&format!("changed at {t}")) && detail.contains(&format!("the merge landed at position {at}")), "{detail}");
    assert!(!detail.contains(&format!("the merge landed at position {q}")), "the editor's last write is never named the landing: {detail}");
    let w = dialer.world();
    assert_eq!(w.docs.get(S).unwrap().runs, theirs, "the other hand's change stands: nothing wiped");
    assert_eq!(w.rows.len(), rows, "nothing committed");
    assert_eq!(w.standing(S), standing, "the base and the marker as they stood");
    drop(w);
    assert!(dialer.frames("insert").is_empty() && dialer.frames("make_link").is_empty(), "no record");
}

/// THE MAPPING (B3-S11; skep #811): the words C holds of `S`'s own
/// identity named by a correspondence record of the merger's — planted
/// after the landing, `from` `S·1–3` and `to` the trunk's `D·19–21` they
/// became — the undo reads the records of C's owned origins at the
/// head, `D` then `S` in run order, the record once, and sends C mapped:
/// the base's text as read, then `D·19–21` where "!!!" stood. The draft
/// holds the mapped runs, its base restored and the marker cleared.
#[test]
fn the_undo_sends_c_mapped_through_the_records_of_the_mergers_own_origins() {
    let (dialer, board, signer) = open(draft_landing_world());
    let session = sign_in(&board, &signer);
    let (_, landed) = landed_in_s(&board, &session, &signer);
    let (at, _) = landing_of(&landed);
    let record = {
        let mut w = dialer.world();
        w.text(D, 19, "!!!");
        plant_record(&mut w, 1, 19, 3)
    };
    dialer.clear();
    let undone = undo(&board, merger(&session, &signer), &a(S), &a(K), None, None).expect("undone");
    assert_eq!(undone.restored, Some((a(&format!("{D}.1")), 11)));
    let correspondence = frames::unit_span(frames::T_CORRESPONDENCE);
    let homes: Vec<String> = dialer.frames("find_links_ftt").iter().filter(|f| f["q"]["ty"] == correspondence).filter_map(|f| f["q"]["home"][0]["start"].as_str().map(str::to_string)).collect();
    assert_eq!(homes, [D, S], "one records' read per owned origin of C, in run order: {:?}", dialer.ops());
    assert_eq!(dialer.frames("read_link").iter().filter(|f| f["a"] == record).count(), 1, "the record read once");
    let sent = vec![run(D, 1, 11), run(D, 19, 3)];
    let frame = &dialer.frames("set_arrangement")[0];
    assert_eq!(frame["changes"], whole_changes(width_of(&draft_m()), &sent), "C mapped: the base's text as read, the trunk's words where S's stood");
    assert_eq!((frame["as_of"].as_u64(), frame["base"].clone()), (Some(at), json!({"at": format!("{D}.1"), "extent": "11"})), "{frame}");
    let w = dialer.world();
    assert_eq!(w.docs.get(S).unwrap().runs, sent, "the draft holds C mapped");
    assert_eq!(w.standing(S), (Some((format!("{D}.1"), 11)), None), "the base restored, the marker cleared");
}

/// Another account's words in C go back as the words its owner published.
///
/// C holds the base's text and "abc", words of `THEIR_DRAFT`, a draft of
/// the account `1.0.2` whose owner published them into `THEIR_EDITION`
/// since, the record homed in the draft. The undo reads the records of C's
/// origins at the head, `D` then the draft in run order, the draft's hit
/// read in the draft's own account, and sends C mapped: the edition's words
/// where the draft's stood (the mutant that reads the merger's own origins
/// alone queries `D` alone and sends the draft's words, which the draft
/// would then hold as words their owner already published).
#[test]
fn the_undo_sends_another_accounts_words_in_c_as_the_words_its_owner_published() {
    let mut w = draft_landing_world();
    let record = their_publication(&mut w);
    let (dialer, board, signer) = open(w);
    let session = sign_in(&board, &signer);
    dialer.world().change(S, vec![run(D, 1, 11), run(THEIR_DRAFT, 1, 3)]);
    let at = landed_by_hand(&board, &session, &dialer, &draft_m());
    dialer.clear();
    let undone = undo(&board, merger(&session, &signer), &a(S), &a(K), None, None).expect("undone");
    assert_eq!(undone.restored, Some((a(&format!("{D}.1")), 11)));
    let correspondence = frames::unit_span(frames::T_CORRESPONDENCE);
    let homes: Vec<String> = dialer.frames("find_links_ftt").iter().filter(|f| f["q"]["ty"] == correspondence).filter_map(|f| f["q"]["home"][0]["start"].as_str().map(str::to_string)).collect();
    assert_eq!(homes, [D, THEIR_DRAFT], "one records' read per origin of C, in run order: {:?}", dialer.ops());
    assert_eq!(dialer.frames("read_link").iter().filter(|f| f["a"] == record).count(), 1, "the draft's record read once");
    let sent = vec![run(D, 1, 11), run(THEIR_EDITION, 1, 3)];
    let frame = &dialer.frames("set_arrangement")[0];
    assert_eq!(frame["changes"], whole_changes(width_of(&draft_m()), &sent), "C mapped: the edition's words where the draft's stood");
    assert_eq!(frame["as_of"].as_u64(), Some(at), "typed against the landing's position: {frame}");
    assert_eq!(dialer.world().docs.get(S).unwrap().runs, sent, "the draft holds C mapped");
}

/// A word another account published is one word at the landing and the
/// put-back.
///
/// M holds "abc", words of `THEIR_DRAFT`, a draft of the account `1.0.2`.
/// After the landing a shot re-windows `S` onto `THEIR_EDITION`, the words
/// the draft's owner published them as, through the record homed in the
/// draft — one commit moving the arrangement and keeping the base and the
/// marker, as a merge's shot naming the draft does. The merge is withdrawn
/// and the withdrawal taken back. The undo reads `S` at the landing and at
/// the put-back and maps both through one read of the records over the two,
/// the draft's read in its own account: the states are one, so the undo is
/// typed at the put-back and lands C (the mutant that reads the merger's
/// own origins alone finds the two states apart, types the undo at the
/// landing, and the board refuses it `arrangement_moved`).
#[test]
fn an_undo_after_a_put_back_is_typed_at_it_where_another_accounts_words_were_re_windowed() {
    let mut w = draft_landing_world();
    their_publication(&mut w);
    let (dialer, board, signer) = open(w);
    let session = sign_in(&board, &signer);
    let m = merger(&session, &signer);
    let at = landed_by_hand(&board, &session, &dialer, &[run(D, 1, 4), run(D, 12, 4), run(D, 5, 7), run(THEIR_DRAFT, 1, 3)]);
    let rewindowed = vec![run(D, 1, 4), run(D, 12, 4), run(D, 5, 7), run(THEIR_EDITION, 1, 3)];
    dialer.world().change(S, rewindowed.clone());
    let withdrawn = withdraw(&board, m, &a(S), &a(K), None).expect("withdrawn");
    let back = unwithdraw(&board, m, &a(S), &a(K), withdrawn.position, None, None).expect("put back");
    assert_eq!(dialer.world().docs.get(S).unwrap().runs, rewindowed, "the premise: the edition's words stand");
    dialer.clear();
    undo(&board, m, &a(S), &a(K), None, None).expect("the undo lands");
    let sent = dialer.frames("set_arrangement");
    assert_eq!(sent.len(), 1, "one write: {:?}", dialer.ops());
    assert_eq!(sent[0]["as_of"].as_u64(), Some(back.position), "typed at the put-back, past the landing at {at}: {}", sent[0]);
    let w = dialer.world();
    assert_eq!(w.docs.get(S).unwrap().runs, draft_c(), "C again");
    assert_eq!(w.standing(S), (Some((format!("{D}.1"), 11)), None), "the base restored, the marker cleared");
}

/// AN UNDO THAT PLACES 5,000 RUNS IS ONE WRITE. C, the draft before the
/// landing, holds 5,000 runs — `S·1–3` and 4,999 of `S`'s positions apart —
/// and the landing replaced them with the merged list's four. The undo puts
/// C back in ONE `set_arrangement` frame, the runs of its changes together
/// past what one wire list holds, in one row: the draft holds C again, the
/// base restored and the marker cleared (the mutant that holds a write to
/// 4,096 runs refuses it `OverCap`). A second undo, of nothing standing, is
/// refused and writes nothing.
#[test]
fn an_undo_that_places_5_000_runs_lands_in_one_write() {
    let (dialer, board, signer) = open(draft_landing_world());
    let session = sign_in(&board, &signer);
    let mut c = vec![run(S, 1, 3)];
    c.extend((0..4_999u64).map(|k| run(S, 5 + 2 * k, 1)));
    dialer.world().text(S, 4, &"x".repeat(10_000));
    dialer.world().change(S, c.clone());
    // The landing by hand, over C.
    let head = format!("{D}.2");
    let typed = dialer.world().position;
    let frame = frames::set_arrangement(S, &whole_of(&dialer, S, &draft_m()), typed, Some((&head, 15)), Some((&head, 15)), Some((&[], None)), None);
    let Answer::Document(ack) = board.op(Some(session.token()), &frame).expect("the landing by hand") else { panic!("closed") };
    assert_eq!(ack["resp"], "ack", "{ack}");
    assert_eq!(dialer.world().docs.get(S).unwrap().runs, draft_m(), "the premise: the merged list landed over C");
    let rows = dialer.world().rows.iter().filter(|r| r.op == "set_arrangement").count();
    dialer.clear();
    undo(&board, merger(&session, &signer), &a(S), &a(K), None, None).expect("the undo lands");
    let sent = dialer.frames("set_arrangement");
    assert_eq!(sent.len(), 1, "one frame: {:?}", dialer.names());
    let placed: usize = sent[0]["changes"].as_array().expect("changes").iter().map(|change| change["runs"].as_array().map_or(0, Vec::len)).sum();
    assert!(placed > 4_096 && placed <= 5_000, "the runs of its changes together, past one wire list: {placed}");
    let w = dialer.world();
    assert_eq!(w.rows.iter().filter(|r| r.op == "set_arrangement").count(), rows + 1, "one row");
    assert_eq!(w.docs.get(S).unwrap().runs, c, "C again, run for run");
    assert!(w.standing(S).1.is_none(), "the marker cleared");
}

/// A C MAPPED PAST THE CAP: C in `SHOT_RUN_CAP` runs, its first split in
/// two by a record covering its head, maps to one run more than one
/// write may name — refused `OverCap` with the count, after the records'
/// read and before any frame: nothing sent, nothing committed, the
/// marker standing.
#[test]
fn an_undo_whose_c_maps_past_the_cap_is_refused_over_cap_with_nothing_sent() {
    let (dialer, board, signer) = open(draft_landing_world());
    let session = sign_in(&board, &signer);
    // C: `S·1–3`, then the cap's worth less one of `S`'s positions apart.
    let mut c = vec![run(S, 1, 3)];
    c.extend((0..SHOT_RUN_CAP as u64 - 1).map(|k| run(S, 5 + 2 * k, 1)));
    let record = {
        let mut w = dialer.world();
        w.change(S, c);
        w.text(D, 19, "!");
        plant_record(&mut w, 1, 19, 1)
    };
    // The landing by hand, over C.
    let head = format!("{D}.2");
    let typed = dialer.world().position;
    let frame = frames::set_arrangement(S, &whole_of(&dialer, S, &draft_m()), typed, Some((&head, 15)), Some((&head, 15)), Some((&[], None)), None);
    let Answer::Document(ack) = board.op(Some(session.token()), &frame).expect("the landing by hand") else { panic!("closed") };
    assert_eq!(ack["resp"], "ack", "{ack}");
    let rows = dialer.world().rows.len();
    dialer.clear();
    assert_eq!(undo(&board, merger(&session, &signer), &a(S), &a(K), None, None), Err(Refusal::OverCap { runs: SHOT_RUN_CAP + 1, cap: SHOT_RUN_CAP }));
    assert!(dialer.frames("read_link").iter().any(|f| f["a"] == record), "the records read first: {:?}", dialer.names());
    assert!(dialer.frames("set_arrangement").is_empty() && dialer.frames("insert").is_empty() && dialer.frames("make_link").is_empty(), "nothing sent");
    assert_eq!(dialer.world().rows.len(), rows, "nothing committed");
    assert!(dialer.world().standing(S).1.is_some(), "the marker stands");
}

/// A record mapping C past the largest ordinal is faced, nothing sent.
///
/// A correspondence record the board serves names `S`'s own words in C as
/// a published span whose last I-address passes the range of an ordinal.
/// It is the board's fault, faced after the records' read and before any
/// frame, never a sum made unchecked and sent as a run (SP-19): nothing
/// sent, nothing committed, the marker standing.
#[test]
fn an_undo_over_a_record_mapping_c_past_the_largest_ordinal_is_faced_with_nothing_sent() {
    let (dialer, board, signer) = open(draft_landing_world());
    let session = sign_in(&board, &signer);
    landed_in_s(&board, &session, &signer);
    let record = plant_record(&mut dialer.world(), 1, u64::MAX, 3);
    let rows = dialer.world().rows.len();
    dialer.clear();
    let err = undo(&board, merger(&session, &signer), &a(S), &a(K), None, None).expect_err("the record maps C past the range");
    let Refusal::Halt(Halt::Halt(face)) = &err else { panic!("{err:?}") };
    assert!(face.state.contains("past the largest ordinal") && face.act.contains("board fault"), "{face:?}");
    assert!(dialer.frames("read_link").iter().any(|f| f["a"] == record), "the records read first: {:?}", dialer.names());
    assert!(dialer.frames("set_arrangement").is_empty() && dialer.frames("insert").is_empty() && dialer.frames("make_link").is_empty(), "nothing sent");
    assert_eq!(dialer.world().rows.len(), rows, "nothing committed");
    assert!(dialer.world().standing(S).1.is_some(), "the marker stands");
}

/// A member's own word in C is sent under the member's chain (skep #1121).
///
/// C holds the base's text and, at the adjoining ordinal, one word a
/// deposit naming `D.2` minted under the member's chain, so the core's runs
/// join the two as one run of `D`. The undo sends each run as itself — the
/// member's word at `D.2.0.1.12`, its `origin` the member — and the draft
/// holds C again, never the trunk's word of that ordinal (the mutant that
/// spells the write from the core's runs sends one run of `D`).
#[test]
fn the_undo_sends_a_members_own_word_under_the_members_chain() {
    let (dialer, board, signer) = open(draft_landing_world());
    let session = sign_in(&board, &signer);
    let c = vec![run(D, 1, 11), run(&member(), 12, 1)];
    {
        let mut w = dialer.world();
        w.text(&member(), 12, "z");
        w.change(S, c.clone());
    }
    let at = landed_by_hand(&board, &session, &dialer, &draft_m());
    dialer.clear();
    let undone = undo(&board, merger(&session, &signer), &a(S), &a(K), None, None).expect("undone");
    assert_eq!(undone.restored, Some((a(&format!("{D}.1")), 11)), "the pair read before the landing");
    let query = &dialer.frames("find_links_ftt")[0]["q"];
    assert_eq!(query["from"], json!([frames::i_span(&format!("{D}.0.1.1"), 12)]), "the premise: the core joins the member's word to the trunk's, one run of D");
    let sent = dialer.frames("set_arrangement");
    assert_eq!(sent.len(), 1, "one write: {:?}", dialer.ops());
    assert_eq!(sent[0]["as_of"].as_u64(), Some(at), "typed against the landing's position: {}", sent[0]);
    let runs = [frames::shot_run(D, &format!("{D}.0.1.1"), 11), frames::shot_run(&member(), &format!("{}.0.1.12", member()), 1)];
    assert_eq!(sent[0]["changes"], json!([frames::placed(1, width_of(&draft_m()), &runs)]), "each run on the chain that minted it, the member its word's origin");
    assert_eq!(dialer.world().docs.get(S).unwrap().runs, c, "C again, the member's word its own");
}

/// A trunk's word standing for a member's is no landing taken back.
///
/// Skep #1121, P4: C holds a word minted under `D.2`'s chain. After the
/// landing of the baseless draft, a re-arrangement leaves the base's text
/// and, in that word's place, the trunk's word of the same ordinal: the
/// core's runs of the two states are one, their words are not. The undo,
/// typed at the caller's own last acknowledgment, the re-arrangement's, is
/// not answered `NothingToUndo`: it lands C with the member's word (the
/// mutant that compares the core's runs answers the merge already taken
/// back and sends nothing).
#[test]
fn a_baseless_landing_is_not_taken_back_where_the_trunks_word_stands_for_a_members() {
    let plain = "1.0.1.0.67";
    let c = vec![run(D, 1, 11), run(&member(), 12, 1)];
    let mut w = draft_landing_world();
    w.text(&member(), 12, "z");
    w.doc(plain, false, ACCOUNT, c.clone());
    let (dialer, board, signer) = open(w);
    let session = sign_in(&board, &signer);
    // The landing by hand: a baseless draft records nothing, and its row
    // carries the request's merge.
    let head = format!("{D}.2");
    let typed = dialer.world().position;
    let landing = frames::set_arrangement(plain, &whole_of(&dialer, plain, &draft_m()), typed, Some((&head, 15)), None, Some((&[S], None)), None);
    let at = dialer.world().apply(&landing)["at"].as_u64().expect("the landing's ack");
    // The re-arrangement: the trunk's twelfth word where the member's stood.
    let rearranged = frames::set_arrangement(plain, &whole_of(&dialer, plain, &[run(D, 1, 12)]), at, None, None, None, None);
    let r = dialer.world().apply(&rearranged)["at"].as_u64().expect("the re-arrangement's ack");
    dialer.clear();
    let undone = undo(&board, merger(&session, &signer), &a(plain), &a(K), Some(r), None).expect("the landing taken back");
    assert_eq!(undone.restored, None, "no base to restore");
    assert_eq!(dialer.positions("image"), [typed, r], "C before the landing, then the draft at its latest re-arrangement: {:?}", dialer.ops());
    let sent = dialer.frames("set_arrangement");
    assert_eq!(sent.len(), 1, "one write: {:?}", dialer.ops());
    assert_eq!(sent[0]["as_of"].as_u64(), Some(r), "typed against the caller's own last ack: {}", sent[0]);
    assert_eq!(sent[0]["changes"], whole_changes(12, &c), "C, the member's word under its own chain, over the twelve the draft holds");
    assert_eq!(dialer.world().docs.get(plain).unwrap().runs, c, "C again");
}

/// An undo is refused at the cap counted on the runs it would write.
///
/// C holds the trunk's words and a member's by turns at adjoining ordinals:
/// one run more than a write may place as the board serves them, read in
/// pages past its run budget, and one run of `D` as the core joins them. The
/// undo answers `OverCap`
/// with the written count after the records' read and before any frame:
/// nothing sent, nothing committed, the marker standing (the mutant that
/// counts the core's runs sends the frame).
#[test]
fn an_undo_is_refused_over_cap_on_the_runs_it_would_write_however_few_the_core_joins() {
    let (dialer, board, signer) = open(draft_landing_world());
    let session = sign_in(&board, &signer);
    dialer.world().change(S, alternating());
    landed_by_hand(&board, &session, &dialer, &draft_m());
    let rows = dialer.world().rows.len();
    dialer.clear();
    assert_eq!(undo(&board, merger(&session, &signer), &a(S), &a(K), None, None), Err(Refusal::OverCap { runs: SHOT_RUN_CAP + 1, cap: SHOT_RUN_CAP }));
    assert_eq!(dialer.frames("image").len(), (SHOT_RUN_CAP + 1).div_ceil(1 << 12), "the premise: C read in pages past the board's run budget, 4,096 runs a page: {:?}", dialer.names());
    let query = &dialer.frames("find_links_ftt")[0]["q"];
    assert_eq!(query["from"], json!([frames::i_span(&format!("{D}.0.1.1"), SHOT_RUN_CAP as u64 + 1)]), "the premise: one run of D as the core joins them, the records read first");
    assert!(dialer.frames("set_arrangement").is_empty() && dialer.frames("insert").is_empty() && dialer.frames("make_link").is_empty(), "nothing sent");
    assert_eq!(dialer.world().rows.len(), rows, "nothing committed");
    assert!(dialer.world().standing(S).1.is_some(), "the marker stands");
}

/// A BASE RECORDED AND NO MARKER (P4's second case): the merge was
/// published from the draft — the draft's own publication moved its base
/// to the member minted and cleared the marker — so there is nothing to
/// undo, and an undo from the feed would re-record the base backward
/// (N4). The words come from the draft's own latest marker-ending feed
/// row, read on the supplement and never acted on: a `publish` row, P4's
/// words with the member the row names first as the version. Nothing is
/// sent and no history is read.
#[test]
fn undo_after_a_publication_answers_nothing_to_undo_with_p4s_words_and_sends_nothing() {
    let (dialer, board, signer) = open(draft_landing_world());
    let session = sign_in(&board, &signer);
    landed_in_s(&board, &session, &signer);
    // The merge published from the draft: the shot committed as the
    // board commits one it admitted.
    let runs = shot_runs(&draft_m());
    let head = format!("{D}.2");
    let frame = frames::publication(&frames::PublishFrame { doc: Some(D), base: Some((&head, 15)), draft: Some(S), runs: &runs, ..frames::PublishFrame::default() });
    let ack = dialer.world().apply(&frame);
    assert_eq!(acked_addr(&ack), Some(format!("{D}.3").as_str()), "{ack}");
    assert_eq!(dialer.world().standing(S), (Some((format!("{D}.3"), 18)), None), "the premise: the base moved, the marker cleared");
    let rows = dialer.world().rows.len();
    dialer.clear();
    let err = undo(&board, merger(&session, &signer), &a(S), &a(K), None, None).expect_err("nothing to undo");
    assert_eq!(err, Refusal::NothingToUndo { draft: a(S), why: NoUndo::Published { version: a(&format!("{D}.3")) } });
    assert_eq!(err.to_string(), format!("nothing to undo: {S} was published as version {D}.3 since, and a version stands — the way back is to publish the older text again"));
    let ops = dialer.ops();
    assert!(dialer.frames("set_arrangement").is_empty() && dialer.frames("insert").is_empty(), "nothing sent: {ops:?}");
    assert!(ops.iter().any(|o| o.starts_with("GET /changes?") && o.contains(&format!("under={S}")) && o.contains("drafts=true")), "the words off the draft's own rows, on the supplement: {ops:?}");
    assert!(dialer.positions("doc_metadata").is_empty() && dialer.positions("image").is_empty(), "no read of history: {ops:?}");
    assert_eq!(dialer.world().rows.len(), rows, "nothing committed");
}

/// An undo after a merge's shot names its version, never the base kept.
///
/// The shot keeps the draft's recorded base (skep #944): the draft,
/// staged at `D.1` and never landed into, carries no marker, so the undo
/// meets a base recorded and no marker, and its words name the member
/// the draft's latest `publish` row names first, the one the shot
/// minted. Nothing is sent.
#[test]
fn undo_after_a_merge_shot_naming_the_draft_names_the_merges_version_not_the_base_it_kept() {
    let (dialer, board, signer) = open(draft_landing_world());
    let session = sign_in(&board, &signer);
    let runs = shot_runs(&draft_m());
    let head = format!("{D}.2");
    let frame = frames::publication(&frames::PublishFrame { doc: Some(D), base: Some((&head, 15)), draft: Some(S), keep_base: true, runs: &runs, ..frames::PublishFrame::default() });
    let ack = dialer.world().apply(&frame);
    assert_eq!(acked_addr(&ack), Some(format!("{D}.3").as_str()), "{ack}");
    assert_eq!(dialer.world().standing(S), (Some((format!("{D}.1"), 11)), None), "the premise: the base kept, no marker");
    let rows = dialer.world().rows.len();
    dialer.clear();
    let err = undo(&board, merger(&session, &signer), &a(S), &a(K), None, None).expect_err("nothing to undo");
    assert_eq!(err, Refusal::NothingToUndo { draft: a(S), why: NoUndo::Published { version: a(&format!("{D}.3")) } });
    assert!(dialer.frames("set_arrangement").is_empty() && dialer.frames("insert").is_empty(), "nothing sent: {:?}", dialer.ops());
    assert_eq!(dialer.world().rows.len(), rows, "nothing committed");
}

/// AN INHERITED MARKER (P2): a `stage` of the marked draft puts the
/// marker on the alternative at the stage's own position, one commit of
/// three records; the undo reads before it — `at − 1` refused
/// `not_a_position`, then `nearest` — and meets the alternative's own
/// `doc_not_registered`: nothing of its own to take back, said in P2's
/// words, with nothing sent.
#[test]
fn undo_at_an_inherited_marker_answers_p2s_words_with_nothing_sent() {
    let (dialer, board, signer) = open(draft_landing_world());
    let session = sign_in(&board, &signer);
    landed_in_s(&board, &session, &signer);
    let before_stage = dialer.world().position;
    let Answer::Document(ack) = board.op(Some(session.token()), &frames::stage(S, None)).expect("the stage") else { panic!("closed") };
    let t = acked_addr(&ack).expect("the alternative").to_string();
    let staged_at = acked_at(&ack).expect("its position");
    assert_eq!(staged_at, before_stage + 3, "the premise: a stage is one commit of three records");
    assert_eq!(
        dialer.world().standing(&t),
        (Some((format!("{D}.2"), 15)), Some(Marker { sides: vec![], head: format!("{D}.2"), head_copied: 15, at: staged_at })),
        "the premise: the marker inherited, stamped at the stage"
    );
    let rows = dialer.world().rows.len();
    dialer.clear();
    let err = undo(&board, merger(&session, &signer), &a(&t), &a(K), None, None).expect_err("inherited");
    assert_eq!(err, Refusal::NothingToUndo { draft: a(&t), why: NoUndo::Inherited });
    assert_eq!(err.to_string(), format!("nothing to undo: {t} inherited the merge when it was staged; discard it or edit it"));
    assert_eq!(dialer.positions("doc_metadata"), [staged_at - 1, before_stage], "at − 1 inside the stage's commit, then nearest, where the alternative is unregistered: {:?}", dialer.ops());
    assert!(dialer.positions("image").is_empty(), "nothing imaged");
    assert!(dialer.frames("set_arrangement").is_empty() && dialer.frames("insert").is_empty(), "nothing sent: {:?}", dialer.ops());
    assert_eq!(dialer.world().rows.len(), rows);
}

/// An inherited marker withdrawn and put back is inherited still (P2).
///
/// Skep #964: the withdrawal's undo puts the marker back with its own
/// `at`, the alternative's mint, so the undo after it reads the state
/// before that position and meets the alternative's own
/// `doc_not_registered`, as before the withdrawal: nothing to undo,
/// nothing sent.
#[test]
fn an_inherited_marker_withdrawn_and_put_back_still_answers_inherited() {
    let (dialer, board, signer) = open(draft_landing_world());
    let session = sign_in(&board, &signer);
    let m = merger(&session, &signer);
    landed_in_s(&board, &session, &signer);
    let Answer::Document(ack) =
        board.op(Some(session.token()), &frames::stage(S, None)).expect("the stage")
    else {
        panic!("closed")
    };
    let t = acked_addr(&ack).expect("the alternative").to_string();
    let staged_at = acked_at(&ack).expect("its position");
    let withdrawn = withdraw(&board, m, &a(&t), &a(K), None).expect("withdrawn");
    unwithdraw(&board, m, &a(&t), &a(K), withdrawn.position, None, None).expect("put back");
    assert_eq!(
        dialer.world().standing(&t).1.map(|m| m.at),
        Some(staged_at),
        "the premise: the marker back at the mint"
    );
    let rows = dialer.world().rows.len();
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
    assert_eq!(dialer.world().rows.len(), rows, "nothing committed");
}

/// An undo of a baseless landing goes by its feed row, with no base sent.
///
/// With no base record (N4's baseless case), the landing is the one
/// standing by the draft's own `set_arrangement` rows on the supplement,
/// here the one row that carries a `merge` term — the request's merge
/// beside a null base, the row being the one place the board keeps a
/// baseless landing's position (wire.md §The change feed; skep #784, #914)
/// — and the undo sends C read before it with no `base`, no `head` and no
/// `merge`, `as_of` the row's `at`. A re-run, in the same session or a
/// fresh one, finds the undo's own row past the landing's, the draft there
/// as C: the merge already taken back, nothing sent (skep #889; the next
/// test).
#[test]
fn undo_of_a_baseless_landing_goes_by_its_feed_row_with_no_base_sent() {
    let plain = "1.0.1.0.67";
    let mut w = draft_landing_world();
    w.doc(plain, false, ACCOUNT, vec![run(D, 1, 11)]);
    let (dialer, board, signer) = open(w);
    let session = sign_in(&board, &signer);
    let merged = compose(&board, Some(session.token()), &draft_inputs()).expect("composed");
    let before = dialer.world().position;
    let landed = land(&board, &merged, draft_landing(&session, &signer, Some(a(plain)))).expect("landed");
    let (at, link) = landing_of(&landed);
    assert_eq!(at, before + 1, "the premise: a baseless landing is one commit of one record, so the number below it is the commit before");
    let feed_row = |w: &World| w.rows.iter().rev().find(|r| r.op == "set_arrangement").map(|r| (r.at, r.terms.clone())).expect("the row");
    assert_eq!(
        feed_row(&dialer.world()),
        (at, Some((None, Some(json!({"sides": [S], "head": format!("{D}.2")}))))),
        "the premise: the landing's row, the request's merge beside no base"
    );
    assert_eq!(dialer.world().standing(plain), (None, None), "the premise: nothing recorded");
    assert_eq!(
        dialer.frames("set_arrangement").last().map(|f| f["changes"].clone()),
        Some(whole_changes(11, &m_runs(&merged))),
        "the landing into a draft the merge never read: one change over the eleven positions it held"
    );
    dialer.clear();
    let undone = undo(&board, merger(&session, &signer), &a(plain), &a(K), None, None).expect("undone");
    let ops = dialer.ops();
    assert!(ops.iter().any(|o| o.starts_with("GET /changes?") && o.contains(&format!("under={plain}")) && o.contains("drafts=true")), "the lookup walks the draft's own rows on the supplement: {ops:?}");
    assert_eq!(undone.restored, None, "no base to restore");
    assert!(undone.record.is_some(), "the landing's record stood, so one replaces it");
    assert_eq!(dialer.positions("doc_metadata"), [before], "the pre-landing read at `at − 1`, the position before the landing's one record");
    let frame = &dialer.frames("set_arrangement")[0];
    assert_eq!(frame["as_of"].as_u64(), Some(at), "the row's at");
    assert_eq!(frame["changes"], whole_changes(width_of(&m_runs(&merged)), &[run(D, 1, 11)]), "C, over every position the draft holds");
    assert!(frame.get("base").is_none() && frame.get("head").is_none() && frame.get("merge").is_none(), "a baseless document is never sent a base: {frame}");
    assert_eq!(frame["id"].as_str(), Some(format!("undo:{plain}:{at}.arrangement").as_str()));
    let w = dialer.world();
    assert_eq!(w.docs.get(plain).unwrap().runs, vec![run(D, 1, 11)]);
    assert_eq!(w.standing(plain), (None, None), "nothing recorded");
    assert_eq!(feed_row(&w), (undone.position, Some((None, None))), "the undo's row, both terms null");
    drop(w);
    let atom = appended_record(&dialer);
    assert!(atom["landed"].is_null());
    assert_eq!(atom["replaces"].as_str(), Some(link.to_string().as_str()));
    // A re-run, in this session and in a fresh one, the memo cleared:
    // the merge already taken back, nothing sent.
    let rows = dialer.world().rows.len();
    for fresh in [false, true] {
        if fresh {
            dialer.world().memo.clear();
        }
        dialer.clear();
        assert_eq!(undo(&board, merger(&session, &signer), &a(plain), &a(K), None, None), Err(Refusal::NothingToUndo { draft: a(plain), why: NoUndo::TakenBack }), "fresh: {fresh}");
        assert!(dialer.frames("set_arrangement").is_empty() && dialer.frames("insert").is_empty(), "fresh: {fresh}: nothing sent: {:?}", dialer.ops());
        assert_eq!(dialer.world().rows.len(), rows, "fresh: {fresh}: nothing committed");
    }
}

/// A baseless undo run again after it landed is nothing to undo.
///
/// The draft carries no base record, so its feed rows are the only
/// account of its landing and of the undo after it, whose row names no
/// merge (wire.md §The change feed). A re-run reads the draft at the
/// undo's row past the landing's and finds it as C mapped: the merge
/// already taken back, for good, nothing sent (P4; skep #889, #914). (a)
/// In a fresh session, the memo cleared: the refusal's words, the reads at
/// the position before the landing and at the undo's, no write, the
/// undo's record current. (b) The undo's record unwritten, its link
/// refused for a head owed: taken back, the landing's record current. (c)
/// The landing's record unwritten: the undo writes none, and its re-run
/// finds the merge taken back. (d) The person's edit since the undo, the
/// re-run typed at their own last ack: nothing sent, the edit standing.
/// (e) A restore of M after the undo, the latest re-arrangement M: the
/// landing stays taken back, a restore bringing none back — in a fresh
/// session and typed at the restore alike, nothing sent and M standing
/// (the mutant that judges only the latest plain row lands C over it).
/// (f) A record minted over C's own words between the two runs: the state
/// at the undo's row, mapped through it, is C mapped. (g) The undo's
/// acknowledgment lost and its re-ask's: the undo reads its own row past
/// the landing, the draft there C, answers that row's position and writes
/// its record; its re-run in the same session finds the merge taken back,
/// the undo's record current.
#[test]
fn a_baseless_undo_run_again_after_it_landed_is_nothing_to_undo() {
    let plain = "1.0.1.0.67";
    let baseless = |c: Vec<Run>| {
        let mut w = draft_landing_world();
        w.text(plain, 1, "?!");
        w.doc(plain, false, ACCOUNT, c);
        w
    };
    let c = vec![run(D, 1, 11)];
    let taken_back = || -> Result<Undone, Refusal> {
        Err(Refusal::NothingToUndo { draft: a(plain), why: NoUndo::TakenBack })
    };
    let writes = ["set_arrangement", "insert", "make_link", "create_new_document"];
    let wrote = |dialer: &Scripted| {
        dialer.ops().into_iter().filter(|o| writes.contains(&o.as_str())).collect::<Vec<_>>()
    };

    // (a) A fresh session.
    let (dialer, board, signer) = open(baseless(c.clone()));
    let session = sign_in(&board, &signer);
    let m = merger(&session, &signer);
    let merged = compose(&board, Some(session.token()), &draft_inputs()).expect("composed");
    let before = dialer.world().position;
    let (at, link) = landing_of(
        &land(&board, &merged, draft_landing(&session, &signer, Some(a(plain))))
            .expect("landed"),
    );
    let undone = undo(&board, m, &a(plain), &a(K), None, None).expect("undone");
    dialer.world().memo.clear();
    let rows = dialer.world().rows.len();
    dialer.clear();
    let err = undo(&board, m, &a(plain), &a(K), None, None);
    assert_eq!(err, taken_back(), "(a)");
    assert_eq!(
        err.unwrap_err().to_string(),
        format!("nothing to undo: the merge in {plain} was already taken back")
    );
    assert_eq!(at - 1, before, "(a): the premise: the landing is one record, the number below it the commit before");
    assert_eq!(
        dialer.positions("doc_metadata"),
        [before],
        "(a): the pre-landing read at the position before the landing: {:?}",
        dialer.ops()
    );
    assert_eq!(
        dialer.positions("image"),
        [before, undone.position],
        "(a): C before the landing, then the draft at the undo's row"
    );
    assert!(wrote(&dialer).is_empty(), "(a): nothing sent: {:?}", dialer.ops());
    let w = dialer.world();
    assert_eq!(w.rows.len(), rows, "(a): nothing committed");
    assert_eq!(w.docs.get(plain).unwrap().runs, c, "(a): C stands");
    drop(w);
    let found = current(&board, Some(session.token()), &a(K), &merged.key)
        .expect("the lookup")
        .expect("a record");
    assert_eq!(
        (found.link, found.landed, found.replaces),
        (undone.record.clone(), None, Some(link)),
        "(a): the undo's record current"
    );

    // (b) The undo's record unwritten, the board too busy to find its
    // journal.
    let (dialer, board, signer) = open(baseless(c.clone()));
    let session = sign_in(&board, &signer);
    let m = merger(&session, &signer);
    let merged = compose(&board, Some(session.token()), &draft_inputs()).expect("composed");
    let (_, link) = landing_of(
        &land(&board, &merged, draft_landing(&session, &signer, Some(a(plain))))
            .expect("landed"),
    );
    too_busy_for_the_find(&mut dialer.world());
    let err =
        undo(&board, m, &a(plain), &a(K), None, None).expect_err("the undo's record unwritten");
    let Refusal::Halt(Halt::Halt(face)) = &err else { panic!("(b): {err:?}") };
    assert!(
        face.state.contains("the record of the undo is not written"),
        "(b): the premise: {face}"
    );
    assert_eq!(dialer.world().docs.get(plain).unwrap().runs, c, "(b): the premise, C");
    dialer.world().memo.clear();
    dialer.clear();
    assert_eq!(undo(&board, m, &a(plain), &a(K), None, None), taken_back(), "(b)");
    assert!(wrote(&dialer).is_empty(), "(b): nothing sent: {:?}", dialer.ops());
    let found = current(&board, Some(session.token()), &a(K), &merged.key)
        .expect("the lookup")
        .expect("a record");
    assert_eq!(found.link, Some(link), "(b): the landing's record current");

    // (c) The landing's record unwritten, the board too busy to find its
    // journal.
    let (dialer, board, signer) = open(baseless(c.clone()));
    let session = sign_in(&board, &signer);
    let m = merger(&session, &signer);
    let merged = compose(&board, Some(session.token()), &draft_inputs()).expect("composed");
    too_busy_for_the_find(&mut dialer.world());
    land(&board, &merged, draft_landing(&session, &signer, Some(a(plain))))
        .expect_err("(c): the premise, the landing's record unwritten");
    dialer.world().memo.clear();
    let undone = undo(&board, m, &a(plain), &a(K), None, None).expect("undone");
    assert_eq!(undone.record, None, "(c): no record stood to replace");
    dialer.world().memo.clear();
    dialer.clear();
    assert_eq!(undo(&board, m, &a(plain), &a(K), None, None), taken_back(), "(c)");
    assert!(wrote(&dialer).is_empty(), "(c): nothing sent: {:?}", dialer.ops());

    // (d) The person's edit since the undo, the re-run typed at it.
    let (dialer, board, signer) = open(baseless(c.clone()));
    let session = sign_in(&board, &signer);
    let m = merger(&session, &signer);
    let merged = compose(&board, Some(session.token()), &draft_inputs()).expect("composed");
    land(&board, &merged, draft_landing(&session, &signer, Some(a(plain)))).expect("landed");
    undo(&board, m, &a(plain), &a(K), None, None).expect("undone");
    // "cat " deleted.
    let edited = vec![run(D, 1, 4), run(D, 9, 3)];
    let e = dialer.world().change(plain, edited.clone());
    let rows = dialer.world().rows.len();
    dialer.clear();
    assert_eq!(undo(&board, m, &a(plain), &a(K), Some(e), None), taken_back(), "(d)");
    assert!(wrote(&dialer).is_empty(), "(d): nothing sent: {:?}", dialer.ops());
    let w = dialer.world();
    assert_eq!(w.docs.get(plain).unwrap().runs, edited, "(d): the edit stands");
    assert_eq!(w.rows.len(), rows, "(d): nothing committed");
    drop(w);

    // (e) A restore of M after the undo, by hand: a `set_arrangement`
    // naming no merge.
    let (dialer, board, signer) = open(baseless(c.clone()));
    let session = sign_in(&board, &signer);
    let m = merger(&session, &signer);
    let merged = compose(&board, Some(session.token()), &draft_inputs()).expect("composed");
    land(&board, &merged, draft_landing(&session, &signer, Some(a(plain)))).expect("landed");
    undo(&board, m, &a(plain), &a(K), None, None).expect("undone");
    let restored = m_runs(&merged);
    let typed = dialer.world().position;
    let frame =
        frames::set_arrangement(plain, &whole_of(&dialer, plain, &restored), typed, None, None, None, None);
    let r = dialer.world().apply(&frame)["at"].as_u64().expect("(e): the restore's ack");
    assert_eq!(dialer.world().docs.get(plain).unwrap().runs, restored, "(e): the premise, M");
    // A fresh session, as the command's run is: no memo of the undo's
    // write under its id; then typed at the restore, the editor's own.
    dialer.world().memo.clear();
    let rows = dialer.world().rows.len();
    for own_ack in [None, Some(r)] {
        dialer.clear();
        assert_eq!(undo(&board, m, &a(plain), &a(K), own_ack, None), taken_back(), "(e): {own_ack:?}");
        assert!(wrote(&dialer).is_empty(), "(e): {own_ack:?}: nothing sent: {:?}", dialer.ops());
        let w = dialer.world();
        assert_eq!(w.rows.len(), rows, "(e): {own_ack:?}: nothing committed");
        assert_eq!(w.docs.get(plain).unwrap().runs, restored, "(e): {own_ack:?}: M stands");
    }

    // (f) A record minted over C's own words between the two runs.
    let mine = vec![run(D, 1, 11), run(plain, 1, 2)];
    let (dialer, board, signer) = open(baseless(mine.clone()));
    let session = sign_in(&board, &signer);
    let m = merger(&session, &signer);
    let merged = compose(&board, Some(session.token()), &draft_inputs()).expect("composed");
    land(&board, &merged, draft_landing(&session, &signer, Some(a(plain)))).expect("landed");
    undo(&board, m, &a(plain), &a(K), None, None).expect("undone");
    assert_eq!(dialer.world().docs.get(plain).unwrap().runs, mine, "(f): the premise, C");
    // The record: `from` the draft's "?!", `to` the trunk's `D·19–20`.
    let record = {
        let mut w = dialer.world();
        w.text(D, 19, "?!");
        let addr = format!("{plain}.0.2.{}", 90 + w.links.len());
        w.links.push(LinkRow {
            addr: addr.clone(),
            home: plain.into(),
            from: vec![i_addr(&a(plain), 1)],
            to: vec![i_addr(&a(D), 19)],
            ty: frames::T_CORRESPONDENCE.into(),
            width: 2,
            at: None,
        });
        w.memo.clear();
        addr
    };
    dialer.clear();
    assert_eq!(undo(&board, m, &a(plain), &a(K), None, None), taken_back(), "(f)");
    assert!(
        dialer.frames("read_link").iter().any(|f| f["a"] == record),
        "(f): the record read: {:?}",
        dialer.ops()
    );
    assert!(wrote(&dialer).is_empty(), "(f): nothing sent: {:?}", dialer.ops());

    // (g) The undo's acknowledgment lost and its re-ask's, the re-run in
    // the same session.
    let (dialer, board, signer) = open(baseless(c.clone()));
    let session = sign_in(&board, &signer);
    let m = merger(&session, &signer);
    let merged = compose(&board, Some(session.token()), &draft_inputs()).expect("composed");
    let (_, link) = landing_of(
        &land(&board, &merged, draft_landing(&session, &signer, Some(a(plain))))
            .expect("landed"),
    );
    dialer.clear();
    dialer.world().drop_acks = 2;
    let undone = undo(&board, m, &a(plain), &a(K), None, None).expect("(g): its own row found");
    let row = dialer.world().rows.iter().rev().find(|r| r.op == "set_arrangement").expect("(g): the undo's row").at;
    assert_eq!(undone.position, row, "(g): the position its row names");
    assert_eq!(dialer.frames("set_arrangement").len(), 2, "(g): the write and its re-ask, nothing more: {:?}", dialer.ops());
    assert_eq!(dialer.world().docs.get(plain).unwrap().runs, c, "(g): C");
    assert_eq!(appended_record(&dialer)["replaces"].as_str(), Some(link.to_string().as_str()), "(g): the undo's record written");
    dialer.clear();
    assert_eq!(undo(&board, m, &a(plain), &a(K), None, None), taken_back(), "(g)");
    assert!(wrote(&dialer).is_empty(), "(g): nothing sent: {:?}", dialer.ops());
    let found = current(&board, Some(session.token()), &a(K), &merged.key)
        .expect("the lookup")
        .expect("a record");
    assert_eq!((found.link, found.replaces), (undone.record, Some(link)), "(g): the undo's record current");
}

/// Lands `draft_m()` in the baseless draft `plain` by hand, its row
/// carrying the request's merge, answering the landing's position.
fn baseless_landing(dialer: &Scripted, plain: &str) -> u64 {
    let head = format!("{D}.2");
    let typed = dialer.world().position;
    let landing = frames::set_arrangement(plain, &whole_of(dialer, plain, &draft_m()), typed, Some((&head, 15)), None, Some((&[S], None)), None);
    dialer.world().apply(&landing)["at"].as_u64().expect("the landing's ack")
}

/// A baseless undo that sent another account's words mapped is taken back.
///
/// The baseless draft's C holds "abc", words of `THEIR_DRAFT`, which the
/// draft's owner published as `THEIR_EDITION`'s: the undo sends them as the
/// edition's. Run again, it reads the draft at its own row, the edition's
/// words where C held the draft's, and maps both through one read of the
/// records over the two: one state, the merge already taken back, nothing
/// sent.
#[test]
fn a_baseless_undo_that_sent_another_accounts_words_mapped_is_taken_back_when_run_again() {
    let plain = "1.0.1.0.67";
    let mut w = draft_landing_world();
    their_publication(&mut w);
    w.doc(plain, false, ACCOUNT, vec![run(D, 1, 11), run(THEIR_DRAFT, 1, 3)]);
    let (dialer, board, signer) = open(w);
    let session = sign_in(&board, &signer);
    let m = merger(&session, &signer);
    baseless_landing(&dialer, plain);
    undo(&board, m, &a(plain), &a(K), None, None).expect("undone");
    let mapped = vec![run(D, 1, 11), run(THEIR_EDITION, 1, 3)];
    assert_eq!(dialer.world().docs.get(plain).unwrap().runs, mapped, "the premise: C sent mapped");
    dialer.world().memo.clear();
    let rows = dialer.world().rows.len();
    dialer.clear();
    assert_eq!(undo(&board, m, &a(plain), &a(K), None, None), Err(Refusal::NothingToUndo { draft: a(plain), why: NoUndo::TakenBack }));
    assert!(dialer.frames("set_arrangement").is_empty() && dialer.frames("insert").is_empty(), "nothing sent: {:?}", dialer.ops());
    assert_eq!(dialer.world().rows.len(), rows, "nothing committed");
    assert_eq!(dialer.world().docs.get(plain).unwrap().runs, mapped, "the draft as it stands");
}

/// A baseless landing's re-arrangement holding words a record maps onto C's
/// is the merge taken back.
///
/// C holds the base's text and `D`'s "!!!", the words a publication of `S`
/// made of `S`'s own "!!!", its record homed in `S`. After the landing a
/// re-arrangement leaves the base's text and `S`'s own words in their place.
/// The undo reads the draft there before the records, then one read of the
/// records over C and that state finds `S`'s record: the state maps onto
/// C, the merge already taken back, nothing sent and the re-arrangement
/// standing (the mutant that reads the records over C alone never reads
/// `S`'s, finds the states apart and sends the write, which the board
/// refuses `arrangement_moved`).
#[test]
fn a_baseless_landing_is_taken_back_where_its_re_arrangement_holds_words_a_record_maps_onto_c() {
    let plain = "1.0.1.0.67";
    let mut w = draft_landing_world();
    w.text(D, 19, "!!!");
    let record = plant_record(&mut w, 1, 19, 3);
    w.doc(plain, false, ACCOUNT, vec![run(D, 1, 11), run(D, 19, 3)]);
    let (dialer, board, signer) = open(w);
    let session = sign_in(&board, &signer);
    let before = dialer.world().position;
    let at = baseless_landing(&dialer, plain);
    let stray = vec![run(D, 1, 11), run(S, 1, 3)];
    let rearranged = frames::set_arrangement(plain, &whole_of(&dialer, plain, &stray), at, None, None, None, None);
    let r = dialer.world().apply(&rearranged)["at"].as_u64().expect("the re-arrangement's ack");
    let rows = dialer.world().rows.len();
    dialer.clear();
    assert_eq!(undo(&board, merger(&session, &signer), &a(plain), &a(K), None, None), Err(Refusal::NothingToUndo { draft: a(plain), why: NoUndo::TakenBack }));
    assert_eq!(dialer.positions("image"), [before, r], "C before the landing, then the draft at its re-arrangement: {:?}", dialer.ops());
    let names = dialer.names();
    let first_find = names.iter().position(|n| n == "find_links_ftt").expect("the records' read");
    assert!(names.iter().rposition(|n| n == "image").is_some_and(|last| last < first_find), "both states read before the records: {names:?}");
    assert!(dialer.frames("read_link").iter().any(|f| f["a"] == record), "S's record read over the re-arrangement's words: {:?}", dialer.ops());
    assert!(dialer.frames("set_arrangement").is_empty() && dialer.frames("insert").is_empty(), "nothing sent: {:?}", dialer.ops());
    assert_eq!(dialer.world().rows.len(), rows, "nothing committed");
    assert_eq!(dialer.world().docs.get(plain).unwrap().runs, stray, "the re-arrangement stands");
}

/// One merge landed twice in a baseless draft is undone a landing at a time.
///
/// Skep #914, over skep #790's same landing: the draft landing's merge lands
/// in `P`, a draft the board records no base for, with its record, then is
/// composed again and landed again with nothing between — the same landing,
/// its record the first's, its row a write of its own. The first undo takes
/// the second write back: C, the state before it, is M, sent as a plain
/// re-arrangement naming no `merge`, and no record is written, the first
/// landing's standing for the landing that stands again, which
/// `standing_landing` answers (the mutant that judges the record by no
/// landing beneath replaces it). The second undo takes the first landing
/// back, typed against the first undo's write — the put-back, `P`'s words
/// there the first landing's — `P` as it stood before the merge, the first
/// record replaced (the mutant that never finds the landing beneath answers
/// the merge taken back). A third has nothing to undo.
#[test]
fn one_merge_landed_twice_in_a_baseless_draft_is_undone_a_landing_at_a_time() {
    let p = "1.0.1.0.67";
    let c = vec![run(D, 1, 11)];
    let mut w = draft_landing_world();
    w.doc(p, false, ACCOUNT, c.clone());
    let (dialer, board, signer) = open(w);
    let session = sign_in(&board, &signer);
    let m = merger(&session, &signer);
    let into_p = || draft_landing(&session, &signer, Some(a(p)));
    let merged = compose(&board, Some(session.token()), &draft_inputs()).expect("composed");
    let (first_at, first) = landing_of(&land(&board, &merged, into_p()).expect("landed"));
    let again = compose(&board, Some(session.token()), &draft_inputs()).expect("composed again");
    let (second_at, record) = landing_of(&land(&board, &again, into_p()).expect("landed again"));
    assert!(
        record == first && second_at > first_at,
        "the premise: the same landing, a write of its own"
    );
    // The first undo: the second write taken back, no record.
    dialer.clear();
    let undone = undo(&board, m, &a(p), &a(K), None, None).expect("the second write taken back");
    let frame = dialer.frames("set_arrangement")[0].clone();
    assert_eq!(frame["as_of"].as_u64(), Some(second_at), "typed against the second write: {frame}");
    assert!(
        frame.get("base").is_none() && frame.get("head").is_none() && frame.get("merge").is_none(),
        "a plain re-arrangement: {frame}"
    );
    assert_eq!((undone.record.clone(), undone.restored.clone(), undone.marker.clone()), (None, None, None));
    assert!(
        dialer.frames("insert").is_empty() && dialer.frames("make_link").is_empty(),
        "no record: {:?}",
        dialer.ops()
    );
    assert_eq!(dialer.world().docs.get(p).unwrap().runs, m_runs(&merged), "P holds M, as the first landing left it");
    assert_eq!(
        standing_landing(&board, Some(session.token()), &a(K), &a(p), ACCOUNT)
            .expect("the lookup")
            .and_then(|r| r.link),
        Some(first.clone()),
        "the first landing standing again, on its record"
    );
    // The second undo: typed against the first undo's write.
    dialer.clear();
    let restored = undo(&board, m, &a(p), &a(K), None, None).expect("the first landing taken back");
    assert_eq!(
        dialer.frames("set_arrangement")[0]["as_of"],
        json!(undone.position),
        "typed against the put-back"
    );
    assert_eq!(restored.marker, None);
    assert_eq!(dialer.world().docs.get(p).unwrap().runs, c, "P as it stood before the merge");
    assert_eq!(
        appended_record(&dialer)["replaces"].as_str(),
        Some(first.to_string().as_str()),
        "the first landing's record replaced"
    );
    // A third: nothing to undo.
    assert_eq!(
        undo(&board, m, &a(p), &a(K), None, None),
        Err(Refusal::NothingToUndo { draft: a(p), why: NoUndo::TakenBack })
    );
}

/// An undo of a baseless landing with no record replaces no other merge's.
///
/// Skep #914: the draft landing's merge, K, lands in `P`, a draft the board
/// records no base for, with its record; then another merge lands over it
/// by hand, its row naming other sides, no record written. The first undo
/// takes that landing back, `P` as K left it, and writes no record: none
/// stands for that landing, and K's stays current. The next undo takes K's
/// landing back, typed against the first undo's write — the put-back, `P`'s
/// words there K's — and replaces K's record (the mutant that never finds
/// the landing beneath answers the merge taken back). And where K's landing
/// was taken back, its take-back recorded, before the other merge landed by
/// hand: the undo of that landing writes no record, nothing standing
/// beneath it, and the take-back's record stays current (the mutant that
/// replaces the newest record naming the draft as landed in replaces K's
/// again).
#[test]
fn an_undo_of_a_baseless_landing_with_no_record_replaces_no_other_merges() {
    let p = "1.0.1.0.67";
    let c = vec![run(D, 1, 11)];
    let head = format!("{D}.2");
    let theirs = vec![run(D, 1, 4), run(D, 12, 4), run(D, 5, 7)];
    // Another merge landed in P by hand: its row names other sides, and no
    // record is written. Answers the landing's position.
    let landed_over = |dialer: &Scripted| {
        let typed = dialer.world().position;
        let over = frames::set_arrangement(p, &whole_of(dialer, p, &theirs), typed, Some((&head, 15)), None, Some((&[Z], None)), None);
        dialer.world().apply(&over)["at"].as_u64().expect("the landing by hand")
    };
    let mut w = draft_landing_world();
    w.doc(p, false, ACCOUNT, c.clone());
    let (dialer, board, signer) = open(w);
    let session = sign_in(&board, &signer);
    let m = merger(&session, &signer);
    let k = compose(&board, Some(session.token()), &draft_inputs()).expect("K composed");
    let into_p = draft_landing(&session, &signer, Some(a(p)));
    let (_, k_record) = landing_of(&land(&board, &k, into_p).expect("K landed"));
    let over_at = landed_over(&dialer);
    dialer.clear();
    let undone = undo(&board, m, &a(p), &a(K), None, None).expect("the landing over K taken back");
    assert_eq!(
        dialer.frames("set_arrangement")[0]["as_of"].as_u64(),
        Some(over_at),
        "typed against the landing over K"
    );
    assert_eq!(undone.record, None, "no record stood for the landing over K");
    assert!(
        dialer.frames("insert").is_empty() && dialer.frames("make_link").is_empty(),
        "nothing of a record: {:?}",
        dialer.ops()
    );
    assert_eq!(dialer.world().docs.get(p).unwrap().runs, m_runs(&k), "P as K left it");
    let found = current(&board, Some(session.token()), &a(K), &k.key)
        .expect("the lookup")
        .expect("a record");
    assert_eq!(
        (found.link, found.landed.is_some()),
        (Some(k_record.clone()), true),
        "K's record current"
    );
    dialer.clear();
    undo(&board, m, &a(p), &a(K), None, None).expect("K taken back");
    assert_eq!(
        dialer.frames("set_arrangement")[0]["as_of"],
        json!(undone.position),
        "typed against the first undo's write"
    );
    assert_eq!(dialer.world().docs.get(p).unwrap().runs, c, "P as it stood before K");
    assert_eq!(
        appended_record(&dialer)["replaces"].as_str(),
        Some(k_record.to_string().as_str()),
        "K's record replaced"
    );

    // K taken back with its record, then another merge landed by hand.
    let mut w = draft_landing_world();
    w.doc(p, false, ACCOUNT, c.clone());
    let (dialer, board, signer) = open(w);
    let session = sign_in(&board, &signer);
    let m = merger(&session, &signer);
    let k = compose(&board, Some(session.token()), &draft_inputs()).expect("K composed");
    let into_p = draft_landing(&session, &signer, Some(a(p)));
    land(&board, &k, into_p).expect("K landed");
    let take_back =
        undo(&board, m, &a(p), &a(K), None, None).expect("K taken back").record.expect("its record");
    landed_over(&dialer);
    dialer.clear();
    let undone = undo(&board, m, &a(p), &a(K), None, None).expect("the landing by hand taken back");
    assert_eq!(undone.record, None, "no record stood for the landing by hand");
    assert!(
        dialer.frames("insert").is_empty() && dialer.frames("make_link").is_empty(),
        "nothing of a record: {:?}",
        dialer.ops()
    );
    assert_eq!(dialer.world().docs.get(p).unwrap().runs, c, "P as K's take-back left it");
    let found = current(&board, Some(session.token()), &a(K), &k.key)
        .expect("the lookup")
        .expect("a record");
    assert_eq!(found.link, Some(take_back), "K's take-back's record current");
}

/// THE PRE-LANDING POSITION RECLAIMED: the journal's floor stands at the
/// landing, so `nearest` lies below it; the read there is
/// `history_reclaimed`, typed as the refusal — the state before the merge
/// is no longer on this board — with nothing sent and nothing read at
/// another position.
#[test]
fn undo_where_the_pre_landing_position_is_reclaimed_is_refused_with_nothing_sent() {
    let (dialer, board, signer) = open(draft_landing_world());
    let session = sign_in(&board, &signer);
    let before = dialer.world().position;
    let (_, landed) = landed_in_s(&board, &session, &signer);
    let (at, _) = landing_of(&landed);
    dialer.world().floor = Some(at);
    let rows = dialer.world().rows.len();
    dialer.clear();
    assert_eq!(
        undo(&board, merger(&session, &signer), &a(S), &a(K), None, None),
        Err(Refusal::HistoryReclaimed { at: before, floor: Some(at) }),
        "the position before the landing, reclaimed"
    );
    assert_eq!(dialer.positions("doc_metadata"), [at - 1, before], "at − 1 inside the commit, then nearest, reclaimed: {:?}", dialer.ops());
    assert!(dialer.positions("image").is_empty(), "nothing read elsewhere");
    assert!(dialer.frames("set_arrangement").is_empty() && dialer.frames("insert").is_empty(), "nothing sent: {:?}", dialer.ops());
    assert_eq!(dialer.world().rows.len(), rows);
    assert_eq!(dialer.world().standing(S).1.map(|m| m.at), Some(at), "the marker stands");
}

/// THE PRE-LANDING READ GOES TO `nearest`, NEVER TO `at − 1` ITSELF: the
/// world answers `not_a_position` at `at − 1`, naming the position
/// before the landing's commit, and every read of the state before the
/// merge is made there — the metadata, the extent and the image — so
/// the write carries C as it stood then, never M.
#[test]
fn the_pre_landing_read_goes_to_nearest_never_to_at_minus_one_itself() {
    let (dialer, board, signer) = open(draft_landing_world());
    let session = sign_in(&board, &signer);
    let before = dialer.world().position;
    let (_, landed) = landed_in_s(&board, &session, &signer);
    let (at, _) = landing_of(&landed);
    {
        let w = dialer.world();
        assert!(w.inside_commits.contains(&(at - 1)), "the premise: the number inside the landing's commit of two records");
        assert_eq!(at - 2, before, "the premise: the commit before lies just below it");
        assert!(!w.inside_commits.contains(&before));
    }
    dialer.clear();
    undo(&board, merger(&session, &signer), &a(S), &a(K), None, None).expect("undone");
    let asked: Vec<u64> = dialer.served.lock().unwrap().iter().filter(|(line, _)| line.starts_with("at:")).map(|(_, f)| f["at"].as_u64().unwrap()).collect();
    assert_eq!(asked, [at - 1, before, before, before], "doc_metadata at at − 1, then doc_metadata, the span set and the image at nearest: {:?}", dialer.ops());
    assert_eq!(dialer.frames("set_arrangement")[0]["changes"], whole_changes(width_of(&draft_m()), &draft_c()), "C as it stood at nearest, never M");
}

/// Files `record` in a sub-account's journal, answering its link.
///
/// The link runs to `S` and is minted after every other. The journal is
/// `1.0.1.2.0.65`, a draft of the sub-account `1.0.1.2` nested under the
/// merger's, which the merger may read.
fn filed_by_a_sub_account(dialer: &Scripted, record: &Record) -> String {
    let mut w = dialer.world();
    w.position += 1;
    let minted = w.position;
    file(&mut w, "1.0.1.2.0.65", record, &[S], Some(minted))
}

/// An undo and a withdrawal replace the merger's own record (skep #1154).
///
/// P20, a record replacing one of its own home's: after a landing in `S`,
/// a sub-account files a newer record naming `S` as landed in at the
/// marker's position, with the marker's head and sides. The undo and the
/// withdrawal each replace the merger's own landing record, and neither
/// reads the sub-account's: no `read_link` names its link (the mutant that
/// keeps every account's records replaces the sub-account's; the one that
/// drops them after reading them reads it).
#[test]
fn an_undo_and_a_withdrawal_replace_the_mergers_own_record_whatever_another_account_files() {
    for act in ["undo", "withdraw"] {
        let (dialer, board, signer) = open(draft_landing_world());
        let session = sign_in(&board, &signer);
        let m = merger(&session, &signer);
        let (merged, landed) = landed_in_s(&board, &session, &signer);
        let (at, own) = landing_of(&landed);
        let in_s = RecordLanding::Draft { draft: a(S), position: at };
        let theirs = filed_by_a_sub_account(&dialer, &Record { landed: Some(in_s), ..merged.record.clone() });
        dialer.clear();
        let record = match act {
            "undo" => undo(&board, m, &a(S), &a(K), None, None).expect("undone").record,
            _ => withdraw(&board, m, &a(S), &a(K), None).expect("withdrawn").record,
        };
        assert!(record.is_some(), "{act}: a record of the merger's stood, so one replaces it");
        assert_eq!(appended_record(&dialer)["replaces"].as_str(), Some(own.to_string().as_str()), "{act}: the merger's own landing record replaced");
        assert!(dialer.frames("read_link").iter().all(|f| f["a"] != theirs), "{act}: the sub-account's record never read: {:?}", dialer.ops());
    }
}

/// Another account's take-back never stops an undo or a withdrawal.
///
/// Skep #1154, P20: after a landing in `S`, a sub-account files a
/// take-back naming the merger's landing record in `replaces`, linked to
/// `S`. That record is no replacement of the merger's: the undo writes its
/// record, replacing the merger's own, and so does the withdrawal (the
/// mutant that drops another account's records only after judging which of
/// the merger's are replaced writes none at the undo).
#[test]
fn an_undo_is_not_stopped_by_another_accounts_take_back_of_the_mergers_record() {
    for act in ["undo", "withdraw"] {
        let (dialer, board, signer) = open(draft_landing_world());
        let session = sign_in(&board, &signer);
        let m = merger(&session, &signer);
        let (merged, landed) = landed_in_s(&board, &session, &signer);
        let (_, own) = landing_of(&landed);
        filed_by_a_sub_account(&dialer, &Record { landed: None, replaces: Some(own.clone()), ..merged.record.clone() });
        dialer.clear();
        let record = match act {
            "undo" => undo(&board, m, &a(S), &a(K), None, None).expect("undone").record,
            _ => withdraw(&board, m, &a(S), &a(K), None).expect("withdrawn").record,
        };
        assert!(record.is_some(), "{act}: the merger's record stands, so one replaces it");
        assert_eq!(appended_record(&dialer)["replaces"].as_str(), Some(own.to_string().as_str()), "{act}: the merger's own landing record replaced");
    }
}

/// The changed stretch of two images makes the one the other.
///
/// Each cell names two images and the stretch between them — its first
/// position, the positions removed and the positions placed — and the
/// stretch made by hand on the first leaves the second, position for
/// position: the same image and one cut into other runs differ nowhere; a
/// member's word is never the trunk's of its ordinal; a word the two hold
/// once and twice is shared once, the lead and the tail never overlapping
/// (the mutant that lets them answers a stretch of fewer than no
/// positions). Then generated pairs over two chains and few ordinals, so
/// words recur: the stretch made leaves the image wanted, and it is the
/// least one — its first position and its last differ between the two.
#[test]
fn the_changed_stretch_of_two_images_makes_one_the_other() {
    use crate::board::Image;
    use crate::merge::undo::{changed_stretch, Stretch};
    let image = |runs: &[(&str, u64, u64)]| Image::tiled(runs.iter().map(|(prefix, first, width)| (prefix.to_string(), *first, *width))).expect("an image");
    let positions = |image: &Image| -> Vec<(String, u64)> { image.runs().iter().flat_map(|r| (0..r.width).map(move |k| (r.prefix.clone(), r.first + k))).collect() };
    let made = |standing: &Image, stretch: &Option<Stretch>| {
        let mut all = positions(standing);
        if let Some(Stretch { at, removed, placed }) = stretch {
            let from = (*at - 1) as usize;
            all.splice(from..from + *removed as usize, positions(placed));
        }
        all
    };
    let (d, m, s) = ("1.0.1.0.64.0.1", "1.0.1.0.64.2.0.1", "1.0.1.0.66.0.1");
    let c = [(d, 1, 11), (s, 1, 3)];
    let big = [(d, 1, 4), (d, 12, 4), (d, 5, 7), (s, 1, 3)];
    // A cell: its name, the image standing, the image wanted, and the
    // stretch between them — its first position, the positions removed and
    // the positions placed — where they differ.
    type Cell = (&'static str, Image, Image, Option<(u64, u64, u64)>);
    let cells: Vec<Cell> = vec![
        ("the same image", image(&c), image(&c), None),
        ("one run cut in two", image(&[(d, 1, 11)]), image(&[(d, 1, 4), (d, 5, 7)]), None),
        ("words placed in the middle", image(&c), image(&big), Some((5, 0, 4))),
        ("words removed from the middle", image(&big), image(&c), Some((5, 4, 0))),
        ("a member's word for the trunk's of its ordinal", image(&[(d, 1, 12)]), image(&[(d, 1, 11), (m, 12, 1)]), Some((12, 1, 1))),
        ("the first word", image(&[(s, 1, 1), (d, 2, 9)]), image(&[(d, 1, 10)]), Some((1, 1, 1))),
        ("the last word", image(&[(d, 1, 9), (s, 3, 1)]), image(&[(d, 1, 10)]), Some((10, 1, 1))),
        ("the first word and the last, all between", image(&[(s, 1, 1), (d, 2, 8), (s, 3, 1)]), image(&[(d, 1, 10)]), Some((1, 10, 10))),
        ("nothing shared", image(&[(d, 1, 3)]), image(&[(s, 1, 2)]), Some((1, 3, 2))),
        ("from an empty image", Image::default(), image(&[(d, 1, 3)]), Some((1, 0, 3))),
        ("to an empty image", image(&[(d, 1, 3)]), Image::default(), Some((1, 3, 0))),
        ("a word held once and twice", image(&[(d, 1, 1)]), image(&[(d, 1, 1), (d, 1, 1)]), Some((2, 0, 1))),
    ];
    for (cell, standing, wanted, expect) in &cells {
        let stretch = changed_stretch(standing, wanted);
        assert_eq!(stretch.as_ref().map(|s| (s.at, s.removed, s.placed.extent())), *expect, "{cell}");
        assert_eq!(made(standing, &stretch), positions(wanted), "{cell}: the stretch made leaves the image wanted");
    }
    // Generated pairs: a xorshift walk over two chains and eight ordinals.
    let mut state = 0x9e37_79b9_7f4a_7c15u64;
    let mut next = |below: u64| {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state % below
    };
    for round in 0..2_000 {
        let generated = |next: &mut dyn FnMut(u64) -> u64| {
            let runs = next(6);
            let pieces: Vec<(String, u64, u64)> = (0..runs).map(|_| ((if next(2) == 0 { d } else { m }).to_string(), 1 + next(8), 1 + next(3))).collect();
            Image::tiled(pieces).expect("an image")
        };
        let (standing, wanted) = (generated(&mut next), generated(&mut next));
        let stretch = changed_stretch(&standing, &wanted);
        let (held, meant) = (positions(&standing), positions(&wanted));
        assert_eq!(made(&standing, &stretch), meant, "round {round}: {standing:?} to {wanted:?} by {stretch:?}");
        match &stretch {
            None => assert_eq!(held, meant, "round {round}: no stretch between two images that differ"),
            Some(Stretch { at, removed, placed }) => {
                let (from, gone, put) = ((*at - 1) as usize, *removed as usize, placed.extent() as usize);
                assert!(gone + put > 0, "round {round}: a stretch of nothing");
                // The least stretch: where it both removes and places, its
                // first positions differ, and its last.
                if gone > 0 && put > 0 {
                    assert_ne!(held[from], meant[from], "round {round}: a shared first position inside the stretch");
                    assert_ne!(held[from + gone - 1], meant[from + put - 1], "round {round}: a shared last position inside the stretch");
                }
            }
        }
    }
}
