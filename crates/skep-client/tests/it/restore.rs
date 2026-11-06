//! THE RESTORE against the real daemon (B3-S7; `client.md` §4b.1's
//! `history.restore` row): over the merge suite's rig, a claimed permissive
//! board. A DRAFT PUT BACK — typed in three bursts and restored to the state
//! after the first in ONE `set_arrangement`: its image the state's runs, the
//! bytes read back equal, a link made on those words found by
//! `find_links_v` again, the feed row naming the write with `base` and
//! `merge` null, `doc_metadata` unchanged, a second call over the same
//! `Past` in the same session answered from the memo, and THE WAY BACK — the
//! state at the `as_of` the first restore was typed against restored in
//! turn. THE REFUSALS — a position at or past the draft's own refused before
//! any read at a position, a published document at the one read, a position
//! inside a commit with its nearest, a RECLAIMED position reached honestly
//! (the floor raised by the daemon's own checkpoints through its
//! `test-hooks` seam, as the search suite raises it), each with nothing
//! written; and A MOVED DRAFT — edited between the read and the write,
//! refused `arrangement_moved` with the edit kept. A MARKED DRAFT — a merge
//! landed in it, an edit after, the draft restored to the landing's state:
//! the base and the marker stand, nothing of the record moved. ACROSS A
//! PUBLICATION — the draft's words published with their kept place, so the
//! board re-windows the draft and homes a correspondence record in it, then
//! an edit, then the restore to the pre-publication state: the sent runs
//! carry the TRUNK as their origin, the restored image is the member's
//! identity, the bytes are the old text, a link made on the published words
//! is found at the restored place, and a second shot sends them by
//! reference with no fresh identity.

use serde_json::{json, Value};
use skep_address::Address;
use skep_client::board::{acked_addr, acked_at, frames, AtAnswer, Token};
use skep_client::ceremony::handshake::Session;
use skep_client::halt::Halt;
use skep_client::history::{past, restore, Restored};
use skep_client::merge::{compose, land, Inputs, Landed, Landing, Refusal, Run, Side};
use skep_identity::{entry_body_publish, ShotSegmentPiece};

use crate::common::{insert_text, mint};
use crate::merge::{acked, addr, as_image, attest, image, m_of, merger, published_document, read, shot, Rig, Staged};

/// The claimant's account on a notebook.
const ACCOUNT: &str = "1.0.1";
/// A formatting type a mark takes: `3.23.2` strong.
const T_STRONG: &str = "1.1.0.1.0.1.0.3.23.2";

/// A private draft of the claimant's, minted from the bare session.
fn draft(rig: &Rig) -> Address {
    addr(&mint(&rig.board, &rig.bare, ACCOUNT, false))
}

/// A mark in `home`'s own set over its V-positions `from ..`, `width` of
/// them, from the bare session: the stored end is the identity the
/// positions resolve to.
fn mark(rig: &Rig, home: &Address, from: u64, width: u64) -> String {
    let frame = json!({"op": "make_link", "home": home.to_string(), "from": [{"source": home.to_string(), "span": {"start": format!("1.{from}"), "width": format!("0.{width}")}}], "to": {"addrs": []}, "ty": {"addrs": [T_STRONG]}});
    acked_addr(&acked(rig.board.op(Some(&rig.bare), &frame))).expect("the mark").to_string()
}

/// The bytes at content ordinals `1 ..= width` of `doc`.
fn text_of(rig: &Rig, token: &Token, doc: &Address, width: u64) -> String {
    let v = read(&rig.board, Some(token), &frames::retrieve_v(&doc.to_string(), 1, width));
    v["items"].as_array().expect("items").iter().filter_map(|i| i["content"].as_str()).collect()
}

/// The draft's `base` and `merge` members off `doc_metadata`, as they stand.
fn record_of(rig: &Rig, token: &Token, doc: &Address) -> (Value, Value) {
    let meta = rig.metadata(token, doc);
    (meta["base"].clone(), meta["merge"].clone())
}

/// A draft typed in three bursts — "the cat", " sat", "!!!" — put back to
/// the state after the first in one write, then back again.
#[test]
fn a_draft_is_put_back_to_a_past_state_in_one_write_and_back_again() {
    let rig = Rig::new();
    let session = rig.session();
    let token = session.token().clone();
    let d = draft(&rig);
    let d_s = d.to_string();
    let p1 = insert_text(&rig.board, &rig.bare, &d_s, 1, "the cat");
    insert_text(&rig.board, &rig.bare, &d_s, 8, " sat");
    insert_text(&rig.board, &rig.bare, &d_s, 12, "!!!");
    let whole = vec![(format!("{d}.0.1.1"), 14)];
    assert_eq!(image(&rig.board, &token, &d, 14), whole, "the premise: three bursts at one caret, one run");
    let link = mark(&rig, &d, 5, 3);
    let before = rig.position();
    // THE READS write nothing.
    let p = past(&rig.board, &token, ACCOUNT, &d, p1).expect("the past read");
    assert_eq!(p.state, vec![Run::new(d.clone(), 1, 7)], "the state as of the first burst");
    assert_eq!(p.sent, p.state, "no record names the words: sent as read");
    assert_eq!((p.at, p.as_of, p.records.len(), p.covered(), p.extent(), p.marker.is_none()), (p1, before, 0, 0, 7, true));
    assert_eq!(rig.position(), before, "the reads write nothing");
    // THE ONE WRITE.
    let restored = restore(&rig.board, &token, &p).expect("restored");
    assert_eq!((restored.draft.clone(), restored.at), (d.clone(), p1));
    assert!(restored.position > before, "{restored:?}");
    assert_eq!(image(&rig.board, &token, &d, 7), vec![(format!("{d}.0.1.1"), 7)], "the image is the state's runs");
    assert_eq!(text_of(&rig, &token, &d, 7), "the cat", "the bytes read back");
    // The region read answers every link whose endset touches the region —
    // the account's credential records through their unit span at the
    // account among them (the publication's enumeration filters those by
    // the stored-endset test) — so the mark is looked for among them.
    let found = read(&rig.board, Some(&token), &frames::find_links_v(&d_s, &[(5, 3)]));
    assert!(found["addrs"].as_array().is_some_and(|a| a.contains(&json!(link))), "the mark on those words is found again: {found}");
    let rows = rig.rows_under(&token, &d);
    let row = rows.iter().rev().find(|r| r["op"] == "set_arrangement").expect("the restore's row");
    assert_eq!((row["at"].as_u64(), row["base"].is_null(), row["merge"].is_null()), (Some(restored.position), true, true), "the row names the write, no base and no merge: {row}");
    assert_eq!(record_of(&rig, &token, &d), (Value::Null, Value::Null), "a plain mint: nothing recorded, nothing moved");
    // The same `Past` again in this session: the memo's answer, nothing
    // written twice.
    assert_eq!(restore(&rig.board, &token, &p), Ok(restored.clone()));
    assert_eq!(rig.position(), restored.position, "nothing written twice");
    // THE WAY BACK: the state at the position the restore was typed against
    // is the whole text, restored in turn.
    let back = past(&rig.board, &token, ACCOUNT, &d, p.as_of).expect("the way back's read");
    assert_eq!(back.state, vec![Run::new(d.clone(), 1, 14)]);
    let again = restore(&rig.board, &token, &back).expect("restored back");
    assert!(again.position > restored.position);
    assert_eq!(image(&rig.board, &token, &d, 14), whole, "the whole text again");
    assert_eq!(text_of(&rig, &token, &d, 14), "the cat sat!!!");
    session.close().expect("close");
}

/// The position refusals, each with nothing written: at or past the draft's
/// own before any read at a position; a published document at the one
/// read; a position inside a commit, its nearest named; a reclaimed
/// position, reached honestly.
#[test]
fn a_position_at_the_head_inside_a_commit_or_reclaimed_is_refused_with_nothing_written() {
    let rig = Rig::new();
    let session = rig.session();
    let token = session.token().clone();
    let d = draft(&rig);
    let d_s = d.to_string();
    let early = insert_text(&rig.board, &rig.bare, &d_s, 1, "written before the floor rose");
    let head = rig.position();
    // AT OR PAST THE HEAD: `as_of` is the head, so the head itself is no
    // past position.
    for at in [head, head + 1, head + 1_000] {
        assert_eq!(past(&rig.board, &token, ACCOUNT, &d, at), Err(Refusal::NotPast { draft: d.clone(), at, current: head }));
    }
    // A PUBLISHED DOCUMENT.
    let e = published_document(&rig.board, &session, &rig.device);
    assert_eq!(past(&rig.board, &token, ACCOUNT, &e, early), Err(Refusal::Published { doc: e.clone() }));
    // INSIDE A COMMIT: a stage is one commit of several records, so the
    // number below its ack's `at` is no position, and `nearest` is the
    // position before the commit.
    let base = shot(&rig.board, &session, &rig.device, &rig.bare, &e, None, &[Staged::Fresh { text: "the cat sat" }]);
    let before_stage = rig.position();
    let staged = acked(rig.board.op(Some(&rig.bare), &frames::stage(&base.to_string(), None)));
    let s = addr(acked_addr(&staged).expect("the staged draft"));
    let staged_at = acked_at(&staged).expect("the stage's position");
    let AtAnswer::NotAPosition { nearest } = rig.board.op_at(Some(&token), staged_at - 1, &frames::doc_metadata(&s.to_string())).expect("the read") else { panic!("the premise: at − 1 lies inside the stage's commit") };
    assert_eq!(nearest, Some(before_stage));
    assert_eq!(past(&rig.board, &token, ACCOUNT, &s, staged_at - 1), Err(Refusal::NotAPosition { at: staged_at - 1, nearest: Some(before_stage), recorded: None }));
    assert_eq!(rig.position(), staged_at, "nothing written");
    // RECLAIMED: the floor rises past `early` — bulk inserts rotate the
    // journal's segment, then three checkpoints retain two and reclaim
    // below the oldest kept (the search suite's resume, the same seam).
    let bulk = "z".repeat(262_144);
    let filler = draft(&rig);
    for _ in 0..3 {
        for _ in 0..3 {
            insert_text(&rig.board, &rig.bare, &filler.to_string(), 1, &bulk);
        }
        rig.sd.daemon().service_the_checkpoint_now();
    }
    let standing = rig.position();
    let err = past(&rig.board, &token, ACCOUNT, &d, early).expect_err("the position is reclaimed");
    let Refusal::HistoryReclaimed { at, floor } = err else { panic!("{err:?}") };
    assert_eq!(at, early);
    assert!(floor.is_some_and(|f| f > early), "the floor the board named: {floor:?}");
    assert_eq!(rig.position(), standing, "nothing written");
    assert_eq!(image(&rig.board, &token, &d, 29), vec![(format!("{d}.0.1.1"), 29)], "the draft as it stands");
    session.close().expect("close");
}

/// A MOVED DRAFT: the state read, the draft edited, the write refused
/// `arrangement_moved` by the board — its words the person's — with the
/// edit kept and nothing committed.
#[test]
fn a_draft_changed_between_the_read_and_the_write_is_refused_with_the_edit_kept() {
    let rig = Rig::new();
    let session = rig.session();
    let token = session.token().clone();
    let d = draft(&rig);
    let d_s = d.to_string();
    let p1 = insert_text(&rig.board, &rig.bare, &d_s, 1, "hello");
    insert_text(&rig.board, &rig.bare, &d_s, 6, " world");
    let p = past(&rig.board, &token, ACCOUNT, &d, p1).expect("the past read");
    assert_eq!(p.state, vec![Run::new(d.clone(), 1, 5)]);
    let moved_at = insert_text(&rig.board, &rig.bare, &d_s, 12, "!");
    let edited = image(&rig.board, &token, &d, 12);
    let err = restore(&rig.board, &token, &p).expect_err("the draft changed since the read");
    let Refusal::Halt(Halt::Refused(refused)) = &err else { panic!("{err:?}") };
    assert_eq!(refused.code, "arrangement_moved", "{refused:?}");
    let detail = refused.detail.as_deref().expect("the person's words");
    assert!(detail.contains(&d_s) && detail.contains("changed since it was read") && detail.contains("nothing was changed"), "{detail}");
    assert!(detail.contains(&format!("position {}", p.as_of)) && detail.contains(&format!("changed at {moved_at}")), "{detail}");
    assert_eq!(image(&rig.board, &token, &d, 12), edited, "the edit kept");
    assert_eq!(text_of(&rig, &token, &d, 12), "hello world!");
    assert_eq!(rig.position(), moved_at, "nothing committed");
    // Read again, the write lands: the state as of the first burst.
    let again = past(&rig.board, &token, ACCOUNT, &d, p1).expect("read again");
    assert_eq!(again.as_of, moved_at);
    restore(&rig.board, &token, &again).expect("restored");
    assert_eq!(text_of(&rig, &token, &d, 5), "hello");
    session.close().expect("close");
}

/// A MARKED DRAFT: a merge landed in the staged draft `S`, "?" typed after
/// it, then `S` restored to the landing's state — the words M again, its
/// base on the head and the marker at the landing standing, nothing of the
/// record moved; the number below the landing's `at` refused as inside its
/// commit.
#[test]
fn a_restore_on_a_marked_draft_leaves_the_base_and_the_marker_standing() {
    let rig = Rig::new();
    let session = rig.session();
    let token = session.token().clone();
    let (d, base, head) = rig.race(&session);
    let s = rig.staged(&base, 12, "!!!");
    let kind = draft(&rig);
    let merger = merger(&rig, &session);
    let inputs = Inputs { doc: d.clone(), head: head.clone(), base: None, sides: vec![Side::Draft { at: s.clone(), position: None }], options: Default::default(), kind };
    let merged = compose(&rig.board, Some(&token), &inputs).expect("composed");
    let before_landing = rig.position();
    let landed = land(&rig.board, &merged, Landing::Draft { merger, into: Some(s.clone()), journal: None }).expect("landed");
    let Landed::Draft { position: at, .. } = landed else { panic!("{landed:?}") };
    let m = as_image(&m_of(&merged));
    let standing = record_of(&rig, &token, &s);
    assert_eq!((standing.0.as_str(), standing.1["at"].as_u64()), (Some(head.to_string().as_str()), Some(at)), "the premise: the base on the head, the marker at the landing");
    insert_text(&rig.board, &rig.bare, &s.to_string(), 1, "?");
    assert_eq!(image(&rig.board, &token, &s, 19).len(), 5, "the premise: ?the big cat sat!!!");
    // Inside the landing's commit: refused, its nearest the position before.
    assert_eq!(past(&rig.board, &token, ACCOUNT, &s, at - 1), Err(Refusal::NotAPosition { at: at - 1, nearest: Some(before_landing), recorded: None }));
    // The landing's state, restored: M, the record untouched.
    let p = past(&rig.board, &token, ACCOUNT, &s, at).expect("the past read");
    assert_eq!(as_image(&p.state), m, "the state at the landing is M");
    assert_eq!(p.marker.as_ref().and_then(|mk| mk.at), Some(at), "the marker carried as it stands: {:?}", p.marker);
    let restored = restore(&rig.board, &token, &p).expect("restored");
    assert_eq!(image(&rig.board, &token, &s, 18), m, "M again, the edit gone");
    assert_eq!(record_of(&rig, &token, &s), standing, "the base and the marker stand: nothing of the record moved");
    let rows = rig.rows_under(&token, &s);
    let row = rows.iter().rev().find(|r| r["op"] == "set_arrangement").expect("the restore's row");
    assert_eq!((row["at"].as_u64(), row["base"].is_null(), row["merge"].is_null()), (Some(restored.position), true, true), "{row}");
    session.close().expect("close");
}

/// THE SHOT WITH A KEPT PLACE: `d`'s whole text, `text` at its first
/// positions, published as `e`'s own words with the place the run holds in
/// `d` beside it, so the commit re-windows `d` through the record it homes
/// there (wire.md §The publish shot and head-float, the kept places).
fn publish_with_place(rig: &Rig, session: &Session<'_>, e: &Address, d: &Address, text: &str) -> Address {
    let (e_s, d_s) = (e.to_string(), d.to_string());
    let runs = [frames::shot_run(&d_s, &format!("{d}.0.1.1"), text.len() as u64)];
    let places = [frames::place(1)];
    let pieces: Vec<[u8; 1]> = text.bytes().map(|b| [b]).collect();
    let body = entry_body_publish(pieces.iter().map(|b| ShotSegmentPiece::Value(b)), None);
    let mut frame = frames::publication(&frames::PublishFrame { doc: Some(&e_s), draft: Some(&d_s), runs: &runs, places: &places, ..frames::PublishFrame::default() });
    frame["attest"] = attest(&rig.board, &rig.device, &addr(ACCOUNT), e, &body);
    addr(acked_addr(&acked(session.op(&frame))).expect("the member"))
}

/// ACROSS A PUBLICATION: `d`'s "hello world" published into `e` with its
/// kept place, `d` re-windowed and a record homed in it; "!!!" typed after;
/// `d` restored to the state before the publication — the sent runs the
/// member's identity under the TRUNK, the image that identity, the bytes
/// the old text, a mark made on the published words found at the restored
/// place; and a second shot sends them by reference, no fresh identity.
#[test]
fn words_a_publication_made_public_come_back_as_the_published_words_they_became() {
    let rig = Rig::new();
    let session = rig.session();
    let token = session.token().clone();
    let e = published_document(&rig.board, &session, &rig.device);
    let d = draft(&rig);
    let d_s = d.to_string();
    let p1 = insert_text(&rig.board, &rig.bare, &d_s, 1, "hello world");
    let e1 = publish_with_place(&rig, &session, &e, &d, "hello world");
    assert_eq!(e1.to_string(), format!("{e}.1"));
    assert_eq!(image(&rig.board, &token, &d, 11), vec![(format!("{e}.0.1.1"), 11)], "the premise: d re-windowed at its kept place");
    let link = mark(&rig, &d, 1, 5);
    insert_text(&rig.board, &rig.bare, &d_s, 12, "!!!");
    assert_eq!(image(&rig.board, &token, &d, 14), vec![(format!("{e}.0.1.1"), 11), (format!("{d}.0.1.12"), 3)]);
    let standing = record_of(&rig, &token, &d);
    // THE READS: the state before the publication, mapped through the record.
    let p = past(&rig.board, &token, ACCOUNT, &d, p1).expect("the past read");
    assert_eq!(p.state, vec![Run::new(d.clone(), 1, 11)], "the state as read: the draft's own identity");
    assert_eq!(p.sent, vec![Run::new(e.clone(), 1, 11)], "sent as the published words they became, the trunk their origin");
    assert_eq!((p.records.len(), p.covered(), p.extent()), (1, 11, 11));
    assert_eq!((p.records[0].home.clone(), p.records[0].from.first, p.records[0].to.first), (d.clone(), 1, 1));
    // THE ONE WRITE.
    let Restored { position, .. } = restore(&rig.board, &token, &p).expect("restored");
    assert_eq!(image(&rig.board, &token, &d, 11), vec![(format!("{e}.0.1.1"), 11)], "the member's identity at the restored place");
    assert_eq!(text_of(&rig, &token, &d, 11), "hello world");
    // Among the links the region read answers — the record homed in `d`
    // touches it through its `to` — the mark stands.
    let found = read(&rig.board, Some(&token), &frames::find_links_v(&d_s, &[(1, 5)]));
    assert!(found["addrs"].as_array().is_some_and(|a| a.contains(&json!(link))), "the mark on the published words is found at the restored place: {found}");
    assert_eq!(record_of(&rig, &token, &d), standing, "nothing of the record moved");
    assert!(position > p.as_of);
    // A SECOND SHOT from the restored draft sends the words by reference:
    // the next member holds e's identity and mints nothing fresh.
    let e2 = shot(&rig.board, &session, &rig.device, &rig.bare, &e, Some((&e1, 11)), &[Staged::Own { from: 1, text: "hello world" }]);
    assert_eq!(e2.to_string(), format!("{e}.2"));
    assert_eq!(image(&rig.board, &token, &e2, 11), vec![(format!("{e}.0.1.1"), 11)], "no fresh identity");
    session.close().expect("close");
}
