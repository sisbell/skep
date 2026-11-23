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
//! reference with no fresh identity. A member's own words — a deposit
//! naming the member, minted under its chain, staged into a draft — come
//! back as themselves, never as the trunk's word of the same ordinal.
//! ANOTHER ACCOUNT'S WORDS — a sibling account's draft, granted and
//! windowed, published since by its owner — come back as the words that
//! owner published, the record read in the owner's account; the grant
//! revoked, no record is answered and the board refuses the write
//! `withheld` naming that draft.

use serde_json::{json, Value};
use skep_address::Address;
use skep_client::board::{acked_addr, acked_at, frames, AtAnswer, Scope, Token, T_ENROLL};
use skep_client::ceremony::handshake::{handshake, Session, Site};
use skep_client::halt::Halt;
use skep_client::history::{past, restore, Restored};
use skep_client::merge::{compose, land, Inputs, Landed, Landing, Refusal, Run, Side};
use skep_client::share::{revoke, share, Issuer};
use skep_client::sign::signer_from_seed;
use skep_identity::{entry_body_empty, entry_body_insert, ContentFreeOp};
use skep_signature::HybridSigner;

use crate::common::{insert_text, keyed_sub_account, mint, typed_at};
use crate::merge::{acked, addr, as_image, attest, image, m_of, mark, merger, publish_with_place, publish_with_place_as, published_document, read, shot, text_of, Rig, Staged};

/// The claimant's account on a notebook.
const ACCOUNT: &str = "1.0.1";

/// A private draft of the claimant's, minted from the bare session.
fn draft(rig: &Rig) -> Address {
    addr(&mint(&rig.board, &rig.bare, ACCOUNT, false))
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
    let p = past(&rig.board, &token, &d, p1).expect("the past read");
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
    let back = past(&rig.board, &token, &d, p.as_of).expect("the way back's read");
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
        assert_eq!(past(&rig.board, &token, &d, at), Err(Refusal::NotPast { draft: d.clone(), at, current: head }));
    }
    // A PUBLISHED DOCUMENT.
    let e = published_document(&rig.board, &session, &rig.device);
    assert_eq!(past(&rig.board, &token, &e, early), Err(Refusal::Published { doc: e.clone() }));
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
    assert_eq!(past(&rig.board, &token, &s, staged_at - 1), Err(Refusal::NotAPosition { at: staged_at - 1, nearest: Some(before_stage), recorded: None }));
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
    let err = past(&rig.board, &token, &d, early).expect_err("the position is reclaimed");
    let Refusal::HistoryReclaimed { at, floor } = err else { panic!("{err:?}") };
    assert_eq!(at, early);
    assert!(floor.is_some_and(|f| f > early), "the floor the board named: {floor:?}");
    assert_eq!(rig.position(), standing, "nothing written");
    assert_eq!(image(&rig.board, &token, &d, 29), vec![(format!("{d}.0.1.1"), 29)], "the draft as it stands");
    session.close().expect("close");
}

/// A MOVED DRAFT: the state read, the draft edited, the write refused
/// `arrangement_moved` by the board — its words the person's, asking a
/// read and a restore typed at it, never the same call again — with the
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
    let p = past(&rig.board, &token, &d, p1).expect("the past read");
    assert_eq!(p.state, vec![Run::new(d.clone(), 1, 5)]);
    let moved_at = insert_text(&rig.board, &rig.bare, &d_s, 12, "!");
    let edited = image(&rig.board, &token, &d, 12);
    let err = restore(&rig.board, &token, &p).expect_err("the draft changed since the read");
    let Refusal::Halt(Halt::Refused(refused)) = &err else { panic!("{err:?}") };
    assert_eq!(refused.code, "arrangement_moved", "{refused:?}");
    let detail = refused.detail.as_deref().expect("the person's words");
    assert!(detail.contains(&d_s) && detail.contains("changed since it was read") && detail.contains("nothing was changed"), "{detail}");
    assert!(detail.contains(&format!("position {}", p.as_of)) && detail.contains(&format!("changed at {moved_at}")), "{detail}");
    assert!(detail.contains("read the draft as it stands, then restore again typed at that read") && !detail.contains("run this again"), "{detail}");
    assert_eq!(image(&rig.board, &token, &d, 12), edited, "the edit kept");
    assert_eq!(text_of(&rig, &token, &d, 12), "hello world!");
    assert_eq!(rig.position(), moved_at, "nothing committed");
    // Read again, the write lands: the state as of the first burst.
    let again = past(&rig.board, &token, &d, p1).expect("read again");
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
    assert_eq!(past(&rig.board, &token, &s, at - 1), Err(Refusal::NotAPosition { at: at - 1, nearest: Some(before_landing), recorded: None }));
    // The landing's state, restored: M, the record untouched.
    let p = past(&rig.board, &token, &s, at).expect("the past read");
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
    let p = past(&rig.board, &token, &d, p1).expect("the past read");
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

/// A member's own words come back as themselves.
///
/// `e.1` holds "abc", the trunk's words, and "z", a declared deposit naming
/// the member and so minted under its chain; `s` is staged from `e.1`, typed
/// into, and restored to the stage's state: the image is the stage's runs
/// again and the bytes are the deposit's, never the trunk's "a" of the same
/// ordinal.
#[test]
fn a_members_own_words_come_back_as_themselves() {
    let rig = Rig::new();
    let session = rig.session();
    let token = session.token().clone();
    let e = published_document(&rig.board, &session, &rig.device);
    let e1 = shot(&rig.board, &session, &rig.device, &rig.bare, &e, None, &[Staged::Fresh { text: "abc" }]);
    let as_of = typed_at(&rig.board, &token, &e1.to_string());
    let mut deposit = json!({"op": "insert", "doc": e1.to_string(), "at": {"subspace": "1", "ordinal": "4"}, "values": ["z"], "deposit": T_ENROLL, "as_of": as_of});
    // The entry frame of an insert names the trunk, whichever member the
    // frame names.
    deposit["attest"] = attest(&rig.board, &rig.device, &addr(ACCOUNT), &e, &entry_body_insert(Some(&addr(T_ENROLL)), b"z".chunks(1)));
    acked(session.op(&deposit));
    let theirs = vec![(format!("{e}.0.1.1"), 3), (format!("{e1}.0.1.1"), 1)];
    assert_eq!(image(&rig.board, &token, &e1, 4), theirs, "the premise: the deposit minted under the member's chain");
    let staged = acked(rig.board.op(Some(&rig.bare), &frames::stage(&e1.to_string(), None)));
    let s = addr(acked_addr(&staged).expect("the staged draft"));
    let staged_at = acked_at(&staged).expect("the stage's position");
    assert_eq!(image(&rig.board, &token, &s, 4), theirs, "the stage copies the member's words by identity");
    insert_text(&rig.board, &rig.bare, &s.to_string(), 5, "!");
    let p = past(&rig.board, &token, &s, staged_at).expect("the past read");
    assert_eq!(p.state, vec![Run::new(e.clone(), 1, 3), Run::new(e.clone(), 1, 1)], "the core's runs spell the deposit as the trunk's first word");
    restore(&rig.board, &token, &p).expect("restored");
    assert_eq!(image(&rig.board, &token, &s, 4), theirs, "the stage's runs again");
    assert_eq!(text_of(&rig, &token, &s, 4), "abcz", "the deposit's bytes");
    session.close().expect("close");
}

/// A keyed sibling of the claimant's, `1.0.1.<n>`, its home minted: its
/// account, its principal and its signer (the share suite's rig).
struct Sibling {
    account: String,
    principal: u64,
    signer: HybridSigner,
}

impl Sibling {
    /// Keys the sibling `n` under the rig's claimant, its anchor enrolling
    /// the sibling's key, and mints its home from its own signed session.
    fn keyed(rig: &Rig, n: u8, label: &str) -> Sibling {
        let signer = signer_from_seed(&[50 + n; 32]);
        let principal = 700 + u64::from(n);
        let account = keyed_sub_account(&rig.board, &rig.anchors, &rig.device, u64::from(n), principal, &signer, label);
        let who = Sibling { account, principal, signer };
        let session = who.session(rig);
        who.minted(rig, &session, true);
        session.close().expect("close");
        who
    }

    /// A content-scoped signed session as the sibling.
    fn session<'b>(&self, rig: &'b Rig) -> Session<'b> {
        handshake(&rig.board, Scope::Content, &self.signer, self.principal, Site::Session).expect("a content session")
    }

    /// A document of the sibling's minted from `session` with its attest:
    /// published where `published` — the account's first mint is its home,
    /// born published — else a private draft.
    fn minted(&self, rig: &Rig, session: &Session<'_>, published: bool) -> Address {
        let account = addr(&self.account);
        let mut frame = json!({"op": "create_new_document", "account": self.account, "published": published});
        frame["attest"] = attest(&rig.board, &self.signer, &account, &account, &entry_body_empty(ContentFreeOp::CreateNewDocument));
        addr(acked_addr(&acked(session.op(&frame))).expect("a minted address"))
    }
}

/// ANOTHER ACCOUNT'S WORDS, PUBLISHED SINCE: `b`, a sibling account, grants
/// `a` its draft `z` holding "quote"; `a`'s draft `s` windows `z`'s words
/// and "!" is typed after them; `b` publishes `z` into `f` with its kept
/// place, so the board re-windows `z` and homes the record in it. `a`'s
/// restore of `s` to its state before that publication reads `z`'s record
/// in `b`'s account and writes the words as `f`'s, which `s` then holds.
/// The grant revoked, no record of `z`'s is answered `a`: the state is
/// written as read, and the board refuses the write `withheld` naming `z`,
/// nothing written and `s` as it stood.
#[test]
fn another_accounts_words_published_since_come_back_as_its_published_words() {
    let rig = Rig::new();
    let (a, b) = (Sibling::keyed(&rig, 2, "a"), Sibling::keyed(&rig, 3, "b"));
    let (sa, sb) = (a.session(&rig), b.session(&rig));
    let issuer_b = Issuer { token: sb.token(), account: sb.account(), signer: &b.signer };
    // `b`'s draft `z`, granted to `a`.
    let z = b.minted(&rig, &sb, false);
    insert_text(&rig.board, sb.token(), &z.to_string(), 1, "quote");
    let grant = share(&rig.board, &issuer_b, &z, &addr(&a.account)).expect("shared");
    // `a`'s draft `s` windows `z`'s words, then "!" after them.
    let s = a.minted(&rig, &sa, false);
    let s_s = s.to_string();
    let typed = typed_at(&rig.board, sa.token(), &s_s);
    let window = frames::set_arrangement(&s_s, &[frames::shot_run(&z.to_string(), &format!("{z}.0.1.1"), 5)], typed, None, None, None, None);
    let p1 = acked_at(&acked(sa.op(&window))).expect("the window's position");
    insert_text(&rig.board, sa.token(), &s_s, 6, "!");
    // `b` publishes `z` with its kept place.
    let f = b.minted(&rig, &sb, true);
    publish_with_place_as(&rig.board, &sb, &b.signer, &addr(&b.account), &f, &z, "quote");
    assert_eq!(image(&rig.board, sb.token(), &z, 5), vec![(format!("{f}.0.1.1"), 5)], "the premise: z re-windowed onto f's words");
    assert_eq!(image(&rig.board, sa.token(), &s, 6), vec![(format!("{z}.0.1.1"), 5), (format!("{s}.0.1.1"), 1)], "the premise: s windows z's own words");
    // THE RESTORE, `z` read by the grant: its record read in `b`'s account.
    let p = past(&rig.board, sa.token(), &s, p1).expect("the past read");
    assert_eq!(p.state, vec![Run::new(z.clone(), 1, 5)], "the state as read: z's own identity");
    assert_eq!(p.sent, vec![Run::new(f.clone(), 1, 5)], "sent as the words b published");
    assert_eq!((p.records.len(), p.covered(), p.extent()), (1, 5, 5));
    assert_eq!(p.records[0].home, z, "the record homed in z");
    restore(&rig.board, sa.token(), &p).expect("restored");
    assert_eq!(image(&rig.board, sa.token(), &s, 5), vec![(format!("{f}.0.1.1"), 5)], "s holds f's words");
    assert_eq!(text_of(&rig, sa.token(), &s, 5), "quote");
    // THE GRANT REVOKED: no record of `z`'s answered, the write refused.
    revoke(&rig.board, &issuer_b, &grant.at).expect("revoked");
    let q = past(&rig.board, sa.token(), &s, p1).expect("the past read");
    assert_eq!((q.sent.clone(), q.records.len()), (vec![Run::new(z.clone(), 1, 5)], 0), "z's words as read");
    let before = rig.position();
    assert_eq!(restore(&rig.board, sa.token(), &q), Err(Refusal::WindowWithheld(z.clone())));
    assert_eq!(rig.position(), before, "nothing written");
    assert_eq!(image(&rig.board, sa.token(), &s, 5), vec![(format!("{f}.0.1.1"), 5)], "s as it stood");
    for session in [sa, sb] {
        session.close().expect("close");
    }
}
