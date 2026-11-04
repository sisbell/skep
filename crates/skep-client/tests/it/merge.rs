//! THE MERGE against the real daemon (the merge record's §7, "Its tests"):
//! ONE WHOLE MERGE on a claimed permissive board — a base version published,
//! two versions off it so the second lands as a DAUGHTER (wire.md §The
//! publish shot and head-float: "a base the trunk has moved past yields the
//! base's own DAUGHTER"), the head and the daughter composed, the merge
//! landed as a shot — then: the member's image equals M over `placed`; the
//! record is found FROM the daughter by the link of the kind, whose type
//! slot and the record's `type` agree (D13); `verify` says Equal and Differs
//! against another member; `current` returns the record; a second `compose`
//! reports it as prior; a second `land` writes nothing; `head_of` follows
//! the trunk; and `in_claims` at the daughter answers what this wire admits —
//! no claim over version members (the landing's doc). ONE CROSS-ACCOUNT
//! FORK merged back (case (j)): a second account's private fork of a
//! published version, its base the source the board serves for it, composed
//! and landed. And ONE DRAFT SIDE (skep #743): a draft `stage` minted off
//! the base version, its base the one the board records for it and never
//! named — a named base the record does not derive refused — composed and
//! landed as the shot, the draft's fresh text re-minted; its record naming
//! the position the draft was read at and verifying Equal as of it once
//! the shot has moved the draft's base and the draft is edited (skep #453),
//! Unreadable to a guest the draft is withheld from, and refused as the
//! record's where it names a position past the board's head (skep #761).
//! And ONE DRAFT LANDING (the landing lane's brief B; skep #762, #764): the
//! merge composed at one position, the draft edited after it and the
//! landing refused `arrangement_moved` whole; composed again and landed in
//! ONE `set_arrangement` — the draft holding M, its base re-recorded on the
//! head at the extent read and `doc_metadata`'s `merge` read back with the
//! write's position, the record naming that position and verifying Equal;
//! land and tell against a real newer member, `head_moved`; and a fresh
//! draft staged from the head and landed in, a re-run staging nothing, and
//! once it is undone the same composition landed fresh again in the same
//! session, a draft and a record of its own.
//! THE TWO TAKE-BACKS (skep #783): a landing undone — the pre-landing
//! state read at `/op-at`'s `nearest` for `at − 1`, which the daemon
//! answers `not_a_position` inside the landing's commit — the draft's text
//! and base restored and the marker cleared in one write, the replacing
//! record current, and the merge landed again after it, in the same session
//! and in a fresh one, a write and a record of its own; a landing withdrawn
//! — the words kept, the marker cleared; an undo after an edit refused with
//! the edit kept. And THE TWO
//! LANDINGS THE FAKE ALONE CHECKED (skep #775's note): into a free-standing
//! draft, admitted with no base and no marker — its feed row carrying the
//! request's merge beside a null base, by which the undo finds the landing
//! and takes it back in one write (skep #784) — and into a fork whose
//! source is not the head, refused `fork_base_moved` with nothing
//! committed. And ONE MERGE OF MANY DAUGHTERS (skep #792): twenty daughters
//! off the base version merged with the head, a record key whose text alone
//! passes the daemon's 256-byte id cap, landed on the trunk with its record.

use serde_json::{json, Value};
use skep_address::Address;
use skep_client::address::{document_of, parse_address};
use skep_client::board::{
    acked_addr, acked_at, frames, Answer, AtAnswer, Board, ChangesAnswer, ChangesQuery, Scope,
    Token,
};
use skep_client::ceremony::handshake::{handshake, Session, Site};
use skep_client::halt::Halt;
use skep_client::merge::{
    compose, current, head_of, land, resume, undo, verify, withdraw, Inputs, Landed, Landing,
    Merger, NoUndo, RecordLanding, Refusal, Role, Run, RunCounts, Side, SideAt, Verdict,
};
use skep_client::sign::{sig_hex, signer_from_seed, Signer};
use skep_identity::{
    entry_body_empty, entry_body_publish, entry_frame, ContentFreeOp, DocTerm, EntryBody, ShotBase,
    ShotSegmentPiece,
};
use skep_signature::HybridSigner;

use crate::common::{
    bare, board, claim, insert_text, keyed_sub_account, keygen, mint, spawn, wire_delegate,
    wire_session,
};

/// The claimant's account and principal on a notebook.
const ACCOUNT: &str = "1.0.1";
const PRINCIPAL: u64 = 1;

/// THE FORKER: principal 2 at a sub-account delegated under the claimant's,
/// so the claimant — its ancestor — may read the forker's drafts (PUB-1.33)
/// and merge one back. `1.0.1.2`: the claim ceremony seats `1.0.1.1`.
const FORKER_ACCOUNT: &str = "1.0.1.2";
const FORKER: u64 = 2;

fn addr(text: &str) -> Address {
    parse_address(text).expect("an address")
}

/// The `attest` member over `body` for a write whose `doc` row is `doc`,
/// under `account`, signed by the device key — the one composer,
/// `skep_identity::entry_frame`.
fn attest(
    board: &Board,
    signer: &HybridSigner,
    account: &Address,
    doc: &Address,
    body: &EntryBody,
) -> Value {
    let term =
        board.board_term().expect("the board term read").expect("H.1 stands on a claimed board");
    let alg = Signer::public_key(signer).alg();
    let frame = entry_frame(alg, term, account, DocTerm::One(doc), body);
    json!({"alg": alg, "sig": sig_hex(&Signer::sign(signer, &frame))})
}

/// The response document of an acked exchange.
fn acked(answer: Result<Answer, skep_client::Halt>) -> Value {
    match answer.expect("the exchange") {
        Answer::Document(v) => {
            assert!(
                matches!(v["resp"].as_str(), Some("ack" | "ack_addr")),
                "the board refused: {v}"
            );
            v
        }
        Answer::Closed => panic!("the session was closed"),
    }
}

/// A guest read's document, not a rejection.
fn read(board: &Board, token: Option<&Token>, frame: &Value) -> Value {
    let Answer::Document(v) = board.op(token, frame).expect("the read") else { panic!("closed") };
    assert_ne!(v["resp"].as_str(), Some("rejected"), "{v}");
    v
}

/// A read as of `at` through `/op-at`: its document, not a rejection.
fn read_at(board: &Board, token: Option<&Token>, at: u64, frame: &Value) -> Value {
    let AtAnswer::Document(v) = board.op_at(token, at, frame).expect("the read at a position")
    else {
        panic!("no document as of {at}")
    };
    assert_ne!(v["resp"].as_str(), Some("rejected"), "{v}");
    v
}

/// `image` over content ordinals `1 ..= width` of `doc`: the runs as
/// `(i_start, width)`.
fn image(board: &Board, token: &Token, doc: &Address, width: u64) -> Vec<(String, u64)> {
    let v = read(board, Some(token), &frames::image(&doc.to_string(), 1, width));
    v["runs"]
        .as_array()
        .expect("runs")
        .iter()
        .map(|r| {
            (
                r["i_start"].as_str().unwrap().to_string(),
                r["width"].as_str().unwrap().parse().unwrap(),
            )
        })
        .collect()
}

/// A published document minted into the claimant's account from the signed
/// session with its attest.
fn published_document(board: &Board, session: &Session<'_>, signer: &HybridSigner) -> Address {
    let account = addr(ACCOUNT);
    let mut frame = json!({"op": "create_new_document", "account": ACCOUNT, "published": true});
    frame["attest"] = attest(
        board,
        signer,
        &account,
        &account,
        &entry_body_empty(ContentFreeOp::CreateNewDocument),
    );
    addr(acked_addr(&acked(session.op(&frame))).expect("a minted address"))
}

/// One run of a shot as the test stages it: the document's own positions by
/// reference, or a staging draft's fresh text.
enum Staged<'a> {
    /// `width` positions of `doc`'s own I-space from ordinal `from`, whose
    /// bytes are `text`.
    Own { from: u64, text: &'a str },
    /// A draft minted and filled with `text`, re-inserted by the shot.
    Fresh { text: &'a str },
}

/// THE SHOT by hand, as the daemon's own suite composes it: `runs` in V-order,
/// each own run by reference and each fresh run through a staging draft, the
/// body the copied values one per position with the base group, attested;
/// the member minted.
fn shot(
    board: &Board,
    session: &Session<'_>,
    signer: &HybridSigner,
    bare_token: &Token,
    doc: &Address,
    base: Option<(&Address, u64)>,
    staged: &[Staged<'_>],
) -> Address {
    let account = addr(ACCOUNT);
    let mut runs = Vec::new();
    let mut values: Vec<u8> = Vec::new();
    let mut draft: Option<Address> = None;
    for s in staged {
        match s {
            Staged::Own { from, text } => {
                runs.push(frames::shot_run(
                    &doc.to_string(),
                    &format!("{doc}.0.1.{from}"),
                    text.len() as u64,
                ));
                values.extend_from_slice(text.as_bytes());
            }
            Staged::Fresh { text } => {
                let d = addr(&mint(board, bare_token, ACCOUNT, false));
                insert_text(board, bare_token, &d.to_string(), 1, text);
                let image = image(board, bare_token, &d, text.len() as u64);
                assert_eq!(image.len(), 1, "one burst at one caret is one run: {image:?}");
                runs.push(frames::shot_run(&d.to_string(), &image[0].0, image[0].1));
                values.extend_from_slice(text.as_bytes());
                assert!(draft.is_none(), "one staging draft a shot");
                draft = Some(d);
            }
        }
    }
    let pieces: Vec<[u8; 1]> = values.iter().map(|b| [*b]).collect();
    let shot_base = base.map(|(member, extent)| ShotBase { member, extent });
    let body = entry_body_publish(pieces.iter().map(|b| ShotSegmentPiece::Value(b)), shot_base);
    let base_text = base.map(|(m, e)| (m.to_string(), e));
    let draft_text = draft.as_ref().map(ToString::to_string);
    let doc_text = doc.to_string();
    let mut frame = frames::publication(&frames::PublishFrame {
        doc: Some(&doc_text),
        base: base_text.as_ref().map(|(m, e)| (m.as_str(), *e)),
        draft: draft_text.as_deref(),
        runs: &runs,
        ..frames::PublishFrame::default()
    });
    frame["attest"] = attest(board, signer, &account, doc, &body);
    addr(acked_addr(&acked(session.op(&frame))).expect("the member's address"))
}

/// The runs of the race shape over `d`: `(d, s, w)`.
fn rd(d: &Address, s: u64, w: u64) -> Run {
    Run::new(d.clone(), s, w)
}

/// ONE WHOLE MERGE: the race shape of the record's §9 — the base "the cat
/// sat", the head adding "big " at `D·4|D·5`, the daughter removing " sat"
/// — composed and landed, then every read-back the record names.
#[test]
fn one_whole_merge_lands_on_the_trunk_with_its_record() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(&dir.path().join("board"), true);
    let board = board(sd.port());
    let store = skep_client::store::FileStore::open(dir.path().join("store"));
    let fp = keygen(&store, "notebook");
    claim(&board, &store, &dir.path().join("anchors"));
    let device = store.load(&store.key_path(&fp)).expect("the device key").signer();
    let session = handshake(&board, Scope::Content, &device, PRINCIPAL, Site::Session)
        .expect("a content session");
    let token = session.token().clone();
    let bare_token = bare(&board, PRINCIPAL);

    // The document, its base version and the two versions off it.
    let d = published_document(&board, &session, &device);
    let base = shot(
        &board,
        &session,
        &device,
        &bare_token,
        &d,
        None,
        &[Staged::Fresh { text: "the cat sat" }],
    );
    assert_eq!(base.to_string(), format!("{d}.1"), "the birth version");
    assert_eq!(
        image(&board, &token, &base, 11),
        vec![(format!("{d}.0.1.1"), 11)],
        "one run of the document's own chain"
    );
    let head = shot(
        &board,
        &session,
        &device,
        &bare_token,
        &d,
        Some((&base, 11)),
        &[
            Staged::Own { from: 1, text: "the " },
            Staged::Fresh { text: "big " },
            Staged::Own { from: 5, text: "cat sat" },
        ],
    );
    assert_eq!(head.to_string(), format!("{d}.2"), "the trunk's next member");
    assert_eq!(
        image(&board, &token, &head, 15),
        vec![(format!("{d}.0.1.1"), 4), (format!("{d}.0.1.12"), 4), (format!("{d}.0.1.5"), 7)],
        "the fresh text minted at D·12"
    );
    let daughter = shot(
        &board,
        &session,
        &device,
        &bare_token,
        &d,
        Some((&base, 11)),
        &[Staged::Own { from: 1, text: "the cat" }],
    );
    assert_eq!(
        daughter.to_string(),
        format!("{d}.1.1"),
        "a base the trunk has moved past yields the base's own DAUGHTER"
    );
    assert_eq!(
        head_of(&board, Some(&token), &d).expect("the feed walk"),
        Some(head.clone()),
        "the head member off the feed"
    );

    // The kind: a document of the account standing as the record kind's type.
    let kind = addr(&mint(&board, &bare_token, ACCOUNT, false));

    // COMPOSE: the reads, the walk, nothing written.
    let before = board.health().unwrap().log_position();
    let inputs = Inputs {
        doc: d.clone(),
        head: head.clone(),
        base: None,
        sides: vec![Side::Member(daughter.clone())],
        options: Default::default(),
        kind: kind.clone(),
    };
    let merged = compose(&board, Some(&token), &inputs).expect("composed");
    assert_eq!(
        merged.composed.runs.iter().map(|p| p.run.clone()).collect::<Vec<_>>(),
        vec![rd(&d, 1, 4), rd(&d, 12, 4), rd(&d, 5, 3)],
        "the big cat"
    );
    assert_eq!(merged.composed.counts, RunCounts { a: 3, b: 1, m: 3 });
    assert!(merged.composed.gaps.is_empty(), "{:?}", merged.composed.gaps);
    assert_eq!(merged.key.base, base);
    assert_eq!(merged.head_extent, 15);
    assert_eq!(merged.prior, None);
    assert_eq!(merged.record.landed, None);
    assert_eq!(board.health().unwrap().log_position(), before, "compose writes nothing");

    // LAND as a shot, the merger the session's facts and the device key.
    let merger = Merger { token: session.token(), account: session.account(), signer: &device };
    let landed = land(&board, &merged, Landing::Shot { merger, draft: None, journal: None })
        .expect("landed");
    let Landed::Member { address: member, position, claims, record: link, retries } =
        landed.clone()
    else {
        panic!("{landed:?}")
    };
    assert_eq!(member.to_string(), format!("{d}.3"), "the merge is the trunk's next member");
    assert_eq!((claims.as_slice(), retries), (&[][..], 0));
    assert!(position > before);
    // The member's image over its first `placed` positions is M.
    let meta = read(&board, Some(&token), &frames::doc_metadata(&member.to_string()));
    assert_eq!(meta["placed"].as_str(), Some("11"), "{meta}");
    assert_eq!(
        image(&board, &token, &member, 11),
        vec![(format!("{d}.0.1.1"), 4), (format!("{d}.0.1.12"), 4), (format!("{d}.0.1.5"), 3)]
    );
    // The claim, as this wire admits it: none over version members.
    let claims_at_daughter = read(&board, Some(&token), &frames::in_claims(&daughter.to_string()));
    assert_eq!(
        claims_at_daughter["claims"].as_array().map(Vec::len),
        Some(0),
        "{claims_at_daughter}"
    );
    // The record is found FROM the daughter by the link of the kind, and its
    // `type` agrees with the link's type slot (D13).
    let found = read(
        &board,
        Some(&token),
        &frames::find_links_ftt(&kind.to_string(), &daughter.to_string()),
    );
    assert_eq!(
        found["addrs"].as_array().map(|a| a.iter().filter_map(Value::as_str).collect::<Vec<_>>()),
        Some(vec![link.to_string().as_str()]),
        "{found}"
    );
    let lv = read(&board, Some(&token), &frames::read_link(&link.to_string()));
    let starts = |slot: usize| {
        lv["link"]["slots"][slot]
            .as_array()
            .unwrap()
            .iter()
            .map(|s| s["start"].as_str().unwrap().to_string())
            .collect::<Vec<_>>()
    };
    assert_eq!(starts(2), vec![kind.to_string()], "the link's type slot is the kind");
    assert_eq!(
        starts(1),
        vec![member.to_string(), daughter.to_string()],
        "to the member and the daughter"
    );
    assert_eq!(
        document_of(&link.to_string()).as_deref(),
        Some("1.0.1.0.1"),
        "homed in the merger's doc 1"
    );
    let atom = &starts(0)[0];
    let journal = addr(&document_of(atom).expect("the atom's document"));
    let journal_meta = read(&board, Some(&token), &frames::doc_metadata(&journal.to_string()));
    assert_eq!(
        journal_meta["published"].as_bool(),
        Some(false),
        "the default journal is a private draft: {journal_meta}"
    );
    // The record, current for the key, read through the journal.
    let record = current(&board, Some(&token), &kind, &merged.key)
        .expect("the lookup")
        .expect("a current record");
    assert_eq!(record.landed, Some(RecordLanding::Member { member: member.clone(), position }));
    assert_eq!(record.link, Some(link.clone()));
    assert_eq!(
        record.to_value()["type"].as_str(),
        Some("merge"),
        "the record's type agrees with the link's class"
    );
    assert_eq!(
        (record.runs, record.retries, record.replaces.clone()),
        (RunCounts { a: 3, b: 1, m: 3 }, 0, None)
    );
    assert_eq!(record.key(), merged.key);
    // Its testimony recomputed.
    assert_eq!(verify(&board, Some(&token), &record).expect("verified"), Verdict::Equal);
    let mut wrong = record.clone();
    wrong.landed = Some(RecordLanding::Member { member: head.clone(), position });
    assert_eq!(
        verify(&board, Some(&token), &wrong).expect("verified"),
        Verdict::Differs { at: 12 },
        "the head holds ' sat' past M's eleven positions"
    );
    // A second compose reports the prior; a second land writes nothing.
    let again = compose(&board, Some(&token), &inputs).expect("composed again");
    assert_eq!(again.prior.as_ref().map(|p| p.landed.clone()), Some(record.landed.clone()));
    assert_eq!(again.record.replaces, Some(link.clone()), "a later record names what it replaces");
    let position_before = board.health().unwrap().log_position();
    let second = land(&board, &merged, Landing::Shot { merger, draft: None, journal: None })
        .expect("landed again");
    assert_eq!(second, landed, "the same landing, read back");
    assert_eq!(board.health().unwrap().log_position(), position_before, "nothing written twice");
    assert_eq!(
        head_of(&board, Some(&token), &d).expect("the feed walk"),
        Some(member),
        "the trunk's head is the merge"
    );
    session.close().expect("close");
}

/// CASE (j) ON THE REAL DAEMON — a cross-account fork of a PUBLISHED version
/// merged back (the merge record's §1.2 shape (4); the fork-source design
/// record's arm A). The forker's account `1.0.1.1` is delegated under the
/// claimant's, so the claimant, its ancestor, may read the fork; the forker
/// forks the base version `D.1` privately — a fresh document of its own
/// account, born sharing `D.1`, which the board serves as its `source` — and
/// removes " sat", while the head has added "big ". The library reads that
/// source off the fork's `doc_metadata`, takes it as the base, never named
/// (a base named beside the fork is refused), composes "the big cat", lands
/// it as the trunk's next member with its record found from the fork, and
/// `verify` recomputes the record against the served source.
#[test]
fn a_cross_account_fork_of_a_published_version_merges_from_its_served_source() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(&dir.path().join("board"), true);
    let board = board(sd.port());
    let store = skep_client::store::FileStore::open(dir.path().join("store"));
    let fp = keygen(&store, "notebook");
    claim(&board, &store, &dir.path().join("anchors"));
    let device = store.load(&store.key_path(&fp)).expect("the device key").signer();
    let session = handshake(&board, Scope::Content, &device, PRINCIPAL, Site::Session)
        .expect("a content session");
    let token = session.token().clone();
    let bare_token = bare(&board, PRINCIPAL);

    // The document, its base version and the head.
    let d = published_document(&board, &session, &device);
    let base = shot(
        &board,
        &session,
        &device,
        &bare_token,
        &d,
        None,
        &[Staged::Fresh { text: "the cat sat" }],
    );
    let head = shot(
        &board,
        &session,
        &device,
        &bare_token,
        &d,
        Some((&base, 11)),
        &[
            Staged::Own { from: 1, text: "the " },
            Staged::Fresh { text: "big " },
            Staged::Own { from: 5, text: "cat sat" },
        ],
    );
    assert_eq!((base.to_string(), head.to_string()), (format!("{d}.1"), format!("{d}.2")));

    // THE FORK: the forker's account delegated from the claimant's
    // full-scope session, then its bare session's private `version` of the
    // base member — a fresh document of its own, born sharing `D.1`.
    let as_owner = wire_session(&board, PRINCIPAL, &device);
    wire_delegate(&board, &as_owner, FORKER_ACCOUNT, FORKER).expect("the forker delegated");
    board.session_close(&as_owner).expect("closed");
    let forker = bare(&board, FORKER);
    // Its home first: a mint into an account without one is `mint_home_first`.
    assert_eq!(mint(&board, &forker, FORKER_ACCOUNT, false), format!("{FORKER_ACCOUNT}.0.1"));
    let fork_frame = json!({"op": "version", "d_src": base.to_string(), "published": false});
    let forked = acked(board.op(Some(&forker), &fork_frame));
    let fork = addr(acked_addr(&forked).expect("the fork"));
    let forked_at = forked["at"].as_u64().expect("the fork's position");
    assert!(fork.to_string().starts_with(&format!("{FORKER_ACCOUNT}.0.")), "{fork}");
    let meta = read(&board, Some(&token), &frames::doc_metadata(&fork.to_string()));
    assert_eq!(meta["source"].as_str(), Some(base.to_string().as_str()), "the served source: {meta}");
    assert_eq!(meta["published"].as_bool(), Some(false), "{meta}");
    // The forker removes " sat" — positions 8–11 of its own draft, typed
    // against the fork's own mint, the forker's last ack on it.
    acked(board.op(Some(&forker), &frames::delete(&fork.to_string(), 8, 4, forked_at, None)));
    assert_eq!(
        image(&board, &token, &fork, 7),
        vec![(format!("{d}.0.1.1"), 7)],
        "the fork, read by the claimant as the forker's ancestor"
    );
    let kind = addr(&mint(&board, &bare_token, ACCOUNT, false));

    // COMPOSE from the served source: the base is `D.1`, derived and never
    // named; a base named beside the fork is refused before any read.
    let before = board.health().unwrap().log_position();
    let inputs = Inputs {
        doc: d.clone(),
        head: head.clone(),
        base: None,
        sides: vec![Side::Fork(fork.clone())],
        options: Default::default(),
        kind: kind.clone(),
    };
    let merged = compose(&board, Some(&token), &inputs).expect("composed");
    assert_eq!(
        merged.composed.runs.iter().map(|p| p.run.clone()).collect::<Vec<_>>(),
        vec![rd(&d, 1, 4), rd(&d, 12, 4), rd(&d, 5, 3)],
        "the big cat"
    );
    assert_eq!(merged.key.base, base, "the fork's served source is the base");
    assert!(merged.composed.gaps.is_empty(), "{:?}", merged.composed.gaps);
    assert_eq!(merged.composed.counts, RunCounts { a: 3, b: 1, m: 3 });
    assert_eq!(
        merged.record.sides.iter().map(|s| s.role()).collect::<Vec<_>>(),
        [Role::Head, Role::Fork]
    );
    assert_eq!(board.health().unwrap().log_position(), before, "compose writes nothing");
    let named = Inputs { base: Some(base.clone()), ..inputs.clone() };
    assert_eq!(
        compose(&board, Some(&token), &named),
        Err(Refusal::ForkBaseNamed { fork: fork.clone(), base: base.clone() })
    );

    // LAND as the shot: the trunk's next member holds M, the record is found
    // FROM the fork by the kind, and verifies against the served source.
    let merger = Merger { token: session.token(), account: session.account(), signer: &device };
    let landed = land(&board, &merged, Landing::Shot { merger, draft: None, journal: None })
        .expect("landed");
    let Landed::Member { address: member, record: link, .. } = landed else { panic!("{landed:?}") };
    assert_eq!(member.to_string(), format!("{d}.3"), "the trunk's next member");
    assert_eq!(
        image(&board, &token, &member, 11),
        vec![(format!("{d}.0.1.1"), 4), (format!("{d}.0.1.12"), 4), (format!("{d}.0.1.5"), 3)]
    );
    let found =
        read(&board, Some(&token), &frames::find_links_ftt(&kind.to_string(), &fork.to_string()));
    assert_eq!(found["addrs"], json!([link.to_string()]), "the record is found FROM the fork");
    let record = current(&board, Some(&token), &kind, &merged.key)
        .expect("the lookup")
        .expect("a current record");
    assert_eq!(record.base, base);
    assert_eq!(record.link, Some(link));
    assert_eq!(verify(&board, Some(&token), &record).expect("verified"), Verdict::Equal);
    session.close().expect("close");
}

/// A DRAFT SIDE ON THE REAL DAEMON (skep #743; the merge record's §1.2
/// shape (2)): the draft `stage` minted off the base version `D.1` — the
/// board recording `D.1` as its base — with "!!!" typed at its end, merged
/// with the head `D.2`, which added "big ". The library reads the base off
/// the draft's `doc_metadata`, never named, and composes "the big cat
/// sat!!!" with the draft's fresh text as its own family; a base named
/// beside the draft is checked against the one the record derives — the
/// head refused by name, the base taken; the shot lands as the trunk's next
/// member, the draft's text re-minted under the document, with its record
/// found from the draft; and the board moves the draft's recorded base to
/// the member the merge minted. The record verifies Equal as of the
/// position it names for the draft, Unreadable naming the draft to a guest
/// the board withholds it from, and one naming a position past the board's
/// head is refused as the record's, the daemon's head carried.
#[test]
fn a_draft_side_merges_from_the_base_the_board_records() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(&dir.path().join("board"), true);
    let board = board(sd.port());
    let store = skep_client::store::FileStore::open(dir.path().join("store"));
    let fp = keygen(&store, "notebook");
    claim(&board, &store, &dir.path().join("anchors"));
    let device = store.load(&store.key_path(&fp)).expect("the device key").signer();
    let session = handshake(&board, Scope::Content, &device, PRINCIPAL, Site::Session)
        .expect("a content session");
    let token = session.token().clone();
    let bare_token = bare(&board, PRINCIPAL);

    // The document, its base version and the head.
    let d = published_document(&board, &session, &device);
    let base = shot(
        &board,
        &session,
        &device,
        &bare_token,
        &d,
        None,
        &[Staged::Fresh { text: "the cat sat" }],
    );
    let head = shot(
        &board,
        &session,
        &device,
        &bare_token,
        &d,
        Some((&base, 11)),
        &[
            Staged::Own { from: 1, text: "the " },
            Staged::Fresh { text: "big " },
            Staged::Own { from: 5, text: "cat sat" },
        ],
    );
    assert_eq!((base.to_string(), head.to_string()), (format!("{d}.1"), format!("{d}.2")));

    // THE STAGED DRAFT: `stage` off the base from the bare session — the
    // board records the base and what the copy took — and "!!!" typed at
    // its end.
    let staged = acked(board.op(Some(&bare_token), &frames::stage(&base.to_string(), None)));
    let draft = addr(acked_addr(&staged).expect("the staged draft's address"));
    insert_text(&board, &bare_token, &draft.to_string(), 12, "!!!");
    let meta = read(&board, Some(&token), &frames::doc_metadata(&draft.to_string()));
    assert_eq!(
        (meta["base"].as_str(), meta["base_copied"].as_str()),
        (Some(base.to_string().as_str()), Some("11")),
        "the premise — the board records the draft's base: {meta}"
    );
    assert_eq!(
        image(&board, &token, &draft, 14),
        vec![(format!("{d}.0.1.1"), 11), (format!("{draft}.0.1.1"), 3)],
        "the base's text by identity, the draft's own after it"
    );
    let kind = addr(&mint(&board, &bare_token, ACCOUNT, false));

    // COMPOSE with no base named: the base is read off the draft's metadata.
    let before = board.health().unwrap().log_position();
    let side = Side::Draft { at: draft.clone(), position: None };
    let inputs = Inputs {
        doc: d.clone(),
        head: head.clone(),
        base: None,
        sides: vec![side.clone()],
        options: Default::default(),
        kind: kind.clone(),
    };
    let merged = compose(&board, Some(&token), &inputs).expect("composed");
    assert_eq!(
        merged.composed.runs.iter().map(|p| p.run.clone()).collect::<Vec<_>>(),
        vec![rd(&d, 1, 4), rd(&d, 12, 4), rd(&d, 5, 7), Run::new(draft.clone(), 1, 3)],
        "the big cat sat!!!"
    );
    assert_eq!(merged.key.base, base, "the base the board records for the draft, never named");
    assert_eq!(merged.composed.counts, RunCounts { a: 3, b: 2, m: 4 });
    assert!(merged.composed.gaps.is_empty(), "{:?}", merged.composed.gaps);
    assert_eq!(
        merged.record.sides.iter().map(|s| s.role()).collect::<Vec<_>>(),
        [Role::Head, Role::Draft]
    );
    assert_eq!(board.health().unwrap().log_position(), before, "compose writes nothing");
    // A NAMED BASE is checked against the one the record derives: the head
    // refused by name, the base itself taken.
    let named = |b: &Address| Inputs { base: Some(b.clone()), ..inputs.clone() };
    assert_eq!(
        compose(&board, Some(&token), &named(&head)),
        Err(Refusal::DraftBaseDisagrees {
            side: side.clone(),
            named: head.clone(),
            served: base.clone()
        })
    );
    assert_eq!(compose(&board, Some(&token), &named(&base)).expect("composed").key.base, base);
    assert_eq!(board.health().unwrap().log_position(), before, "nothing written");

    // LAND as the shot: the draft's text re-minted under the document at its
    // next fresh ordinals, the trunk's next member holding M, the record
    // found FROM the draft by the kind.
    let merger = Merger { token: session.token(), account: session.account(), signer: &device };
    let landed = land(&board, &merged, Landing::Shot { merger, draft: None, journal: None })
        .expect("landed");
    let Landed::Member { address: member, record: link, .. } = landed else { panic!("{landed:?}") };
    assert_eq!(member.to_string(), format!("{d}.3"), "the trunk's next member");
    assert_eq!(
        image(&board, &token, &member, 18),
        vec![
            (format!("{d}.0.1.1"), 4),
            (format!("{d}.0.1.12"), 4),
            (format!("{d}.0.1.5"), 7),
            (format!("{d}.0.1.16"), 3)
        ],
        "the draft's text re-minted under D at D·16"
    );
    let found =
        read(&board, Some(&token), &frames::find_links_ftt(&kind.to_string(), &draft.to_string()));
    assert_eq!(found["addrs"], json!([link.to_string()]), "the record is found FROM the draft");
    let record = current(&board, Some(&token), &kind, &merged.key)
        .expect("the lookup")
        .expect("a current record");
    assert_eq!((record.base.clone(), record.link.clone()), (base.clone(), Some(link)));
    // THE BASE MOVES with the shot that rendered the draft (wire.md
    // §Namespace, `stage`): the board now records the member the merge
    // minted as the draft's base.
    let meta = read(&board, Some(&token), &frames::doc_metadata(&draft.to_string()));
    assert_eq!(
        meta["base"].as_str(),
        Some(member.to_string().as_str()),
        "the draft's recorded base moved to the merge's member: {meta}"
    );
    // THE RECORD NAMES THE POSITION the draft was read at (skep #453) — the
    // board's position when `compose` imaged it — and `verify` reads the
    // draft and its recorded base as of it: the premise, `doc_metadata` on
    // `/op-at` at that position answers the base that stood; then Equal, and
    // Equal still once the draft is edited past the shot, where a record
    // naming no position reads the draft as it stands and is refused by name
    // against the moved base.
    let SideAt::Draft { position: Some(at), .. } = &record.sides[1] else {
        panic!("the record's draft side names no position: {:?}", record.sides)
    };
    assert_eq!(*at, before, "the position the draft was imaged at");
    let meta_at = read_at(&board, Some(&token), *at, &frames::doc_metadata(&draft.to_string()));
    assert_eq!(
        meta_at["base"].as_str(),
        Some(base.to_string().as_str()),
        "the premise — as of the record's position, the base that stood: {meta_at}"
    );
    assert_eq!(verify(&board, Some(&token), &record), Ok(Verdict::Equal));
    // A GUEST may not read the draft: the verdict is withheld, naming the
    // draft, never refused (the merge record's §4, testimony; D14). The
    // premise: as of the record's position, the board answers a guest's read
    // of the draft `withheld`.
    let AtAnswer::Document(masked) = board
        .op_at(None, *at, &frames::doc_metadata(&draft.to_string()))
        .expect("the read at a position")
    else {
        panic!("no document as of {at}")
    };
    assert_eq!(
        masked["code"].as_str(),
        Some("withheld"),
        "the premise — the draft is withheld from a guest: {masked}"
    );
    assert_eq!(verify(&board, None, &record), Ok(Verdict::Unreadable(draft.clone())));
    insert_text(&board, &bare_token, &draft.to_string(), 1, "?");
    assert_eq!(
        verify(&board, Some(&token), &record),
        Ok(Verdict::Equal),
        "the testimony is of the state the merge composed from"
    );
    let mut headless = record.clone();
    headless.sides[1] = SideAt::Draft { at: draft.clone(), position: None };
    assert!(
        matches!(
            verify(&board, Some(&token), &headless),
            Err(Refusal::DraftBaseDisagrees { ref named, .. }) if *named == base
        ),
        "a record naming no position reads the draft as it stands"
    );
    // A RECORD NAMING A POSITION PAST THE BOARD'S HEAD is refused as the
    // record's, the daemon's head carried and nothing read at another
    // position in its place (skep #761).
    let now = board.health().unwrap().log_position();
    let mut ahead = record.clone();
    ahead.sides[1] = SideAt::Draft { at: draft.clone(), position: Some(now + 1000) };
    assert_eq!(
        verify(&board, Some(&token), &ahead),
        Err(Refusal::BeyondHead { at: now + 1000, head: Some(now), recorded: Some(draft.clone()) })
    );
    session.close().expect("close");
}

/// M's runs as `image` spells them, `(i_start, width)`.
fn as_image(runs: &[Run]) -> Vec<(String, u64)> {
    runs.iter().map(|r| (format!("{}.0.1.{}", r.origin, r.i_start), r.width)).collect()
}

/// THE DRAFT LANDING ON THE REAL DAEMON (the landing lane's brief B; skep
/// #762, #764): the staged draft `S` off `D.1` with "!!!" typed, merged with
/// the head `D.2` — every read at ONE position, the record's draft side
/// naming it. An edit to `S` after the composition makes the landing refuse
/// `arrangement_moved` whole, nothing written and nothing wiped. Composed
/// again, the landing is ONE write: `S` holds M, its base is re-recorded on
/// `D.2` at the fifteen positions read, `doc_metadata`'s `merge` names the
/// head, no side (the draft was the side) and the write's position, the
/// record names that position and verifies Equal. LAND AND TELL: version 3
/// published, a second draft `T` staged off `D.2` and merged with `D.2`
/// named as the head lands and carries `head_moved` = `D.3`, its base
/// recorded on `D.2`. A FRESH DRAFT: `into` none stages from the head and
/// lands there, the base and the marker recorded; composed again, the
/// standing record names the landing and nothing is staged. Undone, the
/// composition that landed it lands fresh again in the same session — a
/// draft, a write and a record of its own, replacing the undo's — and the
/// later composition answers that landing.
#[test]
fn a_draft_landing_is_one_write_refused_whole_where_the_draft_changed_and_tells_a_newer_head() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(&dir.path().join("board"), true);
    let board = board(sd.port());
    let store = skep_client::store::FileStore::open(dir.path().join("store"));
    let fp = keygen(&store, "notebook");
    claim(&board, &store, &dir.path().join("anchors"));
    let device = store.load(&store.key_path(&fp)).expect("the device key").signer();
    let session = handshake(&board, Scope::Content, &device, PRINCIPAL, Site::Session)
        .expect("a content session");
    let token = session.token().clone();
    let bare_token = bare(&board, PRINCIPAL);
    let position = || board.health().unwrap().log_position();

    let d = published_document(&board, &session, &device);
    let base = shot(&board, &session, &device, &bare_token, &d, None, &[Staged::Fresh { text: "the cat sat" }]);
    let head = shot(
        &board,
        &session,
        &device,
        &bare_token,
        &d,
        Some((&base, 11)),
        &[Staged::Own { from: 1, text: "the " }, Staged::Fresh { text: "big " }, Staged::Own { from: 5, text: "cat sat" }],
    );
    assert_eq!((base.to_string(), head.to_string()), (format!("{d}.1"), format!("{d}.2")));
    let staged = acked(board.op(Some(&bare_token), &frames::stage(&base.to_string(), None)));
    let draft = addr(acked_addr(&staged).expect("the staged draft's address"));
    insert_text(&board, &bare_token, &draft.to_string(), 12, "!!!");
    let kind = addr(&mint(&board, &bare_token, ACCOUNT, false));
    let merger = Merger { token: session.token(), account: session.account(), signer: &device };
    let into = |draft: &Address| Landing::Draft { merger, into: Some(draft.clone()), journal: None };

    // COMPOSE at one position: the head when it began.
    let before = position();
    let inputs = Inputs {
        doc: d.clone(),
        head: head.clone(),
        base: None,
        sides: vec![Side::Draft { at: draft.clone(), position: None }],
        options: Default::default(),
        kind: kind.clone(),
    };
    let merged = compose(&board, Some(&token), &inputs).expect("composed");
    assert_eq!(merged.as_of, before, "the one position every read was made at");
    assert_eq!(merged.record.sides[1], SideAt::Draft { at: draft.clone(), position: Some(before) });
    assert_eq!(merged.head_extent, 15);
    // ANOTHER HAND's edit after the composition: the landing is refused
    // whole, nothing written, nothing wiped.
    insert_text(&board, &bare_token, &draft.to_string(), 1, "?");
    let edited = image(&board, &token, &draft, 15);
    assert_eq!(edited.len(), 3, "?the cat sat!!!: {edited:?}");
    let untouched = position();
    let err = land(&board, &merged, into(&draft)).expect_err("the draft changed after the merge was composed");
    let Refusal::Halt(Halt::Refused(refused)) = &err else { panic!("{err:?}") };
    assert_eq!(refused.code, "arrangement_moved", "{refused:?}");
    let detail = refused.detail.as_deref().expect("the person's words");
    assert!(detail.contains(&draft.to_string()) && detail.contains("nothing was merged"), "{detail}");
    assert_eq!(position(), untouched, "nothing written");
    assert_eq!(image(&board, &token, &draft, 15), edited, "nothing wiped");
    let meta = read(&board, Some(&token), &frames::doc_metadata(&draft.to_string()));
    assert_eq!((meta["base"].as_str(), meta["merge"].is_null()), (Some(base.to_string().as_str()), true), "the base and no marker, as they stood: {meta}");

    // COMPOSED AGAIN and landed: one write.
    let merged = compose(&board, Some(&token), &inputs).expect("composed again");
    let m = merged.composed.runs.iter().map(|p| p.run.clone()).collect::<Vec<_>>();
    assert_eq!(m.len(), 5, "?the big cat sat!!!: {m:?}");
    let landed = land(&board, &merged, into(&draft)).expect("landed");
    let Landed::Draft { into: landed_in, position: at, record: link, head_moved } = landed.clone() else { panic!("{landed:?}") };
    assert_eq!((landed_in, head_moved), (draft.clone(), None));
    let extent: u64 = m.iter().map(|r| r.width).sum();
    assert_eq!(extent, 19, "?the big cat sat!!!");
    assert_eq!(image(&board, &token, &draft, extent), as_image(&m), "the draft holds M, whole");
    let meta = read(&board, Some(&token), &frames::doc_metadata(&draft.to_string()));
    assert_eq!(
        (meta["base"].as_str(), meta["base_copied"].as_str()),
        (Some(head.to_string().as_str()), Some("15")),
        "the base re-recorded on the head at the extent read: {meta}"
    );
    assert_eq!(meta["merge"], json!({"at": at, "head": head.to_string(), "head_copied": "15", "sides": []}), "the marker, at the write's position: {meta}");
    let record = current(&board, Some(&token), &kind, &merged.key).expect("the lookup").expect("a current record");
    assert_eq!(record.landed, Some(RecordLanding::Draft { draft: draft.clone(), position: at }), "the write's position");
    assert_eq!(record.link, Some(link));
    assert_eq!(verify(&board, Some(&token), &record), Ok(Verdict::Equal));
    // The same landing again in this session: the board answers the id
    // again, and nothing is written twice.
    let standing = position();
    assert_eq!(land(&board, &merged, into(&draft)).expect("landed again"), landed);
    assert_eq!(position(), standing, "nothing written twice");

    // LAND AND TELL: version 3 published since; a draft off version 2 merged
    // with version 2 named lands and is told the newer head.
    let third = shot(
        &board,
        &session,
        &device,
        &bare_token,
        &d,
        Some((&head, 15)),
        &[Staged::Own { from: 1, text: "the " }, Staged::Own { from: 12, text: "big " }, Staged::Own { from: 5, text: "cat sat" }, Staged::Fresh { text: "?" }],
    );
    assert_eq!(third.to_string(), format!("{d}.3"));
    let t = addr(acked_addr(&acked(board.op(Some(&bare_token), &frames::stage(&head.to_string(), None)))).expect("the second draft"));
    insert_text(&board, &bare_token, &t.to_string(), 16, "...");
    let inputs_t = Inputs { sides: vec![Side::Draft { at: t.clone(), position: None }], ..inputs.clone() };
    let merged_t = compose(&board, Some(&token), &inputs_t).expect("composed on version 2");
    let landed_t = land(&board, &merged_t, into(&t)).expect("landed");
    let Landed::Draft { position: at_t, head_moved, .. } = landed_t else { panic!("{landed_t:?}") };
    assert_eq!(head_moved, Some(third.clone()), "the trunk's current head, told");
    let meta = read(&board, Some(&token), &frames::doc_metadata(&t.to_string()));
    assert_eq!(meta["base"].as_str(), Some(head.to_string().as_str()), "recorded on the head used: {meta}");
    assert_eq!(meta["merge"]["head"].as_str(), Some(head.to_string().as_str()));
    assert_eq!(meta["merge"]["at"].as_u64(), Some(at_t));

    // A FRESH DRAFT: staged from the head, landed in; composed again, the
    // standing record names the landing and nothing is staged.
    let inputs_fresh = Inputs { head: third.clone(), sides: vec![Side::Draft { at: t.clone(), position: None }], ..inputs.clone() };
    let merged_fresh = compose(&board, Some(&token), &inputs_fresh).expect("composed on version 3");
    let fresh_landing = || Landing::Draft { merger, into: None, journal: None };
    let landed_fresh = land(&board, &merged_fresh, fresh_landing()).expect("landed in a fresh draft");
    let Landed::Draft { into: fresh, position: at_fresh, head_moved, .. } = landed_fresh.clone() else { panic!("{landed_fresh:?}") };
    assert!(fresh != t && fresh != draft, "a fresh draft: {fresh}");
    assert_eq!(head_moved, None);
    let m = merged_fresh.composed.runs.iter().map(|p| p.run.clone()).collect::<Vec<_>>();
    let extent: u64 = m.iter().map(|r| r.width).sum();
    assert_eq!(image(&board, &token, &fresh, extent), as_image(&m), "the fresh draft holds M");
    let meta = read(&board, Some(&token), &frames::doc_metadata(&fresh.to_string()));
    assert_eq!((meta["base"].as_str(), meta["base_copied"].as_str(), meta["source"].as_str()), (Some(third.to_string().as_str()), Some("16"), Some(third.to_string().as_str())), "staged from the head, the base re-recorded on it: {meta}");
    assert_eq!(meta["merge"], json!({"at": at_fresh, "head": third.to_string(), "head_copied": "16", "sides": [t.to_string()]}), "{meta}");
    let standing = position();
    let again = compose(&board, Some(&token), &inputs_fresh).expect("composed again");
    assert!(matches!(again.prior.as_ref().and_then(|p| p.landed.as_ref()), Some(RecordLanding::Draft { draft, .. }) if *draft == fresh), "the standing record names the landing: {:?}", again.prior);
    assert_eq!(land(&board, &again, fresh_landing()).expect("the standing landing"), landed_fresh);
    assert_eq!(position(), standing, "nothing staged, nothing written");

    // UNDONE, then the composition that landed it landed fresh again in
    // this session: the undo's record is the merger's newest for the key,
    // so nothing stands for `again`, and the stage's id names the undo's
    // record — a draft and a write of their own, never the board's memo of
    // the first landing — the record replacing the undo's; `again` then
    // answers that landing, nothing written.
    let undone = undo(&board, merger, &fresh, &kind, None).expect("the fresh landing undone");
    let replacing = undone.record.clone().expect("the landing's record stood, so one replaces it");
    assert_eq!(resume(&board, &again, fresh_landing()).expect("resumed"), None, "nothing stands for the key");
    let relanded = land(&board, &merged_fresh, fresh_landing()).expect("landed fresh again");
    let Landed::Draft { into: fresh_again, position: at_again, record: link_again, head_moved } = relanded.clone() else { panic!("{relanded:?}") };
    assert!(fresh_again != fresh && at_again > undone.position && head_moved.is_none(), "a draft and a write of its own: {relanded:?}");
    assert_eq!(image(&board, &token, &fresh_again, extent), as_image(&m), "the new draft holds M");
    let record = current(&board, Some(&token), &kind, &merged_fresh.key).expect("the lookup").expect("a current record");
    assert_eq!(
        (record.landed, record.replaces, record.link),
        (Some(RecordLanding::Draft { draft: fresh_again.clone(), position: at_again }), Some(replacing), Some(link_again))
    );
    let standing = position();
    assert_eq!(land(&board, &again, fresh_landing()).expect("the standing landing"), relanded);
    assert_eq!(position(), standing, "nothing staged, nothing written");
    session.close().expect("close");
}

/// The take-backs' rig: a claimed permissive board, the device key's signer
/// and the claimant's bare token. The daemon is dropped before its directory.
struct Rig {
    _sd: skepd::Skepd,
    _dir: tempfile::TempDir,
    board: Board,
    device: HybridSigner,
    bare: Token,
    /// The claim's two anchor files, under `a` and `b`.
    anchors: std::path::PathBuf,
}

impl Rig {
    fn new() -> Rig {
        let dir = tempfile::tempdir().expect("tempdir");
        let sd = spawn(&dir.path().join("board"), true);
        let board = board(sd.port());
        let store = skep_client::store::FileStore::open(dir.path().join("store"));
        let fp = keygen(&store, "notebook");
        let anchors = dir.path().join("anchors");
        claim(&board, &store, &anchors);
        let device = store.load(&store.key_path(&fp)).expect("the device key").signer();
        let bare = bare(&board, PRINCIPAL);
        Rig { _sd: sd, _dir: dir, board, device, bare, anchors }
    }

    /// A content session under the device key.
    fn session(&self) -> Session<'_> {
        handshake(&self.board, Scope::Content, &self.device, PRINCIPAL, Site::Session).expect("a content session")
    }

    /// The board's committed head.
    fn position(&self) -> u64 {
        self.board.health().unwrap().log_position()
    }

    fn metadata(&self, token: &Token, doc: &Address) -> Value {
        read(&self.board, Some(token), &frames::doc_metadata(&doc.to_string()))
    }

    /// A fresh document with its base version `D.1` "the cat sat" and its
    /// head `D.2` "the big cat sat".
    fn race(&self, session: &Session<'_>) -> (Address, Address, Address) {
        let d = published_document(&self.board, session, &self.device);
        let base = shot(&self.board, session, &self.device, &self.bare, &d, None, &[Staged::Fresh { text: "the cat sat" }]);
        let head = shot(
            &self.board,
            session,
            &self.device,
            &self.bare,
            &d,
            Some((&base, 11)),
            &[Staged::Own { from: 1, text: "the " }, Staged::Fresh { text: "big " }, Staged::Own { from: 5, text: "cat sat" }],
        );
        assert_eq!((base.to_string(), head.to_string()), (format!("{d}.1"), format!("{d}.2")));
        (d, base, head)
    }

    /// A draft staged from `from` with `text` typed at ordinal `at`.
    fn staged(&self, from: &Address, at: u64, text: &str) -> Address {
        let staged = acked(self.board.op(Some(&self.bare), &frames::stage(&from.to_string(), None)));
        let draft = addr(acked_addr(&staged).expect("the staged draft's address"));
        insert_text(&self.board, &self.bare, &draft.to_string(), at, text);
        draft
    }

    /// Every row of the feed under `doc` on the supplement, oldest first.
    fn rows_under(&self, token: &Token, doc: &Address) -> Vec<Value> {
        let under = doc.to_string();
        let (mut since, mut rows) = (0u64, Vec::new());
        loop {
            let query = ChangesQuery { since, under: Some(&under), drafts: true, limit: None };
            match self.board.changes(Some(token), &query).expect("the feed") {
                ChangesAnswer::Page(page) => {
                    rows.extend(page.changes);
                    if !page.more {
                        return rows;
                    }
                    since = page.last;
                }
                other => panic!("the feed answered {other:?}"),
            }
        }
    }
}

/// The merger's facts off a session, with the rig's device key as its hand.
fn merger<'s>(rig: &'s Rig, session: &'s Session<'_>) -> Merger<'s> {
    Merger { token: session.token(), account: session.account(), signer: &rig.device }
}

/// M's runs off a composition.
fn m_of(merged: &skep_client::merge::Merged) -> Vec<Run> {
    merged.composed.runs.iter().map(|p| p.run.clone()).collect()
}

/// THE UNDO ON THE REAL DAEMON (skep #783): the staged draft `S` off `D.1`
/// with "!!!" typed, merged with `D.2` and landed in one write. The premise
/// of the pre-landing read: `/op-at` at the landing's `at − 1` answers
/// `not_a_position` naming the position before the landing as `nearest`.
/// `undo` reads there and sends one `set_arrangement`: `S` holds C again,
/// its base is `D.1` at eleven, the marker is gone, the undo's feed row
/// names the base restored and no merge, and the replacing record —
/// `landed` none, `replaces` the landing's link — is current for the key.
/// A second undo has nothing to undo, the merge already taken back, and
/// writes nothing. The merge composed again and landed in the same session
/// is a write of its own, whose record replaces the undo's.
#[test]
fn a_landed_merge_is_undone_in_one_write_restoring_the_text_and_the_base_and_clearing_the_marker() {
    let rig = Rig::new();
    let session = rig.session();
    let token = session.token().clone();
    let (d, base, head) = rig.race(&session);
    let draft = rig.staged(&base, 12, "!!!");
    let c = image(&rig.board, &token, &draft, 14);
    assert_eq!(c, vec![(format!("{d}.0.1.1"), 11), (format!("{draft}.0.1.1"), 3)], "C: the base's text and the draft's own");
    let kind = addr(&mint(&rig.board, &rig.bare, ACCOUNT, false));
    let merger = merger(&rig, &session);
    let inputs = Inputs { doc: d.clone(), head: head.clone(), base: None, sides: vec![Side::Draft { at: draft.clone(), position: None }], options: Default::default(), kind: kind.clone() };
    let before = rig.position();
    let merged = compose(&rig.board, Some(&token), &inputs).expect("composed");
    let landed = land(&rig.board, &merged, Landing::Draft { merger, into: Some(draft.clone()), journal: None }).expect("landed");
    let Landed::Draft { position: at, record: link, .. } = landed else { panic!("{landed:?}") };
    let m = m_of(&merged);
    assert_eq!(image(&rig.board, &token, &draft, 18), as_image(&m), "the premise: the draft holds M");
    let meta = rig.metadata(&token, &draft);
    assert_eq!((meta["base"].as_str(), meta["merge"]["at"].as_u64()), (Some(head.to_string().as_str()), Some(at)), "the premise: the base on the head, the marker at the landing: {meta}");
    // THE PRE-LANDING READ's premise: `at − 1` lies inside the landing's
    // commit, and `nearest` is the position before it.
    let AtAnswer::NotAPosition { nearest } = rig.board.op_at(Some(&token), at - 1, &frames::doc_metadata(&draft.to_string())).expect("the read at a position") else {
        panic!("at − 1 answered a document or another refusal")
    };
    assert_eq!(nearest, Some(before), "nearest is the position before the landing");
    // THE UNDO: one write.
    let undone = undo(&rig.board, merger, &draft, &kind, None).expect("undone");
    assert_eq!(undone.draft, draft);
    assert_eq!(undone.restored, Some((base.clone(), 11)), "the base read before the landing, address and extent");
    assert!(undone.position > at, "{undone:?}");
    let replacing = undone.record.clone().expect("a record of the landing stood, so one replaces it");
    assert_ne!(replacing, link);
    assert_eq!(image(&rig.board, &token, &draft, 14), c, "C again");
    let meta = rig.metadata(&token, &draft);
    assert_eq!((meta["base"].as_str(), meta["base_copied"].as_str()), (Some(base.to_string().as_str()), Some("11")), "the base restored: {meta}");
    assert!(meta["merge"].is_null(), "the marker cleared: {meta}");
    let rows = rig.rows_under(&token, &draft);
    let row = rows.iter().rev().find(|r| r["op"] == "set_arrangement").expect("the undo's row");
    assert_eq!((row["at"].as_u64(), row["base"].as_str(), row["merge"].is_null()), (Some(undone.position), Some(base.to_string().as_str()), true), "the undo's row: the base restored, no merge: {row}");
    // The replacing record, current for the key.
    let record = current(&rig.board, Some(&token), &kind, &merged.key).expect("the lookup").expect("a current record");
    assert_eq!((record.landed.clone(), record.replaces.clone(), record.link.clone()), (None, Some(link.clone()), Some(replacing.clone())));
    // A re-run: nothing to undo, nothing written.
    let standing = rig.position();
    assert_eq!(undo(&rig.board, merger, &draft, &kind, None), Err(Refusal::NothingToUndo { draft: draft.clone(), why: NoUndo::TakenBack }));
    assert_eq!(rig.position(), standing, "nothing written");
    // Composed again — the undo restored the base, so the key is the first
    // landing's — and landed again in this session: a write of its own, the
    // draft holding M with the marker at the new position, and a record of
    // its own replacing the undo's, current for the key. A re-run of it is
    // answered by the board's ids, nothing written twice.
    let again = compose(&rig.board, Some(&token), &inputs).expect("composed again");
    assert_eq!(again.key, merged.key, "the premise: the first landing's key");
    let into = || Landing::Draft { merger, into: Some(draft.clone()), journal: None };
    let relanded = land(&rig.board, &again, into()).expect("landed again");
    let Landed::Draft { position: again_at, record: again_link, .. } = relanded.clone() else { panic!("{relanded:?}") };
    assert!(again_at > undone.position, "{relanded:?}");
    assert_eq!(image(&rig.board, &token, &draft, 18), as_image(&m), "the draft holds M again");
    let meta = rig.metadata(&token, &draft);
    assert_eq!(meta["merge"]["at"].as_u64(), Some(again_at), "the marker at the new landing: {meta}");
    assert!(again_link != link && again_link != replacing, "a record of its own: {again_link}");
    let record = current(&rig.board, Some(&token), &kind, &merged.key).expect("the lookup").expect("a current record");
    assert_eq!(
        (record.landed, record.replaces, record.link),
        (Some(RecordLanding::Draft { draft: draft.clone(), position: again_at }), Some(replacing), Some(again_link))
    );
    let standing = rig.position();
    assert_eq!(land(&rig.board, &again, into()), Ok(relanded), "the board answers the landing's ids again");
    assert_eq!(rig.position(), standing, "nothing written twice");
    session.close().expect("close");
}

/// THE WITHDRAWAL ON THE REAL DAEMON: a merge landed in the staged draft
/// `T` is taken out by one write — `T` still holds M, its base stays `D.2`
/// at fifteen, the marker is gone, the withdrawal's feed row names the base
/// re-sent and no merge — and the replacing record is current; a second
/// withdrawal finds no merge, an undo nothing to undo, and neither writes.
#[test]
fn a_landed_merge_is_withdrawn_keeping_the_words_and_clearing_the_marker() {
    let rig = Rig::new();
    let session = rig.session();
    let token = session.token().clone();
    let (d, base, head) = rig.race(&session);
    let draft = rig.staged(&base, 12, "???");
    let kind = addr(&mint(&rig.board, &rig.bare, ACCOUNT, false));
    let merger = merger(&rig, &session);
    let inputs = Inputs { doc: d.clone(), head: head.clone(), base: None, sides: vec![Side::Draft { at: draft.clone(), position: None }], options: Default::default(), kind: kind.clone() };
    let merged = compose(&rig.board, Some(&token), &inputs).expect("composed");
    let landed = land(&rig.board, &merged, Landing::Draft { merger, into: Some(draft.clone()), journal: None }).expect("landed");
    let Landed::Draft { position: at, record: link, .. } = landed else { panic!("{landed:?}") };
    let m = m_of(&merged);
    let withdrawn = withdraw(&rig.board, merger, &draft, &kind, None).expect("withdrawn");
    assert_eq!(withdrawn.draft, draft);
    assert!(withdrawn.position > at, "{withdrawn:?}");
    let replacing = withdrawn.record.clone().expect("a record of the landing stood, so one replaces it");
    assert_ne!(replacing, link);
    assert_eq!(image(&rig.board, &token, &draft, 18), as_image(&m), "the words stay: M");
    let meta = rig.metadata(&token, &draft);
    assert_eq!((meta["base"].as_str(), meta["base_copied"].as_str()), (Some(head.to_string().as_str()), Some("15")), "the base unchanged: {meta}");
    assert!(meta["merge"].is_null(), "the marker cleared: {meta}");
    let rows = rig.rows_under(&token, &draft);
    let row = rows.iter().rev().find(|r| r["op"] == "set_arrangement").expect("the withdrawal's row");
    assert_eq!((row["at"].as_u64(), row["base"].as_str(), row["merge"].is_null()), (Some(withdrawn.position), Some(head.to_string().as_str()), true), "{row}");
    let record = current(&rig.board, Some(&token), &kind, &merged.key).expect("the lookup").expect("a current record");
    assert_eq!((record.landed.clone(), record.replaces.clone(), record.link.clone()), (None, Some(link), Some(replacing)));
    let standing = rig.position();
    assert_eq!(withdraw(&rig.board, merger, &draft, &kind, None), Err(Refusal::NoMerge { draft: draft.clone() }));
    assert_eq!(undo(&rig.board, merger, &draft, &kind, None), Err(Refusal::NothingToUndo { draft: draft.clone(), why: NoUndo::TakenBack }));
    assert_eq!(rig.position(), standing, "nothing written");
    session.close().expect("close");
}

/// AN EDIT SINCE THE LANDING: "?" typed at the start of the landed draft,
/// then `undo` — typed against the landing's position — is refused
/// `arrangement_moved` by the board, the edit kept, the marker standing,
/// nothing written.
#[test]
fn an_undo_after_an_edit_since_the_landing_is_refused_with_the_edit_kept() {
    let rig = Rig::new();
    let session = rig.session();
    let token = session.token().clone();
    let (d, base, head) = rig.race(&session);
    let draft = rig.staged(&base, 12, "!!!");
    let kind = addr(&mint(&rig.board, &rig.bare, ACCOUNT, false));
    let merger = merger(&rig, &session);
    let inputs = Inputs { doc: d.clone(), head: head.clone(), base: None, sides: vec![Side::Draft { at: draft.clone(), position: None }], options: Default::default(), kind: kind.clone() };
    let merged = compose(&rig.board, Some(&token), &inputs).expect("composed");
    let landed = land(&rig.board, &merged, Landing::Draft { merger, into: Some(draft.clone()), journal: None }).expect("landed");
    let Landed::Draft { position: at, .. } = landed else { panic!("{landed:?}") };
    insert_text(&rig.board, &rig.bare, &draft.to_string(), 1, "?");
    let edited = image(&rig.board, &token, &draft, 19);
    assert_eq!(edited.len(), 5, "?the big cat sat!!!: {edited:?}");
    let standing = rig.position();
    let err = undo(&rig.board, merger, &draft, &kind, None).expect_err("the draft changed since the merge landed");
    let Refusal::Halt(Halt::Refused(refused)) = &err else { panic!("{err:?}") };
    assert_eq!(refused.code, "arrangement_moved", "{refused:?}");
    let detail = refused.detail.as_deref().expect("the person's words");
    assert!(detail.contains(&draft.to_string()) && detail.contains("changed since the merge landed") && detail.contains("nothing was changed"), "{detail}");
    assert!(detail.contains(&format!("position {at}")), "{detail}");
    assert_eq!(image(&rig.board, &token, &draft, 19), edited, "the edit kept");
    let meta = rig.metadata(&token, &draft);
    assert_eq!((meta["base"].as_str(), meta["merge"]["at"].as_u64()), (Some(head.to_string().as_str()), Some(at)), "the base and the marker as they stood: {meta}");
    assert_eq!(rig.position(), standing, "nothing written");
    session.close().expect("close");
}

/// A FREE-STANDING DRAFT (skep #775's note; N4; skep #784): a plain mint
/// holding "hello", merged into — the head `D.2` against the daughter
/// `D.1.1` — is admitted: the draft holds M, `doc_metadata`'s `base` and
/// `merge` are null, and the landing is one commit of two records, `at − 1`
/// inside it. Its feed row carries the request's merge beside a null base —
/// the one place the board keeps the landing's position — so the undo finds
/// the landing by it: one write typed against the row's `at`, C read before
/// the landing sent back with no base, no head and no merge. The draft reads
/// C again, nothing is recorded, the undo's row names neither term, and the
/// replacing record is current for the key. A re-run finds the landing's
/// row again: in the same session the board answers its ids again, the same
/// undo with nothing written twice; in a fresh session the board refuses it
/// `arrangement_moved`, the undo having moved the arrangement, nothing
/// written. Composed again in that fresh session and landed, the merge
/// writes a record of its own, replacing the undo's.
#[test]
fn a_landing_into_a_free_standing_draft_is_admitted_with_nothing_recorded_and_undone_by_its_row() {
    let rig = Rig::new();
    let session = rig.session();
    let token = session.token().clone();
    let (d, base, head) = rig.race(&session);
    let daughter = shot(&rig.board, &session, &rig.device, &rig.bare, &d, Some((&base, 11)), &[Staged::Own { from: 1, text: "the cat" }]);
    assert_eq!(daughter.to_string(), format!("{d}.1.1"), "a base the trunk has moved past yields the base's own DAUGHTER");
    let plain = addr(&mint(&rig.board, &rig.bare, ACCOUNT, false));
    insert_text(&rig.board, &rig.bare, &plain.to_string(), 1, "hello");
    let c = image(&rig.board, &token, &plain, 5);
    let meta = rig.metadata(&token, &plain);
    assert!(meta["base"].is_null() && meta["source"].is_null() && meta["merge"].is_null(), "the premise: free-standing, no base and no source: {meta}");
    let kind = addr(&mint(&rig.board, &rig.bare, ACCOUNT, false));
    let merger = merger(&rig, &session);
    let inputs = Inputs { doc: d.clone(), head: head.clone(), base: None, sides: vec![Side::Member(daughter.clone())], options: Default::default(), kind: kind.clone() };
    let before = rig.position();
    let merged = compose(&rig.board, Some(&token), &inputs).expect("composed");
    let m = m_of(&merged);
    assert_eq!(m, vec![rd(&d, 1, 4), rd(&d, 12, 4), rd(&d, 5, 3)], "the big cat");
    let landed = land(&rig.board, &merged, Landing::Draft { merger, into: Some(plain.clone()), journal: None }).expect("admitted");
    let Landed::Draft { into, position: at, head_moved, record: link, .. } = landed else { panic!("{landed:?}") };
    assert_eq!((into, head_moved), (plain.clone(), None));
    assert_eq!(image(&rig.board, &token, &plain, 11), as_image(&m), "the draft holds M");
    let meta = rig.metadata(&token, &plain);
    assert!(meta["base"].is_null() && meta["merge"].is_null(), "nothing recorded: {meta}");
    let AtAnswer::NotAPosition { nearest } = rig.board.op_at(Some(&token), at - 1, &frames::doc_metadata(&plain.to_string())).expect("the read at a position") else {
        panic!("at − 1 answered a document or another refusal")
    };
    assert_eq!(nearest, Some(before), "one commit of two records: at − 1 inside it, nearest the position before");
    // The landing's row: the request's merge beside no base.
    let rows = rig.rows_under(&token, &plain);
    let row = rows.iter().rev().find(|r| r["op"] == "set_arrangement").expect("the landing's row");
    assert_eq!(row["at"].as_u64(), Some(at));
    assert!(row["base"].is_null(), "no base named: {row}");
    assert_eq!(row["merge"], json!({"head": head.to_string(), "sides": [daughter.to_string()]}), "the request's merge beside no base: {row}");
    // THE UNDO, by the row: one write.
    let undone = undo(&rig.board, merger, &plain, &kind, None).expect("undone");
    assert_eq!(undone.draft, plain);
    assert_eq!(undone.restored, None, "no base to restore");
    assert!(undone.position > at, "{undone:?}");
    let replacing = undone.record.clone().expect("a record of the landing stood, so one replaces it");
    assert_ne!(replacing, link);
    assert_eq!(image(&rig.board, &token, &plain, 5), c, "C again");
    let meta = rig.metadata(&token, &plain);
    assert!(meta["base"].is_null() && meta["merge"].is_null(), "nothing recorded: {meta}");
    let rows = rig.rows_under(&token, &plain);
    let row = rows.iter().rev().find(|r| r["op"] == "set_arrangement").expect("the undo's row");
    assert_eq!((row["at"].as_u64(), row["base"].is_null(), row["merge"].is_null()), (Some(undone.position), true, true), "the undo's row names neither term: {row}");
    let record = current(&rig.board, Some(&token), &kind, &merged.key).expect("the lookup").expect("a current record");
    assert_eq!((record.landed.clone(), record.replaces.clone(), record.link.clone()), (None, Some(link.clone()), Some(replacing.clone())));
    // A re-run: the same undo in this session, nothing written twice.
    let standing = rig.position();
    assert_eq!(undo(&rig.board, merger, &plain, &kind, None), Ok(undone.clone()), "the board answers the undo's ids again");
    assert_eq!(rig.position(), standing, "nothing written twice");
    session.close().expect("close");
    // In a fresh session: refused, the arrangement moved at the undo.
    let fresh = rig.session();
    let again = Merger { token: fresh.token(), account: fresh.account(), signer: &rig.device };
    let err = undo(&rig.board, again, &plain, &kind, None).expect_err("the undo moved the arrangement");
    let Refusal::Halt(Halt::Refused(refused)) = &err else { panic!("{err:?}") };
    assert_eq!(refused.code, "arrangement_moved", "{refused:?}");
    assert_eq!(rig.position(), standing, "nothing written");
    assert_eq!(image(&rig.board, fresh.token(), &plain, 5), c, "C stands");
    // Composed again in the fresh session and landed in the draft: a landing
    // of its own, whose record replaces the undo's.
    let composed = compose(&rig.board, Some(fresh.token()), &inputs).expect("composed again");
    assert_eq!(composed.prior.as_ref().and_then(|p| p.link.clone()), Some(replacing.clone()), "the premise: the undo's record is the prior");
    let relanded = land(&rig.board, &composed, Landing::Draft { merger: again, into: Some(plain.clone()), journal: None }).expect("landed again");
    let Landed::Draft { position: again_at, record: again_link, .. } = relanded else { panic!("{relanded:?}") };
    assert!(again_link != link && again_link != replacing, "a record of its own: {again_link}");
    assert_eq!(image(&rig.board, fresh.token(), &plain, 11), as_image(&m), "the draft holds M again");
    let record = current(&rig.board, Some(fresh.token()), &kind, &merged.key).expect("the lookup").expect("a current record");
    assert_eq!(
        (record.landed, record.replaces, record.link),
        (Some(RecordLanding::Draft { draft: plain.clone(), position: again_at }), Some(replacing), Some(again_link))
    );
    fresh.close().expect("close");
}

/// A FORK WHOSE SOURCE IS NOT THE HEAD (skep #775's note; N4, P5). The
/// board refuses its owner a private `version` of a published member
/// (`private_version_of_published`), so the fork is another account's: the
/// forker, keyed at a sub-account delegated under the claimant's, takes a
/// private `version` of `D.1` and removes " sat"; then `D.2` is published.
/// The forker, as the merger that owns the fork, composes on `D.2` with the
/// fork as its side, and the landing into the fork is refused
/// `fork_base_moved` — the fork, its source `D.1` and the head named — the
/// fork's position and words as they were, nothing committed, no record.
#[test]
fn a_landing_into_a_fork_whose_source_is_not_the_head_is_refused_with_nothing_committed() {
    let rig = Rig::new();
    let session = rig.session();
    let token = session.token().clone();
    let d = published_document(&rig.board, &session, &rig.device);
    let base = shot(&rig.board, &session, &rig.device, &rig.bare, &d, None, &[Staged::Fresh { text: "the cat sat" }]);
    // The owner's own private version of a published member is refused.
    let Answer::Document(refused) = rig.board.op(Some(&rig.bare), &json!({"op": "version", "d_src": base.to_string(), "published": false})).expect("the exchange") else { panic!("closed") };
    assert_eq!(refused["code"].as_str(), Some("private_version_of_published"), "the premise: {refused}");
    // The forker, keyed at a sub-account, and its private fork of D.1.
    let forker_key = signer_from_seed(&[7; 32]);
    assert_eq!(keyed_sub_account(&rig.board, &rig.anchors, &rig.device, 2, FORKER, &forker_key, "forker"), FORKER_ACCOUNT);
    let forker_bare = bare(&rig.board, FORKER);
    assert_eq!(mint(&rig.board, &forker_bare, FORKER_ACCOUNT, false), format!("{FORKER_ACCOUNT}.0.1"), "the forker's home first");
    let forked = acked(rig.board.op(Some(&forker_bare), &json!({"op": "version", "d_src": base.to_string(), "published": false})));
    let fork = addr(acked_addr(&forked).expect("the fork"));
    let forked_at = acked_at(&forked).expect("the fork's position");
    acked(rig.board.op(Some(&forker_bare), &frames::delete(&fork.to_string(), 8, 4, forked_at, None)));
    let meta = rig.metadata(&token, &fork);
    assert_eq!((meta["source"].as_str(), meta["base"].is_null(), meta["published"].as_bool()), (Some(base.to_string().as_str()), true, Some(false)), "the premise: a fork of D.1, no base: {meta}");
    // The head, published after the fork.
    let head = shot(
        &rig.board,
        &session,
        &rig.device,
        &rig.bare,
        &d,
        Some((&base, 11)),
        &[Staged::Own { from: 1, text: "the " }, Staged::Fresh { text: "big " }, Staged::Own { from: 5, text: "cat sat" }],
    );
    assert_eq!(head.to_string(), format!("{d}.2"));
    session.close().expect("close");
    // The forker composes on D.2 with its fork as the side, and lands into
    // the fork it owns.
    let kind = addr(&mint(&rig.board, &forker_bare, FORKER_ACCOUNT, false));
    let forker = handshake(&rig.board, Scope::Content, &forker_key, FORKER, Site::Session).expect("the forker's content session");
    let merger = Merger { token: forker.token(), account: forker.account(), signer: &forker_key };
    assert_eq!(forker.account(), FORKER_ACCOUNT, "the merger is the fork's owner");
    let inputs = Inputs { doc: d.clone(), head: head.clone(), base: None, sides: vec![Side::Fork(fork.clone())], options: Default::default(), kind: kind.clone() };
    let merged = compose(&rig.board, Some(forker.token()), &inputs).expect("composed");
    assert_eq!(m_of(&merged), vec![rd(&d, 1, 4), rd(&d, 12, 4), rd(&d, 5, 3)], "the big cat");
    assert_eq!(merged.key.base, base, "the fork's served source is the base");
    let words = image(&rig.board, forker.token(), &fork, 7);
    let standing = rig.position();
    assert_eq!(
        land(&rig.board, &merged, Landing::Draft { merger, into: Some(fork.clone()), journal: None }),
        Err(Refusal::ForkBaseMoved { fork: fork.clone(), source: base.clone(), head: head.clone() })
    );
    assert_eq!(rig.position(), standing, "nothing committed");
    assert_eq!(image(&rig.board, forker.token(), &fork, 7), words, "the fork's words as they were");
    let meta = rig.metadata(forker.token(), &fork);
    assert!(meta["base"].is_null() && meta["merge"].is_null(), "nothing recorded: {meta}");
    assert_eq!(read(&rig.board, Some(forker.token()), &frames::find_links_ftt(&kind.to_string(), &fork.to_string()))["addrs"], json!([]), "no record");
    forker.close().expect("close");
}

/// A MERGE OF MANY DAUGHTERS ON THE REAL DAEMON (skep #792): the head and
/// twenty daughters off the base version, each removing " sat", spell a
/// record key whose text alone passes the 256-byte id cap the daemon holds
/// at parse, yet the merge lands as the trunk's next member under ids the
/// daemon admits — its record current for the key with every side, its
/// testimony verifying Equal — and a second landing in the session is
/// answered by the board's ids, nothing written twice.
#[test]
fn a_merge_of_many_daughters_lands_on_the_trunk_with_its_record() {
    let rig = Rig::new();
    let session = rig.session();
    let token = session.token().clone();
    let (d, base, head) = rig.race(&session);
    let daughters: Vec<Address> = (1..=20)
        .map(|k| {
            let daughter = shot(&rig.board, &session, &rig.device, &rig.bare, &d, Some((&base, 11)), &[Staged::Own { from: 1, text: "the cat" }]);
            assert_eq!(daughter.to_string(), format!("{d}.1.{k}"), "a base the trunk has moved past yields its own daughter");
            daughter
        })
        .collect();
    let kind = addr(&mint(&rig.board, &rig.bare, ACCOUNT, false));
    let inputs = Inputs {
        doc: d.clone(),
        head: head.clone(),
        base: None,
        sides: daughters.iter().cloned().map(Side::Member).collect(),
        options: Default::default(),
        kind: kind.clone(),
    };
    let merged = compose(&rig.board, Some(&token), &inputs).expect("composed");
    assert!(merged.key.text().len() > 256, "the premise: the key's text alone passes the cap, {} bytes", merged.key.text().len());
    assert_eq!(m_of(&merged), vec![rd(&d, 1, 4), rd(&d, 12, 4), rd(&d, 5, 3)], "the big cat");
    let merger = merger(&rig, &session);
    let shot_landing = || Landing::Shot { merger, draft: None, journal: None };
    let landed = land(&rig.board, &merged, shot_landing()).expect("landed");
    let Landed::Member { address: member, position, record: link, .. } = landed.clone() else { panic!("{landed:?}") };
    assert_eq!(member.to_string(), format!("{d}.3"), "the merge is the trunk's next member");
    assert_eq!(image(&rig.board, &token, &member, 11), as_image(&m_of(&merged)), "the member holds M");
    let record = current(&rig.board, Some(&token), &kind, &merged.key).expect("the lookup").expect("a current record");
    assert_eq!((record.landed.clone(), record.link.clone()), (Some(RecordLanding::Member { member: member.clone(), position }), Some(link)));
    assert_eq!(record.sides.len(), 21, "the head and every daughter");
    assert_eq!(verify(&rig.board, Some(&token), &record).expect("verified"), Verdict::Equal);
    let standing = rig.position();
    assert_eq!(land(&rig.board, &merged, shot_landing()), Ok(landed), "the board answers the landing's ids again");
    assert_eq!(rig.position(), standing, "nothing written twice");
    session.close().expect("close");
}
