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
//! no claim over version members (the landing's doc).

use serde_json::{json, Value};
use skep_address::Address;
use skep_client::address::{document_of, parse_address};
use skep_client::board::{acked_addr, frames, Answer, Board, Scope, Token};
use skep_client::ceremony::handshake::{handshake, Session, Site};
use skep_client::merge::{
    compose, current, head_of, land, verify, Inputs, Landed, Landing, Merger, RecordLanding, Run,
    RunCounts, Side, Verdict,
};
use skep_client::sign::{sig_hex, Signer};
use skep_identity::{
    entry_body_empty, entry_body_publish, entry_frame, ContentFreeOp, DocTerm, EntryBody, ShotBase,
    ShotSegmentPiece,
};
use skep_signature::HybridSigner;

use crate::common::{bare, board, claim, insert_text, keygen, mint, spawn};

/// The claimant's account and principal on a notebook.
const ACCOUNT: &str = "1.0.1";
const PRINCIPAL: u64 = 1;

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
    let mut frame = frames::publish(
        &doc.to_string(),
        base_text.as_ref().map(|(m, e)| (m.as_str(), *e)),
        draft_text.as_deref(),
        &runs,
        None,
        None,
    );
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
