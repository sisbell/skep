//! The merge family (`client.md` §4b.1's merge row; THE MERGE BRIDGE LANE).
//!
//! The suite checks the rules the shell alone keeps, with no daemon behind
//! it — the rows' own members read before the session, `land` and `undo`
//! with nothing composed `no_merge`, a bare session refused, the library's
//! typed session's end alone ending the session, and the compose's head
//! read refused `shape` once its doubling is spent at a board on which
//! every trunk member answers, the composition handed the newest member at
//! one whose trunk ends — and, against
//! the real daemon, the family end to end: a daughter composed and landed
//! into a fresh draft staged from the head and into a named one, each by
//! one write; the undo and the withdrawal each one write, the undo typed at
//! the editor's own last arrangement write on the draft — landing once the
//! person's later edits are taken back, refused `arrangement_moved` past
//! another hand's write and never typed at a link's ack, nothing wiped; the
//! landing, the undo and the withdrawal refused `held_lines` over the
//! draft's held lines, a burst held behind them, and the undo going out once
//! the run is dropped; the rows refused `stopped` and `poisoned` under those
//! holds with nothing dialed; the
//! re-open landing nothing, reading the side at the marker's position and
//! settling a gap the draft no longer arranges; `resolutions` refused where
//! they name no gap or no choice the gap admits, nothing landed; the
//! landing on the trunk through the publication family's shot with the
//! claim, then the record; the draft side composed and landed with no
//! claim, its re-open reading the side as merged; the merged arm naming the
//! member and writing a missing record once; another account's record of
//! the kind, read as the composition's `prior`, never deciding where the
//! merge lands — its own draft carrying the merge never re-opened, a draft
//! of the person's it names never landed into — and the merged arm writing
//! the person's own record where only another account's names the member;
//! the `head_moved` race typed, nothing re-sent; the composition dying
//! with its session; a merge landed in a panel's draft since its open
//! re-stated at the confirm with the claim composed off the marker, landing
//! at the next; and a landing over a panel read under another marker (skep
//! #949): a panel opened before the compose landing the merge in the one
//! call with its claim — the draft untouched, its words deleted, its base
//! moved by the compose — the draft side named `also`, a selection the page
//! passed held and re-stated, a moved base among what it states, a panel
//! opened after the compose keeping its selection, a re-open and a second
//! compose read under the marker the draft carries, links the merge brought
//! onto a switched-on row re-stated with no run index beside them, and the
//! window the merge brought asked, no earlier answer carried onto it; and a
//! landing over a panel of the draft that mints an edition or publishes
//! into another document, standing or held, refused `other_panel`
//! (skep #956) with nothing sent and every panel as it stood, landing once
//! that panel is cancelled, and refused `base_unrecorded` once the draft
//! was published as a document of its own.

use std::io::{Read, Write};

use skep_client::address::{account_of, document_of, parse_address};
use skep_client::board::{frames, Opened, SessionBody};
use skep_client::halt::Halt;
use skep_client::merge::{Inputs, Merged, RecordLanding, Refusal as Library, Side};
use skep_client::store::{FileStore, KeyId, KeyStore};

use super::publication::{ground, register, second_device, signed_facts, Ground};
use super::*;
use crate::sessions::Facts;

/// The ground every daemon cell stands on: E published as E.1 ("the fox")
/// from D, D on to E.2 ("the fox jumps"), and S — staged from E.1 and so
/// behind — published as the daughter E.1.1 ("the fox today"): the merge
/// of E.2 with E.1.1 over base E.1 has both sides adding at one spot, an
/// `order` gap.
pub(super) struct Family {
    pub(super) edition: String,
    pub(super) e1: String,
    pub(super) e2: String,
    pub(super) e11: String,
}

pub(super) fn family(g: &Ground) -> Family {
    let edition = g.addr(json!({"op": "create_new_document", "account": "1.0.1", "published": true}));
    let open = |draft: &str| g.call("publication.open", json!({"session": g.session, "draft": draft, "doc": edition, "readable_drafts": [draft], "published": [edition]})).unwrap_or_else(|r| panic!("{r}"));
    let confirm = || g.call("publication.confirm", json!({"session": g.session})).unwrap_or_else(|r| panic!("{r}"));
    let d = g.staged(&edition, "the fox");
    open(&d);
    let e1 = format!("{edition}.1");
    let first = confirm();
    assert_eq!(first["member"].as_str(), Some(e1.as_str()), "{first}");
    let s = g.addr(skep_client::board::frames::stage(&e1, None));
    g.op(json!({"op": "insert", "doc": s, "at": {"subspace": "1", "ordinal": "8"}, "values": [" today"], "as_of": g.position()}));
    g.op(json!({"op": "insert", "doc": d, "at": {"subspace": "1", "ordinal": "8"}, "values": [" jumps"], "as_of": g.position()}));
    open(&d);
    let e2 = format!("{edition}.2");
    let second = confirm();
    assert_eq!(second["member"].as_str(), Some(e2.as_str()), "{second}");
    open(&s);
    let e11 = format!("{e1}.1");
    let daughter = confirm();
    assert_eq!(daughter["member"].as_str(), Some(e11.as_str()), "the daughter under E.1: {daughter}");
    Family { edition, e1, e2, e11 }
}

/// Holds a report to its declaration, every member of it.
fn assert_report_declared(report: &Value) {
    crate::shapes::assert_declared("MergeReport", report);
    for side in report["sides"].as_array().unwrap() {
        crate::shapes::assert_declared("MergeSide", side);
    }
    for run in report["runs"].as_array().unwrap() {
        crate::shapes::assert_declared("MergeRun", run);
    }
    for gap in report["gaps"].as_array().unwrap() {
        crate::shapes::assert_declared("MergeGap", gap);
        for run in gap["runs"].as_array().unwrap() {
            crate::shapes::assert_declared("GapRun", run);
        }
    }
    crate::shapes::assert_declared("RunCounts", &report["counts"]);
}

/// The `set_arrangement` rows under `doc` since `since`, each as
/// `(base present, merge present)`.
pub(super) fn arrangement_rows(g: &Ground, doc: &str, since: u64) -> Vec<(bool, bool)> {
    let entry = g.shell.sessions.get(&g.session).unwrap();
    changes_under(&entry.board, &entry.token, doc, since).iter().filter(|r| r["op"] == "set_arrangement").map(|r| (r["base"].is_string(), r["merge"].is_object())).collect()
}

/// The kind this shell names for the claimant's merge records: its doc 1.
const KIND: &str = "1.0.1.0.1";

/// Another account: a sub-account of the claimant's, its home minted.
///
/// Each of the two reads the other's drafts, the subtree running both ways
/// (wire.md §The read predicate; PUB-1.32), and owns none of them; its bare
/// session writes into no published document.
struct Other {
    account: String,
    token: Token,
}

/// Returns a bare session of `principal`'s at the ground's permissive board.
fn bare(g: &Ground, principal: u64) -> Token {
    let entry = g.shell.sessions.get(&g.session).unwrap();
    match entry.board.session_open(SessionBody::Bare { principal }).unwrap() {
        Opened::Token(token) => token,
        other => panic!("a bare session as principal {principal}: {other:?}"),
    }
}

/// Returns the answer to `frame` sent under `token`, acknowledged.
fn written(g: &Ground, token: &Token, frame: &Value) -> Value {
    let entry = g.shell.sessions.get(&g.session).unwrap();
    let Answer::Document(v) = entry.board.op(Some(token), frame).unwrap() else { panic!("the session stands") };
    assert!(v["resp"].as_str().is_some_and(|r| r.starts_with("ack")), "{frame}: {v}");
    v
}

/// Returns another account, delegated under the claimant's.
///
/// Its prefix is the next under `1.0.1`, delegated to a free principal from
/// the claimant's bare session, and its home is minted from its own.
fn other_account(g: &Ground) -> Other {
    let entry = g.shell.sessions.get(&g.session).unwrap();
    let account = entry.board.next_account_prefix("1.0.1").unwrap().expect("a prefix under the claimant's");
    let mut principal = 2;
    while entry.board.principal_prefix(principal).unwrap().is_some() {
        principal += 1;
    }
    written(g, &bare(g, 1), &frames::delegate(&account, principal, None));
    let token = bare(g, principal);
    written(g, &token, &frames::create_home(&account, None));
    Other { account, token }
}

/// Returns the merge of E.2 with E.1.1 as the library composes it.
///
/// It is composed under [`KIND`], read under the ground's session.
fn composed(g: &Ground, f: &Family) -> Merged {
    let entry = g.shell.sessions.get(&g.session).unwrap();
    let a = |s: &str| parse_address(s).unwrap();
    let inputs = Inputs { doc: a(&f.edition), head: a(&f.e2), base: None, sides: vec![Side::Member(a(&f.e11))], options: skep_client::merge::Options::default(), kind: a(KIND) };
    skep_client::merge::compose(&entry.board, Some(&entry.token), &inputs).unwrap_or_else(|r| panic!("{r:?}"))
}

/// Lands `merged` in `draft` under `token` by hand, writing no record.
///
/// It is the draft landing's one write as the library sends it: M as the
/// draft's whole arrangement, the head's pair as its base and the merge of
/// `side` marked beside it. Answers the write's position.
fn mark(g: &Ground, token: &Token, draft: &str, merged: &Merged, side: &str) -> u64 {
    let runs: Vec<Value> = merged.composed.runs.iter().map(|p| frames::shot_run(&p.run.origin.to_string(), &p.run.address_at(0).unwrap().to_string(), p.run.width)).collect();
    let head = merged.inputs.head.to_string();
    let pair = (head.as_str(), merged.head_extent);
    written(g, token, &frames::set_arrangement(draft, &runs, g.position(), Some(pair), Some(pair), Some(&[side]), None))["at"].as_u64().unwrap()
}

/// Writes `other`'s record of [`KIND`], answering its link's address.
///
/// It is the record `merged` describes, landed as `landed`. Its atom is
/// appended to a private journal of theirs and its link homed there beside
/// it, from the atom to the landed address and `side`, as the library's
/// record writer homes it.
fn record_of_the_kind(g: &Ground, other: &Other, merged: &Merged, landed: RecordLanding, side: &str) -> String {
    let minted = written(g, &other.token, &frames::create_document(&other.account, false, None));
    let journal = minted["addr"].as_str().unwrap().to_string();
    let target = match &landed {
        RecordLanding::Member { member, .. } => member.to_string(),
        RecordLanding::Draft { draft, .. } => draft.to_string(),
    };
    let mut record = merged.record.clone();
    record.landed = Some(landed);
    let appended = written(g, &other.token, &frames::insert_plain_atom(&journal, 1, &record.to_value().to_string(), minted["at"].as_u64().unwrap(), None));
    let atom = appended["addr"].as_str().unwrap().to_string();
    written(g, &other.token, &frames::make_link(&journal, &[&atom], &[&target, side], KIND, None))["addr"].as_str().unwrap().to_string()
}

/// Asserts that the merge of E.2 with E.1.1 reads `link` as its `prior`.
///
/// The library's currency takes another account's record where the
/// claimant's account holds none.
fn assert_prior_is(g: &Ground, f: &Family, link: &str) {
    let prior = composed(g, f).prior.and_then(|p| p.link).map(|l| l.to_string());
    assert_eq!(prior.as_deref(), Some(link), "the premise: the other account's record is the composition's prior");
}

/// Checks the rows' own members and the family's answers with nothing
/// composed, with no daemon behind the shell.
///
/// `merge.compose` reads its members before the session — `doc` missing or
/// no bare document, `alternative` no daughter of `doc`'s chain, both forms
/// or neither, `into` the draft side itself — each `malformed_args` naming
/// the member; in their form the call goes on to the session, which is
/// gone. `merge.withdraw` reads `draft` first. `land` and `undo` with
/// nothing composed answer `no_merge` naming the session, and a bare
/// session is refused `write_in_bare_session` naming the call at each row
/// (the mutants that look the session up first, or read a member as
/// absent, answer `session_ended` or dial).
#[test]
fn the_rows_read_their_members_first_and_answer_no_merge_with_nothing_composed() {
    let dir = TempDir::new().unwrap();
    let (shell, _) = open_shell(&super::door::nowhere(), &dir.path().join("store"), SessionMode::Bare { principal: 1 });
    let signed = register(&shell, "8e", signed_facts(2));
    let bare = register(&shell, "9f", Facts { principal: 1, account: Some("1.0.1".into()), kind: SessionKind::Bare });
    let what = |args: Value| {
        let refused = shell.call("merge.compose", &args).unwrap_err();
        let v = refused.to_value();
        assert_eq!(refused.name(), "malformed_args", "{args}: {v}");
        v["what"].as_str().unwrap().to_string()
    };
    assert_eq!(what(json!({"session": "s-gone", "alternative": "1.0.2.0.1.1.1"})), "doc", "missing");
    assert_eq!(what(json!({"session": "s-gone", "doc": "1.0.2.0.1.1", "alternative": "1.0.2.0.1.1.1"})), "doc", "a member, no bare document");
    assert_eq!(what(json!({"session": "s-gone", "doc": "1.0.2.0.1", "alternative": "1.0.2.0.1.1"})), "alternative", "a trunk member is no daughter");
    assert_eq!(what(json!({"session": "s-gone", "doc": "1.0.2.0.1", "alternative": "1.0.3.0.1.1.1"})), "alternative", "another document's daughter");
    assert_eq!(what(json!({"session": "s-gone", "doc": "1.0.2.0.1", "alternative": "1.0.2.0.1.1.1", "draft": "1.0.2.0.4"})), "draft", "both forms");
    assert_eq!(what(json!({"session": "s-gone", "doc": "1.0.2.0.1"})), "alternative or draft", "neither form");
    assert_eq!(what(json!({"session": "s-gone", "doc": "1.0.2.0.1", "draft": "1.0.2.0.4", "into": "1.0.2.0.4"})), "into", "the draft side itself");
    assert_eq!(what(json!({"session": "s-gone", "doc": "1.0.2.0.1", "alternative": "1.0.2.0.1.1.1", "into": 7})), "into", "another form");
    for in_form in [json!({"session": "s-gone", "doc": "1.0.2.0.1", "alternative": "1.0.2.0.1.1.1"}), json!({"session": "s-gone", "doc": "1.0.2.0.1", "draft": "1.0.2.0.4", "into": "1.0.2.0.5"})] {
        assert_eq!(shell.call("merge.compose", &in_form).unwrap_err().name(), "session_ended", "{in_form}: in its form, the members pass to the session");
    }
    let refused = shell.call("merge.withdraw", &json!({"session": "s-gone"})).unwrap_err().to_value();
    assert_eq!((refused["name"].as_str(), refused["what"].as_str()), (Some("malformed_args"), Some("draft")));
    for call in ["merge.land", "merge.undo"] {
        let refused = shell.call(call, &json!({"session": signed})).unwrap_err();
        let v = refused.to_value();
        assert_eq!((refused.name(), v["session"].as_str()), ("no_merge", Some(signed.as_str())), "{call}: {v}");
        assert_eq!(shell.call(call, &json!({"session": bare})).unwrap_err().name(), "no_merge", "{call}: nothing composed is answered before the hand is asked");
    }
    let keyless = shell.call("merge.compose", &json!({"session": bare, "doc": "1.0.1.0.1", "alternative": "1.0.1.0.1.1.1"})).unwrap_err();
    assert_eq!((keyless.name(), keyless.to_value()["call"].as_str()), ("write_in_bare_session", Some("merge.compose")), "{keyless}");
    let keyless = shell.call("merge.withdraw", &json!({"session": bare, "draft": "1.0.1.0.4"})).unwrap_err();
    assert_eq!((keyless.name(), keyless.to_value()["call"].as_str()), ("write_in_bare_session", Some("merge.withdraw")), "{keyless}");
}

/// Checks that only the library's typed session's end ends the session,
/// with no daemon behind the shell.
///
/// The library's `SessionEnded` ends the session it met — `session_died`
/// naming it, and a later call on the reference answered the end — and
/// every halt crosses as itself: the board's fault a token-free read meets
/// at the death signal, its words naming the signal, is `halt`, the session
/// standing, so a later `merge.land` on it answers `no_merge` (the mutant
/// that reads the face's words ends a live session on the board's fault;
/// the one that crosses the typed end as a halt keeps a dead session's
/// reference standing).
#[test]
fn only_the_librarys_typed_session_end_ends_the_session() {
    let dir = TempDir::new().unwrap();
    let (shell, _) = open_shell(&super::door::nowhere(), &dir.path().join("store"), SessionMode::Bare { principal: 1 });
    let standing = register(&shell, "8e", signed_facts(2));
    let ending = register(&shell, "7d", signed_facts(3));
    let board_fault = Halt::face(
        "a token-free read met the death signal",
        "the board answered `Skepd-Session: closed` to a request that presented no token",
        "this is a fault in the board or the transport, not in your keys; nothing was written",
    );
    let crossed = shell.merge_refusal(&shell.sessions.get(&standing).unwrap(), Library::Halt(board_fault));
    assert_eq!(crossed.name(), "halt", "{}", crossed.to_value());
    assert_eq!(shell.call("merge.land", &json!({"session": standing})).unwrap_err().name(), "no_merge", "the session stands");
    let end = Halt::face(
        "the session ended while reading",
        "the board answered `Skepd-Session: closed` (wire.md §Sessions)",
        "open a session again and run this again: it reads what stands before it writes",
    );
    let died = shell.merge_refusal(&shell.sessions.get(&ending).unwrap(), Library::SessionEnded(end));
    let v = died.to_value();
    assert_eq!((died.name(), v["session"].as_str()), ("session_died", Some(ending.as_str())), "{v}");
    assert_eq!(shell.call("merge.land", &json!({"session": ending})).unwrap_err().name(), "session_died", "a later call on the reference is answered the end");
    shell.shutdown();
}

/// Checks that a published journal crosses as typed data naming it.
///
/// The library's `PublishedJournal` is `merge_refused` with the arm
/// `published_journal` and the journal's address beside it, so a page words
/// it from data, and the session stands.
#[test]
fn a_published_journal_crosses_as_typed_data_naming_it() {
    let dir = TempDir::new().unwrap();
    let (shell, _) = open_shell(&super::door::nowhere(), &dir.path().join("store"), SessionMode::Bare { principal: 1 });
    let standing = register(&shell, "8e", signed_facts(2));
    let journal = skep_client::address::parse_address("1.0.1.0.1").expect("an address");
    let crossed = shell.merge_refusal(&shell.sessions.get(&standing).unwrap(), Library::PublishedJournal { journal });
    let v = crossed.to_value();
    assert_eq!((crossed.name(), v["arm"].as_str(), v["journal"].as_str()), ("merge_refused", Some("published_journal"), Some("1.0.1.0.1")), "{v}");
    assert_eq!(shell.call("merge.land", &json!({"session": standing})).unwrap_err().name(), "no_merge", "the session stands");
    shell.shutdown();
}

/// Checks that the twin fence met again past the shot's one re-read crosses
/// as typed data naming the draft and the member.
///
/// The library's `AlreadyPublished` is `merge_refused` with the arm
/// `already_published`, so a page words it from data, and the session stands.
#[test]
fn already_published_crosses_as_typed_data_naming_the_draft_and_the_member() {
    let dir = TempDir::new().unwrap();
    let (shell, _) = open_shell(&super::door::nowhere(), &dir.path().join("store"), SessionMode::Bare { principal: 1 });
    let standing = register(&shell, "8e", signed_facts(2));
    let parse = |text: &str| skep_client::address::parse_address(text).expect("an address");
    let crossed = shell.merge_refusal(&shell.sessions.get(&standing).unwrap(), Library::AlreadyPublished { draft: parse("1.0.1.0.2"), member: parse("1.0.1.0.3.1") });
    let v = crossed.to_value();
    assert_eq!((crossed.name(), v["arm"].as_str(), v["draft"].as_str(), v["member"].as_str()), ("merge_refused", Some("already_published"), Some("1.0.1.0.2"), Some("1.0.1.0.3.1")), "{v}");
    assert_eq!(shell.call("merge.land", &json!({"session": standing})).unwrap_err().name(), "no_merge", "the session stands");
    shell.shutdown();
}

/// Returns a board whose trunk `doc` holds `members`, and the frames sent it.
///
/// Every member answers where `members` is none. Its `/health` is a board
/// that takes writes and its `in_claims` names no claim; its `doc_metadata`
/// of `doc` and of each member the trunk holds is a published document's, of
/// any other address `doc_not_registered`; its `retrieve_doc_v_span_set` at
/// a position is `withheld`, so a composition stops at its read of the head
/// it was handed, naming it. Every other `/op` is an empty delivery (no
/// `H.1`, so no index opens) and every other path is answered nothing. Past
/// its 64th read of a trunk member it answers nothing either, so a head read
/// that walks on past the bound ends `unreachable` and never holds the
/// suite. It keeps the frame of each `/op` and `/op-at` in the order sent.
fn trunk_board(doc: &str, members: Option<u64>) -> (String, Arc<Mutex<Vec<Value>>>) {
    let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let origin = format!("http://127.0.0.1:{}", listener.local_addr().unwrap().port());
    let frames = Arc::new(Mutex::new(Vec::new()));
    let kept = Arc::clone(&frames);
    let doc = doc.to_string();
    thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            let (kept, doc) = (Arc::clone(&kept), doc.clone());
            thread::spawn(move || answer_as_a_trunk(stream, &doc, members, &kept));
        }
    });
    (origin, frames)
}

/// Returns the version of the trunk member a `doc_metadata` frame reads.
///
/// The trunk is `doc`'s; `None` for another frame, and for `doc` itself, a
/// daughter or another document.
fn trunk_member_read(doc: &str, frame: &Value) -> Option<u64> {
    if frame["op"] != "doc_metadata" {
        return None;
    }
    frame["doc"].as_str()?.strip_prefix(doc)?.strip_prefix('.')?.parse().ok()
}

/// Answers one request off `stream` as `trunk_board`'s board.
///
/// The request is its head through the blank line, its body as long as its
/// `Content-Length` says.
fn answer_as_a_trunk(mut stream: std::net::TcpStream, doc: &str, members: Option<u64>, frames: &Mutex<Vec<Value>>) {
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        match stream.read(&mut byte) {
            Ok(1) => head.push(byte[0]),
            _ => return,
        }
    }
    let head = String::from_utf8_lossy(&head).into_owned();
    let declared = head.lines().filter_map(|line| line.split_once(':')).find(|(name, _)| name.eq_ignore_ascii_case("content-length")).and_then(|(_, n)| n.trim().parse().ok()).unwrap_or(0);
    let mut body = vec![0u8; declared];
    if stream.read_exact(&mut body).is_err() {
        return;
    }
    let path = head.split_whitespace().nth(1).unwrap_or("");
    let answer = match path {
        "/health" => json!({"ok": true, "log_position": 10, "auth": {"claimant": null, "local_trust": true, "origins": [], "signed_origins": []}, "writes": {"halted": false}}),
        "/op" | "/op-at" => {
            let sent: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
            let frame = if path == "/op-at" { sent["frame"].clone() } else { sent };
            let member = trunk_member_read(doc, &frame);
            let trunk_reads = {
                let mut kept = frames.lock().unwrap();
                kept.push(frame.clone());
                kept.iter().filter(|f| trunk_member_read(doc, f).is_some()).count()
            };
            let registered = frame["doc"] == doc || member.is_some_and(|k| members.is_none_or(|n| k <= n));
            match frame["op"].as_str() {
                _ if member.is_some() && trunk_reads > 64 => return,
                Some("doc_metadata") if registered => json!({"resp": "doc_metadata", "as_of": 10, "published": true, "owner": "1.0.2"}),
                Some("doc_metadata") => json!({"resp": "rejected", "code": "doc_not_registered", "op": "doc_metadata"}),
                Some("in_claims") => json!({"resp": "claims", "as_of": 10, "claims": []}),
                Some("retrieve_doc_v_span_set") if path == "/op-at" => json!({"resp": "rejected", "code": "withheld", "op": "retrieve_doc_v_span_set"}),
                _ => json!({"resp": "delivery", "as_of": 10, "items": []}),
            }
        }
        _ => return,
    };
    let body = answer.to_string();
    let _ = write!(stream, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len());
}

/// Checks that the compose's head read is bounded and finds the newest member.
///
/// No daemon stands behind the shell (SP-17; skep #957). At a board on which
/// every member of the trunk answers, `merge.compose` of a daughter under
/// `⟨doc⟩.1` reads the members `⟨doc⟩.(1 + 2^i)`, `i` from 0 to 63, once
/// each and in that order, and is refused `shape` naming `doc_metadata`:
/// nothing composed, staged or set (the mutant that reads one member after
/// another walks on past the 64th read, which the board answers nothing, and
/// is refused `unreachable`). At a trunk ending five versions past
/// `⟨doc⟩.1`, and at one ending at it, the composition is handed the newest
/// member: its read of the head, which the board withholds, names `⟨doc⟩.6`
/// and `⟨doc⟩.1` (the mutant that composes on the side's own member where
/// the trunk has moved past it, and the one that composes on the member
/// after the head).
#[test]
fn the_head_read_is_refused_past_its_doubling_and_hands_the_composition_the_newest_member() {
    let doc = "1.0.2.0.2";
    let compose = |members: Option<u64>| -> (Refusal, Vec<Value>) {
        let dir = TempDir::new().unwrap();
        let (origin, frames) = trunk_board(doc, members);
        let store = dir.path().join("store");
        let (shell, _) = open_shell(&origin, &store, SessionMode::Bare { principal: 1 });
        // A key in the store, so the hand is admitted and the head is read.
        let KeyId(fingerprint) = FileStore::open(&store).generate(None).unwrap();
        let session = register(&shell, "8e", Facts { principal: 2, account: Some("1.0.2".into()), kind: SessionKind::Signed { fingerprint, set_account: "1.0.2".into() } });
        let refused = shell.call("merge.compose", &json!({"session": session, "doc": doc, "alternative": format!("{doc}.1.1")})).unwrap_err();
        shell.shutdown();
        let sent = frames.lock().unwrap().clone();
        (refused, sent)
    };
    let (refused, sent) = compose(None);
    let v = refused.to_value();
    assert_eq!((refused.name(), v["op"].as_str()), ("shape", Some("doc_metadata")), "{v}");
    let read: Vec<u64> = sent.iter().filter_map(|f| trunk_member_read(doc, f)).collect();
    let doubling: Vec<u64> = (0..64).map(|i| 1 + (1u64 << i)).collect();
    assert_eq!(read, doubling, "the doubling's reads, once each");
    assert!(sent.iter().all(|f| f["doc"] != doc && f["op"] != "stage" && f["op"] != "set_arrangement"), "nothing composed, staged or set: {sent:?}");
    for (members, head) in [(6, format!("{doc}.6")), (1, format!("{doc}.1"))] {
        let (refused, _) = compose(Some(members));
        let v = refused.to_value();
        assert_eq!((refused.name(), v["doc"].as_str()), ("unreadable", Some(head.as_str())), "composed on the newest member: {v}");
    }
}

/// Checks a daughter composed and landed, and taken back, against the
/// daemon.
///
/// With no `into`, `merge.compose` lands M in a FRESH draft staged from the
/// head — `fresh` true, the draft's recorded base E.2 and its marker naming
/// E.1.1 under E.2 at the landing's position, its text the merge of both
/// sides, the report declared with its one unsettled `order` gap; the
/// composition stands and `merge.undo` takes the landing back by ONE
/// `set_arrangement` — the draft's text E.2's again, its base restored with
/// its extent, its marker gone, one arrangement row under the draft naming
/// a base and no merge — and the composition is gone. With `into` a level
/// draft L staged from E.2, the landing goes into L, `fresh` false. A burst
/// to L after the landing and its taking back, each typed at the editor's
/// own last ack, leave L holding M, its arrangement moved past the landing;
/// `merge.undo`, typed at the editor's own last ack, takes the landing back
/// by ONE `set_arrangement`, L's text E.2's again and its base restored.
/// Landed into L again, `merge.withdraw` takes the merge out of L by ONE
/// `set_arrangement`, its words kept, its marker gone, the landing's record
/// replaced, and the composition gone (the mutants that land by a second
/// write, stage where a draft is named, drop the marker, keep a taken-back
/// composition standing, or type the undo at the landing past the editor's
/// own later acks).
#[test]
fn the_family_lands_a_daughter_into_a_fresh_draft_and_into_a_named_one_and_takes_each_back_by_one_write() {
    use skep_client::board::frames::doc_metadata;
    let dir = TempDir::new().unwrap();
    let sd = spawn(&dir.path().join("board"), true);
    let g = ground(&dir, &sd);
    let f = family(&g);
    // A fresh draft: staged from the head first, then the one write.
    let before = g.position();
    let report = g.call("merge.compose", json!({"session": g.session, "doc": f.edition, "alternative": f.e11})).unwrap_or_else(|r| panic!("{r}"));
    assert_report_declared(&report);
    assert_eq!((report["outcome"].as_str(), report["form"].as_str(), report["fresh"].as_bool(), report["head_moved"].is_null()), (Some("landed"), Some("daughter"), Some(true), true), "{report}");
    assert_eq!((report["doc"].as_str(), report["head"].as_str(), report["base"].as_str(), report["side"].as_str()), (Some(f.edition.as_str()), Some(f.e2.as_str()), Some(f.e1.as_str()), Some(f.e11.as_str())), "{report}");
    let fresh = report["into"].as_str().expect("the fresh draft").to_string();
    let position = report["position"].as_u64().expect("the landing's position");
    assert!(position > before, "{report}");
    assert!(report["record_link"].is_string() && !report["over_cap"].as_bool().unwrap(), "{report}");
    let gaps = report["gaps"].as_array().unwrap();
    assert_eq!(gaps.len(), 1, "both sides added at one spot: {report}");
    assert_eq!((gaps[0]["kind"].as_str(), gaps[0]["settled"].as_bool(), gaps[0]["resolved_by"].is_null()), (Some("order"), Some(false), true), "{report}");
    let meta = g.op(doc_metadata(&fresh));
    assert_eq!((meta["base"].as_str(), meta["merge"]["sides"].clone(), meta["merge"]["head"].as_str(), meta["merge"]["at"].as_u64()), (Some(f.e2.as_str()), json!([f.e11]), Some(f.e2.as_str()), Some(position)), "staged from the head, marked: {meta}");
    let text = g.text(&fresh, 19);
    assert!(text.starts_with("the fox") && text.contains(" jumps") && text.contains(" today") && text.len() == 19, "{text:?}");
    // The undo: one write, the draft as it stood.
    let since = g.position();
    let undone = g.call("merge.undo", json!({"session": g.session})).unwrap_or_else(|r| panic!("{r}"));
    crate::shapes::assert_declared("Undone", &undone);
    assert_eq!((undone["draft"].as_str(), undone["restored"].clone(), undone["record"].is_string()), (Some(fresh.as_str()), json!({"base": f.e2, "extent": 13}), true), "{undone}");
    assert_eq!(g.text(&fresh, 13), "the fox jumps");
    assert!(g.op(doc_metadata(&fresh))["merge"].is_null(), "the marker gone");
    assert_eq!(arrangement_rows(&g, &fresh, since), [(true, false)], "one arrangement row, a base and no merge");
    assert_eq!(g.call("merge.undo", json!({"session": g.session})).unwrap_err().name(), "no_merge", "the composition went with the undo");
    // A named level draft: landed into, nothing staged.
    let l = g.addr(skep_client::board::frames::stage(&f.e2, None));
    let compose_into_l = || g.call("merge.compose", json!({"session": g.session, "doc": f.edition, "alternative": f.e11, "into": l})).unwrap_or_else(|r| panic!("{r}"));
    let report = compose_into_l();
    assert_eq!((report["outcome"].as_str(), report["into"].as_str(), report["fresh"].as_bool()), (Some("landed"), Some(l.as_str()), Some(false)), "{report}");
    let landed_at = report["position"].as_u64().unwrap();
    assert_eq!(g.op(doc_metadata(&l))["merge"]["sides"], json!([f.e11]));
    // A burst after the landing and its taking back, each typed at the
    // editor's own last ack: L holds M again, its arrangement past the
    // landing, and the undo typed at the editor's own last ack lands.
    let burst = g.op(json!({"op": "insert", "doc": l, "at": {"subspace": "1", "ordinal": "20"}, "values": ["!"], "as_of": g.position()}));
    let taken = g.op(json!({"op": "delete", "doc": l, "p": {"subspace": "1", "ordinal": "20"}, "width": "1", "as_of": burst["at"]}));
    assert!(taken["at"].as_u64().is_some_and(|at| at > landed_at) && g.text(&l, 20).len() == 19, "the premise: M again, its arrangement past the landing: {taken}");
    let since = g.position();
    let undone = g.call("merge.undo", json!({"session": g.session})).unwrap_or_else(|r| panic!("{r}"));
    crate::shapes::assert_declared("Undone", &undone);
    assert_eq!((undone["draft"].as_str(), undone["restored"].clone()), (Some(l.as_str()), json!({"base": f.e2, "extent": 13})), "{undone}");
    assert_eq!(g.text(&l, 13), "the fox jumps", "L as it stood before the landing");
    assert!(g.op(doc_metadata(&l))["merge"].is_null(), "the marker gone");
    assert_eq!(arrangement_rows(&g, &l, since), [(true, false)], "one arrangement row, a base and no merge");
    // Landed into L again, and withdrawn: one write, the words kept, the
    // marker gone.
    let report = compose_into_l();
    assert_eq!((report["outcome"].as_str(), report["into"].as_str()), (Some("landed"), Some(l.as_str())), "{report}");
    let since = g.position();
    let withdrawn = g.call("merge.withdraw", json!({"session": g.session, "draft": l})).unwrap_or_else(|r| panic!("{r}"));
    crate::shapes::assert_declared("Withdrawn", &withdrawn);
    assert_eq!((withdrawn["draft"].as_str(), withdrawn["record"].is_string()), (Some(l.as_str()), true), "{withdrawn}");
    assert_eq!(g.text(&l, 20).len(), 19, "the words kept");
    assert!(g.op(doc_metadata(&l))["merge"].is_null(), "the marker gone");
    assert_eq!(arrangement_rows(&g, &l, since), [(true, false)], "one arrangement row");
    assert_eq!(g.call("merge.land", json!({"session": g.session})).unwrap_err().name(), "no_merge", "the composition went with the withdrawal");
    assert_eq!(g.call("merge.withdraw", json!({"session": g.session, "draft": l})).unwrap_err().name(), "no_merge", "no merge to take out");
    g.shell.shutdown();
    sd.shutdown();
}

/// Checks that the landing, the undo and the withdrawal are refused over
/// the draft's held lines, a burst held behind them, against the daemon
/// (§3c.4, THE HELD-LINES GATE; skep #849).
///
/// L takes the merge of E.2 with E.1.1; a burst on L at a far ordinal is
/// refused `out_of_bounds` and held, a refused run awaiting the person's
/// act, and a second burst on L is held `behind` it — not refused, the
/// burst writes being ungated: `merge.undo`, `merge.withdraw` and
/// `merge.land` are each refused `held_lines` naming L and the two lines,
/// the board's position unmoved, L's text and marker standing, the
/// composition standing (the landing answers the gate, never `no_merge`);
/// the run dropped — the one way such a line clears — `merge.undo` goes
/// out: L's text E.2's again, its marker gone (the mutants that let the undo
/// or the withdrawal dial past the held lines, which then land on the
/// rewritten arrangement as a move the person never made; the one that
/// gates the landing's shot by the panel's drafts alone and lands into L
/// first; the one that refuses a burst on L instead of holding it).
#[test]
fn the_landing_the_undo_and_the_withdrawal_are_refused_over_the_drafts_held_lines_and_a_burst_is_held_behind() {
    use skep_client::board::frames::doc_metadata;
    let dir = TempDir::new().unwrap();
    let sd = spawn(&dir.path().join("board"), true);
    let g = ground(&dir, &sd);
    let f = family(&g);
    let l = g.addr(skep_client::board::frames::stage(&f.e2, None));
    let landed = g.call("merge.compose", json!({"session": g.session, "doc": f.edition, "alternative": f.e11, "into": l})).unwrap_or_else(|r| panic!("{r}"));
    let landed_at = landed["position"].as_u64().expect("the landing's position");
    let text = g.text(&l, 20);
    assert_eq!(text.len(), 19, "the premise: L holds M");
    // The refused run, and a burst held behind it.
    let refused = g.op(json!({"op": "insert", "doc": l, "at": {"subspace": "1", "ordinal": "900000"}, "values": ["r"], "as_of": g.position()}));
    assert!(refused["resp"] == "held" && refused["cause"].as_str().is_some_and(|c| c.starts_with("out_of_bounds")), "premise: a refused run stands on L: {refused}");
    let k = refused["held"].as_u64().unwrap();
    let behind = g.op(json!({"op": "insert", "doc": l, "at": {"subspace": "1", "ordinal": "900001"}, "values": ["s"], "as_of": g.position()}));
    assert_eq!((behind["resp"].as_str(), behind["cause"].as_str()), (Some("held"), Some("behind")), "a burst on L is held behind the run, never refused: {behind}");
    let before = g.position();
    for (call, args) in [("merge.undo", json!({"session": g.session})), ("merge.withdraw", json!({"session": g.session, "draft": l})), ("merge.land", json!({"session": g.session}))] {
        let refused = g.call(call, args).unwrap_err();
        let v = refused.to_value();
        assert_eq!((refused.name(), v["kind"].as_str(), v["doc"].as_str(), v["held"].as_u64()), ("held_lines", Some("shell"), Some(l.as_str()), Some(2)), "{call}: {v}");
    }
    assert_eq!(g.position(), before, "nothing sent");
    assert_eq!((g.text(&l, 20), g.op(doc_metadata(&l))["merge"]["at"].as_u64()), (text, Some(landed_at)), "L and its marker stand");
    // The run dropped, the undo goes out.
    g.call("resolve", json!({"session": g.session, "held": k, "act": "drop"})).unwrap_or_else(|r| panic!("{r}"));
    assert!(g.call("held", json!({"session": g.session})).unwrap().as_array().unwrap().is_empty(), "the run and the line behind it are dropped");
    let undone = g.call("merge.undo", json!({"session": g.session})).unwrap_or_else(|r| panic!("the lines gone, the undo goes out: {r}"));
    crate::shapes::assert_declared("Undone", &undone);
    assert_eq!(g.text(&l, 20), "the fox jumps", "{undone}");
    assert!(g.op(doc_metadata(&l))["merge"].is_null(), "the marker gone");
    g.shell.shutdown();
    sd.shutdown();
}

/// Checks that the merge rows are refused under a stopped node and under a
/// poisoned write path with nothing dialed, against the daemon (skep #850).
///
/// L takes the merge of E.2 with E.1.1; the own node stopped, `merge.land`,
/// `merge.undo`, `merge.withdraw` and `merge.compose` — into L, and naming
/// no `into` — are refused `stopped` naming the op each would first dial
/// (`publish`, `set_arrangement`, `set_arrangement`, `set_arrangement`,
/// `stage`), the board's position unmoved and the composition standing; the
/// node running, the kernel poisoned as the held suite poisons it, a burst
/// on another draft is refused `poisoned` and held, and each row is refused
/// `poisoned` naming the same op, nothing landed (the mutant that asks no
/// hold at a merge row dials a stopped or poisoned board and hands the page
/// the board's verdict or `unreachable` for a reason the shell knew; the
/// one that asks it under the wrong op misnames the write).
#[test]
fn the_merge_rows_are_refused_under_a_stopped_node_and_a_poisoned_path_with_nothing_dialed() {
    let dir = TempDir::new().unwrap();
    let sd = spawn(&dir.path().join("board"), true);
    let g = ground(&dir, &sd);
    let f = family(&g);
    let l = g.addr(skep_client::board::frames::stage(&f.e2, None));
    g.call("merge.compose", json!({"session": g.session, "doc": f.edition, "alternative": f.e11, "into": l})).unwrap_or_else(|r| panic!("{r}"));
    let other = g.draft("elsewhere");
    let rows = || {
        [
            ("merge.land", json!({"session": g.session}), "publish"),
            ("merge.undo", json!({"session": g.session}), "set_arrangement"),
            ("merge.withdraw", json!({"session": g.session, "draft": l}), "set_arrangement"),
            ("merge.compose", json!({"session": g.session, "doc": f.edition, "alternative": f.e11, "into": l}), "set_arrangement"),
            ("merge.compose", json!({"session": g.session, "doc": f.edition, "alternative": f.e11}), "stage"),
        ]
    };
    let refused_each = |cause: &str| {
        let before = g.position();
        for (call, args, op) in rows() {
            let refused = g.call(call, args).unwrap_err();
            let v = refused.to_value();
            assert_eq!((refused.name(), v["kind"].as_str(), v["op"].as_str()), (cause, Some("shell"), Some(op)), "{cause}: {call}: {v}");
        }
        assert_eq!(g.position(), before, "{cause}: nothing sent");
    };
    g.shell.set_node_state(NodeState::Stopped);
    refused_each("stopped");
    g.shell.set_node_state(NodeState::Running);
    // The poisoned write path: the kernel's next checkpoint fails and its
    // repair with it, so the next write is refused `poisoned` and held.
    sd.daemon().fail_the_next_checkpoint_step(Step::JournalBarrier, std::io::ErrorKind::Other);
    sd.daemon().fail_the_next_checkpoint_step(Step::JournalRepair, std::io::ErrorKind::Other);
    let held = g.op(json!({"op": "insert", "doc": other, "at": {"subspace": "1", "ordinal": "2"}, "values": ["b"], "as_of": g.position()}));
    assert_eq!((held["resp"].as_str(), held["cause"].as_str()), (Some("held"), Some("poisoned")), "premise: the write path is poisoned: {held}");
    refused_each("poisoned");
    g.shell.shutdown();
    sd.shutdown();
}

/// Checks `merge.undo`'s typing against the daemon (P3; skep #811).
///
/// L takes the merge of E.2 with E.1.1, the editor's burst lands on it, and
/// a SECOND DEVICE's write lands after it — another hand's: `merge.undo`,
/// typed at the editor's own last ack, the burst's, is the board's
/// `arrangement_moved`, `site.as_of` the burst's position and `site.current`
/// the second device's, both writes kept, the marker standing and the
/// composition with it. The editor's own link homed in L then lands — a link
/// write changes no arrangement — and the undo is refused again at the
/// burst's position, never the link's (the mutants that type the undo at
/// the landing, or at the hold's last ack on L, which the link raises and
/// which would replace the other hand's write).
#[test]
fn merge_undo_is_typed_at_the_editors_own_last_arrangement_write_and_refused_past_another_hands() {
    use skep_client::board::frames::doc_metadata;
    let dir = TempDir::new().unwrap();
    let sd = spawn(&dir.path().join("board"), true);
    let g = ground(&dir, &sd);
    let f = family(&g);
    let l = g.addr(skep_client::board::frames::stage(&f.e2, None));
    let landed = g.call("merge.compose", json!({"session": g.session, "doc": f.edition, "alternative": f.e11, "into": l})).unwrap_or_else(|r| panic!("{r}"));
    let landed_at = landed["position"].as_u64().expect("the landing's position");
    // The editor's burst on L, then a second device's write after it.
    let burst = g.op(json!({"op": "insert", "doc": l, "at": {"subspace": "1", "ordinal": "20"}, "values": ["!"], "as_of": g.position()}));
    let burst_at = burst["at"].as_u64().expect("the burst's position");
    let second = second_device(&dir, &sd);
    let theirs = second.op(json!({"op": "insert", "doc": l, "at": {"subspace": "1", "ordinal": "1"}, "values": ["#"], "as_of": second.position()}));
    let theirs_at = theirs["at"].as_u64().expect("the other hand's position");
    second.shell.shutdown();
    assert!(landed_at < burst_at && burst_at < theirs_at, "the premise: the landing, the burst, the other hand's write");
    let refused = |when: &str| {
        let moved = g.call("merge.undo", json!({"session": g.session})).unwrap_err();
        let v = moved.to_value();
        assert_eq!(
            (moved.name(), v["kind"].as_str(), v["site"]["as_of"].as_u64(), v["site"]["current"].as_u64()),
            ("arrangement_moved", Some("refused"), Some(burst_at), Some(theirs_at)),
            "{when}: typed at the burst's position: {v}"
        );
        assert_eq!(g.text(&l, 21), "#the fox jumps today!", "{when}: both writes kept");
        assert_eq!(g.op(doc_metadata(&l))["merge"]["at"].as_u64(), Some(landed_at), "{when}: the marker stands");
    };
    refused("after the other hand's write");
    // The editor's own link homed in L: a write, and no arrangement write.
    let link = g.op(json!({"op": "make_link", "home": l, "from": [{"source": l, "span": {"start": "1.2", "width": "0.3"}}], "to": {"addrs": []}, "ty": {"addrs": ["1.1.0.1.0.1.0.3.13"]}}));
    assert!(link["at"].as_u64().is_some_and(|at| at > theirs_at), "the premise: the link lands past the other hand's write: {link}");
    refused("after the editor's own link, the composition standing");
    g.shell.shutdown();
    sd.shutdown();
}

/// Checks the re-open, the resolutions and the landing on the trunk against
/// the daemon.
///
/// L takes the merge of E.2 with E.1.1; `merge.compose` again on the same
/// daughter into L is THE RE-OPEN: the report with nothing landed, its
/// `position` the marker's, the board's position unmoved, the gap unsettled
/// as it was; the draft's additions deleted whole, the re-open reads the
/// gap off the draft as SETTLED by the person. `merge.land` with a
/// resolution naming no gap, a choice no gap admits, a side not of the gap
/// or an anchor the gap does not name is refused `malformed_args` naming
/// `resolutions`, nothing landed; with a checked one it lands: the shot
/// through the publication family carrying the claim, E.3 acknowledged with
/// `supersede [E.1.1]`, the record written — read back by the next
/// `merge.compose` of the daughter, THE MERGED ARM, naming the member and
/// the standing record, whose gap the person resolved `omitted`, nothing
/// landed and nothing written again (the mutants that land at the re-open,
/// read the gap off the composition alone, apply an unchecked resolution,
/// or write the record twice).
#[test]
fn the_re_open_lands_nothing_and_a_checked_resolution_lands_on_the_trunk_with_the_claim_and_its_record() {
    let dir = TempDir::new().unwrap();
    let sd = spawn(&dir.path().join("board"), true);
    let g = ground(&dir, &sd);
    let f = family(&g);
    let l = g.addr(skep_client::board::frames::stage(&f.e2, None));
    let compose = || g.call("merge.compose", json!({"session": g.session, "doc": f.edition, "alternative": f.e11, "into": l})).unwrap_or_else(|r| panic!("{r}"));
    let landed = compose();
    assert_eq!(landed["outcome"].as_str(), Some("landed"), "{landed}");
    let position = landed["position"].as_u64().unwrap();
    let gap = landed["gaps"][0]["id"].as_u64().expect("the order gap");
    // The re-open: nothing landed.
    let before = g.position();
    let reopened = compose();
    assert_report_declared(&reopened);
    assert_eq!((reopened["outcome"].as_str(), reopened["into"].as_str(), reopened["position"].as_u64(), reopened["gaps"][0]["settled"].as_bool()), (Some("reopened"), Some(l.as_str()), Some(position), Some(false)), "{reopened}");
    assert_eq!(reopened["runs"], landed["runs"], "the side as compose read it");
    assert_eq!(g.position(), before, "nothing landed");
    // The gap's default no longer arranged: both additions deleted whole.
    g.op(json!({"op": "delete", "doc": l, "p": {"subspace": "1", "ordinal": "8"}, "width": "12", "as_of": g.position()}));
    assert_eq!(g.text(&l, 7), "the fox");
    let settled = compose();
    assert_eq!((settled["outcome"].as_str(), settled["gaps"][0]["settled"].as_bool(), settled["gaps"][0]["resolved_by"].as_str()), (Some("reopened"), Some(true), Some("person")), "{settled}");
    // The resolutions, UNTRUSTED.
    let before = g.position();
    for bad in [json!({"99": "omit"}), json!({gap.to_string(): "frob"}), json!({gap.to_string(): {"order": [7]}}), json!({gap.to_string(): {"keep_only": 9}}), json!({gap.to_string(): {"after": "1.0.9.0.1.0.1.1"}}), json!({gap.to_string(): {"order": []}}), json!({gap.to_string(): {"order": [0, 0]}})] {
        let refused = g.call("merge.land", json!({"session": g.session, "resolutions": bad})).unwrap_err().to_value();
        assert_eq!((refused["name"].as_str(), refused["what"].as_str()), (Some("malformed_args"), Some("resolutions")), "{bad}: {refused}");
    }
    assert_eq!(g.position(), before, "nothing landed");
    // A checked one: the landing on the trunk with the claim and the record.
    let landed = g.call("merge.land", json!({"session": g.session, "resolutions": {gap.to_string(): "omit"}})).unwrap_or_else(|r| panic!("{r}"));
    crate::shapes::assert_declared("MergeLanded", &landed);
    let e3 = format!("{}.3", f.edition);
    assert_eq!((landed["outcome"].as_str(), landed["member"].as_str(), landed["supersede"].clone(), landed["daughter"].as_bool(), landed["claim"].as_bool()), (Some("landed"), Some(e3.as_str()), json!([f.e11]), Some(false), Some(false)), "{landed}");
    assert!(landed["record"].is_string() && landed["claims"].as_array().is_some_and(|c| c.len() == 1), "the record and the claim read back: {landed}");
    assert_eq!(g.text(&e3, 7), "the fox");
    assert_eq!(g.call("merge.land", json!({"session": g.session})).unwrap_err().name(), "no_merge", "the composition went with the landing");
    // THE MERGED ARM: the member named, the standing record, nothing written.
    let before = g.position();
    let merged = g.call("merge.compose", json!({"session": g.session, "doc": f.edition, "alternative": f.e11})).unwrap_or_else(|r| panic!("{r}"));
    assert_report_declared(&merged);
    assert_eq!((merged["outcome"].as_str(), merged["member"].as_str(), merged["record_link"].as_str(), merged.get("into")), (Some("merged"), Some(e3.as_str()), landed["record"].as_str(), None), "{merged}");
    assert_eq!(merged["claims"], landed["claims"]);
    let record_gap = merged["record"]["gaps"].as_array().unwrap().iter().find(|gp| gp["id"].as_u64() == Some(gap)).expect("the gap in the record");
    assert_eq!((record_gap["resolved_by"].as_str(), record_gap["placed"].as_str()), (Some("person"), Some("omitted")), "the person's resolution in the record: {merged}");
    assert_eq!(g.position(), before, "nothing landed, nothing written");
    assert_eq!(g.call("merge.land", json!({"session": g.session})).unwrap_err().name(), "no_merge", "a merged daughter composes nothing to land");
    g.shell.shutdown();
    sd.shutdown();
}

/// Checks that a merge landed in a panel's draft since its open is
/// re-stated and carries its claim into the next confirm (D4 (b′); skep
/// #934).
///
/// L, staged from E.1 and behind, opens its panel over the whole draft. A
/// SECOND DEVICE lands the merge of E.2 with E.1.1 in L — the draft's
/// recorded base moving to the head E.2 and its marker set beside it. The
/// confirm is `restated`, naming `base` E.2 and `standing: at_head`, the
/// panel re-keyed on it, `selection` empty as the panel re-took what L now
/// arranges, nothing sent; `publication.count` answers the claim composed
/// off the marker; the next confirm lands E.3 with `supersede [E.1.1]`,
/// holding the merged words (the mutant that re-keys the base alone
/// publishes no claim; the one that keeps the held runs publishes the old
/// words and no merge).
#[test]
fn a_merge_landed_in_a_panels_draft_since_its_open_is_re_stated_and_lands_with_its_claim() {
    let dir = TempDir::new().unwrap();
    let sd = spawn(&dir.path().join("board"), true);
    let g = ground(&dir, &sd);
    let f = family(&g);
    let l = g.addr(frames::stage(&f.e1, None));
    let panel = g.call("publication.open", json!({"session": g.session, "draft": l, "doc": f.edition, "readable_drafts": [l], "published": [f.edition]})).unwrap_or_else(|r| panic!("{r}"));
    assert_eq!(panel["standing"], "behind", "L stands behind the head E.2: {panel}");
    let second = second_device(&dir, &sd);
    let landed = second.call("merge.compose", json!({"session": second.session, "doc": f.edition, "alternative": f.e11, "into": l})).unwrap_or_else(|r| panic!("{r}"));
    assert_eq!((landed["outcome"].as_str(), landed["into"].as_str()), (Some("landed"), Some(l.as_str())), "{landed}");
    second.shell.shutdown();
    let before = g.position();
    let restated = g.call("publication.confirm", json!({"session": g.session})).unwrap_or_else(|r| panic!("{r}"));
    crate::shapes::assert_declared("Restated", &restated);
    assert_eq!((restated["outcome"].as_str(), restated["base"].as_str(), restated["standing"].as_str(), restated["selection"].clone()), (Some("restated"), Some(f.e2.as_str()), Some("at_head"), json!([])), "the merge moved L's base to the head: {restated}");
    assert_eq!(g.position(), before, "nothing sent");
    let counted = g.call("publication.count", json!({"session": g.session})).unwrap_or_else(|r| panic!("{r}"));
    assert_eq!(counted["count"]["supersede"], json!([f.e11]), "the claim composed off the marker the re-read found: {counted}");
    let acked = g.call("publication.confirm", json!({"session": g.session})).unwrap_or_else(|r| panic!("{r}"));
    let e3 = format!("{}.3", f.edition);
    assert_eq!((acked["outcome"].as_str(), acked["member"].as_str(), acked["supersede"].clone()), (Some("acknowledged"), Some(e3.as_str()), json!([f.e11])), "the next confirm lands on the moved base with the merge's claim: {acked}");
    let text = g.text(&e3, 19);
    assert!(text.starts_with("the fox") && text.contains(" jumps") && text.contains(" today") && text.len() == 19, "the merged words, not the held old ones: {text:?}");
    g.shell.shutdown();
    sd.shutdown();
}

/// Returns the page's panel over the whole of `draft`, before or after a
/// merge lands in it.
fn page_panel(g: &Ground, f: &Family, draft: &str) -> Value {
    g.call("publication.open", json!({"session": g.session, "draft": draft, "doc": f.edition, "readable_drafts": [draft], "published": [f.edition]})).unwrap_or_else(|r| panic!("{r}"))
}

/// Lands the merge of the head with the daughter `side` in `draft`.
fn merged_into(g: &Ground, f: &Family, side: &str, draft: &str) -> Value {
    let landed = g.call("merge.compose", json!({"session": g.session, "doc": f.edition, "alternative": side, "into": draft})).unwrap_or_else(|r| panic!("{r}"));
    assert_eq!((landed["outcome"].as_str(), landed["into"].as_str()), (Some("landed"), Some(draft)), "{landed}");
    landed
}

/// Publishes another daughter of E.1, `words` at its end: answers the
/// member.
fn another_daughter(g: &Ground, f: &Family, words: &str) -> String {
    let s = g.addr(frames::stage(&f.e1, None));
    g.op(json!({"op": "insert", "doc": s, "at": {"subspace": "1", "ordinal": "8"}, "values": [words], "as_of": g.position()}));
    page_panel(g, f, &s);
    let acked = g.call("publication.confirm", json!({"session": g.session})).unwrap_or_else(|r| panic!("{r}"));
    acked["member"].as_str().unwrap_or_else(|| panic!("the daughter: {acked}")).to_string()
}

/// Asserts that `member` holds M's nineteen characters: the head's and the
/// daughter's added words beside the base's.
fn assert_holds_the_merge(g: &Ground, member: &str, label: &str) {
    let text = g.text(member, 19);
    assert!(text.starts_with("the fox") && text.contains(" jumps") && text.contains(" today") && text.len() == 19, "{label}: the merged words, not the held old ones: {text:?}");
}

/// Checks that a landing over a panel opened before the compose lands the
/// merge in the one call, carrying its claim (skep #949; **The landing** of
/// `shell/publication.rs`).
///
/// Three cells over the family's ground, the panel opened over the whole of
/// L and reading no merge. L staged from the head E.2 and untouched: the
/// held run stands whole inside M, and a request held to it with no claim
/// changes nothing against the base (the mutant that keys neither answers
/// `inert`). L with " jumps" deleted before the open: the base pair stands
/// as the compose records it (the same mutant publishes "the fox", no
/// claim). L staged from E.1: the compose moves its base to the head (the
/// mutant that leaves the standing unwritten answers `restated`). Each
/// lands E.3 holding M's nineteen characters with `supersede [E.1.1]` and
/// the merge's record (the mutant that re-takes the words alone publishes
/// no claim; the one that composes the claim alone publishes the old words
/// under it).
#[test]
fn a_landing_over_a_panel_opened_before_the_compose_lands_the_merge_with_its_claim() {
    let cell = |label: &str, from_head: bool, deleted: bool, standing: &str| {
        let dir = TempDir::new().unwrap();
        let sd = spawn(&dir.path().join("board"), true);
        let g = ground(&dir, &sd);
        let f = family(&g);
        let l = g.addr(frames::stage(if from_head { &f.e2 } else { &f.e1 }, None));
        if deleted {
            g.op(json!({"op": "delete", "doc": l, "p": {"subspace": "1", "ordinal": "8"}, "width": "6", "as_of": g.position()}));
        }
        let panel = page_panel(&g, &f, &l);
        assert_eq!((panel["count"]["supersede"].clone(), panel["standing"].as_str()), (json!([]), Some(standing)), "{label}: the panel reads no merge: {panel}");
        merged_into(&g, &f, &f.e11, &l);
        let landed = g.call("merge.land", json!({"session": g.session})).unwrap_or_else(|r| panic!("{r}"));
        crate::shapes::assert_declared("MergeLanded", &landed);
        let e3 = format!("{}.3", f.edition);
        assert_eq!((landed["outcome"].as_str(), landed["member"].as_str(), landed["supersede"].clone(), landed["daughter"].as_bool()), (Some("landed"), Some(e3.as_str()), json!([f.e11]), Some(false)), "{label}: {landed}");
        assert!(landed["record"].is_string() && landed.get("unrecorded").is_none(), "{label}: the merge's record: {landed}");
        assert_holds_the_merge(&g, &e3, label);
        assert_eq!(g.call("merge.land", json!({"session": g.session})).unwrap_err().name(), "no_merge", "{label}: the composition went with the landing");
        g.shell.shutdown();
        sd.shutdown();
    };
    cell("level and untouched", true, false, "at_head");
    cell("words deleted", true, true, "at_head");
    cell("behind the head", false, false, "behind");
}

/// Checks the draft side of a landing over an earlier panel.
///
/// L's panel is opened before B, a draft behind the head, is composed as
/// the merge's side into L. `merge.land` names B `also` as a panel it opened
/// itself would, so B's words are the document's own, every run of E.3 in
/// E's chain and no window asked of them, and lands E.3 holding both sides'
/// words with no claim (the mutants that keep the selection, answering
/// `inert`, or leave B out of `also`, refusing `window_parts_owed`).
#[test]
fn a_draft_side_landing_over_an_earlier_panel_names_the_side_also() {
    let dir = TempDir::new().unwrap();
    let sd = spawn(&dir.path().join("board"), true);
    let g = ground(&dir, &sd);
    let f = family(&g);
    let b = g.addr(frames::stage(&f.e1, None));
    g.op(json!({"op": "insert", "doc": b, "at": {"subspace": "1", "ordinal": "8"}, "values": [" quietly"], "as_of": g.position()}));
    let l = g.addr(frames::stage(&f.e2, None));
    page_panel(&g, &f, &l);
    let landed = g.call("merge.compose", json!({"session": g.session, "doc": f.edition, "draft": b, "into": l})).unwrap_or_else(|r| panic!("{r}"));
    assert_eq!((landed["outcome"].as_str(), landed["form"].as_str()), (Some("landed"), Some("draft")), "{landed}");
    let shot = g.call("merge.land", json!({"session": g.session})).unwrap_or_else(|r| panic!("{r}"));
    let e3 = format!("{}.3", f.edition);
    assert_eq!((shot["outcome"].as_str(), shot["member"].as_str(), shot["supersede"].clone(), shot["daughter"].as_bool()), (Some("landed"), Some(e3.as_str()), json!([]), Some(false)), "{shot}");
    let text = g.text(&e3, 21);
    assert!(text.contains(" jumps") && text.contains(" quietly") && text.len() == 21, "both sides' words: {text:?}");
    let image = g.op(frames::image(&e3, 1, 21));
    let runs = image["runs"].as_array().unwrap_or_else(|| panic!("the image: {image}"));
    assert!(runs.iter().all(|r| r["i_start"].as_str().and_then(document_of).as_deref() == Some(f.edition.as_str())), "B's words are the document's own: {image}");
    g.shell.shutdown();
    sd.shutdown();
}

/// Checks that a selection the page passed is kept held at a landing over
/// an earlier panel, and re-stated (PUB-3.108).
///
/// L, staged from the head, holds words of its own; the page's panel holds
/// E's run and those words, or those words alone. The compose lands M as L's
/// whole arrangement, so L's own words leave it. With E's run held, the first
/// `merge.land` answers `restated`, run 1 absent, nothing sent, the event
/// said and the panel keyed on the marker, its count naming the claim; the
/// next lands E.3 holding the held run, `supersede [E.1.1]` (the mutant that
/// re-takes the selection publishes the merge; the one that keeps the
/// re-statement's silence publishes the held run in one call). With the
/// words alone every run is absent: `restated` all the same, and the next
/// call refused `selection_not_arranged`, nothing sent (the mutant that
/// prices the panel without the guard refuses at the first call).
#[test]
fn a_selection_the_page_passed_is_kept_held_and_re_stated_at_the_landing() {
    let cell = |own_alone: bool| {
        let dir = TempDir::new().unwrap();
        let sd = spawn(&dir.path().join("board"), true);
        let g = ground(&dir, &sd);
        let f = family(&g);
        let l = g.addr(frames::stage(&f.e2, None));
        g.op(json!({"op": "insert", "doc": l, "at": {"subspace": "1", "ordinal": "14"}, "values": [" quick"], "as_of": g.position()}));
        let own = json!({"origin": l, "i_start": 1, "width": 6});
        let selection = if own_alone { json!([own]) } else { json!([{"origin": f.edition, "i_start": 1, "width": 13}, own]) };
        g.call("publication.open", json!({"session": g.session, "draft": l, "doc": f.edition, "selection": selection, "readable_drafts": [l], "published": [f.edition]})).unwrap_or_else(|r| panic!("{r}"));
        merged_into(&g, &f, &f.e11, &l);
        let said = g.states().len();
        let before = g.position();
        let restated = g.call("merge.land", json!({"session": g.session})).unwrap_or_else(|r| panic!("{r}"));
        crate::shapes::assert_declared("Restated", &restated);
        let absent = if own_alone { 0 } else { 1 };
        assert_eq!((restated["outcome"].as_str(), restated["selection"].clone()), (Some("restated"), json!([{"run": absent, "placement": "absent"}])), "L's own words left it: {restated}");
        assert_eq!(g.position(), before, "nothing sent");
        assert_eq!(g.states_once(said + 1).last().map(String::as_str), Some("restated"), "the landing's re-statement is said");
        let counted = g.call("publication.count", json!({"session": g.session})).unwrap_or_else(|r| panic!("{r}"));
        assert_eq!(counted["count"]["supersede"], json!([f.e11]), "the panel keyed on the marker: {counted}");
        if own_alone {
            let refused = g.call("merge.land", json!({"session": g.session})).unwrap_err();
            assert_eq!((refused.name(), refused.to_value()["index"].as_u64()), ("selection_not_arranged", Some(0)), "{refused}");
            assert_eq!(g.position(), before, "nothing sent");
        } else {
            let landed = g.call("merge.land", json!({"session": g.session})).unwrap_or_else(|r| panic!("{r}"));
            let e3 = format!("{}.3", f.edition);
            assert_eq!((landed["outcome"].as_str(), landed["member"].as_str(), landed["supersede"].clone()), (Some("landed"), Some(e3.as_str()), json!([f.e11])), "{landed}");
            assert_eq!(g.text(&e3, 13), "the fox jumps", "the held selection");
        }
        g.shell.shutdown();
        sd.shutdown();
    };
    cell(false);
    cell(true);
}

/// Checks that a selection the page passed re-states a base the compose
/// moved, nothing sent (D4 (b′); PUB-3.108).
///
/// L, staged from E.1 and behind, holds one run the merge leaves standing:
/// no placement differs, and the base and the standing moved are what the
/// panel told the person (the mutant that drops the re-statement of a
/// passed selection publishes in the one call). The next call lands E.3
/// holding the selection, the claim composed off the marker.
#[test]
fn a_selection_the_page_passed_re_states_a_base_the_compose_moved() {
    let dir = TempDir::new().unwrap();
    let sd = spawn(&dir.path().join("board"), true);
    let g = ground(&dir, &sd);
    let f = family(&g);
    let l = g.addr(frames::stage(&f.e1, None));
    let panel = g.call("publication.open", json!({"session": g.session, "draft": l, "doc": f.edition, "selection": [{"origin": f.edition, "i_start": 1, "width": 7}], "readable_drafts": [l], "published": [f.edition]})).unwrap_or_else(|r| panic!("{r}"));
    assert_eq!(panel["standing"], "behind", "{panel}");
    merged_into(&g, &f, &f.e11, &l);
    let before = g.position();
    let restated = g.call("merge.land", json!({"session": g.session})).unwrap_or_else(|r| panic!("{r}"));
    crate::shapes::assert_declared("Restated", &restated);
    assert_eq!((restated["outcome"].as_str(), restated["base"].as_str(), restated["standing"].as_str(), restated["selection"].clone()), (Some("restated"), Some(f.e2.as_str()), Some("at_head"), json!([])), "{restated}");
    assert_eq!(g.position(), before, "nothing sent");
    let landed = g.call("merge.land", json!({"session": g.session})).unwrap_or_else(|r| panic!("{r}"));
    let e3 = format!("{}.3", f.edition);
    assert_eq!((landed["outcome"].as_str(), landed["member"].as_str(), landed["supersede"].clone()), (Some("landed"), Some(e3.as_str()), json!([f.e11])), "{landed}");
    assert_eq!(g.text(&e3, 7), "the fox", "the selection");
    g.shell.shutdown();
    sd.shutdown();
}

/// Checks that a panel opened after the compose over a selection the page
/// chose lands as the open read it: the selection, and the claim the open
/// composed off the marker, nothing re-stated and nothing re-taken.
#[test]
fn a_panel_opened_after_the_compose_keeps_its_selection() {
    let dir = TempDir::new().unwrap();
    let sd = spawn(&dir.path().join("board"), true);
    let g = ground(&dir, &sd);
    let f = family(&g);
    let l = g.addr(frames::stage(&f.e2, None));
    merged_into(&g, &f, &f.e11, &l);
    let panel = g.call("publication.open", json!({"session": g.session, "draft": l, "doc": f.edition, "selection": [{"origin": f.edition, "i_start": 1, "width": 7}], "readable_drafts": [l], "published": [f.edition]})).unwrap_or_else(|r| panic!("{r}"));
    assert_eq!(panel["count"]["supersede"], json!([f.e11]), "{panel}");
    let landed = g.call("merge.land", json!({"session": g.session})).unwrap_or_else(|r| panic!("{r}"));
    let e3 = format!("{}.3", f.edition);
    assert_eq!((landed["outcome"].as_str(), landed["member"].as_str(), landed["supersede"].clone()), (Some("landed"), Some(e3.as_str()), json!([f.e11])), "{landed}");
    assert_eq!(g.text(&e3, 7), "the fox", "the selection the page chose");
    let extent = g.op(frames::span_set(&e3));
    assert_eq!(extent["set"][0]["width"].as_str().and_then(|w| w.rsplit('.').next()), Some("7"), "the selection alone: {extent}");
    g.shell.shutdown();
    sd.shutdown();
}

/// Checks that a panel of the whole draft opened after the compose is met
/// by the confirm's re-read at the landing, and keyed by no one: the draft
/// edited since the panel is re-stated, nothing sent (the mutant that keys
/// every panel, or that reads no marker at the open, re-takes the draft
/// behind the panel and lands an edit the person was never told of).
#[test]
fn a_panel_opened_after_the_compose_is_re_stated_at_the_landing_as_a_confirm_is() {
    let dir = TempDir::new().unwrap();
    let sd = spawn(&dir.path().join("board"), true);
    let g = ground(&dir, &sd);
    let f = family(&g);
    let l = g.addr(frames::stage(&f.e2, None));
    merged_into(&g, &f, &f.e11, &l);
    page_panel(&g, &f, &l);
    g.op(json!({"op": "delete", "doc": l, "p": {"subspace": "1", "ordinal": "14"}, "width": "6", "as_of": g.position()}));
    let before = g.position();
    let restated = g.call("merge.land", json!({"session": g.session})).unwrap_or_else(|r| panic!("{r}"));
    crate::shapes::assert_declared("Restated", &restated);
    assert_eq!(restated["outcome"].as_str(), Some("restated"), "{restated}");
    assert_eq!((restated["selection"][0]["run"].as_u64(), restated["selection"][0]["placement"]["split"].is_array()), (Some(0), true), "the held run, cut by the edit: {restated}");
    assert_eq!(g.position(), before, "nothing sent");
    g.shell.shutdown();
    sd.shutdown();
}

/// Checks that a panel re-opened after the compose lands the merge, not the
/// words the first open held.
///
/// The re-open composes the claim off the marker and keeps the selection
/// read before the merge, so the panel's flag says a merge was asked (the
/// mutant that tells an earlier panel by `merge_landing` alone publishes
/// E.3 with " today" missing and E.1.1 marked superseded by it).
#[test]
fn a_panel_re_opened_after_the_compose_lands_the_merge_not_its_old_words() {
    let dir = TempDir::new().unwrap();
    let sd = spawn(&dir.path().join("board"), true);
    let g = ground(&dir, &sd);
    let f = family(&g);
    let l = g.addr(frames::stage(&f.e2, None));
    page_panel(&g, &f, &l);
    merged_into(&g, &f, &f.e11, &l);
    let reopened = page_panel(&g, &f, &l);
    assert_eq!(reopened["count"]["supersede"], json!([f.e11]), "the re-open's claim off the marker: {reopened}");
    let landed = g.call("merge.land", json!({"session": g.session})).unwrap_or_else(|r| panic!("{r}"));
    let e3 = format!("{}.3", f.edition);
    assert_eq!((landed["outcome"].as_str(), landed["member"].as_str(), landed["supersede"].clone()), (Some("landed"), Some(e3.as_str()), json!([f.e11])), "{landed}");
    assert_holds_the_merge(&g, &e3, "re-opened");
    g.shell.shutdown();
    sd.shutdown();
}

/// Checks that a second compose re-keys a panel read under the first.
///
/// The panel is opened over a draft already carrying the merge of E.1.1, its
/// flag set and its selection M. A second compose lands the merge of E.1.2
/// over it: the landing publishes the second merge's words and claims E.1.2
/// alone (the mutant that re-keys only an unflagged panel holds the first
/// merge's runs, re-stated as moved).
#[test]
fn a_second_compose_re_keys_a_panel_read_under_the_first() {
    let dir = TempDir::new().unwrap();
    let sd = spawn(&dir.path().join("board"), true);
    let g = ground(&dir, &sd);
    let f = family(&g);
    let e12 = another_daughter(&g, &f, " later");
    let l = g.addr(frames::stage(&f.e2, None));
    merged_into(&g, &f, &f.e11, &l);
    let panel = page_panel(&g, &f, &l);
    assert_eq!(panel["count"]["supersede"], json!([f.e11]), "{panel}");
    merged_into(&g, &f, &e12, &l);
    let landed = g.call("merge.land", json!({"session": g.session})).unwrap_or_else(|r| panic!("{r}"));
    let e3 = format!("{}.3", f.edition);
    assert_eq!((landed["outcome"].as_str(), landed["member"].as_str(), landed["supersede"].clone()), (Some("landed"), Some(e3.as_str()), json!([e12])), "the second merge's claim alone: {landed}");
    let text = g.text(&e3, 19);
    assert!(text.starts_with("the fox") && text.contains(" jumps") && text.contains(" later") && !text.contains(" today"), "the second merge's words: {text:?}");
    g.shell.shutdown();
    sd.shutdown();
}

/// Checks that links the merge brought onto a switched-on row are re-stated
/// before they are published (PUB-3.108).
///
/// A note on words L holds makes the row; a second note lies on the
/// daughter's words, which L holds only once the merge lands, so the row
/// the page switched on before the compose never offered it. The landing
/// answers `restated` with that link in `came`, `selection` empty and no
/// `parts`, nothing sent; the panel then counts both, and the next call
/// lands with neither left private (the mutant that drops the re-statement
/// publishes a link the person never saw). With the row left off the
/// landing is the one call and both notes stay private.
#[test]
fn a_row_switched_on_before_the_compose_re_states_the_links_the_merge_brought() {
    let cell = |switched: bool| {
        let dir = TempDir::new().unwrap();
        let sd = spawn(&dir.path().join("board"), true);
        let g = ground(&dir, &sd);
        let f = family(&g);
        let l = g.addr(frames::stage(&f.e2, None));
        let citation = "1.1.0.1.0.1.0.3.13";
        let notes = g.draft("notes here");
        let held = g.addr(json!({"op": "make_link", "home": notes, "from": [{"source": f.e2, "span": {"start": "1.1", "width": "0.3"}}], "to": {"addrs": []}, "ty": {"addrs": [citation]}}));
        let brought = g.addr(json!({"op": "make_link", "home": notes, "from": [{"source": f.e11, "span": {"start": "1.8", "width": "0.6"}}], "to": {"addrs": []}, "ty": {"addrs": [citation]}}));
        let panel = g.call("publication.open", json!({"session": g.session, "draft": l, "doc": f.edition, "notes": [notes], "readable_drafts": [l, notes], "published": [f.edition]})).unwrap_or_else(|r| panic!("{r}"));
        assert_eq!(panel["rows"][0]["links"], json!([held]), "the row offers the note on the words L holds: {panel}");
        if switched {
            g.call("publication.count", json!({"session": g.session, "switches": {"on": [notes]}})).unwrap_or_else(|r| panic!("{r}"));
        }
        merged_into(&g, &f, &f.e11, &l);
        let e3 = format!("{}.3", f.edition);
        let before = g.position();
        let shot = g.call("merge.land", json!({"session": g.session})).unwrap_or_else(|r| panic!("{r}"));
        let landed = if switched {
            crate::shapes::assert_declared("Restated", &shot);
            assert_eq!((shot["outcome"].as_str(), shot["came"].clone(), shot["selection"].clone(), shot.get("parts")), (Some("restated"), json!([brought]), json!([]), None), "{shot}");
            assert_eq!(g.position(), before, "nothing sent");
            let counted = g.call("publication.count", json!({"session": g.session, "switches": {"on": [notes]}})).unwrap_or_else(|r| panic!("{r}"));
            assert_eq!(counted["count"]["l"], 2, "the row now offers both: {counted}");
            assert!([&held, &brought].iter().all(|link| counted["rows"][0]["links"].as_array().unwrap().iter().any(|l| l == *link)), "{counted}");
            g.call("merge.land", json!({"session": g.session})).unwrap_or_else(|r| panic!("{r}"))
        } else {
            shot
        };
        assert_eq!((landed["outcome"].as_str(), landed["member"].as_str(), landed["supersede"].clone()), (Some("landed"), Some(e3.as_str()), json!([f.e11])), "{landed}");
        let private = if switched { json!([]) } else { json!([{"set": notes, "links": 2}]) };
        assert_eq!(landed["left_private"], private, "{landed}");
        assert_holds_the_merge(&g, &e3, "the landing");
        g.shell.shutdown();
        sd.shutdown();
    };
    cell(true);
    cell(false);
}

/// Checks that a re-statement over a re-taken selection names no run
/// index, and no window part, beside the links it states.
///
/// L's own words stand before E's run, and B, composed as the merge's side,
/// windows `O`: the re-taken selection's runs are other runs at other
/// places, so the re-read's run-by-index differences say nothing. The row
/// switched on before the compose takes a note on B's words: the first call
/// re-states that link alone, `selection` empty and no `parts` (the mutant
/// that keeps them names a run and a part that are no such thing), and the
/// next two ask the window and land.
#[test]
fn a_re_statement_over_a_re_taken_selection_names_no_run_and_no_part() {
    let dir = TempDir::new().unwrap();
    let sd = spawn(&dir.path().join("board"), true);
    let g = ground(&dir, &sd);
    let f = family(&g);
    let o = g.draft("quote");
    let b = g.addr(frames::stage(&f.e1, None));
    g.op(json!({"op": "insert", "doc": b, "at": {"subspace": "1", "ordinal": "8"}, "values": [" quietly"], "as_of": g.position()}));
    g.op(json!({"op": "copy", "doc": b, "at": {"subspace": "1", "ordinal": "16"}, "specs": [{"source": o, "span": {"start": "1.1", "width": "0.5"}}], "as_of": g.position()}));
    let l = g.addr(frames::stage(&f.e2, None));
    g.op(json!({"op": "insert", "doc": l, "at": {"subspace": "1", "ordinal": "1"}, "values": ["Very "], "as_of": g.position()}));
    let citation = "1.1.0.1.0.1.0.3.13";
    let notes = g.draft("notes here");
    let held = g.addr(json!({"op": "make_link", "home": notes, "from": [{"source": f.e2, "span": {"start": "1.1", "width": "0.3"}}], "to": {"addrs": []}, "ty": {"addrs": [citation]}}));
    let brought = g.addr(json!({"op": "make_link", "home": notes, "from": [{"source": b, "span": {"start": "1.8", "width": "0.8"}}], "to": {"addrs": []}, "ty": {"addrs": [citation]}}));
    let panel = g.call("publication.open", json!({"session": g.session, "draft": l, "doc": f.edition, "notes": [notes], "readable_drafts": [l, notes], "published": [f.edition]})).unwrap_or_else(|r| panic!("{r}"));
    assert_eq!(panel["rows"][0]["links"], json!([held]), "{panel}");
    g.call("publication.count", json!({"session": g.session, "switches": {"on": [notes]}})).unwrap_or_else(|r| panic!("{r}"));
    let landed = g.call("merge.compose", json!({"session": g.session, "doc": f.edition, "draft": b, "into": l})).unwrap_or_else(|r| panic!("{r}"));
    assert_eq!(landed["outcome"].as_str(), Some("landed"), "{landed}");
    let before = g.position();
    let restated = g.call("merge.land", json!({"session": g.session})).unwrap_or_else(|r| panic!("{r}"));
    crate::shapes::assert_declared("Restated", &restated);
    assert_eq!((restated["outcome"].as_str(), restated["came"].clone(), restated["selection"].clone(), restated.get("parts")), (Some("restated"), json!([brought]), json!([]), None), "{restated}");
    assert_eq!(g.position(), before, "nothing sent");
    let refused = g.call("merge.land", json!({"session": g.session})).unwrap_err();
    assert_eq!(refused.name(), "window_parts_owed", "{refused}");
    let part = refused.to_value()["parts"][0].clone();
    assert_eq!(part["words"].as_str(), Some("quote"), "{part}");
    assert_eq!(g.position(), before, "nothing sent");
    let answers = json!({ format!("{}.{}", part["run"], part["part"]): "keep_private" });
    let shot = g.call("merge.land", json!({"session": g.session, "answers": answers})).unwrap_or_else(|r| panic!("{r}"));
    assert_eq!((shot["outcome"].as_str(), shot["member"].as_str(), shot["left_private"].clone()), (Some("landed"), Some(format!("{}.3", f.edition).as_str()), json!([])), "{shot}");
    g.shell.shutdown();
    sd.shutdown();
}

/// Checks that an answer an earlier panel held is not carried onto another
/// part the merge brought to its key.
///
/// L's panel windows `O` at run 1 and the page answers it. The compose lands
/// B's window onto `O2` as the merge's run 1, the same key, other words: the
/// landing asks it, naming "other", nothing sent (the mutant that keeps the
/// panel's answers composes the part under the answer `O` was given and
/// keeps `O2` private, asked nothing).
#[test]
fn an_answer_an_earlier_panel_held_is_not_carried_onto_another_part() {
    let dir = TempDir::new().unwrap();
    let sd = spawn(&dir.path().join("board"), true);
    let g = ground(&dir, &sd);
    let f = family(&g);
    let (o, o2) = (g.draft("quote"), g.draft("other"));
    let b = g.addr(frames::stage(&f.e1, None));
    g.op(json!({"op": "copy", "doc": b, "at": {"subspace": "1", "ordinal": "8"}, "specs": [{"source": o2, "span": {"start": "1.1", "width": "0.5"}}], "as_of": g.position()}));
    let l = g.addr(frames::stage(&f.e2, None));
    g.op(json!({"op": "copy", "doc": l, "at": {"subspace": "1", "ordinal": "14"}, "specs": [{"source": o, "span": {"start": "1.1", "width": "0.5"}}], "as_of": g.position()}));
    let panel = g.call("publication.open", json!({"session": g.session, "draft": l, "doc": f.edition, "readable_drafts": [l], "published": [f.edition]})).unwrap_or_else(|r| panic!("{r}"));
    assert_eq!((panel["windows"][0]["run"].as_u64(), panel["windows"][0]["origin"].as_str()), (Some(1), Some(o.as_str())), "{panel}");
    g.call("publication.count", json!({"session": g.session, "answers": {"1.0": "keep_private"}})).unwrap_or_else(|r| panic!("{r}"));
    let landed = g.call("merge.compose", json!({"session": g.session, "doc": f.edition, "draft": b, "into": l})).unwrap_or_else(|r| panic!("{r}"));
    assert_eq!(landed["outcome"].as_str(), Some("landed"), "{landed}");
    let before = g.position();
    let refused = g.call("merge.land", json!({"session": g.session})).unwrap_err();
    assert_eq!(refused.name(), "window_parts_owed", "{refused}");
    let v = refused.to_value();
    assert_eq!((v["parts"][0]["run"].as_u64(), v["parts"][0]["part"].as_u64(), v["parts"][0]["words"].as_str(), v["parts"][0]["origin"].as_str()), (Some(1), Some(0), Some("other"), Some(o2.as_str())), "the merge's part at the same key: {v}");
    assert_eq!(g.position(), before, "nothing sent");
    g.shell.shutdown();
    sd.shutdown();
}

/// Checks that a landing over an earlier panel asks the window the merge
/// brought as a panel opened over the merge would.
///
/// B windows `O`, a draft no record names, and is composed as the merge's
/// side into L, whose panel was opened before: the landing refuses
/// `window_parts_owed` naming the part and sends nothing, and given
/// `keep_private` lands (the mutant that keeps the windows the open read
/// composes no part to ask, its answer refused as no part the panel holds).
#[test]
fn a_landing_over_an_earlier_panel_asks_the_window_the_merge_brought() {
    let dir = TempDir::new().unwrap();
    let sd = spawn(&dir.path().join("board"), true);
    let g = ground(&dir, &sd);
    let f = family(&g);
    let o = g.draft("quote");
    let b = g.addr(frames::stage(&f.e1, None));
    g.op(json!({"op": "insert", "doc": b, "at": {"subspace": "1", "ordinal": "8"}, "values": [" quietly"], "as_of": g.position()}));
    g.op(json!({"op": "copy", "doc": b, "at": {"subspace": "1", "ordinal": "16"}, "specs": [{"source": o, "span": {"start": "1.1", "width": "0.5"}}], "as_of": g.position()}));
    let l = g.addr(frames::stage(&f.e2, None));
    page_panel(&g, &f, &l);
    let landed = g.call("merge.compose", json!({"session": g.session, "doc": f.edition, "draft": b, "into": l})).unwrap_or_else(|r| panic!("{r}"));
    assert_eq!(landed["outcome"].as_str(), Some("landed"), "{landed}");
    let before = g.position();
    let refused = g.call("merge.land", json!({"session": g.session})).unwrap_err();
    assert_eq!(refused.name(), "window_parts_owed", "{refused}");
    let v = refused.to_value();
    let part = v["parts"][0].clone();
    assert_eq!((part["words"].as_str(), part["origin"].as_str()), (Some("quote"), Some(o.as_str())), "{v}");
    assert_eq!(g.position(), before, "nothing sent");
    let answers = json!({ format!("{}.{}", part["run"], part["part"]): "keep_private" });
    let shot = g.call("merge.land", json!({"session": g.session, "answers": answers})).unwrap_or_else(|r| panic!("{r}"));
    assert_eq!((shot["outcome"].as_str(), shot["member"].as_str()), (Some("landed"), Some(format!("{}.3", f.edition).as_str())), "{shot}");
    g.shell.shutdown();
    sd.shutdown();
}

/// Returns the `publication` events seen once one of them says `state`.
///
/// Each is its draft and its state. The events are copied in order on the
/// answerer's thread, so every one said before it has arrived by then.
fn said_once(g: &Ground, state: &str) -> Vec<(String, String)> {
    let text = |v: &Value| v.as_str().unwrap_or("?").to_string();
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        let said: Vec<(String, String)> = g.seen.lock().unwrap().iter().filter(|e| e.name == EventName::Publication).map(|e| (text(&e.data["draft"]), text(&e.data["state"]))).collect();
        if said.iter().any(|(_, s)| s == state) {
            return said;
        }
        assert!(Instant::now() < deadline, "no `{state}` was said: {said:?}");
        thread::sleep(Duration::from_millis(20));
    }
}

/// Checks a landing over a mint-form panel of the draft, refused by name.
///
/// L is staged from the head, and a notes draft holds a note on E.2's
/// words: a mint-form panel over L with the notes row switched on stands
/// when the merge of E.2 with E.1.1 lands in L. `merge.land` is refused
/// exactly `other_panel` naming L and the account the panel mints under,
/// nothing sent and no event said; the panel re-opens standing, its row
/// still switched on. Cancelled, the next `merge.land` opens its own panel
/// at E and lands E.3 with the claim and the merge's record (the mutants
/// that take the panel, minting an edition answered `landed` as a daughter
/// with no record; that drop it and open their own, landing in one call;
/// and that refuse another document alone, letting the mint form through).
#[test]
fn a_landing_over_a_mint_form_panel_of_the_draft_is_refused_and_lands_once_the_panel_is_cancelled() {
    let dir = TempDir::new().unwrap();
    let sd = spawn(&dir.path().join("board"), true);
    let g = ground(&dir, &sd);
    let f = family(&g);
    let l = g.addr(frames::stage(&f.e2, None));
    let notes = g.draft("notes here");
    let note = g.addr(json!({"op": "make_link", "home": notes, "from": [{"source": f.e2, "span": {"start": "1.1", "width": "0.3"}}], "to": {"addrs": []}, "ty": {"addrs": ["1.1.0.1.0.1.0.3.13"]}}));
    let open = json!({"session": g.session, "draft": l, "mint": "1.0.1", "notes": [notes], "readable_drafts": [l, notes], "published": [f.edition]});
    let panel = g.call("publication.open", open.clone()).unwrap_or_else(|r| panic!("{r}"));
    assert_eq!((panel.get("standing"), panel["rows"][0]["links"].clone()), (None, json!([note])), "the premise: a mint-form panel offering the note: {panel}");
    g.call("publication.count", json!({"session": g.session, "switches": {"on": [notes]}})).unwrap_or_else(|r| panic!("{r}"));
    merged_into(&g, &f, &f.e11, &l);
    let before = g.position();
    let refused = g.call("merge.land", json!({"session": g.session})).unwrap_err().to_value();
    crate::shapes::assert_declared("OtherPanelRefusal", &refused);
    assert_eq!(refused, json!({"kind": "shell", "name": "other_panel", "draft": l, "mint": "1.0.1"}), "{refused}");
    assert_eq!(g.position(), before, "nothing sent");
    let reopened = g.call("publication.open", open).unwrap_or_else(|r| panic!("{r}"));
    assert_eq!((reopened.get("hold"), reopened["count"]["l"].as_u64()), (None, Some(1)), "the panel standing as it stood, its row switched on: {reopened}");
    g.call("publication.cancel", json!({"session": g.session})).unwrap();
    let said: Vec<String> = said_once(&g, "cancelled").into_iter().filter(|(d, _)| *d == l).map(|(_, s)| s).collect();
    assert_eq!(said, ["cancelled"], "no event of L's but the cancel's");
    let landed = g.call("merge.land", json!({"session": g.session})).unwrap_or_else(|r| panic!("{r}"));
    crate::shapes::assert_declared("MergeLanded", &landed);
    let e3 = format!("{}.3", f.edition);
    assert_eq!((landed["member"].as_str(), landed["daughter"].as_bool(), landed["supersede"].clone()), (Some(e3.as_str()), Some(false), json!([f.e11])), "{landed}");
    assert!(landed["record"].is_string() && landed.get("unrecorded").is_none(), "the merge's record: {landed}");
    assert_holds_the_merge(&g, &e3, "landed once the panel was cancelled");
    g.shell.shutdown();
    sd.shutdown();
}

/// Checks a landing over a panel of the draft over another document.
///
/// The merge of E.2 with E.1.1 lands in L, and L is then published at the
/// mint form, minting E′ and moving L's base to E′.1. With a word written
/// in L, L's panel over E′ stands when `merge.land` is called: refused
/// exactly `other_panel` naming L and E′, nothing sent (the mutant that
/// refuses the mint form alone publishes E′.2, answered `landed` as a
/// daughter with its record `unrecorded`). The panel cancelled, the row
/// opens its own over E and is refused `base_unrecorded` naming L, E and
/// `other_chain`, nothing sent.
#[test]
fn a_landing_over_a_panel_of_the_draft_over_another_document_is_refused_naming_it() {
    let dir = TempDir::new().unwrap();
    let sd = spawn(&dir.path().join("board"), true);
    let g = ground(&dir, &sd);
    let f = family(&g);
    let l = g.addr(frames::stage(&f.e2, None));
    merged_into(&g, &f, &f.e11, &l);
    g.call("publication.open", json!({"session": g.session, "draft": l, "mint": "1.0.1", "readable_drafts": [l], "published": [f.edition]})).unwrap_or_else(|r| panic!("{r}"));
    let minted = g.call("publication.confirm", json!({"session": g.session})).unwrap_or_else(|r| panic!("{r}"));
    let other = minted["edition"].as_str().unwrap_or_else(|| panic!("L published at the mint form: {minted}")).to_string();
    g.op(json!({"op": "insert", "doc": l, "at": {"subspace": "1", "ordinal": "20"}, "values": [" now"], "as_of": g.position()}));
    let panel = g.call("publication.open", json!({"session": g.session, "draft": l, "doc": other, "readable_drafts": [l], "published": [f.edition, other]})).unwrap_or_else(|r| panic!("{r}"));
    assert_eq!(panel["standing"], "at_head", "the premise: L's panel over E′, at its head: {panel}");
    let before = g.position();
    let refused = g.call("merge.land", json!({"session": g.session})).unwrap_err().to_value();
    crate::shapes::assert_declared("OtherPanelRefusal", &refused);
    assert_eq!(refused, json!({"kind": "shell", "name": "other_panel", "draft": l, "doc": other}), "{refused}");
    assert_eq!(g.position(), before, "nothing sent");
    g.call("publication.cancel", json!({"session": g.session})).unwrap();
    let unrecorded = g.call("merge.land", json!({"session": g.session})).unwrap_err().to_value();
    assert_eq!(
        (unrecorded["name"].as_str(), unrecorded["draft"].as_str(), unrecorded["doc"].as_str(), unrecorded["reason"].as_str()),
        (Some("base_unrecorded"), Some(l.as_str()), Some(f.edition.as_str()), Some("other_chain")),
        "the draft left the trunk's chain: {unrecorded}"
    );
    assert_eq!(g.position(), before, "nothing sent");
    g.shell.shutdown();
    sd.shutdown();
}

/// Checks a landing over a held mint-form panel, every panel as it stood.
///
/// A mint-form panel over L is put behind one over another draft X, and the
/// merge of E.2 with E.1.1 then lands in L: `merge.land` is refused
/// `other_panel` naming L, nothing sent. X's panel still stands,
/// `publication.cancel` saying `cancelled` of X and no event of L's, and
/// L's re-opens with its hold's `since` (the mutant that stands the panel
/// before testing it puts X behind and cancels L's).
#[test]
fn a_landing_over_a_held_mint_form_panel_is_refused_and_every_panel_stands_as_it_stood() {
    let dir = TempDir::new().unwrap();
    let sd = spawn(&dir.path().join("board"), true);
    let g = ground(&dir, &sd);
    let f = family(&g);
    let l = g.addr(frames::stage(&f.e2, None));
    let x = g.draft("elsewhere");
    let mint = |draft: &str| json!({"session": g.session, "draft": draft, "mint": "1.0.1", "readable_drafts": [draft], "published": [f.edition]});
    g.call("publication.open", mint(&l)).unwrap_or_else(|r| panic!("{r}"));
    g.call("publication.open", mint(&x)).unwrap_or_else(|r| panic!("{r}"));
    merged_into(&g, &f, &f.e11, &l);
    let before = g.position();
    let refused = g.call("merge.land", json!({"session": g.session})).unwrap_err().to_value();
    assert_eq!(refused, json!({"kind": "shell", "name": "other_panel", "draft": l, "mint": "1.0.1"}), "{refused}");
    assert_eq!(g.position(), before, "nothing sent");
    g.call("publication.cancel", json!({"session": g.session})).unwrap();
    let said = said_once(&g, "cancelled");
    let of_the_two: Vec<(&str, &str)> = said.iter().filter(|(d, _)| *d == x || *d == l).map(|(d, s)| (d.as_str(), s.as_str())).collect();
    assert_eq!(of_the_two, [(x.as_str(), "cancelled")], "X's panel stood and was cancelled, L's untouched");
    let reopened = g.call("publication.open", mint(&l)).unwrap_or_else(|r| panic!("{r}"));
    assert!(reopened["hold"]["since"].is_u64(), "L's panel held as it stood: {reopened}");
    g.shell.shutdown();
    sd.shutdown();
}

/// Checks the draft side against the daemon.
///
/// B, staged from E.1 and behind the head E.2 with words of its own,
/// composes as the merge's side into L, a level draft: landed, L's marker
/// naming B — a private draft — and the report's draft side carrying the
/// position it was read at; L's `publication.open` carries no claim. B
/// written since, the re-open reads the side AS COMPOSE READ IT — the
/// draft side's position the marker's, the runs the first report's, B's
/// new words nowhere in them — and lands nothing. `merge.land` opens the
/// panel itself, B named `also`, and lands E.3 holding both sides' words
/// with NO claim, `supersede []` (the mutants that claim a private draft,
/// read a moved side as it stands, or drop `also` and window B's words).
#[test]
fn the_draft_side_composes_and_lands_with_no_claim_and_its_re_open_reads_the_side_as_merged() {
    use skep_client::board::frames::doc_metadata;
    let dir = TempDir::new().unwrap();
    let sd = spawn(&dir.path().join("board"), true);
    let g = ground(&dir, &sd);
    let f = family(&g);
    let b = g.addr(skep_client::board::frames::stage(&f.e1, None));
    g.op(json!({"op": "insert", "doc": b, "at": {"subspace": "1", "ordinal": "8"}, "values": [" quietly"], "as_of": g.position()}));
    let l = g.addr(skep_client::board::frames::stage(&f.e2, None));
    let compose = || g.call("merge.compose", json!({"session": g.session, "doc": f.edition, "draft": b, "into": l})).unwrap_or_else(|r| panic!("{r}"));
    let landed = compose();
    assert_report_declared(&landed);
    assert_eq!((landed["outcome"].as_str(), landed["form"].as_str(), landed["side"].as_str(), landed["into"].as_str()), (Some("landed"), Some("draft"), Some(b.as_str()), Some(l.as_str())), "{landed}");
    assert_eq!((landed["sides"][1]["at"].as_str(), landed["sides"][1]["role"].as_str(), landed["sides"][1]["position"].as_u64()), (Some(b.as_str()), Some("draft"), Some(landed["as_of"].as_u64().unwrap())), "{landed}");
    let marker = g.op(doc_metadata(&l))["merge"].clone();
    assert_eq!((marker["sides"].clone(), marker["head"].as_str()), (json!([b]), Some(f.e2.as_str())), "{marker}");
    let text = g.text(&l, 21);
    assert!(text.contains(" jumps") && text.contains(" quietly") && text.len() == 21, "{text:?}");
    let panel = g.call("publication.open", json!({"session": g.session, "draft": l, "doc": f.edition, "readable_drafts": [l, b], "published": [f.edition]})).unwrap_or_else(|r| panic!("{r}"));
    assert_eq!(panel["count"]["supersede"], json!([]), "a draft-side marker carries no claim: {panel}");
    g.call("publication.cancel", json!({"session": g.session})).unwrap();
    // B moves; the re-open reads it as merged.
    g.op(json!({"op": "insert", "doc": b, "at": {"subspace": "1", "ordinal": "16"}, "values": [" again"], "as_of": g.position()}));
    let before = g.position();
    let reopened = compose();
    assert_eq!((reopened["outcome"].as_str(), reopened["sides"][1]["position"].as_u64(), reopened["position"].as_u64()), (Some("reopened"), marker["at"].as_u64(), marker["at"].as_u64()), "the side at the marker's position: {reopened}");
    assert_eq!(reopened["runs"], landed["runs"], "the side as compose read it, B's new words nowhere");
    assert_eq!(g.position(), before, "nothing landed");
    // The landing on the trunk: no claim.
    let landed = g.call("merge.land", json!({"session": g.session})).unwrap_or_else(|r| panic!("{r}"));
    crate::shapes::assert_declared("MergeLanded", &landed);
    let e3 = format!("{}.3", f.edition);
    assert_eq!((landed["member"].as_str(), landed["supersede"].clone(), landed["daughter"].as_bool()), (Some(e3.as_str()), json!([]), Some(false)), "{landed}");
    assert!(landed["record"].is_string(), "{landed}");
    let text = g.text(&e3, 21);
    assert!(text.contains(" jumps") && text.contains(" quietly") && text.len() == 21, "both sides' words, B's as the document's own: {text:?}");
    g.shell.shutdown();
    sd.shutdown();
}

/// Checks that a landing over a window a record names refuses by name.
///
/// B, staged from E.1, windows `O`, a draft of the person's, beside words
/// of its own, and composes as the merge's side into L; `O` is then
/// published at the mint form, so a record names its words as the new
/// edition's. `merge.land`, opening the panel itself, composes no answer it
/// was not given: the shot refuses `window_parts_owed`, final in meaning,
/// the part named — its words, its pair, its origin, the sides showing it —
/// nothing sent (skep #932; B3-S11 P2 (i): no placeholder over published
/// words). The landing follows the publication at once, and holds whether
/// or not the document index has listed `O`. The refusal is the panel's
/// `inert` nowhere: the page reads a landing's answer, not an open panel's.
#[test]
fn a_landing_over_a_window_a_record_names_refuses_naming_the_part() {
    let dir = TempDir::new().unwrap();
    let sd = spawn(&dir.path().join("board"), true);
    let g = ground(&dir, &sd);
    let f = family(&g);
    let o = g.draft("quote");
    let b = g.addr(skep_client::board::frames::stage(&f.e1, None));
    g.op(json!({"op": "insert", "doc": b, "at": {"subspace": "1", "ordinal": "8"}, "values": [" quietly"], "as_of": g.position()}));
    g.op(json!({"op": "copy", "doc": b, "at": {"subspace": "1", "ordinal": "16"}, "specs": [{"source": o, "span": {"start": "1.1", "width": "0.5"}}], "as_of": g.position()}));
    let l = g.addr(skep_client::board::frames::stage(&f.e2, None));
    let landed = g.call("merge.compose", json!({"session": g.session, "doc": f.edition, "draft": b, "into": l})).unwrap_or_else(|r| panic!("{r}"));
    assert_eq!(landed["outcome"].as_str(), Some("landed"), "{landed}");
    assert!(g.text(&l, 26).contains("quote"), "L windows O's words: {:?}", g.text(&l, 26));
    g.call("publication.open", json!({"session": g.session, "draft": o, "mint": "1.0.1", "readable_drafts": [o], "published": [f.edition]})).unwrap_or_else(|r| panic!("{r}"));
    let minted = g.call("publication.confirm", json!({"session": g.session})).unwrap_or_else(|r| panic!("{r}"));
    assert!(minted["edition"].is_string(), "O published at the mint form: {minted}");
    let before = g.position();
    let refusal = g.call("merge.land", json!({"session": g.session})).unwrap_err();
    assert_eq!(refusal.name(), "window_parts_owed", "{refusal}");
    let v = refusal.to_value();
    crate::shapes::assert_declared("WindowPartsOwedRefusal", &v);
    let parts = v["parts"].as_array().unwrap_or_else(|| panic!("the parts: {v}"));
    assert_eq!(parts.len(), 1, "{v}");
    crate::shapes::assert_declared("WindowPart", &parts[0]);
    assert_eq!((parts[0]["words"].as_str(), parts[0]["origin"].as_str(), parts[0]["admits"].clone()), (Some("quote"), Some(o.as_str()), json!(["counterpart", "drop"])), "the part a record names: {v}");
    assert!(parts[0]["record"].is_string() && parts[0]["counterpart"].is_object(), "the pair: {v}");
    assert_eq!(g.position(), before, "nothing sent");
    g.shell.shutdown();
    sd.shutdown();
}

/// Checks that a landing over the page's panel names a part whatever the
/// page listed.
///
/// As above, B windows `O` and composes as the merge's side into L, and
/// `O` is then published, so a record names its words. The page opens L's
/// panel itself, B named `also` and `readable_drafts` leaving `O` out: the
/// window's one part is named all the same, admitting the counterpart and
/// `drop`. `merge.land` takes the page's panel, the part unanswered, and
/// refuses `window_parts_owed` naming the part, nothing sent (B3-S11 P2
/// (i); the link-sets design §5.5).
#[test]
fn a_landing_over_a_page_panel_that_lists_no_origin_still_names_the_part() {
    let dir = TempDir::new().unwrap();
    let sd = spawn(&dir.path().join("board"), true);
    let g = ground(&dir, &sd);
    let f = family(&g);
    let o = g.draft("quote");
    let b = g.addr(skep_client::board::frames::stage(&f.e1, None));
    g.op(json!({"op": "insert", "doc": b, "at": {"subspace": "1", "ordinal": "8"}, "values": [" quietly"], "as_of": g.position()}));
    g.op(json!({"op": "copy", "doc": b, "at": {"subspace": "1", "ordinal": "16"}, "specs": [{"source": o, "span": {"start": "1.1", "width": "0.5"}}], "as_of": g.position()}));
    let l = g.addr(skep_client::board::frames::stage(&f.e2, None));
    let landed = g.call("merge.compose", json!({"session": g.session, "doc": f.edition, "draft": b, "into": l})).unwrap_or_else(|r| panic!("{r}"));
    assert_eq!(landed["outcome"].as_str(), Some("landed"), "{landed}");
    g.call("publication.open", json!({"session": g.session, "draft": o, "mint": "1.0.1", "readable_drafts": [o], "published": [f.edition]})).unwrap_or_else(|r| panic!("{r}"));
    let minted = g.call("publication.confirm", json!({"session": g.session})).unwrap_or_else(|r| panic!("{r}"));
    assert!(minted["edition"].is_string(), "O published at the mint form: {minted}");
    let open = json!({"session": g.session, "draft": l, "doc": f.edition, "also": [b], "readable_drafts": [l, b], "published": [f.edition]});
    let panel = g.call("publication.open", open).unwrap_or_else(|r| panic!("{r}"));
    let windows = panel["windows"].as_array().unwrap_or_else(|| panic!("the windows: {panel}"));
    assert!(windows.len() == 1 && windows[0]["origin"] == o, "the one window, onto O: {panel}");
    let parts = windows[0]["parts"].as_array().unwrap_or_else(|| panic!("its parts: {panel}"));
    assert!(parts.len() == 1 && parts[0]["record"].is_string() && parts[0]["admits"] == json!(["counterpart", "drop"]), "one part the record names: {panel}");
    let before = g.position();
    let refusal = g.call("merge.land", json!({"session": g.session})).unwrap_err();
    assert_eq!(refusal.name(), "window_parts_owed", "{refusal}");
    let v = refusal.to_value();
    crate::shapes::assert_declared("WindowPartsOwedRefusal", &v);
    assert_eq!(v["parts"].as_array().map(Vec::len), Some(1), "{v}");
    assert_eq!(g.position(), before, "nothing sent");
    g.shell.shutdown();
    sd.shutdown();
}

/// Checks that a part no record names is asked, never kept private, and that
/// answers compose as the panel's.
///
/// B windows `O`, a draft of the person's no record names. `merge.land`
/// refuses `window_parts_owed` naming the part's three answers, nothing
/// sent; given `keep_private` it lands, the member holding the window and
/// the acknowledgment naming the answer, its private rows left private and
/// the merge's defaults taken. The same answers through the page's panel
/// compose the same member (skep #932: the one request, the shared core).
#[test]
fn a_part_no_record_names_is_asked_and_its_answer_composes_as_the_panels() {
    let compose = |dir: &TempDir, sd: &Skepd, panel_route: bool| -> Vec<(String, String)> {
        let g = ground(dir, sd);
        let f = family(&g);
        let o = g.draft("quote");
        let b = g.addr(skep_client::board::frames::stage(&f.e1, None));
        g.op(json!({"op": "insert", "doc": b, "at": {"subspace": "1", "ordinal": "8"}, "values": [" quietly"], "as_of": g.position()}));
        g.op(json!({"op": "copy", "doc": b, "at": {"subspace": "1", "ordinal": "16"}, "specs": [{"source": o, "span": {"start": "1.1", "width": "0.5"}}], "as_of": g.position()}));
        let l = g.addr(skep_client::board::frames::stage(&f.e2, None));
        let landed = g.call("merge.compose", json!({"session": g.session, "doc": f.edition, "draft": b, "into": l})).unwrap_or_else(|r| panic!("{r}"));
        assert_eq!(landed["outcome"].as_str(), Some("landed"), "{landed}");
        let before = g.position();
        let refused = g.call("merge.land", json!({"session": g.session})).unwrap_err();
        assert_eq!(refused.name(), "window_parts_owed", "{refused}");
        let v = refused.to_value();
        crate::shapes::assert_declared("WindowPartsOwedRefusal", &v);
        let part = v["parts"][0].clone();
        assert_eq!((part["words"].as_str(), part["record"].clone(), part["admits"].clone()), (Some("quote"), Value::Null, json!(["publish_first", "drop", "keep_private"])), "{v}");
        assert_eq!(g.position(), before, "nothing sent");
        let key = format!("{}.{}", part["run"], part["part"]);
        let answers = json!({ key: "keep_private" });
        let member = if panel_route {
            let open = json!({"session": g.session, "draft": l, "doc": f.edition, "also": [b], "readable_drafts": [l, b], "published": [f.edition]});
            g.call("publication.open", open).unwrap_or_else(|r| panic!("{r}"));
            let acked = g.call("publication.confirm", json!({"session": g.session, "answers": answers})).unwrap_or_else(|r| panic!("{r}"));
            acked["member"].as_str().expect("the member").to_string()
        } else {
            let landed = g.call("merge.land", json!({"session": g.session, "answers": answers})).unwrap_or_else(|r| panic!("{r}"));
            crate::shapes::assert_declared("MergeLanded", &landed);
            assert_eq!(landed["answers"].as_array().map(Vec::len), Some(1), "the answer named: {landed}");
            crate::shapes::assert_declared("WindowPart", &landed["answers"][0]);
            assert_eq!(landed["answers"][0]["answer"], "keep_private", "{landed}");
            assert!(landed["left_private"].is_array() && landed["defaults"].is_array(), "{landed}");
            landed["member"].as_str().expect("the member").to_string()
        };
        let image = g.op(frames::image(&member, 1, 26));
        let runs = image["runs"].as_array().unwrap_or_else(|| panic!("the image: {image}"));
        assert!(runs.iter().any(|r| r["i_start"].as_str().is_some_and(|i| i.starts_with(&o))), "the member windows O: {image}");
        g.shell.shutdown();
        runs.iter().map(|r| (r["i_start"].as_str().unwrap().to_string(), r["width"].as_str().unwrap().to_string())).collect()
    };
    let dir_a = TempDir::new().unwrap();
    let sd_a = spawn(&dir_a.path().join("board"), true);
    let landed = compose(&dir_a, &sd_a, false);
    sd_a.shutdown();
    let dir_b = TempDir::new().unwrap();
    let sd_b = spawn(&dir_b.path().join("board"), true);
    let paneled = compose(&dir_b, &sd_b, true);
    sd_b.shutdown();
    assert_eq!(landed, paneled, "the same request through either route");
}

/// Checks the merged arm's record written once where the page's own slot
/// published the merge, against the daemon.
///
/// L takes the merge of E.2 with E.1.1 (the landing's record names L);
/// the page takes the publish slot itself — `publication.open` carrying the
/// claim, `confirm` acknowledged E.3 — which writes no merge record of the
/// member. `merge.compose` of the daughter then answers MERGED, naming E.3,
/// and WRITES the missing record — its link new, the board's position
/// moved by the record's two writes; a second `merge.compose` names the
/// same record, nothing written (the mutants that re-land a merged
/// daughter, skip the record, or write it again).
#[test]
fn merged_names_the_member_and_writes_a_missing_record_once() {
    let dir = TempDir::new().unwrap();
    let sd = spawn(&dir.path().join("board"), true);
    let g = ground(&dir, &sd);
    let f = family(&g);
    let l = g.addr(skep_client::board::frames::stage(&f.e2, None));
    let landed = g.call("merge.compose", json!({"session": g.session, "doc": f.edition, "alternative": f.e11, "into": l})).unwrap_or_else(|r| panic!("{r}"));
    let landing_record = landed["record_link"].as_str().unwrap().to_string();
    let panel = g.call("publication.open", json!({"session": g.session, "draft": l, "doc": f.edition, "readable_drafts": [l], "published": [f.edition]})).unwrap_or_else(|r| panic!("{r}"));
    assert_eq!(panel["count"]["supersede"], json!([f.e11]), "{panel}");
    let acked = g.call("publication.confirm", json!({"session": g.session})).unwrap_or_else(|r| panic!("{r}"));
    let e3 = format!("{}.3", f.edition);
    assert_eq!((acked["member"].as_str(), acked["supersede"].clone()), (Some(e3.as_str()), json!([f.e11])), "{acked}");
    let before = g.position();
    let merged = g.call("merge.compose", json!({"session": g.session, "doc": f.edition, "alternative": f.e11})).unwrap_or_else(|r| panic!("{r}"));
    assert_report_declared(&merged);
    assert_eq!((merged["outcome"].as_str(), merged["member"].as_str()), (Some("merged"), Some(e3.as_str())), "{merged}");
    let record = merged["record_link"].as_str().expect("the record written").to_string();
    assert_ne!(record, landing_record, "a record of the member's landing, not the draft's");
    assert!(g.position() > before, "the record's writes");
    assert_eq!(merged["claims"].as_array().map(Vec::len), Some(1), "{merged}");
    let after = g.position();
    let again = g.call("merge.compose", json!({"session": g.session, "doc": f.edition, "alternative": f.e11})).unwrap_or_else(|r| panic!("{r}"));
    assert_eq!((again["outcome"].as_str(), again["record_link"].as_str()), (Some("merged"), Some(record.as_str())), "{again}");
    assert_eq!((again["record"]["landed"]["member"].as_str(), g.position()), (Some(e3.as_str()), after), "the standing record, nothing written again: {again}");
    g.shell.shutdown();
    sd.shutdown();
}

/// Checks that another account's record of its own draft is never re-opened.
///
/// Against the daemon: another account stages a draft of its own from E.2,
/// lands the merge of E.2 with E.1.1 in it by hand — its marker naming E.1.1
/// under E.2 — and writes a record of the claimant's kind naming that draft as
/// landed in, which the composition reads as its `prior`. `merge.compose` with
/// no `into` lands in a fresh draft of the claimant's staged from the head,
/// `fresh` true, and their draft stands as they left it (the mutant that takes
/// the `prior` for the person's own record answers the re-open into the other
/// account's draft).
#[test]
fn another_accounts_record_naming_its_own_draft_is_never_re_opened() {
    let dir = TempDir::new().unwrap();
    let sd = spawn(&dir.path().join("board"), true);
    let g = ground(&dir, &sd);
    let f = family(&g);
    let other = other_account(&g);
    let merged = composed(&g, &f);
    let theirs = written(&g, &other.token, &frames::stage(&f.e2, None))["addr"].as_str().unwrap().to_string();
    let at = mark(&g, &other.token, &theirs, &merged, &f.e11);
    let link = record_of_the_kind(&g, &other, &merged, RecordLanding::Draft { draft: parse_address(&theirs).unwrap(), position: at }, &f.e11);
    assert_prior_is(&g, &f, &link);
    let marker = g.op(frames::doc_metadata(&theirs))["merge"].clone();
    assert_eq!((marker["sides"].clone(), marker["head"].as_str()), (json!([f.e11]), Some(f.e2.as_str())), "the premise: their draft carries the merge: {marker}");
    let report = g.call("merge.compose", json!({"session": g.session, "doc": f.edition, "alternative": f.e11})).unwrap_or_else(|r| panic!("{r}"));
    assert_report_declared(&report);
    assert_eq!((report["outcome"].as_str(), report["fresh"].as_bool()), (Some("landed"), Some(true)), "{report}");
    let fresh = report["into"].as_str().expect("the fresh draft").to_string();
    assert_ne!(fresh, theirs, "{report}");
    let meta = g.op(frames::doc_metadata(&fresh));
    assert_eq!((meta["owner"].as_str(), meta["merge"]["sides"].clone()), (Some("1.0.1"), json!([f.e11])), "the person's own draft, marked: {meta}");
    assert_eq!(g.op(frames::doc_metadata(&theirs))["merge"], marker, "their draft as they left it");
    g.shell.shutdown();
    sd.shutdown();
}

/// Checks that another account's record never steers the person's landing.
///
/// Against the daemon: the claimant stages L from E.2, which carries no merge;
/// another account writes a record of the claimant's kind naming L as landed
/// in, the composition's `prior`. `merge.compose` with no `into` lands in a
/// fresh draft staged from the head, `fresh` true, and L stands as it was:
/// E.2's words, no marker, no arrangement row since (the mutant that lands in
/// the draft the `prior` names wherever the person owns it writes M over L).
#[test]
fn another_accounts_record_naming_the_persons_draft_never_steers_the_landing_into_it() {
    let dir = TempDir::new().unwrap();
    let sd = spawn(&dir.path().join("board"), true);
    let g = ground(&dir, &sd);
    let f = family(&g);
    let other = other_account(&g);
    let merged = composed(&g, &f);
    let l = g.addr(frames::stage(&f.e2, None));
    let link = record_of_the_kind(&g, &other, &merged, RecordLanding::Draft { draft: parse_address(&l).unwrap(), position: g.position() }, &f.e11);
    assert_prior_is(&g, &f, &link);
    let since = g.position();
    let report = g.call("merge.compose", json!({"session": g.session, "doc": f.edition, "alternative": f.e11})).unwrap_or_else(|r| panic!("{r}"));
    assert_eq!((report["outcome"].as_str(), report["fresh"].as_bool()), (Some("landed"), Some(true)), "{report}");
    assert_ne!(report["into"].as_str(), Some(l.as_str()), "{report}");
    assert_eq!(g.text(&l, 13), "the fox jumps", "L's words E.2's");
    assert!(g.op(frames::doc_metadata(&l))["merge"].is_null(), "no marker on L");
    assert!(arrangement_rows(&g, &l, since).is_empty(), "nothing written into L");
    g.shell.shutdown();
    sd.shutdown();
}

/// Checks that the merged arm writes the person's own record of the member.
///
/// Against the daemon: the claimant lands the merge of E.2 with E.1.1 in L by
/// hand, writing no record, and publishes L as E.3 through the panel, the claim
/// riding; another account writes a record of the claimant's kind naming E.3 as
/// landed in, the composition's `prior`. `merge.compose` of the daughter
/// answers merged, naming E.3, and writes the person's own record — its link
/// homed in a private journal of the claimant's, never its doc 1, the board's
/// position moved; a second `merge.compose` names that record, nothing
/// written (the mutant that takes the `prior` naming the member for the
/// person's own answers the other account's record and writes none).
#[test]
fn merged_writes_the_persons_own_record_where_only_another_accounts_names_the_member() {
    let dir = TempDir::new().unwrap();
    let sd = spawn(&dir.path().join("board"), true);
    let g = ground(&dir, &sd);
    let f = family(&g);
    let other = other_account(&g);
    let merged = composed(&g, &f);
    let l = g.addr(frames::stage(&f.e2, None));
    mark(&g, &bare(&g, 1), &l, &merged, &f.e11);
    let panel = g.call("publication.open", json!({"session": g.session, "draft": l, "doc": f.edition, "readable_drafts": [l], "published": [f.edition]})).unwrap_or_else(|r| panic!("{r}"));
    assert_eq!(panel["count"]["supersede"], json!([f.e11]), "{panel}");
    let acked = g.call("publication.confirm", json!({"session": g.session})).unwrap_or_else(|r| panic!("{r}"));
    let e3 = format!("{}.3", f.edition);
    assert_eq!((acked["member"].as_str(), acked["supersede"].clone()), (Some(e3.as_str()), json!([f.e11])), "{acked}");
    let landed = RecordLanding::Member { member: parse_address(&e3).unwrap(), position: acked["at"].as_u64().unwrap() };
    let theirs = record_of_the_kind(&g, &other, &merged, landed, &f.e11);
    assert_prior_is(&g, &f, &theirs);
    let before = g.position();
    let answer = g.call("merge.compose", json!({"session": g.session, "doc": f.edition, "alternative": f.e11})).unwrap_or_else(|r| panic!("{r}"));
    assert_report_declared(&answer);
    assert_eq!((answer["outcome"].as_str(), answer["member"].as_str()), (Some("merged"), Some(e3.as_str())), "{answer}");
    let record = answer["record_link"].as_str().expect("the record written").to_string();
    assert_ne!(record, theirs, "{answer}");
    let journal = document_of(&record).expect("the record's journal");
    assert_eq!((account_of(&record), journal.as_str() == KIND), (account_of(KIND), false), "homed in a journal of the claimant's, never its doc 1: {answer}");
    let entry = g.shell.sessions.get(&g.session).unwrap();
    let Answer::Document(meta) = entry.board.op(Some(&bare(&g, 1)), &frames::doc_metadata(&journal)).unwrap() else { panic!("the session stands") };
    assert_eq!(meta["published"], json!(false), "a private draft: {meta}");
    assert!(g.position() > before, "the record's writes");
    let after = g.position();
    let again = g.call("merge.compose", json!({"session": g.session, "doc": f.edition, "alternative": f.e11})).unwrap_or_else(|r| panic!("{r}"));
    assert_eq!((again["outcome"].as_str(), again["record_link"].as_str(), g.position()), (Some("merged"), Some(record.as_str()), after), "the person's own record standing, nothing written: {again}");
    g.shell.shutdown();
    sd.shutdown();
}

/// Checks the `head_moved` race typed and the composition's death with its
/// session, against the daemon.
///
/// L takes the merge of E.2 with E.1.1 and the page opens L's panel, the
/// claim riding; a SECOND DEVICE's shell publishes E.3 meanwhile. The first
/// `merge.land` re-reads the base and re-states the standing `behind`,
/// nothing sent; the second sends the claim as the panel composed it at the
/// open, which the board refuses WHOLE, `supersede_refused` with `detail`
/// `head_moved` and `head` E.3, crossing as the board answered it — the
/// board's position unmoved, nothing re-sent, the composition gone, so a
/// third `merge.land` answers `no_merge`. A new merge composed on E.3 into
/// a fresh level draft then dies with its session: the session closed and
/// another opened, `merge.land` and `merge.undo` answer `no_merge` (the
/// mutants that drop the claim at a moved standing and land a daughter
/// silently, re-send after the refusal, or keep a dead session's
/// composition).
#[test]
fn the_head_moved_race_is_typed_nothing_re_sent_and_a_composition_dies_with_its_session() {
    let dir = TempDir::new().unwrap();
    let sd = spawn(&dir.path().join("board"), true);
    let g = ground(&dir, &sd);
    let f = family(&g);
    let l = g.addr(skep_client::board::frames::stage(&f.e2, None));
    let landed = g.call("merge.compose", json!({"session": g.session, "doc": f.edition, "alternative": f.e11, "into": l})).unwrap_or_else(|r| panic!("{r}"));
    assert_eq!(landed["outcome"].as_str(), Some("landed"), "{landed}");
    let panel = g.call("publication.open", json!({"session": g.session, "draft": l, "doc": f.edition, "readable_drafts": [l], "published": [f.edition]})).unwrap_or_else(|r| panic!("{r}"));
    assert_eq!((panel["count"]["supersede"].clone(), panel["standing"].as_str()), (json!([f.e11]), Some("at_head")), "{panel}");
    // The second device moves the head.
    let second = second_device(&dir, &sd);
    let t = second.addr(skep_client::board::frames::stage(&f.e2, None));
    second.op(json!({"op": "insert", "doc": t, "at": {"subspace": "1", "ordinal": "14"}, "values": ["!"], "as_of": second.position()}));
    second.call("publication.open", json!({"session": second.session, "draft": t, "doc": f.edition, "readable_drafts": [t], "published": [f.edition]})).unwrap_or_else(|r| panic!("{r}"));
    let e3 = format!("{}.3", f.edition);
    assert_eq!(second.call("publication.confirm", json!({"session": second.session})).unwrap_or_else(|r| panic!("{r}"))["member"].as_str(), Some(e3.as_str()));
    second.shell.shutdown();
    let before = g.position();
    let restated = g.call("merge.land", json!({"session": g.session})).unwrap_or_else(|r| panic!("{r}"));
    assert_eq!((restated["outcome"].as_str(), restated["standing"].as_str()), (Some("restated"), Some("behind")), "the standing moved, nothing sent: {restated}");
    let refused = g.call("merge.land", json!({"session": g.session})).unwrap_or_else(|r| panic!("{r}"));
    crate::shapes::assert_declared("PublicationRefused", &refused);
    assert_eq!((refused["outcome"].as_str(), refused["arm"].as_str(), refused["detail"].as_str(), refused["head"].as_str()), (Some("refused"), Some("supersede_refused"), Some("head_moved"), Some(e3.as_str())), "{refused}");
    assert_eq!(g.position(), before, "refused whole, nothing re-sent");
    assert_eq!(g.call("merge.land", json!({"session": g.session})).unwrap_err().name(), "no_merge", "the composition went with the race: made again on the head the refusal names");
    g.call("publication.cancel", json!({"session": g.session})).unwrap();
    // A composition dies with its session.
    let l2 = g.addr(skep_client::board::frames::stage(&e3, None));
    let landed = g.call("merge.compose", json!({"session": g.session, "doc": f.edition, "alternative": f.e11, "into": l2})).unwrap_or_else(|r| panic!("{r}"));
    assert_eq!((landed["outcome"].as_str(), landed["head"].as_str()), (Some("landed"), Some(e3.as_str())), "composed on the new head: {landed}");
    g.call("close", json!({"session": g.session})).unwrap();
    let session = g.call("session", json!({"board": g.board})).unwrap()["session"].as_str().unwrap().to_string();
    for call in ["merge.land", "merge.undo"] {
        assert_eq!(g.call(call, json!({"session": session})).unwrap_err().name(), "no_merge", "{call}: the composition died with its session");
    }
    g.shell.shutdown();
    sd.shutdown();
}
