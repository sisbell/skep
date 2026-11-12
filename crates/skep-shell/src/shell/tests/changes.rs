//! The `changes` call: a client that comes back to a board catches up.
//!
//! It catches up from a position it names, at its session's class. Against
//! the real daemon the suite checks that a write by a second session after a
//! position appears in the page from it with its position, under the
//! `drafts` class and the session, `next` advances past it, a second ask
//! from `next` answers nothing new, a draft in an account the session cannot
//! read never appears while that account's published home does, `limit`
//! bounds the page, and the refusals by name; that the drafts-only read
//! from the session's `opened_at` answers the drafts rows an end cut off,
//! the guest form the published rows alone, and `class` is refused by name
//! in its other values and in the guest form; that `under` narrows each
//! form to the rows under an address, a draft's or an account's; and that a
//! row a session of this shell wrote names that session and its burst, its
//! end past, while every row the library's own sessions wrote names none.
//! Over a scripted board it checks the two reads merged by position — a
//! straddle answered once, by the wider rendering — the published read
//! token-free and the drafts read under the token, the cut where a read's
//! `more` stands, and where a read to the head is sure of no more, `next` at
//! the head read first on a quiet board, `limit` over the merged page, a page
//! past the budget re-asked at the limit that fits, the retention floor as
//! the board's own 410, the death signal as the death, the drafts class read
//! alone with its own `next`, the guest form's one token-free read, `under`
//! on every ask of every form, and the writer the hold recorded named on a
//! drafts entry alone.

use std::io::Read;

use skep_client::board::{frames, Opened, SessionBody};
use skep_client::dial::{DialError, Dialer, Headers, Method, Request, RequestHead, Response, StreamedResponse};

use super::*;
use crate::feed::{changes_since, CaughtUp, ChangesRead};
use crate::hold::Written;
use crate::refs::BoardEntry;
use crate::sessions::{Facts, Open, Sessions, Supplements};

/// Checks that a client catches up from a position at its session's class.
///
/// A draft minted and written by a second session of the claimant's — the
/// library's own bare session as principal 1 — after the position N the
/// shell's session read, appears in `changes(N)` with its position, of the
/// `drafts` class under the session, every entry past N; `next` advances
/// past the write, and a second ask from `next` answers nothing new; from
/// the start, the session's own draft rows ride its class, a sibling
/// account's published home is everyone's, and that sibling's draft — which
/// the claimant's class never reads — appears nowhere, every entry once,
/// oldest first; `limit` bounds the page, `next` at the last entry kept and
/// the next ask reading on from it; `since` and `limit` of another form are
/// `malformed_args` by name, a stale session `session_ended`, and a `limit`
/// off the route's range the board's own `malformed_changes` (the mutant
/// that reads the drafts page without the session's token loses the
/// session's own rows; the one that reads the published feed under the
/// token answers one class for both).
#[test]
fn changes_answers_what_changed_since_a_position_at_the_sessions_class() {
    let dir = TempDir::new().unwrap();
    let sd = spawn(&dir.path().join("board"), true);
    let origin = format!("http://127.0.0.1:{}", sd.port());
    let store = dir.path().join("store");
    claim_board(&origin, &store);
    let (shell, _) = open_shell(&origin, &store, SessionMode::Bare { principal: 1 });
    let board = shell.board_references().remove(0);
    let session = shell.call("session", &json!({"board": board})).unwrap()["session"].as_str().unwrap().to_string();
    let library = Board::new(Origin::parse(&origin).unwrap(), skep_client::PlainHttp::new());
    let bare = |principal: u64| -> Token {
        match library.session_open(SessionBody::Bare { principal }).unwrap() {
            Opened::Token(token) => token,
            _ => panic!("a bare session as principal {principal} on the permissive board"),
        }
    };
    let written = |token: &Token, frame: &Value| -> Value {
        let Answer::Document(v) = library.op(Some(token), frame).unwrap() else { panic!("the library's session stands") };
        assert!(v["resp"].as_str().is_some_and(|r| r.starts_with("ack")), "the library's write: {v}");
        v
    };
    let addr = |v: Value| v["addr"].as_str().unwrap().to_string();
    // A sibling account — whose drafts the claimant's class never reads —
    // delegated from principal 0's bare session, its home born published
    // and a draft of its own written beside it under principal 2's.
    let boot = bare(0);
    let sibling = library.next_account_prefix("1").unwrap().expect("a delegable prefix");
    written(&boot, &frames::delegate(&sibling, 2, None));
    let two = bare(2);
    let sibling_home = addr(written(&two, &frames::create_home(&sibling, None)));
    let minted = written(&two, &frames::create_document(&sibling, false, None));
    let foreign = addr(minted.clone());
    written(&two, &json!({"op": "insert", "doc": foreign, "at": {"subspace": "1", "ordinal": "1"}, "values": ["theirs"], "as_of": minted["at"]}));
    // The position N, the board's head as the session reads it.
    let n = shell.call("health", &json!({"board": board})).unwrap()["health"]["log_position"].as_u64().unwrap();
    // A write by a second session of the claimant's after N.
    let one = bare(1);
    let minted = written(&one, &frames::create_document("1.0.1", false, None));
    let draft = addr(minted.clone());
    let at = written(&one, &json!({"op": "insert", "doc": draft, "at": {"subspace": "1", "ordinal": "1"}, "values": ["mine"], "as_of": minted["at"]}))["at"].as_u64().unwrap();
    let page = shell.call("changes", &json!({"session": session, "since": n})).unwrap();
    crate::shapes::assert_declared("ChangesAnswer", &page);
    let entries = page["entries"].as_array().unwrap();
    entries.iter().for_each(|entry| crate::shapes::assert_declared("FeedUpdate", entry));
    let row = entries.iter().find(|entry| entry["at"] == at).unwrap_or_else(|| panic!("the insert at {at}, after {n}: {page}"));
    assert_eq!((row["position"].as_u64(), row["class"].as_str(), row["session"].as_str(), &row["docs"]), (Some(at), Some("drafts"), Some(session.as_str()), &json!([draft])), "{row}");
    assert!(entries.iter().all(|entry| entry.get("by").is_none() && entry.get("burst").is_none()), "the library's sessions wrote each row, none of this shell's: no writer named: {page}");
    assert!(entries.iter().all(|entry| entry["at"].as_u64().unwrap() > n), "every entry is past N: {page}");
    let next = page["next"].as_u64().unwrap();
    assert!(next >= at && page["head"].as_u64().unwrap() >= n, "`next` advances past the write and `head` is the board's: {page}");
    let again = shell.call("changes", &json!({"session": session, "since": next})).unwrap();
    assert_eq!(again["entries"], json!([]), "nothing new from `next`: {again}");
    assert!(again["next"].as_u64().unwrap() >= next, "`next` never falls back: {again}");
    // From the start.
    let all = shell.call("changes", &json!({"session": session, "since": 0})).unwrap();
    let all_entries = all["entries"].as_array().unwrap();
    assert!(all_entries.iter().any(|entry| entry["docs"] == json!([draft]) && entry["class"] == "drafts"), "the session's own draft rows ride its class: {all}");
    assert!(all_entries.iter().any(|entry| entry["docs"] == json!([sibling_home]) && entry["class"] == "published"), "the sibling's published home is everyone's: {all}");
    assert!(all_entries.iter().all(|entry| entry["docs"].as_array().is_none_or(|docs| !docs.contains(&json!(foreign)))), "a draft the session cannot read never appears: {all}");
    assert!(all_entries.windows(2).all(|pair| pair[0]["at"].as_u64() < pair[1]["at"].as_u64()), "oldest first, each position once: {all}");
    // `limit` bounds the page.
    let first = shell.call("changes", &json!({"session": session, "since": 0, "limit": 1})).unwrap();
    assert_eq!(first["entries"].as_array().unwrap().len(), 1, "{first}");
    assert_eq!(first["next"], first["entries"][0]["at"], "`next` is the last entry kept: {first}");
    let second = shell.call("changes", &json!({"session": session, "since": first["next"], "limit": 1})).unwrap();
    assert_eq!(second["entries"][0]["at"], all_entries[1]["at"], "the next ask reads on from it: {second}");
    // The refusals by name.
    for (args, what) in [(json!({"session": session}), "since"), (json!({"session": session, "since": -1}), "since"), (json!({"session": session, "since": 0, "limit": "x"}), "limit")] {
        let refused = shell.call("changes", &args).unwrap_err().to_value();
        assert_eq!((refused["name"].as_str(), refused["what"].as_str()), (Some("malformed_args"), Some(what)), "{args}: {refused}");
    }
    assert_eq!(shell.call("changes", &json!({"session": "s-gone", "since": 0})).unwrap_err().name(), "session_ended");
    let off_range = shell.call("changes", &json!({"session": session, "since": 0, "limit": 0})).unwrap_err();
    assert_eq!((off_range.name(), off_range.to_value()["kind"].as_str()), ("malformed_changes", Some("refused")), "a limit off the route's range is the board's verdict: {off_range}");
    shell.shutdown();
    sd.shutdown();
}

/// Checks that the drafts-only read from `opened_at` answers what an end cut
/// off, and the guest form the published rows alone (skep #740, #749).
///
/// A session's `opened_at`, on its answer, is the board's position read
/// before it opened; after it a draft of the principal's is minted and
/// written under a second session of the principal's — the library's own
/// bare session — and a sibling account's home is published beside it; the
/// session's token is then closed at the board, and a call on it meets the
/// death — `session_died`, the restart arm, nothing re-opened under the
/// bare mode. The page regains a session and reads `changes(regained,
/// since: opened_at, class: "drafts")`: the draft's rows alone, each of the
/// `drafts` class naming the regained session and past the open, the
/// sibling's home among none of them, and `next` past the last; the guest
/// form, at the board's reference and at its origin alike, answers the
/// sibling's home and no draft, every entry `published` naming no session;
/// and `class` of another value, of another form, or in the guest form is
/// `malformed_args` naming `class`, before any session is looked up (the
/// mutants that read both classes under `class: "drafts"` answer the
/// published rows the page took already; the one that reads a drafts page
/// as a guest presents no token; the one that reads `class` as absent
/// merges where the page asked for the supplement alone).
#[test]
fn the_drafts_read_from_opened_at_answers_what_an_end_cut_off_and_the_guest_form_the_published_rows() {
    let dir = TempDir::new().unwrap();
    let sd = spawn(&dir.path().join("board"), true);
    let origin = format!("http://127.0.0.1:{}", sd.port());
    let store = dir.path().join("store");
    claim_board(&origin, &store);
    let (shell, _) = open_shell(&origin, &store, SessionMode::Bare { principal: 1 });
    let board = shell.board_references().remove(0);
    let opened = shell.call("session", &json!({"board": board})).unwrap();
    crate::shapes::assert_declared("SessionOpened", &opened);
    let session = opened["session"].as_str().unwrap().to_string();
    let opened_at = opened["opened_at"].as_u64().expect("the session answer carries `opened_at`");
    assert_eq!(opened_at, shell.sessions.get(&session).unwrap().opened_at, "the entry's own, read before the open");
    let library = Board::new(Origin::parse(&origin).unwrap(), skep_client::PlainHttp::new());
    let bare = |principal: u64| -> Token {
        match library.session_open(SessionBody::Bare { principal }).unwrap() {
            Opened::Token(token) => token,
            _ => panic!("a bare session as principal {principal} on the permissive board"),
        }
    };
    let written = |token: &Token, frame: &Value| -> Value {
        let Answer::Document(v) = library.op(Some(token), frame).unwrap() else { panic!("the library's session stands") };
        assert!(v["resp"].as_str().is_some_and(|r| r.starts_with("ack")), "the library's write: {v}");
        v
    };
    let addr = |v: Value| v["addr"].as_str().unwrap().to_string();
    // After the open: the principal's draft and its insert under a second
    // session of the principal's, and a sibling's home published beside it.
    let one = bare(1);
    let minted = written(&one, &frames::create_document("1.0.1", false, None));
    let draft = addr(minted.clone());
    let inserted = written(&one, &json!({"op": "insert", "doc": draft, "at": {"subspace": "1", "ordinal": "1"}, "values": ["mine"], "as_of": minted["at"]}))["at"].as_u64().unwrap();
    let boot = bare(0);
    let sibling = library.next_account_prefix("1").unwrap().expect("a delegable prefix");
    written(&boot, &frames::delegate(&sibling, 2, None));
    let sibling_home = addr(written(&bare(2), &frames::create_home(&sibling, None)));
    // The end, met by a call: the token closed at the board.
    library.session_close(&shell.sessions.get(&session).unwrap().token).unwrap();
    let died = shell.call("changes", &json!({"session": session, "since": opened_at})).unwrap_err().to_value();
    assert_eq!((died["name"].as_str(), died["reason"]["arm"].as_str(), died["reason"]["reopened"].as_bool()), (Some("session_died"), Some("restart"), Some(false)), "{died}");
    // The page regains a session and reads the drafts class alone, from the
    // position the ended session opened at.
    let regained = shell.call("session", &json!({"board": board})).unwrap()["session"].as_str().unwrap().to_string();
    let drafts = shell.call("changes", &json!({"session": regained, "since": opened_at, "class": "drafts"})).unwrap();
    crate::shapes::assert_declared("ChangesAnswer", &drafts);
    let entries = drafts["entries"].as_array().unwrap();
    entries.iter().for_each(|entry| crate::shapes::assert_declared("FeedUpdate", entry));
    assert!(entries.iter().all(|e| e["class"] == "drafts" && e["session"] == regained && e["at"].as_u64().unwrap() > opened_at), "the drafts class alone, naming the regained session, past the open: {drafts}");
    assert!(entries.iter().any(|e| e["at"] == inserted && e["docs"] == json!([draft])), "the draft's row the end cut off: {drafts}");
    assert!(entries.iter().all(|e| e.get("by").is_none() && e.get("burst").is_none()), "the library's sessions wrote each row, none of this shell's: no writer named: {drafts}");
    assert!(entries.iter().all(|e| e["docs"] != json!([sibling_home])), "no published row: {drafts}");
    assert!(drafts["next"].as_u64().unwrap() >= inserted, "`next` is past the last drafts row: {drafts}");
    // The guest form: the published rows alone, token-free, at the board's
    // reference and at its origin.
    for args in [json!({"guest": true, "board": board, "since": opened_at}), json!({"guest": true, "origin": origin, "since": opened_at})] {
        let published = shell.call("changes", &args).unwrap();
        crate::shapes::assert_declared("ChangesAnswer", &published);
        let entries = published["entries"].as_array().unwrap();
        assert!(entries.iter().any(|e| e["docs"] == json!([sibling_home]) && e["class"] == "published"), "{args}: the sibling's home: {published}");
        assert!(entries.iter().all(|e| e["class"] == "published" && e.get("session").is_none() && e["docs"] != json!([draft])), "{args}: the published class alone, no session, no draft: {published}");
    }
    // `class` refused by name: another value, another form, and in the
    // guest form — each before the session is looked up.
    for args in [json!({"session": regained, "since": 0, "class": "published"}), json!({"session": "s-gone", "since": 0, "class": 7}), json!({"guest": true, "board": board, "since": 0, "class": "drafts"})] {
        let refused = shell.call("changes", &args).unwrap_err().to_value();
        assert_eq!((refused["name"].as_str(), refused["what"].as_str()), (Some("malformed_args"), Some("class")), "{args}: {refused}");
    }
    shell.shutdown();
    sd.shutdown();
}

/// Checks that `under` narrows the page to the rows under an address.
///
/// Two drafts of the claimant's, D and D2, are minted and written by the
/// library's own bare session as principal 1, D2's rows between D's, beside
/// a sibling account's published home (skep #652). Under D, the session form
/// answers D's mint and insert alone, each naming D and of the `drafts`
/// class, `next` past them and nothing new from it; `limit` cuts the
/// narrowed page at D's mint, the next ask from `next` reading D's insert
/// past D2's rows; `class: "drafts"` answers the same rows. The guest form
/// under the home answers the home's rows alone, under the sibling's
/// account — an address of another level — the same, the sibling's draft
/// masked, and under D, a draft no guest reads, nothing, `next` at the head
/// (the mutants that send no `under`, or send it on one read alone, answer
/// rows of every document the class reads).
#[test]
fn under_narrows_the_page_to_the_rows_under_an_address() {
    let dir = TempDir::new().unwrap();
    let sd = spawn(&dir.path().join("board"), true);
    let origin = format!("http://127.0.0.1:{}", sd.port());
    let store = dir.path().join("store");
    claim_board(&origin, &store);
    let (shell, _) = open_shell(&origin, &store, SessionMode::Bare { principal: 1 });
    let board = shell.board_references().remove(0);
    let session = shell.call("session", &json!({"board": board})).unwrap()["session"].as_str().unwrap().to_string();
    let library = Board::new(Origin::parse(&origin).unwrap(), skep_client::PlainHttp::new());
    let bare = |principal: u64| -> Token {
        match library.session_open(SessionBody::Bare { principal }).unwrap() {
            Opened::Token(token) => token,
            _ => panic!("a bare session as principal {principal} on the permissive board"),
        }
    };
    let written = |token: &Token, frame: &Value| -> Value {
        let Answer::Document(v) = library.op(Some(token), frame).unwrap() else { panic!("the library's session stands") };
        assert!(v["resp"].as_str().is_some_and(|r| r.starts_with("ack")), "the library's write: {v}");
        v
    };
    let addr = |v: Value| v["addr"].as_str().unwrap().to_string();
    let insert = |doc: &str, typed: &Value| json!({"op": "insert", "doc": doc, "at": {"subspace": "1", "ordinal": "1"}, "values": ["words"], "as_of": typed});
    // D's mint, D2's mint and insert, then D's insert.
    let one = bare(1);
    let minted = written(&one, &frames::create_document("1.0.1", false, None));
    let (d, d_minted) = (addr(minted.clone()), minted["at"].as_u64().unwrap());
    let minted2 = written(&one, &frames::create_document("1.0.1", false, None));
    let d2 = addr(minted2.clone());
    written(&one, &insert(&d2, &minted2["at"]));
    let d_inserted = written(&one, &insert(&d, &minted["at"]))["at"].as_u64().unwrap();
    let boot = bare(0);
    let sibling = library.next_account_prefix("1").unwrap().expect("a delegable prefix");
    written(&boot, &frames::delegate(&sibling, 2, None));
    let two = bare(2);
    let home = addr(written(&two, &frames::create_home(&sibling, None)));
    let foreign = addr(written(&two, &frames::create_document(&sibling, false, None)));
    // The session form under D.
    let page = shell.call("changes", &json!({"session": session, "since": 0, "under": d})).unwrap();
    crate::shapes::assert_declared("ChangesAnswer", &page);
    let entries = page["entries"].as_array().unwrap();
    entries.iter().for_each(|entry| crate::shapes::assert_declared("FeedUpdate", entry));
    assert_eq!(entries.iter().map(|e| e["at"].as_u64().unwrap()).collect::<Vec<_>>(), [d_minted, d_inserted], "D's rows alone, oldest first: {page}");
    assert!(entries.iter().all(|e| e["docs"] == json!([d]) && e["class"] == "drafts" && e["session"] == session), "each names D, of the drafts class under the session: {page}");
    assert!(entries.iter().all(|e| e.get("by").is_none() && e.get("burst").is_none()), "the library's session wrote D's rows, none of this shell's: no writer named: {page}");
    let next = page["next"].as_u64().unwrap();
    assert!(next >= d_inserted, "`next` is past D's rows: {page}");
    let again = shell.call("changes", &json!({"session": session, "since": next, "under": d})).unwrap();
    assert_eq!(again["entries"], json!([]), "nothing new from `next`: {again}");
    // `limit` over the narrowed page, and the drafts class narrowed alike.
    let first = shell.call("changes", &json!({"session": session, "since": 0, "under": d, "limit": 1})).unwrap();
    assert_eq!((first["entries"].as_array().map(Vec::len), first["entries"][0]["at"].as_u64(), first["next"].as_u64()), (Some(1), Some(d_minted), Some(d_minted)), "{first}");
    let second = shell.call("changes", &json!({"session": session, "since": first["next"], "under": d, "limit": 1})).unwrap();
    assert_eq!(second["entries"][0]["at"].as_u64(), Some(d_inserted), "the next ask reads on past D2's rows: {second}");
    let drafts = shell.call("changes", &json!({"session": session, "since": 0, "under": d, "class": "drafts"})).unwrap();
    assert_eq!(drafts["entries"], page["entries"], "the drafts class under D: {drafts}");
    // The guest form under the home, the sibling's account and D.
    let guest = |under: &str| shell.call("changes", &json!({"guest": true, "board": board, "since": 0, "under": under})).unwrap();
    let at_home = guest(&home);
    let homed = at_home["entries"].as_array().unwrap();
    assert!(!homed.is_empty() && homed.iter().all(|e| e["docs"] == json!([home]) && e["class"] == "published"), "the home's rows alone: {at_home}");
    let in_account = guest(&sibling);
    assert_eq!(in_account["entries"], at_home["entries"], "under the account, its published rows, `{foreign}` masked: {in_account}");
    let unread = guest(&d);
    assert_eq!((&unread["entries"], &unread["next"]), (&json!([]), &unread["head"]), "a draft no guest reads: nothing, `next` at the head: {unread}");
    shell.shutdown();
    sd.shutdown();
}

/// A board's answer to one `/changes` ask.
///
/// It is given by the ask's `since`, whether it is the `drafts=true` read,
/// and its `limit`.
type Script = Box<dyn Fn(u64, bool, Option<u64>) -> Response + Send + Sync>;

/// The asks a board saw.
///
/// Each holds its `since`, whether it was the drafts read, its `limit`,
/// whether a token rode it, and its `under`.
type Asked = Vec<(u64, bool, Option<u64>, bool, Option<String>)>;

/// A board whose `/changes` answers each ask as `script` says.
///
/// Its `/health` names `head`, and every ask is recorded.
struct Scripted {
    head: u64,
    script: Script,
    asked: Mutex<Asked>,
}

/// Returns the text the query member `key` names in `path`, if any.
fn query_text<'p>(path: &'p str, key: &str) -> Option<&'p str> {
    path.split_once(&format!("{key}=")).and_then(|(_, rest)| rest.split('&').next())
}

/// Returns the number the query member `key` names in `path`, if any.
fn query_of(path: &str, key: &str) -> Option<u64> {
    query_text(path, key).and_then(|n| n.parse().ok())
}

fn ok(v: Value) -> Response {
    Response { status: 200, headers: Headers::default(), body: v.to_string().into_bytes() }
}

/// Returns one row at `at` naming `docs`.
fn row(at: u64, docs: &[&str]) -> Value {
    json!({"at": at, "op": "insert", "docs": docs, "key": "bare"})
}

/// Returns a page of `rows` with its `last` and its `more`.
fn page(rows: Vec<Value>, last: u64, more: bool) -> Response {
    ok(json!({"changes": rows, "last": last, "more": more}))
}

/// Returns a non-200 answer of `body`.
fn refused(status: u16, body: Value) -> Response {
    Response { status, headers: Headers::default(), body: body.to_string().into_bytes() }
}

impl Dialer for Scripted {
    fn exchange(&self, _: &Origin, req: &Request) -> Result<Response, DialError> {
        if req.method == Method::Get && req.path.starts_with("/health") {
            return Ok(ok(json!({"ok": true, "log_position": self.head, "auth": {"claimant": null, "local_trust": true, "origins": [], "signed_origins": []}, "writes": {"halted": false}})));
        }
        assert!(req.method == Method::Get && req.path.starts_with("/changes?"), "the catch-up dials `/health` and `/changes` alone: {}", req.path);
        let (since, limit) = (query_of(&req.path, "since").expect("a `since`"), query_of(&req.path, "limit"));
        let drafts = req.path.contains("drafts=true");
        let with_token = req.headers.iter().any(|(k, _)| k.eq_ignore_ascii_case("Skepd-Session"));
        self.asked.lock().unwrap().push((since, drafts, limit, with_token, query_text(&req.path, "under").map(str::to_string)));
        Ok((self.script)(since, drafts, limit))
    }

    fn stream(&self, _: &Origin, _: &RequestHead, _: &mut dyn Read, _: &mut dyn FnMut(&Headers)) -> Result<StreamedResponse, DialError> {
        Err(DialError::Connect("no stream here".into()))
    }
}

struct NoSupplements;
impl Supplements for NoSupplements {
    fn widen(&mut self, _: &Arc<SessionEntry>) {}
    fn narrow(&mut self, _: u64) {}
}

/// The form a scripted catch-up reads in.
#[derive(Debug, Clone, Copy)]
enum Form {
    /// The session form: the two reads merged.
    Session,
    /// The session form narrowed to `class: "drafts"`: the supplement alone.
    Drafts,
    /// The guest form: the published feed alone, token-free.
    Guest,
}

/// Reads the catch-up in the session form at a scripted board.
///
/// It is [`catch_up_in`] in the session form, under no address.
fn catch_up_over(head: u64, script: impl Fn(u64, bool, Option<u64>) -> Response + Send + Sync + 'static, since: u64, limit: Option<u64>) -> (Result<ChangesRead, Refusal>, Asked) {
    catch_up_in(Form::Session, head, script, since, limit, None)
}

/// Reads the catch-up in `form` at a scripted board, no writer recorded.
///
/// It is [`catch_up_with`]'s read where the hold recorded the writer of no
/// row.
fn catch_up_in(
    form: Form,
    head: u64,
    script: impl Fn(u64, bool, Option<u64>) -> Response + Send + Sync + 'static,
    since: u64,
    limit: Option<u64>,
    under: Option<&str>,
) -> (Result<ChangesRead, Refusal>, Asked) {
    catch_up_with(form, head, script, since, limit, under, |_| None)
}

/// Reads the catch-up in `form` at a scripted board.
///
/// It reads from `since` under `limit`, narrowed to `under` where it names
/// an address; the session is a bare one of principal 1, the board scripted
/// by `script`, its head at `head`, and `written` the writer the hold
/// recorded at each position; it returns the read and the asks the board
/// saw.
fn catch_up_with(
    form: Form,
    head: u64,
    script: impl Fn(u64, bool, Option<u64>) -> Response + Send + Sync + 'static,
    since: u64,
    limit: Option<u64>,
    under: Option<&str>,
    written: impl Fn(u64) -> Option<Written>,
) -> (Result<ChangesRead, Refusal>, Asked) {
    let fake = Arc::new(Scripted { head, script: Box::new(script), asked: Mutex::new(Vec::new()) });
    let entry = Arc::new(BoardEntry { reference: "b-1".into(), board: Arc::new(Board::new(Origin::parse("http://127.0.0.1:9").unwrap(), Arc::clone(&fake))) });
    let facts = Facts { principal: 1, account: Some("1.0.1".into()), kind: SessionKind::Bare };
    let session = Sessions::new(None, Arc::new(|_: &str| {})).register(&entry, Open { token: Token::parse(&"9f".repeat(16)).unwrap(), facts, opened_at: 0 }, &mut NoSupplements);
    let under = under.map(|text| skep_client::address::parse_address(text).expect("an address"));
    let read = match form {
        Form::Session => changes_since(&entry.board, Some(&session), false, since, limit, under.as_ref(), written),
        Form::Drafts => changes_since(&entry.board, Some(&session), true, since, limit, under.as_ref(), written),
        Form::Guest => changes_since(&entry.board, None, false, since, limit, under.as_ref(), written),
    };
    let asked = fake.asked.lock().unwrap().clone();
    (read, asked)
}

/// Returns the page a read answered.
///
/// # Panics
///
/// Panics naming what the read answered where it answered no page.
fn page_of(read: Result<ChangesRead, Refusal>) -> crate::feed::CaughtUp {
    match read {
        Ok(ChangesRead::Page(page)) => page,
        other => panic!("a page: {other:?}"),
    }
}

/// Returns the positions of a page's entries, with each entry's class.
fn classed(page: &crate::feed::CaughtUp) -> Vec<(u64, &str)> {
    page.entries.iter().map(|entry| (entry["at"].as_u64().unwrap(), entry["class"].as_str().unwrap())).collect()
}

/// Checks that the two reads merge by position, the wider rendering winning.
///
/// The published feed is read token-free and the drafts supplement under the
/// session's token, from the same `since` — each entry in the update's
/// shape, `published` or `drafts` by the read that answered it, a drafts
/// entry naming the session; a position both answer — a straddle, the
/// guest's `[T]` beside the supplement's `[D, T]` — is answered once, by the
/// rendering naming more documents; and, both reads read to the head, `next`
/// is the head read first, which lies past every entry (the mutants that
/// read the drafts page token-free, read the published feed under the token,
/// keep the narrower rendering, or answer `next` as the last entry on a
/// board that moved past it on masked commits).
#[test]
fn the_two_reads_merge_by_position_the_wider_rendering_winning() {
    let script = |since: u64, drafts: bool, _: Option<u64>| match drafts {
        false => page(vec![row(22, &["1.0.1.0.1"]), row(30, &["1.0.1.0.1"])], 30, false),
        true => page(vec![row(24, &["1.0.1.0.2"]), row(30, &["1.0.1.0.2", "1.0.1.0.1"])], 30.max(since), false),
    };
    let (read, asked) = catch_up_over(40, script, 20, None);
    let caught = page_of(read);
    assert_eq!(classed(&caught), [(22, "published"), (24, "drafts"), (30, "drafts")]);
    assert_eq!(caught.entries[2]["docs"], json!(["1.0.1.0.2", "1.0.1.0.1"]), "the wider rendering: {:?}", caught.entries);
    assert_eq!((caught.entries[0].get("session"), caught.entries[1]["session"].as_str().map(|s| s.starts_with("s-"))), (None, Some(true)), "a drafts entry names the session, a published one none");
    assert!(caught.entries.iter().all(|entry| entry["position"] == entry["at"]), "{:?}", caught.entries);
    assert_eq!((caught.next, caught.head), (40, 40), "both reads complete: `next` is the head read first");
    assert_eq!(asked, [(20, false, None, false, None), (20, true, None, true, None)], "the published feed token-free, the supplement under the token, each from `since`");
}

/// Checks that the page is cut where a read's `more` stands.
///
/// Nothing past the lower `last` of an unfinished read is answered — the
/// other read may hold a position between — and `next` is that cut,
/// whichever read is the short one; both reads complete and empty, `next` is
/// the head, and a `since` past the head is echoed back (the mutants that
/// answer every row of both reads, skipping the positions between, or take
/// the greater `last`).
#[test]
fn the_page_is_cut_where_a_reads_more_stands() {
    let published_short =
        |_: u64, drafts: bool, _: Option<u64>| if drafts { page(vec![row(13, &["1.0.1.0.2"])], 13, false) } else { page(vec![row(11, &["1.0.1.0.1"]), row(12, &["1.0.1.0.1"])], 12, true) };
    let caught = page_of(catch_up_over(50, published_short, 10, None).0);
    assert_eq!((classed(&caught), caught.next), (vec![(11, "published"), (12, "published")], 12), "the drafts row at 13 is withheld: a published position may lie between 12 and 13");
    let drafts_short =
        |_: u64, drafts: bool, _: Option<u64>| if drafts { page(vec![row(11, &["1.0.1.0.2"]), row(13, &["1.0.1.0.2"])], 13, true) } else { page(vec![row(15, &["1.0.1.0.1"])], 15, false) };
    let caught = page_of(catch_up_over(50, drafts_short, 10, None).0);
    assert_eq!((classed(&caught), caught.next), (vec![(11, "drafts"), (13, "drafts")], 13));
    let quiet = |since: u64, _: bool, _: Option<u64>| page(Vec::new(), since, false);
    let caught = page_of(catch_up_over(50, quiet, 45, None).0);
    assert_eq!((caught.entries.len(), caught.next, caught.head), (0, 50, 50), "a quiet board: `next` is the head");
    let caught = page_of(catch_up_over(50, quiet, 60, None).0);
    assert_eq!((caught.entries.len(), caught.next), (0, 60), "a `since` past the head is echoed");
}

/// Checks that a read to the head is sure of no more than its snapshot.
///
/// The two reads are answered from two snapshots, the published read's the
/// earlier: a drafts row past the head read first and the published read's
/// `last` is withheld, `next` at that bound, since a published commit may
/// have landed between the two snapshots, on neither page; and a published
/// row past the head read first is answered, `next` at it, the drafts read
/// made after it being sure of it too (the mutant that takes a read to the
/// head as sure of every position skips such a commit for good; the one that
/// is sure of the head read first alone withholds a row the board answered,
/// its next ask answering it again).
#[test]
fn a_read_to_the_head_is_sure_of_no_more_than_its_snapshot() {
    let drafts_later = |since: u64, drafts: bool, _: Option<u64>| if drafts { page(vec![row(45, &["1.0.1.0.2"])], 45, false) } else { page(Vec::new(), since, false) };
    let caught = page_of(catch_up_over(40, drafts_later, 30, None).0);
    assert_eq!((caught.entries.len(), caught.next), (0, 40), "the drafts row at 45 is withheld: a published commit may lie between 40 and 45 on neither page");
    let published_later = |_: u64, drafts: bool, _: Option<u64>| if drafts { page(vec![row(38, &["1.0.1.0.2"])], 38, false) } else { page(vec![row(42, &["1.0.1.0.1"])], 42, false) };
    let caught = page_of(catch_up_over(40, published_later, 30, None).0);
    assert_eq!((classed(&caught), caught.next), (vec![(38, "drafts"), (42, "published")], 42), "the published row past the head is answered, the drafts read made after it");
}

/// Checks that `limit` bounds the merged page and the budget is re-asked.
///
/// A page past the budget is re-asked at the limit that fits: the merged
/// entries cut to `limit`, `next` the last kept, both reads asked at
/// `limit`; a `malformed_changes` naming `fits` re-asked at `fits` on that
/// read alone (the mutants that bound each read and not the merge, or face
/// the budget's refusal).
#[test]
fn limit_bounds_the_merged_page_and_the_budget_is_re_asked() {
    let script = |_: u64, drafts: bool, _: Option<u64>| if drafts { page(vec![row(12, &["1.0.1.0.2"])], 12, false) } else { page(vec![row(11, &["1.0.1.0.1"]), row(13, &["1.0.1.0.1"])], 13, false) };
    let (read, asked) = catch_up_over(20, script, 10, Some(2));
    let caught = page_of(read);
    assert_eq!((classed(&caught), caught.next), (vec![(11, "published"), (12, "drafts")], 12));
    assert_eq!(asked.iter().map(|(_, _, limit, _, _)| *limit).collect::<Vec<_>>(), [Some(2), Some(2)], "each read asked at `limit`");
    let too_large = |_: u64, drafts: bool, limit: Option<u64>| match (drafts, limit) {
        (true, _) => page(Vec::new(), 10, false),
        (false, Some(1)) => page(vec![row(11, &["1.0.1.0.1"])], 11, true),
        (false, _) => refused(400, json!({"error": "malformed_changes", "budget": 2_097_152, "fits": 1})),
    };
    let (read, asked) = catch_up_over(20, too_large, 10, None);
    let caught = page_of(read);
    assert_eq!((classed(&caught), caught.next), (vec![(11, "published")], 11));
    assert_eq!(asked, [(10, false, None, false, None), (10, false, Some(1), false, None), (10, true, None, true, None)], "the published read re-asked at `fits`, the drafts read as asked");
}

/// Checks that the floor and the death are faced.
///
/// A `since` below the feed's memory is the board's own
/// `410 history_reclaimed` with its floor, never resumed behind the caller's
/// back; another refusal is the board's verdict; and the death signal on the
/// drafts read is the death, for the shell to end the session by (the
/// mutants that resume at the floor as the feed thread does — a catch-up
/// silently short of what the caller asked — or read the death as an empty
/// page).
#[test]
fn the_floor_and_the_death_are_faced() {
    let (read, _) = catch_up_over(20, |_, _, _| refused(410, json!({"error": "history_reclaimed", "floor": 5})), 3, None);
    let reclaimed = read.expect_err("the floor is a refusal");
    let v = reclaimed.to_value();
    assert_eq!((reclaimed.name(), v["kind"].as_str(), v["status"].as_u64(), v["body"]["floor"].as_u64()), ("history_reclaimed", Some("refused"), Some(410), Some(5)), "{v}");
    let (read, _) = catch_up_over(20, |_, _, _| refused(410, json!({"error": "history_reclaimed"})), 3, None);
    assert_eq!(read.expect_err("a floor unknown").to_value()["body"].get("floor"), None, "no floor invented");
    let (read, _) = catch_up_over(20, |_, _, _| refused(503, json!({"error": "feed_rebuilding"})), 10, None);
    assert_eq!(read.expect_err("the board's verdict").name(), "feed_rebuilding");
    let closed = |_: u64, drafts: bool, _: Option<u64>| {
        if drafts {
            Response { status: 200, headers: Headers(vec![("Skepd-Session".into(), "closed".into())]), body: Vec::new() }
        } else {
            page(Vec::new(), 10, false)
        }
    };
    assert_eq!(catch_up_over(20, closed, 10, None).0, Ok(ChangesRead::Died), "the death signal on the session's token is the death");
}

/// Checks that `class: "drafts"` answers the drafts page alone with its `next`.
///
/// The one read is the supplement's, under the token, from `since`: no
/// published read is made, every entry is of the `drafts` class naming the
/// session, and `next` is the head read first where the page was read to
/// it — the page's `last` where its `more` stands, the last entry kept
/// where `limit` cuts it (the mutants that read both classes answer the
/// published rows a page took already, or make a token-free read the page
/// never asked for; the one that answers `next` as the page's `last` on a
/// quiet board asks again from behind the head).
#[test]
fn class_drafts_answers_the_drafts_page_alone_with_its_next() {
    let script = |since: u64, drafts: bool, _: Option<u64>| match drafts {
        false => page(vec![row(22, &["1.0.1.0.1"])], 30, false),
        true => page(vec![row(24, &["1.0.1.0.2"]), row(30, &["1.0.1.0.2", "1.0.1.0.1"])], 30.max(since), false),
    };
    let (read, asked) = catch_up_in(Form::Drafts, 40, script, 20, None, None);
    let caught = page_of(read);
    assert_eq!(classed(&caught), [(24, "drafts"), (30, "drafts")]);
    assert!(caught.entries.iter().all(|entry| entry["session"].as_str().is_some_and(|s| s.starts_with("s-"))), "every entry names the session: {:?}", caught.entries);
    assert_eq!((caught.next, caught.head), (40, 40), "read to the head: `next` is the head read first");
    assert_eq!(asked, [(20, true, None, true, None)], "the one read: the supplement under the token, from `since`");
    let more = |_: u64, drafts: bool, _: Option<u64>| if drafts { page(vec![row(24, &["1.0.1.0.2"])], 24, true) } else { panic!("the published feed is not read") };
    let caught = page_of(catch_up_in(Form::Drafts, 40, more, 20, None, None).0);
    assert_eq!((classed(&caught), caught.next), (vec![(24, "drafts")], 24), "`more` standing: `next` is the page's `last`");
    let (read, asked) = catch_up_in(Form::Drafts, 40, script, 20, Some(1), None);
    let caught = page_of(read);
    assert_eq!((classed(&caught), caught.next), (vec![(24, "drafts")], 24), "`limit` cuts the page: `next` is the last kept");
    assert_eq!(asked, [(20, true, Some(1), true, None)]);
}

/// Checks that the guest form answers the published rows alone, no token.
///
/// The one read is the published feed's, token-free, from `since`: every
/// entry is of the `published` class naming no session, and `next` is the
/// head read first where the page was read to it (the mutant that reads a
/// drafts page as a guest presents no token and meets the board's refusal;
/// the one that sends the published read under a token the guest form
/// never holds).
#[test]
fn the_guest_form_answers_the_published_rows_alone_with_no_token() {
    let script = |_: u64, drafts: bool, _: Option<u64>| if drafts { panic!("no drafts page is read as a guest") } else { page(vec![row(22, &["1.0.1.0.1"]), row(30, &["1.0.1.0.1"])], 30, false) };
    let (read, asked) = catch_up_in(Form::Guest, 40, script, 20, None, None);
    let caught = page_of(read);
    assert_eq!(classed(&caught), [(22, "published"), (30, "published")]);
    assert!(caught.entries.iter().all(|entry| entry.get("session").is_none()), "no entry names a session: {:?}", caught.entries);
    assert_eq!((caught.next, caught.head), (40, 40));
    assert_eq!(asked, [(20, false, None, false, None)], "the one read: the published feed, token-free");
}

/// Checks that `under` rides every ask of every form, and meets the floor.
///
/// The session form's two reads, the drafts-only read and the guest read
/// each ask under the address, a page past the budget re-asked at `fits`
/// under it too, as every ask of the cells above rides none; and a narrowed
/// `since` below the feed's memory is the board's own `history_reclaimed`
/// with its floor (skep #652; the mutants that narrow the published read
/// alone answer every draft the session reads; the one that drops `under`
/// from the re-ask answers the whole feed's page at `fits`).
#[test]
fn under_rides_every_ask_of_every_form_and_meets_the_floor() {
    const DRAFT: &str = "1.0.1.0.2";
    let script = |_: u64, drafts: bool, limit: Option<u64>| match (drafts, limit) {
        (false, None) => refused(400, json!({"error": "malformed_changes", "budget": 2_097_152, "fits": 1})),
        (false, Some(_)) => page(Vec::new(), 10, false),
        (true, _) => page(vec![row(12, &[DRAFT])], 12, false),
    };
    let under = || Some(DRAFT.to_string());
    let published = [(10, false, None, false, under()), (10, false, Some(1), false, under())];
    let drafts = [(10, true, None, true, under())];
    for (form, owed) in [(Form::Session, [&published[..], &drafts[..]].concat()), (Form::Drafts, drafts.to_vec()), (Form::Guest, published.to_vec())] {
        let (read, asked) = catch_up_in(form, 20, script, 10, None, Some(DRAFT));
        page_of(read);
        assert_eq!(asked, owed, "{form:?}: every ask under the address, the re-ask at `fits` too");
    }
    let (read, asked) = catch_up_in(Form::Session, 20, |_, _, _| refused(410, json!({"error": "history_reclaimed", "floor": 5})), 3, None, Some(DRAFT));
    let reclaimed = read.expect_err("the floor is a refusal").to_value();
    assert_eq!((reclaimed["name"].as_str(), reclaimed["status"].as_u64(), reclaimed["body"]["floor"].as_u64()), (Some("history_reclaimed"), Some(410), Some(5)), "{reclaimed}");
    assert_eq!(asked, [(3, false, None, false, under())], "the narrowed ask met the floor");
}

/// Checks that a drafts entry names the hold's writer, a published one none.
///
/// It is skep #1000's catch-up. The lookup names a writer at every position but
/// 28, and a burst at 24 alone. Under a session the drafts entries at 24 and 30
/// — the straddle answered by the token's wider rendering — carry its `by`, 24
/// its `burst` too, the drafts entry at 28 neither, and the published entries
/// at 22 and 26 neither, whatever the lookup holds at their positions; the
/// drafts class alone the same drafts entries; and the guest form, which reads
/// no drafts page, names no writer (the mutant that names a writer by position
/// whatever the class tells a guest's page this shell wrote a row; the one that
/// names none leaves a page that comes back no way to know its own writes).
#[test]
fn a_drafts_entry_names_the_writer_the_hold_recorded_and_a_published_one_none() {
    let script = |since: u64, drafts: bool, _: Option<u64>| match drafts {
        false => page(vec![row(22, &["1.0.1.0.1"]), row(26, &["1.0.1.0.1"]), row(30, &["1.0.1.0.1"])], 30, false),
        true => page(vec![row(24, &["1.0.1.0.2"]), row(28, &["1.0.1.0.2"]), row(30, &["1.0.1.0.2", "1.0.1.0.1"])], 30.max(since), false),
    };
    let written = |at: u64| (at != 28).then(|| Written { by: Some("s-writer".to_string()), burst: (at == 24).then(|| "b-7".to_string()) });
    let named = |caught: &CaughtUp| -> Vec<(u64, String, Option<String>, Option<String>)> {
        caught.entries.iter().map(|e| (e["at"].as_u64().unwrap(), e["class"].as_str().unwrap().to_string(), e["by"].as_str().map(str::to_string), e["burst"].as_str().map(str::to_string))).collect()
    };
    let (by, burst) = (|| Some("s-writer".to_string()), || Some("b-7".to_string()));
    let drafts = |at: u64, by: Option<String>, burst: Option<String>| (at, "drafts".to_string(), by, burst);
    let published = |at: u64| (at, "published".to_string(), None, None);
    let caught = page_of(catch_up_with(Form::Session, 40, script, 20, None, None, written).0);
    assert_eq!(named(&caught), [published(22), drafts(24, by(), burst()), published(26), drafts(28, None, None), drafts(30, by(), None)]);
    let caught = page_of(catch_up_with(Form::Drafts, 40, script, 20, None, None, written).0);
    assert_eq!(named(&caught), [drafts(24, by(), burst()), drafts(28, None, None), drafts(30, by(), None)]);
    let caught = page_of(catch_up_with(Form::Guest, 40, script, 20, None, None, written).0);
    assert_eq!(named(&caught), [published(22), published(26), published(30)]);
}

/// Checks that a drafts entry names its writing session past that one's end.
///
/// It is skep #1000's catch-up after a death. Against the real daemon, a signed
/// session mints a draft through `op` and writes a burst with the `id` `b-1` on
/// it: `changes(class: "drafts")` from the session's open names the session as
/// `by` on both of the draft's rows and `b-1` as `burst` on the burst's alone.
/// The session's token is then closed at the board and a call meets the death;
/// a session the page regains reads the drafts class from the ended session's
/// `opened_at`, and both rows still name the ended session and the burst (the
/// mutant that drops a session's record at its `session-died` names no writer
/// on the very read a page makes to learn what the end cut off).
#[test]
fn a_drafts_entry_names_the_session_that_wrote_it_past_that_sessions_end() {
    let dir = TempDir::new().unwrap();
    let sd = spawn(&dir.path().join("board"), true);
    let origin = format!("http://127.0.0.1:{}", sd.port());
    let store = dir.path().join("store");
    claim_board(&origin, &store);
    let (shell, _) = open_shell(&origin, &store, SessionMode::Signed { principal: 1 });
    let seen = Arc::new(Mutex::new(Vec::new()));
    let _answerer = answer_moments(shell.subscribe(), Arc::clone(&shell.pending), Arc::clone(&seen));
    let board = shell.board_references().remove(0);
    let opened = shell.call("session", &json!({"board": board})).unwrap();
    let (session, opened_at) = (opened["session"].as_str().unwrap().to_string(), opened["opened_at"].as_u64().unwrap());
    let minted = shell.call("op", &json!({"session": session, "frame": {"op": "create_new_document", "account": "1.0.1"}})).unwrap();
    let draft = minted["addr"].as_str().unwrap().to_string();
    let burst = json!({"op": "insert", "doc": draft, "at": {"subspace": "1", "ordinal": "1"}, "values": ["mine"], "as_of": minted["at"], "id": "b-1"});
    let inserted = shell.call("op", &json!({"session": session, "frame": burst})).unwrap();
    let owed = [(minted["at"].as_u64().unwrap(), Some(session.as_str()), None), (inserted["at"].as_u64().unwrap(), Some(session.as_str()), Some("b-1"))];
    let named = |page: &Value| -> Vec<(u64, Option<String>, Option<String>)> {
        crate::shapes::assert_declared("ChangesAnswer", page);
        let entries = page["entries"].as_array().unwrap();
        entries.iter().for_each(|entry| crate::shapes::assert_declared("FeedUpdate", entry));
        entries.iter().filter(|e| e["docs"] == json!([draft])).map(|e| (e["at"].as_u64().unwrap(), e["by"].as_str().map(str::to_string), e["burst"].as_str().map(str::to_string))).collect()
    };
    let owed: Vec<(u64, Option<String>, Option<String>)> = owed.iter().map(|(at, by, burst)| (*at, by.map(str::to_string), burst.map(str::to_string))).collect();
    let before = shell.call("changes", &json!({"session": session, "since": opened_at, "class": "drafts"})).unwrap();
    assert_eq!(named(&before), owed, "the writing session on both rows, the burst on its own: {before}");
    // The end, met by a call: the token closed at the board.
    let library = Board::new(Origin::parse(&origin).unwrap(), skep_client::PlainHttp::new());
    library.session_close(&shell.sessions.get(&session).unwrap().token).unwrap();
    let died = shell.call("changes", &json!({"session": session, "since": opened_at})).unwrap_err();
    assert_eq!(died.name(), "session_died", "{died}");
    let regained = shell.call("session", &json!({"board": board})).unwrap()["session"].as_str().unwrap().to_string();
    let after = shell.call("changes", &json!({"session": regained, "since": opened_at, "class": "drafts"})).unwrap();
    assert_eq!(named(&after), owed, "the ended session and its burst still named: {after}");
    shell.shutdown();
    sd.shutdown();
}
