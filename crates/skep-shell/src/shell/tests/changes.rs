//! THE `changes` CALL: a client that comes back to a board catches up from
//! a position it names, at its session's class. Against the real daemon: a
//! write by a second session after a position appears in the page from it
//! with its position, under the `drafts` class and the session, `next`
//! advances past it, a second ask from `next` answers nothing new, a draft
//! in an account the session cannot read never appears while that
//! account's published home does, `limit` bounds the page, and the
//! refusals by name. Over a scripted board: the two reads merged by
//! position — a straddle answered once, by the wider rendering — the
//! published read token-free and the drafts read under the token, the cut
//! where a read's `more` stands, `next` at the head read first on a quiet
//! board, `limit` over the merged page, a page past the budget re-asked at
//! the limit that fits, the retention floor as the board's own 410, and
//! the death signal as the death.

use std::io::Read;

use skep_client::board::{frames, Opened, SessionBody};
use skep_client::dial::{DialError, Dialer, Headers, Method, Request, RequestHead, Response, StreamedResponse};

use super::*;
use crate::feed::{changes_since, ChangesRead};
use crate::refs::BoardEntry;
use crate::sessions::{Facts, Open, Sessions, Supplements};

/// A CLIENT CATCHES UP FROM A POSITION AT ITS SESSION's CLASS: a draft
/// minted and written by a second session of the claimant's — the
/// library's own bare session as principal 1 — after the position N the
/// shell's session read, appears in `changes(N)` with its position, of the
/// `drafts` class under the session, every entry past N; `next` advances
/// past the write, and a second ask from `next` answers nothing new; from
/// the start, the session's own draft rows ride its class, a sibling
/// account's published home is everyone's, and that sibling's draft —
/// which the claimant's class never reads — appears nowhere, every entry
/// once, oldest first; `limit` bounds the page, `next` at the last entry
/// kept and the next ask reading on from it; `since` and `limit` of another
/// form are `malformed_args` by name, a stale session `session_ended`, and
/// a `limit` off the route's range the board's own `malformed_changes`
/// (the mutant that reads the drafts page without the session's token
/// loses the session's own rows; the one that reads the published feed
/// under the token answers one class for both).
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
    let foreign = addr(written(&two, &frames::create_document(&sibling, false, None)));
    written(&two, &json!({"op": "insert", "doc": foreign, "at": {"subspace": "1", "ordinal": "1"}, "values": ["theirs"]}));
    // The position N, the board's head as the session reads it.
    let n = shell.call("health", &json!({"board": board})).unwrap()["health"]["log_position"].as_u64().unwrap();
    // A write by a second session of the claimant's after N.
    let one = bare(1);
    let draft = addr(written(&one, &frames::create_document("1.0.1", false, None)));
    let at = written(&one, &json!({"op": "insert", "doc": draft, "at": {"subspace": "1", "ordinal": "1"}, "values": ["mine"]}))["at"].as_u64().unwrap();
    let page = shell.call("changes", &json!({"session": session, "since": n})).unwrap();
    crate::shapes::assert_declared("ChangesAnswer", &page);
    let entries = page["entries"].as_array().unwrap();
    entries.iter().for_each(|entry| crate::shapes::assert_declared("FeedUpdate", entry));
    let row = entries.iter().find(|entry| entry["at"] == at).unwrap_or_else(|| panic!("the insert at {at}, after {n}: {page}"));
    assert_eq!((row["position"].as_u64(), row["class"].as_str(), row["session"].as_str(), &row["docs"]), (Some(at), Some("drafts"), Some(session.as_str()), &json!([draft])), "{row}");
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

/// A board's answer to one `/changes` ask: by the ask's `since`, whether it
/// is the `drafts=true` read, and its `limit`.
type Script = Box<dyn Fn(u64, bool, Option<u64>) -> Response + Send + Sync>;

/// The asks a board saw: each one's `since`, whether it was the drafts read,
/// its `limit`, and whether a token rode it.
type Asked = Vec<(u64, bool, Option<u64>, bool)>;

/// A board whose `/changes` answers each ask as `script` says and whose
/// `/health` names `head`; every ask recorded.
struct Scripted {
    head: u64,
    script: Script,
    asked: Mutex<Asked>,
}

/// The number the query member `key` names in `path`, where it names one.
fn query_of(path: &str, key: &str) -> Option<u64> {
    path.split_once(&format!("{key}=")).and_then(|(_, rest)| rest.split('&').next()).and_then(|n| n.parse().ok())
}

fn ok(v: Value) -> Response {
    Response { status: 200, headers: Headers::default(), body: v.to_string().into_bytes() }
}

/// One row at `at` naming `docs`.
fn row(at: u64, docs: &[&str]) -> Value {
    json!({"at": at, "op": "insert", "docs": docs, "key": "bare"})
}

/// A page of `rows` with its `last` and its `more`.
fn page(rows: Vec<Value>, last: u64, more: bool) -> Response {
    ok(json!({"changes": rows, "last": last, "more": more}))
}

/// A non-200 answer of `body`.
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
        self.asked.lock().unwrap().push((since, drafts, limit, with_token));
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

/// A bare session of principal 1 at a board scripted by `script`, its head
/// at `head`; the catch-up read from `since` under `limit`, and the asks
/// the board saw.
fn catch_up_over(head: u64, script: impl Fn(u64, bool, Option<u64>) -> Response + Send + Sync + 'static, since: u64, limit: Option<u64>) -> (Result<ChangesRead, Refusal>, Asked) {
    let fake = Arc::new(Scripted { head, script: Box::new(script), asked: Mutex::new(Vec::new()) });
    let entry = Arc::new(BoardEntry { reference: "b-1".into(), board: Arc::new(Board::new(Origin::parse("http://127.0.0.1:9").unwrap(), Arc::clone(&fake))) });
    let facts = Facts { principal: 1, account: Some("1.0.1".into()), kind: SessionKind::Bare };
    let session = Sessions::new(None).register(&entry, Open { token: Token::parse(&"9f".repeat(16)).unwrap(), facts, opened_at: 0 }, &mut NoSupplements);
    let read = changes_since(&session, since, limit);
    let asked = fake.asked.lock().unwrap().clone();
    (read, asked)
}

/// The page a read answered, or a panic naming what it answered instead.
fn page_of(read: Result<ChangesRead, Refusal>) -> crate::feed::CaughtUp {
    match read {
        Ok(ChangesRead::Page(page)) => page,
        other => panic!("a page: {other:?}"),
    }
}

/// The positions of a page's entries, with each entry's class.
fn classed(page: &crate::feed::CaughtUp) -> Vec<(u64, &str)> {
    page.entries.iter().map(|entry| (entry["at"].as_u64().unwrap(), entry["class"].as_str().unwrap())).collect()
}

/// THE TWO READS MERGE BY POSITION, THE WIDER RENDERING WINNING: the
/// published feed read token-free and the drafts supplement under the
/// session's token, from the same `since` — each entry in the update's
/// shape, `published` or `drafts` by the read that answered it, a drafts
/// entry naming the session; a position both answer — a straddle, the
/// guest's `[T]` beside the supplement's `[D, T]` — answered once, by the
/// rendering naming more documents; and, both reads read to the head,
/// `next` the head read first, which lies past every entry (the mutants
/// that read the drafts page token-free, read the published feed under the
/// token, keep the narrower rendering, or answer `next` as the last entry
/// on a board that moved past it on masked commits).
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
    assert_eq!(asked, [(20, false, None, false), (20, true, None, true)], "the published feed token-free, the supplement under the token, each from `since`");
}

/// THE PAGE IS CUT WHERE A READ's `more` STANDS: nothing past the lower
/// `last` of an unfinished read is answered — the other read may hold a
/// position between — and `next` is that cut, whichever read is the short
/// one; both reads complete and empty, `next` is the head, and a `since`
/// past the head is echoed back (the mutants that answer every row of both
/// reads, skipping the positions between, or take the greater `last`).
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

/// `limit` BOUNDS THE MERGED PAGE, and a page past the budget is re-asked
/// at the limit that fits: the merged entries cut to `limit`, `next` the
/// last kept, both reads asked at `limit`; a `malformed_changes` naming
/// `fits` re-asked at `fits` on that read alone (the mutants that bound
/// each read and not the merge, or face the budget's refusal).
#[test]
fn limit_bounds_the_merged_page_and_the_budget_is_re_asked() {
    let script = |_: u64, drafts: bool, _: Option<u64>| if drafts { page(vec![row(12, &["1.0.1.0.2"])], 12, false) } else { page(vec![row(11, &["1.0.1.0.1"]), row(13, &["1.0.1.0.1"])], 13, false) };
    let (read, asked) = catch_up_over(20, script, 10, Some(2));
    let caught = page_of(read);
    assert_eq!((classed(&caught), caught.next), (vec![(11, "published"), (12, "drafts")], 12));
    assert_eq!(asked.iter().map(|(_, _, limit, _)| *limit).collect::<Vec<_>>(), [Some(2), Some(2)], "each read asked at `limit`");
    let too_large = |_: u64, drafts: bool, limit: Option<u64>| match (drafts, limit) {
        (true, _) => page(Vec::new(), 10, false),
        (false, Some(1)) => page(vec![row(11, &["1.0.1.0.1"])], 11, true),
        (false, _) => refused(400, json!({"error": "malformed_changes", "budget": 2_097_152, "fits": 1})),
    };
    let (read, asked) = catch_up_over(20, too_large, 10, None);
    let caught = page_of(read);
    assert_eq!((classed(&caught), caught.next), (vec![(11, "published")], 11));
    assert_eq!(asked, [(10, false, None, false), (10, false, Some(1), false), (10, true, None, true)], "the published read re-asked at `fits`, the drafts read as asked");
}

/// THE FLOOR AND THE DEATH ARE FACED: a `since` below the feed's memory is
/// the board's own `410 history_reclaimed` with its floor, never resumed
/// behind the caller's back; another refusal is the board's verdict; and
/// the death signal on the drafts read is the death, for the shell to end
/// the session by (the mutants that resume at the floor as the feed thread
/// does — a catch-up silently short of what the caller asked — or read the
/// death as an empty page).
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
