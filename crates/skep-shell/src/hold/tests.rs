//! THE HOLD's FENCE: the classification table (T6) — every `DialError`, every
//! disposition, `poisoned`, `write_busy`, `durability` once/twice/three times,
//! and an ack, each to exactly its row; the five kinds are bursts and the
//! twelve other `WRITE_OPS` are not. And THE RESEND WALK over a fake board in
//! its three outcomes (§3c.5) — no row (send from the head), one own row
//! confirmed by content (the head `done kept`, nothing re-sent), a foreign row
//! (MOVED, nothing sent, never rebased) — a read the board refuses deciding
//! nothing, `history_reclaimed` decided by the arrangement alone, a refusal
//! the table holds nowhere leaving its line standing, a second window's
//! burst resent from memory, the `base` a hold takes, the refused run's
//! `resolve(drop)` dropping it and every line held behind it, and a drop's
//! `held` event saying the state of the line that stands first after it.

use std::io::Read;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::Receiver;
use std::sync::{Arc, Mutex};

use serde_json::json;
use skep_client::board::{Token, HEAD_MEMBER_1};
use skep_client::dial::{DialError, Dialer, Headers, Method, Request, RequestHead, Response, StreamedResponse};
use skep_client::Origin;
use tempfile::TempDir;

use super::*;
use crate::events::Event;
use crate::sessions::{Facts, Kind, Open, Supplements};

/// The five burst kinds are bursts; the twelve other write ops are not.
#[test]
fn the_five_kinds_are_bursts_and_no_other_write_op_is() {
    for op in BURST_KINDS {
        assert!(is_burst(&json!({"op": op})), "{op}");
    }
    for op in crate::shell::WRITE_OPS {
        let burst = BURST_KINDS.contains(&op);
        assert_eq!(is_burst(&json!({"op": op})), burst, "{op}");
    }
    assert!(!is_burst(&json!({"op": "publish"})));
    assert!(!is_burst(&json!({"op": "doc_metadata"})), "a read is no burst");
    assert!(!is_burst(&json!({})), "a frame with no op is no burst");
}

fn rej(code: &str, disposition: &str) -> Decision {
    classify(Outcome::Rejected { code, disposition }, 0)
}

/// THE CLASSIFICATION TABLE (§3c.4): each outcome to exactly its row. The own
/// node stopped, an ack, the death signal and a non-burst write sit outside
/// `classify` (the module doc) and are pinned by the shell's suite.
#[test]
fn every_outcome_classifies_to_exactly_its_row() {
    // No connection made — the burst did not leave (`sent: false`).
    for e in [DialError::Connect("x".into()), DialError::Resolve("x".into()), DialError::Tls("x".into())] {
        assert_eq!(classify(Outcome::Dial(&e), 0), Decision::Hold { cause: "unreachable", sent: false }, "{e}");
    }
    // The request left, its answer lost — it MAY have landed (`sent: true`).
    for e in [DialError::Timeout("x".into()), DialError::Io("x".into()), DialError::Truncated { declared: 9, got: 1 }, DialError::Response("x".into()), DialError::TooLarge { cap: 1 }] {
        assert_eq!(classify(Outcome::Dial(&e), 0), Decision::Hold { cause: "unreachable", sent: true }, "{e}");
    }
    // The scheme this build does not hold, or a request refused before any
    // connection — faced as built, no probe ends either.
    for e in [DialError::NotHeld("https".into()), DialError::Request("x".into())] {
        assert_eq!(classify(Outcome::Dial(&e), 0), Decision::Neither, "{e}");
    }
    // The codes. `poisoned` MAY have landed (§3c.2): the frames reached the
    // journal and a restart replays them, so its line says `sent: true`.
    assert_eq!(rej("poisoned", "halt"), Decision::Hold { cause: "poisoned", sent: true });
    assert_eq!(rej("write_busy", "retry"), Decision::Reissue);
    // `durability` once, twice → reissue; a THIRD on the same burst → hold.
    assert_eq!(classify(Outcome::Rejected { code: "durability", disposition: "retry" }, 0), Decision::Reissue);
    assert_eq!(classify(Outcome::Rejected { code: "durability", disposition: "retry" }, 1), Decision::Reissue);
    assert_eq!(classify(Outcome::Rejected { code: "durability", disposition: "retry" }, 2), Decision::Hold { cause: "durability", sent: false });
    // A `permanent` or `reorder` refusal → a REFUSED run.
    assert_eq!(rej("out_of_bounds", "permanent"), Decision::Refused);
    assert_eq!(rej("not_registered", "reorder"), Decision::Refused);
    // Any other retry-class rejection on a burst → faced, not held.
    assert_eq!(rej("history_busy", "retry"), Decision::Neither);
}

// ── THE RESEND WALK (a fake board, §3c.5) ────────────────────────────────────

/// A board under test: the chain `board_term` reads; the `/changes` rows the
/// read sees, each served only past the query's `since`, or a refusal armed
/// in the page's place; the draft's text, of which a `retrieve_v` answers
/// the positions it names — or no answer, where the site is armed unread;
/// the frames POSTed to `/op` recorded; and a scripted rejection where one is
/// armed.
struct Fake {
    chain: String,
    rows: Mutex<Vec<Value>>,
    changes_refused: Mutex<Option<(u16, Value)>>,
    text: Mutex<String>,
    site_unread: AtomicBool,
    sent: Mutex<Vec<Value>>,
    reject: Mutex<Option<Value>>,
    next_at: AtomicU64,
    writes_halted: AtomicBool,
}

impl Fake {
    fn new() -> Arc<Fake> {
        Arc::new(Fake {
            chain: "ab".repeat(32),
            rows: Mutex::new(Vec::new()),
            changes_refused: Mutex::new(None),
            text: Mutex::new(String::new()),
            site_unread: AtomicBool::new(false),
            sent: Mutex::new(Vec::new()),
            reject: Mutex::new(None),
            next_at: AtomicU64::new(50),
            writes_halted: AtomicBool::new(false),
        })
    }

    fn sent(&self) -> usize {
        self.sent.lock().unwrap().len()
    }
}

fn respond(status: u16, v: Value) -> Response {
    Response { status, headers: Headers::default(), body: v.to_string().into_bytes() }
}

fn ok(v: Value) -> Response {
    respond(200, v)
}

/// The number a query names under `key`, where it names one.
fn query(path: &str, key: &str) -> Option<u64> {
    path.split_once('?')?.1.split('&').find_map(|kv| kv.strip_prefix(key)?.strip_prefix('=')?.parse().ok())
}

/// A V-spec's `1.<from>` and `0.<width>`, as numbers.
fn span(spec: &Value) -> Option<(usize, usize)> {
    let from = spec["span"]["start"].as_str()?.strip_prefix("1.")?.parse().ok()?;
    let width = spec["span"]["width"].as_str()?.strip_prefix("0.")?.parse().ok()?;
    Some((from, width))
}

impl Dialer for Fake {
    fn exchange(&self, _origin: &Origin, req: &Request) -> Result<Response, DialError> {
        if req.method == Method::Get && req.path.starts_with("/health") {
            let halted = self.writes_halted.load(Ordering::SeqCst);
            return Ok(ok(
                json!({"ok": true, "log_position": 10, "chain_head": self.chain, "auth": {"claimant": "1.0.1", "local_trust": true, "origins": [], "signed_origins": []}, "media": {"uploads": true}, "head_time": 1, "writes": {"halted": halted}}),
            ));
        }
        if req.method == Method::Get && req.path.starts_with("/changes") {
            if let Some((status, body)) = self.changes_refused.lock().unwrap().clone() {
                return Ok(respond(status, body));
            }
            let since = query(&req.path, "since").unwrap_or(0);
            let limit = query(&req.path, "limit").unwrap_or(256) as usize;
            let past: Vec<Value> = self.rows.lock().unwrap().iter().filter(|r| r["at"].as_u64().unwrap_or(0) > since).cloned().collect();
            let page: Vec<Value> = past.iter().take(limit).cloned().collect();
            let last = page.last().and_then(|r| r["at"].as_u64()).unwrap_or(since);
            return Ok(ok(json!({"changes": page, "last": last, "more": past.len() > limit})));
        }
        if req.method == Method::Post && req.path == "/op" {
            let body: Value = serde_json::from_slice(&req.body).unwrap_or(Value::Null);
            if body["op"].as_str() == Some("retrieve_v") {
                if body["specs"][0]["doc"].as_str() == Some(HEAD_MEMBER_1) {
                    let head = json!({"type": "skep-head", "position": 1, "chain": self.chain}).to_string();
                    return Ok(ok(json!({"resp": "delivery", "items": [{"atom": head}]})));
                }
                if self.site_unread.load(Ordering::SeqCst) {
                    return Err(DialError::Connect("the site read is not answered".into()));
                }
                let text = self.text.lock().unwrap().clone();
                let (from, width) = span(&body["specs"][0]).unwrap_or((0, 0));
                return Ok(match text.get(from.saturating_sub(1)..from.saturating_sub(1) + width) {
                    Some(cut) if from > 0 => ok(json!({"resp": "delivery", "items": [{"content": cut}]})),
                    _ => ok(json!({"resp": "rejected", "code": "out_of_bounds", "disposition": "permanent", "op": "retrieve_v"})),
                });
            }
            self.sent.lock().unwrap().push(body.clone());
            if let Some(r) = self.reject.lock().unwrap().clone() {
                return Ok(ok(r));
            }
            let at = self.next_at.fetch_add(1, Ordering::SeqCst);
            return Ok(ok(json!({"resp": "ack", "at": at})));
        }
        Ok(ok(json!({})))
    }

    fn stream(&self, _: &Origin, _: &RequestHead, _: &mut dyn Read, _: &mut dyn FnMut(&Headers)) -> Result<StreamedResponse, DialError> {
        Err(DialError::Connect("no stream here".into()))
    }
}

struct NoSupp;
impl Supplements for NoSupp {
    fn widen(&mut self, _: &Arc<SessionEntry>) {}
    fn narrow(&mut self, _: u64) {}
}

/// The holds over the fake board, a session registered and its open read as
/// the shell reads it — the ground every resend cell stands on; the store
/// directory kept for the ground's life.
struct Ground {
    holds: Arc<Holds>,
    fake: Arc<Fake>,
    session: Arc<SessionEntry>,
    rx: Receiver<Event>,
    store: TempDir,
}

/// A `held` event held to its declaration (`shapes`' `HeldEvent`): every
/// required member present, none outside the table, and `session` a
/// reference — never null, as the declared type says.
fn declared(event: &Value) {
    let shape = crate::shapes::shape("HeldEvent").expect("HeldEvent is declared");
    let members = event.as_object().expect("an event's data is an object");
    for field in shape.fields {
        assert!(!field.required || members.contains_key(field.name), "{event}: `{}` is required", field.name);
    }
    assert!(members.keys().all(|k| shape.fields.iter().any(|f| f.name == k)), "{event}: a member the table does not declare");
    let session = shape.fields.iter().find(|f| f.name == "session").expect("`session` is declared");
    assert!(session.required && !session.ty.contains("null") && event["session"].is_string(), "{event}: the session is named, never null");
}

impl Ground {
    /// The `held` event states seen since the last look, each event held to
    /// its declaration.
    fn states(&self) -> Vec<String> {
        self.rx
            .try_iter()
            .filter(|e| e.name == "held")
            .map(|e| {
                declared(&e.data);
                e.data["state"].as_str().unwrap_or("?").to_string()
            })
            .collect()
    }

    /// `held(session)`'s lines.
    fn lines(&self) -> Vec<Value> {
        self.holds.lines("b-1", &self.session).unwrap().as_array().unwrap().clone()
    }

    /// A burst held for `cause`, `sent` as a lost answer's would be.
    fn hold(&self, frame: &Value, cause: &str, sent: bool) -> Value {
        self.holds.hold("b-1", &self.session, frame, Reason::of(cause, sent)).unwrap()
    }
}

/// The facts of a bare session as principal 1.
fn bare_facts() -> Facts {
    Facts { principal: 1, account: Some("1.0.1".into()), kind: Kind::Bare }
}

/// The facts of a session that holds a key — the signed mode's, its set the
/// account's own.
fn keyed_facts() -> Facts {
    let fingerprint = skep_identity::Fingerprint::parse_hex(&"5a".repeat(32)).unwrap();
    Facts { principal: 1, account: Some("1.0.1".into()), kind: Kind::Signed { fingerprint, set_account: "1.0.1".into() } }
}

/// The ground under a bare session opened at position 0.
fn ground() -> Ground {
    ground_in(TempDir::new().unwrap(), bare_facts(), 0)
}

/// The ground over `store`, under a session of `facts` opened at `opened_at`.
fn ground_in(store: TempDir, facts: Facts, opened_at: u64) -> Ground {
    let fake = Fake::new();
    let board = Arc::new(Board::new(Origin::parse("http://127.0.0.1:1").unwrap(), Arc::clone(&fake)));
    let sessions = Arc::new(Sessions::new());
    let bus = Arc::new(EventBus::new());
    let rx = bus.subscribe();
    let keys = Arc::new(FileStore::open(store.path().join("store")));
    let holds = Holds::new(Arc::clone(&sessions), bus, keys, store.path().to_path_buf(), Arc::new(|_: &str| {}));
    holds.register_board("b-1", board);
    let open = Open { token: Token::parse(&"9f".repeat(16)).unwrap(), facts, opened_at };
    let session = sessions.register("b-1", open, &mut NoSupp);
    holds.open_session("b-1", &session);
    Ground { holds, fake, session, rx, store }
}

fn insert(doc: &str, values: Value) -> Value {
    json!({"op": "insert", "doc": doc, "at": {"subspace": "1", "ordinal": "1"}, "values": values})
}

const DOC: &str = "1.0.1.0.1";

/// OUTCOME (i): no row since `base` — the held burst is sent from the head and
/// acked, the line resolved, the document's state `kept`.
#[test]
fn outcome_i_no_row_sends_from_the_head() {
    let g = ground();
    g.hold(&insert(DOC, json!(["hello"])), "unreachable", false);
    g.holds.probe("b-1");
    assert_eq!(g.fake.sent(), 1, "the head is sent once");
    assert_eq!(g.fake.sent.lock().unwrap()[0]["op"], "insert");
    assert!(g.lines().is_empty(), "the line is kept and gone");
    assert!(g.states().contains(&"kept".to_string()));
}

/// OUTCOME (ii): the in-flight burst (its line `sent: true`) landed — one row
/// of the session's own hand, consistent, its five values read back equal at
/// the site — so the head is `done kept` and NOTHING is re-sent (the mutant
/// that resends the head; the mutant that compares the frame's one string
/// with one position's value faces the person's own text `moved`).
#[test]
fn outcome_ii_a_landed_burst_is_kept_not_resent() {
    let g = ground();
    *g.fake.text.lock().unwrap() = "hello".into();
    *g.fake.rows.lock().unwrap() = vec![json!({"at": 77, "op": "insert", "key": "bare", "docs": [DOC]})];
    g.hold(&insert(DOC, json!(["hello"])), "unreachable", true);
    g.holds.probe("b-1");
    assert_eq!(g.fake.sent(), 0, "the landed head is NOT re-sent: {:?}", g.fake.sent.lock().unwrap());
    assert!(g.lines().is_empty(), "the line is done kept");
    let states = g.states();
    assert!(states.contains(&"kept".to_string()) && !states.contains(&"moved".to_string()), "{states:?}");
}

/// OUTCOME (iii): a foreign row on the document since `base` — the site MOVED:
/// no line is sent, the lines are re-faced `moved`, never rebased (the mutant
/// that sends the moved line at its old base).
#[test]
fn outcome_iii_a_foreign_row_moves_the_document() {
    let g = ground();
    *g.fake.rows.lock().unwrap() = vec![json!({"at": 77, "op": "insert", "key": "ff".repeat(32), "docs": [DOC]})];
    g.hold(&insert(DOC, json!(["hello"])), "unreachable", true);
    g.holds.probe("b-1");
    assert_eq!(g.fake.sent(), 0, "no line of a moved document is sent");
    let lines = g.lines();
    assert_eq!(lines[0]["cause"], "moved", "the line is faced moved: {lines:?}");
    let states = g.states();
    assert!(states.contains(&"moved".to_string()) && !states.contains(&"sending".to_string()), "a moved document is never said `sending`: {states:?}");
}

/// THE OWN HAND on a read (§3c.5; wire.md §`/changes`): a SIGNED entry's row
/// carries `attest` and NO `key`, and is the session's own under a session
/// that holds a key — the head `done kept`, nothing re-sent — and NOT own
/// under a bare session (the mutant that keys the test on `key` alone faces
/// the signed row `moved`); a row with `key: "bare"` is own under a bare
/// session alone, never under a keyed one.
#[test]
fn a_signed_row_is_own_under_a_keyed_session_alone() {
    let signed_row = json!({"at": 77, "op": "insert", "docs": [DOC], "attest": {"alg": "x", "sig": "y"}});
    let bare_row = json!({"at": 77, "op": "insert", "docs": [DOC], "key": "bare"});
    let walk = |facts: Facts, row: Value| -> (Vec<String>, usize) {
        let g = ground_in(TempDir::new().unwrap(), facts, 0);
        *g.fake.text.lock().unwrap() = "hello".into();
        *g.fake.rows.lock().unwrap() = vec![row];
        g.hold(&insert(DOC, json!(["hello"])), "unreachable", true);
        g.holds.probe("b-1");
        (g.states(), g.fake.sent())
    };
    let (states, sent) = walk(keyed_facts(), signed_row.clone());
    assert!(states.contains(&"kept".to_string()) && !states.contains(&"moved".to_string()), "the signed row is the keyed session's own: {states:?}");
    assert_eq!(sent, 0, "the landed head is not re-sent");
    let (states, _) = walk(Facts { kind: Kind::Bare, ..keyed_facts() }, signed_row);
    assert!(states.contains(&"moved".to_string()), "a signed row is foreign to a bare session: {states:?}");
    let (states, _) = walk(keyed_facts(), bare_row);
    assert!(states.contains(&"moved".to_string()), "a bare hand's row is foreign to a keyed session: {states:?}");
}

/// A ROW WHOSE TESTIMONY THE BOARD LOST (`docs`, `key`, `op` the reserved
/// null — the `poisoned` burst a restart replays, §3c.2) is judged by the
/// arrangement alone, decisively: a `sent` insert whose values read back
/// equal is kept and not re-sent (the mutant that reads it as a foreign hand
/// faces the person's own text `moved`); values that differ are `moved`; a
/// kind the site read cannot confirm is `moved` too, the person's act; and a
/// head that was never sent reads any row as `moved`.
#[test]
fn a_lost_testimony_row_is_judged_by_the_arrangement_alone() {
    let lost = json!({"at": 77, "docs": null, "key": null, "time": null, "op": null, "new_prefix": null, "new_id": null, "link": null, "placed": null, "base_extent": null});
    let walk = |frame: Value, text: &str, sent: bool| -> (Vec<String>, usize) {
        let g = ground();
        *g.fake.text.lock().unwrap() = text.into();
        *g.fake.rows.lock().unwrap() = vec![lost.clone()];
        g.hold(&frame, "poisoned", sent);
        g.holds.probe("b-1");
        (g.states(), g.fake.sent())
    };
    let (states, sent) = walk(insert(DOC, json!(["hello"])), "hello", true);
    assert!(states.contains(&"kept".to_string()) && !states.contains(&"moved".to_string()), "the landed insert is kept: {states:?}");
    assert_eq!(sent, 0, "the landed head is not re-sent");
    let (states, sent) = walk(insert(DOC, json!(["hello"])), "other", true);
    assert!(states.contains(&"moved".to_string()) && sent == 0, "values that differ: moved, nothing sent: {states:?}");
    let (states, sent) = walk(json!({"op": "delete", "doc": DOC, "at": {"subspace": "1", "ordinal": "1"}, "width": 1}), "hello", true);
    assert!(states.contains(&"moved".to_string()) && sent == 0, "a kind the site read cannot confirm: moved: {states:?}");
    let (states, sent) = walk(insert(DOC, json!(["hello"])), "hello", false);
    assert!(states.contains(&"moved".to_string()) && sent == 0, "a head never sent reads any row as moved: {states:?}");
}

/// A `halted` hold — the feed's `writes.halted` read, before any dial — is
/// `sent: false`: no dial was made, so nothing of it can have landed.
#[test]
fn a_halted_hold_before_any_dial_is_sent_false() {
    let g = ground();
    g.holds.note_health("b-1", true);
    let BurstAnswer::Answered(Ok(answer)) = g.holds.send_burst("b-1", &g.session, insert(DOC, json!(["hello"]))) else { panic!("held before the dial") };
    assert_eq!(answer["cause"], "halted", "{answer}");
    let lines = g.lines();
    assert_eq!((lines[0]["cause"].as_str(), lines[0]["sent"].as_bool()), (Some("halted"), Some(false)), "{lines:?}");
    assert_eq!(g.fake.sent(), 0, "no dial was made");
}

/// A READ THE BOARD REFUSES DECIDES NOTHING (§3c.5): a `/changes` answered
/// `503 feed_rebuilding` — the daemon re-covering a lost `commits.log` behind
/// its listener after an open, exactly when a resend runs — leaves a `sent`
/// head held and unsent (the mutant that reads the refusal as "no row" sends
/// a burst that may have landed a second time); once the board serves the
/// page, the next wake reads it and sends.
#[test]
fn a_read_the_board_refuses_decides_nothing() {
    let g = ground();
    *g.fake.changes_refused.lock().unwrap() = Some((503, json!({"error": "feed_rebuilding", "detail": "the feed is being re-covered"})));
    g.hold(&insert(DOC, json!(["hello"])), "unreachable", true);
    g.holds.probe("b-1");
    assert_eq!(g.fake.sent(), 0, "nothing is sent on a read the board refused");
    assert_eq!(g.lines()[0]["cause"], "unreachable", "the line stands as it was");
    let states = g.states();
    assert!(!states.contains(&"sending".to_string()), "an unread document is not said `sending`: {states:?}");
    *g.fake.changes_refused.lock().unwrap() = None;
    g.holds.probe("b-1");
    assert_eq!(g.fake.sent(), 1, "the next wake reads the page and sends");
    assert!(g.lines().is_empty());
}

/// `history_reclaimed` on the read (§3c.5): the arrangement alone decides — a
/// `sent` head whose values read back equal at its site is (ii), kept and not
/// re-sent; values that differ are (iii); a site read the board does not
/// answer decides nothing and the line stands (the mutant that trusts an
/// unread site keeps a burst that never landed).
#[test]
fn history_reclaimed_decides_by_the_arrangement() {
    let reclaimed = || Some((410, json!({"error": "history_reclaimed", "floor": 90})));
    let g = ground();
    *g.fake.changes_refused.lock().unwrap() = reclaimed();
    *g.fake.text.lock().unwrap() = "hello".into();
    g.hold(&insert(DOC, json!(["hello"])), "unreachable", true);
    g.holds.probe("b-1");
    assert_eq!(g.fake.sent(), 0, "the landed head is not re-sent");
    assert!(g.lines().is_empty(), "the values at the site keep it");
    assert!(g.states().contains(&"kept".to_string()));

    let g = ground();
    *g.fake.changes_refused.lock().unwrap() = reclaimed();
    *g.fake.text.lock().unwrap() = "other".into();
    g.hold(&insert(DOC, json!(["hello"])), "unreachable", true);
    g.holds.probe("b-1");
    assert_eq!((g.fake.sent(), g.lines()[0]["cause"].as_str()), (0, Some("moved")), "values that differ: moved");

    let g = ground();
    *g.fake.changes_refused.lock().unwrap() = reclaimed();
    g.fake.site_unread.store(true, Ordering::SeqCst);
    g.hold(&insert(DOC, json!(["hello"])), "unreachable", true);
    g.holds.probe("b-1");
    assert_eq!(g.fake.sent(), 0);
    assert_eq!(g.lines()[0]["cause"], "unreachable", "an unread site decides nothing: the line stands");
    assert!(!g.states().contains(&"kept".to_string()));
}

/// A REFUSAL THE TABLE HOLDS NOWHERE leaves a resent line standing: the board
/// answering `credential_refused`/`index_rebuilding`, retry-class — the cell
/// index rebuilding after an open, when resends run — is faced to no one and
/// never makes the line `done` (the mutant that writes `done kept` loses text
/// the board refused); the next wake, the index ready, sends and keeps it.
#[test]
fn a_refusal_the_table_holds_nowhere_leaves_the_line_standing() {
    let g = ground();
    *g.fake.reject.lock().unwrap() = Some(json!({"resp": "rejected", "code": "credential_refused", "detail": "index_rebuilding", "disposition": "retry", "op": "insert"}));
    g.hold(&insert(DOC, json!(["hello"])), "unreachable", false);
    g.holds.probe("b-1");
    assert_eq!(g.fake.sent(), 1, "the line was sent");
    assert_eq!(g.lines().len(), 1, "and stands: the board did not take it");
    assert!(!g.states().contains(&"kept".to_string()));
    *g.fake.reject.lock().unwrap() = None;
    g.holds.probe("b-1");
    assert_eq!(g.fake.sent(), 2, "the next wake sends it again");
    assert!(g.lines().is_empty() && g.states().contains(&"kept".to_string()));
}

/// A SECOND WINDOW (§3c.3): with the board's `held/<chain>/lock` held by
/// another shell, a burst is held in this shell's memory alone — answered
/// `other_window`, nothing written under the directory — and RESENT like any
/// line once the board answers (the mutant that skips another window's
/// queue holds every later burst `behind` it for the uptime); after it is
/// kept, the next burst is dialed.
#[test]
fn a_second_windows_burst_is_held_in_memory_and_resent() {
    let store = TempDir::new().unwrap();
    let dir = HeldDir::new(store.path(), Chain::parse(&"ab".repeat(32)).unwrap());
    dir.ensure().unwrap();
    let _first_window = dir.try_lock().unwrap().expect("the first window holds the lock");
    let held_dir = store.path().join("held").join("ab".repeat(32));
    let g = ground_in(store, bare_facts(), 0);
    let answer = g.hold(&insert(DOC, json!(["hello"])), "unreachable", false);
    assert_eq!((answer["resp"].as_str(), answer["cause"].as_str()), (Some("held"), Some("other_window")), "{answer}");
    assert!(!held_dir.join("principal-1.held").exists(), "a second window writes nothing");
    assert_eq!(g.lines().len(), 1, "the line stands in memory");
    g.holds.probe("b-1");
    assert_eq!(g.fake.sent(), 1, "the line is resent");
    assert!(g.lines().is_empty() && g.states().contains(&"kept".to_string()));
    let BurstAnswer::Answered(Ok(next)) = g.holds.send_burst("b-1", &g.session, insert(DOC, json!(["!"]))) else { panic!("the burst was answered") };
    assert_eq!(next["resp"], "ack", "no line stands, so the next burst is dialed: {next}");
}

/// THE BASE a hold takes (§3c.2): the `at` of the last ACKED write on its
/// document — whatever its kind: a mint's at its minted `addr`, a link's at
/// its `home`, a burst's at its `doc` — and where none, the session's OPEN
/// POSITION: a burst held on a document no ack names, its mint's row at 50
/// below the session's open at 60, reads past it, is sent, and kept (the
/// mutant whose base falls back to 0 faces the person's own text `moved`).
#[test]
fn a_hold_takes_the_last_acked_write_or_the_sessions_open_as_its_base() {
    let g = ground_in(TempDir::new().unwrap(), bare_facts(), 60);
    *g.fake.rows.lock().unwrap() = vec![json!({"at": 50, "op": "create_new_document", "key": "bare", "docs": [DOC]})];
    g.hold(&insert(DOC, json!(["hello"])), "unreachable", false);
    assert_eq!(g.lines()[0]["base"], 60, "no ack names the document: the session's open");
    g.holds.probe("b-1");
    assert_eq!(g.fake.sent(), 1);
    assert!(g.lines().is_empty() && g.states().contains(&"kept".to_string()), "the row before the open moves nothing");

    let g = ground();
    let mint = json!({"op": "create_new_document", "account": "1.0.1"});
    g.holds.note_ack("b-1", &g.session, &mint, &json!({"resp": "ack_addr", "addr": "1.0.1.0.2", "at": 70}));
    let link = json!({"op": "make_link", "home": "1.0.1.0.3", "from": {"addrs": []}, "to": {"addrs": []}, "ty": {"addrs": []}});
    g.holds.note_ack("b-1", &g.session, &link, &json!({"resp": "ack_addr", "addr": "1.0.1.0.3.0.2.1", "at": 71}));
    g.holds.note_ack("b-1", &g.session, &insert("1.0.1.0.4", json!(["x"])), &json!({"resp": "delivery", "items": []}));
    for (doc, base) in [("1.0.1.0.2", 70), ("1.0.1.0.3", 71), ("1.0.1.0.4", 0)] {
        let held = g.hold(&insert(doc, json!(["x"])), "unreachable", false);
        let k = held["held"].as_u64().unwrap();
        let line = g.lines().into_iter().find(|l| l["held"] == k).unwrap();
        assert_eq!(line["base"], base, "{doc}: {line}");
    }

    // A burst dialed and acked notes its own `at`.
    let g = ground();
    let BurstAnswer::Answered(Ok(ack)) = g.holds.send_burst("b-1", &g.session, insert(DOC, json!(["a"]))) else { panic!("acked") };
    let at = ack["at"].as_u64().unwrap();
    g.hold(&insert(DOC, json!(["b"])), "unreachable", false);
    assert_eq!(g.lines()[0]["base"], at);
}

/// A REFUSED run and `resolve`: `drop` on the refused head drops it AND every
/// line held `behind` it on that document (the mutant that leaves them
/// standing), the `held` event naming the session that acted; `resolve` on a
/// holding line answers `not_resolvable`; an unknown ordinal answers
/// `no_such_held`.
#[test]
fn a_refused_run_drops_its_behind_lines() {
    let g = ground();
    let verdict = json!({"resp": "rejected", "code": "out_of_bounds", "disposition": "permanent"});
    let head = insert(DOC, json!(["a"]));
    let k1 = g.holds.hold("b-1", &g.session, &head, Reason::refused("out_of_bounds", verdict)).unwrap()["held"].as_u64().unwrap();
    // Two more bursts on the same document arrive while the run stands → behind.
    let behind = |values: Value| -> Value {
        let BurstAnswer::Answered(Ok(answer)) = g.holds.send_burst("b-1", &g.session, insert(DOC, values)) else { panic!("held behind the run") };
        answer
    };
    let k2 = behind(json!(["b"]))["held"].as_u64().unwrap();
    assert_eq!(behind(json!(["c"]))["cause"], "behind");
    assert_eq!(g.lines().len(), 3, "the run and its two behind lines stand");
    // A holding line is not resolvable; an unknown ordinal is no_such_held.
    assert_eq!(g.holds.resolve("b-1", &g.session, k2, "drop").unwrap_err().name(), "not_resolvable");
    assert_eq!(g.holds.resolve("b-1", &g.session, 999, "drop").unwrap_err().name(), "no_such_held");
    // Drop the refused head: the whole run goes.
    let _ = g.rx.try_iter().count();
    g.holds.resolve("b-1", &g.session, k1, "drop").unwrap();
    assert!(g.lines().is_empty(), "the run and its behind lines are dropped");
    assert_eq!(g.fake.sent(), 0, "nothing is dialed on a drop");
    let said: Vec<Event> = g.rx.try_iter().filter(|e| e.name == "held").collect();
    assert_eq!(said.len(), 1, "{said:?}");
    let said = &said[0].data;
    declared(said);
    assert_eq!((said["session"].as_str(), said["held"].as_u64(), said["state"].as_str()), (Some(g.session.reference.as_str()), Some(0), Some("kept")), "the drop is said under the session that acted");
}

/// A DROP on a MOVED document (§4b.1's `resolve`, §4b.2's `held`): the
/// person drops a later line of a document the read faced `moved`, and the
/// line held before it stands moved still — the `held` event says `moved`
/// with the one line left, never `kept` over text still held (the mutant
/// that says `kept` at every drop lifts the page's marks); the drop of the
/// last line says `kept` with none.
#[test]
fn a_drop_says_the_state_of_the_line_that_stands_first() {
    let g = ground();
    *g.fake.rows.lock().unwrap() = vec![json!({"at": 77, "op": "insert", "key": "ff".repeat(32), "docs": [DOC]})];
    let ks: Vec<u64> = ["a", "b", "c"].iter().map(|v| g.hold(&insert(DOC, json!([v])), "unreachable", false)["held"].as_u64().unwrap()).collect();
    g.holds.probe("b-1");
    assert!(g.lines().iter().all(|l| l["cause"] == "moved"), "the read faces every line moved: {:?}", g.lines());
    let _ = g.rx.try_iter().count();
    g.holds.resolve("b-1", &g.session, ks[1], "drop").unwrap();
    let said: Vec<Event> = g.rx.try_iter().filter(|e| e.name == "held").collect();
    assert_eq!(said.len(), 1, "{said:?}");
    declared(&said[0].data);
    assert_eq!((said[0].data["state"].as_str(), said[0].data["held"].as_u64()), (Some("moved"), Some(1)), "{said:?}");
    let left: Vec<u64> = g.lines().iter().map(|l| l["held"].as_u64().unwrap()).collect();
    assert_eq!(left, [ks[0]], "the dropped line and the one after it are gone");
    g.holds.resolve("b-1", &g.session, ks[0], "drop").unwrap();
    let said: Vec<Event> = g.rx.try_iter().filter(|e| e.name == "held").collect();
    assert_eq!((said[0].data["state"].as_str(), said[0].data["held"].as_u64()), (Some("kept"), Some(0)), "{said:?}");
}

/// No line is written outside the board's own directory: a burst held at a
/// board whose directory is this shell's lands in `held/<chain>/`.
#[test]
fn a_held_line_lands_under_the_boards_own_directory() {
    let g = ground();
    let answer = g.hold(&insert(DOC, json!(["hello"])), "unreachable", false);
    assert!(answer.get("unwritable").is_none(), "{answer}");
    let file = g.store.path().join("held").join("ab".repeat(32)).join("principal-1.held");
    let text = std::fs::read_to_string(&file).unwrap();
    assert!(text.lines().next().unwrap().contains("\"account\":\"1.0.1\""), "the header names the session's account: {text}");
}
