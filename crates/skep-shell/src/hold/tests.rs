//! THE HOLD's FENCE: the classification table (T6) — every `DialError`, every
//! disposition, `poisoned`, `write_busy`, `durability` once/twice/three times,
//! and an ack, each to exactly its row; the five kinds are bursts and the
//! eleven other `WRITE_OPS` are not. And THE RESEND WALK over a fake board:
//! THE READ's TABLE (§3c.5), every answer the read can meet against every
//! answer its site read can — no row (send from the head), one own row its
//! site does not contradict (the head `done kept`, nothing re-sent), a lost
//! testimony and `history_reclaimed` decided by the site alone, a foreign
//! row, two rows and a page too large (MOVED, nothing sent, never rebased),
//! a read or a site the board does not answer deciding nothing — with the
//! narrative cells beside it; a refusal the table holds nowhere faced at the
//! first dial and leaving a resent line standing; a second window's burst
//! resent from memory; the `base` a hold takes; the own node stopped,
//! `writes.halted` and a third `durability` holding a burst over time; P38's
//! halted file and a copy the store cannot make; the stored frame without
//! its attest; the refused run's `resolve(drop)` dropping it and every line
//! held behind it on its own document alone, a move facing its own document
//! alone, and a drop's `held` event saying the state of the line that stands
//! first after it; and one drain per board at a time, a drain that unwinds
//! leaving the board free to drain again.

use std::io::Read;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::mpsc::Receiver;
use std::sync::{Arc, Condvar, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use serde_json::json;
use skep_client::board::{Token, HEAD_MEMBER_1};
use skep_client::dial::{DialError, Dialer, Headers, Method, Request, RequestHead, Response, StreamedResponse};
use skep_client::Origin;
use tempfile::TempDir;

use super::*;
use crate::events::Event;
use crate::sessions::{Facts, Kind, Open, Supplements};

/// The five burst kinds are bursts; the eleven other write ops are not.
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

/// A board under test: the chain `board_term` reads — or no `H.1` at all,
/// where one is armed missing; the `/changes` rows the read sees, each served
/// only past the query's `since` and at or under its `under`, or a refusal
/// armed in the page's place; the draft's text, of which a `retrieve_v`
/// answers the positions it names — or no answer, where the site is armed
/// unread; the frames POSTed to `/op` recorded, and a scripted rejection or
/// a non-200 answered where one is armed; and the `/health` reads counted,
/// one armed to panic once, and each held at a gate while it is shut.
struct Fake {
    chain: String,
    no_head: AtomicBool,
    rows: Mutex<Vec<Value>>,
    changes_refused: Mutex<Option<(u16, Value)>>,
    text: Mutex<String>,
    site_unread: AtomicBool,
    sent: Mutex<Vec<Value>>,
    reject: Mutex<Option<Value>>,
    refuse_op: Mutex<Option<(u16, Value)>>,
    next_at: AtomicU64,
    writes_halted: AtomicBool,
    panic_next_health: AtomicBool,
    health_reads: AtomicUsize,
    health_gate: (Mutex<bool>, Condvar),
}

impl Fake {
    fn new() -> Arc<Fake> {
        Arc::new(Fake {
            chain: "ab".repeat(32),
            no_head: AtomicBool::new(false),
            rows: Mutex::new(Vec::new()),
            changes_refused: Mutex::new(None),
            text: Mutex::new(String::new()),
            site_unread: AtomicBool::new(false),
            sent: Mutex::new(Vec::new()),
            reject: Mutex::new(None),
            refuse_op: Mutex::new(None),
            next_at: AtomicU64::new(50),
            writes_halted: AtomicBool::new(false),
            panic_next_health: AtomicBool::new(false),
            health_reads: AtomicUsize::new(0),
            health_gate: (Mutex::new(false), Condvar::new()),
        })
    }

    fn sent(&self) -> usize {
        self.sent.lock().unwrap().len()
    }

    /// The `/health` gate shut: each read waits there until it opens.
    fn shut_health(&self) {
        *self.health_gate.0.lock().unwrap() = true;
    }

    /// The `/health` gate opened, every read waiting at it let through.
    fn open_health(&self) {
        *self.health_gate.0.lock().unwrap() = false;
        self.health_gate.1.notify_all();
    }
}

fn respond(status: u16, v: Value) -> Response {
    Response { status, headers: Headers::default(), body: v.to_string().into_bytes() }
}

fn ok(v: Value) -> Response {
    respond(200, v)
}

/// The text a query names under `key`, where it names one.
fn query_text<'p>(path: &'p str, key: &str) -> Option<&'p str> {
    path.split_once('?')?.1.split('&').find_map(|kv| kv.strip_prefix(key)?.strip_prefix('='))
}

/// The number a query names under `key`, where it names one.
fn query(path: &str, key: &str) -> Option<u64> {
    query_text(path, key)?.parse().ok()
}

/// Whether a row passes a read's `under` (wire.md §The change feed): every
/// row where the read names none; a row naming a document at or under it;
/// and a row whose testimony was lost (`docs` null), which this board places
/// on every document.
fn names_under(row: &Value, under: Option<&str>) -> bool {
    let (Some(under), Some(docs)) = (under, row["docs"].as_array()) else { return true };
    docs.iter().filter_map(Value::as_str).any(|doc| doc.strip_prefix(under).is_some_and(|rest| rest.is_empty() || rest.starts_with('.')))
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
            self.health_reads.fetch_add(1, Ordering::SeqCst);
            // The gate's guard is dropped before the armed panic, which would
            // otherwise poison the gate for every later read.
            let (gate, opened) = &self.health_gate;
            drop(opened.wait_while(gate.lock().unwrap(), |shut| *shut).unwrap());
            assert!(!self.panic_next_health.swap(false, Ordering::SeqCst), "the health read is made to panic");
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
            let under = query_text(&req.path, "under");
            let past: Vec<Value> = self.rows.lock().unwrap().iter().filter(|r| r["at"].as_u64().unwrap_or(0) > since && names_under(r, under)).cloned().collect();
            let page: Vec<Value> = past.iter().take(limit).cloned().collect();
            let last = page.last().and_then(|r| r["at"].as_u64()).unwrap_or(since);
            return Ok(ok(json!({"changes": page, "last": last, "more": past.len() > limit})));
        }
        if req.method == Method::Post && req.path == "/op" {
            let body: Value = serde_json::from_slice(&req.body).unwrap_or(Value::Null);
            if body["op"].as_str() == Some("retrieve_v") {
                if body["specs"][0]["doc"].as_str() == Some(HEAD_MEMBER_1) {
                    if self.no_head.load(Ordering::SeqCst) {
                        return Ok(ok(json!({"resp": "delivery", "items": []})));
                    }
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
            if let Some((status, refusal)) = self.refuse_op.lock().unwrap().clone() {
                return Ok(respond(status, refusal));
            }
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
            .filter(|e| e.name == EventName::Held)
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
    ground_over(Fake::new(), store, facts, opened_at)
}

/// The ground over `fake` — armed before the session opens and the holds
/// read its `H.1` — and `store`, under a session of `facts` opened at
/// `opened_at`.
fn ground_over(fake: Arc<Fake>, store: TempDir, facts: Facts, opened_at: u64) -> Ground {
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

/// A `delete` of the document's first position, in the wire's own form
/// (wire.md §Arrangement: `p` and `width`) — a burst whose site no read
/// confirms.
fn delete(doc: &str) -> Value {
    json!({"op": "delete", "doc": doc, "p": {"subspace": "1", "ordinal": "1"}, "width": "1"})
}

/// A `/changes` row whose testimony the board lost (wire.md §`/changes`):
/// every member but its `at` the reserved null.
fn lost_row() -> Value {
    json!({"at": 77, "docs": null, "key": null, "time": null, "op": null, "new_prefix": null, "new_id": null, "link": null, "placed": null, "base_extent": null})
}

const DOC: &str = "1.0.1.0.1";

/// A second document of the session's account.
const OTHER: &str = "1.0.1.0.2";

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
    let lost = lost_row();
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
    let (states, sent) = walk(delete(DOC), "hello", true);
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
/// document — whatever its kind: a mint's, a fork's and a version's at the
/// `addr` it minted, a link write's at its `home`, an edit's at both its
/// documents, a burst's at its `doc` — and where none, the session's OPEN
/// POSITION: a burst held on a document no ack names, its mint's row at 50
/// below the session's open at 60, reads past it, is sent, and kept (the
/// mutant whose base falls back to 0 faces the person's own text `moved`);
/// a read notes nothing, so its document keeps the open (the mutant that
/// drops one kind from the documents an ack names leaves that kind's
/// document at the open).
#[test]
fn a_hold_takes_the_last_acked_write_or_the_sessions_open_as_its_base() {
    let g = ground_in(TempDir::new().unwrap(), bare_facts(), 60);
    *g.fake.rows.lock().unwrap() = vec![json!({"at": 50, "op": "create_new_document", "key": "bare", "docs": [DOC]})];
    g.hold(&insert(DOC, json!(["hello"])), "unreachable", false);
    assert_eq!(g.lines()[0]["base"], 60, "no ack names the document: the session's open");
    g.holds.probe("b-1");
    assert_eq!(g.fake.sent(), 1);
    assert!(g.lines().is_empty() && g.states().contains(&"kept".to_string()), "the row before the open moves nothing");

    let g = ground_in(TempDir::new().unwrap(), bare_facts(), 60);
    let noted = |frame: Value, ack: Value| g.holds.note_ack("b-1", &g.session, &frame, &ack);
    let minted = |addr: &str, at: u64| json!({"resp": "ack_addr", "addr": addr, "at": at});
    noted(json!({"op": "create_new_document", "account": "1.0.1"}), minted("1.0.1.0.2", 70));
    noted(json!({"op": "make_link", "home": "1.0.1.0.3", "from": {"addrs": []}, "to": {"addrs": []}, "ty": {"addrs": []}}), minted("1.0.1.0.3.0.2.1", 71));
    noted(insert("1.0.1.0.4", json!(["x"])), json!({"resp": "delivery", "items": []}));
    noted(json!({"op": "emit", "home": "1.0.1.0.5", "ty": [], "from": "1.0.1.0.5.0.1.1", "to": []}), minted("1.0.1.0.5.0.2.1", 72));
    noted(json!({"op": "nullify", "home": "1.0.1.0.6", "target": "1.0.1.0.3.0.2.1"}), minted("1.0.1.0.6.0.2.1", 73));
    noted(json!({"op": "assert_sup", "home": "1.0.1.0.7", "old": "1.0.1.0.3.0.2.1", "new": "1.0.1.0.5.0.2.1"}), minted("1.0.1.0.7.0.2.1", 74));
    noted(json!({"op": "edit_link", "original": "1.0.1.0.3.0.2.1", "d_s": "1.0.1.0.8", "d_a": "1.0.1.0.9", "successor": {}}), json!({"resp": "ack_edit", "at": 75}));
    noted(json!({"op": "fork"}), minted("1.0.1.0.10", 76));
    noted(json!({"op": "version", "d_src": "1.0.1.0.2"}), minted("1.0.1.0.2.1", 77));
    let bases = [
        ("1.0.1.0.2", 70),
        ("1.0.1.0.3", 71),
        ("1.0.1.0.4", 60),
        ("1.0.1.0.5", 72),
        ("1.0.1.0.6", 73),
        ("1.0.1.0.7", 74),
        ("1.0.1.0.8", 75),
        ("1.0.1.0.9", 75),
        ("1.0.1.0.10", 76),
        ("1.0.1.0.2.1", 77),
    ];
    for (doc, base) in bases {
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

/// A REFUSED run and `resolve`: the run's line carries the board's verdict
/// as its `refusal` (§3c.2, "for the face") and the lines `behind` it carry
/// none; `drop` on the refused head drops it AND every line held `behind`
/// it on that document (the mutant that leaves them standing), the `held`
/// event naming the session that acted; `resolve` on a holding line answers
/// `not_resolvable`, as an act of no name does on the run, which stands
/// whole (the mutant whose last arm drops it); an unknown ordinal answers
/// `no_such_held`.
#[test]
fn a_refused_run_drops_its_behind_lines() {
    let g = ground();
    let verdict = json!({"resp": "rejected", "code": "out_of_bounds", "disposition": "permanent"});
    let head = insert(DOC, json!(["a"]));
    let k1 = g.holds.hold("b-1", &g.session, &head, Reason::refused("out_of_bounds", verdict.clone())).unwrap()["held"].as_u64().unwrap();
    // Two more bursts on the same document arrive while the run stands → behind.
    let behind = |values: Value| -> Value {
        let BurstAnswer::Answered(Ok(answer)) = g.holds.send_burst("b-1", &g.session, insert(DOC, values)) else { panic!("held behind the run") };
        answer
    };
    let k2 = behind(json!(["b"]))["held"].as_u64().unwrap();
    assert_eq!(behind(json!(["c"]))["cause"], "behind");
    let lines = g.lines();
    assert_eq!(lines.len(), 3, "the run and its two behind lines stand");
    assert_eq!(lines[0]["refusal"], verdict, "the refused run's line carries the board's verdict");
    assert!(lines[1..].iter().all(|l| l.get("refusal").is_none()), "a line behind the run carries no refusal: {lines:?}");
    // A holding line is not resolvable; an unknown ordinal is no_such_held.
    assert_eq!(g.holds.resolve("b-1", &g.session, k2, "drop").unwrap_err().name(), "not_resolvable");
    assert_eq!(g.holds.resolve("b-1", &g.session, 999, "drop").unwrap_err().name(), "no_such_held");
    // An act of no name is no act: the run stands whole.
    assert_eq!(g.holds.resolve("b-1", &g.session, k1, "dropp").unwrap_err().name(), "not_resolvable");
    assert_eq!(g.lines().len(), 3, "an act of no name drops nothing");
    // Drop the refused head: the whole run goes.
    let _ = g.rx.try_iter().count();
    g.holds.resolve("b-1", &g.session, k1, "drop").unwrap();
    assert!(g.lines().is_empty(), "the run and its behind lines are dropped");
    assert_eq!(g.fake.sent(), 0, "nothing is dialed on a drop");
    let said: Vec<Event> = g.rx.try_iter().filter(|e| e.name == EventName::Held).collect();
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
    let said: Vec<Event> = g.rx.try_iter().filter(|e| e.name == EventName::Held).collect();
    assert_eq!(said.len(), 1, "{said:?}");
    declared(&said[0].data);
    assert_eq!((said[0].data["state"].as_str(), said[0].data["held"].as_u64()), (Some("moved"), Some(1)), "{said:?}");
    let left: Vec<u64> = g.lines().iter().map(|l| l["held"].as_u64().unwrap()).collect();
    assert_eq!(left, [ks[0]], "the dropped line and the one after it are gone");
    g.holds.resolve("b-1", &g.session, ks[0], "drop").unwrap();
    let said: Vec<Event> = g.rx.try_iter().filter(|e| e.name == EventName::Held).collect();
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

/// A DRAIN THAT UNWINDS leaves no mark (§3c.4): a probe whose `/health`
/// dial panics leaves the board free to drain, and the next probe sends and
/// keeps the line (the mutant whose mark outlives an unwinding drain sends
/// nothing for the shell's life).
#[test]
fn a_drain_that_unwinds_leaves_the_board_free_to_drain() {
    let g = ground();
    g.hold(&insert(DOC, json!(["hello"])), "unreachable", false);
    g.fake.panic_next_health.store(true, Ordering::SeqCst);
    let unwound = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| g.holds.probe("b-1")));
    assert!(unwound.is_err(), "the health read panicked");
    assert_eq!(g.fake.sent(), 0, "nothing was sent while it unwound");
    g.holds.probe("b-1");
    assert_eq!(g.fake.sent(), 1, "the next probe drains");
    assert!(g.lines().is_empty() && g.states().contains(&"kept".to_string()));
}

/// ONE DRAIN PER BOARD AT A TIME (§3c.4): a probe that comes while another
/// drains the board — the feed's cadence beside `resolve(send)` or
/// `set_node_state(Running)`, each on its own thread — dials nothing, so the
/// line is sent once (the mutant whose mark admits a second drain reads
/// `/health` twice, and may send the burst twice).
#[test]
fn a_probe_while_a_drain_runs_dials_nothing() {
    let g = ground();
    g.hold(&insert(DOC, json!(["hello"])), "unreachable", false);
    g.fake.shut_health();
    // The ground's receiver is no `Sync`: the threads take its holds and its
    // board alone.
    let (holds, fake) = (&g.holds, &g.fake);
    let reads = thread::scope(|s| {
        let first = s.spawn(move || holds.probe("b-1"));
        let deadline = Instant::now() + Duration::from_secs(5);
        while fake.health_reads.load(Ordering::SeqCst) < 1 && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(5));
        }
        let second = s.spawn(move || holds.probe("b-1"));
        let deadline = Instant::now() + Duration::from_secs(5);
        while !second.is_finished() && fake.health_reads.load(Ordering::SeqCst) < 2 && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(5));
        }
        let reads = fake.health_reads.load(Ordering::SeqCst);
        // The gate opens before any assertion, so a failure never hangs here.
        fake.open_health();
        first.join().unwrap();
        second.join().unwrap();
        reads
    });
    assert_eq!(reads, 1, "a second probe read `/health` while the first drained the board");
    assert_eq!(g.fake.sent(), 1, "the line is sent once");
    assert!(g.lines().is_empty());
}

// ── THE READ's TABLE (§3c.5) ─────────────────────────────────────────────────

/// What the board answers THE READ of the held head's document.
#[derive(Debug, Clone, Copy)]
enum TheRead {
    /// A page holding no row since the head's `base`.
    NoRow,
    /// A page of one row of the session's own hand, of the `op` named.
    OwnRow(&'static str),
    /// A page of one row whose testimony the board lost.
    LostRow,
    /// A page of one row of another hand.
    ForeignRow,
    /// A page of two rows of the session's own hand.
    TwoOwnRows,
    /// `410 history_reclaimed`: the head's `base` below the feed's floor.
    Reclaimed,
    /// `400 malformed_changes` naming a `fits` of one row: two rows or more.
    TooLarge,
    /// `503 feed_rebuilding`: no page.
    Refused,
}

/// The held head: an `insert`, whose site a read can confirm, or a `delete`,
/// whose site none can.
#[derive(Debug, Clone, Copy)]
enum Head {
    Insert,
    Delete,
}

/// What a read of the head's site answers: the head's own values, other
/// values, or no answer.
#[derive(Debug, Clone, Copy)]
enum AtTheSite {
    Equal,
    Differs,
    Unread,
}

/// How one probe settles the head.
#[derive(Debug, Clone, Copy)]
enum Settles {
    /// Sent from the head, acked and kept.
    Resent,
    /// Kept as landed, nothing sent.
    Kept,
    /// Faced `moved`, nothing sent.
    Moved,
    /// Left as it stood: nothing sent, nothing said.
    Standing,
}

/// THE READ's TABLE (§3c.5), cell by cell: no row sends from the head; ONE
/// row is the head's landing only where the head was sent and the row is of
/// the session's own hand and of the head's own `op`, its site not
/// contradicting it — an `insert` read back equal, a kind no read confirms
/// trusted on its hand; a row whose testimony the board lost, and
/// `history_reclaimed`, are decided by the site alone, a kind no read
/// confirms faced `moved`; a foreign row, two rows and a page too large to
/// serve are `moved`; a read or a site read the board does not answer
/// decides nothing. The mutants the cells hold off: a second tab's own-hand
/// row landing a head whose site says otherwise (3), a delete faced on its
/// own hand (4), an unread site taken as either answer (5, 11, 18), a head
/// never sent kept off a row (6, 19), another `op` of the own hand (7), the
/// first of two rows taken as the landing (14), a reclaimed kind no read
/// confirms kept (17), and a page too large read as none or as unread (20).
#[test]
fn every_read_answer_meets_every_site_answer_as_the_table_says() {
    use AtTheSite::{Differs, Equal, Unread};
    use Head::{Delete, Insert};
    use Settles::{Kept, Moved, Resent, Standing};
    use TheRead::{ForeignRow, LostRow, NoRow, OwnRow, Reclaimed, Refused, TooLarge, TwoOwnRows};
    let table = [
        (NoRow, Insert, None, true, Resent),
        (OwnRow("insert"), Insert, Some(Equal), true, Kept),
        (OwnRow("insert"), Insert, Some(Differs), true, Moved),
        (OwnRow("delete"), Delete, None, true, Kept),
        (OwnRow("insert"), Insert, Some(Unread), true, Standing),
        (OwnRow("insert"), Insert, Some(Equal), false, Moved),
        (OwnRow("delete"), Insert, Some(Equal), true, Moved),
        (LostRow, Insert, Some(Equal), true, Kept),
        (LostRow, Insert, Some(Differs), true, Moved),
        (LostRow, Delete, None, true, Moved),
        (LostRow, Insert, Some(Unread), true, Standing),
        (LostRow, Insert, Some(Equal), false, Moved),
        (ForeignRow, Insert, Some(Equal), true, Moved),
        (TwoOwnRows, Insert, Some(Equal), true, Moved),
        (Reclaimed, Insert, Some(Equal), true, Kept),
        (Reclaimed, Insert, Some(Differs), true, Moved),
        (Reclaimed, Delete, None, true, Moved),
        (Reclaimed, Insert, Some(Unread), true, Standing),
        (Reclaimed, Insert, Some(Equal), false, Moved),
        (TooLarge, Insert, Some(Equal), true, Moved),
        (Refused, Insert, Some(Equal), true, Standing),
    ];
    for (n, (read, head, site, sent, settles)) in table.into_iter().enumerate() {
        let g = ground();
        let own = |at: u64, op: &str| json!({"at": at, "op": op, "key": "bare", "docs": [DOC]});
        let refused = |status: u16, body: Value| *g.fake.changes_refused.lock().unwrap() = Some((status, body));
        match read {
            NoRow => {}
            OwnRow(op) => *g.fake.rows.lock().unwrap() = vec![own(77, op)],
            LostRow => *g.fake.rows.lock().unwrap() = vec![lost_row()],
            ForeignRow => *g.fake.rows.lock().unwrap() = vec![json!({"at": 77, "op": "insert", "key": "ff".repeat(32), "docs": [DOC]})],
            TwoOwnRows => *g.fake.rows.lock().unwrap() = vec![own(77, "insert"), own(78, "insert")],
            Reclaimed => refused(410, json!({"error": "history_reclaimed", "floor": 90})),
            TooLarge => refused(400, json!({"error": "malformed_changes", "fits": 1})),
            Refused => refused(503, json!({"error": "feed_rebuilding"})),
        }
        match site {
            Some(Equal) => *g.fake.text.lock().unwrap() = "hello".into(),
            Some(Differs) => *g.fake.text.lock().unwrap() = "other".into(),
            Some(Unread) => g.fake.site_unread.store(true, Ordering::SeqCst),
            None => {}
        }
        let frame = match head {
            Insert => insert(DOC, json!(["hello"])),
            Delete => delete(DOC),
        };
        g.hold(&frame, "unreachable", sent);
        g.holds.probe("b-1");
        // The sends, the causes still standing, and the `held` states said
        // after the hold's own `holding`.
        let (sends, standing, says): (usize, &[&str], &[&str]) = match settles {
            Resent => (1, &[], &["sending", "kept"]),
            Kept => (0, &[], &["kept"]),
            Moved => (0, &["moved"], &["moved"]),
            Standing => (0, &["unreachable"], &[]),
        };
        let lines = g.lines();
        let causes: Vec<&str> = lines.iter().map(|l| l["cause"].as_str().unwrap_or("?")).collect();
        let states = g.states();
        let said: Vec<&str> = states.iter().map(String::as_str).skip(1).collect();
        assert_eq!(states.first().map(String::as_str), Some("holding"), "row {}: the hold says `holding` first: {states:?}", n + 1);
        assert_eq!(
            (g.fake.sent(), causes, said),
            (sends, standing.to_vec(), says.to_vec()),
            "row {}: {read:?}, a held {head:?} head, its site {site:?}, sent {sent} — {settles:?} (sends, causes standing, states said)",
            n + 1
        );
    }
}

/// A DROP acts on its own document's run and on no other (§4b.1's
/// `resolve`): a refused run on one document, a burst on a second held
/// `behind` it — a standing line holds every later burst, whatever its
/// document — and the run's drop leaves the second document's line
/// standing, which the next probe sends and keeps (the mutant that drops
/// every later line, whatever its document, loses the person's text on the
/// other document).
#[test]
fn a_drop_drops_its_own_documents_run_and_no_other() {
    let g = ground();
    let verdict = json!({"resp": "rejected", "code": "out_of_bounds", "disposition": "permanent"});
    let k1 = g.holds.hold("b-1", &g.session, &insert(DOC, json!(["a"])), Reason::refused("out_of_bounds", verdict)).unwrap()["held"].as_u64().unwrap();
    let BurstAnswer::Answered(Ok(behind)) = g.holds.send_burst("b-1", &g.session, insert(OTHER, json!(["z"]))) else { panic!("held behind the run") };
    assert_eq!(behind["cause"], "behind", "{behind}");
    g.holds.resolve("b-1", &g.session, k1, "drop").unwrap();
    let docs: Vec<String> = g.lines().iter().map(|l| l["doc"].as_str().unwrap_or("?").to_string()).collect();
    assert_eq!(docs, [OTHER], "the run is dropped, the other document's line stands");
    g.holds.probe("b-1");
    assert_eq!(g.fake.sent(), 1, "the other document's line is sent");
    assert!(g.lines().is_empty() && g.states().contains(&"kept".to_string()));
}

/// A MOVED document faces its own lines and no other (§3c.5, J3): a foreign
/// row on one document moves it, while a burst held `behind` it on a second
/// document, whose read finds no row under it, is sent and kept (the mutant
/// that faces every line moved at one document's foreign row strands the
/// person's text on the other).
#[test]
fn a_moved_document_faces_its_own_lines_alone() {
    let g = ground();
    *g.fake.rows.lock().unwrap() = vec![json!({"at": 77, "op": "insert", "key": "ff".repeat(32), "docs": [DOC]})];
    g.hold(&insert(DOC, json!(["a"])), "unreachable", false);
    let BurstAnswer::Answered(Ok(behind)) = g.holds.send_burst("b-1", &g.session, insert(OTHER, json!(["z"]))) else { panic!("held behind the line") };
    assert_eq!(behind["cause"], "behind", "{behind}");
    g.holds.probe("b-1");
    let lines = g.lines();
    let standing: Vec<(&str, &str)> = lines.iter().map(|l| (l["doc"].as_str().unwrap_or("?"), l["cause"].as_str().unwrap_or("?"))).collect();
    assert_eq!(standing, [(DOC, "moved")], "the moved document's line alone stands");
    let sent: Vec<Value> = g.fake.sent.lock().unwrap().iter().map(|f| f["doc"].clone()).collect();
    assert_eq!(sent, [json!(OTHER)], "the other document's line is sent");
}

/// THE OWN NODE STOPPED (§3c.4): while its owner's stop stands, a burst is
/// held `stopped` without a dial — `sent: false`, since nothing left — and
/// the probe dials nothing; once the node runs, the probe sends and keeps
/// it (the mutant that dials past the stop, and the one whose probe drains
/// a stopped node).
#[test]
fn a_stopped_node_holds_every_burst_until_it_runs() {
    let g = ground();
    g.holds.set_node_stopped("b-1", true);
    let BurstAnswer::Answered(Ok(held)) = g.holds.send_burst("b-1", &g.session, insert(DOC, json!(["hello"]))) else { panic!("held before the dial") };
    assert_eq!((held["resp"].as_str(), held["cause"].as_str()), (Some("held"), Some("stopped")), "{held}");
    assert_eq!(g.lines()[0]["sent"], false);
    g.holds.probe("b-1");
    assert_eq!((g.fake.sent(), g.fake.health_reads.load(Ordering::SeqCst)), (0, 0), "nothing is dialed while the stop stands");
    g.holds.set_node_stopped("b-1", false);
    g.holds.probe("b-1");
    assert_eq!(g.fake.sent(), 1, "the running node takes the line");
    assert!(g.lines().is_empty() && g.states().contains(&"kept".to_string()));
}

/// THE HALTED HOLD lasts from the first `true` read of `writes.halted` to the
/// first `false` (§3c.4): a burst holds `halted`, a probe reading `true`
/// sends nothing, the probe reading `false` sends and keeps the line, and a
/// burst after it is dialed and acked (the mutant whose read only ever sets
/// the flag holds every later burst `halted` for the shell's life).
#[test]
fn the_halted_hold_ends_at_the_first_read_that_says_writes_go() {
    let g = ground();
    g.fake.writes_halted.store(true, Ordering::SeqCst);
    g.holds.note_health("b-1", true);
    let BurstAnswer::Answered(Ok(held)) = g.holds.send_burst("b-1", &g.session, insert(DOC, json!(["hello"]))) else { panic!("held before the dial") };
    assert_eq!(held["cause"], "halted", "{held}");
    g.holds.probe("b-1");
    assert_eq!(g.fake.sent(), 0, "a board whose writes are halted is sent nothing");
    g.fake.writes_halted.store(false, Ordering::SeqCst);
    g.holds.probe("b-1");
    assert_eq!(g.fake.sent(), 1, "the read that says writes go ends the hold");
    assert!(g.lines().is_empty());
    let BurstAnswer::Answered(Ok(next)) = g.holds.send_burst("b-1", &g.session, insert(DOC, json!(["!"]))) else { panic!("the burst was answered") };
    assert_eq!(next["resp"], "ack", "the hold has ended: {next}");
}

/// THE RIDER (§3c.4): a resent line's first and second `durability` are
/// reissued at the next wake, its THIRD holds it `durability` — counted per
/// line across the resends — and the board taking writes again keeps it
/// (the mutant that never counts reissues the line forever).
#[test]
fn a_third_durability_on_a_resent_line_holds_it() {
    let g = ground();
    *g.fake.reject.lock().unwrap() = Some(json!({"resp": "rejected", "code": "durability", "disposition": "retry", "op": "insert"}));
    g.hold(&insert(DOC, json!(["hello"])), "unreachable", false);
    for (wake, cause) in [(1, "unreachable"), (2, "unreachable"), (3, "durability")] {
        g.holds.probe("b-1");
        assert_eq!((g.fake.sent(), g.lines()[0]["cause"].as_str()), (wake, Some(cause)), "wake {wake}");
    }
    *g.fake.reject.lock().unwrap() = None;
    g.holds.probe("b-1");
    assert_eq!(g.fake.sent(), 4);
    assert!(g.lines().is_empty() && g.states().contains(&"kept".to_string()));
}

/// A REFUSAL THE TABLE HOLDS NOWHERE is faced at the burst's first dial
/// (§3c.4's NEITHER and REISSUE): a retry-class refusal of no row, and a
/// `write_busy` the board answers as a 503 — read by its code, the table's
/// REISSUE row — each answer the act as its own refusal, and neither burst
/// is held (the mutants that hold either, as if the board had not answered).
#[test]
fn a_refusal_the_table_holds_nowhere_is_faced_at_the_first_dial() {
    let g = ground();
    *g.fake.reject.lock().unwrap() = Some(json!({"resp": "rejected", "code": "credential_refused", "detail": "index_rebuilding", "disposition": "retry", "op": "insert"}));
    let BurstAnswer::Answered(Err(refused)) = g.holds.send_burst("b-1", &g.session, insert(DOC, json!(["a"]))) else { panic!("faced at the act") };
    assert_eq!(refused.name(), "index_rebuilding", "{refused}");
    *g.fake.reject.lock().unwrap() = None;
    *g.fake.refuse_op.lock().unwrap() = Some((503, json!({"error": "write_busy"})));
    let BurstAnswer::Answered(Err(busy)) = g.holds.send_burst("b-1", &g.session, insert(DOC, json!(["b"]))) else { panic!("faced at the act") };
    let v = busy.to_value();
    assert_eq!((busy.name(), v["status"].as_u64()), ("write_busy", Some(503)), "{v}");
    assert!(g.lines().is_empty(), "neither burst is held");
    assert_eq!(g.fake.sent(), 2, "each was dialed once");
}

/// THE STORED FRAME carries no `attest` (§3c.2): a burst held with one is
/// kept and listed without it, since the resend composes its attest when it
/// sends (the mutant that stores the frame as it came).
#[test]
fn a_held_frame_is_stored_without_its_attest() {
    let g = ground();
    let mut frame = insert(DOC, json!(["hello"]));
    frame["attest"] = json!({"alg": "x", "sig": "00"});
    g.hold(&frame, "unreachable", false);
    let lines = g.lines();
    assert!(lines[0]["frame"].get("attest").is_none() && lines[0]["frame"]["op"] == "insert", "{lines:?}");
    let file = g.store.path().join("held").join("ab".repeat(32)).join("principal-1.held");
    let text = std::fs::read_to_string(&file).unwrap();
    assert!(!text.contains("attest"), "{text}");
}

/// P38's HALT at the hold (§3c.3): a principal's file written by a newer skep
/// stands untouched, and every act on it answers `store_halted` naming why —
/// the burst is not dialed, no line is held, `held(session)` lists nothing —
/// so no burst is sent past a file this shell may not write and none is
/// rebuilt over (the mutant that dials past a halted file).
#[test]
fn a_halted_file_refuses_every_act_and_dials_nothing() {
    let store = TempDir::new().unwrap();
    let chain = "ab".repeat(32);
    HeldDir::new(store.path(), Chain::parse(&chain).unwrap()).ensure().unwrap();
    let file = store.path().join("held").join(&chain).join("principal-1.held");
    let newer = format!("{{\"type\":\"skep-held-bursts\",\"v\":2,\"board\":\"{chain}\",\"principal\":1,\"account\":\"1.0.1\"}}\n");
    std::fs::write(&file, &newer).unwrap();
    let g = ground_in(store, bare_facts(), 0);
    let BurstAnswer::Answered(Err(refused)) = g.holds.send_burst("b-1", &g.session, insert(DOC, json!(["hello"]))) else { panic!("a burst at a halted file is refused") };
    assert_eq!((refused.name(), refused.to_value()["why"].as_str()), ("store_halted", Some("newer")), "{refused}");
    assert_eq!(g.fake.sent(), 0, "nothing is dialed past a halted file");
    assert_eq!(g.holds.lines("b-1", &g.session).unwrap_err().name(), "store_halted");
    let held = g.holds.hold("b-1", &g.session, &insert(DOC, json!(["x"])), Reason::of("unreachable", false));
    assert_eq!(held.unwrap_err().name(), "store_halted", "no line is held");
    assert_eq!(std::fs::read_to_string(&file).unwrap(), newer, "the halted file is never rebuilt over");
}

/// A LINE THE STORE CANNOT COPY stands in memory and says why (§3c.3,
/// "Persist first"): at a board with no `H.1` to name its directory, the
/// burst is held under its own cause — never `other_window`, another
/// window's lock alone — its answer `unwritable` naming the missing term,
/// nothing written; at a file the device refuses (a directory where the
/// file would be), the device's refusal rides the answer. Either line
/// stands in the queue, and the next probe resends and keeps it (the mutant
/// that drops `unwritable` tells the page a burst a crash would lose is on
/// disk).
#[test]
fn a_line_the_store_cannot_copy_says_why_and_stands() {
    let fake = Fake::new();
    fake.no_head.store(true, Ordering::SeqCst);
    let g = ground_over(fake, TempDir::new().unwrap(), bare_facts(), 0);
    let answer = g.hold(&insert(DOC, json!(["hello"])), "unreachable", false);
    assert_eq!(answer["cause"], "unreachable", "{answer}");
    assert!(answer["unwritable"].as_str().is_some_and(|why| why.contains("H.1")), "the answer says why: {answer}");
    assert!(!g.store.path().join("held").exists(), "nothing is written");
    assert_eq!(g.lines().len(), 1, "the line stands");
    g.holds.probe("b-1");
    assert_eq!(g.fake.sent(), 1, "the line is resent");
    assert!(g.lines().is_empty() && g.states().contains(&"kept".to_string()));

    let g = ground();
    let file = g.store.path().join("held").join("ab".repeat(32)).join("principal-1.held");
    std::fs::create_dir(&file).unwrap();
    let answer = g.hold(&insert(DOC, json!(["hello"])), "unreachable", false);
    assert_eq!(answer["cause"], "unreachable", "{answer}");
    assert!(answer["unwritable"].is_string(), "the device's refusal rides the answer: {answer}");
    assert_eq!(g.lines().len(), 1, "the line stands");
    std::fs::remove_dir(&file).unwrap();
    g.holds.probe("b-1");
    assert_eq!(g.fake.sent(), 1, "the line is resent");
    assert!(g.lines().is_empty() && g.states().contains(&"kept".to_string()));
}
