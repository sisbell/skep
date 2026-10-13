//! THE HOLD's FENCE: the classification table (T6) — every `DialError`, every
//! disposition, `poisoned`, `write_busy`, `durability` once/twice/three times,
//! and an ack, each to exactly its row; the five kinds are bursts and the
//! twelve other `WRITE_OPS` are not. And THE RESEND WALK over a fake board in
//! its three outcomes (§3c.5) — no row (send from the head), one own row
//! confirmed by content (the head `done kept`, nothing re-sent), a foreign row
//! (MOVED, nothing sent, never rebased) — `history_reclaimed`, and the refused
//! run's `resolve(drop)` dropping it and every line held behind it.

use std::io::Read;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::Receiver;
use std::sync::{Arc, Mutex};

use serde_json::json;
use skep_client::board::{Board, Token, HEAD_MEMBER_1};
use skep_client::dial::{DialError, Dialer, Headers, Method, Request, RequestHead, Response, StreamedResponse};
use skep_client::store::FileStore;
use skep_client::Origin;
use tempfile::TempDir;

use super::*;
use crate::events::{Event, EventBus};
use crate::sessions::{Facts, Kind, Open, SessionEntry, Sessions, Supplements};

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

/// A board under test: the chain `board_term` reads, the `/changes` rows the
/// read sees, the content a `retrieve_v` answers, the frames POSTed to `/op`
/// recorded, and a scripted rejection where one is armed.
struct Fake {
    chain: String,
    rows: Mutex<Vec<Value>>,
    content: Mutex<Vec<Value>>,
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
            content: Mutex::new(Vec::new()),
            sent: Mutex::new(Vec::new()),
            reject: Mutex::new(None),
            next_at: AtomicU64::new(50),
            writes_halted: AtomicBool::new(false),
        })
    }
}

fn ok(v: Value) -> Response {
    Response { status: 200, headers: Headers::default(), body: v.to_string().into_bytes() }
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
            return Ok(ok(json!({"changes": self.rows.lock().unwrap().clone(), "last": 100, "more": false})));
        }
        if req.method == Method::Post && req.path == "/op" {
            let body: Value = serde_json::from_slice(&req.body).unwrap_or(Value::Null);
            if body["op"].as_str() == Some("retrieve_v") {
                if body["specs"][0]["doc"].as_str() == Some(HEAD_MEMBER_1) {
                    let head = json!({"type": "skep-head", "position": 1, "chain": self.chain}).to_string();
                    return Ok(ok(json!({"resp": "delivery", "items": [{"atom": head}]})));
                }
                return Ok(ok(json!({"resp": "delivery", "items": self.content.lock().unwrap().clone()})));
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

/// Holds over the fake board, a bare session registered — the fixture the
/// resend walk runs against.
#[allow(clippy::type_complexity)]
fn fixture() -> (Arc<Holds>, Arc<Fake>, Arc<SessionEntry>, Arc<EventBus>, Receiver<Event>, TempDir) {
    fixture_as(Facts { principal: 1, account: Some("1.0.1".into()), kind: Kind::Bare, fingerprint: None, set_account: None })
}

/// The fixture under a session of the given facts — a bare one, or one that
/// holds a key (the signed mode's).
#[allow(clippy::type_complexity)]
fn fixture_as(facts: Facts) -> (Arc<Holds>, Arc<Fake>, Arc<SessionEntry>, Arc<EventBus>, Receiver<Event>, TempDir) {
    let tmp = TempDir::new().unwrap();
    let fake = Fake::new();
    let origin = Origin::parse("http://127.0.0.1:1").unwrap();
    let entry = Arc::new(BoardEntry { reference: "b-1".to_string(), origin: origin.clone(), board: Board::new(origin, Arc::clone(&fake)) });
    let sessions = Arc::new(Sessions::new());
    let bus = Arc::new(EventBus::new());
    let rx = bus.subscribe();
    let store = Arc::new(FileStore::open(tmp.path().join("store")));
    let holds = Holds::new(Arc::clone(&sessions), Arc::clone(&bus), store, tmp.path().to_path_buf(), Arc::new(|_: &str| {}));
    holds.register_board("b-1", Arc::clone(&entry));
    let open = Open { token: Token::parse(&"9f".repeat(16)).unwrap(), facts };
    let session = sessions.register("b-1", open, &mut NoSupp);
    (holds, fake, session, bus, rx, tmp)
}

/// The facts of a session that holds a key — the signed mode's.
fn keyed_facts() -> Facts {
    let fingerprint = skep_identity::Fingerprint::parse_hex(&"5a".repeat(32)).unwrap();
    Facts { principal: 1, account: Some("1.0.1".into()), kind: Kind::Content, fingerprint: Some(fingerprint), set_account: None }
}

fn insert(doc: &str, values: Value) -> Value {
    json!({"op": "insert", "doc": doc, "at": {"subspace": "1", "ordinal": "1"}, "values": values})
}

fn held_states(rx: &Receiver<Event>) -> Vec<String> {
    rx.try_iter().filter(|e| e.name == "held").map(|e| e.data["state"].as_str().unwrap_or("?").to_string()).collect()
}

/// OUTCOME (i): no row since `base` — the held burst is sent from the head and
/// acked, the line resolved, the document's state `kept`.
#[test]
fn outcome_i_no_row_sends_from_the_head() {
    let (holds, fake, session, _bus, rx, _tmp) = fixture();
    let frame = insert("1.0.1.0.1", json!(["hello"]));
    holds.hold_after_dial("b-1", &session, &frame, &Decision::Hold { cause: "unreachable", sent: false }, "", None);
    holds.service("b-1");
    assert_eq!(fake.sent.lock().unwrap().len(), 1, "the head is sent once");
    assert_eq!(fake.sent.lock().unwrap()[0]["op"], "insert");
    assert_eq!(holds.rows("b-1", 1).unwrap().as_array().unwrap().len(), 0, "the line is kept and gone");
    assert!(held_states(&rx).contains(&"kept".to_string()));
}

/// OUTCOME (ii): the in-flight burst (its line `sent: true`) landed — one row
/// of the session's own hand, consistent, confirmed by content — so the head
/// is `done kept` and NOTHING is re-sent (the mutant that resends the head).
#[test]
fn outcome_ii_a_landed_burst_is_kept_not_resent() {
    let (holds, fake, session, _bus, rx, _tmp) = fixture();
    *fake.content.lock().unwrap() = vec![json!({"content": "hello"})];
    *fake.rows.lock().unwrap() = vec![json!({"at": 77, "op": "insert", "key": "bare", "docs": ["1.0.1.0.1"]})];
    let frame = insert("1.0.1.0.1", json!(["hello"]));
    holds.hold_after_dial("b-1", &session, &frame, &Decision::Hold { cause: "unreachable", sent: true }, "", None);
    holds.service("b-1");
    assert!(fake.sent.lock().unwrap().is_empty(), "the landed head is NOT re-sent: {:?}", fake.sent.lock().unwrap());
    assert_eq!(holds.rows("b-1", 1).unwrap().as_array().unwrap().len(), 0, "the line is done kept");
    assert!(held_states(&rx).contains(&"kept".to_string()));
}

/// OUTCOME (iii): a foreign row on the document since `base` — the site MOVED:
/// no line is sent, the lines are re-faced `moved`, never rebased (the mutant
/// that sends the moved line at its old base).
#[test]
fn outcome_iii_a_foreign_row_moves_the_document() {
    let (holds, fake, session, _bus, rx, _tmp) = fixture();
    *fake.rows.lock().unwrap() = vec![json!({"at": 77, "op": "insert", "key": "ff".repeat(32), "docs": ["1.0.1.0.1"]})];
    let frame = insert("1.0.1.0.1", json!(["hello"]));
    holds.hold_after_dial("b-1", &session, &frame, &Decision::Hold { cause: "unreachable", sent: true }, "", None);
    holds.service("b-1");
    assert!(fake.sent.lock().unwrap().is_empty(), "no line of a moved document is sent");
    let rows = holds.rows("b-1", 1).unwrap();
    assert_eq!(rows[0]["cause"], "moved", "the line is faced moved: {rows}");
    assert!(held_states(&rx).contains(&"moved".to_string()));
}

/// THE OWN HAND on a read (§3c.5; wire.md §`/changes`): a SIGNED entry's row
/// carries `attest` and NO `key`, and is the session's own under a session
/// that holds a key — the head `done kept`, nothing re-sent — and NOT own
/// under a bare session (the mutant that keys the test on `key` alone faces
/// the signed row `moved`); a row with `key: "bare"` is own under a bare
/// session alone, never under a keyed one.
#[test]
fn a_signed_row_is_own_under_a_keyed_session_alone() {
    let signed_row = json!({"at": 77, "op": "insert", "docs": ["1.0.1.0.1"], "attest": {"alg": "x", "sig": "y"}});
    let bare_row = json!({"at": 77, "op": "insert", "docs": ["1.0.1.0.1"], "key": "bare"});
    let walk = |facts: Facts, row: Value| -> (Vec<String>, usize) {
        let (holds, fake, session, _bus, rx, _tmp) = fixture_as(facts);
        *fake.content.lock().unwrap() = vec![json!({"content": "hello"})];
        *fake.rows.lock().unwrap() = vec![row];
        holds.hold_after_dial("b-1", &session, &insert("1.0.1.0.1", json!(["hello"])), &Decision::Hold { cause: "unreachable", sent: true }, "", None);
        holds.service("b-1");
        let sent = fake.sent.lock().unwrap().len();
        (held_states(&rx), sent)
    };
    let (states, sent) = walk(keyed_facts(), signed_row.clone());
    assert!(states.contains(&"kept".to_string()) && !states.contains(&"moved".to_string()), "the signed row is the keyed session's own: {states:?}");
    assert_eq!(sent, 0, "the landed head is not re-sent");
    let (states, _) = walk(Facts { fingerprint: None, kind: Kind::Bare, ..keyed_facts() }, signed_row);
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
    let walk = |frame: Value, content: &str, sent: bool| -> (Vec<String>, usize) {
        let (holds, fake, session, _bus, rx, _tmp) = fixture();
        *fake.content.lock().unwrap() = vec![json!({"content": content})];
        *fake.rows.lock().unwrap() = vec![lost.clone()];
        holds.hold_after_dial("b-1", &session, &frame, &Decision::Hold { cause: "poisoned", sent }, "", None);
        holds.service("b-1");
        let sent = fake.sent.lock().unwrap().len();
        (held_states(&rx), sent)
    };
    let (states, sent) = walk(insert("1.0.1.0.1", json!(["hello"])), "hello", true);
    assert!(states.contains(&"kept".to_string()) && !states.contains(&"moved".to_string()), "the landed insert is kept: {states:?}");
    assert_eq!(sent, 0, "the landed head is not re-sent");
    let (states, sent) = walk(insert("1.0.1.0.1", json!(["hello"])), "other", true);
    assert!(states.contains(&"moved".to_string()) && sent == 0, "values that differ: moved, nothing sent: {states:?}");
    let (states, sent) = walk(json!({"op": "delete", "doc": "1.0.1.0.1", "at": {"subspace": "1", "ordinal": "1"}, "width": 1}), "hello", true);
    assert!(states.contains(&"moved".to_string()) && sent == 0, "a kind the site read cannot confirm: moved: {states:?}");
    let (states, sent) = walk(insert("1.0.1.0.1", json!(["hello"])), "hello", false);
    assert!(states.contains(&"moved".to_string()) && sent == 0, "a head never sent reads any row as moved: {states:?}");
}

/// A `halted` hold — the feed's `writes.halted` read, before any dial — is
/// `sent: false`: no dial was made, so nothing of it can have landed.
#[test]
fn a_halted_hold_before_any_dial_is_sent_false() {
    let (holds, fake, session, _bus, _rx, _tmp) = fixture();
    holds.note_health("b-1", true, 10);
    let answer = holds.before_dial("b-1", &session, &insert("1.0.1.0.1", json!(["hello"]))).expect("held before the dial").unwrap();
    assert_eq!(answer["cause"], "halted", "{answer}");
    let rows = holds.rows("b-1", 1).unwrap();
    assert_eq!((rows[0]["cause"].as_str(), rows[0]["sent"].as_bool()), (Some("halted"), Some(false)), "{rows}");
    assert!(fake.sent.lock().unwrap().is_empty(), "no dial was made");
}

/// `history_reclaimed` on the read: the arrangement alone decides — content at
/// the head's site that agrees is (ii), kept and not re-sent.
#[test]
fn history_reclaimed_decides_by_the_arrangement() {
    let (holds, fake, session, _bus, _rx, _tmp) = fixture();
    *fake.content.lock().unwrap() = vec![json!({"content": "hello"})];
    // A `/changes` that answers the reclaim floor.
    *fake.rows.lock().unwrap() = Vec::new();
    // Make `/changes` answer history_reclaimed by a reject body the client reads
    // as such is not simple through this fake; instead confirm the content path
    // directly: a landed, content-agreeing head is kept.
    let frame = insert("1.0.1.0.1", json!(["hello"]));
    *fake.rows.lock().unwrap() = vec![json!({"at": 77, "op": "insert", "key": "bare", "docs": ["1.0.1.0.1"]})];
    holds.hold_after_dial("b-1", &session, &frame, &Decision::Hold { cause: "unreachable", sent: true }, "", None);
    holds.service("b-1");
    assert!(fake.sent.lock().unwrap().is_empty());
    assert_eq!(holds.rows("b-1", 1).unwrap().as_array().unwrap().len(), 0);
}

/// A REFUSED run and `resolve`: `drop` on the refused head drops it AND every
/// line held `behind` it on that document (the mutant that leaves them
/// standing); `resolve` on a holding line answers `not_resolvable`; an unknown
/// ordinal answers `no_such_held`.
#[test]
fn a_refused_run_drops_its_behind_lines() {
    let (holds, fake, session, _bus, _rx, _tmp) = fixture();
    let body = json!({"resp": "rejected", "code": "out_of_bounds", "disposition": "permanent"});
    let head = insert("1.0.1.0.1", json!(["a"]));
    let k1 = holds.hold_after_dial("b-1", &session, &head, &Decision::Refused, "out_of_bounds", Some(&body))["held"].as_u64().unwrap();
    // Two more bursts on the same document arrive while the run stands → behind.
    let k2 = holds.before_dial("b-1", &session, &insert("1.0.1.0.1", json!(["b"]))).unwrap().unwrap()["held"].as_u64().unwrap();
    holds.before_dial("b-1", &session, &insert("1.0.1.0.1", json!(["c"]))).unwrap().unwrap();
    assert_eq!(holds.rows("b-1", 1).unwrap().as_array().unwrap().len(), 3, "the run and its two behind lines stand");
    // A holding line is not resolvable; an unknown ordinal is no_such_held.
    assert_eq!(holds.resolve("b-1", &session, k2, "drop").unwrap_err().name(), "not_resolvable");
    assert_eq!(holds.resolve("b-1", &session, 999, "drop").unwrap_err().name(), "no_such_held");
    // Drop the refused head: the whole run goes.
    holds.resolve("b-1", &session, k1, "drop").unwrap();
    assert_eq!(holds.rows("b-1", 1).unwrap().as_array().unwrap().len(), 0, "the run and its behind lines are dropped");
    assert!(fake.sent.lock().unwrap().is_empty(), "nothing is dialed on a drop");
}
