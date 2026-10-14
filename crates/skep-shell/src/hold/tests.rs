//! THE HOLD's FENCE: the classification table (T6) — every `DialError`, every
//! disposition, `poisoned`, `write_busy` once/twice, `durability`
//! once/twice/three times, and an ack, each to exactly its row, the table the
//! one owner of every reissue's bound; the five kinds are bursts and the
//! eleven other `WRITE_KINDS` are not; the five held states are the declared
//! ones, and the two acts of `resolve` the declared words and no other
//! spelling. And the ground its two children stand on: a fake board (`Fake`) —
//! its `H.1`, its `/changes` rows, a draft's text, the frames POSTed to `/op`
//! recorded and a refusal or the death signal armed for a send — the holds
//! over it with a session opened as the shell opens one and every line the
//! hold says on TALK recorded (`Ground`), and each `held` event, `held` row
//! and `held` answer held to its declaration.
//! `write` holds the one path of a session's `op` — a burst's door and its
//! hold, and a write the hold never holds; `resend` the probe and the resend
//! walk.

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
use crate::sessions::{Facts, Open, SessionKind, Supplements};

mod resend;
mod write;

/// The five burst kinds are bursts; the eleven other write kinds are not.
#[test]
fn the_five_kinds_are_bursts_and_no_other_write_kind_is() {
    for op in BURST_KINDS {
        assert!(is_burst(&json!({"op": op})), "{op}");
    }
    for op in crate::shell::WRITE_KINDS {
        let burst = BURST_KINDS.contains(&op);
        assert_eq!(is_burst(&json!({"op": op})), burst, "{op}");
    }
    assert!(!is_burst(&json!({"op": "publish"})));
    assert!(!is_burst(&json!({"op": "doc_metadata"})), "a read is no burst");
    assert!(!is_burst(&json!({})), "a frame with no op is no burst");
}

fn rej(code: &str, disposition: &str) -> Decision {
    classify(DialOutcome::Rejected { code, disposition }, Reissues::default())
}

/// The reissues a burst has been given: `write_busy` ones and `durability`
/// ones.
fn given(write_busy: u32, durability: u32) -> Reissues {
    Reissues { write_busy, durability }
}

/// A `rejected` document of `code` at the retry disposition.
fn retry(code: &str) -> Value {
    json!({"resp": "rejected", "code": code, "disposition": "retry", "op": "insert"})
}

/// THE CLASSIFICATION TABLE (§3c.4): each outcome to exactly its row. The own
/// node stopped, an ack and the death signal sit outside `classify`
/// (`DialOutcome`'s doc); a write the hold never holds is read through it as
/// a burst is, and faced where a burst is held (`write`'s suite).
#[test]
fn every_outcome_classifies_to_exactly_its_row() {
    // No connection made — the burst did not leave (`sent: false`).
    for e in [DialError::Connect("x".into()), DialError::Resolve("x".into()), DialError::Tls("x".into())] {
        assert_eq!(classify(DialOutcome::Dial(&e), Reissues::default()), Decision::Hold { cause: "unreachable", sent: false }, "{e}");
    }
    // The request left, its answer lost — it MAY have landed (`sent: true`).
    for e in [DialError::Timeout("x".into()), DialError::Io("x".into()), DialError::Truncated { declared: 9, got: 1 }, DialError::Response("x".into()), DialError::TooLarge { cap: 1 }] {
        assert_eq!(classify(DialOutcome::Dial(&e), Reissues::default()), Decision::Hold { cause: "unreachable", sent: true }, "{e}");
    }
    // The scheme this build does not hold, or a request refused before any
    // connection — faced as built, no probe ends either.
    for e in [DialError::NotHeld("https".into()), DialError::Request("x".into())] {
        assert_eq!(classify(DialOutcome::Dial(&e), Reissues::default()), Decision::Neither, "{e}");
    }
    // The codes. `poisoned` MAY have landed (§3c.2): the frames reached the
    // journal and a restart replays them, so its line says `sent: true`.
    assert_eq!(rej("poisoned", "halt"), Decision::Hold { cause: "poisoned", sent: true });
    // `write_busy` once → reissue, after the short wait; the reissue's own →
    // the next refusal, faced.
    let busy = DialOutcome::Rejected { code: "write_busy", disposition: "retry" };
    assert_eq!(classify(busy, given(0, 0)), Decision::Reissue(Reissue::WriteBusy));
    assert_eq!(classify(busy, given(1, 0)), Decision::Neither);
    // `durability` once, twice → reissue as-is; a THIRD on the same burst →
    // hold; a `write_busy` given beside counts nothing toward the rider.
    let durability = DialOutcome::Rejected { code: "durability", disposition: "retry" };
    assert_eq!(classify(durability, given(0, 0)), Decision::Reissue(Reissue::Durability));
    assert_eq!(classify(durability, given(1, 1)), Decision::Reissue(Reissue::Durability));
    assert_eq!(classify(durability, given(0, 2)), Decision::Hold { cause: "durability", sent: false });
    assert_eq!((Reissue::WriteBusy.wait(), Reissue::Durability.wait()), (WRITE_BUSY_WAIT, Duration::ZERO));
    let mut noted = Reissues::default();
    for kind in [Reissue::WriteBusy, Reissue::Durability, Reissue::Durability] {
        noted.note(kind);
    }
    assert_eq!(noted, given(1, 2), "each reissue counted under its own kind");
    // A `permanent` or `reorder` refusal → a REFUSED run.
    assert_eq!(rej("out_of_bounds", "permanent"), Decision::Refused);
    assert_eq!(rej("not_registered", "reorder"), Decision::Refused);
    // Any other retry-class rejection on a burst → faced, not held.
    assert_eq!(rej("history_busy", "retry"), Decision::Neither);
}

/// The five held states are the declared `HeldEvent.state` union's words,
/// each spelled as the event carries it (the mutant that misspells one says
/// a state no page renders).
#[test]
fn the_held_states_are_the_declared_five() {
    let states = [HeldState::Holding, HeldState::Sending, HeldState::Kept, HeldState::Refused, HeldState::Moved];
    let declared = crate::shapes::shape("HeldEvent").unwrap().fields.iter().find(|f| f.name == "state").unwrap().ty;
    let spelled: std::collections::BTreeSet<String> = states.iter().map(|s| format!("'{}'", s.as_str())).collect();
    let words: std::collections::BTreeSet<String> = declared.split(" | ").map(str::to_string).collect();
    assert_eq!((spelled.len(), spelled), (5, words), "{declared}");
}

/// The two acts are the declared `Resolve.act` union's words, each naming
/// its act, and no other spelling names one (the mutant that reads a near
/// spelling as an act drops a run the page never asked to drop).
#[test]
fn the_two_acts_are_the_declared_words_and_no_other() {
    let declared = crate::shapes::shape("Resolve").unwrap().fields.iter().find(|f| f.name == "act").unwrap().ty;
    let named: Vec<Option<ResolveAct>> = declared.split(" | ").map(|word| ResolveAct::named(word.trim_matches('\''))).collect();
    assert_eq!(named, [Some(ResolveAct::Drop), Some(ResolveAct::Send)], "{declared}");
    for other in ["dropp", "Drop", "", "send "] {
        assert_eq!(ResolveAct::named(other), None, "{other:?}");
    }
}

/// An answer armed at the fake's `/op`: given to every send, or to the
/// next `n` alone.
struct Armed<T>(Mutex<Option<(T, Option<usize>)>>);

impl<T: Clone> Armed<T> {
    fn none() -> Armed<T> {
        Armed(Mutex::new(None))
    }

    /// `answer` given to every send from now on.
    fn every(&self, answer: T) {
        *self.0.lock().unwrap() = Some((answer, None));
    }

    /// `answer` given to the next `n` sends alone.
    fn next(&self, n: usize, answer: T) {
        *self.0.lock().unwrap() = Some((answer, Some(n)));
    }

    /// Nothing armed.
    fn clear(&self) {
        *self.0.lock().unwrap() = None;
    }

    /// The answer armed for this send, where one is — one fewer left.
    fn take(&self) -> Option<T> {
        let mut armed = self.0.lock().unwrap();
        let (answer, left) = armed.as_mut()?;
        let answer = answer.clone();
        let spent = left.as_mut().is_some_and(|n| {
            *n -= 1;
            *n == 0
        });
        if spent {
            *armed = None;
        }
        Some(answer)
    }
}

/// A board under test: the chain `board_term` reads — or no `H.1` at all,
/// where one is armed missing, the death signal, where its read is armed
/// closed, or an answer lost on the way, where it is armed unanswered; the
/// `/changes` rows the read sees, each served
/// only past the query's `since` and at or under its `under`, or a refusal
/// armed in the page's place; the draft's text, of which a `retrieve_v`
/// answers the positions it names — or no answer, the death signal, or one
/// position more than it names, where the site is armed so; the frames
/// POSTed to `/op` recorded, and the death signal, a scripted rejection or a
/// non-200 answered where one is armed — to every send, or to the next few
/// alone, the death first and the non-200 next; and the `/health` reads
/// counted, one armed to panic once, and each held at a gate while it is
/// shut.
struct Fake {
    chain: String,
    no_head: AtomicBool,
    head_closed: AtomicBool,
    head_unreachable: AtomicBool,
    rows: Mutex<Vec<Value>>,
    changes_refused: Mutex<Option<(u16, Value)>>,
    text: Mutex<String>,
    site_unread: AtomicBool,
    site_closed: AtomicBool,
    over_deliver: AtomicBool,
    sends: Mutex<Vec<Value>>,
    op_closed: AtomicBool,
    op_rejected: Armed<Value>,
    op_refused: Armed<(u16, Value)>,
    next_at: AtomicU64,
    writes_halted: AtomicBool,
    panic_next_health: AtomicBool,
    health_reads: AtomicUsize,
    health_gate: (Mutex<bool>, Condvar),
}

impl Fake {
    fn new() -> Arc<Fake> {
        Fake::on_chain(&"ab".repeat(32))
    }

    /// A board whose `H.1` names `chain`.
    fn on_chain(chain: &str) -> Arc<Fake> {
        Arc::new(Fake {
            chain: chain.to_string(),
            no_head: AtomicBool::new(false),
            head_closed: AtomicBool::new(false),
            head_unreachable: AtomicBool::new(false),
            rows: Mutex::new(Vec::new()),
            changes_refused: Mutex::new(None),
            text: Mutex::new(String::new()),
            site_unread: AtomicBool::new(false),
            site_closed: AtomicBool::new(false),
            over_deliver: AtomicBool::new(false),
            sends: Mutex::new(Vec::new()),
            op_closed: AtomicBool::new(false),
            op_rejected: Armed::none(),
            op_refused: Armed::none(),
            next_at: AtomicU64::new(50),
            writes_halted: AtomicBool::new(false),
            panic_next_health: AtomicBool::new(false),
            health_reads: AtomicUsize::new(0),
            health_gate: (Mutex::new(false), Condvar::new()),
        })
    }

    fn sends(&self) -> usize {
        self.sends.lock().unwrap().len()
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

/// The death signal: an answer whose `Skepd-Session` says `closed`.
fn closed() -> Response {
    Response { status: 200, headers: Headers(vec![("Skepd-Session".into(), "closed".into())]), body: Vec::new() }
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
                    if self.head_closed.load(Ordering::SeqCst) {
                        return Ok(closed());
                    }
                    if self.head_unreachable.load(Ordering::SeqCst) {
                        return Err(DialError::Io("the head read's answer was lost".into()));
                    }
                    if self.no_head.load(Ordering::SeqCst) {
                        return Ok(ok(json!({"resp": "delivery", "items": []})));
                    }
                    let head = json!({"type": "skep-head", "position": 1, "chain": self.chain}).to_string();
                    return Ok(ok(json!({"resp": "delivery", "items": [{"atom": head}]})));
                }
                if self.site_unread.load(Ordering::SeqCst) {
                    return Err(DialError::Connect("the site read is not answered".into()));
                }
                if self.site_closed.load(Ordering::SeqCst) {
                    return Ok(closed());
                }
                let text = self.text.lock().unwrap().clone();
                let (from, width) = span(&body["specs"][0]).unwrap_or((0, 0));
                let width = width + usize::from(self.over_deliver.load(Ordering::SeqCst));
                return Ok(match text.get(from.saturating_sub(1)..from.saturating_sub(1) + width) {
                    Some(cut) if from > 0 => ok(json!({"resp": "delivery", "items": [{"content": cut}]})),
                    _ => ok(json!({"resp": "rejected", "code": "out_of_bounds", "disposition": "permanent", "op": "retrieve_v"})),
                });
            }
            self.sends.lock().unwrap().push(body.clone());
            if self.op_closed.load(Ordering::SeqCst) {
                return Ok(closed());
            }
            if let Some((status, refusal)) = self.op_refused.take() {
                return Ok(respond(status, refusal));
            }
            if let Some(r) = self.op_rejected.take() {
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

struct NoSupplements;
impl Supplements for NoSupplements {
    fn widen(&mut self, _: &Arc<SessionEntry>) {}
    fn narrow(&mut self, _: u64) {}
}

/// The holds over the fake board, a session registered and its open read as
/// the shell reads it — the ground every resend cell stands on; every line
/// the hold says on TALK, in order; the store directory kept for the ground's
/// life.
struct Ground {
    holds: Arc<Holds>,
    fake: Arc<Fake>,
    session: Arc<SessionEntry>,
    rx: Receiver<Event>,
    said: Arc<Mutex<Vec<String>>>,
    store: TempDir,
}

/// A `held` event held to its declaration (`shapes`' `HeldEvent`): every
/// required member present, none outside the table, and `session` a
/// reference — never null, as the declared type says.
fn assert_held_event_declared(event: &Value) {
    crate::shapes::assert_declared("HeldEvent", event);
    let shape = crate::shapes::shape("HeldEvent").expect("HeldEvent is declared");
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
                assert_held_event_declared(&e.data);
                e.data["state"].as_str().unwrap_or("?").to_string()
            })
            .collect()
    }

    /// `held(session)`'s lines, each held to its declaration (`HeldRow`).
    fn lines(&self) -> Vec<Value> {
        let lines = self.holds.lines(&self.session).unwrap().as_array().unwrap().clone();
        for line in &lines {
            crate::shapes::assert_declared("HeldRow", line);
        }
        lines
    }

    /// `frame` admitted at the ground's session — a test's own frame, which
    /// the burst's door lets in.
    fn burst(&self, frame: &Value) -> Burst {
        Burst::admit(frame.clone(), &self.session).unwrap()
    }

    /// A burst held for `cause`, `sent` as a lost answer's would be: the
    /// `held` answer, held to its declaration (`HeldAnswer`).
    fn hold(&self, frame: &Value, cause: &str, sent: bool) -> Value {
        let answer = self.holds.hold(&self.session, self.burst(frame), Reason::of(cause, sent)).unwrap();
        crate::shapes::assert_declared("HeldAnswer", &answer);
        answer
    }
}

/// The facts of a bare session as principal 1.
fn bare_facts() -> Facts {
    Facts { principal: 1, account: Some("1.0.1".into()), kind: SessionKind::Bare }
}

/// The facts of a session that holds a key — the signed mode's, its set the
/// account's own.
fn keyed_facts() -> Facts {
    let fingerprint = skep_identity::Fingerprint::parse_hex(&"5a".repeat(32)).unwrap();
    Facts { principal: 1, account: Some("1.0.1".into()), kind: SessionKind::Signed { fingerprint, set_account: "1.0.1".into() } }
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
    let entry = Arc::new(BoardEntry { reference: "b-1".into(), board: Arc::new(Board::new(Origin::parse("http://127.0.0.1:1").unwrap(), Arc::clone(&fake))) });
    let sessions = Arc::new(Sessions::new(None));
    let bus = Arc::new(EventBus::new());
    let rx = bus.subscribe();
    let keys = Arc::new(FileStore::open(store.path().join("store")));
    let said = Arc::new(Mutex::new(Vec::new()));
    let kept = Arc::clone(&said);
    let talk: Talk = Arc::new(move |line: &str| kept.lock().unwrap().push(line.to_string()));
    let holds = Holds::new(Arc::clone(&sessions), bus, keys, store.path().to_path_buf(), talk, [Arc::clone(&entry)]);
    let open = Open { token: Token::parse(&"9f".repeat(16)).unwrap(), facts, opened_at };
    let session = sessions.register(&entry, open, &mut NoSupplements);
    holds.open_session(&session);
    Ground { holds, fake, session, rx, said, store }
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
