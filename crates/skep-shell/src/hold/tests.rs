//! The hold's classification table, and the ground its child suites stand on.
//!
//! The table (T6) takes every `DialError`, every disposition, `poisoned`,
//! `internal_panic`, `write_busy` once and twice, `durability` once, twice and
//! three times, `arrangement_moved`, and an ack, each to exactly its row, the
//! table the one owner of every reissue's bound; the five kinds are bursts and
//! the eleven other
//! `WRITE_KINDS` are not; the five held states are the declared ones, and the
//! two acts of `resolve` the declared words and no other spelling.
//!
//! The ground is a fake board (`Fake`) — its `H.1`, or an answer armed in the
//! record's place, and whether it names a claimant; its `/changes` rows and
//! the reads of them counted, a draft's text, its content image and the
//! reads of it counted, the position its arrangement last changed at as a
//! cell sets it — a burst typed below it refused `arrangement_moved`, the
//! fake's own acks moving nothing, so every frame typed at the fake's head
//! meets no refusal — the frames POSTed to `/op`
//! recorded, a look taken as each is recorded, and a refusal or the death
//! signal armed for a send — the holds over it with a session opened as the
//! shell opens one and every line the hold says on `Talk` recorded (`Ground`),
//! a burst held through the hold's own door at the base a hold takes now, and
//! each `held` event, `held` row and `held` answer held to its declaration.
//! The ground's session is a writer's — signed, under a key its store
//! generates, since a bare session reads alone and no probe resends under it —
//! save where a cell asks for a bare one (`bare_ground`) or for a key no store
//! holds (`keyed_facts`). `write` holds the one path of a session's `op` — a
//! burst's door and its hold, and a write the hold never holds; `resend` the
//! probe and the resend walk.

use std::collections::HashMap;
use std::io::Read;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::mpsc::Receiver;
use std::sync::{Arc, Condvar, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use serde_json::json;
use skep_client::board::{Token, HEAD_MEMBER_1};
use skep_client::dial::{DialError, Dialer, Headers, Method, Request, RequestHead, Response, StreamedResponse};
use skep_client::store::{KeyId, KeyStore};
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
    Reissues { write_busy, durability, ..Reissues::default() }
}

/// A `rejected` document of `code` at the retry disposition.
fn retry(code: &str) -> Value {
    json!({"resp": "rejected", "code": code, "disposition": "retry", "op": "insert"})
}

/// THE CLASSIFICATION TABLE (§3c.4): each outcome to exactly its row. The own
/// node stopped, an ack and the death signal sit outside `classify`
/// (`DialOutcome`'s doc); a write the hold never holds is read through it as
/// a burst is, and faced where a burst is held (`write`'s suite). The mutant
/// that leaves `arrangement_moved` to the disposition's row holds a stale
/// burst as a refused run, whose resend meets the same refusal.
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
    // The board's `500 internal_panic` may have landed too: its write may
    // have committed before the handler panicked, its body riding no
    // disposition — held as a lost answer is, `sent: true`.
    assert_eq!(rej("internal_panic", ""), Decision::Hold { cause: "unreachable", sent: true });
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
    // A burst typed against an older state of its document, `permanent` → a
    // MOVED document, never a refused run.
    assert_eq!(rej("arrangement_moved", "permanent"), Decision::Moved);
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

/// A lost answer the fake's `/op` gives a send it recorded.
#[derive(Debug, Clone, Copy)]
enum Lost {
    /// The answer does not come in time: `DialError::Timeout`.
    Timeout,
    /// A `200` whose body is no JSON, as a proxy's page is: the client's
    /// `DialError::Response`.
    Garbled,
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

/// A board under test, its every answer armed or recorded.
///
/// It holds the chain `board_term` reads — or no `H.1` at all, where one is
/// armed missing; the death signal, where its read is armed closed; an answer
/// lost on the way, where it is armed unanswered; or the answer armed in its
/// place, a record that cannot be read among them — and whether `/health`
/// names a claimant, as it does unless armed unclaimed. It holds the
/// `/changes` rows the read sees, each served only past the query's `since`
/// and at or under its `under`, or a refusal armed in the page's place — the
/// page budget's for the next few reads among them — and the reads of them
/// counted; the draft's text, of which a `retrieve_v`
/// answers the positions it names — or
/// no answer, the death signal, or one position more than it names, where the
/// site is armed so; the draft's content image, of which an `image` answers
/// the runs its region covers, clipped as the board clips them — or no
/// answer where the read is armed unanswered — the reads of it counted and
/// each answered at the board's position; the position each document's
/// arrangement last changed at, as a cell sets it, a burst typed below it
/// refused `arrangement_moved` naming both; the frames POSTed to `/op`
/// recorded, a look the cell takes as each is recorded, the n-th one's
/// answer lost on the way where one is armed lost, and the death signal, a
/// scripted rejection or a non-200 answered where one is armed — to every
/// send, or to the next few alone, the death first and the non-200 next;
/// and the `/health` reads counted, one armed to panic once, and each held
/// at a gate while it is shut.
struct Fake {
    chain: String,
    no_head: AtomicBool,
    head_closed: AtomicBool,
    head_unreachable: AtomicBool,
    /// The answer armed for the head record's read, in the record's place.
    ///
    /// It is a status and its body, a `200`'s body the document served.
    head_answer: Mutex<Option<(u16, Value)>>,
    /// Whether `/health` names no claimant: a board no one has claimed.
    unclaimed: AtomicBool,
    rows: Mutex<Vec<Value>>,
    changes_refused: Mutex<Option<(u16, Value)>>,
    /// The page budget's refusal armed for the next `/changes` reads: `400
    /// malformed_changes` naming the `fits` armed, the page then served at
    /// the limit re-asked.
    changes_too_large: Armed<u64>,
    /// The `/changes` reads made, a page or a refusal answered alike.
    changes_reads: AtomicUsize,
    text: Mutex<String>,
    site_unread: AtomicBool,
    site_closed: AtomicBool,
    over_deliver: AtomicBool,
    /// The draft's content image: its runs in V-order from the first
    /// position, each `{i_start, width}` as the board answers one.
    image: Mutex<Vec<Value>>,
    /// Every `image` read fails at the connect: no image is read.
    image_unread: AtomicBool,
    /// The `image` reads made.
    image_reads: AtomicUsize,
    /// The position each document's arrangement last changed at, as a cell
    /// sets it (`move_arrangement`): a burst typed below it is refused
    /// `arrangement_moved`. The fake's own acks move nothing, so every frame
    /// typed at the fake's head meets no refusal.
    arrangement: Mutex<HashMap<String, u64>>,
    sends: Mutex<Vec<Value>>,
    /// A look the cell takes as `/op` records a send, before it answers.
    ///
    /// It reads the held file as the dial leaves, or moves the file out of
    /// the way of what follows the answer.
    at_send: Mutex<Option<Box<dyn Fn() + Send>>>,
    op_closed: AtomicBool,
    /// Every `/op` dial fails at the connect: the board is not answering,
    /// and no request leaves.
    op_unreachable: AtomicBool,
    /// The ordinal, from 1, of the frame POSTed to `/op` whose answer is lost.
    ///
    /// The frame is recorded, then answered no answer (`DialError::Io`): a
    /// write that may have landed. It is 0 where none is armed lost.
    op_lost_at: AtomicUsize,
    /// A lost answer armed for the sends `/op` records: each recorded, then
    /// answered with the loss armed.
    op_lost: Armed<Lost>,
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
            head_answer: Mutex::new(None),
            unclaimed: AtomicBool::new(false),
            rows: Mutex::new(Vec::new()),
            changes_refused: Mutex::new(None),
            changes_too_large: Armed::none(),
            changes_reads: AtomicUsize::new(0),
            text: Mutex::new(String::new()),
            site_unread: AtomicBool::new(false),
            site_closed: AtomicBool::new(false),
            over_deliver: AtomicBool::new(false),
            image: Mutex::new(Vec::new()),
            image_unread: AtomicBool::new(false),
            image_reads: AtomicUsize::new(0),
            arrangement: Mutex::new(HashMap::new()),
            sends: Mutex::new(Vec::new()),
            at_send: Mutex::new(None),
            op_closed: AtomicBool::new(false),
            op_unreachable: AtomicBool::new(false),
            op_lost_at: AtomicUsize::new(0),
            op_lost: Armed::none(),
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

    /// The board's head as the fake stands: the `at` of its last ack, the
    /// state a burst built now is typed against (`as_of`, wire.md
    /// §Arrangement; skep #442). The fake judges a burst's `as_of` against
    /// the position a cell set its document's arrangement at
    /// (`move_arrangement`) alone — never against its own acks — so every
    /// frame the suites build at the head is the wire's frame, member and
    /// all, and meets no refusal.
    fn head(&self) -> u64 {
        self.next_at.load(Ordering::SeqCst) - 1
    }

    /// Sets the position `doc`'s arrangement last changed at: a burst on it
    /// typed against an older state is refused `arrangement_moved` from now.
    fn move_arrangement(&self, doc: &str, at: u64) {
        self.arrangement.lock().unwrap().insert(doc.to_string(), at);
    }

    /// The position a read answers in its `as_of`: the board's head, past
    /// every arrangement change a cell set.
    fn read_as_of(&self) -> u64 {
        self.arrangement.lock().unwrap().values().copied().fold(self.head(), u64::max)
    }

    /// The image's runs clipped to the region `width` positions from `from`,
    /// as the board clips an `image` to the arrangement: a run the window
    /// cuts answered from its first position inside, a window past the
    /// arrangement answering what the arrangement holds.
    fn image_runs(&self, from: u64, width: u64) -> Vec<Value> {
        let (lo, hi) = (from, from.saturating_add(width));
        let mut v = 1u64;
        let mut runs = Vec::new();
        for run in self.image.lock().unwrap().iter() {
            let (prefix, first) = run["i_start"].as_str().and_then(|s| s.rsplit_once('.')).map(|(p, n)| (p.to_string(), n.parse::<u64>().unwrap())).unwrap();
            let w: u64 = run["width"].as_str().unwrap().parse().unwrap();
            let (run_lo, run_hi) = (v.max(lo), (v + w).min(hi));
            if run_lo < run_hi {
                runs.push(json!({"i_start": format!("{prefix}.{}", first + (run_lo - v)), "width": (run_hi - run_lo).to_string()}));
            }
            v += w;
        }
        runs
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
            let claimant = if self.unclaimed.load(Ordering::SeqCst) { Value::Null } else { Value::from("1.0.1") };
            return Ok(ok(
                json!({"ok": true, "log_position": 10, "chain_head": self.chain, "auth": {"claimant": claimant, "local_trust": true, "origins": [], "signed_origins": []}, "media": {"uploads": true}, "head_time": 1, "writes": {"halted": halted}}),
            ));
        }
        if req.method == Method::Get && req.path.starts_with("/changes") {
            self.changes_reads.fetch_add(1, Ordering::SeqCst);
            if let Some((status, body)) = self.changes_refused.lock().unwrap().clone() {
                return Ok(respond(status, body));
            }
            if let Some(fits) = self.changes_too_large.take() {
                return Ok(respond(400, json!({"error": "malformed_changes", "fits": fits})));
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
            if body["op"].as_str() == Some("image") {
                self.image_reads.fetch_add(1, Ordering::SeqCst);
                if self.image_unread.load(Ordering::SeqCst) {
                    return Err(DialError::Connect("the image read is not answered".into()));
                }
                let region = &body["region"][0];
                let from = region["start"].as_str().and_then(|s| s.strip_prefix("1.")).and_then(|s| s.parse().ok()).unwrap_or(1);
                let width = region["width"].as_str().and_then(|s| s.strip_prefix("0.")).and_then(|s| s.parse().ok()).unwrap_or(0);
                return Ok(ok(json!({"resp": "runs", "runs": self.image_runs(from, width), "as_of": self.read_as_of()})));
            }
            if body["op"].as_str() == Some("retrieve_v") {
                if body["specs"][0]["doc"].as_str() == Some(HEAD_MEMBER_1) {
                    if self.head_closed.load(Ordering::SeqCst) {
                        return Ok(closed());
                    }
                    if self.head_unreachable.load(Ordering::SeqCst) {
                        return Err(DialError::Io("the head read's answer was lost".into()));
                    }
                    if let Some((status, answer)) = self.head_answer.lock().unwrap().clone() {
                        return Ok(respond(status, answer));
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
            if self.op_unreachable.load(Ordering::SeqCst) {
                return Err(DialError::Connect("the board is not answering".into()));
            }
            let sent = {
                let mut sends = self.sends.lock().unwrap();
                sends.push(body.clone());
                sends.len()
            };
            if let Some(look) = self.at_send.lock().unwrap().as_ref() {
                look();
            }
            if sent == self.op_lost_at.load(Ordering::SeqCst) {
                return Err(DialError::Io("the answer was lost on the way".into()));
            }
            if let Some(lost) = self.op_lost.take() {
                return match lost {
                    Lost::Timeout => Err(DialError::Timeout("the answer did not come in time".into())),
                    Lost::Garbled => Ok(Response { status: 200, headers: Headers::default(), body: b"<html>a proxy's page</html>".to_vec() }),
                };
            }
            if self.op_closed.load(Ordering::SeqCst) {
                return Ok(closed());
            }
            if let Some((status, refusal)) = self.op_refused.take() {
                return Ok(respond(status, refusal));
            }
            if let Some(r) = self.op_rejected.take() {
                return Ok(ok(r));
            }
            // The typed state (wire.md §Arrangement): a burst typed below
            // the position its document's arrangement last changed at — as a
            // cell set it — is refused, naming both.
            if let (Some(op), Some(doc), Some(typed)) = (body["op"].as_str().filter(|op| BURST_KINDS.contains(op)), body["doc"].as_str(), body["as_of"].as_u64()) {
                if let Some(current) = self.arrangement.lock().unwrap().get(doc).copied().filter(|current| typed < *current) {
                    return Ok(ok(arrangement_moved_on(op, typed, current)));
                }
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
        let answer = self.hold_for(frame, Reason::of(cause, sent)).unwrap();
        crate::shapes::assert_declared("HeldAnswer", &answer);
        answer
    }

    /// A burst held for `reason` through the hold's own door, at the base a
    /// hold on its document takes now — as a dial's answer holds it, no dial
    /// between: the `held` answer, or the hold's refusal.
    fn hold_for(&self, frame: &Value, reason: Reason) -> Result<Value, Refusal> {
        let burst = self.burst(frame);
        let base = self.base_of(&burst.doc);
        self.holds.hold(&self.session, burst, reason, base)
    }

    /// A burst carrying `anchors` held for `cause`, `sent` as a lost answer's
    /// would be — the page's burst, which the shift can move: the `held`
    /// answer, held to its declaration.
    fn hold_anchored(&self, frame: &Value, anchors: Anchors, cause: &str, sent: bool) -> Value {
        let burst = self.burst(frame).with_anchors(Some(anchors));
        let base = self.base_of(&burst.doc);
        let answer = self.holds.hold(&self.session, burst, Reason::of(cause, sent), base).unwrap();
        crate::shapes::assert_declared("HeldAnswer", &answer);
        answer
    }

    /// The base a line held on `doc` under the ground's session takes now
    /// (§3c.2): its principal's latest acked write there, else the session's
    /// open.
    fn base_of(&self, doc: &str) -> u64 {
        let (board, principal, opened_at) = (self.session.board_reference.as_str(), self.session.facts.principal, self.session.opened_at);
        self.holds.with_principal(board, principal, |ph| ph.base_of(doc, opened_at)).unwrap_or(opened_at)
    }

    /// The session's own hand as a `/changes` row's `key` names it (wire.md
    /// §`/changes`): its key's fingerprint, or `bare`.
    fn own_key(&self) -> String {
        match &self.session.facts.kind {
            SessionKind::Signed { fingerprint, .. } => fingerprint.to_hex(),
            SessionKind::Bare => "bare".to_string(),
        }
    }
}

/// The facts of a bare session as principal 1: the keyless session, which
/// reads alone.
fn bare_facts() -> Facts {
    Facts { principal: 1, account: Some("1.0.1".into()), kind: SessionKind::Bare }
}

/// The facts of a session that holds a key — the signed mode's, its set the
/// account's own — its key in no store, for the cells that sign nothing.
fn keyed_facts() -> Facts {
    let fingerprint = skep_identity::Fingerprint::parse_hex(&"5a".repeat(32)).unwrap();
    Facts { principal: 1, account: Some("1.0.1".into()), kind: SessionKind::Signed { fingerprint, set_account: "1.0.1".into() } }
}

/// The facts of a writer as `principal`, acting as `account`: a signed
/// session under a key generated into the key store under `store`, its set
/// the account's own — a session that may write (`SessionEntry::may_write`),
/// whose every write of the checked set the composer attests.
fn writer_facts_as(store: &TempDir, principal: u64, account: &str) -> Facts {
    let KeyId(fingerprint) = FileStore::open(store.path().join("store")).generate(None).unwrap();
    Facts { principal, account: Some(account.into()), kind: SessionKind::Signed { fingerprint, set_account: account.into() } }
}

/// The facts of the ground's writer: principal 1, acting as `1.0.1`.
fn writer_facts(store: &TempDir) -> Facts {
    writer_facts_as(store, 1, "1.0.1")
}

/// The ground under a writer opened at position 0.
fn ground() -> Ground {
    writer_at(0)
}

/// The ground under a writer opened at `opened_at`.
fn writer_at(opened_at: u64) -> Ground {
    let store = TempDir::new().unwrap();
    let facts = writer_facts(&store);
    ground_in(store, facts, opened_at)
}

/// The ground under a bare session opened at position 0: the keyless
/// session, which reads alone, so no probe resends a line it holds.
fn bare_ground() -> Ground {
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
    let sessions = Arc::new(Sessions::new(None, Arc::new(|_: &str| {})));
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

/// An `insert` of `values` at the document's first position, typed against
/// `as_of` (wire.md §Arrangement, the typed state): the fake board's head
/// as the cell read it (`Fake::head`), which is what a page holding the
/// board's text at that state sends.
fn insert(doc: &str, values: Value, as_of: u64) -> Value {
    json!({"op": "insert", "doc": doc, "at": {"subspace": "1", "ordinal": "1"}, "values": values, "as_of": as_of})
}

/// A `delete` of the document's first position, in the wire's own form
/// (wire.md §Arrangement: `p` and `width`) — a burst whose site no read
/// confirms — typed against `as_of` as [`insert`]'s is.
fn delete(doc: &str, as_of: u64) -> Value {
    json!({"op": "delete", "doc": doc, "p": {"subspace": "1", "ordinal": "1"}, "width": "1", "as_of": as_of})
}

/// The board's refusal of a burst typed against an older state (wire.md
/// §Rejection codes, `arrangement_moved`): `as_of` the state it was typed
/// against, echoed, and `current` the position the document's arrangement
/// last changed at.
fn arrangement_moved(as_of: u64, current: u64) -> Value {
    arrangement_moved_on("insert", as_of, current)
}

/// The board's `arrangement_moved` on a burst of kind `op`.
fn arrangement_moved_on(op: &str, as_of: u64, current: u64) -> Value {
    json!({"resp": "rejected", "op": op, "code": "arrangement_moved", "disposition": "permanent", "site": {"as_of": as_of, "current": current}})
}

/// An `insert` of `values` at the document's position `at`, typed against
/// `as_of`.
fn insert_at(doc: &str, at: u64, values: Value, as_of: u64) -> Value {
    json!({"op": "insert", "doc": doc, "at": {"subspace": "1", "ordinal": at.to_string()}, "values": values, "as_of": as_of})
}

/// A `delete` of `width` positions from the document's position `p`, typed
/// against `as_of`.
fn delete_at(doc: &str, p: u64, width: u64, as_of: u64) -> Value {
    json!({"op": "delete", "doc": doc, "p": {"subspace": "1", "ordinal": p.to_string()}, "width": width.to_string(), "as_of": as_of})
}

/// A `copy` of the other document's first position into `doc` at `at`,
/// typed against `as_of`.
fn copy_at(doc: &str, at: u64, as_of: u64) -> Value {
    json!({"op": "copy", "doc": doc, "at": {"subspace": "1", "ordinal": at.to_string()}, "specs": [{"source": OTHER, "span": {"start": "1.1", "width": "0.1"}}], "as_of": as_of})
}

/// A `reinstate` of one run of `doc`'s own ninth I-position into `doc` at
/// `at`, typed against `as_of`.
fn reinstate_at(doc: &str, at: u64, as_of: u64) -> Value {
    json!({"op": "reinstate", "doc": doc, "at": {"subspace": "1", "ordinal": at.to_string()}, "runs": [{"origin": doc, "i_start": i(9), "width": "1"}], "as_of": as_of})
}

/// A `rearrange` of `doc` about `cuts`, typed against `as_of`.
fn rearrange_at(doc: &str, cuts: &[u64], as_of: u64) -> Value {
    let cuts: Vec<Value> = cuts.iter().map(|c| json!({"subspace": "1", "ordinal": c.to_string()})).collect();
    json!({"op": "rearrange", "doc": doc, "cuts": cuts, "as_of": as_of})
}

/// The I-address of `DOC`'s content position `n`, as the board spells one.
fn i(n: u64) -> String {
    format!("{DOC}.0.1.{n}")
}

/// One run of a content image: `width` positions from the I-address
/// `i_start`, as the board answers it.
fn run(i_start: &str, width: u64) -> Value {
    json!({"i_start": i_start, "width": width.to_string()})
}

/// The anchors a page sends: `before` and `after`, each an I-address or none
/// at the document's edge.
fn anchors(before: Option<&str>, after: Option<&str>) -> Anchors {
    Anchors::of(&json!({"before": before, "after": after})).expect("the anchors' form")
}

/// The anchors a page sends for a delete or a rearrange (skep #751).
///
/// They are `before` and `after`, and the span's runs as its `image` read
/// gave them, each `width` units from the I-address `start`.
fn spanned(before: Option<&str>, after: Option<&str>, runs: &[(&str, u64)]) -> Anchors {
    let span: Vec<Value> = runs.iter().map(|(start, width)| json!({"start": start, "width": width.to_string()})).collect();
    Anchors::of(&json!({"before": before, "after": after, "span": span})).expect("the anchors' form")
}

/// The principal's held file under the ground's store, at the fake's chain.
fn held_file(g: &Ground) -> std::path::PathBuf {
    g.store.path().join("held").join("ab".repeat(32)).join("principal-1.held")
}

/// The `held` lines a held file's text holds, each parsed, in file order.
fn file_lines(text: &str) -> Vec<Value> {
    text.lines().skip(1).filter_map(|line| serde_json::from_str::<Value>(line).ok()).filter(|line| line.get("held").is_some()).collect()
}

/// A `/changes` row whose testimony the board lost (wire.md §`/changes`):
/// every member but its `at` the reserved null.
fn lost_row() -> Value {
    json!({"at": 77, "docs": null, "key": null, "time": null, "op": null, "new_prefix": null, "new_id": null, "link": null, "placed": null, "base_extent": null})
}

const DOC: &str = "1.0.1.0.1";

/// A second document of the session's account.
const OTHER: &str = "1.0.1.0.2";
