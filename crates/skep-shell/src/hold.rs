//! THE HOLD (`client.md` §3c.4, §3c.5): the per-(board, principal) state the
//! shell consults on every burst, and the resend walk that drains it once the
//! board returns.
//!
//! A BURST is an `op` under a session (never the guest form) whose `frame["op"]`
//! is one of [`BURST_KINDS`] — the burst machine's five — on a draft. THE
//! CLASSIFICATION TABLE ([`classify`]) maps what a dial answers to exactly one
//! of HOLD(cause) / REISSUE / NEITHER, as §3c.4 rules. THE QUEUE lives in
//! `held`'s append-only file, mirrored in memory, in `k` order across the
//! board's documents. THE PROBE runs on the feed worker's own thread — a timed
//! wake ([`PROBE_CADENCE`]) that reads `/health` while a hold stands, because
//! `Cmd::Tick` is driven by COMMITTED writes and a poisoned, halted, stopped or
//! unreachable board commits nothing (and an unreachable board's stream is
//! down), so no tick arrives to end a hold whose cause was a failed dial. THE
//! RESEND ([`Holds::service`]) is AUTOMATIC at the hold's end and at reopen
//! (J2): one READ per document (`GET /changes`) before its first resend, with
//! §3c.5's three outcomes — (i) nothing landed, send from the head; (ii) the
//! in-flight burst landed, the head `done kept`; (iii) the site MOVED, no line
//! sent and the lines faced `moved`, NEVER rebased (J3).

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use serde_json::{json, Value};
use skep_client::board::{frames, Answer, ChangesAnswer, ChangesQuery, Rejection};
use skep_client::store::FileStore;
use skep_client::DialError;
use skep_identity::BoardTerm;
use skep_search::Chain;

use crate::attest::{wants_attest, Composer};
use crate::events::{EventBus, HELD};
use crate::feed::BoardEntry;
use crate::held::{now_ms, HaltWhy, HeldDir, HeldFile, HeldLine, Opened};
use crate::refusal::{Name, Refusal};
use crate::sessions::{signer, SessionEntry, Sessions};
use crate::Talk;

/// THE INTERIM PROBE CADENCE (§3c.4): `GET /health` at this interval while a
/// burst is held at a board whose cause is a failed dial — the lane's to tune.
pub const PROBE_CADENCE: std::time::Duration = std::time::Duration::from_secs(2);

/// The burst machine's five kinds (§3c.4) — the ops the store holds.
pub const BURST_KINDS: [&str; 5] = ["insert", "delete", "copy", "reinstate", "rearrange"];

/// Whether `frame` is a burst: one of the five kinds (§3c.4 says "on a draft
/// under the session" — the kind test is the shell's; a write on a document
/// that is no draft is the board's refusal, permanent, and so a refused run).
pub fn is_burst(frame: &Value) -> bool {
    frame["op"].as_str().is_some_and(|op| BURST_KINDS.contains(&op))
}

/// What a burst's dial answered that [`classify`] reads (§3c.4). The own node
/// STOPPED (no dial), an ACK, the death signal and a non-burst write are not
/// here: the shell holds `stopped` before the dial, carries an ack as any
/// `op`'s, ends the session on the death signal, and never reaches a non-burst.
#[derive(Debug, Clone, Copy)]
pub enum Outcome<'a> {
    /// The dial failed at the transport.
    Dial(&'a DialError),
    /// The board answered a `rejected` document (or a non-200 refusal): its
    /// `code`, and the `disposition` the body rode.
    Rejected { code: &'a str, disposition: &'a str },
}

/// What the shell does with a burst's outcome (§3c.4's table).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    /// HOLD the burst with this cause; `sent` whether the burst MAY have
    /// landed (§3c.2): a dial made whose answer was lost, or a `poisoned`
    /// answer, whose frames the board's journal keeps for its restart.
    Hold { cause: &'static str, sent: bool },
    /// A REFUSED run — a `permanent` or `reorder` refusal: the caller fills the
    /// `cause` with the board's token and the `refusal` with the body verbatim.
    Refused,
    /// REISSUE — `write_busy`, or a first or second `durability` (silent).
    Reissue,
    /// NEITHER held nor reissued — faced at its act (or resent after a death).
    Neither,
}

/// THE CLASSIFICATION TABLE (§3c.4): a burst's outcome, and how many prior
/// `durability` refusals the SAME burst has met, to exactly one row.
pub fn classify(outcome: Outcome<'_>, durability_seen: u32) -> Decision {
    match outcome {
        Outcome::Dial(e) => match e {
            // No connection was made — the burst did not leave.
            DialError::Connect(_) | DialError::Resolve(_) | DialError::Tls(_) => Decision::Hold { cause: "unreachable", sent: false },
            // The request left and its answer was no answer — it MAY have landed.
            DialError::Timeout(_) | DialError::Io(_) | DialError::Truncated { .. } | DialError::Response(_) | DialError::TooLarge { .. } => Decision::Hold { cause: "unreachable", sent: true },
            // The scheme this build does not hold, or a request refused before any
            // connection opened — faced as built, no probe ends either.
            DialError::NotHeld(_) | DialError::Request(_) => Decision::Neither,
            // A later transport error (the enum is non-exhaustive): the request
            // may have left, so hold `sent: true` — the resend reads first.
            _ => Decision::Hold { cause: "unreachable", sent: true },
        },
        Outcome::Rejected { code, disposition } => match code {
            // `poisoned` MAY have landed (§3c.2): the board's write path failed
            // AFTER the burst's frames reached its journal, and a restart's open
            // "rebuilds the line from the journal" (wire.md §Rejection codes) —
            // the burst lands at the restart, so the resend READS before it
            // sends, as after a lost answer. A `halted` hold (the feed's
            // `writes.halted` read, before any dial) stays `sent: false`.
            "poisoned" => Decision::Hold { cause: "poisoned", sent: true },
            "write_busy" => Decision::Reissue,
            // The rider (§3c.4): a THIRD `durability` on the same burst HOLDS it.
            "durability" => {
                if durability_seen >= 2 {
                    Decision::Hold { cause: "durability", sent: false }
                } else {
                    Decision::Reissue
                }
            }
            _ => match disposition {
                "permanent" | "reorder" => Decision::Refused,
                _ => Decision::Neither,
            },
        },
    }
}

/// THE OUTCOME of the resend's one read per document (§3c.5).
enum ReadOutcome {
    /// No row since `base` — send from the head.
    SendFromHead,
    /// The in-flight burst landed — the head is `done kept` with this `at`.
    Landed { at: Option<u64> },
    /// The site MOVED — no line sent, the lines faced `moved` (J3).
    Moved,
}

/// One principal's hold state at one board: its `held` file (or memory alone
/// where the store refused or a second window holds the lock), its P38 halt,
/// and the per-document `base` the resend's read starts from.
struct PrincipalHold {
    /// The file, where the store is writable and this window holds the lock;
    /// `None` means the lines are kept in MEMORY alone (`other_window`, or a
    /// `store_unwritable` append) — a close then loses them (§3c.3).
    file: Option<HeldFile>,
    /// The lines held in memory alone (no file): `other_window`'s, and an
    /// unwritable append's.
    mem: Vec<HeldLine>,
    /// P38's HALT: the file was written by a newer skep or its body is damaged.
    halted: Option<(PathBuf, HaltWhy)>,
    /// The `at` of the last ACKED write per document under this principal.
    last_acked: HashMap<String, u64>,
    /// The `durability` refusals the resend has met per held ordinal.
    durability: HashMap<u64, u32>,
    /// The ordinal `k` the memory-alone lines take next (no file to carry it).
    mem_k: u64,
}

impl PrincipalHold {
    fn new() -> PrincipalHold {
        PrincipalHold { file: None, mem: Vec::new(), halted: None, last_acked: HashMap::new(), durability: HashMap::new(), mem_k: 1 }
    }

    /// Every held line, in `k` order — the file's, or memory's.
    fn lines(&self) -> Vec<HeldLine> {
        match &self.file {
            Some(f) => f.lines().to_vec(),
            None => self.mem.clone(),
        }
    }

    /// Whether any hold-class line stands (a hold stands at this principal).
    fn any_held(&self) -> bool {
        !self.lines().is_empty()
    }
}

/// One board's hold state: the entry dialed, the directory and its lock
/// (established lazily at the first hold), and each principal's queue.
struct BoardHold {
    entry: Arc<BoardEntry>,
    /// `H.1`'s chain, once known; `None` means the board has no `H.1` and holds
    /// in MEMORY alone (said on TALK).
    chain: Option<Chain>,
    dir: Option<HeldDir>,
    /// The directory lock, held for the shell's life; `None` once a second
    /// shell is found to hold it (every burst then `other_window`).
    lock: Option<std::fs::File>,
    other_window: bool,
    /// Whether `/health.writes.halted` reads true (the feed's tick): every
    /// burst from then holds `halted` until a restart.
    halted: bool,
    /// Whether the halt has been seen true this uptime — its false reading
    /// after is the restart that clears `poisoned`/`halted` (§3c.4).
    seen_halted: bool,
    /// Whether the own node is STOPPED by the person's act: every burst holds
    /// `stopped` without a dial, and the probe does not resume until
    /// `set_node_state(Running)` clears it (§3c.4).
    node_stopped: bool,
    principals: HashMap<u64, PrincipalHold>,
}

/// THE HOLDS: every board's hold state, shared by the shell (the `op` branch,
/// `held`/`resolve`, the close), the feed workers (the probe wake, the
/// `writes.halted` read, the daemon-running end) and `set_node_state`.
pub struct Holds {
    sessions: Arc<Sessions>,
    bus: Arc<EventBus>,
    store: Arc<FileStore>,
    store_dir: PathBuf,
    talk: Talk,
    boards: Mutex<HashMap<String, BoardHold>>,
    /// The boards a resend is draining right now: one at a time per board, so
    /// the feed worker's probe and a session-open resend never double-send.
    resending: Mutex<HashSet<String>>,
}

impl Holds {
    /// The holds for a shell: no board yet.
    pub fn new(sessions: Arc<Sessions>, bus: Arc<EventBus>, store: Arc<FileStore>, store_dir: PathBuf, talk: Talk) -> Arc<Holds> {
        Arc::new(Holds { sessions, bus, store, store_dir, talk, boards: Mutex::new(HashMap::new()), resending: Mutex::new(HashSet::new()) })
    }

    fn say(&self, line: impl AsRef<str>) {
        (self.talk)(line.as_ref());
    }

    /// One board registered at open: nothing on disk is touched until the first
    /// hold (an idle shell leaves `held/` untouched).
    pub fn register_board(&self, reference: &str, entry: Arc<BoardEntry>) {
        self.boards.lock().expect("the holds' lock").entry(reference.to_string()).or_insert_with(|| BoardHold {
            entry,
            chain: None,
            dir: None,
            lock: None,
            other_window: false,
            halted: false,
            seen_halted: false,
            node_stopped: false,
            principals: HashMap::new(),
        });
    }

    /// The own node's STOPPED state as its owner reports it (§3c.4): every
    /// burst holds `stopped`, and the probe waits for `Running` to resend.
    pub fn set_node_stopped(&self, reference: &str, stopped: bool) {
        if let Some(board) = self.boards.lock().expect("the holds' lock").get_mut(reference) {
            board.node_stopped = stopped;
        }
    }

    /// Whether the board's node stands STOPPED by its owner's act
    /// ([`Holds::set_node_stopped`]) — what the feed reads when the board's
    /// stream fails, so a deliberate stop is announced `stopped` once and
    /// never `unreachable` beside it. A board that is not the own node, or
    /// one the holds never registered, answers false.
    pub fn node_stopped(&self, reference: &str) -> bool {
        self.boards.lock().expect("the holds' lock").get(reference).is_some_and(|b| b.node_stopped)
    }

    /// THE LAUNCH READ (§3c.7 item 1), BEFORE the node is up for writing: the
    /// acting principal's file read whole, its lines fired as `held` events per
    /// document (state `holding`) so the page can re-project at launch. P38's
    /// faces are kept. Best-effort: a board with no `H.1` yet is left for the
    /// first burst to establish.
    pub fn launch_read(&self, reference: &str, principal: u64, account: &str) {
        let mut boards = self.boards.lock().expect("the holds' lock");
        let Some(board) = boards.get_mut(reference) else { return };
        if !Self::ensure_dir(&self.store_dir, board) {
            return;
        }
        Self::open_principal(board, principal, account);
        let docs = board.principals.get(&principal).map(Self::docs_of).unwrap_or_default();
        drop(boards);
        for (doc, count, cause) in docs {
            self.fire(reference, None, &doc, count, "holding", Some(&cause));
        }
    }

    /// THE BEFORE-DIAL BRANCH (§3c.4): a burst at a board where a hold already
    /// stands (or the node is stopped, or the board is halted, or the store is
    /// P38-halted, or a second window holds the lock) is answered WITHOUT a
    /// dial. `None` means the shell dials.
    pub fn before_dial(&self, reference: &str, entry: &SessionEntry, frame: &Value) -> Option<Result<Value, Refusal>> {
        let principal = entry.facts.principal;
        let doc = frame["doc"].as_str().unwrap_or_default().to_string();
        let id = frame["id"].as_str().map(str::to_string);
        let mut boards = self.boards.lock().expect("the holds' lock");
        let board = boards.get_mut(reference)?;
        // P38: the store is halted for this (board, principal) — the halt's face.
        if let Some(ph) = board.principals.get(&principal) {
            if let Some((path, why)) = &ph.halted {
                return Some(Err(Refusal::shell(Name::STORE_HALTED, json!({"path": path.display().to_string(), "why": why.token()}))));
            }
        }
        let cause = if board.node_stopped {
            Some("stopped")
        } else if board.halted {
            Some("halted")
        } else if board.principals.get(&principal).is_some_and(PrincipalHold::any_held) {
            Some("behind")
        } else {
            None
        };
        let cause = cause?;
        Some(Ok(self.hold_locked(&mut boards, reference, entry, &doc, id.as_deref(), cause, None, false, frame)))
    }

    /// Hold the burst answered by a DIAL: its `Decision` from [`classify`], the
    /// board's refusal body where a refused run, the answer `{resp, held, …}`.
    #[allow(clippy::too_many_arguments)]
    pub fn hold_after_dial(&self, reference: &str, entry: &SessionEntry, frame: &Value, decision: &Decision, token: &str, body: Option<&Value>) -> Value {
        let doc = frame["doc"].as_str().unwrap_or_default().to_string();
        let id = frame["id"].as_str().map(str::to_string);
        let (cause, sent, refusal): (String, bool, Option<Value>) = match decision {
            Decision::Hold { cause, sent } => ((*cause).to_string(), *sent, None),
            Decision::Refused => (token.to_string(), false, body.cloned()),
            _ => ("behind".to_string(), false, None),
        };
        let mut boards = self.boards.lock().expect("the holds' lock");
        self.hold_locked(&mut boards, reference, entry, &doc, id.as_deref(), &cause, refusal, sent, frame)
    }

    /// Append one held line (file, or memory where the store refused or a
    /// second window holds the lock), fire the `held` event, answer `{resp:
    /// held, held:<k>, cause, [unwritable], [other_window]}`.
    #[allow(clippy::too_many_arguments)]
    fn hold_locked(
        &self,
        boards: &mut HashMap<String, BoardHold>,
        reference: &str,
        entry: &SessionEntry,
        doc: &str,
        id: Option<&str>,
        cause: &str,
        refusal: Option<Value>,
        sent: bool,
        frame: &Value,
    ) -> Value {
        let principal = entry.facts.principal;
        let base = Self::base_of(boards, reference, principal, doc);
        let Some(board) = boards.get_mut(reference) else {
            return json!({"resp": "held", "held": 0, "cause": cause});
        };
        Self::ensure_dir(&self.store_dir, board);
        Self::open_principal(board, principal, entry.facts.account.as_deref().unwrap_or(""));
        let frame = strip_attest(frame);
        // A refused run's line faces `refused` at once; any other hold `holding`.
        let state = if refusal.is_some() { "refused" } else { "holding" };
        let mut answer = held_answer_map(cause);
        let other_window = board.other_window || board.chain.is_none();
        let ph = board.principals.entry(principal).or_insert_with(PrincipalHold::new);
        let k = if let (false, Some(file)) = (other_window, ph.file.as_mut()) {
            match file.hold(doc, id, base, frame.clone(), cause, refusal.clone(), sent) {
                Ok(k) => k,
                Err(e) => {
                    // store_unwritable: keep the burst in MEMORY, say so on the answer.
                    answer.insert("unwritable".into(), Value::from(e.to_string()));
                    Self::push_mem(ph, doc, id, base, frame.clone(), cause, refusal.clone(), sent)
                }
            }
        } else {
            if other_window {
                answer.insert("cause".into(), Value::from("other_window"));
                self.say(format!("held: another window holds this board's held text; {doc}'s burst is kept in memory alone"));
            }
            Self::push_mem(ph, doc, id, base, frame.clone(), cause, refusal.clone(), sent)
        };
        answer.insert("held".into(), Value::from(k));
        let count = Self::docs_of(board.principals.get(&principal).unwrap()).into_iter().find(|(d, ..)| d == doc).map(|(_, c, _)| c).unwrap_or(0);
        let answer_cause = answer["cause"].as_str().unwrap_or(cause).to_string();
        // `fire` only touches the bus, so it is safe under the holds' lock.
        self.fire(reference, Some(&entry.reference), doc, count, state, Some(&answer_cause));
        Value::Object(answer)
    }

    /// Record the `at` of an ACKED session write on its document, for the
    /// resend's `base` (§3c.5). Best-effort over the kinds whose document the
    /// answer names.
    pub fn note_ack(&self, reference: &str, entry: &SessionEntry, frame: &Value, answer: &Value) {
        let Some(at) = answer["at"].as_u64() else { return };
        let doc = match frame["op"].as_str() {
            Some("create_new_document" | "fork" | "version") => answer["addr"].as_str(),
            _ => frame["doc"].as_str(),
        };
        let Some(doc) = doc else { return };
        let mut boards = self.boards.lock().expect("the holds' lock");
        if let Some(board) = boards.get_mut(reference) {
            board.principals.entry(entry.facts.principal).or_insert_with(PrincipalHold::new).last_acked.insert(doc.to_string(), at);
        }
    }

    /// `held(session)` → the acting principal's held lines at this board in
    /// resend order (§4b.1); `store_halted` where P38 halted the file.
    pub fn rows(&self, reference: &str, principal: u64) -> Result<Value, Refusal> {
        let boards = self.boards.lock().expect("the holds' lock");
        let Some(board) = boards.get(reference) else { return Ok(Value::Array(Vec::new())) };
        if let Some(ph) = board.principals.get(&principal) {
            if let Some((path, why)) = &ph.halted {
                return Err(Refusal::shell(Name::STORE_HALTED, json!({"path": path.display().to_string(), "why": why.token()})));
            }
            let rows: Vec<Value> = ph
                .lines()
                .iter()
                .map(|l| {
                    let mut row = json!({"held": l.k, "doc": l.doc, "base": l.base, "frame": l.frame, "cause": l.cause, "sent": l.sent, "time": l.time});
                    if let Some(r) = &l.refusal {
                        row["refusal"] = r.clone();
                    }
                    row
                })
                .collect();
            return Ok(Value::Array(rows));
        }
        Ok(Value::Array(Vec::new()))
    }

    /// `resolve(session, {held, act})` (§3c.5): `"drop"` on a `refused` or
    /// `moved` line marks it (and, for a refused run, every line held `behind`
    /// it on that document) `done … dropped`; `"send"` re-enters the automatic
    /// machine for that document. `no_such_held` / `not_resolvable` else.
    pub fn resolve(&self, reference: &str, entry: &SessionEntry, k: u64, act: &str) -> Result<Value, Refusal> {
        let principal = entry.facts.principal;
        let (doc, resolvable) = {
            let boards = self.boards.lock().expect("the holds' lock");
            let line = boards.get(reference).and_then(|b| b.principals.get(&principal)).and_then(|ph| ph.lines().into_iter().find(|l| l.k == k));
            let Some(line) = line else { return Err(Refusal::shell(Name::NO_SUCH_HELD, json!({"held": k}))) };
            // A `refused` or `moved` line alone takes an act (P10).
            let resolvable = line.cause == "moved" || line.refusal.is_some();
            (line.doc.clone(), resolvable)
        };
        if !resolvable {
            return Err(Refusal::shell(Name::NOT_RESOLVABLE, json!({"held": k})));
        }
        match act {
            "drop" => {
                self.drop_run(reference, principal, k, &doc);
                Ok(json!({}))
            }
            "send" => {
                // Re-enter the automatic machine (§3c.5): the refused or moved
                // lines on the document are re-armed to send, the read run
                // afresh, and the refusal faced again where it recurs.
                {
                    let mut boards = self.boards.lock().expect("the holds' lock");
                    if let Some(ph) = boards.get_mut(reference).and_then(|b| b.principals.get_mut(&principal)) {
                        let ks: Vec<u64> = ph.lines().into_iter().filter(|l| l.doc == doc && (l.cause == "moved" || l.refusal.is_some())).map(|l| l.k).collect();
                        for k in ks {
                            Self::remark_line(ph, k, "behind", None, false);
                        }
                    }
                }
                self.service(reference);
                Ok(json!({}))
            }
            other => Err(Refusal::shell(Name::NOT_RESOLVABLE, json!({"held": k, "act": other}))),
        }
    }

    /// `"drop"`: the line and, for a refused run, every line held `behind` it on
    /// that document, marked `done … dropped`; the file compacts where emptied.
    fn drop_run(&self, reference: &str, principal: u64, k: u64, doc: &str) {
        let count;
        {
            let mut boards = self.boards.lock().expect("the holds' lock");
            let Some(board) = boards.get_mut(reference) else { return };
            let Some(ph) = board.principals.get_mut(&principal) else { return };
            let drop_ks: Vec<u64> = ph.lines().into_iter().filter(|l| l.doc == doc && l.k >= k).map(|l| l.k).collect();
            for d in drop_ks {
                Self::done_line(ph, d, false, None);
            }
            count = ph.lines().iter().filter(|l| l.doc == doc).count() as u64;
        }
        self.fire(reference, None, doc, count, "kept", None);
    }

    /// THE PROBE and THE RESEND (§3c.4 end, §3c.5), run on the feed worker's
    /// thread: a timed wake, the daemon-running event, `set_node_state(Running)`
    /// and a session opening all route here. While a hold stands, `/health` is
    /// read; where the board is back the resend runs for each standing session.
    pub fn service(&self, reference: &str) {
        // Gather under the lock, then dial outside it so `op` is never blocked
        // on a dead board's connect timeout.
        let (needs, chain_known) = {
            let boards = self.boards.lock().expect("the holds' lock");
            let Some(board) = boards.get(reference) else { return };
            let any = board.principals.values().any(PrincipalHold::any_held);
            // A stopped own node holds until `Running`: the probe does not dial.
            (any && !board.other_window && !board.node_stopped, board.chain.is_some())
        };
        if !needs || !chain_known {
            return;
        }
        // One resend at a time per board.
        if !self.resending.lock().expect("the resend lock").insert(reference.to_string()) {
            return;
        }
        self.drain(reference);
        self.resending.lock().expect("the resend lock").remove(reference);
    }

    /// The probe's dial and the resend (the body of [`Holds::service`], run
    /// once per board at a time).
    fn drain(&self, reference: &str) {
        let entry_arc = {
            let boards = self.boards.lock().expect("the holds' lock");
            boards.get(reference).map(|b| Arc::clone(&b.entry))
        };
        let Some(entry_arc) = entry_arc else { return };
        // THE PROBE's one `/health` read (§3c.4).
        let Ok(health) = entry_arc.board.health() else {
            // Still unreachable — nothing to do this wake.
            return;
        };
        let writes_halted = health.body["writes"]["halted"].as_bool().unwrap_or(false);
        {
            let mut boards = self.boards.lock().expect("the holds' lock");
            let Some(board) = boards.get_mut(reference) else { return };
            if writes_halted {
                // `poisoned`/`halted` stands until a RESTART reads it false
                // (§3c.4; a same-dir restart keeps `log_position`, so the
                // `writes.halted` true→false transition is the signal).
                board.halted = true;
                board.seen_halted = true;
                return;
            }
            board.halted = false;
            board.seen_halted = false;
        }
        // The board answers and writes are not halted: the hold ends. Resume
        // each standing session of a principal that holds lines here.
        let principals: Vec<u64> = {
            let boards = self.boards.lock().expect("the holds' lock");
            boards.get(reference).map(|b| b.principals.iter().filter(|(_, ph)| ph.any_held()).map(|(p, _)| *p).collect()).unwrap_or_default()
        };
        for principal in principals {
            let Some(session) = self.sessions.on_board(reference).into_iter().find(|s| s.facts.principal == principal) else { continue };
            self.resume(reference, &session);
        }
    }

    /// `writes.halted` and the head read at the feed's tick (§3c.4): every burst
    /// from the first `true` holds `halted`.
    pub fn note_health(&self, reference: &str, writes_halted: bool, _log_position: u64) {
        let mut boards = self.boards.lock().expect("the holds' lock");
        if let Some(board) = boards.get_mut(reference) {
            board.halted = writes_halted;
            if writes_halted {
                board.seen_halted = true;
            }
        }
    }

    /// THE RESEND for one session (§3c.5): each document with held lines read
    /// once, then its lines sent in `k` order from where the read left them.
    fn resume(&self, reference: &str, session: &SessionEntry) {
        let principal = session.facts.principal;
        let docs: Vec<String> = {
            let boards = self.boards.lock().expect("the holds' lock");
            let Some(ph) = boards.get(reference).and_then(|b| b.principals.get(&principal)) else { return };
            let mut docs: Vec<String> = Vec::new();
            for l in ph.lines() {
                if !docs.contains(&l.doc) {
                    docs.push(l.doc);
                }
            }
            docs
        };
        for doc in docs {
            self.resume_doc(reference, session, &doc);
        }
    }

    /// One document's resend: the read (§3c.5), then the three outcomes.
    fn resume_doc(&self, reference: &str, session: &SessionEntry, doc: &str) {
        let principal = session.facts.principal;
        let (head, base) = {
            let boards = self.boards.lock().expect("the holds' lock");
            let Some(ph) = boards.get(reference).and_then(|b| b.principals.get(&principal)) else { return };
            let head = ph.lines().into_iter().find(|l| l.doc == doc);
            let Some(head) = head else { return };
            (head.clone(), head.base)
        };
        // A line already faced `moved` or `refused` waits for the person's act.
        if head.cause == "moved" || head.refusal.is_some() {
            return;
        }
        let entry_arc = {
            let boards = self.boards.lock().expect("the holds' lock");
            boards.get(reference).map(|b| Arc::clone(&b.entry))
        };
        let Some(entry_arc) = entry_arc else { return };
        let outcome = self.read_outcome(&entry_arc, session, doc, base, &head);
        self.fire(reference, Some(&session.reference), doc, self.doc_count(reference, principal, doc), "sending", None);
        match outcome {
            ReadOutcome::Moved => {
                self.mark_moved(reference, principal, doc);
                self.fire(reference, Some(&session.reference), doc, self.doc_count(reference, principal, doc), "moved", None);
            }
            ReadOutcome::Landed { at } => {
                self.done(reference, principal, head.k, true, at);
                let rest = self.doc_count(reference, principal, doc) > 0;
                self.send_rest(reference, session, doc);
                // Where the landed head was the document's last held line,
                // `send_rest` sent nothing, so the corner's `kept` is fired here.
                if !rest {
                    self.fire(reference, Some(&session.reference), doc, 0, "kept", None);
                }
            }
            ReadOutcome::SendFromHead => {
                self.send_rest(reference, session, doc);
            }
        }
    }

    /// THE READ (§3c.5): `GET /changes?since=<base>&under=<doc>&drafts=true`
    /// under the session, all pages collected, to one of the three outcomes.
    /// A `sent` head's one row is its own landing by the session's hand
    /// ([`own_row`]) or by a hand the board LOST ([`testimony_lost`], the
    /// `poisoned` burst a restart replays), the latter judged by the
    /// arrangement alone.
    fn read_outcome(&self, entry: &BoardEntry, session: &SessionEntry, doc: &str, base: u64, head: &HeldLine) -> ReadOutcome {
        let mut rows: Vec<Value> = Vec::new();
        let mut since = base;
        loop {
            let query = ChangesQuery { since, under: Some(doc), drafts: true, limit: None };
            match entry.board.changes(Some(&session.token), &query) {
                Ok(ChangesAnswer::Page(page)) => {
                    rows.extend(page.changes.iter().cloned());
                    since = page.last;
                    if !page.more {
                        break;
                    }
                }
                Ok(ChangesAnswer::HistoryReclaimed { .. }) => {
                    // `base` aged below the floor: the arrangement alone decides.
                    return self.reclaimed_outcome(entry, session, head);
                }
                Ok(_) | Err(_) => return ReadOutcome::SendFromHead,
            }
        }
        if rows.is_empty() {
            return ReadOutcome::SendFromHead;
        }
        // AT MOST ONE held burst can have landed without its ack (§7b's single
        // writer): exactly one row, of the session's own hand, consistent with
        // the head → (ii); anything else → (iii) MOVED.
        if head.sent && rows.len() == 1 {
            let row = &rows[0];
            if own_row(session, row) && row["op"].as_str() == head.frame["op"].as_str() && self.content_confirmed(entry, session, doc, head) != Some(false) {
                return ReadOutcome::Landed { at: row["at"].as_u64() };
            }
            // A row whose TESTIMONY THE BOARD LOST — `docs`, `key` and `op` the
            // reserved null (wire.md §`/changes`): a commit the daemon never
            // recorded, re-derived from the journal at its open — which is what
            // a `poisoned` burst's landing at the restart is (§3c.2): the write
            // path records acks alone. The feed cannot say whose it is, so THE
            // ARRANGEMENT ALONE decides, as on `history_reclaimed` (§3c.5), and
            // decisively: an `insert` whose values read back equal is (ii); a
            // kind the site read cannot confirm faces the person (iii).
            if testimony_lost(row) && self.content_confirmed(entry, session, doc, head) == Some(true) {
                return ReadOutcome::Landed { at: row["at"].as_u64() };
            }
        }
        ReadOutcome::Moved
    }

    /// A `history_reclaimed` on the read (§3c.5): `retrieve_v` at the head's
    /// site decides (ii), any difference is (iii).
    fn reclaimed_outcome(&self, entry: &BoardEntry, session: &SessionEntry, head: &HeldLine) -> ReadOutcome {
        if head.sent && self.content_agrees(entry, session, &head.doc, head) {
            ReadOutcome::Landed { at: None }
        } else {
            ReadOutcome::Moved
        }
    }

    /// Outcome (ii)'s content confirm (§3c.5): ONE `retrieve_v` at the burst's
    /// site, the values equal. For an `insert` the values are compared; a burst
    /// of another kind trusts the op-and-hand match (its site read is the
    /// editor lane's to pin). A read that fails trusts the match.
    fn content_agrees(&self, entry: &BoardEntry, session: &SessionEntry, doc: &str, head: &HeldLine) -> bool {
        self.content_confirmed(entry, session, doc, head) != Some(false)
    }

    /// The content confirm's three answers: `Some(true)` an `insert` whose
    /// values read back equal at its site, `Some(false)` one whose values
    /// differ, `None` where the read cannot decide — a burst of another kind,
    /// a frame with no site, or a read that failed. [`Holds::content_agrees`]
    /// trusts `None`; the lost-testimony arm of the read does not.
    fn content_confirmed(&self, entry: &BoardEntry, session: &SessionEntry, doc: &str, head: &HeldLine) -> Option<bool> {
        if head.frame["op"].as_str() != Some("insert") {
            return None;
        }
        let values = head.frame["values"].as_array()?;
        let from = head.frame["at"]["ordinal"].as_str().and_then(|o| o.parse::<u64>().ok())?;
        let width = values.len() as u64;
        match entry.board.op(Some(&session.token), &frames::retrieve_v(doc, from, width)) {
            Ok(Answer::Document(v)) => {
                let read: Vec<&Value> = v["items"].as_array().map(|a| a.iter().map(|it| &it["content"]).collect()).unwrap_or_default();
                Some(read.len() == values.len() && read.iter().zip(values).all(|(a, b)| *a == b))
            }
            _ => None,
        }
    }

    /// Send every un-done, un-faced line on `doc` from the head in `k` order,
    /// each a normal `op` under the session; stop at the first that holds again.
    fn send_rest(&self, reference: &str, session: &SessionEntry, doc: &str) {
        let principal = session.facts.principal;
        loop {
            let line = {
                let boards = self.boards.lock().expect("the holds' lock");
                boards.get(reference).and_then(|b| b.principals.get(&principal)).and_then(|ph| ph.lines().into_iter().find(|l| l.doc == doc && l.cause != "moved" && l.refusal.is_none()))
            };
            let Some(line) = line else { break };
            if !self.send_line(reference, session, &line) {
                break;
            }
        }
    }

    /// Send one line: compose the attest NOW where the session holds a key, dial
    /// `op`, and resolve it. Answers whether sending may continue on this
    /// document (false where the line held again, a refused run, or a reissue
    /// waits for the next wake).
    fn send_line(&self, reference: &str, session: &SessionEntry, line: &HeldLine) -> bool {
        let entry_arc = {
            let boards = self.boards.lock().expect("the holds' lock");
            match boards.get(reference) {
                Some(b) => Arc::clone(&b.entry),
                None => return false,
            }
        };
        let mut frame = line.frame.clone();
        if let Some(fp) = session.facts.fingerprint {
            if wants_attest(&frame) && self.compose_attest(&entry_arc, session, &fp, &mut frame).is_err() {
                return false;
            }
        }
        match entry_arc.board.op(Some(&session.token), &frame) {
            Ok(Answer::Document(v)) => match Rejection::of(&v) {
                None => {
                    // An ack: `done kept`, the document's state moves to `kept`
                    // as its last held line lands.
                    let at = v["at"].as_u64();
                    self.done(reference, session.facts.principal, line.k, true, at);
                    let count = self.doc_count(reference, session.facts.principal, &line.doc);
                    self.fire(reference, Some(&session.reference), &line.doc, count, if count == 0 { "kept" } else { "sending" }, None);
                    true
                }
                Some(r) => {
                    let token = r.token();
                    let disposition = v["disposition"].as_str().unwrap_or("");
                    self.resolve_rejection(reference, session, line, r.key(), disposition, &token, &v)
                }
            },
            Ok(Answer::Closed) => false,
            Err(h) => {
                if let skep_client::halt::Halt::Dial(e) = &h {
                    if let Decision::Hold { cause, sent } = classify(Outcome::Dial(e), 0) {
                        self.remark(reference, session, line, cause, None, sent);
                    }
                } else if let skep_client::halt::Halt::Refused(r) = &h {
                    // A non-200 (e.g. `write_busy` 503): reissue next wake.
                    let _ = r;
                }
                false
            }
        }
    }

    /// A rejection met on a resend: a hold-class code holds the line again, a
    /// `permanent`/`reorder` refusal makes a REFUSED run, a third `durability`
    /// holds, and a reissue-class answer waits for the next wake.
    #[allow(clippy::too_many_arguments)]
    fn resolve_rejection(&self, reference: &str, session: &SessionEntry, line: &HeldLine, code: &str, disposition: &str, token: &str, body: &Value) -> bool {
        let durability_seen = {
            let mut boards = self.boards.lock().expect("the holds' lock");
            match boards.get_mut(reference).and_then(|b| b.principals.get_mut(&session.facts.principal)) {
                Some(ph) if code == "durability" => {
                    let n = ph.durability.entry(line.k).or_insert(0);
                    *n += 1;
                    *n - 1
                }
                _ => 0,
            }
        };
        match classify(Outcome::Rejected { code, disposition }, durability_seen) {
            Decision::Hold { cause, sent } => {
                self.remark(reference, session, line, cause, None, sent);
                false
            }
            Decision::Refused => {
                self.remark(reference, session, line, token, Some(body.clone()), false);
                self.fire(reference, Some(&session.reference), &line.doc, self.doc_count(reference, session.facts.principal, &line.doc), "refused", Some(token));
                false
            }
            Decision::Reissue => false,
            Decision::Neither => {
                // The board took it as something other than a burst refusal:
                // treat it done so the queue drains.
                self.done(reference, session.facts.principal, line.k, true, body["at"].as_u64());
                true
            }
        }
    }

    /// Mark every line of a MOVED document (J3): `cause: moved`, no line sent,
    /// NEVER rebased. The exact rebase by identity — the burst's anchor re-found
    /// and the delta placed after it — stays named as OPEN (§3c.5, the record §5
    /// Q3): it needs an anchor the page's frame does not carry today, and a
    /// silent inexact rebase could put words where the person did not. The
    /// page's half — what the burst machine does at a `held` answer, how it
    /// re-projects the held frames at a launch, the moved document's face — is
    /// the frontend lane's and in neither repository at this pin (UNVERIFIED
    /// HERE, the record §7 item 4; stated from assisted-frontend §7b).
    fn mark_moved(&self, reference: &str, principal: u64, doc: &str) {
        let mut boards = self.boards.lock().expect("the holds' lock");
        let Some(ph) = boards.get_mut(reference).and_then(|b| b.principals.get_mut(&principal)) else { return };
        let ks: Vec<u64> = ph.lines().into_iter().filter(|l| l.doc == doc).map(|l| l.k).collect();
        for k in ks {
            Self::remark_line(ph, k, "moved", None, false);
        }
    }

    /// Re-mark one line in place (a hold that recurs, a refused run, a moved
    /// re-facing), its ordinal kept (no `done` owed).
    fn remark(&self, reference: &str, session: &SessionEntry, line: &HeldLine, cause: &str, refusal: Option<Value>, sent: bool) {
        let mut boards = self.boards.lock().expect("the holds' lock");
        if let Some(ph) = boards.get_mut(reference).and_then(|b| b.principals.get_mut(&session.facts.principal)) {
            Self::remark_line(ph, line.k, cause, refusal, sent);
        }
    }

    fn remark_line(ph: &mut PrincipalHold, k: u64, cause: &str, refusal: Option<Value>, sent: bool) {
        match ph.file.as_mut() {
            Some(file) => {
                let _ = file.remark(k, cause, refusal.clone(), sent);
            }
            None => {
                if let Some(l) = ph.mem.iter_mut().find(|l| l.k == k) {
                    l.cause = cause.to_string();
                    l.refusal = refusal;
                    l.sent = sent;
                    l.time = now_ms();
                }
            }
        }
    }

    /// Resolve one line `done` (kept or dropped), the file compacting where it
    /// empties.
    fn done(&self, reference: &str, principal: u64, k: u64, kept: bool, at: Option<u64>) {
        let mut boards = self.boards.lock().expect("the holds' lock");
        if let Some(ph) = boards.get_mut(reference).and_then(|b| b.principals.get_mut(&principal)) {
            Self::done_line(ph, k, kept, at);
        }
    }

    fn done_line(ph: &mut PrincipalHold, k: u64, kept: bool, at: Option<u64>) {
        match ph.file.as_mut() {
            Some(file) => {
                let _ = file.done(k, kept, at);
            }
            None => ph.mem.retain(|l| l.k != k),
        }
        ph.durability.remove(&k);
    }

    fn doc_count(&self, reference: &str, principal: u64, doc: &str) -> u64 {
        let boards = self.boards.lock().expect("the holds' lock");
        boards.get(reference).and_then(|b| b.principals.get(&principal)).map(|ph| ph.lines().iter().filter(|l| l.doc == doc).count() as u64).unwrap_or(0)
    }

    /// Fire the `held` event (§4b.2): `{board, session, doc, held, state, cause?}`.
    fn fire(&self, reference: &str, session: Option<&str>, doc: &str, held: u64, state: &str, cause: Option<&str>) {
        let mut data = json!({"board": reference, "session": session, "doc": doc, "held": held, "state": state});
        if let Some(c) = cause {
            data["cause"] = Value::from(c);
        }
        self.bus.emit(HELD, data);
    }

    /// Compose the publish-class attest for a resend NOW (§3c.2): the same `H.1`
    /// pair after a restart and the key the session then stands under.
    fn compose_attest(&self, entry: &BoardEntry, session: &SessionEntry, fp: &skep_identity::Fingerprint, frame: &mut Value) -> Result<(), Refusal> {
        let Some(term) = entry.board.board_term().map_err(Refusal::of)? else { return Ok(()) };
        let signer = signer(&self.store, &self.store.key_path(fp))?;
        let account = session.facts.account.as_deref().ok_or_else(|| Refusal::shell(Name::NO_ACCOUNT, json!({})))?;
        let composer = Composer { board: &entry.board, token: &session.token, signer: &*signer, account, term };
        composer.attach(frame).map_err(|h| Refusal::of_named(Name::ATTEST_NOT_COMPOSED, h))
    }

    // ── the per-principal helpers under the lock ─────────────────────────────

    /// Establish the board's chain (`H.1`), directory and lock at the first
    /// hold. Answers whether a directory stands (a board with no `H.1` holds in
    /// memory alone).
    fn ensure_dir(store_dir: &Path, board: &mut BoardHold) -> bool {
        if board.dir.is_some() {
            return true;
        }
        let term: Option<BoardTerm> = board.entry.board.board_term().ok().flatten();
        let Some(term) = term else { return false };
        let chain = Chain::from_bytes(term.chain);
        let dir = HeldDir::new(store_dir, chain);
        if dir.ensure().is_err() {
            return false;
        }
        match dir.try_lock() {
            Ok(Some(lock)) => {
                board.lock = Some(lock);
            }
            Ok(None) => {
                board.other_window = true;
            }
            Err(_) => return false,
        }
        board.chain = Some(chain);
        board.dir = Some(dir);
        true
    }

    /// Open a principal's file, keeping P38's halt where it faces one.
    fn open_principal(board: &mut BoardHold, principal: u64, account: &str) {
        if board.other_window {
            board.principals.entry(principal).or_insert_with(PrincipalHold::new);
            return;
        }
        if board.principals.get(&principal).is_some_and(|ph| ph.file.is_some() || ph.halted.is_some()) {
            return;
        }
        let Some(dir) = &board.dir else { return };
        match dir.open_file(principal, account) {
            Ok(Opened::Live(file)) => {
                let ph = board.principals.entry(principal).or_insert_with(PrincipalHold::new);
                ph.file = Some(file);
            }
            Ok(Opened::Halted { path, why }) => {
                let ph = board.principals.entry(principal).or_insert_with(PrincipalHold::new);
                ph.halted = Some((path, why));
            }
            Err(_) => {
                board.principals.entry(principal).or_insert_with(PrincipalHold::new);
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn push_mem(ph: &mut PrincipalHold, doc: &str, id: Option<&str>, base: u64, frame: Value, cause: &str, refusal: Option<Value>, sent: bool) -> u64 {
        let k = ph.mem_k;
        ph.mem_k += 1;
        ph.mem.push(HeldLine { k, doc: doc.to_string(), id: id.map(str::to_string), base, frame, cause: cause.to_string(), refusal, sent, time: now_ms() });
        k
    }

    fn base_of(boards: &HashMap<String, BoardHold>, reference: &str, principal: u64, doc: &str) -> u64 {
        boards.get(reference).and_then(|b| b.principals.get(&principal)).and_then(|ph| ph.last_acked.get(doc)).copied().unwrap_or(0)
    }

    /// The documents a principal holds, each with its count and the head line's
    /// cause — for the launch events and the count.
    fn docs_of(ph: &PrincipalHold) -> Vec<(String, u64, String)> {
        let mut out: Vec<(String, u64, String)> = Vec::new();
        for l in ph.lines() {
            match out.iter_mut().find(|(d, ..)| *d == l.doc) {
                Some((_, c, _)) => *c += 1,
                None => out.push((l.doc.clone(), 1, l.cause.clone())),
            }
        }
        out
    }
}

/// The session's own hand on the feed (§3c.5), as an UNSIGNED entry's `key`
/// names it: its key's fingerprint, or `bare`.
fn own_hand(session: &SessionEntry) -> String {
    match session.facts.fingerprint {
        Some(fp) => fp.to_hex(),
        None => "bare".to_string(),
    }
}

/// Whether a `/changes` row is of the session's OWN hand (§3c.5). An
/// unsigned entry carries `key` — [`own_hand`]'s value. A SIGNED entry
/// carries NO `key` (wire.md §`/changes`: `key` is present iff the entry is
/// unsigned) and `attest` in its place, and is the session's own where the
/// session holds a key — §3c.5's "its `key` the session's fingerprint" reads
/// the unsigned form alone. The shell attests every `insert` ("Attach when in
/// doubt"), but the daemon keeps an attest on a publish-class write alone and
/// DROPS it on a draft's (wire.md §The two attestation codes), so a burst's
/// row is the unsigned form today, its `key` the signing key's fingerprint;
/// the signed form stands for a row the wire's rule admits. The read's other
/// two guards (`op` equal, the content confirmed) stand beside this one, so
/// another key's signed row still reads as (iii).
fn own_row(session: &SessionEntry, row: &Value) -> bool {
    if row["key"].as_str() == Some(own_hand(session).as_str()) {
        return true;
    }
    session.facts.fingerprint.is_some() && row.get("key").is_none() && row.get("attest").is_some()
}

/// Whether a `/changes` row's testimony is LOST — `docs`, `key` and `op` the
/// reserved null (wire.md §`/changes`: "`null` ONLY for lost metadata"): a
/// commit the daemon never recorded, re-derived from the journal at its open
/// and classified to its documents, whose hand and kind the feed cannot name.
/// A signed row has no `key` but names its `op`; a bare session's row says
/// `bare`; neither is this.
fn testimony_lost(row: &Value) -> bool {
    row["docs"].is_null() && row["key"].is_null() && row["op"].is_null()
}

/// A frame with any `attest` stripped — the stored form carries none (§3c.2).
fn strip_attest(frame: &Value) -> Value {
    let mut frame = frame.clone();
    if let Some(obj) = frame.as_object_mut() {
        obj.remove("attest");
    }
    frame
}

/// A fresh answer map for a held burst, the cause set.
fn held_answer_map(cause: &str) -> serde_json::Map<String, Value> {
    let mut m = serde_json::Map::new();
    m.insert("resp".into(), Value::from("held"));
    m.insert("cause".into(), Value::from(cause.to_string()));
    m
}

#[cfg(test)]
mod tests;
