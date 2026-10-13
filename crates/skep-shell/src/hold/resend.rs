//! THE PROBE and THE RESEND (`client.md` §3c.4, §3c.5): the hold's walk
//! that drains a board's queue once the board returns. THE PROBE
//! ([`Holds::probe`]) runs on the board's feed thread every
//! [`PROBE_CADENCE`](super::PROBE_CADENCE) while a line stands, and there
//! too at the hand-overs of `resolve(send)` and `set_node_state(Running)`,
//! because `Cmd::Tick` is driven by COMMITTED writes and a poisoned,
//! halted, stopped or unreachable board commits nothing. THE RESEND it lets run is AUTOMATIC at the hold's end
//! and at reopen (J2): one READ per document (`GET /changes`) before its
//! first resend, with §3c.5's three outcomes — (i) nothing landed, send from
//! the head; (ii) the in-flight burst landed, the head `done kept`; (iii)
//! the site MOVED, no line sent and the lines faced `moved`, NEVER rebased
//! (J3) — and a read the board did not answer decides nothing: the next
//! probe reads again. Each line goes out through the hold's one reader of a
//! write's answer, as a first dial does.

use std::borrow::Cow;
use std::ops::ControlFlow;
use std::sync::atomic::{AtomicBool, Ordering};

use serde_json::Value;
use skep_client::board::{acked_at, frames, Answer, ChangesAnswer, ChangesQuery, Rejection};

use super::{awaits_act, cause, line_state, BoardSlot, Dialed, HeldState, Holds};
use crate::wire::{delivered_values, values_of};
use crate::held::{Done, HeldLine, Reason};
use crate::sessions::{SessionEntry, SessionKind};

/// THE OUTCOME of the resend's one read per document (§3c.5).
enum ReadOutcome {
    /// No row since `base` — send from the head.
    SendFromHead,
    /// The in-flight burst landed — the head is `done kept` with this `at`.
    Landed { at: Option<u64> },
    /// The site MOVED — no line sent, the lines faced `moved` (J3).
    Moved,
    /// The board answered no page — a refusal (`feed_rebuilding`), the
    /// death signal, no answer: nothing is decided, and the next probe reads
    /// again.
    Unread,
}

/// What ONE `retrieve_v` at a held burst's site says of its values (§3c.5's
/// content confirm).
enum Site {
    /// The values read back equal: the burst stands there.
    Equal,
    /// Other values, or none (the site out of the document's bounds).
    Differs,
    /// No read can decide: a burst of another kind than `insert`, or a frame
    /// that names no site.
    Unconfirmable,
    /// The board did not answer the read.
    Unread,
}

/// A board's drain mark (`BoardSlot`'s `draining`), held for one drain and
/// cleared when the drain ends — however it ends, a dial that unwinds
/// included — so no board stays marked by a drain that never finished.
struct Draining<'h>(&'h AtomicBool);

impl<'h> Draining<'h> {
    /// The mark taken, or `None` where a drain of the board already runs.
    fn begin(mark: &'h AtomicBool) -> Option<Draining<'h>> {
        // No guard is built where no mark was taken: dropped, it would clear
        // the mark of the drain that holds it.
        (!mark.swap(true, Ordering::SeqCst)).then_some(Draining(mark))
    }
}

impl Drop for Draining<'_> {
    fn drop(&mut self) {
        self.0.store(false, Ordering::SeqCst);
    }
}

impl Holds {
    /// THE PROBE (§3c.4), and the RESEND it lets run (§3c.5): run on the
    /// board's feed thread alone — every
    /// [`PROBE_CADENCE`](super::PROBE_CADENCE), at its daemon-running tick,
    /// and at the hand-overs of `resolve(send)` and `set_node_state(Running)`.
    /// While a line stands at a board whose own node is not stopped,
    /// `/health` is read; where the board answers and takes writes, each
    /// standing session of a principal with lines resends them.
    pub fn probe(&self, board_reference: &str) {
        // Gathered under the lock and dialed outside it, so `op` never waits
        // on a dead board's connect timeout.
        let slot = self.slot(board_reference);
        let due = {
            let board_hold = slot.lock();
            !board_hold.node_stopped && board_hold.principals.values().any(|ph| !ph.queue.lines().is_empty())
        };
        if !due {
            return;
        }
        // One drain per board at a time, its mark cleared however it ends.
        let Some(_draining) = Draining::begin(&slot.draining) else { return };
        self.drain(board_reference, slot);
    }

    /// The probe's dial and the resend (the body of [`Holds::probe`], run
    /// once per board at a time).
    fn drain(&self, board_reference: &str, slot: &BoardSlot) {
        let board = &slot.board;
        // THE PROBE's one `/health` read (§3c.4): a board that does not answer
        // is read again at the next probe, and one whose writes are halted
        // holds every line.
        let Ok(health) = board.health() else { return };
        if self.note_health(board_reference, &health) {
            return;
        }
        // The board answers and takes writes: the hold ends. A directory no
        // session's open could establish is tried again, and each standing
        // session of a principal with lines resends them.
        self.establish(slot);
        let principals: Vec<u64> = slot.lock().principals.iter().filter(|(_, ph)| !ph.queue.lines().is_empty()).map(|(p, _)| *p).collect();
        for principal in principals {
            let Some(session) = self.sessions.on_board(board_reference).into_iter().find(|s| s.facts.principal == principal) else { continue };
            self.resume(&session);
        }
    }

    /// THE RESEND for one session (§3c.5), RESUMED BY READ — wire.md's
    /// RESUME-BY-READ (PUB-8.32) — at the board it stands at: each document
    /// with held lines read once, then its lines sent in `k` order from where
    /// the read left them.
    fn resume(&self, session: &SessionEntry) {
        let Some(docs) = self.with_principal(&session.board_reference, session.facts.principal, |ph| {
            let mut docs: Vec<String> = Vec::new();
            for l in ph.queue.lines() {
                if !docs.contains(&l.doc) {
                    docs.push(l.doc.clone());
                }
            }
            docs
        }) else {
            return;
        };
        for doc in docs {
            self.resume_doc(session, &doc);
        }
    }

    /// One document resumed by its read (RESUME-BY-READ, §3c.5): the read,
    /// then its outcome — a head awaiting the person's act read and sent
    /// never.
    fn resume_doc(&self, session: &SessionEntry, doc: &str) {
        let (board_reference, principal) = (session.board_reference.as_str(), session.facts.principal);
        let Some(head) = self.head_of(board_reference, principal, doc) else { return };
        if awaits_act(&head) {
            return;
        }
        match self.read_outcome(session, doc, &head) {
            ReadOutcome::Unread => {}
            ReadOutcome::Moved => {
                self.mark_moved(board_reference, principal, doc);
                self.emit_held(session, doc, self.count(board_reference, principal, doc), HeldState::Moved, None);
            }
            ReadOutcome::Landed { at } => {
                self.done(board_reference, principal, head.k, Done::Kept { at });
                match self.count(board_reference, principal, doc) {
                    0 => self.emit_held(session, doc, 0, HeldState::Kept, None),
                    rest => {
                        self.emit_held(session, doc, rest, HeldState::Sending, None);
                        self.send_rest(session, doc);
                    }
                }
            }
            ReadOutcome::SendFromHead => {
                self.emit_held(session, doc, self.count(board_reference, principal, doc), HeldState::Sending, None);
                self.send_rest(session, doc);
            }
        }
    }

    /// THE READ (§3c.5): `GET /changes?since=<base>&under=<doc>&drafts=true`
    /// under the session, at a page of two rows — the question is none, one,
    /// or more — to one of the outcomes. AT MOST ONE held burst can have
    /// landed without its ack (§7b's single writer): a `sent` head's one row
    /// is its landing where it is of the session's own hand ([`own_row`]),
    /// its `op` the head's and its site not contradicting it, or where the
    /// board LOST its testimony ([`testimony_lost`], the `poisoned` burst a
    /// restart replays) and the site confirms it; any other row is (iii).
    fn read_outcome(&self, session: &SessionEntry, doc: &str, head: &HeldLine) -> ReadOutcome {
        let query = ChangesQuery { since: head.base, under: Some(doc), drafts: true, limit: Some(2) };
        let page = match session.board.changes(Some(&session.token), &query) {
            Ok(ChangesAnswer::Page(page)) => page,
            // `base` aged below the floor: the arrangement alone decides.
            Ok(ChangesAnswer::HistoryReclaimed { .. }) => return self.reclaimed_outcome(session, doc, head),
            // A page of two rows too large to serve holds two rows or more.
            Ok(ChangesAnswer::TooLarge { .. }) => return ReadOutcome::Moved,
            Ok(_) | Err(_) => return ReadOutcome::Unread,
        };
        let [row] = page.changes.as_slice() else {
            return if page.changes.is_empty() { ReadOutcome::SendFromHead } else { ReadOutcome::Moved };
        };
        if !head.reason.sent || page.more {
            return ReadOutcome::Moved;
        }
        let landed = ReadOutcome::Landed { at: row["at"].as_u64() };
        if own_row(session, row) && row["op"].as_str() == head.frame["op"].as_str() {
            // A kind the site read cannot confirm trusts the op-and-hand match.
            return match self.site(session, doc, head) {
                Site::Equal | Site::Unconfirmable => landed,
                Site::Differs => ReadOutcome::Moved,
                Site::Unread => ReadOutcome::Unread,
            };
        }
        // A row whose TESTIMONY THE BOARD LOST — `docs`, `key` and `op` the
        // reserved null (wire.md §`/changes`): a commit the daemon never
        // recorded, re-derived from the journal at its open — which is what
        // a `poisoned` burst's landing at the restart is (§3c.2): the write
        // path records acks alone. The feed cannot say whose it is, so THE
        // ARRANGEMENT ALONE decides, as on `history_reclaimed` (§3c.5), and
        // decisively: an `insert` whose values read back equal is (ii); a
        // kind the site read cannot confirm faces the person (iii).
        if testimony_lost(row) {
            return match self.site(session, doc, head) {
                Site::Equal => landed,
                Site::Differs | Site::Unconfirmable => ReadOutcome::Moved,
                Site::Unread => ReadOutcome::Unread,
            };
        }
        ReadOutcome::Moved
    }

    /// A `history_reclaimed` on the read (§3c.5): the arrangement alone
    /// decides — a `sent` head's values read back equal at its site is (ii);
    /// any difference, a kind no read confirms, or a head never sent is
    /// (iii).
    fn reclaimed_outcome(&self, session: &SessionEntry, doc: &str, head: &HeldLine) -> ReadOutcome {
        if !head.reason.sent {
            return ReadOutcome::Moved;
        }
        match self.site(session, doc, head) {
            Site::Equal => ReadOutcome::Landed { at: None },
            Site::Differs | Site::Unconfirmable => ReadOutcome::Moved,
            Site::Unread => ReadOutcome::Unread,
        }
    }

    /// THE CONTENT CONFIRM (§3c.5): ONE `retrieve_v` at an `insert`'s site,
    /// as wide as the values its frame spells, the delivery read back as
    /// values and held to them.
    fn site(&self, session: &SessionEntry, doc: &str, head: &HeldLine) -> Site {
        if head.frame["op"].as_str() != Some("insert") {
            return Site::Unconfirmable;
        }
        let ordinal = head.frame["at"]["ordinal"].as_str().and_then(|o| o.parse::<u64>().ok());
        let (Ok(want), Some(from)) = (values_of(&head.frame["values"]), ordinal) else { return Site::Unconfirmable };
        match session.board.op(Some(&session.token), &frames::retrieve_v(doc, from, want.len() as u64)) {
            Ok(Answer::Document(v)) if Rejection::of(&v).is_none() => {
                if delivers(&v, &want) {
                    Site::Equal
                } else {
                    Site::Differs
                }
            }
            Ok(Answer::Document(_)) => Site::Differs,
            Ok(Answer::Closed) | Err(_) => Site::Unread,
        }
    }

    /// Send the document's lines from its head in `k` order, each a normal
    /// `op` under the session; stop at a line that awaits the person's act or
    /// is not taken.
    fn send_rest(&self, session: &SessionEntry, doc: &str) {
        while let Some(line) = self.head_of(&session.board_reference, session.facts.principal, doc) {
            if awaits_act(&line) || self.send_line(session, &line).is_break() {
                break;
            }
        }
    }

    /// ONE held line sent as the `op` it is, under the session that stands —
    /// its attest composed NOW (§3c.2) — and settled by what the dial
    /// answered: an ack `done kept`; a hold-class answer or a REFUSED run
    /// re-marked and faced; a reissue-class answer counted against the line
    /// and reissued at the next probe, so its third `durability` holds it; a
    /// refusal the table holds nowhere left standing for the next probe,
    /// never `done`; the death signal left to the hand that ends the
    /// session — the session that stands resends after its read. `Continue`
    /// where sending goes on to the document's next line, `Break` where it
    /// stops at this one.
    fn send_line(&self, session: &SessionEntry, line: &HeldLine) -> ControlFlow<()> {
        let (board_reference, principal) = (session.board_reference.as_str(), session.facts.principal);
        let given = self.with_principal(board_reference, principal, |ph| ph.reissues.get(&line.k).copied()).flatten().unwrap_or_default();
        let dialed = match self.attest_where_owed(session, &line.frame) {
            Ok(frame) => self.dial(session, &frame, given),
            Err(why) => Dialed::from(why),
        };
        match dialed {
            Dialed::Acked(ack) => {
                self.note_ack(session, &line.frame, &ack);
                self.done(board_reference, principal, line.k, Done::Kept { at: acked_at(&ack) });
                let rest = self.count(board_reference, principal, &line.doc);
                self.emit_held(session, &line.doc, rest, if rest == 0 { HeldState::Kept } else { HeldState::Sending }, None);
                ControlFlow::Continue(())
            }
            Dialed::Held { reason, .. } => {
                let state = line_state(&reason);
                let said = reason.cause.clone();
                self.with_principal(board_reference, principal, |ph| self.remark_line(ph, line.k, reason));
                self.emit_held(session, &line.doc, self.count(board_reference, principal, &line.doc), state, Some(&said));
                ControlFlow::Break(())
            }
            Dialed::Reissue { kind, refusal } => {
                // The rider's count (§3c.4), per line across its probes: the
                // third `durability` holds it.
                self.with_principal(board_reference, principal, |ph| ph.reissues.entry(line.k).or_default().note(kind));
                self.say(format!("held: line {} on {} was not taken ({refusal}); it is sent again at the next probe", line.k, line.doc));
                ControlFlow::Break(())
            }
            Dialed::Faced(refusal) => {
                self.say(format!("held: line {} on {} was not taken ({refusal}); it is sent again at the next probe", line.k, line.doc));
                ControlFlow::Break(())
            }
            Dialed::Died => ControlFlow::Break(()),
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
    fn mark_moved(&self, board_reference: &str, principal: u64, doc: &str) {
        self.with_principal(board_reference, principal, |ph| {
            let ks: Vec<u64> = ph.queue.lines().iter().filter(|l| l.doc == doc).map(|l| l.k).collect();
            for k in ks {
                self.remark_line(ph, k, Reason::of(cause::MOVED, false));
            }
        });
    }

    /// Resolve one line `done` — [`Done::Kept`] or [`Done::Dropped`] — the
    /// file compacting where the queue empties.
    fn done(&self, board_reference: &str, principal: u64, k: u64, done: Done) {
        self.with_principal(board_reference, principal, |ph| self.done_line(ph, k, done));
    }

    /// The document's head: its first standing line in `k` order.
    fn head_of(&self, board_reference: &str, principal: u64, doc: &str) -> Option<HeldLine> {
        self.with_principal(board_reference, principal, |ph| ph.queue.lines().iter().find(|l| l.doc == doc).cloned()).flatten()
    }

    /// How many lines stand on the document.
    fn count(&self, board_reference: &str, principal: u64, doc: &str) -> u64 {
        self.with_principal(board_reference, principal, |ph| ph.count(doc)).unwrap_or(0)
    }
}

/// Whether `delivery` delivers `want`, value for value and no more — read
/// lazily, so a board answering more than it was asked costs the comparison
/// the values asked for and one past them, never a value per position it
/// chose to deliver.
fn delivers(delivery: &Value, want: &[Cow<'_, [u8]>]) -> bool {
    let mut got = delivered_values(delivery);
    want.iter().all(|w| matches!(got.next(), Some(Ok(g)) if g == *w)) && got.next().is_none()
}

/// The session's own hand on the feed (§3c.5), as an UNSIGNED entry's `key`
/// names it: its key's fingerprint, or `bare`.
fn own_hand(session: &SessionEntry) -> String {
    match &session.facts.kind {
        SessionKind::Signed { fingerprint, .. } => fingerprint.to_hex(),
        SessionKind::Bare => "bare".to_string(),
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
    matches!(session.facts.kind, SessionKind::Signed { .. }) && row.get("key").is_none() && row.get("attest").is_some()
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
