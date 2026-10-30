//! The probe and the resend (`client.md` §3c.4, §3c.5).
//!
//! They are the hold's walk that drains a board's queue once the board
//! returns. The probe ([`Holds::probe`]) runs on the board's feed thread
//! every [`PROBE_CADENCE`](super::PROBE_CADENCE) while a line stands, and
//! there too at its daemon-running tick and at the hand-overs of
//! `resolve(send)` and `set_node_state(Running)`, because `Cmd::Tick` is
//! driven by committed writes and a poisoned, halted, stopped or
//! unreachable board commits nothing. The resend it lets run is automatic
//! at the hold's end and at reopen, under a standing session of the
//! principal's that may write — never a bare one, the keyless session that
//! reads alone (foundations §3.3 state 3), whose principal's lines stay held
//! until a session that may write stands: one read per document (`GET
//! /changes`) before its first resend, with §3c.5's three outcomes — (i)
//! nothing landed, send from the head; (ii) the in-flight burst landed, the
//! head `done kept` and its position the document's base, as an ack's is
//! (§3c.2); (iii) the site moved, no line sent and the lines faced `moved`,
//! never rebased — and a read the board did not answer decides nothing: the
//! next probe reads again. Every document is read first, and the lines of
//! those its reads let go then go out in `k` order across the documents
//! (§3c.5's order, "which keeps each document's order"), so a `copy` held
//! between two bursts on its source transcludes the source as it stood when
//! the person wrote it. Each line goes out through the hold's one reader of
//! a write's answer, as a first dial does.

use std::borrow::Cow;
use std::collections::HashSet;
use std::ops::ControlFlow;
use std::sync::atomic::{AtomicBool, Ordering};

use serde_json::Value;
use skep_client::board::{acked_at, frames, Answer, ChangesAnswer, ChangesQuery, Rejection};

use super::{awaits_act, cause, line_state, BoardSlot, Dialed, Hand, HeldState, Holds};
use crate::wire::{delivered_values, values_of};
use crate::held::{Done, HeldLine, Reason};
use crate::sessions::{SessionEntry, SessionKind};

/// The outcome of the resend's one read per document (§3c.5).
#[derive(Debug, Clone, PartialEq, Eq)]
enum ReadOutcome {
    /// No row since `base` — send from the head.
    SendFromHead,
    /// The in-flight burst landed — the head is `done kept` with this `at`.
    ///
    /// The position, where the read names one, becomes the document's base,
    /// as an ack's does (§3c.2).
    Landed { at: Option<u64> },
    /// The site moved — no line sent, the lines faced `moved`, the hands
    /// whose rows the read holds named (§3c.5), each once.
    Moved(Vec<Hand>),
    /// The board answered no page: nothing is decided.
    ///
    /// It answered a refusal (`feed_rebuilding`), the death signal, or no
    /// answer, and the next probe reads again.
    Unread,
}

/// What one `retrieve_v` at a held burst's site says of its values.
///
/// It is §3c.5's content confirm.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Site {
    /// The values read back equal: the burst stands there.
    Equal,
    /// Other values, or none (the site out of the document's bounds).
    Differs,
    /// No read can decide.
    ///
    /// It is a burst of another kind than `insert`, or a frame that names no
    /// site.
    Unconfirmable,
    /// The board did not answer the read.
    Unread,
}

/// A board's drain mark (`BoardSlot`'s `draining`), held for one drain.
///
/// It is cleared when the drain ends — however it ends, a dial that unwinds
/// included — so no board stays marked by a drain that never finished.
#[derive(Debug)]
struct Draining<'h>(&'h AtomicBool);

impl<'h> Draining<'h> {
    /// Takes the mark: `None` where a drain of the board already runs.
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
    /// Runs the probe (§3c.4), and the resend it lets run (§3c.5).
    ///
    /// It runs on the board's feed thread alone — every
    /// [`PROBE_CADENCE`](super::PROBE_CADENCE), at its daemon-running tick,
    /// and at the hand-overs of `resolve(send)` and `set_node_state(Running)`.
    /// While a line stands at a board whose own node is not stopped,
    /// `/health` is read; where the board answers and takes writes, each
    /// principal with lines resends them under a standing session of its own
    /// that may write (`SessionEntry::may_write`) — under no bare session.
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

    /// Runs the probe's dial and the resend: the body of [`Holds::probe`].
    ///
    /// It runs once per board at a time.
    fn drain(&self, board_reference: &str, slot: &BoardSlot) {
        let board = &slot.board;
        // The probe's one `/health` read (§3c.4): a board that does not answer
        // is read again at the next probe, and one whose writes are halted
        // holds every line.
        let Ok(health) = board.health() else { return };
        if self.note_health(board_reference, &health) {
            return;
        }
        // The board answers and takes writes: the hold ends. A directory no
        // session's open could establish is tried again, and each principal
        // with lines resends them under a session of its own that may write;
        // a bare one, which reads alone, sends none (foundations §3.3 state
        // 3), so a principal with no other session keeps its lines held.
        self.establish(slot);
        let principals: Vec<u64> = slot.lock().principals.iter().filter(|(_, ph)| !ph.queue.lines().is_empty()).map(|(p, _)| *p).collect();
        for principal in principals {
            let Some(session) = self.sessions.on_board(board_reference).into_iter().find(|s| s.facts.principal == principal && s.may_write()) else { continue };
            self.resume(&session);
        }
    }

    /// Runs the resend for one session (§3c.5), resumed by read.
    ///
    /// It is wire.md's resume-by-read (PUB-8.32) at the board the session
    /// stands at: each document with held lines read once, in the order its
    /// first line was held, then the lines of every document its read lets
    /// go sent in `k` order across the documents ([`Holds::send_in_order`]).
    /// The documents are gathered by one pass over the queue, each found
    /// among those already seen by a set's lookup, never a scan of them.
    fn resume(&self, session: &SessionEntry) {
        let Some(docs) = self.with_principal(&session.board_reference, session.facts.principal, |ph| {
            let mut seen = HashSet::new();
            ph.queue.lines().iter().filter(|l| seen.insert(l.doc.as_str())).map(|l| l.doc.clone()).collect::<Vec<String>>()
        }) else {
            return;
        };
        let sending: HashSet<String> = docs.into_iter().filter(|doc| self.resume_doc(session, doc)).collect();
        self.send_in_order(session, sending);
    }

    /// Resumes one document by its read (resume-by-read, §3c.5).
    ///
    /// It runs the read and its outcome — a moved document faced, a landed
    /// head kept and its position made the document's base (§3c.2) — and
    /// answers whether the document's lines go out now: a document the read
    /// sends from the head, or whose landed head leaves lines behind it;
    /// never one whose head awaits the person's act, which is read never,
    /// nor one the read left undecided.
    fn resume_doc(&self, session: &SessionEntry, doc: &str) -> bool {
        let (board_reference, principal) = (session.board_reference.as_str(), session.facts.principal);
        let Some(head) = self.head_of(board_reference, principal, doc) else { return false };
        if awaits_act(&head) {
            return false;
        }
        match self.read_outcome(session, doc, &head) {
            ReadOutcome::Unread => false,
            ReadOutcome::Moved(hands) => {
                self.mark_moved(board_reference, principal, doc);
                self.emit_held(session, doc, self.count(board_reference, principal, doc), HeldState::Moved, None, &hands);
                false
            }
            ReadOutcome::Landed { at } => {
                // The landing is the session's last write on the document, as
                // an ack is (§3c.2), so a line held on it from here reads past
                // it; a later write noted since the read stands.
                self.with_principal(board_reference, principal, |ph| {
                    if let Some(at) = at {
                        let base = ph.last_acked.entry(doc.to_string()).or_insert(at);
                        *base = (*base).max(at);
                    }
                    self.done_line(ph, head.k, Done::Kept { at });
                });
                match self.count(board_reference, principal, doc) {
                    0 => {
                        self.emit_held(session, doc, 0, HeldState::Kept, None, &[]);
                        false
                    }
                    rest => {
                        self.emit_held(session, doc, rest, HeldState::Sending, None, &[]);
                        true
                    }
                }
            }
            ReadOutcome::SendFromHead => {
                self.emit_held(session, doc, self.count(board_reference, principal, doc), HeldState::Sending, None, &[]);
                true
            }
        }
    }

    /// Reads the document once (§3c.5), to one of the outcomes.
    ///
    /// The read is `GET /changes?since=<base>&under=<doc>&drafts=true` under
    /// the session, at a page of two rows — the question is none, one, or
    /// more. At most one held burst can have landed without its ack (§7b's
    /// single writer): a `sent` head's one row is its landing where it is of
    /// the session's own hand ([`own_row`]), its `op` the head's and its site
    /// not contradicting it, or where the board lost its testimony
    /// ([`testimony_lost`]: the `poisoned` burst a restart replays, a burst
    /// whose write panicked past its commit) and the site confirms it; any
    /// other row is (iii), the hands of the rows the page holds named with
    /// it (`Holds::hands_of`) — the page the read already holds and no
    /// further read, as §3c.5 has it.
    fn read_outcome(&self, session: &SessionEntry, doc: &str, head: &HeldLine) -> ReadOutcome {
        let query = ChangesQuery { since: head.base, under: Some(doc), drafts: true, limit: Some(2) };
        let page = match session.board.changes(Some(&session.token), &query) {
            Ok(ChangesAnswer::Page(page)) => page,
            // `base` aged below the floor: the arrangement alone decides.
            Ok(ChangesAnswer::HistoryReclaimed { .. }) => return self.reclaimed_outcome(session, doc, head),
            // A page of two rows too large to serve holds two rows or more,
            // none of them read: no hand to name.
            Ok(ChangesAnswer::TooLarge { .. }) => return ReadOutcome::Moved(Vec::new()),
            Ok(_) | Err(_) => return ReadOutcome::Unread,
        };
        let moved = || ReadOutcome::Moved(self.hands_of(session, &page.changes));
        let [row] = page.changes.as_slice() else {
            return if page.changes.is_empty() { ReadOutcome::SendFromHead } else { moved() };
        };
        if !head.reason.sent || page.more {
            return moved();
        }
        let landed = ReadOutcome::Landed { at: row["at"].as_u64() };
        if own_row(session, row) && row["op"].as_str() == head.frame["op"].as_str() {
            // A kind the site read cannot confirm trusts the op-and-hand match.
            return match self.site(session, doc, head) {
                Site::Equal | Site::Unconfirmable => landed,
                Site::Differs => moved(),
                Site::Unread => ReadOutcome::Unread,
            };
        }
        // A row whose testimony the board lost — `docs`, `key` and `op` the
        // reserved null (wire.md §`/changes`): a commit whose recorded row
        // the write path never wrote — re-derived from the journal at the
        // board's open, as a `poisoned` burst's landing at the restart is
        // (§3c.2), or written bare by the write path's catch of a panic past
        // the commit, as a burst answered `internal_panic` may be
        // (`operations.md` §4 row 34). The feed cannot say whose it is, so
        // the arrangement alone decides, as on `history_reclaimed` (§3c.5),
        // and decisively: an `insert` whose values read back equal is (ii);
        // a kind the site read cannot confirm faces the person (iii).
        if testimony_lost(row) {
            return match self.site(session, doc, head) {
                Site::Equal => landed,
                Site::Differs | Site::Unconfirmable => moved(),
                Site::Unread => ReadOutcome::Unread,
            };
        }
        moved()
    }

    /// Returns the outcome of a `history_reclaimed` on the read (§3c.5).
    ///
    /// The arrangement alone decides — a `sent` head's values read back equal
    /// at its site is (ii); any difference, a kind no read confirms, or a
    /// head never sent is (iii), no row read and so no hand to name.
    fn reclaimed_outcome(&self, session: &SessionEntry, doc: &str, head: &HeldLine) -> ReadOutcome {
        if !head.reason.sent {
            return ReadOutcome::Moved(Vec::new());
        }
        match self.site(session, doc, head) {
            Site::Equal => ReadOutcome::Landed { at: None },
            Site::Differs | Site::Unconfirmable => ReadOutcome::Moved(Vec::new()),
            Site::Unread => ReadOutcome::Unread,
        }
    }

    /// Confirms an `insert`'s site by its content (§3c.5).
    ///
    /// It makes one `retrieve_v` at the site, as wide as the values its frame
    /// spells, the delivery read back as values and held to them.
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

    /// Sends the standing lines of `docs` in `k` order: §3c.5's order.
    ///
    /// §3c.5 has "lines in `k` order across the board's documents, which
    /// keeps each document's order": each line is a normal `op` under the
    /// session — a document stopping at a line that awaits the person's act
    /// or is not taken, the others going on. Every turn settles its line (an
    /// ack, the one `Continue`, takes it out of the queue) or drops its
    /// document, so the walk ends; a turn finds its line by one set lookup
    /// per line it passes, so the walk's work is the queue's lines — a hold
    /// adds none past `held::MAX_HELD_LINES` — times its turns.
    fn send_in_order(&self, session: &SessionEntry, mut docs: HashSet<String>) {
        let (board_reference, principal) = (session.board_reference.as_str(), session.facts.principal);
        let next = |docs: &HashSet<String>| self.with_principal(board_reference, principal, |ph| ph.queue.lines().iter().find(|l| docs.contains(&l.doc)).cloned()).flatten();
        while let Some(line) = next(&docs) {
            if awaits_act(&line) || self.send_line(session, &line).is_break() {
                docs.remove(&line.doc);
            }
        }
    }

    /// Sends one held line as the `op` it is, under the session that stands.
    ///
    /// Its attest is composed now (§3c.2), and the line settled by what the
    /// dial answered: an ack `done kept`; a hold-class answer or a refused
    /// run re-marked and faced; a reissue-class answer counted against the
    /// line and reissued at the next probe, so its third `durability` holds
    /// it; a refusal the table holds nowhere left standing for the next
    /// probe, never `done`; the death signal left to the caller that ends the
    /// session — the session that stands resends after its read. `Continue`
    /// where the line is settled and sending goes on, `Break` where the
    /// line's document stops at it.
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
                self.emit_held(session, &line.doc, rest, if rest == 0 { HeldState::Kept } else { HeldState::Sending }, None, &[]);
                ControlFlow::Continue(())
            }
            Dialed::Held { reason, .. } => {
                let state = line_state(&reason);
                let said = reason.cause.clone();
                self.with_principal(board_reference, principal, |ph| self.remark_line(ph, line.k, reason));
                self.emit_held(session, &line.doc, self.count(board_reference, principal, &line.doc), state, Some(&said), &[]);
                ControlFlow::Break(())
            }
            Dialed::Reissue { kind, refusal } => {
                // The rider's count (§3c.4), per line across its probes: the
                // third `durability` holds it.
                self.with_principal(board_reference, principal, |ph| ph.reissues.entry(line.k).or_default().note(kind));
                self.say(format_args!("line {} on {} was not taken ({refusal}); it is sent again at the next probe", line.k, line.doc));
                ControlFlow::Break(())
            }
            Dialed::Faced(refusal) => {
                self.say(format_args!("line {} on {} was not taken ({refusal}); it is sent again at the next probe", line.k, line.doc));
                ControlFlow::Break(())
            }
            Dialed::Died => ControlFlow::Break(()),
        }
    }

    /// Marks every line of a moved document: `cause: moved`, never rebased.
    ///
    /// No line is sent. The exact rebase by identity — the burst's anchor
    /// re-found and the delta placed after it — stays named as open (§3c.5,
    /// the record §5 Q3): it needs an anchor the page's frame does not carry
    /// today, and a silent inexact rebase could put words where the person
    /// did not. The hands whose rows moved it ride the `held` event's
    /// `moved` state (§3c.5; §4b.2), the data of the face's three forms. The
    /// page's half — what the burst machine does at a `held` answer, how it
    /// re-projects the held frames at a launch, the moved document's face —
    /// is the frontend's and in neither repository at this pin (unverified
    /// here, the record §7 item 4; stated from assisted-frontend §7b).
    fn mark_moved(&self, board_reference: &str, principal: u64, doc: &str) {
        self.with_principal(board_reference, principal, |ph| {
            let ks: Vec<u64> = ph.queue.lines().iter().filter(|l| l.doc == doc).map(|l| l.k).collect();
            for k in ks {
                self.remark_line(ph, k, Reason::of(cause::MOVED, false));
            }
        });
    }

    /// Resolves one line `done`, the file compacting where the queue empties.
    ///
    /// The `done` is [`Done::Kept`] or [`Done::Dropped`].
    fn done(&self, board_reference: &str, principal: u64, k: u64, done: Done) {
        self.with_principal(board_reference, principal, |ph| self.done_line(ph, k, done));
    }

    /// Returns the document's head: its first standing line in `k` order.
    fn head_of(&self, board_reference: &str, principal: u64, doc: &str) -> Option<HeldLine> {
        self.with_principal(board_reference, principal, |ph| ph.queue.lines().iter().find(|l| l.doc == doc).cloned()).flatten()
    }

    /// Returns how many lines stand on the document.
    fn count(&self, board_reference: &str, principal: u64, doc: &str) -> u64 {
        self.with_principal(board_reference, principal, |ph| ph.count(doc)).unwrap_or(0)
    }
}

/// Returns whether `delivery` delivers `want`, value for value and no more.
///
/// It reads lazily, so a board answering more than it was asked costs the
/// comparison the values asked for and one past them, never a value per
/// position it chose to deliver.
fn delivers(delivery: &Value, want: &[Cow<'_, [u8]>]) -> bool {
    let mut got = delivered_values(delivery);
    want.iter().all(|w| matches!(got.next(), Some(Ok(g)) if g == *w)) && got.next().is_none()
}

/// Returns whether a `/changes` row is of the session's own hand (§3c.5).
///
/// The hand is its key's. An unsigned entry carries `key`, the key's
/// fingerprint. A signed entry carries no `key` (wire.md §`/changes`: `key`
/// is present iff the entry is unsigned) and `attest` in its place, and is
/// the session's own — §3c.5's "its `key` the session's fingerprint" reads
/// the unsigned form alone. The shell attests every `insert` at a board
/// with `H.1` ("Attach when in doubt"), but the daemon keeps an attest on a
/// publish-class write alone and drops it on a draft's (wire.md §The two
/// attestation codes), so a burst's row is the unsigned form today, its
/// `key` the signing key's fingerprint; the signed form stands for a row
/// the wire's rule admits. The read's other two guards (`op` equal, the
/// content confirmed) stand beside this one, so another key's signed row
/// still reads as (iii). A bare session has no hand of its own: it writes
/// nothing (`SessionEntry::may_write`) and the resend reads under no bare
/// session, so every row is another's to one.
fn own_row(session: &SessionEntry, row: &Value) -> bool {
    let SessionKind::Signed { fingerprint, .. } = &session.facts.kind else { return false };
    row["key"].as_str() == Some(fingerprint.to_hex().as_str()) || (row.get("key").is_none() && row.get("attest").is_some())
}

/// Whether a `/changes` row's testimony is lost.
///
/// Its `docs`, `key` and `op` are the reserved null (wire.md §`/changes`:
/// "`null` only for lost metadata"): a commit whose testimony the write path
/// never recorded — re-derived from the journal at the board's open, or
/// written bare by the write path's catch of a panic past the commit
/// (`operations.md` §4 row 34) — classified to its documents, its hand and
/// kind the feed cannot name. A signed row has no `key` but names its `op`;
/// a bare session's row says `bare`; neither is this.
fn testimony_lost(row: &Value) -> bool {
    row["docs"].is_null() && row["key"].is_null() && row["op"].is_null()
}
