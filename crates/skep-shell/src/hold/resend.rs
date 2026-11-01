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
//! /changes`) before its first resend, which answers one question of the
//! document's head — did its own write land? — and nothing more: (i)
//! nothing of it landed, send from the head, or, the head's resends having
//! lost their answer [`MAX_LOST_ANSWERS`] times, hand it to the person as a
//! refused run (`answers_lost`), dialed never again until the person sends
//! it; (ii) the in-flight burst landed, the head `done kept` and its
//! position the document's base, as an ack's is (§3c.2). A head no dial of
//! which left is not read at all: it goes from the head. A row that is not
//! the head's own landing is no verdict — the person's own later write, a
//! sibling's, another hand's — and the head goes from the head; and a read
//! the board did not answer decides nothing: the next probe reads again.
//! Whether the DOCUMENT MOVED is the board's to say, (iii), by one route:
//! a line it refuses as typed against an older state of its document
//! (`arrangement_moved`, the frame's `as_of` below the arrangement's last
//! change) faces the document `moved`, never rebased, the verdict kept on
//! the line and the hands read once since the line's typed state; the read
//! judges no move. Every document is read first, and the lines of those its
//! reads let go then go out in `k` order across the documents (§3c.5's
//! order, "which keeps each document's order"), so a `copy` held between
//! two bursts on its source transcludes the source as it stood when the
//! person wrote it. Each line goes out through the hold's one reader of a
//! write's answer, as a first dial does. A resend marks its line as one
//! that may have landed before it dials, synced, and the line stays so
//! through every resend short of its ack and through a move, so its next
//! read takes a landing it finds as the line's own — after a crash or a
//! refused write between a dial and its answer too (§3c.2's `sent`).

use std::borrow::Cow;
use std::collections::HashSet;
use std::ops::ControlFlow;
use std::sync::atomic::{AtomicBool, Ordering};

use serde_json::{json, Value};
use skep_client::board::{acked_at, frames, Answer, ChangesAnswer, ChangesQuery, Rejection};

use super::{awaits_act, cause, is_lost_answer, line_state, BoardSlot, Dialed, HeldState, Holds, MAX_LOST_ANSWERS};
use crate::held::{Done, HeldLine, Reason};
use crate::refusal::{Name, Refusal};
use crate::sessions::{SessionEntry, SessionKind};
use crate::wire::{delivered_values, values_of};

/// The outcome of the resend's one read per document (§3c.5).
///
/// The read answers whether the document's head's own write landed, and
/// nothing more: whether the document moved is the board's verdict on the
/// send ([`Holds::send_line`]'s moved arm), never the read's.
#[derive(Debug, Clone, PartialEq, Eq)]
enum ReadOutcome {
    /// No row since `base` is the head's own landing — send from the head.
    ///
    /// Every row read is no verdict: the person's own later write, a
    /// sibling's, another hand's. The board judges the send's typed state.
    SendFromHead,
    /// The in-flight burst landed — the head is `done kept` with this `at`.
    ///
    /// The position, where the read names one, becomes the document's base,
    /// as an ack's does (§3c.2), and joins the board's acked positions.
    Landed { at: Option<u64> },
    /// The board answered no page: nothing is decided.
    ///
    /// It answered a refusal (`feed_rebuilding`), the death signal, or no
    /// answer — or the site read the landing needed went unanswered — and
    /// the next probe reads again.
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
    /// It runs the read and its outcome — a landed head kept, its position
    /// made the document's base (§3c.2) and entered in the board's acked
    /// positions — and answers whether the document's lines go out now: a
    /// document the read sends from the head, or whose landed head leaves
    /// lines behind it; never one whose head awaits the person's act, which
    /// is read never, nor one the read left undecided, nor one whose head it
    /// hands to the person ([`Holds::hand_over`]). A head no dial of which
    /// left (`sent` false) is not read at all: nothing of it can stand on the
    /// board, so it goes from the head.
    fn resume_doc(&self, session: &SessionEntry, doc: &str) -> bool {
        let (board_reference, principal) = (session.board_reference.as_str(), session.facts.principal);
        let Some(head) = self.head_of(board_reference, principal, doc) else { return false };
        if awaits_act(&head) {
            return false;
        }
        let outcome = if head.reason.sent { self.read_outcome(session, doc, &head) } else { ReadOutcome::SendFromHead };
        match outcome {
            ReadOutcome::Unread => false,
            ReadOutcome::Landed { at } => {
                // The landing is noted as the session's ack is (§3c.2, §3c.5):
                // a line held on the document from here reads past it, and no
                // read takes its row for another line's landing; a later write
                // noted since the read stands.
                {
                    let mut board_hold = self.lock(board_reference);
                    if let Some(at) = at {
                        board_hold.acked.insert(at);
                    }
                    if let Some(ph) = board_hold.principals.get_mut(&principal) {
                        if let Some(at) = at {
                            ph.note_position(doc, at);
                        }
                        self.done_line(ph, head.k, Done::Kept { at });
                    }
                }
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
                // Nothing of the head has landed: past its lost answers'
                // bound it is the person's, dialed never again (§3c.4; skep
                // #608).
                let lost = self.with_principal(board_reference, principal, |ph| ph.reissues.get(&head.k).map_or(0, |given| given.lost)).unwrap_or(0);
                if lost >= MAX_LOST_ANSWERS {
                    self.hand_over(session, &head, lost);
                    return false;
                }
                self.emit_held(session, doc, self.count(board_reference, principal, doc), HeldState::Sending, None, &[]);
                true
            }
        }
    }

    /// Reads the document once (§3c.5), to one of the outcomes.
    ///
    /// The read is `GET /changes?since=<base>&under=<doc>&drafts=true` under
    /// the session, the rows since `base` IN ORDER — a page whose `more`
    /// stands with no landing found read on from its `last`, at the route's
    /// default page and, where a page is too large to serve, at the limit
    /// that `fits`, as the feed's reads are — and it asks one question of a
    /// `sent` head: did its own write land? At most one held burst can have
    /// landed without its ack (§7b's single writer, the head), so THE FIRST
    /// ROW that is the head's landing is its landing, whatever rows follow
    /// it — the lines behind the head are nobody's to judge here: each is
    /// read as a head in its turn, and the board judges every send's typed
    /// state. A row is the landing where it is of the session's own hand
    /// ([`own_row`]), its `op` the head's, and the head's site does not
    /// contradict it — or where the board lost its testimony
    /// ([`testimony_lost`]: the `poisoned` burst a restart replays, a burst
    /// whose write panicked past its commit) and the site confirms it — AND
    /// it stands at no position this shell acked ([`BoardHold::acked`]): a
    /// row of the same key and kind at an acked position is a sibling's
    /// write through this shell, answered, never the lost landing; a row of
    /// the same key not through this shell — the `skep` command's — the set
    /// cannot tell apart, named as the residue. The site ([`Holds::site`])
    /// is the document's now, read once for the first row that asks for it:
    /// an `insert` whose values stand at its site landed; one whose values do
    /// not is no landing of any row, so the head goes from the head at once;
    /// a kind no read confirms trusts the own hand and the op alone, and
    /// trusts a row whose hand is lost not at all. Every other row — the
    /// person's own later write of another kind, a sibling's, another hand's
    /// — is no verdict: whether the document moved is the board's
    /// (`arrangement_moved`, [`Holds::send_line`]), not this read's.
    fn read_outcome(&self, session: &SessionEntry, doc: &str, head: &HeldLine) -> ReadOutcome {
        let board_reference = session.board_reference.as_str();
        let mut query = ChangesQuery { since: head.base, under: Some(doc), drafts: true, limit: None };
        // The site is the document's, not a row's: read once, for the first
        // row that asks.
        let mut site = None;
        loop {
            let page = match session.board.changes(Some(&session.token), &query) {
                Ok(ChangesAnswer::Page(page)) => page,
                // `base` lies below the feed's floor — a hole in the feed's
                // files (wire.md §`/changes`): the arrangement alone decides.
                Ok(ChangesAnswer::HistoryReclaimed { .. }) => return self.reclaimed_outcome(session, doc, head),
                // A page past the board's budget is re-asked at the limit that
                // fits, as `feed::page_from` re-asks it; the client refuses a
                // `fits` that does not shrink the page, so the re-asks end.
                Ok(ChangesAnswer::TooLarge { fits }) => {
                    query.limit = Some(fits);
                    continue;
                }
                Ok(_) | Err(_) => return ReadOutcome::Unread,
            };
            for row in &page.changes {
                let at = row["at"].as_u64();
                // A write this shell was answered for is never the lost landing.
                if at.is_some_and(|at| self.acked(board_reference, at)) {
                    continue;
                }
                let own = own_row(session, row) && row["op"].as_str() == head.frame["op"].as_str();
                if !own && !testimony_lost(row) {
                    continue;
                }
                let landed = match *site.get_or_insert_with(|| self.site(session, doc, head)) {
                    Site::Equal => true,
                    // A kind the site read cannot confirm trusts the op-and-hand
                    // match; a row whose hand the board lost has none to trust.
                    Site::Unconfirmable => own,
                    // The head's values do not stand at its site: no row is its
                    // landing, and the board judges the send's typed state.
                    Site::Differs => return ReadOutcome::SendFromHead,
                    Site::Unread => return ReadOutcome::Unread,
                };
                if landed {
                    return ReadOutcome::Landed { at };
                }
            }
            if !page.more {
                return ReadOutcome::SendFromHead;
            }
            query.since = page.last;
            query.limit = None;
        }
    }

    /// Returns the outcome of a `history_reclaimed` on the read (§3c.5).
    ///
    /// No row can be read, so the arrangement alone decides the one
    /// question: a `sent` head's values read back equal at its site is (ii),
    /// kept with no position to name; any difference, or a kind no read
    /// confirms, is no landing found, and the head goes from the head — the
    /// board judging its typed state (`arrangement_moved`), as it judges
    /// every send; a site read the board does not answer decides nothing.
    fn reclaimed_outcome(&self, session: &SessionEntry, doc: &str, head: &HeldLine) -> ReadOutcome {
        match self.site(session, doc, head) {
            Site::Equal => ReadOutcome::Landed { at: None },
            Site::Differs | Site::Unconfirmable => ReadOutcome::SendFromHead,
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
    /// Its attest is composed now (§3c.2), the line marked as one that may
    /// have landed before the dial leaves, and the line settled by what the
    /// dial answered: an ack `done kept`; the line refused as typed against
    /// an older state of its document, the document faced `moved`
    /// ([`Holds::mark_moved`]) — the one route to that face — the board's
    /// verdict kept on the line and the hands whose rows moved it named; a
    /// hold-class answer or a refused run
    /// re-marked and faced, the line keeping its `sent` — a resend that never
    /// left, or one the board refused, says nothing of an earlier dial's write
    /// (§3c.2) — and a lost answer counted against the line
    /// ([`MAX_LOST_ANSWERS`]); a reissue-class answer counted against the
    /// line and reissued at the next probe, so its third `durability` holds
    /// it; a refusal the table holds nowhere left standing for the next
    /// probe, never `done`; the death signal left to the caller that ends the
    /// session — the session that stands resends after its read. `Continue`
    /// where the line is settled and sending goes on, `Break` where the
    /// line's document stops at it.
    fn send_line(&self, session: &SessionEntry, line: &HeldLine) -> ControlFlow<()> {
        let (board_reference, principal) = (session.board_reference.as_str(), session.facts.principal);
        let given = self.with_principal(board_reference, principal, |ph| ph.reissues.get(&line.k).copied()).flatten().unwrap_or_default();
        // The line is marked as one that may have landed before its dial
        // leaves (§3c.2's `sent`), synced, so a crash or a refused write
        // between the dial and its answer never leaves a write that may have
        // landed read as one never sent; a line marked so already writes
        // nothing. The mark stands whatever the dial answers, a connection
        // never made among them, and a copy the device refuses is said and
        // the dial made all the same. An attest that could not be composed
        // dials nothing and marks nothing: the line keeps its own `sent`.
        let (dialed, sent) = match self.attest_where_owed(session, &line.frame) {
            Ok(frame) => {
                self.with_principal(board_reference, principal, |ph| self.remark_line(ph, line.k, Reason { sent: true, ..line.reason.clone() }));
                (self.dial(session, &frame, given), true)
            }
            Err(why) => (Dialed::from(why), line.reason.sent),
        };
        match dialed {
            Dialed::Acked(ack) => {
                self.note_ack(session, &line.frame, &ack);
                self.done(board_reference, principal, line.k, Done::Kept { at: acked_at(&ack) });
                let rest = self.count(board_reference, principal, &line.doc);
                self.emit_held(session, &line.doc, rest, if rest == 0 { HeldState::Kept } else { HeldState::Sending }, None, &[]);
                ControlFlow::Continue(())
            }
            Dialed::Held { reason, .. } if reason.cause == cause::MOVED => {
                // The board refused the line as typed against an older state
                // of its document: the document is faced moved — the board's
                // verdict the one judge of a move — each line keeping its own
                // `sent`, the line refused keeping the verdict, and named by
                // the hands whose rows moved it since the line's typed state
                // (§3c.5).
                let hands = self.hands_since_typed_state(session, &line.doc, &reason);
                self.mark_moved(board_reference, principal, &line.doc, reason.refusal.map(|verdict| (line.k, verdict)));
                self.emit_held(session, &line.doc, self.count(board_reference, principal, &line.doc), HeldState::Moved, None, &hands);
                ControlFlow::Break(())
            }
            Dialed::Held { reason, .. } => {
                let state = line_state(&reason);
                let said = reason.cause.clone();
                // A lost answer counts one try against the line
                // (MAX_LOST_ANSWERS), read off this dial's own answer; the
                // read decides at the next probe whether it landed.
                let lost = is_lost_answer(&reason);
                // The line keeps its `sent`, the mark made before the dial
                // included: a resend that never left, or one the board
                // refused, says nothing of an earlier dial's write.
                let reason = Reason { sent: reason.sent || sent, ..reason };
                self.with_principal(board_reference, principal, |ph| {
                    if lost {
                        ph.reissues.entry(line.k).or_default().lost += 1;
                    }
                    self.remark_line(ph, line.k, reason);
                });
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

    /// Hands a line whose resends lost their answer to the person (§3c.4).
    ///
    /// Its lost answers have reached [`MAX_LOST_ANSWERS`] and the read found
    /// no landing: the line is re-marked a refused run under the shell's
    /// `answers_lost`, its `sent` kept — so the person's `send` reads before
    /// it dials, and a landing the read finds then is kept (§3c.5) — and the
    /// lines behind it wait with it, as behind any refused run, until
    /// `resolve` sends or drops it. It is said once in the shell's own
    /// window, and on the `held` event as `refused` (skep #608).
    fn hand_over(&self, session: &SessionEntry, head: &HeldLine, lost: u32) {
        let (board_reference, principal) = (session.board_reference.as_str(), session.facts.principal);
        let refusal = Refusal::shell(Name::ANSWERS_LOST, json!({"tries": lost})).to_value();
        // The count reaches its bound only at a lost answer, which marks the
        // line `sent`; the line keeps whatever it carries.
        let reason = Reason { sent: head.reason.sent, ..Reason::refused(Name::ANSWERS_LOST.as_str(), refusal) };
        self.with_principal(board_reference, principal, |ph| self.remark_line(ph, head.k, reason));
        self.say(format_args!("line {} on {}: {lost} resends lost their answer; it is handed to the person, who may send it again or drop it", head.k, head.doc));
        self.emit_held(session, &head.doc, self.count(board_reference, principal, &head.doc), HeldState::Refused, Some(Name::ANSWERS_LOST.as_str()), &[]);
    }

    /// Marks every line of a moved document: `cause: moved`, never rebased.
    ///
    /// It is reached from the board's verdict alone — a resend refused as
    /// typed against an older state of its document ([`Holds::send_line`]);
    /// a first dial so refused is held `moved` by `Holds::hold` — never from
    /// the read, which judges no move. No line is sent. Each keeps its own
    /// `sent`, so a line that may have landed reads before it is sent again
    /// (§3c.2). `judged` is the line the board refused, with the board's
    /// verdict, kept as its refusal — the state the line was typed against
    /// and the document's current one; a moved reason carries one
    /// (`Dialed::refused`). The exact rebase by identity — the burst's anchor
    /// re-found and the delta placed after it — stays named as open (§3c.5,
    /// the record §5 Q3): it needs an anchor the page's frame does not carry
    /// today, and a silent inexact rebase could put words where the person
    /// did not. The hands whose rows moved it ride the `held` event's
    /// `moved` state (§3c.5; §4b.2), the data of the face's three forms. The
    /// page's half — what the burst machine does at a `held` answer, how it
    /// re-projects the held frames at a launch, the moved document's face —
    /// is the frontend's and in neither repository at this pin (unverified
    /// here, the record §7 item 4; stated from assisted-frontend §7b).
    fn mark_moved(&self, board_reference: &str, principal: u64, doc: &str, judged: Option<(u64, Value)>) {
        self.with_principal(board_reference, principal, |ph| {
            let marks: Vec<(u64, bool)> = ph.queue.lines().iter().filter(|l| l.doc == doc).map(|l| (l.k, l.reason.sent)).collect();
            for (k, sent) in marks {
                let refusal = judged.as_ref().filter(|(judged, _)| *judged == k).map(|(_, verdict)| verdict.clone());
                self.remark_line(ph, k, Reason { refusal, ..Reason::of(cause::MOVED, sent) });
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
/// the wire's rule admits. The read's other guards (`op` equal, the content
/// confirmed, the position not one this shell acked) stand beside this one,
/// so another key's signed row of another kind is no landing. A bare
/// session has no hand of its own: it writes nothing
/// (`SessionEntry::may_write`) and the resend reads under no bare session,
/// so every row is another's to one.
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
