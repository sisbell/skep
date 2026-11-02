//! The resend walk over a fake board (§3c.5).
//!
//! The suite checks the read's table, every answer the read can meet
//! against every answer its site read can — the read's one question being
//! whether the head's own write landed: no row (send from the head), an own
//! row of the head's kind its site does not contradict (the head `done
//! kept`, nothing re-sent, whatever rows follow it), a lost testimony and
//! `history_reclaimed` kept where the site confirms them alone, a foreign
//! row, another kind of the own hand, and a site that differs (no verdict:
//! sent from the head, never faced `moved` by the read), a head never sent
//! going from the head unread, a page too large re-asked at the limit that
//! fits, a read or a site the board does not answer — the death signal among
//! its answers — deciding nothing, and a delivery past the values asked
//! differing — with the narrative cells beside it; the first own row the
//! landing with a later row of anyone's after it, and a landing past the
//! first page found by reading on; a sibling's row of the head's kind at a
//! position this shell acked skipped, the head sent, and a sibling's ack
//! during the dial leaving the base the line is held at where it was read,
//! before the dial; the person's own later write on the document — a link,
//! this tab's or a sibling's, or a write of another kind not through this
//! shell — leaving a held line holding, never `moved`, and a line behind a
//! landing kept with no position sent, never `moved`; the order, the lines
//! sent in `k` order across the documents; the own hand on a read; a refusal
//! the table holds nowhere handing a resent line to the person at once, and
//! the death signal leaving one standing; a resend answered `500
//! internal_panic` marking its line `sent: true`, its landing then kept by
//! the read; a line that may have landed
//! staying so through resends that never left, over a head record that
//! cannot be read or a connection never made, its landing kept by the read;
//! a second window's burst resent from memory; every principal's lines
//! resent by one probe, a bare session's line resent by none until a session
//! of its principal's that may write stands, and a probe with no line
//! standing dialing nothing; one drain per board at a time, and a drain that
//! unwinds leaving the board free to drain again; the board's refusal of a
//! resend as typed against an older state — the one route to the moved face
//! — facing its own document alone, moved, the verdict on the line it
//! refused, each line keeping its own `sent` and the hands named off the
//! rows since the typed state; THE SHIFT at a resend (skep #442): a `sent`
//! head whose own row stands and whose site confirms kept by the read and
//! shifted never; a resent line refused stale shifted through the change by
//! one image read, the shifted frame on the line before the shifted dial,
//! and kept; and the shifts and the lost answers meeting the one deadline,
//! the person's send starting the clock afresh; a resend marking its line
//! `sent` on disk before it dials, and a line acked whose `done` the device
//! refused relaunching so and kept by the read; the own node stopped,
//! `writes.halted` and a third `durability` holding a burst over time, a
//! reused ordinal's reissues counted afresh; every line's read starting past
//! the person's own write — a line held behind a landing or an ack read from
//! its position, and a line held after a landing the read found reading
//! past it; and THE DEADLINE (skep #716, #720, #722): a line handed to the
//! person two minutes from its first failed send, whatever the failure — its
//! resends' lost answers of every way, the first dial's own, a third
//! `durability`, a `write_busy` past its reissue — the clock run from the
//! first failure and never the last, a connection never made starting none,
//! the deadline the two minutes it is pinned to; its landing kept where the
//! read finds one, before the hand-over or at the person's `send`; and
//! "sent again" said once per change of the failure. And THE PERSON's `send`
//! ON A MOVED DOCUMENT (skep #757): a document moved again after it naming
//! only the hands since, the rows the person acknowledged named no more, and
//! a line leaving the queue taking the acknowledgment with it, so a later
//! line of its ordinal names every hand; an anchored line, its base raised
//! past the person's own other write of its kind — which a read from the
//! old base takes for its landing — sent, shifted and kept; and a first
//! moved face naming every hand since the typed state though the line's
//! base stands past it. And THE HEAD THAT WILL NOT READ (skep #725, #727):
//! one head read per probe before any document, the documents held
//! `head_unreadable` skipped unread while it fails; the `held` event and the
//! head's `Talk` line said once per change of state, not per probe; at the
//! head's first read the pending lines joining the board's file and sent in
//! `k` order, and renumbered — `held` said again — where the file already
//! holds lines.

use super::*;

/// Checks outcome (i): no row since `base` sends the burst from the head.
///
/// The held burst is sent and acked, the line resolved, the document's
/// state `kept`.
#[test]
fn outcome_i_no_row_sends_from_the_head() {
    let g = ground();
    g.hold(&insert(DOC, json!(["hello"]), g.fake.head()), "unreachable", false);
    g.holds.probe("b-1");
    assert_eq!(g.fake.sends(), 1, "the head is sent once");
    assert_eq!(g.fake.sends.lock().unwrap()[0]["op"], "insert");
    assert!(g.lines().is_empty(), "the line is kept and gone");
    assert!(g.states().contains(&"kept".to_string()));
}

/// Checks outcome (ii): a landed burst is kept, not re-sent.
///
/// The in-flight burst (its line `sent: true`) landed — one row of the
/// session's own hand, consistent, its five values read back equal at the
/// site — so the head is `done kept` and nothing is re-sent (the mutant that
/// resends the head; the mutant that compares the frame's one string with
/// one position's value faces the person's own text `moved`).
#[test]
fn outcome_ii_a_landed_burst_is_kept_not_resent() {
    let g = ground();
    *g.fake.text.lock().unwrap() = "hello".into();
    *g.fake.rows.lock().unwrap() = vec![json!({"at": 77, "op": "insert", "key": g.own_key(), "docs": [DOC]})];
    g.hold(&insert(DOC, json!(["hello"]), g.fake.head()), "unreachable", true);
    g.holds.probe("b-1");
    assert_eq!(g.fake.sends(), 0, "the landed head is NOT re-sent: {:?}", g.fake.sends.lock().unwrap());
    assert!(g.lines().is_empty(), "the line is done kept");
    let states = g.states();
    assert!(states.contains(&"kept".to_string()) && !states.contains(&"moved".to_string()), "{states:?}");
}

/// Checks that the resend sends its lines in `k` order across the documents.
///
/// It is §3c.5's order, "lines in `k` order across the board's documents,
/// which keeps each document's order": three lines held on two documents —
/// one on `DOC`, one on `OTHER`, one more on `DOC` — go out as they were
/// held, so a `copy` held between two bursts on its source transcludes the
/// source as the person wrote it (the mutant that sends each document's
/// whole run in turn sends the second `DOC` line before the `OTHER` one,
/// and the copy lands the wrong text with no refusal to say so).
#[test]
fn the_resend_sends_its_lines_in_k_order_across_the_documents() {
    let g = ground();
    for (doc, value) in [(DOC, "a"), (OTHER, "b"), (DOC, "c")] {
        g.hold(&insert(doc, json!([value]), g.fake.head()), "unreachable", false);
    }
    g.holds.probe("b-1");
    let sent: Vec<String> = g.fake.sends.lock().unwrap().iter().map(|f| format!("{} {}", f["doc"].as_str().unwrap_or("?"), f["values"][0].as_str().unwrap_or("?"))).collect();
    assert_eq!(sent, [format!("{DOC} a"), format!("{OTHER} b"), format!("{DOC} c")], "the lines in `k` order");
    assert!(g.lines().is_empty(), "each kept");
}

/// Checks that a death signal at a resend's dial leaves its line standing.
///
/// The death is neither held nor faced (§3c.4): the session's end is the
/// caller's that meets it, and the line waits for the session that stands —
/// never `done`, never re-marked; the next probe, the token answering
/// again, sends and keeps it (the mutant that settles the line at the death
/// marks the person's text kept although it never landed).
#[test]
fn a_death_signal_at_a_resend_leaves_its_line_standing() {
    let g = ground();
    g.hold(&insert(DOC, json!(["hello"]), g.fake.head()), "unreachable", false);
    g.fake.op_closed.store(true, Ordering::SeqCst);
    g.holds.probe("b-1");
    assert_eq!(g.fake.sends(), 1, "the line was dialed");
    assert_eq!(g.lines()[0]["cause"], "unreachable", "and stands as it was");
    assert_eq!(g.states(), ["holding", "sending"], "never kept, never faced");
    g.fake.op_closed.store(false, Ordering::SeqCst);
    g.holds.probe("b-1");
    assert_eq!(g.fake.sends(), 2, "the next probe sends it again");
    assert!(g.lines().is_empty() && g.states().contains(&"kept".to_string()));
}

/// Checks that a resend answered `internal_panic` reads before it resends.
///
/// A resend answered `500 internal_panic` marks its line as one that may
/// have landed (§3c.2): a line held `sent: false` is sent at the probe, the
/// board's handler panics — its write perhaps committed — and the line is
/// re-marked `sent: true`, cause `unreachable`; the next probe's read finds
/// the row whose testimony the board lost, the line's values standing at
/// its site, and keeps the line with nothing sent again (the mutant that
/// faces the resend's 500 leaves the line `sent: false`, and the next read
/// faces the person's own text `moved`).
#[test]
fn a_resend_answered_internal_panic_reads_before_it_sends_again() {
    let g = ground();
    g.hold(&insert(DOC, json!(["hello"]), g.fake.head()), "unreachable", false);
    g.fake.op_refused.next(1, (500, json!({"error": "internal_panic"})));
    g.holds.probe("b-1");
    let lines = g.lines();
    assert_eq!((g.fake.sends(), lines[0]["cause"].as_str(), lines[0]["sent"].as_bool()), (1, Some("unreachable"), Some(true)), "{lines:?}");
    *g.fake.rows.lock().unwrap() = vec![lost_row()];
    *g.fake.text.lock().unwrap() = "hello".into();
    g.holds.probe("b-1");
    assert_eq!(g.fake.sends(), 1, "the landed line is not sent again");
    let states = g.states();
    assert!(g.lines().is_empty() && states.contains(&"kept".to_string()) && !states.contains(&"moved".to_string()), "{states:?}");
}

/// Checks that a probe resends every principal's lines (§3c.4).
///
/// Two principals hold a line each at one board — two writers' sessions,
/// each under its own key — and one probe sends both, each under its own
/// session (the mutant that drains its first principal alone leaves the
/// second's text unsent, and every later burst of that principal behind
/// it).
#[test]
fn a_probe_resends_every_principals_lines() {
    let g = ground();
    let facts = writer_facts_as(&g.store, 2, "1.0.2");
    let open = Open { token: Token::parse(&"8e".repeat(16)).unwrap(), facts, opened_at: 0 };
    let board = BoardEntry { reference: g.session.board_reference.clone(), board: Arc::clone(&g.session.board) };
    let second = g.holds.sessions.register(&board, open, &mut NoSupplements);
    g.holds.open_session(&second);
    g.hold(&insert(DOC, json!(["a"]), g.fake.head()), "unreachable", false);
    g.holds.hold(&second, Burst::admit(insert("1.0.2.0.1", json!(["b"]), g.fake.head()), &second).unwrap(), Reason::of("unreachable", false), second.opened_at).unwrap();
    g.holds.probe("b-1");
    let mut sent: Vec<String> = g.fake.sends.lock().unwrap().iter().map(|f| f["doc"].as_str().unwrap_or("?").to_string()).collect();
    sent.sort();
    assert_eq!(sent, [DOC, "1.0.2.0.1"], "each principal's line is sent");
    assert!(g.lines().is_empty() && g.holds.lines(&second).unwrap().as_array().unwrap().is_empty(), "and each kept");
}

/// Checks that a foreign row is no verdict: the head is sent from the head.
///
/// With another hand's row on the document since `base`, the read finds no
/// landing of the head's own and judges no move — its one question is
/// whether the line's own write landed; whether the document moved is the
/// board's verdict on the send (`arrangement_moved`): the line is sent, the
/// board takes it, and it is kept, never faced `moved` by the read (the
/// mutant that faces a foreign row `moved` holds the person's text behind
/// an act for a move the board never found).
#[test]
fn a_foreign_row_is_no_verdict_and_the_head_is_sent() {
    let g = ground();
    *g.fake.rows.lock().unwrap() = vec![json!({"at": 77, "op": "insert", "key": "ff".repeat(32), "docs": [DOC]})];
    g.hold(&insert(DOC, json!(["hello"]), g.fake.head()), "unreachable", true);
    g.holds.probe("b-1");
    assert_eq!(g.fake.sends(), 1, "the head is sent from the head");
    assert!(g.lines().is_empty(), "and kept");
    let states = g.states();
    assert_eq!(states, ["holding", "sending", "kept"], "never faced moved by the read: {states:?}");
}

/// Checks that a bare session resends no held line.
///
/// The keyless session reads alone, no `bare` write of this shell's ever
/// committed (foundations §3.3 state 3): a line held under the principal's
/// one session, a bare one, stands through the probe — the board's
/// `/health` read, nothing sent, nothing said past its `holding` — and once
/// a session of the principal's that may write stands, the next probe sends
/// it, attested by that session's key, and keeps it (the mutant whose drain
/// resends under any session of the principal commits the person's text
/// under the bare hand).
#[test]
fn a_bare_session_resends_no_held_line() {
    let g = bare_ground();
    g.hold(&insert(DOC, json!(["hello"]), g.fake.head()), "unreachable", false);
    g.holds.probe("b-1");
    assert_eq!((g.fake.health_reads.load(Ordering::SeqCst), g.fake.sends()), (1, 0), "the board is read, and nothing is sent under the bare session");
    assert_eq!(g.lines().len(), 1, "the line stands");
    assert_eq!(g.states(), ["holding"], "and nothing past its hold is said");
    let open = Open { token: Token::parse(&"8e".repeat(16)).unwrap(), facts: writer_facts(&g.store), opened_at: 0 };
    let board = BoardEntry { reference: g.session.board_reference.clone(), board: Arc::clone(&g.session.board) };
    let writer = g.holds.sessions.register(&board, open, &mut NoSupplements);
    g.holds.open_session(&writer);
    g.holds.probe("b-1");
    let sent = g.fake.sends.lock().unwrap().clone();
    assert_eq!(sent.len(), 1, "the writer sends the line: {sent:?}");
    assert!(sent[0].get("attest").is_some(), "attested by the writer's key: {sent:?}");
    assert!(g.lines().is_empty() && g.states().contains(&"kept".to_string()), "and keeps it");
}

/// Checks that a signed row is own, and a bare row no verdict.
///
/// It is the own hand on a read (§3c.5; wire.md §`/changes`): a signed
/// entry's row carries `attest` and no `key`, and is the session's own
/// under a session that holds a key — the head `done kept`, nothing re-sent
/// (the mutant that keys the test on `key` alone sends the landed head
/// again); a row with `key: "bare"` is another hand's, never a keyed
/// session's own, and so no verdict — under a writer, whose key the store
/// holds, the head is sent from the head and kept, never faced `moved` (the
/// mutant that reads the bare row as own keeps a head that never landed). No
/// read is made under a bare session, which writes nothing of its own to
/// find (`a_bare_session_resends_no_held_line`).
#[test]
fn a_signed_row_is_own_and_a_bare_row_is_no_verdict() {
    let signed_row = json!({"at": 77, "op": "insert", "docs": [DOC], "attest": {"alg": "x", "sig": "y"}});
    let bare_row = json!({"at": 77, "op": "insert", "docs": [DOC], "key": "bare"});
    let walk = |g: Ground, row: Value| -> (Vec<String>, usize) {
        *g.fake.text.lock().unwrap() = "hello".into();
        *g.fake.rows.lock().unwrap() = vec![row];
        g.hold(&insert(DOC, json!(["hello"]), g.fake.head()), "unreachable", true);
        g.holds.probe("b-1");
        (g.states(), g.fake.sends())
    };
    let (states, sends) = walk(ground_in(TempDir::new().unwrap(), keyed_facts(), 0), signed_row.clone());
    assert_eq!((states, sends), (vec!["holding".to_string(), "kept".to_string()], 0), "the signed row is the keyed session's own: the landed head is not re-sent");
    let (states, sends) = walk(ground(), bare_row);
    assert_eq!((states, sends), (vec!["holding".to_string(), "sending".to_string(), "kept".to_string()], 1), "a bare hand's row is foreign to a keyed session, and no verdict: the head is sent");
}

/// Checks that a lost-testimony row lands the head where its site confirms
/// it, and is no verdict otherwise.
///
/// A row whose testimony the board lost (`docs`, `key`, `op` the reserved
/// null — the `poisoned` burst a restart replays, §3c.2) has no hand to
/// trust, so the site alone decides: a `sent` insert whose values read back
/// equal is kept and not re-sent (the mutant that reads it as a foreign hand
/// sends the person's own text again); values that differ are no landing —
/// the head is sent from the head and kept, never faced `moved`; a kind the
/// site read cannot confirm is no landing on a lost row either, the head
/// sent (the board judging its typed state); and a head that was never sent
/// is not read at all, the row standing or not — sent from the head with no
/// `/changes` read made (the mutant that faces any of the three `moved`
/// marks text nothing moved as "not placed").
#[test]
fn a_lost_testimony_row_lands_the_head_where_its_site_confirms_it_alone() {
    let lost = lost_row();
    // Each walk's frame is typed against its own ground's head; it answers
    // the `held` states said, the sends and the `/changes` reads made.
    let walk = |frame: &dyn Fn(u64) -> Value, text: &str, sent: bool| -> (Vec<String>, usize, usize) {
        let g = ground();
        *g.fake.text.lock().unwrap() = text.into();
        *g.fake.rows.lock().unwrap() = vec![lost.clone()];
        g.hold(&frame(g.fake.head()), "poisoned", sent);
        g.holds.probe("b-1");
        (g.states(), g.fake.sends(), g.fake.changes_reads.load(Ordering::SeqCst))
    };
    let kept = vec!["holding".to_string(), "kept".to_string()];
    let resent = vec!["holding".to_string(), "sending".to_string(), "kept".to_string()];
    assert_eq!(walk(&|at| insert(DOC, json!(["hello"]), at), "hello", true), (kept, 0, 1), "the landed insert is kept, not re-sent");
    assert_eq!(walk(&|at| insert(DOC, json!(["hello"]), at), "other", true), (resent.clone(), 1, 1), "values that differ: no landing, sent from the head");
    assert_eq!(walk(&|at| delete(DOC, at), "hello", true), (resent.clone(), 1, 1), "a kind the site read cannot confirm, on a row with no hand: no landing, sent from the head");
    assert_eq!(walk(&|at| insert(DOC, json!(["hello"]), at), "hello", false), (resent, 1, 0), "a head never sent is not read: sent from the head");
}

/// Checks that a read the board refuses decides nothing (§3c.5).
///
/// A `/changes` answered `503 feed_rebuilding` — the daemon re-covering a
/// lost `commits.log` behind its listener after an open, exactly when a
/// resend runs — leaves a `sent` head held and unsent (the mutant that reads
/// the refusal as "no row" sends a burst that may have landed a second
/// time); once the board serves the page, the next probe reads it and sends.
#[test]
fn a_read_the_board_refuses_decides_nothing() {
    let g = ground();
    *g.fake.changes_refused.lock().unwrap() = Some((503, json!({"error": "feed_rebuilding", "detail": "the feed is being re-covered"})));
    g.hold(&insert(DOC, json!(["hello"]), g.fake.head()), "unreachable", true);
    g.holds.probe("b-1");
    assert_eq!(g.fake.sends(), 0, "nothing is sent on a read the board refused");
    assert_eq!(g.lines()[0]["cause"], "unreachable", "the line stands as it was");
    let states = g.states();
    assert!(!states.contains(&"sending".to_string()), "an unread document is not said `sending`: {states:?}");
    *g.fake.changes_refused.lock().unwrap() = None;
    g.holds.probe("b-1");
    assert_eq!(g.fake.sends(), 1, "the next probe reads the page and sends");
    assert!(g.lines().is_empty());
}

/// Checks that `history_reclaimed` on the read keeps the head where its site
/// confirms it alone.
///
/// No row can be read, so the arrangement alone decides the one question
/// (§3c.5) — a `sent` head whose values read back equal at its site is (ii),
/// kept and not re-sent; values that differ are no landing found, and the
/// head is sent from the head and kept, never faced `moved` (the mutant that
/// faces the difference `moved` marks text nothing moved as "not placed");
/// a site read the board does not answer decides nothing and the line
/// stands (the mutant that trusts an unread site keeps a burst that never
/// landed).
#[test]
fn history_reclaimed_keeps_the_head_where_its_site_confirms_it_alone() {
    let reclaimed = || Some((410, json!({"error": "history_reclaimed", "floor": 90})));
    let g = ground();
    *g.fake.changes_refused.lock().unwrap() = reclaimed();
    *g.fake.text.lock().unwrap() = "hello".into();
    g.hold(&insert(DOC, json!(["hello"]), g.fake.head()), "unreachable", true);
    g.holds.probe("b-1");
    assert_eq!(g.fake.sends(), 0, "the landed head is not re-sent");
    assert!(g.lines().is_empty(), "the values at the site keep it");
    assert!(g.states().contains(&"kept".to_string()));

    let g = ground();
    *g.fake.changes_refused.lock().unwrap() = reclaimed();
    *g.fake.text.lock().unwrap() = "other".into();
    g.hold(&insert(DOC, json!(["hello"]), g.fake.head()), "unreachable", true);
    g.holds.probe("b-1");
    let states = g.states();
    assert_eq!((g.fake.sends(), g.lines().len()), (1, 0), "values that differ: no landing, sent from the head and kept");
    assert_eq!(states, ["holding", "sending", "kept"], "never faced moved: {states:?}");

    let g = ground();
    *g.fake.changes_refused.lock().unwrap() = reclaimed();
    g.fake.site_unread.store(true, Ordering::SeqCst);
    g.hold(&insert(DOC, json!(["hello"]), g.fake.head()), "unreachable", true);
    g.holds.probe("b-1");
    assert_eq!(g.fake.sends(), 0);
    assert_eq!(g.lines()[0]["cause"], "unreachable", "an unread site decides nothing: the line stands");
    assert!(!g.states().contains(&"kept".to_string()));
}

/// Checks that a refusal held nowhere hands a resent line over at once.
///
/// It cannot resolve, so it is the person's (§3c.4; skep #720). The board
/// answering a resend `credential_refused`/`index_rebuilding`, retry-class — a
/// code the table holds nowhere, which no resend resolves — the line is a
/// refused run at once under the board's token, the board's verdict verbatim
/// beside it, its `sent` kept; said once on TALK, never "sent again", and
/// `refused` on the `held` event; never `done`. The line behind it waits with
/// it and no probe dials either; the person's `send` hands the run back, and
/// the next probe reads, sends and keeps both (the mutant that leaves the line
/// standing resends it at every probe for ever; the one that writes `done`
/// loses text the board never took; the one that clears `sent` reads a write
/// that may have landed as one never sent).
#[test]
fn a_refusal_the_table_holds_nowhere_hands_a_resent_line_over_at_once() {
    let g = ground();
    let verdict = json!({"resp": "rejected", "code": "credential_refused", "detail": "index_rebuilding", "disposition": "retry", "op": "insert"});
    let k = g.hold(&insert(DOC, json!(["a"]), g.fake.head()), "unreachable", false)["held"].as_u64().unwrap();
    g.hold(&insert(DOC, json!(["b"]), g.fake.head()), "behind", false);
    g.fake.op_rejected.next(1, verdict.clone());
    let _ = g.states();
    g.holds.probe("b-1");
    let lines = g.lines();
    assert_eq!(g.fake.sends(), 1, "the line was sent once");
    assert_eq!((lines.len(), lines[0]["cause"].as_str(), lines[0]["sent"].as_bool()), (2, Some("credential_refused:index_rebuilding"), Some(true)), "a refused run under the board's token, its `sent` kept: {lines:?}");
    assert_eq!(lines[0]["refusal"], verdict, "the board's verdict verbatim");
    assert_eq!(g.states(), ["sending", "refused"]);
    let said = g.said.lock().unwrap().clone();
    let line = format!("held: line {k} on {DOC} was not taken (");
    assert_eq!(said.iter().filter(|l| l.starts_with(&line) && l.ends_with("it is handed to the person, who may send it again or drop it")).count(), 1, "said once: {said:?}");
    assert!(!said.iter().any(|l| l.contains("sent again at the next probe")), "never sent again: {said:?}");
    g.holds.probe("b-1");
    assert_eq!(g.fake.sends(), 1, "nothing dialed after it: the lines wait for the person's act");
    assert_eq!(g.holds.resolve(&g.session, k, ResolveAct::Send).unwrap(), Resolved::HandedBack);
    g.holds.probe("b-1");
    assert_eq!(g.fake.sends(), 3, "the person's send: both lines sent");
    assert!(g.lines().is_empty() && g.states().contains(&"kept".to_string()));
}

/// Checks that another process's lock leaves the directory not yet this
/// shell's (§3c.3: one shell per data directory).
///
/// With the board's `held/<chain>/lock` held by another process, a burst is
/// held under its own cause — never a second shell's — its answer
/// `unwritable` saying another process holds the store, nothing written
/// under the directory, the line standing in memory and resent like any
/// line once the board answers; and once that process lets the lock go, the
/// next probe takes the directory, so the next line is copied to the
/// board's file (the mutants that keep a second shell's custody with a cause
/// of its own, that write under a lock another process holds, or that never
/// try the lock again).
#[test]
fn another_processs_lock_leaves_the_directory_not_yet_this_shells() {
    let store = TempDir::new().unwrap();
    let dir = HeldDir::new(store.path(), Chain::parse(&"ab".repeat(32)).unwrap());
    dir.ensure().unwrap();
    let other_process = dir.try_lock().unwrap().expect("the other process holds the lock");
    let held_dir = store.path().join("held").join("ab".repeat(32));
    let facts = writer_facts(&store);
    let g = ground_in(store, facts, 0);
    let answer = g.hold(&insert(DOC, json!(["hello"]), g.fake.head()), "unreachable", false);
    assert_eq!((answer["resp"].as_str(), answer["cause"].as_str()), (Some("held"), Some("unreachable")), "the hold's own cause, no second shell's: {answer}");
    let why = answer["unwritable"].as_str().unwrap_or_else(|| panic!("the answer says why: {answer}"));
    assert!(why.contains("another process holds this board's held store") && why.contains("one shell per data directory"), "{why}");
    assert!(!held_dir.join("principal-1.held").exists(), "nothing is written under a lock another process holds");
    assert_eq!(g.lines().len(), 1, "the line stands in memory");
    g.holds.probe("b-1");
    assert_eq!(g.fake.sends(), 1, "the line is resent");
    assert!(g.lines().is_empty() && g.states().contains(&"kept".to_string()));
    // The other process lets go: the lock is tried again at the next probe,
    // the directory taken, and the next line copied to the board's file.
    drop(other_process);
    let still = g.hold(&insert(DOC, json!(["b"]), g.fake.head()), "unreachable", false);
    assert!(still["unwritable"].is_string(), "until a probe or a session's open tries the lock again: {still}");
    g.holds.probe("b-1");
    assert!(g.lines().is_empty(), "resent and kept");
    let next = g.hold(&insert(DOC, json!(["c"]), g.fake.head()), "unreachable", false);
    assert!(next.get("unwritable").is_none(), "the directory is this shell's now: {next}");
    assert!(std::fs::read_to_string(held_dir.join("principal-1.held")).unwrap().contains("\"values\":[\"c\"]"), "the line is copied to the board's file");
}

/// Returns the hands a moved document's `held` event names, over `rows` —
/// built from this store's own fingerprint and a second, labelled key's.
///
/// They are the board's verdict's — a burst refused as typed against an older
/// state at its first dial, its hands read off the rows since its typed state
/// — the one route to the moved face: the resend's read judges no move and
/// names no hand.
fn moved_hands(rows: impl Fn(&str, &str) -> Vec<Value>) -> Vec<Value> {
    let store = TempDir::new().unwrap();
    let facts = writer_facts(&store);
    let KeyId(other) = FileStore::open(store.path().join("store")).generate(Some(skep_client::sheet::Label::new("phone").unwrap())).unwrap();
    let g = ground_in(store, facts, 0);
    *g.fake.rows.lock().unwrap() = rows(&g.own_key(), &other.to_hex());
    g.fake.op_rejected.next(1, arrangement_moved(g.fake.head(), 78));
    let OpAnswer::Answered(Ok(held)) = g.holds.send_burst(&g.session, insert(DOC, json!(["hello"]), g.fake.head()), None) else { panic!("held, not faced") };
    assert_eq!(held["cause"], "moved", "the board's verdict holds the burst moved: {held}");
    let moved = g.rx.try_iter().filter(|e| e.name == EventName::Held).map(|e| e.data).find(|d| d["state"] == "moved").expect("the document moved");
    assert_held_event_declared(&moved);
    let hands = moved["hands"].as_array().cloned().unwrap_or_default();
    for hand in &hands {
        crate::shapes::assert_declared("Hand", hand);
    }
    hands
}

/// Checks that a moved document names its hands, each once (§3c.5; §4b.2).
///
/// The rows that moved it — read since the burst's typed state where the
/// board refused it as typed against an older state, the one route to the
/// moved face — give the hands the `held` event's `moved` state carries:
/// this store's own key by its fingerprint, another key the shell's key
/// store holds with its label, another key it does not hold by its
/// fingerprint alone, `bare`, a row whose testimony the board lost, and a
/// signed row — the own hand, as the read's own-row test reads it; a hand
/// twice on the page is named once (the mutants that name no hand, one per
/// row, or a label for a key the store does not hold; the one that reads no
/// row at the board's verdict).
#[test]
fn a_moved_documents_hands_are_named_each_once() {
    let row = |at: u64, key: Value| json!({"at": at, "op": "insert", "key": key, "docs": [DOC]});
    let hands = moved_hands(|own, other| vec![row(77, json!(own)), row(78, json!(other))]);
    assert_eq!(hands.len(), 2, "{hands:?}");
    assert_eq!((hands[0]["key"].as_str(), hands[0]["fingerprint"].is_string(), hands[0].get("label")), (Some("own"), true, None), "{hands:?}");
    assert_eq!((hands[1]["key"].as_str(), hands[1]["fingerprint"].is_string(), hands[1]["label"].as_str()), (Some("other"), true, Some("phone")), "the label the store holds: {hands:?}");
    let hands = moved_hands(|_, _| vec![row(77, json!("bare")), lost_row()]);
    assert_eq!(hands, [json!({"key": "bare"}), json!({"key": "lost"})], "{hands:?}");
    let hands = moved_hands(|_, _| vec![row(77, json!("ff".repeat(32))), row(78, json!("bare"))]);
    assert_eq!(hands, [json!({"key": "other", "fingerprint": "ff".repeat(32)}), json!({"key": "bare"})], "a key the store does not hold carries no label: {hands:?}");
    let hands = moved_hands(|_, _| vec![row(77, json!("bare")), row(78, json!("bare"))]);
    assert_eq!(hands, [json!({"key": "bare"})], "each hand once: {hands:?}");
    let hands = moved_hands(|_, _| vec![json!({"at": 77, "op": "insert", "docs": [DOC], "attest": {"alg": "x", "sig": "y"}}), row(78, json!("bare"))]);
    assert_eq!((hands.len(), hands[0]["key"].as_str(), hands[1]["key"].as_str()), (2, Some("own"), Some("bare")), "a signed row is the own hand, as the read reads it: {hands:?}");
}

/// Checks that a first moved face names every hand since the typed state,
/// though the line's base stands past it (§3c.5; skep #757).
///
/// The person's link homed in the document is acked at 80, which moves no
/// arrangement and makes 80 the base of the next hold there; a burst typed
/// against the document at 70 — the page's last read of its text — is then
/// refused as typed against an older state, another writer's change at 75
/// having moved it. At a first dial, and at a resend of a line held before
/// any dial, the burst is held moved at the base 80, and its face names the
/// hand of the change at 75, between the typed state and the base (the
/// mutant that reads the hands since the line's base draws the first moved
/// face with no hand).
#[test]
fn a_first_moved_face_names_every_hand_since_the_typed_state_though_the_base_stands_past_it() {
    let link = json!({"op": "make_link", "home": DOC, "from": {"addrs": []}, "to": {"addrs": []}, "ty": {"addrs": []}});
    for at_a_resend in [false, true] {
        let g = ground();
        g.fake.next_at.store(81, Ordering::SeqCst);
        *g.fake.rows.lock().unwrap() = vec![json!({"at": 75, "op": "insert", "key": "ff".repeat(32), "docs": [DOC]})];
        g.holds.note_ack(&g.session, &link, &json!({"resp": "ack_addr", "addr": "1.0.1.0.1.0.2.1", "at": 80}));
        g.fake.op_rejected.next(1, arrangement_moved(70, 75));
        if at_a_resend {
            g.hold(&insert(DOC, json!(["x"]), 70), "unreachable", false);
            g.holds.probe("b-1");
        } else {
            let OpAnswer::Answered(Ok(held)) = g.holds.send_burst(&g.session, insert(DOC, json!(["x"]), 70), None) else { panic!("held, not faced") };
            assert_eq!(held["cause"], "moved", "{held}");
        }
        let lines = g.lines();
        assert_eq!((lines[0]["cause"].as_str(), lines[0]["base"].as_u64()), (Some("moved"), Some(80)), "at a resend {at_a_resend}: {lines:?}");
        let moved = g.rx.try_iter().filter(|e| e.name == EventName::Held).map(|e| e.data).find(|d| d["state"] == "moved").expect("the document faced moved");
        assert_held_event_declared(&moved);
        assert_eq!(moved["hands"], json!([{"key": "other", "fingerprint": "ff".repeat(32)}]), "at a resend {at_a_resend}: the hand between the typed state and the base: {moved}");
    }
}

/// A sibling session of the ground's: a second tab of the same principal,
/// under the same key, opened at the same position — registered and opened
/// at the holds as the shell opens one.
fn sibling_of(g: &Ground) -> Arc<SessionEntry> {
    let open = Open { token: Token::parse(&"8e".repeat(16)).unwrap(), facts: g.session.facts.clone(), opened_at: g.session.opened_at };
    let board = BoardEntry { reference: g.session.board_reference.clone(), board: Arc::clone(&g.session.board) };
    let sibling = g.holds.sessions.register(&board, open, &mut NoSupplements);
    g.holds.open_session(&sibling);
    sibling
}

/// Checks that an own landing followed by a later row of anyone's is kept
/// (§3c.5 (ii)).
///
/// The head's own row stands since `base`, another hand's row after it and
/// the person's own link row after that: the FIRST row that is the head's
/// landing is its landing, whatever follows — the head is `done kept`, its
/// position the document's base, and nothing is re-sent; the rows after it
/// are nobody's to judge here (the mutant that takes two rows for a move
/// faces text the board holds as "not placed", and the person lands it a
/// second time by hand; the one that reads the last row for the landing
/// resends the head).
#[test]
fn an_own_landing_followed_by_a_later_row_of_anyones_is_kept() {
    let g = ground();
    *g.fake.text.lock().unwrap() = "hello".into();
    *g.fake.rows.lock().unwrap() = vec![
        json!({"at": 77, "op": "insert", "key": g.own_key(), "docs": [DOC]}),
        json!({"at": 78, "op": "delete", "key": "ff".repeat(32), "docs": [DOC]}),
        json!({"at": 79, "op": "make_link", "key": g.own_key(), "docs": [DOC]}),
    ];
    g.hold(&insert(DOC, json!(["hello"]), g.fake.head()), "unreachable", true);
    g.holds.probe("b-1");
    assert_eq!(g.fake.sends(), 0, "the landed head is not re-sent");
    assert!(g.lines().is_empty(), "the line is done kept");
    assert_eq!(g.states(), ["holding", "kept"], "never faced moved");
    g.hold(&insert(DOC, json!(["!"]), g.fake.head()), "unreachable", false);
    assert_eq!(g.lines()[0]["base"], 77, "the landing is the document's base");
}

/// Checks that a landing past the first page is found: the read goes on.
///
/// Three hundred rows of another hand stand since `base`, the head's own
/// landing after them: the route's default page ends with `more` standing
/// and no landing found, so the read goes on from its `last` and finds the
/// landing on the next page — the head kept, two pages read, nothing re-sent
/// (the mutant that takes a page whose `more` stands for "nothing landed"
/// sends the head a second time; the one that takes it for a move faces the
/// person's own text "not placed").
#[test]
fn a_landing_past_the_first_page_is_found_by_reading_on() {
    let g = ground();
    *g.fake.text.lock().unwrap() = "hello".into();
    let mut rows: Vec<Value> = (1..=300).map(|n| json!({"at": 100 + n, "op": "insert", "key": "ff".repeat(32), "docs": [DOC]})).collect();
    rows.push(json!({"at": 401, "op": "insert", "key": g.own_key(), "docs": [DOC]}));
    *g.fake.rows.lock().unwrap() = rows;
    g.hold(&insert(DOC, json!(["hello"]), g.fake.head()), "unreachable", true);
    g.holds.probe("b-1");
    assert_eq!((g.fake.changes_reads.load(Ordering::SeqCst), g.fake.sends()), (2, 0), "two pages read, nothing re-sent");
    assert!(g.lines().is_empty() && g.states().contains(&"kept".to_string()), "kept");
}

/// Checks that a sibling's row of the head's kind at a position this shell
/// acked is skipped, and the head goes from the head (§3c.5).
///
/// A held `delete`, whose site no read confirms, its answer lost; a sibling
/// session of the principal — a second tab, the same key — has a `delete` on
/// the document acked through this shell while the line stands, its row the
/// only one since `base`: of the own hand and the head's kind, it would pass
/// for the lost landing, but its position is one this shell acked, so the
/// read skips it, finds no landing, and sends the head — acked and kept, the
/// person's text on the board; the ack raised the base of the next hold
/// alone, never the standing line's (the mutant that keeps no acked set
/// keeps the head on the sibling's row, and the person's write is lost; the
/// one that raises a standing line's base at an ack reads past a landing of
/// its own).
#[test]
fn a_siblings_row_of_the_heads_kind_at_an_acked_position_is_skipped_and_the_head_sent() {
    let g = ground();
    g.hold(&delete(DOC, g.fake.head()), "unreachable", true);
    let sibling = sibling_of(&g);
    g.holds.note_ack(&sibling, &delete(DOC, g.fake.head()), &json!({"resp": "ack", "at": 77}));
    *g.fake.rows.lock().unwrap() = vec![json!({"at": 77, "op": "delete", "key": g.own_key(), "docs": [DOC]})];
    g.fake.next_at.store(78, Ordering::SeqCst);
    assert_eq!(g.lines()[0]["base"], 0, "the standing line keeps the base it was held at");
    g.holds.probe("b-1");
    assert_eq!(g.fake.sends(), 1, "the head is sent from the head: the sibling's row is no landing of its own");
    assert!(g.lines().is_empty(), "and kept");
    assert_eq!(g.states(), ["holding", "sending", "kept"]);
}

/// Checks that a sibling's ack during the dial does not raise the base the
/// line is held at (skep #737).
///
/// The burst's first dial leaves and its answer is lost — it landed at 77;
/// while the dial is out, a sibling session's write on the document is acked
/// through this shell at 78 (the fake's look as `/op` records the send, run
/// inside the dial before its answer). The line is held at the base read
/// BEFORE the dial — the session's open, 0 — not at 78: its read finds the
/// landing at 77 below the sibling's ack and keeps it, nothing sent twice
/// (the mutant that reads the base after the dial holds the line at 78,
/// reads nothing above it, and sends the person's words a second time).
#[test]
fn a_siblings_ack_during_the_dial_does_not_raise_the_base_the_line_is_held_at() {
    let g = ground();
    let sibling = sibling_of(&g);
    let own = g.own_key();
    let acked_during_the_dial = {
        let (holds, sibling) = (Arc::clone(&g.holds), Arc::clone(&sibling));
        move || holds.note_ack(&sibling, &insert(DOC, json!(["!"]), 0), &json!({"resp": "ack", "at": 78}))
    };
    *g.fake.at_send.lock().unwrap() = Some(Box::new(acked_during_the_dial));
    g.fake.op_lost_at.store(1, Ordering::SeqCst);
    *g.fake.text.lock().unwrap() = "hello".into();
    *g.fake.rows.lock().unwrap() = vec![json!({"at": 77, "op": "insert", "key": own, "docs": [DOC]}), json!({"at": 78, "op": "insert", "key": own, "docs": [DOC]})];
    let OpAnswer::Answered(Ok(held)) = g.holds.send_burst(&g.session, insert(DOC, json!(["hello"]), g.fake.head()), None) else { panic!("held, not faced") };
    assert_eq!((held["cause"].as_str(), g.fake.sends()), (Some("unreachable"), 1), "the answer lost, the line held: {held}");
    let lines = g.lines();
    assert_eq!((lines[0]["base"].as_u64(), lines[0]["sent"].as_bool()), (Some(0), Some(true)), "held at the base read before the dial, not at the sibling's ack: {lines:?}");
    *g.fake.at_send.lock().unwrap() = None;
    g.holds.probe("b-1");
    assert_eq!(g.fake.sends(), 1, "the landing at 77 is found below the sibling's ack: never sent twice");
    assert!(g.lines().is_empty(), "kept");
    assert_eq!(g.states(), ["holding", "kept"]);
}

/// Checks that a head no dial of which left is sent from the head, unread.
///
/// A line held `sent: false` — the board unreachable at its first dial, no
/// request leaving — can have landed nothing, so the probe makes no
/// `/changes` read for it, whatever rows stand on the document since its
/// base (another hand's row here), and sends it from the head: acked and
/// kept (the mutant that reads it spends a read to learn what `sent` already
/// says, or takes the foreign row for a verdict).
#[test]
fn a_head_never_sent_goes_from_the_head_with_no_read() {
    let g = ground();
    *g.fake.rows.lock().unwrap() = vec![json!({"at": 77, "op": "insert", "key": "ff".repeat(32), "docs": [DOC]})];
    g.hold(&insert(DOC, json!(["hello"]), g.fake.head()), "unreachable", false);
    g.holds.probe("b-1");
    assert_eq!((g.fake.changes_reads.load(Ordering::SeqCst), g.fake.sends()), (0, 1), "no read, one send");
    assert!(g.lines().is_empty() && g.states().contains(&"kept".to_string()), "kept");
}

/// Whose later write lands on a held line's document.
#[derive(Debug, Clone, Copy)]
enum LaterWriter {
    /// The line's own session links in the draft, acked through this shell.
    ThisSession,
    /// A sibling session of the principal — a second tab, the same key —
    /// links in the draft, acked through this shell (skep #736).
    Sibling,
    /// The person's own write of another kind, not through this shell — the
    /// `skep` command's `delete`, the same key, no ack the shell saw.
    NotThroughTheShell,
}

/// Checks that the person's own later write on the document leaves a held
/// line holding, never `moved` (skep #709, #736).
///
/// A line stands, its answer lost; the person's own write lands on the
/// document after it — a link through this session, a link through a
/// sibling session of the principal, or a `delete` not through this shell —
/// and its row is the one since `base`: of the own hand but not the head's
/// kind, it is no verdict. An ack the shell saw raises the base of the NEXT
/// hold alone, the standing line keeping the base it was held at; the line
/// is sent from the head and kept, never faced `moved` (the mutant that
/// faces the own row `moved` marks text nothing moved as "not placed"; the
/// one that raises the standing line's base at the ack reads past a landing
/// of the line's own). A write of the head's own kind not through this
/// shell is the named residue: no ack of it reached the shell, so the read
/// cannot tell it from the lost landing.
#[test]
fn the_persons_own_later_write_on_the_document_leaves_the_line_holding() {
    for writer in [LaterWriter::ThisSession, LaterWriter::Sibling, LaterWriter::NotThroughTheShell] {
        let g = ground();
        g.hold(&insert(DOC, json!(["hello"]), g.fake.head()), "unreachable", true);
        let link = json!({"op": "make_link", "home": DOC, "from": {"addrs": []}, "to": {"addrs": []}, "ty": {"addrs": []}});
        let row = match writer {
            LaterWriter::ThisSession | LaterWriter::Sibling => {
                let session = if matches!(writer, LaterWriter::Sibling) { sibling_of(&g) } else { Arc::clone(&g.session) };
                let OpAnswer::Answered(Ok(ack)) = g.holds.send(&session, link, None) else { panic!("{writer:?}: the link is acked") };
                json!({"at": ack["at"], "op": "make_link", "key": g.own_key(), "docs": [DOC]})
            }
            LaterWriter::NotThroughTheShell => json!({"at": 77, "op": "delete", "key": g.own_key(), "docs": [DOC]}),
        };
        *g.fake.rows.lock().unwrap() = vec![row];
        let lines = g.lines();
        assert_eq!((lines[0]["cause"].as_str(), lines[0]["base"].as_u64()), (Some("unreachable"), Some(0)), "{writer:?}: the standing line keeps its base: {lines:?}");
        let sends_before = g.fake.sends();
        g.holds.probe("b-1");
        let states = g.states();
        assert_eq!(g.fake.sends(), sends_before + 1, "{writer:?}: the line is sent from the head");
        assert!(g.lines().is_empty() && states.contains(&"kept".to_string()) && !states.contains(&"moved".to_string()), "{writer:?}: kept, never moved: {states:?}");
    }
}

/// Checks that a line behind a landing kept with no position is not faced
/// `moved` (skep #711).
///
/// Under `history_reclaimed` — the feed's files holding a hole below the
/// head's `base` — the head's values stand at its site and it is kept with
/// no position to name, so the line behind it keeps its base, below the
/// floor; the board does not take that line at the probe (a connection never
/// made), and it is held again, marked as one that may have landed. Its own
/// read meets `history_reclaimed` too, its site differing — it never landed
/// — and it is sent from the head, acked and kept, never faced `moved` (the
/// mutant that faces a reclaimed read's unconfirmed site `moved` marks text
/// nothing moved as "not placed", and sends it back to the same read at
/// every `send`).
#[test]
fn a_line_behind_a_landing_kept_with_no_position_is_not_faced_moved() {
    let g = ground();
    *g.fake.changes_refused.lock().unwrap() = Some((410, json!({"error": "history_reclaimed", "floor": 90})));
    *g.fake.text.lock().unwrap() = "hello".into();
    g.hold(&insert(DOC, json!(["hello"]), g.fake.head()), "unreachable", true);
    g.hold(&insert(DOC, json!(["!"]), g.fake.head()), "behind", false);
    g.fake.op_unreachable.store(true, Ordering::SeqCst);
    g.holds.probe("b-1");
    let lines = g.lines();
    assert_eq!(
        (lines.len(), lines[0]["cause"].as_str(), lines[0]["sent"].as_bool(), lines[0]["base"].as_u64()),
        (1, Some("unreachable"), Some(true), Some(0)),
        "the head kept with no position, the line behind held again at its base: {lines:?}"
    );
    g.fake.op_unreachable.store(false, Ordering::SeqCst);
    let _ = g.states();
    g.holds.probe("b-1");
    let states = g.states();
    assert_eq!(g.fake.sends(), 1, "the line behind is sent from the head");
    assert!(g.lines().is_empty() && states.contains(&"kept".to_string()) && !states.contains(&"moved".to_string()), "{states:?}");
}

/// Checks that a drain that unwinds leaves the board free to drain (§3c.4).
///
/// It leaves no mark: a probe whose `/health` dial panics leaves the board
/// free to drain, and the next probe sends and keeps the line (the mutant
/// whose mark outlives an unwinding drain sends nothing for the shell's
/// life).
#[test]
fn a_drain_that_unwinds_leaves_the_board_free_to_drain() {
    let g = ground();
    g.hold(&insert(DOC, json!(["hello"]), g.fake.head()), "unreachable", false);
    g.fake.panic_next_health.store(true, Ordering::SeqCst);
    let unwound = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| g.holds.probe("b-1")));
    assert!(unwound.is_err(), "the health read panicked");
    assert_eq!(g.fake.sends(), 0, "nothing was sent while it unwound");
    g.holds.probe("b-1");
    assert_eq!(g.fake.sends(), 1, "the next probe drains");
    assert!(g.lines().is_empty() && g.states().contains(&"kept".to_string()));
}

/// Checks that a probe while a drain runs dials nothing (§3c.4).
///
/// One drain runs per board at a time: a probe that comes while another
/// drains the board — whatever thread reaches `Holds::probe` — dials
/// nothing, so the line is sent once (the mutant whose mark admits a second
/// drain reads `/health` twice, and may send the burst twice).
#[test]
fn a_probe_while_a_drain_runs_dials_nothing() {
    let g = ground();
    g.hold(&insert(DOC, json!(["hello"]), g.fake.head()), "unreachable", false);
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
    assert_eq!(g.fake.sends(), 1, "the line is sent once");
    assert!(g.lines().is_empty());
}

/// What the board answers the read of the held head's document.
#[derive(Debug, Clone, Copy)]
enum ReadAnswer {
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
    /// `400 malformed_changes` naming a `fits` of one row at the first ask,
    /// then the page of one own row at the limit re-asked.
    TooLarge,
    /// `503 feed_rebuilding`: no page.
    Refused,
}

/// The held head: an `insert` or a `delete`.
///
/// A read can confirm an `insert`'s site; none can a `delete`'s.
#[derive(Debug, Clone, Copy)]
enum Head {
    Insert,
    Delete,
}

/// What a read of the head's site answers.
///
/// It is the head's own values, other values, no answer, the death signal,
/// or the head's values and one more position than the read asked.
#[derive(Debug, Clone, Copy)]
enum SiteAnswer {
    Equal,
    Differs,
    Unread,
    Closed,
    OverDelivers,
}

/// How one probe settles the head.
#[derive(Debug, Clone, Copy)]
enum Settles {
    /// Sent from the head, acked and kept.
    Resent,
    /// Kept as landed, nothing sent.
    Kept,
    /// Left as it stood: nothing sent, nothing said.
    Standing,
}

/// Checks the read's table (§3c.5), cell by cell.
///
/// The read asks one question — did the head's own write land? — and never
/// faces a document `moved`, which is the board's verdict on a send. No row
/// sends from the head; a row is the head's landing only where the head was
/// sent and the row is of the session's own hand and of the head's own `op`,
/// its site not contradicting it — an `insert` read back equal, a kind no
/// read confirms trusted on its hand; the first such row is the landing,
/// whatever follows it; a row whose testimony the board lost, and
/// `history_reclaimed`, are decided by the site alone, a kind no read
/// confirms on them no landing; a foreign row, another `op` of the own hand,
/// a site that differs, and a lost row the site does not confirm are no
/// verdict — sent from the head; a head never sent goes from the head with
/// no read; a page too large to serve is re-asked at the limit that fits
/// and read; a read or a site read the board does not answer — its answer
/// the death signal among them — decides nothing; a site read delivering
/// past the values asked differs. The mutants the cells hold off: a second
/// tab's own-hand row landing a head whose site says otherwise (3), a
/// delete faced on its own hand (4), an unread site taken as either answer
/// (5, 11, 18), a head never sent kept off a row or read at all (6, 12, 19),
/// another `op` of the own hand taken for the landing (7), a lost row kept
/// on a kind no read confirms (10, 17), two rows or a foreign row faced
/// `moved` (13, 14), a page too large read as none or as unread (20), the
/// death signal at the site read taken as an answer (22–24), and a delivery
/// past the values asked read as theirs (25–27).
#[test]
fn every_read_answer_meets_every_site_answer_as_the_table_says() {
    use Head::{Delete, Insert};
    use ReadAnswer::{ForeignRow, LostRow, NoRow, OwnRow, Reclaimed, Refused, TooLarge, TwoOwnRows};
    use Settles::{Kept, Resent, Standing};
    use SiteAnswer::{Closed, Differs, Equal, OverDelivers, Unread};
    let table = [
        (NoRow, Insert, None, true, Resent),
        (OwnRow("insert"), Insert, Some(Equal), true, Kept),
        (OwnRow("insert"), Insert, Some(Differs), true, Resent),
        (OwnRow("delete"), Delete, None, true, Kept),
        (OwnRow("insert"), Insert, Some(Unread), true, Standing),
        (OwnRow("insert"), Insert, Some(Equal), false, Resent),
        (OwnRow("delete"), Insert, Some(Equal), true, Resent),
        (LostRow, Insert, Some(Equal), true, Kept),
        (LostRow, Insert, Some(Differs), true, Resent),
        (LostRow, Delete, None, true, Resent),
        (LostRow, Insert, Some(Unread), true, Standing),
        (LostRow, Insert, Some(Equal), false, Resent),
        (ForeignRow, Insert, Some(Equal), true, Resent),
        (TwoOwnRows, Insert, Some(Equal), true, Kept),
        (Reclaimed, Insert, Some(Equal), true, Kept),
        (Reclaimed, Insert, Some(Differs), true, Resent),
        (Reclaimed, Delete, None, true, Resent),
        (Reclaimed, Insert, Some(Unread), true, Standing),
        (Reclaimed, Insert, Some(Equal), false, Resent),
        (TooLarge, Insert, Some(Equal), true, Kept),
        (Refused, Insert, Some(Equal), true, Standing),
        (OwnRow("insert"), Insert, Some(Closed), true, Standing),
        (LostRow, Insert, Some(Closed), true, Standing),
        (Reclaimed, Insert, Some(Closed), true, Standing),
        (OwnRow("insert"), Insert, Some(OverDelivers), true, Resent),
        (LostRow, Insert, Some(OverDelivers), true, Resent),
        (Reclaimed, Insert, Some(OverDelivers), true, Resent),
    ];
    for (n, (read, head, site, sent, settles)) in table.into_iter().enumerate() {
        let g = ground();
        let key = g.own_key();
        let own = |at: u64, op: &str| json!({"at": at, "op": op, "key": key, "docs": [DOC]});
        let refused = |status: u16, body: Value| *g.fake.changes_refused.lock().unwrap() = Some((status, body));
        match read {
            NoRow => {}
            OwnRow(op) => *g.fake.rows.lock().unwrap() = vec![own(77, op)],
            LostRow => *g.fake.rows.lock().unwrap() = vec![lost_row()],
            ForeignRow => *g.fake.rows.lock().unwrap() = vec![json!({"at": 77, "op": "insert", "key": "ff".repeat(32), "docs": [DOC]})],
            TwoOwnRows => *g.fake.rows.lock().unwrap() = vec![own(77, "insert"), own(78, "insert")],
            Reclaimed => refused(410, json!({"error": "history_reclaimed", "floor": 90})),
            TooLarge => {
                g.fake.changes_too_large.next(1, 1);
                *g.fake.rows.lock().unwrap() = vec![own(77, "insert")];
            }
            Refused => refused(503, json!({"error": "feed_rebuilding"})),
        }
        match site {
            Some(Equal) => *g.fake.text.lock().unwrap() = "hello".into(),
            Some(Differs) => *g.fake.text.lock().unwrap() = "other".into(),
            Some(Unread) => g.fake.site_unread.store(true, Ordering::SeqCst),
            Some(Closed) => g.fake.site_closed.store(true, Ordering::SeqCst),
            Some(OverDelivers) => {
                *g.fake.text.lock().unwrap() = "hello!".into();
                g.fake.over_deliver.store(true, Ordering::SeqCst);
            }
            None => {}
        }
        let frame = match head {
            Insert => insert(DOC, json!(["hello"]), g.fake.head()),
            Delete => delete(DOC, g.fake.head()),
        };
        g.hold(&frame, "unreachable", sent);
        g.holds.probe("b-1");
        // The sends, the causes still standing, and the `held` states said
        // after the hold's own `holding`.
        let (sends, standing, says): (usize, &[&str], &[&str]) = match settles {
            Resent => (1, &[], &["sending", "kept"]),
            Kept => (0, &[], &["kept"]),
            Standing => (0, &["unreachable"], &[]),
        };
        let lines = g.lines();
        let causes: Vec<&str> = lines.iter().map(|l| l["cause"].as_str().unwrap_or("?")).collect();
        let states = g.states();
        let said: Vec<&str> = states.iter().map(String::as_str).skip(1).collect();
        assert_eq!(states.first().map(String::as_str), Some("holding"), "row {}: the hold says `holding` first: {states:?}", n + 1);
        assert_eq!(
            (g.fake.sends(), causes, said),
            (sends, standing.to_vec(), says.to_vec()),
            "row {}: {read:?}, a held {head:?} head, its site {site:?}, sent {sent} — {settles:?} (sends, causes standing, states said)",
            n + 1
        );
        // A head never sent is read never; a page too large is read twice,
        // the second ask at the limit that fits; every other head once.
        let reads = g.fake.changes_reads.load(Ordering::SeqCst);
        let expected = match read {
            _ if !sent => 0,
            TooLarge => 2,
            _ => 1,
        };
        assert_eq!(reads, expected, "row {}: {read:?}, sent {sent} — the `/changes` reads made", n + 1);
    }
}

/// Checks that a moved document faces its own lines alone (§3c.5).
///
/// The board refusing one document's resend as typed against an older state
/// of it — the row that moved it standing since the line's `base`, which the
/// read passes over as no verdict, the line `sent: true` so the read runs —
/// moves that document alone, by the verdict: its line stands `moved`,
/// carrying the board's verdict, the `held` event naming the hand whose row
/// moved it since the line's typed state, while a burst held `behind` it on
/// a second document is sent after it and kept (the mutant that faces every
/// line moved at one document's verdict strands the person's text on the
/// other; the one that faces the foreign row `moved` by the read holds the
/// line undialed, the other document's line sent alone; the ones that read
/// the hands from the line's `base`, or not at all, draw the moved face with
/// no hand).
#[test]
fn a_moved_document_faces_its_own_lines_alone() {
    let g = writer_at(80);
    g.fake.next_at.store(81, Ordering::SeqCst);
    *g.fake.rows.lock().unwrap() = vec![json!({"at": 85, "op": "insert", "key": "ff".repeat(32), "docs": [DOC]})];
    g.hold(&insert(DOC, json!(["a"]), 70), "unreachable", true);
    let OpAnswer::Answered(Ok(behind)) = g.holds.send_burst(&g.session, insert(OTHER, json!(["z"]), g.fake.head()), None) else { panic!("held behind the line") };
    assert_eq!(behind["cause"], "behind", "{behind}");
    g.fake.op_rejected.next(1, arrangement_moved(70, 85));
    g.holds.probe("b-1");
    let lines = g.lines();
    let standing: Vec<(&str, &str)> = lines.iter().map(|l| (l["doc"].as_str().unwrap_or("?"), l["cause"].as_str().unwrap_or("?"))).collect();
    assert_eq!(standing, [(DOC, "moved")], "the moved document's line alone stands");
    assert_eq!(lines[0]["refusal"], arrangement_moved(70, 85), "the board's verdict rides the line it refused");
    let moved = g.rx.try_iter().filter(|e| e.name == EventName::Held).map(|e| e.data).find(|d| d["state"] == "moved").expect("the document faced moved");
    assert_held_event_declared(&moved);
    assert_eq!((moved["doc"].as_str(), &moved["hands"]), (Some(DOC), &json!([{"key": "other", "fingerprint": "ff".repeat(32)}])), "the hand whose row moved it since its typed state: {moved}");
    let sent_docs: Vec<Value> = g.fake.sends.lock().unwrap().iter().map(|f| f["doc"].clone()).collect();
    assert_eq!(sent_docs, [json!(DOC), json!(OTHER)], "the moved document's line was refused, the other document's line sent");
}

/// Checks that a stopped node holds every burst until it runs (§3c.4).
///
/// While its owner's stop stands, a burst is held `stopped` without a dial
/// — `sent: false`, since nothing left — and the probe dials nothing; once
/// the node runs, the probe sends and keeps it (the mutant that dials past
/// the stop, and the one whose probe drains a stopped node).
#[test]
fn a_stopped_node_holds_every_burst_until_it_runs() {
    let g = ground();
    g.holds.set_node_stopped("b-1", true);
    let OpAnswer::Answered(Ok(held)) = g.holds.send_burst(&g.session, insert(DOC, json!(["hello"]), g.fake.head()), None) else { panic!("held before the dial") };
    assert_eq!((held["resp"].as_str(), held["cause"].as_str()), (Some("held"), Some("stopped")), "{held}");
    assert_eq!(g.lines()[0]["sent"], false);
    g.holds.probe("b-1");
    assert_eq!((g.fake.sends(), g.fake.health_reads.load(Ordering::SeqCst)), (0, 0), "nothing is dialed while the stop stands");
    g.holds.set_node_stopped("b-1", false);
    g.holds.probe("b-1");
    assert_eq!(g.fake.sends(), 1, "the running node takes the line");
    assert!(g.lines().is_empty() && g.states().contains(&"kept".to_string()));
}

/// Checks that the halted hold ends at the first read that says writes go.
///
/// The hold lasts from the first `true` read of `writes.halted` to the
/// first `false` (§3c.4): a burst holds `halted`, a probe reading `true`
/// sends nothing, the probe reading `false` sends and keeps the line, and a
/// burst after it is dialed and acked (the mutant whose read only ever sets
/// the flag holds every later burst `halted` for the shell's life).
#[test]
fn the_halted_hold_ends_at_the_first_read_that_says_writes_go() {
    let g = ground();
    g.fake.writes_halted.store(true, Ordering::SeqCst);
    g.holds.note_health("b-1", &g.session.board.health().unwrap());
    let OpAnswer::Answered(Ok(held)) = g.holds.send_burst(&g.session, insert(DOC, json!(["hello"]), g.fake.head()), None) else { panic!("held before the dial") };
    assert_eq!(held["cause"], "halted", "{held}");
    g.holds.probe("b-1");
    assert_eq!(g.fake.sends(), 0, "a board whose writes are halted is sent nothing");
    g.fake.writes_halted.store(false, Ordering::SeqCst);
    g.holds.probe("b-1");
    assert_eq!(g.fake.sends(), 1, "the read that says writes go ends the hold");
    assert!(g.lines().is_empty());
    let OpAnswer::Answered(Ok(next)) = g.holds.send_burst(&g.session, insert(DOC, json!(["!"]), g.fake.head()), None) else { panic!("the burst was answered") };
    assert_eq!(next["resp"], "ack", "the hold has ended: {next}");
}

/// Checks that a third `durability` on a resent line holds it (§3c.4's rider).
///
/// A resent line's first and second `durability` are reissued at the next
/// probe, its third holds it `durability` — counted per line across the
/// resends — and the board taking writes again keeps it (the mutant that
/// never counts reissues the line forever).
#[test]
fn a_third_durability_on_a_resent_line_holds_it() {
    let g = ground();
    g.fake.op_rejected.every(retry("durability"));
    g.hold(&insert(DOC, json!(["hello"]), g.fake.head()), "unreachable", false);
    for (probe, cause) in [(1, "unreachable"), (2, "unreachable"), (3, "durability")] {
        g.holds.probe("b-1");
        assert_eq!((g.fake.sends(), g.lines()[0]["cause"].as_str()), (probe, Some(cause)), "probe {probe}");
    }
    g.fake.op_rejected.clear();
    g.holds.probe("b-1");
    assert_eq!(g.fake.sends(), 4);
    assert!(g.lines().is_empty() && g.states().contains(&"kept".to_string()));
}

/// Checks that a reused ordinal starts its reissues afresh.
///
/// The rider is counted per line (§3c.4), and the compaction starts the
/// ordinals again (§3c.3): a line reissued twice and then kept leaves the
/// queue empty, so the next line held takes ordinal 1 again — and its first
/// `durability` is reissued, never counted as the settled line's third (the
/// mutant that keeps a settled line's count holds the person's next burst at
/// its first `durability`).
#[test]
fn a_reused_ordinal_starts_its_reissues_afresh() {
    let g = ground();
    g.fake.op_rejected.next(2, retry("durability"));
    let first = g.hold(&insert(DOC, json!(["a"]), g.fake.head()), "unreachable", false);
    for _ in 0..3 {
        g.holds.probe("b-1");
    }
    assert_eq!(g.fake.sends(), 3, "reissued twice, then sent and kept");
    assert!(g.lines().is_empty(), "the line is kept and the queue empties");
    let again = g.hold(&insert(DOC, json!(["b"]), g.fake.head()), "unreachable", false);
    assert_eq!((first["held"].as_u64(), again["held"].as_u64()), (Some(1), Some(1)), "the ordinal is reused");
    g.fake.op_rejected.next(1, retry("durability"));
    g.holds.probe("b-1");
    assert_eq!((g.fake.sends(), g.lines()[0]["cause"].as_str()), (4, Some("unreachable")), "the new line's first `durability` is reissued");
}

/// Checks that a probe with no line standing dials nothing (§3c.4).
///
/// The probe reads `/health` only while a line stands: a probe over an
/// empty queue dials nothing; a line held is sent and kept by the next
/// probe, its one `/health` read the probe's own; and the probe after it,
/// the queue empty again, reads nothing more (the mutant that probes every
/// board at every cadence reads `/health` for the shell's life).
#[test]
fn a_probe_with_no_line_standing_dials_nothing() {
    let g = ground();
    let reads = || g.fake.health_reads.load(Ordering::SeqCst);
    g.holds.probe("b-1");
    assert_eq!((reads(), g.fake.sends()), (0, 0), "an empty queue is probed for nothing");
    g.hold(&insert(DOC, json!(["a"]), g.fake.head()), "unreachable", false);
    g.holds.probe("b-1");
    assert_eq!((reads(), g.fake.sends()), (1, 1), "a standing line is probed and sent");
    assert!(g.lines().is_empty(), "and kept");
    g.holds.probe("b-1");
    assert_eq!(reads(), 1, "the queue empty again, the probe reads nothing more");
}

/// Checks that a line held behind a landing reads past it at its next resend.
///
/// Two lines on one document, the first `sent: true` and found landed on a
/// lost row at 77, the second held behind it before the landing: the probe
/// keeps the first and the board does not take the second, held again
/// `sent: false`; the next probe reads it from 77, sends it and keeps it (the
/// mutant that leaves a line behind a kept one at its hold-time base faces
/// the person's own landing as a move).
#[test]
fn a_line_held_behind_a_landing_reads_past_it() {
    let g = ground();
    *g.fake.rows.lock().unwrap() = vec![lost_row()];
    *g.fake.text.lock().unwrap() = "hello".into();
    g.hold(&insert(DOC, json!(["hello"]), g.fake.head()), "unreachable", true);
    g.hold(&insert(DOC, json!(["!"]), g.fake.head()), "behind", false);
    g.fake.op_unreachable.store(true, Ordering::SeqCst);
    g.holds.probe("b-1");
    let lines = g.lines();
    assert_eq!((lines.len(), lines[0]["cause"].as_str(), lines[0]["base"].as_u64()), (1, Some("unreachable"), Some(77)), "{lines:?}");
    g.fake.op_unreachable.store(false, Ordering::SeqCst);
    g.fake.next_at.store(78, Ordering::SeqCst);
    g.holds.probe("b-1");
    let states = g.states();
    assert_eq!(g.fake.sends(), 1, "the second line is sent once");
    assert!(g.lines().is_empty() && states.contains(&"kept".to_string()) && !states.contains(&"moved".to_string()), "{states:?}");
}

/// Checks that a line behind an acked line reads past its ack.
///
/// Two lines on one document, both resent by one probe: the first acked at
/// 60, the second's answer lost — held again, `sent: true` — the board then
/// serving the first's row and, where the second landed, its row at 61. Over
/// an `insert`, whose site the read confirms, and a `delete`, whose site no
/// read confirms, the next probe reads the second from 60: resent and kept
/// where it did not land, kept and not resent where it did, never moved (the
/// mutant that keeps the hold-time base faces the person's own text as a
/// move, and keeps an unlanded `delete` unsent on the first line's row).
#[test]
fn a_line_behind_an_acked_line_reads_past_its_ack() {
    for (kind, landed) in [("insert", false), ("insert", true), ("delete", false), ("delete", true)] {
        let g = ground();
        g.fake.next_at.store(60, Ordering::SeqCst);
        g.fake.op_lost_at.store(2, Ordering::SeqCst);
        let frame = |value: &str| if kind == "insert" { insert(DOC, json!([value]), g.fake.head()) } else { delete(DOC, g.fake.head()) };
        g.hold(&frame("a"), "unreachable", false);
        g.hold(&frame("b"), "behind", false);
        g.holds.probe("b-1");
        let lines = g.lines();
        assert_eq!((g.fake.sends(), lines.len(), lines[0]["sent"].as_bool(), lines[0]["base"].as_u64()), (2, 1, Some(true), Some(60)), "{kind}, landed {landed}: {lines:?}");
        let own = |at: u64| json!({"at": at, "op": kind, "key": g.own_key(), "docs": [DOC]});
        *g.fake.rows.lock().unwrap() = if landed { vec![own(60), own(61)] } else { vec![own(60)] };
        *g.fake.text.lock().unwrap() = if landed { "ba" } else { "a" }.into();
        g.holds.probe("b-1");
        let states = g.states();
        assert_eq!(g.fake.sends(), if landed { 2 } else { 3 }, "{kind}, landed {landed}: sent again only where it did not land");
        assert!(g.lines().is_empty() && states.contains(&"kept".to_string()) && !states.contains(&"moved".to_string()), "{kind}, landed {landed}: {states:?}");
    }
}

/// Checks that a line held after a landing the read found reads past it.
///
/// A line `sent: true` is found landed on a lost row at 77 and kept; a line
/// held on the document afterwards, `sent: false`, while the board still
/// serves that row, takes 77 as its base, and the next probe sends it and
/// keeps it (the mutant that leaves a found landing out of the document's
/// base faces the person's own landing as a move).
#[test]
fn a_line_held_after_a_landing_the_read_found_reads_past_it() {
    let g = ground();
    *g.fake.rows.lock().unwrap() = vec![lost_row()];
    *g.fake.text.lock().unwrap() = "hello".into();
    g.hold(&insert(DOC, json!(["hello"]), g.fake.head()), "unreachable", true);
    g.holds.probe("b-1");
    assert!(g.lines().is_empty(), "the landed line is kept");
    g.hold(&insert(DOC, json!(["!"]), g.fake.head()), "unreachable", false);
    assert_eq!(g.lines()[0]["base"], 77, "the landing is the document's base");
    g.fake.next_at.store(78, Ordering::SeqCst);
    g.holds.probe("b-1");
    let states = g.states();
    assert_eq!(g.fake.sends(), 1, "the line is sent");
    assert!(g.lines().is_empty() && states.contains(&"kept".to_string()) && !states.contains(&"moved".to_string()), "{states:?}");
}

/// Arms the fake's next send to lose its answer, the `n`-th try's way.
///
/// The ways come in turn: a timeout, a garbled answer, and the board's
/// handler panicking (`500 internal_panic`).
fn lose_the_next_answer(g: &Ground, n: u32) {
    match n % 3 {
        0 => g.fake.op_lost.next(1, Lost::Timeout),
        1 => g.fake.op_lost.next(1, Lost::Garbled),
        _ => g.fake.op_refused.next(1, (500, json!({"error": "internal_panic"}))),
    }
}

/// Checks that a line whose resends lose their answer is handed over.
///
/// It is handed over at its deadline (§3c.4; skep #716). A line held before any
/// dial — a connection never made, its clock not started — is resent at each
/// probe, each answer lost: a timeout, a garbled answer and the board's handler
/// panicking in turn, the first its first failed send. Ninety seconds after it
/// the line holds, resent, `not_resolvable`; once `HAND_OVER_DEADLINE` stands
/// past, the next probe's read runs, finds no landing and hands it to the
/// person undialed: a refused run under `answers_lost`, its refusal
/// `{kind, name, last, elapsed_ms}` naming the last failure and the time since
/// the first, its `sent` kept, said once on TALK and `refused` on the `held`
/// event. A burst after it is held `behind`, and the probe dials nothing more;
/// the person's `send` hands the line back, its clock afresh, and the next
/// probe sends and keeps both. The mutant that never starts the clock resends
/// it for ever; the one that keeps the clock at the person's `send` hands it
/// straight back.
#[test]
fn a_line_whose_resends_lose_their_answer_is_handed_to_the_person() {
    let g = ground();
    let k = g.hold(&insert(DOC, json!(["a"]), g.fake.head()), "unreachable", false)["held"].as_u64().unwrap();
    for n in 0..4 {
        lose_the_next_answer(&g, n);
        g.holds.probe("b-1");
        g.holds.advance(Duration::from_secs(30));
    }
    let lines = g.lines();
    assert_eq!((g.fake.sends(), lines[0]["cause"].as_str(), lines[0]["sent"].as_bool()), (4, Some("unreachable"), Some(true)), "{lines:?}");
    assert_eq!(g.holds.resolve(&g.session, k, ResolveAct::Drop).unwrap_err().name(), "not_resolvable", "the board's to answer still");
    g.holds.advance(Duration::from_secs(1));
    let _ = g.states();
    let reads = g.fake.changes_reads.load(Ordering::SeqCst);
    g.holds.probe("b-1");
    let lines = g.lines();
    assert_eq!((g.fake.sends(), g.fake.changes_reads.load(Ordering::SeqCst)), (4, reads + 1), "read first, then handed over undialed");
    assert_eq!((lines[0]["cause"].as_str(), lines[0]["sent"].as_bool()), (Some("answers_lost"), Some(true)), "{lines:?}");
    let refusal = &lines[0]["refusal"];
    let members: Vec<&str> = refusal.as_object().unwrap().keys().map(String::as_str).collect();
    assert_eq!((members.len(), refusal["kind"].as_str(), refusal["name"].as_str(), refusal["last"].as_str()), (4, Some("shell"), Some("answers_lost"), Some("unreachable")), "{refusal}");
    let elapsed = refusal["elapsed_ms"].as_u64().unwrap();
    assert!((121_000..181_000).contains(&elapsed), "the time since the first failed send: {refusal}");
    assert_eq!(g.states(), ["refused"]);
    let said = g.said.lock().unwrap().clone();
    let line = format!("held: line {k} on {DOC}: no landing {} s after its first failed send (last: unreachable); it is handed to the person, who may send it again or drop it", elapsed / 1000);
    assert_eq!(said.iter().filter(|l| **l == line).count(), 1, "said once: {said:?}");
    let OpAnswer::Answered(Ok(behind)) = g.holds.send_burst(&g.session, insert(DOC, json!(["b"]), g.fake.head()), None) else { panic!("held behind the line handed over") };
    assert_eq!(behind["cause"], "behind", "{behind}");
    g.holds.probe("b-1");
    assert_eq!(g.fake.sends(), 4, "the lines wait for the person's act");
    assert_eq!(g.holds.resolve(&g.session, k, ResolveAct::Send).unwrap(), Resolved::HandedBack);
    let lines = g.lines();
    assert_eq!((lines[0]["cause"].as_str(), lines[0]["sent"].as_bool()), (Some("behind"), Some(true)), "the person's send keeps `sent`: {lines:?}");
    g.holds.probe("b-1");
    assert_eq!(g.fake.sends(), 6, "both lines sent, the clock afresh");
    assert!(g.lines().is_empty() && g.states().contains(&"kept".to_string()));
}

/// Checks that a line handed over whose write landed is kept at the send.
///
/// A line handed to the person at its deadline keeps its `sent`, and the
/// person's `send` keeps it: where the write whose answer the board lost has
/// landed after all — a row whose testimony the board lost, the line's values
/// at its site — the next probe's read finds it and keeps the line, never
/// sending it twice (§3c.5; skep #608; the mutant whose `send` re-marks the
/// line `sent: false` faces the person's own text `moved`).
#[test]
fn a_handed_over_line_whose_write_landed_is_kept_at_the_persons_send() {
    let g = ground();
    let k = g.hold(&insert(DOC, json!(["hello"]), g.fake.head()), "unreachable", true)["held"].as_u64().unwrap();
    g.fake.op_refused.next(1, (500, json!({"error": "internal_panic"})));
    g.holds.probe("b-1");
    g.holds.advance(HAND_OVER_DEADLINE);
    g.holds.probe("b-1");
    assert_eq!(g.lines()[0]["cause"], "answers_lost", "handed to the person");
    *g.fake.rows.lock().unwrap() = vec![lost_row()];
    *g.fake.text.lock().unwrap() = "hello".into();
    assert_eq!(g.holds.resolve(&g.session, k, ResolveAct::Send).unwrap(), Resolved::HandedBack);
    let _ = g.states();
    g.holds.probe("b-1");
    let states = g.states();
    assert_eq!(g.fake.sends(), 1, "never sent twice");
    assert!(g.lines().is_empty() && states.contains(&"kept".to_string()) && !states.contains(&"moved".to_string()), "{states:?}");
}

/// Checks that a line whose last lost answer landed is never handed over.
///
/// Before a line is handed to the person its read runs the landed test
/// (§3c.5): a line whose first dial and resend lost their answer, its clock
/// far past `HAND_OVER_DEADLINE`, the last write then found landed — a row
/// whose testimony the board lost, the line's values at its site — is kept
/// at the next probe, never refused and never sent again (skep #608; the
/// mutant that hands the line over before its read refuses text the board
/// holds).
#[test]
fn a_line_whose_last_lost_answer_landed_is_kept_never_handed_over() {
    let g = ground();
    g.hold(&insert(DOC, json!(["hello"]), g.fake.head()), "unreachable", true);
    g.fake.op_refused.next(1, (500, json!({"error": "internal_panic"})));
    g.holds.probe("b-1");
    g.holds.advance(HAND_OVER_DEADLINE * 2);
    *g.fake.rows.lock().unwrap() = vec![lost_row()];
    *g.fake.text.lock().unwrap() = "hello".into();
    let _ = g.states();
    g.holds.probe("b-1");
    assert_eq!(g.states(), ["kept"]);
    assert_eq!(g.fake.sends(), 1, "never sent again");
    assert!(g.lines().is_empty(), "kept, never refused");
}

/// Checks that a connection never made starts no clock.
///
/// Where every resend fails at the connect — the board not answering, no
/// request leaving — no send failed: the line holds `unreachable` with the
/// clock moved far past `HAND_OVER_DEADLINE` between the probes,
/// `not_resolvable`, never handed over, until the board answers and the next
/// probe sends and keeps it (§3c.4; the mutant that reads a connection never
/// made as a failed send — off the dial's answer, or off the line's `sent`,
/// which its resend marked before the dial — hands an outage's line to the
/// person).
#[test]
fn a_connection_never_made_starts_no_clock() {
    let g = ground();
    let k = g.hold(&insert(DOC, json!(["a"]), g.fake.head()), "unreachable", false)["held"].as_u64().unwrap();
    g.fake.op_unreachable.store(true, Ordering::SeqCst);
    for _ in 0..3 {
        g.holds.probe("b-1");
        g.holds.advance(HAND_OVER_DEADLINE * 10);
    }
    g.holds.probe("b-1");
    assert_eq!((g.fake.sends(), g.lines()[0]["cause"].as_str()), (0, Some("unreachable")));
    assert_eq!(g.holds.resolve(&g.session, k, ResolveAct::Drop).unwrap_err().name(), "not_resolvable");
    g.fake.op_unreachable.store(false, Ordering::SeqCst);
    g.holds.probe("b-1");
    assert_eq!(g.fake.sends(), 1, "the board answering, the line is sent");
    assert!(g.lines().is_empty() && g.states().contains(&"kept".to_string()));
}

/// Checks that a line that may have landed stays so through resends that
/// never left.
///
/// A line held `sent: true`, its first dial's answer lost, is resent at each
/// probe, and each resend never leaves: its signature not made over a head
/// record that cannot be read, or its connection never made. Through the
/// probes the line stands `sent: true`, nothing dialed; and where the earlier
/// write has landed after all — a row whose testimony the board lost, the
/// line's values at its site — the next probe's read keeps it, never sent
/// twice (§3c.2; the mutant that re-marks with the resend's own `sent` faces
/// the person's own text `moved`).
#[test]
fn a_line_that_may_have_landed_stays_so_through_resends_that_never_left() {
    for (cell, unreadable_head, cause) in [("a head record that cannot be read", true, "head_unreadable"), ("a connection never made", false, "unreachable")] {
        let fake = Fake::new();
        if unreadable_head {
            *fake.head_answer.lock().unwrap() = Some((200, json!({"resp": "delivery", "items": [{"atom": "not a head record"}]})));
        }
        let store = TempDir::new().unwrap();
        let facts = writer_facts(&store);
        let g = ground_over(fake, store, facts, 0);
        g.fake.op_unreachable.store(!unreadable_head, Ordering::SeqCst);
        g.hold(&insert(DOC, json!(["hello"]), g.fake.head()), "unreachable", true);
        for _ in 0..3 {
            g.holds.probe("b-1");
        }
        let lines = g.lines();
        assert_eq!((g.fake.sends(), lines[0]["cause"].as_str(), lines[0]["sent"].as_bool()), (0, Some(cause), Some(true)), "{cell}: {lines:?}");
        *g.fake.head_answer.lock().unwrap() = None;
        g.fake.op_unreachable.store(false, Ordering::SeqCst);
        *g.fake.rows.lock().unwrap() = vec![lost_row()];
        *g.fake.text.lock().unwrap() = "hello".into();
        let _ = g.states();
        g.holds.probe("b-1");
        let states = g.states();
        assert_eq!(g.fake.sends(), 0, "{cell}: never sent twice");
        assert!(g.lines().is_empty() && states.contains(&"kept".to_string()) && !states.contains(&"moved".to_string()), "{cell}: {states:?}");
    }
}

/// Checks that the hand-over deadline is two minutes (§3c.4).
///
/// It is the number the deadline was given, and the words the shift's
/// refusal past it states it in, as the MCP tools' `held` card does ("two
/// minutes after the line's first failed send").
#[test]
fn the_hand_over_deadline_is_two_minutes() {
    assert_eq!(HAND_OVER_DEADLINE, Duration::from_secs(2 * 60));
    let past = crate::hold::resend::Unshiftable::PastTheDeadline { elapsed_ms: 120_000 }.to_string();
    assert_eq!(past, "its first failed send was 120 s ago, past the two-minute deadline");
}

/// Checks that a resent line held `durability` is handed over at its deadline.
///
/// It is skep #720's `durability` loop. A line's resends meet the board's
/// failed durability barrier: the first two reissued at the next probe, the
/// third holding it `durability`, each a failed send, the first starting its
/// clock; it is resent at the probe after and held again. With the clock past
/// `HAND_OVER_DEADLINE` the next probe's read finds no landing and hands it to
/// the person under `answers_lost`, its `last` `durability`, dialed never again
/// (the mutant that starts no clock at a reissue or a `durability` hold resends
/// it for ever).
#[test]
fn a_resent_line_held_durability_is_handed_over_at_its_deadline() {
    let g = ground();
    g.fake.op_rejected.every(retry("durability"));
    g.hold(&insert(DOC, json!(["hello"]), g.fake.head()), "unreachable", false);
    for (probe, cause) in [(1, "unreachable"), (2, "unreachable"), (3, "durability"), (4, "durability")] {
        g.holds.probe("b-1");
        assert_eq!((g.fake.sends(), g.lines()[0]["cause"].as_str()), (probe, Some(cause)), "probe {probe}");
    }
    g.holds.advance(HAND_OVER_DEADLINE);
    g.holds.probe("b-1");
    let lines = g.lines();
    assert_eq!(g.fake.sends(), 4, "handed over at the next probe's read, undialed");
    assert_eq!((lines[0]["cause"].as_str(), lines[0]["refusal"]["last"].as_str()), (Some("answers_lost"), Some("durability")), "{lines:?}");
    g.holds.probe("b-1");
    assert_eq!(g.fake.sends(), 4, "dialed never again until the person's act");
}

/// Checks that a resend's `write_busy` past its reissue runs to the deadline.
///
/// It is skep #720's `write_busy` loop. A line's resends meet `write_busy` at
/// every probe: the first reissued at the next probe, every one after it past
/// its one reissue — a reissue-class answer at its count — the line standing
/// for the next probe, never handed over at once, the clock running from the
/// first; "sent again" said once. With the clock past `HAND_OVER_DEADLINE` the
/// next probe's read finds no landing and hands it to the person under
/// `answers_lost`, its `last` `write_busy` (the mutant that starts no clock
/// there resends it for ever; the one that hands every code the table holds
/// nowhere over at once, `write_busy` among them, hands the person a line a
/// busy board would take in a moment; the one that says "sent again" at every
/// probe fills the log).
#[test]
fn a_write_busy_past_its_reissue_at_a_resend_runs_the_clock_to_its_deadline() {
    let g = ground();
    g.fake.op_refused.every((503, json!({"error": "write_busy"})));
    let k = g.hold(&insert(DOC, json!(["hello"]), g.fake.head()), "unreachable", false)["held"].as_u64().unwrap();
    for probe in 1..=3 {
        g.holds.probe("b-1");
        let lines = g.lines();
        assert_eq!((g.fake.sends(), lines[0]["cause"].as_str()), (probe, Some("unreachable")), "probe {probe}: the line stands for the next: {lines:?}");
    }
    let said = g.said.lock().unwrap().clone();
    let again = format!("held: line {k} on {DOC} was not taken (");
    assert_eq!(said.iter().filter(|l| l.starts_with(&again) && l.ends_with("it is sent again at the next probe")).count(), 1, "said once: {said:?}");
    g.holds.advance(HAND_OVER_DEADLINE);
    g.holds.probe("b-1");
    let lines = g.lines();
    assert_eq!(g.fake.sends(), 3, "handed over at the next probe's read, undialed");
    assert_eq!((lines[0]["cause"].as_str(), lines[0]["refusal"]["last"].as_str()), (Some("answers_lost"), Some("write_busy")), "{lines:?}");
}

/// Checks that the deadline runs from the first failed send, not the last.
///
/// It is skep #722's patchy link. A line loses an answer at one probe, its
/// first failed send; then meets connections never made for a while, which
/// start nothing and stop nothing; then loses another. Ninety seconds after the
/// first failure it holds; 121 seconds after it — 31 after the last — the next
/// probe's read finds no landing and hands it over, its `elapsed_ms` counted
/// from the first (the mutant that runs the clock from the last failure holds
/// the line past its deadline, and a flaky board's line for ever).
#[test]
fn the_deadline_runs_from_the_first_failure_not_the_last() {
    let g = ground();
    g.hold(&insert(DOC, json!(["a"]), g.fake.head()), "unreachable", false);
    lose_the_next_answer(&g, 0);
    g.holds.probe("b-1");
    g.fake.op_unreachable.store(true, Ordering::SeqCst);
    for _ in 0..2 {
        g.holds.advance(Duration::from_secs(30));
        g.holds.probe("b-1");
    }
    g.fake.op_unreachable.store(false, Ordering::SeqCst);
    g.holds.advance(Duration::from_secs(30));
    lose_the_next_answer(&g, 1);
    g.holds.probe("b-1");
    assert_eq!((g.fake.sends(), g.lines()[0]["cause"].as_str()), (2, Some("unreachable")), "two answers lost, ninety seconds from the first: the line holds");
    g.holds.advance(Duration::from_secs(31));
    let reads = g.fake.changes_reads.load(Ordering::SeqCst);
    g.holds.probe("b-1");
    let lines = g.lines();
    assert_eq!((g.fake.sends(), g.fake.changes_reads.load(Ordering::SeqCst)), (2, reads + 1), "read first, then handed over undialed");
    assert_eq!(lines[0]["cause"], "answers_lost", "{lines:?}");
    assert!(lines[0]["refusal"]["elapsed_ms"].as_u64().is_some_and(|ms| ms >= 121_000), "counted from the first failure: {lines:?}");
}

/// Checks that the first dial's lost answer starts the line's clock (§3c.4).
///
/// The person's own first dial is the line's first failed send where its
/// answer is lost: the burst answered `held`, `sent: true`, its clock started
/// then. Its resends lose their answer too; ninety seconds after the first
/// dial it holds, and 121 seconds after it — 61 after its first resend — the
/// next probe's read finds no landing and hands it over, `elapsed_ms`
/// counted from the first dial (the mutant that starts a line's clock at a
/// resend alone holds the line a minute past its deadline).
#[test]
fn the_first_dials_lost_answer_starts_the_clock() {
    let g = ground();
    g.fake.op_lost.next(1, Lost::Timeout);
    let OpAnswer::Answered(Ok(held)) = g.holds.send_burst(&g.session, insert(DOC, json!(["a"]), g.fake.head()), None) else { panic!("held, its answer lost") };
    assert_eq!((held["cause"].as_str(), g.lines()[0]["sent"].as_bool()), (Some("unreachable"), Some(true)), "{held}");
    g.holds.advance(Duration::from_secs(60));
    lose_the_next_answer(&g, 1);
    g.holds.probe("b-1");
    g.holds.advance(Duration::from_secs(30));
    lose_the_next_answer(&g, 2);
    g.holds.probe("b-1");
    assert_eq!((g.fake.sends(), g.lines()[0]["cause"].as_str()), (3, Some("unreachable")), "ninety seconds from the first dial: the line holds, resent");
    g.holds.advance(Duration::from_secs(31));
    g.holds.probe("b-1");
    let lines = g.lines();
    assert_eq!(g.fake.sends(), 3, "handed over undialed");
    assert_eq!(lines[0]["cause"], "answers_lost", "121 s from the first dial, 61 s from the first resend: {lines:?}");
    assert!(lines[0]["refusal"]["elapsed_ms"].as_u64().is_some_and(|ms| ms >= 121_000), "counted from the first dial: {lines:?}");
}

/// Checks that "sent again" is said once per change of the failure.
///
/// It is said as the failure changes (§3c.4; skep #720). A line held before any
/// dial is resent at seven probes: three answers lost — a timeout, a garbled
/// answer, the board's handler panicking, one failure — then three
/// `write_busy`, the first reissued and the two past its reissue faced, then a
/// `durability` reissued. The shell's window says "it is sent again at the next
/// probe" three times: at the first lost answer, at the first `write_busy` and
/// at the `durability`, each a change of the failure; the probes failing alike
/// say nothing more (the mutant that says it at every probe fills the log with
/// seven).
#[test]
fn sent_again_is_said_once_per_change_of_the_failure() {
    let g = ground();
    let k = g.hold(&insert(DOC, json!(["a"]), g.fake.head()), "unreachable", false)["held"].as_u64().unwrap();
    for n in 0..3 {
        lose_the_next_answer(&g, n);
        g.holds.probe("b-1");
    }
    g.fake.op_refused.every((503, json!({"error": "write_busy"})));
    for _ in 0..3 {
        g.holds.probe("b-1");
    }
    g.fake.op_refused.clear();
    g.fake.op_rejected.next(1, retry("durability"));
    g.holds.probe("b-1");
    assert_eq!((g.fake.sends(), g.lines().len()), (7, 1), "seven probes, the line standing");
    let said = g.said.lock().unwrap().clone();
    let line = format!("held: line {k} on {DOC} was not taken (");
    let again: Vec<&String> = said.iter().filter(|l| l.starts_with(&line) && l.ends_with("it is sent again at the next probe")).collect();
    assert_eq!(again.len(), 3, "once per change: {said:?}");
    assert!(again[0].contains("unreachable") && again[1].contains("write_busy") && again[2].contains("durability"), "{again:?}");
}

/// Checks that a resend marks its line `sent` on disk before it dials.
///
/// The mark is written ahead of the dial, synced (§3c.2's `sent`): the held
/// file read as the resend's dial leaves holds the line re-marked `sent:
/// true`, so a crash at the dial leaves a line that may have landed read as
/// one; a line marked so already is written no line more. A resend whose
/// attest cannot be composed — over a head record that cannot be read —
/// dials nothing and marks nothing, the line `sent: false` still (the
/// mutants that mark the line after its answer, or never; the one that marks
/// it before the attest reads a write that never left as one that may have
/// landed).
#[test]
fn a_resend_marks_its_line_sent_on_disk_before_it_dials() {
    for sent in [false, true] {
        let g = ground();
        g.hold(&insert(DOC, json!(["hello"]), g.fake.head()), "unreachable", sent);
        let (file, at_the_dial) = (held_file(&g), Arc::new(Mutex::new(Vec::new())));
        let seen = Arc::clone(&at_the_dial);
        *g.fake.at_send.lock().unwrap() = Some(Box::new(move || seen.lock().unwrap().push(std::fs::read_to_string(&file).unwrap_or_default())));
        g.holds.probe("b-1");
        let files: Vec<String> = at_the_dial.lock().unwrap().clone();
        let [text] = &files[..] else { panic!("sent {sent}: one dial: {files:?}") };
        let marks: Vec<Value> = text.lines().skip(1).map(|line| serde_json::from_str::<Value>(line).unwrap()).filter(|line| line["held"] == 1).collect();
        assert_eq!(marks.last().map(|line| &line["sent"]), Some(&json!(true)), "sent {sent}: the line is marked before its dial: {text}");
        assert_eq!(marks.len(), if sent { 1 } else { 2 }, "sent {sent}: a line marked so already is written no line more: {text}");
        assert!(g.lines().is_empty() && g.states().contains(&"kept".to_string()), "sent {sent}: acked and kept");
    }
    let fake = Fake::new();
    *fake.head_answer.lock().unwrap() = Some((200, json!({"resp": "delivery", "items": [{"atom": "not a head record"}]})));
    let store = TempDir::new().unwrap();
    let facts = writer_facts(&store);
    let g = ground_over(fake, store, facts, 0);
    g.hold(&insert(DOC, json!(["hello"]), g.fake.head()), "unreachable", false);
    g.holds.probe("b-1");
    let lines = g.lines();
    assert_eq!((g.fake.sends(), lines[0]["cause"].as_str(), lines[0]["sent"].as_bool()), (0, Some("head_unreadable"), Some(false)), "no dial, no mark: {lines:?}");
}

/// Checks that a line acked whose `done` was refused relaunches `sent` and is
/// kept (skep #710).
///
/// A resend's ack comes and its `done` is refused by the device — the held
/// file moved aside under the dial and a directory left at its name — so the
/// line stands on disk as held; the relaunch over the same store reads it
/// `sent: true`, the mark its resend wrote before the dial, and the read
/// finds the line's own landing and keeps it, never faced `moved` and never
/// sent twice (the mutant that marks no line before its dial relaunches it
/// `sent: false`, and the read faces the person's own text `moved`).
#[test]
fn a_line_acked_whose_done_was_refused_relaunches_sent_and_is_kept() {
    let g = ground();
    let own = g.own_key();
    g.hold(&insert(DOC, json!(["hello"]), g.fake.head()), "unreachable", false);
    let file = held_file(&g);
    let aside = file.with_extension("aside");
    let (from, to) = (file.clone(), aside.clone());
    *g.fake.at_send.lock().unwrap() = Some(Box::new(move || {
        std::fs::rename(&from, &to).unwrap();
        std::fs::create_dir(&from).unwrap();
    }));
    g.holds.probe("b-1");
    *g.fake.at_send.lock().unwrap() = None;
    assert!(g.lines().is_empty() && g.fake.sends() == 1, "the line is resent and acked");
    let said = g.said.lock().unwrap().clone();
    assert!(said.iter().any(|line| line.starts_with("held: line 1 is settled, and its `done` could not be written")), "the refused `done` is said: {said:?}");
    // The relaunch: this run's holds gone, the file standing as the refused
    // `done` left it, the board serving the line's own landing at its ack.
    let Ground { holds, fake, session, store, .. } = g;
    drop(holds);
    std::fs::remove_dir(&file).unwrap();
    std::fs::rename(&aside, &file).unwrap();
    *fake.rows.lock().unwrap() = vec![json!({"at": 50, "op": "insert", "key": own, "docs": [DOC]})];
    *fake.text.lock().unwrap() = "hello".into();
    let g = ground_over(fake, store, session.facts.clone(), 0);
    let lines = g.lines();
    assert_eq!((lines.len(), lines[0]["sent"].as_bool()), (1, Some(true)), "the relaunch reads the line as one that may have landed: {lines:?}");
    g.holds.probe("b-1");
    let states = g.states();
    assert_eq!(g.fake.sends(), 1, "never sent twice");
    assert!(g.lines().is_empty() && states.contains(&"kept".to_string()) && !states.contains(&"moved".to_string()), "{states:?}");
}

/// Checks that a `sent` head whose own row stands and whose site confirms
/// is kept and never shifted (skep #442; the landed test first).
///
/// The line — `hello` typed between `a` and `b`, carrying both as its
/// anchors — had its first dial's answer lost, and landed at 77: the row of
/// the own hand stands since `base`, the text at its site. The document's
/// arrangement has moved past the line's typed state, so a dial would be
/// refused and shifted; but the read comes first, finds the landing and
/// keeps the line: nothing dialed, no image read, never faced moved (the
/// mutant that shifts before the read sends the person's words a second
/// time — or, the span between the anchors holding the words that landed,
/// faces them moved).
#[test]
fn a_sent_head_whose_own_row_stands_and_whose_site_confirms_is_kept_and_never_shifted() {
    let g = ground();
    let typed = g.fake.head();
    g.hold_anchored(&insert_at(DOC, 2, json!(["hello"]), typed), anchors(Some(&i(1)), Some(&i(2))), "unreachable", true);
    *g.fake.rows.lock().unwrap() = vec![json!({"at": 77, "op": "insert", "key": g.own_key(), "docs": [DOC]})];
    *g.fake.text.lock().unwrap() = "ahellob".into();
    *g.fake.image.lock().unwrap() = vec![run(&i(1), 1), run(&i(10), 5), run(&i(2), 1)];
    g.fake.move_arrangement(DOC, 77);
    g.holds.probe("b-1");
    assert_eq!((g.fake.sends(), g.fake.image_reads.load(Ordering::SeqCst), g.fake.changes_reads.load(Ordering::SeqCst)), (0, 0, 1), "the landed head is read once, never dialed and never shifted");
    assert!(g.lines().is_empty(), "kept");
    assert_eq!(g.states(), ["holding", "kept"], "never faced moved");
}

/// Checks that a resent line refused stale is shifted and kept (skep #442).
///
/// The line is refused as typed against an older state of its document, and
/// shifted through the change. A held delete of `b` and `c` — `abc` as the page
/// read it, the `before` anchor `a`, no `after`, and its span the I-run of `b`
/// and `c` — held before any dial; another writer put `XY` before the text and
/// the arrangement moved to 77. The probe reads nothing of a head never sent,
/// dials it, meets the refusal, shifts it by one image read — `a` two positions
/// later, the two positions after it whole to the document's end — writes the
/// shifted frame to the line before the shifted dial, marked `sent` under the
/// cause it had, and dials it again: `p` moved by two, the width kept, typed at
/// the read's state; acked and kept, the file gone, never faced moved (the
/// mutant that re-faces the resend moved holds text the shell could place; the
/// one that dials before the rewrite leaves a relaunch the page's positions).
#[test]
fn a_resent_line_refused_stale_is_shifted_through_the_change_and_kept() {
    let g = ground();
    let typed = g.fake.head();
    g.hold_anchored(&delete_at(DOC, 2, 2, typed), spanned(Some(&i(1)), None, &[(&i(2), 2)]), "unreachable", false);
    *g.fake.image.lock().unwrap() = vec![run(&i(10), 2), run(&i(1), 3)];
    g.fake.move_arrangement(DOC, 77);
    let (file, at_the_dial) = (held_file(&g), Arc::new(Mutex::new(Vec::new())));
    let seen = Arc::clone(&at_the_dial);
    *g.fake.at_send.lock().unwrap() = Some(Box::new(move || seen.lock().unwrap().push(std::fs::read_to_string(&file).unwrap_or_default())));
    g.holds.probe("b-1");
    let sent = g.fake.sends.lock().unwrap().clone();
    let reads = (g.fake.image_reads.load(Ordering::SeqCst), g.fake.changes_reads.load(Ordering::SeqCst));
    assert_eq!((sent.len(), reads), (2, (1, 0)), "refused once, shifted by one image read, no history read, sent again");
    assert_eq!((sent[0]["p"]["ordinal"].as_str(), sent[0]["as_of"].as_u64()), (Some("2"), Some(typed)), "the line as held: {sent:?}");
    assert_eq!((sent[1]["p"]["ordinal"].as_str(), sent[1]["width"].as_str(), sent[1]["as_of"].as_u64()), (Some("4"), Some("2"), Some(77)), "the delete's `p` moved by two, its width kept, typed at the read's state: {sent:?}");
    let files = at_the_dial.lock().unwrap().clone();
    let last = file_lines(&files[1]);
    let last = last.last().expect("the line on disk at the shifted dial");
    assert_eq!((last["frame"]["p"]["ordinal"].as_str(), last["sent"].as_bool(), last["cause"].as_str()), (Some("4"), Some(true), Some("unreachable")), "the shifted frame on the line before the shifted dial, its cause kept: {}", files[1]);
    assert!(g.lines().is_empty() && !held_file(&g).exists(), "kept, the file gone");
    assert_eq!(g.states(), ["holding", "sending", "kept"], "shifted and kept, never moved");
}

/// Checks that a rearrange landed unseen is held moved, never applied twice.
///
/// The read cannot see the landing (skep #751). A rearrange of `abcd` swapping
/// `b` and `c` — cuts 2, 3 and 4, its anchors `a` and `d`, its span the I-run
/// of `b` and `c` — met a `poisoned` answer, its line `sent`, and landed at the
/// board's restart: the document reads `acbd`, its arrangement moved to 77, and
/// the read finds no landing it can take — the row the restart replayed has
/// lost its testimony, or the feed's history is reclaimed, and no read confirms
/// a rearrange's site. The resend dials the line, the board refuses it as typed
/// against the older state, and the shift finds the span's own units between
/// the anchors in another order: the line is held moved, `sent` kept, one dial
/// made and one image read, the swap applied once (the mutant that judges the
/// span by its count alone shifts by nothing and dials the swap again, putting
/// `b` and `c` back where they stood before the person moved them).
#[test]
fn a_rearrange_that_landed_unseen_is_held_moved_and_never_applied_twice() {
    for reclaimed in [false, true] {
        let g = ground();
        let typed = g.fake.head();
        let swap = rearrange_at(DOC, &[2, 3, 4], typed);
        g.hold_anchored(&swap, spanned(Some(&i(1)), Some(&i(4)), &[(&i(2), 2)]), "poisoned", true);
        if reclaimed {
            *g.fake.changes_refused.lock().unwrap() = Some((410, json!({"error": "history_reclaimed", "floor": 90})));
        } else {
            *g.fake.rows.lock().unwrap() = vec![lost_row()];
        }
        *g.fake.image.lock().unwrap() = vec![run(&i(1), 1), run(&i(3), 1), run(&i(2), 1), run(&i(4), 1)];
        g.fake.move_arrangement(DOC, 77);
        g.holds.probe("b-1");
        assert_eq!((g.fake.sends(), g.fake.image_reads.load(Ordering::SeqCst)), (1, 1), "reclaimed {reclaimed}: refused once and not shifted: the swap is dialed no second time");
        let lines = g.lines();
        assert_eq!((lines.len(), lines[0]["cause"].as_str(), lines[0]["sent"].as_bool()), (1, Some("moved"), Some(true)), "reclaimed {reclaimed}: {lines:?}");
        assert_eq!(lines[0]["frame"], swap, "reclaimed {reclaimed}: the frame as the page composed it");
        assert_eq!(g.states(), ["holding", "sending", "moved"], "reclaimed {reclaimed}");
        let talk = g.said.lock().unwrap().clone();
        let why = "was not shifted (the span its anchors bound no longer holds the units the burst names";
        assert_eq!(talk.iter().filter(|l| l.contains(why)).count(), 1, "reclaimed {reclaimed}: said why, once: {talk:?}");
    }
}

/// Checks that the shifts and the lost answers meet the one deadline.
///
/// It is the shift's bound (skep #442, #716). A line held before any dial loses
/// its answer at one probe — its first failed send, the clock started — and
/// sixty seconds pass; then another writer's change lands as each dial reaches
/// the board, twenty seconds passing at each: the next probe's read finds no
/// landing, the dial is refused, and the line is shifted and refused again —
/// each refusal a failed send — until its first failed send, the lost answer,
/// stands two minutes past: two shifts made, the third not, the line held moved
/// and the deadline said once. The person's `send` starts the clock afresh: the
/// other writer's change landing twice more, the next probe sends, shifts twice
/// and keeps it (the mutant that runs the shifts on a clock of their own, from
/// the first refusal, shifts the line past its deadline; the one whose `send`
/// keeps the clock holds the line moved again at its first shift).
#[test]
fn the_shifts_and_the_lost_answers_meet_the_one_deadline() {
    let g = ground();
    let typed = g.fake.head();
    let k = g.hold_anchored(&insert_at(DOC, 2, json!(["x"]), typed), anchors(Some(&i(1)), Some(&i(2))), "unreachable", false)["held"].as_u64().unwrap();
    lose_the_next_answer(&g, 0);
    g.holds.probe("b-1");
    assert_eq!(g.fake.sends(), 1, "one answer lost: the line's first failed send");
    g.holds.advance(Duration::from_secs(60));
    *g.fake.image.lock().unwrap() = vec![run(&i(1), 3)];
    // The other writer's change lands as each dial reaches the board, for
    // as many dials as are left to it, twenty seconds passing at each.
    let changes_left = Arc::new(AtomicUsize::new(usize::MAX));
    let (fake, left, holds) = (Arc::clone(&g.fake), Arc::clone(&changes_left), Arc::downgrade(&g.holds));
    *g.fake.at_send.lock().unwrap() = Some(Box::new(move || {
        if left.try_update(Ordering::SeqCst, Ordering::SeqCst, |n| n.checked_sub(1)).is_ok() {
            let at = fake.next_at.fetch_add(1, Ordering::SeqCst);
            fake.move_arrangement(DOC, at);
            if let Some(holds) = holds.upgrade() {
                holds.advance(Duration::from_secs(20));
            }
        }
    }));
    let _ = g.states();
    g.holds.probe("b-1");
    assert_eq!((g.fake.sends(), g.fake.image_reads.load(Ordering::SeqCst)), (1 + 1 + 2, 2), "refused, shifted and refused again until two minutes from the lost answer: then held");
    let lines = g.lines();
    assert_eq!((lines[0]["cause"].as_str(), lines[0]["sent"].as_bool(), lines[0]["refusal"]["code"].as_str()), (Some("moved"), Some(true), Some("arrangement_moved")), "{lines:?}");
    assert_eq!(g.states(), ["sending", "moved"]);
    let talk = g.said.lock().unwrap().clone();
    assert_eq!(talk.iter().filter(|l| l.starts_with(&format!("held: line {k} on {DOC} was not shifted (its first failed send was ")) && l.contains(" s ago, past the two-minute deadline)")).count(), 1, "{talk:?}");
    changes_left.store(2, Ordering::SeqCst);
    assert_eq!(g.holds.resolve(&g.session, k, ResolveAct::Send).unwrap(), Resolved::HandedBack);
    g.holds.probe("b-1");
    assert_eq!((g.fake.sends(), g.fake.image_reads.load(Ordering::SeqCst)), (4 + 3, 2 + 2), "the person's send starts the clock afresh: refused, shifted and refused once more, shifted again and kept");
    assert!(g.lines().is_empty() && g.states().contains(&"kept".to_string()));
}

/// Checks that a moved document's lines keep each its own `sent` (§3c.2).
///
/// Two lines on a document — the first `sent: true`, an earlier answer of it
/// lost, the second held `behind` it, `sent: false` — and the board refusing
/// the first's resend as typed against an older state: the document is faced
/// moved, the first line `sent: true` still and carrying the board's verdict,
/// the second `sent: false` and carrying none; the person's `send` hands both
/// back, each keeping its own (the mutant that clears `sent` at a move
/// forgets the first may have landed, and a resend lands it twice; the one
/// that marks every moved line `sent` reads the second's write, which never
/// left, as one that may have landed).
#[test]
fn a_moved_documents_lines_keep_each_its_own_sent() {
    let g = writer_at(80);
    g.fake.next_at.store(81, Ordering::SeqCst);
    *g.fake.rows.lock().unwrap() = vec![json!({"at": 77, "op": "insert", "key": "ff".repeat(32), "docs": [DOC]})];
    let k = g.hold(&insert(DOC, json!(["a"]), 70), "unreachable", true)["held"].as_u64().unwrap();
    g.hold(&insert(DOC, json!(["b"]), 70), "behind", false);
    g.fake.op_rejected.next(1, arrangement_moved(70, 77));
    g.holds.probe("b-1");
    let marks = || -> Vec<(String, Option<bool>, bool)> { g.lines().iter().map(|l| (l["cause"].as_str().unwrap_or("?").to_string(), l["sent"].as_bool(), l.get("refusal").is_some())).collect() };
    assert_eq!(marks(), [("moved".to_string(), Some(true), true), ("moved".to_string(), Some(false), false)], "each line keeps its own, the verdict on the line refused");
    assert_eq!(g.holds.resolve(&g.session, k, ResolveAct::Send).unwrap(), Resolved::HandedBack);
    assert_eq!(marks(), [("behind".to_string(), Some(true), false), ("behind".to_string(), Some(false), false)], "and through the person's send");
}

/// Checks that a document moved again after the person's `send` names the
/// hands since it alone (§3c.4; skep #757).
///
/// A burst without anchors — an agent's — refused at its first dial as typed
/// against an older state, another writer's change at 77 having moved the
/// document: held moved, its face naming that writer's hand. The person's
/// `send` acknowledges the rows the board's verdict read through, the line's
/// base raised to 77; a third hand's change lands at 78, and the next
/// probe's resend, refused again with no shift exact without anchors, is
/// held moved: its face names the third hand alone, the change the person
/// acknowledged named no more, the line standing at its raised base under
/// the newest verdict (the mutant that reads the hands since the typed state
/// at every face names the acknowledged hand again beside the new one, and
/// the person meets the face they sent past).
#[test]
fn a_document_moved_again_after_the_persons_send_names_only_the_hands_since() {
    let g = ground();
    let typed = g.fake.head();
    let row = |at: u64, key: String| json!({"at": at, "op": "insert", "key": key, "docs": [DOC]});
    *g.fake.rows.lock().unwrap() = vec![row(77, "ff".repeat(32))];
    let faces = || -> Vec<Value> {
        let moved: Vec<Value> = g.rx.try_iter().filter(|e| e.name == EventName::Held && e.data["state"] == "moved").map(|e| e.data).collect();
        moved.iter().for_each(assert_held_event_declared);
        moved.iter().map(|d| d["hands"].clone()).collect()
    };
    g.fake.op_rejected.next(1, arrangement_moved(typed, 77));
    let OpAnswer::Answered(Ok(held)) = g.holds.send_burst(&g.session, insert(DOC, json!(["x"]), typed), None) else { panic!("held, not faced") };
    let k = held["held"].as_u64().unwrap();
    assert_eq!((held["cause"].as_str(), faces()), (Some("moved"), vec![json!([{"key": "other", "fingerprint": "ff".repeat(32)}])]), "the first face names the writer who moved it: {held}");
    assert_eq!(g.holds.resolve(&g.session, k, ResolveAct::Send).unwrap(), Resolved::HandedBack);
    assert_eq!(g.lines()[0]["base"], 77, "the base raised to the verdict's `site.current`");
    g.fake.rows.lock().unwrap().push(row(78, "ee".repeat(32)));
    g.fake.op_rejected.next(1, arrangement_moved(typed, 78));
    g.holds.probe("b-1");
    assert_eq!(faces(), [json!([{"key": "other", "fingerprint": "ee".repeat(32)}])], "moved again: the hand since the person's send alone");
    let lines = g.lines();
    assert_eq!((lines[0]["cause"].as_str(), lines[0]["base"].as_u64(), &lines[0]["refusal"]), (Some("moved"), Some(77), &arrangement_moved(typed, 78)), "{lines:?}");
}

/// Checks that a line leaving the queue takes the person's acknowledgment of
/// its document with it (skep #757).
///
/// A line typed against the document at 70, refused at a resend as typed
/// against an older state — two other writers' changes at 75 and 77 having
/// moved it — is held moved naming both hands; the person's `send`
/// acknowledges them, and the resend is acked and kept, the queue emptied and
/// its ordinals starting again. A later burst typed at 70 too — an agent's,
/// from its last read — takes the line's ordinal, and the board refuses its
/// resend as typed against an older state: its first moved face names both
/// hands again, the acknowledgment having gone with the line it was the
/// person's act on (the mutant that keeps it past the line's `done` reads
/// the new line's hands since the old line's acknowledgment, and its first
/// face names none).
#[test]
fn a_line_leaving_the_queue_takes_the_persons_acknowledgment_with_it() {
    let g = ground();
    g.fake.next_at.store(100, Ordering::SeqCst);
    let row = |at: u64, key: String| json!({"at": at, "op": "insert", "key": key, "docs": [DOC]});
    *g.fake.rows.lock().unwrap() = vec![row(75, "dd".repeat(32)), row(77, "ff".repeat(32))];
    let both = json!([{"key": "other", "fingerprint": "dd".repeat(32)}, {"key": "other", "fingerprint": "ff".repeat(32)}]);
    let face = || g.rx.try_iter().filter(|e| e.name == EventName::Held).map(|e| e.data).find(|d| d["state"] == "moved").map(|d| d["hands"].clone());
    let k = g.hold(&insert(DOC, json!(["a"]), 70), "unreachable", false)["held"].as_u64().unwrap();
    g.fake.op_rejected.next(1, arrangement_moved(70, 77));
    g.holds.probe("b-1");
    assert_eq!(face(), Some(both.clone()), "the first line's face");
    assert_eq!(g.holds.resolve(&g.session, k, ResolveAct::Send).unwrap(), Resolved::HandedBack);
    g.holds.probe("b-1");
    assert!(g.lines().is_empty() && g.states().contains(&"kept".to_string()), "the person's send: sent and kept");
    let reused = g.hold(&insert(DOC, json!(["b"]), 70), "unreachable", false)["held"].as_u64().unwrap();
    assert_eq!(reused, k, "the emptied queue's ordinals start again");
    g.fake.op_rejected.next(1, arrangement_moved(70, 100));
    g.holds.probe("b-1");
    assert_eq!((g.lines()[0]["cause"].as_str(), face()), (Some("moved"), Some(both)), "the later line's first face names every hand since its typed state");
}

/// Checks that an anchored resend after the person's `send` is shifted and
/// kept (§3c.4; skep #757).
///
/// A held delete of `b` and `c` — `Wabc` as the page read it, its `before`
/// anchor `a`, no `after`, its span the I-run of `b` and `c` — its first
/// dial's answer lost, `sent`. At the next probe its read finds no landing,
/// and as the resend reaches the board the person's own other delete, of
/// `W` — made not through this shell, the `skep` command's — lands and moves
/// the document: the resend is refused as typed against an older state, the
/// shift's image read goes unanswered, and the document is held moved, the
/// person's own hand named. The person's `send` acknowledges the rows the
/// verdict read through, the base raised to that delete's position; the
/// next probe's read starts past it — a row of the head's own hand and kind,
/// no landing of the head's, since the head's dial after it was refused,
/// which a read from the old base takes for the head's landing — finds
/// none, and sends the head: refused again, shifted through the change by
/// one image read, `a` one position earlier and `b` and `c` whole after it
/// to the document's end, `p` moved by one and typed at the read's state,
/// acked and kept (the mutant that leaves the base keeps the head on the
/// person's other delete, and `b` and `c` are never deleted).
#[test]
fn after_the_persons_send_an_anchored_resend_whose_span_is_whole_is_shifted_and_kept() {
    let g = ground();
    let typed = g.fake.head();
    // `Wabc` as the page read it: `W` the I-position 10, `a` to `c` 1 to 3.
    *g.fake.image.lock().unwrap() = vec![run(&i(10), 1), run(&i(1), 3)];
    let k = g.hold_anchored(&delete_at(DOC, 3, 2, typed), spanned(Some(&i(1)), None, &[(&i(2), 2)]), "unreachable", true)["held"].as_u64().unwrap();
    // The person's own delete of `W` lands as the resend reaches the board.
    let (fake, own, landed) = (Arc::clone(&g.fake), g.own_key(), AtomicBool::new(false));
    *g.fake.at_send.lock().unwrap() = Some(Box::new(move || {
        if !landed.swap(true, Ordering::SeqCst) {
            let at = fake.next_at.fetch_add(1, Ordering::SeqCst);
            fake.rows.lock().unwrap().push(json!({"at": at, "op": "delete", "key": own, "docs": [DOC]}));
            *fake.image.lock().unwrap() = vec![run(&i(1), 3)];
            fake.move_arrangement(DOC, at);
        }
    }));
    g.fake.image_unread.store(true, Ordering::SeqCst);
    g.holds.probe("b-1");
    let lines = g.lines();
    let current = lines[0]["refusal"]["site"]["current"].as_u64().expect("the verdict's position");
    assert!(current > typed, "{lines:?}");
    assert_eq!(
        (g.fake.sends(), lines[0]["cause"].as_str(), lines[0]["sent"].as_bool(), lines[0]["base"].as_u64()),
        (1, Some("moved"), Some(true), Some(0)),
        "refused stale, its image unread: held moved: {lines:?}"
    );
    let moved = g.rx.try_iter().filter(|e| e.name == EventName::Held).map(|e| e.data).find(|d| d["state"] == "moved").expect("the document faced moved");
    assert_eq!(moved["hands"], json!([{"key": "own", "fingerprint": g.own_key()}]), "the person's own other delete: {moved}");
    *g.fake.at_send.lock().unwrap() = None;
    g.fake.image_unread.store(false, Ordering::SeqCst);
    assert_eq!(g.holds.resolve(&g.session, k, ResolveAct::Send).unwrap(), Resolved::HandedBack);
    assert_eq!(g.lines()[0]["base"].as_u64(), Some(current), "the base raised past the person's own other delete");
    let _ = g.states();
    g.holds.probe("b-1");
    let sent = g.fake.sends.lock().unwrap().clone();
    assert_eq!((sent.len(), g.fake.image_reads.load(Ordering::SeqCst)), (3, 2), "sent, refused once more, shifted by one image read and sent again: {sent:?}");
    assert_eq!(
        (sent[2]["p"]["ordinal"].as_str(), sent[2]["width"].as_str(), sent[2]["as_of"].as_u64()),
        (Some("2"), Some("2"), Some(current)),
        "`p` moved by one, typed at the read's state: {sent:?}"
    );
    assert!(g.lines().is_empty() && !held_file(&g).exists(), "kept, the file gone");
    assert_eq!(g.states(), ["sending", "kept"], "shifted and kept, never moved again");
}

/// Checks that one probe over two documents held on an unreadable head makes
/// ONE head read and reads no document (skep #727).
///
/// Two documents' heads are held `head_unreadable`, each `sent` — a lost
/// answer's line the head then held so — so the resend's read would run for
/// each were it not skipped. The probe reads the board's head once, before
/// any document, and while it answers `head_unreadable` skips both: no
/// `/changes` read, nothing dialed, nothing said; the lines stand (the mutant
/// that reads the head per document costs a read per held document per probe;
/// the one that reads each document first costs a `/changes` read and a
/// `sending`/`holding` pair per document per probe, for as long as the head
/// stays unreadable).
#[test]
fn one_probe_over_two_head_unreadable_documents_makes_one_head_read_and_reads_no_document() {
    let fake = Fake::new();
    fake.head_garbled.store(true, Ordering::SeqCst);
    let store = TempDir::new().unwrap();
    let facts = writer_facts(&store);
    let g = ground_over(fake, store, facts, 0);
    let unreadable = |sent: bool| Reason { cause: "head_unreadable".into(), refusal: Some(json!({"kind": "halt", "name": "head_unreadable"})), sent };
    g.hold_for(&insert(DOC, json!(["a"]), g.fake.head()), unreadable(true)).unwrap();
    g.hold_for(&insert(OTHER, json!(["b"]), g.fake.head()), unreadable(true)).unwrap();
    let _ = g.states();
    let (head_reads, changes_reads) = (g.fake.head_reads.load(Ordering::SeqCst), g.fake.changes_reads.load(Ordering::SeqCst));
    g.holds.probe("b-1");
    assert_eq!(g.fake.head_reads.load(Ordering::SeqCst) - head_reads, 1, "one head read per probe, before any document");
    assert_eq!(g.fake.changes_reads.load(Ordering::SeqCst) - changes_reads, 0, "no document is read while the head will not");
    assert_eq!((g.fake.sends(), g.states()), (0, Vec::<String>::new()), "nothing dialed, nothing said");
    assert_eq!(g.lines().len(), 2, "both lines stand");
}

/// Checks that the `held` event and the head's `Talk` line are said once per
/// change of state while the head will not read (skep #727).
///
/// The head's state is said once as the session's open first reads it; a
/// burst held on it says `holding` once; three probes say nothing more —
/// no event, no second line; once the head reads, one line says so, the line
/// is sent and kept, and a further probe says nothing (the mutant that says
/// the state per probe floods the log; the one that emits the event per
/// probe shows the page a `sending` that never leads anywhere).
#[test]
fn the_held_event_and_the_heads_talk_line_are_said_once_per_change_of_state() {
    let fake = Fake::new();
    fake.head_garbled.store(true, Ordering::SeqCst);
    let store = TempDir::new().unwrap();
    let facts = writer_facts(&store);
    let g = ground_over(fake, store, facts, 0);
    assert_eq!(said_containing(&g, "cannot be read").len(), 1, "the head's state, said once at the session's open: {:?}", g.said.lock().unwrap());
    let OpAnswer::Answered(Ok(held)) = g.holds.send_burst(&g.session, insert(DOC, json!(["a"]), g.fake.head()), None) else { panic!("held") };
    assert_eq!(held["cause"], "head_unreadable", "{held}");
    assert_eq!(g.states(), ["holding"], "the hold's one event");
    for _ in 0..3 {
        g.holds.probe("b-1");
    }
    assert_eq!(g.states(), Vec::<String>::new(), "the event once, across three probes");
    assert_eq!(said_containing(&g, "cannot be read").len(), 1, "the line once per change of state, not per probe");
    assert!(said_containing(&g, "reads again").is_empty());
    g.fake.head_garbled.store(false, Ordering::SeqCst);
    g.holds.probe("b-1");
    assert_eq!(said_containing(&g, "reads again").len(), 1, "said once as the state clears: {:?}", g.said.lock().unwrap());
    assert!(g.lines().is_empty() && g.states().contains(&"kept".to_string()), "sent and kept");
    g.holds.probe("b-1");
    assert_eq!((said_containing(&g, "reads again").len(), said_containing(&g, "cannot be read").len()), (1, 1), "nothing more on a board whose head reads");
}

/// Checks that at the head's first read the pending lines join the board's
/// file and are sent in order (skep #725).
///
/// Three bursts on two documents, held while the head record stood damaged,
/// are on the pending file; the record then reads, and the next probe joins
/// them into the board's own file — their ordinals kept, the join said once
/// — removes the pending file, and sends them in `k` order across the
/// documents, each kept, the board's file compacting away after (the mutant
/// that sends the pending lines without the join leaves them on a file no
/// relaunch at the chain reads; the one that joins out of order lands a
/// later burst before an earlier one).
#[test]
fn at_the_heads_first_read_the_pending_lines_join_and_are_sent_in_order() {
    let fake = Fake::new();
    *fake.head_answer.lock().unwrap() = Some((200, json!({"resp": "delivery", "items": [{"atom": "not a head record"}]})));
    let store = TempDir::new().unwrap();
    let facts = writer_facts(&store);
    let g = ground_over(fake, store, facts, 0);
    for (doc, value) in [(DOC, "a"), (OTHER, "b"), (DOC, "c")] {
        let OpAnswer::Answered(Ok(held)) = g.holds.send_burst(&g.session, insert(doc, json!([value]), g.fake.head()), None) else { panic!("{value}: held") };
        assert_eq!(held["resp"], "held", "{held}");
    }
    let pending = pending_file(&g);
    assert_eq!(file_lines(&std::fs::read_to_string(&pending).unwrap()).len(), 3, "three lines on the pending file");
    let _ = g.states();
    *g.fake.head_answer.lock().unwrap() = None;
    g.holds.probe("b-1");
    let sent: Vec<String> = g.fake.sends.lock().unwrap().iter().map(|f| f["values"][0].as_str().unwrap_or("?").to_string()).collect();
    assert_eq!(sent, ["a", "b", "c"], "sent in `k` order across the documents");
    assert!(g.lines().is_empty(), "every line kept");
    assert!(!pending.exists(), "the pending file is removed once its lines joined");
    assert!(!held_file(&g).exists(), "the board's file compacted away once every line was kept");
    let joined = said_containing(&g, "joined the board's held file");
    assert!(joined.len() == 1 && joined[0].contains("3 held lines joined") && joined[0].contains("their ordinals kept"), "{joined:?}");
}

/// Checks that pending lines joining a file that holds lines are renumbered
/// and `held` said again (skep #725; the join's hazard).
///
/// An earlier run left a line in the board's own file under ordinal 1; this
/// run, the head unreadable, holds two lines on the pending file under
/// ordinals 1 and 2. At the head's first read the pending lines join behind
/// the earlier one, renumbered 2 and 3, and the `held` event is said again
/// for their document — the state and the count as they were, the event
/// forced past the once-per-change memory — so the page reads the new
/// ordinals before it acts on one; the join is said once as renumbered (the
/// mutant that keeps the ordinals writes two lines under one; the one that
/// trusts the memory leaves the page acting on an ordinal that now names
/// another line).
#[test]
fn pending_lines_joining_a_file_that_holds_lines_are_renumbered_and_held_is_said_again() {
    let store = TempDir::new().unwrap();
    let dir = HeldDir::new(store.path(), Chain::parse(&"ab".repeat(32)).unwrap());
    dir.ensure().unwrap();
    let Opened::Live { mut queue, .. } = dir.open_file(1, "1.0.1").unwrap() else { panic!("a fresh file") };
    assert!(queue.hold(DOC, None, 0, insert(DOC, json!(["earlier"]), 0), None, Reason::of("unreachable", false)).unwrap().unwritten.is_none());
    drop(queue);
    let fake = Fake::new();
    fake.head_garbled.store(true, Ordering::SeqCst);
    let facts = writer_facts(&store);
    let g = ground_over(fake, store, facts, 0);
    for value in ["x", "y"] {
        let OpAnswer::Answered(Ok(held)) = g.holds.send_burst(&g.session, insert(OTHER, json!([value]), g.fake.head()), None) else { panic!("{value}: held") };
        assert_eq!(held["resp"], "held", "{held}");
    }
    let ks = |g: &Ground| g.lines().iter().map(|l| (l["held"].as_u64().unwrap(), l["doc"].as_str().unwrap().to_string())).collect::<Vec<_>>();
    assert_eq!(ks(&g), [(1, OTHER.to_string()), (2, OTHER.to_string())], "the pending file's ordinals");
    let _ = g.states();
    // The head reads, the board away for the dial: the lines stand to be read.
    g.fake.head_garbled.store(false, Ordering::SeqCst);
    g.fake.op_unreachable.store(true, Ordering::SeqCst);
    g.holds.probe("b-1");
    assert_eq!(ks(&g), [(1, DOC.to_string()), (2, OTHER.to_string()), (3, OTHER.to_string())], "renumbered behind the earlier run's line");
    let events: Vec<(String, String, u64)> = g.rx.try_iter().filter(|e| e.name == EventName::Held).map(|e| (e.data["doc"].as_str().unwrap().to_string(), e.data["state"].as_str().unwrap().to_string(), e.data["held"].as_u64().unwrap())).collect();
    assert_eq!(events.first(), Some(&(OTHER.to_string(), "holding".to_string(), 2)), "the `held` event said again for the renumbered document, before any resend: {events:?}");
    assert!(!pending_file(&g).exists(), "the pending file is gone");
    let joined = said_containing(&g, "joined the board's held file");
    assert!(joined.len() == 1 && joined[0].contains("2 held lines joined") && joined[0].contains("renumbered"), "{joined:?}");
    let on_disk = file_lines(&std::fs::read_to_string(held_file(&g)).unwrap());
    let disk_ks: Vec<u64> = on_disk.iter().map(|l| l["held"].as_u64().unwrap()).collect();
    assert!(disk_ks.contains(&2) && disk_ks.contains(&3), "the renumbered lines on the board's file: {disk_ks:?}");
}
