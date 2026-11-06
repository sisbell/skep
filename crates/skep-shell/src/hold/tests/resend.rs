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
//! the death signal leaving one standing — at its dial, or at its shift's
//! image read or its read of the hands, never then faced moved (skep #826);
//! a resend answered `500
//! internal_panic` marking its line `sent: true`, its landing then kept by
//! the read; a line that may have landed
//! staying so through resends that never left, over a head record that
//! cannot be read or a connection never made, its landing kept by the read;
//! another shell's lock on the board's store (skep #789): the store found
//! another's at the session's open and said once, no file opened and nothing
//! listed, a line held before the state was found counted, resent from
//! memory and kept, nothing written under the lock, the state left only as a
//! later session's open takes the lock, and each edge emitted once as
//! `another-window`, at the open or the probe that finds it, and never at a
//! try that finds no change (skep #827); one writer per board across its two
//! locks (skep #828): a pending store meeting the board's own lock held as
//! the head reads, read alone, its line counted on the pending file and sent
//! from it under the lock this shell keeps until it takes the board's own,
//! and a head that reads beside another shell's pending lock taking no lock
//! and reading alone; a board away at the first touch
//! holding in memory and joining its file once it returns, and joining it —
//! the board's own, or the pending one — at a later probe where the device
//! refused the join, the refusal said once and every answer meanwhile
//! carrying it (skep #823) and its class (skep #820); a held store this
//! shell may not make answering `read_only` and joining once it can, and a
//! queue kept in memory answering the store's refusal that stands once the
//! board returns, never the board away; and the lines a refused join's copy
//! left standing in the file, their cut-back refused, never read back once
//! their bursts are sent from memory (skep #817, #821); every
//! principal's lines resent by one probe, a bare session's line resent by
//! none until a session
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
//! `sent` on disk before it dials, a line acked whose `done` the device
//! refused relaunching so and kept by the read, and a mark the device refused
//! written at the probe and read `sent` by a relaunch (skep #821); the own
//! node stopped,
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
//! holds lines; and a pending join the device refused joining at a later
//! probe, the pending directory under this shell's lock until it has. And
//! THE DRAIN'S TURNS (skep #817): a drain in bounded turns sending every
//! line in `k` order, each document read as the walk reaches it and once in
//! a pass, a document a turn stopped at dialed no more until the pass ends,
//! and the person's `send` walking it again within the pass; a full pending
//! file joined at the session's open in one copy with one sync; and, over
//! the board's feed thread, a search answered between two turns, the turns
//! running back to back. And, timed (`#[ignore]`, the full gate's), the walk
//! over a full queue drained within its ceiling, each line's send measured
//! beside it.

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

/// Checks that a death at a resend's shift, or at its read of the hands,
/// leaves its line standing (§3c.4; skep #826).
///
/// A held line the board refuses as typed against an older state is shifted
/// by one image read where it carries anchors, and held moved after one read
/// of the hands where it carries none. Either read meeting the death signal
/// is the session's death and no verdict on the document: the line stands as
/// the resend's dial left it — its cause kept, marked `sent`, no refusal
/// beside it — nothing faced moved and nothing said of a move; the next
/// probe, the token answering again, shifts and keeps the anchored line, and
/// holds the other moved under the board's verdict, naming the hand that
/// moved the document (the mutant that reads the death as a read unanswered
/// faces the person a move no read found, on a line the session that stands
/// would have placed).
#[test]
fn a_death_at_a_resends_shift_or_its_read_of_the_hands_leaves_its_line_standing() {
    let ff = "ff".repeat(32);
    for (cell, anchored) in [("the shift's image read", true), ("the read of the hands", false)] {
        let g = ground();
        let typed = g.fake.head();
        *g.fake.rows.lock().unwrap() = vec![json!({"at": 77, "op": "insert", "key": ff, "docs": [DOC]})];
        *g.fake.image.lock().unwrap() = vec![run(&i(10), 2), run(&i(1), 3)];
        let frame = insert_at(DOC, 2, json!(["x"]), typed);
        if anchored {
            g.hold_anchored(&frame, anchors(Some(&i(1)), Some(&i(2))), "unreachable", false);
        } else {
            g.hold(&frame, "unreachable", false);
        }
        g.fake.move_arrangement(DOC, 77);
        let closed = if anchored { &g.fake.image_closed } else { &g.fake.changes_closed };
        closed.store(true, Ordering::SeqCst);
        g.holds.probe("b-1");
        let lines = g.lines();
        assert_eq!(g.fake.sends(), 1, "{cell}: the line was dialed, and refused stale");
        assert_eq!(
            (lines[0]["cause"].as_str(), lines[0]["sent"].as_bool(), lines[0].get("refusal")),
            (Some("unreachable"), Some(true), None),
            "{cell}: the line stands as its dial left it: {lines:?}"
        );
        assert_eq!(g.states(), ["holding", "sending"], "{cell}: never faced moved");
        assert!(said_containing(&g, "held as moved").is_empty(), "{cell}: nothing said of a move: {:?}", g.said.lock().unwrap());
        closed.store(false, Ordering::SeqCst);
        g.holds.probe("b-1");
        let said: Vec<Value> = g.rx.try_iter().filter(|e| e.name == EventName::Held).map(|e| e.data).collect();
        said.iter().for_each(assert_held_event_declared);
        let sent = g.fake.sends.lock().unwrap().clone();
        if anchored {
            assert_eq!((sent.len(), sent[2]["at"]["ordinal"].as_str(), sent[2]["as_of"].as_u64()), (3, Some("4"), Some(77)), "{cell}: refused once more, shifted and sent: {sent:?}");
            assert!(g.lines().is_empty() && said.len() == 1 && said[0]["state"] == "kept", "{cell}: kept: {said:?}");
        } else {
            let lines = g.lines();
            assert_eq!(
                (sent.len(), lines[0]["cause"].as_str(), &lines[0]["refusal"]),
                (2, Some("moved"), &arrangement_moved_on("insert", typed, 77)),
                "{cell}: held moved under the verdict: {lines:?}"
            );
            assert_eq!((said.len(), &said[0]["state"], &said[0]["hands"]), (1, &json!("moved"), &json!([{"key": "other", "fingerprint": ff}])), "{cell}: the hand named: {said:?}");
        }
    }
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
    g.holds.hold(&second, Burst::admit(insert("1.0.2.0.1", json!(["b"]), g.fake.head()), &second).unwrap(), Reason::of("unreachable", false), None, second.opened_at).answered().unwrap();
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

/// The `Talk` line that says another shell's store as its state begins.
const ANOTHER_SHELLS_STORE: &str = "held: another shell holds this board's held store — one shell per data directory: this shell reads alone at the board, every write refused `another_window` before any dial and nothing held, and tries the store again at each session's open";

/// The `Talk` line that says the board's store is this shell's again.
const THIS_SHELLS_STORE: &str = "held: this shell holds this board's held store now: writes at the board go out again";

/// The board's held directory under `store`, at the fake's chain, locked as
/// another shell over the same data directory holds it (§3c.3).
fn another_shell_holds(store: &Path) -> File {
    let dir = HeldDir::new(store, Chain::parse(&"ab".repeat(32)).unwrap());
    dir.ensure().unwrap();
    dir.try_lock().unwrap().expect("the other shell holds the lock")
}

/// Checks that another shell's lock makes the board's store that shell's,
/// and this one reads alone there (§3c.3: one shell per data directory;
/// skep #789, #827).
///
/// With the board's `held/<chain>/lock` held by another shell as the session
/// opens, the store is found another's ([`Holds::another_window`], the
/// question the shell's write door asks before any dial), said once on
/// `Talk` and emitted once, `another-window` `true`; no file is opened,
/// `held(session)` lists nothing, and a probe with no line standing dials
/// nothing and says nothing more. A line a write brought past the door
/// before the state was found stands in memory alone, its answer
/// `unwritable` naming the other shell, nothing written under its lock, and
/// is resent and kept once the board takes it, the probe's try of the store
/// emitting nothing. Once the other shell lets go, a probe with no line
/// standing leaves the state as it was, and the next session's open takes
/// the lock, says so once and emits `false` once: the next line is copied to
/// the board's file (the mutants that keep a second shell's bursts in memory
/// as its own custody, that write under another shell's lock, that leave the
/// state at a read that takes no lock, that never try the lock again, and
/// that emit the state at every try).
#[test]
fn another_shells_lock_makes_the_store_its_own_and_this_shell_reads_alone() {
    let store = TempDir::new().unwrap();
    let other_shell = another_shell_holds(store.path());
    let held_dir = store.path().join("held").join("ab".repeat(32));
    let facts = writer_facts(&store);
    let g = ground_in(store, facts, 0);
    assert!(g.holds.another_window("b-1"), "the session's open finds the store another shell's");
    assert_eq!(said_containing(&g, "another shell holds this board's held store"), [ANOTHER_SHELLS_STORE], "said once as it begins");
    assert_eq!(edges(&g.rx), [true], "and emitted once");
    // Every later edge, read beside the receiver `states` reads.
    let later = g.bus.subscribe();
    assert!(g.lines().is_empty() && !held_dir.join("principal-1.held").exists(), "no file is opened, nothing listed");
    g.holds.probe("b-1");
    assert_eq!(g.fake.sends(), 0, "a probe with no line standing dials nothing");
    // A line a write brought past the door before the state was found: in
    // memory alone, saying why, and sent as the board takes it.
    let answer = g.hold(&insert(DOC, json!(["hello"]), g.fake.head()), "unreachable", false);
    let why = answer["unwritable"].as_str().unwrap_or_else(|| panic!("the answer says why: {answer}"));
    assert!(why.contains("another shell holds this board's held store") && why.contains("kept in memory alone"), "{why}");
    assert!(!held_dir.join("principal-1.held").exists(), "nothing is written under another shell's lock");
    g.holds.probe("b-1");
    assert_eq!(g.fake.sends(), 1, "the line is resent from memory");
    assert!(g.lines().is_empty() && g.states().contains(&"kept".to_string()));
    assert!(g.holds.another_window("b-1") && !held_dir.join("principal-1.held").exists(), "the store stays the other shell's");
    assert!(edges(&later).is_empty(), "the probe's try of the store finds no change, and emits nothing");
    // The other shell lets go: a probe with no line standing leaves the
    // state, and the next session's open takes the lock.
    drop(other_shell);
    g.holds.probe("b-1");
    assert!(g.holds.another_window("b-1"), "a probe with no line standing tries no lock");
    let open = Open { token: Token::parse(&"8e".repeat(16)).unwrap(), facts: writer_facts(&g.store), opened_at: 0 };
    let board = BoardEntry { reference: g.session.board_reference.clone(), board: Arc::clone(&g.session.board) };
    let next_session = g.holds.sessions.register(&board, open, &mut NoSupplements);
    g.holds.open_session(&next_session);
    assert!(!g.holds.another_window("b-1"), "the next session's open takes the lock");
    assert_eq!(said_containing(&g, "held store now"), [THIS_SHELLS_STORE], "said once as it ends");
    assert_eq!(said_containing(&g, "another shell holds this board's held store"), [ANOTHER_SHELLS_STORE], "the beginning said no second time");
    assert_eq!(edges(&later), [false], "emitted once as it ends, the beginning no second time");
    let next = g.hold(&insert(DOC, json!(["c"]), g.fake.head()), "unreachable", false);
    assert!(next.get("unwritable").is_none(), "the store is this shell's now: {next}");
    assert!(std::fs::read_to_string(held_dir.join("principal-1.held")).unwrap().contains("\"values\":[\"c\"]"), "the line is copied to the board's file");
}

/// Checks that lines held in memory before another shell's store is found
/// are counted as it is said, and resent from memory (§3c.3; skep #789,
/// #827).
///
/// The board away at the session's open — its head unread, the store not
/// yet this shell's, nothing emitted — a burst is held in memory alone, its
/// answer naming the board away. Another shell then takes the store's lock
/// and the board returns: the probe's one head read finds the store
/// another's, says so once, naming the one line kept in memory and that a
/// close before it is sent loses it, and emits `another-window` `true` once;
/// the line is resent and kept, nothing written under the other shell's lock
/// (the mutant that gates the resend on the state loses the line at the
/// close; the one that counts no line leaves the operator unwarned; the one
/// that emits at the open alone leaves the page unaware of a state a probe
/// found).
#[test]
fn lines_held_before_another_shells_store_is_found_are_counted_and_resent_from_memory() {
    let fake = Fake::new();
    fake.head_unreachable.store(true, Ordering::SeqCst);
    let store = TempDir::new().unwrap();
    let facts = writer_facts(&store);
    let g = ground_over(fake, store, facts, 0);
    assert!(!g.holds.another_window("b-1"), "premise: the board away at the open, no lock tried");
    assert!(edges(&g.rx).is_empty(), "the open finds no state, and emits nothing");
    let answer = g.hold(&insert(DOC, json!(["hello"]), g.fake.head()), "unreachable", false);
    assert!(answer["unwritable"].as_str().is_some_and(|why| why.contains("could not be reached")), "held in memory, the board away: {answer}");
    let other_shell = another_shell_holds(g.store.path());
    g.fake.head_unreachable.store(false, Ordering::SeqCst);
    // The probe's edge, read beside the receiver `states` reads.
    let probed = g.bus.subscribe();
    g.holds.probe("b-1");
    assert!(g.holds.another_window("b-1"), "the probe's head read finds the store another shell's");
    let counted = format!("{ANOTHER_SHELLS_STORE}; the 1 held line kept in memory before then is sent as the board takes it, and a close before then loses it");
    assert_eq!(said_containing(&g, "another shell holds this board's held store"), [counted], "said once, the line counted");
    assert_eq!(edges(&probed), [true], "and emitted once");
    assert_eq!(g.fake.sends(), 1, "the line is resent from memory");
    assert!(g.lines().is_empty() && g.states().contains(&"kept".to_string()), "and kept");
    assert!(!held_file(&g).exists(), "nothing is written under the other shell's lock");
    drop(other_shell);
}

/// Checks that a board away at the first touch still holds its lines in
/// memory and joins them to its file once it returns (§3c.3).
///
/// The other causes of a store not yet this shell's keep the memory custody
/// another shell's lock has none of: the board away at the session's open, a
/// burst is held in memory, its answer naming the board away; the board
/// returns, refusing the resend `write_busy` so the line stands, and the
/// probe's head read takes the directory — no other shell holds it — and
/// joins the line to the board's file, said once, the store never another
/// shell's, said or emitted (the mutant that reads any store not yet this
/// shell's as another shell's refuses the person's writes at every outage;
/// the one that emits `another-window` at every step to a directory this
/// shell locks tells the page of a state that never stood).
#[test]
fn a_board_away_at_the_first_touch_holds_in_memory_and_joins_its_file_later() {
    let fake = Fake::new();
    fake.head_unreachable.store(true, Ordering::SeqCst);
    let store = TempDir::new().unwrap();
    let facts = writer_facts(&store);
    let g = ground_over(fake, store, facts, 0);
    let answer = g.hold(&insert(DOC, json!(["a"]), g.fake.head()), "unreachable", false);
    assert!(answer["unwritable"].as_str().is_some_and(|why| why.contains("could not be reached")), "held in memory, the board away: {answer}");
    assert!(!g.store.path().join("held").exists(), "nothing written while the board is away");
    g.fake.head_unreachable.store(false, Ordering::SeqCst);
    g.fake.op_refused.every((503, json!({"error": "write_busy"})));
    g.holds.probe("b-1");
    assert!(!g.holds.another_window("b-1"), "no other shell holds the store");
    assert!(std::fs::read_to_string(held_file(&g)).unwrap().contains("\"values\":[\"a\"]"), "the standing line joined the board's file");
    let joined = said_containing(&g, "joined the board's held file");
    assert!(joined.len() == 1 && joined[0].contains("1 held line joined"), "{joined:?}");
    assert!(said_containing(&g, "another shell").is_empty(), "never said another shell's");
    assert!(edges(&g.rx).is_empty(), "nor emitted, at the open or at the probe's step");
    g.fake.op_refused.clear();
    g.holds.probe("b-1");
    assert!(g.lines().is_empty() && g.states().contains(&"kept".to_string()), "resent and kept");
}

/// Checks that a pending store whose board's own lock another shell holds as
/// the head reads makes the store that shell's, and its lines are sent from
/// the pending file (§3c.3; skep #828: one writer per board).
///
/// The board's head record stands damaged at the session's open, so the
/// store is the pending one, and a burst is held `head_unreadable` on its
/// file. Another shell then takes the board's own directory's lock, and the
/// head reads: the probe's step finds that lock held, so this shell reads
/// alone at the board ([`Holds::another_window`]), said once on `Talk` — the
/// line counted on the pending file, never among the lines a close loses —
/// and emitted once, `true`. The line stays on the pending file, under this
/// shell's lock, nothing written under the board's own directory: its
/// resend, refused `write_busy`, leaves it standing; once the refusal clears
/// the next probe sends it again and keeps it, its `done` written to the
/// pending file, which compacts away, saying and emitting nothing. Once the
/// other shell lets go, the next session's open takes the board's own lock,
/// says so once and emits `false` once, the pending lock let go after the
/// join, and the next line is copied to the board's file (the mutant that
/// leaves the store pending writes beside the other shell; the one that
/// lets the pending lock go while the line stands leaves its file to a third
/// shell; the one that takes the line into memory leaves its `done`
/// unwritten, for a relaunch to send it twice; the one that counts it in
/// memory tells the operator a close loses it; the one that emits nothing
/// leaves the page unaware of either edge).
#[test]
fn a_pending_store_whose_boards_own_lock_another_shell_holds_reads_alone_and_sends_its_lines_from_the_pending_file() {
    let fake = Fake::new();
    *fake.head_answer.lock().unwrap() = Some((200, json!({"resp": "delivery", "items": [{"atom": "not a head record"}]})));
    let store = TempDir::new().unwrap();
    let facts = writer_facts(&store);
    let g = ground_over(fake, store, facts, 0);
    let OpAnswer::Answered(Ok(held)) = g.holds.send_burst(&g.session, insert(DOC, json!(["a"]), g.fake.head()), None) else { panic!("held, not faced") };
    assert_eq!(held["cause"], "head_unreadable", "{held}");
    let pending = pending_file(&g);
    assert!(std::fs::read_to_string(&pending).unwrap().contains("\"values\":[\"a\"]"), "premise: the line is on the pending file");
    assert!(edges(&g.rx).is_empty(), "premise: the pending store is this shell's, nothing emitted");
    let other_shell = another_shell_holds(g.store.path());
    *g.fake.head_answer.lock().unwrap() = None;
    g.fake.op_refused.every((503, json!({"error": "write_busy"})));
    // Every later edge, read beside the receiver `states` reads.
    let probed = g.bus.subscribe();
    g.holds.probe("b-1");
    assert!(g.holds.another_window("b-1"), "the head reads beside another shell's lock on the board's own directory: the store is another's");
    let counted = format!("{ANOTHER_SHELLS_STORE}; the 1 held line in the pending held file stays there and is sent as the board takes it");
    assert_eq!(said_containing(&g, "another shell holds this board's held store"), [counted], "said once, the line counted on the pending file");
    assert_eq!(edges(&probed), [true], "and emitted once");
    assert_eq!((g.fake.sends(), g.lines().len()), (1, 1), "the line resent and refused, still standing");
    assert!(std::fs::read_to_string(&pending).unwrap().contains("\"values\":[\"a\"]"), "the line stays on the pending file");
    assert!(!held_file(&g).exists(), "nothing is written under the other shell's lock");
    let pending_store = HeldDir::pending(g.store.path(), g.session.board.dialed());
    assert!(pending_store.try_lock().unwrap().is_none(), "the pending directory stays under this shell's lock while its line stands");
    // The refusal clears: the line goes out from the pending file.
    g.fake.op_refused.clear();
    let _ = g.states();
    g.holds.probe("b-1");
    assert_eq!(g.fake.sends(), 2, "the line is sent again");
    assert!(g.lines().is_empty() && g.states().contains(&"kept".to_string()), "and kept");
    assert!(!pending.exists(), "its `done` written to the pending file, which compacts away");
    assert!(g.holds.another_window("b-1") && edges(&probed).is_empty(), "the store stays the other shell's, nothing emitted");
    assert_eq!(said_containing(&g, "another shell holds this board's held store").len(), 1, "nothing said again");
    // The other shell lets go: the next session's open takes the board's own
    // lock.
    drop(other_shell);
    let open = Open { token: Token::parse(&"8e".repeat(16)).unwrap(), facts: writer_facts(&g.store), opened_at: 0 };
    let board = BoardEntry { reference: g.session.board_reference.clone(), board: Arc::clone(&g.session.board) };
    let next_session = g.holds.sessions.register(&board, open, &mut NoSupplements);
    g.holds.open_session(&next_session);
    assert!(!g.holds.another_window("b-1"), "the next session's open takes the board's own lock");
    assert_eq!(said_containing(&g, "held store now"), [THIS_SHELLS_STORE], "said once as it ends");
    assert_eq!(edges(&probed), [false], "emitted once as it ends");
    assert!(pending_store.try_lock().unwrap().is_some(), "the pending lock is let go once no queue is its file's");
    let next = g.hold(&insert(DOC, json!(["c"]), g.fake.head()), "unreachable", false);
    assert!(next.get("unwritable").is_none(), "the store is this shell's now: {next}");
    assert!(std::fs::read_to_string(held_file(&g)).unwrap().contains("\"values\":[\"c\"]"), "the next line is copied to the board's file");
}

/// The pending directory under `store` for the origin the ground's board
/// dials, locked as another shell over the same data directory holds it
/// while the board's head will not read for it (§3c.1, §3c.3).
fn another_shell_holds_pending(store: &Path) -> File {
    let dir = HeldDir::pending(store, &Origin::parse("http://127.0.0.1:1").unwrap());
    dir.ensure().unwrap();
    dir.try_lock().unwrap().expect("the other shell holds the pending lock")
}

/// Checks that a head that reads beside another shell's pending lock takes
/// no lock and reads alone (§3c.3; skep #828: one writer per board).
///
/// Another shell stands at the board's pending directory, its lock held, as
/// this shell's session opens with the board's head reading: the pending
/// lock is tried before the board's own and found held, so the store is
/// another's ([`Holds::another_window`]), said once and emitted once,
/// `true`, and no lock of the board's own is taken — the other shell's to
/// take at its next try, the board's one writer. No file is opened and
/// nothing is listed. Once the other shell lets go, the next session's open
/// takes both locks, says so once and emits `false` once, lets the pending
/// lock go after the join, and the next line is copied to the board's file
/// (the mutant that takes the board's own lock first writes beside the
/// other shell; the one that refuses on the pending lock found held beside
/// the board's own holds the lock the other shell waits for, and neither
/// writes).
#[test]
fn a_head_that_reads_beside_another_shells_pending_lock_takes_no_lock_and_reads_alone() {
    let store = TempDir::new().unwrap();
    let other_shell = another_shell_holds_pending(store.path());
    let facts = writer_facts(&store);
    let g = ground_in(store, facts, 0);
    assert!(g.holds.another_window("b-1"), "the pending lock is tried first and found another shell's");
    assert_eq!(said_containing(&g, "another shell holds this board's held store"), [ANOTHER_SHELLS_STORE], "said once as it begins");
    assert_eq!(edges(&g.rx), [true], "and emitted once");
    let later = g.bus.subscribe();
    let own = HeldDir::new(g.store.path(), Chain::parse(&"ab".repeat(32)).unwrap());
    own.ensure().unwrap();
    assert!(own.try_lock().unwrap().is_some(), "no lock of the board's own is taken: it is the other shell's to take");
    assert!(g.lines().is_empty() && !held_file(&g).exists() && !pending_file(&g).exists(), "no file is opened, nothing listed");
    // The other shell lets go: the next session's open takes both locks.
    drop(other_shell);
    let open = Open { token: Token::parse(&"8e".repeat(16)).unwrap(), facts: writer_facts(&g.store), opened_at: 0 };
    let board = BoardEntry { reference: g.session.board_reference.clone(), board: Arc::clone(&g.session.board) };
    let next_session = g.holds.sessions.register(&board, open, &mut NoSupplements);
    g.holds.open_session(&next_session);
    assert!(!g.holds.another_window("b-1"), "the next session's open takes the store");
    assert_eq!(said_containing(&g, "held store now"), [THIS_SHELLS_STORE], "said once as it ends");
    assert_eq!(edges(&later), [false], "emitted once as it ends");
    assert!(HeldDir::pending(g.store.path(), g.session.board.dialed()).try_lock().unwrap().is_some(), "the pending lock is let go after the join");
    let next = g.hold(&insert(DOC, json!(["c"]), g.fake.head()), "unreachable", false);
    assert!(next.get("unwritable").is_none(), "the store is this shell's now: {next}");
    assert!(std::fs::read_to_string(held_file(&g)).unwrap().contains("\"values\":[\"c\"]"), "the line is copied to the board's file");
}

/// Makes `dir`, at `path`, and its lock by hand, the lock let go, then seals
/// the directory (`0500`): a step to it takes the lock, and every file's
/// create there is refused. Returns the refusal a create there meets, in its
/// words.
#[cfg(unix)]
fn seal(dir: &HeldDir, path: &Path) -> String {
    use std::os::unix::fs::PermissionsExt;
    dir.ensure().unwrap();
    drop(dir.try_lock().unwrap());
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o500)).unwrap();
    File::create(path.join("probe")).expect_err("premise: a sealed directory refuses a create").to_string()
}

/// Seals the board's own held directory under `store` ([`seal`]): its path,
/// and the refusal a create there meets.
#[cfg(unix)]
fn seal_the_boards_directory(store: &Path) -> (std::path::PathBuf, String) {
    let sealed = store.join("held").join("ab".repeat(32));
    let refused = seal(&HeldDir::new(store, Chain::parse(&"ab".repeat(32)).unwrap()), &sealed);
    (sealed, refused)
}

/// Opens a directory [`seal`] sealed.
#[cfg(unix)]
fn unseal(sealed: &Path) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(sealed, std::fs::Permissions::from_mode(0o700)).unwrap();
}

/// Checks that a queue kept in memory whose join the device refuses joins
/// the board's file at a later probe (§3c.1, §3c.3; skep #823).
///
/// The board away at the session's open, a burst is held in memory, of the
/// class `other`. The board's directory stands sealed, so when the board
/// returns the probe's step takes its lock and the join is refused at the
/// file's create: the line stands in memory, its resend refused
/// `write_busy`, and the refusal is said once on `Talk` — naming the loss a
/// close makes, and no launch memory does not survive. The next burst, held
/// `behind` it, answers the device's own refusal as its `unwritable`, never
/// the board away, of its kind's class, `read_only` (skep #820). A second
/// probe, still sealed, says nothing more. The node stopped and the
/// directory opened, the next probe — which dials nothing — joins both lines
/// into the board's file in `k` order and says so once (the mutant that
/// never retries the join keeps every line in memory for a close to lose;
/// the one that gates the retry on the node keeps them while the person has
/// stopped it; the one that leaves the custody's why as it stood tells the
/// page the board is away; the one that reads the class off the line's own
/// copy alone gives the sealed directory the class `other`; the one that
/// says each refusal tells the window at every probe).
#[cfg(unix)]
#[test]
fn a_queue_kept_in_memory_whose_join_the_device_refuses_joins_once_the_device_takes_it() {
    let fake = Fake::new();
    fake.head_unreachable.store(true, Ordering::SeqCst);
    let store = TempDir::new().unwrap();
    let facts = writer_facts(&store);
    let g = ground_over(fake, store, facts, 0);
    let first = g.hold(&insert(DOC, json!(["a"]), g.fake.head()), "unreachable", false);
    assert!(first["unwritable"].as_str().is_some_and(|why| why.contains("could not be reached")), "held in memory, the board away: {first}");
    assert_eq!(first["unwritable_class"], "other", "the board away is no device's refusal: {first}");
    let (sealed, refused) = seal_the_boards_directory(g.store.path());
    g.fake.head_unreachable.store(false, Ordering::SeqCst);
    g.fake.op_refused.every((503, json!({"error": "write_busy"})));
    g.holds.probe("b-1");
    assert!(!g.holds.another_window("b-1") && !held_file(&g).exists(), "the store is this shell's, and the join refused at the file's create");
    let said = said_containing(&g, "could not join");
    assert_eq!(said.len(), 1, "the refusal said once: {said:?}");
    assert!(said[0].contains(&refused) && said[0].contains("waits in memory") && said[0].contains("a close before then loses it"), "{said:?}");
    let OpAnswer::Answered(Ok(behind)) = g.holds.send_burst(&g.session, insert(DOC, json!(["b"]), g.fake.head()), None) else { panic!("held behind the standing line") };
    assert_eq!(behind["cause"], "behind", "{behind}");
    assert_eq!(behind["unwritable"].as_str(), Some(refused.as_str()), "the device's refusal, never the board away: {behind}");
    assert_eq!(behind["unwritable_class"], "read_only", "the sealed directory's refusal, of its kind's class: {behind}");
    g.holds.probe("b-1");
    assert_eq!(said_containing(&g, "could not join").len(), 1, "a second refused probe says nothing more: {:?}", g.said.lock().unwrap());
    // The node stopped and the directory opened: the probe joins both.
    g.holds.set_node_stopped("b-1", true);
    unseal(&sealed);
    let sends = g.fake.sends();
    g.holds.probe("b-1");
    let joined: Vec<u64> = file_lines(&std::fs::read_to_string(held_file(&g)).unwrap()).iter().map(|line| line["held"].as_u64().unwrap()).collect();
    assert_eq!(joined, [1, 2], "both lines joined the board's file, in `k` order");
    assert_eq!(g.fake.sends(), sends, "nothing dialed while the node is stopped");
    let landed = said_containing(&g, "joined the board's held file");
    assert!(landed.len() == 1 && landed[0].contains("2 held lines joined") && landed[0].contains("their ordinals kept"), "{landed:?}");
    assert!(g.said.lock().unwrap().iter().all(|line| !line.contains("next launch")), "no line promises a launch memory does not survive: {:?}", g.said.lock().unwrap());
    let next = g.hold(&insert(DOC, json!(["c"]), g.fake.head()), "unreachable", false);
    assert!(next.get("unwritable").is_none(), "the next line is copied to the board's file: {next}");
}

/// Checks that a queue kept in memory whose join into the pending file the
/// device refuses joins it at a later probe (§3c.3 (i); skep #823).
///
/// The board away at the session's open, a burst is held in memory. The
/// pending directory stands sealed, so when the board returns serving a head
/// record that cannot be read, the probe's step to the pending directory
/// takes its lock and the join is refused at the file's create, said once,
/// and a second probe says nothing more. The directory opened, the next
/// probe joins the line into the pending file while the record still stands
/// damaged (the mutant that retries at the board's own directory alone keeps
/// the line in memory for as long as the record does not read).
#[cfg(unix)]
#[test]
fn a_queue_kept_in_memory_whose_pending_join_the_device_refuses_joins_at_a_later_probe() {
    let fake = Fake::new();
    fake.head_unreachable.store(true, Ordering::SeqCst);
    let store = TempDir::new().unwrap();
    let facts = writer_facts(&store);
    let g = ground_over(fake, store, facts, 0);
    let first = g.hold(&insert(DOC, json!(["a"]), g.fake.head()), "unreachable", false);
    assert!(first["unwritable"].is_string(), "held in memory, the board away: {first}");
    let pending = pending_file(&g);
    let sealed = pending.parent().unwrap().to_path_buf();
    let refused = seal(&HeldDir::pending(g.store.path(), g.session.board.dialed()), &sealed);
    g.fake.head_unreachable.store(false, Ordering::SeqCst);
    *g.fake.head_answer.lock().unwrap() = Some((200, json!({"resp": "delivery", "items": [{"atom": "not a head record"}]})));
    g.holds.probe("b-1");
    assert!(!pending.exists(), "the join into the pending file is refused at its create");
    let said = said_containing(&g, "could not join the pending held file");
    assert!(said.len() == 1 && said[0].contains(&refused) && said[0].contains("a close before then loses it"), "said once: {said:?}");
    g.holds.probe("b-1");
    assert_eq!(said_containing(&g, "could not join").len(), 1, "a second refused probe says nothing more: {:?}", g.said.lock().unwrap());
    unseal(&sealed);
    g.holds.probe("b-1");
    assert!(std::fs::read_to_string(&pending).unwrap().contains("\"values\":[\"a\"]"), "the line joined the pending file");
    let landed = said_containing(&g, "joined the pending held file");
    assert!(landed.len() == 1 && landed[0].contains("1 held line joined"), "{landed:?}");
    assert_eq!(g.fake.sends(), 0, "nothing sent unsigned");
}

/// Makes `held/` under `store` by hand and seals it (`0500`), so no board's
/// held directory can be made under it; returns its path, for [`unseal`].
#[cfg(unix)]
fn seal_the_held_store(store: &Path) -> std::path::PathBuf {
    use std::os::unix::fs::PermissionsExt;
    let held = store.join("held");
    std::fs::create_dir(&held).unwrap();
    std::fs::set_permissions(&held, std::fs::Permissions::from_mode(0o500)).unwrap();
    held
}

/// Checks that a held store this shell may not make answers `read_only`.
///
/// It is §3c.3's store out of reach (skep #820). With `held/` sealed before
/// the session opens, the board's directory cannot be made under it, so the
/// store is not yet this shell's. A burst is held in memory, its answer
/// naming the store's refusal — "could not be made or locked" — of the class
/// `read_only`, which no space freed ends. Opened again, the next probe makes
/// the directory and joins the line into the board's file, its resend
/// refused `write_busy` (the mutant that keeps the directory's refusal as
/// words alone gives a data directory this shell may not write the class
/// `other`).
#[cfg(unix)]
#[test]
fn a_held_directory_the_shell_may_not_make_answers_read_only_and_joins_once_it_can() {
    let store = TempDir::new().unwrap();
    let held = seal_the_held_store(store.path());
    let facts = writer_facts(&store);
    let g = ground_in(store, facts, 0);
    let answer = g.hold(&insert(DOC, json!(["a"]), g.fake.head()), "unreachable", false);
    assert!(answer["unwritable"].as_str().is_some_and(|why| why.contains("could not be made or locked")), "the store's refusal rides the answer: {answer}");
    assert_eq!(answer["unwritable_class"], "read_only", "{answer}");
    g.fake.op_refused.every((503, json!({"error": "write_busy"})));
    unseal(&held);
    g.holds.probe("b-1");
    assert!(std::fs::read_to_string(held_file(&g)).unwrap().contains("\"values\":[\"a\"]"), "the line joined the board's file once its directory could be made");
    assert_eq!(g.lines().len(), 1, "the line stands in the file, its resend refused");
}

/// Checks that a queue in memory answers the store's refusal that stands now.
///
/// It is §3c.3's store out of reach, once the board returns (skep #820).
/// The board away at the session's open, a burst is held in memory, its
/// answer naming the board away, of the class `other`. `held/` is then
/// sealed and the board returns: the probe's step finds the board's
/// directory cannot be made, so the store is still not this shell's, and the
/// line, resent and refused `write_busy`, stands. The next burst, held
/// `behind` it, answers the directory's refusal, of the class `read_only`,
/// never the board away. Opened again, the next probe joins both lines into
/// the board's file in `k` order (the mutant that leaves a standing memory
/// custody's why at a step between two such tries tells the page the board
/// is away, the person's act to wait).
#[cfg(unix)]
#[test]
fn a_queue_kept_in_memory_answers_the_directorys_refusal_once_the_board_returns() {
    let fake = Fake::new();
    fake.head_unreachable.store(true, Ordering::SeqCst);
    let store = TempDir::new().unwrap();
    let facts = writer_facts(&store);
    let g = ground_over(fake, store, facts, 0);
    let first = g.hold(&insert(DOC, json!(["a"]), g.fake.head()), "unreachable", false);
    assert!(first["unwritable"].as_str().is_some_and(|why| why.contains("could not be reached")), "held in memory, the board away: {first}");
    assert_eq!(first["unwritable_class"], "other", "{first}");
    let held = seal_the_held_store(g.store.path());
    g.fake.head_unreachable.store(false, Ordering::SeqCst);
    g.fake.op_refused.every((503, json!({"error": "write_busy"})));
    g.holds.probe("b-1");
    assert_eq!((g.fake.sends(), g.lines().len()), (1, 1), "the line resent and refused, still standing");
    let OpAnswer::Answered(Ok(behind)) = g.holds.send_burst(&g.session, insert(DOC, json!(["b"]), g.fake.head()), None) else { panic!("held behind the standing line") };
    assert_eq!(behind["cause"], "behind", "{behind}");
    assert!(behind["unwritable"].as_str().is_some_and(|why| why.contains("could not be made or locked")), "the store's refusal, never the board away: {behind}");
    assert_eq!(behind["unwritable_class"], "read_only", "{behind}");
    unseal(&held);
    g.holds.probe("b-1");
    let joined: Vec<u64> = file_lines(&std::fs::read_to_string(held_file(&g)).unwrap()).iter().map(|line| line["held"].as_u64().unwrap()).collect();
    assert_eq!(joined, [1, 2], "both lines joined the board's file, in `k` order");
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
/// its one reissue held `unreachable`, as at a first dial (skep #786) — the
/// line standing for the next probe, never handed over at once, the clock
/// running from the first; "sent again" said once. With the clock past
/// `HAND_OVER_DEADLINE` the next probe's read finds no landing and hands it to
/// the person under `answers_lost`, its `last` `write_busy`. The person's
/// `send` starts the clock afresh at the line's next failed send, and a board
/// still busy past the next deadline hands it over again, dialed once in
/// between (the mutant that starts no clock there resends it for ever, and
/// the one that reads a held `write_busy` by its reason alone does so once
/// the person's `send` has cleared the clock; the one that hands every code
/// the table holds nowhere over at once, `write_busy` among them, hands the
/// person a line a busy board would take in a moment; the one that says
/// "sent again" at every probe fills the log).
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
    // The person's `send`: the board still busy, the line is dialed once,
    // held again, and handed over again at its next deadline.
    assert_eq!(g.holds.resolve(&g.session, k, ResolveAct::Send).unwrap(), Resolved::HandedBack);
    g.holds.probe("b-1");
    let lines = g.lines();
    assert_eq!((g.fake.sends(), lines[0]["cause"].as_str()), (4, Some("unreachable")), "sent again, held: {lines:?}");
    g.holds.advance(HAND_OVER_DEADLINE);
    g.holds.probe("b-1");
    let lines = g.lines();
    assert_eq!(g.fake.sends(), 4, "handed over again at its next deadline, undialed");
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

/// Checks that the first dial's connection never made starts no clock.
///
/// The person's own first dial is no failed send where its connection is
/// never made — the board away, no request leaving (§3c.4): the burst is
/// answered `held`, `unreachable`, `sent: false`. With the board away
/// through three probes and the clock moved far past `HAND_OVER_DEADLINE`
/// after each, the line holds, never handed over; the probe after the board
/// answers sends it once and keeps it (the mutant that reads the first
/// dial's connection never made as a failed send hands an outage's line to
/// the person under `answers_lost`, undialed).
#[test]
fn the_first_dials_connection_never_made_starts_no_clock() {
    let g = ground();
    g.fake.op_unreachable.store(true, Ordering::SeqCst);
    let OpAnswer::Answered(Ok(held)) = g.holds.send_burst(&g.session, insert(DOC, json!(["a"]), g.fake.head()), None) else { panic!("held, its connection never made") };
    assert_eq!((held["resp"].as_str(), held["cause"].as_str(), g.lines()[0]["sent"].as_bool()), (Some("held"), Some("unreachable"), Some(false)), "{held}");
    for _ in 0..3 {
        g.holds.probe("b-1");
        g.holds.advance(HAND_OVER_DEADLINE * 10);
    }
    g.holds.probe("b-1");
    let lines = g.lines();
    assert_eq!((g.fake.sends(), lines[0]["cause"].as_str()), (0, Some("unreachable")), "the board away: held, never handed over: {lines:?}");
    g.fake.op_unreachable.store(false, Ordering::SeqCst);
    g.holds.probe("b-1");
    assert_eq!(g.fake.sends(), 1, "the board answering, the line is sent once");
    assert!(g.lines().is_empty() && g.states().contains(&"kept".to_string()), "kept, never refused");
}

/// Checks that "sent again" is said once per change of the failure.
///
/// It is said as the failure changes (§3c.4; skep #720). A line held before any
/// dial is resent at seven probes: three answers lost — a timeout, a garbled
/// answer, the board's handler panicking, one failure — then three
/// `write_busy`, the first reissued and the two past its reissue held
/// `unreachable`, then a `durability` reissued. The shell's window says "it is sent again at the next
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
/// `done` is owed, the wait said in the shell's own window, and the line
/// stands on disk as held; the relaunch over the same store, before any retry
/// writes the `done`, reads it `sent: true`, the mark its resend wrote before
/// the dial, and the read finds the line's own landing and keeps it, never
/// faced `moved` and never sent twice (the mutant that marks no line before
/// its dial relaunches it `sent: false`, and the read faces the person's own
/// text `moved`).
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
    assert!(said.iter().any(|line| line.starts_with("held: principal 1's held line 1's `done` could not be copied to its held file")), "the owed `done` is said: {said:?}");
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

/// Checks that a resend's mark of `sent` the device refused is written at the
/// probe, and a relaunch reads the line `sent` (§3c.3; skep #821).
///
/// A burst held unsent; its held file moved aside and a directory left at its
/// name, the probe's resend marks it `sent` before its dial — the mark's copy
/// refused and owed, the wait said once — and the dial is answered a first
/// `durability`, the line standing. The file put back and the node stopped,
/// the next probe — which dials nothing — writes the mark and says the wait's
/// end once, and a relaunch over the same store reads the line `sent`, as one
/// whose dial may have landed (the mutant that writes a refused mark once and
/// never again relaunches it unsent, and its resend goes out with no read for
/// its landing).
#[test]
fn a_resends_sent_mark_the_device_refused_is_written_at_the_probe_and_a_relaunch_reads_it_sent() {
    let g = ground();
    g.hold(&insert(DOC, json!(["hello"]), g.fake.head()), "unreachable", false);
    let file = held_file(&g);
    let aside = file.with_extension("aside");
    std::fs::rename(&file, &aside).unwrap();
    std::fs::create_dir(&file).unwrap();
    g.fake.op_rejected.next(1, retry("durability"));
    g.holds.probe("b-1");
    let lines = g.lines();
    assert_eq!((g.fake.sends(), lines.len(), lines[0]["sent"].as_bool()), (1, 1, Some(true)), "dialed once, the line standing marked in the queue");
    let begun = said_containing(&g, "held line 1's re-mark could not be copied to its held file");
    assert_eq!(begun.len(), 1, "the owed mark said once: {:?}", g.said.lock().unwrap());
    std::fs::remove_dir(&file).unwrap();
    std::fs::rename(&aside, &file).unwrap();
    g.holds.set_node_stopped("b-1", true);
    g.holds.probe("b-1");
    assert_eq!(g.fake.sends(), 1, "nothing dialed while the node is stopped");
    assert_eq!(said_containing(&g, "wait in memory no more").len(), 1, "the mark written, said once: {:?}", g.said.lock().unwrap());
    // The relaunch: this run's holds gone, the file as the retry left it.
    let Ground { holds, fake, session, store, .. } = g;
    drop(holds);
    let g = ground_over(fake, store, session.facts.clone(), 0);
    let lines = g.lines();
    assert_eq!((lines.len(), lines[0]["sent"].as_bool()), (1, Some(true)), "the relaunch reads the line as one whose dial may have landed: {lines:?}");
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

/// Checks that pending lines whose join the device refused join the board's
/// file at a later probe, the pending directory under this shell's lock
/// until they have (§3c.1, §3c.3; skep #823).
///
/// A burst held while the board's head record stood damaged is on the
/// pending file. The record reads while the board's directory stands
/// sealed: the probe's step takes the directory, the join is refused at the
/// file's create and said once — the line on disk, in the pending file — and
/// the line stands there, its resend refused `write_busy`, the pending
/// directory still under this shell's lock, so no other shell opens the file
/// this one appends to. The directory opened, the next probe joins the line
/// into the board's file, removes the pending file and lets the pending
/// directory's lock go (the mutant that never retries the join leaves the
/// line on a file no relaunch at the chain reads; the one that hands the
/// retry no pending directory refuses it for good; the one that lets the
/// lock go at the step leaves another shell free to open the file).
#[cfg(unix)]
#[test]
fn a_pending_join_the_device_refused_is_joined_at_a_later_probe() {
    let fake = Fake::new();
    *fake.head_answer.lock().unwrap() = Some((200, json!({"resp": "delivery", "items": [{"atom": "not a head record"}]})));
    let store = TempDir::new().unwrap();
    let facts = writer_facts(&store);
    let g = ground_over(fake, store, facts, 0);
    let OpAnswer::Answered(Ok(held)) = g.holds.send_burst(&g.session, insert(DOC, json!(["a"]), g.fake.head()), None) else { panic!("held, not faced") };
    assert_eq!(held["cause"], "head_unreadable", "{held}");
    let pending = pending_file(&g);
    assert!(std::fs::read_to_string(&pending).unwrap().contains("\"values\":[\"a\"]"), "the line is on the pending file");
    let (sealed, refused) = seal_the_boards_directory(g.store.path());
    *g.fake.head_answer.lock().unwrap() = None;
    g.fake.op_refused.every((503, json!({"error": "write_busy"})));
    g.holds.probe("b-1");
    assert!(!held_file(&g).exists(), "the join is refused at the board's file's create");
    let said = said_containing(&g, "could not join");
    assert!(said.len() == 1 && said[0].contains(&refused) && said[0].contains("stands in the pending held file"), "said once, the line on disk: {said:?}");
    assert_eq!(g.lines().len(), 1, "the line stands");
    assert!(std::fs::read_to_string(&pending).unwrap().contains("\"values\":[\"a\"]"), "on the pending file");
    let pending_store = HeldDir::pending(g.store.path(), g.session.board.dialed());
    assert!(pending_store.try_lock().unwrap().is_none(), "the pending directory stays under this shell's lock");
    g.holds.probe("b-1");
    assert_eq!(said_containing(&g, "could not join").len(), 1, "a second refused probe says nothing more");
    unseal(&sealed);
    g.holds.probe("b-1");
    assert!(std::fs::read_to_string(held_file(&g)).unwrap().contains("\"values\":[\"a\"]"), "the line joined the board's file");
    assert!(!pending.exists(), "the pending file is removed once its line joined");
    let landed = said_containing(&g, "joined the board's held file");
    assert!(landed.len() == 1 && landed[0].contains("1 held line joined"), "{landed:?}");
    assert!(pending_store.try_lock().unwrap().is_some(), "the pending directory's lock is let go");
}

/// Checks that the lines a refused join's copy left standing in the file are
/// never read back once their bursts are sent from memory (§3c.3; skep #817,
/// #821).
///
/// The board's file holds a line an earlier run left, and the board is away
/// at the session's open, so two bursts are held in memory. The board
/// returns: the join's one copy into its file is refused, and so is its
/// cut-back, the copy's two lines left standing past the file's whole lines,
/// so the join is refused, said once naming the copy left standing, and the
/// two bursts are sent from memory and kept. The device takes copies again,
/// and either the principal's door — `held(session)` — comes first, listing
/// the earlier run's line alone, the queue the join wrote taken in place of
/// a read of its file; or a probe comes first, its retry cutting the copy off
/// the file from the queue it keeps and saying so once, so the file reads the
/// earlier run's line alone. Either way the next probe sends that line, so
/// each burst is dialed once (the mutant that drops the join's queue reads
/// the copy at the door as held lines and sends the person's text a second
/// time; the one whose door reads the file in the queue's place reads it so
/// too; the one whose retry never cuts the kept queue's copy leaves it
/// standing in the file for a close to relaunch).
#[test]
fn a_refused_joins_copy_left_standing_is_never_read_back_once_it_is_sent_from_memory() {
    for door_first in [true, false] {
        let store = TempDir::new().unwrap();
        let ours = Chain::parse(&"ab".repeat(32)).unwrap();
        let dir = HeldDir::new(store.path(), ours);
        dir.ensure().unwrap();
        let Opened::Live { mut queue, .. } = dir.open_file(1, "1.0.1").unwrap() else { panic!("a fresh file") };
        assert!(queue.hold(OTHER, None, 0, insert(OTHER, json!(["earlier"]), 0), None, Reason::of("unreachable", false)).unwrap().unwritten.is_none());
        drop(queue);
        let fake = Fake::new();
        fake.head_unreachable.store(true, Ordering::SeqCst);
        let facts = writer_facts(&store);
        let g = ground_over(fake, store, facts, 0);
        for value in ["a", "b"] {
            let answer = g.hold(&insert(DOC, json!([value]), g.fake.head()), "unreachable", false);
            assert!(answer["unwritable"].as_str().is_some_and(|why| why.contains("could not be reached")), "door first {door_first}: held in memory, the board away: {answer}");
        }
        g.fake.head_unreachable.store(false, Ordering::SeqCst);
        crate::held::tests::refuse_copies_after(0);
        crate::held::tests::refuse_the_next_cut_back();
        g.holds.probe("b-1");
        crate::held::tests::take_copies();
        let standing = file_lines(&std::fs::read_to_string(held_file(&g)).unwrap());
        assert!(standing.iter().any(|line| line["frame"]["values"] == json!(["a"])), "door first {door_first}: premise: the join's copy of the first burst stands in the file: {standing:?}");
        let said = said_containing(&g, "could not join");
        assert!(said.len() == 1 && said[0].contains("the refused copy's lines stand in the file"), "door first {door_first}: said once, naming the copy left standing: {said:?}");
        let sent = |g: &Ground| g.fake.sends.lock().unwrap().iter().map(|frame| frame["values"][0].as_str().unwrap_or("?").to_string()).collect::<Vec<_>>();
        assert_eq!(sent(&g), ["a", "b"], "door first {door_first}: both sent from memory and kept");
        if !door_first {
            g.holds.probe("b-1");
            let Opened::Live { queue, .. } = HeldDir::new(g.store.path(), ours).open_file(1, "1.0.1").unwrap() else { panic!("the file reads live") };
            let read: Vec<Value> = queue.lines().iter().map(|line| line.frame["values"].clone()).collect();
            assert_eq!(read, [json!(["earlier"])], "the probe cut the copy: the file reads the earlier run's line alone");
            assert_eq!(said_containing(&g, "holds the copy a refused join made no more").len(), 1, "said once: {:?}", g.said.lock().unwrap());
        }
        let listed: Vec<Value> = g.lines().iter().map(|line| line["frame"]["values"].clone()).collect();
        assert_eq!(listed, [json!(["earlier"])], "door first {door_first}: the door lists the earlier run's line alone, never the copy the join undid");
        g.holds.probe("b-1");
        assert_eq!(sent(&g), ["a", "b", "earlier"], "door first {door_first}: each burst dialed once");
        assert!(g.lines().is_empty() && !held_file(&g).exists(), "door first {door_first}: every line kept, the file compacted");
    }
}

// ── THE DRAIN'S TURNS (§3c.5; skep #817) ────────────────────────────────────

/// The values of the bursts the fake board was sent, in the order it was.
fn sent_values(g: &Ground) -> Vec<String> {
    g.fake.sends.lock().unwrap().iter().map(|frame| frame["values"][0].as_str().unwrap_or("?").to_string()).collect()
}

/// Checks that a drain runs in bounded turns and sends every line in `k`
/// order.
///
/// `2 × TURN_STEPS + 1` lines no dial of which left, alternating between two
/// documents, drain in three probes: the first two turns stop at their
/// bound, `TURN_STEPS` sends each, answering `Bounded`, and the third sends
/// the last line and answers `Done`; the board meets every burst once, in
/// `k` order across the documents, and no line stands (the mutant that
/// drains the queue in one probe holds the feed thread from the first line
/// to the last; the one whose bound counts nothing stops nowhere; the one
/// that sends a document's lines apart from the other's breaks §3c.5's
/// order).
#[test]
fn a_drain_runs_in_bounded_turns_and_sends_every_line_in_k_order() {
    let g = unclaimed_ground();
    let lines = 2 * TURN_STEPS + 1;
    for n in 0..lines {
        let doc = if n % 2 == 0 { DOC } else { OTHER };
        g.hold(&insert(doc, json!([n.to_string()]), g.fake.head()), "unreachable", false);
    }
    let turns: Vec<(Turn, usize)> = (0..3).map(|_| (g.holds.probe("b-1"), g.fake.sends())).collect();
    assert_eq!(turns, [(Turn::Bounded, TURN_STEPS), (Turn::Bounded, 2 * TURN_STEPS), (Turn::Done, lines)], "two turns at the bound, then the last line");
    let want: Vec<String> = (0..lines).map(|n| n.to_string()).collect();
    assert_eq!(sent_values(&g), want, "every burst once, in `k` order across the documents");
    assert!(g.lines().is_empty(), "every line kept");
}

/// Checks that a turn reads a document as the walk reaches it, and that the
/// turns of one pass read each document once.
///
/// `2 × TURN_STEPS` documents each hold one line that may have landed and
/// did not: each is read for its landing, found none, and sent — a read and
/// a send, two steps — so the first turn reads and sends `TURN_STEPS / 2` of
/// them and stops at its bound, and the turns together read every document
/// once and send each line once (the mutant that reads every document before
/// its turn's sends reads them all at the first turn and the unreached ones
/// again at each turn after; the one whose bound counts no read lets a turn
/// read without end).
#[test]
fn a_turn_reads_a_document_as_it_reaches_it_and_a_pass_reads_each_once() {
    let g = unclaimed_ground();
    let docs = 2 * TURN_STEPS;
    for n in 0..docs {
        let doc = format!("1.0.1.0.{}", 100 + n);
        g.hold(&insert(&doc, json!(["x"]), g.fake.head()), "unreachable", true);
    }
    let reads = |g: &Ground| g.fake.changes_reads.load(Ordering::SeqCst);
    let first = g.holds.probe("b-1");
    assert_eq!((first, reads(&g), g.fake.sends()), (Turn::Bounded, TURN_STEPS / 2, TURN_STEPS / 2), "the first turn: a read and a send a document");
    let mut turns = 1;
    while g.holds.probe("b-1") == Turn::Bounded {
        turns += 1;
        assert!(turns <= 4, "a pass of {docs} documents ends within four turns");
    }
    assert_eq!((reads(&g), g.fake.sends(), g.lines().len()), (docs, docs, 0), "the turns together read each document once and send each line once");
}

/// Checks that a document's read waits for a turn with a step left for its
/// send.
///
/// `TURN_STEPS - 1` lines no dial of which left stand on one document, and
/// behind them one line that may have landed on another: the first turn
/// sends the first document's lines and, one step left, stops short of the
/// other's read; the next turn reads it, sends its line, and ends the pass,
/// the document read once (the mutant that spends a turn's last step on a
/// read leaves its send to the next turn, which reads the document again).
#[test]
fn a_documents_read_waits_for_a_turn_with_a_step_left_for_its_send() {
    let g = unclaimed_ground();
    for n in 0..TURN_STEPS - 1 {
        g.hold(&insert(DOC, json!([n.to_string()]), g.fake.head()), "unreachable", false);
    }
    g.hold(&insert(OTHER, json!(["read"]), g.fake.head()), "unreachable", true);
    let reads = |g: &Ground| g.fake.changes_reads.load(Ordering::SeqCst);
    assert_eq!((g.holds.probe("b-1"), g.fake.sends(), reads(&g)), (Turn::Bounded, TURN_STEPS - 1, 0), "the read waits for the next turn");
    assert_eq!((g.holds.probe("b-1"), g.fake.sends(), reads(&g)), (Turn::Done, TURN_STEPS, 1), "read once, and sent");
}

/// Checks that a document a turn stopped at is dialed no more until the
/// pass ends.
///
/// One line stands on one document, and `2 × TURN_STEPS` behind it in `k`
/// order on another. The first send of the pass — the first document's head
/// — is answered `durability`, which the next probe reissues, and the turns
/// go on with the other document: the second and third turns pass the first
/// document over, its head dialed once in the pass, and the third, reaching
/// the end, ends the pass. The next probe starts a pass of its own, and
/// sends the head and keeps it (the mutant that keeps no pass across its
/// turns reads and dials a failing head again at every turn, hammering the
/// board at the turns' pace; the one that never ends the pass sends the head
/// never again).
#[test]
fn a_document_a_turn_stopped_at_is_dialed_no_more_until_the_pass_ends() {
    let g = unclaimed_ground();
    g.hold(&insert(OTHER, json!(["first"]), g.fake.head()), "unreachable", false);
    for n in 0..2 * TURN_STEPS {
        g.hold(&insert(DOC, json!([n.to_string()]), g.fake.head()), "unreachable", false);
    }
    g.fake.op_rejected.next(1, retry("durability"));
    let dialed = |g: &Ground| sent_values(g).iter().filter(|value| *value == "first").count();
    let turns: Vec<(Turn, usize, usize)> = (0..3).map(|_| (g.holds.probe("b-1"), g.fake.sends(), dialed(&g))).collect();
    let want = [(Turn::Bounded, TURN_STEPS, 1), (Turn::Bounded, 2 * TURN_STEPS, 1), (Turn::Done, 2 * TURN_STEPS + 1, 1)];
    assert_eq!(turns, want, "the head dialed once in the pass, the other document's lines sent past it");
    assert_eq!(g.lines().len(), 1, "the head stands at the pass's end");
    assert_eq!((g.holds.probe("b-1"), dialed(&g), g.lines().len()), (Turn::Done, 2, 0), "the next pass sends it, and keeps it");
}

/// Checks that the person's `send` walks a document the pass stopped at
/// again at the pass's next turn.
///
/// A refused run stands on one document, `2 × TURN_STEPS` lines on another
/// behind it: the first turn passes the refused run over and sends
/// `TURN_STEPS` lines; the person sends the run again, and the next turn,
/// within the same pass, sends it first and keeps it (the mutant that leaves
/// the document stopped in the pass holds the person's act until the pass
/// ends and the cadence comes round).
#[test]
fn the_persons_send_walks_a_stopped_document_again_within_the_pass() {
    let g = unclaimed_ground();
    let verdict = json!({"resp": "rejected", "code": "out_of_bounds", "disposition": "permanent", "op": "insert"});
    let k = g.hold_for(&insert(OTHER, json!(["run"]), g.fake.head()), Reason::refused("out_of_bounds", verdict)).unwrap()["held"].as_u64().unwrap();
    for n in 0..2 * TURN_STEPS {
        g.hold(&insert(DOC, json!([n.to_string()]), g.fake.head()), "behind", false);
    }
    assert_eq!((g.holds.probe("b-1"), g.fake.sends()), (Turn::Bounded, TURN_STEPS), "the refused run passed over");
    assert_eq!(g.holds.resolve(&g.session, k, ResolveAct::Send).unwrap(), Resolved::HandedBack);
    assert_eq!(g.holds.probe("b-1"), Turn::Bounded, "the pass goes on");
    assert_eq!(sent_values(&g)[TURN_STEPS], "run", "the next turn sends the run first");
    assert!(g.lines().iter().all(|line| line["doc"] == DOC), "the run kept");
}

/// Checks that a full pending file joins the board's file in one copy with
/// one sync at the session's open.
///
/// An earlier run left `held::MAX_HELD_LINES` lines in the pending file of
/// the board's origin; the session's open reads the board's head and joins
/// them: the board's file holds every line, the pending file is gone, the
/// join said once, and the lines took one copy beside the file's header (the
/// mutant that copies the joined lines one by one syncs once a line, the
/// board's lock held across every one and the page's open waiting on them).
#[test]
fn a_full_pending_file_joins_the_boards_file_in_one_copy_with_one_sync() {
    use sha2::{Digest, Sha256};
    let store = TempDir::new().unwrap();
    // The origin the ground's board dials, as `Board::dialed` spells it.
    let origin = Origin::parse("http://127.0.0.1:1").unwrap().as_str().to_string();
    let hash = Chain::from_bytes(Sha256::digest(origin.as_bytes()).into());
    let pending = store.path().join("held").join("pending").join(hash.to_string());
    std::fs::create_dir_all(&pending).unwrap();
    let mut body = format!("{{\"type\":\"skep-held-bursts\",\"v\":2,\"board\":\"{origin}\",\"principal\":1,\"account\":\"1.0.1\"}}\n");
    for k in 1..=MAX_HELD_LINES {
        body.push_str(&format!("{}\n", json!({"held": k, "doc": DOC, "base": 0, "frame": insert(DOC, json!([k.to_string()]), 0), "cause": "head_unreadable", "sent": false, "time": 1})));
    }
    std::fs::write(pending.join("principal-1.held"), body).unwrap();
    let copies = crate::held::tests::count_copies();
    let facts = writer_facts(&store);
    let g = ground_over(Fake::new(), store, facts, 0);
    crate::held::tests::take_copies();
    assert_eq!(copies.get(), 1, "one copy, one sync");
    assert!(!pending_file(&g).exists(), "the pending file is gone");
    let Opened::Live { queue, .. } = HeldDir::new(g.store.path(), Chain::parse(&g.fake.chain).unwrap()).open_file(1, "1.0.1").unwrap() else { panic!("the board's file reads live") };
    assert_eq!(queue.lines().len(), MAX_HELD_LINES, "the board's file holds every line");
    let joined = said_containing(&g, "joined the board's held file");
    assert!(joined.len() == 1 && joined[0].contains(&format!("{MAX_HELD_LINES} held lines joined")), "{joined:?}");
}

/// Checks that a search at the board answers between two turns of a drain,
/// and that the turns run back to back.
///
/// `4 × TURN_STEPS` lines stand in memory at a board no one has claimed, and
/// the board's feed thread runs over the ground's holds. A probe handed over
/// starts the drain; its first send waits until a search is queued, and the
/// first send of the second turn until the search has answered. The search
/// answers between the two turns, `TURN_STEPS` lines kept and the rest
/// standing; released, the turns run on at once, every line kept within one
/// `PROBE_CADENCE`, in `k` order (the mutant that drains the queue in one
/// probe answers the search only once every line is kept; the one whose next
/// turn waits for the cadence keeps the last line three cadences later).
#[test]
fn a_search_answers_between_two_turns_of_a_drain_and_the_turns_run_back_to_back() {
    use crate::feed::{BridgeSearchOpts, Searcher};
    let g = unclaimed_ground();
    let lines = 4 * TURN_STEPS;
    for n in 0..lines {
        g.hold(&insert(DOC, json!([n.to_string()]), g.fake.head()), "unreachable", false);
    }
    let (queued_tx, queued_rx) = std::sync::mpsc::channel::<()>();
    let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
    let sends = AtomicUsize::new(0);
    *g.fake.at_send.lock().unwrap() = Some(Box::new(move || {
        let wait = Duration::from_secs(10);
        match sends.fetch_add(1, Ordering::SeqCst) + 1 {
            // The search is queued a moment after it is said to be.
            1 => {
                let _ = queued_rx.recv_timeout(wait);
                thread::sleep(Duration::from_millis(50));
            }
            n if n == TURN_STEPS + 1 => {
                let _ = release_rx.recv_timeout(wait);
            }
            _ => {}
        }
    }));
    let threads = feed_threads(&g);
    threads.feed().probe();
    queued_tx.send(()).unwrap();
    assert!(threads.feed().search(Searcher::Guest, "x", BridgeSearchOpts::default()).is_ok(), "the search answers");
    assert_eq!(g.lines().len(), lines - TURN_STEPS, "answered between the first two turns: one turn's lines kept, the rest standing");
    release_tx.send(()).unwrap();
    let released = Instant::now();
    while !g.lines().is_empty() {
        assert!(released.elapsed() < PROBE_CADENCE, "the turns ran back to back: {} lines stand after {:?}", g.lines().len(), released.elapsed());
        thread::sleep(Duration::from_millis(5));
    }
    threads.stop();
    let want: Vec<String> = (0..lines).map(|n| n.to_string()).collect();
    assert_eq!(sent_values(&g), want, "every line once, in `k` order");
}

/// Checks that a board that keeps committing starves no turn of a drain.
///
/// The board's commit stream yields a commit a millisecond, and each tick's
/// read of its feeds takes longer than that, so a tick waits behind every
/// tick the feed thread serves. `2 × TURN_STEPS` lines stand in memory, and
/// once the ticks flow a probe handed over starts the drain: between its two
/// turns the feed thread serves the commands queued, ticks among them, up to
/// the second tick, and runs the next turn, every line kept within one
/// `PROBE_CADENCE` (the mutant that serves every queued command between two
/// turns serves ticks for as long as the board commits, and the drain's next
/// turn never comes).
#[test]
fn a_board_that_keeps_committing_starves_no_turn_of_a_drain() {
    let g = unclaimed_ground();
    for n in 0..2 * TURN_STEPS {
        g.hold(&insert(DOC, json!([n.to_string()]), g.fake.head()), "unreachable", false);
    }
    g.fake.changes_delay_ms.store(3, Ordering::SeqCst);
    g.fake.commits.store(true, Ordering::SeqCst);
    let threads = feed_threads(&g);
    let flowing = Instant::now() + Duration::from_secs(10);
    while g.fake.changes_reads.load(Ordering::SeqCst) < 4 {
        assert!(Instant::now() < flowing, "premise: the ticks flow");
        thread::sleep(Duration::from_millis(5));
    }
    threads.feed().probe();
    let handed = Instant::now();
    while !g.lines().is_empty() {
        assert!(handed.elapsed() < PROBE_CADENCE, "the drain's turns went on behind the ticks: {} lines stand after {:?}", g.lines().len(), handed.elapsed());
        thread::sleep(Duration::from_millis(5));
    }
    threads.stop();
    assert_eq!(g.fake.sends(), 2 * TURN_STEPS, "every line sent once");
}

// ── THE BUDGETS, TIMED (§3c.3) ──────────────────────────────────────────────

/// Checks that the walk over a full queue drains within the ceiling.
///
/// It is the resend's own work at `held::MAX_HELD_LINES` lines whose frames
/// and anchors are `held::MAX_HELD_BYTES`: the queue in memory alone, at a
/// board no one has claimed that serves no head record — no line owing an
/// attest, no copy synced, the board answering at once — so the figure is
/// the walk's bookkeeping, in its two worst shapes, every line on one
/// document and each on its own; the probes, one a turn until a turn answers
/// `Done`, send every line and keep it, within `held::TIMED_CEILING`. Beside
/// it, what each line's send costs held or not: a queue of 256 lines on a
/// claimed board under a writer's session, its file this shell's, drained
/// turn by turn — each line attested, its mark and its `done` synced — and
/// its cost a line printed. The figures are printed with the build's
/// profile, and `held::MAX_HELD_LINES` states them.
#[test]
#[ignore = "timing test - gate-full only"]
fn the_walk_over_a_full_queue_drains_within_the_ceiling() {
    let profile = if cfg!(debug_assertions) { "unoptimized" } else { "optimized" };
    let edges = anchors(Some(&i(4)), Some(&i(5)));
    for (shape, apart) in [("on one document", false), ("each on its own document", true)] {
        let doc = |n: usize| if apart { format!("1.0.1.0.{}", 100_000 + n) } else { DOC.to_string() };
        let fake = Fake::new();
        fake.no_head.store(true, Ordering::SeqCst);
        fake.unclaimed.store(true, Ordering::SeqCst);
        let store = TempDir::new().unwrap();
        let facts = writer_facts(&store);
        let g = ground_over(fake, store, facts, 0);
        // Each line's frame and anchors a share of the byte budget, the
        // frame's values sized by the rest of its spelling.
        let rest = json_len(&insert(&doc(0), json!([""]), g.fake.head()));
        let values = "x".repeat(MAX_HELD_BYTES / MAX_HELD_LINES - edges.bytes() - rest);
        g.holds
            .with_principal("b-1", 1, |ph| {
                for n in 0..MAX_HELD_LINES {
                    ph.queue.hold(&doc(n), None, 0, insert(&doc(n), json!([values]), g.fake.head()), Some(edges.clone()), Reason::of("unreachable", false)).unwrap();
                }
            })
            .unwrap();
        let started = Instant::now();
        while g.holds.probe("b-1") == Turn::Bounded {}
        let took = started.elapsed();
        eprintln!("the walk over a full held queue, {MAX_HELD_LINES} lines {shape}, drains in {took:?} ({profile})");
        assert_eq!((g.fake.sends(), g.lines().len()), (MAX_HELD_LINES, 0), "{shape}: every line sent and kept");
        assert!(took < crate::held::TIMED_CEILING, "{shape}: the walk took {took:?}, past {:?}", crate::held::TIMED_CEILING);
    }
    // Each line's send, held or not: attested, its mark and its `done`
    // synced to the board's held file.
    let g = ground();
    let lines = 256;
    let frame = insert(DOC, json!(["x".repeat(2000)]), g.fake.head());
    g.holds
        .with_principal("b-1", 1, |ph| {
            for _ in 0..lines {
                ph.queue.hold(DOC, None, 0, frame.clone(), Some(edges.clone()), Reason::of("unreachable", false)).unwrap();
            }
        })
        .unwrap();
    let started = Instant::now();
    while g.holds.probe("b-1") == Turn::Bounded {}
    let took = started.elapsed();
    assert_eq!((g.fake.sends(), g.lines().len()), (lines, 0), "every line sent and kept");
    assert!(g.fake.sends.lock().unwrap().iter().all(|sent| sent.get("attest").is_some()), "each line attested");
    eprintln!("each held line's send — attested, its mark and its `done` synced to the held file — takes {:?} ({profile})", took / u32::try_from(lines).unwrap());
}
