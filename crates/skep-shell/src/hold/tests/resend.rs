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
//! the table holds nowhere, and the death signal, leaving a resent line
//! standing; a resend answered `500 internal_panic` marking its line `sent:
//! true`, its landing then kept by the read; a line that may have landed
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
//! and kept; and the lost answers and the shifts meeting the one bound, the
//! person's send counting both afresh; a resend marking its line `sent` on
//! disk before it dials, and a line acked whose `done` the device refused
//! relaunching so and kept by the read; the own node stopped,
//! `writes.halted` and a third `durability` holding a burst over time, a
//! reused ordinal's reissues counted afresh; every line's read starting past
//! the person's own write — a line held behind a landing or an ack read from
//! its position, and a line held after a landing the read found reading
//! past it; and a line whose resends keep losing their answer handed to the
//! person at its bound, a minute or two of probes — a timeout, a garbled
//! answer and a handler panic each one try, a connection never made none —
//! its landing kept where the read finds one, before the hand-over or at the
//! person's `send`.

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

/// Checks that a refusal the table holds nowhere leaves the line standing.
///
/// The board answering `credential_refused`/`index_rebuilding`,
/// retry-class — the cell index rebuilding after an open, when resends run
/// — is faced to no one and never makes the line `done` (the mutant that
/// writes `done kept` loses text the board refused); the next probe, the
/// index ready, sends and keeps it.
#[test]
fn a_refusal_the_table_holds_nowhere_leaves_the_line_standing() {
    let g = ground();
    g.fake.op_rejected.every(json!({"resp": "rejected", "code": "credential_refused", "detail": "index_rebuilding", "disposition": "retry", "op": "insert"}));
    g.hold(&insert(DOC, json!(["hello"]), g.fake.head()), "unreachable", false);
    g.holds.probe("b-1");
    assert_eq!(g.fake.sends(), 1, "the line was sent");
    assert_eq!(g.lines().len(), 1, "and stands: the board did not take it");
    assert!(!g.states().contains(&"kept".to_string()));
    g.fake.op_rejected.clear();
    g.holds.probe("b-1");
    assert_eq!(g.fake.sends(), 2, "the next probe sends it again");
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
/// A line that may have landed is resent at each probe, each answer lost —
/// a timeout, a garbled answer and the board's handler panicking in turn,
/// each one try. Through `MAX_LOST_ANSWERS` tries it holds, `not_resolvable`;
/// at the next probe, its read finding no landing, it is handed to the
/// person undialed: a refused run under `answers_lost`, its `sent` kept,
/// said once on TALK and `refused` on the `held` event. A burst after it is
/// held `behind`, and the probe dials nothing more; the person's `send`
/// hands the line back, its tries counted afresh, and the next probe sends
/// and keeps both (§3c.4; skep #608). The mutants that never count resend
/// it for ever; the one that keeps the count at the person's `send` hands
/// it straight back.
#[test]
fn a_line_whose_resends_lose_their_answer_is_handed_to_the_person() {
    let g = ground();
    let k = g.hold(&insert(DOC, json!(["a"]), g.fake.head()), "unreachable", true)["held"].as_u64().unwrap();
    for n in 0..MAX_LOST_ANSWERS {
        lose_the_next_answer(&g, n);
        g.holds.probe("b-1");
    }
    let tries = MAX_LOST_ANSWERS as usize;
    let lines = g.lines();
    assert_eq!((g.fake.sends(), lines[0]["cause"].as_str(), lines[0]["sent"].as_bool()), (tries, Some("unreachable"), Some(true)), "{lines:?}");
    assert_eq!(g.holds.resolve(&g.session, k, ResolveAct::Drop).unwrap_err().name(), "not_resolvable", "the board's to answer still");
    let _ = g.states();
    g.holds.probe("b-1");
    let lines = g.lines();
    assert_eq!(g.fake.sends(), tries, "handed over undialed");
    assert_eq!((lines[0]["cause"].as_str(), lines[0]["sent"].as_bool()), (Some("answers_lost"), Some(true)), "{lines:?}");
    assert_eq!(lines[0]["refusal"], json!({"kind": "shell", "name": "answers_lost", "tries": MAX_LOST_ANSWERS}));
    assert_eq!(g.states(), ["refused"]);
    let said = g.said.lock().unwrap().clone();
    let line = format!("held: line {k} on {DOC}: {MAX_LOST_ANSWERS} resends lost their answer");
    assert_eq!(said.iter().filter(|l| l.starts_with(&line)).count(), 1, "said once: {said:?}");
    let OpAnswer::Answered(Ok(behind)) = g.holds.send_burst(&g.session, insert(DOC, json!(["b"]), g.fake.head()), None) else { panic!("held behind the line handed over") };
    assert_eq!(behind["cause"], "behind", "{behind}");
    g.holds.probe("b-1");
    assert_eq!(g.fake.sends(), tries, "the lines wait for the person's act");
    assert_eq!(g.holds.resolve(&g.session, k, ResolveAct::Send).unwrap(), Resolved::HandedBack);
    let lines = g.lines();
    assert_eq!((lines[0]["cause"].as_str(), lines[0]["sent"].as_bool()), (Some("behind"), Some(true)), "the person's send keeps `sent`: {lines:?}");
    g.holds.probe("b-1");
    assert_eq!(g.fake.sends(), tries + 2, "both lines sent");
    assert!(g.lines().is_empty() && g.states().contains(&"kept".to_string()));
}

/// Checks that a line handed over whose write landed is kept at the send.
///
/// A line handed to the person after its resends lost their answer keeps
/// its `sent`, and the person's `send` keeps it: where the write whose
/// answer the board lost has landed after all — a row whose testimony the
/// board lost, the line's values at its site — the next probe's read finds
/// it and keeps the line, never sending it twice (§3c.5; skep #608; the
/// mutant whose `send` re-marks the line `sent: false` faces the person's
/// own text `moved`).
#[test]
fn a_handed_over_line_whose_write_landed_is_kept_at_the_persons_send() {
    let g = ground();
    let k = g.hold(&insert(DOC, json!(["hello"]), g.fake.head()), "unreachable", true)["held"].as_u64().unwrap();
    for _ in 0..MAX_LOST_ANSWERS {
        g.fake.op_refused.next(1, (500, json!({"error": "internal_panic"})));
        g.holds.probe("b-1");
    }
    g.holds.probe("b-1");
    assert_eq!(g.lines()[0]["cause"], "answers_lost", "handed to the person");
    *g.fake.rows.lock().unwrap() = vec![lost_row()];
    *g.fake.text.lock().unwrap() = "hello".into();
    assert_eq!(g.holds.resolve(&g.session, k, ResolveAct::Send).unwrap(), Resolved::HandedBack);
    let _ = g.states();
    g.holds.probe("b-1");
    let states = g.states();
    assert_eq!(g.fake.sends(), MAX_LOST_ANSWERS as usize, "never sent twice");
    assert!(g.lines().is_empty() && states.contains(&"kept".to_string()) && !states.contains(&"moved".to_string()), "{states:?}");
}

/// Checks that a line whose last lost answer landed is never handed over.
///
/// Before a line is handed to the person its read runs the landed test
/// (§3c.5): a line whose resends lost their answer `MAX_LOST_ANSWERS`
/// times, the last write then found landed — a row whose testimony the
/// board lost, the line's values at its site — is kept at the next probe,
/// never refused and never sent again (skep #608; the mutant that hands
/// the line over before its read refuses text the board holds).
#[test]
fn a_line_whose_last_lost_answer_landed_is_kept_never_handed_over() {
    let g = ground();
    g.hold(&insert(DOC, json!(["hello"]), g.fake.head()), "unreachable", true);
    for _ in 0..MAX_LOST_ANSWERS {
        g.fake.op_refused.next(1, (500, json!({"error": "internal_panic"})));
        g.holds.probe("b-1");
    }
    *g.fake.rows.lock().unwrap() = vec![lost_row()];
    *g.fake.text.lock().unwrap() = "hello".into();
    let _ = g.states();
    g.holds.probe("b-1");
    assert_eq!(g.states(), ["kept"]);
    assert_eq!(g.fake.sends(), MAX_LOST_ANSWERS as usize, "never sent again");
    assert!(g.lines().is_empty(), "kept, never refused");
}

/// Checks that a connection never made counts no try.
///
/// Where every resend fails at the connect — the board not answering, no
/// request leaving — no answer was lost: the line holds `unreachable` past
/// `MAX_LOST_ANSWERS` probes, `not_resolvable`, until the board answers and
/// the next probe sends and keeps it (§3c.4; the mutant that counts a
/// connection never made hands an outage's line to the person).
#[test]
fn a_connection_never_made_counts_no_try() {
    let g = ground();
    let k = g.hold(&insert(DOC, json!(["a"]), g.fake.head()), "unreachable", false)["held"].as_u64().unwrap();
    g.fake.op_unreachable.store(true, Ordering::SeqCst);
    for _ in 0..=MAX_LOST_ANSWERS {
        g.holds.probe("b-1");
    }
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
/// record that cannot be read, or its connection never made. Past
/// `MAX_LOST_ANSWERS` probes the line stands `sent: true`, nothing dialed and
/// no try counted; and where the earlier write has landed after all — a row
/// whose testimony the board lost, the line's values at its site — the next
/// probe's read keeps it, never sent twice (§3c.2; the mutant that re-marks
/// with the resend's own `sent` faces the person's own text `moved`, and the
/// one that counts a try off the line's kept `sent` hands an outage's line to
/// the person).
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
        for _ in 0..=MAX_LOST_ANSWERS {
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

/// Checks that the hand-over comes within a minute or two of probes.
///
/// `MAX_LOST_ANSWERS` tries at `PROBE_CADENCE` hand a line over between one
/// minute and two of wall time where each try fails at once (skep #608).
#[test]
fn the_hand_over_comes_within_a_minute_or_two_of_probes() {
    let wall = u64::from(MAX_LOST_ANSWERS) * PROBE_CADENCE.as_secs();
    assert!((60..=120).contains(&wall), "{MAX_LOST_ANSWERS} tries at {PROBE_CADENCE:?} take {wall} s");
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

/// Checks that the lost answers and the shifts meet the one bound (skep
/// #442; the resend's bound).
///
/// A line that may have landed loses its answer at one probe; then another
/// writer's change lands as each dial reaches the board: the next probe's
/// read finds no landing, the dial is refused, and the line is shifted and
/// refused again until its one lost answer and its shifts together reach
/// the bound — `MAX_LOST_ANSWERS − 1` shifts — and the shift is not made
/// again: the line is held moved, the bound said once. The person's `send`
/// counts both afresh: the other writer's change landing once more, the
/// next probe sends, shifts twice and keeps it (the mutant that counts the
/// shifts apart from the lost answers shifts a line thirty more times past
/// a lost answer; the one whose `send` keeps the shift count holds the line
/// moved again at its second shift).
#[test]
fn the_lost_answers_and_the_shifts_meet_the_one_bound() {
    let g = ground();
    let typed = g.fake.head();
    let k = g.hold_anchored(&insert_at(DOC, 2, json!(["x"]), typed), anchors(Some(&i(1)), Some(&i(2))), "unreachable", true)["held"].as_u64().unwrap();
    lose_the_next_answer(&g, 0);
    g.holds.probe("b-1");
    assert_eq!(g.fake.sends(), 1, "one answer lost");
    *g.fake.image.lock().unwrap() = vec![run(&i(1), 3)];
    // The other writer's change lands as each dial reaches the board, for
    // as many dials as are left to it.
    let changes_left = Arc::new(AtomicUsize::new(usize::MAX));
    let (fake, left) = (Arc::clone(&g.fake), Arc::clone(&changes_left));
    *g.fake.at_send.lock().unwrap() = Some(Box::new(move || {
        if left.try_update(Ordering::SeqCst, Ordering::SeqCst, |n| n.checked_sub(1)).is_ok() {
            let at = fake.next_at.fetch_add(1, Ordering::SeqCst);
            fake.move_arrangement(DOC, at);
        }
    }));
    let _ = g.states();
    g.holds.probe("b-1");
    let shifts = (MAX_LOST_ANSWERS - 1) as usize;
    assert_eq!((g.fake.sends(), g.fake.image_reads.load(Ordering::SeqCst)), (1 + 1 + shifts, shifts), "refused, shifted and refused again to the bound, the lost answer counted with the shifts: then held");
    let lines = g.lines();
    assert_eq!((lines[0]["cause"].as_str(), lines[0]["sent"].as_bool(), lines[0]["refusal"]["code"].as_str()), (Some("moved"), Some(true), Some("arrangement_moved")), "{lines:?}");
    assert_eq!(g.states(), ["sending", "moved"]);
    let talk = g.said.lock().unwrap().clone();
    assert_eq!(talk.iter().filter(|l| l.contains(&format!("its {MAX_LOST_ANSWERS} tries stand at the bound"))).count(), 1, "{talk:?}");
    changes_left.store(2, Ordering::SeqCst);
    assert_eq!(g.holds.resolve(&g.session, k, ResolveAct::Send).unwrap(), Resolved::HandedBack);
    g.holds.probe("b-1");
    assert_eq!((g.fake.sends(), g.fake.image_reads.load(Ordering::SeqCst)), (1 + 1 + shifts + 3, shifts + 2), "the person's send counts afresh: refused, shifted and refused once more, shifted again and kept");
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
