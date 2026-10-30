//! The resend walk over a fake board (§3c.5).
//!
//! The suite checks the read's table, every answer the read can meet
//! against every answer its site read can — no row (send from the head), one
//! own row its site does not contradict (the head `done kept`, nothing
//! re-sent), a lost testimony and `history_reclaimed` decided by the site
//! alone, a foreign row, two rows and a page too large (moved, nothing
//! sent, never rebased), a read or a site the board does not answer — the
//! death signal among its answers — deciding nothing, and a delivery past
//! the values asked differing — with the narrative cells beside it; the
//! order, the lines sent in `k` order across the documents; the own hand on
//! a read; a refusal the table holds nowhere, and the death signal, leaving
//! a resent line standing; a resend answered `500 internal_panic` marking
//! its line `sent: true`, its landing then kept by the read; a second
//! window's burst resent from memory; every principal's lines resent by one
//! probe, a bare session's line resent by none until a session of its
//! principal's that may write stands, and a probe with no line standing
//! dialing nothing; one drain per board at a time, and a drain that unwinds
//! leaving the board free to drain again; a move facing its own document
//! alone; and the own node stopped, `writes.halted` and a third
//! `durability` holding a burst over time, a reused ordinal's reissues
//! counted afresh.

use super::*;

/// Checks outcome (i): no row since `base` sends the burst from the head.
///
/// The held burst is sent and acked, the line resolved, the document's
/// state `kept`.
#[test]
fn outcome_i_no_row_sends_from_the_head() {
    let g = ground();
    g.hold(&insert(DOC, json!(["hello"])), "unreachable", false);
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
    g.hold(&insert(DOC, json!(["hello"])), "unreachable", true);
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
        g.hold(&insert(doc, json!([value])), "unreachable", false);
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
    g.hold(&insert(DOC, json!(["hello"])), "unreachable", false);
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
    g.hold(&insert(DOC, json!(["hello"])), "unreachable", false);
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
    g.hold(&insert(DOC, json!(["a"])), "unreachable", false);
    g.holds.hold(&second, Burst::admit(insert("1.0.2.0.1", json!(["b"])), &second).unwrap(), Reason::of("unreachable", false)).unwrap();
    g.holds.probe("b-1");
    let mut sent: Vec<String> = g.fake.sends.lock().unwrap().iter().map(|f| f["doc"].as_str().unwrap_or("?").to_string()).collect();
    sent.sort();
    assert_eq!(sent, [DOC, "1.0.2.0.1"], "each principal's line is sent");
    assert!(g.lines().is_empty() && g.holds.lines(&second).unwrap().as_array().unwrap().is_empty(), "and each kept");
}

/// Checks outcome (iii): a foreign row moves the document.
///
/// With a foreign row on the document since `base` the site moved: no line
/// is sent, the lines are re-faced `moved`, never rebased (the mutant that
/// sends the moved line at its old base).
#[test]
fn outcome_iii_a_foreign_row_moves_the_document() {
    let g = ground();
    *g.fake.rows.lock().unwrap() = vec![json!({"at": 77, "op": "insert", "key": "ff".repeat(32), "docs": [DOC]})];
    g.hold(&insert(DOC, json!(["hello"])), "unreachable", true);
    g.holds.probe("b-1");
    assert_eq!(g.fake.sends(), 0, "no line of a moved document is sent");
    let lines = g.lines();
    assert_eq!(lines[0]["cause"], "moved", "the line is faced moved: {lines:?}");
    let states = g.states();
    assert!(states.contains(&"moved".to_string()) && !states.contains(&"sending".to_string()), "a moved document is never said `sending`: {states:?}");
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
    g.hold(&insert(DOC, json!(["hello"])), "unreachable", false);
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

/// Checks that a signed row is own under a keyed session alone.
///
/// It is the own hand on a read (§3c.5; wire.md §`/changes`): a signed
/// entry's row carries `attest` and no `key`, and is the session's own
/// under a session that holds a key — the head `done kept`, nothing re-sent
/// (the mutant that keys the test on `key` alone faces the signed row
/// `moved`); a row with `key: "bare"` is another hand's, never a keyed
/// session's own. No read is made under a bare session, which writes
/// nothing of its own to find (`a_bare_session_resends_no_held_line`).
#[test]
fn a_signed_row_is_own_under_a_keyed_session_alone() {
    let signed_row = json!({"at": 77, "op": "insert", "docs": [DOC], "attest": {"alg": "x", "sig": "y"}});
    let bare_row = json!({"at": 77, "op": "insert", "docs": [DOC], "key": "bare"});
    let walk = |facts: Facts, row: Value| -> (Vec<String>, usize) {
        let g = ground_in(TempDir::new().unwrap(), facts, 0);
        *g.fake.text.lock().unwrap() = "hello".into();
        *g.fake.rows.lock().unwrap() = vec![row];
        g.hold(&insert(DOC, json!(["hello"])), "unreachable", true);
        g.holds.probe("b-1");
        (g.states(), g.fake.sends())
    };
    let (states, sends) = walk(keyed_facts(), signed_row.clone());
    assert!(states.contains(&"kept".to_string()) && !states.contains(&"moved".to_string()), "the signed row is the keyed session's own: {states:?}");
    assert_eq!(sends, 0, "the landed head is not re-sent");
    let (states, _) = walk(keyed_facts(), bare_row);
    assert!(states.contains(&"moved".to_string()), "a bare hand's row is foreign to a keyed session: {states:?}");
}

/// Checks that a lost-testimony row is judged by the arrangement alone.
///
/// A row whose testimony the board lost (`docs`, `key`, `op` the reserved
/// null — the `poisoned` burst a restart replays, §3c.2) is judged so,
/// decisively: a `sent` insert whose values read back equal is kept and not
/// re-sent (the mutant that reads it as a foreign hand faces the person's
/// own text `moved`); values that differ are `moved`; a kind the site read
/// cannot confirm is `moved` too, the person's act; and a head that was
/// never sent reads any row as `moved`.
#[test]
fn a_lost_testimony_row_is_judged_by_the_arrangement_alone() {
    let lost = lost_row();
    let walk = |frame: Value, text: &str, sent: bool| -> (Vec<String>, usize) {
        let g = ground();
        *g.fake.text.lock().unwrap() = text.into();
        *g.fake.rows.lock().unwrap() = vec![lost.clone()];
        g.hold(&frame, "poisoned", sent);
        g.holds.probe("b-1");
        (g.states(), g.fake.sends())
    };
    let (states, sends) = walk(insert(DOC, json!(["hello"])), "hello", true);
    assert!(states.contains(&"kept".to_string()) && !states.contains(&"moved".to_string()), "the landed insert is kept: {states:?}");
    assert_eq!(sends, 0, "the landed head is not re-sent");
    let (states, sends) = walk(insert(DOC, json!(["hello"])), "other", true);
    assert!(states.contains(&"moved".to_string()) && sends == 0, "values that differ: moved, nothing sent: {states:?}");
    let (states, sends) = walk(delete(DOC), "hello", true);
    assert!(states.contains(&"moved".to_string()) && sends == 0, "a kind the site read cannot confirm: moved: {states:?}");
    let (states, sends) = walk(insert(DOC, json!(["hello"])), "hello", false);
    assert!(states.contains(&"moved".to_string()) && sends == 0, "a head never sent reads any row as moved: {states:?}");
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
    g.hold(&insert(DOC, json!(["hello"])), "unreachable", true);
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

/// Checks that `history_reclaimed` on the read decides by the arrangement.
///
/// The arrangement alone decides (§3c.5) — a `sent` head whose values read
/// back equal at its site is (ii), kept and not re-sent; values that differ
/// are (iii); a site read the board does not answer decides nothing and the
/// line stands (the mutant that trusts an unread site keeps a burst that
/// never landed).
#[test]
fn history_reclaimed_decides_by_the_arrangement() {
    let reclaimed = || Some((410, json!({"error": "history_reclaimed", "floor": 90})));
    let g = ground();
    *g.fake.changes_refused.lock().unwrap() = reclaimed();
    *g.fake.text.lock().unwrap() = "hello".into();
    g.hold(&insert(DOC, json!(["hello"])), "unreachable", true);
    g.holds.probe("b-1");
    assert_eq!(g.fake.sends(), 0, "the landed head is not re-sent");
    assert!(g.lines().is_empty(), "the values at the site keep it");
    assert!(g.states().contains(&"kept".to_string()));

    let g = ground();
    *g.fake.changes_refused.lock().unwrap() = reclaimed();
    *g.fake.text.lock().unwrap() = "other".into();
    g.hold(&insert(DOC, json!(["hello"])), "unreachable", true);
    g.holds.probe("b-1");
    assert_eq!((g.fake.sends(), g.lines()[0]["cause"].as_str()), (0, Some("moved")), "values that differ: moved");

    let g = ground();
    *g.fake.changes_refused.lock().unwrap() = reclaimed();
    g.fake.site_unread.store(true, Ordering::SeqCst);
    g.hold(&insert(DOC, json!(["hello"])), "unreachable", true);
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
    g.hold(&insert(DOC, json!(["hello"])), "unreachable", false);
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
    let answer = g.hold(&insert(DOC, json!(["hello"])), "unreachable", false);
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
    let still = g.hold(&insert(DOC, json!(["b"])), "unreachable", false);
    assert!(still["unwritable"].is_string(), "until a probe or a session's open tries the lock again: {still}");
    g.holds.probe("b-1");
    assert!(g.lines().is_empty(), "resent and kept");
    let next = g.hold(&insert(DOC, json!(["c"])), "unreachable", false);
    assert!(next.get("unwritable").is_none(), "the directory is this shell's now: {next}");
    assert!(std::fs::read_to_string(held_dir.join("principal-1.held")).unwrap().contains("\"values\":[\"c\"]"), "the line is copied to the board's file");
}

/// Returns the hands a moved document's `held` event names, over `rows` —
/// built from this store's own fingerprint and a second, labelled key's.
fn moved_hands(rows: impl Fn(&str, &str) -> Vec<Value>) -> Vec<Value> {
    let store = TempDir::new().unwrap();
    let facts = writer_facts(&store);
    let KeyId(other) = FileStore::open(store.path().join("store")).generate(Some(skep_client::sheet::Label::new("phone").unwrap())).unwrap();
    let g = ground_in(store, facts, 0);
    *g.fake.rows.lock().unwrap() = rows(&g.own_key(), &other.to_hex());
    g.hold(&insert(DOC, json!(["hello"])), "unreachable", false);
    g.holds.probe("b-1");
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
/// The rows since `base` the read holds — its page of two — give the hands
/// the `held` event's `moved` state carries: this store's own key by its
/// fingerprint, another key the shell's key store holds with its label,
/// another key it does not hold by its fingerprint alone, `bare`, a row
/// whose testimony the board lost, and a signed row — the own hand, as the
/// read reads it; a hand twice on the page is named once (the mutants that
/// name no hand, one per row, or a label for a key the store does not
/// hold).
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

/// Checks that a drain that unwinds leaves the board free to drain (§3c.4).
///
/// It leaves no mark: a probe whose `/health` dial panics leaves the board
/// free to drain, and the next probe sends and keeps the line (the mutant
/// whose mark outlives an unwinding drain sends nothing for the shell's
/// life).
#[test]
fn a_drain_that_unwinds_leaves_the_board_free_to_drain() {
    let g = ground();
    g.hold(&insert(DOC, json!(["hello"])), "unreachable", false);
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
    g.hold(&insert(DOC, json!(["hello"])), "unreachable", false);
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
    /// `400 malformed_changes` naming a `fits` of one row: two rows or more.
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
    /// Faced `moved`, nothing sent.
    Moved,
    /// Left as it stood: nothing sent, nothing said.
    Standing,
}

/// Checks the read's table (§3c.5), cell by cell.
///
/// No row sends from the head; one row is the head's landing only where the
/// head was sent and the row is of the session's own hand and of the head's
/// own `op`, its site not contradicting it — an `insert` read back equal, a
/// kind no read confirms trusted on its hand; a row whose testimony the
/// board lost, and `history_reclaimed`, are decided by the site alone, a
/// kind no read confirms faced `moved`; a foreign row, two rows and a page
/// too large to serve are `moved`; a read or a site read the board does not
/// answer — its answer the death signal among them — decides nothing; a
/// site read delivering past the values asked differs. The mutants the
/// cells hold off: a second tab's own-hand row landing a head whose site
/// says otherwise (3), a delete faced on its own hand (4), an unread site
/// taken as either answer (5, 11, 18), a head never sent kept off a row (6,
/// 19), another `op` of the own hand (7), the first of two rows taken as
/// the landing (14), a reclaimed kind no read confirms kept (17), a page too
/// large read as none or as unread (20), the death signal at the site read
/// taken as an answer (22–24), and a delivery past the values asked read as
/// theirs (25–27).
#[test]
fn every_read_answer_meets_every_site_answer_as_the_table_says() {
    use Head::{Delete, Insert};
    use ReadAnswer::{ForeignRow, LostRow, NoRow, OwnRow, Reclaimed, Refused, TooLarge, TwoOwnRows};
    use Settles::{Kept, Moved, Resent, Standing};
    use SiteAnswer::{Closed, Differs, Equal, OverDelivers, Unread};
    let table = [
        (NoRow, Insert, None, true, Resent),
        (OwnRow("insert"), Insert, Some(Equal), true, Kept),
        (OwnRow("insert"), Insert, Some(Differs), true, Moved),
        (OwnRow("delete"), Delete, None, true, Kept),
        (OwnRow("insert"), Insert, Some(Unread), true, Standing),
        (OwnRow("insert"), Insert, Some(Equal), false, Moved),
        (OwnRow("delete"), Insert, Some(Equal), true, Moved),
        (LostRow, Insert, Some(Equal), true, Kept),
        (LostRow, Insert, Some(Differs), true, Moved),
        (LostRow, Delete, None, true, Moved),
        (LostRow, Insert, Some(Unread), true, Standing),
        (LostRow, Insert, Some(Equal), false, Moved),
        (ForeignRow, Insert, Some(Equal), true, Moved),
        (TwoOwnRows, Insert, Some(Equal), true, Moved),
        (Reclaimed, Insert, Some(Equal), true, Kept),
        (Reclaimed, Insert, Some(Differs), true, Moved),
        (Reclaimed, Delete, None, true, Moved),
        (Reclaimed, Insert, Some(Unread), true, Standing),
        (Reclaimed, Insert, Some(Equal), false, Moved),
        (TooLarge, Insert, Some(Equal), true, Moved),
        (Refused, Insert, Some(Equal), true, Standing),
        (OwnRow("insert"), Insert, Some(Closed), true, Standing),
        (LostRow, Insert, Some(Closed), true, Standing),
        (Reclaimed, Insert, Some(Closed), true, Standing),
        (OwnRow("insert"), Insert, Some(OverDelivers), true, Moved),
        (LostRow, Insert, Some(OverDelivers), true, Moved),
        (Reclaimed, Insert, Some(OverDelivers), true, Moved),
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
            TooLarge => refused(400, json!({"error": "malformed_changes", "fits": 1})),
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
            Insert => insert(DOC, json!(["hello"])),
            Delete => delete(DOC),
        };
        g.hold(&frame, "unreachable", sent);
        g.holds.probe("b-1");
        // The sends, the causes still standing, and the `held` states said
        // after the hold's own `holding`.
        let (sends, standing, says): (usize, &[&str], &[&str]) = match settles {
            Resent => (1, &[], &["sending", "kept"]),
            Kept => (0, &[], &["kept"]),
            Moved => (0, &["moved"], &["moved"]),
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
    }
}

/// Checks that a moved document faces its own lines alone (§3c.5).
///
/// A foreign row on one document moves it, while a burst held `behind` it
/// on a second document, whose read finds no row under it, is sent and
/// kept (the mutant that faces every line moved at one document's foreign
/// row strands the person's text on the other).
#[test]
fn a_moved_document_faces_its_own_lines_alone() {
    let g = ground();
    *g.fake.rows.lock().unwrap() = vec![json!({"at": 77, "op": "insert", "key": "ff".repeat(32), "docs": [DOC]})];
    g.hold(&insert(DOC, json!(["a"])), "unreachable", false);
    let OpAnswer::Answered(Ok(behind)) = g.holds.send_burst(&g.session, insert(OTHER, json!(["z"]))) else { panic!("held behind the line") };
    assert_eq!(behind["cause"], "behind", "{behind}");
    g.holds.probe("b-1");
    let lines = g.lines();
    let standing: Vec<(&str, &str)> = lines.iter().map(|l| (l["doc"].as_str().unwrap_or("?"), l["cause"].as_str().unwrap_or("?"))).collect();
    assert_eq!(standing, [(DOC, "moved")], "the moved document's line alone stands");
    let sent_docs: Vec<Value> = g.fake.sends.lock().unwrap().iter().map(|f| f["doc"].clone()).collect();
    assert_eq!(sent_docs, [json!(OTHER)], "the other document's line is sent");
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
    let OpAnswer::Answered(Ok(held)) = g.holds.send_burst(&g.session, insert(DOC, json!(["hello"]))) else { panic!("held before the dial") };
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
    let OpAnswer::Answered(Ok(held)) = g.holds.send_burst(&g.session, insert(DOC, json!(["hello"]))) else { panic!("held before the dial") };
    assert_eq!(held["cause"], "halted", "{held}");
    g.holds.probe("b-1");
    assert_eq!(g.fake.sends(), 0, "a board whose writes are halted is sent nothing");
    g.fake.writes_halted.store(false, Ordering::SeqCst);
    g.holds.probe("b-1");
    assert_eq!(g.fake.sends(), 1, "the read that says writes go ends the hold");
    assert!(g.lines().is_empty());
    let OpAnswer::Answered(Ok(next)) = g.holds.send_burst(&g.session, insert(DOC, json!(["!"]))) else { panic!("the burst was answered") };
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
    g.hold(&insert(DOC, json!(["hello"])), "unreachable", false);
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
    let first = g.hold(&insert(DOC, json!(["a"])), "unreachable", false);
    for _ in 0..3 {
        g.holds.probe("b-1");
    }
    assert_eq!(g.fake.sends(), 3, "reissued twice, then sent and kept");
    assert!(g.lines().is_empty(), "the line is kept and the queue empties");
    let again = g.hold(&insert(DOC, json!(["b"])), "unreachable", false);
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
    g.hold(&insert(DOC, json!(["a"])), "unreachable", false);
    g.holds.probe("b-1");
    assert_eq!((reads(), g.fake.sends()), (1, 1), "a standing line is probed and sent");
    assert!(g.lines().is_empty(), "and kept");
    g.holds.probe("b-1");
    assert_eq!(reads(), 1, "the queue empty again, the probe reads nothing more");
}
