//! THE RESEND WALK over a fake board (§3c.5): THE READ's TABLE, every answer
//! the read can meet against every answer its site read can — no row (send
//! from the head), one own row its site does not contradict (the head `done
//! kept`, nothing re-sent), a lost testimony and `history_reclaimed`
//! decided by the site alone, a foreign row, two rows and a page too large
//! (MOVED, nothing sent, never rebased), a read or a site the board does not
//! answer — the death signal among its answers — deciding nothing, and a
//! delivery past the values asked differing — with the narrative cells
//! beside it; THE ORDER, the lines sent in `k` order across the documents;
//! the own hand on a read; a refusal the table holds nowhere, and the death
//! signal, leaving a resent line standing; a second window's burst resent
//! from memory; every principal's lines resent by one probe; one drain per
//! board at a time, and a drain that unwinds leaving the board free to drain
//! again; a move facing its own document alone; and the own node stopped,
//! `writes.halted` and a third `durability` holding a burst over time.

use super::*;

/// OUTCOME (i): no row since `base` — the held burst is sent from the head and
/// acked, the line resolved, the document's state `kept`.
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

/// OUTCOME (ii): the in-flight burst (its line `sent: true`) landed — one row
/// of the session's own hand, consistent, its five values read back equal at
/// the site — so the head is `done kept` and NOTHING is re-sent (the mutant
/// that resends the head; the mutant that compares the frame's one string
/// with one position's value faces the person's own text `moved`).
#[test]
fn outcome_ii_a_landed_burst_is_kept_not_resent() {
    let g = ground();
    *g.fake.text.lock().unwrap() = "hello".into();
    *g.fake.rows.lock().unwrap() = vec![json!({"at": 77, "op": "insert", "key": "bare", "docs": [DOC]})];
    g.hold(&insert(DOC, json!(["hello"])), "unreachable", true);
    g.holds.probe("b-1");
    assert_eq!(g.fake.sends(), 0, "the landed head is NOT re-sent: {:?}", g.fake.sends.lock().unwrap());
    assert!(g.lines().is_empty(), "the line is done kept");
    let states = g.states();
    assert!(states.contains(&"kept".to_string()) && !states.contains(&"moved".to_string()), "{states:?}");
}

/// THE ORDER (§3c.5: "lines in `k` order across the board's documents, which
/// keeps each document's order"): three lines held on two documents — one on
/// `DOC`, one on `OTHER`, one more on `DOC` — go out as they were held, so a
/// `copy` held between two bursts on its source transcludes the source as
/// the person wrote it (the mutant that sends each document's whole run in
/// turn sends the second `DOC` line before the `OTHER` one, and the copy
/// lands the wrong text with no refusal to say so).
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

/// THE DEATH SIGNAL at a resend's dial leaves its line standing (§3c.4: the
/// death is neither held nor faced): the session's end is the hand's that
/// meets it, and the line waits for the session that stands — never `done`,
/// never re-marked; the next probe, the token answering again, sends and
/// keeps it (the mutant that settles the line at the death marks the
/// person's text kept although it never landed).
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

/// THE PROBE RESENDS EVERY PRINCIPAL's LINES (§3c.4): two principals hold a
/// line each at one board — two tabs of the bare mode, opened as two
/// principals — and one probe sends both, each under its own session (the
/// mutant that drains its first principal alone leaves the second's text
/// unsent, and every later burst of that principal behind it).
#[test]
fn a_probe_resends_every_principals_lines() {
    let g = ground();
    let facts = Facts { principal: 2, account: Some("1.0.2".into()), kind: SessionKind::Bare };
    let open = Open { token: Token::parse(&"8e".repeat(16)).unwrap(), facts, opened_at: 0 };
    let second = g.holds.sessions.register("b-1", Arc::clone(&g.session.board), open, &mut NoSupplements);
    g.holds.open_session(&second);
    g.hold(&insert(DOC, json!(["a"])), "unreachable", false);
    g.holds.hold(&second, Burst::admit(insert("1.0.2.0.1", json!(["b"])), &second).unwrap(), Reason::of("unreachable", false)).unwrap();
    g.holds.probe("b-1");
    let mut sent: Vec<String> = g.fake.sends.lock().unwrap().iter().map(|f| f["doc"].as_str().unwrap_or("?").to_string()).collect();
    sent.sort();
    assert_eq!(sent, [DOC, "1.0.2.0.1"], "each principal's line is sent");
    assert!(g.lines().is_empty() && g.holds.lines(&second).unwrap().as_array().unwrap().is_empty(), "and each kept");
}

/// OUTCOME (iii): a foreign row on the document since `base` — the site MOVED:
/// no line is sent, the lines are re-faced `moved`, never rebased (the mutant
/// that sends the moved line at its old base).
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

/// THE OWN HAND on a read (§3c.5; wire.md §`/changes`): a SIGNED entry's row
/// carries `attest` and NO `key`, and is the session's own under a session
/// that holds a key — the head `done kept`, nothing re-sent — and NOT own
/// under a bare session (the mutant that keys the test on `key` alone faces
/// the signed row `moved`); a row with `key: "bare"` is own under a bare
/// session alone, never under a keyed one.
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
    let (states, _) = walk(Facts { kind: SessionKind::Bare, ..keyed_facts() }, signed_row);
    assert!(states.contains(&"moved".to_string()), "a signed row is foreign to a bare session: {states:?}");
    let (states, _) = walk(keyed_facts(), bare_row);
    assert!(states.contains(&"moved".to_string()), "a bare hand's row is foreign to a keyed session: {states:?}");
}

/// A ROW WHOSE TESTIMONY THE BOARD LOST (`docs`, `key`, `op` the reserved
/// null — the `poisoned` burst a restart replays, §3c.2) is judged by the
/// arrangement alone, decisively: a `sent` insert whose values read back
/// equal is kept and not re-sent (the mutant that reads it as a foreign hand
/// faces the person's own text `moved`); values that differ are `moved`; a
/// kind the site read cannot confirm is `moved` too, the person's act; and a
/// head that was never sent reads any row as `moved`.
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

/// A READ THE BOARD REFUSES DECIDES NOTHING (§3c.5): a `/changes` answered
/// `503 feed_rebuilding` — the daemon re-covering a lost `commits.log` behind
/// its listener after an open, exactly when a resend runs — leaves a `sent`
/// head held and unsent (the mutant that reads the refusal as "no row" sends
/// a burst that may have landed a second time); once the board serves the
/// page, the next probe reads it and sends.
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

/// `history_reclaimed` on the read (§3c.5): the arrangement alone decides — a
/// `sent` head whose values read back equal at its site is (ii), kept and not
/// re-sent; values that differ are (iii); a site read the board does not
/// answer decides nothing and the line stands (the mutant that trusts an
/// unread site keeps a burst that never landed).
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

/// A REFUSAL THE TABLE HOLDS NOWHERE leaves a resent line standing: the board
/// answering `credential_refused`/`index_rebuilding`, retry-class — the cell
/// index rebuilding after an open, when resends run — is faced to no one and
/// never makes the line `done` (the mutant that writes `done kept` loses text
/// the board refused); the next probe, the index ready, sends and keeps it.
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

/// A SECOND WINDOW (§3c.3): with the board's `held/<chain>/lock` held by
/// another shell, a burst is held in this shell's memory alone — answered
/// `other_window`, nothing written under the directory — and RESENT like any
/// line once the board answers (the mutant that skips another window's
/// queue holds every later burst `behind` it for the uptime); after it is
/// kept, the next burst is dialed.
#[test]
fn a_second_windows_burst_is_held_in_memory_and_resent() {
    let store = TempDir::new().unwrap();
    let dir = HeldDir::new(store.path(), Chain::parse(&"ab".repeat(32)).unwrap());
    dir.ensure().unwrap();
    let _first_window = dir.try_lock().unwrap().expect("the first window holds the lock");
    let held_dir = store.path().join("held").join("ab".repeat(32));
    let g = ground_in(store, bare_facts(), 0);
    let answer = g.hold(&insert(DOC, json!(["hello"])), "unreachable", false);
    assert_eq!((answer["resp"].as_str(), answer["cause"].as_str()), (Some("held"), Some("other_window")), "{answer}");
    assert!(!held_dir.join("principal-1.held").exists(), "a second window writes nothing");
    assert_eq!(g.lines().len(), 1, "the line stands in memory");
    g.holds.probe("b-1");
    assert_eq!(g.fake.sends(), 1, "the line is resent");
    assert!(g.lines().is_empty() && g.states().contains(&"kept".to_string()));
    let OpAnswer::Answered(Ok(next)) = g.holds.send_burst(&g.session, insert(DOC, json!(["!"]))) else { panic!("the burst was answered") };
    assert_eq!(next["resp"], "ack", "no line stands, so the next burst is dialed: {next}");
}

/// A DRAIN THAT UNWINDS leaves no mark (§3c.4): a probe whose `/health`
/// dial panics leaves the board free to drain, and the next probe sends and
/// keeps the line (the mutant whose mark outlives an unwinding drain sends
/// nothing for the shell's life).
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

/// ONE DRAIN PER BOARD AT A TIME (§3c.4): a probe that comes while another
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

/// What the board answers THE READ of the held head's document.
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

/// The held head: an `insert`, whose site a read can confirm, or a `delete`,
/// whose site none can.
#[derive(Debug, Clone, Copy)]
enum Head {
    Insert,
    Delete,
}

/// What a read of the head's site answers: the head's own values, other
/// values, no answer, the death signal, or the head's values and one more
/// position than the read asked.
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

/// THE READ's TABLE (§3c.5), cell by cell: no row sends from the head; ONE
/// row is the head's landing only where the head was sent and the row is of
/// the session's own hand and of the head's own `op`, its site not
/// contradicting it — an `insert` read back equal, a kind no read confirms
/// trusted on its hand; a row whose testimony the board lost, and
/// `history_reclaimed`, are decided by the site alone, a kind no read
/// confirms faced `moved`; a foreign row, two rows and a page too large to
/// serve are `moved`; a read or a site read the board does not answer — its
/// answer the death signal among them — decides nothing; a site read
/// delivering past the values asked differs. The mutants the cells hold
/// off: a second tab's own-hand row landing a head whose site says otherwise
/// (3), a delete faced on its own hand (4), an unread site taken as either
/// answer (5, 11, 18), a head never sent kept off a row (6, 19), another
/// `op` of the own hand (7), the first of two rows taken as the landing
/// (14), a reclaimed kind no read confirms kept (17), a page too large read
/// as none or as unread (20), the death signal at the site read taken as an
/// answer (22–24), and a delivery past the values asked read as theirs
/// (25–27).
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
        let own = |at: u64, op: &str| json!({"at": at, "op": op, "key": "bare", "docs": [DOC]});
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

/// A MOVED document faces its own lines and no other (§3c.5, J3): a foreign
/// row on one document moves it, while a burst held `behind` it on a second
/// document, whose read finds no row under it, is sent and kept (the mutant
/// that faces every line moved at one document's foreign row strands the
/// person's text on the other).
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

/// THE OWN NODE STOPPED (§3c.4): while its owner's stop stands, a burst is
/// held `stopped` without a dial — `sent: false`, since nothing left — and
/// the probe dials nothing; once the node runs, the probe sends and keeps
/// it (the mutant that dials past the stop, and the one whose probe drains
/// a stopped node).
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

/// THE HALTED HOLD lasts from the first `true` read of `writes.halted` to the
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

/// THE RIDER (§3c.4): a resent line's first and second `durability` are
/// reissued at the next probe, its THIRD holds it `durability` — counted per
/// line across the resends — and the board taking writes again keeps it
/// (the mutant that never counts reissues the line forever).
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
