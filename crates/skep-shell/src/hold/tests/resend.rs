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
//! another shell's lock on the board's store (skep #789, #873): the store
//! found another's at the session's open and said once, no lock of the
//! board's taken, no file opened and nothing listed, a burst past the write
//! door refused at the hold's own, the state left as a probe takes both
//! locks, and each edge emitted once as `another-window`, at the open or the
//! probe that finds it, and never at a try that finds no change (skep #827);
//! one writer per board across its two locks (skep #828): a pending store
//! meeting the board's own lock held as the head reads, read alone, its line
//! counted on the pending file and sent from it under the lock this shell
//! keeps for its life, and a head that reads beside another shell's pending
//! lock taking no lock and reading alone; THE STORE FROM THE FIRST TOUCH
//! (skep #857, #859): a board away or unclaimed at the first touch holding
//! on the pending file — the line on disk before its answer, a relaunch
//! listing it — and moving its lines to the board's file once the board's
//! own directory is this shell's, the pending file removed; the board's own
//! store the device refuses keeping the lines on the pending file until it
//! can be made, at the first touch or later, the board's file counted; the
//! pending store the device refuses at the first touch keeping the lines in
//! memory, owed, each answer carrying the refusal and its class (skep #820),
//! until the retry makes the directory, takes its lock and writes them; a
//! held store this shell may not make answering `read_only`; the change's
//! copy the device refuses parking the lines on the pending file until it
//! lands, a parked line listed with no refusal and counted by no read of
//! what the file owes, and a `done` the pending file owed counted across
//! the change (skep #860), part-way keeping what landed, and with its
//! cut-back refused leaving nothing a relaunch reads twice (skep #817, #821);
//! the board's file found halted at the change halting the principal, a
//! relaunch listing every line once the file is moved aside (skep #858); and
//! a crash between the change's copy and the pending file's removal doubling no
//! line; every principal's lines resent by one probe, a bare session's line
//! resent by none until a session of its principal's that may write stands,
//! the keyless session's discard dropping a line in any state and that
//! session resending the rest (skep #896), and a probe with no line standing
//! dialing nothing; one drain per board at a time, and a drain that
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
//! `writes.halted` and a third `durability` holding a burst over time, the
//! next line's reissues counted afresh; every line's read starting past
//! the person's own write — a line held behind a landing or an ack read from
//! its position, and a line held after a landing the read found reading
//! past it; and THE DEADLINE (skep #716, #720, #722): a line handed to the
//! person two minutes from its first failed send, whatever the failure — its
//! resends' lost answers of every way, the first dial's own, a third
//! `durability`, a `write_busy` past its reissue — the clock run from the
//! first failure and never the last, a connection never made starting none,
//! the deadline the two minutes it is pinned to; its landing kept where the
//! read finds one, before the hand-over or at the person's `send`; and
//! "sent again" said once per change of the failure. THE DROP OF A LINE
//! WHOSE ANSWER WAS LOST (skep #866): the read's table met by the person's
//! drop of a `sent` line handed over — kept where the read finds a landing,
//! dropped where no row could be one, refused `landing_unread` naming why
//! where the read cannot tell, and the death answered — a line handed over
//! whose write landed after the hand-over kept and the line behind it sent,
//! a `send` made while the drop's read is out leaving the drop nothing to
//! drop, a hold standing or a silent board refusing the drop unread, a read
//! unanswered holding the board so, and the keyless session's discard read
//! for nothing; and THE LINES A DROP NAMES (skep #993): a refused or moved
//! line marked `sent`, the keyless session's discard of one and a `sent`
//! line behind the one a drop read each named in its answer, a line no dial
//! of which left the device named in none. And *the board's
//! silence* (skep #863): a pass ending at the first request the board gives
//! no answer to — a send timing out, a hang-up, a connection never made, a
//! read, a site's read, the head's read — nothing more dialed, read or said
//! at the documents it did not reach, a burst of another principal's held at
//! once, and the next turn walking those documents first and the cut one
//! last; a send so cut its line's own failure only where the next probe
//! finds the board answering; a line's two minutes paused across the board's
//! silence, kept, and the hand-over naming the wall time; a resend's shift
//! whose read goes unanswered untried, its verdict kept and run when the
//! board answers; a moved face whose hands' read goes unanswered naming them
//! `unread`, read again at the board's answer; and, over the board's feed
//! thread, a cut announcing nothing while the board's `/health` answers. And
//! THE PERSON's `send`
//! ON A MOVED DOCUMENT (skep #757): a document moved again after it naming
//! only the hands since, the rows the person acknowledged named no more, and
//! a line leaving the queue taking the acknowledgment with it, so a later
//! line of its ordinal names every hand; an anchored line, its base raised
//! past the person's own other write of its kind — which a read from the
//! old base takes for its landing — sent, shifted and kept; and a first
//! moved face naming every hand since the typed state though the line's
//! base stands past it. And A MOVED DOCUMENT'S SHIFT TEST (skep #867):
//! `sendable` true or false as a `send` would shift the line or hold it moved
//! again, and a `send` doing what it said; a moved hold's own shift the test,
//! no second read; a row naming the document testing it once, however many,
//! and telling nothing while the answer stands; an edit that restores the
//! span flipping it to true with one `moved` event naming the hands; a read
//! the board does not answer or refuses leaving it absent, an unanswered one
//! read again and a refused one not, until a row names the document; a flip
//! whose hands' read goes unanswered naming them `unread`; the death signal
//! leaving the test owed; a `send` overtaking a test's read leaving it
//! nothing to say, and taking the answer with it; a test a step of its turn;
//! a relaunched line tested at its first probe; a line with no anchors or no
//! span false with no read; and the document's first moved line alone
//! carrying it, under a session that may write. And A BOARD'S STATE told once
//! per change with no
//! line held (skep #865): a quiet board's halt and its clearing, over the
//! board's feed thread too, a head that will not read told with its reason
//! before any write, each in turn where both hold, the probe's reads kept to
//! a session that may write or a state told to clear. And THE HEAD THAT WILL
//! NOT READ (skep #725, #727):
//! one head read per probe before any document, the documents held
//! `head_unreadable` skipped unread while it fails; the `held` event and the
//! head's `Talk` line said once per change of state, not per probe; at the
//! head's first read the pending lines joining the board's file and sent in
//! `k` order, their ordinals kept, and a line the board's file held from an
//! earlier run — the file first read at the change, under an ordinal this
//! run's lines hold — renumbered past them and sent after them, no `held`
//! event re-said (skep #856; the owner's ruling); a pending queue moved
//! behind an earlier run's line keeping its ordinals, so the person's
//! `resolve` on an ordinal answered before the change acts on the same line
//! after it; an ordinal this run settled before the change naming no earlier
//! run's line after it, the file renumbered past the counter whether a line
//! of this run's stands or none is left, a pending file read at the first
//! touch keeping its ordinals, a renumbering the change could not write said
//! once and landing at a later probe, and a file at or past the counter
//! keeping its ordinals (skep #875). And
//! THE DRAIN'S TURNS (skep #817, #862): a drain in bounded turns sending
//! every line in `k` order, each document read as the walk reaches it and
//! once in a pass, a document a turn stopped at dialed no more until the
//! pass ends, and the person's `send` walking it again within the pass; a
//! document another writer keeps moving taking one turn's steps in shifts,
//! the lines after it sent at the next turn, its line left as its last dial
//! left it, said once per change of its failure, and kept at a later pass,
//! or handed to the person at the first read past its deadline; a full
//! pending file joined at the session's open in one copy with one sync; and,
//! over the board's feed thread, a search answered between two turns, the
//! turns running back to back. And each line kept, named (skep #968): a
//! resent line's ack named on its `held` event with its `id`, its position
//! and the I-address an insert minted, two lines kept in one pass each on
//! its own event, an ack said though it leaves the state and count as told,
//! and a landing the read found, or the drop's read, named at its position.
//! And, timed (`#[ignore]`, the full gate's), the
//! walk over a full queue drained within its ceiling, each line's send
//! measured beside it, and the person's drop of a refused run over a full
//! queue, each in time in proportion to the lines.

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
/// site — so the head is `done kept` and nothing is re-sent, its `kept`
/// event naming the line at its row's position and no I-address, which no
/// ack names (skep #968) (the mutant that resends the head; the mutant that
/// compares the frame's one string with one position's value faces the
/// person's own text `moved`; the one that names no line leaves the page no
/// position for the words it typed).
#[test]
fn outcome_ii_a_landed_burst_is_kept_not_resent() {
    let g = ground();
    *g.fake.text.lock().unwrap() = "hello".into();
    *g.fake.rows.lock().unwrap() = vec![json!({"at": 77, "op": "insert", "key": g.own_key(), "docs": [DOC]})];
    g.hold(&insert(DOC, json!(["hello"]), g.fake.head()), "unreachable", true);
    g.holds.probe("b-1");
    assert_eq!(g.fake.sends(), 0, "the landed head is NOT re-sent: {:?}", g.fake.sends.lock().unwrap());
    assert!(g.lines().is_empty(), "the line is done kept");
    let said = held_events(&g);
    let states: Vec<&str> = said.iter().filter_map(|e| e["state"].as_str()).collect();
    assert!(states.contains(&"kept") && !states.contains(&"moved"), "{states:?}");
    let kept = said.iter().find(|e| e["state"] == "kept").expect("the document kept");
    assert_eq!(kept["landed"], json!([{"held": 1, "at": 77}]), "the line the read found landed, at its row's position: {kept}");
}

/// Returns each `held` event's state, its count and the lines it names kept.
fn named_kept(said: &[Value]) -> Vec<(&str, u64, Option<&Value>)> {
    said.iter().map(|e| (e["state"].as_str().unwrap_or("?"), e["held"].as_u64().unwrap_or(u64::MAX), e.get("landed"))).collect()
}

/// Checks that a resent line's ack names the line on its `held` event.
///
/// It is the page's one word of the ack (§4b.2; skep #968). An insert
/// carrying the page's `id` is held before any dial, and the board takes
/// its resend, answering `ack_addr`: the `kept` event names the line — its
/// ordinal, the `id`, the ack's `at` and the I-address the insert minted —
/// and no event before it names a line (the mutant that drops the ack once
/// the line is `done` leaves the page naming the words it typed by its own
/// name after the board holds them).
#[test]
fn a_resent_lines_ack_names_the_line_on_its_held_event() {
    let g = ground();
    let mut frame = insert(DOC, json!(["hello"]), g.fake.head());
    frame["id"] = json!("b-1");
    let k = g.hold(&frame, "unreachable", false)["held"].as_u64().unwrap();
    g.fake.op_rejected.next(1, json!({"resp": "ack_addr", "addr": i(9), "at": 50}));
    g.holds.probe("b-1");
    assert!(g.lines().is_empty(), "the line is kept");
    let landed = json!([{"held": k, "burst": "b-1", "at": 50, "addr": i(9)}]);
    assert_eq!(named_kept(&held_events(&g)), [("holding", 1, None), ("sending", 1, None), ("kept", 0, Some(&landed))]);
}

/// Returns the envelope `id` of each frame the ground's board was sent.
fn dialed_ids(g: &Ground) -> Vec<String> {
    g.fake.sends.lock().unwrap().iter().map(|sent| sent["id"].as_str().unwrap_or("").to_string()).collect()
}

/// Checks that two held lines under one page `id` resend under two dial ids.
///
/// Each resends under a dial id of its own (skep #971). A page reload, or a
/// second tab, gives two lines one `id`: two inserts
/// held under `b-1`, on two documents, are resent in one pass, the board
/// answering each a first `durability`, and again at the next, where it
/// acks them. Each line dials under a dial id of its own — `shell:` and hex,
/// neither the page's nor the other line's — the same at both its resends;
/// the rows list each frame with the page's `id`; and each line's `kept`
/// event names it `b-1` (the mutant that resends under the page's `id` dials
/// both lines under one `id`, which the board's retry memo answers the second
/// with the first's acknowledgment; the one that draws an id at each dial
/// meets no memo entry of the line's own at a true reissue).
#[test]
fn two_held_lines_under_one_page_id_each_resend_under_a_dial_id_of_its_own() {
    let g = ground();
    for (doc, word) in [(DOC, "x"), (OTHER, "y")] {
        g.hold(&with_id(insert(doc, json!([word]), g.fake.head()), "b-1"), "unreachable", false);
    }
    g.fake.op_rejected.next(2, retry("durability"));
    g.holds.probe("b-1");
    let rows = g.lines();
    assert!(rows.len() == 2 && rows.iter().all(|row| row["frame"]["id"] == "b-1"), "each row lists its frame with the page's `id`: {rows:?}");
    g.holds.probe("b-1");
    let ids = dialed_ids(&g);
    assert_eq!(ids.len(), 4, "each line dialed twice: {ids:?}");
    assert!(ids.iter().all(|id| id.starts_with("shell:")), "every resend under a dial id: {ids:?}");
    assert_ne!(ids[0], ids[1], "the two lines' dial ids differ");
    assert_eq!((&ids[2], &ids[3]), (&ids[0], &ids[1]), "each line dials its one id at each resend");
    let kept: Vec<Value> = held_events(&g).into_iter().filter(|event| event["state"] == "kept").collect();
    let named: Vec<(&str, &str)> = kept.iter().map(|event| (event["doc"].as_str().unwrap_or("?"), event["landed"][0]["burst"].as_str().unwrap_or("?"))).collect();
    assert_eq!(named, [(DOC, "b-1"), (OTHER, "b-1")], "each line kept, named by the page's `id`: {kept:?}");
    assert!(g.lines().is_empty(), "both kept");
}

/// Checks that a line dials one dial id across its resends and a relaunch.
///
/// It is the `id` a true reissue of the line is recognised by (skep #971).
/// A held line is resent twice, the board answering each a `durability`,
/// and the shell relaunched over the same store; the line read back resends
/// under the id its earlier resends dialed, the held file carrying it, and
/// the board acks it (the mutant that keeps the id in memory alone dials
/// under a new one after the relaunch).
#[test]
fn a_line_dials_one_dial_id_across_its_resends_and_a_relaunch() {
    let g = ground();
    g.hold(&with_id(insert(DOC, json!(["x"]), g.fake.head()), "b-1"), "unreachable", false);
    g.fake.op_rejected.next(2, retry("durability"));
    g.holds.probe("b-1");
    g.holds.probe("b-1");
    let text = std::fs::read_to_string(held_file(&g)).unwrap();
    let carried = file_lines(&text).last().and_then(|line| line["dial"].as_str().map(str::to_owned)).unwrap_or_else(|| panic!("the held file carries the dial id: {text}"));
    let Ground { holds, fake, session, store, .. } = g;
    drop(holds);
    let g = ground_over(fake, store, session.facts.clone(), 0);
    g.holds.probe("b-1");
    assert_eq!(dialed_ids(&g), [carried.clone(), carried.clone(), carried], "one id at each resend, before the relaunch and after");
    assert!(g.lines().is_empty(), "kept");
}

/// Checks that a line renumbered at the join dials the dial id it carried.
///
/// It is an earlier run's line (skep #856, #971). That run's resend named its
/// line's dial id in the board's own file,
/// under ordinal 1; this run, the head unreadable at its first touch, holds a
/// line under 1 on the pending file. The head read, the join renumbers the
/// earlier line past this run's, and the walk sends this run's line under a
/// dial id of its own and the earlier one under the id its file carried (the
/// mutant whose renumbering drops the member sends the earlier line under an
/// `id` no earlier resend of it dialed).
#[test]
fn an_earlier_runs_line_renumbered_at_the_join_dials_the_id_its_file_carried() {
    let store = TempDir::new().unwrap();
    let dir = HeldDir::new(store.path(), Chain::parse(&"ab".repeat(32)).unwrap());
    dir.ensure().unwrap();
    let Opened::Live { mut queue, .. } = dir.open_file(1, "1.0.1").unwrap() else { panic!("a fresh file") };
    let k = queue.hold_next(OTHER, None, 0, insert(OTHER, json!(["earlier"]), 0), None, Reason::of("unreachable", false)).unwrap().k;
    let (carried, refused) = queue.ready_to_resend(k).expect("the earlier run's line stands");
    assert!(refused.is_none(), "{refused:?}");
    drop(queue);
    let fake = Fake::new();
    fake.head_garbled.store(true, Ordering::SeqCst);
    let facts = writer_facts(&store);
    let g = ground_over(fake, store, facts, 0);
    let OpAnswer::Answered(Ok(held)) = g.holds.send_burst(&g.session, insert(DOC, json!(["x"]), g.fake.head()), None) else { panic!("held") };
    assert_eq!(held["held"], 1, "{held}");
    g.fake.head_garbled.store(false, Ordering::SeqCst);
    while g.holds.probe("b-1") == Turn::Bounded {}
    let renumbered = said_containing(&g, "joined the board's held file");
    assert!(renumbered.len() == 1 && renumbered[0].contains("renumbered past this run's ordinals"), "premise: the earlier line renumbered at the join: {renumbered:?}");
    let sends = g.fake.sends.lock().unwrap().clone();
    let under = |value: &str| sends.iter().find(|sent| sent["values"][0] == value).and_then(|sent| sent["id"].as_str().map(str::to_owned));
    assert_eq!(under("earlier").as_deref(), Some(carried.as_str()), "the renumbered line dials the id its file carried");
    let ours = under("x").unwrap_or_default();
    assert!(ours.starts_with("shell:") && ours != carried.as_str(), "this run's line dials an id of its own: {ours}");
    assert!(g.lines().is_empty(), "both kept");
}

/// Checks that a burst whose first dial landed unseen is held moved at resend.
///
/// It is never kept by another dial's answer (skep #971). A burst's first
/// dial goes out under the page's `id`, and its answer is
/// lost: it landed, its row the person's own, and another writer has put
/// words before its site since, so the read finds the row, a site that
/// differs, and decides nothing, and the line is resent. The resend dials
/// under the line's dial id, which meets no memo entry of the first dial's;
/// the board judges it by the state the burst was typed against and refuses
/// it as typed against an older one, and the shift, finding the burst's own
/// words between its anchors, holds the line moved — its `sent` kept, the
/// board's verdict on it, nothing kept and nothing sent past the resend (the
/// mutant that resends under the page's `id` dials what a board's retry memo
/// answers with the first dial's acknowledgment; the one that shifts past a
/// cut span writes the person's words a second time).
#[test]
fn a_burst_whose_first_dial_landed_unseen_is_held_moved_at_its_resend() {
    let g = ground();
    let typed = g.fake.head();
    g.fake.op_lost_at.store(1, Ordering::SeqCst);
    let frame = with_id(insert_at(DOC, 2, json!(["hello"]), typed), "b-1");
    let OpAnswer::Answered(Ok(held)) = g.holds.send(&g.session, frame, Some(anchors(Some(&i(1)), Some(&i(2))))) else { panic!("held, its answer lost") };
    assert_eq!((held["cause"].as_str(), g.lines()[0]["sent"].as_bool()), (Some("unreachable"), Some(true)), "{held}");
    // It landed at 77, between `a` and `b`; another writer's `XY` at 78 went
    // before it.
    *g.fake.rows.lock().unwrap() = vec![json!({"at": 77, "op": "insert", "key": g.own_key(), "docs": [DOC]}), json!({"at": 78, "op": "insert", "key": "ff".repeat(32), "docs": [DOC]})];
    *g.fake.text.lock().unwrap() = "XYahellob".into();
    *g.fake.image.lock().unwrap() = vec![run(&i(50), 2), run(&i(1), 1), run(&i(100), 5), run(&i(2), 1)];
    g.fake.move_arrangement(DOC, 78);
    let _ = g.states();
    g.holds.probe("b-1");
    let ids = dialed_ids(&g);
    assert!(ids.len() == 2 && ids[0] == "b-1" && ids[1].starts_with("shell:"), "the first dial under the page's `id`, the resend under the line's dial id: {ids:?}");
    let lines = g.lines();
    assert_eq!((lines.len(), lines[0]["cause"].as_str(), lines[0]["sent"].as_bool()), (1, Some("moved"), Some(true)), "{lines:?}");
    assert_eq!(lines[0]["refusal"], arrangement_moved_on("insert", typed, 78), "the board's verdict on the line");
    assert_eq!(g.states(), ["sending", "moved"], "never kept");
    assert_eq!(said_containing(&g, "was not shifted (the span its anchors bound holds 5 positions now").len(), 1, "{:?}", g.said.lock().unwrap());
}

/// Checks that two lines kept in one pass are named each on its own event.
///
/// They are named in order (skep #968). Two deletes on one document are
/// resent in one pass: the first's ack says the document `sending`, naming
/// the first line at its ack's position, the second's says it `kept`, naming
/// the second, and neither names an I-address, a delete minting none (the
/// mutant that names the lines on the document's last event alone tells the
/// page of the first line only when the last one lands).
#[test]
fn two_lines_kept_in_one_pass_are_named_each_on_its_own_event() {
    let g = ground();
    for _ in 0..2 {
        g.hold(&delete(DOC, g.fake.head()), "unreachable", false);
    }
    let _ = g.states();
    g.holds.probe("b-1");
    let (first, second) = (json!([{"held": 1, "at": 50}]), json!([{"held": 2, "at": 51}]));
    assert_eq!(named_kept(&held_events(&g)), [("sending", 2, None), ("sending", 1, Some(&first)), ("kept", 0, Some(&second))]);
}

/// Checks that an ack is said though it leaves the state and count as told.
///
/// It is said whatever the event last said (skep #968). A line held before
/// any dial is resent, and as its dial reaches the board a line is entered
/// behind it on its document with no event said — as a first dial's shift
/// enters its line, or a hold under another session of the principal's — so
/// the ack leaves the document `sending` with one line, the pair the walk
/// said before the dial. The ack's event is said all the same, naming the
/// line kept, and the line entered is sent and named in its turn (the mutant
/// that judges an event naming a line kept by its pair alone drops the
/// ack's one word).
#[test]
fn an_ack_that_leaves_the_state_and_count_as_told_is_said() {
    let g = ground();
    let typed = g.fake.head();
    g.hold(&insert(DOC, json!(["a"]), typed), "unreachable", false);
    let _ = g.states();
    let (holds, entered) = (Arc::downgrade(&g.holds), AtomicBool::new(false));
    *g.fake.at_send.lock().unwrap() = Some(Box::new(move || {
        if entered.swap(true, Ordering::SeqCst) {
            return;
        }
        if let Some(holds) = holds.upgrade() {
            holds.with_principal("b-1", 1, |ph| ph.hold(DOC, None, 0, insert(DOC, json!(["b"]), typed), None, Reason::of("behind", false)).unwrap());
        }
    }));
    g.holds.probe("b-1");
    *g.fake.at_send.lock().unwrap() = None;
    let (first, second) = (json!([{"held": 1, "at": 50}]), json!([{"held": 2, "at": 51}]));
    assert_eq!(named_kept(&held_events(&g)), [("sending", 1, None), ("sending", 1, Some(&first)), ("kept", 0, Some(&second))]);
    assert!(g.lines().is_empty(), "both lines kept");
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

/// Checks that the keyless session's discard drops a line in any state.
///
/// It is the bare session's one act on its principal's held lines (§4b.1's
/// `resolve` row; foundations §3.3 state 3; skep #896): a line the death
/// held `session_died` and one held `behind` it stand `holding` through a
/// probe that sends nothing, and the drop of either drops it and every
/// later line of its document — the `held` event saying the line that
/// stands first, then `kept` with none, both `done`s on the held file and
/// nothing dialed — while `send` on a holding line stays refused; the line
/// on another document stands, and a session of the principal's that may
/// write resends it (the mutant that keeps the drop to refused and moved
/// lines leaves the keyless reader no way to give up words no key will
/// send; the one keyed on `session_died` alone refuses the `behind` line;
/// the one that admits it under any session lets a writer drop a holding
/// line its own resend may be dialing, which the write suite's death cell
/// pins).
#[test]
fn the_keyless_sessions_discard_drops_a_line_in_any_state_and_a_writer_resends_the_rest() {
    let g = bare_ground();
    let died = g.hold(&insert(DOC, json!(["a"]), g.fake.head()), "session_died", false)["held"].as_u64().unwrap();
    let behind = g.hold(&insert_at(DOC, 2, json!(["b"]), g.fake.head()), "behind", false)["held"].as_u64().unwrap();
    g.hold(&insert(OTHER, json!(["c"]), g.fake.head()), "unreachable", false);
    g.holds.probe("b-1");
    assert_eq!(g.fake.sends(), 0, "nothing is sent under the bare session");
    assert_eq!(g.states(), ["holding", "holding", "holding"], "and nothing past each line's hold is said");
    assert_eq!(g.holds.resolve(&g.session, behind, ResolveAct::Send).map_err(|r| r.name().to_string()), Err("not_resolvable".to_string()), "the send stays refused");
    let dropped = |k: u64| -> Value {
        assert_eq!(g.holds.resolve(&g.session, k, ResolveAct::Drop).map_err(|r| r.name().to_string()), Ok(Resolved::dropped(&[])), "line {k}: the discard");
        let said: Vec<Value> = g.rx.try_iter().filter(|e| e.name == EventName::Held).map(|e| e.data).collect();
        assert_eq!(said.len(), 1, "{said:?}");
        assert_held_event_declared(&said[0]);
        said[0].clone()
    };
    let said = dropped(behind);
    assert_eq!((said["doc"].as_str(), said["held"].as_u64(), said["state"].as_str()), (Some(DOC), Some(1), Some("holding")), "the line held at the death stands first: {said}");
    let said = dropped(died);
    assert_eq!((said["doc"].as_str(), said["held"].as_u64(), said["state"].as_str()), (Some(DOC), Some(0), Some("kept")), "no line stands on the document: {said}");
    let left = g.lines();
    assert_eq!((left.len(), left[0]["doc"].as_str()), (1, Some(OTHER)), "the other document's line stands: {left:?}");
    let text = std::fs::read_to_string(held_file(&g)).unwrap();
    assert_eq!(text.matches("\"as\":\"dropped\"").count(), 2, "both drops on the held file: {text}");
    assert_eq!(g.fake.sends(), 0, "nothing is dialed on a drop");
    let open = Open { token: Token::parse(&"8e".repeat(16)).unwrap(), facts: writer_facts(&g.store), opened_at: 0 };
    let board = BoardEntry { reference: g.session.board_reference.clone(), board: Arc::clone(&g.session.board) };
    let writer = g.holds.sessions.register(&board, open, &mut NoSupplements);
    g.holds.open_session(&writer);
    g.holds.probe("b-1");
    let sent = g.fake.sends.lock().unwrap().clone();
    assert_eq!(sent.len(), 1, "the writer sends the line left: {sent:?}");
    assert_eq!((sent[0]["doc"].as_str(), sent[0].get("attest").is_some()), (Some(OTHER), true), "attested by the writer's key: {sent:?}");
    assert!(g.lines().is_empty(), "and keeps it");
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
/// kept and not re-sent, its `kept` event naming the line with no position,
/// none read (skep #968); values that differ are no landing found, and the
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
    let landed = json!([{"held": 1}]);
    assert_eq!(named_kept(&held_events(&g)), [("holding", 1, None), ("kept", 0, Some(&landed))], "kept, the line named with no position");

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
const ANOTHER_SHELLS_STORE: &str = "held: another shell holds this board's held store — one shell per data directory: this shell reads alone at the board, every write refused `another_window` before any dial and nothing held, and tries the store again at each probe and each session's open";

/// The `Talk` line that says the board's store is this shell's again.
const THIS_SHELLS_STORE: &str = "held: this shell holds this board's held store now: writes at the board go out again";

/// The board's held directory under `store`, at the fake's chain, locked as
/// another shell over the same data directory holds it (§3c.3).
fn another_shell_holds(store: &Path) -> File {
    let dir = HeldDir::new(store, Chain::parse(&"ab".repeat(32)).unwrap());
    dir.ensure().unwrap();
    dir.try_lock().unwrap().expect("the other shell holds the lock")
}

/// Checks that another shell's lock on the board's own directory makes the
/// board's store that shell's, this one taking no lock and reading alone
/// there, until a probe finds both locks free (§3c.3: one shell per data
/// directory; skep #789, #827, #828, #873).
///
/// With the board's `held/<chain>/lock` held by another shell as the session
/// opens, the first touch takes the pending lock, finds the board's own held,
/// and lets the pending one go — no lock of the board's is this shell's —
/// the store found another's ([`Holds::another_window`], the question the
/// shell's write door asks before any dial), said once on `Talk` and emitted
/// once, `another-window` `true`; no file is opened, `held(session)` lists
/// nothing, and a probe with no line standing dials nothing and says nothing
/// more, its try of the locks finding no change. A burst that passed the
/// write door before the state was found is refused `another_window` at the
/// hold's own door, nothing held, nothing written under the other shell's
/// lock and nothing sent. Once the other shell lets go, the next probe tries
/// both locks and takes them, says so once and emits `false` once, and the
/// next line is copied to the board's file; a later session's open says
/// nothing more (the mutants that hold a second shell's bursts in memory,
/// that write under another shell's lock, that keep the pending lock taken
/// beside a held one, that never try the locks again, and that emit the
/// state at every try).
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
    let pending_store = HeldDir::pending(g.store.path(), g.session.board.dialed());
    assert!(pending_store.try_lock().unwrap().is_some(), "the pending lock this try took is let go: no lock of the board's is held");
    assert!(g.lines().is_empty() && !held_dir.join("principal-1.held").exists() && !pending_file(&g).exists(), "no file is opened, nothing listed");
    g.holds.probe("b-1");
    assert_eq!(g.fake.sends(), 0, "a probe with no line standing dials nothing");
    // A burst that passed the write door before the state was found: refused
    // at the hold's own door, nothing held and nothing written.
    let answer = g.holds.send_burst(&g.session, insert(DOC, json!(["hello"]), g.fake.head()), None);
    let OpAnswer::Answered(Err(refused)) = answer else { panic!("refused, never held: {answer:?}") };
    assert_eq!((refused.name(), refused.to_value()["op"].as_str()), ("another_window", Some("insert")), "{refused}");
    assert!(g.lines().is_empty() && !held_dir.join("principal-1.held").exists() && g.fake.sends() == 0, "nothing held, nothing written under another shell's lock, nothing sent");
    assert!(g.holds.another_window("b-1") && edges(&later).is_empty(), "the store stays the other shell's; the probe's try finds no change, and emits nothing");
    assert_eq!(said_containing(&g, "another shell holds this board's held store").len(), 1, "nothing said again");
    // The other shell lets go: the next probe tries both locks and takes them.
    drop(other_shell);
    g.holds.probe("b-1");
    assert!(!g.holds.another_window("b-1"), "the probe takes both locks");
    assert!(pending_store.try_lock().unwrap().is_none(), "the pending lock is this shell's now");
    assert_eq!(said_containing(&g, "held store now"), [THIS_SHELLS_STORE], "said once as it ends");
    assert_eq!(said_containing(&g, "another shell holds this board's held store"), [ANOTHER_SHELLS_STORE], "the beginning said no second time");
    assert_eq!(edges(&later), [false], "emitted once as it ends, the beginning no second time");
    let next = g.hold(&insert(DOC, json!(["c"]), g.fake.head()), "unreachable", false);
    assert!(next.get("unwritable").is_none(), "the store is this shell's now: {next}");
    assert!(std::fs::read_to_string(held_dir.join("principal-1.held")).unwrap().contains("\"values\":[\"c\"]"), "the line is copied to the board's file");
    open_another_session(&g);
    assert!(said_containing(&g, "held store now").len() == 1 && edges(&later).is_empty(), "a later open finds the store whole, and says and emits nothing");
}

/// Checks that lines held on the pending file before another shell's lock on
/// the board's own directory is found are counted as it is said, and resent
/// from the pending file, the pending lock kept (§3c.3; skep #789, #827,
/// #873).
///
/// The board away at the session's open — its head unread — the pending
/// store is taken, nothing emitted, and a burst is held on the pending file,
/// no `unwritable`. Another shell then takes the board's own lock and the
/// board returns: the probe's one head read names the chain, finds its lock
/// another's, and the store is another shell's, said once — the one line
/// counted on the pending file, never among the lines a close loses — and
/// emitted `another-window` `true` once; the line is resent from the pending
/// file and kept, its `done` written there and the file compacting away,
/// nothing written under the other shell's lock, and the pending lock,
/// taken at the first touch, is kept (the mutant that gates the resend on
/// the state keeps the line for the other shell's life; the one that counts
/// it in memory tells the operator a close loses it; the one that lets the
/// pending lock go leaves another shell free to write beside this one).
#[test]
fn lines_held_on_the_pending_file_before_another_shells_lock_is_found_are_counted_and_resent_from_it() {
    let fake = Fake::new();
    fake.head_unreachable.store(true, Ordering::SeqCst);
    let store = TempDir::new().unwrap();
    let facts = writer_facts(&store);
    let g = ground_over(fake, store, facts, 0);
    assert!(!g.holds.another_window("b-1"), "premise: the board away at the open, the pending store this shell's");
    assert!(edges(&g.rx).is_empty(), "the open finds no state, and emits nothing");
    let answer = g.hold(&insert(DOC, json!(["hello"]), g.fake.head()), "unreachable", false);
    assert!(answer.get("unwritable").is_none(), "held on the pending file, the board away: {answer}");
    let pending = pending_file(&g);
    assert!(std::fs::read_to_string(&pending).unwrap().contains("\"values\":[\"hello\"]"), "premise: the line is on the pending file");
    let other_shell = another_shell_holds(g.store.path());
    g.fake.head_unreachable.store(false, Ordering::SeqCst);
    // The probe's edge, read beside the receiver `states` reads.
    let probed = g.bus.subscribe();
    g.holds.probe("b-1");
    assert!(g.holds.another_window("b-1"), "the probe's head read finds the board's own lock another shell's");
    let counted = format!("{ANOTHER_SHELLS_STORE}; the 1 held line in the pending held file stays there and is sent as the board takes it");
    assert_eq!(said_containing(&g, "another shell holds this board's held store"), [counted], "said once, the line counted on the pending file");
    assert_eq!(edges(&probed), [true], "and emitted once");
    assert_eq!(g.fake.sends(), 1, "the line is resent from the pending file");
    assert!(g.lines().is_empty() && g.states().contains(&"kept".to_string()), "and kept");
    assert!(!pending.exists(), "its `done` written to the pending file, which compacts away");
    assert!(!held_file(&g).exists(), "nothing is written under the other shell's lock");
    assert!(HeldDir::pending(g.store.path(), g.session.board.dialed()).try_lock().unwrap().is_none(), "the pending lock, taken at the first touch, is kept");
    drop(other_shell);
}

/// Checks that a board away at the first touch holds its lines on the pending
/// file and moves them to the board's file once it returns (§3c.1, §3c.3;
/// skep #857).
///
/// The board away at the session's open, the first touch makes and locks the
/// pending directory, and a burst is held on the pending file, its answer
/// carrying no `unwritable`, nothing under a chain the board has not named;
/// the board returns, refusing the resend `write_busy` so the line stands,
/// and the probe's head read takes the board's own directory — no other
/// shell holds it — and moves the line to the board's file, the pending file
/// removed, said once, the store never another shell's, said or emitted (the
/// mutant that keeps a board-away line in memory loses it at a close; the one
/// that reads any store not yet whole as another shell's refuses the
/// person's writes at every outage; the one that emits `another-window` at
/// every step to a directory this shell locks tells the page of a state that
/// never stood).
#[test]
fn a_board_away_at_the_first_touch_holds_on_the_pending_file_and_moves_its_lines_to_the_boards_file_later() {
    let fake = Fake::new();
    fake.head_unreachable.store(true, Ordering::SeqCst);
    let store = TempDir::new().unwrap();
    let facts = writer_facts(&store);
    let g = ground_over(fake, store, facts, 0);
    let pending_store = HeldDir::pending(g.store.path(), g.session.board.dialed());
    assert!(pending_store.try_lock().unwrap().is_none(), "the pending directory is made and locked at the first touch");
    let answer = g.hold(&insert(DOC, json!(["a"]), g.fake.head()), "unreachable", false);
    assert!(answer.get("unwritable").is_none(), "held on the pending file, the board away: {answer}");
    let pending = pending_file(&g);
    assert!(std::fs::read_to_string(&pending).unwrap().contains("\"values\":[\"a\"]"), "the pending file holds the line");
    assert!(!held_file(&g).exists(), "nothing under a chain the board has not named");
    g.fake.head_unreachable.store(false, Ordering::SeqCst);
    g.fake.op_refused.every((503, json!({"error": "write_busy"})));
    g.holds.probe("b-1");
    assert!(!g.holds.another_window("b-1"), "no other shell holds the store");
    assert!(std::fs::read_to_string(held_file(&g)).unwrap().contains("\"values\":[\"a\"]"), "the standing line moved to the board's file");
    assert!(!pending.exists(), "the pending file removed once nothing is owed to the board's file");
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
/// says so once and emits `false` once, the pending lock kept for the
/// shell's life (skep #873), and the next line is copied to the board's file
/// (the mutant that leaves the store pending writes beside the other shell;
/// the one that lets the pending lock go leaves its directory to a third
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
    assert!(pending_store.try_lock().unwrap().is_none(), "the pending lock is kept for the shell's life, no pending file standing");
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
/// no lock and reads alone (§3c.3; skep #828, #873: one writer per board).
///
/// Another shell stands at the board's pending directory, its lock held, as
/// this shell's session opens with the board's head reading: the pending
/// lock is tried before the board's own and found held, so the store is
/// another's ([`Holds::another_window`]), said once and emitted once,
/// `true`, and no lock of the board's own is taken — the other shell's to
/// take at its next try, the board's one writer. No file is opened and
/// nothing is listed. Once the other shell lets go, the next session's open
/// takes both locks, says so once and emits `false` once, keeps both for the
/// shell's life, and the next line is copied to the board's file (the mutant
/// that takes the board's own lock first writes beside the other shell; the
/// one that refuses on the pending lock found held beside the board's own
/// holds the lock the other shell waits for, and neither writes; the one
/// that lets the pending lock go leaves it to a third shell).
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
    assert!(HeldDir::pending(g.store.path(), g.session.board.dialed()).try_lock().unwrap().is_none() && own.try_lock().unwrap().is_none(), "both locks are kept for the shell's life");
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

/// Checks that the board's own store the device refuses keeps the lines on
/// the pending file until it can be made (§3c.1, §3c.3; skep #859).
///
/// The board away at the session's open, a burst is held on the pending
/// file. `held/` is then sealed, so no directory can be made under it, and
/// the board returns: the probe's head read names the chain, the board's own
/// directory cannot be made, and the refusal is said once — the lines stay
/// on the pending file, this shell's, the line resent from it and refused
/// `write_busy`, so it stands. The next burst, held `behind` it, goes to the
/// pending file too, no `unwritable`: the store is this shell's, the pending
/// one. A second probe, still sealed, says nothing more. The node stopped and
/// `held/` opened, the next probe — which dials nothing — takes the board's
/// own lock and moves both lines to the board's file in `k` order, said
/// once, the pending file removed and the store's clearing said once (the
/// mutant that keeps the lines in memory while the board's own store is
/// refused loses them at a close; the one that says each refusal tells the
/// window at every probe; the one that never tries the board's own store
/// again leaves the lines on a file no relaunch at the chain reads).
#[cfg(unix)]
#[test]
fn the_boards_own_store_the_device_refuses_keeps_the_lines_on_the_pending_file_until_it_can_be_made() {
    use std::os::unix::fs::PermissionsExt;
    let fake = Fake::new();
    fake.head_unreachable.store(true, Ordering::SeqCst);
    let store = TempDir::new().unwrap();
    let facts = writer_facts(&store);
    let g = ground_over(fake, store, facts, 0);
    let first = g.hold(&insert(DOC, json!(["a"]), g.fake.head()), "unreachable", false);
    assert!(first.get("unwritable").is_none(), "held on the pending file, the board away: {first}");
    let pending = pending_file(&g);
    let held = g.store.path().join("held");
    std::fs::set_permissions(&held, std::fs::Permissions::from_mode(0o500)).unwrap();
    g.fake.head_unreachable.store(false, Ordering::SeqCst);
    g.fake.op_refused.every((503, json!({"error": "write_busy"})));
    g.holds.probe("b-1");
    assert!(!g.holds.another_window("b-1") && !held_file(&g).exists(), "the store is this shell's, the board's own directory refused");
    let said = said_containing(&g, "the board's own held store could not be made or locked");
    assert!(said.len() == 1 && said[0].contains("stay on the pending held file"), "the refusal said once: {said:?}");
    assert_eq!((g.fake.sends(), g.lines().len()), (1, 1), "the line resent from the pending file and refused, still standing");
    let OpAnswer::Answered(Ok(behind)) = g.holds.send_burst(&g.session, insert(DOC, json!(["b"]), g.fake.head()), None) else { panic!("held behind the standing line") };
    assert_eq!(behind["cause"], "behind", "{behind}");
    assert!(behind.get("unwritable").is_none(), "on the pending file, this shell's: {behind}");
    assert!(std::fs::read_to_string(&pending).unwrap().contains("\"values\":[\"b\"]"), "the next line is on the pending file too");
    g.holds.probe("b-1");
    assert_eq!(said_containing(&g, "held: the board's own held store could not be made or locked").len(), 1, "a second refused probe says nothing more: {:?}", g.said.lock().unwrap());
    // The node stopped and `held/` opened: the probe takes the board's own
    // lock and moves both.
    g.holds.set_node_stopped("b-1", true);
    unseal(&held);
    let sends = g.fake.sends();
    g.holds.probe("b-1");
    let moved: Vec<u64> = file_lines(&std::fs::read_to_string(held_file(&g)).unwrap()).iter().map(|line| line["held"].as_u64().unwrap()).collect();
    assert_eq!(moved, [1, 2], "both lines moved to the board's file, in `k` order");
    assert!(!pending.exists(), "the pending file removed, nothing owed");
    assert_eq!(g.fake.sends(), sends, "nothing dialed while the node is stopped");
    let landed = said_containing(&g, "joined the board's held file");
    assert!(landed.len() == 1 && landed[0].contains("2 held lines joined") && !landed[0].contains("renumbered"), "{landed:?}");
    assert_eq!(said_containing(&g, "is made and locked").len(), 1, "the store's clearing said once: {:?}", g.said.lock().unwrap());
    let next = g.hold(&insert(DOC, json!(["c"]), g.fake.head()), "unreachable", false);
    assert!(next.get("unwritable").is_none(), "the next line is copied to the board's file: {next}");
}

/// Checks that the pending store the device refuses at the first touch
/// keeps the lines in memory, owed, until it can be made (§3c.3; skep #857,
/// #859).
///
/// `held/` sealed before the session opens, so no held directory can be made
/// under it, and the board away: the pending directory cannot be made at the
/// first touch, said once; a burst is held in memory, its answer carrying
/// the refusal — "could not be made or locked" — of the class `read_only`,
/// the wait said once, and the next burst, held `behind` it, carries the
/// same. A probe, still sealed, says nothing more and dials nothing, the
/// node stopped. `held/` opened, the next probe makes the pending directory,
/// takes its lock and writes both lines to the pending file in `k` order —
/// the store's clearing and the wait's end each said once — and the next
/// line goes to disk at its hold (the mutant that drops the refusal tells
/// the page a line a close loses is on disk; the one that never tries the
/// store again keeps the lines in memory for good; the one that opens the
/// file at an empty queue alone keeps them there while one stands).
#[cfg(unix)]
#[test]
fn the_pending_store_the_device_refuses_at_the_first_touch_keeps_the_lines_in_memory_until_it_can_be_made() {
    let fake = Fake::new();
    fake.head_unreachable.store(true, Ordering::SeqCst);
    let store = TempDir::new().unwrap();
    let held = seal_the_held_store(store.path());
    let facts = writer_facts(&store);
    let g = ground_over(fake, store, facts, 0);
    assert!(!g.holds.another_window("b-1"), "the store is no other shell's");
    let refused_store = "held: the board's held store could not be made or locked";
    let said = said_containing(&g, refused_store);
    assert!(said.len() == 1 && said[0].contains("wait in memory"), "the store's refusal said once: {said:?}");
    let first = g.hold(&insert(DOC, json!(["a"]), g.fake.head()), "unreachable", false);
    assert!(first["unwritable"].as_str().is_some_and(|why| why.contains("could not be made or locked")), "the refusal rides the answer: {first}");
    assert_eq!(first["unwritable_class"], "read_only", "{first}");
    let OpAnswer::Answered(Ok(behind)) = g.holds.send_burst(&g.session, insert(DOC, json!(["b"]), g.fake.head()), None) else { panic!("held behind the first") };
    assert_eq!((behind["cause"].as_str(), behind["unwritable_class"].as_str()), (Some("behind"), Some("read_only")), "the line behind carries the same: {behind}");
    assert!(!pending_file(&g).exists(), "nothing written");
    assert_eq!(said_containing(&g, "could not be copied to its held file").len(), 1, "the wait said once: {:?}", g.said.lock().unwrap());
    g.holds.set_node_stopped("b-1", true);
    g.holds.probe("b-1");
    assert_eq!((said_containing(&g, refused_store).len(), g.fake.sends()), (1, 0), "a probe, still sealed, says nothing more and dials nothing");
    unseal(&held);
    g.holds.probe("b-1");
    let written: Vec<u64> = file_lines(&std::fs::read_to_string(pending_file(&g)).unwrap()).iter().map(|line| line["held"].as_u64().unwrap()).collect();
    assert_eq!(written, [1, 2], "the retry made the directory, took its lock and wrote both lines in `k` order");
    assert!(HeldDir::pending(g.store.path(), g.session.board.dialed()).try_lock().unwrap().is_none(), "the pending lock is this shell's");
    assert_eq!(said_containing(&g, "is made and locked").len(), 1, "the store's clearing said once");
    assert_eq!(said_containing(&g, "wait in memory no more").len(), 1, "the wait's end said once");
    let next = g.hold(&insert(DOC, json!(["c"]), g.fake.head()), "unreachable", false);
    assert!(next.get("unwritable").is_none(), "the next line goes to disk at its hold: {next}");
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

/// Checks that the board's own store refused at the first touch, the head
/// reading, puts the lines on the pending file and counts the board's file
/// (§3c.1, §3c.3; skep #856, #859).
///
/// An earlier run left the pending directory standing and the board's own
/// file holding a line under ordinal 5; the board's own directory is then
/// sealed, so its lock cannot be made. The session opens with the head
/// reading: the pending lock is taken, the board's own refused and said
/// once, and the first touch reads the pending file as the queue's own and
/// counts the board's file it could not open, so the first burst held takes
/// 6, past the board's file's 5, and goes to the pending file, no
/// `unwritable`; a second burst, held `behind` it, goes there too. The
/// directory opened, the next probe takes the board's own lock and moves
/// both to the board's file under their own ordinals; the earlier run's
/// line, first read after the first touch under an ordinal below the
/// counter, is renumbered past them and walks after them (`held`'s THE
/// ORDER), the pending file removed (the mutant that starts the counter at
/// the queue's own file hands out the board's file's ordinal, so a line this
/// run answered would share it with the earlier run's; the one that keeps
/// the lines in memory while the board's own store is refused loses them at
/// a close).
#[cfg(unix)]
#[test]
fn the_boards_own_store_refused_at_the_first_touch_puts_the_lines_on_the_pending_file_and_counts_the_boards_file() {
    use std::os::unix::fs::PermissionsExt;
    let store = TempDir::new().unwrap();
    an_earlier_runs_line(&store, 5, "earlier");
    HeldDir::pending(store.path(), &Origin::parse("http://127.0.0.1:1").unwrap()).ensure().unwrap();
    let board_dir = store.path().join("held").join("ab".repeat(32));
    std::fs::set_permissions(&board_dir, std::fs::Permissions::from_mode(0o500)).unwrap();
    let facts = writer_facts(&store);
    let g = ground_over(Fake::new(), store, facts, 0);
    assert!(!g.holds.another_window("b-1"), "the store is no other shell's");
    let said = said_containing(&g, "the board's own held store could not be made or locked");
    assert!(said.len() == 1 && said[0].contains("stay on the pending held file"), "the refusal said once: {said:?}");
    assert!(g.lines().is_empty(), "the board's file, not read, lists nothing yet");
    g.fake.op_refused.every((503, json!({"error": "write_busy"})));
    let first = g.hold(&insert(DOC, json!(["a"]), g.fake.head()), "unreachable", false);
    assert_eq!((first["held"].as_u64(), first.get("unwritable")), (Some(6), None), "past the board's file's 5, on the pending file: {first}");
    let OpAnswer::Answered(Ok(behind)) = g.holds.send_burst(&g.session, insert(DOC, json!(["b"]), g.fake.head()), None) else { panic!("held behind the first") };
    assert_eq!((behind["cause"].as_str(), behind["held"].as_u64(), behind.get("unwritable")), (Some("behind"), Some(7), None), "{behind}");
    let pending = pending_file(&g);
    assert!(std::fs::read_to_string(&pending).unwrap().contains("\"values\":[\"b\"]"), "both on the pending file");
    std::fs::set_permissions(&board_dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    g.holds.probe("b-1");
    let listed = ordinals(&g);
    assert_eq!(listed, [(6, "a".to_string()), (7, "b".to_string()), (8, "earlier".to_string())], "both moved to the board's file under their own ordinals, the earlier run's line renumbered past them");
    assert!(!pending.exists(), "the pending file removed, nothing owed");
    assert_eq!(said_containing(&g, "is made and locked").len(), 1, "the store's clearing said once");
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
    /// No answer: the read times out.
    Unanswered,
    /// The death signal on the session's token.
    Closed,
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
/// death signal at the site read taken as an answer (22–24), a delivery
/// past the values asked read as theirs (25–27), and a read unanswered or
/// met by the death signal taken as a page (28, 29).
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
        (ReadAnswer::Unanswered, Insert, None, true, Standing),
        (ReadAnswer::Closed, Insert, None, true, Standing),
    ];
    for (n, (read, head, site, sent, settles)) in table.into_iter().enumerate() {
        let g = ground();
        arm_read(&g, read, site);
        g.hold(&head_frame(&g, head), "unreachable", sent);
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

/// Arms the fake board's answers to the head's document read and site read.
fn arm_read(g: &Ground, read: ReadAnswer, site: Option<SiteAnswer>) {
    let key = g.own_key();
    let own = |at: u64, op: &str| json!({"at": at, "op": op, "key": key, "docs": [DOC]});
    let refused = |status: u16, body: Value| *g.fake.changes_refused.lock().unwrap() = Some((status, body));
    match read {
        ReadAnswer::NoRow => {}
        ReadAnswer::OwnRow(op) => *g.fake.rows.lock().unwrap() = vec![own(77, op)],
        ReadAnswer::LostRow => *g.fake.rows.lock().unwrap() = vec![lost_row()],
        ReadAnswer::ForeignRow => *g.fake.rows.lock().unwrap() = vec![json!({"at": 77, "op": "insert", "key": "ff".repeat(32), "docs": [DOC]})],
        ReadAnswer::TwoOwnRows => *g.fake.rows.lock().unwrap() = vec![own(77, "insert"), own(78, "insert")],
        ReadAnswer::Reclaimed => refused(410, json!({"error": "history_reclaimed", "floor": 90})),
        ReadAnswer::TooLarge => {
            g.fake.changes_too_large.next(1, 1);
            *g.fake.rows.lock().unwrap() = vec![own(77, "insert")];
        }
        ReadAnswer::Refused => refused(503, json!({"error": "feed_rebuilding"})),
        ReadAnswer::Unanswered => g.fake.changes_unanswered.store(true, Ordering::SeqCst),
        ReadAnswer::Closed => g.fake.changes_closed.store(true, Ordering::SeqCst),
    }
    match site {
        Some(SiteAnswer::Equal) => *g.fake.text.lock().unwrap() = "hello".into(),
        Some(SiteAnswer::Differs) => *g.fake.text.lock().unwrap() = "other".into(),
        Some(SiteAnswer::Unread) => g.fake.site_unread.store(true, Ordering::SeqCst),
        Some(SiteAnswer::Closed) => g.fake.site_closed.store(true, Ordering::SeqCst),
        Some(SiteAnswer::OverDelivers) => {
            *g.fake.text.lock().unwrap() = "hello!".into();
            g.fake.over_deliver.store(true, Ordering::SeqCst);
        }
        None => {}
    }
}

/// Returns the head's frame, typed against the board's head.
///
/// It is an insert of `hello` at the document's first position, or a delete
/// of that position.
fn head_frame(g: &Ground, head: Head) -> Value {
    match head {
        Head::Insert => insert(DOC, json!(["hello"]), g.fake.head()),
        Head::Delete => delete(DOC, g.fake.head()),
    }
}

/// A line the drop's cells hold for the person's drop.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Held {
    /// Handed to the person under `answers_lost` (§3c.4).
    HandedOver,
    /// Holding for this cause, a resend to follow (skep #983).
    Holding(&'static str),
}

impl Held {
    /// Returns the line's cause.
    fn cause(self) -> &'static str {
        match self {
            Held::HandedOver => "answers_lost",
            Held::Holding(cause) => cause,
        }
    }

    /// Returns the line's reason, its `sent` as `sent` says.
    ///
    /// It is the shell's own `answers_lost` refusal as the hand-over makes
    /// it, the head's refusal beside a line held `head_unreadable`, and no
    /// refusal beside any other holding line.
    fn reason(self, sent: bool) -> Reason {
        match self {
            Held::HandedOver => {
                let lost = Refusal::shell(Name::ANSWERS_LOST, json!({"last": "unreachable", "elapsed_ms": 120_000})).to_value();
                Reason { sent, ..Reason::refused(Name::ANSWERS_LOST.as_str(), lost) }
            }
            Held::Holding(cause @ "head_unreadable") => Reason { cause: cause.to_string(), refusal: Some(json!({"kind": "halt", "name": "head_unreadable"})), sent },
            Held::Holding(cause) => Reason::of(cause, sent),
        }
    }
}

/// Holds `frame` as a line of `kind`, and returns its ordinal.
fn held_as(g: &Ground, kind: Held, frame: &Value, sent: bool) -> u64 {
    let answer = g.hold_for(frame, kind.reason(sent)).unwrap();
    assert_eq!(answer["cause"], kind.cause(), "{answer}");
    answer["held"].as_u64().unwrap()
}

/// Holds `frame` as a line handed to the person, and returns its ordinal.
///
/// The line is a refused run under `answers_lost`, its refusal the shell's
/// as the hand-over makes it, its `sent` as `sent` says (§3c.4).
fn handed_over(g: &Ground, frame: &Value, sent: bool) -> u64 {
    held_as(g, Held::HandedOver, frame, sent)
}

/// What the person's drop of a line that may have landed does.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Drops {
    /// The line kept as landed, nothing dropped.
    Kept,
    /// The line dropped.
    Dropped,
    /// Nothing dropped: refused `landing_unread` with this `why`.
    Refused(&'static str),
    /// Nothing dropped: the session's death answered.
    Died,
}

/// Checks the drop's table, the read's table's cells (§3c.4).
///
/// The drop of a line whose dial may have landed (`sent`; skep #866, #983) —
/// handed over as `answers_lost`, or holding where a resend follows,
/// `unreachable` or `head_unreadable` — reads for its landing first, as a
/// resend does, and never drops words the board is found to hold: each answer
/// of the read's table meets the drop of each kind of line. A landing found
/// keeps the line, nothing dropped and nothing dialed; no row that could be
/// the landing — no row, a foreign one, another `op` of the own hand — drops
/// it; and where the read cannot tell nothing is dropped and the drop is
/// refused naming why: a row that could be the landing and is not confirmed —
/// a site that differs or delivers past the values asked, a lost row or
/// `history_reclaimed` on a kind no read confirms — `undecided`, a read or a
/// site read the board does not answer `unanswered`, a read answered with no
/// page `unread`; the death signal at either read drops nothing and answers
/// the death. A line never sent is dropped unread, whatever its kind. A drop
/// names no line that may have landed: each takes the line its read found
/// unlanded, or one never sent (skep #993). The mutants the cells hold off:
/// a drop made unread (2, 4, 8, 14, 15, 20, keeping nothing — a holding
/// line's among them, the read kept to a line handed over), a row not
/// confirmed taken for no landing (3, 9, 10, 16, 17, 25–27), a read that
/// decided nothing taken for no landing (5, 11, 18, 21, 28), the death taken
/// for either (22–24, 29), and the line a read ruled out named as one that
/// may have landed (1, 7, 13).
#[test]
fn every_read_answer_meets_the_drop_of_a_line_that_may_have_landed_as_the_table_says() {
    use Drops::{Died, Dropped, Kept, Refused};
    use Head::{Delete, Insert};
    use ReadAnswer::{ForeignRow, LostRow, NoRow, OwnRow, Reclaimed, TooLarge, TwoOwnRows};
    use SiteAnswer::{Differs, Equal, OverDelivers, Unread};
    let table = [
        (NoRow, Insert, None, true, Dropped),
        (OwnRow("insert"), Insert, Some(Equal), true, Kept),
        (OwnRow("insert"), Insert, Some(Differs), true, Refused("undecided")),
        (OwnRow("delete"), Delete, None, true, Kept),
        (OwnRow("insert"), Insert, Some(Unread), true, Refused("unanswered")),
        (OwnRow("insert"), Insert, Some(Equal), false, Dropped),
        (OwnRow("delete"), Insert, Some(Equal), true, Dropped),
        (LostRow, Insert, Some(Equal), true, Kept),
        (LostRow, Insert, Some(Differs), true, Refused("undecided")),
        (LostRow, Delete, None, true, Refused("undecided")),
        (LostRow, Insert, Some(Unread), true, Refused("unanswered")),
        (LostRow, Insert, Some(Equal), false, Dropped),
        (ForeignRow, Insert, Some(Equal), true, Dropped),
        (TwoOwnRows, Insert, Some(Equal), true, Kept),
        (Reclaimed, Insert, Some(Equal), true, Kept),
        (Reclaimed, Insert, Some(Differs), true, Refused("undecided")),
        (Reclaimed, Delete, None, true, Refused("undecided")),
        (Reclaimed, Insert, Some(Unread), true, Refused("unanswered")),
        (Reclaimed, Insert, Some(Equal), false, Dropped),
        (TooLarge, Insert, Some(Equal), true, Kept),
        (ReadAnswer::Refused, Insert, Some(Equal), true, Refused("unread")),
        (OwnRow("insert"), Insert, Some(SiteAnswer::Closed), true, Died),
        (LostRow, Insert, Some(SiteAnswer::Closed), true, Died),
        (Reclaimed, Insert, Some(SiteAnswer::Closed), true, Died),
        (OwnRow("insert"), Insert, Some(OverDelivers), true, Refused("undecided")),
        (LostRow, Insert, Some(OverDelivers), true, Refused("undecided")),
        (Reclaimed, Insert, Some(OverDelivers), true, Refused("undecided")),
        (ReadAnswer::Unanswered, Insert, None, true, Refused("unanswered")),
        (ReadAnswer::Closed, Insert, None, true, Died),
    ];
    for kind in [Held::HandedOver, Held::Holding("unreachable"), Held::Holding("head_unreadable")] {
        for (n, (read, head, site, sent, drops)) in table.into_iter().enumerate() {
            let g = ground();
            arm_read(&g, read, site);
            let k = held_as(&g, kind, &head_frame(&g, head), sent);
            let _ = g.states();
            let row = format!("{kind:?}, row {}: {read:?}, a {head:?} line, its site {site:?}, sent {sent} — {drops:?}", n + 1);
            let answered = match g.holds.resolve(&g.session, k, ResolveAct::Drop) {
                Ok(Resolved::Kept) => Kept,
                Ok(Resolved::Dropped { may_have_landed }) => {
                    assert!(may_have_landed.is_empty(), "{row}: the drop read its line and took no other that may have landed: {may_have_landed:?}");
                    Dropped
                }
                Ok(Resolved::Died) => Died,
                Ok(other) => panic!("{row}: {other:?}"),
                Err(refused) => {
                    let Refused(why) = drops else { panic!("{row}: refused {refused}") };
                    assert_eq!(refused.to_value(), json!({"kind": "shell", "name": "landing_unread", "held": k, "why": why}), "{row}");
                    drops
                }
            };
            assert_eq!(answered, drops, "{row}");
            // What stands, and what was said: the line and nothing said where
            // nothing was dropped; else no line, and the document `kept`.
            let (standing, says): (&[&str], &[&str]) = match drops {
                Kept | Dropped => (&[], &["kept"]),
                Refused(_) | Died => (&[kind.cause()], &[]),
            };
            let lines = g.lines();
            let causes: Vec<&str> = lines.iter().map(|l| l["cause"].as_str().unwrap_or("?")).collect();
            let states = g.states();
            assert_eq!((g.fake.sends(), causes, states.iter().map(String::as_str).collect::<Vec<_>>()), (0, standing.to_vec(), says.to_vec()), "{row} (sends, causes standing, states said)");
            let reads = g.fake.changes_reads.load(Ordering::SeqCst);
            let expected = match read {
                _ if !sent => 0,
                TooLarge => 2,
                _ => 1,
            };
            assert_eq!(reads, expected, "{row}: the `/changes` reads made");
            assert_eq!(g.holds.lock("b-1").answers(), drops != Refused("unanswered"), "{row}: a read unanswered holds the board unanswered");
        }
    }
}

/// Checks that a drop of a handed-over line whose write landed keeps it.
///
/// It keeps it and the line behind it goes out (§3c.4; skep #866). A line
/// whose resend lost its answer is handed to the person at its deadline, the
/// read then finding no landing, and a burst on its document is held behind
/// it; the write lands after all — its row the person's own, its values at
/// its site — and the person drops the line: the drop reads first, keeps the
/// line `done kept` at its row's position, nothing dialed and nothing
/// dropped, the position noted as an ack's is — the document's base, the
/// principal's latest arrangement write there, an acked position — and the
/// `held` event saying the line behind `holding`, naming the line kept at
/// that position (skep #968); the next probe sends and keeps that line. The
/// mutant that drops unread drops both lines and the words the board holds;
/// the one that drops the lines behind a kept line loses the person's later
/// words; the one that names no line leaves the page no position for them.
#[test]
fn a_drop_of_a_handed_over_line_whose_write_landed_keeps_it_and_sends_the_line_behind() {
    let g = ground();
    let k = g.hold(&insert(DOC, json!(["hello"]), g.fake.head()), "unreachable", true)["held"].as_u64().unwrap();
    g.fake.op_refused.next(1, (500, json!({"error": "internal_panic"})));
    g.holds.probe("b-1");
    g.holds.advance(HAND_OVER_DEADLINE);
    g.holds.probe("b-1");
    assert_eq!((g.lines()[0]["cause"].as_str(), g.lines()[0]["sent"].as_bool()), (Some("answers_lost"), Some(true)), "handed to the person");
    let OpAnswer::Answered(Ok(behind)) = g.holds.send_burst(&g.session, insert_at(DOC, 6, json!([" world"]), g.fake.head()), None) else { panic!("held behind the line handed over") };
    assert_eq!(behind["cause"], "behind", "{behind}");
    let key = g.own_key();
    *g.fake.rows.lock().unwrap() = vec![json!({"at": 77, "op": "insert", "key": key, "docs": [DOC]})];
    *g.fake.text.lock().unwrap() = "hello".into();
    let _ = g.states();
    let (sends, reads) = (g.fake.sends(), g.fake.changes_reads.load(Ordering::SeqCst));
    assert_eq!(g.holds.resolve(&g.session, k, ResolveAct::Drop).unwrap(), Resolved::Kept);
    assert_eq!((g.fake.sends(), g.fake.changes_reads.load(Ordering::SeqCst)), (sends, reads + 1), "read once, nothing dialed");
    let lines = g.lines();
    assert_eq!((lines.len(), lines[0]["cause"].as_str()), (1, Some("behind")), "the line behind stands: {lines:?}");
    let text = std::fs::read_to_string(held_file(&g)).unwrap();
    let kept = text.lines().filter_map(|line| serde_json::from_str::<Value>(line).ok()).any(|line| line["done"] == k && line["as"] == "kept" && line["at"] == 77);
    assert!(kept && !text.contains("\"as\":\"dropped\""), "the line `done kept` at its row's position, nothing dropped: {text}");
    let said: Vec<Value> = g.rx.try_iter().filter(|e| e.name == EventName::Held).map(|e| e.data).collect();
    assert_eq!(said.len(), 1, "{said:?}");
    assert_held_event_declared(&said[0]);
    assert_eq!((said[0]["held"].as_u64(), said[0]["state"].as_str()), (Some(1), Some("holding")), "the document as it stands: {}", said[0]);
    assert_eq!(said[0]["landed"], json!([{"held": k, "at": 77}]), "the line kept, at its row's position: {}", said[0]);
    assert_eq!((g.base_of(DOC), g.holds.last_arranged(&g.session, DOC), g.holds.acked("b-1", 77)), (77, Some(77), true), "noted as an ack is");
    g.holds.probe("b-1");
    assert_eq!(g.fake.sends(), sends + 1, "the line behind is sent");
    assert!(g.lines().is_empty() && g.states().contains(&"kept".to_string()), "and kept");
}

/// Checks that a drop whose line is sent back during its read drops nothing.
///
/// The read runs outside the board's lock (§3c.4; skep #866), and the drop
/// is checked again under it: the person's `send` on the same line, made as
/// the drop's read reaches the board, hands the line back, and the drop then
/// answers `not_resolvable`, nothing dropped and nothing said; the next
/// probe sends and keeps the line. The mutant that reads under the lock
/// deadlocks the `send`; the one that drops what it read for drops the line
/// handed back.
#[test]
fn a_drop_whose_line_is_sent_back_while_its_read_is_out_drops_nothing() {
    let g = ground();
    let k = handed_over(&g, &insert(DOC, json!(["hello"]), g.fake.head()), true);
    let (holds, session) = (Arc::clone(&g.holds), Arc::clone(&g.session));
    *g.fake.at_changes.lock().unwrap() = Some(Box::new(move || assert_eq!(holds.resolve(&session, k, ResolveAct::Send).unwrap(), Resolved::HandedBack)));
    let _ = g.states();
    let refused = g.holds.resolve(&g.session, k, ResolveAct::Drop).unwrap_err().to_value();
    assert_eq!(refused, json!({"kind": "shell", "name": "not_resolvable", "held": k}));
    let lines = g.lines();
    assert_eq!((lines.len(), lines[0]["cause"].as_str(), lines[0]["sent"].as_bool()), (1, Some("behind"), Some(true)), "the line handed back stands: {lines:?}");
    assert!(g.states().is_empty(), "nothing said of a drop that dropped nothing");
    g.holds.probe("b-1");
    assert_eq!(g.fake.sends(), 1, "the line handed back is sent");
    assert!(g.lines().is_empty() && g.states().contains(&"kept".to_string()), "and kept");
}

/// Checks that a drop reads nothing under a standing hold or a silent board.
///
/// It is §3c.4's and §3c.5's (skep #866, #983). The own node stopped, the
/// write path poisoned, the writes halted — a restart rebuilding what the
/// journal holds — and a board whose last `/health` went unanswered: the drop
/// of a `sent` line, handed over or holding, is refused `landing_unread`
/// naming the cause, no read made and nothing dropped; once the hold clears,
/// the same drop reads, finds no landing, and drops the line. The mutant that
/// reads through a halt drops a commit the restart lands; the one that dials
/// a silent board waits out its bound; the one that drops a holding line
/// unread drops, under a poisoned board, the words its restart lands.
#[test]
fn a_drop_that_reads_first_makes_no_read_while_a_hold_stands_or_the_board_is_silent() {
    /// Arms the hold `why` names at the ground's board, or clears it.
    fn arm(g: &Ground, why: &str, on: bool) {
        let health = || g.holds.note_health_read("b-1", &g.session.board.health());
        match why {
            "stopped" => g.holds.set_node_stopped("b-1", on),
            "poisoned" if on => g.holds.lock("b-1").poisoned = true,
            "poisoned" => {
                health();
            }
            "halted" => {
                g.fake.writes_halted.store(on, Ordering::SeqCst);
                health();
            }
            "unanswered" => {
                g.fake.health_unanswered.store(on, Ordering::SeqCst);
                health();
            }
            other => unreachable!("no hold named {other}"),
        }
    }
    for kind in [Held::HandedOver, Held::Holding("unreachable")] {
        for why in ["stopped", "poisoned", "halted", "unanswered"] {
            let g = ground();
            let k = held_as(&g, kind, &insert(DOC, json!(["hello"]), g.fake.head()), true);
            arm(&g, why, true);
            let refused = g.holds.resolve(&g.session, k, ResolveAct::Drop).unwrap_err().to_value();
            assert_eq!(refused, json!({"kind": "shell", "name": "landing_unread", "held": k, "why": why}), "{kind:?}, {why}");
            assert_eq!((g.fake.changes_reads.load(Ordering::SeqCst), g.lines().len()), (0, 1), "{kind:?}, {why}: no read made, nothing dropped");
            arm(&g, why, false);
            assert_eq!(g.holds.resolve(&g.session, k, ResolveAct::Drop).unwrap(), Resolved::dropped(&[]), "{kind:?}, {why}: the hold cleared");
            assert_eq!((g.fake.changes_reads.load(Ordering::SeqCst), g.lines().len()), (1, 0), "{kind:?}, {why}: read, no landing found, dropped");
        }
    }
}

/// Checks that a drop whose read goes unanswered holds the board so.
///
/// It holds it unanswered until a `/health` answers (§3c.5; skep #863,
/// #866): nothing is dropped, the drop refused `unanswered`, and a second
/// drop makes no read while the board stands unanswered; once a probe finds
/// the board answering, the drop reads again and drops the line (the mutant
/// that leaves the board answering dials a board that just gave no answer).
#[test]
fn a_drop_whose_read_goes_unanswered_holds_the_board_unanswered() {
    let g = ground();
    let k = handed_over(&g, &insert(DOC, json!(["hello"]), g.fake.head()), true);
    g.fake.changes_unanswered.store(true, Ordering::SeqCst);
    for reads in [1, 1] {
        let refused = g.holds.resolve(&g.session, k, ResolveAct::Drop).unwrap_err().to_value();
        assert_eq!(refused, json!({"kind": "shell", "name": "landing_unread", "held": k, "why": "unanswered"}));
        assert_eq!((g.fake.changes_reads.load(Ordering::SeqCst), g.lines().len()), (reads, 1), "the board unanswered: one read, nothing dropped");
    }
    g.fake.changes_unanswered.store(false, Ordering::SeqCst);
    g.holds.probe("b-1");
    assert!(g.holds.lock("b-1").answers(), "the probe's `/health` answers");
    assert_eq!(g.holds.resolve(&g.session, k, ResolveAct::Drop).unwrap(), Resolved::dropped(&[]));
    assert_eq!((g.fake.changes_reads.load(Ordering::SeqCst), g.lines().len()), (2, 0), "read again, and dropped");
}

/// Checks that the keyless session's discard reads nothing before it drops.
///
/// It is §4b.1's `resolve` row (skep #866, #896, #983). Under the bare
/// session the drop of a `sent` line, handed over as `answers_lost` or
/// holding, is the discard as it stands: dropped with no read, though the
/// board holds the write, and named in the answer as a line that may have
/// landed (skep #993). The mutant that reads under the keyless session reads
/// rows that are never its own; the one that names no line answers the
/// person that words the board holds are gone.
#[test]
fn the_keyless_sessions_discard_of_a_line_that_may_have_landed_reads_nothing() {
    for kind in [Held::HandedOver, Held::Holding("unreachable")] {
        let g = bare_ground();
        let k = held_as(&g, kind, &insert(DOC, json!(["hello"]), g.fake.head()), true);
        *g.fake.rows.lock().unwrap() = vec![lost_row()];
        *g.fake.text.lock().unwrap() = "hello".into();
        assert_eq!(g.holds.resolve(&g.session, k, ResolveAct::Drop).unwrap(), Resolved::dropped(&[k]), "{kind:?}: the line named");
        assert_eq!((g.fake.changes_reads.load(Ordering::SeqCst), g.lines().len()), (0, 0), "{kind:?}: dropped, no read made");
    }
}

/// Checks that a line no dial of which left the device drops with no read.
///
/// It is the drop of a line marked `sent` whose every resend committed
/// nothing (§3c.4; skep #983): its resends answered a `write_busy`, reissued
/// and then held, a third `durability`, or connections never made, and then
/// one more whose connection is never made, which leaves the board
/// unanswered — each a write the board ran nothing of, or one no byte of
/// which left — so the shell knows none landed (`PrincipalHold::never_left`),
/// and the drop takes the line at once though its row says `sent`, no read
/// made, the board unanswered all the same. A resend whose answer was lost
/// first leaves the line one that may have landed, and its drop reads first
/// though every later answer commits nothing (the mutant that reads at every
/// `sent` line refuses the drop `landing_unread` at a board not answering,
/// for a write it never had; the one that forgets an earlier lost answer at
/// the next quiet send drops, unread, words that may stand).
#[test]
fn a_line_no_dial_of_which_left_the_device_drops_with_no_read() {
    type Arm = fn(&Fake);
    let busy: Arm = |fake| fake.op_refused.every((503, json!({"error": "write_busy"})));
    let durable: Arm = |fake| fake.op_rejected.every(retry("durability"));
    let unreachable: Arm = |fake| fake.op_unreachable.store(true, Ordering::SeqCst);
    for (cell, arm, probes) in [("a write_busy past its reissue", busy, 2), ("a third durability", durable, 3), ("connections never made", unreachable, 2)] {
        let g = ground();
        let k = g.hold(&insert(DOC, json!(["a"]), g.fake.head()), "unreachable", false)["held"].as_u64().unwrap();
        arm(&g.fake);
        for _ in 0..probes {
            g.holds.probe("b-1");
        }
        // One more resend whose connection is never made, as an outage
        // begins: the board stands unanswered.
        g.fake.op_unreachable.store(true, Ordering::SeqCst);
        g.holds.probe("b-1");
        assert!(!g.holds.lock("b-1").answers(), "{cell}: premise: the board stands unanswered");
        let lines = g.lines();
        assert_eq!(lines[0]["sent"].as_bool(), Some(true), "{cell}: resent, and marked `sent`: {lines:?}");
        let reads = g.fake.changes_reads.load(Ordering::SeqCst);
        assert_eq!(g.holds.resolve(&g.session, k, ResolveAct::Drop).unwrap(), Resolved::dropped(&[]), "{cell}");
        assert_eq!((g.fake.changes_reads.load(Ordering::SeqCst), g.lines().len()), (reads, 0), "{cell}: dropped, no read made");
    }
    // An answer lost first: the line may have landed, and its drop reads.
    let g = ground();
    let k = g.hold(&insert(DOC, json!(["a"]), g.fake.head()), "unreachable", false)["held"].as_u64().unwrap();
    g.fake.op_lost.next(1, Lost::Timeout);
    g.holds.probe("b-1");
    g.fake.op_refused.every((503, json!({"error": "write_busy"})));
    g.holds.probe("b-1");
    assert_eq!(g.fake.sends(), 2, "premise: resent twice, the first answer lost");
    let reads = g.fake.changes_reads.load(Ordering::SeqCst);
    assert_eq!(g.holds.resolve(&g.session, k, ResolveAct::Drop).unwrap(), Resolved::dropped(&[]));
    assert_eq!((g.fake.changes_reads.load(Ordering::SeqCst), g.lines().len()), (reads + 1, 0), "read first, no landing found, dropped");
}

/// Checks that a drop takes a holding line never sent at once.
///
/// It is the person's discard of words the board never had (§3c.4; skep
/// #726, #983), at each cause a line holds under with a resend to follow,
/// the line never sent: the drop takes it and the line held behind it on its
/// document, no read made and nothing dialed, and leaves standing the line
/// held before it there and the line on another document, the document said
/// `holding` as its first line stands (the mutant that keeps a writer's drop
/// to the refused and moved faces refuses it `not_resolvable`, leaving the
/// person no way to take back a run of writes the board has not kept; the
/// one that drops every later line whatever its document loses the other
/// document's words).
#[test]
fn a_holding_line_never_sent_drops_at_once_with_the_lines_after_it() {
    for cause in ["unreachable", "stopped", "halted", "behind", "durability", "session_died", "head_unreadable"] {
        let g = ground();
        let typed = g.fake.head();
        g.hold(&insert(DOC, json!(["before"]), typed), "unreachable", false);
        let k = held_as(&g, Held::Holding(cause), &insert(DOC, json!(["dropped"]), typed), false);
        g.hold(&insert(OTHER, json!(["other"]), typed), "behind", false);
        g.hold(&insert(DOC, json!(["after"]), typed), "behind", false);
        let _ = g.states();
        assert_eq!(g.holds.resolve(&g.session, k, ResolveAct::Drop).map_err(|r| r.to_value()), Ok(Resolved::dropped(&[])), "{cause}");
        let standing: Vec<String> = g.lines().iter().map(|l| l["frame"]["values"][0].as_str().unwrap_or("?").to_string()).collect();
        assert_eq!(standing, ["before", "other"], "{cause}: the line and the one behind it on its document dropped");
        assert_eq!((g.fake.changes_reads.load(Ordering::SeqCst), g.fake.sends()), (0, 0), "{cause}: no read made, nothing dialed");
        assert_eq!(g.states(), ["holding"], "{cause}: the document's first line stands holding");
    }
}

/// Checks that the drop of a moved line marked `sent` makes no read.
///
/// It is the moved face's discard as #866 settled it (§3c.4; skep #866,
/// #983): a `delete` held `unreachable` with `sent: true`, a row whose
/// testimony the board lost standing on its document, so its resend's read
/// is undecided and the line is sent; the board refuses it as typed against
/// an older state, and, carrying no anchors, it is held moved, its `sent`
/// kept. Its drop takes it at once, no read made, and names it as a line
/// that may have landed (skep #993). The mutant that reads before every drop
/// of a `sent` line meets the same undecided read and refuses the drop
/// `landing_unread` at every try, leaving the moved face no discard, since
/// its `send` is refused as typed against an older state again; the one that
/// names no line answers the person that words the board may hold are gone.
#[test]
fn the_drop_of_a_moved_line_marked_sent_makes_no_read() {
    let g = ground();
    let k = g.hold(&delete(DOC, g.fake.head()), "unreachable", true)["held"].as_u64().unwrap();
    *g.fake.rows.lock().unwrap() = vec![lost_row()];
    g.fake.move_arrangement(DOC, 77);
    g.holds.probe("b-1");
    let lines = g.lines();
    assert_eq!((lines[0]["cause"].as_str(), lines[0]["sent"].as_bool(), g.fake.sends()), (Some("moved"), Some(true), 1), "read undecided, sent, refused stale and held moved: {lines:?}");
    let reads = g.fake.changes_reads.load(Ordering::SeqCst);
    assert_eq!(g.holds.resolve(&g.session, k, ResolveAct::Drop).map_err(|r| r.to_value()), Ok(Resolved::dropped(&[k])), "the line named");
    assert_eq!((g.fake.changes_reads.load(Ordering::SeqCst), g.lines().len()), (reads, 0), "dropped, no read made");
}

/// Checks that the drop of a refused line marked `sent` names it alone.
///
/// The drop takes it with no read, and its words may stand (§3c.4; skep
/// #993): a `delete` held `unreachable` with `sent: true`, a row whose
/// testimony the board lost standing on its document, so its resend's read
/// is undecided and the line is sent; the board refuses the resend under a
/// `permanent` code, and the line stands a refused run, its `sent` kept. Its
/// drop takes it and the line held behind it, never sent, no read made and
/// nothing dialed, and names the refused line alone (the mutant that answers
/// the drop bare tells the person words the board may hold are gone; the one
/// that names every line it takes names a line never dialed).
#[test]
fn the_drop_of_a_refused_line_marked_sent_names_it_and_not_a_line_never_sent() {
    let g = ground();
    let k = g.hold(&delete(DOC, g.fake.head()), "unreachable", true)["held"].as_u64().unwrap();
    g.hold(&delete(DOC, g.fake.head()), "behind", false);
    *g.fake.rows.lock().unwrap() = vec![lost_row()];
    g.fake.op_rejected.next(1, json!({"resp": "rejected", "code": "out_of_bounds", "disposition": "permanent", "op": "delete"}));
    g.holds.probe("b-1");
    let lines = g.lines();
    let refused = (lines[0]["cause"].as_str(), lines[0]["sent"].as_bool(), lines[1]["sent"].as_bool(), g.fake.sends());
    assert_eq!(refused, (Some("out_of_bounds"), Some(true), Some(false), 1), "read undecided, sent and refused, the line behind it unsent: {lines:?}");
    let reads = g.fake.changes_reads.load(Ordering::SeqCst);
    assert_eq!(g.holds.resolve(&g.session, k, ResolveAct::Drop).map_err(|r| r.to_value()), Ok(Resolved::dropped(&[k])), "the refused line alone named");
    assert_eq!((g.fake.changes_reads.load(Ordering::SeqCst), g.fake.sends(), g.lines().len()), (reads, 1, 0), "both dropped, no read made, nothing dialed");
}

/// Checks that the drop of a moved line no dial of which left names none.
///
/// The shell knows no write of it landed (§3c.4; skep #983, #993): a line
/// held before any dial is resent, marked `sent` before the dial, and the
/// board refuses it as typed against an older state, a refusal that commits
/// nothing (`PrincipalHold::never_left`); carrying no anchors, it is held
/// moved, its row saying `sent`. Its drop takes it at once, no read made, and
/// names no line (the mutant that names every `sent` line tells the person
/// of a landing no dial could have made).
#[test]
fn the_drop_of_a_moved_line_no_dial_of_which_left_names_none() {
    let g = ground();
    let k = g.hold(&insert(DOC, json!(["a"]), g.fake.head()), "unreachable", false)["held"].as_u64().unwrap();
    g.fake.move_arrangement(DOC, 77);
    g.holds.probe("b-1");
    let lines = g.lines();
    assert_eq!((lines[0]["cause"].as_str(), lines[0]["sent"].as_bool(), g.fake.sends()), (Some("moved"), Some(true), 1), "resent, refused stale and held moved: {lines:?}");
    assert_eq!(g.holds.with_principal("b-1", 1, |ph| ph.never_left.contains(&k)), Some(true), "premise: no dial of it left the device");
    let reads = g.fake.changes_reads.load(Ordering::SeqCst);
    assert_eq!(g.holds.resolve(&g.session, k, ResolveAct::Drop).map_err(|r| r.to_value()), Ok(Resolved::dropped(&[])), "no line named");
    assert_eq!((g.fake.changes_reads.load(Ordering::SeqCst), g.lines().len()), (reads, 0), "dropped, no read made");
}

/// Checks that a drop that read first names a `sent` line behind its own.
///
/// Its read rules out the landing of the line it read alone (§3c.4; skep
/// #993): three lines held `unreachable` with `sent: true` on one document,
/// no row standing on it — as first dials of one document that went out
/// together and lost their answers leave them, two tabs or a page and an
/// agent — and a line never sent behind them. The drop of the second reads
/// once, finds no landing, and drops it and the two behind it, nothing
/// dialed, naming the `sent` line behind it alone, while the line before it
/// stands, named nowhere (the mutant that names nothing after a read answers
/// the person that words the board may hold are gone; the one that names the
/// line read names a landing its read ruled out; the one that names every
/// line of the document names one the drop left standing).
#[test]
fn a_drop_that_read_first_names_a_sent_line_behind_the_one_it_read() {
    let g = ground();
    let typed = g.fake.head();
    let line = |ordinal: u64, value: &str, cause: &str, sent: bool| g.hold(&insert_at(DOC, ordinal, json!([value]), typed), cause, sent)["held"].as_u64().unwrap();
    let before = line(1, "a", "unreachable", true);
    let k = line(2, "b", "unreachable", true);
    let behind = line(3, "c", "unreachable", true);
    line(4, "d", "behind", false);
    let reads = g.fake.changes_reads.load(Ordering::SeqCst);
    assert_eq!(g.holds.resolve(&g.session, k, ResolveAct::Drop).map_err(|r| r.to_value()), Ok(Resolved::dropped(&[behind])), "the `sent` line behind alone named");
    let standing: Vec<u64> = g.lines().iter().filter_map(|l| l["held"].as_u64()).collect();
    assert_eq!((g.fake.changes_reads.load(Ordering::SeqCst), g.fake.sends(), standing), (reads + 1, 0, vec![before]), "read once, nothing dialed, the line before it standing");
}

/// Checks that an outage's resends write nothing past the first.
///
/// A line whose every resend is a connection never made (§3c.2; skep #971,
/// #983): its first resend marks it `sent` and names its dial id in one copy,
/// and no later resend writes a line more, so the outage costs the held file
/// nothing per probe; that no dial of it left the device is the shell's
/// memory alone (`PrincipalHold::never_left`), so a relaunch, reading the
/// line `sent` from its file, reads for its landing before the drop drops it
/// (the mutant that writes the mark at every resend grows the file a line a
/// probe for as long as the outage lasts; the one that keeps the knowledge
/// across a relaunch would drop, unread, words a dial made before a crash may
/// have landed).
#[test]
fn an_outages_resends_write_nothing_past_the_first_and_a_relaunch_reads_before_the_drop() {
    let g = ground();
    let k = g.hold(&insert(DOC, json!(["a"]), g.fake.head()), "unreachable", false)["held"].as_u64().unwrap();
    g.fake.op_unreachable.store(true, Ordering::SeqCst);
    let length = |g: &Ground| std::fs::metadata(held_file(g)).unwrap().len();
    let held = length(&g);
    g.holds.probe("b-1");
    let readied = length(&g);
    assert!(readied > held, "the first resend writes its mark and its dial id");
    for _ in 0..2 {
        g.holds.probe("b-1");
    }
    assert_eq!(length(&g), readied, "no resend after the first writes a line");
    assert_eq!((g.fake.sends(), g.lines()[0]["sent"].as_bool()), (0, Some(true)), "no request left, the line marked `sent`");
    // The relaunch: this run's holds gone, the line read `sent` from its file.
    let Ground { holds, fake, session, store, .. } = g;
    drop(holds);
    let g = ground_over(fake, store, session.facts.clone(), 0);
    assert_eq!(g.lines()[0]["sent"].as_bool(), Some(true), "the relaunch reads the line `sent`");
    let reads = g.fake.changes_reads.load(Ordering::SeqCst);
    assert_eq!(g.holds.resolve(&g.session, k, ResolveAct::Drop).unwrap(), Resolved::dropped(&[]));
    assert_eq!((g.fake.changes_reads.load(Ordering::SeqCst), g.lines().len()), (reads + 1, 0), "read first, no landing found, dropped");
}

/// Checks that a drop drops nothing where a send takes its line mid-read.
///
/// It is §3c.4's drop beside a resend (skep #983): the person drops a
/// holding line marked `sent`, its drop reading for its landing first, and
/// while that read is out the probe resends the line, the resend's answer
/// garbled, so its write may have landed after the drop's read: the drop
/// answers `not_resolvable`, nothing dropped, the line standing as its send
/// left it, and the next drop reads again (the mutant that holds the drop to
/// the line's reason alone drops a line whose resend may have landed after
/// the read that cleared it).
#[test]
fn a_drop_whose_read_is_out_as_a_send_takes_the_line_drops_nothing() {
    let g = ground();
    let k = g.hold(&insert(DOC, json!(["hello"]), g.fake.head()), "unreachable", true)["held"].as_u64().unwrap();
    let (holds, fake) = (Arc::clone(&g.holds), Arc::clone(&g.fake));
    *g.fake.at_changes.lock().unwrap() = Some(Box::new(move || {
        fake.op_lost.next(1, Lost::Garbled);
        holds.probe("b-1");
    }));
    let refused = g.holds.resolve(&g.session, k, ResolveAct::Drop).unwrap_err().to_value();
    assert_eq!(refused, json!({"kind": "shell", "name": "not_resolvable", "held": k}));
    let lines = g.lines();
    assert_eq!((g.fake.sends(), lines.len(), lines[0]["cause"].as_str(), lines[0]["sent"].as_bool()), (1, 1, Some("unreachable"), Some(true)), "the line as its send left it: {lines:?}");
    let reads = g.fake.changes_reads.load(Ordering::SeqCst);
    assert_eq!(g.holds.resolve(&g.session, k, ResolveAct::Drop).unwrap(), Resolved::dropped(&[]), "the next drop reads again");
    assert_eq!(g.fake.changes_reads.load(Ordering::SeqCst), reads + 1);
}

/// Checks that a send that panics lets its line go, and its drop reads.
///
/// A dial that unwinds the resend leaves the line out of the sends' set
/// (skep #983), so the person's drop takes it, and outside the lines no dial
/// of which left, the dial's fate unknown, so the drop reads first (the
/// mutant whose guard lets the line go on the send's own return alone leaves
/// it `not_resolvable` for the shell's life; the one that enters it among
/// those lines as it unwinds drops, unread, words the dial may have landed).
#[test]
fn a_send_that_panics_lets_its_line_go_and_its_drop_reads_first() {
    let g = ground();
    let k = g.hold(&insert(DOC, json!(["hello"]), g.fake.head()), "unreachable", false)["held"].as_u64().unwrap();
    *g.fake.at_send.lock().unwrap() = Some(Box::new(|| panic!("the resend's dial is made to panic")));
    let unwound = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| g.holds.probe("b-1")));
    assert!(unwound.is_err() && g.fake.sends() == 1, "the dial left, and panicked");
    let reads = g.fake.changes_reads.load(Ordering::SeqCst);
    assert_eq!(g.holds.resolve(&g.session, k, ResolveAct::Drop).unwrap(), Resolved::dropped(&[]));
    assert_eq!((g.fake.changes_reads.load(Ordering::SeqCst), g.lines().len()), (reads + 1, 0), "read first: the dial's fate is unknown");
}

/// Checks that no act takes a line while the walk's dial of it is out.
///
/// The person drops, and sends, a holding line as the resend's dial of it
/// reaches the board (skep #983): each act answers `not_resolvable`, nothing
/// dropped or re-marked, and the dial's ack keeps the line (the mutant that
/// takes the drop drops a line the board is writing, the ack then landing
/// words the person was told are gone).
#[test]
fn no_act_takes_a_line_while_the_walks_dial_of_it_is_out() {
    let g = ground();
    let k = g.hold(&insert(DOC, json!(["a"]), g.fake.head()), "unreachable", false)["held"].as_u64().unwrap();
    let acted = Arc::new(Mutex::new(Vec::new()));
    let (holds, session, seen) = (Arc::downgrade(&g.holds), Arc::clone(&g.session), Arc::clone(&acted));
    *g.fake.at_send.lock().unwrap() = Some(Box::new(move || {
        let Some(holds) = holds.upgrade() else { return };
        for act in [ResolveAct::Drop, ResolveAct::Send] {
            seen.lock().unwrap().push(holds.resolve(&session, k, act).map_err(|r| r.to_value()));
        }
    }));
    let _ = g.states();
    g.holds.probe("b-1");
    *g.fake.at_send.lock().unwrap() = None;
    let refused: Result<Resolved, Value> = Err(json!({"kind": "shell", "name": "not_resolvable", "held": k}));
    assert_eq!(*acted.lock().unwrap(), vec![refused.clone(), refused], "each act refused while the dial is out");
    assert_eq!(g.fake.sends(), 1, "sent once");
    assert!(g.lines().is_empty() && g.states() == ["sending", "kept"], "the ack keeps the line");
}

/// Checks that a resend lets its line go before the line's face is told.
///
/// The board refuses a resend under a `permanent` code, and the `refused`
/// face reaches a watcher on the bus on the resend's own thread, which drops
/// the line as the face asks (skep #983): the drop takes it (the mutant that
/// lets the line go as the send returns, after its face, answers the act the
/// face asks for `not_resolvable`).
#[test]
fn a_resend_lets_its_line_go_before_the_lines_face_is_told() {
    let g = ground();
    let k = g.hold(&insert(DOC, json!(["a"]), g.fake.head()), "unreachable", false)["held"].as_u64().unwrap();
    g.fake.op_rejected.next(1, json!({"resp": "rejected", "code": "out_of_bounds", "disposition": "permanent", "op": "insert"}));
    let acted = Arc::new(Mutex::new(Vec::new()));
    let (holds, session, seen) = (Arc::downgrade(&g.holds), Arc::clone(&g.session), Arc::clone(&acted));
    g.bus.watch(move |_, event| {
        if event.name == EventName::Held && event.data["state"] == "refused" {
            if let Some(holds) = holds.upgrade() {
                seen.lock().unwrap().push(holds.resolve(&session, k, ResolveAct::Drop).map_err(|r| r.to_value()));
            }
        }
    });
    g.holds.probe("b-1");
    assert_eq!((acted.lock().unwrap().clone(), g.fake.sends()), (vec![Ok(Resolved::dropped(&[]))], 1), "the act the face asks for takes the line");
    assert!(g.lines().is_empty(), "the line dropped");
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

/// Checks that the next line after a settled one starts its reissues afresh.
///
/// The rider is counted per line (§3c.4): a line reissued twice and then
/// kept leaves the queue empty, and the next line held takes the next
/// ordinal — the ordinals run on past the compaction, never reused (skep
/// #856) — and its first `durability` is reissued, never counted as the
/// settled line's third (the mutant that counts the rider per document
/// holds the person's next burst at its first `durability`).
#[test]
fn the_next_line_after_a_settled_one_starts_its_reissues_afresh() {
    let g = ground();
    g.fake.op_rejected.next(2, retry("durability"));
    let first = g.hold(&insert(DOC, json!(["a"]), g.fake.head()), "unreachable", false);
    for _ in 0..3 {
        g.holds.probe("b-1");
    }
    assert_eq!(g.fake.sends(), 3, "reissued twice, then sent and kept");
    assert!(g.lines().is_empty(), "the line is kept and the queue empties");
    let again = g.hold(&insert(DOC, json!(["b"]), g.fake.head()), "unreachable", false);
    assert_eq!((first["held"].as_u64(), again["held"].as_u64()), (Some(1), Some(2)), "the ordinals run on");
    g.fake.op_rejected.next(1, retry("durability"));
    g.holds.probe("b-1");
    assert_eq!((g.fake.sends(), g.lines()[0]["cause"].as_str()), (4, Some("unreachable")), "the new line's first `durability` is reissued");
}

/// Checks that a probe owes no read where no session that may write stands.
///
/// A bare session reads alone: a probe over an empty queue dials nothing, and
/// a halt once told is read on only until it clears (§3c.4; skep #865; the
/// mutant that probes every board at every cadence reads `/health` for the
/// shell's life).
#[test]
fn a_probe_with_no_session_that_may_write_and_no_line_dials_nothing() {
    let g = bare_ground();
    let reads = || g.fake.health_reads.load(Ordering::SeqCst);
    g.holds.probe("b-1");
    assert_eq!((reads(), g.fake.sends()), (0, 0), "an empty queue is probed for nothing");
    g.fake.writes_halted.store(true, Ordering::SeqCst);
    g.holds.note_health("b-1", &g.session.board.health().unwrap());
    let reads_at_the_halt = reads();
    g.holds.probe("b-1");
    assert_eq!(reads(), reads_at_the_halt + 1, "a halt told is read until it clears");
    g.fake.writes_halted.store(false, Ordering::SeqCst);
    g.holds.probe("b-1");
    let reads_at_the_clearing = reads();
    g.holds.probe("b-1");
    assert_eq!(reads(), reads_at_the_clearing, "cleared, the probe reads nothing more");
}

/// Checks that a signed session's probe reads the board with no line held.
///
/// Each probe reads `/health` once and, once the pair is read and kept,
/// dials nothing more for the head; a line held is sent by the probe that
/// reads it (§3c.3; P37; skep #865; the mutant that keeps the probe to the
/// held lines finds no halt on a board that commits nothing, and the one
/// that reads the head past the kept pair dials it at every tick for good).
#[test]
fn a_signed_sessions_probe_reads_the_board_with_no_line_held_and_no_kept_head_again() {
    let g = ground();
    let (health, head) = (|| g.fake.health_reads.load(Ordering::SeqCst), || g.fake.head_reads.load(Ordering::SeqCst));
    let head_at_the_open = head();
    assert_eq!(head_at_the_open, 1, "premise: the open read the head and kept the pair");
    for probe in 1..=3 {
        g.holds.probe("b-1");
        assert_eq!((health(), g.fake.sends()), (probe, 0), "one `/health` a probe, nothing sent");
    }
    assert_eq!(head(), head_at_the_open, "a pair once read costs no dial");
    g.hold(&insert(DOC, json!(["a"]), g.fake.head()), "unreachable", false);
    g.holds.probe("b-1");
    assert_eq!((health(), g.fake.sends()), (4, 1), "a standing line is sent by the probe that reads");
    assert!(g.lines().is_empty(), "and kept");
}

/// Checks that a quiet board's halt and its clearing are told once each.
///
/// With no line held and nothing committing, the probe alone can read the
/// halt: `halted` is the one change as the halt is read, a steady halt
/// answers none however many probes read it, and `running` is the one change
/// as it clears (§4b.2; skep #865; the mutant that takes no change at the
/// halt tells the page nothing until a write meets it, and the one that keeps
/// no told state says it at every tick).
#[test]
fn a_quiet_boards_halt_and_its_clearing_are_told_once_each() {
    let g = ground();
    g.fake.writes_halted.store(true, Ordering::SeqCst);
    assert_eq!(g.holds.state_change("b-1"), None, "premise: nothing told before a probe reads the halt");
    g.holds.probe("b-1");
    let edge = g.holds.state_change("b-1").expect("the halt told");
    assert_eq!((edge.from, edge.to), (BoardState::Running, BoardState::Halted));
    for _ in 0..3 {
        g.holds.probe("b-1");
        assert_eq!(g.holds.state_change("b-1"), None, "a steady halt is told no more");
    }
    g.fake.writes_halted.store(false, Ordering::SeqCst);
    g.holds.probe("b-1");
    let edge = g.holds.state_change("b-1").expect("the clearing told");
    assert_eq!((edge.from, edge.to), (BoardState::Halted, BoardState::Running));
    g.holds.probe("b-1");
    assert_eq!(g.holds.state_change("b-1"), None, "and the state told holds");
}

/// Checks that a head that will not read is told before any write meets it.
///
/// With no line held and nothing written, a head answered garbled from the
/// session's open, and a board unclaimed at the open that then names a
/// claimant and serves no head record, are each told `head_unreadable` with
/// their reason by the probe alone; a steady unreadable head is told no more;
/// and once the head reads the one change is `running`, the pair kept (§3c.3;
/// §4b.2; skep #865; the mutant that reads the head only behind a held line
/// finds a head its board stopped serving only when a write is held for it).
#[test]
fn a_head_that_will_not_read_is_told_with_its_reason_before_any_write() {
    let garbled = |fake: &Fake| fake.head_garbled.store(true, Ordering::SeqCst);
    let unclaimed = |fake: &Fake| {
        fake.no_head.store(true, Ordering::SeqCst);
        fake.unclaimed.store(true, Ordering::SeqCst);
    };
    type Arm<'a> = &'a dyn Fn(&Fake);
    let cells: [(&str, Arm<'_>, bool, &str); 2] =
        [("garbled from the open", &garbled, false, "served garbled"), ("unclaimed at the open, a claimant named after", &unclaimed, true, "serves no head record")];
    for (cell, arm, named_after, why) in cells {
        let fake = Fake::new();
        arm(&fake);
        let store = TempDir::new().unwrap();
        let facts = writer_facts(&store);
        let g = ground_over(fake, store, facts, 0);
        if named_after {
            assert_eq!(g.holds.state_change("b-1"), None, "{cell}: an unclaimed board owes no head");
            g.fake.unclaimed.store(false, Ordering::SeqCst);
            g.holds.probe("b-1");
        }
        let edge = g.holds.state_change("b-1").unwrap_or_else(|| panic!("{cell}: told"));
        assert_eq!((edge.from, edge.to.as_str()), (BoardState::Running, "head_unreadable"), "{cell}");
        assert!(edge.to.reason().is_some_and(|reason| reason.contains(why)), "{cell}: {:?}", edge.to.reason());
        assert_eq!(g.fake.sends(), 0, "{cell}: no write");
        for _ in 0..2 {
            g.holds.probe("b-1");
            assert_eq!(g.holds.state_change("b-1"), None, "{cell}: a steady state is told no more");
        }
        g.fake.head_garbled.store(false, Ordering::SeqCst);
        g.fake.no_head.store(false, Ordering::SeqCst);
        g.holds.probe("b-1");
        let edge = g.holds.state_change("b-1").unwrap_or_else(|| panic!("{cell}: told"));
        assert_eq!((edge.from.as_str(), edge.to), ("head_unreadable", BoardState::Running), "{cell}");
    }
}

/// Checks that a board halted whose head will not read says each in turn.
///
/// The halt is the more severe, so it alone is told while it stands, the
/// head not read meanwhile, then `head_unreadable` as it clears, then
/// `running` as the head reads (§4b.2; skep #865; the mutant that clears the
/// head's state at the halt says `running` over a head that will not read,
/// and the one that reads the head under the halt dials a board that says it
/// takes no write at every tick).
#[test]
fn a_board_halted_whose_head_will_not_read_says_halted_then_head_unreadable_then_running() {
    let fake = Fake::new();
    fake.head_garbled.store(true, Ordering::SeqCst);
    let store = TempDir::new().unwrap();
    let facts = writer_facts(&store);
    let g = ground_over(fake, store, facts, 0);
    g.fake.writes_halted.store(true, Ordering::SeqCst);
    let head_reads = g.fake.head_reads.load(Ordering::SeqCst);
    g.holds.probe("b-1");
    let edge = g.holds.state_change("b-1").expect("the halt told");
    assert_eq!((edge.from, edge.to), (BoardState::Running, BoardState::Halted), "the more severe is told first");
    g.holds.probe("b-1");
    assert_eq!((g.holds.state_change("b-1"), g.fake.head_reads.load(Ordering::SeqCst)), (None, head_reads), "while the halt stands nothing more is told, and the head is not read");
    g.fake.writes_halted.store(false, Ordering::SeqCst);
    g.holds.probe("b-1");
    let edge = g.holds.state_change("b-1").expect("the head told as the halt clears");
    assert_eq!((edge.from, edge.to.as_str()), (BoardState::Halted, "head_unreadable"));
    g.fake.head_garbled.store(false, Ordering::SeqCst);
    g.holds.probe("b-1");
    let edge = g.holds.state_change("b-1").expect("the head reads");
    assert_eq!((edge.from.as_str(), edge.to), ("head_unreadable", BoardState::Running));
}

/// Checks that a live feed thread says a quiet board's halt once each way.
///
/// Over the board's real feed thread, its commit stream live and silent, no
/// line held and nothing committing, `daemon` says `halted` and then
/// `running` as the probe reads each, and nothing more across further probes
/// (§4b.2; skep #865; the mutant that leaves the probe to held lines never
/// says the halt).
#[test]
fn the_feed_thread_says_a_quiet_boards_halt_and_its_clearing_once_each() {
    let g = ground();
    g.fake.quiet_stream.store(true, Ordering::SeqCst);
    let threads = feed_threads(&g);
    let next_daemon = || loop {
        let event = g.rx.recv_timeout(Duration::from_secs(20)).expect("a `daemon` event within the deadline");
        if event.name == EventName::Daemon {
            crate::shapes::assert_declared("DaemonEvent", &event.data);
            break event.data;
        }
    };
    g.fake.writes_halted.store(true, Ordering::SeqCst);
    assert_eq!(next_daemon(), json!({"board": "b-1", "state": "halted"}));
    g.fake.writes_halted.store(false, Ordering::SeqCst);
    assert_eq!(next_daemon(), json!({"board": "b-1", "state": "running"}));
    let reads = g.fake.health_reads.load(Ordering::SeqCst);
    let deadline = Instant::now() + Duration::from_secs(20);
    while g.fake.health_reads.load(Ordering::SeqCst) < reads + 2 && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(20));
    }
    threads.stop();
    assert!(g.fake.health_reads.load(Ordering::SeqCst) >= reads + 2, "two probes more read the board");
    let said: Vec<Value> = g.rx.try_iter().filter(|e| e.name == EventName::Daemon).map(|e| e.data).collect();
    assert!(said.is_empty(), "a steady state says nothing at each tick: {said:?}");
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
/// the line holds, resent, and its drop, owed a read for its landing, is
/// refused `landing_unread` `unanswered` with no read made while its last
/// resend's answer awaits the board's verdict (skep #983); once
/// `HAND_OVER_DEADLINE` stands past, the next probe's read runs, finds no
/// landing and hands it to the
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
    let before = g.fake.changes_reads.load(Ordering::SeqCst);
    let refused = g.holds.resolve(&g.session, k, ResolveAct::Drop).unwrap_err().to_value();
    assert_eq!(refused, json!({"kind": "shell", "name": "landing_unread", "held": k, "why": "unanswered"}), "a line that may have landed, its last resend unanswered");
    assert_eq!((g.fake.changes_reads.load(Ordering::SeqCst), g.lines().len()), (before, 1), "no read made, nothing dropped");
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
/// clock moved far past `HAND_OVER_DEADLINE` between the probes, its `send`
/// `not_resolvable` and the shell knowing no dial of it left the device
/// (`PrincipalHold::never_left`; skep #983), never handed over, until the
/// board answers and the next probe sends and keeps it (§3c.4; the mutant
/// that reads a connection never made as a failed send — off the dial's
/// answer, or off the line's `sent`, which its resend marked before the
/// dial — hands an outage's line to the person).
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
    assert_eq!(g.holds.resolve(&g.session, k, ResolveAct::Send).unwrap_err().name(), "not_resolvable");
    assert_eq!(g.holds.with_principal("b-1", 1, |ph| ph.never_left.contains(&k)), Some(true), "no dial of it left the device");
    g.fake.op_unreachable.store(false, Ordering::SeqCst);
    g.holds.probe("b-1");
    assert_eq!(g.fake.sends(), 1, "the board answering, the line is sent");
    assert!(g.lines().is_empty() && g.states().contains(&"kept".to_string()));
}

/// Checks that a pass ends at the first request the board leaves unanswered.
///
/// It is §3c.5's end of a pass.
///
/// Two documents hold a line each, `DOC`'s first. The board gives no answer to
/// the walk's first request — `DOC`'s send timing out, the board hanging up on
/// it, its connection never made, `DOC`'s read, its site's read, or the
/// probe's read of the board's head — and the pass ends there: nothing reaches
/// `OTHER`, no dial, no read and no `held` event; a line whose send was cut
/// goes back to `holding`, `unreachable` with its `sent`, and one whose read
/// was cut stands as it was; nothing is said of either in the shell's own
/// window. A burst of another principal's at the board is held `unreachable`
/// at once, undialed. The board answering again, the next probe walks first
/// the documents the pass did not reach — `OTHER`, then the other
/// principal's — and the document it cut last, and keeps every line (the
/// mutant that walks on past the silence waits out every document's bound;
/// the one that dials a burst into it waits out the burst's; the one that
/// starts the next turn at the cut document holds every other document's
/// words behind a line the board keeps leaving unanswered).
#[test]
fn a_pass_ends_at_the_first_request_the_board_gives_no_answer_to() {
    let cells = ["the send times out", "the board hangs up", "no connection is made", "the read goes unanswered", "the site's read goes unanswered", "the head's read goes unanswered"];
    for cell in cells {
        let fake = Fake::new();
        // The head's read unanswered from the open, so no head is held.
        let head = cell == "the head's read goes unanswered";
        fake.head_unreachable.store(head, Ordering::SeqCst);
        let store = TempDir::new().unwrap();
        let facts = writer_facts(&store);
        let g = ground_over(fake, store, facts, 0);
        let read = matches!(cell, "the read goes unanswered" | "the site's read goes unanswered");
        g.hold(&insert(DOC, json!(["a"]), g.fake.head()), "unreachable", read);
        g.hold(&insert(OTHER, json!(["b"]), g.fake.head()), "behind", false);
        match cell {
            "the send times out" => g.fake.op_lost.next(1, Lost::Timeout),
            "the board hangs up" => g.fake.op_lost_at.store(1, Ordering::SeqCst),
            "no connection is made" => g.fake.op_unreachable.store(true, Ordering::SeqCst),
            "the read goes unanswered" => g.fake.changes_unanswered.store(true, Ordering::SeqCst),
            "the site's read goes unanswered" => {
                *g.fake.rows.lock().unwrap() = vec![json!({"at": 60, "op": "insert", "key": g.own_key(), "docs": [DOC]})];
                g.fake.site_unread.store(true, Ordering::SeqCst);
            }
            _ => {}
        }
        let before = g.lines();
        let _ = g.states();
        g.holds.probe("b-1");
        let dialed = |doc: &str| g.fake.sends.lock().unwrap().iter().filter(|frame| frame["doc"] == doc).count();
        assert_eq!((dialed(OTHER), g.fake.changes_reads.load(Ordering::SeqCst)), (0, usize::from(read)), "{cell}: nothing dialed or read at `OTHER`");
        let said: Vec<Value> = g.rx.try_iter().filter(|e| e.name == EventName::Held).map(|e| e.data).collect();
        said.iter().for_each(assert_held_event_declared);
        assert!(said.iter().all(|e| e["doc"] == DOC), "{cell}: no `held` event at `OTHER`: {said:?}");
        let lines = g.lines();
        if matches!(cell, "the send times out" | "the board hangs up" | "no connection is made") {
            assert_eq!((lines[0]["cause"].as_str(), lines[0]["sent"].as_bool()), (Some("unreachable"), Some(true)), "{cell}: back to holding with its `sent`: {lines:?}");
            let states: Vec<&str> = said.iter().filter_map(|e| e["state"].as_str()).collect();
            assert_eq!(states, ["sending", "holding"], "{cell}");
        } else {
            assert_eq!(lines, before, "{cell}: the line as it was");
            assert!(said.is_empty(), "{cell}: nothing said of the document: {said:?}");
        }
        assert!(said_containing(&g, "was not taken").is_empty(), "{cell}: nothing said of the line: {:?}", g.said.lock().unwrap());
        // Another principal's burst is held at once, the verdict pending.
        let open = Open { token: Token::parse(&"8e".repeat(16)).unwrap(), facts: writer_facts_as(&g.store, 2, "1.0.2"), opened_at: 0 };
        let second = g.sessions.register(&g.entry, open, &mut NoSupplements);
        g.holds.open_session(&second);
        let sends = g.fake.sends();
        let OpAnswer::Answered(Ok(held)) = g.holds.send(&second, insert("1.0.2.0.1", json!(["c"]), g.fake.head()), None) else { panic!("{cell}: held") };
        assert_eq!((held["cause"].as_str(), g.fake.sends()), (Some("unreachable"), sends), "{cell}: held at once, undialed: {held}");
        // The board answers again.
        g.fake.op_lost_at.store(0, Ordering::SeqCst);
        for arm in [&g.fake.op_unreachable, &g.fake.changes_unanswered, &g.fake.site_unread, &g.fake.head_unreachable] {
            arm.store(false, Ordering::SeqCst);
        }
        g.fake.sends.lock().unwrap().clear();
        g.holds.probe("b-1");
        let order: Vec<String> = g.fake.sends.lock().unwrap().iter().map(|frame| frame["doc"].as_str().unwrap_or("?").to_string()).collect();
        let want = if head { [DOC, OTHER, "1.0.2.0.1"] } else { [OTHER, "1.0.2.0.1", DOC] };
        assert_eq!(order, want, "{cell}: the documents the pass did not reach first, the cut one last");
        assert!(g.lines().is_empty() && g.holds.lines(&second).unwrap().as_array().unwrap().is_empty(), "{cell}: every line kept");
    }
}

/// Checks that an unanswered send fails its line only if the board answers.
///
/// The board answering is the next probe's verdict (§3c.4).
///
/// A line's resend times out. Where the probe after it finds the board
/// answering, the send was the line's own failure: its clock runs from that
/// send, its "not taken" said once at that probe and never at the cut, and
/// two minutes after the send that probe's read hands the line to the person,
/// undialed. Where the probe after it finds the board silent, the send was
/// the board's silence: no clock starts and nothing is said, and ten minutes
/// on, the board answering, the line is read, sent and kept, never handed
/// over (the mutant that notes the cut's failure at once hands a stalled
/// board's line to the person; the one that never notes it resends a frame
/// the board chokes on for ever).
#[test]
fn an_unanswered_sends_failure_counts_only_where_the_next_probe_finds_the_board_answering() {
    for silent in [false, true] {
        let g = ground();
        g.hold(&insert(DOC, json!(["a"]), g.fake.head()), "unreachable", false);
        g.fake.op_lost.next(1, Lost::Timeout);
        g.holds.probe("b-1");
        assert!(said_containing(&g, "was not taken").is_empty(), "silent {silent}: nothing said at the cut");
        if silent {
            g.fake.health_unanswered.store(true, Ordering::SeqCst);
            g.holds.probe("b-1");
            g.holds.advance(Duration::from_secs(600));
            g.fake.health_unanswered.store(false, Ordering::SeqCst);
            g.holds.probe("b-1");
            assert!(g.lines().is_empty() && g.fake.sends() == 2, "the board answering, read, sent and kept, never handed over: {:?}", g.lines());
            assert!(said_containing(&g, "was not taken").is_empty(), "the board's silence says nothing of the line: {:?}", g.said.lock().unwrap());
        } else {
            g.holds.advance(HAND_OVER_DEADLINE + Duration::from_secs(1));
            g.holds.probe("b-1");
            let lines = g.lines();
            assert_eq!((g.fake.sends(), lines[0]["cause"].as_str()), (1, Some("answers_lost")), "the line's own failure, two minutes past: handed over undialed: {lines:?}");
            assert_eq!(said_containing(&g, "was not taken").len(), 1, "said once, at the verdict: {:?}", g.said.lock().unwrap());
        }
    }
}

/// Checks that a line's two minutes run only while the board answers (§3c.4).
///
/// A line's resend answered garbled starts its clock; the next resend times
/// out, and the probe after it finds the board silent, ten minutes passing
/// while it stays so. The board answering again, the line's read finds no
/// landing and the line is resent, never handed over: its count paused across
/// the silence and kept. Two minutes more of the board answering, the next
/// read hands it to the person, naming the wall time since its first failed
/// send, past the ten minutes (the mutant that runs the clock through the
/// silence hands it over at the first read after it; the one that resets it
/// at the silence lets a board that flaps postpone the hand-over for ever).
#[test]
fn a_lines_two_minutes_run_only_while_the_board_answers() {
    let g = ground();
    g.hold(&insert(DOC, json!(["a"]), g.fake.head()), "unreachable", false);
    g.fake.op_lost.next(1, Lost::Garbled);
    g.holds.probe("b-1");
    g.fake.op_lost.next(1, Lost::Timeout);
    g.holds.probe("b-1");
    g.fake.health_unanswered.store(true, Ordering::SeqCst);
    g.holds.probe("b-1");
    g.holds.advance(Duration::from_secs(600));
    g.holds.probe("b-1");
    g.fake.health_unanswered.store(false, Ordering::SeqCst);
    g.fake.op_lost.every(Lost::Garbled);
    g.holds.probe("b-1");
    let lines = g.lines();
    assert_eq!((g.fake.sends(), lines[0]["cause"].as_str()), (3, Some("unreachable")), "the silence paused its count: resent, never handed over: {lines:?}");
    g.holds.advance(HAND_OVER_DEADLINE);
    g.holds.probe("b-1");
    let lines = g.lines();
    assert_eq!((g.fake.sends(), lines[0]["cause"].as_str()), (3, Some("answers_lost")), "two minutes of the board answering: handed over: {lines:?}");
    let elapsed = lines[0]["refusal"]["elapsed_ms"].as_u64().unwrap();
    assert!(elapsed >= 720_000, "the wall time since its first failed send: {}", lines[0]["refusal"]);
}

/// Checks that a resend's shift is untried until its image read is answered.
///
/// It is §3c.5's THE SHIFT (2).
///
/// An anchored line the board refuses as typed against an older state meets
/// no answer to the shift's live read: the shift is not tried and the
/// document never faced moved — nothing said of a shift, the line back to
/// `holding`, `unreachable` with its `sent`, no refusal beside it — and the
/// pass ends there. The board answering, the next probe runs the shift from
/// the verdict it kept, no stale frame dialed first: one image read more, the
/// shifted dial, the line kept (the mutant that faces the unanswered read
/// `moved` asks the person to place words a read never saw; the one that
/// drops the verdict dials the stale frame again first).
#[test]
fn a_resends_shift_whose_image_read_goes_unanswered_holds_the_line_and_shifts_it_when_the_board_answers() {
    let g = ground();
    let typed = g.fake.head();
    *g.fake.image.lock().unwrap() = vec![run(&i(10), 2), run(&i(1), 3)];
    g.hold_anchored(&insert_at(DOC, 2, json!(["x"]), typed), anchors(Some(&i(1)), Some(&i(2))), "unreachable", false);
    g.fake.move_arrangement(DOC, 77);
    g.fake.image_unread.store(true, Ordering::SeqCst);
    let _ = g.states();
    g.holds.probe("b-1");
    let lines = g.lines();
    assert_eq!((g.fake.sends(), g.fake.image_reads.load(Ordering::SeqCst)), (1, 1), "refused stale, its shift's read unanswered");
    assert_eq!((lines[0]["cause"].as_str(), lines[0]["sent"].as_bool(), lines[0].get("refusal")), (Some("unreachable"), Some(true), None), "back to holding with its `sent`: {lines:?}");
    assert_eq!(g.states(), ["sending", "holding"], "never faced moved");
    assert!(said_containing(&g, "not shifted").is_empty(), "nothing said of a shift: {:?}", g.said.lock().unwrap());
    g.fake.image_unread.store(false, Ordering::SeqCst);
    g.holds.probe("b-1");
    let sent = g.fake.sends.lock().unwrap().clone();
    assert_eq!((sent.len(), g.fake.image_reads.load(Ordering::SeqCst)), (2, 2), "the kept verdict's shift, no stale frame dialed first: {sent:?}");
    assert_eq!((sent[1]["at"]["ordinal"].as_str(), sent[1]["as_of"].as_u64()), (Some("4"), Some(77)), "shifted by the one displacement, typed at the read's state: {sent:?}");
    assert!(g.lines().is_empty() && g.states().contains(&"kept".to_string()));
}

/// Checks that a moved face's unanswered hands are said unread, then named.
///
/// It is §3c.5's THE SHIFT (6).
///
/// A line without anchors the board refuses as typed against an older state
/// is held moved on that verdict; its read of the hands that moved the
/// document goes unanswered, and the moved face stands with its hands not
/// read — the one hand `unread`, never `lost` — and the pass ends there. The
/// board answering, the walk reads the hands again as it meets the document
/// and says the face once more, naming the other writer's hand; the line
/// awaits the person's act, sent no more (the mutant that reads the
/// unanswered hands as none names nobody where the board lost nothing; the
/// one that never reads them again leaves the face without its hand).
#[test]
fn a_moved_face_whose_hands_read_goes_unanswered_says_hands_not_read_and_names_them_when_the_board_answers() {
    let ff = "ff".repeat(32);
    let g = ground();
    let typed = g.fake.head();
    *g.fake.rows.lock().unwrap() = vec![json!({"at": 77, "op": "insert", "key": ff, "docs": [DOC]})];
    g.hold(&insert_at(DOC, 2, json!(["x"]), typed), "unreachable", false);
    g.fake.move_arrangement(DOC, 77);
    g.fake.changes_unanswered.store(true, Ordering::SeqCst);
    let _ = g.states();
    let held = |g: &Ground| -> Vec<Value> {
        let said: Vec<Value> = g.rx.try_iter().filter(|e| e.name == EventName::Held).map(|e| e.data).collect();
        said.iter().for_each(assert_held_event_declared);
        said
    };
    g.holds.probe("b-1");
    let said = held(&g);
    let moved = said.iter().find(|e| e["state"] == "moved").unwrap_or_else(|| panic!("faced moved on the board's verdict: {said:?}"));
    assert_eq!(moved["hands"], json!([{"key": "unread"}]), "its hands not read: {moved}");
    let lines = g.lines();
    assert_eq!((lines[0]["cause"].as_str(), &lines[0]["refusal"]), (Some("moved"), &arrangement_moved_on("insert", typed, 77)), "{lines:?}");
    g.fake.changes_unanswered.store(false, Ordering::SeqCst);
    g.holds.probe("b-1");
    let said = held(&g);
    assert_eq!(said.len(), 1, "the face said once more: {said:?}");
    assert_eq!((&said[0]["state"], &said[0]["hands"]), (&json!("moved"), &json!([{"key": "other", "fingerprint": ff}])), "the hand named: {said:?}");
    assert_eq!(g.fake.sends(), 1, "the line awaits the person's act");
}

/// The anchors of a point between the document's first and second units.
fn between_one_and_two() -> Anchors {
    anchors(Some(&i(1)), Some(&i(2)))
}

/// The image the anchors [`between_one_and_two`] stand adjacent in, an edit
/// made before them.
fn edited_elsewhere() -> Vec<Value> {
    vec![run(&i(10), 2), run(&i(1), 3)]
}

/// The image the anchors [`between_one_and_two`] no longer stand adjacent in.
fn span_cut() -> Vec<Value> {
    vec![run(&i(1), 1), run(&i(10), 1), run(&i(2), 2)]
}

/// The documents a drafts read named, as the feed thread hands them over.
fn rows_naming(docs: &[&str]) -> RowsNamed {
    let mut named = RowsNamed::default();
    named.note(&json!({"docs": docs}));
    named
}

/// The `sendable` the ground's first row carries, where it carries one.
fn row_sendable(g: &Ground) -> Option<bool> {
    g.lines()[0].get("sendable").map(|sendable| sendable.as_bool().expect("a boolean"))
}

/// The `held` events since the last look, each held to its declaration.
fn held_events(g: &Ground) -> Vec<Value> {
    let said: Vec<Value> = g.rx.try_iter().filter(|e| e.name == EventName::Held).map(|e| e.data).collect();
    said.iter().for_each(assert_held_event_declared);
    said
}

/// The image reads the ground's board has served.
fn image_reads(g: &Ground) -> usize {
    g.fake.image_reads.load(Ordering::SeqCst)
}

/// Checks that `sendable` says what a `send` would do, and a `send` does it.
///
/// It is §3c.5's shift test (skep #867). A line held moved, tested at the
/// probe: an edit elsewhere leaves its anchors adjacent, and it reads true,
/// told on the `moved` event; a deleted span, a cut span or an anchor lost
/// reads false, and tells nothing, the page's act inert on false as on
/// absent. The test sends nothing and reads the image once. Then the
/// person's `send`: where it read true the next probe shifts the line and
/// keeps it, and where it read false it holds the line moved again (the
/// mutant that answers true without running the shift lights an act that
/// moves the line again; the one that answers false for a span still whole
/// hides an act that would land).
#[test]
fn a_moved_lines_sendable_says_what_a_send_would_do_and_a_send_does_it() {
    type Cell = (&'static str, Box<dyn Fn(u64) -> Value>, Anchors, Vec<Value>, bool);
    let insert_between = || -> Box<dyn Fn(u64) -> Value> { Box::new(|typed| insert_at(DOC, 2, json!(["x"]), typed)) };
    let delete_two = || -> Box<dyn Fn(u64) -> Value> { Box::new(|typed| delete_at(DOC, 2, 2, typed)) };
    let cells: Vec<Cell> = vec![
        ("an edit elsewhere", insert_between(), between_one_and_two(), edited_elsewhere(), true),
        ("a deleted span", delete_two(), spanned(Some(&i(1)), None, &[(&i(2), 2)]), vec![run(&i(1), 1)], false),
        ("a cut span", insert_between(), between_one_and_two(), span_cut(), false),
        ("an anchor lost", insert_between(), between_one_and_two(), vec![run(&i(10), 2), run(&i(1), 1)], false),
    ];
    for (cell, frame, anchored, image, want) in cells {
        let g = ground();
        let typed = g.fake.head();
        *g.fake.image.lock().unwrap() = image;
        g.hold_anchored(&frame(typed), anchored, "moved", false);
        assert_eq!(row_sendable(&g), None, "{cell}: nothing known before a test");
        let _ = held_events(&g);
        g.holds.probe("b-1");
        assert_eq!((row_sendable(&g), image_reads(&g), g.fake.sends()), (Some(want), 1, 0), "{cell}: one read, nothing sent");
        let said = held_events(&g);
        assert_eq!(said.len(), usize::from(want), "{cell}: only true is told: {said:?}");
        if want {
            assert_eq!((said[0]["state"].as_str(), said[0]["sendable"].as_bool()), (Some("moved"), Some(true)), "{cell}: {said:?}");
        }
        g.fake.move_arrangement(DOC, 77);
        assert_eq!(g.holds.resolve(&g.session, 1, ResolveAct::Send).unwrap(), Resolved::HandedBack);
        g.holds.probe("b-1");
        if want {
            assert!(g.lines().is_empty(), "{cell}: the send shifted the line and it landed: {:?}", g.lines());
        } else {
            assert_eq!(g.lines()[0]["cause"], "moved", "{cell}: the send held the line moved again");
        }
    }
}

/// Checks that a row naming a moved document tests it once, telling nothing
/// while the answer stands.
///
/// A burst the board refuses as typed against an older state, its span cut:
/// the moved hold's own shift is the test, its read the only one, the row and
/// the event saying false. A probe owes nothing, and a row naming another
/// document owes nothing; two rows naming the document cost one read at the
/// next probe, and no event (the mutant that reads again per row dials the
/// board for every commit on a busy document; the one that tells every test
/// says a `moved` the page has nothing to do with).
#[test]
fn a_row_that_leaves_the_span_cut_costs_one_read_and_tells_nothing() {
    let g = ground();
    let typed = g.fake.head();
    *g.fake.image.lock().unwrap() = span_cut();
    g.fake.move_arrangement(DOC, 77);
    let OpAnswer::Answered(Ok(held)) = g.holds.send_burst(&g.session, insert_at(DOC, 2, json!(["x"]), typed), Some(between_one_and_two())) else { panic!("held") };
    assert_eq!((held["cause"].as_str(), image_reads(&g)), (Some("moved"), 1), "the shift's own read, no second: {held}");
    let said = held_events(&g);
    assert_eq!((said.len(), said[0]["sendable"].as_bool(), row_sendable(&g)), (1, Some(false), Some(false)), "{said:?}");
    g.holds.probe("b-1");
    g.holds.note_rows("b-1", 1, &rows_naming(&[OTHER]));
    g.holds.probe("b-1");
    assert_eq!(image_reads(&g), 1, "nothing owed: no read at a probe, none for a row of another document");
    g.holds.note_rows("b-1", 1, &rows_naming(&[DOC]));
    g.holds.note_rows("b-1", 1, &rows_naming(&[DOC]));
    g.holds.probe("b-1");
    assert_eq!((image_reads(&g), held_events(&g).len(), row_sendable(&g)), (2, 0, Some(false)), "one read however many rows, no event");
    g.holds.probe("b-1");
    assert_eq!(image_reads(&g), 2, "the test made, nothing owed");
}

/// Checks that a resend's moved hold enters its shift's answer, no second read.
///
/// It is the moved hold at a resend, as a first dial's is tested above. A
/// line held behind an outage, its span cut, is refused stale at the probe's
/// send: the shift's own read answers false, and no further read is owed
/// (the mutant that leaves the resend's hold unrecorded reads the image again
/// at the next probe).
#[test]
fn a_resends_moved_hold_is_its_own_shift_test() {
    let g = ground();
    let typed = g.fake.head();
    g.hold_anchored(&insert_at(DOC, 2, json!(["x"]), typed), between_one_and_two(), "unreachable", false);
    *g.fake.image.lock().unwrap() = span_cut();
    g.fake.move_arrangement(DOC, 77);
    let _ = held_events(&g);
    g.holds.probe("b-1");
    let moved: Vec<Value> = held_events(&g).into_iter().filter(|e| e["state"] == "moved").collect();
    assert_eq!((moved.len(), moved[0]["sendable"].as_bool(), row_sendable(&g), image_reads(&g)), (1, Some(false), Some(false), 1), "{moved:?}");
    g.holds.probe("b-1");
    assert_eq!(image_reads(&g), 1, "no test owed");
}

/// Checks that an edit restoring a span flips `sendable` with one event.
///
/// A line held moved on the board's verdict, its span cut, reads false, a
/// writer's change named on its face. The span restored and a row naming the
/// document: the next probe flips it to true with one `moved` event naming
/// the hand, as every moved face does, and the row says true; a change that
/// cuts it again flips it back with one event; a probe with nothing new says
/// nothing (the mutant that tells the flip with no hands has the page erase
/// the names on its face; the one that never tells it leaves the act inert
/// on a line a send would land).
#[test]
fn an_edit_restoring_the_span_flips_sendable_with_one_event_naming_the_hands() {
    let ff = "ff".repeat(32);
    let g = ground();
    let typed = g.fake.head();
    *g.fake.rows.lock().unwrap() = vec![json!({"at": 77, "op": "insert", "key": ff, "docs": [DOC]})];
    *g.fake.image.lock().unwrap() = span_cut();
    g.fake.move_arrangement(DOC, 77);
    let OpAnswer::Answered(Ok(held)) = g.holds.send_burst(&g.session, insert_at(DOC, 2, json!(["x"]), typed), Some(between_one_and_two())) else { panic!("held") };
    assert_eq!(held["cause"], "moved", "{held}");
    let _ = held_events(&g);
    let hands = json!([{"key": "other", "fingerprint": ff}]);
    *g.fake.image.lock().unwrap() = vec![run(&i(1), 3)];
    g.holds.note_rows("b-1", 1, &rows_naming(&[DOC]));
    g.holds.probe("b-1");
    let said = held_events(&g);
    let [flip] = &said[..] else { panic!("one held event: {said:?}") };
    assert_eq!((flip["state"].as_str(), flip["sendable"].as_bool(), &flip["hands"]), (Some("moved"), Some(true), &hands), "the flip names the hands: {flip}");
    assert_eq!(row_sendable(&g), Some(true));
    g.holds.probe("b-1");
    assert!(held_events(&g).is_empty(), "nothing new, nothing said");
    *g.fake.image.lock().unwrap() = span_cut();
    g.holds.note_rows("b-1", 1, &rows_naming(&[DOC]));
    g.holds.probe("b-1");
    let said = held_events(&g);
    let [back] = &said[..] else { panic!("one held event: {said:?}") };
    assert_eq!((back["state"].as_str(), back["sendable"].as_bool(), &back["hands"]), (Some("moved"), Some(false), &hands), "{back}");
    assert_eq!(row_sendable(&g), Some(false));
}

/// Checks that an unanswered shift test leaves `sendable` absent.
///
/// It is absent until a read answers (skep #863, #867). The image read goes
/// unanswered: the pass ends there, the row carries no mark and nothing is
/// said, and the test stays owed, read again while the board answers its
/// `/health`. An answer tells true, once. A told answer that a later read
/// goes unanswered over stands told: the row goes absent, nothing is said,
/// and the read that answers tells only a change from true (the mutant that
/// tells the unanswered read says a state no read saw; the one that forgets
/// what was told after it leaves the page's act live on a line a send would
/// hold moved).
#[test]
fn an_unanswered_shift_test_leaves_sendable_absent_until_a_read_answers() {
    let g = ground();
    let typed = g.fake.head();
    *g.fake.image.lock().unwrap() = edited_elsewhere();
    g.hold_anchored(&insert_at(DOC, 2, json!(["x"]), typed), between_one_and_two(), "moved", false);
    let _ = held_events(&g);
    g.fake.image_unread.store(true, Ordering::SeqCst);
    assert_eq!(g.holds.probe("b-1"), Turn::Unanswered, "the pass ends at the read");
    assert_eq!((row_sendable(&g), held_events(&g).len(), image_reads(&g)), (None, 0, 1), "absent, nothing said");
    assert_eq!(g.holds.probe("b-1"), Turn::Unanswered, "the test still owed, the board answering its `/health`");
    assert_eq!(image_reads(&g), 2);
    g.fake.image_unread.store(false, Ordering::SeqCst);
    assert_eq!(g.holds.probe("b-1"), Turn::Done);
    let said = held_events(&g);
    assert_eq!((said.len(), said[0]["sendable"].as_bool(), row_sendable(&g)), (1, Some(true), Some(true)), "{said:?}");
    g.holds.note_rows("b-1", 1, &rows_naming(&[DOC]));
    g.fake.image_unread.store(true, Ordering::SeqCst);
    g.holds.probe("b-1");
    assert_eq!((row_sendable(&g), held_events(&g).len()), (None, 0), "absent again, nothing said");
    g.fake.image_unread.store(false, Ordering::SeqCst);
    g.holds.probe("b-1");
    assert_eq!((row_sendable(&g), held_events(&g).len()), (Some(true), 0), "the page was told true: no change to tell");
    g.holds.note_rows("b-1", 1, &rows_naming(&[DOC]));
    g.fake.image_unread.store(true, Ordering::SeqCst);
    g.holds.probe("b-1");
    *g.fake.image.lock().unwrap() = span_cut();
    g.fake.image_unread.store(false, Ordering::SeqCst);
    g.holds.probe("b-1");
    let said = held_events(&g);
    assert_eq!((said.len(), said[0]["sendable"].as_bool(), row_sendable(&g)), (1, Some(false), Some(false)), "the change from true told: {said:?}");
}

/// Checks that a refused shift test waits for a row naming the document.
///
/// A document past the board's image budget answers every read
/// `image_too_large`: the row carries no mark, and the test is read once, not
/// again at every pass, until a row names the document (the mutant that marks
/// a refused read owed reads the image at every probe for as long as the line
/// stands).
#[test]
fn a_refused_shift_test_is_not_read_again_until_a_row_names_the_document() {
    let g = ground();
    let typed = g.fake.head();
    g.hold_anchored(&insert_at(DOC, 2, json!(["x"]), typed), between_one_and_two(), "moved", false);
    let _ = held_events(&g);
    g.fake.image_refused.store(true, Ordering::SeqCst);
    g.holds.probe("b-1");
    g.holds.probe("b-1");
    assert_eq!((image_reads(&g), row_sendable(&g), held_events(&g).len()), (1, None, 0), "refused once, read no more, absent");
    g.holds.note_rows("b-1", 1, &rows_naming(&[DOC]));
    g.holds.probe("b-1");
    assert_eq!(image_reads(&g), 2, "a row naming the document owes the read again");
    g.fake.image_refused.store(false, Ordering::SeqCst);
    *g.fake.image.lock().unwrap() = edited_elsewhere();
    g.holds.note_rows("b-1", 1, &rows_naming(&[DOC]));
    g.holds.probe("b-1");
    let said = held_events(&g);
    assert_eq!((said.len(), said[0]["sendable"].as_bool(), row_sendable(&g)), (1, Some(true), Some(true)), "a read that answers says it: {said:?}");
}

/// Checks that a relaunched moved line is tested at its first probe.
///
/// The answer is in memory, so a relaunch owes a first test: the file read at
/// the session's open says nothing and carries no mark, and the first probe
/// tests the line and tells true (the mutant that keeps the debt to a row
/// leaves a relaunched line's act inert until the document next changes).
#[test]
fn a_relaunched_moved_line_is_tested_at_its_first_probe() {
    let g = ground();
    let typed = g.fake.head();
    *g.fake.image.lock().unwrap() = edited_elsewhere();
    g.hold_anchored(&insert_at(DOC, 2, json!(["x"]), typed), between_one_and_two(), "moved", false);
    g.holds.probe("b-1");
    assert_eq!(row_sendable(&g), Some(true));
    let Ground { holds, fake, session, store, .. } = g;
    drop(holds);
    let g = ground_over(fake, store, session.facts.clone(), 0);
    assert_eq!((row_sendable(&g), held_events(&g).len()), (None, 0), "the open tests nothing and says nothing");
    g.holds.probe("b-1");
    let said = held_events(&g);
    assert_eq!((said.len(), said[0]["sendable"].as_bool(), row_sendable(&g)), (1, Some(true), Some(true)), "{said:?}");
}

/// Checks that a line with no anchors or no span reads false with no read.
///
/// A burst of an agent's carries no anchors, so it never shifts: held moved
/// at its first dial it reads false, on the row and on the event, and the
/// tests it owes read no image. A delete whose anchors name no span is false
/// the same way (the mutant that reads the image first dials the board for
/// an answer no image can change).
#[test]
fn a_line_with_no_anchors_or_no_span_reads_false_with_no_read() {
    let g = ground();
    let typed = g.fake.head();
    g.fake.op_rejected.next(1, arrangement_moved(typed, 77));
    let OpAnswer::Answered(Ok(held)) = g.holds.send_burst(&g.session, insert(DOC, json!(["x"]), typed), None) else { panic!("held") };
    assert_eq!(held["cause"], "moved", "{held}");
    let said = held_events(&g);
    assert_eq!((said.len(), said[0]["sendable"].as_bool(), row_sendable(&g)), (1, Some(false), Some(false)), "{said:?}");
    g.holds.note_rows("b-1", 1, &rows_naming(&[DOC]));
    g.holds.probe("b-1");
    assert_eq!((image_reads(&g), held_events(&g).len(), row_sendable(&g)), (0, 0, Some(false)), "tested again, no read and no event");
    let g = ground();
    let typed = g.fake.head();
    g.hold_anchored(&delete_at(DOC, 2, 2, typed), anchors(Some(&i(1)), None), "moved", false);
    g.holds.probe("b-1");
    assert_eq!((image_reads(&g), row_sendable(&g)), (0, Some(false)), "a delete with no span");
}

/// Checks that a moved document's first moved line alone carries the mark.
///
/// Three lines held moved on one document: the first carries `sendable`, the
/// others none. The keyless session, whose `send` is refused, reads none on
/// the row, and its discard of a later line says the moved face with none,
/// where a discard under a session that may write says it; a line that is
/// not moved carries none (the mutant that marks every moved line promises a
/// shift of a line the walk never tested; the one that marks a keyless row
/// lights an act that cannot run).
#[test]
fn only_a_moved_documents_first_line_carries_the_mark_and_the_keyless_session_none() {
    let g = ground();
    let typed = g.fake.head();
    *g.fake.image.lock().unwrap() = edited_elsewhere();
    let mut ks = Vec::new();
    for word in ["x", "y", "z"] {
        ks.push(g.hold_anchored(&insert_at(DOC, 2, json!([word]), typed), between_one_and_two(), "moved", false)["held"].as_u64().unwrap());
    }
    g.holds.probe("b-1");
    let rows = |lines: &[Value]| lines.iter().map(|line| line.get("sendable").cloned()).collect::<Vec<_>>();
    assert_eq!(rows(&g.lines()), [Some(json!(true)), None, None]);
    let _ = held_events(&g);
    let bare = g.holds.sessions.register(&BoardEntry { reference: "b-1".into(), board: Arc::clone(&g.session.board) }, Open { token: Token::parse(&"9e".repeat(16)).unwrap(), facts: bare_facts(), opened_at: 0 }, &mut NoSupplements);
    let listed = g.holds.lines(&bare).unwrap();
    assert_eq!(rows(listed.as_array().unwrap()), [None, None, None], "{listed}");
    assert_eq!(g.holds.resolve(&bare, ks[2], ResolveAct::Drop).unwrap(), Resolved::dropped(&[]));
    let said = held_events(&g);
    assert_eq!((said.len(), said[0]["state"].as_str(), said[0].get("sendable")), (1, Some("moved"), None), "the keyless session's discard: {said:?}");
    assert_eq!(g.holds.resolve(&g.session, ks[1], ResolveAct::Drop).unwrap(), Resolved::dropped(&[]));
    let said = held_events(&g);
    assert_eq!((said.len(), said[0]["state"].as_str(), said[0]["sendable"].as_bool()), (1, Some("moved"), Some(true)), "a writer's discard: {said:?}");
    assert_eq!(g.holds.resolve(&g.session, ks[0], ResolveAct::Drop).unwrap(), Resolved::dropped(&[]));
    assert_eq!(g.holds.shift_test_stale(&g.session, DOC), None, "the line leaving the queue takes its test");
    let g = ground();
    g.hold_anchored(&insert_at(DOC, 2, json!(["x"]), g.fake.head()), between_one_and_two(), "unreachable", false);
    assert_eq!(row_sendable(&g), None, "a line that is not moved carries none");
}

/// Checks that a flip whose hands' read goes unanswered names them not read.
///
/// It is the moved hold's own face at a told change (skep #863, #867). The
/// span restored and the read of the hands going unanswered: the flip is
/// said, its hands `unread`, the pass ends there, and at the board's answer
/// the walk names them, `sendable` still said (the mutant that drops the flip
/// at the unanswered hands leaves the act inert on a line a send would land).
#[test]
fn a_flip_whose_hands_read_goes_unanswered_says_them_not_read_and_names_them_after() {
    let ff = "ff".repeat(32);
    let g = ground();
    let typed = g.fake.head();
    *g.fake.rows.lock().unwrap() = vec![json!({"at": 77, "op": "insert", "key": ff, "docs": [DOC]})];
    *g.fake.image.lock().unwrap() = span_cut();
    g.fake.move_arrangement(DOC, 77);
    let OpAnswer::Answered(Ok(held)) = g.holds.send_burst(&g.session, insert_at(DOC, 2, json!(["x"]), typed), Some(between_one_and_two())) else { panic!("held") };
    assert_eq!(held["cause"], "moved", "{held}");
    let _ = held_events(&g);
    *g.fake.image.lock().unwrap() = vec![run(&i(1), 3)];
    g.holds.note_rows("b-1", 1, &rows_naming(&[DOC]));
    g.fake.changes_unanswered.store(true, Ordering::SeqCst);
    assert_eq!(g.holds.probe("b-1"), Turn::Unanswered, "the pass ends at the hands' read");
    let said = held_events(&g);
    let [flip] = &said[..] else { panic!("one held event: {said:?}") };
    assert_eq!((flip["sendable"].as_bool(), &flip["hands"]), (Some(true), &json!([{"key": "unread"}])), "{flip}");
    assert_eq!(row_sendable(&g), Some(true));
    g.fake.changes_unanswered.store(false, Ordering::SeqCst);
    g.holds.probe("b-1");
    let said = held_events(&g);
    let [named] = &said[..] else { panic!("the face said once more: {said:?}") };
    assert_eq!((named["sendable"].as_bool(), &named["hands"]), (Some(true), &json!([{"key": "other", "fingerprint": ff}])), "{named}");
}

/// Checks that the death signal at a shift test leaves it owed.
///
/// It is the session's death and no verdict on the document (§3c.4; skep
/// #867): met at the image read, or at the read of the hands a told change
/// makes, nothing is entered and nothing said, and the next probe tests the
/// line again (the mutant that enters an answer at the death never tests the
/// line for the session that stands next).
#[test]
fn the_death_signal_at_a_shift_test_leaves_it_owed() {
    for (cell, at_the_image) in [("the image read", true), ("the read of the hands", false)] {
        let g = ground();
        let typed = g.fake.head();
        *g.fake.rows.lock().unwrap() = vec![json!({"at": 77, "op": "insert", "key": "ff".repeat(32), "docs": [DOC]})];
        *g.fake.image.lock().unwrap() = span_cut();
        g.fake.move_arrangement(DOC, 77);
        let OpAnswer::Answered(Ok(held)) = g.holds.send_burst(&g.session, insert_at(DOC, 2, json!(["x"]), typed), Some(between_one_and_two())) else { panic!("{cell}: held") };
        assert_eq!(held["cause"], "moved", "{cell}: {held}");
        let _ = held_events(&g);
        *g.fake.image.lock().unwrap() = vec![run(&i(1), 3)];
        g.holds.note_rows("b-1", 1, &rows_naming(&[DOC]));
        let closed = if at_the_image { &g.fake.image_closed } else { &g.fake.changes_closed };
        closed.store(true, Ordering::SeqCst);
        g.holds.probe("b-1");
        assert_eq!((row_sendable(&g), held_events(&g).len()), (Some(false), 0), "{cell}: nothing entered, nothing said");
        closed.store(false, Ordering::SeqCst);
        g.holds.probe("b-1");
        assert_eq!(row_sendable(&g), Some(true), "{cell}: tested again at the next probe");
    }
}

/// Checks that a shift test the person's `send` overtakes enters nothing.
///
/// The test's image read reaches the board and the person's `send` hands the
/// line back before it answers, the read answered or going unanswered: under
/// the lock again the line stands moved at the head no more, so the answer
/// is dropped, no entry and no `moved` event (the mutant that enters it
/// anyway says `sendable` of a line the person sent, and a `moved` the page
/// has just been told is over).
#[test]
fn a_send_made_while_a_shift_test_reads_leaves_it_nothing_to_say() {
    for (cell, unanswered) in [("the read answered", false), ("the read unanswered", true)] {
        let g = ground();
        let typed = g.fake.head();
        *g.fake.image.lock().unwrap() = edited_elsewhere();
        g.hold_anchored(&insert_at(DOC, 2, json!(["x"]), typed), between_one_and_two(), "moved", false);
        let _ = held_events(&g);
        g.fake.image_unread.store(unanswered, Ordering::SeqCst);
        let (holds, session) = (Arc::downgrade(&g.holds), Arc::clone(&g.session));
        *g.fake.at_image.lock().unwrap() = Some(Box::new(move || {
            if let Some(holds) = holds.upgrade() {
                let _ = holds.resolve(&session, 1, ResolveAct::Send);
            }
        }));
        g.holds.probe("b-1");
        *g.fake.at_image.lock().unwrap() = None;
        assert_eq!(g.lines()[0]["cause"], "behind", "{cell}: the person's send stands");
        assert_eq!(g.holds.shift_test_stale(&g.session, DOC), None, "{cell}: no answer entered");
        assert!(held_events(&g).iter().all(|e| e["state"] != "moved"), "{cell}: no `moved` said");
    }
}

/// Checks that the person's `send` takes the shift test with it.
///
/// A moved line tested true, handed back by the person's `send`, and held
/// moved again at its deadline, which tests nothing: the answer was of the
/// line before the send, so the row carries no mark until the next probe
/// tests it (the mutant that keeps the entry across the `send` says what a
/// send would have done before it, and owes the line no test).
#[test]
fn the_persons_send_takes_the_shift_test_with_it() {
    let g = ground();
    let typed = g.fake.head();
    *g.fake.image.lock().unwrap() = vec![run(&i(1), 3)];
    g.hold_anchored(&insert_at(DOC, 2, json!(["x"]), typed), between_one_and_two(), "moved", false);
    g.holds.probe("b-1");
    assert_eq!(row_sendable(&g), Some(true));
    let (fake, holds) = (Arc::clone(&g.fake), Arc::downgrade(&g.holds));
    *g.fake.at_send.lock().unwrap() = Some(Box::new(move || {
        let at = fake.next_at.fetch_add(1, Ordering::SeqCst);
        fake.move_arrangement(DOC, at);
        if let Some(holds) = holds.upgrade() {
            holds.advance(HAND_OVER_DEADLINE);
        }
    }));
    g.fake.move_arrangement(DOC, 77);
    assert_eq!(g.holds.resolve(&g.session, 1, ResolveAct::Send).unwrap(), Resolved::HandedBack);
    g.holds.probe("b-1");
    *g.fake.at_send.lock().unwrap() = None;
    assert_eq!((g.lines()[0]["cause"].as_str(), row_sendable(&g)), (Some("moved"), None), "held at its deadline, nothing tested since the send");
    g.holds.probe("b-1");
    assert_eq!(row_sendable(&g), Some(true), "the next probe tests it");
}

/// Checks that a moved document's shift test is a step of its turn.
///
/// It is §3c.5's bound on a drain's turn (skep #817, #867). More moved
/// documents than a turn takes steps: the first turn tests as many as it has
/// steps for and stops at its bound, the next tests the rest (the mutant
/// that spends no step reads the board for a whole queue of moved documents
/// while the work queued behind the turn waits).
#[test]
fn a_shift_test_is_a_step_of_its_turn() {
    let g = unclaimed_ground();
    let typed = g.fake.head();
    *g.fake.image.lock().unwrap() = edited_elsewhere();
    for n in 0..=TURN_STEPS {
        g.hold_anchored(&insert_at(&format!("1.0.1.0.{}", n + 1), 2, json!(["x"]), typed), between_one_and_two(), "moved", false);
    }
    assert_eq!((g.holds.probe("b-1"), image_reads(&g)), (Turn::Bounded, TURN_STEPS), "a turn's steps");
    assert_eq!((g.holds.probe("b-1"), image_reads(&g)), (Turn::Done, TURN_STEPS + 1), "the next turn tests the rest");
}

/// Checks that a cut pass announces nothing while the `/health` answers.
///
/// It is §4b.2's `daemon` event (P37).
///
/// Over the board's feed thread, every send of a held line times out while
/// the board answers its `/health`: each probe's pass ends at the send, and
/// the verdict after it finds the board answering — the line's own failure —
/// so no `daemon` event goes out, the commit stream's failure beside them
/// announcing nothing either (the mutant that announces a request's failure
/// flickers "unreachable" over a board that answers).
#[test]
fn a_pass_the_boards_silence_cut_announces_nothing_while_its_health_answers() {
    let g = ground();
    g.hold(&insert(DOC, json!(["a"]), g.fake.head()), "unreachable", false);
    g.fake.op_lost.every(Lost::Timeout);
    let threads = feed_threads(&g);
    let deadline = Instant::now() + Duration::from_secs(20);
    while g.fake.sends() < 2 && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(20));
    }
    threads.stop();
    assert!(g.fake.sends() >= 2, "two probes sent the line");
    let daemon: Vec<Value> = g.rx.try_iter().filter(|e| e.name == EventName::Daemon).map(|e| e.data).collect();
    assert!(daemon.is_empty(), "no `daemon` event: {daemon:?}");
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
/// `unreachable`, then a `durability` reissued. The shell's window says "it is
/// sent again" three times: at the first lost answer — the timeout, said as the
/// next probe finds the board answering (skep #863) — at the first
/// `write_busy` and at the `durability`, each a change of the failure; the
/// probes failing alike say nothing more (the mutant that says it at every
/// probe fills the log with seven).
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
    let again: Vec<&String> = said.iter().filter(|l| l.starts_with(&line) && (l.ends_with("it is sent again at the next probe") || l.ends_with("it is sent again as the board answers"))).collect();
    assert_eq!(again.len(), 3, "once per change: {said:?}");
    assert!(again[0].contains("unreachable") && again[1].contains("write_busy") && again[2].contains("durability"), "{again:?}");
}

/// Checks that a resend marks its line `sent` on disk before it dials.
///
/// The mark is written ahead of the dial, synced (§3c.2's `sent`), the
/// line's dial id named in the same copy (skep #971): the held file read as
/// the resend's dial leaves holds the line re-marked `sent: true`, naming the
/// id the dial goes out under, so a crash at the dial leaves a line that may
/// have landed read as one, and the id its next resend dials under; a line
/// marked so already writes that one copy for its id, and a line carrying
/// both is written no line more at its next resend. A resend whose attest
/// cannot be composed — over a head record that cannot be read — dials
/// nothing and marks nothing, the line `sent: false` still (the mutants that
/// mark the line after its answer, or never; the one that marks it before
/// the attest reads a write that never left as one that may have landed; the
/// one that names the id in a copy of its own syncs twice before a dial).
#[test]
fn a_resend_marks_its_line_sent_on_disk_before_it_dials() {
    for sent in [false, true] {
        let g = ground();
        g.hold(&insert(DOC, json!(["hello"]), g.fake.head()), "unreachable", sent);
        let (file, at_the_dial) = (held_file(&g), Arc::new(Mutex::new(Vec::new())));
        let seen = Arc::clone(&at_the_dial);
        *g.fake.at_send.lock().unwrap() = Some(Box::new(move || seen.lock().unwrap().push(std::fs::read_to_string(&file).unwrap_or_default())));
        g.fake.op_rejected.next(1, retry("durability"));
        g.holds.probe("b-1");
        g.holds.probe("b-1");
        let files: Vec<String> = at_the_dial.lock().unwrap().clone();
        let [text, again] = &files[..] else { panic!("sent {sent}: two dials: {files:?}") };
        let marks: Vec<Value> = text.lines().skip(1).map(|line| serde_json::from_str::<Value>(line).unwrap()).filter(|line| line["held"] == 1).collect();
        let dialed = g.fake.sends.lock().unwrap()[0]["id"].clone();
        let last = marks.last().unwrap_or_else(|| panic!("sent {sent}: {text}"));
        assert_eq!((&last["sent"], &last["dial"]), (&json!(true), &dialed), "sent {sent}: the line is marked, naming the id its dial goes out under, before the dial: {text}");
        assert_eq!(marks.len(), 2, "sent {sent}: the mark and the id in one copy beside the hold's: {text}");
        assert_eq!(again, text, "sent {sent}: a line carrying both is written no line more");
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
/// acknowledged named no more and the face not named `again`, the line
/// standing at its raised base under the newest verdict (the mutant that
/// reads the hands since the typed state at every face names the
/// acknowledged hand again beside the new one, and the person meets the face
/// they sent past; the one that marks every face after a `send` `again` says
/// a new change is the old one).
#[test]
fn a_document_moved_again_after_the_persons_send_names_only_the_hands_since() {
    let g = ground();
    let typed = g.fake.head();
    let row = |at: u64, key: String| json!({"at": at, "op": "insert", "key": key, "docs": [DOC]});
    *g.fake.rows.lock().unwrap() = vec![row(77, "ff".repeat(32))];
    let faces = || -> Vec<(Value, Option<Value>)> {
        let moved: Vec<Value> = g.rx.try_iter().filter(|e| e.name == EventName::Held && e.data["state"] == "moved").map(|e| e.data).collect();
        moved.iter().for_each(assert_held_event_declared);
        moved.iter().map(|d| (d["hands"].clone(), d.get("again").cloned())).collect()
    };
    g.fake.op_rejected.next(1, arrangement_moved(typed, 77));
    let OpAnswer::Answered(Ok(held)) = g.holds.send_burst(&g.session, insert(DOC, json!(["x"]), typed), None) else { panic!("held, not faced") };
    let k = held["held"].as_u64().unwrap();
    assert_eq!((held["cause"].as_str(), faces()), (Some("moved"), vec![(json!([{"key": "other", "fingerprint": "ff".repeat(32)}]), None)]), "the first face names the writer who moved it: {held}");
    assert_eq!(g.holds.resolve(&g.session, k, ResolveAct::Send).unwrap(), Resolved::HandedBack);
    assert_eq!(g.lines()[0]["base"], 77, "the base raised to the verdict's `site.current`");
    g.fake.rows.lock().unwrap().push(row(78, "ee".repeat(32)));
    g.fake.op_rejected.next(1, arrangement_moved(typed, 78));
    g.holds.probe("b-1");
    assert_eq!(faces(), [(json!([{"key": "other", "fingerprint": "ee".repeat(32)}]), None)], "moved again: the hand since the person's send alone, not named again");
    let lines = g.lines();
    assert_eq!((lines[0]["cause"].as_str(), lines[0]["base"].as_u64(), &lines[0]["refusal"]), (Some("moved"), Some(77), &arrangement_moved(typed, 78)), "{lines:?}");
    assert!(lines[0].get("again").is_none(), "the row not named again: {lines:?}");
}

/// The hand of the other key whose change at 77 moves [`moved_and_sent`]'s
/// document.
fn hand_ff() -> Value {
    json!([{"key": "other", "fingerprint": "ff".repeat(32)}])
}

/// Returns the `held` events said `moved` since the last look, each held to
/// its declaration.
fn moved_faces(g: &Ground) -> Vec<Value> {
    let said: Vec<Value> = g.rx.try_iter().filter(|e| e.name == EventName::Held).map(|e| e.data).collect();
    said.iter().for_each(assert_held_event_declared);
    said.into_iter().filter(|e| e["state"] == "moved").collect()
}

/// Returns a writer's ground whose moved document the person has sent.
///
/// Three lines typed against the document at 70 stand on it; the board
/// refused the first's resend as typed against an older state, another key's
/// change at 77 having moved it, and the face named that hand
/// ([`hand_ff`]); the person's `send` then handed the document back. It
/// answers the ground and the lines' ordinals.
fn moved_and_sent() -> (Ground, Vec<u64>) {
    let g = writer_at(80);
    g.fake.next_at.store(81, Ordering::SeqCst);
    *g.fake.rows.lock().unwrap() = vec![json!({"at": 77, "op": "insert", "key": "ff".repeat(32), "docs": [DOC]})];
    let ks: Vec<u64> = ["a", "b", "c"].iter().map(|v| g.hold(&insert(DOC, json!([v]), 70), "unreachable", false)["held"].as_u64().unwrap()).collect();
    g.fake.op_rejected.next(1, arrangement_moved(70, 77));
    g.holds.probe("b-1");
    let faced = moved_faces(&g);
    let [face] = &faced[..] else { panic!("premise: the document faced moved once: {faced:?}") };
    assert_eq!((&face["hands"], face.get("again")), (&hand_ff(), None), "premise: the face names the change at 77: {face}");
    assert_eq!(g.holds.resolve(&g.session, ks[0], ResolveAct::Send).unwrap(), Resolved::HandedBack);
    (g, ks)
}

/// Checks that a burst refused again with no change since the person's
/// `send` names again the hands named before, marked `again` (§3c.4, §3c.5;
/// skep #989).
///
/// The person sent the moved document back ([`moved_and_sent`]), and the
/// board refuses the resend as typed against an older state again, for the
/// same change, no row having landed since: the face says `moved` with the
/// hand of the change the person acknowledged, `again`, true, beside it;
/// every moved row lists that hand with `again`; and a drop of the last line
/// says the document `moved` with them, `again` still (the mutant that reads
/// the hands since the person's `send` alone says no one moved words the
/// board refused for an old change; the one that drops `again` from the
/// memory's repeat says a drop's face as a first one).
#[test]
fn a_send_refused_again_with_no_change_since_names_again_the_hands_named_before() {
    let (g, ks) = moved_and_sent();
    g.fake.op_rejected.next(1, arrangement_moved(70, 77));
    let reads = g.fake.changes_reads.load(Ordering::SeqCst);
    g.holds.probe("b-1");
    let faced = moved_faces(&g);
    let [face] = &faced[..] else { panic!("the document faced moved once: {faced:?}") };
    assert_eq!((face["held"].as_u64(), &face["hands"], &face["again"]), (Some(3), &hand_ff(), &json!(true)), "{face}");
    assert_eq!(g.fake.changes_reads.load(Ordering::SeqCst), reads + 3, "the landing's read, then the hands since the send, then the hands from the acknowledged face");
    let rows = g.lines();
    assert!(rows.iter().all(|row| row["cause"] == "moved" && row["hands"] == hand_ff() && row["again"] == true), "every moved row names them again: {rows:?}");
    assert_eq!(g.fake.changes_reads.load(Ordering::SeqCst), reads + 3, "the list reads nothing: the session was told");
    assert_eq!(g.holds.resolve(&g.session, ks[2], ResolveAct::Drop).unwrap(), Resolved::dropped(&[]));
    let faced = moved_faces(&g);
    let [face] = &faced[..] else { panic!("the drop says the document moved: {faced:?}") };
    assert_eq!((face["held"].as_u64(), &face["hands"], &face["again"]), (Some(2), &hand_ff(), &json!(true)), "{face}");
}

/// Checks that a second `send` refused again with no change since still names
/// the hands of the change the person first acknowledged (§3c.4; skep #989).
///
/// The person sent the moved document back ([`moved_and_sent`]), the board
/// refused it again for the same change and the face named that change's hand
/// `again`; the person sends again, and the board refuses it again, no row
/// having landed since: the face names that hand `again` still (the mutant
/// that takes the later of the acknowledged position and the typed state as
/// where the acknowledged face read from, at every `send`, reads past the
/// change at the second and names no one).
#[test]
fn a_second_send_refused_again_with_no_change_since_still_names_the_hands_named_before() {
    let (g, ks) = moved_and_sent();
    g.fake.op_rejected.next(1, arrangement_moved(70, 77));
    g.holds.probe("b-1");
    let faced = moved_faces(&g);
    assert_eq!(faced.iter().map(|face| (&face["hands"], &face["again"])).collect::<Vec<_>>(), [(&hand_ff(), &json!(true))], "premise: refused again: {faced:?}");
    assert_eq!(g.holds.resolve(&g.session, ks[0], ResolveAct::Send).unwrap(), Resolved::HandedBack);
    g.fake.op_rejected.next(1, arrangement_moved(70, 77));
    g.holds.probe("b-1");
    let faced = moved_faces(&g);
    let [face] = &faced[..] else { panic!("the document faced moved once more: {faced:?}") };
    assert_eq!((&face["hands"], &face["again"]), (&hand_ff(), &json!(true)), "{face}");
}

/// Checks that a `send` refused again after a later change names that
/// change's hands again, never the one an earlier `send` acknowledged
/// (§3c.4; skep #757, #989).
///
/// The person sent the moved document back ([`moved_and_sent`]); a third
/// hand's change lands at 80, and the board refuses the resend as typed
/// against an older state, the face naming that hand alone, not `again`. The
/// person sends again, and the board refuses it again, no row having landed
/// since: the face names the change at 80 alone, `again` (the mutant that
/// keeps the first acknowledged face's position at every `send` names the
/// change the person acknowledged first beside it).
#[test]
fn a_send_refused_again_after_a_later_change_names_that_changes_hands_again() {
    let (g, ks) = moved_and_sent();
    let ee = json!([{"key": "other", "fingerprint": "ee".repeat(32)}]);
    g.fake.rows.lock().unwrap().push(json!({"at": 80, "op": "insert", "key": "ee".repeat(32), "docs": [DOC]}));
    g.fake.op_rejected.next(1, arrangement_moved(70, 80));
    g.holds.probe("b-1");
    let faced = moved_faces(&g);
    assert_eq!(faced.iter().map(|face| (&face["hands"], face.get("again"))).collect::<Vec<_>>(), [(&ee, None)], "premise: moved again by the change at 80: {faced:?}");
    assert_eq!(g.holds.resolve(&g.session, ks[0], ResolveAct::Send).unwrap(), Resolved::HandedBack);
    g.fake.op_rejected.next(1, arrangement_moved(70, 80));
    g.holds.probe("b-1");
    let faced = moved_faces(&g);
    let [face] = &faced[..] else { panic!("the document faced moved once more: {faced:?}") };
    assert_eq!((&face["hands"], &face["again"]), (&ee, &json!(true)), "{face}");
}

/// Checks that a line leaving the queue takes the person's acknowledgment of
/// its document with it (skep #757).
///
/// A line typed against the document at 70, refused at a resend as typed
/// against an older state — two other writers' changes at 75 and 77 having
/// moved it — is held moved naming both hands; the person's `send`
/// acknowledges them, and the resend is acked and kept, the queue emptied,
/// its ordinals running on. A later burst typed at 70 too — an agent's,
/// from its last read — takes the next ordinal, never the old line's (skep
/// #856), and the board refuses its resend as typed against an older state:
/// its first moved face names both hands again, the acknowledgment having
/// gone with the line it was the person's act on (the mutant that keys the
/// acknowledgment by document reads the new line's hands since the old
/// line's acknowledgment, and its first face names none).
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
    let later = g.hold(&insert(DOC, json!(["b"]), 70), "unreachable", false)["held"].as_u64().unwrap();
    assert_eq!(later, k + 1, "the emptied queue's ordinals run on: the later line takes the next, never the old line's");
    g.fake.op_rejected.next(1, arrangement_moved(70, 100));
    g.holds.probe("b-1");
    assert_eq!((g.lines()[0]["cause"].as_str(), face()), (Some("moved"), Some(both)), "the later line's first face names every hand since its typed state");
}

/// Checks that an anchored resend after the person's `send` is shifted, kept.
///
/// It is §3c.4's raise (skep #757).
///
/// A held delete of `b` and `c` — `Wabc` as the page read it, its `before`
/// anchor `a`, no `after`, its span the I-run of `b` and `c` — its first
/// dial's answer lost, `sent`. At the next probe its read finds no landing,
/// and as the resend reaches the board the person's own other delete, of
/// `W` — made not through this shell, the `skep` command's — lands and moves
/// the document: the resend is refused as typed against an older state, the
/// shift's image read is refused, and the document is held moved, the
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
    g.fake.image_refused.store(true, Ordering::SeqCst);
    g.holds.probe("b-1");
    let lines = g.lines();
    let current = lines[0]["refusal"]["site"]["current"].as_u64().expect("the verdict's position");
    assert!(current > typed, "{lines:?}");
    assert_eq!(
        (g.fake.sends(), lines[0]["cause"].as_str(), lines[0]["sent"].as_bool(), lines[0]["base"].as_u64()),
        (1, Some("moved"), Some(true), Some(0)),
        "refused stale, its image read refused: held moved: {lines:?}"
    );
    let moved = g.rx.try_iter().filter(|e| e.name == EventName::Held).map(|e| e.data).find(|d| d["state"] == "moved").expect("the document faced moved");
    assert_eq!(moved["hands"], json!([{"key": "own", "fingerprint": g.own_key()}]), "the person's own other delete: {moved}");
    *g.fake.at_send.lock().unwrap() = None;
    g.fake.image_refused.store(false, Ordering::SeqCst);
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
    assert!(joined.len() == 1 && joined[0].contains("3 held lines joined") && !joined[0].contains("renumbered"), "{joined:?}");
}

/// Checks that an earlier run's line read at the join walks after this run's.
///
/// The earlier run's held file, first read at the join, holds an ordinal this
/// run has answered: it takes fresh ordinals past this run's and walks after
/// them (skep #856; the owner's ruling of 2026-11-06).
///
/// An earlier run left a line in the board's own file under ordinal 1; this
/// run, the head unreadable at its first touch — the board's file not nameable
/// then — holds two lines on the pending file under ordinals 1 and 2, which the
/// page holds. At the head's first read the board's file is read for the first
/// time: its line stands under an ordinal this run's lines hold, so it is
/// renumbered past them, 3, by one copy — its `done` and its `held` under the
/// fresh ordinal — and this run's lines enter under 1 and 2 as answered; the
/// join is said once, naming the line renumbered past them; no `held` event is
/// re-said for the join; the pending file is gone — the board too busy for the
/// dial meanwhile, an answer, so the pass walks every line. The walk then sends
/// this run's lines first and the earlier run's after them, in `k` order (the
/// mutant that renumbers this run's lines behind the earlier one re-targets the
/// ordinals the page holds; the one that keeps the earlier line's ordinal
/// re-marks it with this run's line and loses it; the one that re-says `held`
/// tells the page to re-read ordinals that never moved).
#[test]
fn an_earlier_runs_file_first_read_at_the_join_takes_fresh_ordinals_past_this_runs_and_walks_after_them() {
    let store = TempDir::new().unwrap();
    let dir = HeldDir::new(store.path(), Chain::parse(&"ab".repeat(32)).unwrap());
    dir.ensure().unwrap();
    let Opened::Live { mut queue, .. } = dir.open_file(1, "1.0.1").unwrap() else { panic!("a fresh file") };
    assert!(queue.hold_next(DOC, None, 0, insert(DOC, json!(["earlier"]), 0), None, Reason::of("unreachable", false)).unwrap().unwritten.is_none());
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
    assert_eq!(ks(&g), [(1, OTHER.to_string()), (2, OTHER.to_string())], "the pending file's ordinals, the page's");
    let _ = g.states();
    // The head reads, the board too busy for the dial — an answer, so the
    // pass walks every line, and the lines stand to be read.
    g.fake.head_garbled.store(false, Ordering::SeqCst);
    g.fake.op_refused.every((503, json!({"error": "write_busy"})));
    g.holds.probe("b-1");
    assert_eq!(ks(&g), [(1, OTHER.to_string()), (2, OTHER.to_string()), (3, DOC.to_string())], "this run's ordinals kept, the earlier run's line renumbered past them");
    let events: Vec<(String, String, u64)> = g.rx.try_iter().filter(|e| e.name == EventName::Held).map(|e| (e.data["doc"].as_str().unwrap().to_string(), e.data["state"].as_str().unwrap().to_string(), e.data["held"].as_u64().unwrap())).collect();
    assert_eq!(events.first(), Some(&(OTHER.to_string(), "sending".to_string(), 2)), "the first `held` event is the walk's, none re-said for the join: {events:?}");
    assert!(!pending_file(&g).exists(), "the pending file is gone");
    let joined = said_containing(&g, "joined the board's held file");
    assert!(joined.len() == 1 && joined[0].contains("2 held lines joined") && joined[0].contains("the 1 line an earlier run left in it is renumbered past this run's ordinals"), "{joined:?}");
    let on_disk = file_lines(&std::fs::read_to_string(held_file(&g)).unwrap());
    let disk_ks: Vec<u64> = on_disk.iter().map(|l| l["held"].as_u64().unwrap()).collect();
    assert_eq!(&disk_ks[..4], [1, 3, 1, 2], "the earlier line, its copy under 3, then this run's two, the copy after every line the file held: {disk_ks:?}");
    // The board takes writes: this run's lines go first, the earlier run's
    // after.
    g.fake.op_refused.clear();
    g.fake.sends.lock().unwrap().clear();
    while g.holds.probe("b-1") == Turn::Bounded {}
    let sent: Vec<String> = g.fake.sends.lock().unwrap().iter().map(|f| f["values"][0].as_str().unwrap_or("?").to_string()).collect();
    assert_eq!(sent, ["x", "y", "earlier"], "this run's lines first, the earlier run's after them");
    assert!(g.lines().is_empty(), "every line kept");
}

/// Checks that a memory queue joined into a file holding an earlier run's
/// lines keeps every memory line's ordinal, and `resolve` on an ordinal
/// answered before the join acts on that same line after it (skep #856).
///
/// The board unclaimed at the session's open, two bursts are held in memory
/// — a refused run's head under ordinal 1 and a line behind it under 2 —
/// and the page holds 1 off its `held` answer; an earlier run's held file
/// stands under the board's chain, holding one line under ordinal 1 on
/// another document. The board is then claimed, away for the dial: the
/// probe's one head read establishes the directory, and the join enters the
/// memory lines under 1 and 2 as they were answered, the earlier run's line
/// renumbered past them to 3 — the one renumbering, of a line no one was
/// answered — and no `held` event is said for the join. `resolve(1, drop)`
/// then drops the run the page meant, 1 and 2, and the earlier run's line
/// stands alone under 3 (the mutant that renumbers the memory lines behind
/// the earlier one drops the earlier run's line in the page's run's place;
/// the one that re-says `held` for the join tells the page to re-read
/// ordinals that never moved).
#[test]
fn a_memory_queue_joined_behind_an_earlier_runs_line_keeps_its_ordinals_and_resolve_acts_on_the_same_line() {
    let store = TempDir::new().unwrap();
    let dir = HeldDir::new(store.path(), Chain::parse(&"ab".repeat(32)).unwrap());
    dir.ensure().unwrap();
    let Opened::Live { mut queue, .. } = dir.open_file(1, "1.0.1").unwrap() else { panic!("a fresh file") };
    assert!(queue.hold_next(OTHER, None, 0, insert(OTHER, json!(["earlier"]), 0), None, Reason::of("unreachable", false)).unwrap().unwritten.is_none());
    drop(queue);
    let fake = Fake::new();
    fake.no_head.store(true, Ordering::SeqCst);
    fake.unclaimed.store(true, Ordering::SeqCst);
    let facts = writer_facts(&store);
    let g = ground_over(fake, store, facts, 0);
    let verdict = json!({"resp": "rejected", "code": "out_of_bounds", "disposition": "permanent", "op": "insert"});
    let head = g.hold_for(&insert(DOC, json!(["x"]), g.fake.head()), Reason::refused("out_of_bounds", verdict)).unwrap();
    let behind = g.hold(&insert(DOC, json!(["y"]), g.fake.head()), "behind", false);
    assert_eq!((head["held"].as_u64(), behind["held"].as_u64()), (Some(1), Some(2)), "the page holds 1 and 2: {head} {behind}");
    let _ = g.states();
    g.fake.no_head.store(false, Ordering::SeqCst);
    g.fake.unclaimed.store(false, Ordering::SeqCst);
    g.fake.op_unreachable.store(true, Ordering::SeqCst);
    g.holds.probe("b-1");
    let listed = |g: &Ground| g.lines().iter().map(|l| (l["held"].as_u64().unwrap(), l["frame"]["values"][0].as_str().unwrap_or("?").to_string())).collect::<Vec<_>>();
    assert_eq!(listed(&g), [(1, "x".to_string()), (2, "y".to_string()), (3, "earlier".to_string())], "the memory lines keep their ordinals, the earlier run's line renumbered past them");
    let joined = said_containing(&g, "joined the board's held file");
    assert!(joined.len() == 1 && joined[0].contains("2 held lines joined") && joined[0].contains("the 1 line an earlier run left in it is renumbered past this run's ordinals"), "{joined:?}");
    let about_doc: Vec<Value> = g.rx.try_iter().filter(|e| e.name == EventName::Held && e.data["doc"] == DOC).map(|e| e.data).collect();
    assert!(about_doc.is_empty(), "no `held` event is said for the join of the page's lines: {about_doc:?}");
    assert_eq!(g.holds.resolve(&g.session, 1, ResolveAct::Drop).unwrap(), Resolved::dropped(&[]));
    assert_eq!(listed(&g), [(3, "earlier".to_string())], "the page's run dropped, the earlier run's line standing");
    let on_disk: Vec<u64> = file_lines(&std::fs::read_to_string(held_file(&g)).unwrap()).iter().map(|l| l["held"].as_u64().unwrap()).collect();
    assert_eq!(&on_disk[..4], [1, 3, 1, 2], "the file: the earlier run's line, its copy under 3, then this run's two: {on_disk:?}");
}

/// Checks that a renumbering the device refuses lands at a later probe.
///
/// It enters nothing and is said once (skep #856; `HeldQueue::renumber`). The
/// board unclaimed at the session's open, two bursts are held in memory under 1
/// and 2; an earlier run's held file stands under the board's chain, holding a
/// line under 1. The board claimed, the device refuses every copy: the probe's
/// join reads the file for the first time, finds its line under an ordinal
/// below the counter, one this run's lines hold, and its renumbering — the one
/// copy before any line enters — is refused, nothing entered: the memory lines
/// stand as they were, each answer carrying the refusal, the file's line under
/// 1 as it was, and the refusal said once. The device takes copies again: the
/// next probe renumbers the earlier line past this run's and enters this run's
/// lines under their own (the mutant that enters this run's lines past a
/// refused renumbering re-marks the earlier line with this run's and loses it;
/// the one that moves the counter at a refused renumbering skips ordinals).
#[test]
fn a_renumbering_the_device_refuses_enters_nothing_and_lands_at_a_later_probe() {
    let store = TempDir::new().unwrap();
    let dir = HeldDir::new(store.path(), Chain::parse(&"ab".repeat(32)).unwrap());
    dir.ensure().unwrap();
    let Opened::Live { mut queue, .. } = dir.open_file(1, "1.0.1").unwrap() else { panic!("a fresh file") };
    assert!(queue.hold_next(OTHER, None, 0, insert(OTHER, json!(["earlier"]), 0), None, Reason::of("unreachable", false)).unwrap().unwritten.is_none());
    drop(queue);
    let fake = Fake::new();
    fake.no_head.store(true, Ordering::SeqCst);
    fake.unclaimed.store(true, Ordering::SeqCst);
    let facts = writer_facts(&store);
    let g = ground_over(fake, store, facts, 0);
    for value in ["a", "b"] {
        g.hold(&insert(DOC, json!([value]), g.fake.head()), "unreachable", false);
    }
    g.fake.no_head.store(false, Ordering::SeqCst);
    g.fake.unclaimed.store(false, Ordering::SeqCst);
    g.fake.op_unreachable.store(true, Ordering::SeqCst);
    crate::held::tests::refuse_copies_after(0);
    g.holds.probe("b-1");
    let listed = |g: &Ground| g.lines().iter().map(|l| (l["held"].as_u64().unwrap(), l["frame"]["values"][0].as_str().unwrap_or("?").to_string())).collect::<Vec<_>>();
    assert_eq!(listed(&g), [(1, "a".to_string()), (2, "b".to_string())], "the memory lines stand as they were");
    let said = said_containing(&g, "could not be renumbered past this run's");
    assert_eq!(said.len(), 1, "the refusal said once: {said:?}");
    let on_disk = |g: &Ground| file_lines(&std::fs::read_to_string(held_file(g)).unwrap()).iter().map(|l| l["held"].as_u64().unwrap()).collect::<Vec<_>>();
    assert_eq!(on_disk(&g), [1], "the file's line as it was, nothing entered");
    let next = g.hold(&insert(DOC, json!(["c"]), g.fake.head()), "behind", false);
    assert!(next["unwritable"].as_str().is_some_and(|why| why.contains("sync was made to fail")), "each answer carries the refusal: {next}");
    g.holds.probe("b-1");
    assert_eq!(said_containing(&g, "could not be renumbered past this run's").len(), 1, "a second refused probe says nothing more");
    crate::held::tests::take_copies();
    g.holds.probe("b-1");
    assert_eq!(listed(&g), [(1, "a".to_string()), (2, "b".to_string()), (3, "c".to_string()), (4, "earlier".to_string())], "the earlier line renumbered past this run's, this run's entered under their own");
    assert_eq!(&on_disk(&g)[..5], [1, 4, 1, 2, 3], "the file: the earlier line, its copy under 4, then this run's three");
    let joined = said_containing(&g, "joined the board's held file");
    assert!(joined.len() == 1 && joined[0].contains("3 held lines joined") && joined[0].contains("the 1 line an earlier run left in it is renumbered past this run's ordinals"), "{joined:?}");
}

/// Leaves an earlier run's line in the board's own held file, unanswered.
///
/// It is `value`, on `OTHER`, under ordinal `k`, the file closed as a relaunch
/// finds it.
fn an_earlier_runs_line(store: &TempDir, k: u64, value: &str) {
    let dir = HeldDir::new(store.path(), Chain::parse(&"ab".repeat(32)).unwrap());
    dir.ensure().unwrap();
    let Opened::Live { mut queue, .. } = dir.open_file(1, "1.0.1").unwrap() else { panic!("a fresh file") };
    assert!(queue.hold(k, OTHER, None, 0, insert(OTHER, json!([value]), 0), None, Reason::of("unreachable", false)).unwrap().unwritten.is_none());
}

/// Returns `held(session)`'s lines, each as its ordinal and its first value.
fn ordinals(g: &Ground) -> Vec<(u64, String)> {
    g.lines().iter().map(|l| (l["held"].as_u64().unwrap(), l["frame"]["values"][0].as_str().unwrap_or("?").to_string())).collect()
}

/// Opens another session of the ground's principal, as a second tab does.
fn open_another_session(g: &Ground) {
    let open = Open { token: Token::parse(&"8e".repeat(16)).unwrap(), facts: g.session.facts.clone(), opened_at: 0 };
    let another = g.sessions.register(&g.entry, open, &mut NoSupplements);
    g.holds.open_session(&another);
}

/// Returns a refused run's verdict: the board's `out_of_bounds`.
fn out_of_bounds() -> Value {
    json!({"resp": "rejected", "code": "out_of_bounds", "disposition": "permanent", "op": "insert"})
}

/// Checks that an ordinal settled before the join names no earlier line.
///
/// An ordinal this run settled names no earlier run's line after the join, and
/// the earlier line walks after this run's (skep #875). The board unclaimed at
/// the session's open, a refused run's head is held in memory under ordinal 1
/// and dropped by the person, and a burst is held under 2; an earlier run's
/// held file stands under the board's chain, holding one line, on another
/// document, under 1. The board is then claimed, too busy for the dial — an
/// answer, so the pass walks every line: the probe's
/// join reads the board's file for the first time, finds its line under 1 —
/// below the counter, though no line of this run's stands there — and renumbers
/// it past this run's, to 3, the join said once naming the line renumbered;
/// `resolve(1, drop)` finds no line, the one it was answered for settled. The
/// board answers: the walk sends this run's line first and the earlier run's
/// after it (the mutant that renumbers only where a standing line holds the
/// ordinal keeps the earlier line under 1, so the page's act on the ordinal it
/// dropped reaches it, and walks it ahead of this run's line).
#[test]
fn an_ordinal_settled_before_the_join_names_no_earlier_runs_line_and_the_earlier_line_walks_after() {
    let store = TempDir::new().unwrap();
    an_earlier_runs_line(&store, 1, "earlier");
    let fake = Fake::new();
    fake.no_head.store(true, Ordering::SeqCst);
    fake.unclaimed.store(true, Ordering::SeqCst);
    let facts = writer_facts(&store);
    let g = ground_over(fake, store, facts, 0);
    let settled = g.hold_for(&insert(DOC, json!(["x"]), g.fake.head()), Reason::refused("out_of_bounds", out_of_bounds())).unwrap();
    assert_eq!(settled["held"], 1, "{settled}");
    assert_eq!(g.holds.resolve(&g.session, 1, ResolveAct::Drop).unwrap(), Resolved::dropped(&[]));
    let standing = g.hold(&insert(DOC, json!(["y"]), g.fake.head()), "unreachable", false);
    assert_eq!(standing["held"], 2, "the ordinals run on past the settled one: {standing}");
    g.fake.no_head.store(false, Ordering::SeqCst);
    g.fake.unclaimed.store(false, Ordering::SeqCst);
    g.fake.op_refused.every((503, json!({"error": "write_busy"})));
    g.holds.probe("b-1");
    assert_eq!(ordinals(&g), [(2, "y".to_string()), (3, "earlier".to_string())], "the earlier run's line renumbered past every ordinal this run gave out");
    assert_eq!(g.holds.resolve(&g.session, 1, ResolveAct::Drop).unwrap_err().name(), "no_such_held", "the settled ordinal names no line");
    let joined = said_containing(&g, "joined the board's held file");
    assert!(joined.len() == 1 && joined[0].contains("1 held line joined") && joined[0].contains("the 1 line an earlier run left in it is renumbered past this run's ordinals"), "{joined:?}");
    g.fake.op_refused.clear();
    g.fake.sends.lock().unwrap().clear();
    while g.holds.probe("b-1") == Turn::Bounded {}
    assert_eq!(sent_values(&g), ["y", "earlier"], "this run's line first, the earlier run's after it");
    assert!(g.lines().is_empty(), "every line kept");
}

/// Checks that an emptied pending queue joins a file renumbered past it.
///
/// A pending queue emptied before the head reads joins a board's file
/// renumbered past the ordinal it settled (skep #875). The head record damaged
/// at the session's open, a signed burst is held `head_unreadable` on the
/// pending file under ordinal 1, and the person drops it, so the pending file
/// compacts away; an earlier run's held file stands under the board's chain,
/// holding one line under 1. The head reads, and another session's open — no
/// probe drains with no line standing — joins the emptied pending queue into
/// the board's file, read for the first time: its line under 1, below the
/// counter, is renumbered past it, to 2, and `resolve(1, drop)` finds no line
/// (the mutant that renumbers only where a standing line holds the ordinal
/// keeps the earlier line under the ordinal the page dropped).
#[test]
fn a_pending_queue_emptied_before_the_head_reads_joins_a_file_renumbered_past_the_ordinal_it_settled() {
    let store = TempDir::new().unwrap();
    an_earlier_runs_line(&store, 1, "earlier");
    let fake = Fake::new();
    fake.head_garbled.store(true, Ordering::SeqCst);
    let facts = writer_facts(&store);
    let g = ground_over(fake, store, facts, 0);
    let OpAnswer::Answered(Ok(held)) = g.holds.send_burst(&g.session, insert(DOC, json!(["x"]), g.fake.head()), None) else { panic!("held") };
    assert_eq!((held["held"].as_u64(), held["cause"].as_str()), (Some(1), Some("head_unreadable")), "{held}");
    assert_eq!(g.holds.resolve(&g.session, 1, ResolveAct::Drop).unwrap(), Resolved::dropped(&[]));
    assert!(!pending_file(&g).exists(), "premise: the pending file compacted away");
    g.fake.head_garbled.store(false, Ordering::SeqCst);
    open_another_session(&g);
    assert_eq!(ordinals(&g), [(2, "earlier".to_string())], "the earlier run's line renumbered past the ordinal this run settled");
    assert_eq!(g.holds.resolve(&g.session, 1, ResolveAct::Drop).unwrap_err().name(), "no_such_held", "the settled ordinal names no line");
}

/// Checks that a pending file read at the first touch is this run's queue,
/// its line keeping its ordinal, and the board's file read at the change
/// is renumbered past the counter (skep #875).
///
/// An earlier run left a line in the board's file under ordinal 2 and one in
/// the pending file under 1. The board away at the session's open, the first
/// touch reads the pending file as the queue's own — its line standing under
/// 1, the counter past it — so a refused run's head is held under 2, and the
/// person drops it. The board returns, and another session's open makes the
/// pending → chain change: the board's file is read for the first time, its
/// line under 2 renumbered past the counter, to 3, and the pending file's
/// line moves under its own ordinal, 1 — answered by `held(session)` since
/// the first touch, so never re-targeted (I13) — walking before it;
/// `resolve(2, drop)` finds no line, and the pending file is removed (the
/// mutant that renumbers only where a standing line holds the ordinal keeps
/// the earlier line under 2, the ordinal the page dropped; the one that gives
/// the pending file's line a fresh ordinal re-targets one the page holds).
#[test]
fn a_pending_file_read_at_the_first_touch_keeps_its_ordinals_and_the_boards_file_is_renumbered_past_the_counter() {
    let store = TempDir::new().unwrap();
    an_earlier_runs_line(&store, 2, "earlier");
    let pending = HeldDir::pending(store.path(), &Origin::parse("http://127.0.0.1:1").unwrap());
    pending.ensure().unwrap();
    let Opened::Live { mut queue, .. } = pending.open_file(1, "1.0.1").unwrap() else { panic!("a fresh file") };
    assert!(queue.hold(1, DOC, None, 0, insert(DOC, json!(["pending"]), 0), None, Reason::of("head_unreadable", false)).unwrap().unwritten.is_none());
    drop(queue);
    let fake = Fake::new();
    fake.head_unreachable.store(true, Ordering::SeqCst);
    let facts = writer_facts(&store);
    let g = ground_over(fake, store, facts, 0);
    assert_eq!(ordinals(&g), [(1, "pending".to_string())], "premise: the pending file read at the first touch, its line under its own ordinal");
    let settled = g.hold_for(&insert(DOC, json!(["x"]), g.fake.head()), Reason::refused("out_of_bounds", out_of_bounds())).unwrap();
    assert_eq!(settled["held"], 2, "premise: past the pending file's 1: {settled}");
    assert_eq!(g.holds.resolve(&g.session, 2, ResolveAct::Drop).unwrap(), Resolved::dropped(&[]));
    g.fake.head_unreachable.store(false, Ordering::SeqCst);
    open_another_session(&g);
    assert_eq!(ordinals(&g), [(1, "pending".to_string()), (3, "earlier".to_string())], "the pending file's line keeps its ordinal; the board's file renumbered past the counter");
    assert_eq!(g.holds.resolve(&g.session, 2, ResolveAct::Drop).unwrap_err().name(), "no_such_held", "the settled ordinal names no line");
    let joined = said_containing(&g, "joined the board's held file");
    assert!(joined.len() == 1 && joined[0].contains("1 held line joined") && joined[0].contains("the 1 line an earlier run left in it is renumbered past this run's ordinals, and sent after this run's lines"), "{joined:?}");
    assert!(!pending_file(&g).exists(), "the pending file is removed once its line moved");
}

/// Checks that the door's later open renumbers past a settled ordinal.
///
/// The board's file the door opens at a later touch is renumbered past the
/// ordinal this run settled (skep #875). The board away at the session's open,
/// a refused run's head is held in memory under ordinal 1 and dropped by the
/// person; an earlier run's held file stands under the board's chain, holding
/// one line under 1. The board returns: another session's open establishes the
/// directory, and no join runs, no line standing anywhere, so the principal's
/// door opens the board's file at this later touch, the queue empty: its line
/// under 1, below the counter, is renumbered past it, to 2, before it is taken,
/// and `resolve(1, drop)` finds no line; a burst held after it takes 3 (the
/// mutant whose door takes the file as it reads keeps the earlier line under
/// the ordinal the page dropped).
#[test]
fn the_doors_later_open_renumbers_the_boards_file_past_the_ordinal_this_run_settled() {
    let store = TempDir::new().unwrap();
    an_earlier_runs_line(&store, 1, "earlier");
    let fake = Fake::new();
    fake.head_unreachable.store(true, Ordering::SeqCst);
    let facts = writer_facts(&store);
    let g = ground_over(fake, store, facts, 0);
    let settled = g.hold_for(&insert(DOC, json!(["x"]), g.fake.head()), Reason::refused("out_of_bounds", out_of_bounds())).unwrap();
    assert_eq!(settled["held"], 1, "{settled}");
    assert_eq!(g.holds.resolve(&g.session, 1, ResolveAct::Drop).unwrap(), Resolved::dropped(&[]));
    g.fake.head_unreachable.store(false, Ordering::SeqCst);
    open_another_session(&g);
    assert!(said_containing(&g, "joined the board's held file").is_empty(), "premise: no join ran: {:?}", g.said.lock().unwrap());
    assert_eq!(ordinals(&g), [(2, "earlier".to_string())], "the earlier run's line renumbered past the ordinal this run settled");
    assert_eq!(g.holds.resolve(&g.session, 1, ResolveAct::Drop).unwrap_err().name(), "no_such_held", "the settled ordinal names no line");
    let next = g.hold(&insert(DOC, json!(["y"]), g.fake.head()), "unreachable", false);
    assert_eq!(next["held"], 3, "the counter past the renumbered line: {next}");
    let on_disk: Vec<u64> = file_lines(&std::fs::read_to_string(held_file(&g)).unwrap()).iter().map(|l| l["held"].as_u64().unwrap()).collect();
    assert_eq!(on_disk, [1, 2, 3], "the file: the earlier line, its copy under 2, then the burst held after it");
}

/// Checks that a renumbering the door could not write lands later.
///
/// The renumbering the door's later open could not write keeps the file from
/// the queue, is said once, and lands at a later probe (skep #875). As the cell
/// above, the device refusing every copy as the board returns: the door's
/// renumbering of the board's file is refused, nothing taken — no line listed,
/// the refusal said once though every act retries the door — and a burst held
/// meanwhile stands in memory, its answer carrying the refusal and its class.
/// The device takes copies again: the next probe's join renumbers the earlier
/// line past this run's, to 3, and enters the burst under its own, 2 (the
/// mutant that takes the file past a refused renumbering lists the earlier line
/// under the ordinal the page dropped).
#[test]
fn a_renumbering_the_doors_later_open_could_not_write_is_said_once_and_lands_at_a_later_probe() {
    let store = TempDir::new().unwrap();
    an_earlier_runs_line(&store, 1, "earlier");
    let fake = Fake::new();
    fake.head_unreachable.store(true, Ordering::SeqCst);
    let facts = writer_facts(&store);
    let g = ground_over(fake, store, facts, 0);
    let settled = g.hold_for(&insert(DOC, json!(["x"]), g.fake.head()), Reason::refused("out_of_bounds", out_of_bounds())).unwrap();
    assert_eq!(settled["held"], 1, "{settled}");
    assert_eq!(g.holds.resolve(&g.session, 1, ResolveAct::Drop).unwrap(), Resolved::dropped(&[]));
    g.fake.head_unreachable.store(false, Ordering::SeqCst);
    crate::held::tests::refuse_copies_after(0);
    open_another_session(&g);
    assert!(ordinals(&g).is_empty(), "nothing taken past the refused renumbering");
    let next = g.hold(&insert(DOC, json!(["y"]), g.fake.head()), "unreachable", false);
    assert_eq!(next["held"], 2, "{next}");
    assert!(next["unwritable"].as_str().is_some_and(|why| why.contains("sync was made to fail")) && next["unwritable_class"] == "full", "held in memory, carrying the refusal: {next}");
    let said = said_containing(&g, "could not be renumbered past this run's");
    assert_eq!(said.len(), 1, "the refusal said once, every act retrying the door: {said:?}");
    let on_disk = |g: &Ground| file_lines(&std::fs::read_to_string(held_file(g)).unwrap()).iter().map(|l| l["held"].as_u64().unwrap()).collect::<Vec<_>>();
    assert_eq!(on_disk(&g), [1], "the file's line as it was");
    crate::held::tests::take_copies();
    g.fake.op_unreachable.store(true, Ordering::SeqCst);
    g.holds.probe("b-1");
    assert_eq!(ordinals(&g), [(2, "y".to_string()), (3, "earlier".to_string())], "the earlier line renumbered past this run's, the burst under its own");
    assert_eq!(&on_disk(&g)[..3], [1, 3, 2], "the file: the earlier line, its copy under 3, then the burst");
}

/// Checks that a file at or past the counter keeps its ordinals.
///
/// A file whose lines all stand at or past the counter keeps them at the
/// door's later open (skep #875; `PrincipalHold::renumbers`). The board away
/// at the session's open, a refused run's head is held under ordinal 1 and
/// dropped; an earlier run's line stands in the board's file under 2, the
/// counter's next. The board returns, and the door's later open finds no
/// ordinal this run gave out among the file's, its line walking after this
/// run's already: it takes the file as it reads, no renumbering written, and
/// the counter moves past it, a burst held after it taking 3 (the mutant
/// that renumbers every file read at a later touch writes a copy no ordinal
/// needs).
#[test]
fn a_file_whose_lines_stand_at_or_past_the_counter_keeps_its_ordinals() {
    let store = TempDir::new().unwrap();
    an_earlier_runs_line(&store, 2, "earlier");
    let fake = Fake::new();
    fake.head_unreachable.store(true, Ordering::SeqCst);
    let facts = writer_facts(&store);
    let g = ground_over(fake, store, facts, 0);
    let settled = g.hold_for(&insert(DOC, json!(["x"]), g.fake.head()), Reason::refused("out_of_bounds", out_of_bounds())).unwrap();
    assert_eq!(settled["held"], 1, "{settled}");
    assert_eq!(g.holds.resolve(&g.session, 1, ResolveAct::Drop).unwrap(), Resolved::dropped(&[]));
    g.fake.head_unreachable.store(false, Ordering::SeqCst);
    open_another_session(&g);
    assert_eq!(ordinals(&g), [(2, "earlier".to_string())], "the file's own ordinal kept");
    let next = g.hold(&insert(DOC, json!(["y"]), g.fake.head()), "unreachable", false);
    assert_eq!(next["held"], 3, "the counter past the file's line: {next}");
    let on_disk: Vec<u64> = file_lines(&std::fs::read_to_string(held_file(&g)).unwrap()).iter().map(|l| l["held"].as_u64().unwrap()).collect();
    assert_eq!(on_disk, [2, 3], "no renumbering written: {on_disk:?}");
}

/// Checks that the change's copy the device refuses parks the lines on the
/// pending file until it lands, the pending lock kept (§3c.1, §3c.3; skep
/// #859, #873).
///
/// A burst held while the board's head record stood damaged is on the
/// pending file. The record reads while the board's own directory stands
/// sealed against new files, its lock file standing: the probe takes the
/// board's own lock and the change opens the board's file, but the copy is
/// refused at the file's create — the line stays on the pending file,
/// PARKED: owed to the board's file and sent by no walk, since a send would
/// leave the pending file reading it as never sent (I5); the wait is said
/// once, a second probe saying nothing more and sending nothing, the pending
/// directory under this shell's lock. The directory opened, the next probe
/// writes the copy, removes the pending file, and sends the line — refused
/// `write_busy`, so it stands — both locks this shell's for its life (the
/// mutant that sends a parked line lets a relaunch send it twice; the one
/// that lets the pending lock go leaves another shell free to take it; the
/// one that never retries the copy leaves the line on a file no relaunch at
/// the chain reads).
#[cfg(unix)]
#[test]
fn the_changes_copy_the_device_refuses_parks_the_lines_on_the_pending_file_until_it_lands() {
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
    let own = HeldDir::new(g.store.path(), Chain::parse(&"ab".repeat(32)).unwrap());
    assert!(!g.holds.another_window("b-1") && own.try_lock().unwrap().is_none(), "the board's own lock is taken");
    assert!(!held_file(&g).exists(), "the copy is refused at the board's file's create");
    let said = said_containing(&g, "could not be copied to its held file");
    assert!(said.len() == 1 && said[0].contains(&refused), "the wait said once: {said:?}");
    let rows = g.lines();
    assert_eq!((g.fake.sends(), rows.len(), rows[0].get("unwritable")), (0, 1, None), "the line stands, parked: sent by no walk while its copy is owed, and listed with no refusal, its copy on the pending file");
    assert_eq!(g.holds.copies_owed("b-1", 1), CopiesOwed::default(), "a close keeps a parked line: nothing is counted");
    assert!(std::fs::read_to_string(&pending).unwrap().contains("\"values\":[\"a\"]"), "on the pending file");
    let pending_store = HeldDir::pending(g.store.path(), g.session.board.dialed());
    assert!(pending_store.try_lock().unwrap().is_none(), "the pending directory stays under this shell's lock");
    g.holds.probe("b-1");
    assert_eq!((said_containing(&g, "could not be copied").len(), g.fake.sends()), (1, 0), "a second refused probe says nothing more, and sends nothing");
    unseal(&sealed);
    g.holds.probe("b-1");
    assert!(std::fs::read_to_string(held_file(&g)).unwrap().contains("\"values\":[\"a\"]"), "the line's copy landed in the board's file");
    assert!(!pending.exists(), "the pending file is removed once nothing is owed");
    assert_eq!((g.fake.sends(), g.lines().len()), (1, 1), "the line sent once its copy landed, and refused, still standing");
    assert!(pending_store.try_lock().unwrap().is_none() && own.try_lock().unwrap().is_none(), "both locks kept for the shell's life");
    assert_eq!(said_containing(&g, "wait in memory no more").len(), 1, "the wait's end said once: {:?}", g.said.lock().unwrap());
}

/// Checks that a `done` the pending file owed is counted across the change.
///
/// It is the owed `done` the stop must count (§3c.3; skep #860). The board
/// unclaimed, a line resent and acked with its `done` refused by the device
/// beside a line awaiting `resolve`; the board then names a chain, and the
/// change's copies are refused too. The settled line is off `held(session)`,
/// the pending file holds it standing and `copies_owed` counts it; the device
/// taking copies again, the copies land, the pending file goes and nothing is
/// counted (the mutant that lets the replaced queue's `done`s go with it says
/// nothing of a line that returns from the pending file).
#[test]
fn a_done_the_pending_file_owed_is_counted_across_the_change() {
    let fake = Fake::new();
    fake.no_head.store(true, Ordering::SeqCst);
    fake.unclaimed.store(true, Ordering::SeqCst);
    let store = TempDir::new().unwrap();
    let facts = writer_facts(&store);
    let g = ground_over(fake, store, facts, 0);
    let verdict = json!({"resp": "rejected", "code": "out_of_bounds", "disposition": "permanent", "op": "insert"});
    g.hold_for(&insert(OTHER, json!(["r"]), g.fake.head()), Reason::refused("out_of_bounds", verdict)).unwrap();
    g.hold(&insert(DOC, json!(["a"]), g.fake.head()), "unreachable", false);
    crate::held::tests::refuse_copies_as(std::io::ErrorKind::StorageFull);
    g.holds.probe("b-1");
    assert_eq!(g.fake.sends(), 1, "premise: the line is sent, and acked");
    g.fake.no_head.store(false, Ordering::SeqCst);
    g.fake.unclaimed.store(false, Ordering::SeqCst);
    g.holds.probe("b-1");
    crate::held::tests::take_copies();
    let rows = g.lines();
    assert_eq!((rows.len(), rows[0]["doc"].as_str(), rows[0].get("unwritable")), (1, Some(OTHER), None), "the settled line is off the rows, the other parked: {rows:?}");
    assert!(std::fs::read_to_string(pending_file(&g)).unwrap().contains("\"values\":[\"a\"]"), "premise: the pending file still lists the settled line");
    assert_eq!(g.holds.copies_owed("b-1", 1), CopiesOwed { lines: 0, kept: 1, dropped: 0 }, "the `done` the pending file never wrote is counted");
    g.holds.probe("b-1");
    assert!(!pending_file(&g).exists(), "premise: the pending file goes once nothing is owed");
    assert_eq!(g.holds.copies_owed("b-1", 1), CopiesOwed::default(), "and nothing is counted");
}

/// Checks that the change's copy the device refuses, its cut-back refused
/// too, leaves nothing a relaunch reads twice (§3c.3; skep #817, #821,
/// #859).
///
/// The board's file holds a line an earlier run left — under ordinal 9,
/// past any this run holds, so nothing is renumbered — and the board is
/// away at the session's open, so two bursts are held on the pending file.
/// The board returns: the change's one copy into the board's file is
/// refused, and so is its cut-back, the copy's two lines left standing past
/// the file's whole lines — and cut by the fallback's first try, refused in
/// its turn. Both lines are parked on the pending file, sent by no walk; the
/// earlier run's line, on the board's file, is sent and kept, its `done`
/// owed; the wait is said once. The device takes copies again: the next
/// probe writes the copies owed — the `done`, the two lines — removes the
/// pending file and sends the two lines, so each burst is dialed once, and
/// both files compact away; a relaunch over the store reads no line (the
/// mutant that reads the refused copy's bytes back as held lines sends the
/// person's text a second time; the one that sends a parked line relaunches
/// it as never sent; the one whose retry never cuts the copy's bytes writes
/// the lines after them, read as re-marks of lines never held).
#[test]
fn the_changes_copy_refused_with_its_cut_back_leaves_nothing_a_relaunch_reads_twice() {
    let store = TempDir::new().unwrap();
    an_earlier_runs_line(&store, 9, "earlier");
    let fake = Fake::new();
    fake.head_unreachable.store(true, Ordering::SeqCst);
    let facts = writer_facts(&store);
    let g = ground_over(fake, store, facts, 0);
    for value in ["a", "b"] {
        let answer = g.hold(&insert(DOC, json!([value]), g.fake.head()), "unreachable", false);
        assert!(answer.get("unwritable").is_none(), "held on the pending file, the board away: {answer}");
    }
    let pending = pending_file(&g);
    g.fake.head_unreachable.store(false, Ordering::SeqCst);
    crate::held::tests::refuse_copies_after(0);
    crate::held::tests::refuse_the_next_cut_back();
    g.holds.probe("b-1");
    crate::held::tests::take_copies();
    assert_eq!(sent_values(&g), ["earlier"], "the earlier run's line, on the board's file, is sent; the two parked lines are not");
    assert_eq!(ordinals(&g), [(1, "a".to_string()), (2, "b".to_string())], "the two lines stand, parked, the earlier run's kept");
    let on_disk = file_lines(&std::fs::read_to_string(held_file(&g)).unwrap());
    assert!(on_disk.iter().all(|line| line["frame"]["values"] != json!(["a"]) && line["frame"]["values"] != json!(["b"])), "nothing of the refused copy stands in the board's file: {on_disk:?}");
    let text = std::fs::read_to_string(&pending).unwrap();
    assert!(text.contains("\"values\":[\"a\"]") && text.contains("\"values\":[\"b\"]"), "both still on the pending file");
    assert_eq!(said_containing(&g, "could not be copied to its held file").len(), 1, "the wait said once: {:?}", g.said.lock().unwrap());
    g.holds.probe("b-1");
    assert_eq!(sent_values(&g), ["earlier", "a", "b"], "each burst dialed once");
    assert!(g.lines().is_empty() && !held_file(&g).exists() && !pending.exists(), "every line kept, both files gone");
    // A relaunch over the store reads no line.
    let Ground { holds, fake, session, store, .. } = g;
    drop(holds);
    let g = ground_over(fake, store, session.facts.clone(), 0);
    assert!(g.lines().is_empty(), "a relaunch reads no line: {:?}", g.lines());
}

/// Checks that a board away or unclaimed at the first touch has its lines
/// on the pending file before `op` answers `held`, and a relaunch lists
/// them (§3c.1, §3c.3; skep #857; persist-first, SP-1).
///
/// The board away at the session's open — or unclaimed, serving no head
/// record — the first touch makes and locks the pending directory, and a
/// burst's line is in the pending file at the sync that precedes its
/// answer, the answer carrying no `unwritable`; a relaunch over the store,
/// the board still so, lists the line from the pending file (the mutant
/// that keeps a board-away line in memory answers `held` for a line a close
/// loses, and the relaunch lists nothing).
#[test]
fn a_board_away_or_unclaimed_at_the_first_touch_holds_on_the_pending_file_before_it_answers() {
    for (cell, away) in [("the board away", true), ("the board unclaimed", false)] {
        let fake = Fake::new();
        if away {
            fake.head_unreachable.store(true, Ordering::SeqCst);
        } else {
            fake.no_head.store(true, Ordering::SeqCst);
            fake.unclaimed.store(true, Ordering::SeqCst);
        }
        let store = TempDir::new().unwrap();
        let facts = writer_facts(&store);
        let g = ground_over(fake, store, facts, 0);
        let pending_store = HeldDir::pending(g.store.path(), g.session.board.dialed());
        assert!(pending_store.try_lock().unwrap().is_none(), "{cell}: the pending directory is made and locked at the first touch");
        let pending = pending_file(&g);
        let at_sync = Arc::new(Mutex::new(Vec::new()));
        let seen = Arc::clone(&at_sync);
        let path = pending.clone();
        crate::held::tests::on_sync(move |_| seen.lock().unwrap().push(std::fs::read_to_string(&path).unwrap_or_default()));
        let answer = g.hold(&insert(DOC, json!(["a"]), g.fake.head()), "unreachable", false);
        crate::held::tests::take_copies();
        assert!(answer.get("unwritable").is_none(), "{cell}: on disk: {answer}");
        assert!(at_sync.lock().unwrap().iter().any(|text| text.contains("\"values\":[\"a\"]")), "{cell}: the line was in the pending file at its sync, before the answer: {:?}", at_sync.lock().unwrap());
        // A relaunch over the store lists it.
        let Ground { holds, fake, session, store, .. } = g;
        drop(holds);
        let g = ground_over(fake, store, session.facts.clone(), 0);
        let listed: Vec<Value> = g.lines().iter().map(|line| line["frame"]["values"].clone()).collect();
        assert_eq!(listed, [json!(["a"])], "{cell}: a relaunch lists the line from the pending file");
    }
}

/// Checks that the board's file found halted at the pending → chain change
/// halts the principal from that moment, and a relaunch lists every line
/// once the file is moved aside (§3c.3; skep #858; beside `I8`).
///
/// The board away at the session's open, two bursts are held on the pending
/// file; an earlier run's held file stands under the board's chain, written
/// by a newer skep. The board returns: the change opens the board's file,
/// finds it halted, and the principal halts — nothing sent from then, the
/// halt said once and answered `store_halted` at the door, the pending file
/// intact with both lines, the halted file never rebuilt over; a later probe
/// sends nothing and says nothing more. The person moves the halted file
/// aside, as the halt asks, and relaunches: the first touch reads the
/// pending file beside a fresh board's file, and every line is listed (the
/// mutant that keeps sending past a halt lands text behind what the newer
/// file holds; the one that removes the pending file at the halt loses both
/// lines).
#[test]
fn a_boards_file_found_halted_at_the_change_halts_the_principal_and_a_relaunch_lists_every_line() {
    let fake = Fake::new();
    fake.head_unreachable.store(true, Ordering::SeqCst);
    let store = TempDir::new().unwrap();
    let chain = "ab".repeat(32);
    HeldDir::new(store.path(), Chain::parse(&chain).unwrap()).ensure().unwrap();
    let file = store.path().join("held").join(&chain).join("principal-1.held");
    let newer = format!("{{\"type\":\"skep-held-bursts\",\"v\":2,\"board\":\"{chain}\",\"principal\":1,\"account\":\"1.0.1\"}}\n");
    std::fs::write(&file, &newer).unwrap();
    let facts = writer_facts(&store);
    let g = ground_over(fake, store, facts, 0);
    for value in ["a", "b"] {
        let answer = g.hold(&insert(DOC, json!([value]), g.fake.head()), "unreachable", false);
        assert!(answer.get("unwritable").is_none(), "held on the pending file: {answer}");
    }
    let pending = pending_file(&g);
    let before = std::fs::read_to_string(&pending).unwrap();
    g.fake.head_unreachable.store(false, Ordering::SeqCst);
    g.holds.probe("b-1");
    assert_eq!(g.fake.sends(), 0, "nothing is sent from the moment the halt stands");
    assert_eq!(g.holds.lines(&g.session).unwrap_err().name(), "store_halted", "the halt is answered at the door");
    assert_eq!(std::fs::read_to_string(&pending).unwrap(), before, "the pending file is intact, both lines on it");
    assert_eq!(std::fs::read_to_string(&file).unwrap(), newer, "the halted file is never rebuilt over");
    assert_eq!(said_containing(&g, "is halted").len(), 1, "the halt said once: {:?}", g.said.lock().unwrap());
    g.holds.probe("b-1");
    assert_eq!((g.fake.sends(), said_containing(&g, "is halted").len()), (0, 1), "a later probe sends nothing and says nothing more");
    // The halted file moved aside, the relaunch lists every line.
    let Ground { holds, fake, session, store, .. } = g;
    drop(holds);
    std::fs::rename(&file, file.with_extension("held.aside")).unwrap();
    let g = ground_over(fake, store, session.facts.clone(), 0);
    let listed: Vec<Value> = g.lines().iter().map(|line| line["frame"]["values"].clone()).collect();
    assert_eq!(listed, [json!(["a"]), json!(["b"])], "a relaunch lists every line");
}

/// Checks that the change's copy refused part-way keeps what landed and
/// writes the rest at a later probe, the pending file removed only then
/// (§3c.3; skep #822, #859).
///
/// The board away at the session's open, three bursts are held on the
/// pending file; an earlier run left the board's file holding no line, its
/// header alone. The board returns with the device cutting the one copy's
/// write short and refusing every sync after the first: the change writes
/// the three lines one by one, the first lands and the second is refused —
/// the first kept in the board's file, the other two owed, parked on the
/// pending file, which stands; the wait is said once. The device takes
/// copies again: the next probe writes the rest, removes the pending file,
/// and a reopen reads all three (the mutant that undoes the whole copy
/// throws the landed line away and copies every line again; the one that
/// removes the pending file before every copy lands loses the two).
#[test]
fn the_changes_copy_refused_part_way_keeps_what_landed_and_writes_the_rest_at_a_later_probe() {
    let fake = Fake::new();
    fake.head_unreachable.store(true, Ordering::SeqCst);
    fake.op_unreachable.store(true, Ordering::SeqCst);
    let store = TempDir::new().unwrap();
    let chain = Chain::parse(&"ab".repeat(32)).unwrap();
    HeldDir::new(store.path(), chain).ensure().unwrap();
    let file = store.path().join("held").join(chain.to_string()).join("principal-1.held");
    std::fs::write(&file, format!("{{\"type\":\"skep-held-bursts\",\"v\":1,\"board\":\"{chain}\",\"principal\":1,\"account\":\"1.0.1\"}}\n")).unwrap();
    let facts = writer_facts(&store);
    let g = ground_over(fake, store, facts, 0);
    for value in ["a", "b", "c"] {
        let answer = g.hold(&insert(DOC, json!([value]), g.fake.head()), "unreachable", false);
        assert!(answer.get("unwritable").is_none(), "held on the pending file: {answer}");
    }
    let pending = pending_file(&g);
    g.fake.head_unreachable.store(false, Ordering::SeqCst);
    crate::held::tests::cut_the_next_write_short(10);
    crate::held::tests::refuse_copies_after(1);
    g.holds.probe("b-1");
    let read = |file: &std::path::Path| -> Vec<u64> {
        let Opened::Live { queue, .. } = HeldDir::new(g.store.path(), chain).open_file(1, "1.0.1").unwrap() else { panic!("the file reads live: {}", file.display()) };
        queue.lines().iter().map(|line| line.k).collect()
    };
    assert_eq!(read(&file), [1], "the line that landed is kept in the board's file");
    assert_eq!(ordinals(&g).len(), 3, "every line stands in the queue");
    assert!(pending.exists(), "the pending file stands while a copy is owed");
    let said = said_containing(&g, "could not be copied to its held file");
    assert!(said.len() == 1 && said[0].contains("held line 2"), "the wait said once, at the first copy refused: {said:?}");
    crate::held::tests::take_copies();
    g.holds.probe("b-1");
    assert_eq!(read(&file), [1, 2, 3], "the rest written at the next probe");
    assert!(!pending.exists(), "the pending file removed only then");
    assert_eq!(said_containing(&g, "wait in memory no more").len(), 1, "the wait's end said once: {:?}", g.said.lock().unwrap());
}

/// Checks that a crash between the change's copy and the pending file's
/// removal doubles no line at the relaunch (§3c.3; skep #859; I5).
///
/// The board away at the session's open, two bursts are held on the pending
/// file. The pending directory is then sealed against the removal and the
/// board returns: the change's copy lands in the board's file, and the
/// pending file stands, its removal refused and said once — as a crash
/// between the two leaves them. The directory opened, a relaunch over the
/// store reads both files: each line stands once, the pending file's lines
/// passed over as lines the board's file already carries, the pending file
/// removed, and the lines sent once each (the mutant that enters the
/// pending file's lines again sends the person's text twice).
#[cfg(unix)]
#[test]
fn a_crash_between_the_changes_copy_and_the_pending_files_removal_doubles_no_line_at_the_relaunch() {
    use std::os::unix::fs::PermissionsExt;
    let fake = Fake::new();
    fake.head_unreachable.store(true, Ordering::SeqCst);
    let store = TempDir::new().unwrap();
    let facts = writer_facts(&store);
    let g = ground_over(fake, store, facts, 0);
    for value in ["a", "b"] {
        let answer = g.hold(&insert(DOC, json!([value]), g.fake.head()), "unreachable", false);
        assert!(answer.get("unwritable").is_none(), "held on the pending file: {answer}");
    }
    let pending = pending_file(&g);
    let pending_dir = pending.parent().unwrap().to_path_buf();
    std::fs::set_permissions(&pending_dir, std::fs::Permissions::from_mode(0o500)).unwrap();
    g.fake.head_unreachable.store(false, Ordering::SeqCst);
    g.fake.op_refused.every((503, json!({"error": "write_busy"})));
    g.holds.probe("b-1");
    let Opened::Live { queue, .. } = HeldDir::new(g.store.path(), Chain::parse(&"ab".repeat(32)).unwrap()).open_file(1, "1.0.1").unwrap() else { panic!("the board's file reads live") };
    assert_eq!(queue.lines().iter().map(|line| line.k).collect::<Vec<_>>(), [1, 2], "the change's copy landed in the board's file");
    assert!(pending.exists(), "the pending file stands, its removal refused");
    assert_eq!(said_containing(&g, "could not be removed").len(), 1, "the refused removal said once: {:?}", g.said.lock().unwrap());
    std::fs::set_permissions(&pending_dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    // The relaunch, both files standing.
    let Ground { holds, fake, session, store, .. } = g;
    drop(holds);
    fake.sends.lock().unwrap().clear();
    fake.op_refused.clear();
    let g = ground_over(fake, store, session.facts.clone(), 0);
    let listed: Vec<Value> = g.lines().iter().map(|line| line["frame"]["values"].clone()).collect();
    assert_eq!(listed, [json!(["a"]), json!(["b"])], "each line once at the relaunch");
    assert!(!pending.exists(), "the pending file removed at the relaunch's first touch, nothing to enter");
    g.holds.probe("b-1");
    assert_eq!(sent_values(&g), ["a", "b"], "each line sent once");
    assert!(g.lines().is_empty(), "every line kept");
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

/// The ground for a document another writer keeps moving (skep #862).
///
/// An anchored line on `DOC` is held before any dial and a line on `OTHER`
/// behind it, the image the shift reads `DOC`'s three units, and another
/// writer's change lands on `DOC` as each dial reaches the board while the
/// flag answered stands, `per_dial` passing at each: the ground, the
/// anchored line's ordinal, the state it was typed against and the flag.
fn kept_moving(per_dial: Duration) -> (Ground, u64, u64, Arc<AtomicBool>) {
    let g = unclaimed_ground();
    let typed = g.fake.head();
    let k = g.hold_anchored(&insert_at(DOC, 2, json!(["x"]), typed), anchors(Some(&i(1)), Some(&i(2))), "unreachable", false)["held"].as_u64().unwrap();
    g.hold(&insert(OTHER, json!(["other"]), g.fake.head()), "unreachable", false);
    *g.fake.image.lock().unwrap() = vec![run(&i(1), 3)];
    let writing = Arc::new(AtomicBool::new(true));
    let (fake, still, holds) = (Arc::clone(&g.fake), Arc::clone(&writing), Arc::downgrade(&g.holds));
    *g.fake.at_send.lock().unwrap() = Some(Box::new(move || {
        if still.load(Ordering::SeqCst) {
            let at = fake.next_at.fetch_add(1, Ordering::SeqCst);
            fake.move_arrangement(DOC, at);
            if let Some(holds) = holds.upgrade() {
                holds.advance(per_dial);
            }
        }
    }));
    let _ = g.states();
    (g, k, typed, writing)
}

/// The frames the fake board was sent on `doc`.
fn dials_on(g: &Ground, doc: &str) -> usize {
    g.fake.sends.lock().unwrap().iter().filter(|frame| frame["doc"] == doc).count()
}

/// Checks that a document another writer keeps moving takes a turn's steps.
///
/// The lines after it go at the next turn (skep #862). An anchored line held
/// before any dial stands on one document, a line on another behind it, and
/// another writer's change lands on the first as each dial reaches the
/// board, half a second passing at each. The first turn sends the line and
/// shifts it as each refusal asks, a step a shift — its image read and its
/// shifted dial — until no step is left for the next: the turn answers
/// `Bounded`, `TURN_STEPS` dials made on the first document and
/// one image read fewer, none on the other, the line standing as its last
/// dial left it — its cause kept, `sent`, the frame its last shift wrote,
/// typed at the last read's state — both documents `sending`, never `moved`,
/// and the refusal said once. The next turn passes the document over, keeps
/// the other line and ends the pass; the next pass reads the line once and
/// runs out of steps again, said no more, the failure being the same; and
/// once the other writer stops, the pass after it reads the line once, meets
/// the refusal its last dial left, shifts it once and keeps it (the mutant
/// whose shifts take no step holds the feed thread from the first refusal to
/// the line's deadline and faces the document moved; the one that leaves the
/// document unstopped at the bound spends the next turn on it, the other line
/// unsent; the one that faces it moved at the bound hands the person a line
/// the shell can still place; the one that takes the step after the read
/// reads once more than it dials; the one that says it at every pass says it
/// twice).
#[test]
fn a_document_another_writer_keeps_moving_takes_one_turns_steps_and_the_lines_after_it_go_at_the_next() {
    let (g, k, typed, writing) = kept_moving(Duration::from_millis(500));
    let images = |g: &Ground| g.fake.image_reads.load(Ordering::SeqCst);
    let reads = |g: &Ground| g.fake.changes_reads.load(Ordering::SeqCst);
    let bounded = format!(
        "held: line {k} on {DOC} was not taken (the board refused: arrangement_moved (op insert)) and the turn has no step left to shift it; it is shifted and sent again at the drain's next pass"
    );
    let said = |g: &Ground| g.said.lock().unwrap().iter().filter(|line| **line == bounded).count();
    assert_eq!(g.holds.probe("b-1"), Turn::Bounded, "the turn stops at its bound");
    assert_eq!((dials_on(&g, DOC), images(&g), dials_on(&g, OTHER)), (TURN_STEPS, TURN_STEPS - 1, 0), "the send, then a step a shift until none is left for the next");
    let lines = g.lines();
    // The last dial's frame, its `id` the line's dial id and no part of the
    // frame the line keeps (skep #971).
    let mut last = g.fake.sends.lock().unwrap().last().cloned().unwrap();
    let dialed_under = last.as_object_mut().and_then(|members| members.remove("id"));
    assert!(dialed_under.as_ref().and_then(Value::as_str).is_some_and(|id| id.starts_with("shell:")), "the shift dialed under the line's dial id: {dialed_under:?}");
    assert_eq!((lines[0]["cause"].as_str(), lines[0]["sent"].as_bool()), (Some("unreachable"), Some(true)), "the line as its last dial left it: {lines:?}");
    assert!(lines[0]["frame"] == last && last["as_of"].as_u64() > Some(typed), "the frame its last shift wrote, typed at the last read's state: {}", lines[0]);
    assert_eq!(g.states(), ["sending", "sending"], "both documents sending, never moved");
    assert_eq!(said(&g), 1, "said once: {:?}", g.said.lock().unwrap());
    assert_eq!((g.holds.probe("b-1"), dials_on(&g, DOC), dials_on(&g, OTHER), g.lines().len()), (Turn::Done, TURN_STEPS, 1, 1), "the next turn passes the document over and keeps the other line");
    let read = reads(&g);
    assert_eq!((g.holds.probe("b-1"), reads(&g), dials_on(&g, DOC)), (Turn::Done, read + 1, 2 * TURN_STEPS - 1), "the next pass reads the line once, sends it and shifts it until no step is left");
    assert_eq!(said(&g), 1, "said no more: the failure is the same");
    writing.store(false, Ordering::SeqCst);
    assert_eq!(
        (g.holds.probe("b-1"), reads(&g), dials_on(&g, DOC), images(&g)),
        (Turn::Done, read + 2, 2 * TURN_STEPS + 1, 2 * TURN_STEPS - 2),
        "read once, refused as its last dial left it, shifted once and sent"
    );
    assert!(g.lines().is_empty(), "kept");
    assert_eq!((g.states().contains(&"moved".to_string()), said(&g)), (false, 1), "never faced moved");
}

/// Checks that a line kept moving meets its deadline at a later pass's read.
///
/// It is the deadline across the turn's bound (§3c.4; skep #862). The first
/// turn runs out of steps for the line's shifts and the next ends the pass,
/// as above; two minutes then pass, the other writer going on, and the next
/// pass reads the line once, finds no landing and hands it to the person
/// undialed: a refused run under `answers_lost` naming `moved`, the
/// last failure, its `sent` kept, said once, never faced moved (the mutant
/// that starts the line's clock afresh at each pass sends it again for as
/// long as the other writer writes).
#[test]
fn a_line_another_writer_keeps_moving_meets_its_deadline_at_a_later_passs_read() {
    let (g, k, _, _) = kept_moving(Duration::from_millis(500));
    assert_eq!((g.holds.probe("b-1"), g.holds.probe("b-1")), (Turn::Bounded, Turn::Done), "a turn at its bound, then the pass's end");
    g.holds.advance(HAND_OVER_DEADLINE);
    let (reads, dials) = (g.fake.changes_reads.load(Ordering::SeqCst), dials_on(&g, DOC));
    assert_eq!(g.holds.probe("b-1"), Turn::Done);
    assert_eq!((g.fake.changes_reads.load(Ordering::SeqCst), dials_on(&g, DOC)), (reads + 1, dials), "read once, and dialed no more");
    let lines = g.lines();
    assert_eq!((lines.len(), lines[0]["cause"].as_str(), lines[0]["sent"].as_bool(), lines[0]["refusal"]["last"].as_str()), (1, Some("answers_lost"), Some(true), Some("moved")), "{lines:?}");
    assert_eq!(g.states(), ["sending", "sending", "kept", "refused"], "never faced moved");
    let handed = said_containing(&g, &format!("held: line {k} on {DOC}: no landing "));
    assert!(handed.len() == 1 && handed[0].contains("(last: moved)"), "said once: {handed:?}");
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

// ── ANCHORS THAT NAME HELD WORDS (skep #969) ────────────────────────────────

/// Checks that a burst typed next to held, unminted words names them, and
/// lands at them once the board returns (skep #969).
///
/// It is the issue's own case. The document reads `ad`; the own node
/// stopped, the page types `cat` between them — an insert under the envelope
/// `id` `b-1`, held `stopped` — then `s` right after its `t`, its `before` a
/// piece naming `t`, `cat`'s third unit, and its `after` the `d`: the burst's
/// door binds the piece to the held line, the burst held as the line before
/// it is, its row listing the piece. Another writer puts `XY` before the
/// text. The node running, `cat`, refused as typed against an older state,
/// is shifted by its anchors and lands, its ack minting its words at `100`;
/// the piece becomes `t`'s address; `s` is refused so too, shifted by the
/// placed anchor to stand right after `t`, and lands, no `moved` said and no
/// line left (the mutant that keeps the door's anchors to I-addresses
/// refuses the second burst `malformed_args`, and the page can name no place
/// for it; the one that leaves the piece unplaced holds it moved, freed by a
/// drop alone).
#[test]
fn a_burst_typed_next_to_held_unminted_words_names_them_and_lands_at_them_once_the_board_returns() {
    let g = ground();
    g.fake.minting.store(true, Ordering::SeqCst);
    let typed = g.fake.head();
    g.holds.set_node_stopped("b-1", true);
    let send = |frame: Value, anchors: Anchors| g.holds.send(&g.session, frame, Some(anchors)).answered().unwrap_or_else(|r| panic!("refused: {r}"));
    let held = send(with_id(insert_at(DOC, 2, json!(["cat"]), typed), "b-1"), anchors(Some(&i(1)), Some(&i(2))));
    assert_eq!(held["cause"], "stopped", "{held}");
    let named = send(with_id(insert_at(DOC, 5, json!(["s"]), typed), "b-2"), pieced(piece("b-1", 2), Value::String(i(2))));
    assert_eq!(named["cause"], "stopped", "{named}");
    let rows = g.lines();
    assert_eq!(rows[1]["anchors"], json!({"before": piece("b-1", 2), "after": i(2)}), "the row lists the piece: {rows:?}");
    let _ = g.states();
    // Another writer's `XY` before the text, at 60; `cat`, once it lands,
    // minted at 100 between the `a` and the `d`.
    g.fake.next_at.store(61, Ordering::SeqCst);
    g.fake.move_arrangement(DOC, 60);
    *g.fake.image.lock().unwrap() = vec![run(&i(50), 2), run(&i(1), 2)];
    let (fake, sent) = (Arc::clone(&g.fake), AtomicUsize::new(0));
    *g.fake.at_send.lock().unwrap() = Some(Box::new(move || {
        if sent.fetch_add(1, Ordering::SeqCst) == 1 {
            *fake.image.lock().unwrap() = vec![run(&i(50), 2), run(&i(1), 1), run(&i(100), 3), run(&i(2), 1)];
        }
    }));
    g.holds.set_node_stopped("b-1", false);
    g.holds.probe("b-1");
    *g.fake.at_send.lock().unwrap() = None;
    assert_eq!(sent_values(&g), ["cat", "cat", "s", "s"], "each refused as typed stale once, and shifted");
    let sends = g.fake.sends.lock().unwrap().clone();
    let at = |n: usize| sends[n]["at"]["ordinal"].as_str().map(str::to_owned);
    assert_eq!((at(1), at(3)), (Some("4".into()), Some("7".into())), "`cat` past `XY`, `s` right after its `t`: {sends:?}");
    assert!(g.lines().is_empty(), "every line kept");
    let said = held_events(&g);
    assert!(said.iter().all(|event| event["state"] != "moved"), "no `moved` said: {said:?}");
}

/// Checks that a burst naming held words survives a relaunch, and is placed
/// at the words' ack after it (skep #969).
///
/// The own node stopped, `XYZ` is held under the `id` `b-1` and `!` between
/// its `X` and its `Y`, naming its words by two pieces; the shell relaunches
/// over the same store, its memory gone: the file's lines read back whole,
/// the pieces bound again, and the probe sends `XYZ`, its ack minting the
/// words, the pieces placed from it, `!` shifted by them and kept (the
/// mutant reader that drops a piece it cannot place at once loses the place
/// the page named at every relaunch).
#[test]
fn a_burst_naming_held_words_survives_a_relaunch_and_is_placed_at_their_ack_after_it() {
    let g = ground();
    let typed = g.fake.head();
    g.holds.set_node_stopped("b-1", true);
    let bursts =
        [(with_id(insert_at(DOC, 4, json!(["XYZ"]), typed), "b-1"), anchors(Some(&i(3)), None)), (with_id(insert_at(DOC, 5, json!(["!"]), typed), "b-2"), pieced(piece("b-1", 0), piece("b-1", 1)))];
    for (frame, edges) in bursts {
        let held = g.holds.send(&g.session, frame, Some(edges)).answered().unwrap();
        assert_eq!(held["cause"], "stopped", "{held}");
    }
    let before = g.lines();
    let Ground { holds, fake, session, store, .. } = g;
    drop(holds);
    let g = ground_over(fake, store, session.facts.clone(), 0);
    assert_eq!(g.lines(), before, "the relaunch reads the lines back whole, the pieces among them");
    g.fake.minting.store(true, Ordering::SeqCst);
    *g.fake.image.lock().unwrap() = vec![run(&i(1), 3), run(&i(100), 3)];
    let (fake, sent) = (Arc::clone(&g.fake), AtomicUsize::new(0));
    *g.fake.at_send.lock().unwrap() = Some(Box::new(move || {
        if sent.fetch_add(1, Ordering::SeqCst) == 1 {
            fake.move_arrangement(DOC, typed + 1);
        }
    }));
    g.holds.probe("b-1");
    *g.fake.at_send.lock().unwrap() = None;
    assert_eq!(sent_values(&g), ["XYZ", "!", "!"], "the held words, then the burst naming them, refused once and shifted");
    assert_eq!(g.fake.sends.lock().unwrap()[2]["at"]["ordinal"].as_str(), Some("5"), "placed between `X` and `Y`");
    assert!(g.lines().is_empty(), "every line kept");
}

/// Checks that a burst naming the words of an insert kept before it arrives
/// is placed at the burst's door (skep #969).
///
/// The page types `XYZ` and, before its ack reaches the page, `!` between
/// its `X` and its `Y`; the shell has the ack first, the insert kept and its
/// words minted at `100`. The second burst's pieces are placed at the door
/// from the principal's landed inserts — an offset at the insert's
/// positions refused `malformed_args` there first, nothing dialed — and the
/// board's refusal of it as typed against an older state is shifted within
/// the call by the anchors so placed, the page answered the ack, each dial
/// of the call — the first, and the shift within it — under the page's own
/// `id` (skep #971; the mutant that keeps no landed insert refuses the second
/// burst `no_such_burst`, though its words stand on the board; the one that
/// dials a first dial under a dial id leaves the page's own reissue of its
/// burst no memo entry to meet).
#[test]
fn a_burst_naming_the_words_of_an_insert_kept_before_it_arrives_is_placed_at_the_door() {
    let g = ground();
    g.fake.minting.store(true, Ordering::SeqCst);
    let typed = g.fake.head();
    let ack = g.holds.send(&g.session, with_id(insert_at(DOC, 4, json!(["XYZ"]), typed), "b-1"), Some(anchors(Some(&i(3)), None))).answered().unwrap();
    assert_eq!((ack["resp"].as_str(), ack["addr"].as_str()), (Some("ack_addr"), Some(i(100).as_str())), "{ack}");
    *g.fake.image.lock().unwrap() = vec![run(&i(1), 3), run(&i(100), 3)];
    g.fake.move_arrangement(DOC, ack["at"].as_u64().unwrap());
    let second = || with_id(insert_at(DOC, 5, json!(["!"]), typed), "b-2");
    let past = g.holds.send(&g.session, second(), Some(pieced(piece("b-1", 3), Value::Null))).answered().unwrap_err();
    assert_eq!((past.to_value(), g.fake.sends()), (Refusal::malformed("anchors.before").to_value(), 1), "an offset at the insert's positions, nothing dialed for it");
    let landed = g.holds.send(&g.session, second(), Some(pieced(piece("b-1", 0), piece("b-1", 1)))).answered().unwrap();
    assert_eq!(landed["resp"], "ack_addr", "shifted through the insert's landing and acked within the call: {landed}");
    let sends = g.fake.sends.lock().unwrap().clone();
    assert_eq!((sends.len(), sends[2]["at"]["ordinal"].as_str()), (3, Some("5")), "{sends:?}");
    let ids: Vec<&Value> = sends.iter().map(|sent| &sent["id"]).collect();
    assert_eq!(ids, [&json!("b-1"), &json!("b-2"), &json!("b-2")], "a first dial and its shift go out under the page's `id`");
    assert!(g.lines().is_empty(), "nothing held");
}

/// Holds, under `g`, a burst naming the words of an insert that landed.
///
/// A refused run stands on `OTHER`, so the held file stands; an insert of
/// `XYZ` after `DOC`'s `c`, its `id` `b-1`, whose answer was lost; and a
/// burst of `!` between its `X` and its `Y`, its anchors two pieces of its
/// words, held `behind` it at the burst's door. The board then holds the
/// insert's row, the person's own, at 77, its values at its site and its
/// words minted at `100`, the arrangement moved by it. It answers the
/// insert's ordinal.
fn held_a_named_landing(g: &Ground, typed: u64) -> u64 {
    let verdict = json!({"resp": "rejected", "code": "out_of_bounds", "disposition": "permanent", "op": "insert"});
    g.hold_for(&insert(OTHER, json!(["r"]), typed), Reason::refused("out_of_bounds", verdict)).unwrap();
    let k = g.hold_for(&with_id(insert_at(DOC, 4, json!(["XYZ"]), typed), "b-1"), Reason::of("unreachable", true)).unwrap()["held"].as_u64().unwrap();
    let behind = g.holds.send(&g.session, with_id(insert_at(DOC, 5, json!(["!"]), typed), "b-2"), Some(pieced(piece("b-1", 0), piece("b-1", 1)))).answered().unwrap();
    assert_eq!(behind["cause"], "behind", "{behind}");
    *g.fake.rows.lock().unwrap() = vec![json!({"at": 77, "op": "insert", "key": g.own_key(), "docs": [DOC]})];
    *g.fake.text.lock().unwrap() = "abcXYZ".into();
    *g.fake.image.lock().unwrap() = vec![run(&i(1), 3), run(&i(100), 3)];
    g.fake.move_arrangement(DOC, 77);
    g.fake.next_at.store(78, Ordering::SeqCst);
    k
}

/// Returns the `done` of line `k` the ground's held file holds.
fn done_of(g: &Ground, k: u64) -> Value {
    let text = std::fs::read_to_string(held_file(g)).unwrap();
    text.lines().filter_map(|line| serde_json::from_str::<Value>(line).ok()).find(|line| line["done"] == k).unwrap_or_else(|| panic!("line {k}'s `done`: {text}"))
}

/// Checks that a landing the read finds places the pieces naming its words
/// at the address its site reads (skep #969).
///
/// The read finds the insert landed ([`held_a_named_landing`]) and — its
/// words named — reads their address with one `image` of the site through
/// `/op-at`, at the position the site read answered at: the line is kept,
/// its `done` carrying the address, the pieces placed, and the burst naming
/// them, refused as typed against an older state, is shifted by them, sent
/// again and kept, the insert never sent twice (the mutant that keeps a
/// found landing with no address drops the pieces, and the burst is held
/// moved; the one that reads the address at the head reads past a write
/// that moved the words since).
#[test]
fn a_landing_the_read_finds_places_the_pieces_naming_its_words_at_the_address_its_site_reads() {
    let g = ground();
    let k = held_a_named_landing(&g, g.fake.head());
    g.holds.probe("b-1");
    assert_eq!(*g.fake.at_reads.lock().unwrap(), [77], "one `/op-at` read, at the site read's position");
    assert_eq!(sent_values(&g), ["!", "!"], "the burst naming the words, refused once and shifted; the insert never sent again");
    let sends = g.fake.sends.lock().unwrap().clone();
    assert_eq!(sends[1]["at"]["ordinal"].as_str(), Some("5"), "{sends:?}");
    let lines = g.lines();
    assert_eq!((lines.len(), lines[0]["doc"].as_str()), (1, Some(OTHER)), "the refused run alone stands: {lines:?}");
    let done = done_of(&g, k);
    assert_eq!((done["as"].as_str(), done["at"].as_u64(), done["addr"].as_str()), (Some("kept"), Some(77), Some(i(100).as_str())), "{done}");
}

/// Checks that an address read the board gives no answer to decides
/// nothing, and is read again at its answer (§3c.5; skep #863, #969).
///
/// The read finds the insert landed ([`held_a_named_landing`]) and its
/// address read goes unanswered: the pass ends there, every line as it
/// stood, nothing sent and the board held unanswered; the board answering,
/// the next probe reads again, places the pieces and lands the burst naming
/// them (the mutant that keeps the line at an unanswered read drops the
/// pieces for a read the board left unanswered).
#[test]
fn an_address_read_the_board_gives_no_answer_to_decides_nothing_and_is_read_again() {
    let g = ground();
    held_a_named_landing(&g, g.fake.head());
    g.fake.at_unanswered.store(true, Ordering::SeqCst);
    let before = g.lines();
    assert_eq!(g.holds.probe("b-1"), Turn::Unanswered, "the pass ends at the address read");
    assert_eq!((g.lines(), g.fake.sends()), (before, 0), "every line as it stood, nothing sent");
    assert!(!g.holds.lock("b-1").answers(), "the board held unanswered until a `/health` answers");
    g.fake.at_unanswered.store(false, Ordering::SeqCst);
    assert_eq!(g.holds.probe("b-1"), Turn::Done);
    assert_eq!(*g.fake.at_reads.lock().unwrap(), [77, 77], "read again");
    assert_eq!((sent_values(&g), g.lines().len()), (vec!["!".to_string(), "!".to_string()], 1), "placed, shifted and kept, the refused run alone standing");
}

/// Checks that a landing whose site names no one run of its words keeps its
/// line, and drops the anchors naming them (skep #969).
///
/// The read finds the insert landed ([`held_a_named_landing`]) and its
/// address read answers a reclaimed position, or two runs: no address is
/// known, so the line is kept with none, its `done` naming none, and the
/// burst naming its words loses its anchors, said once in the shell's own
/// window; refused as typed against an older state, it is held as moved,
/// its row listing no anchors and its `sendable` false (the mutant that
/// takes the first of two runs places the pieces in words another write
/// put there).
#[test]
fn a_landing_whose_site_names_no_one_run_of_its_words_keeps_its_line_and_drops_the_anchors_naming_it() {
    type Arm = fn(&Fake);
    let reclaimed: Arm = |fake| *fake.at_refused.lock().unwrap() = Some((410, json!({"error": "history_reclaimed", "floor": 90})));
    let two_runs: Arm = |fake| *fake.at_runs.lock().unwrap() = Some(vec![run(&i(100), 1), run(&i(200), 2)]);
    for (cell, arm) in [("a reclaimed position", reclaimed), ("two runs", two_runs)] {
        let g = ground();
        let k = held_a_named_landing(&g, g.fake.head());
        arm(&g.fake);
        g.holds.probe("b-1");
        let lines = g.lines();
        let named = lines.iter().find(|line| line["doc"] == DOC).unwrap_or_else(|| panic!("{cell}: the burst naming the words stands: {lines:?}"));
        assert_eq!((named["cause"].as_str(), named.get("anchors"), named["sendable"].as_bool()), (Some("moved"), None, Some(false)), "{cell}: held moved, its anchors dropped: {named}");
        assert_eq!(sent_values(&g), ["!"], "{cell}: refused once, never shifted");
        assert_eq!(said_containing(&g, "named words of line(s)").len(), 1, "{cell}: said once: {:?}", g.said.lock().unwrap());
        let done = done_of(&g, k);
        assert_eq!((done["as"].as_str(), done.get("addr")), (Some("kept"), None), "{cell}: kept, naming no address: {done}");
    }
}

/// Checks that a drop that finds its line landed places the pieces naming
/// its words (§3c.4; skep #866, #969).
///
/// An insert handed to the person as `answers_lost`, its line `sent`, and a
/// burst naming its words held behind it; the insert landed, and the
/// person's drop reads first, finds it, reads its words' address through
/// `/op-at` and keeps it: the burst naming them stands with its anchors
/// placed (the mutant that keeps the drop's landing with no address drops
/// the words' place the page named).
#[test]
fn a_drop_that_finds_its_line_landed_places_the_pieces_naming_its_words() {
    let g = ground();
    let typed = g.fake.head();
    let k = handed_over(&g, &with_id(insert_at(DOC, 4, json!(["XYZ"]), typed), "b-1"), true);
    let behind = g.holds.send(&g.session, with_id(insert_at(DOC, 5, json!(["!"]), typed), "b-2"), Some(pieced(piece("b-1", 0), piece("b-1", 1)))).answered().unwrap();
    assert_eq!(behind["cause"], "behind", "{behind}");
    *g.fake.rows.lock().unwrap() = vec![json!({"at": 77, "op": "insert", "key": g.own_key(), "docs": [DOC]})];
    *g.fake.text.lock().unwrap() = "abcXYZ".into();
    *g.fake.image.lock().unwrap() = vec![run(&i(1), 3), run(&i(100), 3)];
    g.fake.next_at.store(78, Ordering::SeqCst);
    assert_eq!(g.holds.resolve(&g.session, k, ResolveAct::Drop).unwrap(), Resolved::Kept);
    let lines = g.lines();
    assert_eq!((lines.len(), &lines[0]["anchors"]), (1, &json!({"before": i(100), "after": i(101)})), "{lines:?}");
    assert_eq!(*g.fake.at_reads.lock().unwrap(), [77], "one `/op-at` read, at the site read's position");
}

/// Checks that the landed-insert record keeps the principal's newest
/// inserts, one per document and `id` (skep #969).
///
/// Past `LANDED_INSERTS_KEPT` inserts the oldest is let go; a later insert
/// of one document and `id` takes the earlier one's place; an insert with no
/// `id`, or one past `MAX_BURST_ID_BYTES`, is noted nowhere; and the record
/// is keyed by document (the mutant that keeps every insert grows without
/// bound; the one keyed by `id` alone places a piece in another document's
/// words).
#[test]
fn the_landed_insert_record_keeps_the_principals_newest_inserts() {
    let g = ground();
    let noted = g.holds.with_principal("b-1", 1, |ph| {
        for n in 0..=LANDED_INSERTS_KEPT as u64 {
            ph.note_landed_insert(&with_id(insert(DOC, json!(["ab"]), 0), &format!("b-{n}")), &i(100 + 2 * n));
        }
        assert!(ph.landed_insert(DOC, "b-0").is_none(), "the oldest let go past the record's bound");
        assert_eq!(ph.landed_insert(DOC, "b-1").map(|landed| landed.addr.clone()), Some(i(102)));
        ph.note_landed_insert(&with_id(insert(DOC, json!(["abc"]), 0), "b-1"), &i(900));
        assert_eq!(ph.landed_insert(DOC, "b-1").map(|landed| (landed.addr.clone(), landed.positions)), Some((i(900), 3)), "a later insert of the `id` in its place");
        assert!(ph.landed_insert(OTHER, "b-1").is_none(), "keyed by its document");
        ph.note_landed_insert(&insert(DOC, json!(["x"]), 0), &i(1000));
        ph.note_landed_insert(&with_id(insert(DOC, json!(["x"]), 0), &"b".repeat(MAX_BURST_ID_BYTES + 1)), &i(1001));
        ph.landed_inserts.len()
    });
    assert_eq!(noted, Some(LANDED_INSERTS_KEPT), "an insert with no `id`, or one past its bound, noted nowhere");
}

// ── THE BUDGETS, TIMED (§3c.3) ──────────────────────────────────────────────

/// Returns a writer's ground holding `lines` lines in memory alone.
///
/// It is the board no one has claimed, over a store the device refuses
/// ([`unclaimed_ground`]): line `n` on `doc(n)`, held for `reason(n)`, no
/// line owing an attest or a synced copy. Where `at_both_budgets`, each
/// line's frame and anchors are a share of `held::MAX_HELD_BYTES` by
/// `held::MAX_HELD_LINES`, so at the line budget the queue is at both
/// budgets; else each frame is the least an insert spells.
fn full_ground(lines: usize, at_both_budgets: bool, doc: impl Fn(usize) -> String, reason: impl Fn(usize) -> Reason) -> Ground {
    let g = unclaimed_ground();
    let edges = anchors(Some(&i(4)), Some(&i(5)));
    // The frame's values sized by the rest of its spelling.
    let rest = json_len(&insert(&doc(0), json!([""]), g.fake.head()));
    let values = if at_both_budgets { "x".repeat(MAX_HELD_BYTES / MAX_HELD_LINES - edges.bytes() - rest) } else { "x".to_string() };
    g.holds
        .with_principal("b-1", 1, |ph| {
            for n in 0..lines {
                ph.hold(&doc(n), None, 0, insert(&doc(n), json!([values]), g.fake.head()), Some(edges.clone()), reason(n)).unwrap();
            }
        })
        .unwrap();
    g
}

/// Checks that the walk over a full queue drains within the ceiling.
///
/// It drains in time in proportion to its lines (skep #816). It is the
/// resend's own work over a full queue ([`full_ground`]): the
/// queue in memory alone, the one memory case, no line owing an attest, no
/// copy synced and no retry writing one, the board answering at once — so the
/// figure is the walk's bookkeeping, in its two worst shapes, every line on
/// one document and each on its own; the probes, one a turn until a turn
/// answers `Done`, send every line and keep it. Over a quarter of
/// `held::MAX_HELD_LINES` and all of it, each line's frame the least an
/// insert spells, the drain is held to `held::tests::LINEAR_GROWTH` (the
/// mutants whose settle walks the queue, or whose count of a document's
/// lines does, grow as the square of the lines); at both budgets, within
/// `held::TIMED_CEILING`. A store this shell can write would put each line
/// on the pending file at its hold, a copy synced a line, and the fill, not
/// the walk, would set the figure. Beside it, what each line's send costs
/// held or not: a queue of 256 lines on a claimed board under a writer's
/// session, its file this shell's, drained turn by turn — each line
/// attested, its mark and its `done` synced — and its cost a line printed.
/// The figures are printed with the build's profile, and
/// `held::MAX_HELD_LINES` states them.
#[test]
#[ignore = "timing test - gate-full only"]
fn the_walk_over_a_full_queue_drains_within_the_ceiling() {
    for (shape, apart) in [("on one document", false), ("each on its own document", true)] {
        let doc = move |n: usize| if apart { format!("1.0.1.0.{}", 100_000 + n) } else { DOC.to_string() };
        let drained_in = |lines: usize, at_both_budgets: bool| {
            let g = full_ground(lines, at_both_budgets, doc, |_| Reason::of("unreachable", false));
            let started = Instant::now();
            while g.holds.probe("b-1") == Turn::Bounded {}
            let took = started.elapsed();
            assert_eq!((g.fake.sends(), g.lines().len()), (lines, 0), "{shape}: every line sent and kept");
            took
        };
        let what = format!("the walk over a full held queue, every line {shape}");
        crate::held::tests::assert_linear(&what, |lines| drained_in(lines, false));
        crate::held::tests::assert_within_the_ceiling(&what, drained_in(MAX_HELD_LINES, true));
    }
    // Each line's send, held or not: attested, its mark and its `done`
    // synced to the board's held file.
    let edges = anchors(Some(&i(4)), Some(&i(5)));
    let g = ground();
    let lines = 256;
    let frame = insert(DOC, json!(["x".repeat(2000)]), g.fake.head());
    g.holds
        .with_principal("b-1", 1, |ph| {
            for _ in 0..lines {
                ph.hold(DOC, None, 0, frame.clone(), Some(edges.clone()), Reason::of("unreachable", false)).unwrap();
            }
        })
        .unwrap();
    let started = Instant::now();
    while g.holds.probe("b-1") == Turn::Bounded {}
    let took = started.elapsed();
    assert_eq!((g.fake.sends(), g.lines().len()), (lines, 0), "every line sent and kept");
    assert!(g.fake.sends.lock().unwrap().iter().all(|sent| sent.get("attest").is_some()), "each line attested");
    eprintln!("each held line's send — attested, its mark and its `done` synced to the held file — takes {:?} ({})", took / u32::try_from(lines).unwrap(), crate::held::tests::profile());
}

/// Checks that a person's drop of a full refused run is within the ceiling.
///
/// It takes time in proportion to its lines (skep #816). It is
/// `resolve(drop)` of a refused line heading a run on one document,
/// the rest held `behind` it, every line of the run dropped with it, in
/// memory alone ([`full_ground`]): over a quarter of `held::MAX_HELD_LINES`
/// and all of it, each line's frame the least an insert spells, held to
/// `held::tests::LINEAR_GROWTH` (the mutant whose settle removes each line
/// from the front of a vector moves every line after it, and grows as the
/// square of the lines); at both budgets, within `held::TIMED_CEILING`.
#[test]
#[ignore = "timing test - gate-full only"]
fn the_drop_of_a_refused_run_over_a_full_queue_is_within_the_ceiling() {
    let verdict = json!({"resp": "rejected", "code": "out_of_bounds", "disposition": "permanent"});
    let dropped_in = |lines: usize, at_both_budgets: bool| {
        let g = full_ground(lines, at_both_budgets, |_| DOC.to_string(), |n| if n == 0 { Reason::refused("out_of_bounds", verdict.clone()) } else { Reason::of("behind", false) });
        let started = Instant::now();
        let dropped = g.holds.resolve(&g.session, 1, ResolveAct::Drop);
        let took = started.elapsed();
        assert_eq!((dropped.ok(), g.lines().len()), (Some(Resolved::dropped(&[])), 0), "the run dropped whole");
        took
    };
    let what = "the drop of a refused run over a full held queue";
    crate::held::tests::assert_linear(what, |lines| dropped_in(lines, false));
    crate::held::tests::assert_within_the_ceiling(what, dropped_in(MAX_HELD_LINES, true));
}
