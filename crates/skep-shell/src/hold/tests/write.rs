//! The write path over a fake board.
//!
//! The suite checks a `halted` hold before any dial `sent: false`; a burst
//! held under the first hold that stands, over all eight cells of the
//! three; the `base` a hold takes from every kind of ack, an ack read after
//! a later one lowering it never; the refused run's `resolve(drop)`
//! dropping it and every line held behind it on its own document alone,
//! and a drop's `held` event saying the state of the line that stands
//! first after it; a burst the board refuses as typed against an older
//! state held moved at its first dial where it carries no anchors, the
//! board's verdict on its line and the hand that moved the document named,
//! and a moved line with the verdict reading `moved` and taking a moved
//! document's acts; the person's `send` on a moved document raising each
//! waiting line's base to the verdict's `site.current`, in the queue and on
//! disk, a base past it standing, and raising none where no line carries a
//! verdict naming a position (skep #757); THE SHIFT at a first dial (skep
//! #442): a stale burst whose anchors stand with the span between them
//! whole shifted and landing within the call, one cell per op in what the
//! displacement moves; the
//! shifted frame on the line, marked sent, before the shifted dial, and a
//! relaunch after that dial's answer is lost reading the landed test at the
//! shifted positions and keeping the line; a cut span, a lost anchor,
//! anchors at the wrong edge, no anchors and a read the board does not
//! answer each falling to the moved hold with its verdict and hands; and a
//! document that keeps moving stopping the shifts at the line's deadline,
//! held moved, the person's send starting its clock afresh; a held line
//! under the board's own directory;
//! a refusal the table holds nowhere faced at the first dial, a
//! `write_busy` and a first and second `durability` reissued within the
//! first dial's call and a third holding the burst; a burst answered
//! `500 internal_panic` held `sent: true` and read before it is sent again;
//! a write the hold never holds taking the same path, faced where a burst is
//! held and its ack noted for the base; the death signal at a write's dial
//! holding nothing; `resolve(send)` answering once the lines are handed
//! back, before any dial; a board the holds were not opened over stopped as
//! the caller's bug; the stored frame without its attest; P38's halted file
//! refusing every act at the principal's door, `resolve` among them, a copy
//! the store cannot make, and a queue kept in memory for want of its file
//! joining the board's file as soon as the directory is this shell's; no
//! `held` event when a session's open reads its file, and a misplaced file
//! set aside and said on `Talk` alone.
//!
//! It checks the burst's door too: a burst the board takes at no send
//! refused at the act and held never — past the frame cap as sent, or as a
//! signed resend would send it, a page-supplied attest counted out of every
//! resend, naming no document, an insert a signed session cannot attest; one
//! the queue has no room for, by its frames' and anchors' bytes or by its
//! lines, refused `held_full`; and each board's hold its own, a burst at one
//! board answered while another board's hold is held, dialed and kept at the
//! board its session stands at.
//!
//! And it checks the board term a signed write signs over (SP-14): a signed
//! burst over a head record (`H.1`) that stands and cannot be read, or none at
//! a board that names a claimant, held `head_unreadable` with nothing sent
//! unsigned, its line in the pending file under the origin's hash (skep
//! #725), skipped at each probe and sent attested once the record reads; a
//! garbled head answer held so, never `unreachable` (skep #728); the drop
//! admitted on such a line and `send` refused (skep #726); a write the hold
//! never holds refused so; the head read halting, or its answer lost, holding
//! the burst unsent; and an unclaimed board serving no record the one board a
//! signed write goes out unsigned at.

use super::*;
use crate::held::MAX_ANCHOR_BYTES;

/// Checks that a `halted` hold before any dial is `sent: false`.
///
/// The hold comes of the feed's `writes.halted` read, before any dial: no
/// dial was made, so nothing of it can have landed.
#[test]
fn a_halted_hold_before_any_dial_is_sent_false() {
    let g = ground();
    g.fake.writes_halted.store(true, Ordering::SeqCst);
    assert!(g.holds.note_health("b-1", &g.session.board.health().unwrap()), "the hold reads `writes.halted` off the board's `/health`");
    let OpAnswer::Answered(Ok(answer)) = g.holds.send_burst(&g.session, insert(DOC, json!(["hello"]), g.fake.head()), None) else { panic!("held before the dial") };
    assert_eq!(answer["cause"], "halted", "{answer}");
    let lines = g.lines();
    assert_eq!((lines[0]["cause"].as_str(), lines[0]["sent"].as_bool()), (Some("halted"), Some(false)), "{lines:?}");
    assert_eq!(g.fake.sends(), 0, "no dial was made");
}

/// Checks that a burst is held under the first hold that stands (§3c.4).
///
/// It is `send_burst`'s order, the law over all eight cells of the three:
/// the own node stopped, else the board's writes halted, else a line of the
/// principal's already held — the burst held under the first that stands
/// with no dial made, and dialed where none does (the mutant that reorders
/// the three faces the page `halted` for a stop the person made, or
/// `behind` for a board that takes no write).
#[test]
fn a_burst_is_held_under_the_first_hold_that_stands() {
    for stopped in [false, true] {
        for halted in [false, true] {
            for line in [false, true] {
                let cell = format!("stopped {stopped}, halted {halted}, a line standing {line}");
                let g = ground();
                if line {
                    g.hold(&insert(OTHER, json!(["a"]), g.fake.head()), "unreachable", false);
                }
                g.holds.set_node_stopped("b-1", stopped);
                g.fake.writes_halted.store(halted, Ordering::SeqCst);
                g.holds.note_health("b-1", &g.session.board.health().unwrap());
                let first = if stopped {
                    Some("stopped")
                } else if halted {
                    Some("halted")
                } else if line {
                    Some("behind")
                } else {
                    None
                };
                let OpAnswer::Answered(Ok(answer)) = g.holds.send_burst(&g.session, insert(DOC, json!(["b"]), g.fake.head()), None) else { panic!("{cell}: answered") };
                match first {
                    Some(cause) => assert_eq!((answer["resp"].as_str(), answer["cause"].as_str(), g.fake.sends()), (Some("held"), Some(cause), 0), "{cell}: {answer}"),
                    None => assert_eq!((answer["resp"].as_str(), g.fake.sends()), (Some("ack"), 1), "{cell}: {answer}"),
                }
            }
        }
    }
}

/// Checks the base a hold takes (§3c.2): the latest ack's `at`, else the open.
///
/// It is the `at` of the latest acked write on its document — whatever its
/// kind: a mint's, a fork's, a version's and a stage's at the `addr` it
/// minted (never at a stage's source), a link write's at its `home`, an
/// edit's at both its documents, a burst's at its `doc` — and where none,
/// the session's open position: a burst held on a
/// document no ack names, its mint's row at 50 below the session's open at
/// 60, reads past it, is sent, and kept (the mutant whose base falls back to
/// 0 faces the person's own text `moved`); a read notes nothing, so its
/// document keeps the open (the mutant that drops one kind from the
/// documents an ack names leaves that kind's document at the open).
#[test]
fn a_hold_takes_the_last_acked_write_or_the_sessions_open_as_its_base() {
    let g = writer_at(60);
    *g.fake.rows.lock().unwrap() = vec![json!({"at": 50, "op": "create_new_document", "key": g.own_key(), "docs": [DOC]})];
    g.hold(&insert(DOC, json!(["hello"]), g.fake.head()), "unreachable", false);
    assert_eq!(g.lines()[0]["base"], 60, "no ack names the document: the session's open");
    g.holds.probe("b-1");
    assert_eq!(g.fake.sends(), 1);
    assert!(g.lines().is_empty() && g.states().contains(&"kept".to_string()), "the row before the open moves nothing");

    let g = writer_at(60);
    let noted = |frame: Value, ack: Value| g.holds.note_ack(&g.session, &frame, &ack);
    let minted = |addr: &str, at: u64| json!({"resp": "ack_addr", "addr": addr, "at": at});
    noted(json!({"op": "create_new_document", "account": "1.0.1"}), minted("1.0.1.0.2", 70));
    noted(json!({"op": "make_link", "home": "1.0.1.0.3", "from": {"addrs": []}, "to": {"addrs": []}, "ty": {"addrs": []}}), minted("1.0.1.0.3.0.2.1", 71));
    noted(insert("1.0.1.0.4", json!(["x"]), g.fake.head()), json!({"resp": "delivery", "items": []}));
    noted(json!({"op": "emit", "home": "1.0.1.0.5", "ty": [], "from": "1.0.1.0.5.0.1.1", "to": []}), minted("1.0.1.0.5.0.2.1", 72));
    noted(json!({"op": "nullify", "home": "1.0.1.0.6", "target": "1.0.1.0.3.0.2.1"}), minted("1.0.1.0.6.0.2.1", 73));
    noted(json!({"op": "assert_sup", "home": "1.0.1.0.7", "old": "1.0.1.0.3.0.2.1", "new": "1.0.1.0.5.0.2.1"}), minted("1.0.1.0.7.0.2.1", 74));
    noted(json!({"op": "edit_link", "original": "1.0.1.0.3.0.2.1", "d_s": "1.0.1.0.8", "d_a": "1.0.1.0.9", "successor": {}}), json!({"resp": "ack_edit", "at": 75}));
    noted(json!({"op": "fork"}), minted("1.0.1.0.10", 76));
    noted(json!({"op": "version", "d_src": "1.0.1.0.2"}), minted("1.0.1.0.2.1", 77));
    // A stage's ack names the draft it minted, never the source it copied:
    // the source's base stands at its own last ack.
    noted(json!({"op": "stage", "from": "1.0.1.0.2"}), minted("1.0.1.0.11", 78));
    let bases = [
        ("1.0.1.0.2", 70),
        ("1.0.1.0.3", 71),
        ("1.0.1.0.4", 60),
        ("1.0.1.0.5", 72),
        ("1.0.1.0.6", 73),
        ("1.0.1.0.7", 74),
        ("1.0.1.0.8", 75),
        ("1.0.1.0.9", 75),
        ("1.0.1.0.10", 76),
        ("1.0.1.0.2.1", 77),
        ("1.0.1.0.11", 78),
    ];
    for (doc, base) in bases {
        let held = g.hold(&insert(doc, json!(["x"]), g.fake.head()), "unreachable", false);
        let k = held["held"].as_u64().unwrap();
        let line = g.lines().into_iter().find(|l| l["held"] == k).unwrap();
        assert_eq!(line["base"], base, "{doc}: {line}");
    }

    // A burst dialed and acked notes its own `at`.
    let g = ground();
    let OpAnswer::Answered(Ok(ack)) = g.holds.send_burst(&g.session, insert(DOC, json!(["a"]), g.fake.head()), None) else { panic!("acked") };
    let at = ack["at"].as_u64().unwrap();
    g.hold(&insert(DOC, json!(["b"]), g.fake.head()), "unreachable", false);
    assert_eq!(g.lines()[0]["base"], at);
}

/// Checks that an ack read after a later one never lowers the base (§3c.2).
///
/// Answers are noted as they are read — a call's on its connection's thread,
/// a resend's on the board's feed thread — not as the board committed them: a
/// link homed in the document at 99 and an insert there at 100, noted in
/// either order, leave 100 the base of the next burst held on it, whose read
/// passes over both of the principal's rows, sends it and keeps it (the
/// mutant that overwrites the base with each ack's `at` reads from 99 where
/// the answers came out of order, and faces the person's own insert as a
/// move; the one that keeps the first position noted does so where they came
/// in order).
#[test]
fn an_ack_read_after_a_later_one_never_lowers_the_base() {
    let link = json!({"op": "make_link", "home": DOC, "from": {"addrs": []}, "to": {"addrs": []}, "ty": {"addrs": []}});
    // The insert that landed at 100 was typed against the link's ack at
    // 99, the newest state the page held when it typed.
    let acks = [(link, json!({"resp": "ack_addr", "addr": "1.0.1.0.1.0.2.1", "at": 99})), (insert(DOC, json!(["a"]), 99), json!({"resp": "ack", "at": 100}))];
    for in_commit_order in [false, true] {
        let g = ground();
        let mut read = acks.clone();
        if !in_commit_order {
            read.reverse();
        }
        for (frame, ack) in &read {
            g.holds.note_ack(&g.session, frame, ack);
        }
        let own = |at: u64, op: &str| json!({"at": at, "op": op, "key": g.own_key(), "docs": [DOC]});
        *g.fake.rows.lock().unwrap() = vec![own(99, "make_link"), own(100, "insert")];
        g.hold(&insert(DOC, json!(["b"]), g.fake.head()), "unreachable", false);
        assert_eq!(g.lines()[0]["base"], 100, "in commit order {in_commit_order}: the later write's position stands");
        g.fake.next_at.store(101, Ordering::SeqCst);
        g.holds.probe("b-1");
        let states = g.states();
        assert_eq!(g.fake.sends(), 1, "in commit order {in_commit_order}: the line is sent");
        assert!(g.lines().is_empty() && states.contains(&"kept".to_string()) && !states.contains(&"moved".to_string()), "in commit order {in_commit_order}: {states:?}");
    }
}

/// Checks that a refused run's drop drops its `behind` lines.
///
/// The run's line carries the board's verdict as its `refusal` (§3c.2, "for
/// the face") and the lines `behind` it carry none; `drop` on the refused
/// head drops it and every line held `behind` it on that document (the
/// mutant that leaves them standing), the `held` event naming the session
/// that acted; `resolve` on a holding line answers `not_resolvable`; an
/// unknown ordinal answers `no_such_held`.
#[test]
fn a_refused_run_drops_its_behind_lines() {
    let g = ground();
    let verdict = json!({"resp": "rejected", "code": "out_of_bounds", "disposition": "permanent"});
    let head = insert(DOC, json!(["a"]), g.fake.head());
    let k1 = g.hold_for(&head, Reason::refused("out_of_bounds", verdict.clone())).unwrap()["held"].as_u64().unwrap();
    // Two more bursts on the same document arrive while the run stands
    // → behind.
    let behind = |values: Value| -> Value {
        let OpAnswer::Answered(Ok(answer)) = g.holds.send_burst(&g.session, insert(DOC, values, g.fake.head()), None) else { panic!("held behind the run") };
        answer
    };
    let k2 = behind(json!(["b"]))["held"].as_u64().unwrap();
    assert_eq!(behind(json!(["c"]))["cause"], "behind");
    let lines = g.lines();
    assert_eq!(lines.len(), 3, "the run and its two behind lines stand");
    assert_eq!(lines[0]["refusal"], verdict, "the refused run's line carries the board's verdict");
    assert!(lines[1..].iter().all(|l| l.get("refusal").is_none()), "a line behind the run carries no refusal: {lines:?}");
    // A holding line is not resolvable; an unknown ordinal is no_such_held.
    assert_eq!(g.holds.resolve(&g.session, k2, ResolveAct::Drop).unwrap_err().name(), "not_resolvable");
    assert_eq!(g.holds.resolve(&g.session, 999, ResolveAct::Drop).unwrap_err().name(), "no_such_held");
    // Drop the refused head: the whole run goes.
    let _ = g.rx.try_iter().count();
    assert_eq!(g.holds.resolve(&g.session, k1, ResolveAct::Drop).unwrap(), Resolved::Dropped);
    assert!(g.lines().is_empty(), "the run and its behind lines are dropped");
    assert_eq!(g.fake.sends(), 0, "nothing is dialed on a drop");
    let said: Vec<Event> = g.rx.try_iter().filter(|e| e.name == EventName::Held).collect();
    assert_eq!(said.len(), 1, "{said:?}");
    let said = &said[0].data;
    assert_held_event_declared(said);
    assert_eq!((said["session"].as_str(), said["held"].as_u64(), said["state"].as_str()), (Some(g.session.reference.as_str()), Some(0), Some("kept")), "the drop is said under the session that acted");
}

/// Checks that a drop says the state of the line that stands first.
///
/// On a moved document (§4b.1's `resolve`, §4b.2's `held`) — the board
/// refusing its head's resend as typed against an older state, every line of
/// it faced `moved` — the person drops a later line, and the line held
/// before it stands moved still — the `held` event says `moved` with the one
/// line left, never `kept` over text still held (the mutant that says
/// `kept` at every drop lifts the page's marks); the drop of the last line
/// says `kept` with none.
#[test]
fn a_drop_says_the_state_of_the_line_that_stands_first() {
    let g = writer_at(80);
    g.fake.next_at.store(81, Ordering::SeqCst);
    *g.fake.rows.lock().unwrap() = vec![json!({"at": 77, "op": "insert", "key": "ff".repeat(32), "docs": [DOC]})];
    let ks: Vec<u64> = ["a", "b", "c"].iter().map(|v| g.hold(&insert(DOC, json!([v]), 70), "unreachable", false)["held"].as_u64().unwrap()).collect();
    g.fake.op_rejected.next(1, arrangement_moved(70, 77));
    g.holds.probe("b-1");
    assert!(g.lines().iter().all(|l| l["cause"] == "moved"), "the board's verdict faces every line moved: {:?}", g.lines());
    let _ = g.rx.try_iter().count();
    assert_eq!(g.holds.resolve(&g.session, ks[1], ResolveAct::Drop).unwrap(), Resolved::Dropped);
    let said: Vec<Event> = g.rx.try_iter().filter(|e| e.name == EventName::Held).collect();
    assert_eq!(said.len(), 1, "{said:?}");
    assert_held_event_declared(&said[0].data);
    assert_eq!((said[0].data["state"].as_str(), said[0].data["held"].as_u64()), (Some("moved"), Some(1)), "{said:?}");
    let left: Vec<u64> = g.lines().iter().map(|l| l["held"].as_u64().unwrap()).collect();
    assert_eq!(left, [ks[0]], "the dropped line and the one after it are gone");
    assert_eq!(g.holds.resolve(&g.session, ks[0], ResolveAct::Drop).unwrap(), Resolved::Dropped);
    let said: Vec<Event> = g.rx.try_iter().filter(|e| e.name == EventName::Held).collect();
    assert_eq!((said[0].data["state"].as_str(), said[0].data["held"].as_u64()), (Some("kept"), Some(0)), "{said:?}");
}

/// Checks that a burst refused as typed against an older state is held moved.
///
/// At its first dial the board refuses it `arrangement_moved` (wire.md
/// §Arrangement, the typed state), and it carries no anchors — an agent's
/// burst — so no shift is tried: it is answered `held`, cause `moved`, its
/// line carrying the board's verdict as its refusal, `sent: false`; the
/// `held` event says `moved`, naming the hand whose row moved the document
/// since the burst's typed state — the rows under it alone — and no cause;
/// and no probe sends it again, the line awaiting the person's act (the
/// mutant that holds it a refused run faces an act whose resend meets the
/// same refusal; the one that names no hand draws the moved face with none).
#[test]
fn a_burst_refused_as_typed_against_an_older_state_is_held_moved_at_its_first_dial() {
    let g = ground();
    let typed = g.fake.head();
    let foreign = |at: u64, doc: &str| json!({"at": at, "op": "delete", "key": "ff".repeat(32), "docs": [doc]});
    *g.fake.rows.lock().unwrap() = vec![foreign(77, DOC), foreign(78, OTHER)];
    g.fake.op_rejected.next(1, arrangement_moved(typed, 77));
    let OpAnswer::Answered(Ok(held)) = g.holds.send_burst(&g.session, insert(DOC, json!(["x"]), typed), None) else { panic!("held, not faced") };
    crate::shapes::assert_declared("HeldAnswer", &held);
    assert_eq!((held["resp"].as_str(), held["cause"].as_str(), g.fake.sends()), (Some("held"), Some("moved"), 1), "{held}");
    let lines = g.lines();
    assert_eq!((lines[0]["cause"].as_str(), lines[0]["sent"].as_bool()), (Some("moved"), Some(false)), "{lines:?}");
    assert_eq!(lines[0]["refusal"], arrangement_moved(typed, 77), "the board's verdict rides the line");
    let said: Vec<Value> = g.rx.try_iter().filter(|e| e.name == EventName::Held).map(|e| e.data).collect();
    let [moved] = &said[..] else { panic!("one `held` event: {said:?}") };
    assert_held_event_declared(moved);
    assert_eq!((moved["state"].as_str(), moved.get("cause")), (Some("moved"), None), "{moved}");
    assert_eq!(moved["hands"], json!([{"key": "other", "fingerprint": "ff".repeat(32)}]), "the hand of the row under the document since its typed state: {moved}");
    g.holds.probe("b-1");
    assert_eq!((g.fake.sends(), g.lines().len()), (1, 1), "the line awaits the person's act: no probe sends it");
}

/// Checks that a moved line keeps the board's verdict and takes a moved
/// document's acts.
///
/// A line held `moved` with the board's verdict as its refusal reads `moved`
/// — its state, the `held` event's — never `refused` for the refusal beside
/// it (the mutant that reads the refusal first faces it a refused run);
/// `resolve(send)` hands it back `behind`, its base raised to the verdict's
/// `site.current` (§3c.4) and the burst held behind it, which awaited no
/// act, at its own, the probe then sending and keeping both; and
/// `resolve(drop)` drops a second such line, its document then `kept`.
#[test]
fn a_moved_line_with_the_boards_verdict_takes_a_moved_documents_acts() {
    let verdict = arrangement_moved(40, 45);
    let moved = Reason { cause: "moved".to_string(), refusal: Some(verdict.clone()), sent: false };
    assert_eq!(line_state(&moved), HeldState::Moved, "the verdict beside it, the line is moved");
    let g = ground();
    let k = g.hold_for(&insert(DOC, json!(["a"]), 40), moved.clone()).unwrap()["held"].as_u64().unwrap();
    let OpAnswer::Answered(Ok(behind)) = g.holds.send_burst(&g.session, insert(DOC, json!(["b"]), g.fake.head()), None) else { panic!("held behind the moved line") };
    assert_eq!(behind["cause"], "behind", "{behind}");
    let lines = g.lines();
    assert_eq!((lines[0]["cause"].as_str(), &lines[0]["refusal"]), (Some("moved"), &verdict), "{lines:?}");
    assert_eq!(g.states(), ["moved", "holding"], "the moved line says `moved`, the burst behind it `holding`");
    assert_eq!(g.holds.resolve(&g.session, k, ResolveAct::Send).unwrap(), Resolved::HandedBack);
    let handed: Vec<(String, Option<u64>)> = g.lines().iter().map(|l| (l["cause"].as_str().unwrap_or("?").to_string(), l["base"].as_u64())).collect();
    assert_eq!(handed, [("behind".to_string(), Some(45)), ("behind".to_string(), Some(0))], "handed back, the moved line's base raised to the verdict's `site.current`");
    g.holds.probe("b-1");
    assert_eq!(g.fake.sends(), 2, "both sent");
    assert!(g.lines().is_empty() && g.states().contains(&"kept".to_string()), "and kept");
    let k = g.hold_for(&insert(DOC, json!(["c"]), 40), moved).unwrap()["held"].as_u64().unwrap();
    assert_eq!(g.states(), ["moved"]);
    assert_eq!(g.holds.resolve(&g.session, k, ResolveAct::Drop).unwrap(), Resolved::Dropped);
    assert_eq!((g.states(), g.lines().len()), (vec!["kept".to_string()], 0), "the drop of the document's one line says `kept`");
}

/// Checks that the person's `send` on a moved document raises its waiting
/// lines' bases to the verdict's `site.current` (§3c.4; skep #757).
///
/// Two lines held on a document at the session's open, 80 — the first a
/// lost answer's, `sent: true`, the second held after the person's link
/// homed in the document was acked at 99, which moves no arrangement, so its
/// base is 99 — and another writer's change at 95: the board refuses the
/// first line's resend as typed against an older state, its verdict reading
/// through 95, and both stand `moved`, the verdict on the first. The
/// person's `send` re-marks both `behind`, each keeping its own `sent`, the
/// first's base raised to 95 and the second's standing at 99, past it — in
/// the queue, and on disk as the last line of each ordinal (the mutant that
/// leaves the bases reads the rows the person acknowledged again, and may
/// take the person's own other write among them for a line's landing; the
/// one that sets each base to the position lowers the second's to 95; the
/// one that raises the queue alone relaunches the bases below the rows).
#[test]
fn the_persons_send_on_a_moved_document_raises_each_waiting_lines_base_to_the_verdicts_current() {
    let g = writer_at(80);
    g.fake.next_at.store(100, Ordering::SeqCst);
    *g.fake.rows.lock().unwrap() = vec![json!({"at": 95, "op": "insert", "key": "ff".repeat(32), "docs": [DOC]})];
    let k1 = g.hold(&insert(DOC, json!(["a"]), 70), "unreachable", true)["held"].as_u64().unwrap();
    let link = json!({"op": "make_link", "home": DOC, "from": {"addrs": []}, "to": {"addrs": []}, "ty": {"addrs": []}});
    g.holds.note_ack(&g.session, &link, &json!({"resp": "ack_addr", "addr": "1.0.1.0.1.0.2.1", "at": 99}));
    let k2 = g.hold(&insert(DOC, json!(["b"]), 70), "behind", false)["held"].as_u64().unwrap();
    g.fake.op_rejected.next(1, arrangement_moved(70, 95));
    g.holds.probe("b-1");
    let marks = || -> Vec<(u64, String, Option<bool>, Option<u64>)> {
        g.lines().iter().map(|l| (l["held"].as_u64().unwrap_or(0), l["cause"].as_str().unwrap_or("?").to_string(), l["sent"].as_bool(), l["base"].as_u64())).collect()
    };
    assert_eq!(marks(), [(k1, "moved".to_string(), Some(true), Some(80)), (k2, "moved".to_string(), Some(false), Some(99))], "the document moved at the first line's resend");
    assert_eq!(g.lines()[0]["refusal"], arrangement_moved(70, 95), "the verdict on the line the board refused");
    assert_eq!(g.holds.resolve(&g.session, k1, ResolveAct::Send).unwrap(), Resolved::HandedBack);
    assert_eq!(
        marks(),
        [(k1, "behind".to_string(), Some(true), Some(95)), (k2, "behind".to_string(), Some(false), Some(99))],
        "the first raised to the verdict's `site.current`, the second past it standing"
    );
    let text = std::fs::read_to_string(held_file(&g)).unwrap();
    let last = |k: u64| file_lines(&text).into_iter().rfind(|l| l["held"] == k).map(|l| (l["cause"].as_str().unwrap_or("?").to_string(), l["base"].as_u64()));
    assert_eq!((last(k1), last(k2)), (Some(("behind".to_string(), Some(95))), Some(("behind".to_string(), Some(99)))), "each raise on disk: {text}");
}

/// Checks that the person's `send` raises no base where no line of the
/// moved document carries a verdict naming a position (§3c.4).
///
/// A line held `moved` with no verdict beside it, and one whose verdict
/// names its `site.current` as no natural, give the raise no position: the
/// person's `send` re-marks the line `behind`, its base standing where it
/// was held, though the person's later ack on the document stands past it
/// (the mutant that raises to a position of its own choosing — the last ack
/// the shell noted there — reads past rows no verdict read through).
#[test]
fn the_persons_send_on_a_moved_document_with_no_verdict_raises_no_base() {
    let unnatural = json!({"resp": "rejected", "op": "insert", "code": "arrangement_moved", "disposition": "permanent", "site": {"as_of": 40, "current": "45"}});
    for (cell, refusal) in [("no verdict", None), ("a verdict naming no natural position", Some(unnatural))] {
        let g = ground();
        let k = g.hold_for(&insert(DOC, json!(["a"]), 40), Reason { cause: "moved".to_string(), refusal, sent: false }).unwrap()["held"].as_u64().unwrap();
        g.holds.note_ack(&g.session, &insert(DOC, json!(["z"]), 40), &json!({"resp": "ack", "at": 60}));
        assert_eq!(g.holds.resolve(&g.session, k, ResolveAct::Send).unwrap(), Resolved::HandedBack, "{cell}");
        let lines = g.lines();
        assert_eq!((lines[0]["cause"].as_str(), lines[0]["base"].as_u64()), (Some("behind"), Some(0)), "{cell}: {lines:?}");
    }
}

/// Checks that a stale burst whose span stands whole is shifted and lands.
///
/// It lands within the call (skep #442, #751), one cell per op. The draft as
/// the page read it ran `abc` (I-positions 1 to 3); another writer then put
/// `XY` before it (I-positions 10 and 11), and the board's arrangement moved
/// to 77. Each burst, typed against the older state and carrying the identities
/// on either side of the span it edits — and, for the delete and the rearrange,
/// of the units the span holds — is refused `arrangement_moved` at its first
/// dial and shifted by one image read — its `before` anchor stands two
/// positions later, the span between the anchors holding its own units still —
/// and dialed again with every position it names moved by two and `as_of` the
/// read's state, the rest of the frame as composed: the insert's `at` (the
/// units on either side of it), the delete's `p` (the units on either side of
/// its two positions, the `after` the document's end), the copy's `at`
/// (appended after the last unit, no `after`), the reinstate's `at`, the
/// rearrange's every cut (the units on either side of its first cut to its
/// last). However the board split the span's runs — the page's read answering
/// them apart where the shell's answers one, or the shell's apart where the
/// page's answered one — the span compares whole. The page meets the ack within
/// the call, two dials made, one image read, no `/changes` read, no line
/// standing, the file gone, and no `held` event said for a line entered and
/// settled within one call. An insert at the document's start, the other
/// writer's text appended after it, moves by nothing and is sent again typed at
/// the read's state alone (the mutants that hold the stale burst moved, that
/// move one op's positions and not another's, that compare the span's runs
/// unjoined, or that type the shifted frame at the page's state — refused again
/// — each leave the page's text unplaced; the one that reads history reads what
/// the shift never needs).
#[test]
fn a_stale_burst_whose_anchors_stand_with_the_span_whole_is_shifted_and_lands_within_the_call() {
    let moved_before = || vec![run(&i(10), 2), run(&i(1), 3)];
    let moved_after = || vec![run(&i(1), 3), run(&i(10), 2)];
    let at = |ordinal: u64| json!({"subspace": "1", "ordinal": ordinal.to_string()});
    let positions = |frame: &Value| -> Value {
        match frame["op"].as_str() {
            Some("delete") => frame["p"].clone(),
            Some("rearrange") => frame["cuts"].clone(),
            _ => frame["at"].clone(),
        }
    };
    /// A cell: its name, the image now, the burst typed at a state, its
    /// anchors, and the positions the shifted dial names.
    type Cell = (&'static str, Vec<Value>, Box<dyn Fn(u64) -> Value>, Anchors, Value);
    let cells: Vec<Cell> = vec![
        ("an insert between a and b", moved_before(), Box::new(|typed| insert_at(DOC, 2, json!(["x"]), typed)), anchors(Some(&i(1)), Some(&i(2))), at(4)),
        ("a delete of b and c", moved_before(), Box::new(|typed| delete_at(DOC, 2, 2, typed)), spanned(Some(&i(1)), None, &[(&i(2), 2)]), at(4)),
        ("a delete of b and c, the page's read answering them apart", moved_before(), Box::new(|typed| delete_at(DOC, 2, 2, typed)), spanned(Some(&i(1)), None, &[(&i(2), 1), (&i(3), 1)]), at(4)),
        ("a copy appended after c", moved_before(), Box::new(|typed| copy_at(DOC, 4, typed)), anchors(Some(&i(3)), None), at(6)),
        ("a reinstate between b and c", moved_before(), Box::new(|typed| reinstate_at(DOC, 3, typed)), anchors(Some(&i(2)), Some(&i(3))), at(5)),
        ("a rearrange about b and c", moved_before(), Box::new(|typed| rearrange_at(DOC, &[2, 3, 4], typed)), spanned(Some(&i(1)), None, &[(&i(2), 2)]), json!([at(4), at(5), at(6)])),
        (
            "a rearrange about b and c, the shell's read answering them apart",
            vec![run(&i(10), 2), run(&i(1), 1), run(&i(2), 1), run(&i(3), 1)],
            Box::new(|typed| rearrange_at(DOC, &[2, 3, 4], typed)),
            spanned(Some(&i(1)), None, &[(&i(2), 2)]),
            json!([at(4), at(5), at(6)]),
        ),
        ("an insert at the start, the change after it", moved_after(), Box::new(|typed| insert_at(DOC, 1, json!(["x"]), typed)), anchors(None, Some(&i(1))), at(1)),
    ];
    for (cell, image, frame, anchors, moved) in cells {
        let g = ground();
        let typed = g.fake.head();
        *g.fake.image.lock().unwrap() = image;
        g.fake.move_arrangement(DOC, 77);
        let OpAnswer::Answered(Ok(ack)) = g.holds.send_burst(&g.session, frame(typed), Some(anchors)) else { panic!("{cell}: the shifted burst is acked within the call") };
        assert_eq!(ack["resp"], "ack", "{cell}: {ack}");
        let sent = g.fake.sends.lock().unwrap().clone();
        let reads = (g.fake.image_reads.load(Ordering::SeqCst), g.fake.changes_reads.load(Ordering::SeqCst));
        assert_eq!((sent.len(), reads), (2, (1, 0)), "{cell}: two dials, one image read, no history read");
        assert_eq!((positions(&sent[0]), sent[0]["as_of"].as_u64()), (positions(&frame(typed)), Some(typed)), "{cell}: the first dial sends the page's frame");
        assert_eq!((positions(&sent[1]), sent[1]["as_of"].as_u64()), (moved, Some(77)), "{cell}: the shifted dial moves every position by the displacement, typed at the read's state: {sent:?}");
        let rest = |frame: &Value| {
            let mut rest = frame.clone();
            for member in ["at", "p", "cuts", "as_of", "attest"] {
                rest.as_object_mut().unwrap().remove(member);
            }
            rest
        };
        assert_eq!(rest(&sent[1]), rest(&sent[0]), "{cell}: the rest of the frame as composed");
        assert!(g.lines().is_empty() && !held_file(&g).exists(), "{cell}: the line is kept and the file gone");
        assert!(g.states().is_empty(), "{cell}: no held event for a line entered and settled within one call");
    }
}

/// Checks that the shifted frame is on the line before the shifted dial,
/// and a relaunch reads the landed test at the shifted positions (skep
/// #442).
///
/// The held file read as each dial leaves holds nothing at the page's own
/// dial and, at the shifted dial, the line carrying the shifted frame —
/// `at` moved to 4, `as_of` the read's state — marked `sent`, the anchors
/// beside it, under the verdict the line was entered with; the shifted
/// dial's answer lost, the call answers `held` under `unreachable`, the line
/// holding the shifted frame and its anchors, which `held(session)` lists;
/// the relaunch over the same store reads the shifted frame, and the
/// shifted write having landed after all — the own row at its position, the
/// text at the shifted site — the read keeps the line, never sent again (the
/// mutant that writes the frame after the dial, or never, relaunches the
/// page's positions, and the landed test reads the wrong site and sends
/// the text a second time).
#[test]
fn the_shifted_frame_is_on_the_line_before_the_shifted_dial_and_a_relaunch_reads_the_landed_test_there() {
    let g = ground();
    let (typed, own) = (g.fake.head(), g.own_key());
    *g.fake.image.lock().unwrap() = vec![run(&i(10), 2), run(&i(1), 3)];
    g.fake.move_arrangement(DOC, 77);
    let (file, at_the_dial) = (held_file(&g), Arc::new(Mutex::new(Vec::new())));
    let seen = Arc::clone(&at_the_dial);
    *g.fake.at_send.lock().unwrap() = Some(Box::new(move || seen.lock().unwrap().push(std::fs::read_to_string(&file).unwrap_or_default())));
    g.fake.op_lost_at.store(2, Ordering::SeqCst);
    let OpAnswer::Answered(Ok(held)) = g.holds.send_burst(&g.session, insert_at(DOC, 2, json!(["x"]), typed), Some(anchors(Some(&i(1)), Some(&i(2))))) else { panic!("held, its shifted answer lost") };
    assert_eq!((held["resp"].as_str(), held["cause"].as_str(), held["held"].as_u64()), (Some("held"), Some("unreachable"), Some(1)), "{held}");
    let files = at_the_dial.lock().unwrap().clone();
    let [first, second] = &files[..] else { panic!("two dials: {files:?}") };
    assert!(file_lines(first).is_empty(), "nothing on the line at the page's own dial: {first}");
    let marks = file_lines(second);
    let last = marks.last().expect("the line is on disk at the shifted dial");
    assert_eq!(
        (last["frame"]["at"]["ordinal"].as_str(), last["frame"]["as_of"].as_u64(), last["sent"].as_bool(), last["cause"].as_str()),
        (Some("4"), Some(77), Some(true), Some("moved")),
        "the shifted frame, marked sent, is on the line before the shifted dial: {second}"
    );
    assert_eq!((&last["anchors"], last["refusal"]["code"].as_str()), (&json!({"before": i(1), "after": i(2)}), Some("arrangement_moved")), "the anchors and the verdict ride the line: {second}");
    let lines = g.lines();
    assert_eq!((lines[0]["cause"].as_str(), lines[0]["sent"].as_bool(), lines[0]["frame"]["at"]["ordinal"].as_str()), (Some("unreachable"), Some(true), Some("4")), "the shifted answer lost, the line holds the shifted frame: {lines:?}");
    assert_eq!(lines[0]["anchors"], json!({"before": i(1), "after": i(2)}), "held(session) lists the anchors: {lines:?}");
    assert_eq!(g.states(), ["holding"], "the lost answer is said; the entry was not");
    // The relaunch: the shifted write landed at 78 after all — the row of the
    // own hand, the text at the shifted site — and the read keeps it.
    *g.fake.at_send.lock().unwrap() = None;
    let Ground { holds, fake, session, store, .. } = g;
    drop(holds);
    *fake.rows.lock().unwrap() = vec![json!({"at": 78, "op": "insert", "key": own, "docs": [DOC]})];
    *fake.text.lock().unwrap() = "XYaxbc".into();
    fake.next_at.store(79, Ordering::SeqCst);
    let g = ground_over(fake, store, session.facts.clone(), 0);
    let lines = g.lines();
    assert_eq!((lines.len(), lines[0]["sent"].as_bool(), lines[0]["frame"]["at"]["ordinal"].as_str()), (1, Some(true), Some("4")), "the relaunch reads the shifted frame: {lines:?}");
    g.holds.probe("b-1");
    assert_eq!((g.fake.sends(), g.fake.image_reads.load(Ordering::SeqCst)), (2, 1), "the landed test at the shifted site keeps the line: never sent again, never shifted again");
    assert!(g.lines().is_empty() && g.states() == ["kept"], "kept");
}

/// Checks that each burst the shift cannot carry falls to the moved hold.
///
/// A cut span, a refilled span, a lost anchor, an anchor at two places, anchors
/// at the wrong edge, no anchors, no span and a read the board does not answer
/// each fall to it (skep #442, #751). The draft as the page read it ran `abc`
/// (I-positions 1 to 3). Another writer's row moved the document to 77; the
/// burst, typed against the older state, is refused at its first dial, and the
/// shift is not made: the span between the anchors holds a position it did not
/// hold (another writer's text inside it); a delete's or a rearrange's span
/// holds as many positions as it did and other units — `b` and `c` taken out
/// and `XY` put in their place, nothing else moved, so the shifted frame would
/// remove or move `XY` — or its own in another order, `c` before `b`; the
/// `after` anchor is in the document no longer; the `before` anchor stands at
/// two places, a passage of `abc` quoted again after it; the `before` anchor is
/// none though the span began past the document's start; the burst carries no
/// anchors — an agent's — and no read is made; a delete or a rearrange carries
/// anchors and no span of the units it edits; an insert's anchors name a span,
/// or a delete's a span of other than its width; the image read is not
/// answered. Each is the first brief's moved hold, unchanged: answered `held`
/// under `moved`, one dial, the verdict on the line beside the page's frame and
/// its anchors, the `held` event `moved` naming the hand of the row since the
/// typed state, why said once in the shell's own window save for a burst
/// without anchors, and no probe sending the line (the mutants that shift
/// through a cut span, a refilled or rearranged one by its count alone, a lost
/// anchor, or an anchor at its first place put the person's words where they
/// did not, or act on the other writer's; the one that shifts a span-less
/// delete by its count alone deletes what it cannot name; the one that holds
/// nothing after a failed read loses the burst).
#[test]
fn a_cut_span_a_lost_anchor_no_anchors_and_an_unanswered_read_each_fall_to_the_moved_hold() {
    let whole = || vec![run(&i(10), 2), run(&i(1), 3)];
    let insert = || -> Box<dyn Fn(u64) -> Value> { Box::new(|typed| insert_at(DOC, 2, json!(["x"]), typed)) };
    let delete = || -> Box<dyn Fn(u64) -> Value> { Box::new(|typed| delete_at(DOC, 2, 2, typed)) };
    let rearrange = || -> Box<dyn Fn(u64) -> Value> { Box::new(|typed| rearrange_at(DOC, &[2, 3, 4], typed)) };
    let between = || Some(anchors(Some(&i(1)), Some(&i(2))));
    let b_and_c = || Some(spanned(Some(&i(1)), None, &[(&i(2), 2)]));
    /// A cell: its name, the image now, the burst typed at a state, its
    /// anchors, whether the image read is unanswered, the image reads made,
    /// and the why said.
    type Cell = (&'static str, Vec<Value>, Box<dyn Fn(u64) -> Value>, Option<Anchors>, bool, usize, Option<&'static str>);
    let refilled = "no longer holds the units the burst names";
    let cells: Vec<Cell> = vec![
        ("a cut span", vec![run(&i(1), 1), run(&i(10), 1), run(&i(2), 2)], insert(), between(), false, 1, Some("the span its anchors bound holds 1 positions now, not the 0 it held")),
        ("a delete's span refilled with as many other units", vec![run(&i(1), 1), run(&i(10), 2)], delete(), b_and_c(), false, 1, Some(refilled)),
        ("a rearrange's span refilled with as many other units", vec![run(&i(1), 1), run(&i(10), 2)], rearrange(), b_and_c(), false, 1, Some(refilled)),
        ("a rearrange's span rearranged", vec![run(&i(1), 1), run(&i(3), 1), run(&i(2), 1)], rearrange(), b_and_c(), false, 1, Some(refilled)),
        ("a lost anchor", vec![run(&i(10), 2), run(&i(1), 2)], insert(), Some(anchors(Some(&i(2)), Some(&i(3)))), false, 1, Some("its after anchor is in the document no longer")),
        ("an anchor at two places", vec![run(&i(10), 2), run(&i(1), 3), run(&i(1), 2)], insert(), between(), false, 1, Some("its before anchor stands at two places in the document")),
        ("anchors at the wrong edge", whole(), insert(), Some(anchors(None, Some(&i(2)))), false, 1, Some("the anchors do not bound the span the frame names")),
        ("no anchors", whole(), insert(), None, false, 0, None),
        ("a delete with no span", whole(), delete(), Some(anchors(Some(&i(1)), None)), false, 1, Some("its anchors name no span of the units it edits")),
        ("a rearrange with no span", whole(), rearrange(), Some(anchors(Some(&i(1)), None)), false, 1, Some("its anchors name no span of the units it edits")),
        ("an insert whose anchors name a span", whole(), insert(), Some(spanned(Some(&i(1)), Some(&i(2)), &[(&i(2), 1)])), false, 1, Some("the anchors name a span of units, and the frame places at a point")),
        ("a delete's span of other than its width", whole(), delete(), Some(spanned(Some(&i(1)), None, &[(&i(2), 1)])), false, 1, Some("the anchors' span names other than the 2 units")),
        ("a read the board does not answer", whole(), insert(), between(), true, 1, Some("the document's image could not be read")),
    ];
    for (cell, image, frame, anchors, unread, reads, why) in cells {
        let g = ground();
        let typed = g.fake.head();
        *g.fake.rows.lock().unwrap() = vec![json!({"at": 77, "op": "insert", "key": "ff".repeat(32), "docs": [DOC]})];
        *g.fake.image.lock().unwrap() = image;
        g.fake.image_unread.store(unread, Ordering::SeqCst);
        g.fake.move_arrangement(DOC, 77);
        let page = frame(typed);
        let OpAnswer::Answered(Ok(held)) = g.holds.send_burst(&g.session, page.clone(), anchors.clone()) else { panic!("{cell}: held") };
        crate::shapes::assert_declared("HeldAnswer", &held);
        assert_eq!((held["resp"].as_str(), held["cause"].as_str(), g.fake.sends(), g.fake.image_reads.load(Ordering::SeqCst)), (Some("held"), Some("moved"), 1, reads), "{cell}: {held}");
        let lines = g.lines();
        let verdict = arrangement_moved_on(page["op"].as_str().unwrap(), typed, 77);
        assert_eq!((lines[0]["cause"].as_str(), lines[0]["sent"].as_bool(), &lines[0]["refusal"]), (Some("moved"), Some(false), &verdict), "{cell}: the verdict on the line: {lines:?}");
        assert_eq!(lines[0]["frame"], page, "{cell}: the frame as the page composed it");
        assert_eq!(lines[0].get("anchors").cloned(), anchors.as_ref().map(Anchors::json), "{cell}: the anchors on the line");
        let said: Vec<Value> = g.rx.try_iter().filter(|e| e.name == EventName::Held).map(|e| e.data).collect();
        let [moved] = &said[..] else { panic!("{cell}: one held event: {said:?}") };
        assert_held_event_declared(moved);
        assert_eq!((moved["state"].as_str(), moved.get("cause"), &moved["hands"]), (Some("moved"), None, &json!([{"key": "other", "fingerprint": "ff".repeat(32)}])), "{cell}: {moved}");
        let talk = g.said.lock().unwrap().clone();
        match why {
            Some(why) => assert_eq!(talk.iter().filter(|l| l.starts_with(&format!("held: line 1 on {DOC} was not shifted (")) && l.contains(why)).count(), 1, "{cell}: said why, once: {talk:?}"),
            None => assert!(!talk.iter().any(|l| l.contains("was not shifted")), "{cell}: a burst without anchors is held moved without a word of the shift: {talk:?}"),
        }
        g.holds.probe("b-1");
        assert_eq!(g.fake.sends(), 1, "{cell}: the line awaits the person's act: no probe sends it");
    }
}

/// Checks that a document that keeps moving stops shifting at the deadline.
///
/// It is then held moved (skep #442, #716). Another writer's change lands as
/// each dial of the burst reaches the board, thirty seconds passing at each, so
/// every dial is refused `arrangement_moved` — each refusal a failed send of
/// the line — and every shift is exact: the line is born at the page's refused
/// dial, its clock started, and the shell shifts and dials while its first
/// failed send stands less than two minutes past — four shifts, one image read
/// each — then holds the line moved under the newest verdict, the frame as last
/// shifted, `sent` for the dials that left, the deadline said once in the
/// shell's own window; no probe sends it; and the person's `send` starts the
/// clock afresh — the next probe sends it, shifts it once and keeps it (the
/// mutant that bounds no shift loops the shell for as long as the other writer
/// writes; the one that keeps the clock at the person's send hands the line
/// straight back).
#[test]
fn a_document_that_keeps_moving_stops_shifting_at_the_deadline_and_is_held_moved() {
    let g = ground();
    let typed = g.fake.head();
    *g.fake.image.lock().unwrap() = vec![run(&i(1), 3)];
    let (fake, holds) = (Arc::clone(&g.fake), Arc::downgrade(&g.holds));
    *g.fake.at_send.lock().unwrap() = Some(Box::new(move || {
        let at = fake.next_at.fetch_add(1, Ordering::SeqCst);
        fake.move_arrangement(DOC, at);
        if let Some(holds) = holds.upgrade() {
            holds.advance(Duration::from_secs(30));
        }
    }));
    let OpAnswer::Answered(Ok(held)) = g.holds.send_burst(&g.session, insert_at(DOC, 2, json!(["x"]), typed), Some(anchors(Some(&i(1)), Some(&i(2))))) else { panic!("held moved at the deadline") };
    assert_eq!((held["resp"].as_str(), held["cause"].as_str()), (Some("held"), Some("moved")), "{held}");
    let shifts = 4;
    assert_eq!((g.fake.sends(), g.fake.image_reads.load(Ordering::SeqCst)), (shifts + 1, shifts), "the page's dial, then one shift and one dial each, thirty seconds apart, until two minutes from the first refusal");
    let lines = g.lines();
    let verdict = &lines[0]["refusal"];
    assert_eq!((lines[0]["cause"].as_str(), lines[0]["sent"].as_bool(), verdict["code"].as_str()), (Some("moved"), Some(true), Some("arrangement_moved")), "{lines:?}");
    assert_eq!(verdict["site"]["current"].as_u64(), verdict["site"]["as_of"].as_u64().map(|a| a + 1), "the newest verdict on the line: {verdict}");
    assert_eq!(lines[0]["frame"]["as_of"].as_u64(), verdict["site"]["as_of"].as_u64(), "the frame as last shifted: {lines:?}");
    assert_eq!(g.states(), ["moved"]);
    let talk = g.said.lock().unwrap().clone();
    assert_eq!(talk.iter().filter(|l| l.starts_with(&format!("held: line 1 on {DOC} was not shifted (its first failed send was ")) && l.contains(" s ago, past the two-minute deadline)")).count(), 1, "{talk:?}");
    *g.fake.at_send.lock().unwrap() = None;
    g.holds.probe("b-1");
    assert_eq!(g.fake.sends(), shifts + 1, "the line awaits the person's act");
    assert_eq!(g.holds.resolve(&g.session, 1, ResolveAct::Send).unwrap(), Resolved::HandedBack);
    g.holds.probe("b-1");
    assert_eq!((g.fake.sends(), g.fake.image_reads.load(Ordering::SeqCst)), (shifts + 3, shifts + 1), "the person's send starts the clock afresh: sent, refused once more, shifted and kept");
    assert!(g.lines().is_empty() && g.states().contains(&"kept".to_string()));
}

/// Checks that a held line lands under the board's own directory.
///
/// No line is written outside it: a burst held at a board whose directory
/// is this shell's lands in `held/<chain>/`.
#[test]
fn a_held_line_lands_under_the_boards_own_directory() {
    let g = ground();
    let answer = g.hold(&insert(DOC, json!(["hello"]), g.fake.head()), "unreachable", false);
    assert!(answer.get("unwritable").is_none(), "{answer}");
    let file = g.store.path().join("held").join("ab".repeat(32)).join("principal-1.held");
    let text = std::fs::read_to_string(&file).unwrap();
    assert!(text.lines().next().unwrap().contains("\"account\":\"1.0.1\""), "the header names the session's account: {text}");
}

/// Checks that a drop drops its own document's run and no other.
///
/// It acts on its own document's run (§4b.1's `resolve`): a refused run on
/// one document, a burst on a second held `behind` it — a standing line
/// holds every later burst, whatever its document — and the run's drop
/// leaves the second document's line standing, which the next probe sends
/// and keeps (the mutant that drops every later line, whatever its
/// document, loses the person's text on the other document).
#[test]
fn a_drop_drops_its_own_documents_run_and_no_other() {
    let g = ground();
    let verdict = json!({"resp": "rejected", "code": "out_of_bounds", "disposition": "permanent"});
    let k1 = g.hold_for(&insert(DOC, json!(["a"]), g.fake.head()), Reason::refused("out_of_bounds", verdict)).unwrap()["held"].as_u64().unwrap();
    let OpAnswer::Answered(Ok(behind)) = g.holds.send_burst(&g.session, insert(OTHER, json!(["z"]), g.fake.head()), None) else { panic!("held behind the run") };
    assert_eq!(behind["cause"], "behind", "{behind}");
    assert_eq!(g.holds.resolve(&g.session, k1, ResolveAct::Drop).unwrap(), Resolved::Dropped);
    let docs: Vec<String> = g.lines().iter().map(|l| l["doc"].as_str().unwrap_or("?").to_string()).collect();
    assert_eq!(docs, [OTHER], "the run is dropped, the other document's line stands");
    g.holds.probe("b-1");
    assert_eq!(g.fake.sends(), 1, "the other document's line is sent");
    assert!(g.lines().is_empty() && g.states().contains(&"kept".to_string()));
}

/// Checks that a refusal held nowhere is faced, a `write_busy` reissued once.
///
/// A refusal the table holds nowhere is faced at the burst's first dial
/// (§3c.4's neither), and a `write_busy` — read by its code off the 503 the
/// board answers it as — is reissued within the call, once, after the short
/// wait (§4b.1's `op` row: "reissued by the shell and reach the page as the
/// ack or the next refusal, never as `held`"): a `write_busy` the reissue
/// meets again is the next refusal, faced; one the reissue clears is the
/// ack; no burst is held (the mutants that hold either, that face the first
/// `write_busy`, or that reissue it without bound).
#[test]
fn a_refusal_the_table_holds_nowhere_is_faced_and_a_write_busy_reissued_once() {
    let g = ground();
    g.fake.op_rejected.every(json!({"resp": "rejected", "code": "credential_refused", "detail": "index_rebuilding", "disposition": "retry", "op": "insert"}));
    let OpAnswer::Answered(Err(refused)) = g.holds.send_burst(&g.session, insert(DOC, json!(["a"]), g.fake.head()), None) else { panic!("faced at the act") };
    assert_eq!((refused.name(), g.fake.sends()), ("index_rebuilding", 1), "{refused}");
    g.fake.op_rejected.clear();
    g.fake.op_refused.every((503, json!({"error": "write_busy"})));
    let OpAnswer::Answered(Err(busy)) = g.holds.send_burst(&g.session, insert(DOC, json!(["b"]), g.fake.head()), None) else { panic!("the reissue's refusal faced") };
    let v = busy.to_value();
    assert_eq!((busy.name(), v["status"].as_u64(), g.fake.sends()), ("write_busy", Some(503), 3), "reissued once: {v}");
    g.fake.op_refused.next(1, (503, json!({"error": "write_busy"})));
    let OpAnswer::Answered(Ok(ack)) = g.holds.send_burst(&g.session, insert(DOC, json!(["c"]), g.fake.head()), None) else { panic!("the reissue acked") };
    assert_eq!((ack["resp"].as_str(), g.fake.sends()), (Some("ack"), 5), "{ack}");
    assert!(g.lines().is_empty(), "no burst is held");
}

/// Checks that a first and second `durability` are reissued, a third holds.
///
/// They are reissued within the first dial's call as-is, and a third holds
/// the burst `durability` (§3c.4's rider), its line `sent: false`: two the
/// reissues clear are the ack, and a `write_busy` met beside them counts
/// nothing toward the rider (the mutants that face the first `durability`,
/// hold it before its third, or count every reissue as one).
#[test]
fn a_first_and_second_durability_are_reissued_at_the_first_dial_and_a_third_holds() {
    let g = ground();
    g.fake.op_rejected.next(2, retry("durability"));
    let OpAnswer::Answered(Ok(ack)) = g.holds.send_burst(&g.session, insert(DOC, json!(["a"]), g.fake.head()), None) else { panic!("the second reissue acked") };
    assert_eq!((ack["resp"].as_str(), g.fake.sends()), (Some("ack"), 3), "{ack}");
    g.fake.op_refused.next(1, (503, json!({"error": "write_busy"})));
    g.fake.op_rejected.next(2, retry("durability"));
    let OpAnswer::Answered(Ok(ack)) = g.holds.send_burst(&g.session, insert(DOC, json!(["b"]), g.fake.head()), None) else { panic!("a write_busy counts nothing toward the rider") };
    assert_eq!((ack["resp"].as_str(), g.fake.sends()), (Some("ack"), 7), "{ack}");
    g.fake.op_rejected.every(retry("durability"));
    let OpAnswer::Answered(Ok(held)) = g.holds.send_burst(&g.session, insert(DOC, json!(["c"]), g.fake.head()), None) else { panic!("held at the third") };
    assert_eq!((held["resp"].as_str(), held["cause"].as_str(), g.fake.sends()), (Some("held"), Some("durability"), 10), "{held}");
    assert_eq!(g.lines()[0]["sent"], false);
}

/// Checks that a burst answered `500 internal_panic` is held as a lost answer.
///
/// Its write may have committed before the board's handler panicked
/// (§3c.2, §3c.4), so the burst is answered `held`, cause `unreachable`,
/// its line `sent: true`; and the resend reads before it sends — a row
/// whose testimony the board lost, the burst's values standing at its site,
/// keeps the line with nothing sent again, and no row sends it once more
/// (the mutant that faces the 500 hands the page a refusal for text that
/// may be on the board, a retry of which lands it twice).
#[test]
fn a_burst_answered_internal_panic_is_held_sent_and_read_before_it_is_sent_again() {
    for committed in [true, false] {
        let g = ground();
        g.fake.op_refused.next(1, (500, json!({"error": "internal_panic"})));
        let OpAnswer::Answered(Ok(held)) = g.holds.send_burst(&g.session, insert(DOC, json!(["hello"]), g.fake.head()), None) else { panic!("committed {committed}: held, not faced") };
        assert_eq!((held["resp"].as_str(), held["cause"].as_str()), (Some("held"), Some("unreachable")), "committed {committed}: {held}");
        assert_eq!((g.lines()[0]["sent"].as_bool(), g.fake.sends()), (Some(true), 1), "committed {committed}: the burst may have landed");
        if committed {
            *g.fake.rows.lock().unwrap() = vec![lost_row()];
            *g.fake.text.lock().unwrap() = "hello".into();
        }
        g.holds.probe("b-1");
        let states = g.states();
        assert_eq!(g.fake.sends(), if committed { 1 } else { 2 }, "committed {committed}: sent again only where nothing landed");
        assert!(g.lines().is_empty() && states.contains(&"kept".to_string()) && !states.contains(&"moved".to_string()), "committed {committed}: {states:?}");
    }
}

/// Checks that a write the hold never holds is faced, and its ack noted.
///
/// It takes the one path a burst takes (`Holds::send`; §3c.4: "a non-burst
/// write that fails … is faced at its act"): a `permanent` refusal, a third
/// `durability` and a `500 internal_panic` — each of which holds a burst —
/// are faced, the first and the third after one send each, the second after
/// its two reissues, the third the board's verdict verbatim, and nothing is
/// held; and its ack is noted for the base, so a burst held on the document
/// it names reads from that ack's `at` (the mutants that hold a non-burst's
/// hold-class answer, and that leave its ack unnoted).
#[test]
fn a_write_the_hold_never_holds_is_faced_and_its_ack_noted() {
    let g = ground();
    let link = json!({"op": "make_link", "home": OTHER, "from": {"addrs": [OTHER]}, "to": {"addrs": [DOC]}, "ty": {"addrs": ["1.1.0.1.0.1.0.3.13"]}});
    g.fake.op_rejected.every(json!({"resp": "rejected", "code": "out_of_bounds", "disposition": "permanent", "op": "make_link"}));
    let OpAnswer::Answered(Err(refused)) = g.holds.send(&g.session, link.clone(), None) else { panic!("faced at the act") };
    assert_eq!((refused.name(), g.fake.sends()), ("out_of_bounds", 1), "{refused}");
    g.fake.op_rejected.every(retry("durability"));
    let OpAnswer::Answered(Err(refused)) = g.holds.send(&g.session, link.clone(), None) else { panic!("faced at the third") };
    assert_eq!((refused.name(), g.fake.sends()), ("durability", 4), "{refused}");
    g.fake.op_rejected.clear();
    g.fake.op_refused.next(1, (500, json!({"error": "internal_panic"})));
    let OpAnswer::Answered(Err(refused)) = g.holds.send(&g.session, link.clone(), None) else { panic!("faced, its answer lost") };
    assert_eq!((refused.name(), refused.to_value()["status"].as_u64(), g.fake.sends()), ("internal_panic", Some(500), 5), "{refused}");
    assert!(g.lines().is_empty() && g.states().is_empty(), "a write the hold never holds is held never");
    let OpAnswer::Answered(Ok(ack)) = g.holds.send(&g.session, link, None) else { panic!("acked") };
    let held = g.hold(&insert(OTHER, json!(["a"]), g.fake.head()), "unreachable", false);
    let line = g.lines().into_iter().find(|l| l["held"] == held["held"]).expect("the burst is held");
    assert_eq!(line["base"], ack["at"], "the ack is noted for the base of the next hold on its home: {line}");
}

/// Checks that the eight unholdable writes are refused under a standing hold.
///
/// §3c.4: `fork`, `version`, `stage`, `make_link`, `nullify`, `edit_link`
/// and `publish` arriving while the own node is stopped, the write path
/// poisoned or the writes halted are refused at once under the hold's own
/// name — `stopped`, `poisoned`, `halted` — naming the op, held never and
/// dialed never; a write outside the eight dials as it dials under the same
/// hold; the poisoned state is the dial's own `poisoned` answer, standing
/// until a `/health` read says writes go; and a board that does not answer
/// is no hold of the kind — the write meets the dial's own `unreachable`
/// (the mutants that dial the eight under a stop, hold them as bursts,
/// never clear the poison, or read an unreachable board as a standing
/// hold).
#[test]
fn the_eight_unholdable_writes_are_refused_under_a_standing_hold_and_dialed_elsewhere() {
    let citation = "1.1.0.1.0.1.0.3.13";
    let eight = || {
        vec![
            json!({"op": "fork", "published": true}),
            json!({"op": "version", "d_src": DOC}),
            json!({"op": "stage", "from": DOC}),
            json!({"op": "set_arrangement", "doc": DOC, "runs": [{"origin": DOC, "i_start": format!("{DOC}.0.1.1"), "width": "1"}], "as_of": 1}),
            json!({"op": "make_link", "home": OTHER, "from": {"addrs": [OTHER]}, "to": {"addrs": []}, "ty": {"addrs": [citation]}}),
            json!({"op": "nullify", "home": OTHER, "target": format!("{OTHER}.0.2.1")}),
            json!({"op": "edit_link", "original": format!("{OTHER}.0.2.1"), "d_s": OTHER, "d_a": DOC, "successor": {"from": {"addrs": []}, "to": {"addrs": []}, "ty": {"addrs": [citation]}}}),
            json!({"op": "publish", "doc": OTHER, "draft": DOC, "runs": []}),
        ]
    };
    let poisoned = || json!({"resp": "rejected", "code": "poisoned", "disposition": "retry", "op": "insert"});
    assert_eq!(UNHOLDABLE_WRITES.len(), 8);
    for cause in ["stopped", "poisoned", "halted"] {
        let g = ground();
        match cause {
            "stopped" => g.holds.set_node_stopped("b-1", true),
            "halted" => {
                g.fake.writes_halted.store(true, Ordering::SeqCst);
                g.holds.note_health("b-1", &g.session.board.health().unwrap());
            }
            _ => {
                g.fake.op_rejected.next(1, poisoned());
                let OpAnswer::Answered(Ok(held)) = g.holds.send_burst(&g.session, insert(DOC, json!(["a"]), g.fake.head()), None) else { panic!("the poisoning burst is held") };
                assert_eq!(held["cause"], "poisoned", "{held}");
            }
        }
        let sends = g.fake.sends();
        let lines = g.lines().len();
        for frame in eight() {
            let op = frame["op"].as_str().unwrap();
            assert!(UNHOLDABLE_WRITES.contains(&op), "{op} is of the eight");
            let OpAnswer::Answered(Err(refused)) = g.holds.send(&g.session, frame.clone(), None) else { panic!("{cause}: {op} is refused") };
            let v = refused.to_value();
            assert_eq!((refused.name(), v["kind"].as_str(), v["op"].as_str()), (cause, Some("shell"), Some(op)), "{cause}: {v}");
            assert_eq!(g.holds.unholdable_refusal("b-1", op).map(|r| r.name().to_string()), Some(cause.to_string()), "{cause}: the door the confirm asks");
        }
        assert_eq!((g.fake.sends(), g.lines().len()), (sends, lines), "{cause}: none of the eight is dialed or held");
        let OpAnswer::Answered(Ok(acked)) = g.holds.send(&g.session, json!({"op": "create_new_document", "account": "1.0.1"}), None) else { panic!("{cause}: a write outside the eight dials") };
        assert_eq!((acked["resp"].as_str(), g.fake.sends()), (Some("ack"), sends + 1), "{cause}: a write outside the eight dials as it dials");
    }
    // The poison ends at the read that says writes go.
    let g = ground();
    g.fake.op_rejected.next(1, poisoned());
    let OpAnswer::Answered(Ok(_)) = g.holds.send_burst(&g.session, insert(DOC, json!(["a"]), g.fake.head()), None) else { panic!("held poisoned") };
    assert!(g.holds.unholdable_refusal("b-1", "make_link").is_some(), "poisoned from the answer on");
    g.holds.note_health("b-1", &g.session.board.health().unwrap());
    assert!(g.holds.unholdable_refusal("b-1", "make_link").is_none(), "the read that says writes go ends the poison");
    // A board that does not answer is no hold of the kind.
    let g = ground();
    g.fake.op_unreachable.store(true, Ordering::SeqCst);
    assert!(g.holds.unholdable_refusal("b-1", "make_link").is_none());
    let OpAnswer::Answered(Err(refused)) = g.holds.send(&g.session, eight()[4].clone(), None) else { panic!("the dial fails as it fails") };
    assert_eq!((refused.name(), refused.to_value()["kind"].as_str()), ("unreachable", Some("unreachable")), "{refused}");
    assert!(g.lines().is_empty(), "a write the hold never holds is held never");
}

/// Checks that a death signal at a write's dial holds nothing.
///
/// The death is neither held nor faced (§3c.4): a burst and a write the
/// hold never holds each answer `OpAnswer::Died`, the session's end the
/// caller's to run, and no line is held and no `held` event said (the
/// mutant that holds the burst at the death keeps a line behind a session
/// nobody ends).
#[test]
fn a_death_signal_at_a_writes_dial_holds_nothing() {
    let g = ground();
    g.fake.op_closed.store(true, Ordering::SeqCst);
    let link = json!({"op": "make_link", "home": OTHER, "from": {"addrs": [OTHER]}, "to": {"addrs": [DOC]}, "ty": {"addrs": ["1.1.0.1.0.1.0.3.13"]}});
    assert!(matches!(g.holds.send_burst(&g.session, insert(DOC, json!(["a"]), g.fake.head()), None), OpAnswer::Died), "a burst's dial meets the death");
    assert!(matches!(g.holds.send(&g.session, link, None), OpAnswer::Died), "and a write the hold never holds");
    assert_eq!(g.fake.sends(), 2, "each dialed once");
    assert!(g.lines().is_empty() && g.states().is_empty(), "nothing held, nothing said");
}

/// Checks that `resolve(send)` answers once the lines are handed back.
///
/// It hands the document back to the automatic machine and answers at once
/// (§4b.1: "the call answers once the line is handed to the machine, never
/// after its ack"): nothing is dialed in the act and the run's lines stand
/// re-marked `behind`; the probe its caller hands the board's feed thread
/// then sends and keeps them (the mutant that probes inside the act dials
/// the board before the call answers).
#[test]
fn resolve_send_answers_once_the_lines_are_handed_back() {
    let g = ground();
    let verdict = json!({"resp": "rejected", "code": "out_of_bounds", "disposition": "permanent"});
    let k = g.hold_for(&insert(DOC, json!(["a"]), g.fake.head()), Reason::refused("out_of_bounds", verdict)).unwrap()["held"].as_u64().unwrap();
    assert_eq!(g.holds.resolve(&g.session, k, ResolveAct::Send).unwrap(), Resolved::HandedBack);
    assert_eq!((g.fake.sends(), g.fake.health_reads.load(Ordering::SeqCst)), (0, 0), "nothing is dialed in the act");
    assert_eq!(g.lines()[0]["cause"], "behind", "the run's line re-marked `behind`");
    g.holds.probe("b-1");
    assert_eq!(g.fake.sends(), 1, "the handed probe sends it");
    assert!(g.lines().is_empty() && g.states().contains(&"kept".to_string()));
}

/// Checks that a board the holds were not opened over is the caller's bug.
///
/// The one precondition of the holds — a board reference names a board they
/// were opened over — is the caller's, asked in one place: a reference
/// outside them is a bug of this crate's, stopped loudly, never read as a
/// board with nothing held.
#[test]
#[should_panic(expected = "PRECONDITION of `Holds`")]
fn a_board_the_holds_were_not_opened_over_is_the_callers_bug() {
    ground().holds.probe("b-nowhere");
}

/// Checks that a held frame is stored without its attest (§3c.2).
///
/// A burst held with one is kept and listed without it, since the resend
/// composes its attest when it sends (the mutant that stores the frame as
/// it came).
#[test]
fn a_held_frame_is_stored_without_its_attest() {
    let g = ground();
    let mut frame = insert(DOC, json!(["hello"]), g.fake.head());
    frame["attest"] = json!({"alg": "x", "sig": "00"});
    g.hold(&frame, "unreachable", false);
    let lines = g.lines();
    assert!(lines[0]["frame"].get("attest").is_none() && lines[0]["frame"]["op"] == "insert", "{lines:?}");
    let file = g.store.path().join("held").join("ab".repeat(32)).join("principal-1.held");
    let text = std::fs::read_to_string(&file).unwrap();
    assert!(!text.contains("attest"), "{text}");
}

/// Checks that a halted file refuses every act and dials nothing.
///
/// It is P38's halt at the hold (§3c.3): a principal's file written by a
/// newer skep stands untouched, and every act on it answers `store_halted`
/// naming why — the burst is not dialed, no line is held, `held(session)`
/// lists nothing, `resolve` acts on no line — so no burst is sent past a
/// file this shell may not write and none is rebuilt over (the mutants that
/// dial past a halted file, or answer an act on it as no line).
#[test]
fn a_halted_file_refuses_every_act_and_dials_nothing() {
    let store = TempDir::new().unwrap();
    let chain = "ab".repeat(32);
    HeldDir::new(store.path(), Chain::parse(&chain).unwrap()).ensure().unwrap();
    let file = store.path().join("held").join(&chain).join("principal-1.held");
    let newer = format!("{{\"type\":\"skep-held-bursts\",\"v\":2,\"board\":\"{chain}\",\"principal\":1,\"account\":\"1.0.1\"}}\n");
    std::fs::write(&file, &newer).unwrap();
    let g = ground_in(store, bare_facts(), 0);
    let OpAnswer::Answered(Err(refused)) = g.holds.send_burst(&g.session, insert(DOC, json!(["hello"]), g.fake.head()), None) else { panic!("a burst at a halted file is refused") };
    assert_eq!((refused.name(), refused.to_value()["why"].as_str()), ("store_halted", Some("newer")), "{refused}");
    assert_eq!(g.fake.sends(), 0, "nothing is dialed past a halted file");
    assert_eq!(g.holds.lines(&g.session).unwrap_err().name(), "store_halted");
    assert_eq!(g.holds.resolve(&g.session, 1, ResolveAct::Drop).unwrap_err().name(), "store_halted", "an act on a line answers the halt, never no line");
    let held = g.hold_for(&insert(DOC, json!(["x"]), g.fake.head()), Reason::of("unreachable", false));
    assert_eq!(held.unwrap_err().name(), "store_halted", "no line is held");
    assert_eq!(std::fs::read_to_string(&file).unwrap(), newer, "the halted file is never rebuilt over");
}

/// Checks that a line the store cannot copy says why and stands (§3c.3), and
/// that a line the store CAN copy for want of `H.1` alone goes to the pending
/// file (§3c.1; skep #725).
///
/// A line stands in memory ("Persist first") where no directory can be named
/// or written: at an UNCLAIMED board with no `H.1` to name its directory —
/// which holds no held text (§3c.1) — the burst is held under its own cause
/// — never `other_window`, another window's lock alone — its answer
/// `unwritable` naming the missing term, nothing written; at a file the
/// device refuses (a directory where the file would be), the device's
/// refusal rides the answer. Either line stands in the queue, and the next
/// probe resends and keeps it, unsigned at the unclaimed board, which has no
/// term to sign over (the mutant that drops `unwritable` tells the page a
/// burst a crash would lose is on disk). A board whose head record stands
/// and CANNOT be read is no such board: its line goes to the pending file
/// under the hash of the origin dialed, its answer carrying no `unwritable`
/// (the mutant that keeps such a line in memory loses it at a close).
#[test]
fn a_line_the_store_cannot_copy_says_why_and_stands() {
    let fake = Fake::new();
    fake.no_head.store(true, Ordering::SeqCst);
    fake.unclaimed.store(true, Ordering::SeqCst);
    let store = TempDir::new().unwrap();
    let facts = writer_facts(&store);
    let g = ground_over(fake, store, facts, 0);
    let answer = g.hold(&insert(DOC, json!(["hello"]), g.fake.head()), "unreachable", false);
    assert_eq!(answer["cause"], "unreachable", "{answer}");
    assert!(answer["unwritable"].as_str().is_some_and(|why| why.contains("H.1")), "the answer says why: {answer}");
    assert!(!g.store.path().join("held").exists(), "nothing is written");
    assert_eq!(g.lines().len(), 1, "the line stands");
    g.holds.probe("b-1");
    assert_eq!(g.fake.sends(), 1, "the line is resent");
    assert!(g.lines().is_empty() && g.states().contains(&"kept".to_string()));

    let g = ground();
    let file = g.store.path().join("held").join("ab".repeat(32)).join("principal-1.held");
    std::fs::create_dir(&file).unwrap();
    let answer = g.hold(&insert(DOC, json!(["hello"]), g.fake.head()), "unreachable", false);
    assert_eq!(answer["cause"], "unreachable", "{answer}");
    assert!(answer["unwritable"].is_string(), "the device's refusal rides the answer: {answer}");
    assert_eq!(g.lines().len(), 1, "the line stands");
    std::fs::remove_dir(&file).unwrap();
    g.holds.probe("b-1");
    assert_eq!(g.fake.sends(), 1, "the line is resent");
    assert!(g.lines().is_empty() && g.states().contains(&"kept".to_string()));

    // A head record that stands and cannot be read: the pending file, no
    // `unwritable`.
    let fake = Fake::new();
    *fake.head_answer.lock().unwrap() = Some((200, json!({"resp": "delivery", "items": [{"atom": "not a head record"}]})));
    let store = TempDir::new().unwrap();
    let facts = writer_facts(&store);
    let g = ground_over(fake, store, facts, 0);
    let answer = g.hold(&insert(DOC, json!(["hello"]), g.fake.head()), "unreachable", false);
    assert!(answer.get("unwritable").is_none(), "the line is on disk, in the pending file: {answer}");
    let pending = pending_file(&g);
    assert!(std::fs::read_to_string(&pending).unwrap().contains("\"values\":[\"hello\"]"), "the pending file holds the line at {}", pending.display());
    assert!(!held_file(&g).exists(), "nothing under a chain the board has not named");
}

/// Checks that a queue kept in memory joins the board's file as soon as the
/// directory is this shell's (the record's F4; `Custody::Unwritable`).
///
/// At an unclaimed board, with no `H.1` to name its directory, a line is
/// held in memory alone, `unwritable`, and refused `write_busy` at its resend
/// — reissued at the next probe, the line standing. The board then names its
/// `H.1`: the probe establishes the directory and the standing line JOINS the
/// board's file at once, its ordinal kept, with no wait for an empty queue —
/// so the next burst, held `behind` it, is copied to the file too, under the
/// next ordinal and with no `unwritable`; once both are kept the file
/// compacts and the next line recreates it (the mutant that waits for an
/// empty queue keeps every line of the outage, and every line after it, in
/// memory for a crash to lose; the one that renumbers a line into an empty
/// file hands the page an ordinal it does not hold).
#[test]
fn a_queue_kept_in_memory_joins_the_boards_file_as_soon_as_the_directory_is_this_shells() {
    let fake = Fake::new();
    fake.no_head.store(true, Ordering::SeqCst);
    fake.unclaimed.store(true, Ordering::SeqCst);
    let store = TempDir::new().unwrap();
    let facts = writer_facts(&store);
    let g = ground_over(fake, store, facts, 0);
    let first = g.hold(&insert(DOC, json!(["a"]), g.fake.head()), "unreachable", false);
    assert!(first["unwritable"].is_string(), "{first}");
    g.fake.op_refused.every((503, json!({"error": "write_busy"})));
    g.holds.probe("b-1");
    assert_eq!((g.fake.sends(), g.lines().len()), (1, 1), "the line stands, not taken at its resend");
    assert!(!g.store.path().join("held").exists(), "nothing written while the board names no H.1");
    // The board names its H.1: the probe's one head read establishes the
    // directory, and the standing line joins the file before the resend.
    g.fake.no_head.store(false, Ordering::SeqCst);
    g.fake.unclaimed.store(false, Ordering::SeqCst);
    g.holds.probe("b-1");
    let file = held_file(&g);
    assert!(std::fs::read_to_string(&file).unwrap().contains("\"values\":[\"a\"]"), "the standing line is in the board's file, with no wait for an empty queue");
    let joined = said_containing(&g, "joined the board's held file");
    assert!(joined.len() == 1 && joined[0].contains("1 held line joined") && joined[0].contains("their ordinals kept"), "{joined:?}");
    assert_eq!((g.fake.sends(), g.lines().len()), (2, 1), "resent and refused again, still standing");
    let OpAnswer::Answered(Ok(behind)) = g.holds.send_burst(&g.session, insert(DOC, json!(["b"]), g.fake.head()), None) else { panic!("held behind the standing line") };
    assert_eq!(behind["cause"], "behind", "{behind}");
    assert!(behind.get("unwritable").is_none(), "copied to the board's file: {behind}");
    let ks: Vec<u64> = g.lines().iter().map(|l| l["held"].as_u64().unwrap()).collect();
    assert_eq!(ks, [1, 2], "the joined line kept its ordinal, the next line the one after");
    assert!(std::fs::read_to_string(&file).unwrap().contains("\"values\":[\"b\"]"), "the next line is in the file too");
    g.fake.op_refused.clear();
    g.holds.probe("b-1");
    assert!(g.lines().is_empty(), "both kept");
    assert!(!file.exists(), "the file compacted away");
    let next = g.hold(&insert(DOC, json!(["c"]), g.fake.head()), "unreachable", false);
    assert!(next.get("unwritable").is_none(), "{next}");
    assert!(std::fs::read_to_string(&file).unwrap().contains("\"values\":[\"c\"]"), "the next line recreates the board's file");
}

/// Checks that no `held` event goes out when a session's open reads its file.
///
/// The open reads its principal's file (§4b.2; `EventName::Held`): the line
/// the file holds is listed by `held(session)` at once, and nothing of it
/// is said on the bus (the mutant that announces each document at the open
/// says a state no act of the page's moved).
#[test]
fn no_held_event_goes_out_when_a_sessions_open_reads_its_file() {
    let store = TempDir::new().unwrap();
    let dir = HeldDir::new(store.path(), Chain::parse(&"ab".repeat(32)).unwrap());
    dir.ensure().unwrap();
    let Opened::Live { mut queue, .. } = dir.open_file(1, "1.0.1").unwrap() else { panic!("a fresh file") };
    // A line written into the file by hand, at base 0, typed at genesis: no
    // board stands behind it yet.
    assert!(queue.hold(DOC, None, 0, insert(DOC, json!(["a"]), 0), None, Reason::of("unreachable", false)).unwrap().unwritten.is_none());
    drop(queue);
    let g = ground_in(store, bare_facts(), 0);
    assert_eq!(g.lines().len(), 1, "the session's open lists the line");
    assert!(g.states().is_empty(), "and says nothing of it");
}

/// Checks that a misplaced held file is set aside and said on `Talk`.
///
/// It is said in the shell's own window (§3c.3; P39): a principal's file
/// whose header names another board's chain, found at its session's open,
/// is moved aside under `aside_name`'s form, the queue opened fresh, and the
/// aside's path said on `Talk` — and on no event the page reads (the mutant
/// that sets the file aside unsaid leaves the person's held text gone from
/// every list with nothing said).
#[test]
fn a_misplaced_held_file_is_set_aside_and_said_on_talk() {
    let store = TempDir::new().unwrap();
    let (ours, theirs) = (Chain::parse(&"ab".repeat(32)).unwrap(), Chain::parse(&"ef".repeat(32)).unwrap());
    HeldDir::new(store.path(), ours).ensure().unwrap();
    let held = store.path().join("held").join(ours.to_string());
    let header = format!("{{\"type\":\"skep-held-bursts\",\"v\":1,\"board\":\"{theirs}\",\"principal\":1,\"account\":\"1.0.1\"}}\n");
    std::fs::write(held.join("principal-1.held"), header).unwrap();
    let g = ground_in(store, bare_facts(), 0);
    let aside = held.join(skep_search::aside_name("principal-1.held", &theirs, 1));
    assert!(aside.is_file(), "the misplaced file is set aside at {}", aside.display());
    assert!(g.lines().is_empty(), "the principal's queue is opened fresh");
    let said = g.said.lock().unwrap().clone();
    let line = format!("held: principal 1's held file named another board or principal, and is set aside at {}", aside.display());
    assert!(said.contains(&line), "{said:?}");
    let events: Vec<String> = g.rx.try_iter().map(|e| e.data.to_string()).collect();
    assert!(events.iter().all(|data| !data.contains("aside")), "the aside crossed to the page: {events:?}");
}

/// Returns an insert of one atom, its frame's JSON exactly `bytes` long.
///
/// It is one value, so no value budget speaks before the frame's own.
fn sized_frame(bytes: usize) -> Value {
    // Typed at genesis on both sides of the subtraction: the typed state's
    // digits are part of the frame's length, and this frame is about its
    // length alone.
    let overhead = json_len(&insert(DOC, json!([{"atom": ""}]), 0));
    insert(DOC, json!([{"atom": "x".repeat(bytes - overhead)}]), 0)
}

/// Checks that the burst's door refuses a burst the board takes at no send.
///
/// It refuses at the act and holds none of it: a frame one byte past the
/// board's frame cap — at a running board and at a stopped one, where it
/// would otherwise be held without a dial — while a frame at the cap
/// exactly is dialed and acked; a burst naming no document, an element
/// where its document goes, or a document in another spelling, refused
/// `malformed_args` undialed, and behind a standing line unheld (the mutants
/// that drop the size or the document check dial a frame no send of which
/// the board takes, and hold a line none could ever clear, every later
/// burst of the principal behind it). The door's own arithmetic, under a
/// session whose key attests no insert — a bare one, so the door keeps no
/// attest's room; the shell's `op` row refuses such a session's write
/// before it reaches the hold.
#[test]
fn a_burst_the_board_takes_at_no_send_is_refused_at_the_bursts_door() {
    let g = bare_ground();
    for stopped in [false, true] {
        g.holds.set_node_stopped("b-1", stopped);
        let OpAnswer::Answered(Err(refused)) = g.holds.send_burst(&g.session, sized_frame(MAX_FRAME_BYTES + 1), None) else { panic!("refused at the burst's door") };
        let v = refused.to_value();
        assert_eq!((refused.name(), v["bytes"].as_u64(), v["cap"].as_u64()), ("frame_too_large", Some(MAX_FRAME_BYTES as u64 + 1), Some(MAX_FRAME_BYTES as u64)), "{v}");
        assert!(g.lines().is_empty() && g.fake.sends() == 0, "stopped {stopped}: nothing held, nothing sent");
    }
    g.holds.set_node_stopped("b-1", false);
    let undocumented = [json!({"op": "insert", "values": ["b"]}), insert("1.0.1.0.1.0.1.1", json!(["b"]), g.fake.head()), insert("01.0.1.0.1", json!(["b"]), g.fake.head())];
    for frame in &undocumented {
        let OpAnswer::Answered(Err(refused)) = g.holds.send_burst(&g.session, frame.clone(), None) else { panic!("refused at the burst's door: {frame}") };
        assert_eq!(refused.name(), "malformed_args", "{frame}");
    }
    assert_eq!(g.fake.sends(), 0, "nothing the burst's door refuses is dialed");
    let OpAnswer::Answered(Ok(ack)) = g.holds.send_burst(&g.session, sized_frame(MAX_FRAME_BYTES), None) else { panic!("a frame at the cap is sent") };
    assert_eq!((ack["resp"].as_str(), g.fake.sends()), (Some("ack"), 1));
    g.hold(&insert(DOC, json!(["a"]), g.fake.head()), "unreachable", false);
    for frame in &undocumented {
        let OpAnswer::Answered(Err(refused)) = g.holds.send_burst(&g.session, frame.clone(), None) else { panic!("refused at the burst's door: {frame}") };
        assert_eq!(refused.name(), "malformed_args", "{frame}");
    }
    assert_eq!(g.lines().len(), 1, "nothing was held behind the standing line");
}

/// Checks that a signed session's burst keeps room for its attest.
///
/// Under a session whose key attests an insert, the burst's door keeps the
/// room the attest of every resend takes, and asks the composer's terms of
/// the frame alone: a frame at the cap unattested, which no attested send
/// fits, is refused `frame_too_large`; one the room fits is held behind a
/// standing line; and an insert whose values the composer cannot spell is
/// refused `attest_not_composed` before it is held (the mutant that leaves
/// no room holds a burst every resend of which the board refuses `413`).
#[test]
fn a_signed_sessions_burst_keeps_room_for_its_attest() {
    let g = ground_in(TempDir::new().unwrap(), keyed_facts(), 0);
    g.hold(&insert(DOC, json!(["a"]), g.fake.head()), "unreachable", false);
    let OpAnswer::Answered(Err(refused)) = g.holds.send_burst(&g.session, sized_frame(MAX_FRAME_BYTES), None) else { panic!("refused at the burst's door") };
    assert_eq!(refused.name(), "frame_too_large", "{refused}");
    let OpAnswer::Answered(Ok(held)) = g.holds.send_burst(&g.session, sized_frame(MAX_FRAME_BYTES - attest_room()), None) else { panic!("held behind") };
    assert_eq!(held["cause"], "behind", "{held}");
    let OpAnswer::Answered(Err(refused)) = g.holds.send_burst(&g.session, insert(DOC, json!([7]), g.fake.head()), None) else { panic!("refused at the burst's door") };
    assert_eq!(refused.name(), "attest_not_composed", "{refused}");
    assert_eq!(g.lines().len(), 2, "the one admitted burst held, and nothing else");
}

/// Checks that a page-supplied attest is counted out of every resend.
///
/// It is counted at `Burst::admit`: the held line keeps the frame without
/// it, and every resend under a session whose key attests the kind carries
/// the shell's own — so a frame riding the page's attest is measured as its
/// bytes stripped of that member and grown by the room the shell's takes:
/// at the cap it is held, one byte past it refused `frame_too_large` (the
/// mutant that strips nothing refuses a burst every resend of which fits;
/// the one that strips past the member holds a burst no resend of which
/// does).
#[test]
fn a_page_supplied_attest_is_counted_out_of_every_resend() {
    let g = ground_in(TempDir::new().unwrap(), keyed_facts(), 0);
    g.hold(&insert(DOC, json!(["a"]), g.fake.head()), "unreachable", false);
    let carrying = |bytes: usize| {
        let mut frame = sized_frame(bytes);
        frame["attest"] = json!({"alg": "x", "sig": "00"});
        frame
    };
    let OpAnswer::Answered(Ok(held)) = g.holds.send_burst(&g.session, carrying(MAX_FRAME_BYTES - attest_room()), None) else { panic!("held behind") };
    assert_eq!(held["cause"], "behind", "{held}");
    let OpAnswer::Answered(Err(refused)) = g.holds.send_burst(&g.session, carrying(MAX_FRAME_BYTES - attest_room() + 1), None) else { panic!("refused at the burst's door") };
    let v = refused.to_value();
    assert_eq!((refused.name(), v["bytes"].as_u64()), ("frame_too_large", Some(MAX_FRAME_BYTES as u64 + 1)), "{v}");
    assert_eq!(g.lines().len(), 2, "the one admitted burst held, and nothing else");
}

/// Checks that a head read that halts holds the burst unsent.
///
/// Under a session whose key attests an insert, the read of the board's `H.1`
/// the attest signs over answered with the death signal — no session's
/// answer, a token-free read's halt — holds the burst `head_unreadable`,
/// `sent: false`, its refusal naming the halt, with nothing dialed (SP-14; the
/// mutant that reads the halt as no record sends the burst unsigned, and the
/// one that faces it as the composer's own refusal loses the burst).
#[test]
fn a_head_read_that_halts_holds_the_burst_unsent() {
    let fake = Fake::new();
    fake.head_closed.store(true, Ordering::SeqCst);
    let g = ground_over(fake, TempDir::new().unwrap(), keyed_facts(), 0);
    let OpAnswer::Answered(Ok(held)) = g.holds.send_burst(&g.session, insert(DOC, json!(["a"]), g.fake.head()), None) else { panic!("held, nothing sent") };
    assert_eq!((held["resp"].as_str(), held["cause"].as_str()), (Some("held"), Some("head_unreadable")), "{held}");
    let lines = g.lines();
    let refusal = &lines[0]["refusal"];
    assert_eq!((lines[0]["sent"].as_bool(), refusal["name"].as_str()), (Some(false), Some("head_unreadable")), "{lines:?}");
    assert!(refusal["cause"].as_str().is_some_and(|cause| cause.contains("met the death signal")), "the refusal names the halt: {refusal}");
    assert_eq!(g.fake.sends(), 0, "nothing dialed");
}

/// Checks that a signed burst over an unreadable head record is held unsent,
/// on disk, and sent once the record reads.
///
/// A writer's attest signs over the board's head record (`H.1`). Where the
/// record stands and cannot be read — a content item, an atom of no JSON, a
/// record of another type, of no position or of no chain, a read the board
/// refuses or answers `500` — or the board names a claimant and serves none,
/// as an empty delivery or `doc_not_registered`, and where an unclaimed
/// board's record is damaged, the burst is held `head_unreadable` with nothing
/// dialed. The line goes to the PENDING file under the hash of the origin
/// dialed, the answer carrying no `unwritable` (skep #725); the line, `sent:
/// false`, carries the refusal that says why; the person's `send` on it is
/// `not_resolvable`, since no act of theirs makes the head read; and a probe
/// SKIPS it — nothing dialed, and the `held` event not said again, the
/// `holding` of the hold the one event (skep #727). Once the record reads,
/// the next probe joins the line into the board's own file, sends it
/// attested and keeps it, the pending file gone (SP-14; the mutants that read
/// a record that cannot be read as no record send the person's text
/// unsigned, the one that faces the refusal at the act loses the burst, and
/// the one that keeps the line in memory loses it at a close).
#[test]
fn a_signed_burst_over_an_unreadable_head_record_is_held_and_sent_once_it_reads() {
    let delivery = |items: Value| Some((200, json!({"resp": "delivery", "items": items})));
    let atom = |record: Value| delivery(json!([{"atom": record.to_string()}]));
    let rejected = |code: &str| Some((200, json!({"resp": "rejected", "code": code, "disposition": "permanent", "op": "retrieve_v"})));
    let chain = "ab".repeat(32);
    let (refused, named) = ("refused the read of its head record", "names 1.0.1 its claimant and serves no head record");
    let cells = [
        ("a content item", delivery(json!([{"content": "x"}])), false, false, "its value is no record atom"),
        ("an atom of no JSON", delivery(json!([{"atom": "not a head record"}])), false, false, "its value is no JSON"),
        ("a record of another type", atom(json!({"type": "skep-other", "position": 1, "chain": chain})), false, false, "a record of another type"),
        ("a record of no position", atom(json!({"type": "skep-head", "chain": chain})), false, false, "it names no position"),
        ("a record of no chain", atom(json!({"type": "skep-head", "position": 1})), false, false, "it names no chain"),
        ("a read the board refuses", rejected("out_of_bounds"), false, false, refused),
        ("a read answered `500`", Some((500, json!({"error": "internal_panic"}))), false, false, refused),
        ("an empty delivery at a claimed board", None, true, false, named),
        ("`doc_not_registered` at a claimed board", rejected("doc_not_registered"), false, false, named),
        ("a damaged record at an unclaimed board", delivery(json!([{"atom": "not a head record"}])), false, true, "its value is no JSON"),
    ];
    for (cell, head, no_head, unclaimed, why) in cells {
        let fake = Fake::new();
        *fake.head_answer.lock().unwrap() = head;
        fake.no_head.store(no_head, Ordering::SeqCst);
        fake.unclaimed.store(unclaimed, Ordering::SeqCst);
        let store = TempDir::new().unwrap();
        let facts = writer_facts(&store);
        let g = ground_over(fake, store, facts, 0);
        let OpAnswer::Answered(Ok(held)) = g.holds.send_burst(&g.session, insert(DOC, json!(["hello"]), g.fake.head()), None) else { panic!("{cell}: held, never sent unsigned") };
        crate::shapes::assert_declared("HeldAnswer", &held);
        assert_eq!((held["resp"].as_str(), held["cause"].as_str()), (Some("held"), Some("head_unreadable")), "{cell}: {held}");
        assert!(held.get("unwritable").is_none(), "{cell}: the line is on disk, in the pending file: {held}");
        let pending = pending_file(&g);
        assert!(std::fs::read_to_string(&pending).unwrap().contains("\"values\":[\"hello\"]"), "{cell}: the pending file holds the line at {}", pending.display());
        let lines = g.lines();
        let refusal = &lines[0]["refusal"];
        assert_eq!((lines[0]["sent"].as_bool(), refusal["name"].as_str(), refusal["kind"].as_str()), (Some(false), Some("head_unreadable"), Some("halt")), "{cell}: {lines:?}");
        assert!(refusal["cause"].as_str().is_some_and(|cause| cause.contains(why)), "{cell}: the refusal says why: {refusal}");
        assert_eq!((g.fake.sends(), g.states()), (0, vec!["holding".to_string()]), "{cell}: nothing dialed");
        let k = lines[0]["held"].as_u64().unwrap();
        assert_eq!(g.holds.resolve(&g.session, k, ResolveAct::Send).unwrap_err().name(), "not_resolvable", "{cell}: no act of the person's makes the head read");
        g.holds.probe("b-1");
        assert_eq!((g.fake.sends(), g.states()), (0, Vec::<String>::new()), "{cell}: skipped: nothing sent, nothing said again");
        *g.fake.head_answer.lock().unwrap() = None;
        g.fake.no_head.store(false, Ordering::SeqCst);
        g.holds.probe("b-1");
        let sent = g.fake.sends.lock().unwrap().clone();
        assert!(sent.len() == 1 && sent[0].get("attest").is_some(), "{cell}: sent once the record reads, attested: {sent:?}");
        assert!(g.lines().is_empty() && g.states().contains(&"kept".to_string()), "{cell}: and kept");
        assert!(!pending.exists(), "{cell}: the pending file joined the board's file and is gone");
    }
}

/// Checks that a garbled head answer holds the burst `head_unreadable`, never
/// `unreachable` (skep #728).
///
/// The head read answered — a `200` whose body is no JSON, as a proxy's page
/// is, or an answer past the client's cap — so the board was reached and its
/// head is what cannot be read: the burst is held `head_unreadable`, its
/// refusal's cause "served garbled" with the error, its line in the pending
/// file, nothing dialed. A read whose answer was LOST stays `unreachable`
/// (`an_unanswered_read_the_attest_needs_holds_the_burst_unsent`): the board
/// may be away (the mutant that reads a garbled answer as a lost one points
/// the person at the network for a board that answered, and retries the line
/// at every probe).
#[test]
fn a_garbled_head_answer_holds_the_burst_head_unreadable_never_unreachable() {
    for (cell, garbled, too_large) in [("a 200 of no JSON", true, false), ("an answer past the cap", false, true)] {
        let fake = Fake::new();
        fake.head_garbled.store(garbled, Ordering::SeqCst);
        fake.head_too_large.store(too_large, Ordering::SeqCst);
        let store = TempDir::new().unwrap();
        let facts = writer_facts(&store);
        let g = ground_over(fake, store, facts, 0);
        let OpAnswer::Answered(Ok(held)) = g.holds.send_burst(&g.session, insert(DOC, json!(["a"]), g.fake.head()), None) else { panic!("{cell}: held, nothing sent") };
        assert_eq!((held["resp"].as_str(), held["cause"].as_str()), (Some("held"), Some("head_unreadable")), "{cell}: {held}");
        let lines = g.lines();
        let refusal = &lines[0]["refusal"];
        assert_eq!((lines[0]["sent"].as_bool(), refusal["name"].as_str()), (Some(false), Some("head_unreadable")), "{cell}: {lines:?}");
        assert!(refusal["cause"].as_str().is_some_and(|cause| cause.contains("served garbled")), "{cell}: the board's fault, named: {refusal}");
        assert!(pending_file(&g).is_file(), "{cell}: in the pending file, never memory alone");
        assert_eq!(g.fake.sends(), 0, "{cell}: nothing dialed");
    }
}

/// Checks that a line held `head_unreadable` is dropped by `resolve(drop)` and
/// refused `resolve(send)` (skep #726).
///
/// The board's head may never be repaired, so the person may give such a
/// write up: the drop is admitted, and drops the line AND every later line of
/// its document — a later burst was composed against the page's text with the
/// dropped one in it, so sent alone it would land off — the other document's
/// line standing; the `held` event says the document kept with no line; the
/// `done … dropped` lines are on the pending file; nothing is dialed. `send`
/// stays `not_resolvable`: no act of the person's makes the head read (the
/// mutant that refuses the drop leaves the queue to fill behind a line no one
/// can clear; the one that admits `send` dials a write it cannot sign).
#[test]
fn a_line_held_head_unreadable_is_dropped_by_resolve_drop_and_refused_resolve_send() {
    let fake = Fake::new();
    fake.head_garbled.store(true, Ordering::SeqCst);
    let store = TempDir::new().unwrap();
    let facts = writer_facts(&store);
    let g = ground_over(fake, store, facts, 0);
    let OpAnswer::Answered(Ok(head)) = g.holds.send_burst(&g.session, insert(DOC, json!(["a"]), g.fake.head()), None) else { panic!("held, nothing sent") };
    assert_eq!(head["cause"], "head_unreadable", "{head}");
    let k = head["held"].as_u64().unwrap();
    let OpAnswer::Answered(Ok(behind)) = g.holds.send_burst(&g.session, insert(DOC, json!(["b"]), g.fake.head()), None) else { panic!("held behind") };
    let OpAnswer::Answered(Ok(other)) = g.holds.send_burst(&g.session, insert(OTHER, json!(["c"]), g.fake.head()), None) else { panic!("held behind") };
    assert_eq!((behind["cause"].as_str(), other["cause"].as_str()), (Some("behind"), Some("behind")));
    let _ = g.states();
    assert_eq!(g.holds.resolve(&g.session, k, ResolveAct::Send).unwrap_err().name(), "not_resolvable", "no act of the person's makes the head read");
    assert_eq!(g.holds.resolve(&g.session, k, ResolveAct::Drop).unwrap(), Resolved::Dropped, "the drop is admitted");
    let docs: Vec<String> = g.lines().iter().map(|l| l["doc"].as_str().unwrap().to_string()).collect();
    assert_eq!(docs, [OTHER], "the line and every later line of its document dropped; the other document's stands");
    let events: Vec<Value> = g.rx.try_iter().filter(|e| e.name == EventName::Held).map(|e| e.data).collect();
    assert_eq!(events.len(), 1, "{events:?}");
    assert_eq!((events[0]["doc"].as_str(), events[0]["held"].as_u64(), events[0]["state"].as_str()), (Some(DOC), Some(0), Some("kept")), "{events:?}");
    let text = std::fs::read_to_string(pending_file(&g)).unwrap();
    assert_eq!(text.matches("\"as\":\"dropped\"").count(), 2, "both drops on the pending file: {text}");
    assert_eq!(g.fake.sends(), 0, "nothing dialed");
}

/// Checks that a write the hold never holds is refused over an unreadable head
/// record.
///
/// A signed session's `make_link` over a head record that stands and cannot be
/// read is refused `head_unreadable`, the halt's face naming why the record
/// could not be read, with nothing dialed and nothing held (SP-14; the mutant
/// that reads the record as none sends the link unsigned).
#[test]
fn a_write_the_hold_never_holds_is_refused_over_an_unreadable_head_record() {
    let fake = Fake::new();
    *fake.head_answer.lock().unwrap() = Some((200, json!({"resp": "delivery", "items": [{"atom": "not a head record"}]})));
    let store = TempDir::new().unwrap();
    let facts = writer_facts(&store);
    let g = ground_over(fake, store, facts, 0);
    let link = json!({"op": "make_link", "home": OTHER, "from": {"addrs": [OTHER]}, "to": {"addrs": [DOC]}, "ty": {"addrs": ["1.1.0.1.0.1.0.3.13"]}});
    let OpAnswer::Answered(Err(refused)) = g.holds.send(&g.session, link, None) else { panic!("refused, never sent unsigned") };
    let v = refused.to_value();
    assert_eq!((refused.name(), v["kind"].as_str()), ("head_unreadable", Some("halt")), "{v}");
    assert!(v["cause"].as_str().is_some_and(|cause| cause.contains("its value is no JSON")), "the refusal says why: {v}");
    assert_eq!(g.fake.sends(), 0, "nothing dialed");
    assert!(g.lines().is_empty() && g.states().is_empty(), "nothing held, nothing said");
}

/// Checks that an unclaimed board with no head record takes a signed write
/// unsigned.
///
/// It is the one board a signed write goes out unsigned at: no claimant named
/// and no head record served, so no board term stands to sign over, and the
/// burst is dialed as it stands, no `attest` riding it, and acked (the mutant
/// that refuses every board serving no record takes no signed write at a board
/// before its claim).
#[test]
fn an_unclaimed_board_with_no_head_record_takes_a_signed_write_unsigned() {
    let fake = Fake::new();
    fake.no_head.store(true, Ordering::SeqCst);
    fake.unclaimed.store(true, Ordering::SeqCst);
    let store = TempDir::new().unwrap();
    let facts = writer_facts(&store);
    let g = ground_over(fake, store, facts, 0);
    let OpAnswer::Answered(Ok(ack)) = g.holds.send_burst(&g.session, insert(DOC, json!(["hello"]), g.fake.head()), None) else { panic!("sent and answered") };
    assert_eq!(ack["resp"], "ack", "{ack}");
    let sent = g.fake.sends.lock().unwrap().clone();
    assert!(sent.len() == 1 && sent[0].get("attest").is_none(), "sent as it stands, unsigned: {sent:?}");
    assert!(g.lines().is_empty() && g.states().is_empty(), "nothing held");
}

/// Checks that an unanswered read the attest needs holds the burst unsent.
///
/// It holds the burst like the dial's own failure — and `sent: false`,
/// since the write never left (`Dialed`'s `From<Unattested>`): under a
/// session whose key attests an insert, the read of the board's `H.1` the
/// attest signs over meets a transport fault the table reads as a lost
/// answer, and the burst is held `unreachable`, its line unsent and nothing
/// dialed (the mutant that faces the read's failure loses the burst; the
/// one that keeps the table's `sent` sends the resend to read for a landing
/// that never happened).
#[test]
fn an_unanswered_read_the_attest_needs_holds_the_burst_unsent() {
    let fake = Fake::new();
    fake.head_unreachable.store(true, Ordering::SeqCst);
    let g = ground_over(fake, TempDir::new().unwrap(), keyed_facts(), 0);
    let OpAnswer::Answered(Ok(held)) = g.holds.send_burst(&g.session, insert(DOC, json!(["a"]), g.fake.head()), None) else { panic!("held, nothing sent") };
    assert_eq!((held["resp"].as_str(), held["cause"].as_str()), (Some("held"), Some("unreachable")), "{held}");
    let lines = g.lines();
    assert_eq!(lines[0]["sent"], false, "the write never left: {lines:?}");
    assert_eq!(g.fake.sends(), 0, "nothing dialed");
}

/// Checks that a burst the queue has no room for is refused `held_full`.
///
/// It is the queue's budget at the hold: with the principal's standing
/// frames and anchors at the budget — one burst at the board's frame cap
/// less ten bytes, its anchors at theirs — the next burst is refused
/// `held_full` — no line, no `held` event — and its answer names the bytes
/// held against the queue's cap (the mutant that drops the queue's count
/// holds a page's bursts without bound). The queue's own budget, under a
/// session whose key attests no insert — a bare one, its door keeping no
/// attest's room, so one burst fills the queue.
#[test]
fn a_burst_the_queue_has_no_room_for_is_refused_held_full() {
    let g = bare_ground();
    g.hold_anchored(&sized_frame(MAX_FRAME_BYTES - 10), anchors_of_len(MAX_ANCHOR_BYTES), "unreachable", false);
    let _ = g.states();
    let OpAnswer::Answered(Err(refused)) = g.holds.send_burst(&g.session, insert(DOC, json!(["b"]), g.fake.head()), None) else { panic!("refused, not held") };
    let v = refused.to_value();
    assert_eq!((refused.name(), v["held_bytes"].as_u64(), v["cap"].as_u64()), ("held_full", Some(MAX_HELD_BYTES as u64 - 10), Some(MAX_HELD_BYTES as u64)), "{v}");
    assert_eq!(g.lines().len(), 1, "nothing more held");
    assert!(g.states().is_empty(), "no `held` event for a burst not held");
    assert_eq!(g.fake.sends(), 0);
}

/// Checks that a burst's anchors spend the queue's budget beside its frame.
///
/// Behind one refused run, three small bursts on three documents, each
/// carrying anchors of three quarters of `held::MAX_ANCHOR_BYTES`, sent by
/// the burst's write path: two are held `behind`, and the third — its frame
/// a few bytes, its anchors carrying the queue past `held::MAX_HELD_BYTES` —
/// is refused `held_full`, naming its anchors' bytes against the queue's
/// cap: no line, no `held` event, nothing dialed (the mutant that counts
/// frames alone holds a page's anchors without bound, every one copied to
/// disk and read back at each launch).
#[test]
fn a_bursts_anchors_spend_the_queues_budget_beside_its_frame() {
    let g = bare_ground();
    let verdict = json!({"resp": "rejected", "code": "out_of_bounds", "disposition": "permanent"});
    g.hold_for(&insert(DOC, json!(["a"]), g.fake.head()), Reason::refused("out_of_bounds", verdict)).unwrap();
    let anchors = anchors_of_len(MAX_ANCHOR_BYTES * 3 / 4);
    let send = |doc: &str| g.holds.send_burst(&g.session, delete(doc, g.fake.head()), Some(anchors.clone()));
    for doc in ["1.0.1.0.2", "1.0.1.0.3"] {
        let OpAnswer::Answered(Ok(held)) = send(doc) else { panic!("held behind the refused run") };
        assert_eq!(held["cause"], "behind", "{held}");
    }
    let _ = g.states();
    let OpAnswer::Answered(Err(refused)) = send("1.0.1.0.4") else { panic!("refused, not held") };
    let v = refused.to_value();
    let anchor_bytes = (MAX_ANCHOR_BYTES * 3 / 4) as u64;
    assert_eq!((refused.name(), v["anchor_bytes"].as_u64(), v["cap"].as_u64()), ("held_full", Some(anchor_bytes), Some(MAX_HELD_BYTES as u64)), "{v}");
    assert_eq!(g.lines().len(), 3, "nothing more held");
    assert!(g.states().is_empty(), "no `held` event for a burst not held");
    assert_eq!(g.fake.sends(), 0, "nothing dialed");
}

/// Checks that a burst past the queue's line budget is refused `held_full`.
///
/// It is the queue's line budget at the hold: behind one refused run, small
/// bursts on as many documents held `behind` until the principal's queue
/// stands at `held::MAX_HELD_LINES` — their bytes a few hundred kilobytes,
/// far under the frames' budget — and the next burst refused `held_full`,
/// naming the lines held and the line budget: no line, no `held` event,
/// nothing dialed (the mutant that counts bytes alone holds a quarter of a
/// million such bursts, and the resend walks each past the others).
#[test]
fn a_burst_past_the_queues_line_budget_is_refused_held_full() {
    let fake = Fake::new();
    fake.no_head.store(true, Ordering::SeqCst);
    let g = ground_over(fake, TempDir::new().unwrap(), bare_facts(), 0);
    let verdict = json!({"resp": "rejected", "code": "out_of_bounds", "disposition": "permanent"});
    g.hold_for(&insert(DOC, json!(["a"]), g.fake.head()), Reason::refused("out_of_bounds", verdict)).unwrap();
    for n in 1..MAX_HELD_LINES {
        g.hold(&delete(&format!("1.0.1.0.{}", 100 + n), g.fake.head()), "behind", false);
    }
    let _ = g.rx.try_iter().count();
    let OpAnswer::Answered(Err(refused)) = g.holds.send_burst(&g.session, delete("1.0.1.0.99", g.fake.head()), None) else { panic!("refused, not held") };
    let v = refused.to_value();
    assert_eq!((refused.name(), v["held_lines"].as_u64(), v["line_cap"].as_u64()), ("held_full", Some(MAX_HELD_LINES as u64), Some(MAX_HELD_LINES as u64)), "{v}");
    assert_eq!(g.lines().len(), MAX_HELD_LINES, "nothing more held");
    assert!(g.states().is_empty(), "no `held` event for a burst not held");
    assert_eq!(g.fake.sends(), 0, "nothing dialed");
}

/// The ground over two boards, `b-1` and `b-2`, of their own chains.
///
/// It holds the holds over both, a writer's session of principal 1 at each,
/// under one key — `sessions[0]` at `b-1`, `sessions[1]` at `b-2` — opened
/// as the shell opens them, each board's fake, and the store directory kept
/// for the ground's life.
struct TwoBoards {
    holds: Arc<Holds>,
    sessions: Vec<Arc<SessionEntry>>,
    fakes: [Arc<Fake>; 2],
    store: TempDir,
}

fn two_boards() -> TwoBoards {
    let store = TempDir::new().unwrap();
    let fakes = [Fake::on_chain(&"ab".repeat(32)), Fake::on_chain(&"cd".repeat(32))];
    let boards: Vec<Arc<BoardEntry>> = fakes
        .iter()
        .enumerate()
        .map(|(i, fake)| Arc::new(BoardEntry { reference: format!("b-{}", i + 1), board: Arc::new(Board::new(Origin::parse(&format!("http://127.0.0.1:{}", i + 1)).unwrap(), Arc::clone(fake))) }))
        .collect();
    let table = Arc::new(Sessions::new(None, Arc::new(|_: &str| {})));
    let keys = Arc::new(FileStore::open(store.path().join("store")));
    let holds = Holds::new(Arc::clone(&table), Arc::new(EventBus::new()), keys, store.path().to_path_buf(), Arc::new(|_: &str| {}), boards.iter().cloned());
    let facts = writer_facts(&store);
    let sessions = boards
        .iter()
        .map(|entry| {
            let session = table.register(entry, Open { token: Token::parse(&"9f".repeat(16)).unwrap(), facts: facts.clone(), opened_at: 0 }, &mut NoSupplements);
            holds.open_session(&session);
            session
        })
        .collect();
    TwoBoards { holds, sessions, fakes, store }
}

/// Checks that a burst at one board waits on no other board's hold.
///
/// Each board's hold is its own lock: with one board's hold held — as a
/// burst's synced append, or a file's read at a session's open, holds it —
/// a burst at another board is dialed and acked without waiting (the mutant
/// that puts every board's hold under one lock makes it wait the other
/// board out), and dialed at the board its session stands at, the other
/// board seeing nothing of it.
#[test]
fn a_burst_at_one_board_waits_on_no_other_boards_hold() {
    let TwoBoards { holds, sessions, fakes, store: _store } = two_boards();
    let parked = holds.lock("b-1");
    let (finished, answer) = thread::scope(|s| {
        let other = s.spawn(|| holds.send_burst(&sessions[1], insert(DOC, json!(["z"]), fakes[1].head()), None));
        let deadline = Instant::now() + Duration::from_secs(5);
        while !other.is_finished() && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(5));
        }
        let finished = other.is_finished();
        // The parked hold is let go before any assertion, so a failure never
        // hangs here.
        drop(parked);
        (finished, other.join().unwrap())
    });
    assert!(finished, "a burst at b-2 waited on b-1's hold");
    let OpAnswer::Answered(Ok(ack)) = answer else { panic!("the burst was answered") };
    assert_eq!(ack["resp"], "ack", "{ack}");
    assert_eq!((fakes[0].sends(), fakes[1].sends()), (0, 1), "the burst is dialed at the board its session stands at");
}

/// Checks that a session's held line is kept at the board it stands at.
///
/// A burst held under the session at b-2 lands in b-2's `held/<chain>/` and
/// lists under that session alone — the session carries the board it
/// stands at, so no caller pairs it with another.
#[test]
fn a_sessions_held_line_is_kept_at_the_board_it_stands_at() {
    let TwoBoards { holds, sessions, store, fakes } = two_boards();
    let held = holds.hold(&sessions[1], Burst::admit(insert(DOC, json!(["z"]), fakes[1].head()), &sessions[1]).unwrap(), Reason::of("unreachable", false), sessions[1].opened_at).unwrap();
    assert_eq!(held["resp"], "held", "{held}");
    let file = |chain: &str| store.path().join("held").join(chain).join("principal-1.held");
    assert!(file(&"cd".repeat(32)).is_file() && !file(&"ab".repeat(32)).exists(), "the line is kept in b-2's directory alone");
    assert_eq!(holds.lines(&sessions[1]).unwrap().as_array().unwrap().len(), 1);
    assert!(holds.lines(&sessions[0]).unwrap().as_array().unwrap().is_empty(), "b-1's session lists nothing of it");
}

/// Checks that a held file with no whole header line is read as fresh and
/// said on `Talk` (§3c.3; the tail rule's class A).
///
/// An empty file, and a header torn before its newline, each found at the
/// session's open, are a crash's tail at the file's head: the queue is
/// opened fresh, the finding said once in the shell's own window — and on
/// no event the page reads — and the next hold cuts the file and heads it,
/// its line read back by a reopen (the mutant that halts on a torn header
/// refuses every burst of the principal `store_halted` until a person
/// removes a file that holds no line).
#[test]
fn a_held_file_with_no_whole_header_line_is_read_as_fresh_and_said_on_talk() {
    let ours = Chain::parse(&"ab".repeat(32)).unwrap();
    let torn_header = format!("{{\"type\":\"skep-held-bursts\",\"v\":1,\"board\":\"{ours}\",\"principal\":1");
    for (cell, body) in [("an empty file", String::new()), ("a header torn before its newline", torn_header)] {
        let store = TempDir::new().unwrap();
        let facts = writer_facts(&store);
        HeldDir::new(store.path(), ours).ensure().unwrap();
        let held = store.path().join("held").join(ours.to_string()).join("principal-1.held");
        std::fs::write(&held, &body).unwrap();
        let g = ground_in(store, facts, 0);
        assert!(g.lines().is_empty(), "{cell}: the queue is opened fresh");
        let said = g.said.lock().unwrap().clone();
        let line = format!("held: principal 1's held file holds no whole header line ({} bytes of a torn one", body.len());
        assert_eq!(said.iter().filter(|l| l.starts_with(&line)).count(), 1, "{cell}: said once: {said:?}");
        let events: Vec<String> = g.rx.try_iter().map(|e| e.data.to_string()).collect();
        assert!(events.iter().all(|data| !data.contains("header")), "{cell}: the finding crossed to the page: {events:?}");
        let answer = g.hold(&insert(DOC, json!(["a"]), g.fake.head()), "unreachable", false);
        assert!(answer.get("unwritable").is_none(), "{cell}: the next hold cuts and heads the file: {answer}");
        let Opened::Live { queue, .. } = HeldDir::new(g.store.path(), ours).open_file(1, "1.0.1").unwrap() else { panic!("{cell}: the headed file reads live") };
        assert_eq!(queue.lines().len(), 1, "{cell}: the next hold's line read back");
    }
}

/// Checks that a held file the compaction cannot remove is said on `Talk`
/// and appended on.
///
/// Every line done and the unlink refused — the directory sealed against it
/// — the file stands with every line in it `done`, the failure is said once
/// naming the path, and the next hold appends to the standing file, read
/// back by a reopen (the mutant that marks the file gone refuses every later
/// burst `unwritable: AlreadyExists` and keeps it in memory alone, lost at
/// a relaunch).
#[cfg(unix)]
#[test]
fn a_held_file_the_compaction_cannot_remove_is_said_on_talk_and_appended_on() {
    use std::os::unix::fs::PermissionsExt;
    let g = ground();
    // A refused run's line: the one `resolve(drop)` settles.
    let verdict = json!({"resp": "rejected", "code": "out_of_bounds", "disposition": "permanent"});
    let k = g.hold_for(&insert(DOC, json!(["a"]), g.fake.head()), Reason::refused("out_of_bounds", verdict)).unwrap()["held"].as_u64().unwrap();
    let ours = Chain::parse(&"ab".repeat(32)).unwrap();
    let board_dir = g.store.path().join("held").join(ours.to_string());
    let held = board_dir.join("principal-1.held");
    std::fs::set_permissions(&board_dir, std::fs::Permissions::from_mode(0o500)).unwrap();
    let resolved = g.holds.resolve(&g.session, k, ResolveAct::Drop);
    assert_eq!(resolved.unwrap(), Resolved::Dropped);
    let said = g.said.lock().unwrap().clone();
    let line = format!("held: every held line is done, and the held file {} could not be removed (", held.display());
    assert_eq!(said.iter().filter(|l| l.starts_with(&line)).count(), 1, "{said:?}");
    assert!(held.is_file(), "the file stands");
    let answer = g.hold(&insert(DOC, json!(["b"]), g.fake.head()), "unreachable", false);
    assert!(answer.get("unwritable").is_none(), "the next hold appends to the standing file: {answer}");
    std::fs::set_permissions(&board_dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    let Opened::Live { queue, .. } = HeldDir::new(g.store.path(), ours).open_file(1, "1.0.1").unwrap() else { panic!("the file reads live") };
    assert_eq!(queue.lines().len(), 1, "a reopen reads the line");
}

/// Checks that the `held` event's memory emits a state and count once until
/// it changes or is cleared (skep #727).
///
/// The same state and count for one board, session and document is emitted
/// once; a changed count, or a changed state, is emitted; the join's forced
/// re-emit goes out whatever was last emitted; a document kept with no line
/// left clears its key, so the same pair after it is news again; and the
/// memory is per session — a second session of the principal sees its own
/// first emit (the mutant that forgets the memory floods the page with the
/// same state at every probe; the one that never clears a key keeps a map
/// entry per document ever held; the one that keys by document alone
/// starves a second tab of its first event).
#[test]
fn the_held_events_memory_emits_a_pair_once_until_it_changes_or_is_cleared() {
    let g = ground();
    let emit = |state: HeldState, held: u64| g.holds.emit_held(&g.session, DOC, held, state, Some("unreachable"), &[]);
    emit(HeldState::Holding, 1);
    emit(HeldState::Holding, 1);
    assert_eq!(g.states(), ["holding"], "the same pair once");
    emit(HeldState::Holding, 2);
    emit(HeldState::Sending, 2);
    emit(HeldState::Sending, 2);
    assert_eq!(g.states(), ["holding", "sending"], "a changed count, then a changed state, each once");
    g.holds.emit_held_again(&g.session, DOC, 2, HeldState::Sending, None);
    assert_eq!(g.states(), ["sending"], "the forced re-emit goes out whatever was last emitted");
    emit(HeldState::Kept, 0);
    emit(HeldState::Holding, 1);
    assert_eq!(g.states(), ["kept", "holding"], "a document kept with no line clears its key: the pair after it is news");
    assert_eq!(g.holds.last_emitted.lock().unwrap().len(), 1, "one key per document still held, none for a document kept whole");
    let second = g.holds.sessions.register(&BoardEntry { reference: "b-1".into(), board: Arc::clone(&g.session.board) }, Open { token: Token::parse(&"9e".repeat(16)).unwrap(), facts: writer_facts(&g.store), opened_at: 0 }, &mut NoSupplements);
    g.holds.emit_held(&second, DOC, 1, HeldState::Holding, Some("unreachable"), &[]);
    assert_eq!(g.states(), ["holding"], "a second session of the principal sees its own first emit");
}
