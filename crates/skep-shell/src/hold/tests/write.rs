//! THE WRITE PATH over a fake board: a `halted` hold before any dial
//! `sent: false`; a burst held under the first hold that stands, over all
//! eight cells of the three; the `base` a hold takes from every kind of
//! ack; the refused run's `resolve(drop)` dropping it and every line held
//! behind it on its own document alone, and a drop's `held` event saying
//! the state of the line that stands first after it; a held line under the
//! board's own directory; a refusal the table holds nowhere faced at the
//! first dial, a `write_busy` and a first and second `durability` reissued
//! within the first dial's call and a third holding the burst; a write the
//! hold never holds taking the same path, faced where a burst is held and
//! its ack noted for the base; the death signal at a write's dial holding
//! nothing; `resolve(send)` answering once the lines are handed back,
//! before any dial; a board the holds were not opened over stopped as the
//! caller's bug; the stored frame without its attest; P38's halted file
//! refusing every act at the principal's door, `resolve` among them, a copy
//! the store cannot make, and a queue kept in memory for want of its file
//! taking the file once it empties and never before; no `held` event when a
//! session's open reads its file, and a misplaced file set aside and said
//! on TALK alone. THE BURST's DOOR: a burst the board takes at no send
//! refused at the act and held never — past the frame cap as sent, or as a
//! signed resend would send it, a page-supplied attest counted out of every
//! resend, naming no document, an insert a signed session cannot attest —
//! the read of the board's `H.1` an attest signs over halting as the
//! composer's own refusal, and its answer lost holding the burst unsent;
//! one the queue has no room for, by its frames' bytes or by its lines,
//! refused `held_full`; and each board's hold its own, a burst at one board
//! answered while another board's hold is held, dialed and kept at the
//! board its session stands at.

use super::*;

/// A `halted` hold — the feed's `writes.halted` read, before any dial — is
/// `sent: false`: no dial was made, so nothing of it can have landed.
#[test]
fn a_halted_hold_before_any_dial_is_sent_false() {
    let g = ground();
    g.fake.writes_halted.store(true, Ordering::SeqCst);
    assert!(g.holds.note_health("b-1", &g.session.board.health().unwrap()), "the hold reads `writes.halted` off the board's `/health`");
    let OpAnswer::Answered(Ok(answer)) = g.holds.send_burst(&g.session, insert(DOC, json!(["hello"]))) else { panic!("held before the dial") };
    assert_eq!(answer["cause"], "halted", "{answer}");
    let lines = g.lines();
    assert_eq!((lines[0]["cause"].as_str(), lines[0]["sent"].as_bool()), (Some("halted"), Some(false)), "{lines:?}");
    assert_eq!(g.fake.sends(), 0, "no dial was made");
}

/// A BURST IS HELD UNDER THE FIRST HOLD THAT STANDS (§3c.4; `send_burst`'s
/// order), the law over all eight cells of the three: the own node stopped,
/// else the board's writes halted, else a line of the principal's already
/// held — the burst held under the first that stands with no dial made, and
/// dialed where none does (the mutant that reorders the three faces the
/// page `halted` for a stop the person made, or `behind` for a board that
/// takes no write).
#[test]
fn a_burst_is_held_under_the_first_hold_that_stands() {
    for stopped in [false, true] {
        for halted in [false, true] {
            for line in [false, true] {
                let cell = format!("stopped {stopped}, halted {halted}, a line standing {line}");
                let g = ground();
                if line {
                    g.hold(&insert(OTHER, json!(["a"])), "unreachable", false);
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
                let OpAnswer::Answered(Ok(answer)) = g.holds.send_burst(&g.session, insert(DOC, json!(["b"]))) else { panic!("{cell}: answered") };
                match first {
                    Some(cause) => assert_eq!((answer["resp"].as_str(), answer["cause"].as_str(), g.fake.sends()), (Some("held"), Some(cause), 0), "{cell}: {answer}"),
                    None => assert_eq!((answer["resp"].as_str(), g.fake.sends()), (Some("ack"), 1), "{cell}: {answer}"),
                }
            }
        }
    }
}

/// THE BASE a hold takes (§3c.2): the `at` of the last ACKED write on its
/// document — whatever its kind: a mint's, a fork's and a version's at the
/// `addr` it minted, a link write's at its `home`, an edit's at both its
/// documents, a burst's at its `doc` — and where none, the session's OPEN
/// POSITION: a burst held on a document no ack names, its mint's row at 50
/// below the session's open at 60, reads past it, is sent, and kept (the
/// mutant whose base falls back to 0 faces the person's own text `moved`);
/// a read notes nothing, so its document keeps the open (the mutant that
/// drops one kind from the documents an ack names leaves that kind's
/// document at the open).
#[test]
fn a_hold_takes_the_last_acked_write_or_the_sessions_open_as_its_base() {
    let g = writer_at(60);
    *g.fake.rows.lock().unwrap() = vec![json!({"at": 50, "op": "create_new_document", "key": g.own_key(), "docs": [DOC]})];
    g.hold(&insert(DOC, json!(["hello"])), "unreachable", false);
    assert_eq!(g.lines()[0]["base"], 60, "no ack names the document: the session's open");
    g.holds.probe("b-1");
    assert_eq!(g.fake.sends(), 1);
    assert!(g.lines().is_empty() && g.states().contains(&"kept".to_string()), "the row before the open moves nothing");

    let g = writer_at(60);
    let noted = |frame: Value, ack: Value| g.holds.note_ack(&g.session, &frame, &ack);
    let minted = |addr: &str, at: u64| json!({"resp": "ack_addr", "addr": addr, "at": at});
    noted(json!({"op": "create_new_document", "account": "1.0.1"}), minted("1.0.1.0.2", 70));
    noted(json!({"op": "make_link", "home": "1.0.1.0.3", "from": {"addrs": []}, "to": {"addrs": []}, "ty": {"addrs": []}}), minted("1.0.1.0.3.0.2.1", 71));
    noted(insert("1.0.1.0.4", json!(["x"])), json!({"resp": "delivery", "items": []}));
    noted(json!({"op": "emit", "home": "1.0.1.0.5", "ty": [], "from": "1.0.1.0.5.0.1.1", "to": []}), minted("1.0.1.0.5.0.2.1", 72));
    noted(json!({"op": "nullify", "home": "1.0.1.0.6", "target": "1.0.1.0.3.0.2.1"}), minted("1.0.1.0.6.0.2.1", 73));
    noted(json!({"op": "assert_sup", "home": "1.0.1.0.7", "old": "1.0.1.0.3.0.2.1", "new": "1.0.1.0.5.0.2.1"}), minted("1.0.1.0.7.0.2.1", 74));
    noted(json!({"op": "edit_link", "original": "1.0.1.0.3.0.2.1", "d_s": "1.0.1.0.8", "d_a": "1.0.1.0.9", "successor": {}}), json!({"resp": "ack_edit", "at": 75}));
    noted(json!({"op": "fork"}), minted("1.0.1.0.10", 76));
    noted(json!({"op": "version", "d_src": "1.0.1.0.2"}), minted("1.0.1.0.2.1", 77));
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
    ];
    for (doc, base) in bases {
        let held = g.hold(&insert(doc, json!(["x"])), "unreachable", false);
        let k = held["held"].as_u64().unwrap();
        let line = g.lines().into_iter().find(|l| l["held"] == k).unwrap();
        assert_eq!(line["base"], base, "{doc}: {line}");
    }

    // A burst dialed and acked notes its own `at`.
    let g = ground();
    let OpAnswer::Answered(Ok(ack)) = g.holds.send_burst(&g.session, insert(DOC, json!(["a"]))) else { panic!("acked") };
    let at = ack["at"].as_u64().unwrap();
    g.hold(&insert(DOC, json!(["b"])), "unreachable", false);
    assert_eq!(g.lines()[0]["base"], at);
}

/// A REFUSED run and `resolve`: the run's line carries the board's verdict
/// as its `refusal` (§3c.2, "for the face") and the lines `behind` it carry
/// none; `drop` on the refused head drops it AND every line held `behind`
/// it on that document (the mutant that leaves them standing), the `held`
/// event naming the session that acted; `resolve` on a holding line answers
/// `not_resolvable`; an unknown ordinal answers `no_such_held`.
#[test]
fn a_refused_run_drops_its_behind_lines() {
    let g = ground();
    let verdict = json!({"resp": "rejected", "code": "out_of_bounds", "disposition": "permanent"});
    let head = insert(DOC, json!(["a"]));
    let k1 = g.holds.hold(&g.session, g.burst(&head), Reason::refused("out_of_bounds", verdict.clone())).unwrap()["held"].as_u64().unwrap();
    // Two more bursts on the same document arrive while the run stands → behind.
    let behind = |values: Value| -> Value {
        let OpAnswer::Answered(Ok(answer)) = g.holds.send_burst(&g.session, insert(DOC, values)) else { panic!("held behind the run") };
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

/// A DROP on a MOVED document (§4b.1's `resolve`, §4b.2's `held`): the
/// person drops a later line of a document the read faced `moved`, and the
/// line held before it stands moved still — the `held` event says `moved`
/// with the one line left, never `kept` over text still held (the mutant
/// that says `kept` at every drop lifts the page's marks); the drop of the
/// last line says `kept` with none.
#[test]
fn a_drop_says_the_state_of_the_line_that_stands_first() {
    let g = ground();
    *g.fake.rows.lock().unwrap() = vec![json!({"at": 77, "op": "insert", "key": "ff".repeat(32), "docs": [DOC]})];
    let ks: Vec<u64> = ["a", "b", "c"].iter().map(|v| g.hold(&insert(DOC, json!([v])), "unreachable", false)["held"].as_u64().unwrap()).collect();
    g.holds.probe("b-1");
    assert!(g.lines().iter().all(|l| l["cause"] == "moved"), "the read faces every line moved: {:?}", g.lines());
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

/// No line is written outside the board's own directory: a burst held at a
/// board whose directory is this shell's lands in `held/<chain>/`.
#[test]
fn a_held_line_lands_under_the_boards_own_directory() {
    let g = ground();
    let answer = g.hold(&insert(DOC, json!(["hello"])), "unreachable", false);
    assert!(answer.get("unwritable").is_none(), "{answer}");
    let file = g.store.path().join("held").join("ab".repeat(32)).join("principal-1.held");
    let text = std::fs::read_to_string(&file).unwrap();
    assert!(text.lines().next().unwrap().contains("\"account\":\"1.0.1\""), "the header names the session's account: {text}");
}

/// A DROP acts on its own document's run and on no other (§4b.1's
/// `resolve`): a refused run on one document, a burst on a second held
/// `behind` it — a standing line holds every later burst, whatever its
/// document — and the run's drop leaves the second document's line
/// standing, which the next probe sends and keeps (the mutant that drops
/// every later line, whatever its document, loses the person's text on the
/// other document).
#[test]
fn a_drop_drops_its_own_documents_run_and_no_other() {
    let g = ground();
    let verdict = json!({"resp": "rejected", "code": "out_of_bounds", "disposition": "permanent"});
    let k1 = g.holds.hold(&g.session, g.burst(&insert(DOC, json!(["a"]))), Reason::refused("out_of_bounds", verdict)).unwrap()["held"].as_u64().unwrap();
    let OpAnswer::Answered(Ok(behind)) = g.holds.send_burst(&g.session, insert(OTHER, json!(["z"]))) else { panic!("held behind the run") };
    assert_eq!(behind["cause"], "behind", "{behind}");
    assert_eq!(g.holds.resolve(&g.session, k1, ResolveAct::Drop).unwrap(), Resolved::Dropped);
    let docs: Vec<String> = g.lines().iter().map(|l| l["doc"].as_str().unwrap_or("?").to_string()).collect();
    assert_eq!(docs, [OTHER], "the run is dropped, the other document's line stands");
    g.holds.probe("b-1");
    assert_eq!(g.fake.sends(), 1, "the other document's line is sent");
    assert!(g.lines().is_empty() && g.states().contains(&"kept".to_string()));
}

/// A REFUSAL THE TABLE HOLDS NOWHERE is faced at the burst's first dial
/// (§3c.4's NEITHER), and a `write_busy` — read by its code off the 503 the
/// board answers it as — is REISSUED within the call, once, after the short
/// wait (§4b.1's `op` row: "reissued by the shell and reach the page as the
/// ack or the next refusal, never as `held`"): a `write_busy` the reissue
/// meets again is the next refusal, faced; one the reissue clears is the
/// ack; no burst is held (the mutants that hold either, that face the first
/// `write_busy`, or that reissue it without bound).
#[test]
fn a_refusal_the_table_holds_nowhere_is_faced_and_a_write_busy_reissued_once() {
    let g = ground();
    g.fake.op_rejected.every(json!({"resp": "rejected", "code": "credential_refused", "detail": "index_rebuilding", "disposition": "retry", "op": "insert"}));
    let OpAnswer::Answered(Err(refused)) = g.holds.send_burst(&g.session, insert(DOC, json!(["a"]))) else { panic!("faced at the act") };
    assert_eq!((refused.name(), g.fake.sends()), ("index_rebuilding", 1), "{refused}");
    g.fake.op_rejected.clear();
    g.fake.op_refused.every((503, json!({"error": "write_busy"})));
    let OpAnswer::Answered(Err(busy)) = g.holds.send_burst(&g.session, insert(DOC, json!(["b"]))) else { panic!("the reissue's refusal faced") };
    let v = busy.to_value();
    assert_eq!((busy.name(), v["status"].as_u64(), g.fake.sends()), ("write_busy", Some(503), 3), "reissued once: {v}");
    g.fake.op_refused.next(1, (503, json!({"error": "write_busy"})));
    let OpAnswer::Answered(Ok(ack)) = g.holds.send_burst(&g.session, insert(DOC, json!(["c"]))) else { panic!("the reissue acked") };
    assert_eq!((ack["resp"].as_str(), g.fake.sends()), (Some("ack"), 5), "{ack}");
    assert!(g.lines().is_empty(), "no burst is held");
}

/// A FIRST AND SECOND `durability` are reissued within the first dial's
/// call as-is, and a THIRD holds the burst `durability` (§3c.4's rider), its
/// line `sent: false`: two the reissues clear are the ack, and a
/// `write_busy` met beside them counts nothing toward the rider (the
/// mutants that face the first `durability`, hold it before its third, or
/// count every reissue as one).
#[test]
fn a_first_and_second_durability_are_reissued_at_the_first_dial_and_a_third_holds() {
    let g = ground();
    g.fake.op_rejected.next(2, retry("durability"));
    let OpAnswer::Answered(Ok(ack)) = g.holds.send_burst(&g.session, insert(DOC, json!(["a"]))) else { panic!("the second reissue acked") };
    assert_eq!((ack["resp"].as_str(), g.fake.sends()), (Some("ack"), 3), "{ack}");
    g.fake.op_refused.next(1, (503, json!({"error": "write_busy"})));
    g.fake.op_rejected.next(2, retry("durability"));
    let OpAnswer::Answered(Ok(ack)) = g.holds.send_burst(&g.session, insert(DOC, json!(["b"]))) else { panic!("a write_busy counts nothing toward the rider") };
    assert_eq!((ack["resp"].as_str(), g.fake.sends()), (Some("ack"), 7), "{ack}");
    g.fake.op_rejected.every(retry("durability"));
    let OpAnswer::Answered(Ok(held)) = g.holds.send_burst(&g.session, insert(DOC, json!(["c"]))) else { panic!("held at the third") };
    assert_eq!((held["resp"].as_str(), held["cause"].as_str(), g.fake.sends()), (Some("held"), Some("durability"), 10), "{held}");
    assert_eq!(g.lines()[0]["sent"], false);
}

/// A WRITE THE HOLD NEVER HOLDS takes the one path a burst takes
/// (`Holds::send`; §3c.4: "a non-burst write that fails … is faced at its
/// act"): a `permanent` refusal and a third `durability` — each of which
/// holds a burst — are faced, the first after one send and the second after
/// its two reissues, and nothing is held; and its ack is noted for the base,
/// so a burst held on the document it names reads from that ack's `at` (the
/// mutants that hold a non-burst's hold-class answer, and that leave its ack
/// unnoted).
#[test]
fn a_write_the_hold_never_holds_is_faced_and_its_ack_noted() {
    let g = ground();
    let link = json!({"op": "make_link", "home": OTHER, "from": {"addrs": [OTHER]}, "to": {"addrs": [DOC]}, "ty": {"addrs": ["1.1.0.1.0.1.0.3.13"]}});
    g.fake.op_rejected.every(json!({"resp": "rejected", "code": "out_of_bounds", "disposition": "permanent", "op": "make_link"}));
    let OpAnswer::Answered(Err(refused)) = g.holds.send(&g.session, link.clone()) else { panic!("faced at the act") };
    assert_eq!((refused.name(), g.fake.sends()), ("out_of_bounds", 1), "{refused}");
    g.fake.op_rejected.every(retry("durability"));
    let OpAnswer::Answered(Err(refused)) = g.holds.send(&g.session, link.clone()) else { panic!("faced at the third") };
    assert_eq!((refused.name(), g.fake.sends()), ("durability", 4), "{refused}");
    assert!(g.lines().is_empty() && g.states().is_empty(), "a write the hold never holds is held never");
    g.fake.op_rejected.clear();
    let OpAnswer::Answered(Ok(ack)) = g.holds.send(&g.session, link) else { panic!("acked") };
    let held = g.hold(&insert(OTHER, json!(["a"])), "unreachable", false);
    let line = g.lines().into_iter().find(|l| l["held"] == held["held"]).expect("the burst is held");
    assert_eq!(line["base"], ack["at"], "the ack is noted for the base of the next hold on its home: {line}");
}

/// THE DEATH SIGNAL at a write's dial holds nothing (§3c.4: the death is
/// neither held nor faced): a burst and a write the hold never holds each
/// answer `OpAnswer::Died`, the session's end the caller's to run, and no
/// line is held and no `held` event said (the mutant that holds the burst
/// at the death keeps a line behind a session nobody ends).
#[test]
fn a_death_signal_at_a_writes_dial_holds_nothing() {
    let g = ground();
    g.fake.op_closed.store(true, Ordering::SeqCst);
    let link = json!({"op": "make_link", "home": OTHER, "from": {"addrs": [OTHER]}, "to": {"addrs": [DOC]}, "ty": {"addrs": ["1.1.0.1.0.1.0.3.13"]}});
    assert!(matches!(g.holds.send_burst(&g.session, insert(DOC, json!(["a"]))), OpAnswer::Died), "a burst's dial meets the death");
    assert!(matches!(g.holds.send(&g.session, link), OpAnswer::Died), "and a write the hold never holds");
    assert_eq!(g.fake.sends(), 2, "each dialed once");
    assert!(g.lines().is_empty() && g.states().is_empty(), "nothing held, nothing said");
}

/// `resolve(send)` HANDS the document back to the automatic machine and
/// answers at once (§4b.1: "the call answers once the line is handed to
/// the machine, never after its ack"): nothing is dialed in the act and the
/// run's lines stand re-marked `behind`; the probe its caller hands the
/// board's feed thread then sends and keeps them (the mutant that probes
/// inside the act dials the board before the call answers).
#[test]
fn resolve_send_answers_once_the_lines_are_handed_back() {
    let g = ground();
    let verdict = json!({"resp": "rejected", "code": "out_of_bounds", "disposition": "permanent"});
    let k = g.holds.hold(&g.session, g.burst(&insert(DOC, json!(["a"]))), Reason::refused("out_of_bounds", verdict)).unwrap()["held"].as_u64().unwrap();
    assert_eq!(g.holds.resolve(&g.session, k, ResolveAct::Send).unwrap(), Resolved::HandedBack);
    assert_eq!((g.fake.sends(), g.fake.health_reads.load(Ordering::SeqCst)), (0, 0), "nothing is dialed in the act");
    assert_eq!(g.lines()[0]["cause"], "behind", "the run's line re-marked `behind`");
    g.holds.probe("b-1");
    assert_eq!(g.fake.sends(), 1, "the handed probe sends it");
    assert!(g.lines().is_empty() && g.states().contains(&"kept".to_string()));
}

/// THE ONE PRECONDITION of the holds — a board reference names a board they
/// were opened over — is the caller's, asked in one place: a reference
/// outside them is a bug of this crate's, stopped loudly, never read as a
/// board with nothing held.
#[test]
#[should_panic(expected = "PRECONDITION of `Holds`")]
fn a_board_the_holds_were_not_opened_over_is_the_callers_bug() {
    ground().holds.probe("b-nowhere");
}

/// THE STORED FRAME carries no `attest` (§3c.2): a burst held with one is
/// kept and listed without it, since the resend composes its attest when it
/// sends (the mutant that stores the frame as it came).
#[test]
fn a_held_frame_is_stored_without_its_attest() {
    let g = ground();
    let mut frame = insert(DOC, json!(["hello"]));
    frame["attest"] = json!({"alg": "x", "sig": "00"});
    g.hold(&frame, "unreachable", false);
    let lines = g.lines();
    assert!(lines[0]["frame"].get("attest").is_none() && lines[0]["frame"]["op"] == "insert", "{lines:?}");
    let file = g.store.path().join("held").join("ab".repeat(32)).join("principal-1.held");
    let text = std::fs::read_to_string(&file).unwrap();
    assert!(!text.contains("attest"), "{text}");
}

/// P38's HALT at the hold (§3c.3): a principal's file written by a newer skep
/// stands untouched, and every act on it answers `store_halted` naming why —
/// the burst is not dialed, no line is held, `held(session)` lists nothing,
/// `resolve` acts on no line — so no burst is sent past a file this shell
/// may not write and none is rebuilt over (the mutants that dial past a
/// halted file, or answer an act on it as no line).
#[test]
fn a_halted_file_refuses_every_act_and_dials_nothing() {
    let store = TempDir::new().unwrap();
    let chain = "ab".repeat(32);
    HeldDir::new(store.path(), Chain::parse(&chain).unwrap()).ensure().unwrap();
    let file = store.path().join("held").join(&chain).join("principal-1.held");
    let newer = format!("{{\"type\":\"skep-held-bursts\",\"v\":2,\"board\":\"{chain}\",\"principal\":1,\"account\":\"1.0.1\"}}\n");
    std::fs::write(&file, &newer).unwrap();
    let g = ground_in(store, bare_facts(), 0);
    let OpAnswer::Answered(Err(refused)) = g.holds.send_burst(&g.session, insert(DOC, json!(["hello"]))) else { panic!("a burst at a halted file is refused") };
    assert_eq!((refused.name(), refused.to_value()["why"].as_str()), ("store_halted", Some("newer")), "{refused}");
    assert_eq!(g.fake.sends(), 0, "nothing is dialed past a halted file");
    assert_eq!(g.holds.lines(&g.session).unwrap_err().name(), "store_halted");
    assert_eq!(g.holds.resolve(&g.session, 1, ResolveAct::Drop).unwrap_err().name(), "store_halted", "an act on a line answers the halt, never no line");
    let held = g.holds.hold(&g.session, g.burst(&insert(DOC, json!(["x"]))), Reason::of("unreachable", false));
    assert_eq!(held.unwrap_err().name(), "store_halted", "no line is held");
    assert_eq!(std::fs::read_to_string(&file).unwrap(), newer, "the halted file is never rebuilt over");
}

/// A LINE THE STORE CANNOT COPY stands in memory and says why (§3c.3,
/// "Persist first"): at a board with no `H.1` to name its directory, the
/// burst is held under its own cause — never `other_window`, another
/// window's lock alone — its answer `unwritable` naming the missing term,
/// nothing written; at a file the device refuses (a directory where the
/// file would be), the device's refusal rides the answer. Either line
/// stands in the queue, and the next probe resends and keeps it (the mutant
/// that drops `unwritable` tells the page a burst a crash would lose is on
/// disk).
#[test]
fn a_line_the_store_cannot_copy_says_why_and_stands() {
    let fake = Fake::new();
    fake.no_head.store(true, Ordering::SeqCst);
    let store = TempDir::new().unwrap();
    let facts = writer_facts(&store);
    let g = ground_over(fake, store, facts, 0);
    let answer = g.hold(&insert(DOC, json!(["hello"])), "unreachable", false);
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
    let answer = g.hold(&insert(DOC, json!(["hello"])), "unreachable", false);
    assert_eq!(answer["cause"], "unreachable", "{answer}");
    assert!(answer["unwritable"].is_string(), "the device's refusal rides the answer: {answer}");
    assert_eq!(g.lines().len(), 1, "the line stands");
    std::fs::remove_dir(&file).unwrap();
    g.holds.probe("b-1");
    assert_eq!(g.fake.sends(), 1, "the line is resent");
    assert!(g.lines().is_empty() && g.states().contains(&"kept".to_string()));
}

/// A QUEUE KEPT IN MEMORY FOR WANT OF ITS FILE takes the file once it
/// empties, and never before (§3c.3; `Custody::Unwritable`): at a board with
/// no `H.1`, a line held in memory alone and refused at its resend still
/// stands when the probe — the board now naming its `H.1` — establishes the
/// directory, so the next burst is held `behind` it, still `unwritable`,
/// under the next ordinal; once both are kept, the next line is copied to
/// the board's file (the mutant that opens the file while lines stand
/// replaces the queue and dials the next burst past a line it lost; the
/// ones that never re-open the file, or never establish the directory, keep
/// every later line in memory alone, for a crash to lose).
#[test]
fn an_unwritable_queue_takes_its_file_once_it_empties_and_never_before() {
    let fake = Fake::new();
    fake.no_head.store(true, Ordering::SeqCst);
    let store = TempDir::new().unwrap();
    let facts = writer_facts(&store);
    let g = ground_over(fake, store, facts, 0);
    let first = g.hold(&insert(DOC, json!(["a"])), "unreachable", false);
    assert!(first["unwritable"].is_string(), "{first}");
    g.fake.no_head.store(false, Ordering::SeqCst);
    g.fake.op_rejected.every(json!({"resp": "rejected", "code": "credential_refused", "detail": "index_rebuilding", "disposition": "retry", "op": "insert"}));
    g.holds.probe("b-1");
    assert_eq!((g.fake.sends(), g.lines().len()), (1, 1), "the line stands, not taken at its resend");
    let OpAnswer::Answered(Ok(behind)) = g.holds.send_burst(&g.session, insert(DOC, json!(["b"]))) else { panic!("held behind the standing line") };
    assert_eq!(behind["cause"], "behind", "{behind}");
    assert!(behind["unwritable"].is_string(), "in memory alone while a line stands: {behind}");
    let ks: Vec<u64> = g.lines().iter().map(|l| l["held"].as_u64().unwrap()).collect();
    assert_eq!(ks, [1, 2], "no line renumbered");
    g.fake.op_rejected.clear();
    g.holds.probe("b-1");
    assert!(g.lines().is_empty(), "both kept");
    let next = g.hold(&insert(DOC, json!(["c"])), "unreachable", false);
    assert!(next.get("unwritable").is_none(), "{next}");
    let file = g.store.path().join("held").join("ab".repeat(32)).join("principal-1.held");
    assert!(std::fs::read_to_string(&file).unwrap().contains("\"values\":[\"c\"]"), "the line is copied to the board's file");
}

/// NO `held` EVENT GOES OUT when a session's open reads its principal's
/// file (§4b.2; `EventName::Held`): the line the file holds is listed by
/// `held(session)` at once, and nothing of it is said on the bus (the
/// mutant that announces each document at the open says a state no act of
/// the page's moved).
#[test]
fn no_held_event_goes_out_when_a_sessions_open_reads_its_file() {
    let store = TempDir::new().unwrap();
    let dir = HeldDir::new(store.path(), Chain::parse(&"ab".repeat(32)).unwrap());
    dir.ensure().unwrap();
    let Opened::Live { mut queue, .. } = dir.open_file(1, "1.0.1").unwrap() else { panic!("a fresh file") };
    assert!(queue.hold(DOC, None, 0, insert(DOC, json!(["a"])), Reason::of("unreachable", false)).unwrap().unwritten.is_none());
    drop(queue);
    let g = ground_in(store, bare_facts(), 0);
    assert_eq!(g.lines().len(), 1, "the session's open lists the line");
    assert!(g.states().is_empty(), "and says nothing of it");
}

/// A MISPLACED HELD FILE IS SET ASIDE AND SAID in the shell's own window
/// (§3c.3; P39): a principal's file whose header names another board's
/// chain, found at its session's open, is moved aside under `aside_name`'s
/// form, the queue opened fresh, and the aside's path said on TALK — and on
/// no event the page reads (the mutant that sets the file aside unsaid
/// leaves the person's held text gone from every list with nothing said).
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

/// An insert of one atom, its frame's JSON spelling exactly `bytes` long —
/// one value, so no value budget speaks before the frame's own.
fn sized_frame(bytes: usize) -> Value {
    let overhead = json_len(&insert(DOC, json!([{"atom": ""}])));
    insert(DOC, json!([{"atom": "x".repeat(bytes - overhead)}]))
}

/// THE BURST's DOOR refuses at the act a burst the board takes at no send,
/// and holds none of it: a frame one byte past the board's frame cap — at a
/// running board and at a stopped one, where it would otherwise be held
/// without a dial — while a frame at the cap exactly is dialed and acked; a
/// burst naming no document, an element where its document goes, or a
/// document in another spelling, refused `malformed_args` undialed, and
/// behind a standing line unheld (the mutants that drop the size or the
/// document check dial a frame no send of which the board takes, and hold a
/// line none could ever clear, every later burst of the principal behind
/// it). The door's own arithmetic, under a session whose key attests no
/// insert — a bare one, so the door keeps no attest's room; the shell's `op`
/// row refuses such a session's write before it reaches the hold.
#[test]
fn a_burst_the_board_takes_at_no_send_is_refused_at_the_bursts_door() {
    let g = bare_ground();
    for stopped in [false, true] {
        g.holds.set_node_stopped("b-1", stopped);
        let OpAnswer::Answered(Err(refused)) = g.holds.send_burst(&g.session, sized_frame(MAX_FRAME_BYTES + 1)) else { panic!("refused at the burst's door") };
        let v = refused.to_value();
        assert_eq!((refused.name(), v["bytes"].as_u64(), v["cap"].as_u64()), ("frame_too_large", Some(MAX_FRAME_BYTES as u64 + 1), Some(MAX_FRAME_BYTES as u64)), "{v}");
        assert!(g.lines().is_empty() && g.fake.sends() == 0, "stopped {stopped}: nothing held, nothing sent");
    }
    g.holds.set_node_stopped("b-1", false);
    let undocumented = [json!({"op": "insert", "values": ["b"]}), insert("1.0.1.0.1.0.1.1", json!(["b"])), insert("01.0.1.0.1", json!(["b"]))];
    for frame in &undocumented {
        let OpAnswer::Answered(Err(refused)) = g.holds.send_burst(&g.session, frame.clone()) else { panic!("refused at the burst's door: {frame}") };
        assert_eq!(refused.name(), "malformed_args", "{frame}");
    }
    assert_eq!(g.fake.sends(), 0, "nothing the burst's door refuses is dialed");
    let OpAnswer::Answered(Ok(ack)) = g.holds.send_burst(&g.session, sized_frame(MAX_FRAME_BYTES)) else { panic!("a frame at the cap is sent") };
    assert_eq!((ack["resp"].as_str(), g.fake.sends()), (Some("ack"), 1));
    g.hold(&insert(DOC, json!(["a"])), "unreachable", false);
    for frame in &undocumented {
        let OpAnswer::Answered(Err(refused)) = g.holds.send_burst(&g.session, frame.clone()) else { panic!("refused at the burst's door: {frame}") };
        assert_eq!(refused.name(), "malformed_args", "{frame}");
    }
    assert_eq!(g.lines().len(), 1, "nothing was held behind the standing line");
}

/// Under a session whose key attests an insert, the burst's door keeps the
/// room the attest of every resend takes, and asks the composer's terms of
/// the frame alone: a frame at the cap unattested, which no attested send
/// fits, is refused `frame_too_large`; one the room fits is held behind a
/// standing line; and an insert whose values the composer cannot spell is
/// refused `attest_not_composed` before it is held (the mutant that leaves no
/// room holds a burst every resend of which the board refuses `413`).
#[test]
fn a_signed_sessions_burst_keeps_room_for_its_attest() {
    let g = ground_in(TempDir::new().unwrap(), keyed_facts(), 0);
    g.hold(&insert(DOC, json!(["a"])), "unreachable", false);
    let OpAnswer::Answered(Err(refused)) = g.holds.send_burst(&g.session, sized_frame(MAX_FRAME_BYTES)) else { panic!("refused at the burst's door") };
    assert_eq!(refused.name(), "frame_too_large", "{refused}");
    let OpAnswer::Answered(Ok(held)) = g.holds.send_burst(&g.session, sized_frame(MAX_FRAME_BYTES - attest_room())) else { panic!("held behind") };
    assert_eq!(held["cause"], "behind", "{held}");
    let OpAnswer::Answered(Err(refused)) = g.holds.send_burst(&g.session, insert(DOC, json!([7]))) else { panic!("refused at the burst's door") };
    assert_eq!(refused.name(), "attest_not_composed", "{refused}");
    assert_eq!(g.lines().len(), 2, "the one admitted burst held, and nothing else");
}

/// A PAGE-SUPPLIED ATTEST IS COUNTED OUT OF EVERY RESEND (`Burst::admit`):
/// the held line keeps the frame without it, and every resend under a
/// session whose key attests the kind carries the shell's own — so a frame
/// riding the page's attest is measured as its bytes stripped of that
/// member and grown by the room the shell's takes: at the cap it is held,
/// one byte past it refused `frame_too_large` (the mutant that strips
/// nothing refuses a burst every resend of which fits; the one that strips
/// past the member holds a burst no resend of which does).
#[test]
fn a_page_supplied_attest_is_counted_out_of_every_resend() {
    let g = ground_in(TempDir::new().unwrap(), keyed_facts(), 0);
    g.hold(&insert(DOC, json!(["a"])), "unreachable", false);
    let carrying = |bytes: usize| {
        let mut frame = sized_frame(bytes);
        frame["attest"] = json!({"alg": "x", "sig": "00"});
        frame
    };
    let OpAnswer::Answered(Ok(held)) = g.holds.send_burst(&g.session, carrying(MAX_FRAME_BYTES - attest_room())) else { panic!("held behind") };
    assert_eq!(held["cause"], "behind", "{held}");
    let OpAnswer::Answered(Err(refused)) = g.holds.send_burst(&g.session, carrying(MAX_FRAME_BYTES - attest_room() + 1)) else { panic!("refused at the burst's door") };
    let v = refused.to_value();
    assert_eq!((refused.name(), v["bytes"].as_u64()), ("frame_too_large", Some(MAX_FRAME_BYTES as u64 + 1)), "{v}");
    assert_eq!(g.lines().len(), 2, "the one admitted burst held, and nothing else");
}

/// A HEAD READ THAT HALTS is the composer's refusal: under a session whose
/// key attests an insert, the read of the board's `H.1` the attest signs
/// over answered with the death signal — no session's answer, a token-free
/// read's halt — refuses the burst `attest_not_composed`, nothing dialed and
/// nothing held (the mutant that converts the read's halt past the
/// composer's own conversion answers the bare `halt`, a refusal the page
/// cannot read as the shell's failure to sign).
#[test]
fn a_head_read_that_halts_is_the_composers_refusal() {
    let fake = Fake::new();
    fake.head_closed.store(true, Ordering::SeqCst);
    let g = ground_over(fake, TempDir::new().unwrap(), keyed_facts(), 0);
    let OpAnswer::Answered(Err(refused)) = g.holds.send_burst(&g.session, insert(DOC, json!(["a"]))) else { panic!("refused, nothing sent") };
    assert_eq!(refused.name(), "attest_not_composed", "{refused}");
    assert_eq!(g.fake.sends(), 0, "nothing dialed");
    assert!(g.lines().is_empty() && g.states().is_empty(), "nothing held, nothing said");
}

/// A READ THE ATTEST NEEDS, ITS ANSWER LOST, holds the burst like the
/// dial's own failure — and `sent: false`, since the write never left
/// (`Dialed`'s `From<Unattested>`): under a session whose key attests an
/// insert, the read of the board's `H.1` the attest signs over meets a
/// transport fault the table reads as a lost answer, and the burst is held
/// `unreachable`, its line unsent and nothing dialed (the mutant that faces
/// the read's failure loses the burst; the one that keeps the table's
/// `sent` sends the resend to read for a landing that never happened).
#[test]
fn an_unanswered_read_the_attest_needs_holds_the_burst_unsent() {
    let fake = Fake::new();
    fake.head_unreachable.store(true, Ordering::SeqCst);
    let g = ground_over(fake, TempDir::new().unwrap(), keyed_facts(), 0);
    let OpAnswer::Answered(Ok(held)) = g.holds.send_burst(&g.session, insert(DOC, json!(["a"]))) else { panic!("held, nothing sent") };
    assert_eq!((held["resp"].as_str(), held["cause"].as_str()), (Some("held"), Some("unreachable")), "{held}");
    let lines = g.lines();
    assert_eq!(lines[0]["sent"], false, "the write never left: {lines:?}");
    assert_eq!(g.fake.sends(), 0, "nothing dialed");
}

/// THE QUEUE's BUDGET at the hold: with the principal's standing frames at
/// the budget, the next burst is refused `held_full` — no line, no `held`
/// event — and its answer names the bytes held and its own (the mutant that
/// drops the queue's count holds a page's bursts without bound). The queue's
/// own budget, under a session whose key attests no insert — a bare one, its
/// door keeping no attest's room, so one frame fills the queue.
#[test]
fn a_burst_the_queue_has_no_room_for_is_refused_held_full() {
    let g = bare_ground();
    g.hold(&sized_frame(MAX_HELD_FRAME_BYTES - 10), "unreachable", false);
    let _ = g.states();
    let OpAnswer::Answered(Err(refused)) = g.holds.send_burst(&g.session, insert(DOC, json!(["b"]))) else { panic!("refused, not held") };
    let v = refused.to_value();
    assert_eq!((refused.name(), v["held_bytes"].as_u64(), v["cap"].as_u64()), ("held_full", Some(MAX_HELD_FRAME_BYTES as u64 - 10), Some(MAX_HELD_FRAME_BYTES as u64)), "{v}");
    assert_eq!(g.lines().len(), 1, "nothing more held");
    assert!(g.states().is_empty(), "no `held` event for a burst not held");
    assert_eq!(g.fake.sends(), 0);
}

/// THE QUEUE's LINE BUDGET at the hold: behind one refused run, small
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
    g.holds.hold(&g.session, g.burst(&insert(DOC, json!(["a"]))), Reason::refused("out_of_bounds", verdict)).unwrap();
    for n in 1..MAX_HELD_LINES {
        g.hold(&delete(&format!("1.0.1.0.{}", 100 + n)), "behind", false);
    }
    let _ = g.rx.try_iter().count();
    let OpAnswer::Answered(Err(refused)) = g.holds.send_burst(&g.session, delete("1.0.1.0.99")) else { panic!("refused, not held") };
    let v = refused.to_value();
    assert_eq!((refused.name(), v["held_lines"].as_u64(), v["line_cap"].as_u64()), ("held_full", Some(MAX_HELD_LINES as u64), Some(MAX_HELD_LINES as u64)), "{v}");
    assert_eq!(g.lines().len(), MAX_HELD_LINES, "nothing more held");
    assert!(g.states().is_empty(), "no `held` event for a burst not held");
    assert_eq!(g.fake.sends(), 0, "nothing dialed");
}

/// The ground over two boards, `b-1` and `b-2`, of their own chains: the
/// holds over both, a writer's session of principal 1 at each, under one key
/// — `sessions[0]` at `b-1`, `sessions[1]` at `b-2` — opened as the shell
/// opens them, each board's fake, and the store directory kept for the
/// ground's life.
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
    let table = Arc::new(Sessions::new(None));
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

/// EACH BOARD's HOLD ITS OWN LOCK: with one board's hold held — as a burst's
/// synced append, or a file's read at a session's open, holds it — a burst at
/// another board is dialed and acked without waiting (the mutant that puts
/// every board's hold under one lock makes it wait the other board out),
/// and dialed at the board its session stands at, the other board seeing
/// nothing of it.
#[test]
fn a_burst_at_one_board_waits_on_no_other_boards_hold() {
    let TwoBoards { holds, sessions, fakes, store: _store } = two_boards();
    let parked = holds.lock("b-1");
    let (finished, answer) = thread::scope(|s| {
        let other = s.spawn(|| holds.send_burst(&sessions[1], insert(DOC, json!(["z"]))));
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

/// A SESSION's LINES ARE KEPT AT ITS OWN BOARD: a burst held under the
/// session at b-2 lands in b-2's `held/<chain>/` and lists under that
/// session alone — the session carries the board it stands at, so no caller
/// pairs it with another.
#[test]
fn a_sessions_held_line_is_kept_at_the_board_it_stands_at() {
    let TwoBoards { holds, sessions, store, .. } = two_boards();
    let held = holds.hold(&sessions[1], Burst::admit(insert(DOC, json!(["z"])), &sessions[1]).unwrap(), Reason::of("unreachable", false)).unwrap();
    assert_eq!(held["resp"], "held", "{held}");
    let file = |chain: &str| store.path().join("held").join(chain).join("principal-1.held");
    assert!(file(&"cd".repeat(32)).is_file() && !file(&"ab".repeat(32)).exists(), "the line is kept in b-2's directory alone");
    assert_eq!(holds.lines(&sessions[1]).unwrap().as_array().unwrap().len(), 1);
    assert!(holds.lines(&sessions[0]).unwrap().as_array().unwrap().is_empty(), "b-1's session lists nothing of it");
}
