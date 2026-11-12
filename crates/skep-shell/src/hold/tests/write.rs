//! The write path over a fake board.
//!
//! The suite checks a `halted` hold before any dial `sent: false`; a burst
//! held under the first hold that stands, over all eight cells of the
//! three; the `base` a hold takes from every kind of ack, an ack read after
//! a later one lowering it never; the position of the principal's latest
//! arrangement write, a burst's or a `set_arrangement`'s alone, never a
//! link's or a mint's, a landing the resend's read found, and a restore,
//! noted as a `set_arrangement`'s ack; the refused
//! run's `resolve(drop)`
//! dropping it and every line held behind it on its own document alone,
//! and a drop's `held` event saying the state of the line that stands
//! first after it, a moved face naming the hands the session was told or,
//! where no face told it them, the hands read once the act's locks are let
//! go — named not read where the board does not give them, and named by the
//! walk once it does (skep #960), named not read too where the document is
//! moved again while they are read; hands named not read to a session the
//! walk does not run under named to it, and at a principal no session of
//! which may write named at the board's answer, the walk saying no face of a
//! document handed back while it reads them (skep #972); a burst the board
//! refuses as typed against an older state held moved at its first dial where
//! it carries no anchors, the board's verdict on its line and the hand that
//! moved the document named — its hands read again at the limit that fits
//! where their page is past the budget, and named not read where the board
//! answers no page, read again at each pass until it does (skep #972) —
//! and a moved line with the verdict reading `moved` and taking a moved
//! document's acts; THE STATE THAT STAYS IN FRONT (skep #974): every line
//! entered behind a first line that awaits the person's act — a burst held
//! behind it before any dial, at a stopped node among them, a line a dial's
//! answer holds, an end of a first dial's shift — saying that line's state,
//! its hands as told or read for a session told nothing, the answer naming
//! the line's own cause and a moved line behind a refused run owing no hands,
//! a keep or a landing that leaves such a line first saying it too, and a
//! line behind one a first dial is shifting saying its own face; a first
//! dial's shift that is not exact marking its line and the lines after it
//! alone, a line ahead keeping its state and its verdict — a refused run's
//! said in front and owed no hands, a holding one sent at the next probe
//! (skep #1002); the person's `send` on a moved document raising each
//! waiting line's base to the verdict's `site.current`, in the queue and on
//! disk, a base past it standing, and raising none where no line carries a
//! verdict naming a position (skep #757); a drop's `done`s, a moved
//! document's marks and the person's `send` on it each one copy with one
//! sync, the marks the device refused waiting as one run for the probe's one
//! copy, and the re-marks of a run the writer refuses said in one line (skep
//! #861); THE SHIFT at a first dial (skep
//! #442): a stale burst whose anchors stand with the span between them
//! whole shifted and landing within the call, one cell per op in what the
//! displacement moves; the
//! shifted frame on the line, marked sent, before the shifted dial, and a
//! relaunch after that dial's answer is lost reading the landed test at the
//! shifted positions and keeping the line; a cut span, a lost anchor,
//! anchors at the wrong edge, no anchors and a read the board refuses each
//! falling to the moved hold with its verdict and hands, and a read the
//! board gives no answer to leaving the shift untried, the burst held
//! `unreachable` and shifted when the board answers (skep #863); and a
//! document that keeps moving stopping the shifts at the line's deadline,
//! held moved, the person's send starting its clock afresh; a held line
//! under the board's own directory;
//! a refusal the table holds nowhere faced at the first dial, a
//! `write_busy` and a first and second `durability` reissued within the
//! first dial's call, a second `write_busy` holding the burst `sent: false`
//! with its clock started at its birth and a third `durability` holding it;
//! a burst answered `500 internal_panic` held `sent: true` and read before it
//! is sent again; a write the hold never holds taking the same path, faced
//! where a burst is held and its ack noted for the base; the death signal at
//! a burst's dial, or at its shifted dial, holding it `session_died` and at
//! any other write's holding nothing, the line taking the death's reason
//! unless the resend re-marked it first, and kept by the probe with no clock
//! run on it; the death at a stale burst's shift's image read, or at its
//! moved hold's read of the hands, holding it so, never faced moved, the
//! burst held behind it left as it stood, and the line's clock run from its
//! refused first dial (skep #826); over the real dialer, a refused
//! connection held `unreachable` unsent and a request the dialer cannot make
//! faced; a first dial the board gives no answer to holding every burst at
//! the board at once until the probe's verdict, `behind` a standing line
//! while it pends and `unreachable` once it finds the board silent
//! (skep #863); `resolve(send)` answering once the lines are handed
//! back, before any dial; a board the holds were not opened over stopped as
//! the caller's bug; the stored frame without its attest; P38's halted file
//! refusing every act at the principal's door, `resolve` among them, with
//! its `why` alone, said once as found, its path read and shown on the
//! native side alone; a copy the device cannot make saying why, a line at an
//! unclaimed board or one whose head will not read going to the pending
//! file, a pending file's lines moving to the board's file as soon as the
//! board's own directory is this shell's, a board away at the first touch
//! keeping its lines on the pending file while the head will not read (skep
//! #857, #859), lines held while the door could not read the file written
//! to it once it reads, the door's refusal said once (skep #823), and a
//! burst the device refused waiting with the bursts after it until the
//! probe's clock copies them in order, its node stopped, the wait said at
//! its two edges; each such answer carrying its refusal's class beside the
//! words — a full disk's, a read-only volume's, a file this shell may not
//! read, or another cause — the line waiting behind it the same (skep #820);
//! a line no file holds listed so and its landing said, under each session
//! of its principal and for each document it wrote alone, the event's state,
//! cause, hands and `sendable` as last told (skep #860), a session told
//! nothing of a moved document hearing it with the hands read for it, or
//! named not read at a stopped node and named by the walk (skep #972), a line
//! settled whose `done` is owed off the rows and counted; no
//! `held` event when a session's open reads its file, and a misplaced file
//! set aside and said on `Talk` alone; the first touch with a term taking
//! both locks and keeping the pending one with no pending file (skep #873),
//! and an earlier run's halted pending file halting the principal before
//! any hold (skep #857).
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
//! admitted on such a line and `send` refused (skep #726), the drop's `done`s
//! the device refused written at the probe and a relaunch sending none of
//! what was dropped (skep #821); a write the hold
//! never holds refused so; the head read halting, or its answer lost, holding
//! the burst unsent; a signed write's own head read deciding the board's
//! state (skep #865); and an unclaimed board serving no record the one board
//! a signed write goes out unsigned at.

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

/// Checks the position of the principal's latest arrangement write (P3).
///
/// It is the editor's own last ack `merge.undo` types its undo against:
/// noted for a burst's ack on its `doc` and a `set_arrangement`'s, never for
/// a link homed in the document nor a mint, each of which raises the hold's
/// base all the same; an earlier arrangement ack read after a later one
/// never lowers it; a held line notes nothing until the resend's read finds
/// its landing, whose position it then is (the mutant that notes it for
/// every document `written_docs` names gives the link's position, and an
/// undo typed there replaces another hand's change; the one that skips the
/// resend's landing types the undo below the person's own burst).
#[test]
fn the_arrangement_position_is_an_arrangement_writes_alone_never_a_links_or_a_mints() {
    let g = writer_at(60);
    let noted = |frame: Value, ack: Value| g.holds.note_ack(&g.session, &frame, &ack);
    let arranged = |doc: &str| g.holds.last_arranged(&g.session, doc);
    let draft = "1.0.1.0.4";
    noted(insert(DOC, json!(["x"]), 60), json!({"resp": "ack_addr", "addr": i(1), "at": 70}));
    noted(json!({"op": "set_arrangement", "doc": draft, "runs": [], "as_of": 60}), json!({"resp": "ack", "at": 71}));
    noted(json!({"op": "make_link", "home": DOC, "from": {"addrs": []}, "to": {"addrs": []}, "ty": {"addrs": []}}), json!({"resp": "ack_addr", "addr": "1.0.1.0.1.0.2.1", "at": 72}));
    noted(json!({"op": "create_new_document", "account": "1.0.1"}), json!({"resp": "ack_addr", "addr": "1.0.1.0.7", "at": 73}));
    noted(json!({"op": "stage", "from": DOC}), json!({"resp": "ack_addr", "addr": "1.0.1.0.8", "at": 74}));
    assert_eq!((arranged(DOC), arranged(draft)), (Some(70), Some(71)), "a burst's and a set_arrangement's, each on its `doc`");
    assert_eq!(g.base_of(DOC), 72, "the link raises the base");
    assert_eq!((arranged("1.0.1.0.7"), arranged("1.0.1.0.8")), (None, None), "a mint is no arrangement write");
    noted(delete(DOC, 50), json!({"resp": "ack", "at": 65}));
    assert_eq!(arranged(DOC), Some(70), "an earlier ack read after a later one lowers it never");
    assert_eq!(arranged(OTHER), None, "no write on the document, none");

    // A held burst whose landing the resend's read finds: its position.
    let g = ground();
    *g.fake.text.lock().unwrap() = "hello".into();
    *g.fake.rows.lock().unwrap() = vec![json!({"at": 77, "op": "insert", "key": g.own_key(), "docs": [DOC]})];
    g.hold(&insert(DOC, json!(["hello"]), g.fake.head()), "unreachable", true);
    assert_eq!(g.holds.last_arranged(&g.session, DOC), None, "a held line is no acknowledged write");
    g.holds.probe("b-1");
    assert!(g.lines().is_empty() && g.fake.sends() == 0, "the premise: the landing found and kept, nothing re-sent");
    assert_eq!(g.holds.last_arranged(&g.session, DOC), Some(77), "the landing the read found");
}

/// Checks that a restore is noted as an acknowledged `set_arrangement` on
/// its draft (B3-S7; P3).
///
/// The `history.restore` row's write — the library's, dialed outside the
/// one path — is noted as an ack of a `set_arrangement` on its draft: its
/// position the principal's latest arrangement write there, the base of the
/// next hold on the draft, and one of the board's acked positions; an
/// earlier restore noted after a later write lowers neither, and another
/// document is noted nothing (the mutant that notes no restore types a
/// merge's undo below the person's own restore; the one that raises no base
/// reads a later held line's landing from below the restore).
#[test]
fn a_restore_is_noted_as_an_acknowledged_set_arrangement_on_its_draft() {
    let g = writer_at(60);
    let draft = "1.0.1.0.4";
    let restored = |at: u64, position: u64| Restored { draft: crate::wire::bounded_address(draft).unwrap(), at, position };
    g.holds.note_restored(&g.session, &restored(5, 80));
    assert_eq!((g.holds.last_arranged(&g.session, draft), g.base_of(draft), g.holds.acked("b-1", 80)), (Some(80), 80, true), "the restore's position, as an ack's");
    g.holds.note_ack(&g.session, &insert(draft, json!(["x"]), 80), &json!({"resp": "ack_addr", "addr": i(1), "at": 81}));
    g.holds.note_restored(&g.session, &restored(6, 78));
    assert_eq!((g.holds.last_arranged(&g.session, draft), g.base_of(draft)), (Some(81), 81), "an earlier restore noted after a later write lowers neither");
    assert_eq!((g.holds.last_arranged(&g.session, DOC), g.base_of(DOC)), (None, 60), "another document noted nothing");
}

/// Checks that a refused run's drop drops its `behind` lines.
///
/// The run's line carries the board's verdict as its `refusal` (§3c.2, "for
/// the face") and the lines `behind` it carry none; `drop` on the refused
/// head drops it and every line held `behind` it on that document (the
/// mutant that leaves them standing), the `held` event naming the session
/// that acted; `send` on a holding line answers `not_resolvable` under the
/// writer, the probe its sender; an unknown ordinal answers `no_such_held`.
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
    // A holding line takes no send; an unknown ordinal is no_such_held.
    assert_eq!(g.holds.resolve(&g.session, k2, ResolveAct::Send).unwrap_err().name(), "not_resolvable");
    assert_eq!(g.holds.resolve(&g.session, 999, ResolveAct::Drop).unwrap_err().name(), "no_such_held");
    // Drop the refused head: the whole run goes.
    let _ = g.rx.try_iter().count();
    assert_eq!(g.holds.resolve(&g.session, k1, ResolveAct::Drop).unwrap(), Resolved::dropped(&[]));
    assert!(g.lines().is_empty(), "the run and its behind lines are dropped");
    assert_eq!(g.fake.sends(), 0, "nothing is dialed on a drop");
    let said: Vec<Event> = g.rx.try_iter().filter(|e| e.name == EventName::Held).collect();
    assert_eq!(said.len(), 1, "{said:?}");
    let said = &said[0].data;
    assert_held_event_declared(said);
    assert_eq!((said["session"].as_str(), said["held"].as_u64(), said["state"].as_str()), (Some(g.session.reference.as_str()), Some(0), Some("kept")), "the drop is said under the session that acted");
}

/// Returns a writer's ground whose document's three held lines stand moved.
///
/// The board refused the first line's resend as typed against an older
/// state, another key's row at 77 having moved the document, and the face
/// said under the ground's session named that hand. It answers the ground,
/// the lines' ordinals and the hands the face named.
fn moved_document() -> (Ground, Vec<u64>, Value) {
    let g = writer_at(80);
    g.fake.next_at.store(81, Ordering::SeqCst);
    *g.fake.rows.lock().unwrap() = vec![json!({"at": 77, "op": "insert", "key": "ff".repeat(32), "docs": [DOC]})];
    let ks: Vec<u64> = ["a", "b", "c"].iter().map(|v| g.hold(&insert(DOC, json!([v]), 70), "unreachable", false)["held"].as_u64().unwrap()).collect();
    g.fake.op_rejected.next(1, arrangement_moved(70, 77));
    g.holds.probe("b-1");
    assert!(g.lines().iter().all(|l| l["cause"] == "moved"), "the board's verdict faces every line moved: {:?}", g.lines());
    let faced: Vec<Value> = g.rx.try_iter().filter(|e| e.name == EventName::Held && e.data["state"] == "moved").map(|e| e.data).collect();
    let hands = faced.last().expect("the document faced moved")["hands"].clone();
    assert_eq!(hands, json!([{"key": "other", "fingerprint": "ff".repeat(32)}]), "the face names the other key's hand");
    (g, ks, hands)
}

/// Returns the session a restart re-opens in place of the ground's.
///
/// The ground's session is closed, and one of its principal's under its key
/// stands at its board under a fresh reference, told nothing.
fn reopened_session(g: &Ground) -> Arc<SessionEntry> {
    g.sessions.close(&g.session.reference).expect("the ground's session stands");
    let open = Open { token: Token::parse(&"8d".repeat(16)).unwrap(), facts: g.session.facts.clone(), opened_at: 80 };
    let session = g.sessions.register(&g.entry, open, &mut NoSupplements);
    g.holds.open_session(&session);
    session
}

/// Returns the `/changes` reads the ground's board has served.
fn changes_reads(g: &Ground) -> usize {
    g.fake.changes_reads.load(Ordering::SeqCst)
}

/// Checks that a drop says the state of the line that stands first.
///
/// On a moved document (§4b.1's `resolve`, §4b.2's `held`) — the board
/// refusing its head's resend as typed against an older state, every line of
/// it faced `moved` — the person drops a later line, and the line held
/// before it stands moved still — the `held` event says `moved` with the one
/// line left, never `kept` over text still held, with the hands the face
/// told the session named, no read made for them (the mutant that says
/// `kept` at every drop lifts the page's marks; the one that says it with no
/// hands erases them; the one that reads them again dials the board at every
/// drop); the drop of the last line says `kept` with none.
#[test]
fn a_drop_says_the_state_of_the_line_that_stands_first() {
    let (g, ks, hands) = moved_document();
    let reads = changes_reads(&g);
    assert_eq!(g.holds.resolve(&g.session, ks[1], ResolveAct::Drop).unwrap(), Resolved::dropped(&[]));
    let said: Vec<Event> = g.rx.try_iter().filter(|e| e.name == EventName::Held).collect();
    assert_eq!(said.len(), 1, "{said:?}");
    assert_held_event_declared(&said[0].data);
    assert_eq!((said[0].data["state"].as_str(), said[0].data["held"].as_u64(), &said[0].data["hands"]), (Some("moved"), Some(1), &hands), "the face keeps the hands it named: {said:?}");
    assert_eq!(changes_reads(&g), reads, "the hands as told, no read made");
    let left: Vec<u64> = g.lines().iter().map(|l| l["held"].as_u64().unwrap()).collect();
    assert_eq!(left, [ks[0]], "the dropped line and the one after it are gone");
    assert_eq!(g.holds.resolve(&g.session, ks[0], ResolveAct::Drop).unwrap(), Resolved::dropped(&[]));
    let said: Vec<Event> = g.rx.try_iter().filter(|e| e.name == EventName::Held).collect();
    assert_eq!((said[0].data["state"].as_str(), said[0].data["held"].as_u64()), (Some("kept"), Some(0)), "{said:?}");
}

/// Checks that a drop reads the hands where no face told the session them.
///
/// It is §4b.2's `held` event (skep #960). Three cells, each a document
/// moved on the board's verdict whose drop leaves its first line standing:
/// the session was told the lines `holding`, the walk under another session
/// of the principal's having held them moved since, telling that one alone;
/// the session is the one a restart re-opened, told nothing; and the keyless
/// session's discard, another bare session told the face. Each drop's event
/// says the document `moved` with its one line under the session that acted,
/// naming the other key's hand read once more under it, the keyless
/// session's with no `sendable` (the mutant that repeats what the session was
/// told says the document moved with no hand, a false picture of who changed
/// it).
#[test]
fn a_drop_under_a_session_told_no_moved_face_names_the_hands_it_reads() {
    let one_line = |said: &[Value], session: &SessionEntry, hands: &Value, cell: &str| {
        let [event] = said else { panic!("{cell}: one event: {said:?}") };
        let face = (event["session"].as_str(), event["state"].as_str(), event["held"].as_u64(), &event["hands"]);
        assert_eq!(face, (Some(session.reference.as_str()), Some("moved"), Some(1), hands), "{cell}: {event}");
    };
    // A keyless session holds the lines, told them `holding`; the walk, under
    // the writer, holds them moved and tells the writer alone.
    let g = writer_at(80);
    g.fake.next_at.store(81, Ordering::SeqCst);
    *g.fake.rows.lock().unwrap() = vec![json!({"at": 77, "op": "insert", "key": "ff".repeat(32), "docs": [DOC]})];
    let keyless = beside(&g, bare_facts(), 0x7c);
    let hold = |v: &str| {
        let burst = Burst::admit(insert(DOC, json!([v]), 70), &keyless).unwrap();
        g.holds.hold(&keyless, burst, Reason::of("unreachable", false), None, keyless.opened_at).answered().unwrap()["held"].as_u64().unwrap()
    };
    let ks: Vec<u64> = ["a", "b", "c"].into_iter().map(hold).collect();
    g.fake.op_rejected.next(1, arrangement_moved(70, 77));
    g.holds.probe("b-1");
    let hands = json!([{"key": "other", "fingerprint": "ff".repeat(32)}]);
    let said = told_events(&g);
    let told_holding = under(&said, &keyless).iter().all(|e| e["state"] == "holding");
    assert!(told_holding && under(&said, &g.session).iter().any(|e| e["state"] == "moved" && e["hands"] == hands), "premise: the walk tells the writer alone: {said:?}");
    let reads = changes_reads(&g);
    assert_eq!(g.holds.resolve(&keyless, ks[1], ResolveAct::Drop).unwrap(), Resolved::dropped(&[]));
    one_line(&told_events(&g), &keyless, &hands, "a session told `holding` before the walk moved the document");
    assert_eq!(changes_reads(&g), reads + 1, "the hands read once");
    // The session re-opened in the dead one's place, told nothing.
    let (g, ks, hands) = moved_document();
    let session = reopened_session(&g);
    let reads = changes_reads(&g);
    assert_eq!(g.holds.resolve(&session, ks[1], ResolveAct::Drop).unwrap(), Resolved::dropped(&[]));
    one_line(&told_events(&g), &session, &hands, "a re-opened session");
    assert_eq!(changes_reads(&g), reads + 1, "the hands read once");
    // The keyless session's discard.
    let g = bare_ground();
    let moved = Reason { cause: "moved".to_string(), refusal: Some(arrangement_moved(70, 77)), sent: false };
    *g.fake.rows.lock().unwrap() = vec![json!({"at": 77, "op": "insert", "key": "ff".repeat(32), "docs": [DOC]})];
    let ks: Vec<u64> = ["a", "b"].iter().map(|v| g.hold_for(&insert(DOC, json!([v]), 70), moved.clone()).unwrap()["held"].as_u64().unwrap()).collect();
    let hands = told_events(&g).last().expect("the document faced moved")["hands"].clone();
    assert_eq!(hands, json!([{"key": "other", "fingerprint": "ff".repeat(32)}]), "the face names the other key's hand");
    let open = Open { token: Token::parse(&"7c".repeat(16)).unwrap(), facts: bare_facts(), opened_at: 0 };
    let session = g.sessions.register(&g.entry, open, &mut NoSupplements);
    let reads = changes_reads(&g);
    assert_eq!(g.holds.resolve(&session, ks[1], ResolveAct::Drop).unwrap(), Resolved::dropped(&[]));
    let said = told_events(&g);
    one_line(&said, &session, &hands, "the keyless session's discard");
    assert_eq!((said[0].get("sendable"), changes_reads(&g)), (None, reads + 1), "no `sendable` under it, the hands read once: {said:?}");
}

/// Checks that a drop's hands the board does not give are named not read.
///
/// It is §4b.2's `held` event under §3c.5's silence (skep #960, #863). The
/// moved document's second line is dropped under a re-opened session told
/// nothing, in four cells: the read of the hands goes unanswered, the board
/// then marked unanswered; it meets the death signal, the board answering
/// still; the board's last `/health` went unanswered; and the own node
/// stands stopped — no read made in the last two. Each drop is made, and its
/// event says the document `moved` with the hands not read (SP-14); once
/// the board answers, the walk reads them under the re-opened session and
/// names them (the mutant that dials a board not answering waits out its
/// bound on every drop; the ones that owe the walk nothing leave the face
/// unread for good).
#[test]
fn a_drops_hands_the_board_does_not_give_are_named_not_read_and_the_walk_names_them() {
    let unread = json!([{"key": "unread"}]);
    for cell in ["unanswered", "died", "silent", "stopped"] {
        let (g, ks, hands) = moved_document();
        let session = reopened_session(&g);
        match cell {
            "unanswered" => g.fake.changes_unanswered.store(true, Ordering::SeqCst),
            "died" => g.fake.changes_closed.store(true, Ordering::SeqCst),
            "silent" => {
                g.fake.health_unanswered.store(true, Ordering::SeqCst);
                assert_eq!(g.holds.probe("b-1"), Turn::Unanswered, "{cell}: the probe finds the board silent");
            }
            _ => g.holds.set_node_stopped("b-1", true),
        }
        let reads = changes_reads(&g);
        assert_eq!(g.holds.resolve(&session, ks[1], ResolveAct::Drop).unwrap(), Resolved::dropped(&[]), "{cell}");
        let said = told_events(&g);
        let [event] = &said[..] else { panic!("{cell}: one event: {said:?}") };
        assert_eq!((event["state"].as_str(), event["held"].as_u64(), &event["hands"]), (Some("moved"), Some(1), &unread), "{cell}: {event}");
        let read = matches!(cell, "unanswered" | "died");
        assert_eq!(changes_reads(&g), reads + usize::from(read), "{cell}: a read made only where the board answers and the node runs");
        assert_eq!(g.holds.lock("b-1").answers(), matches!(cell, "died" | "stopped"), "{cell}: the board marked unanswered by the read alone, a silent board standing so");
        g.fake.changes_unanswered.store(false, Ordering::SeqCst);
        g.fake.changes_closed.store(false, Ordering::SeqCst);
        g.fake.health_unanswered.store(false, Ordering::SeqCst);
        g.holds.set_node_stopped("b-1", false);
        g.holds.probe("b-1");
        let named: Vec<Value> = told_events(&g).into_iter().filter(|e| e["state"] == "moved").collect();
        let [event] = &named[..] else { panic!("{cell}: the face said once more: {named:?}") };
        assert_eq!((event["session"].as_str(), &event["hands"]), (Some(session.reference.as_str()), &hands), "{cell}: the walk names the hands under the re-opened session: {event}");
    }
}

/// Checks that a drop says what stands where its document moves on meanwhile.
///
/// It is §4b.2's `held` event (skep #960). The moved document's second line
/// is dropped under a re-opened session told nothing, and while the hands
/// are read the person hands the document back by `send`: the event says
/// the document `holding` with its one line, naming no hand (the mutant that
/// says the face it read faces the person a move their own act cleared).
#[test]
fn a_drop_whose_document_moves_on_while_its_hands_are_read_says_what_stands() {
    let (g, ks, _) = moved_document();
    let session = reopened_session(&g);
    let (holds, sent, head) = (Arc::downgrade(&g.holds), Arc::clone(&session), ks[0]);
    *g.fake.at_changes.lock().unwrap() = Some(Box::new(move || {
        if let Some(holds) = holds.upgrade() {
            assert_eq!(holds.resolve(&sent, head, ResolveAct::Send).unwrap(), Resolved::HandedBack, "the send while the read is out");
        }
    }));
    assert_eq!(g.holds.resolve(&session, ks[1], ResolveAct::Drop).unwrap(), Resolved::dropped(&[]));
    let said = told_events(&g);
    let [event] = &said[..] else { panic!("one event: {said:?}") };
    assert_eq!((event["state"].as_str(), event["held"].as_u64(), event.get("hands")), (Some("holding"), Some(1), None), "{event}");
    assert_eq!(g.lines()[0]["cause"], "behind", "the line handed back");
}

/// Returns a session of `facts` registered beside the ground's, under a token
/// of `byte`, and opened as the shell opens one.
fn beside(g: &Ground, facts: Facts, byte: u8) -> Arc<SessionEntry> {
    let open = Open { token: Token::parse(&format!("{byte:02x}").repeat(16)).unwrap(), facts, opened_at: 0 };
    let session = g.sessions.register(&g.entry, open, &mut NoSupplements);
    g.holds.open_session(&session);
    session
}

/// Returns the `held` events of `said` under `session`.
fn under(said: &[Value], session: &SessionEntry) -> Vec<Value> {
    said.iter().filter(|e| e["session"] == session.reference.as_str()).cloned().collect()
}

/// Checks that a drop whose document is moved again while its hands are read
/// names them not read (§4b.2; skep #960, #972).
///
/// The moved document's second line is dropped under a keyless session of
/// the principal's told nothing of it, and while the hands are read the
/// person hands the document back by `send` under the writer, another key's
/// row lands at 79, and the walk's resend of the head is refused under a new
/// verdict. The drop's event says the document `moved` under the keyless
/// session with its hands not read, the document owing them, and the next
/// probe's walk names the hand since the person's `send` to it (the mutant
/// that says what stands with the hands as told says the document moved by
/// no one).
#[test]
fn a_drop_whose_document_is_moved_again_while_its_hands_are_read_names_them_not_read() {
    let (g, ks, _) = moved_document();
    let keyless = beside(&g, bare_facts(), 0x7c);
    let (holds, writer, head, fake) = (Arc::downgrade(&g.holds), Arc::clone(&g.session), ks[0], Arc::clone(&g.fake));
    *g.fake.at_changes.lock().unwrap() = Some(Box::new(move || {
        let Some(holds) = holds.upgrade() else { return };
        assert_eq!(holds.resolve(&writer, head, ResolveAct::Send).unwrap(), Resolved::HandedBack, "the send while the read is out");
        fake.rows.lock().unwrap().push(json!({"at": 79, "op": "insert", "key": "ee".repeat(32), "docs": [DOC]}));
        fake.op_rejected.next(1, arrangement_moved(70, 79));
        holds.probe("b-1");
    }));
    assert_eq!(g.holds.resolve(&keyless, ks[1], ResolveAct::Drop).unwrap(), Resolved::dropped(&[]));
    let said = under(&told_events(&g), &keyless);
    let [event] = &said[..] else { panic!("one event under the keyless session: {said:?}") };
    assert_eq!((event["state"].as_str(), event["held"].as_u64(), &event["hands"]), (Some("moved"), Some(1), &json!([{"key": "unread"}])), "{event}");
    assert_eq!(g.lines()[0]["refusal"], arrangement_moved(70, 79), "the head moved again under the new verdict");
    g.holds.probe("b-1");
    let named = under(&told_events(&g), &keyless);
    let [event] = &named[..] else { panic!("the walk names the hands to the keyless session: {named:?}") };
    assert_eq!((event["state"].as_str(), &event["hands"]), (Some("moved"), &json!([{"key": "other", "fingerprint": "ee".repeat(32)}])), "{event}");
}

/// Checks that hands named not read to a session the walk does not run under
/// are named to it (§3c.5; §4b.2; skep #972).
///
/// The moved document's second line is dropped under a keyless session of
/// the principal's, beside the writer the walk runs under, with the own node
/// stopped: its event names the hands not read. The node running, the next
/// probe's walk reads them for its own session and for the keyless one, and
/// names them to it, no `sendable` beside them (the mutant that says the
/// walk's read under its own session alone leaves the keyless session's face
/// not read for good).
#[test]
fn hands_named_not_read_to_a_session_the_walk_does_not_run_under_are_named_to_it() {
    let (g, ks, hands) = moved_document();
    let keyless = beside(&g, bare_facts(), 0x7c);
    g.holds.set_node_stopped("b-1", true);
    assert_eq!(g.holds.resolve(&keyless, ks[1], ResolveAct::Drop).unwrap(), Resolved::dropped(&[]));
    let said = under(&told_events(&g), &keyless);
    let [event] = &said[..] else { panic!("one event under the keyless session: {said:?}") };
    assert_eq!((event["state"].as_str(), event["held"].as_u64(), &event["hands"], event.get("sendable")), (Some("moved"), Some(1), &json!([{"key": "unread"}]), None), "{event}");
    g.holds.set_node_stopped("b-1", false);
    g.holds.probe("b-1");
    let named = under(&told_events(&g), &keyless);
    let [event] = &named[..] else { panic!("the walk names the hands to the keyless session: {named:?}") };
    assert_eq!((event["state"].as_str(), event["held"].as_u64(), &event["hands"], event.get("sendable")), (Some("moved"), Some(1), &hands, None), "{event}");
    assert_eq!(g.holds.with_principal("b-1", 1, |ph| ph.hands_owed.contains_key(DOC)), Some(false), "the debt paid");
}

/// Checks that the walk says no moved face of a document handed back while
/// its hands are read (§3c.5; skep #972).
///
/// The hands are owed a keyless session, and as the walk's read of them
/// reaches the board the person hands the document back by `send` under the
/// writer: no session is told the document `moved` (the mutant that says
/// the face it read faces the person a move their own act cleared).
#[test]
fn the_walk_says_no_moved_face_of_a_document_handed_back_while_its_hands_are_read() {
    let (g, ks, _) = moved_document();
    let keyless = beside(&g, bare_facts(), 0x7c);
    g.holds.set_node_stopped("b-1", true);
    assert_eq!(g.holds.resolve(&keyless, ks[1], ResolveAct::Drop).unwrap(), Resolved::dropped(&[]));
    let _ = told_events(&g);
    g.holds.set_node_stopped("b-1", false);
    let (holds, writer, head) = (Arc::downgrade(&g.holds), Arc::clone(&g.session), ks[0]);
    *g.fake.at_changes.lock().unwrap() = Some(Box::new(move || {
        if let Some(holds) = holds.upgrade() {
            assert_eq!(holds.resolve(&writer, head, ResolveAct::Send).unwrap(), Resolved::HandedBack, "the send while the read is out");
        }
    }));
    g.holds.probe("b-1");
    let said = told_events(&g);
    assert!(said.iter().all(|e| e["state"] != "moved"), "no moved face of a document handed back: {said:?}");
    assert_eq!(g.lines()[0]["cause"], "behind", "the line handed back");
}

/// Checks that hands named not read where no session of the principal's may
/// write are named at the board's answer (§3c.5; skep #972).
///
/// Lines stand moved at a keyless session's board, and a second keyless
/// session's drop, the own node stopped, names the hands not read. No walk
/// runs, no session of the principal's may write; the node running, the next
/// probe reads the hands for the session told them not read alone — one
/// read, the first session's face naming them already — and names them to
/// it (the mutant that pays a principal's debts in its walk alone leaves the
/// face not read for good).
#[test]
fn hands_named_not_read_where_no_session_may_write_are_named_at_the_boards_answer() {
    let g = bare_ground();
    let moved = Reason { cause: "moved".to_string(), refusal: Some(arrangement_moved(70, 77)), sent: false };
    *g.fake.rows.lock().unwrap() = vec![json!({"at": 77, "op": "insert", "key": "ff".repeat(32), "docs": [DOC]})];
    let ks: Vec<u64> = ["a", "b"].iter().map(|v| g.hold_for(&insert(DOC, json!([v]), 70), moved.clone()).unwrap()["held"].as_u64().unwrap()).collect();
    let hands = told_events(&g).last().expect("the document faced moved")["hands"].clone();
    assert_eq!(hands, json!([{"key": "other", "fingerprint": "ff".repeat(32)}]), "the face names the other key's hand");
    let second = beside(&g, bare_facts(), 0x7c);
    g.holds.set_node_stopped("b-1", true);
    assert_eq!(g.holds.resolve(&second, ks[1], ResolveAct::Drop).unwrap(), Resolved::dropped(&[]));
    let said = under(&told_events(&g), &second);
    let [event] = &said[..] else { panic!("one event under the second session: {said:?}") };
    assert_eq!(&event["hands"], &json!([{"key": "unread"}]), "{event}");
    g.holds.set_node_stopped("b-1", false);
    let reads = changes_reads(&g);
    g.holds.probe("b-1");
    let said = told_events(&g);
    let named = under(&said, &second);
    let [event] = &named[..] else { panic!("the hands named to the second session: {said:?}") };
    assert_eq!((event["state"].as_str(), event["held"].as_u64(), &event["hands"], event.get("sendable")), (Some("moved"), Some(1), &hands, None), "{event}");
    assert_eq!((under(&said, &g.session).len(), changes_reads(&g)), (0, reads + 1), "one read, for the session told the hands not read");
    assert_eq!(g.holds.with_principal("b-1", 1, |ph| ph.hands_owed.contains_key(DOC)), Some(false), "the debt paid");
}

/// Checks that a drop names the hands of its document's current verdict.
///
/// They are never an earlier move's (§4b.2; skep #973). A keyless session
/// beside the writer drops the moved document's third
/// line and is told the hand that moved it. The writer's `send` hands the
/// document back, another key's row lands, and the walk, under the writer,
/// holds the document moved again under a new verdict, telling the writer
/// alone. The keyless session's drop of the second line then names the hand
/// read for the new verdict, never the one it was told for the earlier move
/// (the mutant that keeps the hands a session was told whatever verdict they
/// were read for names in one window a move another window has seen
/// replaced).
#[test]
fn a_drop_names_the_hands_of_the_verdict_its_document_stands_on_now_never_an_earlier_moves() {
    let (g, ks, hands) = moved_document();
    let keyless = beside(&g, bare_facts(), 0x7c);
    assert_eq!(g.holds.resolve(&keyless, ks[2], ResolveAct::Drop).unwrap(), Resolved::dropped(&[]));
    let said = under(&told_events(&g), &keyless);
    let [event] = &said[..] else { panic!("one event under the keyless session: {said:?}") };
    assert_eq!(&event["hands"], &hands, "premise: told the earlier move's hand: {event}");
    assert_eq!(g.holds.resolve(&g.session, ks[0], ResolveAct::Send).unwrap(), Resolved::HandedBack);
    g.fake.rows.lock().unwrap().push(json!({"at": 78, "op": "insert", "key": "ee".repeat(32), "docs": [DOC]}));
    g.fake.op_rejected.next(1, arrangement_moved(70, 78));
    g.holds.probe("b-1");
    let newer = json!([{"key": "other", "fingerprint": "ee".repeat(32)}]);
    let said = told_events(&g);
    let told_writer: Vec<Value> = under(&said, &g.session).into_iter().filter(|e| e["state"] == "moved").collect();
    assert_eq!(told_writer.last().map(|e| &e["hands"]), Some(&newer), "premise: the walk tells the writer the new move's hand: {said:?}");
    assert!(under(&said, &keyless).is_empty(), "premise: and the keyless session nothing: {said:?}");
    assert_eq!(g.holds.resolve(&keyless, ks[1], ResolveAct::Drop).unwrap(), Resolved::dropped(&[]));
    let said = under(&told_events(&g), &keyless);
    let [event] = &said[..] else { panic!("one event under the keyless session: {said:?}") };
    assert_eq!((event["state"].as_str(), event["held"].as_u64(), &event["hands"]), (Some("moved"), Some(1), &newer), "the new move's hand, never the earlier one: {event}");
}

/// Checks that a face names no hand read for a verdict no line carries.
///
/// The writer was told the moved document's hand for the board's verdict
/// (skep #973). Its lines re-marked moved with no verdict beside them, a drop
/// under the writer says the document `moved` with no hand: the verdict the
/// hand was read for stands on no line (the mutant that repeats the hands
/// last told, whatever verdict they were read for, names a move no line
/// carries).
#[test]
fn a_face_names_no_hand_read_for_a_verdict_no_line_carries() {
    let (g, ks, _) = moved_document();
    g.holds.mark_moved("b-1", 1, DOC, None);
    assert_eq!(g.holds.resolve(&g.session, ks[2], ResolveAct::Drop).unwrap(), Resolved::dropped(&[]));
    let said = told_events(&g);
    let [event] = &said[..] else { panic!("one event: {said:?}") };
    assert_eq!((event["state"].as_str(), event["held"].as_u64(), event.get("hands")), (Some("moved"), Some(2), None), "{event}");
}

/// Checks that a landing tells a session the move the walk told another.
///
/// It is the retry's landing (§3c.3; skep #860, #973). A line held under a
/// keyless session beside the writer, its copy refused, is told `holding`
/// with why it stands off disk; the walk, under the writer, holds the
/// document moved, telling the writer alone. Once the device takes copies,
/// the probe that writes the line tells the keyless session the document
/// `moved` with the hand read for it, never the `holding` it was told before
/// the move (the mutant that repeats the face last told says a moved
/// document waits to be sent).
#[test]
fn a_landing_tells_a_session_the_move_the_walk_told_another() {
    let g = ground();
    let typed = g.fake.head();
    let keyless = beside(&g, bare_facts(), 0x7c);
    crate::held::tests::refuse_copies_as(std::io::ErrorKind::StorageFull);
    let burst = Burst::admit(insert(DOC, json!(["a"]), typed), &keyless).unwrap();
    let held = g.holds.hold(&keyless, burst, Reason::of("unreachable", false), None, keyless.opened_at).answered();
    *g.fake.rows.lock().unwrap() = vec![json!({"at": 77, "op": "insert", "key": "ff".repeat(32), "docs": [DOC]})];
    g.fake.move_arrangement(DOC, 77);
    g.holds.probe("b-1");
    crate::held::tests::take_copies();
    assert_eq!(held.unwrap()["unwritable_class"], "full", "premise: the line stands off disk");
    let said = told_events(&g);
    let states = |session: &SessionEntry| under(&said, session).iter().map(|e| e["state"].as_str().unwrap_or("?").to_string()).collect::<Vec<_>>();
    assert_eq!((states(&keyless), states(&g.session)), (vec!["holding".to_string()], vec!["sending".to_string(), "moved".to_string()]), "premise: the walk tells the writer alone: {said:?}");
    g.holds.probe("b-1");
    let said = under(&told_events(&g), &keyless);
    let [event] = &said[..] else { panic!("one event under the keyless session: {said:?}") };
    let hands = json!([{"key": "other", "fingerprint": "ff".repeat(32)}]);
    assert_eq!((event["state"].as_str(), &event["hands"], event.get("unwritable")), (Some("moved"), &hands, None), "{event}");
}

/// Checks that a landing tells a session the refusal the walk told another.
///
/// It is the retry's landing (§3c.3, §4b.2; skep #860, #974). A line held
/// under a keyless session beside the writer, its copy refused, is told
/// `holding` with why it stands off disk; the walk, under the writer, sends
/// it and the board refuses it under a permanent code, telling the writer
/// alone. Once the device takes copies, the probe that writes the line tells
/// the keyless session the run's state, `refused` under its token, never the
/// `holding` it was told before (the mutant that repeats the face last told
/// says a refused run waits to be sent).
#[test]
fn a_landing_tells_a_session_the_refusal_the_walk_told_another() {
    let g = ground();
    let typed = g.fake.head();
    let keyless = beside(&g, bare_facts(), 0x7c);
    crate::held::tests::refuse_copies_as(std::io::ErrorKind::StorageFull);
    let burst = Burst::admit(insert(DOC, json!(["a"]), typed), &keyless).unwrap();
    let held = g.holds.hold(&keyless, burst, Reason::of("unreachable", false), None, keyless.opened_at).answered();
    g.fake.op_rejected.next(1, out_of_bounds());
    g.holds.probe("b-1");
    crate::held::tests::take_copies();
    assert_eq!(held.unwrap()["unwritable_class"], "full", "premise: the line stands off disk");
    let said = told_events(&g);
    let states = |session: &SessionEntry| under(&said, session).iter().map(|e| e["state"].as_str().unwrap_or("?").to_string()).collect::<Vec<_>>();
    assert_eq!((states(&keyless), states(&g.session)), (vec!["holding".to_string()], vec!["sending".to_string(), "refused".to_string()]), "premise: the walk tells the writer alone: {said:?}");
    g.holds.probe("b-1");
    let said = under(&told_events(&g), &keyless);
    let [event] = &said[..] else { panic!("one event under the keyless session: {said:?}") };
    assert_eq!((event["state"].as_str(), event["cause"].as_str(), event.get("unwritable")), (Some("refused"), Some("out_of_bounds"), None), "{event}");
}

/// Checks that a session told nothing of a moved document lists its hands.
///
/// It is the held list (§4b.1; skep #973, #989). A session of the principal's
/// opened beside the walk's after the move, and the one a restart re-opens
/// in the walk's place, each told no event of the document, list each of its
/// three moved lines naming the hand the board's rows name — the lines behind
/// the one the verdict rides were moved by the same write — read once for
/// that session, and no event is said (the mutant that lists no hands shows
/// the document moved by no one in every window but the walk's; the one that
/// names them on the first row alone shows the lines behind it moved by no
/// one; the one that says an event at the list tells the page twice).
#[test]
fn a_session_told_nothing_of_a_moved_document_lists_its_hands() {
    for cell in ["a session opened beside", "a re-opened session"] {
        let (g, _, hands) = moved_document();
        let session = if cell == "a re-opened session" { reopened_session(&g) } else { beside(&g, writer_facts(&g.store), 0x9e) };
        let reads = changes_reads(&g);
        let rows = g.holds.lines(&session).unwrap();
        let rows = rows.as_array().unwrap();
        rows.iter().for_each(|row| crate::shapes::assert_declared("HeldRow", row));
        let named: Vec<Option<&Value>> = rows.iter().map(|row| row.get("hands")).collect();
        assert_eq!(named, [Some(&hands), Some(&hands), Some(&hands)], "{cell}: every moved row names the hands: {rows:?}");
        assert!(rows.iter().all(|row| row.get("again").is_none()), "{cell}: none named again: {rows:?}");
        assert_eq!(changes_reads(&g), reads + 1, "{cell}: read once for the session");
        assert!(told_events(&g).is_empty(), "{cell}: the list says no event");
    }
}

/// Checks that a list names the hands on each moved row and none on a line
/// held behind them (§4b.1; skep #989).
///
/// A burst held `behind` a moved document's lines waits on them, moved by no
/// write: the list names the hands on the moved rows alone (the mutant that
/// names them on every row of the document says a line no board judged was
/// moved).
#[test]
fn a_list_names_the_hands_on_each_moved_row_and_none_on_a_line_held_behind_them() {
    let (g, _, hands) = moved_document();
    let OpAnswer::Answered(Ok(behind)) = g.holds.send_burst(&g.session, insert(DOC, json!(["d"]), g.fake.head()), None) else { panic!("held behind the moved lines") };
    assert_eq!(behind["cause"], "behind", "{behind}");
    let rows = g.lines();
    let named: Vec<(Option<&str>, Option<&Value>)> = rows.iter().map(|row| (row["cause"].as_str(), row.get("hands"))).collect();
    assert_eq!(named, [(Some("moved"), Some(&hands)), (Some("moved"), Some(&hands)), (Some("moved"), Some(&hands)), (Some("behind"), None)], "{rows:?}");
}

/// Checks that a list at a stopped node names the hands not read.
///
/// The walk names them to the session that listed (§3c.5; skep #973). A
/// keyless session beside the writer lists the moved document with the own
/// node stopped: no read is made, the first row names the hands `unread`, no
/// `sendable` beside them, the document owes them, and no event is said. The
/// node running, the next probe's walk reads them for that session and tells
/// it the document `moved` with the hand, and its next list names it with no
/// read (the mutant that owes the walk nothing leaves the row unread for
/// good).
#[test]
fn a_list_at_a_stopped_node_names_the_hands_not_read_and_the_walk_names_them() {
    let (g, _, hands) = moved_document();
    let keyless = beside(&g, bare_facts(), 0x7c);
    g.holds.set_node_stopped("b-1", true);
    let reads = changes_reads(&g);
    let rows = g.holds.lines(&keyless).unwrap();
    assert_eq!((&rows[0]["hands"], rows[0].get("sendable"), changes_reads(&g)), (&json!([{"key": "unread"}]), None, reads), "no read at a stopped node: {rows}");
    assert_eq!(g.holds.with_principal("b-1", 1, |ph| ph.hands_owed.contains_key(DOC)), Some(true), "the document owes its hands");
    assert!(told_events(&g).is_empty(), "the list says no event");
    g.holds.set_node_stopped("b-1", false);
    g.holds.probe("b-1");
    let said = under(&told_events(&g), &keyless);
    let [event] = &said[..] else { panic!("the walk names the hands to the session that listed: {said:?}") };
    assert_eq!((event["state"].as_str(), event["held"].as_u64(), &event["hands"]), (Some("moved"), Some(3), &hands), "{event}");
    let reads = changes_reads(&g);
    let rows = g.holds.lines(&keyless).unwrap();
    assert_eq!((&rows[0]["hands"], changes_reads(&g)), (&hands, reads), "the next list names them with no read: {rows}");
}

/// Checks that two lists of one verdict read its hands once (skep #973).
///
/// The first list reads a moved document's hands for a session told nothing
/// of it and enters them in its memory; the second names them from there
/// with no read, and a drop under that session names them with none either
/// (the mutant that enters nothing reads the board at every list).
#[test]
fn two_lists_of_one_verdict_read_its_hands_once() {
    let (g, ks, hands) = moved_document();
    let keyless = beside(&g, bare_facts(), 0x7c);
    let reads = changes_reads(&g);
    let first = g.holds.lines(&keyless).unwrap();
    let again = g.holds.lines(&keyless).unwrap();
    assert_eq!((&first[0]["hands"], &again[0]["hands"], changes_reads(&g)), (&hands, &hands, reads + 1), "one read for two lists");
    assert_eq!(g.holds.resolve(&keyless, ks[2], ResolveAct::Drop).unwrap(), Resolved::dropped(&[]));
    let said = under(&told_events(&g), &keyless);
    let [event] = &said[..] else { panic!("one event under the keyless session: {said:?}") };
    assert_eq!((&event["hands"], changes_reads(&g)), (&hands, reads + 1), "the drop names the listed hands with no read: {event}");
}

/// Checks that every moved face told leaves the list naming its hands.
///
/// The list names them with no read (skep #973). Every path that tells a
/// session a document `moved` enters the verdict its hands were read for: a
/// first dial held moved, a first dial whose shift is not exact, the shift
/// test's flip, the walk's moved hold, a drop's owed face, and the walk's read
/// of hands a session was told not read. After each, that session's `held`
/// names the hands the face told, and reads nothing (the mutant that tells one
/// such face without its verdict reads the board at every list of that
/// session).
#[test]
fn each_path_telling_a_moved_face_leaves_its_list_naming_the_hands_with_no_read() {
    let ff = json!([{"key": "other", "fingerprint": "ff".repeat(32)}]);
    let lists_with_no_read = |g: &Ground, session: &SessionEntry, hands: &Value, cell: &str| {
        let reads = changes_reads(g);
        let rows = g.holds.lines(session).unwrap();
        assert_eq!((&rows[0]["hands"], changes_reads(g)), (hands, reads), "{cell}: {rows}");
    };
    let foreign = |g: &Ground| *g.fake.rows.lock().unwrap() = vec![json!({"at": 77, "op": "insert", "key": "ff".repeat(32), "docs": [DOC]})];
    let g = ground();
    let typed = g.fake.head();
    foreign(&g);
    g.fake.op_rejected.next(1, arrangement_moved(typed, 77));
    let OpAnswer::Answered(Ok(held)) = g.holds.send_burst(&g.session, insert(DOC, json!(["x"]), typed), None) else { panic!("held moved") };
    assert_eq!(held["cause"], "moved", "{held}");
    lists_with_no_read(&g, &g.session, &ff, "a first dial held moved");
    let g = ground();
    let typed = g.fake.head();
    foreign(&g);
    *g.fake.image.lock().unwrap() = vec![run(&i(1), 1), run(&i(10), 1), run(&i(2), 2)];
    g.fake.move_arrangement(DOC, 77);
    let OpAnswer::Answered(Ok(held)) = g.holds.send_burst(&g.session, insert_at(DOC, 2, json!(["x"]), typed), Some(anchors(Some(&i(1)), Some(&i(2))))) else { panic!("held moved") };
    assert_eq!(held["cause"], "moved", "{held}");
    lists_with_no_read(&g, &g.session, &ff, "a first dial whose shift is not exact");
    *g.fake.image.lock().unwrap() = vec![run(&i(1), 3)];
    let mut named = RowsNamed::default();
    named.note(&json!({"docs": [DOC]}));
    g.holds.note_rows("b-1", 1, &named);
    g.holds.probe("b-1");
    assert!(told_events(&g).iter().any(|e| e["state"] == "moved" && e["sendable"] == true), "premise: the flip is told");
    lists_with_no_read(&g, &g.session, &ff, "the shift test's flip");
    // The walk's moved hold, no list made before the one measured.
    let g = writer_at(80);
    g.fake.next_at.store(81, Ordering::SeqCst);
    foreign(&g);
    g.hold(&insert(DOC, json!(["a"]), 70), "unreachable", false);
    g.fake.op_rejected.next(1, arrangement_moved(70, 77));
    g.holds.probe("b-1");
    assert!(told_events(&g).iter().any(|e| e["state"] == "moved"), "premise: the walk holds the document moved");
    lists_with_no_read(&g, &g.session, &ff, "the walk's moved hold");
    let (g, ks, hands) = moved_document();
    let session = reopened_session(&g);
    assert_eq!(g.holds.resolve(&session, ks[2], ResolveAct::Drop).unwrap(), Resolved::dropped(&[]));
    lists_with_no_read(&g, &session, &hands, "a drop's owed face");
    let (g, ks, hands) = moved_document();
    let keyless = beside(&g, bare_facts(), 0x7c);
    g.holds.set_node_stopped("b-1", true);
    assert_eq!(g.holds.resolve(&keyless, ks[2], ResolveAct::Drop).unwrap(), Resolved::dropped(&[]));
    g.holds.set_node_stopped("b-1", false);
    g.holds.probe("b-1");
    lists_with_no_read(&g, &keyless, &hands, "the walk's read of hands told not read");
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

/// Checks that a hands read past the page budget is asked again at the limit
/// that fits (§3c.5; skep #972).
///
/// A burst the board refuses as typed against an older state is held moved,
/// and the read of the hands is refused `malformed_changes` naming the
/// `fits` its page takes: asked again at that limit, it names the other
/// key's hand, two reads made (the mutant that names no hand past the budget
/// says the document moved by no one).
#[test]
fn a_hands_read_past_the_page_budget_is_asked_again_at_the_limit_that_fits() {
    let g = ground();
    let typed = g.fake.head();
    *g.fake.rows.lock().unwrap() = vec![json!({"at": 77, "op": "delete", "key": "ff".repeat(32), "docs": [DOC]})];
    g.fake.changes_too_large.next(1, 1);
    g.fake.op_rejected.next(1, arrangement_moved(typed, 77));
    let OpAnswer::Answered(Ok(held)) = g.holds.send_burst(&g.session, insert(DOC, json!(["x"]), typed), None) else { panic!("held, not faced") };
    assert_eq!(held["cause"], "moved", "{held}");
    let said = told_events(&g);
    let [moved] = &said[..] else { panic!("one `held` event: {said:?}") };
    assert_eq!((moved["state"].as_str(), &moved["hands"]), (Some("moved"), &json!([{"key": "other", "fingerprint": "ff".repeat(32)}])), "{moved}");
    assert_eq!(changes_reads(&g), 2, "the page past the budget, then the page at the limit that fits");
}

/// Checks that a hands read the board answers with no page names them not
/// read, and the walk reads them again (§3c.5; skep #972).
///
/// A burst the board refuses as typed against an older state is held moved,
/// and the read of the hands is refused (`503 feed_rebuilding`). The moved
/// face names the hands not read, the board answering all the same and the
/// document owing them; each probe's walk reads them again, saying nothing
/// while no page answers, and names them once the board serves the page (the
/// mutant that names no hand where the board answered no page says the
/// document moved by no one; the one that marks the board unanswered holds
/// every burst at a board that answers).
#[test]
fn a_hands_read_the_board_answers_with_no_page_names_them_not_read_and_the_walk_reads_them_again() {
    let g = ground();
    let typed = g.fake.head();
    *g.fake.rows.lock().unwrap() = vec![json!({"at": 77, "op": "insert", "key": "ff".repeat(32), "docs": [DOC]})];
    *g.fake.changes_refused.lock().unwrap() = Some((503, json!({"error": "feed_rebuilding"})));
    g.fake.op_rejected.next(1, arrangement_moved(typed, 77));
    let OpAnswer::Answered(Ok(held)) = g.holds.send_burst(&g.session, insert(DOC, json!(["x"]), typed), None) else { panic!("held, not faced") };
    assert_eq!(held["cause"], "moved", "{held}");
    let said = told_events(&g);
    let [moved] = &said[..] else { panic!("one `held` event: {said:?}") };
    assert_eq!((moved["state"].as_str(), &moved["hands"]), (Some("moved"), &json!([{"key": "unread"}])), "{moved}");
    assert!(g.holds.lock("b-1").answers(), "the board answered: it is not marked unanswered");
    assert_eq!(g.holds.with_principal("b-1", 1, |ph| ph.hands_owed.contains_key(DOC)), Some(true), "the document owes its hands");
    let reads = changes_reads(&g);
    g.holds.probe("b-1");
    assert_eq!((changes_reads(&g), told_events(&g).len()), (reads + 1, 0), "read again, nothing said while no page answers");
    *g.fake.changes_refused.lock().unwrap() = None;
    g.holds.probe("b-1");
    let said = told_events(&g);
    let [moved] = &said[..] else { panic!("the face said once more: {said:?}") };
    assert_eq!((moved["state"].as_str(), &moved["hands"]), (Some("moved"), &json!([{"key": "other", "fingerprint": "ff".repeat(32)}])), "{moved}");
    assert_eq!(g.holds.with_principal("b-1", 1, |ph| ph.hands_owed.contains_key(DOC)), Some(false), "the debt paid");
}

/// The board's answer where it has reclaimed the history a read asks for.
fn reclaimed() -> (u16, Value) {
    (410, json!({"error": "history_reclaimed", "floor": 90}))
}

/// Checks that hands over a reclaimed history are `unknowable`, owed no read.
///
/// It is §3c.5's final state (skep #989). A burst the board refuses as typed
/// against an older state is held moved, and the read of the hands is
/// answered `410 history_reclaimed`: the moved face names the one hand
/// `unknowable`, the board answering and the document owing nothing; a probe
/// makes no `/changes` read; the writer's list names it with no read; and a
/// keyless session told nothing lists it from its own read, owing nothing,
/// its next list reading nothing (the mutant that reads a reclaimed history
/// as an answer with no page names the hands not read and reads the board
/// at every pass for as long as the line stands).
#[test]
fn hands_over_a_reclaimed_history_are_unknowable_and_owed_no_read() {
    let g = ground();
    let typed = g.fake.head();
    *g.fake.rows.lock().unwrap() = vec![json!({"at": 77, "op": "insert", "key": "ff".repeat(32), "docs": [DOC]})];
    *g.fake.changes_refused.lock().unwrap() = Some(reclaimed());
    g.fake.op_rejected.next(1, arrangement_moved(typed, 77));
    let OpAnswer::Answered(Ok(held)) = g.holds.send_burst(&g.session, insert(DOC, json!(["x"]), typed), None) else { panic!("held, not faced") };
    assert_eq!(held["cause"], "moved", "{held}");
    let unknowable = json!([{"key": "unknowable"}]);
    let said = told_events(&g);
    let [moved] = &said[..] else { panic!("one `held` event: {said:?}") };
    assert_eq!((moved["state"].as_str(), &moved["hands"], moved.get("again")), (Some("moved"), &unknowable, None), "{moved}");
    assert!(g.holds.lock("b-1").answers(), "the board answered: it is not marked unanswered");
    assert_eq!(g.holds.with_principal("b-1", 1, |ph| ph.hands_owed.contains_key(DOC)), Some(false), "no debt stands");
    let reads = changes_reads(&g);
    g.holds.probe("b-1");
    assert_eq!((changes_reads(&g), told_events(&g).len()), (reads, 0), "a probe reads nothing, and says nothing");
    let rows = g.lines();
    assert_eq!((&rows[0]["hands"], changes_reads(&g)), (&unknowable, reads), "the writer's list names them with no read: {rows:?}");
    let keyless = beside(&g, bare_facts(), 0x7c);
    let listed = g.holds.lines(&keyless).unwrap();
    assert_eq!((&listed[0]["hands"], changes_reads(&g)), (&unknowable, reads + 1), "a session told nothing reads once: {listed}");
    assert_eq!(g.holds.with_principal("b-1", 1, |ph| ph.hands_owed.contains_key(DOC)), Some(false), "and owes nothing");
    let listed = g.holds.lines(&keyless).unwrap();
    assert_eq!((&listed[0]["hands"], changes_reads(&g)), (&unknowable, reads + 1), "its next list reads nothing: {listed}");
}

/// Checks that hands owed where no session may write, over a history the
/// board then reclaims, are named `unknowable` and the debt paid (§3c.5;
/// skep #972, #989).
///
/// Lines stand moved at a keyless session's board, the hold's read of the
/// hands unanswered: the face names them not read and the document owes them.
/// The board answers, now `410 history_reclaimed`: the next probe reads once
/// for the session told them not read, says `moved` with the one hand
/// `unknowable`, and pays the debt; later probes read nothing (the mutant
/// that keeps the debt at a reclaimed history reads the board at every pass
/// for good).
#[test]
fn hands_owed_where_no_session_may_write_over_a_reclaimed_history_are_named_unknowable_and_paid() {
    let g = bare_ground();
    let moved = Reason { cause: "moved".to_string(), refusal: Some(arrangement_moved(70, 77)), sent: false };
    g.fake.changes_unanswered.store(true, Ordering::SeqCst);
    g.hold_for(&insert(DOC, json!(["a"]), 70), moved).unwrap();
    let said = told_events(&g);
    assert_eq!(said.last().map(|e| &e["hands"]), Some(&json!([{"key": "unread"}])), "premise: the hands not read: {said:?}");
    assert_eq!(g.holds.with_principal("b-1", 1, |ph| ph.hands_owed.contains_key(DOC)), Some(true), "premise: the document owes its hands");
    g.fake.changes_unanswered.store(false, Ordering::SeqCst);
    *g.fake.changes_refused.lock().unwrap() = Some(reclaimed());
    let reads = changes_reads(&g);
    g.holds.probe("b-1");
    let said = told_events(&g);
    let [event] = &said[..] else { panic!("the face said once more: {said:?}") };
    assert_eq!((event["state"].as_str(), &event["hands"], event.get("again")), (Some("moved"), &json!([{"key": "unknowable"}]), None), "{event}");
    assert_eq!(changes_reads(&g), reads + 1, "read once");
    assert_eq!(g.holds.with_principal("b-1", 1, |ph| ph.hands_owed.contains_key(DOC)), Some(false), "the debt paid");
    for _ in 0..2 {
        g.holds.probe("b-1");
    }
    assert_eq!((changes_reads(&g), told_events(&g).len()), (reads + 1, 0), "later passes read nothing");
}

/// Checks that a moved line keeps the board's verdict and takes a moved
/// document's acts.
///
/// A line held `moved` with the board's verdict as its refusal reads `moved`
/// — its state, the `held` event's — never `refused` for the refusal beside
/// it (the mutant that reads the refusal first faces it a refused run), and
/// the burst held behind it says the document `moved` still (skep #974);
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
    assert_eq!(g.states(), ["moved", "moved"], "the moved line says `moved`, and the burst behind it keeps that state in front");
    assert_eq!(g.holds.resolve(&g.session, k, ResolveAct::Send).unwrap(), Resolved::HandedBack);
    let handed: Vec<(String, Option<u64>)> = g.lines().iter().map(|l| (l["cause"].as_str().unwrap_or("?").to_string(), l["base"].as_u64())).collect();
    assert_eq!(handed, [("behind".to_string(), Some(45)), ("behind".to_string(), Some(0))], "handed back, the moved line's base raised to the verdict's `site.current`");
    g.holds.probe("b-1");
    assert_eq!(g.fake.sends(), 2, "both sent");
    assert!(g.lines().is_empty() && g.states().contains(&"kept".to_string()), "and kept");
    let k = g.hold_for(&insert(DOC, json!(["c"]), 40), moved).unwrap()["held"].as_u64().unwrap();
    assert_eq!(g.states(), ["moved"]);
    assert_eq!(g.holds.resolve(&g.session, k, ResolveAct::Drop).unwrap(), Resolved::dropped(&[]));
    assert_eq!((g.states(), g.lines().len()), (vec!["kept".to_string()], 0), "the drop of the document's one line says `kept`");
}

/// Returns the board's permanent refusal of an insert: a refused run's.
fn out_of_bounds() -> Value {
    json!({"resp": "rejected", "code": "out_of_bounds", "disposition": "permanent", "op": "insert"})
}

/// Checks that a burst held behind a moved document keeps its face in front.
///
/// It is §4b.2's `held` event (skep #974). The moved document's three lines
/// stand, the face told the session naming the other key's hand; a fourth
/// burst on it is held `behind` — the `op` answer the line's own cause — and
/// its event says the document `moved`, the four lines it holds, the hand
/// the session was told and `sendable` false, no cause and no read made; a
/// drop of the second line then names the hand as told again, no read made
/// either (the mutant that says the burst's own face says `holding` over a
/// document the person must act on; the one that reads the hands again dials
/// the board at every burst).
#[test]
fn a_burst_held_behind_a_moved_document_keeps_its_face_in_front() {
    let (g, ks, hands) = moved_document();
    let reads = changes_reads(&g);
    let OpAnswer::Answered(Ok(behind)) = g.holds.send_burst(&g.session, insert(DOC, json!(["d"]), g.fake.head()), None) else { panic!("held behind the moved lines") };
    crate::shapes::assert_declared("HeldAnswer", &behind);
    assert_eq!(behind["cause"], "behind", "the answer names the line's own cause: {behind}");
    let said = told_events(&g);
    let [event] = &said[..] else { panic!("one event: {said:?}") };
    let face = (event["state"].as_str(), event["held"].as_u64(), &event["hands"], event["sendable"].as_bool(), event.get("cause"));
    assert_eq!(face, (Some("moved"), Some(4), &hands, Some(false), None), "{event}");
    assert_eq!(changes_reads(&g), reads, "the hands as told, no read made");
    assert_eq!(g.holds.resolve(&g.session, ks[1], ResolveAct::Drop).unwrap(), Resolved::dropped(&[]));
    let said = told_events(&g);
    let [event] = &said[..] else { panic!("one event: {said:?}") };
    assert_eq!((event["state"].as_str(), event["held"].as_u64(), &event["hands"]), (Some("moved"), Some(1), &hands), "{event}");
    assert_eq!(changes_reads(&g), reads, "the drop names them as told, no read made");
}

/// Checks that a line entered behind a refused run keeps the run's face.
///
/// It is §4b.2's `held` event (skep #974). A refused run stands on the
/// document, told `refused` under the board's token. A burst held `behind` it
/// before any dial, and lines entered behind it as a dial's answer holds them —
/// a lost answer, a request the board gave no answer to, and a moved hold whose
/// read of the hands meets the death signal — each says the document `refused`
/// under the run's token, the count counting the line, while each answer names
/// the line's own cause (the mutant that says each line's own face hides the
/// act the run owes behind `holding`).
#[test]
fn every_line_entered_behind_a_refused_run_keeps_its_face_in_front() {
    let g = ground();
    g.hold_for(&insert(DOC, json!(["a"]), g.fake.head()), Reason::refused("out_of_bounds", out_of_bounds())).unwrap();
    let face = |cell: &str| {
        let said = told_events(&g);
        let [event] = &said[..] else { panic!("{cell}: one event: {said:?}") };
        (event["state"].as_str().map(str::to_owned), event["cause"].as_str().map(str::to_owned), event["held"].as_u64())
    };
    let refused = |held: u64| (Some("refused".to_string()), Some("out_of_bounds".to_string()), Some(held));
    assert_eq!(face("the run"), refused(1));
    let OpAnswer::Answered(Ok(behind)) = g.holds.send_burst(&g.session, insert(DOC, json!(["b"]), g.fake.head()), None) else { panic!("held behind the run") };
    assert_eq!(behind["cause"], "behind", "{behind}");
    assert_eq!(face("a burst held behind before any dial"), refused(2));
    assert_eq!(g.hold(&insert(DOC, json!(["c"]), g.fake.head()), "unreachable", true)["cause"], "unreachable");
    assert_eq!(face("a dial's answer lost"), refused(3));
    let burst = g.burst(&insert(DOC, json!(["d"]), g.fake.head()));
    let unanswered = g.holds.hold_unanswered(&g.session, burst, Reason::of("unreachable", true), &Refusal::Unreachable(DialError::Timeout("x".into())), g.base_of(DOC));
    assert_eq!(unanswered.answered().unwrap()["cause"], "unreachable");
    assert_eq!(face("a request the board gave no answer to"), refused(4));
    g.fake.changes_closed.store(true, Ordering::SeqCst);
    let moved = Reason { cause: "moved".to_string(), refusal: Some(arrangement_moved(40, 45)), sent: false };
    let burst = g.burst(&insert(DOC, json!(["e"]), 40));
    let OpAnswer::Died(AtDeath::Held(_)) = g.holds.hold(&g.session, burst, moved, Some("moved".into()), g.base_of(DOC)) else { panic!("held at the death") };
    assert_eq!(face("the death at the read of the hands"), refused(5));
    assert_eq!(g.lines().len(), 5, "every line held behind the run");
}

/// Checks that a burst under a session told nothing names the hands read.
///
/// It is §4b.2's `held` event (skep #974). A second writer of the principal's,
/// opened beside the ground's after the move and told nothing of it, sends a
/// burst on the moved document: it is held `behind`, and its event says the
/// document `moved` under that session alone, the four lines it holds, naming
/// the other key's hand read once for it once the board's lock is let go (the
/// mutant that repeats a face no one told the session says the document moved
/// by no one).
#[test]
fn a_burst_held_behind_a_moved_document_under_a_session_told_nothing_names_the_hands_it_reads() {
    let (g, _, hands) = moved_document();
    let second = beside(&g, writer_facts(&g.store), 0x9e);
    let reads = changes_reads(&g);
    let OpAnswer::Answered(Ok(behind)) = g.holds.send_burst(&second, insert(DOC, json!(["d"]), g.fake.head()), None) else { panic!("held behind the moved lines") };
    assert_eq!(behind["cause"], "behind", "{behind}");
    let said = told_events(&g);
    let [event] = &said[..] else { panic!("one event, under the second session alone: {said:?}") };
    let face = (event["session"].as_str(), event["state"].as_str(), event["held"].as_u64(), &event["hands"]);
    assert_eq!(face, (Some(second.reference.as_str()), Some("moved"), Some(4), &hands), "{event}");
    assert_eq!(changes_reads(&g), reads + 1, "the hands read once, for the second session");
}

/// Checks that a burst held at a stopped node keeps the moved face.
///
/// It is §3c.4's hold and §4b.2's `held` event (skep #974). The own node
/// stopped over the moved document, a burst on it is held, its answer naming
/// the stop, and its event says the document `moved` with the hand the session
/// was told, no read made. Under a keyless session of the principal's told
/// nothing of it, the event names the hands not read, no read made at a stopped
/// node, and the document owes them; once the node runs, the walk names the
/// hand to that session (the mutant that says the stop's own face hides the act
/// owed behind `holding`).
#[test]
fn a_burst_held_at_a_stopped_node_behind_a_moved_document_keeps_its_face_in_front() {
    let (g, _, hands) = moved_document();
    g.holds.set_node_stopped("b-1", true);
    let reads = changes_reads(&g);
    let OpAnswer::Answered(Ok(stopped)) = g.holds.send_burst(&g.session, insert(DOC, json!(["d"]), g.fake.head()), None) else { panic!("held at the stop") };
    assert_eq!(stopped["cause"], "stopped", "{stopped}");
    let said = told_events(&g);
    let [event] = &said[..] else { panic!("one event: {said:?}") };
    assert_eq!((event["state"].as_str(), event["held"].as_u64(), &event["hands"]), (Some("moved"), Some(4), &hands), "{event}");
    let keyless = beside(&g, bare_facts(), 0x7c);
    let OpAnswer::Answered(Ok(stopped)) = g.holds.send_burst(&keyless, insert(DOC, json!(["e"]), g.fake.head()), None) else { panic!("held at the stop") };
    assert_eq!(stopped["cause"], "stopped", "{stopped}");
    let said = told_events(&g);
    let [event] = &said[..] else { panic!("one event, under the keyless session: {said:?}") };
    let face = (event["session"].as_str(), event["state"].as_str(), event["held"].as_u64(), &event["hands"], event.get("sendable"));
    assert_eq!(face, (Some(keyless.reference.as_str()), Some("moved"), Some(5), &json!([{"key": "unread"}]), None), "{event}");
    assert_eq!(changes_reads(&g), reads, "no read at a stopped node");
    assert_eq!(g.holds.with_principal("b-1", 1, |ph| ph.hands_owed.contains_key(DOC)), Some(true), "the document owes its hands");
    g.holds.set_node_stopped("b-1", false);
    g.holds.probe("b-1");
    let named = under(&told_events(&g), &keyless);
    let [event] = &named[..] else { panic!("the walk names the hands to the keyless session: {named:?}") };
    assert_eq!((event["state"].as_str(), &event["hands"]), (Some("moved"), &hands), "{event}");
}

/// Checks that a moved line behind a refused run owes no hands of its own.
///
/// It is the walk's debt (§3c.5; skep #974). A refused run stands, and a burst
/// refused as typed against an older state is held behind it, its read of the
/// hands unanswered: the event says the run's state, `refused`, and the
/// document owes no hands to the walk, which would read them at every pass for
/// a line no face names (the mutant that enters the line's own debt keys the
/// document's debt to a line behind its first, which no read pays).
#[test]
fn a_moved_line_entered_behind_a_refused_run_owes_no_hands_of_its_own() {
    let g = ground();
    g.hold_for(&insert(DOC, json!(["a"]), g.fake.head()), Reason::refused("out_of_bounds", out_of_bounds())).unwrap();
    let _ = told_events(&g);
    g.fake.changes_unanswered.store(true, Ordering::SeqCst);
    let moved = Reason { cause: "moved".to_string(), refusal: Some(arrangement_moved(40, 45)), sent: false };
    let held = g.hold_for(&insert(DOC, json!(["b"]), 40), moved).unwrap();
    assert_eq!(held["cause"], "moved", "the answer names the line's own cause: {held}");
    let said = told_events(&g);
    let [event] = &said[..] else { panic!("one event: {said:?}") };
    let face = (event["state"].as_str(), event["cause"].as_str(), event["held"].as_u64(), event.get("hands"));
    assert_eq!(face, (Some("refused"), Some("out_of_bounds"), Some(2), None), "{event}");
    assert_eq!(g.holds.with_principal("b-1", 1, |ph| ph.hands_owed.contains_key(DOC)), Some(false), "no hands owed for a line behind the run");
}

/// Checks that a shift's end behind a refused run says the run's state.
///
/// It is §4b.2's `held` event (skep #974). While a stale burst's first dial is
/// out, another call holds a refused run on its document; the burst, refused as
/// typed against an older state, is entered behind it for its shift. Where the
/// shift's image read goes unanswered, and where it meets the death signal, the
/// line is held — the call answering `held`, or the death — and its event says
/// the run's state, `refused` under the run's token, the count counting the
/// line (the mutant that says the shift's own face says `holding` over the run
/// the person must act on).
#[test]
fn a_first_dials_shift_ends_behind_a_refused_run_with_the_runs_face_in_front() {
    for died in [false, true] {
        let cell = if died { "the death at the image read" } else { "the image read unanswered" };
        let g = ground();
        let typed = g.fake.head();
        *g.fake.image.lock().unwrap() = vec![run(&i(1), 3)];
        g.fake.move_arrangement(DOC, 77);
        g.fake.image_unread.store(!died, Ordering::SeqCst);
        g.fake.image_closed.store(died, Ordering::SeqCst);
        let (holds, session, entered) = (Arc::downgrade(&g.holds), Arc::clone(&g.session), AtomicBool::new(false));
        *g.fake.at_send.lock().unwrap() = Some(Box::new(move || {
            let Some(holds) = holds.upgrade().filter(|_| !entered.swap(true, Ordering::SeqCst)) else { return };
            let burst = Burst::admit(insert(DOC, json!(["r"]), typed), &session).unwrap();
            let held = holds.hold(&session, burst, Reason::refused("out_of_bounds", out_of_bounds()), None, session.opened_at).answered();
            assert_eq!(held.unwrap()["cause"], "out_of_bounds", "the run held while the first dial is out");
        }));
        let answer = g.holds.send_burst(&g.session, insert_at(DOC, 2, json!(["x"]), typed), Some(anchors(Some(&i(1)), Some(&i(2)))));
        *g.fake.at_send.lock().unwrap() = None;
        match (died, answer) {
            (false, OpAnswer::Answered(Ok(held))) => assert_eq!(held["cause"], "unreachable", "{cell}: {held}"),
            (true, OpAnswer::Died(AtDeath::Held(_))) => {}
            (_, answer) => panic!("{cell}: {answer:?}"),
        }
        let said = told_events(&g);
        let faces: Vec<(Option<&str>, Option<&str>, Option<u64>)> = said.iter().map(|e| (e["state"].as_str(), e["cause"].as_str(), e["held"].as_u64())).collect();
        assert_eq!(faces, [(Some("refused"), Some("out_of_bounds"), Some(1)), (Some("refused"), Some("out_of_bounds"), Some(2))], "{cell}: {said:?}");
    }
}

/// Checks that a first dial's not-exact shift keeps a refused run ahead.
///
/// It is §3c.5's moved hold and §4b.2's `held` event (skep #1002). While a
/// stale burst's first dial is out, another call holds a refused run on its
/// document, and a burst sent while the shift's image read is out is held
/// behind them; another writer has cut the span the burst's anchors bound.
/// The call answers `held` under `moved`. The run keeps its cause and the
/// board's verdict, the burst's line and the line behind it read `moved`, the
/// verdict on the burst's alone, and no event says `moved`, the run's state
/// kept in front. Where the hands' read goes unanswered, the document owes no
/// hands, and the next probe reads none (the mutant that marks every line of
/// the document says the run moved and loses its verdict; the one that marks
/// the judged line alone lists the line behind it as though no write moved
/// it; the one that says the line's own face says `moved` over the run the
/// person must act on; the one that owes the hands reads them at every pass
/// for a line no face names).
#[test]
fn a_first_dials_shift_that_is_not_exact_keeps_a_refused_run_ahead_with_its_verdict_and_its_face() {
    for unread in [false, true] {
        let cell = if unread { "the hands' read unanswered" } else { "the hands read" };
        let g = ground();
        let typed = g.fake.head();
        *g.fake.image.lock().unwrap() = vec![run(&i(1), 1), run(&i(10), 1), run(&i(2), 2)];
        g.fake.move_arrangement(DOC, 77);
        g.fake.changes_unanswered.store(unread, Ordering::SeqCst);
        let (holds, session, entered) = (Arc::downgrade(&g.holds), Arc::clone(&g.session), AtomicBool::new(false));
        *g.fake.at_send.lock().unwrap() = Some(Box::new(move || {
            let Some(holds) = holds.upgrade().filter(|_| !entered.swap(true, Ordering::SeqCst)) else { return };
            let burst = Burst::admit(insert(DOC, json!(["r"]), typed), &session).unwrap();
            let held = holds.hold(&session, burst, Reason::refused("out_of_bounds", out_of_bounds()), None, session.opened_at).answered();
            assert_eq!(held.unwrap()["cause"], "out_of_bounds", "the run held while the first dial is out");
        }));
        let (holds, session, sent) = (Arc::downgrade(&g.holds), Arc::clone(&g.session), AtomicBool::new(false));
        *g.fake.at_image.lock().unwrap() = Some(Box::new(move || {
            let Some(holds) = holds.upgrade().filter(|_| !sent.swap(true, Ordering::SeqCst)) else { return };
            let held = holds.send_burst(&session, insert(DOC, json!(["y"]), typed), None).answered();
            assert_eq!(held.unwrap()["cause"], "behind", "the burst held behind while the shift reads");
        }));
        let answer = g.holds.send_burst(&g.session, insert_at(DOC, 2, json!(["x"]), typed), Some(anchors(Some(&i(1)), Some(&i(2)))));
        *g.fake.at_send.lock().unwrap() = None;
        *g.fake.at_image.lock().unwrap() = None;
        let OpAnswer::Answered(Ok(held)) = answer else { panic!("{cell}: held moved: {answer:?}") };
        assert_eq!((held["held"].as_u64(), held["cause"].as_str()), (Some(2), Some("moved")), "{cell}: {held}");
        assert_eq!(g.holds.lock("b-1").answers(), !unread, "{cell}: premise: the hands' read the board gave no answer to marks it unanswered");
        let (refused, verdict) = (out_of_bounds(), arrangement_moved(typed, 77));
        let lines = g.lines();
        let rows: Vec<(Option<u64>, Option<&str>, Option<&Value>)> = lines.iter().map(|l| (l["held"].as_u64(), l["cause"].as_str(), l.get("refusal"))).collect();
        assert_eq!(rows, [(Some(1), Some("out_of_bounds"), Some(&refused)), (Some(2), Some("moved"), Some(&verdict)), (Some(3), Some("moved"), None)], "{cell}: {lines:?}");
        let said = told_events(&g);
        let faces: Vec<(Option<&str>, Option<&str>, Option<u64>)> = said.iter().map(|e| (e["state"].as_str(), e["cause"].as_str(), e["held"].as_u64())).collect();
        assert_eq!(faces, [(Some("refused"), Some("out_of_bounds"), Some(1)), (Some("refused"), Some("out_of_bounds"), Some(3))], "{cell}: no event says `moved`: {said:?}");
        assert_eq!(g.holds.with_principal("b-1", 1, |ph| ph.hands_owed.contains_key(DOC)), Some(false), "{cell}: no hands owed for a line behind the run");
        g.fake.changes_unanswered.store(false, Ordering::SeqCst);
        let reads = changes_reads(&g);
        g.holds.probe("b-1");
        assert_eq!((changes_reads(&g), g.fake.sends()), (reads, 1), "{cell}: the probe reads no hands and sends nothing");
    }
}

/// Checks that a first dial's not-exact shift leaves a holding line ahead.
///
/// It is §3c.5's moved hold (skep #1002). While a stale burst's first dial is
/// out, another call holds a line on its document `unreachable`, typed
/// against the document's current state, and the shift is not exact. The
/// line ahead stays `unreachable`, the burst's line reads `moved` under the
/// board's verdict, and the event says `moved` with both lines counted. The
/// next probe sends the line ahead alone and keeps it, the event saying the
/// document `moved` with the one line left and naming the line kept (the
/// mutant that marks every line of the document holds the line ahead for an
/// act no board asked for, and no probe sends it).
#[test]
fn a_first_dials_shift_that_is_not_exact_leaves_a_holding_line_ahead_to_be_sent() {
    let g = ground();
    let typed = g.fake.head();
    *g.fake.image.lock().unwrap() = vec![run(&i(1), 1), run(&i(10), 1), run(&i(2), 2)];
    g.fake.move_arrangement(DOC, 77);
    let (holds, session, entered) = (Arc::downgrade(&g.holds), Arc::clone(&g.session), AtomicBool::new(false));
    *g.fake.at_send.lock().unwrap() = Some(Box::new(move || {
        let Some(holds) = holds.upgrade().filter(|_| !entered.swap(true, Ordering::SeqCst)) else { return };
        let burst = Burst::admit(insert(DOC, json!(["h"]), 77), &session).unwrap();
        let held = holds.hold(&session, burst, Reason::of("unreachable", false), None, session.opened_at).answered();
        assert_eq!(held.unwrap()["cause"], "unreachable", "the line held while the first dial is out");
    }));
    let answer = g.holds.send_burst(&g.session, insert_at(DOC, 2, json!(["x"]), typed), Some(anchors(Some(&i(1)), Some(&i(2)))));
    *g.fake.at_send.lock().unwrap() = None;
    let OpAnswer::Answered(Ok(held)) = answer else { panic!("held moved: {answer:?}") };
    assert_eq!((held["held"].as_u64(), held["cause"].as_str()), (Some(2), Some("moved")), "{held}");
    let verdict = arrangement_moved(typed, 77);
    let lines = g.lines();
    let rows: Vec<(Option<u64>, Option<&str>, Option<&Value>)> = lines.iter().map(|l| (l["held"].as_u64(), l["cause"].as_str(), l.get("refusal"))).collect();
    assert_eq!(rows, [(Some(1), Some("unreachable"), None), (Some(2), Some("moved"), Some(&verdict))], "the line ahead keeps its state: {lines:?}");
    let said = told_events(&g);
    let faces: Vec<(Option<&str>, Option<u64>)> = said.iter().map(|e| (e["state"].as_str(), e["held"].as_u64())).collect();
    assert_eq!(faces, [(Some("holding"), Some(1)), (Some("moved"), Some(2))], "{said:?}");
    g.holds.probe("b-1");
    assert_eq!(g.fake.sends(), 2, "the line ahead sent, the burst's line awaiting the person's act");
    let said = told_events(&g);
    let kept = said.last().expect("the keep's event");
    assert_eq!((kept["state"].as_str(), kept["held"].as_u64(), &kept["landed"]), (Some("moved"), Some(1), &json!([{"held": 1, "at": 50}])), "{said:?}");
    let left: Vec<Option<u64>> = g.lines().iter().map(|l| l["held"].as_u64()).collect();
    assert_eq!(left, [Some(2)], "the burst's line stands moved");
}

/// Checks that a burst behind a line being shifted says its own face.
///
/// It is §4b.2's `held` event (skep #974). A stale burst's first dial is
/// refused and its line entered `moved` for the call's shift, said to no one
/// and taken for the call's dials; a burst sent while the shift's image read is
/// out is held `behind` it, and its event says the document `holding` under the
/// line's own cause, no read made: no act of the person's is owed a line the
/// call is settling, which lands (the mutant that keeps a moved first line in
/// front whatever has it out says `moved` for a document whose words land
/// within the call).
#[test]
fn a_burst_held_behind_a_line_a_first_dial_is_shifting_says_its_own_face() {
    let g = ground();
    let typed = g.fake.head();
    *g.fake.image.lock().unwrap() = vec![run(&i(10), 2), run(&i(1), 3)];
    g.fake.move_arrangement(DOC, 77);
    let reads = changes_reads(&g);
    let behind = Arc::new(Mutex::new(None));
    let (holds, session, seen) = (Arc::downgrade(&g.holds), Arc::clone(&g.session), Arc::clone(&behind));
    *g.fake.at_image.lock().unwrap() = Some(Box::new(move || {
        let Some(holds) = holds.upgrade() else { return };
        *seen.lock().unwrap() = Some(holds.send_burst(&session, insert(DOC, json!(["y"]), typed), None).answered().map_err(|r| r.to_value()));
    }));
    let answer = g.holds.send_burst(&g.session, insert_at(DOC, 2, json!(["x"]), typed), Some(anchors(Some(&i(1)), Some(&i(2)))));
    *g.fake.at_image.lock().unwrap() = None;
    let OpAnswer::Answered(Ok(ack)) = answer else { panic!("the shifted burst is acked within the call: {answer:?}") };
    assert_eq!(ack["resp"], "ack", "{ack}");
    let held = behind.lock().unwrap().take().expect("a burst sent while the shift reads").unwrap();
    assert_eq!(held["cause"], "behind", "{held}");
    let said = told_events(&g);
    let [event] = &said[..] else { panic!("one event: {said:?}") };
    assert_eq!((event["state"].as_str(), event["cause"].as_str(), event["held"].as_u64()), (Some("holding"), Some("behind"), Some(2)), "{event}");
    assert_eq!(changes_reads(&g), reads, "no read made");
}

/// Checks that a keep leaving a refused run first says the run's state.
///
/// It is §4b.2's `held` event (skep #974). A line held `unreachable` stands
/// first on a document, a refused run behind it; the probe sends the first and
/// keeps it, and the keep's event says the run's state, `refused` under its
/// token, the one line left, naming the line kept (the mutant that says
/// `sending` after the keep hides the act the run owes, the walk then stopping
/// at it and saying nothing).
#[test]
fn a_keep_leaving_a_refused_run_first_says_the_runs_state() {
    let g = ground();
    let first = g.hold(&insert(DOC, json!(["a"]), g.fake.head()), "unreachable", false)["held"].as_u64().unwrap();
    g.hold_for(&insert(DOC, json!(["b"]), g.fake.head()), Reason::refused("out_of_bounds", out_of_bounds())).unwrap();
    let _ = told_events(&g);
    g.holds.probe("b-1");
    let said = told_events(&g);
    let kept = said.last().expect("the keep's event");
    let face = (kept["state"].as_str(), kept["cause"].as_str(), kept["held"].as_u64(), kept["landed"][0]["held"].as_u64());
    assert_eq!(face, (Some("refused"), Some("out_of_bounds"), Some(1), Some(first)), "{said:?}");
    assert_eq!(g.fake.sends(), 1, "the run is sent nothing");
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

/// The principal's lines as a reopen of the board's held file reads them.
fn reopened(g: &Ground) -> Vec<HeldLine> {
    let Opened::Live { queue, .. } = HeldDir::new(g.store.path(), Chain::parse(&g.fake.chain).unwrap()).open_file(1, "1.0.1").unwrap() else { panic!("the board's file reads live") };
    queue.lines().to_vec()
}

/// Checks that a drop writes its run's `done`s as one copy with one sync.
///
/// A refused run of sixteen lines on one document — its head refused, the
/// fifteen after it `behind` — and a line on another document stand on the
/// board's file: the person's drop of the head settles the run's sixteen
/// `done`s as one copy, one sync under the board's lock (skep #861), and the
/// queue and a reopen hold the other document's line alone (the mutant that
/// settles the run a line at a time pays sixteen syncs while every write at
/// the board waits; the one that leaves the run's `done`s unwritten
/// relaunches the lines the person dropped).
#[test]
fn a_drop_writes_its_runs_dones_as_one_copy_with_one_sync() {
    let g = ground();
    let verdict = json!({"resp": "rejected", "code": "out_of_bounds", "disposition": "permanent", "op": "insert"});
    let k = g.hold_for(&insert(DOC, json!(["0"]), g.fake.head()), Reason::refused("out_of_bounds", verdict)).unwrap()["held"].as_u64().unwrap();
    for n in 1..16 {
        g.hold(&insert(DOC, json!([n.to_string()]), g.fake.head()), "behind", false);
    }
    g.hold(&insert(OTHER, json!(["c"]), g.fake.head()), "behind", false);
    let copies = crate::held::tests::count_copies();
    assert_eq!(g.holds.resolve(&g.session, k, ResolveAct::Drop).unwrap(), Resolved::dropped(&[]));
    crate::held::tests::take_copies();
    assert_eq!(copies.get(), 1, "the run's sixteen `done`s, one copy with one sync");
    let standing: Vec<String> = g.lines().iter().map(|l| l["doc"].as_str().unwrap_or("?").to_string()).collect();
    let on_disk: Vec<String> = reopened(&g).into_iter().map(|l| l.doc).collect();
    assert_eq!((standing, on_disk), (vec![OTHER.to_string()], vec![OTHER.to_string()]), "the run dropped, in the queue and on disk, the other document's line standing");
}

/// Checks that a moved document's marks, and the person's `send` on it, are
/// each one copy.
///
/// Sixteen lines on one document stand on the board's file, every other one
/// `sent`. The board's verdict faces the document moved, and the sixteen
/// marks land as one copy, one sync under the board's lock; the person's
/// `send` re-marks the sixteen `behind`, each raised to the verdict's
/// `site.current`, as one copy more (skep #861). A reopen reads the sixteen
/// `behind` at the raised base, each keeping its `sent` (the mutant that
/// marks a line at a time pays a sync a line at each act; the one that drops
/// the run's raise reads the rows the person acknowledged again).
#[test]
fn a_moved_documents_marks_and_the_persons_send_each_land_as_one_copy() {
    let g = ground();
    for n in 0..16 {
        g.hold(&insert(DOC, json!([n.to_string()]), g.fake.head()), "unreachable", n % 2 == 0);
    }
    let copies = crate::held::tests::count_copies();
    g.holds.mark_moved("b-1", 1, DOC, Some((1, arrangement_moved(40, 45))));
    crate::held::tests::take_copies();
    assert_eq!(copies.get(), 1, "the sixteen marks, one copy with one sync");
    assert!(reopened(&g).iter().all(|l| l.reason.cause == "moved"), "the sixteen moved on disk");
    let copies = crate::held::tests::count_copies();
    assert_eq!(g.holds.resolve(&g.session, 1, ResolveAct::Send).unwrap(), Resolved::HandedBack);
    crate::held::tests::take_copies();
    assert_eq!(copies.get(), 1, "the sixteen re-marks raised, one copy with one sync");
    let marks: Vec<(u64, String, u64, bool)> = reopened(&g).into_iter().map(|l| (l.k, l.reason.cause, l.base, l.reason.sent)).collect();
    let expected: Vec<(u64, String, u64, bool)> = (1..=16).map(|k| (k, "behind".to_string(), 45, k % 2 == 1)).collect();
    assert_eq!(marks, expected, "a reopen reads each `behind` at the raised base, its `sent` kept");
}

/// Checks that a moved document's marks the device refused wait as one run
/// for the probe's one copy.
///
/// Sixteen lines on one document stand on the board's file; with every copy
/// refused, the board's verdict faces the document moved — the queue taking
/// every mark, the sixteen copies owed, and the wait said once in the shell's
/// own window, naming the first line's re-mark (skep #861). The device taking
/// copies again, the next probe writes the sixteen as one copy, says the
/// wait's end once and dials nothing, every line awaiting the person's act,
/// and a reopen reads the sixteen moved (the mutant that loses the marks a
/// run's refused retry left owed relaunches the document as it stood before
/// the verdict).
#[test]
fn a_moved_documents_marks_the_device_refused_wait_as_one_run_for_the_probes_one_copy() {
    let g = ground();
    for n in 0..16 {
        g.hold(&insert(DOC, json!([n.to_string()]), g.fake.head()), "unreachable", false);
    }
    crate::held::tests::refuse_copies_after(0);
    g.holds.mark_moved("b-1", 1, DOC, Some((1, arrangement_moved(40, 45))));
    crate::held::tests::take_copies();
    assert!(g.lines().iter().all(|l| l["cause"] == "moved"), "the queue takes every mark");
    let begun = said_containing(&g, "could not be copied to its held file");
    assert!(begun.len() == 1 && begun[0].contains("held line 1's re-mark"), "the wait said once, naming the first mark: {begun:?}");
    let copies = crate::held::tests::count_copies();
    g.holds.probe("b-1");
    crate::held::tests::take_copies();
    assert_eq!(copies.get(), 1, "the probe writes the sixteen marks as one copy");
    assert_eq!(said_containing(&g, "wait in memory no more").len(), 1, "the wait's end said once: {:?}", g.said.lock().unwrap());
    assert_eq!(g.fake.sends(), 0, "nothing dialed: every line awaits the person's act");
    let on_disk = reopened(&g);
    assert!(on_disk.len() == 16 && on_disk.iter().all(|l| l.reason.cause == "moved"), "a reopen reads the sixteen moved: {on_disk:?}");
}

/// Checks that the re-marks of a run the writer refuses are said in one line.
///
/// Three lines of a large frame stand on one document, and the file's
/// re-mark budget is spent on the first, re-marked under causes shorter than
/// the run's until the writer refuses it. The board's verdict then faces the
/// document moved: the queue takes every line's mark, and the writer refuses
/// each copy past the budget, owed never — said in the shell's own window in
/// one line naming their count and the first, nothing waiting (SP-11; skep
/// #861; the mutant that says a line per refusal says as many lines as the
/// document holds at every such act).
#[test]
fn the_remarks_of_a_run_the_writer_refuses_are_said_in_one_line() {
    let g = bare_ground();
    for _ in 0..3 {
        g.hold(&sized_frame(MAX_FRAME_BYTES / 8), "unreachable", false);
    }
    let flaps = [Reason::of("aa", false), Reason::of("bb", false)];
    let remark = |n: usize| g.holds.with_principal("b-1", 1, |ph| ph.queue.remark(1, flaps[n % 2].clone())).expect("the principal's hold");
    assert!((0..64).any(|n| remark(n).is_err()), "premise: the re-mark budget is spent");
    let before = g.said.lock().unwrap().len();
    g.holds.mark_moved("b-1", 1, DOC, None);
    let said = g.said.lock().unwrap()[before..].to_vec();
    let moved = g.holds.with_principal("b-1", 1, |ph| ph.queue.lines().iter().all(|l| l.reason.cause == "moved"));
    assert_eq!(moved, Some(true), "the queue takes every mark");
    assert!(said.len() == 1 && said[0].contains("3 lines' re-marks could not be written, line 1's the first"), "one line for the run's refusals, and no wait: {said:?}");
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

/// Checks that no act takes a line while a first dial's shift of it is out.
///
/// A stale burst is shifted within its first dial's call, its line entered
/// moved and said to no one (skep #442), and the person's acts on it, made as
/// the shift's image read reaches the board, each answer `not_resolvable`
/// (skep #983): the call's ack keeps the line, no `held` event said (the
/// mutant that takes the line's `send` hands a line the call is shifting back
/// to the walk; the one that takes its drop settles a line the shifted dial
/// then lands).
#[test]
fn no_act_takes_a_line_while_a_first_dials_shift_of_it_is_out() {
    let g = ground();
    let typed = g.fake.head();
    *g.fake.image.lock().unwrap() = vec![run(&i(10), 2), run(&i(1), 3)];
    g.fake.move_arrangement(DOC, 77);
    let acted = Arc::new(Mutex::new(Vec::new()));
    let (holds, session, seen) = (Arc::downgrade(&g.holds), Arc::clone(&g.session), Arc::clone(&acted));
    // The line the call enters is the ground's first, ordinal 1.
    *g.fake.at_image.lock().unwrap() = Some(Box::new(move || {
        let Some(holds) = holds.upgrade() else { return };
        for act in [ResolveAct::Send, ResolveAct::Drop] {
            seen.lock().unwrap().push(holds.resolve(&session, 1, act).map_err(|r| r.to_value()));
        }
    }));
    let OpAnswer::Answered(Ok(ack)) = g.holds.send_burst(&g.session, insert_at(DOC, 2, json!(["x"]), typed), Some(anchors(Some(&i(1)), Some(&i(2))))) else {
        panic!("the shifted burst is acked within the call")
    };
    *g.fake.at_image.lock().unwrap() = None;
    assert_eq!(ack["resp"], "ack", "{ack}");
    let refused: Result<Resolved, Value> = Err(json!({"kind": "shell", "name": "not_resolvable", "held": 1}));
    assert_eq!(*acted.lock().unwrap(), vec![refused.clone(), refused], "each act refused while the shift is out");
    assert_eq!(g.fake.sends(), 2, "the page's dial and the shifted one");
    assert!(g.lines().is_empty() && g.states().is_empty(), "kept within the call, no `held` event said");
}

/// Checks that a first dial's shift lets its line go before its face is told.
///
/// A stale burst's shifted dial is refused under a `permanent` code, and the
/// `refused` face reaches a watcher on the bus on the call's own thread,
/// which drops the line as the face asks (skep #983): the drop takes it, and
/// the call answers `held` under the board's token (the mutant that lets the
/// line go as the call returns, after its face, answers the act the face
/// asks for `not_resolvable`).
#[test]
fn a_first_dials_shift_lets_its_line_go_before_its_face_is_told() {
    let g = ground();
    let typed = g.fake.head();
    *g.fake.image.lock().unwrap() = vec![run(&i(10), 2), run(&i(1), 3)];
    g.fake.move_arrangement(DOC, 77);
    // The shifted dial, the one after the image read, is refused.
    let fake = Arc::downgrade(&g.fake);
    *g.fake.at_image.lock().unwrap() = Some(Box::new(move || {
        if let Some(fake) = fake.upgrade() {
            fake.op_rejected.next(1, json!({"resp": "rejected", "code": "out_of_bounds", "disposition": "permanent", "op": "insert"}));
        }
    }));
    let acted = Arc::new(Mutex::new(Vec::new()));
    let (holds, session, seen) = (Arc::downgrade(&g.holds), Arc::clone(&g.session), Arc::clone(&acted));
    g.bus.watch(move |_, event| {
        if event.name == EventName::Held && event.data["state"] == "refused" {
            if let Some(holds) = holds.upgrade() {
                seen.lock().unwrap().push(holds.resolve(&session, 1, ResolveAct::Drop).map_err(|r| r.to_value()));
            }
        }
    });
    let OpAnswer::Answered(Ok(held)) = g.holds.send_burst(&g.session, insert_at(DOC, 2, json!(["x"]), typed), Some(anchors(Some(&i(1)), Some(&i(2))))) else { panic!("the call answers") };
    *g.fake.at_image.lock().unwrap() = None;
    assert_eq!((held["resp"].as_str(), held["cause"].as_str()), (Some("held"), Some("out_of_bounds")), "{held}");
    assert_eq!((acted.lock().unwrap().clone(), g.fake.sends()), (vec![Ok(Resolved::dropped(&[]))], 2), "the act the face asks for takes the line");
    assert!(g.lines().is_empty(), "the line dropped");
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
/// at the wrong edge, no anchors, no span and a read the board refuses each
/// fall to it (skep #442, #751). The draft as the page read it ran `abc`
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
/// or a delete's a span of other than its width; the image read is refused, an
/// answer that carries no image. Each is the first brief's moved hold,
/// unchanged: answered `held`
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
fn a_cut_span_a_lost_anchor_no_anchors_and_a_refused_read_each_fall_to_the_moved_hold() {
    let whole = || vec![run(&i(10), 2), run(&i(1), 3)];
    let insert = || -> Box<dyn Fn(u64) -> Value> { Box::new(|typed| insert_at(DOC, 2, json!(["x"]), typed)) };
    let delete = || -> Box<dyn Fn(u64) -> Value> { Box::new(|typed| delete_at(DOC, 2, 2, typed)) };
    let rearrange = || -> Box<dyn Fn(u64) -> Value> { Box::new(|typed| rearrange_at(DOC, &[2, 3, 4], typed)) };
    let between = || Some(anchors(Some(&i(1)), Some(&i(2))));
    let b_and_c = || Some(spanned(Some(&i(1)), None, &[(&i(2), 2)]));
    /// A cell of the table.
    ///
    /// It is its name, the image now, the burst typed at a state, its
    /// anchors, whether the image read is refused, the image reads made, and
    /// the why said.
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
        ("a read the board refuses", whole(), insert(), between(), true, 1, Some("the document's image could not be read: the image read was refused image_too_large")),
    ];
    for (cell, image, frame, anchors, refused, reads, why) in cells {
        let g = ground();
        let typed = g.fake.head();
        *g.fake.rows.lock().unwrap() = vec![json!({"at": 77, "op": "insert", "key": "ff".repeat(32), "docs": [DOC]})];
        *g.fake.image.lock().unwrap() = image;
        g.fake.image_refused.store(refused, Ordering::SeqCst);
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
        let sendable = (!refused).then_some(json!(false));
        assert_eq!(lines[0].get("sendable"), sendable.as_ref(), "{cell}: what a send would do, the shift's own read the test, none where it answered no image (skep #867): {lines:?}");
        let said: Vec<Value> = g.rx.try_iter().filter(|e| e.name == EventName::Held).map(|e| e.data).collect();
        let [moved] = &said[..] else { panic!("{cell}: one held event: {said:?}") };
        assert_held_event_declared(moved);
        assert_eq!(moved.get("sendable"), sendable.as_ref(), "{cell}: the event says it as the row does: {moved}");
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
/// shell's own window; no probe sends it, and the next tests it as a `send`
/// would, its deadline reset, `sendable` true and told once (skep #867); and
/// the person's `send` starts the clock afresh — the next probe sends it,
/// shifts it once and keeps it (the
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
    assert_eq!(lines[0].get("sendable"), None, "the deadline tested nothing: {lines:?}");
    g.holds.probe("b-1");
    assert_eq!(g.fake.sends(), shifts + 1, "the line awaits the person's act");
    let lines = g.lines();
    assert_eq!((lines[0]["sendable"].as_bool(), g.fake.image_reads.load(Ordering::SeqCst)), (Some(true), shifts + 1), "held past its deadline, the next probe tests the line as a send would, its deadline reset: {lines:?}");
    let told: Vec<Value> = g.rx.try_iter().filter(|e| e.name == EventName::Held).map(|e| e.data).collect();
    assert_eq!((told.len(), told[0]["state"].as_str(), told[0]["sendable"].as_bool()), (1, Some("moved"), Some(true)), "told once: {told:?}");
    assert_eq!(g.holds.resolve(&g.session, 1, ResolveAct::Send).unwrap(), Resolved::HandedBack);
    assert_eq!(g.lines()[0].get("sendable"), None, "a line that is not moved carries no mark");
    g.holds.probe("b-1");
    assert_eq!((g.fake.sends(), g.fake.image_reads.load(Ordering::SeqCst)), (shifts + 3, shifts + 2), "the person's send starts the clock afresh: sent, refused once more, shifted and kept");
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
    assert_eq!(g.holds.resolve(&g.session, k1, ResolveAct::Drop).unwrap(), Resolved::dropped(&[]));
    let docs: Vec<String> = g.lines().iter().map(|l| l["doc"].as_str().unwrap_or("?").to_string()).collect();
    assert_eq!(docs, [OTHER], "the run is dropped, the other document's line stands");
    g.holds.probe("b-1");
    assert_eq!(g.fake.sends(), 1, "the other document's line is sent");
    assert!(g.lines().is_empty() && g.states().contains(&"kept".to_string()));
}

/// Checks that a refusal held nowhere is faced, and a second `write_busy`
/// holds a burst.
///
/// A refusal the table holds nowhere is faced at the burst's first dial
/// (§3c.4's neither). A `write_busy` — read by its code off the 503 the board
/// answers it as — is reissued within the call, once, after the short wait
/// (§4b.1's `op` row: "reissued by the shell and reach the page as the ack or
/// the next refusal"), and one the reissue clears is the ack. A `write_busy`
/// the reissue meets again holds a burst (§3c.4; skep #786): answered `held`,
/// cause `unreachable`, its line `sent: false` — the board briefly full, the
/// write committing nothing — said `holding`, and at the next probe sent from
/// the head with no read for its landing and kept; while a write the hold
/// never holds faces it, `write_busy` and its 503, nothing held (the mutants
/// that face the burst's second `write_busy`, hold a non-burst's, hold the
/// first, or reissue it without bound).
#[test]
fn a_refusal_the_table_holds_nowhere_is_faced_and_a_second_write_busy_holds_a_burst() {
    let g = ground();
    g.fake.op_rejected.every(json!({"resp": "rejected", "code": "credential_refused", "detail": "index_rebuilding", "disposition": "retry", "op": "insert"}));
    let OpAnswer::Answered(Err(refused)) = g.holds.send_burst(&g.session, insert(DOC, json!(["a"]), g.fake.head()), None) else { panic!("faced at the act") };
    assert_eq!((refused.name(), g.fake.sends()), ("index_rebuilding", 1), "{refused}");
    g.fake.op_rejected.clear();
    g.fake.op_refused.next(1, (503, json!({"error": "write_busy"})));
    let OpAnswer::Answered(Ok(ack)) = g.holds.send_burst(&g.session, insert(DOC, json!(["b"]), g.fake.head()), None) else { panic!("the reissue acked") };
    assert_eq!((ack["resp"].as_str(), g.fake.sends()), (Some("ack"), 3), "reissued once: {ack}");
    g.fake.op_refused.every((503, json!({"error": "write_busy"})));
    let link = json!({"op": "make_link", "home": OTHER, "from": {"addrs": [OTHER]}, "to": {"addrs": [DOC]}, "ty": {"addrs": ["1.1.0.1.0.1.0.3.13"]}});
    let OpAnswer::Answered(Err(busy)) = g.holds.send(&g.session, link, None) else { panic!("a write the hold never holds faces it") };
    let v = busy.to_value();
    assert_eq!((busy.name(), v["status"].as_u64(), g.fake.sends()), ("write_busy", Some(503), 5), "reissued once, then faced: {v}");
    assert!(g.lines().is_empty() && g.states().is_empty(), "nothing held");
    let OpAnswer::Answered(Ok(held)) = g.holds.send_burst(&g.session, insert(DOC, json!(["c"]), g.fake.head()), None) else { panic!("held at the reissue's own write_busy") };
    assert_eq!((held["resp"].as_str(), held["cause"].as_str(), g.fake.sends()), (Some("held"), Some("unreachable"), 7), "reissued once, then held: {held}");
    let lines = g.lines();
    assert_eq!((lines.len(), lines[0]["sent"].as_bool()), (1, Some(false)), "the write committed nothing: {lines:?}");
    assert_eq!(g.states(), ["holding"]);
    g.fake.op_refused.clear();
    let reads = g.fake.changes_reads.load(Ordering::SeqCst);
    g.holds.probe("b-1");
    assert_eq!((g.fake.sends(), g.fake.changes_reads.load(Ordering::SeqCst)), (8, reads), "sent from the head, no read for a landing");
    assert!(g.lines().is_empty() && g.states() == ["sending", "kept"], "kept");
}

/// Checks that a burst held at its second `write_busy` starts its clock then.
///
/// The person's own first dial is the line's first failed send, whatever the
/// failure (`HAND_OVER_DEADLINE`; §3c.4): a burst held at the reissue's own
/// `write_busy` — `unreachable` with `sent: false`, as a connection never
/// made is held, which starts nothing — is born with its clock running, so
/// past the deadline the next probe hands it to the person, `answers_lost`
/// naming `write_busy`, dialing nothing (the mutant that reads the line's
/// clock off its reason alone sends a busy board's line at every probe, the
/// deadline never reached).
#[test]
fn a_burst_held_at_its_second_write_busy_starts_its_clock_at_its_birth() {
    let g = ground();
    g.fake.op_refused.every((503, json!({"error": "write_busy"})));
    let OpAnswer::Answered(Ok(held)) = g.holds.send_burst(&g.session, insert(DOC, json!(["a"]), g.fake.head()), None) else { panic!("held at the reissue's own write_busy") };
    assert_eq!((held["cause"].as_str(), g.fake.sends()), (Some("unreachable"), 2), "{held}");
    g.holds.advance(HAND_OVER_DEADLINE);
    g.holds.probe("b-1");
    let lines = g.lines();
    assert_eq!(g.fake.sends(), 2, "handed over, undialed");
    assert_eq!(
        (lines[0]["cause"].as_str(), lines[0]["refusal"]["last"].as_str(), lines[0]["sent"].as_bool()),
        (Some("answers_lost"), Some("write_busy"), Some(false)),
        "the person's own first dial started the clock: {lines:?}"
    );
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

/// Checks that the nine unholdable writes are refused under a standing hold.
///
/// §3c.4: `create_new_document` (skep #868), `fork`, `version`, `stage`,
/// `set_arrangement`, `make_link`, `nullify`, `edit_link` and `publish`
/// arriving while the own node is stopped, the write path poisoned or the
/// writes halted are refused at once under the hold's own name — `stopped`,
/// `poisoned`, `halted` — naming the op, held never and dialed never, at
/// the door's part the shell asks (`unholdable_refusal`) and at the hold's
/// own check behind it (`send`); a write outside the nine — a
/// `register_node` — dials as it dials under the same hold; the poisoned
/// state is the dial's
/// own `poisoned` answer, standing until a `/health` read says writes go;
/// and a board that does not answer is no hold of the kind — the write
/// meets the dial's own `unreachable` (the mutants that dial the nine
/// under a stop, hold them as bursts, leave the mint out of the set so it
/// fails `unreachable` under a stopped node, never clear the poison, or
/// read an unreachable board as a standing hold).
#[test]
fn the_nine_unholdable_writes_are_refused_under_a_standing_hold_and_dialed_elsewhere() {
    let citation = "1.1.0.1.0.1.0.3.13";
    let nine = || {
        vec![
            json!({"op": "create_new_document", "account": "1.0.1"}),
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
    assert_eq!(UNHOLDABLE_WRITES.len(), 9);
    assert!(UNHOLDABLE_WRITES.contains(&"create_new_document"), "the mint is unholdable (skep #868)");
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
        for frame in nine() {
            let op = frame["op"].as_str().unwrap();
            assert!(UNHOLDABLE_WRITES.contains(&op), "{op} is of the nine");
            let OpAnswer::Answered(Err(refused)) = g.holds.send(&g.session, frame.clone(), None) else { panic!("{cause}: {op} is refused") };
            let v = refused.to_value();
            assert_eq!((refused.name(), v["kind"].as_str(), v["op"].as_str()), (cause, Some("shell"), Some(op)), "{cause}: {v}");
            assert_eq!(g.holds.unholdable_refusal("b-1", op).map(|r| r.name().to_string()), Some(cause.to_string()), "{cause}: the door's part the shell asks");
        }
        assert_eq!((g.fake.sends(), g.lines().len()), (sends, lines), "{cause}: none of the nine is dialed or held");
        // A write outside the nine, and outside the attest's checked set, so
        // the fake's plain ack answers it.
        let outside = json!({"op": "register_node", "account": "1.0.1"});
        assert!(g.holds.unholdable_refusal("b-1", "register_node").is_none(), "{cause}: a write outside the nine meets no refusal of the kind");
        let OpAnswer::Answered(Ok(acked)) = g.holds.send(&g.session, outside, None) else { panic!("{cause}: a write outside the nine dials") };
        assert_eq!((acked["resp"].as_str(), g.fake.sends()), (Some("ack"), sends + 1), "{cause}: a write outside the nine dials as it dials");
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
    let OpAnswer::Answered(Err(refused)) = g.holds.send(&g.session, nine()[5].clone(), None) else { panic!("the dial fails as it fails") };
    assert_eq!((refused.name(), refused.to_value()["kind"].as_str()), ("unreachable", Some("unreachable")), "{refused}");
    assert!(g.lines().is_empty(), "a write the hold never holds is held never");
}

/// The `session_died` refusal the session's end answers, on the restart arm
/// with no re-open: what `Shell::died` hands `Holds::note_death`.
fn died(g: &Ground) -> Refusal {
    Refusal::shell(Name::SESSION_DIED, json!({"session": g.session.reference, "reason": crate::sessions::restart_reason(None, None)}))
}

/// Checks that the death at a dial holds a burst, and no other write.
///
/// The death is neither held nor faced (§3c.4), and a burst that met it is
/// held before its session ends (skep #786): the burst answers
/// `OpAnswer::Died` with its line held `session_died`, `sent: false` — a
/// dead token's write commits nothing — one line and one `held` event,
/// `holding` under the cause; a write the hold never holds answers
/// `OpAnswer::Died` with nothing held. Once the end derives the death, the
/// line takes its reason (`Holds::note_death`) — the `session_died` refusal,
/// its arm — and the call's answer is the `held` answer; the line still
/// holds: under the writer the person's `send` takes it not
/// (`not_resolvable`), the probe its sender, no clock runs on it, and the
/// probe sends it from the head with no read once the board takes the
/// session's writes, two minutes on, and keeps it (the mutants that face the
/// burst, hold it `unreachable`, start its clock and hand it over, read its
/// refusal as a refused run's, admit the send, or hold a non-burst write).
#[test]
fn a_death_at_a_bursts_dial_holds_it_and_at_another_writes_dial_holds_nothing() {
    let g = ground();
    g.fake.op_closed.store(true, Ordering::SeqCst);
    let OpAnswer::Died(AtDeath::Held(held)) = g.holds.send_burst(&g.session, insert(DOC, json!(["a"]), g.fake.head()), None) else { panic!("a burst's dial meets the death, and the burst is held") };
    let link = json!({"op": "make_link", "home": OTHER, "from": {"addrs": [OTHER]}, "to": {"addrs": [DOC]}, "ty": {"addrs": ["1.1.0.1.0.1.0.3.13"]}});
    assert!(matches!(g.holds.send(&g.session, link, None), OpAnswer::Died(AtDeath::NotABurst)), "a write the hold never holds meets the death, held never");
    assert_eq!(g.fake.sends(), 2, "each dialed once");
    let lines = g.lines();
    assert_eq!(lines.len(), 1, "the burst alone is held: {lines:?}");
    assert_eq!((lines[0]["cause"].as_str(), lines[0]["sent"].as_bool(), lines[0].get("refusal")), (Some("session_died"), Some(false), None), "{lines:?}");
    let events: Vec<Value> = g.rx.try_iter().filter(|e| e.name == EventName::Held).map(|e| e.data).collect();
    assert_eq!(events.len(), 1, "{events:?}");
    assert_held_event_declared(&events[0]);
    assert_eq!((events[0]["state"].as_str(), events[0]["cause"].as_str()), (Some("holding"), Some("session_died")), "never `unreachable` while the board answers: {events:?}");
    let k = lines[0]["held"].as_u64().unwrap();
    let answer = g.holds.note_death(&g.session, held, &died(&g));
    crate::shapes::assert_declared("HeldAnswer", &answer);
    assert_eq!((answer["resp"].as_str(), answer["held"].as_u64(), answer["cause"].as_str()), (Some("held"), Some(k), Some("session_died")), "{answer}");
    let lines = g.lines();
    assert_eq!(
        (lines[0]["cause"].as_str(), lines[0]["sent"].as_bool(), lines[0]["refusal"]["name"].as_str(), lines[0]["refusal"]["reason"]["arm"].as_str()),
        (Some("session_died"), Some(false), Some("session_died"), Some("restart")),
        "the line carries the death's arm: {lines:?}"
    );
    assert_eq!(g.holds.resolve(&g.session, k, ResolveAct::Send).map_err(|r| r.name().to_string()), Err("not_resolvable".to_string()), "no send of the person's moves it");
    assert!(g.states().is_empty(), "nothing more is said");
    g.fake.op_closed.store(false, Ordering::SeqCst);
    g.holds.advance(HAND_OVER_DEADLINE);
    let reads = g.fake.changes_reads.load(Ordering::SeqCst);
    g.holds.probe("b-1");
    assert_eq!((g.fake.sends(), g.fake.changes_reads.load(Ordering::SeqCst)), (3, reads), "sent from the head, no read for a landing, never handed over");
    assert!(g.lines().is_empty() && g.states() == ["sending", "kept"], "kept");
}

/// Checks that the death's reason leaves a line the resend re-marked since.
///
/// A line held at the death is the resend's as soon as a session that may
/// write stands, and a probe may reach it before the end's reason comes: a
/// resend whose answer is lost re-marks it `unreachable`, `sent`. The
/// reason arriving after leaves the line as the resend left it, and the call
/// is answered `held` all the same (the mutant that re-marks unguarded writes
/// the death over the resend's verdict, and a line that may have landed reads
/// as one the death held).
#[test]
fn the_deaths_reason_leaves_a_line_the_resend_re_marked_since() {
    let g = ground();
    g.fake.op_closed.store(true, Ordering::SeqCst);
    let OpAnswer::Died(AtDeath::Held(held)) = g.holds.send_burst(&g.session, insert(DOC, json!(["a"]), g.fake.head()), None) else { panic!("the burst is held at the death") };
    g.fake.op_closed.store(false, Ordering::SeqCst);
    g.fake.op_lost.next(1, Lost::Timeout);
    g.holds.probe("b-1");
    let resent = g.lines();
    assert_eq!((g.fake.sends(), resent[0]["cause"].as_str(), resent[0]["sent"].as_bool()), (2, Some("unreachable"), Some(true)), "{resent:?}");
    let answer = g.holds.note_death(&g.session, held, &died(&g));
    assert_eq!((answer["resp"].as_str(), answer["cause"].as_str()), (Some("held"), Some("session_died")), "{answer}");
    assert_eq!(g.lines(), resent, "the resend's re-mark stands");
}

/// Checks the transport class over the real dialer (§3c.4; skep #786).
///
/// A connection the host refuses — a port released — is the dialer's
/// `Connect`, a request the board gave no answer to, which the table holds
/// `unreachable`, `sent: false`: a burst sent there through the hold's one
/// path is answered `held`, its line saying no dial of it may have landed. A
/// request the dialer cannot make — a target outside visible ASCII — is its
/// `Request`, refused before any
/// connection opens, which the table faces (the mutant that reads a refused
/// connection as the dialer's own refusal hands the page an outage's burst;
/// the one that holds the dialer's own refusal holds a burst no send can
/// carry).
#[test]
fn a_refused_connection_is_held_unsent_and_a_request_the_dialer_cannot_make_is_faced() {
    let port = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap().local_addr().unwrap().port();
    let origin = Origin::parse(&format!("http://127.0.0.1:{port}")).unwrap();
    let dialer = skep_client::PlainHttp::new();
    let refused = dialer.exchange(&origin, &Request::post("/op", b"{}".to_vec())).unwrap_err();
    assert!(matches!(refused, DialError::Connect(_)), "a refused connection: {refused:?}");
    assert_eq!(classify(DialOutcome::Dial(&refused), &Reissues::default()), Decision::Unanswered { sent: false });
    let unmade = dialer.exchange(&origin, &Request::post("/op x", Vec::new())).unwrap_err();
    assert!(matches!(unmade, DialError::Request(_)), "a target the dialer will not write: {unmade:?}");
    assert_eq!(classify(DialOutcome::Dial(&unmade), &Reissues::default()), Decision::Neither);
    // A burst through the hold's one path at the released port: a bare
    // session, so the dial is the burst's own and no attest's read.
    let store = TempDir::new().unwrap();
    let entry = Arc::new(BoardEntry { reference: "b-1".into(), board: Arc::new(Board::new(origin, dialer)) });
    let sessions = Arc::new(Sessions::new(None, Arc::new(|_: &str| {})));
    let keys = Arc::new(FileStore::open(store.path().join("store")));
    let holds = Holds::new(Arc::clone(&sessions), Arc::new(EventBus::new()), keys, store.path().to_path_buf(), Arc::new(|_: &str| {}), [Arc::clone(&entry)]);
    let session = sessions.register(&entry, Open { token: Token::parse(&"9f".repeat(16)).unwrap(), facts: bare_facts(), opened_at: 0 }, &mut NoSupplements);
    holds.open_session(&session);
    let OpAnswer::Answered(Ok(held)) = holds.send(&session, insert(DOC, json!(["a"]), 0), None) else { panic!("held at the refused connection") };
    let lines = holds.lines(&session).unwrap();
    assert_eq!((held["cause"].as_str(), lines[0]["sent"].as_bool()), (Some("unreachable"), Some(false)), "{held} {lines}");
}

/// Checks that an unanswered first dial holds the next bursts until a verdict.
///
/// The verdict is the next probe's (§3c.4).
///
/// A burst's first dial times out: it is held `unreachable`, `sent`, and the
/// board marked unanswered. Until the next probe's verdict, a burst of the
/// same principal's is held `behind` undialed — the board may answer still —
/// and another principal's `unreachable` undialed. A probe finding the board
/// silent, a burst of the principal's is held `unreachable` at once, its
/// lines standing or none; the board answering again, every line is sent
/// and kept (the mutant that dials the next burst into the silence waits out
/// its bound; the one that holds it `unreachable` while the verdict is
/// pending says the board away on one request's failure).
#[test]
fn a_first_dial_the_board_gives_no_answer_to_holds_the_next_bursts_at_once_until_the_probes_verdict() {
    let g = ground();
    g.fake.op_lost.next(1, Lost::Timeout);
    let OpAnswer::Answered(Ok(first)) = g.holds.send_burst(&g.session, insert(DOC, json!(["a"]), g.fake.head()), None) else { panic!("held at the timeout") };
    let lines = g.lines();
    assert_eq!((first["cause"].as_str(), lines[0]["sent"].as_bool(), g.fake.sends()), (Some("unreachable"), Some(true), 1), "{first} {lines:?}");
    let OpAnswer::Answered(Ok(behind)) = g.holds.send_burst(&g.session, insert(OTHER, json!(["b"]), g.fake.head()), None) else { panic!("held behind") };
    assert_eq!((behind["cause"].as_str(), g.fake.sends()), (Some("behind"), 1), "the verdict pending, held behind undialed: {behind}");
    let open = Open { token: Token::parse(&"8e".repeat(16)).unwrap(), facts: writer_facts_as(&g.store, 2, "1.0.2"), opened_at: 0 };
    let second = g.sessions.register(&g.entry, open, &mut NoSupplements);
    g.holds.open_session(&second);
    let OpAnswer::Answered(Ok(other)) = g.holds.send(&second, insert("1.0.2.0.1", json!(["c"]), g.fake.head()), None) else { panic!("held at once") };
    assert_eq!((other["cause"].as_str(), g.fake.sends()), (Some("unreachable"), 1), "another principal's burst held at once, undialed: {other}");
    g.fake.health_unanswered.store(true, Ordering::SeqCst);
    assert_eq!(g.holds.probe("b-1"), Turn::Unanswered, "the probe's `/health` unanswered");
    let OpAnswer::Answered(Ok(silent)) = g.holds.send_burst(&g.session, insert("1.0.1.0.3", json!(["d"]), g.fake.head()), None) else { panic!("held at once") };
    assert_eq!((silent["cause"].as_str(), g.fake.sends()), (Some("unreachable"), 1), "the board silent: held `unreachable` at once, undialed: {silent}");
    g.fake.health_unanswered.store(false, Ordering::SeqCst);
    while g.holds.probe("b-1") == Turn::Bounded {}
    assert!(g.lines().is_empty() && g.holds.lines(&second).unwrap().as_array().unwrap().is_empty(), "the board answering, every line kept: {:?}", g.lines());
}

/// Checks that a first dial's shift is untried until its read is answered.
///
/// It is §3c.5's THE SHIFT (2).
///
/// An anchored burst refused at its first dial as typed against an older
/// state meets no answer to the shift's live read: the call answers `held`
/// under `unreachable`, its line `holding` with no refusal beside it, said
/// once, never `moved`, and nothing said of a shift. The board answering, the
/// next probe runs the shift from the verdict kept, no stale frame dialed
/// first: one image read more, the shifted dial, the line kept (the mutant
/// that faces the unanswered read `moved` asks the person to place words a
/// read never saw).
#[test]
fn a_first_dials_shift_whose_image_read_goes_unanswered_is_not_tried_and_runs_when_the_board_answers() {
    let g = ground();
    let typed = g.fake.head();
    *g.fake.image.lock().unwrap() = vec![run(&i(10), 2), run(&i(1), 3)];
    g.fake.move_arrangement(DOC, 77);
    g.fake.image_unread.store(true, Ordering::SeqCst);
    let OpAnswer::Answered(Ok(held)) = g.holds.send_burst(&g.session, insert_at(DOC, 2, json!(["x"]), typed), Some(anchors(Some(&i(1)), Some(&i(2))))) else { panic!("held") };
    crate::shapes::assert_declared("HeldAnswer", &held);
    assert_eq!((held["cause"].as_str(), g.fake.sends(), g.fake.image_reads.load(Ordering::SeqCst)), (Some("unreachable"), 1, 1), "{held}");
    let lines = g.lines();
    assert_eq!((lines[0]["cause"].as_str(), lines[0].get("refusal")), (Some("unreachable"), None), "{lines:?}");
    assert_eq!(g.states(), ["holding"], "said once, never moved");
    assert!(said_containing(&g, "not shifted").is_empty(), "nothing said of a shift: {:?}", g.said.lock().unwrap());
    g.fake.image_unread.store(false, Ordering::SeqCst);
    g.holds.probe("b-1");
    let sent = g.fake.sends.lock().unwrap().clone();
    assert_eq!((sent.len(), g.fake.image_reads.load(Ordering::SeqCst)), (2, 2), "the kept verdict's shift, no stale frame dialed first: {sent:?}");
    assert_eq!((sent[1]["at"]["ordinal"].as_str(), sent[1]["as_of"].as_u64()), (Some("4"), Some(77)), "{sent:?}");
    assert!(g.lines().is_empty() && g.states().contains(&"kept".to_string()));
}

/// Checks that the death at a shifted dial holds the line, and says it.
///
/// A stale burst carrying its anchors is shifted within its first dial's call
/// (skep #442), its line entered `moved` and said to no one while it is the
/// shift's; the shifted dial meets the death signal, and the line is held as
/// the death at a first dial holds a burst — `session_died`, the shifted
/// frame on it and the shift's mark of `sent` kept — the call answered
/// `OpAnswer::Died` with the line's `held` answer, the `held` event said
/// `holding` under the cause; and once the board takes the session's writes
/// the probe reads it, sends the shifted frame and keeps it (the mutant that
/// leaves the line `moved` keeps it unsaid, the person's act awaited by no
/// face, and no probe ever sends it).
#[test]
fn a_death_at_a_shifted_dial_holds_the_line_and_says_it() {
    let g = ground();
    let typed = g.fake.head();
    *g.fake.image.lock().unwrap() = vec![run(&i(10), 2), run(&i(1), 3)];
    g.fake.move_arrangement(DOC, 77);
    // The page's own dial is refused stale; the shifted one meets the death.
    let fake = Arc::clone(&g.fake);
    *g.fake.at_send.lock().unwrap() = Some(Box::new(move || fake.op_closed.store(fake.sends() == 2, Ordering::SeqCst)));
    let answer = g.holds.send_burst(&g.session, insert_at(DOC, 2, json!(["x"]), typed), Some(anchors(Some(&i(1)), Some(&i(2)))));
    *g.fake.at_send.lock().unwrap() = None;
    g.fake.op_closed.store(false, Ordering::SeqCst);
    let OpAnswer::Died(AtDeath::Held(held)) = answer else { panic!("the shifted dial meets the death, the line held") };
    let lines = g.lines();
    assert_eq!((g.fake.sends(), lines.len()), (2, 1), "{lines:?}");
    assert_eq!(
        (lines[0]["cause"].as_str(), lines[0]["sent"].as_bool(), lines[0]["frame"]["at"]["ordinal"].as_str(), lines[0].get("refusal")),
        (Some("session_died"), Some(true), Some("4"), None),
        "held at the death, the shifted frame on it, the shift's mark kept: {lines:?}"
    );
    assert_eq!(g.states(), ["holding"], "said once the death holds it");
    let answer = g.holds.note_death(&g.session, held, &died(&g));
    assert_eq!((answer["held"].as_u64(), answer["cause"].as_str()), (Some(1), Some("session_died")), "{answer}");
    g.holds.probe("b-1");
    let sent = g.fake.sends.lock().unwrap().clone();
    assert_eq!((sent.len(), sent[2]["at"]["ordinal"].as_str()), (3, Some("4")), "the shifted frame sent: {sent:?}");
    assert!(g.lines().is_empty() && g.states() == ["sending", "kept"], "kept");
}

/// Checks that the death at the shift's image read holds the burst for the
/// next session (§3c.4; skep #826).
///
/// A stale burst carrying its anchors is refused at its first dial, and the
/// shift's one image read meets the death signal: the session's death and no
/// verdict on the document, so no dial leaves and nothing is faced moved. The
/// burst is held as the death at a first dial holds one — `session_died`,
/// `sent: false`, the page's frame on its line and no refusal beside it — the
/// call answered `OpAnswer::Died` for its caller to end the session, the
/// `held` event said `holding`, and nothing said of a move; the line takes
/// the death's reason, and once the board takes the session's writes the
/// probe sends it, the board refuses it stale again, and the shift, its read
/// answered, moves it through the change and keeps it (the mutant that reads
/// the death as an unread image faces the person a document no read found
/// moved, the session left standing dead at the call).
#[test]
fn a_death_at_the_shifts_image_read_holds_the_burst_for_the_next_session() {
    let g = ground();
    let typed = g.fake.head();
    *g.fake.image.lock().unwrap() = vec![run(&i(10), 2), run(&i(1), 3)];
    g.fake.move_arrangement(DOC, 77);
    g.fake.image_closed.store(true, Ordering::SeqCst);
    let page = insert_at(DOC, 2, json!(["x"]), typed);
    let answer = g.holds.send_burst(&g.session, page.clone(), Some(anchors(Some(&i(1)), Some(&i(2)))));
    let OpAnswer::Died(AtDeath::Held(held)) = answer else { panic!("the shift's read meets the death, and the burst is held") };
    let lines = g.lines();
    assert_eq!((g.fake.sends(), g.fake.image_reads.load(Ordering::SeqCst), lines.len()), (1, 1, 1), "one dial, one image read, one line: {lines:?}");
    assert_eq!(
        (lines[0]["cause"].as_str(), lines[0]["sent"].as_bool(), lines[0].get("refusal"), &lines[0]["frame"]),
        (Some("session_died"), Some(false), None, &page),
        "held at the death, the page's frame on it: {lines:?}"
    );
    assert_eq!(g.states(), ["holding"], "said once the death holds it, never `moved`");
    assert!(said_containing(&g, "held as moved").is_empty() && said_containing(&g, "was not shifted").is_empty(), "nothing said of a move: {:?}", g.said.lock().unwrap());
    let answer = g.holds.note_death(&g.session, held, &died(&g));
    assert_eq!((answer["resp"].as_str(), answer["cause"].as_str()), (Some("held"), Some("session_died")), "{answer}");
    g.fake.image_closed.store(false, Ordering::SeqCst);
    g.holds.probe("b-1");
    let sent = g.fake.sends.lock().unwrap().clone();
    assert_eq!((sent.len(), sent[2]["at"]["ordinal"].as_str(), sent[2]["as_of"].as_u64()), (3, Some("4"), Some(77)), "sent, refused stale again, shifted and sent: {sent:?}");
    assert!(g.lines().is_empty() && g.states() == ["sending", "kept"], "kept");
}

/// Checks that the death at the moved hold's read of the hands holds the
/// burst for the next session (§3c.4; skep #826).
///
/// A stale burst the shift cannot carry — one without anchors, an agent's,
/// or one whose span another writer cut — is refused at its first dial, and
/// the moved hold's one read of the hands meets the death signal: no verdict
/// on the document, so the burst is held as the death at a first dial holds
/// one — `session_died`, `sent: false`, the page's frame on its line and no
/// refusal beside it — the call answered `OpAnswer::Died`, the `held` event
/// `holding`, and nothing said of a move. Once the board takes the session's
/// writes the probe sends it, the board refuses it stale again, and the
/// moved hold, its read answered, holds it moved under the newest verdict,
/// naming the hand that moved the document. The first dial was a failed
/// send, so the line's clock runs from it: past the deadline the probe hands
/// the line to the person, `answers_lost` naming `moved`, dialing nothing
/// (the mutant that reads the death as a read with no page faces the person
/// a move with no hand, the session left standing dead at the call; the one
/// that says the move before the read says one the death never made; the one
/// that starts no clock at the death resends the line past its deadline).
#[test]
fn a_death_at_the_moved_holds_read_of_the_hands_holds_the_burst_for_the_next_session() {
    let foreign = || vec![json!({"at": 77, "op": "insert", "key": "ff".repeat(32), "docs": [DOC]})];
    // The burst refused stale at its first dial, the read of the hands
    // meeting the death.
    let held_at_the_death = |cell: &str, anchors: Option<Anchors>| -> (Ground, u64, Value) {
        let g = ground();
        let typed = g.fake.head();
        *g.fake.rows.lock().unwrap() = foreign();
        *g.fake.image.lock().unwrap() = vec![run(&i(1), 1), run(&i(10), 1), run(&i(2), 2)];
        g.fake.move_arrangement(DOC, 77);
        g.fake.changes_closed.store(true, Ordering::SeqCst);
        let page = insert_at(DOC, 2, json!(["x"]), typed);
        let OpAnswer::Died(AtDeath::Held(held)) = g.holds.send_burst(&g.session, page.clone(), anchors) else { panic!("{cell}: the read of the hands meets the death, and the burst is held") };
        let lines = g.lines();
        assert_eq!((g.fake.sends(), g.fake.changes_reads.load(Ordering::SeqCst), lines.len()), (1, 1, 1), "{cell}: one dial, one read of the hands, one line: {lines:?}");
        assert_eq!(
            (lines[0]["cause"].as_str(), lines[0]["sent"].as_bool(), lines[0].get("refusal"), &lines[0]["frame"]),
            (Some("session_died"), Some(false), None, &page),
            "{cell}: held at the death, the page's frame on it: {lines:?}"
        );
        assert_eq!(g.states(), ["holding"], "{cell}: said once the death holds it, never `moved`");
        assert!(said_containing(&g, "held as moved").is_empty() && said_containing(&g, "was not shifted").is_empty(), "{cell}: nothing said of a move: {:?}", g.said.lock().unwrap());
        let answer = g.holds.note_death(&g.session, held, &died(&g));
        assert_eq!((answer["resp"].as_str(), answer["cause"].as_str()), (Some("held"), Some("session_died")), "{cell}: {answer}");
        g.fake.changes_closed.store(false, Ordering::SeqCst);
        (g, typed, page)
    };
    for (cell, anchors) in [("no anchors", None), ("a cut span", Some(anchors(Some(&i(1)), Some(&i(2)))))] {
        let (g, typed, page) = held_at_the_death(cell, anchors.clone());
        g.holds.probe("b-1");
        let lines = g.lines();
        assert_eq!(g.fake.sends(), 2, "{cell}: sent once more, refused stale again");
        assert_eq!(
            (lines[0]["cause"].as_str(), &lines[0]["refusal"], &lines[0]["frame"]),
            (Some("moved"), &arrangement_moved_on("insert", typed, 77), &page),
            "{cell}: held moved under the newest verdict: {lines:?}"
        );
        let said: Vec<Value> = g.rx.try_iter().filter(|e| e.name == EventName::Held).map(|e| e.data).collect();
        said.iter().for_each(assert_held_event_declared);
        let states: Vec<&str> = said.iter().filter_map(|e| e["state"].as_str()).collect();
        assert_eq!(states, ["sending", "moved"], "{cell}: {said:?}");
        assert_eq!(said[1]["hands"], json!([{"key": "other", "fingerprint": "ff".repeat(32)}]), "{cell}: the hand the read names under the session that stands: {said:?}");
        let (g, _, _) = held_at_the_death(cell, anchors);
        g.holds.advance(HAND_OVER_DEADLINE);
        g.holds.probe("b-1");
        let lines = g.lines();
        assert_eq!(g.fake.sends(), 1, "{cell}: handed over, undialed");
        assert_eq!((lines[0]["cause"].as_str(), lines[0]["refusal"]["last"].as_str()), (Some("answers_lost"), Some("moved")), "{cell}: the first dial started the clock: {lines:?}");
    }
}

/// Checks that the death at the read of the hands leaves a burst held behind
/// the line as it stood (§3c.4; skep #826).
///
/// A stale burst whose span another writer cut is refused at its first dial,
/// its line entered for the shift; as the shift's image read reaches the
/// board, the person's next burst on the document is held `behind` it. The
/// moved hold's read of the hands meets the death signal: the line is held
/// `session_died`, and the burst behind it stands `behind`, no refusal
/// beside it, awaiting no act — so the session that stands next sends both
/// (the mutant that marks the document before the read leaves the later
/// burst `moved` with no verdict, awaiting an act on a burst no board
/// judged).
#[test]
fn a_death_at_the_read_of_the_hands_leaves_a_burst_held_behind_the_line_as_it_stood() {
    let g = ground();
    let typed = g.fake.head();
    *g.fake.image.lock().unwrap() = vec![run(&i(1), 1), run(&i(10), 1), run(&i(2), 2)];
    g.fake.move_arrangement(DOC, 77);
    g.fake.changes_closed.store(true, Ordering::SeqCst);
    let (holds, session) = (Arc::downgrade(&g.holds), Arc::clone(&g.session));
    *g.fake.at_image.lock().unwrap() = Some(Box::new(move || {
        if let Some(holds) = holds.upgrade() {
            let behind = holds.send_burst(&session, insert_at(DOC, 3, json!(["y"]), typed), None);
            assert!(matches!(&behind, OpAnswer::Answered(Ok(held)) if held["cause"] == "behind"), "held behind the line: {behind:?}");
        }
    }));
    let answer = g.holds.send_burst(&g.session, insert_at(DOC, 2, json!(["x"]), typed), Some(anchors(Some(&i(1)), Some(&i(2)))));
    *g.fake.at_image.lock().unwrap() = None;
    let OpAnswer::Died(AtDeath::Held(_)) = answer else { panic!("the read of the hands meets the death, and the line is held") };
    let marks: Vec<(String, bool)> = g.lines().iter().map(|l| (l["cause"].as_str().unwrap_or("?").to_string(), l.get("refusal").is_some())).collect();
    assert_eq!(marks, [("session_died".to_string(), false), ("behind".to_string(), false)], "the burst behind the line as it stood: {:?}", g.lines());
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
/// dial past a halted file, or answer an act on it as no line). The refusal
/// carries the `why` alone, no path, in its value and its text alike (§4b.3;
/// the mutant that puts the file's path back on the detail hands the page
/// the data directory); the file is the native side's, answered for the
/// halted principal alone, said once on `Talk` as the halt is found and
/// shown there again each time it is asked.
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
    assert_eq!(refused.to_value(), json!({"kind": "shell", "name": "store_halted", "why": "newer"}), "the why alone: {refused}");
    let store_dir = g.store.path().display().to_string();
    for text in [refused.to_value().to_string(), refused.to_string()] {
        assert!(!text.contains(&store_dir) && !text.contains("principal-1.held"), "no path crosses: {text}");
    }
    assert_eq!(g.fake.sends(), 0, "nothing is dialed past a halted file");
    assert_eq!(g.holds.lines(&g.session).unwrap_err(), refused, "`held(session)` answers the same halt");
    assert_eq!(g.holds.resolve(&g.session, 1, ResolveAct::Drop).unwrap_err().name(), "store_halted", "an act on a line answers the halt, never no line");
    let held = g.hold_for(&insert(DOC, json!(["x"]), g.fake.head()), Reason::of("unreachable", false));
    assert_eq!(held.unwrap_err().name(), "store_halted", "no line is held");
    assert_eq!(std::fs::read_to_string(&file).unwrap(), newer, "the halted file is never rebuilt over");
    assert_eq!((g.holds.halted_file("b-1", 1), g.holds.halted_file("b-1", 2)), (Some(file.clone()), None), "the native side reads the halted principal's file, and no other");
    let shown = |g: &Ground| said_containing(g, &format!("principal 1's held file {} is halted (written by a newer skep)", file.display())).len();
    assert_eq!(shown(&g), 1, "the halt is said once as it is found, and not again before it is asked for: {:?}", g.said.lock().unwrap());
    assert!(g.holds.show_halted(&g.session) && g.holds.show_halted(&g.session), "the file is shown");
    assert_eq!(shown(&g), 3, "once each time it is asked: {:?}", g.said.lock().unwrap());
    let fresh = ground();
    assert!(!fresh.holds.show_halted(&fresh.session) && fresh.said.lock().unwrap().iter().all(|line| !line.contains("is halted")), "no halted file, nothing shown");
    assert_eq!(fresh.holds.halted_file("b-1", 1), None);
}

/// Checks that a line the device refuses says why and stands (§3c.3), and
/// that a line at a board whose head names no chain goes to the pending file
/// (§3c.1; skep #725, #857).
///
/// A line stands in memory ("Persist first") only where the device refuses
/// its copy: at a file the device refuses (a directory where the file would
/// be), the device's refusal rides the answer, the line stands in the queue,
/// and the next probe resends and keeps it (the mutant that drops
/// `unwritable` tells the page a burst a crash would lose is on disk). At
/// an UNCLAIMED board with no `H.1` to name its directory — which holds no
/// held text (§3c.1) — the pending store is taken all the same, and the
/// burst goes to the pending file under its own cause, no `unwritable`, the
/// store never another shell's (`Holds::another_window`), nothing under a
/// chain the board has not named; the next probe resends it unsigned, the
/// board having no term to sign over, and keeps it, the pending file
/// compacting away (the mutant that keeps an unclaimed board's line in
/// memory loses it at a close). A board whose head record stands and CANNOT
/// be read is the same: its line goes to the pending file under the hash of
/// the origin dialed, its answer carrying no `unwritable`.
#[test]
fn a_line_the_store_cannot_copy_says_why_and_stands() {
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

    // An unclaimed board: the pending file, no `unwritable`.
    let fake = Fake::new();
    fake.no_head.store(true, Ordering::SeqCst);
    fake.unclaimed.store(true, Ordering::SeqCst);
    let store = TempDir::new().unwrap();
    let facts = writer_facts(&store);
    let g = ground_over(fake, store, facts, 0);
    let answer = g.hold(&insert(DOC, json!(["hello"]), g.fake.head()), "unreachable", false);
    assert_eq!(answer["cause"], "unreachable", "{answer}");
    assert!(answer.get("unwritable").is_none(), "on disk, in the pending file: {answer}");
    assert!(!g.holds.another_window("b-1"), "an unclaimed board's store is no other shell's");
    let pending = pending_file(&g);
    assert!(std::fs::read_to_string(&pending).unwrap().contains("\"values\":[\"hello\"]"), "the pending file holds the line at {}", pending.display());
    assert!(!held_file(&g).exists(), "nothing under a chain the board has not named");
    assert_eq!(g.lines().len(), 1, "the line stands");
    g.holds.probe("b-1");
    assert_eq!(g.fake.sends(), 1, "the line is resent");
    assert!(g.lines().is_empty() && g.states().contains(&"kept".to_string()));
    assert!(!pending.exists(), "the pending file compacted away");

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

/// Checks that a pending file's lines move to the board's file as soon as
/// the board's own directory is this shell's (§3c.1; skep #859).
///
/// At an unclaimed board, with no `H.1` to name its directory, a line is
/// held on the pending file, no `unwritable`, and refused `write_busy` at
/// its resend — reissued at the next probe, the line standing. The board
/// then names its `H.1`: the probe's head read takes the board's own
/// directory and the standing line MOVES to the board's file at once, its
/// ordinal kept, the pending file removed, with no wait for an empty queue —
/// so the next burst, held `behind` it, is copied to the board's file too,
/// under the next ordinal and with no `unwritable`; once both are kept the
/// file compacts and the next line recreates it (the mutant that waits for
/// an empty queue keeps every line of the outage on a file no relaunch at
/// the chain reads; the one that renumbers a line into an empty file hands
/// the page an ordinal it does not hold).
#[test]
fn a_pending_files_lines_move_to_the_boards_file_as_soon_as_the_boards_own_directory_is_this_shells() {
    let fake = Fake::new();
    fake.no_head.store(true, Ordering::SeqCst);
    fake.unclaimed.store(true, Ordering::SeqCst);
    let store = TempDir::new().unwrap();
    let facts = writer_facts(&store);
    let g = ground_over(fake, store, facts, 0);
    let first = g.hold(&insert(DOC, json!(["a"]), g.fake.head()), "unreachable", false);
    assert!(first.get("unwritable").is_none(), "on the pending file: {first}");
    let pending = pending_file(&g);
    assert!(std::fs::read_to_string(&pending).unwrap().contains("\"values\":[\"a\"]"), "premise: the line is on the pending file");
    g.fake.op_refused.every((503, json!({"error": "write_busy"})));
    g.holds.probe("b-1");
    assert_eq!((g.fake.sends(), g.lines().len()), (1, 1), "the line stands, not taken at its resend");
    assert!(!held_file(&g).exists(), "nothing under a chain the board has not named");
    // The board names its H.1: the probe's one head read takes the board's
    // own directory, and the standing line moves to its file before the
    // resend.
    g.fake.no_head.store(false, Ordering::SeqCst);
    g.fake.unclaimed.store(false, Ordering::SeqCst);
    g.holds.probe("b-1");
    let file = held_file(&g);
    assert!(std::fs::read_to_string(&file).unwrap().contains("\"values\":[\"a\"]"), "the standing line is in the board's file, with no wait for an empty queue");
    assert!(!pending.exists(), "the pending file removed, nothing owed to the board's file");
    let joined = said_containing(&g, "joined the board's held file");
    assert!(joined.len() == 1 && joined[0].contains("1 held line joined") && !joined[0].contains("renumbered"), "{joined:?}");
    assert_eq!((g.fake.sends(), g.lines().len()), (2, 1), "resent and refused again, still standing");
    let OpAnswer::Answered(Ok(behind)) = g.holds.send_burst(&g.session, insert(DOC, json!(["b"]), g.fake.head()), None) else { panic!("held behind the standing line") };
    assert_eq!(behind["cause"], "behind", "{behind}");
    assert!(behind.get("unwritable").is_none(), "copied to the board's file: {behind}");
    let ks: Vec<u64> = g.lines().iter().map(|l| l["held"].as_u64().unwrap()).collect();
    assert_eq!(ks, [1, 2], "the moved line kept its ordinal, the next line the one after");
    assert!(std::fs::read_to_string(&file).unwrap().contains("\"values\":[\"b\"]"), "the next line is in the file too");
    g.fake.op_refused.clear();
    g.holds.probe("b-1");
    assert!(g.lines().is_empty(), "both kept");
    assert!(!file.exists(), "the file compacted away");
    let next = g.hold(&insert(DOC, json!(["c"]), g.fake.head()), "unreachable", false);
    assert!(next.get("unwritable").is_none(), "{next}");
    assert!(std::fs::read_to_string(&file).unwrap().contains("\"values\":[\"c\"]"), "the next line recreates the board's file");
}

/// Checks that lines held while the board is away stand on the pending file,
/// and stay there while the board's head turns out not to read (§3c.1,
/// §3c.3 (i); skep #857).
///
/// The board away at the session's open, the pending store is taken and a
/// burst is held on the pending file, no `unwritable`. The board returns
/// serving a head record that cannot be read: the probe takes nothing new —
/// the pending store is this shell's already — nothing is sent unsigned, and
/// the next burst, held `behind` it, is copied to the pending file too, with
/// no `unwritable`. The record then reads: one probe moves both to the
/// board's own file, removes the pending file and sends them attested, in
/// `k` order, each kept (the mutant that keeps a board-away line in memory
/// while the head will not read loses it at a close).
#[test]
fn a_board_away_at_the_first_touch_keeps_its_lines_on_the_pending_file_while_the_head_will_not_read() {
    let fake = Fake::new();
    fake.head_unreachable.store(true, Ordering::SeqCst);
    let store = TempDir::new().unwrap();
    let facts = writer_facts(&store);
    let g = ground_over(fake, store, facts, 0);
    let first = g.hold(&insert(DOC, json!(["a"]), g.fake.head()), "unreachable", false);
    assert!(first.get("unwritable").is_none(), "on the pending file, the board away: {first}");
    let pending = pending_file(&g);
    assert!(std::fs::read_to_string(&pending).unwrap().contains("\"values\":[\"a\"]"), "the line is on the pending file at {}", pending.display());
    g.fake.head_unreachable.store(false, Ordering::SeqCst);
    *g.fake.head_answer.lock().unwrap() = Some((200, json!({"resp": "delivery", "items": [{"atom": "not a head record"}]})));
    g.holds.probe("b-1");
    assert_eq!(g.fake.sends(), 0, "nothing is sent unsigned");
    let OpAnswer::Answered(Ok(behind)) = g.holds.send_burst(&g.session, insert(DOC, json!(["b"]), g.fake.head()), None) else { panic!("held behind the first") };
    assert_eq!(behind["cause"], "behind", "{behind}");
    assert!(behind.get("unwritable").is_none(), "on disk, in the pending file: {behind}");
    assert!(std::fs::read_to_string(&pending).unwrap().contains("\"values\":[\"b\"]"), "the next line is on the pending file too");
    assert!(!held_file(&g).exists(), "nothing under a chain the board has not named");
    // The record reads: one probe moves both to the board's own file and
    // sends them, signed.
    *g.fake.head_answer.lock().unwrap() = None;
    g.holds.probe("b-1");
    let sent = g.fake.sends.lock().unwrap().clone();
    let values: Vec<&str> = sent.iter().map(|frame| frame["values"][0].as_str().unwrap_or("?")).collect();
    assert_eq!(values, ["a", "b"], "both sent, in `k` order");
    assert!(sent.iter().all(|frame| frame.get("attest").is_some()), "each attested: {sent:?}");
    assert!(g.lines().is_empty() && !pending.exists(), "both kept, the pending file gone");
}

/// Checks that lines held while the principal's file cannot be read are
/// written to it once it reads (§3c.3; skep #823, #857).
///
/// The held file's name taken by a directory before the session opens, the
/// door's read is refused and said once on `Talk`, naming the loss a close
/// makes; a burst is held in memory, owed to the file, its answer carrying
/// the refusal and its class — `other`, a name taken being no full disk and
/// no read-only volume (skep #820). A probe while the name stands taken says
/// nothing more. The name freed, the next probe — the line's resend refused
/// `write_busy` — reads the file, said once, and writes the line to it. On
/// unix, a file this shell may not read refuses the door the same way, its
/// answer of the class `read_only` (the mutant that opens the file only at
/// an empty queue keeps every line in memory while one stands; the one that
/// leaves the door's refusal unsaid tells the page alone that a close loses
/// the line; the one that keeps the door's refusal as words alone gives the
/// page no class to key its act by).
#[test]
fn a_held_file_the_door_could_not_read_joins_once_it_reads() {
    door_read_refused_then_joined("a directory at the file's name", "other", |file| std::fs::create_dir_all(file).unwrap(), |file| std::fs::remove_dir(file).unwrap());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let header = format!("{{\"type\":\"skep-held-bursts\",\"v\":1,\"board\":\"{}\",\"principal\":1,\"account\":\"1.0.1\"}}\n", "ab".repeat(32));
        let unreadable = |file: &Path| {
            std::fs::create_dir_all(file.parent().unwrap()).unwrap();
            std::fs::write(file, &header).unwrap();
            std::fs::set_permissions(file, std::fs::Permissions::from_mode(0o000)).unwrap();
        };
        let readable = |file: &Path| std::fs::set_permissions(file, std::fs::Permissions::from_mode(0o600)).unwrap();
        door_read_refused_then_joined("a file this shell may not read", "read_only", unreadable, readable);
    }
}

/// Runs one cell of the door's refused read and the join once it reads.
///
/// It is a cell of [`a_held_file_the_door_could_not_read_joins_once_it_reads`]:
/// `refuse` makes the held file's read refused before the session opens, its
/// answer of `class`, and `free` lets it read again.
fn door_read_refused_then_joined(cell: &str, class: &str, refuse: impl Fn(&Path), free: impl Fn(&Path)) {
    let store = TempDir::new().unwrap();
    let file = store.path().join("held").join("ab".repeat(32)).join("principal-1.held");
    refuse(&file);
    let facts = writer_facts(&store);
    let g = ground_in(store, facts, 0);
    let refused_read = "held: principal 1's held file could not be read";
    let said = said_containing(&g, refused_read);
    assert!(said.len() == 1 && said[0].contains("a close before then loses them"), "{cell}: the door's refused read said once: {said:?}");
    let answer = g.hold(&insert(DOC, json!(["a"]), g.fake.head()), "unreachable", false);
    assert!(answer["unwritable"].as_str().is_some_and(|why| why.contains("could not be read")), "{cell}: the refusal rides the answer: {answer}");
    assert_eq!(answer["unwritable_class"].as_str(), Some(class), "{cell}: its class beside it: {answer}");
    g.fake.op_refused.every((503, json!({"error": "write_busy"})));
    g.holds.probe("b-1");
    assert_eq!(said_containing(&g, refused_read).len(), 1, "{cell}: a retry the same cause refuses says nothing more: {:?}", g.said.lock().unwrap());
    free(&file);
    g.holds.probe("b-1");
    assert!(std::fs::read_to_string(&file).unwrap().contains("\"values\":[\"a\"]"), "{cell}: the line is written to the file once it reads");
    let opened = said_containing(&g, "held file opens");
    assert!(opened.len() == 1 && opened[0].contains("the lines held for the principal go to it"), "{cell}: the open said once: {opened:?}");
    let joined = said_containing(&g, "joined the board's held file");
    assert!(joined.len() == 1 && joined[0].contains("1 held line joined"), "{cell}: {joined:?}");
    assert_eq!(g.lines().len(), 1, "{cell}: the line stands in the file, its resend refused");
}

/// Checks that the probe's clock copies the bursts the device refused.
///
/// It is §3c.3's wait (skep #813). The held file's name taken by a
/// directory, a burst is held `unwritable` under the device's refusal, of
/// the class `other`, and the next burst is held `behind` it under the same
/// refusal and class, neither on disk; the wait is said once in the shell's
/// own window. The node stopped and the name freed, the next probe — which
/// dials nothing while the node is stopped — copies both in `k` order and
/// says the wait's end once, and a second probe says nothing more (the
/// mutant that retries at a hold alone keeps both in memory while no one
/// types; the one that gates the retry on the node or the board keeps them
/// while the person has stopped it).
#[test]
fn a_burst_the_device_refused_waits_with_the_bursts_after_it_and_the_probes_clock_copies_them() {
    let g = ground();
    let file = held_file(&g);
    std::fs::create_dir(&file).unwrap();
    let first = g.hold(&insert(DOC, json!(["a"]), g.fake.head()), "unreachable", false);
    let why = first["unwritable"].as_str().unwrap_or_else(|| panic!("the device's refusal rides the answer: {first}")).to_string();
    assert_eq!(first["unwritable_class"], "other", "a name a directory takes is no full disk and no read-only volume: {first}");
    let OpAnswer::Answered(Ok(behind)) = g.holds.send_burst(&g.session, insert(DOC, json!(["b"]), g.fake.head()), None) else { panic!("held behind the first") };
    let waits = (behind["cause"].as_str(), behind["unwritable"].as_str(), behind["unwritable_class"].as_str());
    assert_eq!(waits, (Some("behind"), Some(why.as_str()), Some("other")), "the line behind waits under the same refusal: {behind}");
    assert_eq!(said_containing(&g, "could not be copied to its held file").len(), 1, "the wait said once as it begins: {:?}", g.said.lock().unwrap());
    g.holds.set_node_stopped("b-1", true);
    std::fs::remove_dir(&file).unwrap();
    g.holds.probe("b-1");
    let copied: Vec<u64> = file_lines(&std::fs::read_to_string(&file).unwrap()).iter().map(|line| line["held"].as_u64().unwrap()).collect();
    assert_eq!(copied, [1, 2], "both copied by the probe, in `k` order");
    assert_eq!(g.fake.sends(), 0, "nothing dialed while the node is stopped");
    assert_eq!(said_containing(&g, "wait in memory no more").len(), 1, "the wait's end said once: {:?}", g.said.lock().unwrap());
    g.holds.probe("b-1");
    let said = (said_containing(&g, "could not be copied").len(), said_containing(&g, "wait in memory no more").len());
    assert_eq!(said, (1, 1), "a second probe says nothing more: {:?}", g.said.lock().unwrap());
}

/// Checks that a refusal at the writer reaches the page with its class.
///
/// It is §3c.3's face, its act keyed by cause (skep #820). The device refuses
/// every copy — as a full disk, then as a read-only volume: a burst is held
/// with the device's words as `unwritable` and their class beside them as
/// `unwritable_class`, `full` or `read_only`, and the next burst, held
/// `behind` it and waiting behind its copy, carries the same words and the
/// same class. The device taking copies again, the next hold copies all
/// three and carries neither member (the mutant that reads the class off the
/// words, or drops it, gives a read-only volume the full disk's act; the one
/// that leaves the class beside a line copied tells the page a copy on disk
/// is not).
#[test]
fn a_refusal_at_the_writer_reaches_the_page_with_its_class() {
    for (kind, class) in [(std::io::ErrorKind::StorageFull, "full"), (std::io::ErrorKind::ReadOnlyFilesystem, "read_only")] {
        let g = ground();
        crate::held::tests::refuse_copies_as(kind);
        let first = g.hold(&insert(DOC, json!(["a"]), g.fake.head()), "unreachable", false);
        let behind = g.holds.send_burst(&g.session, insert(DOC, json!(["b"]), g.fake.head()), None);
        crate::held::tests::take_copies();
        let why = first["unwritable"].as_str().unwrap_or_else(|| panic!("{class}: the device's refusal rides the answer: {first}"));
        assert_eq!(first["unwritable_class"].as_str(), Some(class), "{class}: its class beside it: {first}");
        let OpAnswer::Answered(Ok(behind)) = behind else { panic!("{class}: held behind the first") };
        crate::shapes::assert_declared("HeldAnswer", &behind);
        let waits = (behind["cause"].as_str(), behind["unwritable"].as_str(), behind["unwritable_class"].as_str());
        assert_eq!(waits, (Some("behind"), Some(why), Some(class)), "{class}: the line behind carries the refusal it waits behind: {behind}");
        let next = g.hold(&insert(DOC, json!(["c"]), g.fake.head()), "unreachable", false);
        assert!(next.get("unwritable").is_none() && next.get("unwritable_class").is_none(), "{class}: the device takes copies again: {next}");
        let copied: Vec<u64> = file_lines(&std::fs::read_to_string(held_file(&g)).unwrap()).iter().map(|line| line["held"].as_u64().unwrap()).collect();
        assert_eq!(copied, [1, 2, 3], "{class}: all three copied, in `k` order");
    }
}

/// The `held` events since the last look, each held to its declaration.
fn told_events(g: &Ground) -> Vec<Value> {
    let said: Vec<Value> = g.rx.try_iter().filter(|e| e.name == EventName::Held).map(|e| e.data).collect();
    said.iter().for_each(assert_held_event_declared);
    said
}

/// Checks that a line no file holds is listed so and its landing is said.
///
/// It is §3c.3's face and its lift (skep #860). Every copy refused, a burst
/// is held: `held(session)` lists it with the refusal its answer named, in
/// its words and its class, and the `held` event carries the same. The
/// device takes copies again, the node stopped so the resend sends nothing:
/// the next probe writes the line, the row carries neither member, and a
/// `held` event follows with neither, its state, count and cause as the
/// event last told them; a second probe says nothing (the mutant that leaves
/// the members off the rows tells a launched page nothing; the one that
/// never says the landing keeps up a face saying a close loses words the
/// file now holds; the one that says it at each probe floods the page).
#[test]
fn a_line_no_file_holds_is_listed_so_and_its_landing_is_said() {
    let g = ground();
    crate::held::tests::refuse_copies_as(std::io::ErrorKind::StorageFull);
    let held = g.hold(&insert(DOC, json!(["a"]), g.fake.head()), "unreachable", false);
    crate::held::tests::take_copies();
    let why = held["unwritable"].as_str().unwrap_or_else(|| panic!("the device's refusal rides the answer: {held}")).to_string();
    let rows = g.lines();
    let row = |rows: &[Value]| (rows[0].get("unwritable").cloned(), rows[0].get("unwritable_class").cloned());
    assert_eq!(row(&rows), (Some(json!(why)), Some(json!("full"))), "the row carries the answer's two members: {rows:?}");
    let told = told_events(&g);
    assert_eq!(told.len(), 1, "{told:?}");
    let said = |event: &Value| (event["state"].clone(), event["held"].clone(), event["cause"].clone());
    assert_eq!(said(&told[0]), (json!("holding"), json!(1), json!("unreachable")), "{told:?}");
    assert_eq!((told[0]["unwritable"].as_str(), told[0]["unwritable_class"].as_str()), (Some(why.as_str()), Some("full")), "the event carries them too: {told:?}");
    g.holds.set_node_stopped("b-1", true);
    g.holds.probe("b-1");
    assert_eq!(row(&g.lines()), (None, None), "the row carries neither once the retry has written the line");
    let lifted = told_events(&g);
    assert_eq!(lifted.len(), 1, "one event says the landing: {lifted:?}");
    assert_eq!(said(&lifted[0]), said(&told[0]), "its state, count and cause as last told: {lifted:?}");
    assert!(lifted[0].get("unwritable").is_none() && lifted[0].get("unwritable_class").is_none(), "and neither member: {lifted:?}");
    g.holds.probe("b-1");
    assert_eq!(told_events(&g), Vec::<Value>::new(), "a second probe says nothing");
}

/// Checks that a landing lifts each document it wrote, and no other.
///
/// It is the retry's partial landing (§3c.3; skep #860). Two documents' lines
/// wait for their first copies, and the device has room for the first alone:
/// the probe writes it, and the `held` event lifts its document alone, the
/// other's row and event keeping the refusal; once the device takes copies
/// the next probe lifts the other (the mutant that lifts at the wait's end
/// alone keeps the first document's face up while a copy it does not wait for
/// is owed; the one that lifts every waiting document says a copy on disk
/// that is not).
#[test]
fn a_landing_lifts_each_document_it_wrote_and_no_other() {
    let g = ground();
    // The file stands, so the retry's one copy is the lines' own.
    g.hold(&insert("1.0.1.0.3", json!(["x"]), g.fake.head()), "unreachable", false);
    let _ = told_events(&g);
    crate::held::tests::refuse_copies_as(std::io::ErrorKind::StorageFull);
    g.hold(&insert(DOC, json!(["a"]), g.fake.head()), "unreachable", false);
    g.hold(&insert(OTHER, json!(["b"]), g.fake.head()), "unreachable", false);
    crate::held::tests::take_copies();
    let told = told_events(&g);
    assert_eq!((told.len(), told[0]["unwritable_class"].as_str(), told[1]["unwritable_class"].as_str()), (2, Some("full"), Some("full")), "{told:?}");
    g.holds.set_node_stopped("b-1", true);
    // The one copy is cut short, and the device takes the first line alone.
    crate::held::tests::cut_the_next_write_short(10);
    crate::held::tests::refuse_copies_after(1);
    g.holds.probe("b-1");
    crate::held::tests::take_copies();
    let lifted = told_events(&g);
    assert_eq!((lifted.len(), lifted[0]["doc"].as_str(), lifted[0].get("unwritable")), (1, Some(DOC), None), "the first document alone is lifted: {lifted:?}");
    let rows = g.lines();
    let waits: Vec<bool> = rows.iter().map(|row| row.get("unwritable").is_some()).collect();
    assert_eq!(waits, [false, false, true], "the second document's line waits still: {rows:?}");
    g.holds.probe("b-1");
    let lifted = told_events(&g);
    assert_eq!((lifted.len(), lifted[0]["doc"].as_str(), lifted[0].get("unwritable")), (1, Some(OTHER), None), "the next probe lifts the other: {lifted:?}");
}

/// Checks that a landing repeats what the event last told, moved or sending.
///
/// The lift changes the two members and nothing else (§3c.3; skep #860). A
/// burst the board refused as typed against an older state, no anchors
/// beside it, its copy refused, is told `moved`, its hands and `sendable`
/// false; and a burst the walk has marked `sending`, its dial answered a
/// reissue, its copy refused — each lifted by the probe that writes it with
/// its state, its hands and its `sendable` as told (the mutant that derives
/// the lifting event's state flips a document mid-resend to `holding`; the
/// one that says a moved document's lift with no hands erases them).
#[test]
fn a_landing_repeats_what_the_event_last_told_moved_or_sending() {
    // A moved document.
    let g = ground();
    let row = json!({"at": g.fake.head() + 1, "key": "bare", "docs": [DOC], "op": "insert"});
    *g.fake.rows.lock().unwrap() = vec![row];
    g.fake.op_rejected.next(1, arrangement_moved(g.fake.head(), 78));
    crate::held::tests::refuse_copies_as(std::io::ErrorKind::StorageFull);
    let OpAnswer::Answered(Ok(held)) = g.holds.send_burst(&g.session, insert(DOC, json!(["hello"]), g.fake.head()), None) else { panic!("held, not faced") };
    crate::held::tests::take_copies();
    assert_eq!((held["cause"].as_str(), held["unwritable_class"].as_str()), (Some("moved"), Some("full")), "{held}");
    let told = told_events(&g);
    assert_eq!((told.len(), told[0]["state"].as_str(), told[0]["unwritable_class"].as_str()), (1, Some("moved"), Some("full")), "{told:?}");
    assert_eq!(told[0]["hands"], json!([{"key": "bare"}]), "{told:?}");
    assert_eq!(told[0]["sendable"], json!(false), "a burst with no anchors never shifts: {told:?}");
    g.holds.set_node_stopped("b-1", true);
    g.holds.probe("b-1");
    let lifted = told_events(&g);
    assert_eq!(lifted.len(), 1, "{lifted:?}");
    assert_eq!((&lifted[0]["state"], &lifted[0]["hands"], &lifted[0]["sendable"], lifted[0].get("cause")), (&told[0]["state"], &told[0]["hands"], &told[0]["sendable"], None), "the moved face as told, its hands among it: {lifted:?}");
    assert!(lifted[0].get("unwritable").is_none(), "{lifted:?}");

    // A document mid-resend.
    let g = ground();
    crate::held::tests::refuse_copies_as(std::io::ErrorKind::StorageFull);
    g.hold(&insert(DOC, json!(["a"]), g.fake.head()), "unreachable", false);
    g.fake.op_rejected.next(1, retry("durability"));
    g.holds.probe("b-1");
    crate::held::tests::take_copies();
    let told = told_events(&g);
    let last = told.last().expect("the walk's event");
    assert_eq!((last["state"].as_str(), last["unwritable_class"].as_str()), (Some("sending"), Some("full")), "premise: the walk marked it sending, its copy still refused: {told:?}");
    g.holds.set_node_stopped("b-1", true);
    g.holds.probe("b-1");
    let lifted = told_events(&g);
    assert_eq!((lifted.len(), lifted[0]["state"].as_str(), lifted[0].get("unwritable")), (1, Some("sending"), None), "still sending, the copy landed: {lifted:?}");
}

/// Checks that a landing is said under each session of the line's principal.
///
/// A second session of the principal's, told nothing of the document, hears
/// its landing as the queue gives it, and another principal's session hears
/// nothing (the mutant that says the landing under the session told alone
/// leaves another window's rows, which read the two members, unlifted; the
/// one that says it to every session on the board tells another principal
/// of a draft it cannot read, P39).
#[test]
fn a_landing_is_said_under_each_session_of_the_lines_principal() {
    let g = ground();
    let register = |principal: u64, account: &str, n: u8| g.holds.sessions.register(&BoardEntry { reference: "b-1".into(), board: Arc::clone(&g.session.board) }, Open { token: Token::parse(&format!("{n:02x}").repeat(16)).unwrap(), facts: writer_facts_as(&g.store, principal, account), opened_at: 0 }, &mut NoSupplements);
    let second = register(1, "1.0.1", 0x9e);
    let other = register(2, "1.0.2", 0x9d);
    crate::held::tests::refuse_copies_as(std::io::ErrorKind::StorageFull);
    g.hold(&insert(DOC, json!(["a"]), g.fake.head()), "unreachable", false);
    crate::held::tests::take_copies();
    let _ = told_events(&g);
    g.holds.set_node_stopped("b-1", true);
    g.holds.probe("b-1");
    let lifted = told_events(&g);
    let by = |session: &SessionEntry| lifted.iter().filter(|event| event["session"] == session.reference.as_str()).count();
    assert_eq!((by(&g.session), by(&second), by(&other)), (1, 1, 0), "{lifted:?}");
    let derived = lifted.iter().find(|event| event["session"] == second.reference.as_str()).expect("the second session's event");
    assert_eq!((derived["state"].as_str(), derived["held"].as_u64(), derived["cause"].as_str()), (Some("holding"), Some(1), Some("unreachable")), "derived from the queue: {derived}");
}

/// Returns a ground whose burst is held moved, its copy refused.
///
/// The board refused it as typed against an older state, another key's row
/// having moved the document, and the face told the ground's session named
/// that hand. It answers the ground and the hands the face named.
fn moved_and_unwritten() -> (Ground, Value) {
    let g = ground();
    let typed = g.fake.head();
    *g.fake.rows.lock().unwrap() = vec![json!({"at": typed + 1, "op": "insert", "key": "ff".repeat(32), "docs": [DOC]})];
    g.fake.op_rejected.next(1, arrangement_moved(typed, 78));
    crate::held::tests::refuse_copies_as(std::io::ErrorKind::StorageFull);
    let held = g.holds.send_burst(&g.session, insert(DOC, json!(["hello"]), typed), None);
    crate::held::tests::take_copies();
    let OpAnswer::Answered(Ok(held)) = held else { panic!("held, not faced") };
    assert_eq!((held["cause"].as_str(), held["unwritable_class"].as_str()), (Some("moved"), Some("full")), "{held}");
    let told = told_events(&g);
    let [face] = &told[..] else { panic!("one face told the ground's session: {told:?}") };
    assert_eq!(face["hands"], json!([{"key": "other", "fingerprint": "ff".repeat(32)}]), "{face}");
    let hands = face["hands"].clone();
    (g, hands)
}

/// Checks that a landing under a session told nothing of a moved document
/// names the hands it reads (§3c.3, §4b.2; skep #972).
///
/// The burst is held moved, its copy refused, the face told the ground's
/// session naming another key's hand. Two cells, each a session told
/// nothing of the document: the one a restart re-opens in the ground's
/// place, and a second writer of the principal's beside it. The device
/// takes copies again, and the probe that writes the line says the document
/// `moved` under that session with the hand it reads for it, its
/// `sendable`, no `unwritable`, one `/changes` read made; the ground's
/// session, in the second cell, repeats the face it was told with no read
/// (the mutant that says an untold session's lift with no hands says the
/// document moved by no one).
#[test]
fn a_landing_under_a_session_told_nothing_of_a_moved_document_names_the_hands_it_reads() {
    for cell in ["a re-opened session", "a second session"] {
        let (g, hands) = moved_and_unwritten();
        let untold = if cell == "a re-opened session" { reopened_session(&g) } else { beside(&g, writer_facts(&g.store), 0x9e) };
        let reads = changes_reads(&g);
        g.holds.probe("b-1");
        let said = told_events(&g);
        let lifted = under(&said, &untold);
        let [face] = &lifted[..] else { panic!("{cell}: one event under the untold session: {said:?}") };
        assert_eq!((face["state"].as_str(), face["held"].as_u64(), &face["hands"], face["sendable"].as_bool()), (Some("moved"), Some(1), &hands, Some(false)), "{cell}: {face}");
        assert!(face.get("unwritable").is_none() && face.get("unwritable_class").is_none(), "{cell}: the copy landed: {face}");
        assert_eq!(changes_reads(&g), reads + 1, "{cell}: one read, for the untold session");
        if cell == "a second session" {
            let repeated = under(&said, &g.session);
            let [face] = &repeated[..] else { panic!("{cell}: the ground's session's lift: {said:?}") };
            assert_eq!((face["state"].as_str(), &face["hands"]), (Some("moved"), &hands), "{cell}: the face as told: {face}");
        }
    }
}

/// Checks that a landing whose hands the shell cannot read yet names them not
/// read, and the walk names them (§3c.5; skep #972).
///
/// The burst is held moved, its copy refused, a second writer of the
/// principal's told nothing of it, and the own node stopped: the probe that
/// writes the line makes no read, and says the document `moved` under the
/// second session with its hands not read, the document owing them. The
/// node running, the next probe's walk — under either writer — reads them
/// for the second session and names them to it, the debt paid (the mutant
/// that reads at a stopped node dials a notebook its owner stopped; the one
/// that names them to the walk's session alone leaves the second session's
/// face not read whenever the walk runs under the ground's).
#[test]
fn a_landing_whose_hands_the_board_does_not_give_names_them_not_read_and_the_walk_names_them() {
    let (g, hands) = moved_and_unwritten();
    let second = beside(&g, writer_facts(&g.store), 0x9e);
    g.holds.set_node_stopped("b-1", true);
    let reads = changes_reads(&g);
    g.holds.probe("b-1");
    let said = told_events(&g);
    let lifted = under(&said, &second);
    let [face] = &lifted[..] else { panic!("one event under the second session: {said:?}") };
    assert_eq!((face["state"].as_str(), face["held"].as_u64(), &face["hands"], face["sendable"].as_bool()), (Some("moved"), Some(1), &json!([{"key": "unread"}]), Some(false)), "{face}");
    assert_eq!(changes_reads(&g), reads, "no read at a stopped node");
    assert_eq!(g.holds.with_principal("b-1", 1, |ph| ph.hands_owed.contains_key(DOC)), Some(true), "the document owes its hands");
    g.holds.set_node_stopped("b-1", false);
    g.holds.probe("b-1");
    let named = under(&told_events(&g), &second);
    let [face] = &named[..] else { panic!("the walk names the hands to the second session: {named:?}") };
    assert_eq!((face["state"].as_str(), &face["hands"]), (Some("moved"), &hands), "{face}");
    assert_eq!(g.holds.with_principal("b-1", 1, |ph| ph.hands_owed.contains_key(DOC)), Some(false), "the debt paid");
}

/// Checks that a settled line whose `done` is owed stays counted (§3c.3).
///
/// It is the owed `done` the stop must count (skep #860). A held line is
/// resent and acked while the device refuses every copy, a refused run
/// standing on another document so the file stays: the line has left
/// `held(session)` and is counted `kept` by `copies_owed`, and a reopen before
/// the retry would read it as held; the device takes copies again and the
/// next probe writes the `done`, the count falling to zero (the mutant that
/// reads the rows alone says nothing of a line the next start lists).
#[test]
fn a_settled_line_whose_done_is_owed_stays_off_the_rows_and_counted() {
    let g = ground();
    g.hold_for(&insert(OTHER, json!(["r"]), g.fake.head()), Reason::refused("out_of_bounds", json!({"code": "out_of_bounds"}))).unwrap();
    g.hold(&insert(DOC, json!(["a"]), g.fake.head()), "unreachable", false);
    assert_eq!(g.holds.copies_owed("b-1", 1), CopiesOwed::default(), "premise: both lines on disk");
    crate::held::tests::refuse_copies_as(std::io::ErrorKind::StorageFull);
    g.holds.probe("b-1");
    crate::held::tests::take_copies();
    assert_eq!(g.fake.sends(), 1, "the line is sent, and acked");
    let rows = g.lines();
    assert_eq!((rows.len(), rows[0]["doc"].as_str()), (1, Some(OTHER)), "the settled line is off the rows: {rows:?}");
    assert_eq!(g.holds.copies_owed("b-1", 1), CopiesOwed { lines: 0, kept: 1, dropped: 0 }, "and counted");
    g.holds.probe("b-1");
    assert_eq!(g.holds.copies_owed("b-1", 1), CopiesOwed::default(), "the retry has written the `done`");
    assert_eq!(g.holds.copies_owed("b-1", 2), CopiesOwed::default(), "another principal owes nothing here");
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
    assert!(queue.hold_next(DOC, None, 0, insert(DOC, json!(["a"]), 0), None, Reason::of("unreachable", false)).unwrap().unwritten.is_none());
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
/// It refuses at the act and holds none of it: a frame one byte past what
/// every send of it fits, a resend's dial id in the page's `id`'s place
/// within the board's frame cap (`DIAL_ID_ROOM`; skep #971) — at a running
/// board and at a stopped one, where it would otherwise be held without a
/// dial — while a frame at that bound exactly is dialed and acked; a burst
/// naming no document, an element where its document goes, or a document in
/// another spelling, refused `malformed_args` undialed, and behind a
/// standing line unheld (the mutants that drop the size or the document
/// check dial a frame no send of which the board takes, and hold a line none
/// could ever clear, every later burst of the principal behind it). The
/// door's own arithmetic, under a session whose key attests no insert — a
/// bare one, so the door keeps no attest's room; the shell's `op` row refuses
/// such a session's write before it reaches the hold.
#[test]
fn a_burst_the_board_takes_at_no_send_is_refused_at_the_bursts_door() {
    let g = bare_ground();
    for stopped in [false, true] {
        g.holds.set_node_stopped("b-1", stopped);
        let OpAnswer::Answered(Err(refused)) = g.holds.send_burst(&g.session, sized_frame(MAX_FRAME_BYTES - DIAL_ID_ROOM + 1), None) else { panic!("refused at the burst's door") };
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
    let OpAnswer::Answered(Ok(ack)) = g.holds.send_burst(&g.session, sized_frame(MAX_FRAME_BYTES - DIAL_ID_ROOM), None) else { panic!("a frame every send of which fits is sent") };
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
/// room the attest of every resend takes, beside a resend's dial id's, and
/// asks the composer's terms of the frame alone: a frame at the cap
/// unattested, which no attested send fits, is refused `frame_too_large`;
/// one the two rooms fit is held behind a standing line; and an insert
/// whose values the composer cannot spell is refused `attest_not_composed`
/// before it is held (the mutant that leaves no room holds a burst every
/// resend of which the board refuses `413`).
#[test]
fn a_signed_sessions_burst_keeps_room_for_its_attest() {
    let g = ground_in(TempDir::new().unwrap(), keyed_facts(), 0);
    g.hold(&insert(DOC, json!(["a"]), g.fake.head()), "unreachable", false);
    let OpAnswer::Answered(Err(refused)) = g.holds.send_burst(&g.session, sized_frame(MAX_FRAME_BYTES), None) else { panic!("refused at the burst's door") };
    assert_eq!(refused.name(), "frame_too_large", "{refused}");
    let OpAnswer::Answered(Ok(held)) = g.holds.send_burst(&g.session, sized_frame(MAX_FRAME_BYTES - attest_room() - DIAL_ID_ROOM), None) else { panic!("held behind") };
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
/// bytes stripped of that member and grown by the room the shell's takes,
/// and by the room of a resend's dial id: at the cap it is held, one byte
/// past it refused `frame_too_large` (the mutant that strips nothing
/// refuses a burst every resend of which fits; the one that strips past the
/// member holds a burst no resend of which does).
#[test]
fn a_page_supplied_attest_is_counted_out_of_every_resend() {
    let g = ground_in(TempDir::new().unwrap(), keyed_facts(), 0);
    g.hold(&insert(DOC, json!(["a"]), g.fake.head()), "unreachable", false);
    let carrying = |bytes: usize| {
        let mut frame = sized_frame(bytes);
        frame["attest"] = json!({"alg": "x", "sig": "00"});
        frame
    };
    let OpAnswer::Answered(Ok(held)) = g.holds.send_burst(&g.session, carrying(MAX_FRAME_BYTES - attest_room() - DIAL_ID_ROOM), None) else { panic!("held behind") };
    assert_eq!(held["cause"], "behind", "{held}");
    let OpAnswer::Answered(Err(refused)) = g.holds.send_burst(&g.session, carrying(MAX_FRAME_BYTES - attest_room() - DIAL_ID_ROOM + 1), None) else { panic!("refused at the burst's door") };
    let v = refused.to_value();
    assert_eq!((refused.name(), v["bytes"].as_u64()), ("frame_too_large", Some(MAX_FRAME_BYTES as u64 + 1)), "{v}");
    assert_eq!(g.lines().len(), 2, "the one admitted burst held, and nothing else");
}

/// Checks that a page's `id` gives way to the dial id's room in every resend.
///
/// A resend dials the line under its own dial id in the page's `id`'s place
/// (skep #971), so the burst's door counts the page's `id` out of a resend's
/// bytes and the dial id's room (`DIAL_ID_ROOM`) in: a frame carrying a page
/// `id` that every send fits is held, the page's `id` spending none of the
/// resend's room, and one byte more is refused `frame_too_large`, naming the
/// resend's bytes (the mutant that keeps no room holds a burst every resend
/// of which the board refuses `413`; the one that counts the page's `id` in
/// beside the room refuses a burst every send of which fits).
#[test]
fn a_page_id_gives_way_to_the_dial_ids_room_in_every_resend() {
    let g = bare_ground();
    g.hold(&insert(DOC, json!(["a"]), g.fake.head()), "unreachable", false);
    let carrying = |bytes: usize| with_id(sized_frame(bytes), "b-1");
    let OpAnswer::Answered(Ok(held)) = g.holds.send_burst(&g.session, carrying(MAX_FRAME_BYTES - DIAL_ID_ROOM), None) else { panic!("held behind") };
    assert_eq!(held["cause"], "behind", "{held}");
    let OpAnswer::Answered(Err(refused)) = g.holds.send_burst(&g.session, carrying(MAX_FRAME_BYTES - DIAL_ID_ROOM + 1), None) else { panic!("refused at the burst's door") };
    let v = refused.to_value();
    assert_eq!((refused.name(), v["bytes"].as_u64()), ("frame_too_large", Some(MAX_FRAME_BYTES as u64 + 1)), "{v}");
    assert_eq!((g.lines().len(), g.fake.sends()), (2, 0), "the one admitted burst held, nothing dialed");
}

/// Checks that the burst's door refuses a page `id` of the dial ids' prefix.
///
/// The hold resends a held line under a dial id of its own, `shell:` and hex
/// (skep #971), so a burst whose `id` begins `shell:` is refused at the act,
/// `malformed_args` naming `frame.id`, nothing held or dialed — at a board
/// that takes it, and behind a standing line, where it would otherwise be
/// held; an `id` the prefix does not begin — `shellx`, `Shell:x` — is
/// admitted and dialed (the mutant that admits the prefix lets a page's
/// burst share an `id` with a resend, the board's retry memo answering one
/// with the other's acknowledgment; the one that reserves more refuses ids a
/// page may send).
#[test]
fn the_bursts_door_refuses_a_page_id_of_the_dial_ids_prefix() {
    let g = ground();
    let burst = |g: &Ground, id: &str| g.holds.send_burst(&g.session, with_id(insert(DOC, json!(["a"]), g.fake.head()), id), None);
    for id in ["shell:x", "shell:"] {
        let OpAnswer::Answered(Err(refused)) = burst(&g, id) else { panic!("{id}: refused at the burst's door") };
        assert_eq!(refused.to_value(), Refusal::malformed("frame.id").to_value(), "{id}");
    }
    assert_eq!((g.lines().len(), g.fake.sends()), (0, 0), "nothing held, nothing dialed");
    for id in ["shellx", "Shell:x"] {
        let OpAnswer::Answered(Ok(ack)) = burst(&g, id) else { panic!("{id}: admitted") };
        assert_eq!(ack["resp"], "ack", "{id}: {ack}");
    }
    g.hold(&insert(DOC, json!(["b"]), g.fake.head()), "unreachable", false);
    let OpAnswer::Answered(Err(refused)) = burst(&g, "shell:x") else { panic!("refused behind a standing line") };
    assert_eq!(refused.to_value(), Refusal::malformed("frame.id").to_value());
    assert_eq!((g.lines().len(), g.fake.sends()), (1, 2), "nothing more held, nothing more dialed");
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

/// Checks that a signed write's head read decides the board's state.
///
/// A board unclaimed at the open owes no head, and the state is `running`;
/// where it then names a claimant and serves no head record, the burst's own
/// signing term finds the head owed — no probe has read it — and the board's
/// state is `head_unreadable` with that reason, once (§3c.3; skep #865; the
/// mutant that leaves the attest's read out of the head's state tells the
/// page nothing until the next probe, and nothing at all with no signed
/// session left to probe for).
#[test]
fn a_signed_writes_head_read_decides_the_boards_state() {
    let fake = Fake::new();
    fake.no_head.store(true, Ordering::SeqCst);
    fake.unclaimed.store(true, Ordering::SeqCst);
    let store = TempDir::new().unwrap();
    let facts = writer_facts(&store);
    let g = ground_over(fake, store, facts, 0);
    assert_eq!(g.holds.state("b-1"), BoardState::Running, "an unclaimed board owes no head");
    g.fake.unclaimed.store(false, Ordering::SeqCst);
    let OpAnswer::Answered(Ok(held)) = g.holds.send_burst(&g.session, insert(DOC, json!(["a"]), g.fake.head()), None) else { panic!("held, nothing sent") };
    assert_eq!(held["cause"], "head_unreadable", "{held}");
    let edge = g.holds.state_change("b-1").expect("the write's read decided it");
    assert_eq!((edge.from, edge.to.as_str()), (BoardState::Running, "head_unreadable"));
    assert!(edge.to.reason().is_some_and(|reason| reason.contains("serves no head record")), "{:?}", edge.to.reason());
    assert_eq!(g.holds.state_change("b-1"), None, "told once");
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
    assert_eq!(g.holds.resolve(&g.session, k, ResolveAct::Drop).unwrap(), Resolved::dropped(&[]), "the drop is admitted");
    let docs: Vec<String> = g.lines().iter().map(|l| l["doc"].as_str().unwrap().to_string()).collect();
    assert_eq!(docs, [OTHER], "the line and every later line of its document dropped; the other document's stands");
    let events: Vec<Value> = g.rx.try_iter().filter(|e| e.name == EventName::Held).map(|e| e.data).collect();
    assert_eq!(events.len(), 1, "{events:?}");
    assert_eq!((events[0]["doc"].as_str(), events[0]["held"].as_u64(), events[0]["state"].as_str()), (Some(DOC), Some(0), Some("kept")), "{events:?}");
    let text = std::fs::read_to_string(pending_file(&g)).unwrap();
    assert_eq!(text.matches("\"as\":\"dropped\"").count(), 2, "both drops on the pending file: {text}");
    assert_eq!(g.fake.sends(), 0, "nothing dialed");
}

/// Checks that a dropped line's `done` the device refused is written at the
/// probe, and a relaunch sends none of what was dropped (§3c.3; skep #821).
///
/// Three bursts are held over a head record that cannot be read — two on one
/// document, one on another — in the pending file. The file moved aside and a
/// directory left at its name, the person drops the first: it and the line
/// behind it leave the queue, their `done`s owed, and the wait is said once in
/// the shell's own window, naming the first `done` and what a relaunch reads.
/// The file put back, the next probe — which dials nothing while the head
/// cannot be read — writes both `done`s and says the wait's end once. A
/// relaunch over the same store, the head record readable, sends the other
/// document's line alone (the mutant that writes a refused `done` once and
/// never again relaunches both dropped lines as held, and sends the writes
/// the person threw away, the second composed against the first).
#[test]
fn a_dropped_lines_done_the_device_refused_is_written_at_the_probe_and_a_relaunch_sends_none_of_it() {
    let fake = Fake::new();
    fake.head_garbled.store(true, Ordering::SeqCst);
    let store = TempDir::new().unwrap();
    let facts = writer_facts(&store);
    let g = ground_over(fake, store, facts, 0);
    let OpAnswer::Answered(Ok(head)) = g.holds.send_burst(&g.session, insert(DOC, json!(["a"]), g.fake.head()), None) else { panic!("held, nothing sent") };
    let k = head["held"].as_u64().unwrap();
    for frame in [insert(DOC, json!(["b"]), g.fake.head()), insert(OTHER, json!(["c"]), g.fake.head())] {
        let OpAnswer::Answered(Ok(behind)) = g.holds.send_burst(&g.session, frame, None) else { panic!("held behind") };
        assert_eq!(behind["cause"], "behind", "{behind}");
    }
    let pending = pending_file(&g);
    let aside = pending.with_extension("aside");
    std::fs::rename(&pending, &aside).unwrap();
    std::fs::create_dir(&pending).unwrap();
    assert_eq!(g.holds.resolve(&g.session, k, ResolveAct::Drop).unwrap(), Resolved::dropped(&[]));
    let docs: Vec<String> = g.lines().iter().map(|l| l["doc"].as_str().unwrap().to_string()).collect();
    assert_eq!(docs, [OTHER], "the line and the one behind it have left the queue");
    let begun = said_containing(&g, "could not be copied to its held file");
    assert_eq!(begun.len(), 1, "the wait said once as it begins: {:?}", g.said.lock().unwrap());
    assert!(begun[0].contains(&format!("held line {k}'s `done`")) && begun[0].contains("a relaunch reads each line as the file last held it"), "{begun:?}");
    std::fs::remove_dir(&pending).unwrap();
    std::fs::rename(&aside, &pending).unwrap();
    g.holds.probe("b-1");
    let text = std::fs::read_to_string(&pending).unwrap();
    assert_eq!(text.matches("\"as\":\"dropped\"").count(), 2, "both `done`s written at the probe: {text}");
    assert_eq!(said_containing(&g, "wait in memory no more").len(), 1, "the wait's end said once: {:?}", g.said.lock().unwrap());
    assert_eq!(g.fake.sends(), 0, "nothing dialed while the head cannot be read");
    // The relaunch: this run's holds gone, the head record readable.
    let Ground { holds, fake, session, store, .. } = g;
    drop(holds);
    fake.head_garbled.store(false, Ordering::SeqCst);
    let g = ground_over(fake, store, session.facts.clone(), 0);
    g.holds.probe("b-1");
    let sent: Vec<String> = g.fake.sends.lock().unwrap().iter().map(|frame| frame["values"][0].as_str().unwrap_or("?").to_string()).collect();
    assert_eq!(sent, ["c"], "the other document's line alone is sent");
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
/// frames and anchors at the budget — four bursts at the burst's door's
/// bound, the board's frame cap less a resend's dial id's room, the fourth's
/// anchors at theirs, and a fifth bringing them to ten bytes under it — the
/// next burst is refused `held_full` — no line, no `held` event — and its
/// answer names the bytes held against the queue's cap (the mutant that drops
/// the queue's count holds a page's bursts without bound). The queue's own
/// budget, under a session whose key attests no insert — a bare one, its
/// door keeping no attest's room, so bursts at the door's bound fill the
/// queue.
#[test]
fn a_burst_the_queue_has_no_room_for_is_refused_held_full() {
    let g = bare_ground();
    for _ in 0..3 {
        g.hold(&sized_frame(MAX_FRAME_BYTES - DIAL_ID_ROOM), "unreachable", false);
    }
    g.hold_anchored(&sized_frame(MAX_FRAME_BYTES - DIAL_ID_ROOM), anchors_of_len(MAX_ANCHOR_BYTES), "unreachable", false);
    g.hold(&sized_frame(4 * DIAL_ID_ROOM - 10), "behind", false);
    let _ = g.states();
    let OpAnswer::Answered(Err(refused)) = g.holds.send_burst(&g.session, insert(DOC, json!(["b"]), g.fake.head()), None) else { panic!("refused, not held") };
    let v = refused.to_value();
    assert_eq!((refused.name(), v["held_bytes"].as_u64(), v["cap"].as_u64()), ("held_full", Some(MAX_HELD_BYTES as u64 - 10), Some(MAX_HELD_BYTES as u64)), "{v}");
    assert_eq!(g.lines().len(), 5, "nothing more held");
    assert!(g.states().is_empty(), "no `held` event for a burst not held");
    assert_eq!(g.fake.sends(), 0);
}

/// Checks that a burst's anchors spend the queue's budget beside its frame.
///
/// Behind one refused run, small bursts on as many documents, each carrying
/// anchors of three quarters of `held::MAX_ANCHOR_BYTES`, sent by the
/// burst's write path, are held `behind` as many as `held::MAX_HELD_BYTES`
/// holds beside the run; and the next — its frame a few bytes, its anchors
/// carrying the queue past the budget — is refused `held_full`, naming its
/// anchors' bytes against the queue's cap: no line, no `held` event, nothing
/// dialed (the mutant that counts frames alone holds a page's anchors without
/// bound, every one copied to disk and read back at each launch).
#[test]
fn a_bursts_anchors_spend_the_queues_budget_beside_its_frame() {
    let g = bare_ground();
    let verdict = json!({"resp": "rejected", "code": "out_of_bounds", "disposition": "permanent"});
    let run = insert(DOC, json!(["a"]), g.fake.head());
    g.hold_for(&run, Reason::refused("out_of_bounds", verdict)).unwrap();
    let anchors = anchors_of_len(MAX_ANCHOR_BYTES * 3 / 4);
    // Documents of one spelling's length, so every burst spends the same.
    let doc = |n: usize| format!("1.0.1.0.{}", 100 + n);
    let fits = (MAX_HELD_BYTES - json_len(&run)) / (json_len(&delete(&doc(0), g.fake.head())) + anchors.bytes());
    let send = |n: usize| g.holds.send_burst(&g.session, delete(&doc(n), g.fake.head()), Some(anchors.clone()));
    for n in 0..fits {
        let OpAnswer::Answered(Ok(held)) = send(n) else { panic!("held behind the refused run") };
        assert_eq!(held["cause"], "behind", "{held}");
    }
    let _ = g.states();
    let OpAnswer::Answered(Err(refused)) = send(fits) else { panic!("refused, not held") };
    let v = refused.to_value();
    let anchor_bytes = (MAX_ANCHOR_BYTES * 3 / 4) as u64;
    assert_eq!((refused.name(), v["anchor_bytes"].as_u64(), v["cap"].as_u64()), ("held_full", Some(anchor_bytes), Some(MAX_HELD_BYTES as u64)), "{v}");
    assert_eq!(g.lines().len(), fits + 1, "nothing more held");
    assert!(g.states().is_empty(), "no `held` event for a burst not held");
    assert_eq!(g.fake.sends(), 0, "nothing dialed");
}

/// Checks that a burst past the queue's line budget is refused `held_full`.
///
/// It is the queue's line budget at the hold: the principal's file holds a
/// refused run and small bursts on as many documents `behind` it,
/// `held::MAX_HELD_LINES` lines in all — written whole before the session
/// opens, as a relaunch finds them, their bytes a few megabytes, far under
/// the frames' budget — and the next burst sent is refused `held_full`,
/// naming the lines held and the line budget: no line, no `held` event,
/// nothing dialed (the mutant that counts bytes alone holds millions of such
/// bursts, and the resend walks each past the others).
#[test]
fn a_burst_past_the_queues_line_budget_is_refused_held_full() {
    let store = TempDir::new().unwrap();
    let fake = Fake::new();
    let verdict = json!({"resp": "rejected", "code": "out_of_bounds", "disposition": "permanent"});
    let line = |k: usize, doc: &str, cause: &str| json!({"held": k, "doc": doc, "base": 0, "frame": delete(doc, fake.head()), "cause": cause, "sent": false, "time": 1});
    let mut run = line(1, DOC, "out_of_bounds");
    run["refusal"] = verdict;
    let mut body = format!("{{\"type\":\"skep-held-bursts\",\"v\":1,\"board\":\"{}\",\"principal\":1,\"account\":\"1.0.1\"}}\n{run}\n", fake.chain);
    for k in 2..=MAX_HELD_LINES {
        body.push_str(&format!("{}\n", line(k, &format!("1.0.1.0.{}", 100 + k), "behind")));
    }
    let dir = store.path().join("held").join(&fake.chain);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("principal-1.held"), body).unwrap();
    let g = ground_over(fake, store, bare_facts(), 0);
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
    let held =
        holds.hold(&sessions[1], Burst::admit(insert(DOC, json!(["z"]), fakes[1].head()), &sessions[1]).unwrap(), Reason::of("unreachable", false), None, sessions[1].opened_at).answered().unwrap();
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
    assert_eq!(resolved.unwrap(), Resolved::dropped(&[]));
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

/// Checks that the `held` events' memory says a face once until it changes.
///
/// It is skep #727's memory, a key cleared as its document is kept whole.
/// The same state, count and `sendable` for one board, session and document
/// is emitted once; a changed count, a changed state or a changed `sendable`
/// is emitted; only an emit naming a line kept bypasses the memory, so the
/// pair said again after the same pair is not emitted; a document kept with
/// no line left clears its key, so the same pair after it is news again; the
/// memory is per session — a second session of the principal sees its own
/// first emit; a `moved` face for another verdict than the one remembered is
/// emitted, its state, count and `sendable` alike, the same verdict again not
/// (skep #973); and a face whose hands come to be named `again`, or no longer
/// so, is emitted, the same again not (skep #989; the mutant that forgets the
/// memory floods the page with the same state at every probe; the one that
/// never clears a key keeps a map entry per document ever held; the one that
/// keys by document alone starves a second tab of its first event; the one
/// that leaves the verdict out of the memory tells a window an earlier move's
/// hands for a later move; the one that leaves `again` out of it never tells
/// the page a burst was refused again for the change it acknowledged).
#[test]
fn the_held_events_memory_emits_a_pair_once_until_it_changes_or_is_cleared() {
    let g = ground();
    let lines = |held: u64| LinesOn { held, unwritable: None };
    let emit = |state: HeldState, held: u64| g.holds.emit_held(&g.session, DOC, lines(held), state, Some("unreachable"), MovedFace::default());
    emit(HeldState::Holding, 1);
    emit(HeldState::Holding, 1);
    assert_eq!(g.states(), ["holding"], "the same pair once");
    emit(HeldState::Holding, 2);
    emit(HeldState::Sending, 2);
    emit(HeldState::Sending, 2);
    assert_eq!(g.states(), ["holding", "sending"], "a changed count, then a changed state, each once");
    emit(HeldState::Sending, 2);
    assert_eq!(g.states(), Vec::<String>::new(), "only an emit naming a line kept bypasses the memory: the same pair again is not news");
    emit(HeldState::Kept, 0);
    emit(HeldState::Holding, 1);
    assert_eq!(g.states(), ["kept", "holding"], "a document kept with no line clears its key: the pair after it is news");
    assert_eq!(g.holds.last_emitted.lock().unwrap().len(), 1, "one key per document still held, none for a document kept whole");
    let second = g.holds.sessions.register(&BoardEntry { reference: "b-1".into(), board: Arc::clone(&g.session.board) }, Open { token: Token::parse(&"9e".repeat(16)).unwrap(), facts: writer_facts(&g.store), opened_at: 0 }, &mut NoSupplements);
    g.holds.emit_held(&second, DOC, lines(1), HeldState::Holding, Some("unreachable"), MovedFace::default());
    assert_eq!(g.states(), ["holding"], "a second session of the principal sees its own first emit");
    let moved = |sendable: Option<bool>| g.holds.emit_held(&g.session, OTHER, lines(1), HeldState::Moved, None, MovedFace { sendable, ..MovedFace::default() });
    moved(Some(false));
    moved(Some(false));
    moved(Some(true));
    moved(None);
    assert_eq!(g.states(), ["moved", "moved", "moved"], "`sendable` joins the memory: each change said once, a repeat none (skep #867)");
    let (first, later) = (Judged { k: 1, verdict: arrangement_moved(70, 77) }, Judged { k: 1, verdict: arrangement_moved(70, 78) });
    let judged = |judged: &Judged| g.holds.emit_held(&g.session, OTHER, lines(1), HeldState::Moved, None, MovedFace { judged: Some(judged), ..MovedFace::default() });
    judged(&first);
    judged(&first);
    judged(&later);
    judged(&later);
    assert_eq!(g.states(), ["moved", "moved"], "the verdict joins the memory: a face for another verdict said, the same verdict again none (skep #973)");
    let hands = [Hand { key: "other", fingerprint: Some("ff".repeat(32)), label: None }];
    let again = |again: bool| g.holds.emit_held(&g.session, OTHER, lines(1), HeldState::Moved, None, MovedFace { hands: &hands, again, sendable: None, judged: Some(&later) });
    again(false);
    again(true);
    again(true);
    again(false);
    assert_eq!(g.states(), ["moved", "moved"], "`again` joins the memory: a face named again said, a repeat none, its end said (skep #989)");
    let waits = |why: &str, class: UnwritableClass| g.holds.emit_held(&g.session, DOC, LinesOn { held: 1, unwritable: Some(Unwritable { why: why.to_string(), class }) }, HeldState::Holding, Some("unreachable"), MovedFace::default());
    waits("no room", UnwritableClass::Full);
    waits("no room", UnwritableClass::Full);
    waits("read only", UnwritableClass::ReadOnly);
    emit(HeldState::Holding, 1);
    assert_eq!(g.states(), ["holding", "holding", "holding"], "why a line is off disk joins the memory: each change said once, a repeat none (skep #860)");
}

/// Checks that an event naming a line kept is said though its pair repeats.
///
/// Its pair is still remembered (skep #968). A `sending` pair said, the same
/// pair naming a line kept is said all the same, its `landed` the line's one
/// entry; after a `holding` pair, a keep's `sending` pair is said and
/// remembered, so the same pair after it, naming no line, is not said; and a
/// keep that leaves no line clears the document's key as any `kept` does
/// (the mutant that judges an event naming a line kept by its pair alone
/// drops the ack of a line that lands while a line no event said stands
/// behind it; the one that skips the memory at such an event says the pair
/// after it again).
#[test]
fn an_event_naming_a_line_kept_is_said_though_its_pair_repeats() {
    let g = ground();
    let lines = |held: u64| LinesOn { held, unwritable: None };
    let emit = |state: HeldState| g.holds.emit_held(&g.session, DOC, lines(1), state, None, MovedFace::default());
    let landed = |k: u64, at: u64| LandedLine { k, burst: Some("b-1".into()), at: Some(at), addr: Some(i(9)) };
    emit(HeldState::Sending);
    g.holds.say_kept(&g.session, DOC, lines(1), &landed(1, 50));
    emit(HeldState::Holding);
    g.holds.say_kept(&g.session, DOC, lines(1), &landed(2, 51));
    emit(HeldState::Sending);
    let said: Vec<Value> = g.rx.try_iter().filter(|e| e.name == EventName::Held).map(|e| e.data).collect();
    said.iter().for_each(assert_held_event_declared);
    let told: Vec<(&str, Option<&Value>)> = said.iter().map(|e| (e["state"].as_str().unwrap_or("?"), e.get("landed"))).collect();
    let entry = |k: u64, at: u64| json!([{"held": k, "burst": "b-1", "at": at, "addr": i(9)}]);
    let (first, second) = (entry(1, 50), entry(2, 51));
    assert_eq!(told, [("sending", None), ("sending", Some(&first)), ("holding", None), ("sending", Some(&second))], "each keep said, the pair after the last one remembered");
    g.holds.say_kept(&g.session, DOC, lines(0), &LandedLine { k: 3, burst: None, at: Some(52), addr: None });
    assert_eq!(g.states(), ["kept"]);
    assert!(g.holds.last_emitted.lock().unwrap().is_empty(), "a keep that leaves no line clears the document's key");
}

/// Checks that the compaction keeps the principal's counter: the next
/// line's ordinal is past the last answered (skep #856;
/// `PrincipalHold::next_k`).
///
/// A burst held takes ordinal 1; the probe sends and keeps it, and the
/// board's file compacts away. The next burst held takes 2, never 1 again —
/// the ordinals one space for the shell's life — and the recreated file
/// names it so (the mutant that starts the ordinals again at the compaction
/// hands the page an ordinal it was told was kept).
#[test]
fn the_compaction_keeps_the_counter_and_the_next_ordinal_is_past_the_last_answered() {
    let g = ground();
    let first = g.hold(&insert(DOC, json!(["a"]), g.fake.head()), "unreachable", false);
    assert_eq!(first["held"], 1, "{first}");
    g.holds.probe("b-1");
    assert!(g.lines().is_empty() && !held_file(&g).exists(), "the line kept and the file compacted away");
    let next = g.hold(&insert(DOC, json!(["b"]), g.fake.head()), "unreachable", false);
    assert_eq!(next["held"], 2, "the ordinals run on: {next}");
    let ks: Vec<u64> = file_lines(&std::fs::read_to_string(held_file(&g)).unwrap()).iter().map(|l| l["held"].as_u64().unwrap()).collect();
    assert_eq!(ks, [2], "the recreated file names it so");
}

/// Checks that the first touch reads the files the store holds and counts
/// the one it cannot read, so the first ordinal answered is past every
/// ordinal any of them names (skep #856, #875; `PrincipalHold::next_k`,
/// `HeldDir::greatest_ordinal`).
///
/// An earlier run left the board's own file naming ordinals up to 2 and a
/// pending file naming ordinals up to 9, one line standing in each. Three
/// first touches: (a) the head reads and the store is this shell's — the
/// board's file is read as the queue's and the pending file beside it, its
/// standing line entering under the next fresh ordinal, 3, past the board's
/// file's 2, and the pending file removed; so the first burst held takes 4;
/// (b) another process holds the pending lock, so the store is another's:
/// no file is read, nothing is listed, and a burst is refused
/// `another_window`, nothing held; (c) the board's own directory cannot be
/// locked, sealed, the head read and naming its chain — the queue is on the
/// pending file, read as its own, and the board's file, not read, is
/// counted, so the first burst held takes 21, past its 20 (the mutant that
/// starts the counter at the queue's own file alone hands out an ordinal
/// the board's file names, which the change would then renumber in the
/// page's hands; the one that keeps a line in memory at a refused board's
/// own directory loses it at a close).
#[cfg(unix)]
#[test]
fn the_first_touch_reads_the_pending_file_and_the_boards_file_and_the_first_ordinal_is_past_both() {
    use std::os::unix::fs::PermissionsExt;
    let chain = Chain::parse(&"ab".repeat(32)).unwrap();
    // The files an earlier run left: the board's own naming ordinals up to
    // `board`, the pending one up to `pending`, one line standing in each.
    let seed = |store: &TempDir, board: u64, pending: u64| {
        let dir = HeldDir::new(store.path(), chain);
        dir.ensure().unwrap();
        let Opened::Live { mut queue, .. } = dir.open_file(1, "1.0.1").unwrap() else { panic!("a fresh file") };
        for n in 1..=board {
            queue.hold_next(DOC, None, 0, insert(DOC, json!([format!("b{n}")]), 0), None, Reason::of("unreachable", false)).unwrap();
        }
        for k in 1..board {
            queue.done(k, Done::Dropped).unwrap();
        }
        let dir = HeldDir::pending(store.path(), &Origin::parse("http://127.0.0.1:1").unwrap());
        dir.ensure().unwrap();
        let Opened::Live { mut queue, .. } = dir.open_file(1, "1.0.1").unwrap() else { panic!("a fresh file") };
        for n in 1..=pending {
            queue.hold_next(OTHER, None, 0, insert(OTHER, json!([format!("p{n}")]), 0), None, Reason::of("head_unreadable", false)).unwrap();
        }
        for k in 1..pending {
            queue.done(k, Done::Dropped).unwrap();
        }
        dir
    };
    let listed = |g: &Ground| g.lines().iter().map(|l| (l["held"].as_u64().unwrap(), l["frame"]["values"][0].as_str().unwrap_or("?").to_string())).collect::<Vec<_>>();
    // (a) The store this shell's: the board's file the queue's, the pending
    // file's line joined under a fresh ordinal.
    let store = TempDir::new().unwrap();
    seed(&store, 2, 9);
    let facts = writer_facts(&store);
    let g = ground_over(Fake::new(), store, facts, 0);
    assert!(!g.holds.another_window("b-1") && !pending_file(&g).exists(), "(a) premise: the store is this shell's, the pending file joined and removed: {:?}", g.said.lock().unwrap());
    assert_eq!(listed(&g), [(2, "b2".to_string()), (3, "p9".to_string())], "(a) the board's file's line keeps its ordinal, the pending file's takes the next fresh one");
    let held = g.hold(&insert(DOC, json!(["x"]), g.fake.head()), "unreachable", false);
    assert_eq!(held["held"], 4, "(a) past both: {held}");
    assert!(held.get("unwritable").is_none(), "(a) on the board's file: {held}");
    // (b) Another process holds the pending lock: the store another's.
    let store = TempDir::new().unwrap();
    let pending_dir = seed(&store, 2, 9);
    let _other = pending_dir.try_lock().unwrap().expect("the pending lock is free to take");
    let facts = writer_facts(&store);
    let g = ground_over(Fake::new(), store, facts, 0);
    assert!(g.holds.another_window("b-1"), "(b) premise: the pending lock another process holds makes the store another's");
    assert!(g.lines().is_empty(), "(b) no file is read, nothing listed");
    let refused = g.hold_for(&insert(DOC, json!(["x"]), g.fake.head()), Reason::of("unreachable", false)).unwrap_err();
    assert_eq!(refused.name(), "another_window", "(b) nothing is held at another shell's store: {refused}");
    // (c) The board's directory sealed, the head read: the queue on the
    // pending file, the board's file counted.
    let store = TempDir::new().unwrap();
    seed(&store, 20, 9);
    let board_dir = store.path().join("held").join(chain.to_string());
    std::fs::set_permissions(&board_dir, std::fs::Permissions::from_mode(0o500)).unwrap();
    let facts = writer_facts(&store);
    let g = ground_over(Fake::new(), store, facts, 0);
    let held = g.hold(&insert(DOC, json!(["x"]), g.fake.head()), "unreachable", false);
    std::fs::set_permissions(&board_dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    assert!(!g.holds.another_window("b-1") && held.get("unwritable").is_none(), "(c) premise: the board's own directory refused, the queue on the pending file: {held}");
    assert_eq!(said_containing(&g, "the board's own held store could not be made or locked").len(), 1, "(c) the refusal said once: {:?}", g.said.lock().unwrap());
    assert_eq!(held["held"], 21, "(c) past the board's file's 20 and the pending file's 9: {held}");
    assert!(std::fs::read_to_string(pending_file(&g)).unwrap().contains("\"values\":[\"x\"]"), "(c) on the pending file");
}

/// Checks that the first touch with a term takes both locks, and keeps the
/// pending one with no pending file standing (§3c.1, §3c.3; skep #873).
///
/// The head reads at the session's open: the pending directory is made and
/// locked first, then the board's own, and the pending directory stands
/// empty but for its lock file — the board's file is the queue's, so no
/// pending file is written. A burst goes to the board's file, is kept at
/// the probe, and the file compacts away; both locks are held still, the
/// pending one with no pending file ever standing (the mutant that lets the
/// pending lock go once no pending file stands leaves another shell free to
/// take it and write beside this one; the one that takes the pending lock
/// only where its directory stands never takes it at all).
#[test]
fn the_first_touch_with_a_term_takes_both_locks_and_keeps_the_pending_one_with_no_pending_file() {
    let g = ground();
    let pending = HeldDir::pending(g.store.path(), g.session.board.dialed());
    let own = HeldDir::new(g.store.path(), Chain::parse(&"ab".repeat(32)).unwrap());
    assert!(pending.try_lock().unwrap().is_none() && own.try_lock().unwrap().is_none(), "both locks are taken at the first touch");
    let pending_dir = pending_file(&g).parent().unwrap().to_path_buf();
    assert!(pending_dir.join("lock").is_file() && !pending_file(&g).exists(), "the pending directory stands, empty but for its lock file");
    let held = g.hold(&insert(DOC, json!(["a"]), g.fake.head()), "unreachable", false);
    assert!(held.get("unwritable").is_none() && std::fs::read_to_string(held_file(&g)).unwrap().contains("\"values\":[\"a\"]"), "the line goes to the board's file: {held}");
    assert!(!pending_file(&g).exists(), "no pending file is written");
    g.holds.probe("b-1");
    assert!(g.lines().is_empty() && !held_file(&g).exists(), "the line kept and the board's file compacted away");
    assert!(pending.try_lock().unwrap().is_none() && own.try_lock().unwrap().is_none(), "both locks are kept for the shell's life, the pending one with no pending file");
}

/// Checks that an earlier run's halted pending file halts the principal at
/// the first touch, before any hold (§3c.3; skep #857).
///
/// An earlier run's pending file stands, written by a newer skep, and the
/// head reads at the session's open: the first touch reads the board's file
/// and the pending file beside it, finds the pending one halted, and the
/// principal is halted before any line is held — `held(session)` and a
/// burst each answer `store_halted`, nothing held and nothing written, the
/// halted file the native side's to show and never rebuilt over, the halt
/// said once; a probe sends nothing (the mutant that holds the burst and
/// joins the pending file later keeps this run's lines waiting in memory
/// behind a file no join takes, and the halt's remedy — the file moved aside
/// with the shell stopped — loses them).
#[test]
fn an_earlier_runs_halted_pending_file_halts_the_principal_at_the_first_touch_before_any_hold() {
    let store = TempDir::new().unwrap();
    let origin = Origin::parse("http://127.0.0.1:1").unwrap();
    let pending = HeldDir::pending(store.path(), &origin);
    pending.ensure().unwrap();
    let newer = format!("{{\"type\":\"skep-held-bursts\",\"v\":3,\"board\":\"{}\",\"principal\":1,\"account\":\"1.0.1\"}}\n", origin.as_str());
    let facts = writer_facts(&store);
    let g = ground_over(Fake::new(), store, facts, 0);
    let file = pending_file(&g);
    let Ground { holds, fake, session, store, .. } = g;
    drop(holds);
    std::fs::write(&file, &newer).unwrap();
    let g = ground_over(fake, store, session.facts.clone(), 0);
    assert_eq!(g.holds.lines(&g.session).unwrap_err().name(), "store_halted", "the principal is halted at the first touch");
    let refused = g.hold_for(&insert(DOC, json!(["a"]), g.fake.head()), Reason::of("unreachable", false)).unwrap_err();
    assert_eq!(refused.name(), "store_halted", "nothing is held: {refused}");
    assert_eq!(g.holds.halted_file("b-1", 1).as_deref(), Some(file.as_path()), "the halted file is the pending one");
    assert_eq!(std::fs::read_to_string(&file).unwrap(), newer, "never rebuilt over");
    assert!(!held_file(&g).exists(), "nothing written to the board's file");
    assert_eq!(said_containing(&g, "is halted").len(), 1, "the halt said once: {:?}", g.said.lock().unwrap());
    g.holds.probe("b-1");
    assert_eq!(g.fake.sends(), 0, "nothing is sent");
}

/// Checks that the burst's door refuses a piece that names no place, nothing
/// held or dialed (skep #969).
///
/// The own node stopped, an insert of three positions under the `id` `b-1`,
/// a delete under `d-1` and an insert on another document under `o-1` stand
/// held. A burst naming by a piece a burst never sent, the other document's
/// insert, the delete's words, or the insert's words at an offset at its
/// positions is refused at the act — `no_such_burst` naming the anchor and
/// the burst, or `malformed_args` naming the anchor — no line held for it and
/// nothing dialed; one naming the insert's last position is held behind it
/// (the mutant that binds a piece to a line of its `id` on any document
/// places it in words its burst does not edit; the one that takes any offset
/// places it past the insert's words, at units the page never named).
#[test]
fn the_bursts_door_refuses_a_piece_that_names_no_place_nothing_held_or_dialed() {
    let g = ground();
    let typed = g.fake.head();
    g.holds.set_node_stopped("b-1", true);
    for frame in [with_id(insert_at(DOC, 4, json!(["XYZ"]), typed), "b-1"), with_id(delete_at(DOC, 2, 1, typed), "d-1"), with_id(insert(OTHER, json!(["q"]), typed), "o-1")] {
        let held = g.holds.send(&g.session, frame, None).answered().unwrap();
        assert_eq!(held["cause"], "stopped", "{held}");
    }
    let named = |before: Value, after: Value| g.holds.send(&g.session, with_id(insert_at(DOC, 5, json!(["!"]), typed), "b-2"), Some(pieced(before, after))).answered();
    let no_such = |anchor: &str, burst: &str| json!({"kind": "shell", "name": "no_such_burst", "anchor": anchor, "burst": burst});
    let malformed = |what: &str| Refusal::malformed(what).to_value();
    let cells = [
        ("a burst never sent", piece("b-9", 0), Value::Null, no_such("before", "b-9")),
        ("another document's insert", Value::String(i(3)), piece("o-1", 0), no_such("after", "o-1")),
        ("a delete's words", piece("d-1", 0), Value::Null, malformed("anchors.before")),
        ("an offset at the insert's positions", Value::String(i(3)), piece("b-1", 3), malformed("anchors.after")),
    ];
    for (cell, before, after, refused) in cells {
        assert_eq!(named(before, after).unwrap_err().to_value(), refused, "{cell}");
    }
    assert_eq!((g.lines().len(), g.fake.sends()), (3, 0), "nothing held for them, nothing dialed");
    let held = named(Value::String(i(3)), piece("b-1", 2)).unwrap();
    assert_eq!((held["resp"].as_str(), g.lines().len()), (Some("held"), 4), "the insert's last position is a place: {held}");
}
