//! The held store's defect classes over the holds, each pinned as an
//! expected failure until the brief that closes it lands, and the measure
//! of the syncs each act makes (skep #874; the record
//! `2026-11-06-held-store-investigation` §7's Brief 0).
//!
//! Each cell asserts the invariant the store should keep (the record's §2),
//! its assertion intact and its message opening with the invariant's id,
//! and is marked `should_panic` on that id and its colon alone while its
//! class stands open, so a panic in its setup satisfies nothing: the cell
//! passes while the defect stands and fails the day a brief closes the
//! class, which then removes the marker and the cell pins the invariant
//! from there. The interleaving each cell needs is forced — by the fake's
//! look as a read reaches it, on the thread that made the read — never
//! waited for. `I13` (K1): an ordinal a call holds across the shift's read
//! names the line it held, though a join runs meanwhile — GREEN since Brief
//! A (skep #856): one ordinal space for the shell's life, the join an
//! ordered insert that moves no ordinal this run answered. `I8` (K2): a
//! halt found as the directory is established halts the lines held before
//! it — GREEN since Brief B (skep #858): every line is on disk from the
//! first touch, and a halt found at the pending → chain change halts the
//! principal before any walk. The
//! measure (`#[ignore]`, run by hand): the held file's syncs for a burst
//! held at a stopped node, a burst's whole life to its `done`, a
//! `resolve(drop)` and a `resolve(send)` of a run of sixteen, and a probe
//! draining sixteen — each made under the board lock today (the record's
//! §1.2), so the count is the count under the lock (K4; Brief D's baseline).

use super::*;

/// K1 / `I13` — the ordinal the page holds names the line it held (skep
/// #856; the record §2 I13, §3 K1). GREEN since Brief A, which removed
/// `should_panic`: the cell pins the invariant from here.
///
/// The board unclaimed at the session's open names no chain, so the
/// principal's queue stands in memory alone, its ordinals the principal's
/// one space; an earlier run's held file stands under the board's chain,
/// holding one line under ordinal 1. A stale burst carrying anchors is
/// refused `arrangement_moved` at its first dial and shifted within the
/// call: the line is entered under ordinal 1, and the call holds that
/// ordinal across the shift's one read, made outside every lock. As that
/// read reaches the board, the fake's look runs ANOTHER SESSION's open on a
/// thread of its own, the board claimed by then: the directory is
/// established and the join reads the board's file for the first time,
/// whose line stands under an ordinal this run's line holds, so the earlier
/// run's line is renumbered past it, 2, and the memory line enters under
/// the ordinal the call holds, 1 (the join's `Talk` line names the line
/// renumbered). The call goes on with the ordinal it took — the shifted
/// frame written to it, the line marked `sent`, the shifted dial acked and
/// the ordinal settled `kept`. The invariant: the ack settles the call's own
/// burst, and the earlier run's line, never sent, stands (before Brief A
/// the join renumbered the memory line behind the earlier run's instead, so
/// the earlier run's line was overwritten with the shifted frame and
/// settled kept in the call's place, the call's own burst left `moved`).
#[test]
fn i13_an_ordinal_held_across_the_shifts_read_names_the_line_it_held_when_a_join_renumbers() {
    let fake = Fake::new();
    fake.no_head.store(true, Ordering::SeqCst);
    fake.unclaimed.store(true, Ordering::SeqCst);
    *fake.image.lock().unwrap() = vec![run(&i(10), 2), run(&i(1), 3)];
    fake.move_arrangement(DOC, 77);
    let store = TempDir::new().unwrap();
    // The earlier run's line, under the board's chain, ordinal 1.
    let dir = HeldDir::new(store.path(), Chain::parse(&"ab".repeat(32)).unwrap());
    dir.ensure().unwrap();
    let Opened::Live { mut queue, .. } = dir.open_file(1, "1.0.1").unwrap() else { panic!("a fresh file") };
    assert!(queue.hold_next(DOC, None, 0, insert(DOC, json!(["earlier"]), 0), None, Reason::of("unreachable", false)).unwrap().unwritten.is_none());
    drop(queue);
    let facts = writer_facts(&store);
    let g = ground_over(fake, store, facts, 0);
    let typed = g.fake.head();
    // Another session of the principal's, whose open the look runs on a
    // thread of its own as the shift's read reaches the board.
    let other = g.sessions.register(&g.entry, Open { token: Token::parse(&"8e".repeat(16)).unwrap(), facts: g.session.facts.clone(), opened_at: 0 }, &mut NoSupplements);
    let (fake, holds) = (Arc::clone(&g.fake), Arc::clone(&g.holds));
    *g.fake.at_image.lock().unwrap() = Some(Box::new(move || {
        fake.no_head.store(false, Ordering::SeqCst);
        fake.unclaimed.store(false, Ordering::SeqCst);
        let (holds, other) = (Arc::clone(&holds), Arc::clone(&other));
        thread::spawn(move || holds.open_session(&other)).join().expect("the other session's open");
    }));
    let answer = g.holds.send_burst(&g.session, insert_at(DOC, 2, json!(["x"]), typed), Some(anchors(Some(&i(1)), Some(&i(2)))));
    *g.fake.at_image.lock().unwrap() = None;
    let OpAnswer::Answered(Ok(ack)) = answer else { panic!("premise: the shifted burst is acked within the call: {answer:?}") };
    assert_eq!(ack["resp"], "ack", "premise: {ack}");
    let joined = said_containing(&g, "joined the board's held file");
    assert!(joined.len() == 1 && joined[0].contains("renumbered"), "premise: the join renumbered the memory line while the call held its ordinal: {joined:?}");
    let standing: Vec<String> = g.lines().iter().map(|l| l["frame"]["values"][0].as_str().unwrap_or("?").to_string()).collect();
    assert_eq!(
        standing,
        ["earlier"],
        "I13: the ordinal the page holds names the line it held — ordinal 1 named the call's own burst (\"x\") when the call took it; the join renumbered the queue while the call shifted outside the lock, and the ack settled ordinal 1 as it stood then: the earlier run's line (\"earlier\"), never sent, overwritten with the shifted frame and kept in the call's place, the call's own burst left standing: {:?}",
        g.lines()
    );
}

/// K2 / `I8` — a halt halts the surface (skep #858; the record §2 I8, §3
/// K2). GREEN since Brief B, which removed `should_panic`: the cell pins
/// the invariant from here.
///
/// The board away at the session's open, the pending store is taken at the
/// first touch and a burst is held on the pending file, nothing in memory;
/// an earlier run's held file stands under the board's chain, written by a
/// newer skep, so P38 halts it. The board returns: the probe's one head read
/// takes the board's own directory, and the pending → chain change opens the
/// board's file and finds it halted — the principal halts from that moment,
/// the pending file left as it stands with its line on it, the halt said
/// once. The invariant: once the halt stands no line is sent, wherever it is
/// stored, since a send could land behind text the newer file holds
/// (§3c.3), and the halt is answered at the door (before Brief B the line
/// was held in memory alone, the directory not yet this shell's; the join
/// that found the halt was refused and left it there, the walk that followed
/// in the same probe sent it, and the door halted the principal only at the
/// next touch, the queue empty).
#[test]
fn i8_a_halt_found_as_the_directory_is_established_halts_the_lines_held_in_memory_before_it() {
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
    match g.hold_for(&insert(DOC, json!(["a"]), g.fake.head()), Reason::of("unreachable", false)) {
        Ok(held) => assert!(held.get("unwritable").is_none(), "premise: held on the pending file, the board away: {held}"),
        Err(refused) => assert_eq!(refused.name(), "store_halted", "premise: a hold at a halted principal is refused the halt, or held on the pending file: {refused}"),
    }
    let pending = pending_file(&g);
    let on_pending = std::fs::read_to_string(&pending).unwrap();
    assert!(on_pending.contains("\"values\":[\"a\"]"), "premise: the line is on the pending file");
    g.fake.head_unreachable.store(false, Ordering::SeqCst);
    g.holds.probe("b-1");
    let said = said_containing(&g, "is halted");
    assert_eq!(
        g.fake.sends(),
        0,
        "I8: a halt halts the surface — the principal's held file was found halted (written by a newer skep) as the probe established the directory, and the line held in memory before it went out all the same, past text the newer file may hold; said: {said:?}"
    );
    assert_eq!(g.holds.lines(&g.session).unwrap_err().name(), "store_halted", "the halt stands at the door");
    assert_eq!(std::fs::read_to_string(&file).unwrap(), newer, "the halted file is never rebuilt over");
    assert_eq!(std::fs::read_to_string(&pending).unwrap(), on_pending, "the pending file is left as it stands, its line on it");
    assert_eq!(said.len(), 1, "the halt is said once: {said:?}");
}

/// Measures the syncs the held file makes for each act (the record's K4
/// measure; its §7 Brief 0 and §8 item 8): run by hand, the figures printed
/// and each held above zero alone.
///
/// The count is `held.rs`'s process-wide counter, read under nextest — one
/// process per test — and reset at each act's start; `cargo test`'s shared
/// process would mix in the counts of the cells it runs beside this one.
/// Every sync counted is made under the board lock today (the record's
/// §1.2), so the count is the count under the lock. The acts: (a) one burst
/// held at a stopped node — the header's sync and the line's; (b) a burst's
/// whole life — held at a stopped node, then the node running and the
/// probe's resend acking it, the mark of `sent` and the `done` each synced;
/// (c) `resolve(drop)` of a refused run of sixteen lines on one document — a
/// `done` per line; (d) `resolve(send)` of that run — the refused head alone
/// awaits the person's act, so it alone is re-marked — and, beside it, of a
/// document whose sixteen lines stand `moved`, each re-marked and raised;
/// (e) a probe draining sixteen lines held at a stopped node — a mark and a
/// `done` per line.
#[test]
#[ignore = "measurement - run by hand"]
fn the_syncs_each_act_makes_under_the_board_lock() {
    use crate::held::take_syncs;
    let stopped_burst = |g: &Ground, value: &str| {
        let OpAnswer::Answered(Ok(held)) = g.holds.send_burst(&g.session, insert(DOC, json!([value]), g.fake.head()), None) else { panic!("held at the stopped node") };
        assert_eq!(held["cause"], "stopped", "{held}");
    };
    // (a) One burst held at a stopped node; (b) its life to its `done`.
    let g = ground();
    g.holds.set_node_stopped("b-1", true);
    take_syncs();
    stopped_burst(&g, "a");
    let a = take_syncs();
    g.holds.set_node_stopped("b-1", false);
    g.holds.probe("b-1");
    let b_rest = take_syncs();
    assert!(g.lines().is_empty(), "the burst kept");
    let b = a + b_rest;
    // (c) and (d): a refused run of sixteen lines on one document.
    let refused_run = || -> Ground {
        let g = ground();
        let verdict = json!({"resp": "rejected", "code": "out_of_bounds", "disposition": "permanent", "op": "insert"});
        g.hold_for(&insert(DOC, json!(["0"]), g.fake.head()), Reason::refused("out_of_bounds", verdict)).unwrap();
        for n in 1..16 {
            g.hold(&insert(DOC, json!([n.to_string()]), g.fake.head()), "behind", false);
        }
        assert_eq!(g.lines().len(), 16, "the run of sixteen");
        g
    };
    let g = refused_run();
    take_syncs();
    assert_eq!(g.holds.resolve(&g.session, 1, ResolveAct::Drop).unwrap(), Resolved::Dropped);
    let c = take_syncs();
    assert!(g.lines().is_empty(), "the run dropped");
    let g = refused_run();
    take_syncs();
    assert_eq!(g.holds.resolve(&g.session, 1, ResolveAct::Send).unwrap(), Resolved::HandedBack);
    let d_refused = take_syncs();
    let g = ground();
    for n in 0..16 {
        g.hold(&insert(DOC, json!([n.to_string()]), g.fake.head()), "unreachable", false);
    }
    g.holds.mark_moved("b-1", 1, DOC, Some((1, arrangement_moved(40, 45))));
    assert!(g.lines().iter().all(|l| l["cause"] == "moved"), "the sixteen lines moved");
    take_syncs();
    assert_eq!(g.holds.resolve(&g.session, 1, ResolveAct::Send).unwrap(), Resolved::HandedBack);
    let d_moved = take_syncs();
    // (e) A probe draining sixteen lines.
    let g = ground();
    g.holds.set_node_stopped("b-1", true);
    for n in 0..16 {
        stopped_burst(&g, &n.to_string());
    }
    g.holds.set_node_stopped("b-1", false);
    take_syncs();
    g.holds.probe("b-1");
    let e = take_syncs();
    assert!(g.lines().is_empty(), "the sixteen kept");
    let figures = [
        ("(a) one burst held at a stopped node", a),
        ("(b) a burst held at a stopped node, then resent and its `done` at the ack", b),
        ("(c) resolve(drop) of a refused run of 16 lines", c),
        ("(d) resolve(send) of a refused run of 16 lines", d_refused),
        ("(d') resolve(send) of a moved document's 16 lines", d_moved),
        ("(e) a probe draining 16 lines", e),
    ];
    for (act, syncs) in figures {
        println!("syncs under the board lock — {act}: {syncs}");
        assert!(syncs > 0, "{act}: no sync counted");
    }
}
