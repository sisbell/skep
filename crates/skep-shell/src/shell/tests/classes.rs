//! The held store's open defect classes over a `Shell`, pinned as expected
//! failures against the daemon (skep #874; the record
//! `2026-11-06-held-store-investigation` §7's Brief 0).
//!
//! Each cell asserts the invariant the store should keep (the record's §2),
//! its assertion intact and its message opening with the invariant's id,
//! and is marked `should_panic` on that id and its colon alone, so a panic
//! in its setup satisfies nothing: the cell passes while the defect stands
//! and fails the day a brief closes the class, which then removes the
//! marker. `I6` (K3): a window whose head will not read takes no pending
//! lock the board's own holder let go, and is refused `another_window`
//! while that holder stands — GREEN since Brief B (skep #873): both locks
//! are taken at the first touch and kept for the shell's life, so the
//! pending lock is never let go for a later window to take. `I9` (K5): a whole-draft
//! write — the restore — never lands past the draft's standing held lines
//! — GREEN since Brief C (skep #849, #854): the shell's one write door asks
//! the draft's held lines of every whole-draft write and refuses it
//! `held_lines`, nothing dialed. The merge rows' door (skep #850) is Brief
//! C's too, pinned in `shell/tests/merge.rs` and `shell/tests/publication.rs`.

use skep_search::Chain;

use super::merge::arrangement_rows;
use super::publication::ground;
use super::*;
use crate::held::HeldDir;

/// K3 / `I6` — one writer per board (skep #873; the record §2 I6, §3 K3).
/// GREEN since Brief B, which removed `should_panic`: the cell pins the
/// invariant from here.
///
/// Window A's first session opens with its read of the board's head served
/// garbled (the seam `garble_the_next_head_read_on_this_thread`, armed on
/// the calling thread just before the open): A takes the pending lock, the
/// board's chain unnamed. A's next session opens with the head reading: A
/// takes the board's own lock too, and keeps both for its life. Window B
/// over the same store then opens a session with its head read served
/// garbled too: the pending lock is A's, so B takes none and stands another
/// shell's — its open answers `another_window`, and its burst is refused.
/// The invariant (skep #828's rule): B is refused `another_window` while A
/// holds the board's own lock, never let write beside it (before Brief B,
/// A's second open carried the pending lock to the join and let it go once
/// no queue was its file's, so B, whose head would not read, took the free
/// pending lock, stood `Pending`, and its burst went out and was acked —
/// two windows each holding one of the board's locks, both writing).
#[test]
fn i6_a_window_whose_head_will_not_read_is_refused_while_another_holds_the_boards_own_lock() {
    let dir = TempDir::new().unwrap();
    let sd = spawn(&dir.path().join("board"), true);
    let origin = format!("http://127.0.0.1:{}", sd.port());
    let store = dir.path().join("store");
    claim_board(&origin, &store);
    let chain = Board::new(Origin::parse(&origin).unwrap(), skep_client::PlainHttp::new()).board_term().unwrap().expect("the claim's head stands").chain;
    let pending = HeldDir::pending(&store, &Origin::parse(&origin).unwrap());
    let own = HeldDir::new(&store, Chain::from_bytes(chain));
    // Whether a lock is free: taken and let go at once.
    let free = |dir: &HeldDir| matches!(dir.try_lock(), Ok(Some(_)));
    let open = |shell: &Shell, board: &str| -> Value {
        let opened = shell.call("session", &json!({"board": board})).unwrap();
        crate::shapes::assert_declared("SessionOpened", &opened);
        opened
    };
    // Window A: the pending lock at its first open, the board's own at its
    // second, both kept.
    let (a, a_lines) = open_shell(&origin, &store, SessionMode::Signed { principal: 1 });
    let a_board = a.board_references().remove(0);
    crate::sessions::garble_the_next_head_read_on_this_thread();
    let opened = open(&a, &a_board);
    assert!(opened.get("another_window").is_none() && !free(&pending), "premise: A's first open takes the pending store: {opened}\n{}", a_lines.lock().unwrap().join("\n"));
    let opened = open(&a, &a_board);
    assert!(opened.get("another_window").is_none() && !free(&own) && !free(&pending), "premise: A's second open takes the board's own lock and keeps the pending one: {opened}\n{}", a_lines.lock().unwrap().join("\n"));
    let a_session = opened["session"].as_str().unwrap().to_string();
    let minted = a.call("op", &json!({"session": a_session, "frame": {"op": "create_new_document", "account": "1.0.1"}})).unwrap();
    let draft = minted["addr"].as_str().unwrap_or_else(|| panic!("the draft is minted: {minted}")).to_string();
    // Window B, its head read served garbled.
    let (b, b_lines) = open_shell(&origin, &store, SessionMode::Signed { principal: 1 });
    let b_board = b.board_references().remove(0);
    crate::sessions::garble_the_next_head_read_on_this_thread();
    let opened = open(&b, &b_board);
    let b_session = opened["session"].as_str().unwrap().to_string();
    let burst = json!({"op": "insert", "doc": draft, "at": {"subspace": "1", "ordinal": "1"}, "values": ["b"], "as_of": minted["at"]});
    let answer = b.call("op", &json!({"session": b_session, "frame": burst}));
    assert!(
        matches!(&answer, Err(refused) if refused.name() == "another_window"),
        "I6: one writer per board — window A holds the board's own lock, and window B, whose head would not read, took the pending lock A let go and stands beside it: B's open answered {opened}, its burst {answer:?}, the pending lock {}; B said:\n{}",
        if free(&pending) { "free" } else { "held" },
        b_lines.lock().unwrap().join("\n")
    );
    a.shutdown();
    b.shutdown();
    sd.shutdown();
}

/// K5 / `I9` — a whole-draft write never lands past the draft's standing
/// held lines (skep #849, #854; the record §2 I9, §3 K5). GREEN since Brief
/// C, which removed `should_panic`: the cell pins the invariant from here.
///
/// A draft typed in two bursts; a burst at a far ordinal the draft has no
/// room for is refused `out_of_bounds`, a permanent refusal, and held as a
/// refused run — a line awaiting the person's act, which no probe sends and
/// the node, running, never drains. `history.restore` on the draft, typed at
/// the page's state, the second burst's ack. The invariant (B3-S13's row
/// rule; D6 BM-62, BM-67): the restore is refused while the line stands, its
/// `set_arrangement` never dialed — the shell's one write door asks the
/// draft's held lines of every whole-draft write (`Shell::write_door`,
/// `Holds::held_lines`) and refuses it `held_lines` before any read (before
/// Brief C the door asked the standing cause alone — the node stopped, the
/// write path poisoned, the writes halted — and a running node has none, so
/// the restore's one write landed past the held line). A stopped node is
/// the wrong ground: the standing hold refuses the restore there already,
/// and once the node runs the probe drains a line that awaits no act.
#[test]
fn i9_a_restore_is_refused_while_a_line_of_the_draft_stands_held() {
    let dir = TempDir::new().unwrap();
    let sd = spawn(&dir.path().join("board"), true);
    let g = ground(&dir, &sd);
    let minted = g.op(json!({"op": "create_new_document", "account": "1.0.1"}));
    let d = minted["addr"].as_str().expect("an ack_addr").to_string();
    let p1 = g.op(json!({"op": "insert", "doc": d, "at": {"subspace": "1", "ordinal": "1"}, "values": ["the cat"], "as_of": minted["at"]}))["at"].clone();
    let typed = g.op(json!({"op": "insert", "doc": d, "at": {"subspace": "1", "ordinal": "8"}, "values": [" sat"], "as_of": p1}))["at"].as_u64().expect("the page's state");
    // The refused run: a burst past the draft's head, held awaiting the
    // person's act.
    let refused = g.op(json!({"op": "insert", "doc": d, "at": {"subspace": "1", "ordinal": "900000"}, "values": ["r"], "as_of": typed}));
    assert!(refused["resp"] == "held" && refused["cause"].as_str().is_some_and(|cause| cause.starts_with("out_of_bounds")), "premise: a refused run stands on the draft: {refused}");
    let k = refused["held"].as_u64().unwrap();
    assert_eq!(g.call("probe", json!({})).unwrap()["daemon"], "running", "premise: the node runs, so no hold stands at the board");
    let before = g.position();
    let restore = g.call("history.restore", json!({"session": g.session, "draft": d, "at": p1, "as_of": typed}));
    let rows = arrangement_rows(&g, &d, before);
    let standing = g.call("held", json!({"session": g.session})).unwrap();
    assert!(
        restore.is_err() && rows.is_empty(),
        "I9: a whole-draft write never lands past the draft's standing held lines — line {k} of {d} stands held, a refused run awaiting the person's act, and the restore was let through past it: it answered {restore:?}, the draft's `set_arrangement` rows since {before}: {rows:?}; the lines standing: {standing}"
    );
    g.shell.shutdown();
    sd.shutdown();
}
