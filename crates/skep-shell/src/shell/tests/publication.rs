//! The publication family (`client.md` §4b.1's four rows, §4b.2's event).
//!
//! The suite checks the rules the shell alone keeps, with no daemon behind
//! it — a `publish` frame through `op` refused as a call before any dial,
//! the unholdable writes — the mint among them — refused under a stopped
//! node and under halted writes and `unreachable` not of the set, the merge
//! rows refused under the same holds before any read, `count` and `confirm`
//! with no panel `no_panel`, `cancel` idempotent, a bare session refused at
//! `open`, and the row's own members read before the session, a `base`
//! among them read by nothing — and, against the real daemon, the family
//! end to end: the panel over a draft with a notes link and a read-with set,
//! the count as a row flips, the confirm acknowledged with its two events
//! and the feed row naming the member and the homes, the second open inert,
//! the fold — a note left off at version 1 unchanged since it at the next
//! open, P3 not standing over its compact row, a note made since news —
//! the document's own links on the words a shot re-inserts, one standing P3
//! alone and an edition claim counted never,
//! the stopped node refusing the confirm before it composes, a held line of
//! the rendering draft or of a draft `also` names refusing it `held_lines`
//! until the line clears, the mint form with its claim, and
//! `claim_refused` crossing as answered with the board unmoved; the family's
//! other drafts re-minted as the document's own; and the draft's base, the
//! board's record read on any device (B3-S10) — a draft staged through
//! `stage` publishing from the base the board recorded, a draft minted by
//! `fork` alone refused `base_unrecorded` with its reason, a draft behind
//! the head told `behind` and landing its daughter from a second shell, a
//! draft the board records no base for refused `base_unrecorded`, and a
//! publication that only removes words leaving the next landing after the
//! version it made; and the base's standing (D4 (a)+(b′), (d)) — the
//! family left behind off the shell's own list, a first draft told
//! `superseded_first` once version 1 stands and landing beside it as its
//! daughter, a sibling's shot landing while a panel stands re-stated at the
//! confirm, nothing sent, and version 1 landing while a first draft's panel
//! stands re-stated `superseded_first`, the daughter landing next; and THE
//! MOVED BASE (D4 (b′); skep #934) — a base another publication of the draft
//! moved re-stated `base` at an unmoved standing and the next confirm
//! sending against it, a base moved by its extent alone re-stated, a panel
//! of the whole draft re-taking the draft, a held selection the draft has
//! wholly left refused `selection_not_arranged`, nothing sent. Every draft
//! a cell publishes into a document is staged through `stage`, the one
//! frame that copies its source and records its base.

use skep_client::board::Health;
use skep_client::store::{FileStore, KeyId, KeyStore};

use super::*;
use crate::sessions::{Facts, Open};

/// Returns a signed session's facts: a key that signs nothing here.
pub(super) fn signed_facts(principal: u64) -> Facts {
    let fingerprint = skep_identity::Fingerprint::parse_hex(&"5a".repeat(32)).unwrap();
    Facts { principal, account: Some(format!("1.0.{principal}")), kind: SessionKind::Signed { fingerprint, set_account: format!("1.0.{principal}") } }
}

/// Registers a session of `facts` at the shell's first board: its reference.
pub(super) fn register(shell: &Shell, token: &str, facts: Facts) -> String {
    let board = shell.board_references().remove(0);
    let open = Open { token: Token::parse(&token.repeat(16)).unwrap(), facts, opened_at: 0 };
    shell.sessions.register(&shell.boards[0], open, &mut shell.feed(&board)).reference.clone()
}

/// Checks that a `publish` frame through `op` is refused as a call (§4b.1).
///
/// Under a signed session the frame is refused `publish_is_a_call` naming
/// its op, after the bare check — a bare session's is `write_in_bare_session`
/// first — and before any dial: a listener at the board records no frame
/// (the mutant that dials the page's publish sends a request the page
/// composed, which S-35 (a) forbids; the one that checks the publish ahead
/// of the bare check tells a keyless session a publication is a call).
#[test]
fn a_publish_frame_through_op_is_refused_as_a_call_before_any_dial() {
    let dir = TempDir::new().unwrap();
    let (origin, frames) = super::door::recording_listener();
    let (shell, _) = open_shell(&origin, &dir.path().join("store"), SessionMode::Bare { principal: 1 });
    let signed = register(&shell, "8e", signed_facts(2));
    let bare = register(&shell, "9f", Facts { principal: 1, account: Some("1.0.1".into()), kind: SessionKind::Bare });
    let publish = json!({"op": "publish", "doc": "1.0.2.0.1", "draft": "1.0.2.0.2", "runs": []});
    let refused = shell.call("op", &json!({"session": signed, "frame": publish})).unwrap_err();
    let v = refused.to_value();
    assert_eq!((refused.name(), v["kind"].as_str(), v["op"].as_str()), ("publish_is_a_call", Some("shell"), Some("publish")), "{v}");
    let at_form = shell.call("op", &json!({"session": signed, "frame": {"at": 5, "frame": publish}})).unwrap_err();
    assert_eq!(at_form.name(), "publish_is_a_call", "the /op-at form too: {at_form}");
    assert_eq!(shell.call("op", &json!({"session": bare, "frame": publish})).unwrap_err().name(), "write_in_bare_session", "the bare check first");
    // A read under the signed session is dialed, so the listener sees what a
    // dial would be, and no publish among the frames it recorded.
    let read = json!({"op": "doc_metadata", "doc": "1.0.2.0.1"});
    assert_eq!(shell.call("op", &json!({"session": signed, "frame": read})).unwrap_err().name(), "unreachable");
    let recorded = frames.lock().unwrap().clone();
    assert!(recorded.iter().all(|f| f["op"] != "publish") && recorded.contains(&read), "no publish reached the board: {recorded:?}");
}

/// Checks that the unholdable writes are refused under a standing hold at
/// the shell's one write door, the mint among them (skep #868).
///
/// With the own node stopped, each of `create_new_document`, `fork`,
/// `version`, `stage`, `set_arrangement`, `make_link`, `nullify` and
/// `edit_link` through `op` is refused `stopped` naming its op and dialed
/// never (`publish` is refused as a call ahead of it); with the writes
/// halted — the feed's last `/health` read noted `writes.halted` true — the
/// same writes are refused `halted`, the mint among them, dialed never; a
/// write outside the set — an `emit` — is dialed as it dials under either
/// hold; and with the node running and the writes going, the same writes
/// at a board that does not answer meet the dial's own `unreachable`, never
/// a hold's cause (§3c.4: "`unreachable` not of this set"). The listener
/// keeps the shell's own frames too — the feed thread's `H.1` read at its
/// consumer's open, at the thread's start and at the session's widen — so
/// each count is measured from the frames standing once a call the feed
/// thread answers behind the widen has returned (skep #752). A count, never
/// a filter by op: a mutant that dials one of the set under the stop puts
/// the attest's `H.1` read on the listener, never the write's own op; the
/// mutant that leaves the mint out of the set dials it under the stop and
/// answers `unreachable`, a network fault's face for a stopped notebook.
#[test]
fn the_unholdable_writes_are_refused_under_a_stopped_node_and_unreachable_is_not_of_the_set() {
    let dir = TempDir::new().unwrap();
    let (origin, frames) = super::door::recording_listener();
    let (talk, _) = talk();
    let mut opts = ShellOptions::new(vec![Origin::parse(&origin).unwrap()], dir.path().join("store"), SessionMode::Bare { principal: 1 }, talk);
    opts.own_node = Some(Origin::parse(&origin).unwrap());
    let shell = Shell::open(opts);
    let board = shell.board_references().remove(0);
    let session = register(&shell, "8e", signed_facts(2));
    // The shell's own reads land first: the widen the register sent and this
    // listing are two commands on the feed thread's one channel, in that
    // order, so the listing's answer — pure local where no index opened —
    // means the widen's `H.1` read is done and recorded. The frames standing
    // then are the shell's own, the count the stop is measured from.
    shell.call("places", &json!({"guest": true, "board": board})).unwrap();
    let own = frames.lock().unwrap().len();
    let writes = [
        json!({"op": "create_new_document", "account": "1.0.2"}),
        json!({"op": "fork", "published": true}),
        json!({"op": "version", "d_src": "1.0.2.0.1"}),
        json!({"op": "stage", "from": "1.0.2.0.1"}),
        json!({"op": "set_arrangement", "doc": "1.0.2.0.1", "runs": [{"origin": "1.0.2.0.1", "i_start": "1.0.2.0.1.0.1.1", "width": "1"}], "as_of": 1}),
        json!({"op": "make_link", "home": "1.0.2.0.1", "from": {"addrs": ["1.0.2.0.1"]}, "to": {"addrs": []}, "ty": {"addrs": ["1.1.0.1.0.1.0.3.13"]}}),
        json!({"op": "nullify", "home": "1.0.2.0.1", "target": "1.0.2.0.1.0.2.1"}),
        json!({"op": "edit_link", "original": "1.0.2.0.1.0.2.1", "d_s": "1.0.2.0.1", "d_a": "1.0.2.0.1", "successor": {"from": {"addrs": []}, "to": {"addrs": []}, "ty": {"addrs": ["1.1.0.1.0.1.0.3.13"]}}}),
    ];
    let outside = json!({"op": "emit", "home": "1.0.2.0.1", "from": {"addrs": ["1.0.2.0.1"]}, "to": {"addrs": []}, "ty": {"addrs": ["1.1.0.1.0.1.0.3.13"]}});
    let halted = |halted: bool| Health { body: json!({"writes": {"halted": halted}}), raw: Vec::new() };
    for (cause, stand) in [("stopped", NodeState::Stopped), ("halted", NodeState::Running)] {
        shell.set_node_state(stand);
        if cause == "halted" {
            shell.holds.note_health(&board, &halted(true));
        }
        let standing = frames.lock().unwrap().len();
        for frame in &writes {
            let refused = shell.call("op", &json!({"session": session, "frame": frame})).unwrap_err();
            let v = refused.to_value();
            assert_eq!((refused.name(), v["kind"].as_str(), v["op"].as_str()), (cause, Some("shell"), frame["op"].as_str()), "{cause}: {v}");
        }
        let under_the_hold = frames.lock().unwrap()[standing..].to_vec();
        assert!(under_the_hold.is_empty(), "{cause}: nothing of the set is dialed under the hold: {under_the_hold:?}");
        assert_eq!(shell.call("op", &json!({"session": session, "frame": outside})).unwrap_err().name(), "unreachable", "{cause}: a write outside the set dials as it dials");
    }
    shell.holds.note_health(&board, &halted(false));
    for frame in &writes {
        let refused = shell.call("op", &json!({"session": session, "frame": frame})).unwrap_err();
        assert_eq!(refused.name(), "unreachable", "{}: the dial fails as it fails, no hold's cause: {refused}", frame["op"]);
    }
    // Under the running node each write dials — a signed session's first
    // reads the board's `H.1` for its attest, which is what the listener
    // records of a write it never answers.
    let dialed = frames.lock().unwrap()[own..].to_vec();
    assert!(dialed.len() >= 10, "the two emits and the eight writes under the running node reached the listener: {dialed:?}");
}

/// Checks that the merge rows are refused under a standing hold before any
/// read, with no daemon behind the shell (skep #850).
///
/// `merge.compose` and `merge.withdraw` — the two rows that stand with no
/// composition — under the own node stopped are refused `stopped` naming the
/// op their first write dials: `stage` for a composition naming no `into`,
/// which may stage a fresh draft, `set_arrangement` for one naming it and
/// for the withdrawal; with the writes halted — the feed's last `/health`
/// read noted `writes.halted` true — `halted` naming the same; and nothing
/// reaches the board: the listener keeps no frame past the shell's own,
/// measured as the cell above measures them. The node running and the
/// writes going, the same calls read first and meet the board's silence,
/// `unreachable`, the composition's `in_claims` read and the withdrawal's
/// `doc_metadata` on the listener (the mutant that asks no hold at a merge
/// row reads under the stop and answers `unreachable`, the board's verdict
/// in the hold's place; the one that asks it under the wrong op misnames
/// the write). `merge.land` and `merge.undo` with nothing composed answer
/// `no_merge` before the door, pinned beside the rows' members; their door
/// is pinned against the daemon
/// (`merge::the_merge_rows_are_refused_under_a_stopped_node_and_a_poisoned_path_with_nothing_dialed`).
#[test]
fn the_merge_rows_are_refused_under_a_standing_hold_before_any_read() {
    let dir = TempDir::new().unwrap();
    let (origin, frames) = super::door::recording_listener();
    let (talk, _) = talk();
    let store = dir.path().join("store");
    let mut opts = ShellOptions::new(vec![Origin::parse(&origin).unwrap()], store.clone(), SessionMode::Bare { principal: 1 }, talk);
    opts.own_node = Some(Origin::parse(&origin).unwrap());
    let shell = Shell::open(opts);
    let board = shell.board_references().remove(0);
    // A key in the store, so the hand is admitted and the running case reads.
    let KeyId(fingerprint) = FileStore::open(&store).generate(None).unwrap();
    let session = register(&shell, "8e", Facts { principal: 2, account: Some("1.0.2".into()), kind: SessionKind::Signed { fingerprint, set_account: "1.0.2".into() } });
    shell.call("places", &json!({"guest": true, "board": board})).unwrap();
    let own = frames.lock().unwrap().len();
    let rows = [
        ("merge.compose", json!({"session": session, "doc": "1.0.2.0.1", "alternative": "1.0.2.0.1.1.1"}), "stage"),
        ("merge.compose", json!({"session": session, "doc": "1.0.2.0.1", "alternative": "1.0.2.0.1.1.1", "into": "1.0.2.0.4"}), "set_arrangement"),
        ("merge.withdraw", json!({"session": session, "draft": "1.0.2.0.4"}), "set_arrangement"),
    ];
    let halted = |halted: bool| Health { body: json!({"writes": {"halted": halted}}), raw: Vec::new() };
    for (cause, stand) in [("stopped", NodeState::Stopped), ("halted", NodeState::Running)] {
        shell.set_node_state(stand);
        if cause == "halted" {
            shell.holds.note_health(&board, &halted(true));
        }
        let standing = frames.lock().unwrap().len();
        for (call, args, op) in &rows {
            let refused = shell.call(call, args).unwrap_err();
            let v = refused.to_value();
            assert_eq!((refused.name(), v["kind"].as_str(), v["op"].as_str()), (cause, Some("shell"), Some(*op)), "{cause}: {call} {args}: {v}");
        }
        let under_the_hold = frames.lock().unwrap()[standing..].to_vec();
        assert!(under_the_hold.is_empty(), "{cause}: nothing read or sent under the hold: {under_the_hold:?}");
    }
    shell.holds.note_health(&board, &halted(false));
    for (call, args, _) in &rows {
        let refused = shell.call(call, args).unwrap_err();
        assert_eq!(refused.name(), "unreachable", "{call}: the hold lifted, the reads dial: {refused}");
    }
    let dialed = frames.lock().unwrap()[own..].to_vec();
    assert!(dialed.iter().any(|f| f["op"] == "in_claims") && dialed.iter().any(|f| f["op"] == "doc_metadata"), "the composition's and the withdrawal's reads reached the board: {dialed:?}");
}

/// Checks that a confirm over a held line of the rendering draft, or of a
/// draft `also` names, is refused `held_lines` and goes out once the line
/// clears, against the daemon (§3c.4, THE HELD-LINES GATE; skep #849).
///
/// D publishes E.1; A, staged from D, opens its panel naming D among
/// `also`. A burst on A at a far ordinal is refused `out_of_bounds` and
/// held, a refused run awaiting the person's act: `publication.confirm` is
/// refused `held_lines` naming A and the one line, the board's position
/// unmoved and the panel's `refused` event naming the arm; the run dropped,
/// a refused run on D — the draft `also` names, whose words the shot
/// re-mints — refuses the confirm `held_lines` naming D; that run dropped,
/// the confirm goes out, E.2 acknowledged (the mutant that gates the
/// rendering draft alone sends the shot over D's held line, re-windowing D
/// under words the board never kept; the one that counts the lines of every
/// document names a count the draft does not hold).
#[test]
fn a_confirm_over_a_held_line_of_the_rendering_draft_or_of_a_draft_also_names_is_refused_held_lines_until_it_clears() {
    let dir = TempDir::new().unwrap();
    let sd = spawn(&dir.path().join("board"), true);
    let g = ground(&dir, &sd);
    let edition = g.addr(json!({"op": "create_new_document", "account": "1.0.1", "published": true}));
    let d = g.staged(&edition, "the quick brown fox");
    g.call("publication.open", json!({"session": g.session, "draft": d, "doc": edition, "readable_drafts": [d], "published": [edition]})).unwrap_or_else(|r| panic!("{r}"));
    let first = g.call("publication.confirm", json!({"session": g.session})).unwrap_or_else(|r| panic!("{r}"));
    assert_eq!(first["member"].as_str(), Some(format!("{edition}.1").as_str()), "{first}");
    g.op(json!({"op": "insert", "doc": d, "at": {"subspace": "1", "ordinal": "20"}, "values": [" again"], "as_of": g.position()}));
    let staged = g.op(skep_client::board::frames::stage(&d, None));
    let a = staged["addr"].as_str().expect("an ack_addr").to_string();
    g.op(json!({"op": "insert", "doc": a, "at": {"subspace": "1", "ordinal": "26"}, "values": [" more"], "as_of": staged["at"]}));
    g.call("publication.open", json!({"session": g.session, "draft": a, "doc": edition, "also": [d], "readable_drafts": [a, d], "published": [edition]})).unwrap_or_else(|r| panic!("{r}"));
    let states_before = g.states().len();
    // A refused run on a draft: a burst past its head, `out_of_bounds`.
    let refused_run = |doc: &str| -> u64 {
        let held = g.op(json!({"op": "insert", "doc": doc, "at": {"subspace": "1", "ordinal": "900000"}, "values": ["r"], "as_of": g.position()}));
        assert!(held["resp"] == "held" && held["cause"].as_str().is_some_and(|c| c.starts_with("out_of_bounds")), "premise: a refused run stands on {doc}: {held}");
        held["held"].as_u64().unwrap()
    };
    let drop = |k: u64| g.call("resolve", json!({"session": g.session, "held": k, "act": "drop"})).unwrap_or_else(|r| panic!("{r}"));
    for (which, doc) in [("the rendering draft", &a), ("the draft `also` names", &d)] {
        let k = refused_run(doc);
        let before = g.position();
        let refused = g.call("publication.confirm", json!({"session": g.session})).unwrap_err();
        let v = refused.to_value();
        assert_eq!((refused.name(), v["kind"].as_str(), v["doc"].as_str(), v["held"].as_u64()), ("held_lines", Some("shell"), Some(doc.as_str()), Some(1)), "{which}: {v}");
        assert_eq!(g.position(), before, "{which}: nothing sent");
        drop(k);
        assert!(g.call("held", json!({"session": g.session})).unwrap().as_array().unwrap().is_empty(), "{which}: the run dropped");
    }
    let refused_events: Vec<Value> = g.seen.lock().unwrap().iter().filter(|e| e.name == EventName::Publication && e.data["state"] == "refused").map(|e| e.data.clone()).collect();
    assert_eq!(refused_events.len(), 2, "each refusal said once on the panel: {refused_events:?}");
    assert!(refused_events.iter().all(|e| e["arm"] == "held_lines" && e["draft"] == a), "the event names the arm and the panel's draft: {refused_events:?}");
    assert_eq!(g.states().len(), states_before + 2, "no other publication event between: {:?}", g.states());
    // The lines gone, the shot goes out.
    let acked = g.call("publication.confirm", json!({"session": g.session})).unwrap_or_else(|r| panic!("the lines gone, the confirm goes out: {r}"));
    assert_eq!((acked["outcome"].as_str(), acked["member"].as_str()), (Some("acknowledged"), Some(format!("{edition}.2").as_str())), "{acked}");
    g.shell.shutdown();
    sd.shutdown();
}

/// Checks the family's answers where no panel stands, and the row's members.
///
/// `count` and `confirm` with no panel under the session's board and
/// principal answer `no_panel`; `cancel` answers `{}` twice and says no
/// `publication` event; `open` reads its own members before the session —
/// `draft` missing, neither `doc` nor `mint`, both — each `malformed_args`
/// naming the member, and a bare session is refused `write_in_bare_session`
/// naming the call, since a publication is a write and the keyless session
/// reads alone.
#[test]
fn no_panel_cancel_is_idempotent_and_the_rows_read_their_members_first() {
    let dir = TempDir::new().unwrap();
    let (shell, _) = open_shell(&super::door::nowhere(), &dir.path().join("store"), SessionMode::Bare { principal: 1 });
    let rx = shell.subscribe();
    let signed = register(&shell, "8e", signed_facts(2));
    let bare = register(&shell, "9f", Facts { principal: 1, account: Some("1.0.1".into()), kind: SessionKind::Bare });
    for call in ["publication.count", "publication.confirm"] {
        let refused = shell.call(call, &json!({"session": signed})).unwrap_err();
        let v = refused.to_value();
        assert_eq!((refused.name(), v["session"].as_str()), ("no_panel", Some(signed.as_str())), "{call}: {v}");
    }
    assert_eq!(shell.call("publication.cancel", &json!({"session": signed})).unwrap(), json!({}));
    assert_eq!(shell.call("publication.cancel", &json!({"session": signed})).unwrap(), json!({}), "idempotent");
    assert!(rx.try_iter().all(|e| e.name != EventName::Publication), "no panel dropped, nothing said");
    let what = |args: Value| {
        let refused = shell.call("publication.open", &args).unwrap_err();
        let v = refused.to_value();
        assert_eq!(refused.name(), "malformed_args", "{args}: {v}");
        v["what"].as_str().unwrap().to_string()
    };
    assert_eq!(what(json!({"session": signed, "doc": "1.0.2.0.1"})), "draft");
    assert_eq!(what(json!({"session": signed, "draft": "1.0.2.0.2"})), "doc or mint");
    assert_eq!(what(json!({"session": signed, "draft": "1.0.2.0.2", "doc": "1.0.2.0.1", "mint": "1.0.2"})), "mint");
    assert_eq!(what(json!({"session": "s-gone", "draft": "1.0.2.0.2", "doc": "1.0.2.0.1", "claim": "yes"})), "claim", "the members before the session");
    assert_eq!(what(json!({"session": signed, "draft": "1.0.2.0.2", "doc": "1.0.2.0.1", "selection": [{"origin": "1.0.2.0.2", "i_start": 1, "width": 0}]})), "selection", "a run of no width");
    let stale = shell.call("publication.open", &json!({"session": "s-gone", "draft": "1.0.2.0.2", "doc": "1.0.2.0.1"})).unwrap_err();
    assert_eq!(stale.name(), "session_ended");
    let keyless = shell.call("publication.open", &json!({"session": bare, "draft": "1.0.1.0.2", "doc": "1.0.1.0.1"})).unwrap_err();
    assert_eq!((keyless.name(), keyless.to_value()["call"].as_str()), ("write_in_bare_session", Some("publication.open")), "{keyless}");
}

/// The signed shell over a claimed board, its own node the board: the
/// shell, the events seen, the board's and a signed session's references.
///
/// The merge family's suite (`tests/merge.rs`) stands on the same ground.
pub(super) struct Ground {
    pub(super) shell: Shell,
    pub(super) seen: Arc<Mutex<Vec<Event>>>,
    pub(super) board: String,
    pub(super) session: String,
}

pub(super) fn ground(dir: &TempDir, sd: &Skepd) -> Ground {
    let store = dir.path().join("store");
    claim_board(&format!("http://127.0.0.1:{}", sd.port()), &store);
    open_ground(sd, &store)
}

/// A SECOND DEVICE's ground over the board `ground` claimed: a fresh signed
/// shell over a data directory of its own, holding the claim's key and its
/// binding and no index, held store or panel of the first's.
///
/// One shell per data directory (§3c.3): a second shell over the first's
/// own directory reads alone at a board whose held store the first holds.
pub(super) fn second_device(dir: &TempDir, sd: &Skepd) -> Ground {
    let (store, device) = (dir.path().join("store"), dir.path().join("second-device"));
    std::fs::create_dir_all(device.join("keys")).unwrap();
    for key in std::fs::read_dir(store.join("keys")).unwrap() {
        let key = key.unwrap().path();
        std::fs::copy(&key, device.join("keys").join(key.file_name().unwrap())).unwrap();
    }
    std::fs::copy(store.join("bindings"), device.join("bindings")).unwrap();
    open_ground(sd, &device)
}

/// A fresh signed shell over the board `ground` claimed, over the data
/// directory `store`, its own node the board.
fn open_ground(sd: &Skepd, store: &Path) -> Ground {
    let origin = format!("http://127.0.0.1:{}", sd.port());
    let (talk, _) = talk();
    let mut opts = ShellOptions::new(vec![Origin::parse(&origin).unwrap()], store.to_path_buf(), SessionMode::Signed { principal: 1 }, talk);
    opts.own_node = Some(Origin::parse(&origin).unwrap());
    let shell = Shell::open(opts);
    let seen = Arc::new(Mutex::new(Vec::new()));
    let _answerer = answer_moments(shell.subscribe(), Arc::clone(&shell.pending), Arc::clone(&seen));
    let board = shell.call("boards", &json!({})).unwrap()[0]["board"].as_str().unwrap().to_string();
    let session = shell.call("session", &json!({"board": board})).unwrap()["session"].as_str().unwrap().to_string();
    Ground { shell, seen, board, session }
}

impl Ground {
    pub(super) fn op(&self, frame: Value) -> Value {
        self.shell.call("op", &json!({"session": self.session, "frame": frame})).unwrap_or_else(|r| panic!("{frame}: {r}"))
    }

    pub(super) fn addr(&self, frame: Value) -> String {
        self.op(frame)["addr"].as_str().expect("an ack_addr").to_string()
    }

    /// A draft of the claimant's holding `text`, minted and never staged:
    /// the board records no base for it.
    pub(super) fn draft(&self, text: &str) -> String {
        let minted = self.op(json!({"op": "create_new_document", "account": "1.0.1"}));
        let d = minted["addr"].as_str().expect("an ack_addr").to_string();
        self.op(json!({"op": "insert", "doc": d, "at": {"subspace": "1", "ordinal": "1"}, "values": [text], "as_of": minted["at"]}));
        d
    }

    /// A draft of the claimant's staged from `from` — a version, or the bare
    /// document while its chain is empty — by the one `stage` frame, which
    /// copies `from`'s words by identity and records the draft's base
    /// (B3-S10), `text` written at its head.
    pub(super) fn staged(&self, from: &str, text: &str) -> String {
        let staged = self.op(skep_client::board::frames::stage(from, None));
        let d = staged["addr"].as_str().expect("an ack_addr").to_string();
        self.op(json!({"op": "insert", "doc": d, "at": {"subspace": "1", "ordinal": "1"}, "values": [text], "as_of": staged["at"]}));
        d
    }

    pub(super) fn call(&self, name: &str, args: Value) -> Result<Value, Refusal> {
        self.shell.call(name, &args)
    }

    /// The `publication` events seen so far, their states in order.
    pub(super) fn states(&self) -> Vec<String> {
        self.seen.lock().unwrap().iter().filter(|e| e.name == EventName::Publication).map(|e| e.data["state"].as_str().unwrap_or("?").to_string()).collect()
    }

    /// The `publication` events' states once `n` of them are seen: the
    /// events are copied on the answerer's thread, so a check of the ones a
    /// call said waits for them to arrive.
    pub(super) fn states_once(&self, n: usize) -> Vec<String> {
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            let states = self.states();
            if states.len() >= n {
                return states;
            }
            assert!(Instant::now() < deadline, "{n} publication events never arrived: {states:?}");
            thread::sleep(Duration::from_millis(20));
        }
    }

    pub(super) fn position(&self) -> u64 {
        self.shell.call("health", &json!({"board": self.board})).unwrap()["health"]["log_position"].as_u64().unwrap()
    }

    /// The text a document reads over its first `width` positions, read
    /// under the session — a draft of the person's own among them.
    pub(super) fn text(&self, doc: &str, width: u64) -> String {
        let read = self.op(skep_client::board::frames::retrieve_v(doc, 1, width));
        read["items"].as_array().into_iter().flatten().map(|i| i["content"].as_str().unwrap_or("")).collect()
    }

    /// Waits for the document index to list each of `docs` among the
    /// session's places: the shell's own list, which an open reads for the
    /// family it leaves behind.
    pub(super) fn listed(&self, docs: &[&str]) {
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            let places = self.call("places", json!({"session": self.session})).unwrap_or_else(|r| panic!("{r}"));
            let listed: Vec<&str> = places["docs"].as_array().into_iter().flatten().filter_map(|place| place["doc"].as_str()).collect();
            if docs.iter().all(|d| listed.contains(d)) {
                return;
            }
            assert!(Instant::now() < deadline, "the index never listed {docs:?}: {places}");
            thread::sleep(Duration::from_millis(20));
        }
    }
}

/// Checks the family end to end against the daemon.
///
/// A draft with text staged from the memberless edition through `stage`, a
/// citation of the person's in a notes draft on those words, a published
/// set the edition is read with: `publication.open` answers the panel — the
/// notes row OFF with its one link, the counts at the default, `windows`
/// empty, `read_with` naming the set, the price under its caps, every
/// member declared; `publication.count` with the row ON
/// counts ⟨l⟩ one up, pure local; `publication.confirm` is acknowledged —
/// the member `E.1`, `via: answer`, `claim: false` — with the event's `sent`
/// then `acknowledged`, the panel gone, and the feed's publish row naming
/// the member, the draft and the notes; a second `open` finds no window and
/// its `confirm` is `inert: unchanged`; `cancel` says `cancelled` once and
/// answers `{}` twice; a `publish` frame through `op` is `publish_is_a_call`;
/// the node stopped, `confirm` and a `make_link` are refused `stopped`
/// before anything is composed or dialed; the mint form with `claim` mints
/// the edition, its first member and `claim: true`; a second claim into that
/// edition is `claim_refused` naming it, the board's position unmoved —
/// crossing as answered, nothing re-sent.
#[test]
fn the_family_publishes_a_drafts_links_and_answers_as_data() {
    let dir = TempDir::new().unwrap();
    let sd = spawn(&dir.path().join("board"), true);
    let g = ground(&dir, &sd);
    let edition = g.addr(json!({"op": "create_new_document", "account": "1.0.1", "published": true}));
    let draft = g.staged(&edition, "the quick brown fox");
    let notes = g.draft("notes here");
    let set = g.addr(json!({"op": "create_new_document", "account": "1.0.1", "published": true}));
    let citation = "1.1.0.1.0.1.0.3.13";
    // The notes' citation on the draft's words 5..9 ("quick"), the set read
    // with the edition.
    let link = g.addr(json!({"op": "make_link", "home": notes, "from": [{"source": draft, "span": {"start": "1.5", "width": "0.5"}}], "to": {"addrs": []}, "ty": {"addrs": [citation]}}));
    g.addr(json!({"op": "make_link", "home": set, "from": {"addrs": [edition]}, "to": {"addrs": [set]}, "ty": {"addrs": ["1.1.0.1.0.1.0.3.71"]}}));
    let inputs = json!({"session": g.session, "draft": draft, "doc": edition, "notes": [notes], "readable_drafts": [draft, notes], "published": [edition, set]});
    let panel = g.call("publication.open", inputs.clone()).unwrap_or_else(|r| panic!("{r}"));
    crate::shapes::assert_declared("PublicationPanel", &panel);
    for row in panel["rows"].as_array().unwrap() {
        crate::shapes::assert_declared("PublicationRow", row);
    }
    crate::shapes::assert_declared("Formatting", &panel["formatting"]);
    crate::shapes::assert_declared("Count", &panel["count"]);
    crate::shapes::assert_declared("Price", &panel["price"]);
    let rows = panel["rows"].as_array().unwrap();
    assert_eq!(rows.len(), 1, "the notes row alone — the draft's own set holds no link: {panel}");
    assert_eq!((rows[0]["home"].as_str(), rows[0]["kind"].as_str(), rows[0]["label"].as_str()), (Some(notes.as_str()), Some("notes"), Some("notes here")));
    assert_eq!(rows[0]["links"], json!([link]));
    assert_eq!(rows[0]["types"][0]["ty"], citation);
    assert_eq!((rows[0]["unchanged"].clone(), rows[0]["fold"].clone()), (json!([]), json!({"unchanged": 0, "changed": 1})), "the base is the bare document: nothing folds");
    assert_eq!((rows[0]["changed_types"].clone(), rows[0]["unchanged_types"].clone()), (rows[0]["types"].clone(), json!([])), "every link changed: the changed fold is the whole, the unchanged one empty: {panel}");
    assert_eq!(panel["p3_stands"], true, "a whole private row: {panel}");
    assert_eq!(panel["count"], json!({"l": 0, "n": 0, "r": 0, "e": 0, "claim": false, "read_with": [], "supersede": []}), "the counts at the default: every private row OFF, and no merge marker to claim from");
    assert_eq!(panel["windows"], json!([]), "no run windows an unpublished origin of the person's");
    assert_eq!(panel["read_with"], json!({set.clone(): true}), "the set the edition is read with");
    assert_eq!(panel["price"]["over"], json!([]), "under every cap: {}", panel["price"]);
    assert!(panel["price"]["bytes"].as_u64().unwrap() > 0 && panel.get("hold").is_none(), "{panel}");
    // The count with the notes ON: ⟨l⟩ up by one, nothing dialed.
    let dials = g.shell.log().entries().len();
    let counted = g.call("publication.count", json!({"session": g.session, "switches": {"on": [notes]}})).unwrap();
    assert_eq!(counted["count"], json!({"l": 1, "n": 0, "r": 0, "e": 0, "claim": false, "read_with": [], "supersede": []}), "{counted}");
    assert_eq!((counted["rows"][0]["fold"].clone(), counted["p3_stands"].clone()), (json!({"unchanged": 0, "changed": 1}), json!(true)), "the fold and P3's standing re-keyed by the count: {counted}");
    crate::shapes::assert_declared("Price", &counted["price"]);
    assert!(counted["price"]["bytes"].as_u64().unwrap() > panel["price"]["bytes"].as_u64().unwrap(), "the price moves with the switches: {counted}");
    assert_eq!(g.shell.log().entries().len(), dials + 1, "the count is pure local: its own call logged and no dial");
    let bad_home = g.call("publication.count", json!({"session": g.session, "switches": {"on": [edition]}})).unwrap_err();
    assert_eq!((bad_home.name(), bad_home.to_value()["what"].as_str()), ("malformed_args", Some("switches.on")), "a home no private row holds");
    let bad_answer = g.call("publication.count", json!({"session": g.session, "answers": {"0": "drop"}})).unwrap_err();
    assert_eq!((bad_answer.name(), bad_answer.to_value()["what"].as_str()), ("malformed_args", Some("answers")), "a key no window part holds");
    // The confirm: acknowledged, the events, the feed row.
    let before = g.position();
    let acked = g.call("publication.confirm", json!({"session": g.session, "switches": {"on": [notes]}})).unwrap_or_else(|r| panic!("{r}"));
    crate::shapes::assert_declared("Acknowledged", &acked);
    let member = format!("{edition}.1");
    assert_eq!((acked["outcome"].as_str(), acked["member"].as_str(), acked["via"].as_str(), acked["claim"].as_bool(), acked["edition"].is_null()), (Some("acknowledged"), Some(member.as_str()), Some("answer"), Some(false), true), "{acked}");
    let at = acked["at"].as_u64().unwrap();
    assert!(at > before);
    assert_eq!(g.states_once(2), ["sent", "acknowledged"], "the event at the send and at the outcome");
    let events: Vec<Event> = g.seen.lock().unwrap().iter().filter(|e| e.name == EventName::Publication).cloned().collect();
    assert_events_declared(&events);
    assert_eq!((events[1].data["member"].as_str(), events[1].data["at"].as_u64(), events[1].data["draft"].as_str()), (Some(member.as_str()), Some(at), Some(draft.as_str())), "{:?}", events[1]);
    let entry = g.shell.sessions.get(&g.session).unwrap();
    let rows = changes_under(&entry.board, &entry.token, &edition, at - 1);
    let row = rows.iter().find(|r| r["at"] == at && r["op"] == "publish").unwrap_or_else(|| panic!("the publish row at {at}: {rows:?}"));
    let docs: Vec<&str> = row["docs"].as_array().unwrap().iter().filter_map(Value::as_str).collect();
    assert!(docs[0] == member && docs.contains(&draft.as_str()) && docs.contains(&notes.as_str()), "the row names the member, the draft and the notes: {docs:?}");
    let read = g.call("op", json!({"guest": true, "board": g.board, "frame": skep_client::board::frames::retrieve_v(&member, 1, 19)})).unwrap();
    assert_eq!(read["items"][0]["content"], "the quick brown fox");
    // The panel is gone with the acknowledgment; a second open finds the
    // draft re-windowed onto the member, no window, nothing to publish.
    assert_eq!(g.call("publication.count", json!({"session": g.session})).unwrap_err().name(), "no_panel", "the ceremony ended with the acknowledgment");
    let again = g.call("publication.open", inputs.clone()).unwrap_or_else(|r| panic!("{r}"));
    assert_eq!((again["windows"].clone(), again.get("hold")), (json!([]), None), "{again}");
    let inert = g.call("publication.confirm", json!({"session": g.session})).unwrap_or_else(|r| panic!("{r}"));
    crate::shapes::assert_declared("PublicationRefused", &inert);
    assert_eq!(inert, json!({"outcome": "refused", "arm": "inert", "inert": "unchanged"}));
    assert_eq!(g.states_once(3).last().map(String::as_str), Some("refused"));
    // The cancel, twice.
    assert_eq!(g.call("publication.cancel", json!({"session": g.session})).unwrap(), json!({}));
    assert_eq!(g.states_once(4).last().map(String::as_str), Some("cancelled"));
    let said = g.states().len();
    assert_eq!(g.call("publication.cancel", json!({"session": g.session})).unwrap(), json!({}));
    assert_eq!(g.states().len(), said, "the second cancel says nothing");
    assert_eq!(g.call("publication.confirm", json!({"session": g.session})).unwrap_err().name(), "no_panel");
    // A publish frame through op.
    let through_op = g.call("op", json!({"session": g.session, "frame": {"op": "publish", "doc": edition, "draft": draft, "runs": []}})).unwrap_err();
    assert_eq!(through_op.name(), "publish_is_a_call", "{through_op}");
    // The node stopped: the confirm refused before it composes, a make_link
    // before any dial.
    let fresh = g.staged(&member, "more words");
    g.call("publication.open", json!({"session": g.session, "draft": fresh, "doc": edition, "readable_drafts": [fresh], "published": [edition, set]})).unwrap_or_else(|r| panic!("{r}"));
    g.shell.set_node_state(NodeState::Stopped);
    let dials = g.shell.log().entries().iter().filter(|e| e["kind"] == "dial").count();
    let stopped = g.call("publication.confirm", json!({"session": g.session})).unwrap_err();
    assert_eq!((stopped.name(), stopped.to_value()["op"].as_str()), ("stopped", Some("publish")), "{stopped}");
    let link_stopped = g.call("op", json!({"session": g.session, "frame": {"op": "make_link", "home": notes, "from": {"addrs": [notes]}, "to": {"addrs": []}, "ty": {"addrs": [citation]}}})).unwrap_err();
    assert_eq!((link_stopped.name(), link_stopped.to_value()["op"].as_str()), ("stopped", Some("make_link")), "{link_stopped}");
    assert_eq!(g.shell.log().entries().iter().filter(|e| e["kind"] == "dial").count(), dials, "nothing dialed under the stop");
    assert_eq!(g.states_once(5).last().map(String::as_str), Some("refused"), "the event names the refusal's arm");
    g.shell.set_node_state(NodeState::Running);
    g.call("publication.cancel", json!({"session": g.session})).unwrap();
    // The mint form: the edition minted with its first member and the claim.
    let free = g.draft("a free-standing draft");
    let minted_panel = g.call("publication.open", json!({"session": g.session, "draft": free, "mint": "1.0.1", "claim": true, "readable_drafts": [free], "published": [edition, set]})).unwrap_or_else(|r| panic!("{r}"));
    assert_eq!(minted_panel["count"]["claim"], true);
    let minted = g.call("publication.confirm", json!({"session": g.session})).unwrap_or_else(|r| panic!("{r}"));
    let new_edition = minted["edition"].as_str().expect("the edition minted").to_string();
    assert_eq!((minted["outcome"].as_str(), minted["member"].as_str(), minted["claim"].as_bool()), (Some("acknowledged"), Some(format!("{new_edition}.1").as_str()), Some(true)), "{minted}");
    // A second claim into that edition: refused by the board, crossing as
    // answered, nothing re-sent, the board unmoved.
    let another = g.staged(&format!("{new_edition}.1"), "another draft");
    g.call("publication.open", json!({"session": g.session, "draft": another, "doc": new_edition, "claim": true, "readable_drafts": [another], "published": [edition, set, new_edition]})).unwrap_or_else(|r| panic!("{r}"));
    let before = g.position();
    let refused = g.call("publication.confirm", json!({"session": g.session})).unwrap_or_else(|r| panic!("{r}"));
    assert_eq!(refused, json!({"outcome": "refused", "arm": "claim_refused", "edition": new_edition}), "{refused}");
    assert_eq!(g.position(), before, "a refusal commits nothing, and nothing is re-sent");
    let states = g.states_once(10);
    assert!(states.ends_with(&["sent".to_string(), "refused".to_string()]), "{states:?}");
    g.shell.shutdown();
    sd.shutdown();
}

/// Checks that the open and the count answer THE FOLD (E4 1.8) and whether
/// P3 stands (E4 1.4) against the board.
///
/// A note on the draft's words, made before version 1 and left off at it:
/// at the next open its row's one link is unchanged since the base — read
/// through the draft's record onto the words version 1 arranges — so
/// `unchanged` names it, `fold` counts one and none, and with nothing else
/// to decide P3 does not stand; the count answers the same, nothing dialed.
/// A note made since joins the row changed, of a type of its own, and P3
/// stands: the row's two folds by type (E4 1.3) answer each side alone, at
/// the open and at the count.
#[test]
fn the_open_and_the_count_answer_the_fold_and_whether_p3_stands() {
    let dir = TempDir::new().unwrap();
    let sd = spawn(&dir.path().join("board"), true);
    let g = ground(&dir, &sd);
    let edition = g.addr(json!({"op": "create_new_document", "account": "1.0.1", "published": true}));
    let draft = g.staged(&edition, "the quick brown fox");
    let notes = g.draft("notes here");
    let citation = "1.1.0.1.0.1.0.3.13";
    let link = g.addr(json!({"op": "make_link", "home": notes, "from": [{"source": draft, "span": {"start": "1.5", "width": "0.5"}}], "to": {"addrs": []}, "ty": {"addrs": [citation]}}));
    let inputs = json!({"session": g.session, "draft": draft, "doc": edition, "notes": [notes], "readable_drafts": [draft, notes], "published": [edition]});
    g.call("publication.open", inputs.clone()).unwrap_or_else(|r| panic!("{r}"));
    let acked = g.call("publication.confirm", json!({"session": g.session})).unwrap_or_else(|r| panic!("{r}"));
    assert_eq!(acked["outcome"].as_str(), Some("acknowledged"), "version 1, the notes left off: {acked}");
    let panel = g.call("publication.open", inputs.clone()).unwrap_or_else(|r| panic!("{r}"));
    crate::shapes::assert_declared("PublicationPanel", &panel);
    let rows = panel["rows"].as_array().unwrap();
    assert_eq!(rows.len(), 1, "{panel}");
    crate::shapes::assert_declared("PublicationRow", &rows[0]);
    crate::shapes::assert_declared("RowFold", &rows[0]["fold"]);
    assert_eq!((rows[0]["links"].clone(), rows[0]["unchanged"].clone(), rows[0]["fold"].clone()), (json!([link]), json!([link]), json!({"unchanged": 1, "changed": 0})), "the note stayed private when version 1 was published: {panel}");
    let citations = json!([{"ty": citation, "n": 1, "far": []}]);
    crate::shapes::assert_declared("TypeFold", &rows[0]["unchanged_types"][0]);
    assert_eq!((rows[0]["changed_types"].clone(), rows[0]["unchanged_types"].clone()), (json!([]), citations.clone()), "a compact row: no changed link to fold: {panel}");
    assert_eq!(panel["p3_stands"], false, "a compact row alone: nothing to decide");
    let dials = g.shell.log().entries().len();
    let counted = g.call("publication.count", json!({"session": g.session})).unwrap_or_else(|r| panic!("{r}"));
    assert_eq!((counted["rows"][0]["fold"].clone(), counted["p3_stands"].clone()), (json!({"unchanged": 1, "changed": 0}), json!(false)), "{counted}");
    assert_eq!((counted["rows"][0]["changed_types"].clone(), counted["rows"][0]["unchanged_types"].clone()), (json!([]), citations.clone()), "{counted}");
    assert_eq!(g.shell.log().entries().len(), dials + 1, "the count is pure local");
    g.call("publication.cancel", json!({"session": g.session})).unwrap();
    // A note made since version 1, on the words it holds, of its own type.
    let mark = "1.1.0.1.0.1.0.3.23.4";
    let since = g.addr(json!({"op": "make_link", "home": notes, "from": [{"source": draft, "span": {"start": "1.1", "width": "0.3"}}], "to": {"addrs": []}, "ty": {"addrs": [mark]}}));
    let panel = g.call("publication.open", inputs).unwrap_or_else(|r| panic!("{r}"));
    let row = &panel["rows"][0];
    let links: Vec<&str> = row["links"].as_array().unwrap().iter().filter_map(Value::as_str).collect();
    assert!(links.contains(&link.as_str()) && links.contains(&since.as_str()), "{panel}");
    assert_eq!((row["unchanged"].clone(), row["fold"].clone()), (json!([link]), json!({"unchanged": 1, "changed": 1})), "the new note is news: {panel}");
    let marks = json!([{"ty": mark, "n": 1, "far": []}]);
    assert_eq!((row["changed_types"].clone(), row["unchanged_types"].clone()), (marks.clone(), citations.clone()), "a row folded by change: each side's types alone: {panel}");
    assert_eq!(row["types"].as_array().unwrap().len(), 2, "the whole row's fold keeps both: {panel}");
    assert_eq!(panel["p3_stands"], true, "a row folded by change");
    let counted = g.call("publication.count", json!({"session": g.session})).unwrap_or_else(|r| panic!("{r}"));
    assert_eq!((counted["rows"][0]["changed_types"].clone(), counted["rows"][0]["unchanged_types"].clone()), (marks, citations), "the count answers the two folds as the open does: {counted}");
    g.shell.shutdown();
    sd.shutdown();
}

/// Checks that the open and the count answer the document's own links.
///
/// The link-sets design §5.2; E4 1.4. Version 1 published, a word typed in
/// the draft and a link on it homed in that member: the link is no row's, so
/// the open answers no row, one in `edition_links` and P3 standing on it
/// alone, and the count answers the same, nothing dialed.
#[test]
fn the_open_and_the_count_answer_the_documents_own_links() {
    let dir = TempDir::new().unwrap();
    let sd = spawn(&dir.path().join("board"), true);
    let g = ground(&dir, &sd);
    let edition = g.addr(json!({"op": "create_new_document", "account": "1.0.1", "published": true}));
    let draft = g.staged(&edition, "the quick brown fox");
    let inputs = json!({"session": g.session, "draft": draft, "doc": edition, "readable_drafts": [draft], "published": [edition]});
    let first = g.call("publication.open", inputs.clone()).unwrap_or_else(|r| panic!("{r}"));
    assert_eq!((first["edition_links"].clone(), first["p3_stands"].clone()), (json!(0), json!(false)), "no link of the document's on the first version's words: {first}");
    let acked = g.call("publication.confirm", json!({"session": g.session})).unwrap_or_else(|r| panic!("{r}"));
    assert_eq!(acked["outcome"].as_str(), Some("acknowledged"), "version 1: {acked}");
    let member = format!("{edition}.1");
    g.op(json!({"op": "insert", "doc": draft, "at": {"subspace": "1", "ordinal": "20"}, "values": [" jumps"], "as_of": g.position()}));
    g.addr(json!({"op": "make_link", "home": member, "from": [{"source": draft, "span": {"start": "1.20", "width": "0.6"}}], "to": {"addrs": []}, "ty": {"addrs": ["1.1.0.1.0.1.0.3.13"]}}));
    let panel = g.call("publication.open", inputs).unwrap_or_else(|r| panic!("{r}"));
    crate::shapes::assert_declared("PublicationPanel", &panel);
    assert_eq!((panel["rows"].clone(), panel["edition_links"].clone(), panel["p3_stands"].clone()), (json!([]), json!(1), json!(true)), "its own line alone: {panel}");
    let dials = g.shell.log().entries().len();
    let counted = g.call("publication.count", json!({"session": g.session})).unwrap_or_else(|r| panic!("{r}"));
    assert_eq!((counted["edition_links"].clone(), counted["p3_stands"].clone()), (json!(1), json!(true)), "{counted}");
    assert_eq!(g.shell.log().entries().len(), dials + 1, "the count is pure local");
    g.shell.shutdown();
    sd.shutdown();
}

/// Checks that a claimed draft's next version counts no own link.
///
/// The edition claim is homed in the edition with its `to` the draft whole,
/// so the region read over the words the next version re-inserts answers
/// it: read, it is no link on those words, the count is zero and P3 does
/// not stand.
#[test]
fn a_claimed_drafts_next_version_counts_no_own_link() {
    let dir = TempDir::new().unwrap();
    let sd = spawn(&dir.path().join("board"), true);
    let g = ground(&dir, &sd);
    let free = g.draft("a free-standing draft");
    let minting =
        g.call("publication.open", json!({"session": g.session, "draft": free, "mint": "1.0.1", "claim": true, "readable_drafts": [free], "published": []})).unwrap_or_else(|r| panic!("{r}"));
    assert_eq!(minting["edition_links"], 0, "no document stands yet: {minting}");
    let minted = g.call("publication.confirm", json!({"session": g.session})).unwrap_or_else(|r| panic!("{r}"));
    let edition = minted["edition"].as_str().unwrap_or_else(|| panic!("the edition minted: {minted}")).to_string();
    g.op(json!({"op": "insert", "doc": free, "at": {"subspace": "1", "ordinal": "22"}, "values": [" more"], "as_of": g.position()}));
    let region = g.op(skep_client::board::frames::find_links_v(&free, &[(22, 5)]));
    let homed_in_edition = region["addrs"].as_array().unwrap().iter().filter_map(Value::as_str).filter(|a| a.starts_with(&format!("{edition}.0.2."))).count();
    assert_eq!(homed_in_edition, 1, "the premise: the region read answers the edition claim through its whole-work end: {region}");
    let panel = g.call("publication.open", json!({"session": g.session, "draft": free, "doc": edition, "readable_drafts": [free], "published": [edition]})).unwrap_or_else(|r| panic!("{r}"));
    assert_eq!((panel["edition_links"].clone(), panel["p3_stands"].clone()), (json!(0), json!(false)), "the claim is no link on the new words: {panel}");
    g.shell.shutdown();
    sd.shutdown();
}

/// Checks the family's members are read in their form before the session
/// (the Nelson way, `client.md` §4b.1 item 60): `also` a list of addresses,
/// a repeat or the `draft` among them `malformed_args` naming `also`; in its
/// form it passes to the session, which is gone. A `base` is no member of
/// the row (the shell reads the draft's base itself, B3-S10): in any form,
/// at either form of the row, it is read by nothing and the call goes on to
/// the session.
#[test]
fn the_familys_members_are_read_in_their_form_before_the_session() {
    let dir = TempDir::new().unwrap();
    let (shell, _) = open_shell(&super::door::nowhere(), &dir.path().join("store"), SessionMode::Bare { principal: 1 });
    let what = |args: Value| {
        let refused = shell.call("publication.open", &args).unwrap_err();
        let v = refused.to_value();
        assert_eq!(refused.name(), "malformed_args", "{args}: {v}");
        v["what"].as_str().unwrap().to_string()
    };
    let base_args = json!({"session": "s-gone", "draft": "1.0.2.0.2", "doc": "1.0.2.0.1"});
    let with = |member: &str, value: Value| {
        let mut args = base_args.clone();
        args[member] = value;
        args
    };
    assert_eq!(what(with("also", json!("1.0.2.0.3"))), "also", "no list");
    assert_eq!(what(with("also", json!(["1.0.2.0.3", 7]))), "also", "no address");
    assert_eq!(what(with("also", json!(["1.0.2.0.3", "1.0.2.0.3"]))), "also", "a repeat");
    assert_eq!(what(with("also", json!(["1.0.2.0.2"]))), "also", "the draft itself");
    let in_form = with("also", json!(["1.0.2.0.3", "1.0.2.0.4"]));
    assert_eq!(shell.call("publication.open", &in_form).unwrap_err().name(), "session_ended", "{in_form}: in its form, the member passes to the session");
    for unread in [with("base", json!(7)), with("base", json!("1.0.2.0.9.1")), json!({"session": "s-gone", "draft": "1.0.2.0.2", "mint": "1.0.2", "base": "1.0.2.0.1.1"})] {
        assert_eq!(shell.call("publication.open", &unread).unwrap_err().name(), "session_ended", "{unread}: a `base` is read by nothing");
    }
}

/// Checks the family end to end against the daemon, and a draft's base read
/// on another device (the Nelson way, B3-S10; `client.md` §4b.1 items 60
/// and 61).
///
/// D, staged from the memberless edition through `stage`, publishes E.1 and
/// is re-windowed onto it, the board moving its base to E.1; D goes on with
/// six words of its own; A, an alternative staged from D — the board
/// recording D's base, E.1, as A's — holds D's whole arrangement by identity
/// and five words of its own. A's `publication.open` naming D among `also`
/// answers no window for D's words and `inherited` counting D's one passage,
/// `standing: at_head` and D in `left_behind` — the family it leaves behind
/// (skep #744) — every member declared; its `confirm` is acknowledged E.2 —
/// the member reads A's whole text as E's own words — with one record homed
/// in D for its six words and one in A for its five, each `to` the member's
/// fresh identity, the feed row's `docs` `[E.2, A, D]`, and D RE-WINDOWED in
/// the same write at its own place, which the library read off D's image
/// (skep #739): its six words the member's identity, no private copy left.
/// Then a SECOND
/// DEVICE's shell — a fresh shell over the same board and store, holding no
/// index and no panel of the first's — opens D, a draft BEHIND the head, the
/// page sending `base: E.2`, which nothing reads: the shell reads D's base
/// off the board's record, E.1 — A's publication moved A's base, never D's,
/// re-windowed or not — tells it `standing: behind`, and the `confirm` lands
/// the DAUGHTER E.1.1 under it, holding the words D now windows by
/// reference, never a trunk member that drops A's words. A draft the board
/// records no base for is refused `base_unrecorded` naming it, the edition
/// and the reason, `no_record`, at the document form, and opens at the mint
/// form, which has no chain and no standing.
#[test]
fn the_family_publishes_another_drafts_words_as_the_documents_own_and_a_draft_behind_the_head_lands_a_daughter_on_any_device() {
    use skep_client::board::frames::{find_links_four, read_link, retrieve_v, unit_span, Slot, T_CORRESPONDENCE};
    let dir = TempDir::new().unwrap();
    let sd = spawn(&dir.path().join("board"), true);
    let g = ground(&dir, &sd);
    let edition = g.addr(json!({"op": "create_new_document", "account": "1.0.1", "published": true}));
    // D, staged from the bare document, publishes E.1.
    let d = g.staged(&edition, "the quick brown fox");
    g.call("publication.open", json!({"session": g.session, "draft": d, "doc": edition, "readable_drafts": [d], "published": [edition]})).unwrap_or_else(|r| panic!("{r}"));
    let first = g.call("publication.confirm", json!({"session": g.session})).unwrap_or_else(|r| panic!("{r}"));
    let e1 = format!("{edition}.1");
    assert_eq!(first["member"].as_str(), Some(e1.as_str()), "{first}");
    // D goes on; A, staged from D, holds D's whole arrangement by identity,
    // the board recording the base D stood on as A's, and adds its own.
    g.op(json!({"op": "insert", "doc": d, "at": {"subspace": "1", "ordinal": "20"}, "values": [" again"], "as_of": g.position()}));
    let staged = g.op(skep_client::board::frames::stage(&d, None));
    let a_draft = staged["addr"].as_str().expect("an ack_addr").to_string();
    g.op(json!({"op": "insert", "doc": a_draft, "at": {"subspace": "1", "ordinal": "26"}, "values": [" more"], "as_of": staged["at"]}));
    // A's panel naming D among `also`.
    let panel = g
        .call("publication.open", json!({"session": g.session, "draft": a_draft, "doc": edition, "also": [d], "readable_drafts": [a_draft, d], "published": [edition]}))
        .unwrap_or_else(|r| panic!("{r}"));
    crate::shapes::assert_declared("PublicationPanel", &panel);
    assert_eq!(panel["windows"], json!([]), "D's words are re-minted, not windowed: {panel}");
    assert_eq!(panel["inherited"], json!([{"draft": d, "passages": 1}]), "{panel}");
    assert_eq!((&panel["standing"], &panel["left_behind"]), (&json!("at_head"), &json!([d])), "A's base E.1 heads the chain, and D stands behind A's version: {panel}");
    crate::shapes::assert_declared("Inherited", &panel["inherited"][0]);
    assert_eq!(panel["price"]["over"], json!([]), "{}", panel["price"]);
    let acked = g.call("publication.confirm", json!({"session": g.session})).unwrap_or_else(|r| panic!("{r}"));
    let e2 = format!("{edition}.2");
    assert_eq!((acked["outcome"].as_str(), acked["member"].as_str(), acked["via"].as_str()), (Some("acknowledged"), Some(e2.as_str()), Some("answer")), "{acked}");
    let at = acked["at"].as_u64().unwrap();
    let read = g.call("op", json!({"guest": true, "board": g.board, "frame": retrieve_v(&e2, 1, 30)})).unwrap();
    assert_eq!(read["items"][0]["content"], "the quick brown fox again more", "A's whole text, as E's own words");
    // The records, one in each draft.
    let unit = |addr: &str| unit_span(addr).as_array().cloned().unwrap_or_default();
    let records = |home: &str| -> Vec<Value> {
        let hits = g.op(find_links_four(Slot::Spans(&unit(home)), Slot::Any, Slot::Any, Slot::Spans(&unit(T_CORRESPONDENCE))));
        hits["addrs"].as_array().unwrap().iter().map(|a| g.op(read_link(a.as_str().unwrap()))["link"]["slots"].clone()).collect()
    };
    let in_d = records(&d);
    assert_eq!(in_d.len(), 2, "D's record from E.1, and the one A's shot homed in D: {in_d:?}");
    assert!(in_d.iter().any(|slots| slots[0][0]["start"] == format!("{d}.0.1.20") && slots[0][0]["width"] == "0.0.0.0.0.0.0.6" && slots[1][0]["start"] == format!("{edition}.0.1.20")), "D's six words `to` the member's fresh identity: {in_d:?}");
    let in_a = records(&a_draft);
    assert_eq!(in_a.len(), 1, "{in_a:?}");
    assert!(in_a[0][0][0]["start"] == format!("{a_draft}.0.1.1") && in_a[0][0][0]["width"] == "0.0.0.0.0.0.0.5" && in_a[0][1][0]["start"] == format!("{edition}.0.1.26"), "A's five words `to` the member's fresh identity: {in_a:?}");
    let entry = g.shell.sessions.get(&g.session).unwrap();
    let rows = changes_under(&entry.board, &entry.token, &edition, at - 1);
    let row = rows.iter().find(|r| r["at"] == at && r["op"] == "publish").unwrap_or_else(|| panic!("the publish row at {at}: {rows:?}"));
    assert_eq!(row["docs"], json!([e2, a_draft, d]), "the member, the rendering draft, then the draft `also` named: {row}");
    // D, named `also`, re-windowed in the same write at its own place: its
    // six words the member's identity.
    let d_image = g.op(skep_client::board::frames::image(&d, 20, 6));
    let d_runs: Vec<(String, String)> = d_image["runs"].as_array().expect("runs").iter().map(|r| (r["i_start"].as_str().unwrap().to_string(), r["width"].as_str().unwrap().to_string())).collect();
    assert_eq!(d_runs, vec![(format!("{edition}.0.1.20"), "6".to_string())], "D re-windowed onto E.2's words, no private copy left: {d_image}");
    // A SECOND DEVICE: a fresh shell over the same board, on a data
    // directory of its own holding the same key (`second_device`), D behind
    // the head, the page's `base` read by nothing — the daughter landing.
    g.shell.shutdown();
    let g = second_device(&dir, &sd);
    let behind = g.call("publication.open", json!({"session": g.session, "draft": d, "doc": edition, "base": e2, "readable_drafts": [d], "published": [edition]})).unwrap_or_else(|r| panic!("{r}"));
    assert_eq!((behind["windows"].clone(), behind["inherited"].clone()), (json!([]), json!([])), "{behind}");
    assert_eq!((&behind["standing"], &behind["left_behind"]), (&json!("behind"), &json!([])), "told, never refused; a daughter leaves no draft behind: {behind}");
    let daughter = g.call("publication.confirm", json!({"session": g.session})).unwrap_or_else(|r| panic!("{r}"));
    assert_eq!(
        (daughter["outcome"].as_str(), daughter["member"].as_str(), daughter["via"].as_str()),
        (Some("acknowledged"), Some(format!("{edition}.1.1").as_str()), Some("answer")),
        "the daughter under D's own base, the board's record: {daughter}"
    );
    let read = g.call("op", json!({"guest": true, "board": g.board, "frame": retrieve_v(&format!("{edition}.1.1"), 1, 25)})).unwrap();
    assert_eq!(read["items"][0]["content"], "the quick brown fox again");
    // A draft the board records no base for: refused by name at the
    // document form, never given the head; the mint form opens.
    let free = g.draft("unrecorded words");
    let unrecorded = g.call("publication.open", json!({"session": g.session, "draft": free, "doc": edition, "readable_drafts": [free], "published": [edition]})).unwrap_err();
    let v = unrecorded.to_value();
    assert_eq!(
        (unrecorded.name(), v["kind"].as_str(), v["draft"].as_str(), v["doc"].as_str(), v["reason"].as_str()),
        ("base_unrecorded", Some("shell"), Some(free.as_str()), Some(edition.as_str()), Some("no_record")),
        "{v}"
    );
    let minted = g
        .call("publication.open", json!({"session": g.session, "draft": free, "mint": "1.0.1", "readable_drafts": [free], "published": [edition]}))
        .unwrap_or_else(|r| panic!("the mint form has no chain: {r}"));
    crate::shapes::assert_declared("PublicationPanel", &minted);
    assert_eq!((minted.get("standing"), &minted["left_behind"]), (None, &json!([])), "no chain, no standing: {minted}");
    assert_eq!(g.call("publication.cancel", json!({"session": g.session})).unwrap(), json!({}));
    g.shell.shutdown();
    sd.shutdown();
}

/// Checks a family confirm over a draft `also` names that moved since the
/// panel, against the daemon (skep #739).
///
/// A's panel names D among `also`; D's six own words are swapped about
/// after the panel's reads (a raw `rearrange` under the session). A's
/// `confirm` re-reads D's image — a run D no longer arranges whole takes
/// no place in D's list, and the list, all `null`, is not sent — re-states
/// nothing (A's placements stand; D's move is none of the rendering
/// draft's) and is acknowledged E.2: A re-windowed whole, D LEFT AS IT
/// STANDS — its words its own, swapped, with the record A's shot homed in
/// it — to be healed at its own next publication. The board's
/// `kept_place_moved` naming D meets a move between this re-read and the
/// commit, a window no test holds open: its answer's shape is
/// `the_refusals_that_name_a_draft_carry_it`'s.
#[test]
fn a_family_confirm_over_an_also_draft_moved_since_the_panel_sends_no_place_for_it_and_leaves_it_as_it_stands() {
    use skep_client::board::frames::image;
    let dir = TempDir::new().unwrap();
    let sd = spawn(&dir.path().join("board"), true);
    let g = ground(&dir, &sd);
    let edition = g.addr(json!({"op": "create_new_document", "account": "1.0.1", "published": true}));
    let d = g.staged(&edition, "the quick brown fox");
    g.call("publication.open", json!({"session": g.session, "draft": d, "doc": edition, "readable_drafts": [d], "published": [edition]})).unwrap_or_else(|r| panic!("{r}"));
    g.call("publication.confirm", json!({"session": g.session})).unwrap_or_else(|r| panic!("{r}"));
    g.op(json!({"op": "insert", "doc": d, "at": {"subspace": "1", "ordinal": "20"}, "values": [" again"], "as_of": g.position()}));
    let staged = g.op(skep_client::board::frames::stage(&d, None));
    let a_draft = staged["addr"].as_str().expect("an ack_addr").to_string();
    g.op(json!({"op": "insert", "doc": a_draft, "at": {"subspace": "1", "ordinal": "26"}, "values": [" more"], "as_of": staged["at"]}));
    g.call("publication.open", json!({"session": g.session, "draft": a_draft, "doc": edition, "also": [d], "readable_drafts": [a_draft, d], "published": [edition]})).unwrap_or_else(|r| panic!("{r}"));
    // D's six own words swapped about after the panel: the first three and
    // the last three.
    g.op(json!({"op": "rearrange", "doc": d, "cuts": [{"subspace": "1", "ordinal": "20"}, {"subspace": "1", "ordinal": "23"}, {"subspace": "1", "ordinal": "26"}], "as_of": g.position()}));
    let acked = g.call("publication.confirm", json!({"session": g.session})).unwrap_or_else(|r| panic!("{r}"));
    let e2 = format!("{edition}.2");
    assert_eq!((acked["outcome"].as_str(), acked["member"].as_str(), acked["via"].as_str()), (Some("acknowledged"), Some(e2.as_str()), Some("answer")), "the move absorbed at the re-read, nothing re-stated: {acked}");
    let runs_of = |frame: Value| -> Vec<(String, String)> { g.op(frame)["runs"].as_array().expect("runs").iter().map(|r| (r["i_start"].as_str().unwrap().to_string(), r["width"].as_str().unwrap().to_string())).collect() };
    assert_eq!(runs_of(image(&a_draft, 1, 30)), vec![(format!("{edition}.0.1.1"), "30".to_string())], "A re-windowed whole onto E.2, D's run among its own");
    assert_eq!(runs_of(image(&d, 20, 6)), vec![(format!("{d}.0.1.23"), "3".to_string()), (format!("{d}.0.1.20"), "3".to_string())], "D left as it stands: its own words, swapped, healed at its own next publication");
    let entry = g.shell.sessions.get(&g.session).unwrap();
    let at = acked["at"].as_u64().unwrap();
    let rows = changes_under(&entry.board, &entry.token, &edition, at - 1);
    let row = rows.iter().find(|r| r["at"] == at && r["op"] == "publish").unwrap_or_else(|| panic!("the publish row at {at}: {rows:?}"));
    assert_eq!(row["docs"], json!([e2, a_draft, d]), "D named for the record homed in it: {row}");
    g.shell.shutdown();
    sd.shutdown();
}

/// Checks the answers at a window's parts against the daemon (B3-S11 P2
/// (i)).
///
/// `D`, staged from the memberless edition, windows `O`, a draft of the
/// person's, and a note in the notes lies on `O`'s words; `O` is then
/// published at the mint form, so a record names those words as the new
/// edition's. The open answers the window as one part the record names,
/// admitting the counterpart and `drop`, the note counting toward nothing
/// while the part awaits its answer; `keep_private` there is refused
/// `malformed_args` naming `answers`; `count`, the call per answer, re-keys
/// the panel with no dial — the counterpart puts the note in the notes' row
/// and counts it, leaving the words out takes it back; and the confirm with
/// the counterpart is acknowledged, the note's entry on the edition's words.
#[test]
fn a_windows_parts_take_their_own_answers_and_each_answer_re_keys_the_panel() {
    let dir = TempDir::new().unwrap();
    let sd = spawn(&dir.path().join("board"), true);
    let g = ground(&dir, &sd);
    let edition = g.addr(json!({"op": "create_new_document", "account": "1.0.1", "published": true}));
    let draft = g.staged(&edition, "the quick brown fox");
    let origin = g.draft("quote");
    let notes = g.draft("notes here");
    let citation = "1.1.0.1.0.1.0.3.13";
    g.op(json!({"op": "copy", "doc": draft, "at": {"subspace": "1", "ordinal": "20"}, "specs": [{"source": origin, "span": {"start": "1.1", "width": "0.5"}}], "as_of": g.position()}));
    let note = g.addr(json!({"op": "make_link", "home": notes, "from": [{"source": origin, "span": {"start": "1.2", "width": "0.2"}}], "to": {"addrs": []}, "ty": {"addrs": [citation]}}));
    // O published at the mint form: its words a new edition's, its record
    // in O, the draft still windowing O's own.
    g.call("publication.open", json!({"session": g.session, "draft": origin, "mint": "1.0.1", "readable_drafts": [origin], "published": [edition]})).unwrap_or_else(|r| panic!("{r}"));
    let minted = g.call("publication.confirm", json!({"session": g.session})).unwrap_or_else(|r| panic!("{r}"));
    let published = minted["edition"].as_str().unwrap_or_else(|| panic!("an edition minted: {minted}")).to_string();
    let inputs = json!({"session": g.session, "draft": draft, "doc": edition, "notes": [notes], "readable_drafts": [draft, notes, origin], "published": [edition, published]});
    let panel = g.call("publication.open", inputs).unwrap_or_else(|r| panic!("{r}"));
    crate::shapes::assert_declared("PublicationPanel", &panel);
    let windows = panel["windows"].as_array().unwrap();
    assert_eq!(windows.len(), 1, "{panel}");
    crate::shapes::assert_declared("Window", &windows[0]);
    let part = &windows[0]["parts"][0];
    crate::shapes::assert_declared("Part", part);
    assert_eq!((windows[0]["run"].as_u64(), windows[0]["parts"].as_array().map(Vec::len), part["admits"].clone()), (Some(1), Some(1), json!(["counterpart", "drop"])), "one part the record names: {panel}");
    assert_eq!(part["to"]["chain"], format!("{published}.0.1"), "its counterpart the edition's words");
    assert!(panel["rows"].as_array().unwrap().iter().all(|row| row["home"] != notes), "the note counts toward nothing while the part awaits its answer: {panel}");
    let refused = g.call("publication.count", json!({"session": g.session, "answers": {"1.0": "keep_private"}})).unwrap_err();
    assert_eq!((refused.name(), refused.to_value()["what"].as_str()), ("malformed_args", Some("answers")), "no placeholder over published words");
    let dials = g.shell.log().entries().iter().filter(|e| e["kind"] == "dial").count();
    let taken = g.call("publication.count", json!({"session": g.session, "switches": {"on": [notes]}, "answers": {"1.0": "counterpart"}})).unwrap_or_else(|r| panic!("{r}"));
    let notes_row = taken["rows"].as_array().unwrap().iter().find(|row| row["home"] == notes).unwrap_or_else(|| panic!("the notes' row: {taken}")).clone();
    assert_eq!((notes_row["links"].clone(), taken["count"]["l"].as_u64()), (json!([note]), Some(1)), "the counterpart offers the note: {taken}");
    crate::shapes::assert_declared("Formatting", &taken["formatting"]);
    crate::shapes::assert_declared("PartCounts", &taken["parts"][0]);
    assert_eq!(taken["parts"], json!([{"run": 1, "part": 0, "marks": 0, "links": 1, "kept_marks": 0}]), "what the counterpart brings: the note, offered next");
    let left = g.call("publication.count", json!({"session": g.session, "answers": {"1.0": "drop"}})).unwrap_or_else(|r| panic!("{r}"));
    assert!(left["rows"].as_array().unwrap().iter().all(|row| row["home"] != notes) && left["count"]["l"] == 0, "the words left out take the note's row with them: {left}");
    let stale = g.call("publication.count", json!({"session": g.session, "switches": {"on": [notes]}, "answers": {"1.0": "drop"}})).unwrap_err();
    assert_eq!((stale.name(), stale.to_value()["what"].as_str()), ("malformed_args", Some("switches.on")), "a switch names a row the panel holds as answered");
    assert_eq!(g.shell.log().entries().iter().filter(|e| e["kind"] == "dial").count(), dials, "each answer re-keys with no dial");
    let acked = g.call("publication.confirm", json!({"session": g.session, "switches": {"on": [notes]}, "answers": {"1.0": "counterpart"}})).unwrap_or_else(|r| panic!("{r}"));
    crate::shapes::assert_declared("Acknowledged", &acked);
    assert_eq!(acked["member"], format!("{edition}.1"), "{acked}");
    g.shell.shutdown();
    sd.shutdown();
}

/// Checks the lineage re-statement's face, as `confirm` composes it and as
/// the declaration spells it (B3-S11 P4): `restated` with `left_out`
/// naming the entry the board refused by its lineage, its original and the
/// cause, and `race` where a change since the request's reads explains it —
/// never the own-bug class — and a window part named since the panel among
/// the re-statement's `parts`.
#[test]
fn the_lineage_re_statement_names_the_entry_its_original_and_cause() {
    use skep_client::publication::{LineageCause, PartKey, RaceKey, Restatement};
    let original = skep_client::address::parse_address("1.0.1.0.6.0.2.1").expect("an address");
    let record = skep_client::address::parse_address("1.0.1.0.7.0.2.1").expect("an address");
    let race = RaceKey { at: 999, key: Some("bare".into()), signed: false };
    let restatement = Restatement { parts: vec![(PartKey { run: 2, part: 0 }, Some(record))], ..Restatement::default() };
    let answer = super::super::publication::restated_json(&restatement, Some(&race), Some((3, &original, LineageCause::Superseded)));
    crate::shapes::assert_declared("Restated", &answer);
    assert_eq!(answer["left_out"], json!([{"entry": 3, "original": "1.0.1.0.6.0.2.1", "cause": "superseded"}]));
    assert_eq!(answer["parts"], json!([{"run": 2, "part": 0, "record": "1.0.1.0.7.0.2.1"}]));
    assert_eq!((answer["outcome"].as_str(), answer["race"]["at"].as_u64()), (Some("restated"), Some(999)));
    let quiet = super::super::publication::restated_json(&Restatement::default(), None, Some((0, &original, LineageCause::Retracted)));
    crate::shapes::assert_declared("Restated", &quiet);
    assert!(quiet.get("race").is_none() && quiet.get("parts").is_none() && quiet["left_out"][0]["cause"] == "retracted", "no race behind it, no part moved: {quiet}");
}

/// Checks the refused answers that name a draft, as `confirm` composes
/// them and as the declaration spells them (skep #739): `kept_place_moved
/// {index, draft, race}` — `draft` the draft that no longer honours the
/// place, the rendering draft or one `also` names, `race` the key read
/// under it — and the own fault `stray_place {index, draft}`. The board
/// gives the first to a move between `confirm`'s re-read and its commit, a
/// window no test holds open, so the composition is pinned here.
#[test]
fn the_refusals_that_name_a_draft_carry_it() {
    use skep_client::publication::{OwnFault, RaceKey, Refusal as PubRefusal};
    let d = skep_client::address::parse_address("1.0.1.0.5").expect("an address");
    let race = RaceKey { at: 999, key: Some("bare".into()), signed: false };
    let (arm, members) = super::super::publication::refusal_arm(&PubRefusal::KeptPlaceMoved { index: 1, draft: d.clone(), race: Some(race) });
    let answer = super::super::publication::refused_json(arm, members);
    crate::shapes::assert_declared("PublicationRefused", &answer);
    crate::shapes::assert_declared("RaceKey", &answer["race"]);
    assert_eq!(answer, json!({"outcome": "refused", "arm": "kept_place_moved", "index": 1, "draft": "1.0.1.0.5", "race": {"at": 999, "key": "bare", "signed": false}}));
    let (arm, members) = super::super::publication::refusal_arm(&PubRefusal::OwnFault(OwnFault::StrayPlace { index: 2, draft: d }));
    let answer = super::super::publication::refused_json(arm, members);
    crate::shapes::assert_declared("PublicationRefused", &answer);
    assert_eq!(answer, json!({"outcome": "refused", "arm": "own_fault", "fault": {"kind": "stray_place", "index": 2, "draft": "1.0.1.0.5"}}));
}

/// Checks that a publication that only removes published words leaves the
/// draft's next publication landing after the version it made (B3-S10).
///
/// D is staged from E.1 through `stage` — E.1's words copied by identity,
/// the board recording E.1 as its base — and takes a passage out: its shot
/// re-mints nothing and re-windows nothing, so the commit writes nothing in
/// D, and it lands E.2, the row naming D beside the member all the same.
/// D takes a second passage out, and its shot lands E.3, after the version
/// the first made — the board having moved D's base to it at that shot —
/// never the daughter E.1.1 its first base alone would place it under.
#[test]
fn a_publication_that_only_removes_words_leaves_the_next_landing_after_the_version_it_made() {
    let dir = TempDir::new().unwrap();
    let sd = spawn(&dir.path().join("board"), true);
    let g = ground(&dir, &sd);
    let edition = g.addr(json!({"op": "create_new_document", "account": "1.0.1", "published": true}));
    let first = g.staged(&edition, "the quick brown fox");
    g.call("publication.open", json!({"session": g.session, "draft": first, "doc": edition, "readable_drafts": [first], "published": [edition]})).unwrap_or_else(|r| panic!("{r}"));
    let e1 = g.call("publication.confirm", json!({"session": g.session})).unwrap_or_else(|r| panic!("{r}"))["member"].as_str().expect("E.1").to_string();
    // D, staged from E.1: its words by identity, its base E.1.
    let d = g.addr(skep_client::board::frames::stage(&e1, None));
    let open = json!({"session": g.session, "draft": d, "doc": edition, "readable_drafts": [d], "published": [edition]});
    let mut landed = Vec::new();
    for text in ["the brown fox", "the fox"] {
        // A passage out — "quick ", then "brown " — at the fifth position.
        g.op(json!({"op": "delete", "doc": d, "p": {"subspace": "1", "ordinal": "5"}, "width": "6", "as_of": g.position()}));
        g.call("publication.open", open.clone()).unwrap_or_else(|r| panic!("{r}"));
        let acked = g.call("publication.confirm", json!({"session": g.session})).unwrap_or_else(|r| panic!("{r}"));
        let member = acked["member"].as_str().unwrap_or_else(|| panic!("{acked}")).to_string();
        let read = g.call("op", json!({"guest": true, "board": g.board, "frame": skep_client::board::frames::retrieve_v(&member, 1, text.len() as u64)})).unwrap();
        assert_eq!(read["items"][0]["content"], text, "{member}");
        let at = acked["at"].as_u64().unwrap();
        let entry = g.shell.sessions.get(&g.session).unwrap();
        let rows = changes_under(&entry.board, &entry.token, &edition, at - 1);
        let row = rows.iter().find(|r| r["at"] == at && r["op"] == "publish").unwrap_or_else(|| panic!("the publish row at {at}, naming D: {rows:?}"));
        assert_eq!(row["docs"], json!([member, d]), "the commit wrote nothing in D, and the row names it: {row}");
        landed.push(member);
    }
    assert_eq!(landed, [format!("{edition}.2"), format!("{edition}.3")], "after the version the first shot made, never the daughter E.1.1");
    g.shell.shutdown();
    sd.shutdown();
}

/// Checks that a draft staged through `stage` publishes from the base the
/// board recorded, no record of the client's written, and that a draft
/// minted by `fork` alone is refused `base_unrecorded` (B3-S10).
///
/// D, staged from the memberless edition, publishes E.1, then words of its
/// own as E.2 — the board moving its base at each shot. S, staged from E.1
/// by the one `stage` frame, holds E.1's nineteen positions by identity and
/// no link of its own, and its `doc_metadata` answers E.1 as its `base` and
/// its `source` and nineteen as `base_copied`; its panel opens told
/// `standing: behind`, and its confirm lands the DAUGHTER E.1.1 under that
/// base, behind the head E.2, never after it. F, minted by `fork` and
/// written, is refused `base_unrecorded` naming it, the edition and the
/// reason, `no_record`, never handed the head.
#[test]
fn a_staged_draft_publishes_from_the_base_the_board_recorded_and_a_fork_alone_is_unrecorded() {
    use skep_client::board::frames::{doc_metadata, find_links_four, retrieve_v, stage, unit_span, Slot};
    let dir = TempDir::new().unwrap();
    let sd = spawn(&dir.path().join("board"), true);
    let g = ground(&dir, &sd);
    let edition = g.addr(json!({"op": "create_new_document", "account": "1.0.1", "published": true}));
    let open = |draft: &str| g.call("publication.open", json!({"session": g.session, "draft": draft, "doc": edition, "readable_drafts": [draft], "published": [edition]}));
    let confirm = || g.call("publication.confirm", json!({"session": g.session})).unwrap_or_else(|r| panic!("{r}"));
    // D, staged from the bare document, publishes E.1, then E.2.
    let d = g.staged(&edition, "the quick brown fox");
    open(&d).unwrap_or_else(|r| panic!("{r}"));
    let e1 = format!("{edition}.1");
    assert_eq!(confirm()["member"].as_str(), Some(e1.as_str()));
    g.op(json!({"op": "insert", "doc": d, "at": {"subspace": "1", "ordinal": "20"}, "values": [" jumps"], "as_of": g.position()}));
    open(&d).unwrap_or_else(|r| panic!("{r}"));
    assert_eq!(confirm()["member"].as_str(), Some(format!("{edition}.2").as_str()), "after E.1, where the board moved D's base");
    // S, staged from E.1: the board's record, and no link of S's own.
    let staged = g.op(stage(&e1, None));
    let s = staged["addr"].as_str().expect("an ack_addr").to_string();
    let meta = g.op(doc_metadata(&s));
    assert_eq!((meta["base"].as_str(), meta["base_copied"].as_str(), meta["source"].as_str()), (Some(e1.as_str()), Some("19"), Some(e1.as_str())), "{meta}");
    let home = unit_span(&s).as_array().cloned().unwrap_or_default();
    assert_eq!(g.op(find_links_four(Slot::Spans(&home), Slot::Any, Slot::Any, Slot::Any))["addrs"], json!([]), "no record written in the draft");
    g.op(json!({"op": "insert", "doc": s, "at": {"subspace": "1", "ordinal": "20"}, "values": [" today"], "as_of": staged["at"]}));
    let panel = open(&s).unwrap_or_else(|r| panic!("the board records S's base: {r}"));
    assert_eq!(panel["standing"], "behind", "E.2 stands past S's base, told before the act: {panel}");
    let daughter = confirm();
    let e11 = format!("{edition}.1.1");
    assert_eq!((daughter["outcome"].as_str(), daughter["member"].as_str()), (Some("acknowledged"), Some(e11.as_str())), "the daughter under the recorded base, behind the head: {daughter}");
    let read = g.call("op", json!({"guest": true, "board": g.board, "frame": retrieve_v(&e11, 1, 25)})).unwrap();
    assert_eq!(read["items"][0]["content"], "the quick brown fox today");
    // F, minted by `fork` alone: the board records no base for it.
    let forked = g.op(json!({"op": "fork"}));
    let f = forked["addr"].as_str().expect("an ack_addr").to_string();
    g.op(json!({"op": "insert", "doc": f, "at": {"subspace": "1", "ordinal": "1"}, "values": ["forked words"], "as_of": forked["at"]}));
    let unrecorded = open(&f).unwrap_err();
    let v = unrecorded.to_value();
    assert_eq!((unrecorded.name(), v["draft"].as_str(), v["doc"].as_str(), v["reason"].as_str()), ("base_unrecorded", Some(f.as_str()), Some(edition.as_str()), Some("no_record")), "{v}");
    g.shell.shutdown();
    sd.shutdown();
}

/// Checks a first draft's standing and the family it leaves behind (D4 (a);
/// skep #744), and that a draft begun before version 1 publishes beside it
/// (D4 (d); skep #746).
///
/// B, C and D are staged from the memberless edition, the bare document
/// their base. B's panel opens `standing: first` — the page passing its own
/// `readable_drafts` — and names C and D, staged from the same bare
/// document, in `left_behind`: the shell reads its own list for the family
/// wherever the publication becomes the head. D publishes E.1; then B's
/// held panel re-opened as it stands, and C opened afresh, each answer
/// `standing: superseded_first` — told, never refused; a daughter leaves no
/// draft behind, the held panel keeping the family its first open read.
/// C's confirm lands E.1.1, version 1's daughter, holding C's words, and
/// B's, re-opened, lands E.1.2 beside it; the edition still reads version
/// 1, and no trunk member E.2 is minted.
#[test]
fn a_first_drafts_standing_is_typed_and_once_version_one_stands_it_publishes_beside_it() {
    use skep_client::board::frames::retrieve_v;
    let dir = TempDir::new().unwrap();
    let sd = spawn(&dir.path().join("board"), true);
    let g = ground(&dir, &sd);
    let edition = g.addr(json!({"op": "create_new_document", "account": "1.0.1", "published": true}));
    let open = |draft: &str| g.call("publication.open", json!({"session": g.session, "draft": draft, "doc": edition, "readable_drafts": [draft], "published": [edition]}));
    let confirm = || g.call("publication.confirm", json!({"session": g.session})).unwrap_or_else(|r| panic!("{r}"));
    let read = |doc: &str, width: u64| g.call("op", json!({"guest": true, "board": g.board, "frame": retrieve_v(doc, 1, width)})).unwrap()["items"][0]["content"].clone();
    let b = g.staged(&edition, "an early start");
    let c = g.staged(&edition, "another early start");
    let d = g.staged(&edition, "the quick brown fox");
    g.listed(&[b.as_str(), c.as_str(), d.as_str()]);
    let panel = open(&b).unwrap_or_else(|r| panic!("{r}"));
    crate::shapes::assert_declared("PublicationPanel", &panel);
    assert_eq!((&panel["standing"], &panel["left_behind"]), (&json!("first"), &json!([c, d])), "the bare document's chain is empty, and its other drafts stand behind the first version: {panel}");
    open(&d).unwrap_or_else(|r| panic!("{r}"));
    let e1 = format!("{edition}.1");
    let acked = confirm();
    assert_eq!(acked["member"].as_str(), Some(e1.as_str()), "{acked}");
    // B's held panel, re-opened as it stands: the standing typed again.
    let held = g.call("publication.open", json!({"session": g.session, "draft": b, "doc": edition})).unwrap_or_else(|r| panic!("told, never refused: {r}"));
    crate::shapes::assert_declared("PublicationPanel", &held);
    assert_eq!((&held["standing"], &held["left_behind"]), (&json!("superseded_first"), &json!([c, d])), "begun before version 1, told so; the family as its first open read it: {held}");
    assert!(held["hold"]["since"].is_u64(), "re-opened from behind D's panel: {held}");
    // C opened afresh: told the same, and a daughter leaves no draft behind.
    let fresh = open(&c).unwrap_or_else(|r| panic!("told, never refused: {r}"));
    assert_eq!((&fresh["standing"], &fresh["left_behind"]), (&json!("superseded_first"), &json!([])), "{fresh}");
    let daughter = confirm();
    let e11 = format!("{e1}.1");
    assert_eq!((daughter["outcome"].as_str(), daughter["member"].as_str(), daughter["via"].as_str()), (Some("acknowledged"), Some(e11.as_str()), Some("answer")), "beside version 1, as its daughter: {daughter}");
    assert_eq!(read(&e11, 19), "another early start");
    // B again, its held panel re-opened: the next daughter of version 1.
    let again = g.call("publication.open", json!({"session": g.session, "draft": b, "doc": edition})).unwrap_or_else(|r| panic!("{r}"));
    assert_eq!(again["standing"], "superseded_first", "{again}");
    let second = confirm();
    let e12 = format!("{e1}.2");
    assert_eq!((second["outcome"].as_str(), second["member"].as_str()), (Some("acknowledged"), Some(e12.as_str())), "the second such draft lands beside version 1 too: {second}");
    assert_eq!(read(&e12, 14), "an early start");
    assert_eq!(read(&edition, 19), "the quick brown fox", "the edition still reads version 1: a daughter moves no head");
    assert_eq!(g.call("publication.count", json!({"session": g.session})).unwrap_err().name(), "no_panel", "the panels went with their acknowledgments");
    g.shell.shutdown();
    sd.shutdown();
}

/// Checks that version 1 landing between a first draft's open and its
/// confirm is re-stated as `superseded_first`, nothing sent (D4 (b′), (d)),
/// and that the daughter lands at the next confirm.
///
/// B and D are staged from the memberless edition. B's panel opens
/// `standing: first`; while it stands a SECOND DEVICE's shell — a fresh
/// shell over the same board and key, on its own data directory
/// (`second_device`) — publishes D as E.1. B's confirm
/// reads the base again and answers `restated` with `standing:
/// superseded_first` and every other difference empty, its event
/// `restated`, nothing sent — the board's position unmoved; B's next
/// confirm lands E.1.1, version 1's daughter, holding B's words:
/// `superseded_first` is told, never refused.
#[test]
fn version_one_landing_between_a_first_drafts_open_and_its_confirm_is_restated_and_the_daughter_lands_next() {
    let dir = TempDir::new().unwrap();
    let sd = spawn(&dir.path().join("board"), true);
    let g = ground(&dir, &sd);
    let edition = g.addr(json!({"op": "create_new_document", "account": "1.0.1", "published": true}));
    let open = |g: &Ground, draft: &str| g.call("publication.open", json!({"session": g.session, "draft": draft, "doc": edition, "readable_drafts": [draft], "published": [edition]})).unwrap_or_else(|r| panic!("{r}"));
    let b = g.staged(&edition, "an early start");
    let d = g.staged(&edition, "the quick brown fox");
    assert_eq!(open(&g, &b)["standing"], "first", "the bare document's chain is empty");
    // The second device publishes D as version 1 while B's panel stands here.
    let second = second_device(&dir, &sd);
    open(&second, &d);
    let e1 = format!("{edition}.1");
    let sibling = second.call("publication.confirm", json!({"session": second.session})).unwrap_or_else(|r| panic!("{r}"));
    assert_eq!(sibling["member"].as_str(), Some(e1.as_str()), "{sibling}");
    second.shell.shutdown();
    let before = g.position();
    let restated = g.call("publication.confirm", json!({"session": g.session})).unwrap_or_else(|r| panic!("re-stated, never refused: {r}"));
    crate::shapes::assert_declared("Restated", &restated);
    assert_eq!(restated, json!({"outcome": "restated", "left": [], "superseded": [], "came": [], "removals_undone": [], "removals_came": [], "selection": [], "standing": "superseded_first"}), "the standing moved alone");
    assert_eq!(g.position(), before, "nothing sent");
    assert_eq!(g.states_once(1), ["restated"], "{:?}", g.states());
    let daughter = g.call("publication.confirm", json!({"session": g.session})).unwrap_or_else(|r| panic!("{r}"));
    let e11 = format!("{e1}.1");
    assert_eq!((daughter["outcome"].as_str(), daughter["member"].as_str()), (Some("acknowledged"), Some(e11.as_str())), "superseded_first is told, never refused — the daughter lands: {daughter}");
    assert_eq!(g.states_once(3), ["restated", "sent", "acknowledged"], "{:?}", g.states());
    let read = g.call("op", json!({"guest": true, "board": g.board, "frame": skep_client::board::frames::retrieve_v(&e11, 1, 14)})).unwrap();
    assert_eq!(read["items"][0]["content"], "an early start");
    g.shell.shutdown();
    sd.shutdown();
}

/// Checks that a sibling's shot landing while a panel stands is re-stated at
/// the confirm, nothing sent (D4 (b′)), and that a draft behind publishes.
///
/// D publishes E.1; S and T are staged from it. S's panel opens `standing:
/// at_head`; while it stands a SECOND DEVICE's shell — a fresh shell over
/// the same board and key, on its own data directory (`second_device`) —
/// publishes T as E.2. S's confirm reads the base
/// again and answers `restated` with `standing: behind` and every other
/// difference empty, its event `restated`, nothing sent — the board's
/// position unmoved; S's next confirm lands the daughter E.1.1: `behind` is
/// told, never refused.
#[test]
fn a_siblings_shot_between_the_open_and_the_confirm_is_restated_and_nothing_lands() {
    let dir = TempDir::new().unwrap();
    let sd = spawn(&dir.path().join("board"), true);
    let g = ground(&dir, &sd);
    let edition = g.addr(json!({"op": "create_new_document", "account": "1.0.1", "published": true}));
    let open = |g: &Ground, draft: &str| g.call("publication.open", json!({"session": g.session, "draft": draft, "doc": edition, "readable_drafts": [draft], "published": [edition]})).unwrap_or_else(|r| panic!("{r}"));
    let d = g.staged(&edition, "the quick brown fox");
    open(&g, &d);
    let e1 = format!("{edition}.1");
    assert_eq!(g.call("publication.confirm", json!({"session": g.session})).unwrap_or_else(|r| panic!("{r}"))["member"].as_str(), Some(e1.as_str()));
    let s = g.staged(&e1, "one sibling ");
    let t = g.staged(&e1, "another sibling ");
    assert_eq!(open(&g, &s)["standing"], "at_head", "S's base E.1 heads the chain");
    // The second device publishes T while S's panel stands here.
    let second = second_device(&dir, &sd);
    open(&second, &t);
    let sibling = second.call("publication.confirm", json!({"session": second.session})).unwrap_or_else(|r| panic!("{r}"));
    assert_eq!(sibling["member"].as_str(), Some(format!("{edition}.2").as_str()), "{sibling}");
    second.shell.shutdown();
    let before = g.position();
    let restated = g.call("publication.confirm", json!({"session": g.session})).unwrap_or_else(|r| panic!("{r}"));
    crate::shapes::assert_declared("Restated", &restated);
    assert_eq!(restated, json!({"outcome": "restated", "left": [], "superseded": [], "came": [], "removals_undone": [], "removals_came": [], "selection": [], "standing": "behind"}), "the standing moved alone");
    assert_eq!(g.position(), before, "nothing sent");
    assert_eq!(g.states_once(3), ["sent", "acknowledged", "restated"], "{:?}", g.states());
    let daughter = g.call("publication.confirm", json!({"session": g.session})).unwrap_or_else(|r| panic!("{r}"));
    assert_eq!((daughter["outcome"].as_str(), daughter["member"].as_str()), (Some("acknowledged"), Some(format!("{e1}.1").as_str())), "behind is told, never refused: {daughter}");
    g.shell.shutdown();
    sd.shutdown();
}

/// Checks that a base moved since the panel at an unmoved standing is
/// re-stated, nothing sent, and that the next confirm sends against it
/// (D4 (b′); skep #934).
///
/// S, staged from E.1 — the head — holds twelve words of its own. Its panel
/// holds the last six by a selection the page passes and opens `at_head`;
/// while it stands a SECOND DEVICE's shell publishes the first six as E.2,
/// which moves S's recorded base to E.2: the head moved and the standing
/// `at_head` both times. S's confirm reads the base again and answers
/// `restated` with `base` E.2 and every other difference empty, its event
/// `restated`, nothing sent — the board's position unmoved; the next confirm
/// lands E.3 holding the held words, the request naming the member the
/// panel tested against (the mutant that reads the standing alone sends
/// against E.1 and lands the daughter E.1.1, the issue's own report; the one
/// that sets `base` without re-keying the panel re-states at every confirm
/// and never lands).
#[test]
fn a_moved_base_at_an_unmoved_standing_is_restated_and_the_next_confirm_sends_against_it() {
    let dir = TempDir::new().unwrap();
    let sd = spawn(&dir.path().join("board"), true);
    let g = ground(&dir, &sd);
    let edition = g.addr(json!({"op": "create_new_document", "account": "1.0.1", "published": true}));
    let d = g.staged(&edition, "the quick brown fox");
    g.call("publication.open", json!({"session": g.session, "draft": d, "doc": edition, "readable_drafts": [d], "published": [edition]})).unwrap_or_else(|r| panic!("{r}"));
    let e1 = format!("{edition}.1");
    assert_eq!(g.call("publication.confirm", json!({"session": g.session})).unwrap_or_else(|r| panic!("{r}"))["member"].as_str(), Some(e1.as_str()));
    let s = g.staged(&e1, "abcdefghijkl");
    let open = |g: &Ground, first_word: u64| g.call("publication.open", json!({"session": g.session, "draft": s, "doc": edition, "selection": [{"origin": s, "i_start": first_word, "width": 6}], "readable_drafts": [s], "published": [edition]})).unwrap_or_else(|r| panic!("{r}"));
    assert_eq!(open(&g, 7)["standing"], "at_head", "S's base E.1 heads the chain");
    // The second device publishes S's first six words while this panel stands.
    let second = second_device(&dir, &sd);
    open(&second, 1);
    let e2 = format!("{edition}.2");
    let sibling = second.call("publication.confirm", json!({"session": second.session})).unwrap_or_else(|r| panic!("{r}"));
    assert_eq!(sibling["member"].as_str(), Some(e2.as_str()), "{sibling}");
    second.shell.shutdown();
    let before = g.position();
    let confirm = || g.call("publication.confirm", json!({"session": g.session})).unwrap_or_else(|r| panic!("{r}"));
    let restated = confirm();
    crate::shapes::assert_declared("Restated", &restated);
    assert_eq!(restated, json!({"outcome": "restated", "left": [], "superseded": [], "came": [], "removals_undone": [], "removals_came": [], "selection": [], "base": e2}), "the base moved alone, at_head both times");
    assert_eq!(g.position(), before, "nothing sent");
    assert_eq!(g.states_once(3), ["sent", "acknowledged", "restated"], "{:?}", g.states());
    // Confirmed again: sent against the base the re-read named.
    let acked = confirm();
    let e3 = format!("{edition}.3");
    assert_eq!((acked["outcome"].as_str(), acked["member"].as_str()), (Some("acknowledged"), Some(e3.as_str())), "the next member after the moved base, never E.1's daughter: {acked}");
    assert_eq!(g.text(&e3, 6), "ghijkl", "the held words are what the member holds");
    g.shell.shutdown();
    sd.shutdown();
}

/// Checks that a base differing from the panel's by its extent alone is
/// re-stated, nothing sent, and that the extent re-read is what the next
/// confirm sends (skep #934's catch-all: a base that differs in any way).
///
/// S, staged from E.1 — E.1's nineteen positions by identity — and written
/// on, opens its panel with base E.1 at extent nineteen. A `set_arrangement`
/// of S's own runs, naming E.1 as THE BASE TO RECORD at a smaller extent,
/// moves the record's extent alone; the member and the standing stay. The
/// confirm is `restated`, naming `base` E.1, nothing sent; the next confirm's
/// `publish` row carries extent five (the mutant that compares the member
/// alone reads the extent of E.1 as no difference, and the request goes out
/// at nineteen).
#[test]
fn a_base_moved_by_its_extent_alone_is_re_stated() {
    use skep_client::board::frames::{image, set_arrangement, shot_run};
    let dir = TempDir::new().unwrap();
    let sd = spawn(&dir.path().join("board"), true);
    let g = ground(&dir, &sd);
    let edition = g.addr(json!({"op": "create_new_document", "account": "1.0.1", "published": true}));
    let d = g.staged(&edition, "the quick brown fox");
    g.call("publication.open", json!({"session": g.session, "draft": d, "doc": edition, "readable_drafts": [d], "published": [edition]})).unwrap_or_else(|r| panic!("{r}"));
    let e1 = format!("{edition}.1");
    assert_eq!(g.call("publication.confirm", json!({"session": g.session})).unwrap_or_else(|r| panic!("{r}"))["member"].as_str(), Some(e1.as_str()));
    let s = g.staged(&e1, "abcd");
    let panel = g.call("publication.open", json!({"session": g.session, "draft": s, "doc": edition, "readable_drafts": [s], "published": [edition]})).unwrap_or_else(|r| panic!("{r}"));
    assert_eq!(panel["standing"], "at_head", "{panel}");
    let answer = g.op(image(&s, 1, 23));
    let runs: Vec<Value> = answer["runs"].as_array().expect("the draft's image").iter().map(|r| {
        let i_start = r["i_start"].as_str().expect("an I-address");
        shot_run(&skep_client::address::document_of(i_start).expect("a document"), i_start, r["width"].as_str().expect("a width").parse().expect("a natural"))
    }).collect();
    g.op(set_arrangement(&s, &runs, g.position(), None, Some((e1.as_str(), 5)), None, None));
    let before = g.position();
    let restated = g.call("publication.confirm", json!({"session": g.session})).unwrap_or_else(|r| panic!("{r}"));
    crate::shapes::assert_declared("Restated", &restated);
    assert_eq!(restated, json!({"outcome": "restated", "left": [], "superseded": [], "came": [], "removals_undone": [], "removals_came": [], "selection": [], "base": e1}), "the extent moved alone: the same member, the record's new count");
    assert_eq!(g.position(), before, "nothing sent");
    let acked = g.call("publication.confirm", json!({"session": g.session})).unwrap_or_else(|r| panic!("{r}"));
    let e2 = format!("{edition}.2");
    assert_eq!((acked["outcome"].as_str(), acked["member"].as_str()), (Some("acknowledged"), Some(e2.as_str())), "{acked}");
    let at = acked["at"].as_u64().unwrap();
    let entry = g.shell.sessions.get(&g.session).unwrap();
    let rows = changes_under(&entry.board, &entry.token, &edition, at - 1);
    let row = rows.iter().find(|r| r["at"] == at && r["op"] == "publish").unwrap_or_else(|| panic!("the publish row at {at}: {rows:?}"));
    assert_eq!(row["base_extent"].as_str(), Some("5"), "the extent the re-read named: {row}");
    g.shell.shutdown();
    sd.shutdown();
}

/// Checks that a panel of the whole draft re-takes the draft on a moved base
/// (skep #934; P4's "publish all of this draft", PUB-3.108's "what the draft
/// now arranges"), at a first version and at a later one.
///
/// D, staged from the memberless edition, opens its whole-draft panel here;
/// a SECOND DEVICE publishes the whole draft as E.1, moving D's base. The
/// confirm is `restated` naming `base` E.1 and `standing: at_head`,
/// `selection` empty though the held runs' words went to the board by
/// identity; the panel holds the draft as it now stands, so the next confirm
/// is `inert: unchanged`, nothing sent — never the empty version the held
/// runs would compose over a base with words. D writes on; a fresh
/// panel here, the second device publishing the whole draft again as E.2,
/// and the confirm is `restated` naming `base` E.2 alone, the standing
/// `at_head` both times, then `inert: unchanged`, nothing sent: at a later
/// version too the panel follows the draft the board rewrote. Published in
/// part, the panel re-takes what the draft now holds, the runs' indices the
/// new list's, and the next confirm publishes the whole draft against the
/// new base (the mutant that leaves the whole panel's held runs in place
/// publishes an empty version; the one that keeps the misaligned `selection`
/// difference says runs moved that the panel re-took).
#[test]
fn a_whole_draft_panel_re_takes_the_draft_when_its_base_moves() {
    let dir = TempDir::new().unwrap();
    let sd = spawn(&dir.path().join("board"), true);
    let g = ground(&dir, &sd);
    let edition = g.addr(json!({"op": "create_new_document", "account": "1.0.1", "published": true}));
    let d = g.staged(&edition, "the quick brown fox");
    let open = |g: &Ground, draft: &str| g.call("publication.open", json!({"session": g.session, "draft": draft, "doc": edition, "readable_drafts": [draft], "published": [edition]})).unwrap_or_else(|r| panic!("{r}"));
    let confirm = |g: &Ground| g.call("publication.confirm", json!({"session": g.session})).unwrap_or_else(|r| panic!("{r}"));
    let restated = |base: &str, standing: Option<&str>| {
        let mut v = json!({"outcome": "restated", "left": [], "superseded": [], "came": [], "removals_undone": [], "removals_came": [], "selection": [], "base": base});
        if let Some(standing) = standing {
            v["standing"] = json!(standing);
        }
        v
    };
    let unchanged = |refused: Value| assert_eq!((refused["outcome"].as_str(), refused["arm"].as_str(), refused["inert"].as_str()), (Some("refused"), Some("inert"), Some("unchanged")), "{refused}");
    assert_eq!(open(&g, &d)["standing"], "first", "the panel of the whole draft, the bare document's chain empty");
    let second = second_device(&dir, &sd);
    open(&second, &d);
    let e1 = format!("{edition}.1");
    assert_eq!(confirm(&second)["member"].as_str(), Some(e1.as_str()), "the whole draft published from the second device");
    let before = g.position();
    let first = confirm(&g);
    crate::shapes::assert_declared("Restated", &first);
    assert_eq!(first, restated(&e1, Some("at_head")), "the base moved, the standing typed against it");
    assert_eq!(g.position(), before, "nothing sent");
    unchanged(confirm(&g));
    assert_eq!(g.position(), before, "nothing sent");
    // A later version: D writes on, this device opens afresh, the second
    // device publishes what D now holds.
    g.call("publication.cancel", json!({"session": g.session})).unwrap_or_else(|r| panic!("{r}"));
    g.op(json!({"op": "insert", "doc": d, "at": {"subspace": "1", "ordinal": "20"}, "values": [" jumps"], "as_of": g.position()}));
    assert_eq!(open(&g, &d)["standing"], "at_head", "D's base is E.1, the head");
    open(&second, &d);
    let e2 = format!("{edition}.2");
    assert_eq!(confirm(&second)["member"].as_str(), Some(e2.as_str()), "the second device publishes D's whole draft again");
    let before = g.position();
    let later = confirm(&g);
    assert_eq!(later, restated(&e2, None), "the standing at_head both times, the base moved alone");
    assert_eq!(g.position(), before, "nothing sent");
    unchanged(confirm(&g));
    assert_eq!(g.position(), before, "nothing sent");
    // Published in part: S holds twelve words of its own and E.2's words —
    // two runs, the second at position thirteen. The second device publishes
    // S's first six as E.3, and S's whole-draft panel here re-takes what S
    // now holds, three runs: the second at position seven, so no held run
    // is compared with a new one at its index (the empty `selection`), and
    // the next confirm publishes the whole draft against E.3, as E.4.
    g.call("publication.cancel", json!({"session": g.session})).unwrap_or_else(|r| panic!("{r}"));
    let s = g.staged(&e2, "abcdefghijkl");
    assert_eq!(open(&g, &s)["standing"], "at_head", "S's base E.2 heads the chain");
    second.call("publication.open", json!({"session": second.session, "draft": s, "doc": edition, "selection": [{"origin": s, "i_start": 1, "width": 6}], "readable_drafts": [s], "published": [edition]})).unwrap_or_else(|r| panic!("{r}"));
    let e3 = format!("{edition}.3");
    assert_eq!(confirm(&second)["member"].as_str(), Some(e3.as_str()), "the first six of S published from the second device");
    second.shell.shutdown();
    let before = g.position();
    let part = confirm(&g);
    assert_eq!(part, restated(&e3, None), "at_head both times; the re-take's runs read as no placement difference");
    assert_eq!(g.position(), before, "nothing sent");
    let acked = confirm(&g);
    let e4 = format!("{edition}.4");
    assert_eq!((acked["outcome"].as_str(), acked["member"].as_str()), (Some("acknowledged"), Some(e4.as_str())), "the whole of S as it now stands, against E.3: {acked}");
    assert_eq!(g.text(&e4, 12), "abcdefghijkl", "the words a whole-draft command publishes, the published six among them");
    g.shell.shutdown();
    sd.shutdown();
}

/// Checks that a held selection the draft has wholly left is re-stated and
/// then refused, nothing sent (PUB-3.108; skep #934): no empty version lands
/// on a moved base.
///
/// A selection the page passes holds D's fresh words at a later version; a
/// SECOND DEVICE publishes the whole draft as E.2, re-windowing them at
/// their kept place, so the held run stands absent. The confirm is
/// `restated` naming `base` E.2 with the run placed `absent`, nothing sent;
/// the next confirm is refused `selection_not_arranged`, nothing sent. A
/// panel of the whole draft over a draft EMPTIED while its base moved keeps
/// the held runs, each re-stated absent, and is refused the same at the next
/// confirm (the mutant that lets the selection through publishes an empty
/// head; the one that takes the emptied draft whole publishes an empty
/// member too).
#[test]
fn a_held_selection_the_draft_has_wholly_left_is_re_stated_and_then_refused() {
    let dir = TempDir::new().unwrap();
    let sd = spawn(&dir.path().join("board"), true);
    let g = ground(&dir, &sd);
    let edition = g.addr(json!({"op": "create_new_document", "account": "1.0.1", "published": true}));
    let d = g.staged(&edition, "the quick brown fox");
    let open = |g: &Ground, draft: &str, selection: Option<Value>| {
        let mut args = json!({"session": g.session, "draft": draft, "doc": edition, "readable_drafts": [draft], "published": [edition]});
        if let Some(selection) = selection {
            args["selection"] = selection;
        }
        g.call("publication.open", args).unwrap_or_else(|r| panic!("{r}"))
    };
    let confirm = |g: &Ground| g.call("publication.confirm", json!({"session": g.session}));
    open(&g, &d, None);
    let e1 = format!("{edition}.1");
    assert_eq!(confirm(&g).unwrap_or_else(|r| panic!("{r}"))["member"].as_str(), Some(e1.as_str()));
    g.op(json!({"op": "insert", "doc": d, "at": {"subspace": "1", "ordinal": "20"}, "values": [" jumps"], "as_of": g.position()}));
    // D's fresh words are the draft's own run past E.1's nineteen: the open's
    // strict read is the premise that it stands whole there.
    open(&g, &d, Some(json!([{"origin": d, "i_start": 20, "width": 6}])));
    let second = second_device(&dir, &sd);
    open(&second, &d, None);
    let e2 = format!("{edition}.2");
    assert_eq!(confirm(&second).unwrap_or_else(|r| panic!("{r}"))["member"].as_str(), Some(e2.as_str()), "the second device publishes the whole draft, the held run re-windowed");
    let before = g.position();
    let restated = confirm(&g).unwrap_or_else(|r| panic!("{r}"));
    crate::shapes::assert_declared("Restated", &restated);
    assert_eq!(restated, json!({"outcome": "restated", "left": [], "superseded": [], "came": [], "removals_undone": [], "removals_came": [], "selection": [{"run": 0, "placement": "absent"}], "base": e2}), "the held run gone, its base moved, the standing at_head both times");
    assert_eq!(g.position(), before, "nothing sent");
    let refused = confirm(&g).unwrap_err();
    assert_eq!((refused.name(), refused.to_value()["index"].as_u64()), ("selection_not_arranged", Some(0)), "{refused}");
    assert_eq!(g.position(), before, "nothing sent: no empty version");
    // The whole panel over a draft emptied while its base moves: the second
    // device publishes D whole again, then deletes every word.
    g.call("publication.cancel", json!({"session": g.session})).unwrap_or_else(|r| panic!("{r}"));
    g.op(json!({"op": "insert", "doc": d, "at": {"subspace": "1", "ordinal": "26"}, "values": ["!"], "as_of": g.position()}));
    open(&g, &d, None);
    open(&second, &d, None);
    let e3 = format!("{edition}.3");
    assert_eq!(confirm(&second).unwrap_or_else(|r| panic!("{r}"))["member"].as_str(), Some(e3.as_str()));
    second.op(json!({"op": "delete", "doc": d, "p": {"subspace": "1", "ordinal": "1"}, "width": "26", "as_of": second.position()}));
    second.shell.shutdown();
    let before = g.position();
    let held = confirm(&g).unwrap_or_else(|r| panic!("{r}"));
    assert_eq!((held["outcome"].as_str(), held["base"].as_str()), (Some("restated"), Some(e3.as_str())), "{held}");
    let placed = held["selection"].as_array().expect("the held runs, re-stated");
    assert!(!placed.is_empty() && placed.iter().all(|p| p["placement"] == "absent"), "the emptied draft keeps the held runs, each absent: {held}");
    assert_eq!(g.position(), before, "nothing sent");
    let refused = confirm(&g).unwrap_err();
    assert_eq!(refused.name(), "selection_not_arranged", "{refused}");
    assert_eq!(g.position(), before, "nothing sent: no empty version");
    g.shell.shutdown();
    sd.shutdown();
}

/// Checks the open's read of the draft's merge marker and the claim it
/// composes from it (the merge bridge lane; `client.md` §4b.1's merge row,
/// `land`): the request carries `supersede` ONLY for the marker's published
/// daughters and ONLY where the marker's head is the trunk's head as read
/// at the open, by a direct probe, never off the standing.
///
/// D publishes E.1 and E.2; S, staged from E.1 and behind, publishes the
/// daughter E.1.1 with its own words; L, a level draft staged from E.2,
/// takes the merge of E.2 with E.1.1 (`merge.compose`), its marker naming
/// E.1.1 under head E.2. L's `publication.open` answers `count.supersede
/// [E.1.1]` and its panel, count and acknowledgment are declared; the
/// `confirm` is acknowledged E.3 with `supersede [E.1.1]`, what rode, and
/// `in_claims` at E.1.1 answers one active claim homed in E whose `new` is
/// E.3 — the daughter marked superseded in the member's commit. Then a
/// marked draft BEHIND the head: L2 takes the merge of E.3 with E.2.1 (a
/// daughter S2 publishes under E.2), a SECOND DEVICE's shell publishes E.4
/// meanwhile, and L2's open — the marker's head E.3 no longer the trunk's
/// — carries no claim, `count.supersede []`, its standing `behind`; its
/// confirm lands a daughter E.3.1 with no claim. An unmarked draft's open
/// carries none, and its acknowledgment says none rode: the body today's
/// (the mutants that claim off the standing alone send a claim at a marked
/// draft the trunk moved past, which the board refuses whole; the one that
/// composes the claim from `sides` unfiltered claims a private draft).
#[test]
fn the_open_on_a_marked_draft_carries_the_claim_only_where_the_markers_head_is_the_trunks() {
    let dir = TempDir::new().unwrap();
    let sd = spawn(&dir.path().join("board"), true);
    let g = ground(&dir, &sd);
    let edition = g.addr(json!({"op": "create_new_document", "account": "1.0.1", "published": true}));
    let open = |g: &Ground, draft: &str| g.call("publication.open", json!({"session": g.session, "draft": draft, "doc": edition, "readable_drafts": [draft], "published": [edition]})).unwrap_or_else(|r| panic!("{r}"));
    let confirm = |g: &Ground| g.call("publication.confirm", json!({"session": g.session})).unwrap_or_else(|r| panic!("{r}"));
    // D publishes E.1, then E.2; S, behind at E.1, publishes the daughter
    // E.1.1 with its own words.
    let d = g.staged(&edition, "the fox");
    open(&g, &d);
    let e1 = format!("{edition}.1");
    assert_eq!(confirm(&g)["member"].as_str(), Some(e1.as_str()));
    let s = g.addr(skep_client::board::frames::stage(&e1, None));
    g.op(json!({"op": "insert", "doc": s, "at": {"subspace": "1", "ordinal": "8"}, "values": [" today"], "as_of": g.position()}));
    g.op(json!({"op": "insert", "doc": d, "at": {"subspace": "1", "ordinal": "8"}, "values": [" jumps"], "as_of": g.position()}));
    open(&g, &d);
    let e2 = format!("{edition}.2");
    assert_eq!(confirm(&g)["member"].as_str(), Some(e2.as_str()));
    open(&g, &s);
    let e11 = format!("{e1}.1");
    assert_eq!(confirm(&g)["member"].as_str(), Some(e11.as_str()), "the daughter under E.1");
    // L, level with the head, takes the merge of E.2 with E.1.1.
    let l = g.addr(skep_client::board::frames::stage(&e2, None));
    let landed = g.call("merge.compose", json!({"session": g.session, "doc": edition, "alternative": e11, "into": l})).unwrap_or_else(|r| panic!("{r}"));
    assert_eq!((landed["outcome"].as_str(), landed["into"].as_str()), (Some("landed"), Some(l.as_str())), "{landed}");
    let marker = g.op(skep_client::board::frames::doc_metadata(&l))["merge"].clone();
    assert_eq!((marker["sides"].clone(), marker["head"].as_str()), (json!([e11]), Some(e2.as_str())), "the marker the open reads: {marker}");
    // The open on the marked draft at the head: the claim rides.
    let panel = open(&g, &l);
    crate::shapes::assert_declared("PublicationPanel", &panel);
    crate::shapes::assert_declared("Count", &panel["count"]);
    assert_eq!((panel["count"]["supersede"].clone(), panel["standing"].as_str()), (json!([e11]), Some("at_head")), "the marker's published daughter, the marker's head the trunk's: {panel}");
    let counted = g.call("publication.count", json!({"session": g.session})).unwrap();
    assert_eq!(counted["count"]["supersede"], json!([e11]), "the count carries the claim as data: {counted}");
    let acked = confirm(&g);
    crate::shapes::assert_declared("Acknowledged", &acked);
    let e3 = format!("{edition}.3");
    assert_eq!((acked["member"].as_str(), acked["supersede"].clone()), (Some(e3.as_str()), json!([e11])), "the claim rode: {acked}");
    let text = g.text(&e3, 19);
    assert!(text.starts_with("the fox") && text.contains(" jumps") && text.contains(" today") && text.len() == 19, "{text:?}");
    let claims = g.call("op", json!({"guest": true, "board": g.board, "frame": skep_client::board::frames::in_claims(&e11)})).unwrap();
    let rows = claims["claims"].as_array().cloned().unwrap_or_default();
    assert_eq!(rows.len(), 1, "one claim at the daughter: {claims}");
    assert_eq!((rows[0]["new"].as_str(), rows[0]["home"].as_str(), rows[0]["active"].as_bool().unwrap_or(true)), (Some(e3.as_str()), Some(edition.as_str()), true), "homed in the trunk, naming the member: {claims}");
    // A marked draft BEHIND the head carries none: L2's merge of E.3 with
    // E.2.1, then a second device moves the head to E.4.
    let s2 = g.addr(skep_client::board::frames::stage(&e2, None));
    g.op(json!({"op": "insert", "doc": s2, "at": {"subspace": "1", "ordinal": "14"}, "values": [" high"], "as_of": g.position()}));
    open(&g, &s2);
    let e21 = format!("{e2}.1");
    assert_eq!(confirm(&g)["member"].as_str(), Some(e21.as_str()), "the daughter under E.2");
    let l2 = g.addr(skep_client::board::frames::stage(&e3, None));
    let landed = g.call("merge.compose", json!({"session": g.session, "doc": edition, "alternative": e21, "into": l2})).unwrap_or_else(|r| panic!("{r}"));
    assert_eq!(landed["outcome"].as_str(), Some("landed"), "{landed}");
    let second = second_device(&dir, &sd);
    let t = second.addr(skep_client::board::frames::stage(&e3, None));
    second.op(json!({"op": "insert", "doc": t, "at": {"subspace": "1", "ordinal": "20"}, "values": ["!"], "as_of": second.position()}));
    open(&second, &t);
    let e4 = format!("{edition}.4");
    assert_eq!(confirm(&second)["member"].as_str(), Some(e4.as_str()), "the head moved to E.4");
    second.shell.shutdown();
    let behind = open(&g, &l2);
    assert_eq!((behind["count"]["supersede"].clone(), behind["standing"].as_str()), (json!([]), Some("behind")), "a marked draft behind the head claims nothing: {behind}");
    let daughter = confirm(&g);
    assert_eq!((daughter["member"].as_str(), daughter["supersede"].clone()), (Some(format!("{e3}.1").as_str()), json!([])), "the daughter lands with no claim: {daughter}");
    // An unmarked draft: no claim, and the acknowledgment says none rode.
    let plain = g.addr(skep_client::board::frames::stage(&e4, None));
    g.op(json!({"op": "insert", "doc": plain, "at": {"subspace": "1", "ordinal": "21"}, "values": ["?"], "as_of": g.position()}));
    let unmarked = open(&g, &plain);
    assert_eq!(unmarked["count"]["supersede"], json!([]), "{unmarked}");
    let acked = confirm(&g);
    assert_eq!((acked["member"].as_str(), acked["supersede"].clone()), (Some(format!("{edition}.5").as_str()), json!([])), "{acked}");
    g.shell.shutdown();
    sd.shutdown();
}

/// Checks that a draft placing one run twice publishes whole (skep #753).
///
/// A draft staged from the memberless edition reads `abcd`; its four words
/// are copied after themselves — `abcdabcd`, one run of the draft's own
/// identity at two places. `publication.open` and `confirm`: the shot
/// composed off the draft's image names the run at both places, the confirm
/// is acknowledged, and the member reads `abcdabcd` (the mutant that images
/// the doubled run once composes a shot of the first place alone, and the
/// member reads `abcd`).
#[test]
fn a_draft_placing_a_run_of_its_own_words_twice_publishes_whole() {
    use skep_client::board::frames::retrieve_v;
    let dir = TempDir::new().unwrap();
    let sd = spawn(&dir.path().join("board"), true);
    let g = ground(&dir, &sd);
    let edition = g.addr(json!({"op": "create_new_document", "account": "1.0.1", "published": true}));
    let draft = g.staged(&edition, "abcd");
    let text = |read: &Value| -> String { read["items"].as_array().unwrap().iter().map(|i| i["content"].as_str().unwrap_or("")).collect() };
    g.op(json!({"op": "copy", "doc": draft, "at": {"subspace": "1", "ordinal": "5"}, "specs": [{"source": draft, "span": {"start": "1.1", "width": "0.4"}}], "as_of": g.position()}));
    assert_eq!(text(&g.op(retrieve_v(&draft, 1, 9))), "abcdabcd");
    g.call("publication.open", json!({"session": g.session, "draft": draft, "doc": edition, "readable_drafts": [draft], "published": [edition]})).unwrap_or_else(|r| panic!("{r}"));
    let acked = g.call("publication.confirm", json!({"session": g.session})).unwrap_or_else(|r| panic!("the shot over the doubled run is composed and acknowledged: {r}"));
    let e1 = format!("{edition}.1");
    assert_eq!((acked["outcome"].as_str(), acked["member"].as_str()), (Some("acknowledged"), Some(e1.as_str())), "{acked}");
    let member = g.call("op", json!({"guest": true, "board": g.board, "frame": retrieve_v(&e1, 1, 9)})).unwrap();
    assert_eq!(text(&member), "abcdabcd", "the member holds the run at both places: {member}");
    g.shell.shutdown();
    sd.shutdown();
}

/// THE PRIVATE RIDER through the shell (the link-sets design §5.7 (vi′);
/// skep #894): after a first version, the draft holds a strong mark of its
/// own over the member's words, its public copy in `E.1` with the accept
/// claim in the draft, and the held removal of the copy. `publication.open`
/// answers the removal under its declared shape with `original` the draft's
/// mark and `rest` empty — every word covered — and the price counts the
/// rider as its sixth list; `publication.confirm` lands the version, after
/// which the copy and the original are both retracted, the original's
/// retraction homed in the draft, and the feed row names the draft.
#[test]
fn a_held_removals_original_is_answered_under_its_shape_and_ended_by_the_confirm() {
    use skep_client::board::frames::{find_links_ftt, T_HELD_REMOVAL};
    use skep_client::board::T_RETRACTION;
    let dir = TempDir::new().unwrap();
    let sd = spawn(&dir.path().join("board"), true);
    let g = ground(&dir, &sd);
    let edition = g.addr(json!({"op": "create_new_document", "account": "1.0.1", "published": true}));
    let draft = g.staged(&edition, "the quick brown fox");
    let inputs = json!({"session": g.session, "draft": draft, "doc": edition, "readable_drafts": [draft], "published": [edition]});
    g.call("publication.open", inputs.clone()).unwrap_or_else(|r| panic!("{r}"));
    let first = g.call("publication.confirm", json!({"session": g.session})).unwrap_or_else(|r| panic!("{r}"));
    let member = format!("{edition}.1");
    assert_eq!(first["member"].as_str(), Some(member.as_str()), "{first}");
    // The strong mark in the draft over "quick", its copy in E.1 over the
    // same words, the accept claim in the draft, the held removal.
    let strong = "1.1.0.1.0.1.0.3.23.2";
    let original = g.addr(json!({"op": "make_link", "home": draft, "from": {"addrs": []}, "to": [{"source": draft, "span": {"start": "1.5", "width": "0.5"}}], "ty": {"addrs": [strong]}}));
    let copy = g.addr(json!({"op": "make_link", "home": member, "from": {"addrs": []}, "to": [{"source": member, "span": {"start": "1.5", "width": "0.5"}}], "ty": {"addrs": [strong]}}));
    g.addr(json!({"op": "assert_sup", "home": draft, "old": original, "new": copy}));
    g.addr(json!({"op": "make_link", "home": draft, "from": {"addrs": []}, "to": {"addrs": [copy]}, "ty": {"addrs": [T_HELD_REMOVAL]}}));
    let panel = g.call("publication.open", inputs).unwrap_or_else(|r| panic!("{r}"));
    crate::shapes::assert_declared("Formatting", &panel["formatting"]);
    let removals = panel["formatting"]["removals"].as_array().unwrap();
    assert_eq!(removals.len(), 1, "{panel}");
    crate::shapes::assert_declared("Removal", &removals[0]);
    assert_eq!((removals[0]["mark"].as_str(), removals[0]["original"].as_str(), removals[0]["rest"].as_array().map(Vec::len)), (Some(copy.as_str()), Some(original.as_str()), Some(0)), "{}", removals[0]);
    assert_eq!(panel["price"]["lists"].as_array().map(Vec::len), Some(6), "the rider is the sixth list: {}", panel["price"]);
    assert_eq!(panel["price"]["lists"][5], json!(1), "{}", panel["price"]);
    assert_eq!(panel["count"]["r"], json!(1), "{}", panel["count"]);
    let before = g.position();
    let acked = g.call("publication.confirm", json!({"session": g.session})).unwrap_or_else(|r| panic!("{r}"));
    assert_eq!(acked["member"].as_str(), Some(format!("{edition}.2").as_str()), "{acked}");
    let at = acked["at"].as_u64().unwrap();
    assert!(at > before);
    let retractions = |link: &str| g.call("op", json!({"session": g.session, "frame": find_links_ftt(T_RETRACTION, link)})).unwrap()["addrs"].as_array().map(Vec::len);
    assert_eq!((retractions(&copy), retractions(&original)), (Some(1), Some(1)), "the copy and its original both retracted");
    let ended = g.call("op", json!({"session": g.session, "frame": find_links_ftt(T_RETRACTION, &original)})).unwrap();
    assert!(ended["addrs"][0].as_str().unwrap().starts_with(&format!("{draft}.0.2.")), "the original's retraction homed in the draft: {ended}");
    let entry = g.shell.sessions.get(&g.session).unwrap();
    let rows = changes_under(&entry.board, &entry.token, &edition, at - 1);
    let row = rows.iter().find(|r| r["at"] == at && r["op"] == "publish").unwrap_or_else(|| panic!("the publish row at {at}: {rows:?}"));
    let docs: Vec<&str> = row["docs"].as_array().unwrap().iter().filter_map(Value::as_str).collect();
    assert!(docs.contains(&draft.as_str()) && docs.contains(&member.as_str()), "the row names the draft, the original's home, and E.1, the copy's: {docs:?}");
}
