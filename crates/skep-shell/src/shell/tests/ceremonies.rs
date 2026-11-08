//! The ceremonial rows end to end, against the real daemon in-process.
//!
//! The suite checks `bind` confirming the three facts against the board
//! before it appends the line; a ceremony from a shell finding another's
//! lock on the board's held store refused `another_window` at the shell's
//! one write door, and going out from the shell that holds the store — from
//! a shell that has opened no session at the board too, its door touching
//! the store first, whether another shell holds the pending lock or the
//! board's own alone; a second device's key enrolled from the
//! first device, bound there and retiring the first's key, whose session
//! dies on the arm that names the hand; a rotation ending its old key's
//! session on the own hand's arm; and, beside a key store that cannot be
//! listed, a self-retirement on the own hand's arm still and another hand's
//! answered neither, the failure said once on `Talk` — each death read for
//! its hand, each walk's answer held to its declaration.

use std::sync::mpsc::Receiver;

use skep_search::Chain;

use super::*;

/// Returns the states the `another-window` events `rx` holds carry, in
/// order, each held to its declaration.
fn edges(rx: &Receiver<Event>) -> Vec<bool> {
    rx.try_iter()
        .filter(|e| e.name == EventName::AnotherWindow)
        .map(|e| {
            crate::shapes::assert_declared("AnotherWindowEvent", &e.data);
            e.data["another_window"].as_bool().unwrap_or_else(|| panic!("the state, a boolean: {}", e.data))
        })
        .collect()
}

/// Returns whether a holder keeps `dir`'s lock: its lock file opened and
/// found locked.
fn taken(dir: &HeldDir) -> bool {
    matches!(dir.try_lock(), Ok(None))
}

/// Returns the chain the board at `origin` names in its head record.
fn chain_of(origin: &str) -> Chain {
    let term = Board::new(Origin::parse(origin).unwrap(), skep_client::PlainHttp::new()).board_term().unwrap().expect("the claim's head stands");
    Chain::from_bytes(term.chain)
}

/// Returns the eight writing ceremonies' calls at `board`, each refused at
/// the door before its walk where another shell holds the board's store.
fn eight_ceremonies(board: &str, origin: &str, key: &Value) -> [(&'static str, Value); 8] {
    [
        ("claim", json!({"board": board})),
        ("enroll", json!({"board": board, "payload": key["payload"]})),
        ("bind", json!({"board": board, "principal": 1, "account": "1.0.1", "origin": origin})),
        ("recover", json!({"board": board})),
        ("rotate", json!({"board": board})),
        ("retire", json!({"board": board, "fingerprint": key["fingerprint"]})),
        ("handoff", json!({"board": board, "account": "1.0.1.2"})),
        ("accept", json!({"board": board, "address": "1.0.1.2"})),
    ]
}

/// Checks that `bind` confirms the three facts against the board.
///
/// It confirms them before it appends the line (§4b.1's `bind` row;
/// AUTH-5.32's return leg): a pasted origin that is not the board's is
/// `origin_disagrees`, naming both; a principal the board does not seat at
/// the pasted account is `account_disagrees`, naming the one it seats; an
/// account of another spelling is `malformed_args` naming `account` — each
/// appending nothing; and the claim's own facts are answered `{}`, the
/// binding line appended once more, the newest winning (the mutants that
/// drop the origin's check bind this board's key for a paste meant for
/// another, take any seated principal, or answer `{}` with no line
/// appended).
#[test]
fn bind_confirms_the_three_facts_against_the_board() {
    let dir = TempDir::new().unwrap();
    let sd = spawn(&dir.path().join("board"), true);
    let origin = format!("http://127.0.0.1:{}", sd.port());
    let store = dir.path().join("store");
    claim_board(&origin, &store);
    let (shell, lines) = open_shell(&origin, &store, SessionMode::Bare { principal: 1 });
    let board = shell.board_references().remove(0);
    let bindings = || -> usize { shell.call("fingerprint", &json!({})).unwrap().as_array().unwrap().iter().map(|row| row["bindings"].as_array().unwrap().len()).sum() };
    let bind = |principal: u64, account: &str, pasted: &str| shell.call("bind", &json!({"board": board, "principal": principal, "account": account, "origin": pasted}));
    let before = bindings();
    let elsewhere = bind(1, "1.0.1", "http://127.0.0.1:1").unwrap_err().to_value();
    assert_eq!(
        (elsewhere["name"].as_str(), elsewhere["pasted"].as_str(), elsewhere["dialed"].as_str()),
        (Some("origin_disagrees"), Some("http://127.0.0.1:1"), Some(origin.as_str())),
        "{elsewhere}"
    );
    let unseated = bind(2, "1.0.1", &origin).unwrap_err().to_value();
    assert_eq!((unseated["name"].as_str(), unseated["pasted_principal"].as_u64(), unseated["seated"].as_u64()), (Some("account_disagrees"), Some(2), Some(1)), "{unseated}");
    let misspelled = bind(1, "1.0.x", &origin).unwrap_err().to_value();
    assert_eq!((misspelled["name"].as_str(), misspelled["what"].as_str()), (Some("malformed_args"), Some("account")), "{misspelled}");
    assert_eq!(bindings(), before, "a refused bind appends nothing");
    let bound = bind(1, "1.0.1", &origin).unwrap_or_else(|r| panic!("{r}\n{}", lines.lock().unwrap().join("\n")));
    crate::shapes::assert_declared("Bound", &bound);
    assert_eq!(bound, json!({}));
    assert_eq!(bindings(), before + 1, "the line is appended once more");
    shell.shutdown();
    sd.shutdown();
}

/// Checks that a ceremony from a shell finding another's lock is refused
/// `another_window`, and goes out from the shell that holds the store (§3c.3;
/// skep #829, ruled with the held store's shape (vi): a second window runs
/// no ceremony while the first stands).
///
/// Shell A's session takes the board's held store; shell B over the same
/// data directory opens a session that finds it A's. B's `keygen` dials
/// nothing and goes; each of B's `claim`, `enroll`, `bind`, `recover`,
/// `rotate`, `retire`, `handoff` and `accept` is refused `another_window`
/// naming the call, the board's position unmoved. From A, which holds the
/// store, `enroll` of B's key, `retire` of it, `handoff`'s first beat, and
/// `bind` go out and are answered, and `rotate` goes out last — it retires
/// A's own key (the mutant that leaves the ceremonies off the door runs a
/// rotation or a hand-off from the second window under the first's held
/// lines, which then fail against a board whose keys or claimant moved
/// under them).
#[test]
fn a_ceremony_from_a_shell_finding_anothers_lock_is_refused_and_goes_out_from_the_shell_that_holds_the_store() {
    let dir = TempDir::new().unwrap();
    let sd = spawn(&dir.path().join("board"), true);
    let origin = format!("http://127.0.0.1:{}", sd.port());
    let store = dir.path().join("store");
    claim_board(&origin, &store);
    let (a, a_said) = open_shell(&origin, &store, SessionMode::Signed { principal: 1 });
    let seen = Arc::new(Mutex::new(Vec::new()));
    let a_answerer = answer_moments(a.subscribe(), Arc::clone(&a.pending), Arc::clone(&seen));
    let a_board = a.board_references().remove(0);
    let opened = a.call("session", &json!({"board": a_board})).unwrap();
    assert!(opened.get("another_window").is_none(), "premise: A's open takes the store: {opened}");
    let (b, b_said) = open_shell(&origin, &store, SessionMode::Signed { principal: 1 });
    let b_answerer = answer_moments(b.subscribe(), Arc::clone(&b.pending), Arc::new(Mutex::new(Vec::new())));
    let b_board = b.board_references().remove(0);
    let opened = b.call("session", &json!({"board": b_board})).unwrap();
    assert_eq!(opened["another_window"], true, "premise: B finds the store A's: {opened}\n{}", b_said.lock().unwrap().join("\n"));
    let talked = || format!("{}\n{}", a_said.lock().unwrap().join("\n"), b_said.lock().unwrap().join("\n"));
    let position = || a.call("health", &json!({"board": a_board})).unwrap()["health"]["log_position"].as_u64().unwrap();
    let kb = b.call("keygen", &json!({"label": "second"})).unwrap_or_else(|r| panic!("keygen dials nothing and meets no door: {r}"));
    let before = position();
    for (call, args) in eight_ceremonies(&b_board, &origin, &kb) {
        let refused = b.call(call, &args).unwrap_err();
        let v = refused.to_value();
        assert_eq!((refused.name(), v["kind"].as_str(), v["call"].as_str()), ("another_window", Some("shell"), Some(call)), "{call}: {v}");
    }
    assert_eq!(position(), before, "nothing of the eight is sent from the second window");
    // From the shell that holds the store, the same ceremonies go out.
    let enrolled = a.call("enroll", &json!({"board": a_board, "payload": kb["payload"]})).unwrap_or_else(|r| panic!("enroll from A: {r}\n{}", talked()));
    crate::shapes::assert_declared("Enrolled", &enrolled);
    assert_eq!(enrolled["fingerprints"], json!([kb["fingerprint"]]), "{enrolled}");
    let retired = a.call("retire", &json!({"board": a_board, "fingerprint": kb["fingerprint"]})).unwrap_or_else(|r| panic!("retire from A: {r}\n{}", talked()));
    assert_eq!(retired, json!({}));
    let handed = a.call("handoff", &json!({"board": a_board, "account": "1.0.1.2"})).unwrap_or_else(|r| panic!("handoff from A: {r}\n{}", talked()));
    crate::shapes::assert_declared("HandoffDelegated", &handed);
    let bound = a.call("bind", &json!({"board": a_board, "principal": 1, "account": "1.0.1", "origin": origin})).unwrap_or_else(|r| panic!("bind from A: {r}\n{}", talked()));
    crate::shapes::assert_declared("Bound", &bound);
    let rotated = a.call("rotate", &json!({"board": a_board})).unwrap_or_else(|r| panic!("rotate from A: {r}\n{}", talked()));
    crate::shapes::assert_declared("Rotated", &rotated);
    assert!(position() > before, "the ceremonies from the shell that holds the store went out");
    a.shutdown();
    b.shutdown();
    drop((a, b));
    a_answerer.join().unwrap();
    b_answerer.join().unwrap();
    sd.shutdown();
}

/// Checks that a ceremony from a shell with no session is refused
/// `another_window` while another shell holds the store (§3c.3; skep #880).
///
/// Shell A opens no session: its `bind` of the claim's own facts touches the
/// board's held store at the door, taking the pending lock and the board's
/// own, and goes out. Shell B over the same data directory opens no session
/// either, and its first acts are the eight writing ceremonies, made at
/// once, inside its first probe: each is refused `another_window` naming the
/// call, the board's position unmoved, the state said once in B's own window
/// and emitted once as `another-window`. From A, which holds the store,
/// `enroll` of a new key, `retire` of it, `handoff`'s first beat and
/// `rotate` go out (the mutant whose door reads the state as last set,
/// touching nothing, leaves A holding no lock of the board's and lets B's
/// claim through).
#[test]
fn a_ceremony_from_a_shell_with_no_session_is_refused_while_another_holds_the_store() {
    let dir = TempDir::new().unwrap();
    let sd = spawn(&dir.path().join("board"), true);
    let origin = format!("http://127.0.0.1:{}", sd.port());
    let store = dir.path().join("store");
    claim_board(&origin, &store);
    let (pending, own) = (HeldDir::pending(&store, &Origin::parse(&origin).unwrap()), HeldDir::new(&store, chain_of(&origin)));
    let (a, a_said) = open_shell(&origin, &store, SessionMode::Signed { principal: 1 });
    let a_answerer = answer_moments(a.subscribe(), Arc::clone(&a.pending), Arc::new(Mutex::new(Vec::new())));
    let a_board = a.board_references().remove(0);
    let bound = a.call("bind", &json!({"board": a_board, "principal": 1, "account": "1.0.1", "origin": origin})).unwrap_or_else(|r| panic!("bind from A: {r}\n{}", a_said.lock().unwrap().join("\n")));
    crate::shapes::assert_declared("Bound", &bound);
    assert!(taken(&pending) && taken(&own), "premise: A's door took both of the board's locks:\n{}", a_said.lock().unwrap().join("\n"));
    let kb = a.call("keygen", &json!({"label": "second"})).unwrap();
    let position = || a.call("health", &json!({"board": a_board})).unwrap()["health"]["log_position"].as_u64().unwrap();
    let before = position();
    let (b, b_said) = open_shell(&origin, &store, SessionMode::Signed { principal: 1 });
    let b_events = b.subscribe();
    let b_answerer = answer_moments(b.subscribe(), Arc::clone(&b.pending), Arc::new(Mutex::new(Vec::new())));
    let b_board = b.board_references().remove(0);
    let talked = || format!("{}\n{}", a_said.lock().unwrap().join("\n"), b_said.lock().unwrap().join("\n"));
    for (call, args) in eight_ceremonies(&b_board, &origin, &kb) {
        let refused = match b.call(call, &args) {
            Ok(answered) => panic!("{call} from a shell with no session went out beside the shell that holds the store: {answered}\n{}", talked()),
            Err(refused) => refused,
        };
        let v = refused.to_value();
        assert_eq!((refused.name(), v["kind"].as_str(), v["call"].as_str()), ("another_window", Some("shell"), Some(call)), "{call}: {v}");
    }
    assert_eq!(position(), before, "nothing of the eight is sent from the second window");
    let said: Vec<String> = b_said.lock().unwrap().iter().filter(|l| l.contains("another shell holds this board's held store")).cloned().collect();
    assert_eq!(said.len(), 1, "the state is said once in B's own window: {said:?}");
    assert_eq!(edges(&b_events), [true], "the state is emitted once, as it begins");
    // From the shell that holds the store, the ceremonies go out.
    let enrolled = a.call("enroll", &json!({"board": a_board, "payload": kb["payload"]})).unwrap_or_else(|r| panic!("enroll from A: {r}\n{}", talked()));
    crate::shapes::assert_declared("Enrolled", &enrolled);
    assert_eq!(enrolled["fingerprints"], json!([kb["fingerprint"]]), "{enrolled}");
    let retired = a.call("retire", &json!({"board": a_board, "fingerprint": kb["fingerprint"]})).unwrap_or_else(|r| panic!("retire from A: {r}\n{}", talked()));
    assert_eq!(retired, json!({}));
    let handed = a.call("handoff", &json!({"board": a_board, "account": "1.0.1.2"})).unwrap_or_else(|r| panic!("handoff from A: {r}\n{}", talked()));
    crate::shapes::assert_declared("HandoffDelegated", &handed);
    let rotated = a.call("rotate", &json!({"board": a_board})).unwrap_or_else(|r| panic!("rotate from A: {r}\n{}", talked()));
    crate::shapes::assert_declared("Rotated", &rotated);
    assert!(position() > before, "the ceremonies from the shell that holds the store went out");
    a.shutdown();
    b.shutdown();
    drop((a, b));
    a_answerer.join().unwrap();
    b_answerer.join().unwrap();
    sd.shutdown();
}

/// Checks that a ceremony from a shell with no session is refused where
/// another holds the board's own lock alone (§3c.3; skep #828, #880).
///
/// The board's own held directory, named by its chain, is locked by another
/// holder and its pending one is free. Shell B opens no session, and its
/// `claim` is refused `another_window` naming the call, the board's position
/// unmoved: its door's touch read the board's head and found the board's own
/// lock held, so B stands another shell's — said once in its own window and
/// emitted `true`. Once the other holder lets go, B's `bind` of the claim's
/// own facts touches the store again, takes both locks and goes out, the
/// state's end said once and emitted `false` (the mutant whose touch tries
/// the pending lock alone, reading no head, lets the claim through for the
/// shell's life; the one that touches a store once and never again refuses
/// the bind).
#[test]
fn a_ceremony_from_a_shell_with_no_session_is_refused_where_another_holds_the_boards_own_lock_alone() {
    let dir = TempDir::new().unwrap();
    let sd = spawn(&dir.path().join("board"), true);
    let origin = format!("http://127.0.0.1:{}", sd.port());
    let store = dir.path().join("store");
    claim_board(&origin, &store);
    let (pending, own) = (HeldDir::pending(&store, &Origin::parse(&origin).unwrap()), HeldDir::new(&store, chain_of(&origin)));
    own.ensure().unwrap();
    let held = own.try_lock().unwrap().expect("premise: the board's own lock is free once the claim's shell stopped");
    let (b, b_said) = open_shell(&origin, &store, SessionMode::Signed { principal: 1 });
    let b_events = b.subscribe();
    let b_answerer = answer_moments(b.subscribe(), Arc::clone(&b.pending), Arc::new(Mutex::new(Vec::new())));
    let b_board = b.board_references().remove(0);
    let talked = || b_said.lock().unwrap().join("\n");
    let position = || b.call("health", &json!({"board": b_board})).unwrap()["health"]["log_position"].as_u64().unwrap();
    let before = position();
    let refused = match b.call("claim", &json!({"board": b_board})) {
        Ok(answered) => panic!("the claim from a shell with no session went out beside the board's own lock: {answered}\n{}", talked()),
        Err(refused) => refused.to_value(),
    };
    assert_eq!((refused["name"].as_str(), refused["call"].as_str()), (Some("another_window"), Some("claim")), "{refused}\n{}", talked());
    assert_eq!(position(), before, "nothing of the claim is sent");
    drop(held);
    let bound = b.call("bind", &json!({"board": b_board, "principal": 1, "account": "1.0.1", "origin": origin})).unwrap_or_else(|r| panic!("bind from B once the lock is let go: {r}\n{}", talked()));
    crate::shapes::assert_declared("Bound", &bound);
    assert!(taken(&pending) && taken(&own), "B's touch took both of the board's locks:\n{}", talked());
    assert_eq!(edges(&b_events), [true, false], "the state is emitted at its two edges");
    let said = |text: &str| b_said.lock().unwrap().iter().filter(|l| l.contains(text)).count();
    assert_eq!((said("another shell holds this board's held store"), said("this shell holds this board's held store now")), (1, 1), "each edge is said once:\n{}", talked());
    b.shutdown();
    drop(b);
    b_answerer.join().unwrap();
    sd.shutdown();
}

/// Checks that a retirement by another hand ends a session on its arm.
///
/// It is §4b.2's `retired` arm (AUTH-5.77): a second device's key enrolled
/// from the first device (`enroll`), bound on the second (`bind`) and
/// retiring the first's key from there (`retire`) — and the first device's
/// signed session dies on the `retired` arm naming its key, the hand that
/// retired it and that hand's label off the admitted read, the retirement's
/// position, and `own` false, since no key of the first device's store
/// wrote it (the mutants that read the hand as the store's own, or name the
/// retired key's label for the hand's, face the page a rotation's expected
/// end where another hand evicted the device); the three walks' answers held
/// to their declarations.
#[test]
fn a_retirement_by_another_hand_ends_a_session_on_the_arm_that_names_it() {
    let dir = TempDir::new().unwrap();
    let sd = spawn(&dir.path().join("board"), true);
    let origin = format!("http://127.0.0.1:{}", sd.port());
    let (store_a, store_b) = (dir.path().join("store-a"), dir.path().join("store-b"));
    claim_board(&origin, &store_a);
    let (first, first_said) = open_shell(&origin, &store_a, SessionMode::Signed { principal: 1 });
    let (second, second_said) = open_shell(&origin, &store_b, SessionMode::Signed { principal: 1 });
    let seen = Arc::new(Mutex::new(Vec::new()));
    let first_answerer = answer_moments(first.subscribe(), Arc::clone(&first.pending), Arc::clone(&seen));
    let second_answerer = answer_moments(second.subscribe(), Arc::clone(&second.pending), Arc::new(Mutex::new(Vec::new())));
    let talked = || format!("{}\n{}", first_said.lock().unwrap().join("\n"), second_said.lock().unwrap().join("\n"));
    let (board, second_board) = (first.board_references().remove(0), second.board_references().remove(0));
    let rows = first.call("fingerprint", &json!({})).unwrap();
    let k1 = rows.as_array().unwrap().iter().find(|row| row["label"] == "notebook").expect("the claim's key")["fingerprint"].as_str().unwrap().to_string();
    let kb = second.call("keygen", &json!({"label": "second"})).unwrap();
    let session = first.call("session", &json!({"board": board})).unwrap()["session"].as_str().unwrap().to_string();
    let enrolled = first.call("enroll", &json!({"board": board, "payload": kb["payload"]})).unwrap_or_else(|r| panic!("{r}\n{}", talked()));
    crate::shapes::assert_declared("Enrolled", &enrolled);
    assert_eq!(enrolled["fingerprints"], json!([kb["fingerprint"]]), "{enrolled}");
    let bound = second.call("bind", &json!({"board": second_board, "principal": 1, "account": "1.0.1", "origin": origin})).unwrap_or_else(|r| panic!("{r}\n{}", talked()));
    crate::shapes::assert_declared("Bound", &bound);
    assert!(bound.get("warning").is_none(), "the binding is recorded: {bound}");
    let retired = second.call("retire", &json!({"board": second_board, "fingerprint": k1})).unwrap_or_else(|r| panic!("{r}\n{}", talked()));
    assert_eq!(retired, json!({}));
    let died = wait_for(&seen, |e| e.name == EventName::SessionDied && e.data["session"] == session);
    let reason = &died.data["reason"];
    assert_eq!(
        (reason["arm"].as_str(), reason["fingerprint"].as_str(), reason["own"].as_bool(), reason["hand"].as_str(), reason["label"].as_str()),
        (Some("retired"), Some(k1.as_str()), Some(false), kb["fingerprint"].as_str(), Some("second")),
        "{reason}\n{}",
        talked()
    );
    assert!(reason["position"].is_u64(), "the retirement's position: {reason}");
    first.shutdown();
    second.shutdown();
    drop((first, second));
    first_answerer.join().unwrap();
    second_answerer.join().unwrap();
    sd.shutdown();
}

/// Checks that a rotation ends its old key's session on the own hand's arm.
///
/// It is §4b.2's `retired` arm (AUTH-5.28's expected end): with a signed
/// session open, the rotation (`rotate`) enrolls a new key — its device-name
/// box prefilled from the old key's label, answered with that default — and
/// retires the old key under the old key's own hand, and the session dies on
/// the `retired` arm naming the old key as both the key retired and the
/// hand, its label, the retirement's position, and `own` true, the hand
/// being the session's own key (AUTH-5.28: "the token's own key as its
/// hand"; the mutant that answers a retirement by this store's key `false`
/// faces the person's own rotation as another hand's eviction); the
/// rotation's answer held to its declaration, its new key this store's.
#[test]
fn a_rotation_ends_its_old_keys_session_on_the_own_hands_arm() {
    let dir = TempDir::new().unwrap();
    let sd = spawn(&dir.path().join("board"), true);
    let origin = format!("http://127.0.0.1:{}", sd.port());
    let store = dir.path().join("store");
    claim_board(&origin, &store);
    let (shell, lines) = open_shell(&origin, &store, SessionMode::Signed { principal: 1 });
    let seen = Arc::new(Mutex::new(Vec::new()));
    let answerer = answer_moments(shell.subscribe(), Arc::clone(&shell.pending), Arc::clone(&seen));
    let board = shell.board_references().remove(0);
    let keys = || -> Vec<String> { shell.call("fingerprint", &json!({})).unwrap().as_array().unwrap().iter().map(|row| row["fingerprint"].as_str().unwrap().to_string()).collect() };
    let [k1]: [String; 1] = keys().try_into().expect("the claim's key, the store's only one");
    let session = shell.call("session", &json!({"board": board})).unwrap()["session"].as_str().unwrap().to_string();
    let rotated = shell.call("rotate", &json!({"board": board})).unwrap_or_else(|r| panic!("{r}\n{}", lines.lock().unwrap().join("\n")));
    crate::shapes::assert_declared("Rotated", &rotated);
    let new = rotated["new"].as_str().unwrap().to_string();
    assert_eq!(rotated["old"], k1, "{rotated}");
    assert!(new != k1 && keys().contains(&new), "the new key is this store's: {rotated}");
    let died = wait_for(&seen, |e| e.name == EventName::SessionDied && e.data["session"] == session);
    let reason = &died.data["reason"];
    assert_eq!(
        (reason["arm"].as_str(), reason["fingerprint"].as_str(), reason["own"].as_bool(), reason["hand"].as_str(), reason["label"].as_str()),
        (Some("retired"), Some(k1.as_str()), Some(true), Some(k1.as_str()), Some("notebook")),
        "{reason}"
    );
    assert!(reason["position"].is_u64(), "the retirement's position: {reason}");
    shell.shutdown();
    drop(shell);
    answerer.join().unwrap();
    sd.shutdown();
}

/// Checks that a self-retirement is the own hand's arm though the store
/// cannot be listed.
///
/// It is §4b.2's `retired` arm read off the session's own key (AUTH-5.28:
/// "the token's own key as its hand"): the claim's key copied into a second
/// store, bound there and retiring itself from it, while a file the first
/// store cannot read as a key stops that store's listing — and the first
/// store's session dies on the `retired` arm naming the key as both the key
/// retired and the hand, its label, the retirement's position, and `own`
/// true, asked of no listing; the listing's failure is said once on `Talk`,
/// naming the file and the session, and the reason names nothing of the
/// store (SP-12; the mutants that read a store it cannot list as one holding
/// no keys, or a self-retirement beside it as unsaid, face the person's own
/// act as another hand's or as neither, and the one that drops the line
/// leaves the store's failure said nowhere).
#[test]
fn a_self_retirement_is_the_own_hands_arm_though_the_store_cannot_be_listed() {
    let dir = TempDir::new().unwrap();
    let sd = spawn(&dir.path().join("board"), true);
    let origin = format!("http://127.0.0.1:{}", sd.port());
    let (store, twin) = (dir.path().join("store"), dir.path().join("twin"));
    claim_board(&origin, &store);
    let (first, first_said) = open_shell(&origin, &store, SessionMode::Signed { principal: 1 });
    let seen = Arc::new(Mutex::new(Vec::new()));
    let first_answerer = answer_moments(first.subscribe(), Arc::clone(&first.pending), Arc::clone(&seen));
    let board = first.board_references().remove(0);
    let rows = first.call("fingerprint", &json!({})).unwrap();
    let k1 = rows.as_array().unwrap().iter().find(|row| row["label"] == "notebook").expect("the claim's key")["fingerprint"].as_str().unwrap().to_string();
    let session = first.call("session", &json!({"board": board})).unwrap()["session"].as_str().unwrap().to_string();
    // The same key in a second store, bound there, which retires it.
    let key_file = format!("{k1}.key");
    std::fs::create_dir_all(twin.join("keys")).unwrap();
    std::fs::copy(store.join("keys").join(&key_file), twin.join("keys").join(&key_file)).unwrap();
    let (second, second_said) = open_shell(&origin, &twin, SessionMode::Signed { principal: 1 });
    let second_answerer = answer_moments(second.subscribe(), Arc::clone(&second.pending), Arc::new(Mutex::new(Vec::new())));
    let talked = || format!("{}\n{}", first_said.lock().unwrap().join("\n"), second_said.lock().unwrap().join("\n"));
    let second_board = second.board_references().remove(0);
    let bound = second.call("bind", &json!({"board": second_board, "principal": 1, "account": "1.0.1", "origin": origin})).unwrap_or_else(|r| panic!("{r}\n{}", talked()));
    assert!(bound.get("warning").is_none(), "the binding is recorded: {bound}");
    // A file the first store cannot read as a key: its listing stops.
    std::fs::write(store.join("keys").join("stray.key"), b"not a key file").unwrap();
    let retired = second.call("retire", &json!({"board": second_board, "fingerprint": k1})).unwrap_or_else(|r| panic!("{r}\n{}", talked()));
    assert_eq!(retired, json!({}));
    let died = wait_for(&seen, |e| e.name == EventName::SessionDied && e.data["session"] == session);
    let reason = &died.data["reason"];
    assert_eq!(
        (reason["arm"].as_str(), reason["fingerprint"].as_str(), reason["own"].as_bool(), reason["hand"].as_str(), reason["label"].as_str()),
        (Some("retired"), Some(k1.as_str()), Some(true), Some(k1.as_str()), Some("notebook")),
        "{reason}\n{}",
        talked()
    );
    assert!(reason["position"].is_u64(), "the retirement's position: {reason}");
    let said: Vec<String> = first_said.lock().unwrap().iter().filter(|l| l.contains("stray.key")).cloned().collect();
    assert!(said.len() == 1 && said[0].contains(&session), "the listing's failure is said once, naming its file and the session: {said:?}");
    assert!(!reason.to_string().contains(&store.display().to_string()), "the reason names nothing of the store: {reason}");
    first.shutdown();
    second.shutdown();
    drop((first, second));
    first_answerer.join().unwrap();
    second_answerer.join().unwrap();
    sd.shutdown();
}

/// Checks that another hand's retirement is answered `own` unknown where the
/// store cannot be listed.
///
/// It is §4b.2's `retired` arm where whether the hand is this store's own
/// cannot be said: a second device's key enrolled from the first device,
/// bound on the second and retiring the first's key, while a file the first
/// store cannot read as a key stops that store's listing — and the first
/// device's session dies on the `retired` arm naming the hand and its label
/// off the admitted read and the retirement's position, and `own` null, the
/// face that asserts neither arm (AUTH-5.77); the listing's failure is said
/// once on `Talk`, naming the file (SP-14, SP-12; the mutant that reads the
/// failed listing as a store holding no keys answers `own` false, another
/// device's act asserted on a fact never read).
#[test]
fn another_hands_retirement_is_answered_own_unknown_where_the_store_cannot_be_listed() {
    let dir = TempDir::new().unwrap();
    let sd = spawn(&dir.path().join("board"), true);
    let origin = format!("http://127.0.0.1:{}", sd.port());
    let (store_a, store_b) = (dir.path().join("store-a"), dir.path().join("store-b"));
    claim_board(&origin, &store_a);
    let (first, first_said) = open_shell(&origin, &store_a, SessionMode::Signed { principal: 1 });
    let (second, second_said) = open_shell(&origin, &store_b, SessionMode::Signed { principal: 1 });
    let seen = Arc::new(Mutex::new(Vec::new()));
    let first_answerer = answer_moments(first.subscribe(), Arc::clone(&first.pending), Arc::clone(&seen));
    let second_answerer = answer_moments(second.subscribe(), Arc::clone(&second.pending), Arc::new(Mutex::new(Vec::new())));
    let talked = || format!("{}\n{}", first_said.lock().unwrap().join("\n"), second_said.lock().unwrap().join("\n"));
    let (board, second_board) = (first.board_references().remove(0), second.board_references().remove(0));
    let rows = first.call("fingerprint", &json!({})).unwrap();
    let k1 = rows.as_array().unwrap().iter().find(|row| row["label"] == "notebook").expect("the claim's key")["fingerprint"].as_str().unwrap().to_string();
    let kb = second.call("keygen", &json!({"label": "second"})).unwrap();
    let session = first.call("session", &json!({"board": board})).unwrap()["session"].as_str().unwrap().to_string();
    first.call("enroll", &json!({"board": board, "payload": kb["payload"]})).unwrap_or_else(|r| panic!("{r}\n{}", talked()));
    // A file the first store cannot read as a key: its listing stops.
    std::fs::write(store_a.join("keys").join("stray.key"), b"not a key file").unwrap();
    let bound = second.call("bind", &json!({"board": second_board, "principal": 1, "account": "1.0.1", "origin": origin})).unwrap_or_else(|r| panic!("{r}\n{}", talked()));
    assert!(bound.get("warning").is_none(), "the binding is recorded: {bound}");
    let retired = second.call("retire", &json!({"board": second_board, "fingerprint": k1})).unwrap_or_else(|r| panic!("{r}\n{}", talked()));
    assert_eq!(retired, json!({}));
    let died = wait_for(&seen, |e| e.name == EventName::SessionDied && e.data["session"] == session);
    let reason = &died.data["reason"];
    assert_eq!(
        (reason["arm"].as_str(), reason["fingerprint"].as_str(), reason.get("own"), reason["hand"].as_str(), reason["label"].as_str()),
        (Some("retired"), Some(k1.as_str()), Some(&Value::Null), kb["fingerprint"].as_str(), Some("second")),
        "{reason}\n{}",
        talked()
    );
    assert!(reason["position"].is_u64(), "the retirement's position: {reason}");
    let said: Vec<String> = first_said.lock().unwrap().iter().filter(|l| l.contains("stray.key")).cloned().collect();
    assert!(said.len() == 1 && said[0].contains(&session), "the listing's failure is said once, naming its file and the session: {said:?}");
    assert!(!reason.to_string().contains(&store_a.display().to_string()), "the reason names nothing of the store: {reason}");
    first.shutdown();
    second.shutdown();
    drop((first, second));
    first_answerer.join().unwrap();
    second_answerer.join().unwrap();
    sd.shutdown();
}
