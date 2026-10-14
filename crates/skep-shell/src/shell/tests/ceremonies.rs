//! THE CEREMONIAL ROWS END TO END against the real daemon in-process:
//! `bind` confirming the three facts against the board before it appends
//! the line; a second device's key enrolled from the first device, bound
//! there and retiring the first's key, whose session dies on the arm that
//! names the hand; and a rotation ending its old key's session on the own
//! hand's arm — each death read for its hand, each answer held to its
//! declaration.

use super::*;

/// `bind` CONFIRMS THE THREE FACTS AGAINST THE BOARD before it appends the
/// line (§4b.1's `bind` row; AUTH-5.32's return leg): a pasted origin that
/// is not the board's is `origin_disagrees`, naming both; a principal the
/// board does not seat at the pasted account is `account_disagrees`,
/// naming the one it seats; an account of another spelling is
/// `malformed_args` naming `account` — each appending nothing; and the
/// claim's own facts are answered `{}`, the binding line appended once
/// more, the newest winning (the mutants that drop the origin's check bind
/// this board's key for a paste meant for another, take any seated
/// principal, or answer `{}` with no line appended).
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

/// A RETIREMENT BY ANOTHER HAND ENDS A SESSION ON THE ARM THAT NAMES IT
/// (§4b.2's `retired` arm; AUTH-5.77): a second device's key enrolled from
/// the first device (`enroll`), bound on the second (`bind`) and retiring
/// the first's key from there (`retire`) — and the first device's signed
/// session dies on the `retired` arm naming its key, the hand that retired
/// it and that hand's label off the admitted read, the retirement's
/// position, and `own` false, since no key of the first device's store
/// wrote it (the mutants that read the hand as the store's own, or name
/// the retired key's label for the hand's, face the page a rotation's
/// expected end where another hand evicted the device); every answer held
/// to its declaration.
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

/// A ROTATION ENDS ITS OLD KEY's SESSION ON THE OWN HAND's ARM (§4b.2's
/// `retired` arm; AUTH-5.28's expected end): with a signed session open,
/// the rotation (`rotate`) enrolls a new key — its device-name box
/// prefilled from the old key's label, answered with that default — and
/// retires the old key under the old key's own hand, and the session dies
/// on the `retired` arm naming the old key as both the key retired and the
/// hand, its label, the retirement's position, and `own` true, since this
/// store's key wrote it (the mutant that reads no store's keys faces the
/// person's own rotation as another hand's eviction); the rotation's answer
/// held to its declaration, its new key this store's.
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
