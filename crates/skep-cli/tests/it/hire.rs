//! The twentieth command through the binary (`skep hire`; AUTH-5.58), and
//! `skep bind` at the account it makes.
//!
//! The walk itself is the library's, fenced beat by beat under the scripted
//! person in `skep-client`'s `tests/it/hire.rs`; here, what the command
//! adds: its line read whole ahead of its door — no `--payload`, a
//! `--replaces` that is no address, a key file, the two arms at once, each
//! exit 2 with nothing dialed and nothing written; its door, a person door
//! naming its own moments, refused without a controlling terminal; one run
//! under a pseudo-terminal, typed as a person types it, from the standing
//! statements to the principal on stdout; and `skep bind` at a hired
//! agent's account, refused plainly before any write.

use std::path::Path;

use skep_client::board::{Board, KeySetAnswer};
use skep_client::ceremony::claim::{self, ClaimOutcome, NotebookOptions};
use skep_client::ceremony::first_session::document_present;
use skep_client::ceremony::hire::{hire, HireOptions, Hired};
use skep_client::derive::principal_of;
use skep_client::dial::PlainHttp;
use skep_client::person::scripted::{Script, Scripted};
use skep_client::sheet::Label;
use skep_client::store::{FileStore, KeyStore};
use skep_client::Origin;

use crate::common::{origin, s, skep, spawn, tree};

/// A board its owner claimed through the library, on an ENFORCING daemon:
/// the owner's store holds their device key, their line and the agent
/// space's.
fn claimed(board_origin: &str, store: &Path, anchors: &Path) -> Board {
    let board = Board::new(Origin::parse(board_origin).unwrap(), PlainHttp::new());
    let store = FileStore::open(store);
    store.generate(Some(Label::new("owner laptop").unwrap())).unwrap();
    let mut person = Scripted::new(vec![Script::LabelDefault, Script::LabelDefault]);
    let opts = NotebookOptions { principal: None, display_name: Some("a name".into()), anchor_out: vec![anchors.join("a"), anchors.join("b")], paper: false, host_name: "testhost".into(), date: "2026-11-15".into() };
    let ClaimOutcome::Ours(_) = claim::notebook(&board, &store, &mut person, &opts).unwrap_or_else(|h| panic!("{h}\n{}", person.transcript.join("\n"))) else { panic!("a stranger's board") };
    board
}

/// An agent's host through the binary: `skep keygen --payload` into a store
/// of its own. Answers the record it printed and the key's fingerprint.
fn agent_keygen(store: &Path, label: &str) -> (String, String) {
    let r = skep(&["keygen", "--label", label, "--payload", "--dir", s(store)], &[], None);
    assert_eq!(r.code, 0, "{r:?}");
    assert!(r.err.contains("Where it is an AGENT's working key: hand this payload to the owner hiring the agent, who runs `skep hire --payload`"), "keygen names the hire's arm: {}", r.err);
    (r.lines()[0].to_string(), r.lines()[1].to_string())
}

/// THE LINE IS READ WHOLE AHEAD OF THE DOOR (§2.3's exit 2): `hire` without
/// `--payload`, with a `--replaces` that is no address, with a key file its
/// walk cannot take, and with both arms at once, each names what is wrong
/// before any terminal check, any dial and any write; and the help lists
/// the command, its flags and its two arms.
#[test]
fn hires_usage_refusals_are_judged_ahead_of_its_door_and_the_help_names_it() {
    let dir = tempfile::tempdir().unwrap();
    let store = dir.path().join("store");
    let payload = dir.path().join("p.json");
    std::fs::write(&payload, "{}").unwrap();
    let dead = "http://127.0.0.1:1";
    let base = ["hire", "--board", dead, "--dir", s(&store), "--principal", "1"];
    fn joined<'a>(base: &[&'a str], more: &[&'a str]) -> Vec<&'a str> {
        [base, more].concat()
    }
    for (args, refusal) in [
        (joined(&base, &[]), "--payload <file|-> is required: the agent's key record, as `skep keygen --payload` printed it on the agent's host"),
        (joined(&base, &["--payload", s(&payload), "--replaces", "1.0.1..1"]), "--replaces: '1.0.1..1' is not an address (the wire's dotted spelling)"),
        (joined(&base, &["--payload", s(&payload), "--key", "/x"]), "`--key` (or SKEP_KEY) names a key file, and `skep hire` selects its key from the store's lookup alone"),
        (joined(&base, &["--payload", s(&payload), "--anchorless", "--paper"]), "`--anchorless` and `--paper` belong to two forms of `hire`: give one"),
        (joined(&base, &["--payload", s(&payload), "--anchorless", "--anchor-out", "/a"]), "`--anchorless` and `--anchor-out` belong to two forms of `hire`: give one"),
        (joined(&base, &["--payload", s(&payload), "--anchor-out", "/a", "--anchor-out", "/b", "--anchor-out", "/c"]), "`--anchor-out` is given at most 2 times at `hire`"),
        (joined(&base, &["--payload", s(&payload), "--anchor-label", "x"]), "`--anchor-label` is not a flag of `hire`"),
    ] {
        let r = skep(&args, &[], None);
        assert_eq!(r.code, 2, "{args:?}: {r:?}");
        assert!(r.err.contains(refusal), "{args:?}: {}", r.err);
        assert!(!r.err.contains("controlling terminal"), "ahead of the door: {}", r.err);
        assert!(r.out.is_empty(), "{}", r.out);
    }
    assert!(!store.exists(), "nothing written");
    let help = skep(&["--help"], &[], None);
    assert_eq!(help.code, 0);
    assert!(help.out.contains("\n  hire         hire an agent (a person door): make its account beneath"), "{}", help.out);
    assert!(help.out.contains("\n  hire:     --payload <file|->  [--replaces <address>], and the custody"), "{}", help.out);
    assert!(help.out.contains("decline (--anchorless)"), "{}", help.out);
}

/// THE DOOR (§2.4): without a controlling terminal `hire` is exit 3, a
/// halt's face naming the moments a person answers at this door — the
/// backup moment among them, which this door runs — and nothing is dialed
/// or written.
#[test]
fn hire_is_a_person_door_and_refuses_without_a_terminal() {
    let dir = tempfile::tempdir().unwrap();
    let sd = spawn(&dir.path().join("board"), false);
    let board = origin(sd.port());
    let store = dir.path().join("store");
    let payload = dir.path().join("p.json");
    std::fs::write(&payload, "{}").unwrap();
    for arm in [&[][..], &["--anchorless"]] {
        let args = [&["hire", "--board", &board, "--dir", s(&store), "--principal", "1", "--payload", s(&payload)][..], arm].concat();
        let r = skep(&args, &[], None);
        assert_eq!(r.code, 3, "{args:?}: {r:?}");
        assert!(r.err.contains("`hire` is a person door and requires a controlling terminal"), "{}", r.err);
        assert!(
            r.err.contains("\n  cause: what a person answers here — the label boxes and the backup moment, or on the anchorless arm its typed confirmation, and the fingerprint comparison —"),
            "the door's own moments: {}",
            r.err
        );
        assert!(r.err.contains("\n  act: run it at a terminal"), "{}", r.err);
        assert!(r.out.is_empty(), "{}", r.out);
    }
    assert!(!store.exists(), "nothing generated before the check");
}

/// One hire through the library, as the owner at a terminal makes it.
fn hired(board: &Board, owner: &Path, payload: &str, custody: &Path) -> Hired {
    let mut person = Scripted::new(vec![Script::LabelDefault, Script::LabelDefault, Script::Confirm(true)]);
    let opts = HireOptions {
        principal: 1,
        payload: format!("{payload}\n").into_bytes(),
        anchorless: false,
        replaces: None,
        anchor_out: vec![custody.join("a"), custody.join("b")],
        paper: false,
        host_name: "testhost".into(),
        date: "2026-11-15".into(),
    };
    hire(board, &FileStore::open(owner), &mut person, &opts).unwrap_or_else(|h| panic!("the hire halted: {h}\n{}", person.transcript.join("\n")))
}

/// FENCE 14 (the owner's ruling, 2026-11-15): `skep bind` at a hired agent's
/// account refuses plainly, before any write. From the agent's own store,
/// with the facts `skep hire` printed, it is exit 3 naming the account as an
/// agent's and the settings its program takes instead; no landing is asked,
/// nothing is compared — so the owner's custody pair is never read as keys
/// the agent "did not send" — no session opens, the board's head stands
/// where it stood, and the store is as it was: no binding line. The same
/// facts at the OWNER's own account still bind.
#[test]
fn bind_at_a_hired_agents_account_refuses_plainly_and_writes_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let sd = spawn(&dir.path().join("board"), false);
    let origin = origin(sd.port());
    let owner = dir.path().join("owner");
    let board = claimed(&origin, &owner, &dir.path().join("anchors"));
    let agent = dir.path().join("agent");
    let (payload, fingerprint) = agent_keygen(&agent, "scribe");
    let done = hired(&board, &owner, &payload, &dir.path().join("custody"));
    assert_eq!((done.facts.account.as_str(), done.key.to_hex()), ("1.0.1.1.1", fingerprint));
    let principal = done.facts.principal.to_string();
    let head = || {
        let health = board.health().unwrap();
        (health.log_position(), health.body["chain_head"].clone())
    };
    let (before, store_before) = (head(), tree(&agent));
    // Every way the facts can arrive: the flags, and a reply on stdin with
    // a landing answered behind it.
    let reply = format!("account 1.0.1.1.1\nprincipal {principal}\norigin {origin}\n");
    let by_flags = skep(&["bind", "--board", &origin, "--dir", s(&agent), "--account", "1.0.1.1.1", "--principal", &principal], &[], Some(b"alone\n"));
    let by_reply = skep(&["bind", "--board", &origin, "--dir", s(&agent), "--payload", "-"], &[], Some(reply.as_bytes()));
    for r in [by_flags, by_reply] {
        assert_eq!(r.code, 3, "{r:?}");
        assert!(r.err.contains("skep: `skep bind` is not an agent's door: 1.0.1.1.1 is a hired agent's account"), "{}", r.err);
        assert!(r.err.contains("it is a child of the agent space of 1.0.1") && r.err.contains("nothing was written"), "{}", r.err);
        assert!(r.err.contains(&format!("the principal {principal} that `skep hire` printed (`SKEP_PRINCIPAL`)")), "the act names the settings: {}", r.err);
        assert!(!r.err.contains("which landing is this?") && !r.err.contains("you did not send") && !r.err.contains("NOT yours to keep"), "no landing asked, nothing compared: {}", r.err);
        assert!(r.out.is_empty(), "{}", r.out);
    }
    assert_eq!(head(), before, "nothing written to the board");
    assert_eq!(tree(&agent), store_before, "nor to the agent's store: no binding line");
    assert!(!agent.join("bindings").exists());
    assert_eq!(principal_of(&board, "1.0.1.1.1.1").unwrap(), None, "and no space reserved beneath the agent");
    // The agent's key is enrolled, and `verify` — the act the refusal names —
    // says so from the agent's store.
    let v = skep(&["verify", "--board", &origin, "--dir", s(&agent), "--principal", &principal], &[], None);
    assert_eq!(v.code, 0, "{v:?}");
    assert!(v.lines().contains(&"account 1.0.1.1.1"), "{}", v.out);
    // The owner's own account is no agent's: the same command still binds it.
    let r = skep(&["bind", "--board", &origin, "--dir", s(&owner), "--account", "1.0.1", "--principal", "1"], &[], Some(b"hop\n"));
    assert_eq!(r.code, 0, "{r:?}");
    assert!(r.lines().contains(&"account 1.0.1"), "{}", r.out);
}

/// ONE RUN UNDER A PSEUDO-TERMINAL, typed as a person types it: the agent's
/// host prints its record (`skep keygen --payload`), and the owner's `skep
/// hire` — both ends a terminal, stdout a file — says the standing
/// statements, takes the two label boxes at their defaults and the
/// fingerprint's first group, and prints the agent's three facts and its key
/// on stdout, exit 0: the principal the board seats at `X.1.1`, printed
/// after the mint. The board holds the three-entry set and the agent's
/// published home; the owner's store holds the persist-first line and no
/// custody file. A second run with the same record answers the same facts
/// and writes nothing.
#[cfg(any(target_os = "macos", target_os = "linux"))]
#[test]
fn a_hire_typed_at_a_terminal_prints_the_agents_principal_after_the_mint() {
    use crate::common::{on_a_terminal_typing, shell_word};

    let dir = tempfile::tempdir().unwrap();
    let sd = spawn(&dir.path().join("board"), false);
    let origin = origin(sd.port());
    let owner = dir.path().join("owner");
    let board = claimed(&origin, &owner, &dir.path().join("anchors"));
    let (payload, fingerprint) = agent_keygen(&dir.path().join("agent"), "scribe");
    let record = dir.path().join("scribe.json");
    std::fs::write(&record, format!("{payload}\n")).unwrap();
    let custody = dir.path().join("custody");
    let run = |n: usize, typed: &str| {
        let (out, code) = (dir.path().join(format!("out-{n}")), dir.path().join(format!("code-{n}")));
        let command = format!(
            "{} hire --board {} --dir {} --payload {} --anchor-out {} --anchor-out {} > {}; echo $? > {}",
            shell_word(env!("CARGO_BIN_EXE_skep")),
            shell_word(&origin),
            shell_word(s(&owner)),
            shell_word(s(&record)),
            shell_word(s(&custody.join("a"))),
            shell_word(s(&custody.join("b"))),
            shell_word(s(&out)),
            shell_word(s(&code)),
        );
        let seen = on_a_terminal_typing(&command, typed, &code);
        let exit = std::fs::read_to_string(&code).unwrap_or_else(|e| panic!("the run's exit code: {e}: {seen}"));
        (exit.trim().parse::<i32>().unwrap(), std::fs::read_to_string(&out).unwrap_or_default(), seen)
    };
    // The two boxes at their defaults, then the comparison's first group.
    let (exit, out, seen) = run(1, &format!("\n\n{}\n", &fingerprint[..8]));
    assert_eq!(exit, 0, "the hire ran to its end:\n{seen}");
    assert!(!seen.contains("requires a controlling terminal"), "{seen}");
    let lines: Vec<&str> = out.lines().collect();
    let principal = principal_of(&board, "1.0.1.1.1").unwrap().expect("the agent's seat");
    assert_eq!(lines, vec!["account 1.0.1.1.1".to_string(), format!("principal {principal}"), format!("origin {origin}"), format!("key {fingerprint}")], "stdout carries the agent's facts and its key, and nothing else:\n{seen}");
    for said in ["[AUTH-5.78]", "[AUTH-5.79]", "[AUTH-5.80 (home)]", "[AUTH-5.58 step 2 (disavowal)]", "[AUTH-5.44 (hire)]", "name anchor a", "[AUTH-5.58 step 5]", "[AUTH-5.58 step 6]"] {
        assert!(seen.contains(said), "{said} said on the terminal:\n{seen}");
    }
    assert!(seen.contains("hired: 1.0.1.1.1 beneath your agent space 1.0.1.1"), "{seen}");
    let KeySetAnswer::Set(set) = board.key_set("1.0.1.1.1").unwrap() else { panic!("an account") };
    assert_eq!((set.enrolled.len(), set.enrolled.iter().filter(|e| e.anchor).count()), (3, 2));
    assert_eq!(document_present(&board, "1.0.1.1.1.0.1"), Ok(true), "the agent's home, published");
    let store = FileStore::open(&owner);
    assert_eq!(store.persisted_new_id(board.dialed(), "1.0.1.1.1").unwrap(), Some(principal), "the persist-first line");
    assert_eq!(store.principals_at(board.dialed()).unwrap(), vec![1], "and the owner's own commands still need no `--principal`: the first agent's line is a first child's");
    assert_eq!(store.device_keys().unwrap().len(), 1, "no custody key under the owner's store");
    assert_eq!(std::fs::read_dir(custody.join("a")).unwrap().count() + std::fs::read_dir(custody.join("b")).unwrap().count(), 2, "the two sheets, at the owner's venue");
    // The same record again: the hire stands, and nothing is typed.
    let before = board.health().unwrap().log_position();
    let (exit, again, seen) = run(2, "");
    assert_eq!(exit, 0, "{seen}");
    assert_eq!(again, out, "the same facts");
    assert!(seen.contains("this hire already stood, and nothing was written"), "{seen}");
    assert_eq!(board.health().unwrap().log_position(), before, "nothing written");
}
