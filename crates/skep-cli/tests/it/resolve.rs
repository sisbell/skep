//! The eighteenth command through the binary (`skep resolve`; REG-3.7).
//!
//! **The refusals.** A line that names no address or no root hint, and an
//! address or a hint that does not read, are exit 2 before any socket opens
//! and before the mirror's directory is made; a root that did not answer,
//! exit 4; a root that answered as no board, exit 1; an unclaimed board, a
//! root of another realm than the hint's and a copy that does not read,
//! exit 3, the last two naming the mirror's directory — each a named line
//! on stderr with nothing on stdout.
//!
//! **The walk.** Against a claimed board as its registry, an address whose
//! prefix nothing binds is UNREGISTERED (REG-3.80): exit 3, the face on
//! stderr, nothing on stdout, and with `--json` the face as one object. The
//! root hint is read from `--root-hint` and from `SKEP_ROOT_HINT`, the flag
//! beating the variable; the mirror is kept at `<store>/registry/<genesis>/`
//! with the store's own files untouched; and every run reads the registry
//! to its head (REG-3.10), a held copy resumed and never answered from
//! alone. BOUND is not reached here: the system's resolver resolves none of
//! a suite's hosts, so that face is the daemon suite's cell, over the
//! library call this command makes.

use std::path::{Path, PathBuf};

use serde_json::{json, Value};
use skep_client::board::Board;
use skep_client::ceremony::claim::{self, ClaimOutcome, NotebookOptions};
use skep_client::ceremony::enroll::{enroll, EnrollOptions};
use skep_client::dial::PlainHttp;
use skep_client::person::scripted::{Script, Scripted};
use skep_client::resolve::RootHint;
use skep_client::sheet::Label;
use skep_client::store::{FileStore, KeyStore};
use skep_client::Origin;

use crate::common::{canned, origin, s, skep, spawn, tree, Run};

/// A root at a port nothing listens at.
///
/// A run that reaches it is exit 4, so a usage refusal judged ahead of it
/// is seen to open no socket.
const DEAD: &str = "http://127.0.0.1:1";

/// Claims the board through the library, as `hint.rs` claims its.
///
/// The store holds the device key and the board's binding, and the anchors'
/// files stand under `anchors`.
fn claim_board(board_origin: &str, store: &Path, anchors: &Path) {
    let board = Board::new(Origin::parse(board_origin).unwrap(), PlainHttp::new());
    let store = FileStore::open(store);
    store.generate(Some(Label::new("notebook").unwrap())).unwrap();
    let mut person = Scripted::new(vec![Script::LabelDefault, Script::LabelDefault]);
    let opts = NotebookOptions { principal: None, display_name: Some("a name".into()), anchor_out: vec![anchors.join("a"), anchors.join("b")], paper: false, host_name: "testhost".into(), date: "2026-11-12".into() };
    let ClaimOutcome::Ours(_) = claim::notebook(&board, &store, &mut person, &opts).unwrap_or_else(|h| panic!("{h}\n{}", person.transcript.join("\n"))) else { panic!("a stranger's board") };
}

/// Returns the board's root-hint line, as `skep hint` prints it.
///
/// The line a run of this command is handed is the one that command
/// prints: `skep resolve --root-hint "$(skep hint --board …)"`.
fn hint_of(board: &str) -> String {
    let r = skep(&["hint", "--board", board], &[], None);
    assert_eq!(r.code, 0, "{r:?}");
    r.out.trim_end_matches('\n').to_string()
}

/// Returns the directory the mirror of `hint`'s registry is kept in.
fn mirror_under(store: &Path, hint: &str) -> PathBuf {
    let genesis = RootHint::parse(hint).expect("a root hint").realm().genesis.to_hex();
    assert!(genesis.len() == 64 && genesis == genesis.to_lowercase(), "{genesis}");
    store.join("registry").join(genesis)
}

/// Checks a refusal: its exit code and the line it is named by on stderr.
///
/// Its stdout holds nothing — never a partial answer.
fn refused(r: &Run, code: i32, named: &str) {
    assert_eq!(r.code, code, "{r:?}");
    assert!(r.err.contains(named), "named {named:?}: {}", r.err);
    assert_eq!(r.out, "", "a refusal prints nothing on stdout: {r:?}");
}

/// Returns the head position a run says it read the registry to.
fn head_said(r: &Run) -> u64 {
    let after = r.err.split("to its head, position ").nth(1).unwrap_or_else(|| panic!("the run names the head it read to: {}", r.err));
    after.split(':').next().and_then(|n| n.parse().ok()).unwrap_or_else(|| panic!("a position: {}", r.err))
}

#[cfg(unix)]
fn mode(path: &Path) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(path).unwrap_or_else(|e| panic!("{}: {e}", path.display())).permissions().mode() & 0o777
}

/// Checks each refusal of `skep resolve`: a named line, and nothing printed.
///
/// Each is a named line on stderr with a nonzero exit and nothing on
/// stdout, in five kinds:
///
/// - The line's own shape, exit 2, before any socket opens and before the
///   mirror's directory is made (each names a root at a dead port, which a
///   run that dialed would meet as exit 4, and a store that is absent
///   after): no address; no root hint, by flag or by variable; a hint that
///   is no hint, in the resolver's own words for it, by flag and by
///   variable; an address that is no address, a signed component among
///   them; a second `--address`; a flag of another command's.
/// - A root that did not answer, exit 4: the mirror's directory made ahead
///   of the dial and holding no line of a copy.
/// - A root that answered as no board, exit 1; and one that answered a
///   read as reclaimed, exit 1 under the board's own token, the way on said
///   beside it: the copy's directory, to move aside.
/// - An unclaimed board, exit 3: it is no registry.
/// - The mirror's own, exit 3, each naming the mirror's directory on a line
///   of its own: a root whose genesis set is not the hint's realm, and a
///   held copy that does not read — the file said as it stands within the
///   directory.
#[test]
fn resolve_refuses_by_name_and_prints_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let absent = dir.path().join("no-store");
    let realm = "ab".repeat(32);
    let dead = format!("{DEAD} realm:{realm}");
    let address = "1.5.0.1.0.2";
    let required = "--root-hint (or SKEP_ROOT_HINT) is required: the registry's root-hint line";
    let rows = [
        (vec!["resolve", "--root-hint", &dead], vec![], "--address is required: the cross-board address to resolve".to_string()),
        (vec!["resolve", "--address", address], vec![], required.to_string()),
        (vec!["resolve", "--address", address], vec![("SKEP_ROOT_HINT", "")], required.to_string()),
        (vec!["resolve", "--address", address, "--root-hint", DEAD], vec![], "--root-hint: the hint names no realm (realm:<64 hex>)".to_string()),
        (vec!["resolve", "--address", address, "--root-hint", "realm:zz"], vec![], "--root-hint: 'realm:zz' is no genesis fingerprint (64 hex characters)".to_string()),
        (vec!["resolve", "--address", address], vec![("SKEP_ROOT_HINT", "registry.example")], "--root-hint: 'registry.example' is no canonical origin".to_string()),
        (vec!["resolve", "--address", "1.0", "--root-hint", &dead], vec![], "--address: '1.0' is not an address (the wire's dotted spelling)".to_string()),
        (vec!["resolve", "--address", "+1.5.0.1", "--root-hint", &dead], vec![], "--address: '+1.5.0.1' is not an address".to_string()),
        (vec!["resolve", "--address", address, "--address", "1.6", "--root-hint", &dead], vec![], "`--address` is given at most once at `resolve`".to_string()),
        (vec!["resolve", "--address", address, "--root-hint", &dead, "--also", "https://registry.example"], vec![], "`--also` is not a flag of `resolve`".to_string()),
    ];
    for (args, envs, named) in rows {
        let args: Vec<&str> = args.into_iter().chain(["--dir", s(&absent)]).collect();
        refused(&skep(&args, &envs, None), 2, &named);
    }
    assert!(!absent.exists(), "a line that does not read makes no directory");

    // A root that did not answer: nothing is resolved, and no line is kept.
    let store = dir.path().join("store");
    let r = skep(&["resolve", "--address", address, "--root-hint", &dead, "--dir", s(&store)], &[], None);
    refused(&r, 4, "skep: transport: connect: ");
    let mirror = mirror_under(&store, &dead);
    assert!(r.err.contains(&format!("reading the registry the root hint names ({DEAD}) as a guest; its mirror is kept under {}", mirror.display())), "{}", r.err);
    assert!(r.err.contains("no answer is given from the copy held (REG-3.10); its root is the root hint's — --root-hint, or SKEP_ROOT_HINT"), "{}", r.err);
    for name in ["feed.jsonl", "fetched.jsonl"] {
        assert_eq!(std::fs::read(mirror.join(name)).unwrap(), b"", "{name} holds no line");
    }

    // A root that answered as no board, and one that answered reclaimed.
    let no_board = format!("{} realm:{realm}", canned(404, b"not found"));
    let r = skep(&["resolve", "--address", address, "--root-hint", &no_board, "--dir", s(&store)], &[], None);
    refused(&r, 1, "skep: the board refused: http_error:not found (HTTP 404)");
    assert!(r.err.contains("no answer is given from the copy held (REG-3.10)") && !r.err.contains("reclaimed"), "{}", r.err);
    let reclaimed = format!("{} realm:{}", canned(410, br#"{"error":"history_reclaimed","floor":40}"#), "ef".repeat(32));
    let r = skep(&["resolve", "--address", address, "--root-hint", &reclaimed, "--dir", s(&store)], &[], None);
    refused(&r, 1, "skep: the board refused: history_reclaimed (HTTP 410)");
    let aside = format!("where the copy held under {} is the cause, move that directory aside and run this again", mirror_under(&store, &reclaimed).display());
    assert!(r.err.contains("the registry has reclaimed history the mirror asked for") && r.err.contains(&aside), "{}", r.err);

    // An unclaimed board: it is no registry.
    let sd = spawn(&dir.path().join("unclaimed"), false);
    let unclaimed = origin(sd.port());
    let r = skep(&["resolve", "--address", address, "--root-hint", &format!("{unclaimed} realm:{realm}"), "--dir", s(&store)], &[], None);
    refused(&r, 3, &format!("skep: the board the root hint names ({unclaimed}) is unclaimed: it is no registry"));

    // A root of another realm than the hint's: the directory named.
    let claimed = spawn(&dir.path().join("claimed"), false);
    let board = origin(claimed.port());
    claim_board(&board, &dir.path().join("owner"), &dir.path().join("anchors"));
    let hint = hint_of(&board);
    let other = format!("{board} realm:{}", "cd".repeat(32));
    let r = skep(&["resolve", "--address", address, "--root-hint", &other, "--dir", s(&store)], &[], None);
    refused(&r, 3, &format!("skep: the registry the root hint names is of another realm than the hint's\n  path: {}\n", mirror_under(&store, &other).display()));
    let found = RootHint::parse(&hint).unwrap().realm().genesis.to_hex();
    assert!(r.err.contains(&format!("the root's genesis fingerprint is {found}, and the hint's realm names {}", "cd".repeat(32))), "{}", r.err);

    // A held copy that does not read: the directory named, the file within it.
    let mirror = mirror_under(&store, &hint);
    std::fs::create_dir_all(&mirror).unwrap();
    std::fs::write(mirror.join("feed.jsonl"), b"no copy of a feed\n").unwrap();
    let r = skep(&["resolve", "--address", address, "--root-hint", &hint, "--dir", s(&store)], &[], None);
    refused(&r, 3, &format!("skep: the registry mirror's copy could not be read or written\n  path: {}\n  cause: feed.jsonl:1: ", mirror.display()));
    assert_eq!(std::fs::read(mirror.join("feed.jsonl")).unwrap(), b"no copy of a feed\n", "the copy stands as it was found");
}

/// Checks that `skep resolve` names an address's state off a fresh registry.
///
/// The registry is a claimed board that binds no prefix, so an address is
/// UNREGISTERED under its node field alone — the prefix `1.9` for an
/// address beneath it, never the whole address (the mutant that resolves
/// the address whole names it) — exit 3, the face on stderr and nothing on
/// stdout; with `--json` the face is one object on stdout, the exit code
/// the same. The root hint is the line `skep hint` prints, read from
/// `--root-hint` and from `SKEP_ROOT_HINT`, the flag beating the variable
/// (each of the two runs names a dead root in the other).
///
/// The mirror is kept at `<store>/registry/<genesis>/`, the directory
/// `0700` and its files `0600`: the first run reads the copy from the
/// registry's genesis and every later one resumes it, a run under a hint
/// of another genesis keeping its own directory beside it. Nothing of the key
/// store is touched — `keys/`, `bindings` and `lock` are byte for byte what
/// they were, and the store's own listing reads as before. And every run
/// reads the registry to its head (REG-3.10): once the board has moved, the
/// next run names the later head over the same held copy; and once the
/// board is gone a run refuses, exit 4, and answers nothing from the copy
/// it holds (the mutant that answers a held copy with no open against the
/// root prints the face it held).
#[test]
fn resolve_names_an_addresss_state_off_a_registry_read_afresh_into_a_mirror_beside_the_keys() {
    let dir = tempfile::tempdir().unwrap();
    let sd = spawn(&dir.path().join("board"), false);
    let board = origin(sd.port());
    let store = dir.path().join("store");
    claim_board(&board, &store, &dir.path().join("anchors"));
    let hint = hint_of(&board);
    let mirror = mirror_under(&store, &hint);
    let before = tree(&store);
    assert!(before.keys().any(|path| path.starts_with("keys")) && before.contains_key(Path::new("bindings")), "the store holds a key and a binding: {:?}", before.keys());
    let listing = skep(&["fingerprint", "--dir", s(&store), "--json"], &[], None);
    assert_eq!(listing.code, 0, "{listing:?}");
    let dead = format!("http://127.0.0.1:1 realm:{}", "ab".repeat(32));

    // The flag: UNREGISTERED under the node field, the copy read from genesis.
    let r = skep(&["resolve", "--address", "1.9.0.1.0.2", "--root-hint", &hint, "--dir", s(&store)], &[("SKEP_ROOT_HINT", &dead)], None);
    refused(&r, 3, "skep: UNREGISTERED: no binding on this registry names the prefix 1.9\n");
    assert!(r.err.contains(&format!("reading the registry the root hint names ({board}) as a guest; its mirror is kept under {}", mirror.display())), "{}", r.err);
    assert!(r.err.contains(&format!("registry read at {board} to its head, position ")) && r.err.contains(": the copy read from the registry's genesis (REG-3.12)"), "{}", r.err);
    assert!(r.err.contains("\n  act: check that the address is the global one"), "a halt's face: {}", r.err);
    let first_head = head_said(&r);

    // The variable, and `--json`: the face as one object, the copy resumed.
    let r = skep(&["resolve", "--address", "1.9.0.1.0.2", "--json", "--dir", s(&store)], &[("SKEP_ROOT_HINT", &hint)], None);
    assert_eq!(r.code, 3, "{r:?}");
    assert_eq!(r.out.lines().count(), 1, "one object on stdout and nothing else: {:?}", r.out);
    assert_eq!(serde_json::from_str::<Value>(&r.out).expect("JSON"), json!({ "face": "UNREGISTERED", "address": "1.9.0.1.0.2", "prefix": "1.9" }));
    assert!(r.err.contains("skep: UNREGISTERED: no binding on this registry names the prefix 1.9\n"), "the face is said on stderr too: {}", r.err);
    assert!(r.err.contains("the copy held here resumed, its ") && r.err.contains(" checked against the root first (REG-3.18)"), "{}", r.err);
    assert_eq!(head_said(&r), first_head, "the board has not moved");
    let r = skep(&["resolve", "--address", "1.9.0.1.0.2", "--root-hint", &dead, "--dir", s(&store)], &[("SKEP_ROOT_HINT", &hint)], None);
    refused(&r, 4, "skep: transport: connect: ");
    let other = mirror_under(&store, &dead);

    // A bare prefix, and a deeper one: each resolved whole.
    for (address, prefix) in [("1.9", "1.9"), ("1.9.3.0.1", "1.9.3")] {
        let r = skep(&["resolve", "--address", address, "--root-hint", &hint, "--dir", s(&store), "--json"], &[], None);
        assert_eq!(r.code, 3, "{r:?}");
        assert_eq!(serde_json::from_str::<Value>(&r.out).expect("JSON"), json!({ "face": "UNREGISTERED", "address": address, "prefix": prefix }));
    }

    // The mirror beside the keys, one directory to a genesis: the dead
    // root's hint named another realm, and its run made its own directory
    // and left this registry's copy as it was.
    let after = tree(&store);
    let beside: Vec<&Path> = after.keys().filter(|path| path.starts_with("registry")).map(PathBuf::as_path).collect();
    let genesis = mirror.file_name().unwrap();
    let (held, elsewhere) = (Path::new("registry").join(genesis), Path::new("registry").join(other.file_name().unwrap()));
    let mut expected = vec![PathBuf::from("registry")];
    for directory in [&held, &elsewhere] {
        expected.extend([directory.clone(), directory.join("feed.jsonl"), directory.join("fetched.jsonl"), directory.join("lock")]);
    }
    expected.sort();
    assert_eq!(beside, expected.iter().map(PathBuf::as_path).collect::<Vec<_>>(), "a directory to a genesis, each holding its copy and its lock");
    for name in ["feed.jsonl", "fetched.jsonl"] {
        assert_eq!(std::fs::read(other.join(name)).unwrap(), b"", "the unanswered root's {name} holds no line");
    }
    let header: Value = serde_json::from_str(std::fs::read_to_string(mirror.join("feed.jsonl")).unwrap().lines().next().expect("a header")).expect("JSON");
    assert_eq!((header["realm"].as_str(), header["root"].as_str()), (genesis.to_str(), Some(board.as_str())), "the copy is this registry's: {header}");
    #[cfg(unix)]
    {
        assert_eq!((mode(&store.join("registry")), mode(&mirror)), (0o700, 0o700));
        for name in ["feed.jsonl", "fetched.jsonl", "lock"] {
            assert_eq!(mode(&mirror.join(name)), 0o600, "{name}");
        }
    }
    let untouched: std::collections::BTreeMap<_, _> = after.iter().filter(|(path, _)| !path.starts_with("registry")).map(|(path, bytes)| (path.clone(), bytes.clone())).collect();
    assert_eq!(untouched, before, "keys/, bindings and lock are byte for byte what they were");
    let listed = skep(&["fingerprint", "--dir", s(&store), "--json"], &[], None);
    assert_eq!((listed.code, &listed.out), (0, &listing.out), "the store's own listing reads past the mirror: {listed:?}");

    // The board moves: the next run reads to the later head over the held copy.
    let second = dir.path().join("second");
    let r = skep(&["keygen", "--label", "phone", "--payload", "--dir", s(&second)], &[], None);
    assert_eq!(r.code, 0, "{r:?}");
    let payload = r.lines()[0].to_string();
    let registrar = Board::new(Origin::parse(&board).unwrap(), PlainHttp::new());
    let mut person = Scripted::new(vec![Script::Confirm(true)]);
    enroll(&registrar, &FileStore::open(&store), &mut person, &EnrollOptions { principal: 1, payload: format!("{payload}\n").into_bytes() }).unwrap_or_else(|h| panic!("{h}"));
    let r = skep(&["resolve", "--address", "1.9.0.1.0.2", "--root-hint", &hint, "--dir", s(&store)], &[], None);
    refused(&r, 3, "skep: UNREGISTERED: no binding on this registry names the prefix 1.9\n");
    assert!(r.err.contains("the copy held here resumed"), "{}", r.err);
    assert!(head_said(&r) > first_head, "read to the registry's head at this run, past {first_head}: {}", r.err);

    // The registry gone: the copy held answers nothing.
    let copy = std::fs::read(mirror.join("feed.jsonl")).unwrap();
    sd.shutdown();
    for json in [false, true] {
        let mut args = vec!["resolve", "--address", "1.9.0.1.0.2", "--root-hint", &hint, "--dir", s(&store)];
        args.extend(json.then_some("--json"));
        let r = skep(&args, &[], None);
        refused(&r, 4, "skep: transport: connect: ");
        assert!(r.err.contains("no answer is given from the copy held (REG-3.10)"), "{}", r.err);
    }
    assert_eq!(std::fs::read(mirror.join("feed.jsonl")).unwrap(), copy, "and the copy stands as it was");
}
