//! THE BINARY through argv, stdin and stdout (`client.md` §2; the build
//! brief §3): the command table and the help beneath a refusal, exit 2
//! before any socket for a non-canonical board, the person doors' terminal
//! check, THE LOOP over the hosted arm (keygen → claim --hosted → bind →
//! session → verify → health → fingerprint), the hosted reply as printed
//! landing at `bind`, the token's custody, its two sources in order and its
//! CONTENT scope, the whole-set compare, `bind`'s landing question, its
//! refusal of a reply from another board and of a key file its store does
//! not hold, its warning where the store cannot be appended and its first
//! session's scope on the wire, `fingerprint`'s refusal of two keys named,
//! `keygen`'s box at the prompt, a refused setting never read as an absent
//! one, a variable and an argument that are not text refused, a refused
//! stdout a halt and a refused stderr dropped, the plaintext warning, the
//! default store and its edges, the pending state beside a bound key,
//! `bind`'s paste prompt on stderr.

use std::path::{Path, PathBuf};

use serde_json::Value;
use skep_client::board::{Board, KeySetAnswer, Token};
use skep_client::ceremony::deposit::{deposit, Deposit, DepositKind};
use skep_client::dial::PlainHttp;
use skep_client::sheet::{KeyFile, Label, Seed};
use skep_client::sign::signer_from_seed;
use skep_client::store::FileStore;
use skep_client::Origin;
use skep_identity::{encode_enroll, parse_enroll, Enrollment, Fingerprint};
use skep_signature::HybridSigner;
use skepd::Skepd;

use crate::common::{origin, s, skep, skep_in, skep_os, skep_stderr_closed, skep_stdout_closed, spawn, spawn_tapped};

const SEVEN: [&str; 7] = ["keygen", "claim", "session", "fingerprint", "verify", "health", "bind"];

/// A board claimed through the hosted arm from `store`'s one key and bound
/// there — its home minted and its agent space set up by the account's
/// first signed session: where `session` and a second `bind` start.
struct Bound {
    _sd: Skepd,
    board: String,
    store: PathBuf,
    fp: String,
}

fn hosted_and_bound(dir: &Path) -> Bound {
    let sd = spawn(&dir.join("board"), false);
    let board = origin(sd.port());
    let store = dir.join("store");
    let r = skep(&["keygen", "--label", "mine", "--payload", "--dir", s(&store)], &[], None);
    assert_eq!(r.code, 0, "{r:?}");
    let (payload, fp) = (r.lines()[0].to_string(), r.lines()[1].to_string());
    let r = skep(&["claim", "--hosted", "-", "--board", &board], &[], Some(payload.as_bytes()));
    assert_eq!(r.code, 0, "{r:?}");
    let r = skep(&["bind", "--board", &board, "--dir", s(&store), "--account", "1.0.1", "--principal", "1"], &[], None);
    assert!(r.code == 0 && r.lines().contains(&"agent space 1.0.1.1"), "{r:?}");
    Bound { _sd: sd, board, store, fp }
}

/// `--help` is DATA on stdout and says nothing on stderr; a command line
/// refused is exit 2, its one sentence on stderr with the help beneath it
/// (`Stop`'s usage arm) and nothing on stdout; and every flag shape
/// refused is exit 2.
#[test]
fn help_is_data_and_a_refused_command_line_is_exit_2_with_the_help_beneath_on_stderr() {
    let run = skep(&["--help"], &[], None);
    assert_eq!(run.code, 0, "{run:?}");
    assert!(run.err.is_empty(), "the help is data: {}", run.err);
    for c in SEVEN {
        assert!(run.out.contains(&format!("\n  {c} ")), "{c} listed:\n{}", run.out);
    }
    let r = skep(&["frobnicate"], &[], None);
    assert_eq!(r.code, 2);
    assert!(r.err.contains("unknown command"));
    assert!(r.out.is_empty(), "a refusal is talk: {}", r.out);
    assert!(r.err.starts_with("skep: unknown command `frobnicate`\n\nusage: skep <command> [flags]\n"), "the refusal, then the help beneath it: {}", r.err);
    let r = skep(&[], &[], None);
    assert_eq!(r.code, 2);
    let r = skep(&["health", "--board"], &[], None);
    assert_eq!(r.code, 2, "a flag without its value");
    let r = skep(&["health", "--frob"], &[], None);
    assert_eq!(r.code, 2, "an unknown flag");
}

#[test]
fn a_non_canonical_board_exits_2_before_any_socket_and_a_dead_one_exits_4() {
    for bad in ["HTTP://127.0.0.1:1", "http://127.0.0.1:1/", "http://127.0.0.1:080", "http://127.0.0.1:80", "127.0.0.1:1", "http://Example.com"] {
        let r = skep(&["health", "--board", bad], &[], None);
        assert_eq!(r.code, 2, "{bad}: {r:?}");
        assert!(r.err.contains("not a canonical origin (scheme://host[:port], lowercase, the scheme's default port omitted)"), "{bad}: {}", r.err);
    }
    // The flag beats the variable, and the variable alone is read.
    let r = skep(&["health"], &[("SKEP_BOARD", "http://127.0.0.1:1/")], None);
    assert_eq!(r.code, 2);
    let r = skep(&["health", "--board", "http://127.0.0.1:1/"], &[("SKEP_BOARD", "http://127.0.0.1:1")], None);
    assert_eq!(r.code, 2, "the flag's bad value is judged, not the variable's good one");
    // A canonical origin nobody answers at: transport, exit 4.
    let r = skep(&["health", "--board", "http://127.0.0.1:1"], &[], None);
    assert_eq!(r.code, 4, "{r:?}");
    assert!(r.err.contains("transport:"), "{}", r.err);
}

#[test]
fn the_person_doors_refuse_without_a_terminal_and_the_rest_run_without_one() {
    let dir = tempfile::tempdir().unwrap();
    let sd = spawn(&dir.path().join("board"), false);
    let board = origin(sd.port());
    let store = dir.path().join("store");
    // The notebook arm's door, against a store holding the key a walk would
    // claim with: past the door the walk delegates and mints before its
    // first prompt, so the board's head standing where it stood shows the
    // door came first.
    let keyed = dir.path().join("keyed");
    assert_eq!(skep(&["keygen", "--label", "notebook", "--dir", s(&keyed)], &[], None).code, 0);
    let head = || {
        let v: Value = serde_json::from_str(&skep(&["health", "--board", &board], &[], None).out).expect("one JSON document");
        (v["log_position"].clone(), v["chain_head"].clone(), v["auth"]["claimant"].clone())
    };
    let before = head();
    let r = skep(&["claim", "--board", &board, "--dir", s(&keyed)], &[], None);
    assert_eq!(r.code, 3, "{r:?}");
    assert!(r.err.contains("requires a controlling terminal"), "{}", r.err);
    assert!(r.err.contains("what a person answers here — the name boxes and the backup moment —"), "the door's own moments: {}", r.err);
    assert_eq!(head(), before, "the board was not touched by claim: its head where it stood");
    assert!(before.2.is_null(), "and still unclaimed");
    assert!(!keyed.join("bindings").exists(), "nothing bound");
    let r = skep(&["keygen", "--anchors", "--dir", s(&store)], &[], None);
    assert_eq!(r.code, 3, "{r:?}");
    assert!(r.err.contains("requires a controlling terminal"));
    assert!(r.err.contains("what a person answers here — the door-side backup moment —"), "the door's own moments: {}", r.err);
    assert!(!store.join("keys").exists(), "nothing generated before the check");
    // Plain keygen runs without one.
    let r = skep(&["keygen", "--label", "service key", "--dir", s(&store)], &[], None);
    assert_eq!(r.code, 0, "{r:?}");
    let lines = r.lines();
    assert_eq!(lines.len(), 3, "the fingerprint flat, then grouped on two lines: {:?}", lines);
    assert_eq!(lines[0].len(), 64);
    assert_eq!(lines[1].split_whitespace().count(), 4);
    assert!(r.err.contains("[AUTH-5.42]") && r.err.contains("permanent and cannot be edited"), "the box statements render for a flag-fixed label: {}", r.err);
    assert!(
        r.err.contains("[AUTH-5.42] It holds the DEVICE's name") && r.err.contains("[AUTH-5.42] at this notebook it is readable by anything on the machine"),
        "the device's box, its consequence the one at this venue: {}",
        r.err
    );
    let written = store.join("keys").join(format!("{}.key", lines[0]));
    assert!(r.err.contains(&format!("key file written: {}", written.display())) && r.err.contains("0600 under 0700"), "the custody line beside the path: {}", r.err);
    assert!(!r.out.contains(&format!("{}", "mldsa65")), "no bare public key on stdout");
    // The label's domain at the box, from the flag.
    let r = skep(&["keygen", "--label", &"x".repeat(129), "--dir", s(&store)], &[], None);
    assert_eq!(r.code, 3, "{r:?}");
    assert!(r.err.contains("refused at the box"));
    // health runs without a terminal.
    let r = skep(&["health", "--board", &board], &[], None);
    assert_eq!(r.code, 0);
}

/// THE LOOP over the hosted arm, every command through the binary.
#[test]
fn the_hosted_loop_runs_its_seven_commands_through_the_binary() {
    let dir = tempfile::tempdir().unwrap();
    let sd = spawn(&dir.path().join("board"), false);
    let board = origin(sd.port());
    let store = dir.path().join("store");

    // keygen --payload: the record FIRST, the fingerprint LAST.
    let r = skep(&["keygen", "--label", "customer notebook", "--payload", "--dir", s(&store)], &[], None);
    assert_eq!(r.code, 0, "{r:?}");
    let lines = r.lines();
    assert_eq!(lines.len(), 4, "{lines:?}");
    let payload = lines[0].to_string();
    let entries = parse_enroll(payload.as_bytes()).expect("a canonical record");
    assert_eq!(entries.len(), 1);
    assert!(!entries[0].anchor);
    assert_eq!(entries[0].label(), Some("customer notebook"));
    let fp = lines[1].to_string();
    assert_eq!(fp.len(), 64);
    assert_eq!(skep_identity::Fingerprint::of(&entries[0].key).to_hex(), fp, "the fingerprint is the payload's key's");
    assert!(r.err.contains("not enrolled anywhere yet") && r.err.contains("skep claim"), "the outstanding-act line: {}", r.err);
    assert!(r.err.contains("skep rotate --payload"), "the line is conditioned on the walk: {}", r.err);
    assert!(!r.err.contains("skep accept"), "a key keygen made was never made at `skep accept`: {}", r.err);
    let payload_file = dir.path().join("payload.json");
    std::fs::write(&payload_file, format!("{payload}\n")).unwrap();

    // fingerprint: UNBOUND with the no-board-claimed act — the same
    // conditioned line, the re-print, the claim and the handoff recipient's
    // clause beside it.
    let r = skep(&["fingerprint", "--dir", s(&store)], &[], None);
    assert_eq!(r.code, 0, "{r:?}");
    assert!(r.out.contains(&fp) && r.out.contains("label customer notebook") && r.out.contains("UNBOUND — no board has been claimed from this store"), "{}", r.out);
    assert!(
        r.out.contains("--select <fp> --payload")
            && r.out.contains("skep rotate --payload")
            && r.out.contains("`skep claim`")
            && r.out.contains("the re-offer is `skep accept --reprint`, never `--payload` here"),
        "{}",
        r.out
    );

    // claim --hosted -: the payload on stdin; the reply on stdout.
    let r = skep(&["claim", "--hosted", "-", "--board", &board], &[], Some(payload.as_bytes()));
    assert_eq!(r.code, 0, "{r:?}");
    let out = r.lines();
    assert_eq!(out[0], "claimant 1.0.1");
    assert_eq!(out[1], "account 1.0.1");
    assert_eq!(out[2], "principal 1");
    assert_eq!(out[3], format!("origin {board}"));
    assert_eq!(out.len(), 6, "the claimant, the three facts and the two acts — H6's list and no more: {out:?}");
    assert!(out[4].starts_with("first act: ") && out[4].contains(&format!("skep verify --board {board} --principal 1 --payload")), "{}", out[4]);
    assert!(out[4].contains("it cannot tell you the board will open a session for you"), "the read's limit, in the reply's own words: {}", out[4]);
    assert!(
        out[5].starts_with("second act: ") && out[5].contains("creating your account also creates a space for your agents beneath it, and its home"),
        "the setup act's sentence: {}",
        out[5]
    );
    assert!(!r.out.contains("holds no anchor"), "the reply carries no anchorless sentence: its one carrier is the deployment template (§4.5 H6, cs6-S2): {}", r.out);
    assert!(r.err.contains("ANCHORLESS PERMANENTLY"), "the operator's log: {}", r.err);
    // Idempotent.
    let r = skep(&["claim", "--hosted", &payload_file.to_string_lossy(), "--board", &board], &[], None);
    assert_eq!(r.code, 0, "{r:?}");
    assert_eq!(r.out.trim(), "claimed by 1.0.1");

    // health: the body verbatim on stdout; the mode on stderr.
    let r = skep(&["health", "--board", &board], &[], None);
    assert_eq!(r.code, 0);
    let body: Value = serde_json::from_str(&r.out).expect("one JSON document");
    assert_eq!(body["auth"]["claimant"].as_str(), Some("1.0.1"));
    assert!(body.get("mode").is_none(), "no mode field added (AUTH-5.86)");
    assert!(r.err.contains("mode ENFORCING") && r.err.contains("signed arm") && r.err.contains(&board), "{}", r.err);
    let mut verbatim = Board::new(Origin::parse(&board).unwrap(), PlainHttp::new()).health().unwrap().raw;
    if !verbatim.ends_with(b"\n") {
        verbatim.push(b'\n');
    }
    assert_eq!(r.out.as_bytes(), verbatim.as_slice(), "the body VERBATIM, a newline ending it where it has none");

    // bind: the three facts confirmed, the first signed session's setup act.
    // No `--anchor` says which landing this is and the input has ended:
    // nobody answers, nothing is compared, and the line says so.
    let r = skep(&["bind", "--board", &board, "--dir", s(&store), "--account", "1.0.1", "--principal", "1"], &[], None);
    assert_eq!(r.code, 0, "{r:?}");
    assert!(r.lines().contains(&"agent space 1.0.1.1"), "{}", r.out);
    assert!(r.lines().contains(&"account 1.0.1") && r.lines().contains(&"principal 1"));
    assert!(r.err.contains("which landing is this?") && r.err.contains("no landing was answered before the input ended"), "{}", r.err);
    // The second arm: nothing owed, no session.
    let r = skep(&["bind", "--board", &board, "--dir", s(&store), "--account", "1.0.1", "--principal", "1"], &[], None);
    assert_eq!(r.code, 0, "{r:?}");
    assert!(r.err.contains("nothing is owed"), "{}", r.err);
    assert!(!r.out.contains("agent space"));
    // Wrong facts: confirmed against the board, refused — the act sending the
    // person back to whoever printed the reply, here the host's hosted claim
    // and no enrolling device at all.
    let r = skep(&["bind", "--board", &board, "--dir", s(&store), "--account", "1.0.1", "--principal", "7"], &[], None);
    assert_eq!(r.code, 3, "{r:?}");
    assert!(r.err.contains("not the principal seated at 1.0.1"), "{}", r.err);
    assert!(
        r.err.contains("act: re-take the three facts from whoever printed the reply — the enrolling device, the giver at a handoff, or your host after a hosted signup"),
        "the three landings' senders named: {}",
        r.err
    );

    // fingerprint: now BOUND.
    let r = skep(&["fingerprint", "--dir", s(&store), "--select", &fp[..8], "--payload"], &[], None);
    assert_eq!(r.code, 0, "{r:?}");
    assert!(r.out.contains(&format!("bound {board} principal 1 account 1.0.1")), "{}", r.out);
    assert!(r.out.lines().any(|l| l == payload), "--payload re-prints the record");
    let r = skep(&["fingerprint", "--dir", s(&store), "--select", "customer notebook", "--json"], &[], None);
    assert_eq!(r.code, 0);
    let v: Value = serde_json::from_str(&r.out).unwrap();
    assert_eq!(v[0]["fingerprint"].as_str(), Some(fp.as_str()));
    assert_eq!(v[0]["unbound"], Value::Bool(false));

    // session: CONTENT scope, the token on stdout. After `bind` the store
    // holds TWO bindings at this board — the account's and the agent
    // space's persist-first line — and `--principal` MAY be omitted all the
    // same (§3.5 as RULED 2026-10-04: the agent space's line does not count).
    let r = skep(&["session", "--board", &board, "--dir", s(&store)], &[], None);
    assert_eq!(r.code, 0, "the one-binding test ignores the agent space's line: {r:?}");
    let r = skep(&["session", "--close", "-", "--board", &board], &[], Some(r.out.trim().as_bytes()));
    assert_eq!(r.code, 0, "{r:?}");
    let r = skep(&["session", "--board", &board, "--dir", s(&store), "--principal", "1"], &[], None);
    assert_eq!(r.code, 0, "{r:?}");
    let token = r.out.trim().to_string();
    assert_eq!(token.len(), 32);
    assert!(token.bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()));
    assert!(r.err.contains("content") && r.err.contains("AUTH-4.53"), "{}", r.err);
    // The token is a live CONTENT session, which
    // `the_token_session_prints_is_content_scoped_and_deposits_no_credential`
    // holds it to; --close takes `-` and reads stdin.
    let r = skep(&["session", "--close", "-", "--board", &board], &[], Some(format!("{token}\n").as_bytes()));
    assert_eq!(r.code, 0, "{r:?}");
    assert!(r.err.is_empty(), "{}", r.err);
    let r = skep(&["session", "--close", "-", "--board", &board], &[], Some(token.as_bytes()));
    assert_eq!(r.code, 0);
    assert!(r.err.contains("already dead"), "idempotent, the death signal said: {}", r.err);
    // The token NEVER an argv value.
    let r = skep(&["session", "--close", &token, "--board", &board], &[], None);
    assert_eq!(r.code, 2, "{r:?}");
    assert!(r.err.contains("world-readable"), "{}", r.err);
    // SKEP_SESSION; and SKEP_PRINCIPAL stands for the flag.
    let r = skep(&["session", "--board", &board, "--dir", s(&store)], &[("SKEP_PRINCIPAL", "1")], None);
    assert_eq!(r.code, 0, "{r:?}");
    let token2 = r.out.trim().to_string();
    assert_eq!(token2.len(), 32);
    let r = skep(&["session", "--close", "-", "--board", &board], &[("SKEP_SESSION", &token2)], None);
    assert_eq!(r.code, 0, "{r:?}");
    assert!(r.err.is_empty());
    // SKEP_SESSION where it is set, stdin then unread: the variable's token
    // is the one ended — closed above, so already dead — and a live token
    // piped beside it stands, unread.
    let r = skep(&["session", "--board", &board, "--dir", s(&store)], &[], None);
    assert_eq!(r.code, 0, "{r:?}");
    let piped = r.out.trim().to_string();
    let r = skep(&["session", "--close", "-", "--board", &board], &[("SKEP_SESSION", &token2)], Some(piped.as_bytes()));
    assert_eq!(r.code, 0, "{r:?}");
    assert!(r.err.contains("already dead"), "the variable's token is the one ended: {}", r.err);
    let r = skep(&["session", "--close", "-", "--board", &board], &[], Some(piped.as_bytes()));
    assert_eq!(r.code, 0, "{r:?}");
    assert!(r.err.is_empty(), "the piped token stood live: {}", r.err);
    // Bytes read from stdin that are no token — not a token's text, or no
    // text at all — are a state the read came to (exit 3), named so; never
    // a usage refusal, which is the command line's shape alone. A
    // SKEP_SESSION that is no token is a setting given badly (exit 2), named
    // by its variable.
    for bytes in [&b"not a token"[..], b"\xff\xfe"] {
        let r = skep(&["session", "--close", "-", "--board", &board], &[], Some(bytes));
        assert_eq!(r.code, 3, "{bytes:?}: {r:?}");
        assert!(r.err.contains("the bytes read from stdin are not a session token"), "{}", r.err);
    }
    let r = skep(&["session", "--close", "-", "--board", &board], &[("SKEP_SESSION", "not a token")], None);
    assert_eq!(r.code, 2, "{r:?}");
    assert!(r.err.contains("SKEP_SESSION: the value is not a session token"), "{}", r.err);

    // verify: the origin arm, the key arm, the whole-set compare.
    let r = skep(&["verify", "--board", &board, "--dir", s(&store), "--principal", "1", "--payload", s(&payload_file)], &[], None);
    assert_eq!(r.code, 0, "{r:?}");
    assert!(r.lines().contains(&"account 1.0.1"), "{}", r.out);
    assert!(!r.err.contains("later act"));
    assert!(r.err.contains("block is invisible"), "the limit stated: {}", r.err);
    let r = skep(&["verify", "--board", &board, "--dir", s(&store), "--principal", "1", "--payload", "-", "--json"], &[], Some(payload.as_bytes()));
    assert_eq!(r.code, 0, "{r:?}");
    let v: Value = serde_json::from_str(&r.out).unwrap();
    assert_eq!(v["checks"], serde_json::json!(["origin", "key_set", "payload"]));
    assert_eq!(v["state"].as_str(), Some("enrolled"));
    assert_eq!(v["limit"].as_str(), Some("a block is invisible to these reads"), "the --json document carries the limit the stderr line states");
    let r = skep(&["verify", "--board", &board, "--dir", s(&store), "--principal", "1"], &[], None);
    assert_eq!(r.code, 0);
    assert!(r.err.contains("one-key read"), "without a payload the one-key read is named: {}", r.err);
    let r = skep(&["verify", "--board", &board, "--dir", s(&store), "--principal", "1", "--json"], &[], None);
    assert_eq!(r.code, 0, "{r:?}");
    let v: Value = serde_json::from_str(&r.out).unwrap();
    assert_eq!(v["checks"], serde_json::json!(["origin", "key_set"]), "no artifact held, no whole-set check named");
    assert_eq!(v["limit"].as_str(), Some("a block is invisible to these reads"), "{v}");
    // An agent space's principal is diagnosed against the holder's set
    // above it (§2.2 `verify`): the account named, then the set it opens by
    // reference against.
    let bindings = std::fs::read_to_string(store.join("bindings")).unwrap();
    let space =
        bindings.lines().map(|l| l.split(' ').collect::<Vec<_>>()).find_map(|f| (f.get(2) == Some(&"1.0.1.1")).then(|| f[1].to_string())).expect("the agent space's binding line");
    let r = skep(&["verify", "--board", &board, "--dir", s(&store), "--principal", &space], &[], None);
    assert_eq!(r.code, 0, "{r:?}");
    assert_eq!(r.lines(), ["account 1.0.1.1", "opens by reference against 1.0.1"]);
    // The origin arm: a loopback alias the signed list lacks.
    let alias = format!("http://localhost:{}", sd.port());
    let r = skep(&["verify", "--board", &alias, "--dir", s(&store), "--principal", "1"], &[], None);
    assert_eq!(r.code, 3, "{r:?}");
    assert!(r.err.contains("does not accept signed sessions at this origin"), "{}", r.err);
    // The key arm's third state: a key in neither list.
    let other = dir.path().join("other-store");
    let r = skep(&["keygen", "--label", "stranger", "--dir", s(&other)], &[], None);
    assert_eq!(r.code, 0);
    let r = skep(&["verify", "--board", &board, "--dir", s(&other), "--principal", "1"], &[], None);
    assert_eq!(r.code, 3, "{r:?}");
    assert!(r.err.contains("records do not list this key"), "{}", r.err);
    // --key: an anchor file is refused where the key signs (session), read
    // where it does not (fingerprint).
    let anchor = KeyFile::new(Seed::fresh(), true, Some(Label::new("paper").unwrap()), None);
    let anchor_path = dir.path().join("anchor.skep-key");
    std::fs::write(&anchor_path, anchor.to_json()).unwrap();
    let r = skep(&["session", "--board", &board, "--dir", s(&store), "--key", s(&anchor_path), "--principal", "1"], &[], None);
    assert_eq!(r.code, 3, "{r:?}");
    assert!(r.err.contains("ANCHOR's file"), "{}", r.err);
    let r = skep(&["fingerprint", "--dir", s(&store), "--key", s(&anchor_path)], &[], None);
    assert_eq!(r.code, 0, "{r:?}");
    assert!(r.out.contains("ANCHOR"));
    // A mis-pathed key file: halt naming the path, never a fallback.
    let r = skep(&["session", "--board", &board, "--dir", s(&store), "--key", "/nonexistent/key.key", "--principal", "1"], &[], None);
    assert_eq!(r.code, 3, "{r:?}");
    assert!(r.err.contains("/nonexistent/key.key") && r.err.contains("AUTH-5.67"), "{}", r.err);
}

/// THE TOKEN `session` PRINTS IS CONTENT-SCOPED (§2.1's `session` row,
/// "content only", AUTH RES-63; §2.2): a credential deposit under it answers
/// `content_session` and the key set stands as it was — never a FULL
/// session, whose capture is one permanent enrollment from the account
/// (AUTH-4.53).
#[test]
fn the_token_session_prints_is_content_scoped_and_deposits_no_credential() {
    let dir = tempfile::tempdir().unwrap();
    let b = hosted_and_bound(dir.path());
    let r = skep(&["session", "--board", &b.board, "--dir", s(&b.store)], &[], None);
    assert_eq!(r.code, 0, "{r:?}");
    let token = Token::parse(&r.out).expect("the token on stdout");
    let board = Board::new(Origin::parse(&b.board).unwrap(), PlainHttp::new());
    let store = FileStore::open(&b.store);
    let device = store.load(&store.key_path(&Fingerprint::parse_hex(&b.fp).unwrap())).unwrap().signer();
    let second = signer_from_seed(&[9; 32]);
    let refused = deposit(
        &board,
        &token,
        &Deposit {
            home: "1.0.1.0.1",
            subject: "1.0.1",
            kind: DepositKind::Enroll(vec![Enrollment::new(HybridSigner::public_key(&second).clone(), false, Some("second".into())).unwrap()]),
            hand: Some(&device),
            id: "cli.enroll-under-the-printed-token",
        },
    )
    .expect_err("a content-scoped token deposits no credential");
    assert!(refused.to_string().contains("content_session"), "{refused}");
    let KeySetAnswer::Set(set) = board.key_set("1.0.1").unwrap() else { panic!("1.0.1 is an account") };
    assert_eq!(set.enrolled.len(), 1, "the key set stands as it was");
    assert_eq!(skep(&["session", "--close", "-", "--board", &b.board], &[], Some(token.as_str().as_bytes())).code, 0);
}

/// THE HOSTED REPLY AS PRINTED LANDS AT `bind` (§4.5 H6; `print_facts`, the
/// lines `bind` reads back): `claim --hosted --principal 7` seats the
/// account at the principal given and its reply names it — in the three
/// facts and in the first act's command — and the whole reply, fed to `bind
/// --payload -`, lands: the facts confirmed, the first signed session run,
/// the binding line naming principal 7.
#[test]
fn the_hosted_reply_names_the_principal_given_and_lands_at_bind_as_printed() {
    let dir = tempfile::tempdir().unwrap();
    let sd = spawn(&dir.path().join("board"), false);
    let board = origin(sd.port());
    let store = dir.path().join("store");
    let r = skep(&["keygen", "--label", "mine", "--payload", "--dir", s(&store)], &[], None);
    assert_eq!(r.code, 0, "{r:?}");
    let (payload, fp) = (r.lines()[0].to_string(), r.lines()[1].to_string());
    let reply = skep(&["claim", "--hosted", "-", "--principal", "7", "--board", &board], &[], Some(payload.as_bytes()));
    assert_eq!(reply.code, 0, "{reply:?}");
    assert_eq!(reply.lines()[1..4], ["account 1.0.1", "principal 7", format!("origin {board}").as_str()]);
    assert!(reply.lines()[4].contains("--principal 7 "), "the first act names the principal given: {}", reply.out);
    let r = skep(&["bind", "--board", &board, "--dir", s(&store), "--payload", "-"], &[], Some(reply.out.as_bytes()));
    assert_eq!(r.code, 0, "{r:?}");
    assert!(r.lines().contains(&"principal 7") && r.lines().contains(&"agent space 1.0.1.1"), "{}", r.out);
    let bindings = std::fs::read_to_string(store.join("bindings")).unwrap();
    assert!(bindings.lines().any(|l| l == format!("{board} 7 1.0.1 {fp}")), "the binding line names principal 7: {bindings}");
}

/// THE WHOLE-SET COMPARE through the binary: a key the operator planted in
/// the genesis halts `verify --payload` in AUTH-5.53's terms, and a key held
/// and missing from it is named beside it; the honest genesis passes with
/// `--anchor` files too.
#[test]
fn verify_halts_on_a_planted_key_and_admits_the_honest_genesis_from_anchor_files() {
    // The planted board.
    let dir = tempfile::tempdir().unwrap();
    let sd = spawn(&dir.path().join("board"), false);
    let board = origin(sd.port());
    let store = dir.path().join("store");
    let r = skep(&["keygen", "--label", "mine", "--payload", "--dir", s(&store)], &[], None);
    assert_eq!(r.code, 0, "{r:?}");
    let payload = r.lines()[0].to_string();
    let mut entries = parse_enroll(payload.as_bytes()).unwrap();
    let planted = signer_from_seed(&[42; 32]);
    entries.push(Enrollment::new(HybridSigner::public_key(&planted).clone(), false, Some("planted".into())).unwrap());
    let doctored = encode_enroll(&entries);
    let r = skep(&["claim", "--hosted", "-", "--board", &board], &[], Some(doctored.as_bytes()));
    assert_eq!(r.code, 0, "{r:?}");
    let r = skep(&["verify", "--board", &board, "--dir", s(&store), "--principal", "1", "--payload", "-"], &[], Some(payload.as_bytes()));
    assert_eq!(r.code, 3, "{r:?}");
    assert!(r.err.contains("NOT yours to keep as it stands (AUTH-5.53)"), "{}", r.err);
    assert!(r.err.contains("a key you did not send stands in the genesis") && r.err.contains("planted"), "{}", r.err);
    assert!(r.err.contains("the acts by cell") && r.err.contains("the state is PERMANENT where the flags did not — or decline the account"), "{}", r.err);
    // Membership alone would pass: the one-key read does.
    let r = skep(&["verify", "--board", &board, "--dir", s(&store), "--principal", "1"], &[], None);
    assert_eq!(r.code, 0, "the one-key read sees nothing: {r:?}");
    // A key held and missing from the genesis is named as one, by
    // fingerprint and label, beside the key planted in it (§2.2 `verify`:
    // each differing entry).
    let sent = signer_from_seed(&[7; 32]);
    let mut held = parse_enroll(payload.as_bytes()).unwrap();
    held.push(Enrollment::new(HybridSigner::public_key(&sent).clone(), false, Some("sent".into())).unwrap());
    let r = skep(&["verify", "--board", &board, "--dir", s(&store), "--principal", "1", "--payload", "-"], &[], Some(encode_enroll(&held).as_bytes()));
    assert_eq!(r.code, 3, "{r:?}");
    let missing = format!("a key you sent is missing from the genesis: {} anchor=false label=sent", Fingerprint::of(HybridSigner::public_key(&sent)));
    assert!(r.err.contains(&missing), "{}", r.err);
    assert!(r.err.contains("a key you did not send stands in the genesis") && r.err.contains("label=planted"), "{}", r.err);

    // The honest board, with two anchor files and the device key.
    let dir = tempfile::tempdir().unwrap();
    let sd = spawn(&dir.path().join("board"), false);
    let board = origin(sd.port());
    let store = dir.path().join("store");
    let r = skep(&["keygen", "--label", "mine", "--payload", "--dir", s(&store)], &[], None);
    let device = parse_enroll(r.lines()[0].as_bytes()).unwrap().remove(0);
    let a = KeyFile::new(Seed::fresh(), true, Some(Label::new("paper a").unwrap()), None);
    let b = KeyFile::new(Seed::fresh(), true, Some(Label::new("paper b").unwrap()), None);
    let (pa, pb) = (dir.path().join("a.skep-key"), dir.path().join("b.skep-key"));
    std::fs::write(&pa, a.to_json()).unwrap();
    std::fs::write(&pb, b.to_json()).unwrap();
    let full = encode_enroll(&[
        Enrollment::new(a.public.clone(), true, Some("paper a".into())).unwrap(),
        Enrollment::new(b.public.clone(), true, Some("paper b".into())).unwrap(),
        device,
    ]);
    let r = skep(&["claim", "--hosted", "-", "--board", &board], &[], Some(full.as_bytes()));
    assert_eq!(r.code, 0, "{r:?}");
    assert!(!r.out.contains("holds no anchor"));
    let r = skep(&["verify", "--board", &board, "--dir", s(&store), "--principal", "1", "--anchor", s(&pa), "--anchor", s(&pb), "--json"], &[], None);
    assert_eq!(r.code, 0, "{r:?}");
    let v: Value = serde_json::from_str(&r.out).unwrap();
    assert_eq!(v["checks"], serde_json::json!(["origin", "key_set", "payload"]));
    // One anchor missing from what is held: a difference.
    let r = skep(&["verify", "--board", &board, "--dir", s(&store), "--principal", "1", "--anchor", s(&pa)], &[], None);
    assert_eq!(r.code, 3, "{r:?}");
    assert!(r.err.contains("a key you did not send stands in the genesis") && r.err.contains("anchor=true"), "{}", r.err);
    // bind at this board compares the set whole ahead of its session.
    let r = skep(&["bind", "--board", &board, "--dir", s(&store), "--account", "1.0.1", "--principal", "1", "--anchor", s(&pa)], &[], None);
    assert_eq!(r.code, 3, "{r:?}");
    assert!(r.err.contains("NOT yours to keep"), "{}", r.err);
    assert!(
        r.err.contains("the acts by cell") && r.err.contains("the state is PERMANENT where the flags did not — the extra key is one the giver's hand can act with"),
        "bind halts as at verify, the extra key named as the giver's to act with (§2.2): {}",
        r.err
    );
    assert!(!r.out.contains("agent space"), "no session, no act");
    let r = skep(&["bind", "--board", &board, "--dir", s(&store), "--account", "1.0.1", "--principal", "1", "--anchor", s(&pa), "--anchor", s(&pb)], &[], None);
    assert_eq!(r.code, 0, "{r:?}");
    assert!(r.lines().contains(&"agent space 1.0.1.1"));
    // A binding that names an anchor's file: READ at `verify`, which signs
    // nothing, and refused at `session`, which signs (§2.2's selection
    // test) — by the store's lookup as by `--key`.
    let papers = dir.path().join("papers");
    std::fs::create_dir_all(papers.join("keys")).unwrap();
    std::fs::copy(&pa, papers.join("keys").join(format!("{}.key", a.fingerprint.to_hex()))).unwrap();
    std::fs::write(papers.join("bindings"), format!("{board} 1 1.0.1 {}\n", a.fingerprint.to_hex())).unwrap();
    let r = skep(&["verify", "--board", &board, "--dir", s(&papers)], &[], None);
    assert_eq!(r.code, 0, "{r:?}");
    assert!(r.lines().contains(&"account 1.0.1"), "{}", r.out);
    let r = skep(&["session", "--board", &board, "--dir", s(&papers)], &[], None);
    assert_eq!(r.code, 3, "{r:?}");
    assert!(r.err.contains("ANCHOR's file"), "{}", r.err);
}

/// THE LANDING QUESTION (§2.2 `bind`; P27): where no `--anchor` says which
/// landing this is, `bind` asks — each answer priced, none proposed — ahead
/// of any session. Answered `alone` — a handoff's DECLINE arm, a hosted
/// one-key signup — the genesis is compared against this device's key
/// alone, so a key written beside it halts the binding; an answer that is
/// none of the three is asked again; `pair` stops for the files; `hop`
/// compares nothing, the price its line names.
#[test]
fn bind_asks_which_landing_where_no_anchor_says_and_compares_the_decline_arm_whole() {
    // A genesis another hand wrote around this device's key, and one beside it.
    let dir = tempfile::tempdir().unwrap();
    let sd = spawn(&dir.path().join("board"), false);
    let board = origin(sd.port());
    let store = dir.path().join("store");
    let r = skep(&["keygen", "--label", "mine", "--payload", "--dir", s(&store)], &[], None);
    assert_eq!(r.code, 0, "{r:?}");
    let mut entries = parse_enroll(r.lines()[0].as_bytes()).unwrap();
    entries.push(Enrollment::new(HybridSigner::public_key(&signer_from_seed(&[42; 32])).clone(), false, Some("planted".into())).unwrap());
    let r = skep(&["claim", "--hosted", "-", "--board", &board], &[], Some(encode_enroll(&entries).as_bytes()));
    assert_eq!(r.code, 0, "{r:?}");
    let bindings = || std::fs::read_to_string(store.join("bindings")).ok();
    let before = bindings();
    let bind = ["bind", "--board", &board, "--dir", s(&store), "--account", "1.0.1", "--principal", "1"];
    // `pair` without the files: the act is the files, nothing written.
    let r = skep(&bind, &[], Some(b"pair\n"));
    assert_eq!(r.code, 3, "{r:?}");
    assert!(r.err.contains("which landing is this?") && r.err.contains("re-run with `--anchor <a> --anchor <b>`"), "{}", r.err);
    assert_eq!(bindings(), before, "no binding line written");
    // THIS KEY ALONE, the DECLINE arm's compare: the key written beside it
    // halts, ahead of any session and any line.
    let r = skep(&bind, &[], Some(b"alone\n"));
    assert_eq!(r.code, 3, "{r:?}");
    assert!(r.err.contains("NOT yours to keep as it stands (AUTH-5.53)"), "{}", r.err);
    assert!(r.err.contains("a key you did not send stands in the genesis") && r.err.contains("planted"), "{}", r.err);
    assert!(r.out.is_empty(), "no facts, no agent space: {}", r.out);
    assert_eq!(bindings(), before, "no binding line written");
    // Asked again until the answer is one of the three; `hop` compares
    // nothing, and the key beside this one stands unseen — the price the
    // question names for that answer where another hand wrote the set.
    let r = skep(&bind, &[], Some(b"\nperhaps\nhop\n"));
    assert_eq!(r.code, 0, "{r:?}");
    assert_eq!(r.err.matches("answer hop, alone or pair: ").count(), 3, "{}", r.err);
    assert!(r.lines().contains(&"agent space 1.0.1.1"), "{}", r.out);

    // An honest one-key genesis answered `alone`: compared whole, it passes.
    let dir = tempfile::tempdir().unwrap();
    let sd = spawn(&dir.path().join("board"), false);
    let board = origin(sd.port());
    let store = dir.path().join("store");
    let r = skep(&["keygen", "--label", "mine", "--payload", "--dir", s(&store)], &[], None);
    assert_eq!(r.code, 0, "{r:?}");
    let payload = r.lines()[0].to_string();
    let r = skep(&["claim", "--hosted", "-", "--board", &board], &[], Some(payload.as_bytes()));
    assert_eq!(r.code, 0, "{r:?}");
    let r = skep(&["bind", "--board", &board, "--dir", s(&store), "--account", "1.0.1", "--principal", "1"], &[], Some(b"alone\n"));
    assert_eq!(r.code, 0, "{r:?}");
    assert!(!r.err.contains("no landing was answered"), "{}", r.err);
    assert!(r.lines().contains(&"agent space 1.0.1.1"), "{}", r.out);
}

/// AN UNWRITABLE STORE WARNS WITH THE LINE AND LANDS THE FACTS (§2.2 `bind`;
/// §3.7: a WARNING, never a refusal): the append's lock refused, `bind`
/// exits 0, prints the three facts, says the binding line for the person to
/// record, and leaves the bindings as they were.
#[test]
fn bind_on_a_store_it_cannot_append_warns_with_the_line_and_lands_the_facts() {
    let dir = tempfile::tempdir().unwrap();
    let b = hosted_and_bound(dir.path());
    let before = std::fs::read_to_string(b.store.join("bindings")).unwrap();
    // A directory where the lock file stands: opening it to write fails for
    // every writer, whatever its privilege.
    std::fs::remove_file(b.store.join("lock")).unwrap();
    std::fs::create_dir(b.store.join("lock")).unwrap();
    let r = skep(&["bind", "--board", &b.board, "--dir", s(&b.store), "--account", "1.0.1", "--principal", "1"], &[], None);
    assert_eq!(r.code, 0, "{r:?}");
    assert!(r.err.contains(&format!("record this binding line yourself: {} 1 1.0.1 {}", b.board, b.fp)), "{}", r.err);
    assert_eq!(r.lines(), ["account 1.0.1", "principal 1", format!("origin {}", b.board).as_str()]);
    assert_eq!(std::fs::read_to_string(b.store.join("bindings")).unwrap(), before, "nothing appended");
}

/// A KEY FILE OUTSIDE THE STORE BINDS NOTHING THERE (§3.5 arm 2: the line
/// names a key this store holds): `bind` with `--key`, or `SKEP_KEY`,
/// naming a copy of the bound key, against a store that holds no file for
/// it, halts naming the file before anything is written — never a binding
/// or persist-first line every later lookup would meet as a missing file;
/// the key named inside its own store binds.
#[test]
fn bind_refuses_a_key_file_its_store_does_not_hold() {
    let dir = tempfile::tempdir().unwrap();
    let b = hosted_and_bound(dir.path());
    let held = b.store.join("keys").join(format!("{}.key", b.fp));
    let loose = dir.path().join("loose.key");
    std::fs::copy(&held, &loose).unwrap();
    let empty = dir.path().join("empty");
    for (flags, envs) in [(vec!["--key", s(&loose)], vec![]), (vec![], vec![("SKEP_KEY", s(&loose))])] {
        let mut args = vec!["bind", "--board", &b.board, "--dir", s(&empty), "--account", "1.0.1", "--principal", "1"];
        args.extend(flags);
        let r = skep(&args, &envs, None);
        assert_eq!(r.code, 3, "{envs:?}: {r:?}");
        assert!(r.err.contains(&format!("the key file {} is not this store's", loose.display())), "{}", r.err);
        assert!(r.out.is_empty(), "{}", r.out);
        assert!(!empty.exists(), "nothing written");
    }
    let r = skep(&["bind", "--board", &b.board, "--dir", s(&b.store), "--key", s(&held), "--account", "1.0.1", "--principal", "1"], &[], None);
    assert_eq!(r.code, 0, "{r:?}");
}

/// TWO KEYS NAMED ARE REFUSED, NEVER ONE PICKED (§2.2: selecting within a
/// store is `--select`'s alone, and `--key` names one key file): `fingerprint
/// --select` beside `--key`, or beside `SKEP_KEY`, is exit 2 printing
/// nothing — never one key's record printed for the other's; a SKEP_KEY set
/// empty is unset, and `--select` alone answers.
#[test]
fn fingerprint_refuses_select_beside_a_key_file() {
    let dir = tempfile::tempdir().unwrap();
    let store = dir.path().join("store");
    let phone = skep(&["keygen", "--label", "phone", "--dir", s(&store)], &[], None).lines()[0].to_string();
    let laptop = skep(&["keygen", "--label", "laptop", "--dir", s(&store)], &[], None).lines()[0].to_string();
    let laptop_file = store.join("keys").join(format!("{laptop}.key"));
    for (flags, envs) in [(vec!["--key", s(&laptop_file)], vec![]), (vec![], vec![("SKEP_KEY", s(&laptop_file))])] {
        let mut args = vec!["fingerprint", "--dir", s(&store), "--select", "phone", "--payload"];
        args.extend(flags);
        let r = skep(&args, &envs, None);
        assert_eq!(r.code, 2, "{envs:?}: {r:?}");
        assert!(r.err.contains("`--select` names a key in the store and `--key` (or SKEP_KEY) names a key file: give one"), "{}", r.err);
        assert!(r.out.is_empty(), "{}", r.out);
    }
    let r = skep(&["fingerprint", "--dir", s(&store), "--select", "phone"], &[("SKEP_KEY", "")], None);
    assert_eq!(r.code, 0, "{r:?}");
    assert!(r.lines().contains(&phone.as_str()) && !r.out.contains(&laptop), "{}", r.out);
}

/// THE ACCOUNT'S FIRST SIGNED SESSION IS CONTENT-SCOPED (§2.2 `bind`): the
/// one session `bind` opens as the account's principal, for the first
/// session's acts, carries the content scope on the wire — the one place a
/// scope is visible, since the session is closed before anything reads it
/// and every act it runs is a content session's too.
#[test]
fn the_first_signed_session_bind_runs_is_content_scoped_on_the_wire() {
    let dir = tempfile::tempdir().unwrap();
    let (sd, tap) = spawn_tapped(&dir.path().join("board"));
    let board = origin(sd.port());
    let store = dir.path().join("store");
    let r = skep(&["keygen", "--label", "mine", "--payload", "--dir", s(&store)], &[], None);
    assert_eq!(r.code, 0, "{r:?}");
    let r = skep(&["claim", "--hosted", "-", "--board", &board], &[], Some(r.lines()[0].as_bytes()));
    assert_eq!(r.code, 0, "{r:?}");
    let r = skep(&["bind", "--board", &tap.origin, "--dir", s(&store), "--account", "1.0.1", "--principal", "1"], &[], None);
    assert_eq!(r.code, 0, "{r:?}");
    assert!(r.lines().contains(&"agent space 1.0.1.1"), "the first session's acts ran: {}", r.out);
    let opens: Vec<Value> =
        tap.requests().into_iter().filter(|(line, _)| line == "POST /session HTTP/1.1").map(|(_, body)| serde_json::from_str(&body).expect("a session opening's body")).collect();
    let own: Vec<&Value> = opens.iter().filter(|body| body["principal"] == 1).collect();
    let principals: Vec<&Value> = opens.iter().map(|body| &body["principal"]).collect();
    assert_eq!(own.len(), 1, "one session opened as the account's principal, among the openings for {principals:?}");
    assert_eq!(own[0]["scope"], "content", "the session `bind` opens is CONTENT-scoped; its opening's scope is {}", own[0]["scope"]);
}

/// A REPLY FROM ANOTHER BOARD HALTS `bind` (`facts_of`): a reply whose
/// origin line names another origin than the one this command dials halts
/// naming both, before any socket opens — the dead board behind it is never
/// dialed — and nothing is written.
#[test]
fn a_reply_naming_another_origin_halts_bind_before_any_socket_opens() {
    let dir = tempfile::tempdir().unwrap();
    let store = dir.path().join("store");
    let r = skep(&["bind", "--board", "http://127.0.0.1:1", "--dir", s(&store), "--payload", "-"], &[], Some(b"account 1.0.1\nprincipal 1\norigin http://127.0.0.1:2\n"));
    assert_eq!(r.code, 3, "a halt on the reply, never transport: {r:?}");
    assert!(r.err.contains("the reply names origin http://127.0.0.1:2 and this command dials http://127.0.0.1:1"), "{}", r.err);
    assert!(r.out.is_empty(), "{}", r.out);
    assert!(!store.exists(), "nothing written");
}

/// A SETTING REFUSED IS NEVER A SETTING ABSENT (§2.3's exit 2; `args.rs`):
/// a malformed `--principal` or `SKEP_PRINCIPAL` is a usage refusal at every
/// command that reads one, before any socket opens — the dead board behind
/// it is never dialed — and the store's lone binding never stands in for
/// it; a malformed `--board` at `accept` is refused, never asked for again
/// nor dropped; a reply's principal line that is no principal halts naming
/// it; an unreadable bindings file halts `fingerprint` rather than listing
/// every key UNBOUND.
#[test]
fn a_refused_setting_is_never_read_as_an_absent_one() {
    let dir = tempfile::tempdir().unwrap();
    let store = dir.path().join("store");
    let dead = "http://127.0.0.1:1";
    for args in [
        vec!["session", "--board", dead, "--dir", s(&store), "--principal", "7x"],
        vec!["verify", "--board", dead, "--dir", s(&store), "--principal", "7x"],
        vec!["enroll", "--board", dead, "--dir", s(&store), "--principal", "7x", "--reply", "ab"],
        vec!["recover", "--board", dead, "--dir", s(&store), "--principal", "7x"],
        vec!["retire", "--board", dead, "--dir", s(&store), "--principal", "7x", "--fingerprint", "ab"],
        vec!["rotate", "--board", dead, "--dir", s(&store), "--principal", "7x"],
        vec!["handoff", "--board", dead, "--dir", s(&store), "--principal", "7x", "--account", "1.0.1.2"],
        vec!["bind", "--board", dead, "--dir", s(&store), "--principal", "7x", "--account", "1.0.1"],
        vec!["claim", "--board", dead, "--dir", s(&store), "--principal", "7x", "--hosted", "-"],
    ] {
        let r = skep(&args, &[], None);
        assert_eq!(r.code, 2, "{args:?}: {r:?}");
        assert!(r.err.contains("--principal: '7x' is not a principal"), "{args:?}: {}", r.err);
    }
    // The variable is judged as the flag is, beside a binding that would
    // otherwise stand in for it.
    std::fs::create_dir_all(&store).unwrap();
    std::fs::write(store.join("bindings"), format!("{dead} 1 1.0.1 {}\n", "ab".repeat(32))).unwrap();
    let r = skep(&["verify", "--board", dead, "--dir", s(&store)], &[("SKEP_PRINCIPAL", "7x")], None);
    assert_eq!(r.code, 2, "{r:?}");
    assert!(r.err.contains("--principal: '7x' is not a principal"), "{}", r.err);
    // `accept`'s board given badly: refused at `--reprint` and at the beat.
    for args in [vec!["accept", "--dir", s(&store), "--reprint", "--board", "HTTP://x"], vec!["accept", "--dir", s(&store), "--board", "HTTP://x", "--account", "1.0.1.2"]] {
        let r = skep(&args, &[], None);
        assert_eq!(r.code, 2, "{args:?}: {r:?}");
        assert!(r.err.contains("--board: 'HTTP://x' is not a canonical origin"), "{args:?}: {}", r.err);
    }
    // A reply whose principal line is no principal: a halt naming it, before
    // any socket opens.
    let r = skep(&["bind", "--board", dead, "--dir", s(&store), "--payload", "-"], &[], Some(b"account 1.0.1\nprincipal 7x\n"));
    assert_eq!(r.code, 3, "{r:?}");
    assert!(r.err.contains("the reply's principal line `7x` is not a principal"), "{}", r.err);
    assert!(r.err.contains("as the reply prints it") && r.err.contains("re-take the three facts from whoever printed the reply"), "{}", r.err);
    // An unreadable bindings file: a halt naming it, never every key UNBOUND.
    let unreadable = dir.path().join("unreadable");
    let r = skep(&["keygen", "--label", "k", "--dir", s(&unreadable)], &[], None);
    assert_eq!(r.code, 0, "{r:?}");
    std::fs::create_dir_all(unreadable.join("bindings")).unwrap();
    let r = skep(&["fingerprint", "--dir", s(&unreadable)], &[], None);
    assert_eq!(r.code, 3, "{r:?}");
    assert!(r.err.contains("bindings") && !r.out.contains("UNBOUND"), "{r:?}");
}

/// A VARIABLE THAT IS NOT TEXT IS REFUSED, NEVER READ AS ABSENT (§2.3's exit
/// 2; `args.rs`'s `env_text`, in the daemon's words): each `SKEP_*` variable
/// set to bytes that are not UTF-8 is exit 2 naming it, at a command that
/// reads it — never the default store written in its place, the store's own
/// keys listed, the store's lone binding standing in, the variable's absence
/// refused instead, or the token on stdin closed.
#[cfg(unix)]
#[test]
fn a_variable_that_is_not_text_is_refused_never_read_as_absent() {
    use std::ffi::OsStr;
    use std::os::unix::ffi::OsStrExt;

    let dir = tempfile::tempdir().unwrap();
    let not_text = OsStr::from_bytes(b"\xff");
    // SKEP_KEYSTORE at `keygen`: nothing generated under ~/.skep.
    let home = dir.path().join("home");
    std::fs::create_dir_all(&home).unwrap();
    let r = skep_os(&["keygen", "--label", "k"], &[("HOME", home.as_os_str()), ("SKEP_KEYSTORE", not_text)], None);
    assert_eq!(r.code, 2, "{r:?}");
    assert!(r.err.contains("SKEP_KEYSTORE: the value is not UTF-8 text"), "{}", r.err);
    assert!(!home.join(".skep").exists(), "nothing generated in the default store");
    // The rest, beside a store holding a key and a binding that would stand
    // in for the principal, with a token on stdin that would be closed.
    let store = dir.path().join("store");
    let r = skep(&["keygen", "--label", "k", "--dir", s(&store)], &[], None);
    assert_eq!(r.code, 0, "{r:?}");
    let dead = "http://127.0.0.1:1";
    std::fs::write(store.join("bindings"), format!("{dead} 1 1.0.1 {}\n", r.lines()[0])).unwrap();
    for (var, args) in [
        ("SKEP_KEY", vec!["fingerprint", "--dir", s(&store)]),
        ("SKEP_PRINCIPAL", vec!["verify", "--board", dead, "--dir", s(&store)]),
        ("SKEP_BOARD", vec!["health"]),
        ("SKEP_SESSION", vec!["session", "--close", "-", "--board", dead]),
    ] {
        let r = skep_os(&args, &[(var, not_text)], Some("ab".repeat(16).as_bytes()));
        assert_eq!(r.code, 2, "{var}: {r:?}");
        assert!(r.err.contains(&format!("{var}: the value is not UTF-8 text")), "{var}: {}", r.err);
        assert!(r.out.is_empty(), "{var}: {}", r.out);
    }
}

/// AN ARGUMENT THAT IS NOT TEXT IS REFUSED, NEVER A PANIC (§2.3's exit 2;
/// `args.rs`'s `parse`): a `--dir` whose bytes are not UTF-8 is exit 2
/// naming the argument, as a variable's value is — never std's panic on
/// argv read as text, an exit 101 §2.3 does not have — and nothing is
/// generated.
#[cfg(unix)]
#[test]
fn an_argument_that_is_not_text_is_refused_never_a_panic() {
    use std::ffi::OsStr;
    use std::os::unix::ffi::OsStrExt;

    let dir = tempfile::tempdir().unwrap();
    let store = dir.path().join(OsStr::from_bytes(b"store-\xff"));
    let r = skep_os(&[OsStr::new("keygen"), OsStr::new("--label"), OsStr::new("k"), OsStr::new("--dir"), store.as_os_str()], &[], None);
    assert_eq!(r.code, 2, "{r:?}");
    assert!(r.err.contains("store-\u{fffd}' is not UTF-8 text"), "the argument named: {}", r.err);
    assert!(!r.err.contains("panicked"), "{}", r.err);
    assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0, "nothing generated");
}

/// A DATA WRITE STDOUT REFUSES IS A HALT, NEVER A PANIC (§2.3): with
/// stdout a pipe whose reader is gone, `--help`, the hosted claim and a
/// session each meet the refusal at their first DATA line — exit 3 naming
/// it, its act the read-back, where a print macro's panic is exit 101. The
/// claim's act stands, and the read-back finds it; the session's token,
/// refused, is never handed over — its talk is never said.
#[test]
fn a_stdout_that_refuses_the_data_is_a_halt_never_a_panic() {
    let refused = |r: &crate::common::Run| {
        assert_eq!(r.code, 3, "{r:?}");
        assert!(r.err.contains("stdout refused this command's data") && r.err.contains("read it back"), "{}", r.err);
        assert!(!r.err.contains("panicked"), "{}", r.err);
    };
    refused(&skep_stdout_closed(&["--help"], b""));
    let dir = tempfile::tempdir().unwrap();
    let sd = spawn(&dir.path().join("board"), false);
    let board = origin(sd.port());
    let store = dir.path().join("store");
    let r = skep(&["keygen", "--label", "mine", "--payload", "--dir", s(&store)], &[], None);
    assert_eq!(r.code, 0, "{r:?}");
    let (payload, fp) = (r.lines()[0].to_string(), r.lines()[1].to_string());
    refused(&skep_stdout_closed(&["claim", "--hosted", "-", "--board", &board], payload.as_bytes()));
    let r = skep(&["claim", "--hosted", "-", "--board", &board], &[], Some(payload.as_bytes()));
    assert_eq!(r.code, 0, "{r:?}");
    assert_eq!(r.out.trim(), "claimed by 1.0.1", "the claim committed ahead of the refused write");
    let key = store.join("keys").join(format!("{fp}.key"));
    let r = skep_stdout_closed(&["session", "--board", &board, "--dir", s(&store), "--principal", "1", "--key", s(&key)], b"");
    refused(&r);
    assert!(!r.err.contains("It is live until"), "the refused token is never handed over: {}", r.err);
}

/// A TALK LINE STDERR REFUSES IS DROPPED, NEVER A PANIC (`talk`, `show`):
/// with stderr a pipe whose reader is gone the exit code still carries the
/// outcome — `keygen`'s statements, custody line and box prompt dropped and
/// its DATA written (0), a usage refusal (2), a halt (3) — where a write that
/// panics is exit 101.
#[test]
fn a_stderr_that_refuses_the_talk_drops_it_and_the_exit_code_still_carries_the_outcome() {
    let dir = tempfile::tempdir().unwrap();
    let store = dir.path().join("store");
    let r = skep_stderr_closed(&["keygen", "--label", "k", "--dir", s(&store)], None);
    assert_eq!((r.code, r.lines().len()), (0, 3), "the statements and the custody line dropped, the fingerprint written: {r:?}");
    let r = skep_stderr_closed(&["keygen", "--dir", s(&store)], Some(b"phone\n"));
    assert_eq!(r.code, 0, "the box's prompt dropped, its answer read: {r:?}");
    assert_eq!(skep(&["fingerprint", "--dir", s(&store), "--select", "phone"], &[], None).code, 0, "the key the box named");
    assert_eq!(skep_stderr_closed(&["frobnicate"], None).code, 2);
    assert_eq!(skep_stderr_closed(&["fingerprint", "--dir", s(&store), "--select", "zz"], None).code, 3);
}

/// The plaintext non-loopback WARNING rides before any signed session, and
/// the default store is `~/.skep`.
#[test]
fn the_plaintext_warning_precedes_a_session_and_the_store_defaults_to_home() {
    let dir = tempfile::tempdir().unwrap();
    let store = dir.path().join("store");
    let r = skep(&["session", "--board", "http://192.0.2.1:9", "--dir", s(&store)], &[], None);
    assert!(r.err.contains("plaintext non-loopback origin") && r.err.contains("AUTH-4.53"), "{}", r.err);
    assert_eq!(r.code, 3, "halts on the store, no socket opened: {r:?}");
    // No warning at loopback.
    let r = skep(&["session", "--board", "http://127.0.0.1:1", "--dir", s(&store)], &[], None);
    assert!(!r.err.contains("plaintext non-loopback"));
    // The default store: HOME/.skep.
    let home = dir.path().join("home");
    std::fs::create_dir_all(&home).unwrap();
    let r = skep(&["keygen", "--label", "home key"], &[("HOME", s(&home))], None);
    assert_eq!(r.code, 0, "{r:?}");
    let fp = r.lines()[0].to_string();
    assert!(home.join(".skep").join("keys").join(format!("{fp}.key")).is_file(), "written under ~/.skep");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(std::fs::metadata(home.join(".skep")).unwrap().permissions().mode() & 0o777, 0o700);
        assert_eq!(std::fs::metadata(home.join(".skep/keys").join(format!("{fp}.key"))).unwrap().permissions().mode() & 0o777, 0o600);
    }
    // SKEP_KEYSTORE beats HOME; --dir beats SKEP_KEYSTORE.
    let env_store = dir.path().join("env-store");
    let r = skep(&["keygen", "--label", "env key"], &[("HOME", s(&home)), ("SKEP_KEYSTORE", s(&env_store))], None);
    assert_eq!(r.code, 0);
    assert!(env_store.join("keys").join(format!("{}.key", r.lines()[0])).is_file());
    let flag_store = dir.path().join("flag-store");
    let r = skep(&["keygen", "--label", "flag key", "--dir", s(&flag_store)], &[("HOME", s(&home)), ("SKEP_KEYSTORE", s(&env_store))], None);
    assert_eq!(r.code, 0);
    assert!(flag_store.join("keys").join(format!("{}.key", r.lines()[0])).is_file());
    // Two keys in a store, neither bound: the arm-4 face names them; a
    // `--select` by label that matches both is listed, never picked.
    let two = dir.path().join("two");
    skep(&["keygen", "--label", "twin", "--dir", s(&two)], &[], None);
    skep(&["keygen", "--label", "twin", "--dir", s(&two)], &[], None);
    let r = skep(&["fingerprint", "--dir", s(&two), "--select", "twin"], &[], None);
    assert_eq!(r.code, 3, "{r:?}");
    assert!(r.err.contains("matches more than one key") && r.err.contains("never a pick"), "{}", r.err);
    let r = skep(&["fingerprint", "--dir", s(&two), "--select", "zz"], &[], None);
    assert_eq!(r.code, 3);
    assert!(r.err.contains("no key in the store matches"));
}

/// `bind`'s paste prompt, where neither `--account` nor a reply names the
/// account: the prompt rides stderr — naming the reply's three senders, one
/// per landing — and the answer is read from stdin, so stdout carries
/// nothing but data (§2.4). The facts are judged before any socket opens — a
/// dead board behind them is never dialed.
#[test]
fn bind_asks_for_the_account_on_stderr_and_reads_the_answer_from_stdin() {
    let dir = tempfile::tempdir().unwrap();
    let store = dir.path().join("store");
    let r = skep(&["bind", "--board", "http://127.0.0.1:1", "--dir", s(&store), "--principal", "1"], &[], Some(b"not-an-address\n"));
    assert_eq!(r.code, 3, "a halt on the facts, never transport: {r:?}");
    assert!(r.err.contains("account address (from the reply — the enrolling device's, the giver's at a handoff, or your host's): "), "the prompt on stderr: {}", r.err);
    assert!(r.err.contains("`not-an-address` is not an account address"), "the answer read from stdin: {}", r.err);
    assert!(r.out.is_empty(), "nothing on stdout: {}", r.out);
}

/// NO STORE NAMED AND NO HOME TO DEFAULT IT FROM IS A USAGE REFUSAL (§6; §9
/// item 10): with neither `--dir`, `SKEP_KEYSTORE` nor a home directory,
/// `keygen` is exit 2 naming what is required, and writes nothing — the
/// working directory least of all.
#[test]
fn keygen_with_no_home_and_no_store_named_is_a_usage_refusal_that_writes_nothing() {
    let cwd = tempfile::tempdir().unwrap();
    let r = skep_in(cwd.path(), &["keygen", "--label", "k"], &[], None);
    assert_eq!(r.code, 2, "{r:?}");
    assert!(r.err.contains("--dir (or SKEP_KEYSTORE) is required: no home directory to default ~/.skep from"), "{}", r.err);
    assert_eq!(std::fs::read_dir(cwd.path()).unwrap().count(), 0, "nothing written");
}

/// A VARIABLE SET EMPTY IS A SETTING NOT GIVEN (`args.rs`'s `env_text`):
/// `SKEP_KEYSTORE=` leaves the default store standing — never a store at the
/// empty path, which is the working directory — and `SKEP_BOARD=` is a
/// board not given, never a board given badly.
#[test]
fn a_variable_set_empty_is_a_setting_not_given() {
    let dir = tempfile::tempdir().unwrap();
    let (home, cwd) = (dir.path().join("home"), dir.path().join("cwd"));
    std::fs::create_dir_all(&home).unwrap();
    std::fs::create_dir_all(&cwd).unwrap();
    let r = skep_in(&cwd, &["keygen", "--label", "k"], &[("HOME", s(&home)), ("SKEP_KEYSTORE", "")], None);
    assert_eq!(r.code, 0, "{r:?}");
    assert!(home.join(".skep").join("keys").join(format!("{}.key", r.lines()[0])).is_file(), "written in the default store");
    assert_eq!(std::fs::read_dir(&cwd).unwrap().count(), 0, "nothing written where the empty path points");
    let r = skep(&["health"], &[("SKEP_BOARD", "")], None);
    assert_eq!(r.code, 2, "{r:?}");
    assert!(r.err.contains("--board (or SKEP_BOARD) is required"), "{}", r.err);
}

/// THE DEVICE-NAME BOX AT THE PROMPT (§2.2 `keygen`; §2.4): without
/// `--label` the box is asked on stdin, its statements said — the
/// consequence the notebook's — and a name outside AUTH-1.24's domain is
/// refused at the box and asked again, before anything is generated.
#[test]
fn keygen_without_a_label_asks_the_box_on_stdin_and_asks_again_on_a_refused_name() {
    let dir = tempfile::tempdir().unwrap();
    let store = dir.path().join("store");
    let r = skep(&["keygen", "--dir", s(&store)], &[], Some(b"\nphone\n"));
    assert_eq!(r.code, 0, "{r:?}");
    assert_eq!(r.lines().len(), 3, "the fingerprint, flat and grouped: {}", r.out);
    assert_eq!(r.err.matches("name this device: ").count(), 2, "asked again after the refusal: {}", r.err);
    assert!(r.err.contains("[AUTH-1.24] that name is refused at the box: the label is empty"), "{}", r.err);
    for statement in ["This name is permanent and cannot be edited", "It holds the DEVICE's name — never your own", "at this notebook it is readable by anything on the machine"]
    {
        assert!(r.err.contains(statement), "the box's statement `{statement}`: {}", r.err);
    }
    let v: Value = serde_json::from_str(&skep(&["fingerprint", "--dir", s(&store), "--json"], &[], None).out).unwrap();
    assert_eq!(v.as_array().map(Vec::len), Some(1), "one key generated: {v}");
    assert_eq!(v[0]["label"], "phone");
}

/// THE BOX'S ANSWER WITHOUT ITS LINE ENDING (`answer`; §6's Windows
/// terminal): a name typed and ended `\r\n` is the name alone — AUTH-1.24's
/// domain admits a carriage return, so one kept would be a permanent byline
/// nobody typed.
#[test]
fn keygen_s_box_takes_the_name_without_a_windows_line_ending() {
    let dir = tempfile::tempdir().unwrap();
    let store = dir.path().join("store");
    let r = skep(&["keygen", "--dir", s(&store)], &[], Some(b"laptop\r\n"));
    assert_eq!(r.code, 0, "{r:?}");
    let v: Value = serde_json::from_str(&skep(&["fingerprint", "--dir", s(&store), "--json"], &[], None).out).unwrap();
    assert_eq!(v[0]["label"], "laptop");
}

/// THE BOX ABANDONED IS A HALT, AND NOTHING IS GENERATED (§2.2 `keygen`):
/// with the input ended before a name, `keygen` halts naming the box and
/// the store stays unwritten.
#[test]
fn keygen_s_box_abandoned_is_a_halt_and_generates_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let store = dir.path().join("store");
    let r = skep(&["keygen", "--dir", s(&store)], &[], None);
    assert_eq!(r.code, 3, "{r:?}");
    assert!(r.err.contains("no device name was given"), "{}", r.err);
    assert!(!store.exists(), "nothing generated");
}

/// THE PENDING STATE BESIDE A BOUND KEY (AUTH-5.32; §2.2 `fingerprint`): in a
/// store that has bound a board, an unbound key is pending at no board this
/// store knows — the re-print, the hop's and the rotation's acts and the
/// handoff recipient's clause beside it — and never owed a claim, which is
/// the act only where no board has been claimed from the store at all; the
/// bound key lists its binding and no pending state.
#[test]
fn an_unbound_key_beside_a_bound_one_is_pending_at_no_board_this_store_knows_never_owed_a_claim() {
    let dir = tempfile::tempdir().unwrap();
    let store = dir.path().join("store");
    let bound = skep(&["keygen", "--label", "bound", "--dir", s(&store)], &[], None).lines()[0].to_string();
    let pending = skep(&["keygen", "--label", "pending", "--dir", s(&store)], &[], None).lines()[0].to_string();
    std::fs::write(store.join("bindings"), format!("http://127.0.0.1:1 1 1.0.1 {bound}\n")).unwrap();
    let r = skep(&["fingerprint", "--dir", s(&store), "--select", &pending], &[], None);
    assert_eq!(r.code, 0, "{r:?}");
    let line = r.lines().into_iter().find(|l| l.starts_with("UNBOUND")).expect("the pending state");
    assert!(line.starts_with("UNBOUND — this key is enrolled at no board this store knows:"), "{line}");
    assert!(line.contains("skep rotate --payload") && line.contains("the re-offer is `skep accept --reprint`"), "{line}");
    assert!(!r.out.contains("skep claim"), "a claim is no act of a store that has bound a board: {}", r.out);
    let r = skep(&["fingerprint", "--dir", s(&store), "--select", &bound], &[], None);
    assert_eq!(r.code, 0, "{r:?}");
    assert!(r.lines().contains(&"bound http://127.0.0.1:1 principal 1 account 1.0.1") && !r.out.contains("UNBOUND"), "{}", r.out);
}

/// A PAYLOAD FILE THAT IS NOT THERE HALTS NAMING IT (AUTH-5.67: a
/// mis-pathed file is a halt naming the path, never a fallback), before any
/// socket opens — the dead board behind it is never dialed.
#[test]
fn a_payload_file_that_is_not_there_halts_naming_it_before_any_socket_opens() {
    let dir = tempfile::tempdir().unwrap();
    let missing = dir.path().join("missing.json");
    let r = skep(&["claim", "--hosted", s(&missing), "--board", "http://127.0.0.1:1"], &[], None);
    assert_eq!(r.code, 3, "a halt on the file, never transport: {r:?}");
    assert!(r.err.contains(&format!("the payload file {} could not be read", missing.display())), "{}", r.err);
}
