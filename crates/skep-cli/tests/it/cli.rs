//! THE BINARY through argv, stdin and stdout (`client.md` §2; the build
//! brief §3): the command table, exit 2 before any socket for a
//! non-canonical board, the person doors' terminal check, THE LOOP over the
//! hosted arm (keygen → claim --hosted → bind → session → verify → health →
//! fingerprint), the token's custody, the whole-set compare, `bind`'s
//! landing question, a refused setting never read as an absent one, a
//! variable that is not text refused, the plaintext warning, the default
//! store, `bind`'s paste prompt on stderr.

use serde_json::Value;
use skep_client::sheet::{KeyFile, Label, Seed};
use skep_client::sign::signer_from_seed;
use skep_identity::{encode_enroll, parse_enroll, Enrollment};
use skep_signature::HybridSigner;

use crate::common::{origin, s, skep, skep_os, spawn};

const SEVEN: [&str; 7] = ["keygen", "claim", "session", "fingerprint", "verify", "health", "bind"];

#[test]
fn help_lists_the_first_seven_and_refuses_the_flag_shapes() {
    let run = skep(&["--help"], &[], None);
    assert_eq!(run.code, 0, "{run:?}");
    for c in SEVEN {
        assert!(run.out.contains(&format!("\n  {c} ")), "{c} listed:\n{}", run.out);
    }
    let r = skep(&["frobnicate"], &[], None);
    assert_eq!(r.code, 2);
    assert!(r.err.contains("unknown command"));
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
    let r = skep(&["claim", "--board", &board, "--dir", s(&store)], &[], None);
    assert_eq!(r.code, 3, "{r:?}");
    assert!(r.err.contains("requires a controlling terminal"), "{}", r.err);
    assert_eq!(skep(&["health", "--board", &board], &[], None).out.is_empty(), false, "the board was not touched by claim: still unclaimed");
    let r = skep(&["keygen", "--anchors", "--dir", s(&store)], &[], None);
    assert_eq!(r.code, 3, "{r:?}");
    assert!(r.err.contains("requires a controlling terminal"));
    assert!(!store.join("keys").exists(), "nothing generated before the check");
    // Plain keygen runs without one.
    let r = skep(&["keygen", "--label", "service key", "--dir", s(&store)], &[], None);
    assert_eq!(r.code, 0, "{r:?}");
    let lines = r.lines();
    assert_eq!(lines.len(), 3, "the fingerprint flat, then grouped on two lines: {:?}", lines);
    assert_eq!(lines[0].len(), 64);
    assert_eq!(lines[1].split_whitespace().count(), 4);
    assert!(r.err.contains("[AUTH-5.42]") && r.err.contains("permanent and cannot be edited"), "the box statements render for a flag-fixed label: {}", r.err);
    assert!(r.err.contains("key file written:") && r.err.contains("0600 under 0700"), "the custody line beside the path: {}", r.err);
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
fn the_loop_through_the_binary() {
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
    assert!(r.out.contains("first act:") && r.out.contains("skep verify") && r.out.contains("second act:"), "{}", r.out);
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
    // Wrong facts: confirmed against the board, refused.
    let r = skep(&["bind", "--board", &board, "--dir", s(&store), "--account", "1.0.1", "--principal", "7"], &[], None);
    assert_eq!(r.code, 3, "{r:?}");
    assert!(r.err.contains("not the principal seated at 1.0.1"), "{}", r.err);

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
    // The token is a live CONTENT session: a credential act under it is
    // content_session. (Checked through the library's own reading of the
    // feed is the lane's library suite; here the close suffices.)
    // --close takes `-` and reads stdin.
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
    let r = skep(&["session", "--close", "-", "--board", &board], &[], Some(b"not a token"));
    assert_eq!(r.code, 2);

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
    let r = skep(&["verify", "--board", &board, "--dir", s(&store), "--principal", "1"], &[], None);
    assert_eq!(r.code, 0);
    assert!(r.err.contains("one-key read"), "without a payload the one-key read is named: {}", r.err);
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

/// THE WHOLE-SET COMPARE through the binary: a key the operator planted in
/// the genesis halts `verify --payload` in AUTH-5.53's terms; the honest
/// genesis passes with `--anchor` files too.
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

/// The plaintext non-loopback WARNING rides before any signed session, and
/// the default store is `~/.skep`.
#[test]
fn the_plaintext_warning_and_the_default_store() {
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
/// account: the prompt rides stderr and the answer is read from stdin, so
/// stdout carries nothing but data (§2.4). The facts are judged before any
/// socket opens — a dead board behind them is never dialed.
#[test]
fn bind_asks_for_the_account_on_stderr_and_reads_the_answer_from_stdin() {
    let dir = tempfile::tempdir().unwrap();
    let store = dir.path().join("store");
    let r = skep(&["bind", "--board", "http://127.0.0.1:1", "--dir", s(&store), "--principal", "1"], &[], Some(b"not-an-address\n"));
    assert_eq!(r.code, 3, "a halt on the facts, never transport: {r:?}");
    assert!(r.err.contains("account address (from the enrolling device's reply): "), "the prompt on stderr: {}", r.err);
    assert!(r.err.contains("`not-an-address` is not an account address"), "the answer read from stdin: {}", r.err);
    assert!(r.out.is_empty(), "nothing on stdout: {}", r.out);
}
