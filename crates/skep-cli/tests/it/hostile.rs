//! WHAT ARRIVES FROM OUTSIDE THE PERSON'S TRUST, through the binary: a
//! board's answer — the board may be the very operator AUTH-4.58's compare
//! exists to catch, or anyone on a plaintext path — reaching the terminal
//! inert, on stderr and on stdout; a reply a third party printed, landed by
//! `bind` only as the person's screen shows it; a payload read to its cap
//! and no further; and a principal past the range a JSON number carries.
//! Every board here is a [`canned`] one or a dead origin, so each refusal
//! is seen before, or instead of, any daemon's answer.

use crate::common::{canned, s, skep, Run};

/// An origin nobody answers at: a run that dials it is transport, exit 4,
/// so an exit 3 or 2 there is a refusal made before any socket opened.
const DEAD: &str = "http://127.0.0.1:1";

/// Whether a run said an escape or a bell raw, on either stream.
fn raw_control(r: &Run) -> bool {
    r.err.bytes().chain(r.out.bytes()).any(|b| b == 0x1b || b == 0x07)
}

/// A BOARD'S BYTES REACH THE TERMINAL INERT, NEVER AS COMMANDS (`talk`,
/// `show`, `data`; AUTH-5.2's rendering): an answer that is no JSON, a
/// claimant and an origin list carrying a screen clear and a clipboard
/// write, a refusal whose code sets the title, and a reply carrying an
/// escape each reach stderr as code points — the health body passed
/// VERBATIM on stdout (AUTH-5.86), JSON's own escapes and all — and a
/// claimant on stdout reaches it as code points too, its line break never
/// a second DATA line.
#[test]
fn a_board_s_bytes_reach_the_terminal_inert_never_as_commands() {
    let r = skep(&["health", "--board", &canned(200, b"\x1b]0;pwned\x07\x1b[2J")], &[], None);
    assert_eq!(r.code, 4, "an answer that is no JSON is transport: {r:?}");
    assert!(r.err.contains("<U+001B>]0;pwned<U+0007><U+001B>[2J") && !raw_control(&r), "{r:?}");

    const BODY: &[u8] = br#"{"auth":{"claimant":"1.0.1\u001b[2J","local_trust":false,"origins":["\u001b]52;c;cHduZWQ=\u0007"],"signed_origins":[]},"log_position":0}"#;
    let r = skep(&["health", "--board", &canned(200, BODY)], &[], None);
    assert_eq!(r.code, 0, "{r:?}");
    assert_eq!(r.out, format!("{}\n", std::str::from_utf8(BODY).unwrap()), "the body verbatim");
    assert!(r.err.contains("claimant 1.0.1<U+001B>[2J") && r.err.contains("[<U+001B>]52;c;cHduZWQ=<U+0007>]") && !raw_control(&r), "{r:?}");

    let r = skep(&["health", "--board", &canned(403, br#"{"error":"\u001b]0;x\u0007"}"#)], &[], None);
    assert_eq!(r.code, 1, "{r:?}");
    assert!(r.err.contains("the board refused: <U+001B>]0;x<U+0007> (HTTP 403)") && !raw_control(&r), "{r:?}");

    let dir = tempfile::tempdir().unwrap();
    let r = skep(&["bind", "--board", DEAD, "--dir", s(&dir.path().join("store")), "--payload", "-"], &[], Some(b"account 1.0.1\nprincipal 1\norigin http://x\x1b[2J\n"));
    assert_eq!(r.code, 3, "a halt on the reply, before any socket: {r:?}");
    assert!(r.err.contains("origin http://x<U+001B>[2J") && !raw_control(&r), "{r:?}");

    // stdout: the idempotent hosted claim prints the board's claimant.
    let board = canned(200, br#"{"auth":{"claimant":"1.0.1\u001b]52;c;cHduZWQ=\u0007\naccount 1.0.9","local_trust":false,"origins":[],"signed_origins":[]}}"#);
    let r = skep(&["claim", "--hosted", "-", "--board", &board], &[], Some(b"{}"));
    assert_eq!(r.code, 0, "{r:?}");
    assert_eq!(r.out, "claimed by 1.0.1<U+001B>]52;c;cHduZWQ=<U+0007><U+000A>account 1.0.9\n", "one DATA line, its controls code points");
}

/// A REPLY THAT SAYS TWO THINGS IS REFUSED, NEVER READ AS THE LAST ONE
/// (`facts_of`; §2.2 `bind`: the binding records what the board answered
/// for, and not a paste believed): a second account, a third word on a
/// fact's line, a line a screen shows other than it reads — a carriage
/// return, an escape that erases the fact above it, a bidi override that
/// shows a fact the parse never reads — and a fact against its flag or its
/// variable each halt naming what they found, before any socket opens and
/// with nothing written; a fact repeated with its own value stands, and the
/// dead board behind it is dialed.
#[test]
fn a_reply_that_says_two_things_is_refused_never_read_as_the_last_one() {
    let dir = tempfile::tempdir().unwrap();
    let store = dir.path().join("store");
    let bind = |flags: &[&str], envs: &[(&str, &str)], reply: &[u8]| {
        let mut args = vec!["bind", "--board", DEAD, "--dir", s(&store), "--payload", "-"];
        args.extend_from_slice(flags);
        skep(&args, envs, Some(reply))
    };
    let two_values = |flags: &[&str], envs: &[(&str, &str)], reply: &[u8], named: [&str; 2]| {
        let r = bind(flags, envs, reply);
        assert_eq!(r.code, 3, "{flags:?} {envs:?}: {r:?}");
        assert!(named.iter().all(|n| r.err.contains(n)) && r.err.contains("is already named"), "both values named: {}", r.err);
        assert!(r.out.is_empty(), "{}", r.out);
    };
    two_values(&[], &[], b"account 1.0.1.2\nprincipal 7\naccount 1.0.1.3\n", ["account 1.0.1.3", "account 1.0.1.2"]);
    two_values(&["--account", "1.0.1.2"], &[], b"account 1.0.1.3\nprincipal 7\n", ["account 1.0.1.3", "account 1.0.1.2"]);
    two_values(&["--principal", "7"], &[], b"account 1.0.1.2\nprincipal 8\n", ["principal 8", "principal 7"]);
    two_values(&[], &[("SKEP_PRINCIPAL", "7")], b"account 1.0.1.2\nprincipal 8\n", ["principal 8", "principal 7"]);
    let hidden: &[(&[u8], &str)] = &[
        (b"account 1.0.1.2 1.0.1.3\nprincipal 7\n", "is not one fact"),
        (b"account 1.0.1.3\raccount 1.0.1.2\nprincipal 7\n", "a screen does not show as it reads"),
        (b"account 1.0.1.2\nprincipal 7\nnote \x1b[2A\x1b[2Kaccount 1.0.1.3\n", "a screen does not show as it reads"),
        ("\u{202e}3.1.0.1 tnuocca\naccount 1.0.1.2\nprincipal 7\n".as_bytes(), "a screen does not show as it reads"),
    ];
    for (reply, refusal) in hidden {
        let r = bind(&[], &[], reply);
        assert_eq!(r.code, 3, "{reply:?}: {r:?}");
        assert!(r.err.contains(refusal) && r.err.contains("re-take the three facts from whoever printed the reply"), "{reply:?}: {}", r.err);
        assert!(r.out.is_empty() && !raw_control(&r), "{r:?}");
    }
    assert!(!store.exists(), "nothing written");
    let r = bind(&["--account", "1.0.1.2", "--principal", "7"], &[("SKEP_PRINCIPAL", "7")], b"account 1.0.1.2\naccount 1.0.1.2\nprincipal 7\n");
    assert_eq!(r.code, 4, "one value named three times stands, and the board is dialed: {r:?}");
}

/// A PAYLOAD IS READ TO ITS CAP AND NO FURTHER (`read_payload`; AUTH-1.18):
/// one byte past a record at `MAX_RECORD_BYTES` and its line ending — on
/// stdin, in a file, or a file that never ends, where a read to the end
/// grows without bound — halts naming the cap before any socket opens; at
/// the cap the payload is read whole and the board dialed.
#[test]
fn a_payload_past_its_cap_is_refused_before_it_is_read_whole() {
    let cap = skep_identity::MAX_RECORD_BYTES + 2;
    let hosted = |payload: &str, stdin: Option<&[u8]>| skep(&["claim", "--hosted", payload, "--board", DEAD], &[], stdin);
    let past = vec![b'a'; cap + 1];
    let r = hosted("-", Some(&past[..]));
    assert_eq!(r.code, 3, "{r:?}");
    assert!(r.err.contains(&format!("the payload at stdin runs past {cap} bytes")), "{}", r.err);
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("past.enroll");
    std::fs::write(&file, &past).unwrap();
    let r = hosted(s(&file), None);
    assert_eq!(r.code, 3, "{r:?}");
    assert!(r.err.contains(&format!("the payload at {} runs past {cap} bytes", file.display())), "{}", r.err);
    #[cfg(unix)]
    {
        let r = hosted("/dev/zero", None);
        assert_eq!(r.code, 3, "{r:?}");
        assert!(r.err.contains(&format!("the payload at /dev/zero runs past {cap} bytes")), "{}", r.err);
    }
    let r = hosted("-", Some(&past[..cap]));
    assert_eq!(r.code, 4, "at the cap the payload is read and the board dialed: {r:?}");
}

/// A PRINCIPAL PAST THE WIRE'S RANGE IS NONE (`principal_text`; AUTH-6.36's
/// clause; AUTH-5.20): `--principal 2^53` is a usage refusal before any
/// socket opens, `2^53 − 1` reads and the dead board is dialed, and a
/// reply's `principal 2^53` halts naming it.
#[test]
fn a_principal_past_the_wires_range_is_refused_at_the_flag_and_in_a_reply() {
    let dir = tempfile::tempdir().unwrap();
    let store = dir.path().join("store");
    let verify = |principal: &str| skep(&["verify", "--board", DEAD, "--dir", s(&store), "--principal", principal], &[], None);
    let r = verify("9007199254740992");
    assert_eq!(r.code, 2, "{r:?}");
    assert!(r.err.contains("--principal: '9007199254740992' is not a principal"), "{}", r.err);
    assert_eq!(verify("9007199254740991").code, 4, "the largest principal reads");
    let r = skep(&["bind", "--board", DEAD, "--dir", s(&store), "--payload", "-"], &[], Some(b"account 1.0.1\nprincipal 9007199254740992\n"));
    assert_eq!(r.code, 3, "{r:?}");
    assert!(r.err.contains("the reply's principal line `9007199254740992` is not a principal"), "{}", r.err);
}
