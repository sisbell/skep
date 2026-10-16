//! THE FIFTEENTH COMMAND through the binary (`skep share`; PUB-5.29,
//! PUB-5.14, PUB-5.108–5.111): THE USAGE FORMS refused before any socket
//! opens, exit 2 — no form, a share with neither `--to` nor `--privash`,
//! `--privash` with `--whole-account`, two forms together, a value that is
//! no address, and `--yes` absent off a terminal at a share, a privash and a
//! revoke — while each whole form reaches the dead board; THE SHARE on the
//! real daemon — the statement on stderr ahead of the one JSON document on
//! stdout, read off one combined stream, the key-loss clause and the custody
//! note among its lines, the grantee echoed by address, `--list`'s shape,
//! a second share refused with nothing written, the revoke with its
//! keep-clause and a revoke without `--yes` writing nothing, the re-share
//! saying the revocation it follows and naming it in `replaces`, the
//! whole-account share saying it covers later drafts, and an agent grantee
//! named in its owner's agent space; and THE PRIVASH — its statement in the
//! tier's own words (never a guest; everything this board retains), the
//! grantee `privashed` in the JSON, the board's privashed set listing it,
//! a published document refused, and its revocation closing it.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use serde_json::Value;
use skep_client::board::{acked_addr, frames, Answer, Board, Opened, SessionBody, Token};
use skep_client::board::Scope;
use skep_client::ceremony::claim::{self, ClaimOutcome, NotebookOptions};
use skep_client::ceremony::handshake::{handshake, Site};
use skep_client::dial::PlainHttp;
use skep_client::person::scripted::{Script, Scripted};
use skep_client::sheet::Label;
use skep_client::store::{FileStore, KeyStore};
use skep_client::Origin;
use skep_identity::Fingerprint;
use skep_signature::HybridSigner;
use skepd::Skepd;

use crate::common::{origin, s, scrub, shell_word, skep, spawn, Run};

/// The claimant's account and principal on a notebook.
const ACCOUNT: &str = "1.0.1";
const PRINCIPAL: u64 = 1;

/// The reader the claimant shares with: a sub-account delegated under it,
/// and an agent under the claimant's agent space (AUTH-5.87).
const READER: &str = "1.0.1.2";
const AGENT: &str = "1.0.1.1.1";

/// A port nothing listens at: a run that reaches it is exit 4, so a usage
/// refusal judged ahead of it is seen to open no socket.
const DEAD: &str = "http://127.0.0.1:1";

/// A claimed board through the LIBRARY, as `merge.rs` claims its: the store
/// holds the device key, whose fingerprint is answered.
fn claim_board(board_origin: &str, store: &Path, anchors: &Path) -> Fingerprint {
    let board = Board::new(Origin::parse(board_origin).unwrap(), PlainHttp::new());
    let store = FileStore::open(store);
    let fp = store.generate(Some(Label::new("notebook").unwrap())).unwrap().0;
    let mut person = Scripted::new(vec![Script::LabelDefault, Script::LabelDefault]);
    let opts = NotebookOptions { principal: None, display_name: Some("a name".into()), anchor_out: vec![anchors.join("a"), anchors.join("b")], paper: false, host_name: "testhost".into(), date: "2026-10-16".into() };
    let ClaimOutcome::Ours(_) = claim::notebook(&board, &store, &mut person, &opts).unwrap_or_else(|h| panic!("{h}\n{}", person.transcript.join("\n"))) else { panic!("a stranger's board") };
    fp
}

/// One run's stdout read whole as ONE JSON document: exit 0, one line,
/// nothing beside it.
fn document(r: &Run) -> Value {
    assert_eq!(r.code, 0, "{r:?}");
    assert_eq!(r.out.lines().count(), 1, "one JSON document on one line, nothing else on stdout: {}", r.out);
    serde_json::from_str(&r.out).unwrap_or_else(|e| panic!("stdout is one JSON document: {e}\n{}", r.out))
}

/// A claimed PERMISSIVE board (the bare session mints the drafts), its
/// store, and the two accounts the claimant shares with.
struct Rig {
    _daemon: Skepd,
    origin: String,
    store: PathBuf,
    board: Board,
    bare: Token,
}

impl Rig {
    fn new(dir: &Path) -> Rig {
        let daemon = spawn(&dir.join("board"), true);
        let origin = origin(daemon.port());
        let store = dir.join("store");
        let fp = claim_board(&origin, &store, &dir.join("anchors"));
        let board = Board::new(Origin::parse(&origin).unwrap(), PlainHttp::new());
        let file_store = FileStore::open(&store);
        let device: HybridSigner = file_store.load(&file_store.key_path(&fp)).expect("the device key").signer();
        let bare = match board.session_open(SessionBody::Bare { principal: PRINCIPAL }).expect("a bare session") {
            Opened::Token(t) => t,
            other => panic!("the bare bind answered {other:?}"),
        };
        // The reader, delegated from the claimant's FULL session, and the
        // agent, delegated from a session as the AGENT SPACE's own principal
        // — `1.0.1.1` is seated by the claim's first session and
        // authenticates against the claimant's set (AUTH-5.87) — registry
        // rows, no key: a grantee needs none.
        let delegate = |principal: u64, prefix: &str, id: u64| {
            let full = handshake(&board, Scope::Full, &device, principal, Site::Session).expect("a full session");
            let Answer::Document(v) = full.op(&frames::delegate(prefix, id, None)).expect("the delegate") else { panic!("closed") };
            assert!(acked_addr(&v).is_some(), "{prefix} delegated: {v}");
            full.close().expect("close");
        };
        delegate(PRINCIPAL, READER, 902);
        let space = board.effective_owner("1.0.1.1").expect("the registry read").expect("the agent space is seated");
        assert_eq!(space.prefix, "1.0.1.1", "the claim seated the agent space");
        delegate(space.principal, AGENT, 903);
        Rig { _daemon: daemon, origin, store, board, bare }
    }

    /// `skep share --board … --dir …` with `extra`; `--principal` omitted,
    /// the store's one binding standing in for it.
    fn share(&self, extra: &[&str]) -> Run {
        let mut args = vec!["share", "--board", &self.origin, "--dir", s(&self.store)];
        args.extend_from_slice(extra);
        skep(&args, &[], None)
    }

    /// The same run with stderr and stdout on ONE stream, in the order they
    /// were written — so the statement is seen to precede the JSON.
    fn combined(&self, extra: &[&str]) -> (i32, String) {
        let mut line = format!("{} share --board {} --dir {}", shell_word(env!("CARGO_BIN_EXE_skep")), shell_word(&self.origin), shell_word(s(&self.store)));
        for arg in extra {
            line.push(' ');
            line.push_str(&shell_word(arg));
        }
        line.push_str(" 2>&1");
        let mut cmd = Command::new("/bin/sh");
        cmd.args(["-c", &line]).stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped());
        let out = scrub(&mut cmd).output().expect("the combined run");
        (out.status.code().unwrap_or(-1), String::from_utf8_lossy(&out.stdout).into_owned())
    }

    /// A private draft minted into the account from the bare session.
    fn draft(&self) -> String {
        let Answer::Document(v) = self.board.op(Some(&self.bare), &frames::create_document(ACCOUNT, false, None)).expect("mint") else { panic!("closed") };
        acked_addr(&v).unwrap_or_else(|| panic!("the mint was refused: {v}")).to_string()
    }

    /// The committed head, for "nothing written".
    fn position(&self) -> u64 {
        self.board.health().unwrap().log_position()
    }
}

/// THE USAGE FORMS are judged whole before any socket opens (§2.3's exit 2;
/// the fence): each refusal names what is wrong with the help beneath it,
/// stdout empty, against a dead port — `--yes` absent off a terminal among
/// them — and every whole form reaches the dead board.
#[test]
fn the_usage_forms_are_refused_before_any_socket() {
    let dir = tempfile::tempdir().unwrap();
    let store = dir.path().join("store");
    let (doc, to, grant) = ("1.0.1.0.2", "1.0.1.2", "1.0.1.0.1.0.2.3");
    let refused = |extra: &[&str], words: &str| {
        let mut args = vec!["share", "--board", DEAD, "--dir", s(&store)];
        args.extend_from_slice(extra);
        let r = skep(&args, &[], None);
        assert_eq!(r.code, 2, "{extra:?}: {r:?}");
        assert!(r.err.contains(words), "{extra:?}: {}", r.err);
        assert!(r.err.contains("\n\nusage: skep <command> [flags]\n"), "the help beneath the refusal: {}", r.err);
        assert!(r.out.is_empty(), "{extra:?}: {}", r.out);
    };
    refused(&[], "one form is required: a share (--doc <D> or --whole-account, with --to <account> or --privash), --revoke <grant>, or --list");
    refused(&["--to", to, "--yes"], "one form is required");
    refused(&["--doc", doc, "--yes"], "a share names its reader: --to <account>, or --privash to open the draft to every account on this board (never a guest)");
    refused(&["--whole-account", "--yes"], "a share names its reader");
    refused(&["--doc", doc, "--whole-account", "--to", to, "--yes"], "`--doc` and `--whole-account` belong to two forms of `share`: give one");
    refused(&["--doc", doc, "--to", to, "--privash", "--yes"], "`--to` and `--privash` belong to two forms of `share`: give one");
    refused(&["--whole-account", "--privash", "--yes"], "privashing a whole account is not available: --privash opens ONE draft to every account on this board");
    refused(&["--doc", doc, "--revoke", grant, "--yes"], "`--doc` and `--revoke` belong to two forms of `share`: give one");
    refused(&["--whole-account", "--revoke", grant, "--yes"], "`--whole-account` and `--revoke` belong to two forms of `share`: give one");
    refused(&["--to", to, "--revoke", grant, "--yes"], "`--to` and `--revoke` belong to two forms of `share`: give one");
    refused(&["--privash", "--revoke", grant, "--yes"], "`--privash` and `--revoke` belong to two forms of `share`: give one");
    refused(&["--doc", doc, "--list"], "`--doc` and `--list` belong to two forms of `share`: give one");
    refused(&["--whole-account", "--list"], "`--whole-account` and `--list` belong to two forms of `share`: give one");
    refused(&["--to", to, "--list"], "`--to` and `--list` belong to two forms of `share`: give one");
    refused(&["--privash", "--list"], "`--privash` and `--list` belong to two forms of `share`: give one");
    refused(&["--revoke", grant, "--list"], "`--revoke` and `--list` belong to two forms of `share`: give one");
    refused(&["--yes", "--list"], "`--yes` and `--list` belong to two forms of `share`: give one");
    refused(&["--doc", "nope", "--to", to, "--yes"], "--doc: 'nope' is not an address");
    refused(&["--doc", doc, "--to", "x.y", "--yes"], "--to: 'x.y' is not an address");
    refused(&["--revoke", "bad", "--yes"], "--revoke: 'bad' is not an address");
    // THE STATEMENT PRECEDES THE ACT, and off a terminal `--yes` stands for
    // the answer: without it a share, a privash and a revoke are refused
    // before any socket.
    refused(&["--doc", doc, "--to", to], "--yes is required off a terminal");
    refused(&["--whole-account", "--to", to], "--yes is required off a terminal");
    refused(&["--doc", doc, "--privash"], "--yes is required off a terminal");
    refused(&["--revoke", grant], "--yes is required off a terminal");
    for form in [&["--doc", doc, "--to", to, "--yes"][..], &["--whole-account", "--to", to, "--yes"], &["--doc", doc, "--privash", "--yes"], &["--revoke", grant, "--yes"], &["--list"]] {
        let mut args = vec!["share", "--board", DEAD, "--dir", s(&store), "--principal", "1"];
        args.extend_from_slice(form);
        let r = skep(&args, &[], None);
        assert_eq!(r.code, 4, "a whole form reaches the dead board: {form:?}: {r:?}");
    }
    assert!(!store.exists(), "nothing written");
}

/// THE SHARE through the binary: the statement ahead of the JSON on one
/// stream; every clause on stderr; the grant on stdout; the lists; a second
/// share refused with nothing written; the revoke with its keep-clause, and
/// without `--yes` nothing written; the re-share naming the revocation; the
/// whole account; an agent grantee named in its owner's agent space.
#[test]
fn a_share_states_before_it_writes_and_the_revoke_reshare_and_lists_follow() {
    let dir = tempfile::tempdir().unwrap();
    let rig = Rig::new(dir.path());
    let d = rig.draft();
    // ONE STREAM: the statement's lines, then the JSON, last.
    let (code, seen) = rig.combined(&["--doc", &d, "--to", READER, "--yes"]);
    assert_eq!(code, 0, "{seen}");
    let json_at = seen.find("{\"at\":").or_else(|| seen.find("{\"grantee\"")).or_else(|| seen.find("{\"kind\":\"grant\"")).unwrap_or_else(|| panic!("the JSON on the stream: {seen}"));
    for clause in ["sharing with 1.0.1.2", "this share goes on the public record, permanently", "retained history", "revoking withdraws future delivery alone", "can publish what they read", "is not notified", "only you can revoke this share, and only while you hold a key", "a grant to an agent is a grant to whoever controls it"] {
        let at = seen.find(clause).unwrap_or_else(|| panic!("`{clause}` on the stream: {seen}"));
        assert!(at < json_at, "`{clause}` precedes the JSON: {seen}");
    }
    let last = seen.lines().last().unwrap();
    let g1: Value = serde_json::from_str(last).unwrap_or_else(|e| panic!("the last line is the JSON: {e}: {last}"));
    assert_eq!((g1["kind"].as_str(), g1["prefix"].as_str(), g1["grantee"].as_str(), g1["issuer"].as_str()), (Some("grant"), Some(d.as_str()), Some(READER), Some(ACCOUNT)));
    assert!(g1["replaces"].is_null(), "{g1}");
    let g1_at = g1["at"].as_str().expect("the grant's address").to_string();
    assert!(g1_at.starts_with("1.0.1.0.1."), "homed in the issuer's doc 1: {g1_at}");
    // `--list`: the shape, the custody note beside it.
    let r = rig.share(&["--list"]);
    let v = document(&r);
    assert_eq!(v["issued"].as_array().map(Vec::len), Some(1), "{v}");
    assert_eq!((v["issued"][0]["at"].as_str(), v["issued"][0]["state"].as_str()), (Some(g1_at.as_str()), Some("live")));
    assert!(v["issued"][0]["revoked_by"].is_null());
    assert_eq!(v["held"], Value::Array(vec![]), "{v}");
    assert_eq!(v["privashed"], Value::Array(vec![]), "{v}");
    assert!(r.err.contains("1 grant record issued from 1.0.1, 1 live; 0 held; 0 prefixes privashed"), "{}", r.err);
    assert!(r.err.contains("a grant to an agent is a grant to whoever controls it"), "the custody note on every surface showing grants: {}", r.err);
    // A SECOND SHARE while the first stands: refused, nothing on stdout,
    // nothing written.
    let before = rig.position();
    let r = rig.share(&["--doc", &d, "--to", READER, "--yes"]);
    assert_eq!(r.code, 1, "{r:?}");
    assert!(r.out.is_empty(), "{}", r.out);
    assert!(r.err.contains(&format!("the board refused: already_shared:{d} is already shared with 1.0.1.2: the grant at {g1_at} stands")), "{}", r.err);
    assert!(r.err.contains("revoke that grant"), "{}", r.err);
    assert!(!r.err.contains("sharing with"), "refused before the statement: {}", r.err);
    assert_eq!(rig.position(), before, "nothing written");
    // THE REVOKE without `--yes`: refused, nothing written.
    let r = rig.share(&["--revoke", &g1_at]);
    assert_eq!(r.code, 2, "{r:?}");
    assert!(r.err.contains("--yes is required off a terminal"), "{}", r.err);
    assert_eq!(rig.position(), before, "nothing written");
    // THE REVOKE: the keep-clause before and after, the revocation on stdout.
    let r = rig.share(&["--revoke", &g1_at, "--yes"]);
    let rev = document(&r);
    assert_eq!((rev["kind"].as_str(), rev["revokes"].as_str(), rev["prefix"].as_str(), rev["grantee"].as_str()), (Some("revocation"), Some(g1_at.as_str()), Some(d.as_str()), Some(READER)));
    let r1_at = rev["at"].as_str().expect("the revocation's address").to_string();
    assert!(r.err.contains("revoking deposits a second permanent public record here, naming 1.0.1.2"), "{}", r.err);
    assert!(r.err.contains("it withdraws future delivery alone: 1.0.1.2 keeps what their client has already fetched"), "{}", r.err);
    assert!(r.err.contains(&format!("revoked: 1.0.1.2 reads {d} no further from the next read; they keep what their client already fetched")), "{}", r.err);
    // Revoked again: refused.
    let r = rig.share(&["--revoke", &g1_at, "--yes"]);
    assert_eq!(r.code, 1, "{r:?}");
    assert!(r.err.contains(&format!("already_revoked:{g1_at} is revoked already, by the record at {r1_at}")), "{}", r.err);
    // THE RE-SHARE: the statement names the revocation; the JSON names it in
    // `replaces`.
    let r = rig.share(&["--doc", &d, "--to", READER, "--yes"]);
    let g2 = document(&r);
    assert_eq!(g2["replaces"].as_str(), Some(r1_at.as_str()), "{g2}");
    assert_ne!(g2["at"].as_str(), Some(g1_at.as_str()));
    assert!(r.err.contains(&format!("you revoked this share before (the revocation at {r1_at}); this shares it again, as a fresh grant beside the old one")), "{}", r.err);
    let v = document(&rig.share(&["--list"]));
    let issued = v["issued"].as_array().expect("issued");
    assert_eq!(issued.len(), 2, "{v}");
    assert_eq!((issued[0]["state"].as_str(), issued[0]["revoked_by"].as_str()), (Some("revoked"), Some(r1_at.as_str())));
    assert_eq!((issued[1]["state"].as_str(), issued[1]["replaces"].as_str()), (Some("live"), Some(r1_at.as_str())));
    // THE WHOLE ACCOUNT: the statement says it covers later drafts.
    let r = rig.share(&["--whole-account", "--to", READER, "--yes"]);
    let g3 = document(&r);
    assert_eq!(g3["prefix"].as_str(), Some(ACCOUNT));
    assert!(r.err.contains("1.0.1.2 may read everything under 1.0.1 that is yours — every draft you have there now, every draft you write there later"), "{}", r.err);
    assert!(r.err.contains("only you can revoke this share"), "{}", r.err);
    // AN AGENT GRANTEE: the custody note names its owner's agent space.
    let d2 = rig.draft();
    let r = rig.share(&["--doc", &d2, "--to", AGENT, "--yes"]);
    let g4 = document(&r);
    assert_eq!(g4["grantee"].as_str(), Some(AGENT));
    assert!(r.err.contains("1.0.1.1.1 is in 1.0.1's agent space: this share reaches whoever controls that agent, and its operator"), "{}", r.err);
    // The refusals the library makes before any write, through the binary.
    let before = rig.position();
    let r = rig.share(&["--doc", &d2, "--to", ACCOUNT, "--yes"]);
    assert_eq!(r.code, 1, "{r:?}");
    assert!(r.err.contains("to_yourself:1.0.1 is your own account"), "{}", r.err);
    let r = rig.share(&["--doc", &d2, "--to", "1.0.9", "--yes"]);
    assert_eq!(r.code, 1, "{r:?}");
    assert!(r.err.contains("not_an_account:1.0.9 is no account on this board"), "{}", r.err);
    let r = rig.share(&["--revoke", &r1_at, "--yes"]);
    assert_eq!(r.code, 1, "{r:?}");
    assert!(r.err.contains(&format!("not_a_grant:no grant of yours stands at {r1_at}")), "{}", r.err);
    assert_eq!(rig.position(), before, "nothing written");
}

/// THE PRIVASH through the binary (PUB-5.108–5.111): the statement in the
/// tier's own words, the grantee `privashed` on stdout, the board's
/// privashed set listing it, a published document refused, the revocation
/// closing it with its own keep-clause, and the re-privash naming it.
#[test]
fn a_privash_states_in_the_tiers_own_words_and_lists_as_privashed() {
    let dir = tempfile::tempdir().unwrap();
    let rig = Rig::new(dir.path());
    let d = rig.draft();
    let (code, seen) = rig.combined(&["--doc", &d, "--privash", "--yes"]);
    assert_eq!(code, 0, "{seen}");
    let last = seen.lines().last().unwrap();
    let g: Value = serde_json::from_str(last).unwrap_or_else(|e| panic!("the last line is the JSON: {e}: {last}"));
    assert_eq!((g["kind"].as_str(), g["prefix"].as_str(), g["grantee"].as_str()), (Some("grant"), Some(d.as_str()), Some("privashed")));
    let json_at = seen.find(last).unwrap();
    let opening = format!("{d} will be privashed: every account on this board can read it, including accounts that join later — never a guest");
    let landing = format!("the draft is now privashed: every account on this board reads {d}, never a guest");
    for clause in [
        opening.as_str(),
        "it stays a draft you may keep changing, and readers see your changes as yours",
        "everything this board retains, never forever",
        "revoking stops future reads and takes back nothing already fetched",
        "shows a dead reference in its place",
        "a matter for private recourse",
        "any account on this board can publish what it reads",
        "nobody is notified",
        "only you can revoke it, and only while you hold a key: if you lose every key, it stays privashed",
        "every account includes agents, and a grant to an agent is a grant to whoever controls it",
        landing.as_str(),
    ] {
        let at = seen.find(clause).unwrap_or_else(|| panic!("`{clause}` on the stream: {seen}"));
        assert!(at < json_at, "`{clause}` precedes the JSON: {seen}");
    }
    assert!(!seen.contains("anyone"), "the talk says every account on this board, never anyone: {seen}");
    let g_at = g["at"].as_str().unwrap().to_string();
    let v = document(&rig.share(&["--list"]));
    assert_eq!(v["privashed"].as_array().map(Vec::len), Some(1), "{v}");
    assert_eq!((v["privashed"][0]["prefix"].as_str(), v["privashed"][0]["issuers"].as_array().map(Vec::len)), (Some(d.as_str()), Some(1)));
    assert_eq!(v["privashed"][0]["issuers"][0].as_str(), Some(ACCOUNT));
    assert_eq!((v["issued"][0]["grantee"].as_str(), v["issued"][0]["state"].as_str()), (Some("privashed"), Some("live")));
    // Privashed already: refused; a published document: refused; nothing
    // written by either.
    let before = rig.position();
    let r = rig.share(&["--doc", &d, "--privash", "--yes"]);
    assert_eq!(r.code, 1, "{r:?}");
    assert!(r.err.contains(&format!("already_shared:{d} is already shared with privashed")), "{}", r.err);
    let r = rig.share(&["--doc", "1.0.1.0.1", "--privash", "--yes"]);
    assert_eq!(r.code, 1, "{r:?}");
    assert!(r.err.contains("not_a_draft:1.0.1.0.1 is published already"), "{}", r.err);
    assert_eq!(rig.position(), before, "nothing written");
    // THE REVOKE of a privash: the reader is every account on this board.
    let r = rig.share(&["--revoke", &g_at, "--yes"]);
    let rev = document(&r);
    assert_eq!((rev["kind"].as_str(), rev["grantee"].as_str()), (Some("revocation"), Some("privashed")));
    assert!(r.err.contains("revoking deposits a second permanent public record here, naming every account on this board"), "{}", r.err);
    assert!(r.err.contains("any document that links to or quotes it then shows a dead reference"), "{}", r.err);
    assert!(r.err.contains(&format!("revoked: every account on this board reads {d} no further from the next read")), "{}", r.err);
    let v = document(&rig.share(&["--list"]));
    assert_eq!(v["privashed"], Value::Array(vec![]), "gone from the set: {v}");
    // The re-privash names the revocation.
    let r = rig.share(&["--doc", &d, "--privash", "--yes"]);
    let again = document(&r);
    assert_eq!(again["replaces"].as_str(), rev["at"].as_str());
    assert!(r.err.contains("you revoked this before"), "{}", r.err);
}
