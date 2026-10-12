//! T13 — THE FLOW over the two fakes: (a) the whole flow, call by call,
//! to the snippet, the live status with its facts, the invite spent and ONE
//! mail sent after the status turned live; (b) THE DECISION TABLE, one case
//! per failing step as the provisioning record §5.2 tabulates it, each
//! removing what was made for the name and nothing for any other, the
//! snippet absent, the reload called where the snippet was written, the
//! status D-8, the invite still issued and no mail; (c) a cleanup call
//! failing, logged, the name left taken. Beside them, the flow's halves of
//! T8 (two posts on one name; a fifth past the queue), T9 (a spent, an
//! unknown and a held code refused; no code in the log), T10 (a sign-up,
//! its address in no log line) and T12 (no send before live; an outage
//! with the status live throughout).

use std::fs;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, OnceLock, Weak};

use skep_identity::{encode_enroll, Enrollment, PublicKey, ALG_FNDSA512_PREVIEW_ED25519, ALG_MLDSA65_ED25519, FNDSA512_PREVIEW_ED25519_KEY_LEN, MLDSA65_ED25519_KEY_LEN};

use super::*;
use crate::docker::fake::{line, FakeDocker};
use crate::invites::{lookup, mint, InviteState};
use crate::scratch::Scratch;
use crate::sender::fake::{messages, FakeSender};
use crate::sender::Sender;

/// The six DATA lines a fresh board's dark claim prints (`sidecar/tests.rs`
/// holds them whole beside the `skep` command's pins).
const SIX: &str = "claimant 1.0.1\naccount 1.0.1\nprincipal 1\norigin http://127.0.0.1:8642\nfirst act: from the device …\nsecond act: in your first signed session …\n";

/// The sidecar's TALK: the operator's lines, logged whole.
const TALK: &str = "payload entry: 9f86d081884c7d65 anchor=true label=(none)\nthe genesis stands: committed\n";

/// A claimed alpha board's `/health`, keys sorted.
const PAIRED: &str = r#"{"auth":{"claimant":"1.0.1","local_trust":false,"origins":[],"signed_origins":["https://alice.skep.host"]},"chain_head":"00","head_time":null,"log_position":0,"media":{"uploads":true},"ok":true,"writes":{"halted":false}}"#;

/// An unclaimed board's.
const UNPAIRED: &str = r#"{"auth":{"claimant":null,"local_trust":false,"origins":[],"signed_origins":[]},"ok":true}"#;

/// A record as the person's device printed it: one production key, its
/// anchor flag as given, and the textarea's CRLF after it.
fn record(anchor: bool) -> String {
    let key = PublicKey::parse(ALG_MLDSA65_ED25519, &"9f".repeat(MLDSA65_ED25519_KEY_LEN)).expect("a key");
    format!("{}\r\n", encode_enroll(&[Enrollment::new(key, anchor, None).expect("no label")]))
}

/// THE PROBE in the mailer's place: the fake sender, which at every try
/// also reads the post's status off the service — so the order of a send
/// against the status turning live is what the test reads.
struct Probe {
    fake: FakeSender,
    service: OnceLock<Weak<Service>>,
    token: Mutex<Option<String>>,
    seen: Mutex<Vec<Option<Shown>>>,
}

impl Sender for Probe {
    fn send(&self, message: &Message) -> io::Result<Exit> {
        let token = self.token.lock().unwrap().clone();
        let shown = match (self.service.get().and_then(Weak::upgrade), token) {
            (Some(service), Some(token)) => service.status(&token),
            _ => None,
        };
        self.seen.lock().unwrap().push(shown);
        self.fake.send(message)
    }
}

/// The service over the two fakes, its log kept, its mail through the
/// probe on the worker's own thread.
struct Rig {
    dir: Scratch,
    boards: PathBuf,
    state: StateDir,
    fake: Arc<FakeDocker>,
    probe: Arc<Probe>,
    lines: Arc<Mutex<Vec<String>>>,
    service: Arc<Service>,
}

fn rig(script: &str, mail: Option<Vec<i32>>) -> Rig {
    let dir = Scratch::new();
    let boards = dir.path().join("boards");
    fs::create_dir(&boards).expect("the boards directory");
    let state = StateDir::open(&dir.path().join("state")).expect("the state directory");
    let fake = Arc::new(FakeDocker::parse(script).expect("a script"));
    let lines = Arc::new(Mutex::new(Vec::new()));
    let into = Arc::clone(&lines);
    let log: Log = Arc::new(move |line: &str| into.lock().unwrap().push(line.to_owned()));
    let probe =
        Arc::new(Probe { fake: FakeSender::new(dir.path().join("mail.log"), mail.clone().unwrap_or_default()), service: OnceLock::new(), token: Mutex::new(None), seen: Mutex::new(Vec::new()) });
    let mail = mail.map(|_| Mail { outbox: Outbox::inline(Box::new(Arc::clone(&probe)), Arc::clone(&log), Arc::new(|_| {})), from: "noreply@skep.host".into() });
    let config = Config { boards_dir: boards.clone(), suffix: "skep.host".into(), reply_to: "owner@skep.host".into() };
    let service = Arc::new(Service::new(config, state.clone(), Box::new(Arc::clone(&fake)), mail, log, Arc::new(|_| {})).expect("the service"));
    probe.service.set(Arc::downgrade(&service)).ok();
    Rig { dir, boards, state, fake, probe, lines, service }
}

impl Rig {
    /// One invite minted to the person's address.
    fn invite(&self) -> String {
        mint(&self.state, "person@example.com", None).expect("minted")
    }

    /// One post to the claim form.
    fn post(&self, name: &str, record: &str, code: &str) -> Result<String, Refusal> {
        self.service.claim(&Post { name: name.as_bytes(), record: record.as_bytes(), invite: code.as_bytes() })
    }

    /// A post admitted, its token the probe's.
    fn admitted(&self, name: &str, code: &str) -> String {
        let token = self.post(name, &record(true), code).unwrap_or_else(|r| panic!("{name}: refused {r:?}: {:?}", self.log()));
        *self.probe.token.lock().unwrap() = Some(token.clone());
        token
    }

    fn log(&self) -> Vec<String> {
        self.lines.lock().unwrap().clone()
    }

    fn snippet(&self, name: &str) -> PathBuf {
        self.boards.join(format!("{name}.caddy"))
    }

    fn issued(&self, code: &str) -> bool {
        lookup(&self.state, code).expect("read").expect("held").issued()
    }
}

/// The two inspects, both answering "not standing".
fn inspects(name: &str) -> String {
    line("volume_inspect", Some(name), 1, "", "") + &line("container_inspect", Some(name), 1, "", "")
}

fn said(calls: &[&str]) -> Vec<String> {
    calls.iter().map(|c| (*c).to_owned()).collect()
}

/// T13 (a): THE WHOLE FLOW — the post's two inspects; then the worker's two
/// inspects, `volume_create`, `run_claim`, `sidecar_claim` with the record
/// trimmed on its stdin, `rm_force`, `run_serving`, `health` once per try,
/// `caddy_reload`, in that order and no other call; the snippet on disk;
/// the status live with its three facts; the invite spent; ONE mail sent,
/// to the invite's address, after the status turned live, its body the
/// page's text; and no record byte, address, code or token in the log.
#[test]
fn the_whole_flow_runs_every_step_in_order() {
    let script = [
        inspects("alice"),
        inspects("alice"),
        line("volume_create", Some("alice"), 0, "alice\n", ""),
        line("run_claim", Some("alice"), 0, "c0ffee\n", ""),
        line("sidecar_claim", Some("alice"), 0, SIX, TALK),
        line("rm_force", Some("alice"), 0, "alice\n", ""),
        line("run_serving", Some("alice"), 0, "beef\n", ""),
        line("health", Some("alice"), 1, "", "the board did not answer\n"),
        line("health", Some("alice"), 0, PAIRED, ""),
        line("caddy_reload", None, 0, "", ""),
    ]
    .concat();
    let rig = rig(&script, Some(Vec::new()));
    let code = rig.invite();
    let token = rig.admitted("alice", &code);
    assert_eq!(rig.service.status(&token), Some(Shown::BeingMade));
    assert!(rig.service.run_next());
    assert!(!rig.service.run_next(), "one post, one turn");
    rig.fake.assert_done();
    assert_eq!(
        rig.fake.said(),
        said(&[
            "volume_inspect alice",
            "container_inspect alice",
            "volume_inspect alice",
            "container_inspect alice",
            "volume_create alice",
            "run_claim alice",
            "sidecar_claim alice",
            "rm_force alice",
            "run_serving alice",
            "health alice",
            "health alice",
            "caddy_reload",
        ])
    );
    let trimmed = record(true).trim_end().to_owned();
    assert_eq!(rig.fake.calls()[6].stdin.as_deref(), Some(trimmed.as_bytes()), "the record, trimmed, on the sidecar's stdin");
    assert_eq!(fs::read_to_string(rig.snippet("alice")).expect("the snippet"), crate::caddy::snippet(&Name::parse(b"alice").expect("a name"), "skep.host"));
    let status = crate::pages::status_address("skep.host", &token);
    let page = reply::text("https://alice.skep.host", false, &status);
    assert_eq!(rig.service.status(&token), Some(Shown::Live(page.clone())));
    let facts = rig.service.book().map.live().get(&Name::parse(b"alice").expect("a name")).cloned();
    assert_eq!(facts, Some(names::Facts { account: "1.0.1", principal: 1, origin: "https://alice.skep.host".into() }));
    assert!(matches!(lookup(&rig.state, &code).expect("read").expect("held").state, InviteState::Spent { ref name, .. } if name == "alice"));
    assert_eq!(rig.probe.seen.lock().unwrap().as_slice(), [Some(Shown::Live(page.clone()))], "one send, made with the status already live");
    let mail = messages(&rig.dir.path().join("mail.log")).expect("the mail log");
    assert_eq!(mail.len(), 1);
    assert!(mail[0].starts_with("To: person@example.com\nFrom: noreply@skep.host\nReply-To: owner@skep.host\nSubject: Your board is live\n"));
    assert!(mail[0].ends_with(&format!("\n\n{page}")), "the mail's body is the page's text");
    let log = rig.log().join("\n");
    for line in [
        "alice: admitted; 1 waiting",
        "alice: sidecar: payload entry: 9f86d081884c7d65 anchor=true label=(none)",
        "alice: sidecar: the genesis stands: committed",
        "alice: LIVE at https://alice.skep.host",
        "alice: the invite is spent",
        "alice: mail: sent at try 1 of 7",
    ] {
        assert!(log.contains(line), "{line}: {log}");
    }
    for never in [code.as_str(), token.as_str(), "person@example.com", "9f9f9f9f", "skep-enroll"] {
        assert!(!log.contains(never), "the log carries {never:?}: {log}");
    }
}

/// One case of the decision table: its worker steps through the failure
/// and the cleanup, the calls that follow the four inspects, and what the
/// case does to the rig before the worker's turn.
struct Case {
    what: &'static str,
    steps: String,
    calls: Vec<&'static str>,
    reloads: bool,
    before: fn(&Rig),
}

fn nothing(_: &Rig) {}

#[cfg(unix)]
fn boards_read_only(rig: &Rig) {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(&rig.boards, fs::Permissions::from_mode(0o555)).expect("read-only");
}

/// The steps that reach the dark claim.
fn to_the_claim() -> String {
    line("volume_create", Some("alice"), 0, "", "") + &line("run_claim", Some("alice"), 0, "", "")
}

/// The steps that reach the serving run.
fn to_the_serving_run() -> String {
    to_the_claim() + &line("sidecar_claim", Some("alice"), 0, SIX, "") + &line("rm_force", Some("alice"), 0, "", "")
}

/// The cleanup of a claim run or a serving run and the volume.
fn run_and_volume_removed() -> String {
    line("rm_force", Some("alice"), 0, "", "") + &line("volume_rm", Some("alice"), 0, "", "")
}

fn cases() -> Vec<Case> {
    let mut cases = vec![
        Case { what: "volume_create fails", steps: line("volume_create", Some("alice"), 1, "", "Error response from daemon\n"), calls: vec!["volume_create alice"], reloads: false, before: nothing },
        Case {
            what: "run_claim fails",
            steps: line("volume_create", Some("alice"), 0, "", "") + &line("run_claim", Some("alice"), 125, "", "Unable to find image\n") + &line("volume_rm", Some("alice"), 0, "", ""),
            calls: vec!["volume_create alice", "run_claim alice", "volume_rm alice"],
            reloads: false,
            before: nothing,
        },
        Case {
            what: "sidecar_claim exits 4 past the bound",
            steps: to_the_claim()
                + &(0..SIDECAR_WAIT.tries).map(|_| line("sidecar_claim", Some("alice"), 4, "", "skep: the board could not be dialed\n")).collect::<String>()
                + &run_and_volume_removed(),
            calls: [vec!["volume_create alice", "run_claim alice"], vec!["sidecar_claim alice"; SIDECAR_WAIT.tries as usize], vec!["rm_force alice", "volume_rm alice"]].concat(),
            reloads: false,
            before: nothing,
        },
    ];
    for (code, stdout) in [(3, ""), (1, ""), (2, ""), (0, "claimed by 1.0.1\n")] {
        cases.push(Case {
            what: match code {
                3 => "sidecar_claim exits 3",
                1 => "sidecar_claim exits 1",
                2 => "sidecar_claim exits 2",
                _ => "sidecar_claim answers `claimed by` on the fresh volume",
            },
            steps: to_the_claim() + &line("sidecar_claim", Some("alice"), code, stdout, "skep: a halt\n") + &run_and_volume_removed(),
            calls: vec!["volume_create alice", "run_claim alice", "sidecar_claim alice", "rm_force alice", "volume_rm alice"],
            reloads: false,
            before: nothing,
        });
    }
    let serving = vec!["volume_create alice", "run_claim alice", "sidecar_claim alice", "rm_force alice", "run_serving alice"];
    cases.push(Case {
        what: "run_serving fails",
        steps: to_the_serving_run() + &line("run_serving", Some("alice"), 125, "", "Conflict\n") + &run_and_volume_removed(),
        calls: [serving.clone(), vec!["rm_force alice", "volume_rm alice"]].concat(),
        reloads: false,
        before: nothing,
    });
    cases.push(Case {
        what: "health never pairs",
        steps: to_the_serving_run()
            + &line("run_serving", Some("alice"), 0, "", "")
            + &(0..HEALTH_WAIT.tries).map(|_| line("health", Some("alice"), 0, UNPAIRED, "")).collect::<String>()
            + &run_and_volume_removed(),
        calls: [serving.clone(), vec!["health alice"; HEALTH_WAIT.tries as usize], vec!["rm_force alice", "volume_rm alice"]].concat(),
        reloads: false,
        before: nothing,
    });
    #[cfg(unix)]
    cases.push(Case {
        what: "the snippet's write fails",
        steps: to_the_serving_run() + &line("run_serving", Some("alice"), 0, "", "") + &line("health", Some("alice"), 0, PAIRED, "") + &run_and_volume_removed(),
        calls: [serving.clone(), vec!["health alice", "rm_force alice", "volume_rm alice"]].concat(),
        reloads: false,
        before: boards_read_only,
    });
    cases.push(Case {
        what: "caddy_reload fails",
        steps: to_the_serving_run()
            + &line("run_serving", Some("alice"), 0, "", "")
            + &line("health", Some("alice"), 0, PAIRED, "")
            + &line("caddy_reload", None, 1, "", "Error: loading new config\n")
            + &line("caddy_reload", None, 0, "", "")
            + &run_and_volume_removed(),
        calls: [serving, vec!["health alice", "caddy_reload", "caddy_reload", "rm_force alice", "volume_rm alice"]].concat(),
        reloads: true,
        before: nothing,
    });
    cases
}

/// T13 (b): THE DECISION TABLE — for each failing step, the removals the
/// record tabulates for what was made, in the reverse of the order made,
/// for the name alone; the snippet absent; the reload called again where
/// the snippet was written; the status D-8; the invite still issued; no
/// mail tried.
#[test]
fn each_failed_step_removes_what_was_made_and_nothing_else() {
    for case in cases() {
        let rig = rig(&(inspects("alice") + &inspects("alice") + &case.steps), Some(Vec::new()));
        let code = rig.invite();
        let token = rig.admitted("alice", &code);
        (case.before)(&rig);
        assert!(rig.service.run_next(), "{}", case.what);
        rig.fake.assert_done();
        let calls = rig.fake.said();
        assert_eq!(calls[4..], said(&case.calls)[..], "{}", case.what);
        assert!(rig.fake.calls().iter().all(|c| c.name.as_deref().is_none_or(|n| n == "alice")), "{}: a call for another name", case.what);
        assert_eq!(calls.iter().filter(|c| *c == "caddy_reload").count(), if case.reloads { 2 } else { 0 }, "{}", case.what);
        assert!(!rig.snippet("alice").exists(), "{}: the snippet stands", case.what);
        assert_eq!(rig.service.status(&token), Some(Shown::Failed), "{}", case.what);
        assert!(rig.issued(&code), "{}: the invite was spent", case.what);
        assert!(rig.probe.seen.lock().unwrap().is_empty(), "{}: a mail was tried", case.what);
        let log = rig.log().join("\n");
        assert!(log.contains("alice: FAILED at "), "{}: {log}", case.what);
        assert!(!log.contains("INCOMPLETE"), "{}: {log}", case.what);
        assert!(!log.contains(&code) && !log.contains(&token), "{}", case.what);
    }
}

/// T13 (c): A CLEANUP CALL THAT FAILS is logged, the next removal still
/// made, and the name LEFT TAKEN — a re-post meets D-4 off what stands.
#[test]
fn a_failed_cleanup_call_leaves_the_name_taken_and_is_logged() {
    let script = [
        inspects("alice"),
        inspects("alice"),
        to_the_serving_run(),
        line("run_serving", Some("alice"), 125, "", ""),
        line("rm_force", Some("alice"), 1, "", "Error: cannot remove container\n"),
        line("volume_rm", Some("alice"), 0, "", ""),
        line("volume_inspect", Some("alice"), 1, "", ""),
        line("container_inspect", Some("alice"), 0, "[{}]", ""),
    ]
    .concat();
    let rig = rig(&script, Some(Vec::new()));
    let first = rig.invite();
    let token = rig.admitted("alice", &first);
    assert!(rig.service.run_next());
    assert_eq!(rig.service.status(&token), Some(Shown::Failed));
    let log = rig.log().join("\n");
    assert!(log.contains("alice: cleanup: rm_force: exit 1"), "{log}");
    assert!(log.contains("alice: cleanup: rm_force: Error: cannot remove container"), "{log}");
    assert!(log.contains("alice: cleanup: volume_rm: exit 0"), "the next removal still made: {log}");
    assert!(log.contains("alice: cleanup: INCOMPLETE — the name stands"), "{log}");
    let second = rig.invite();
    assert_eq!(rig.post("alice", &record(true), &second), Err(Refusal::Name));
    assert!(rig.log().join("\n").contains("alice: a post refused: taken — a container stands under it"));
    rig.fake.assert_done();
}

/// T8: TWO POSTS ON ONE NAME — the second meets D-4 at the post, held by
/// the first in flight, with no docker call made for it.
#[test]
fn a_second_post_on_one_name_meets_d4_at_the_post() {
    let rig = rig(&inspects("alice"), Some(Vec::new()));
    let first = rig.invite();
    rig.admitted("alice", &first);
    let second = rig.invite();
    assert_eq!(rig.post("ALICE", &record(true), &second), Err(Refusal::Name));
    rig.fake.assert_done();
    assert!(rig.issued(&second));
}

/// T8: A FIFTH POST PAST THE QUEUE meets D-8, "try again later", and leaves
/// no entry — no token, no queued post, no held code, no docker call.
#[test]
fn a_fifth_post_past_the_queue_meets_d8_and_leaves_no_entry() {
    let names = ["alice", "bob", "carol", "dave"];
    let rig = rig(&names.iter().map(|n| inspects(n)).collect::<String>(), Some(Vec::new()));
    for name in names {
        let code = rig.invite();
        rig.admitted(name, &code);
    }
    let fifth = rig.invite();
    assert_eq!(rig.post("erin", &record(true), &fifth), Err(Refusal::Busy));
    rig.fake.assert_done();
    let book = rig.service.book();
    assert_eq!(book.queue.len(), QUEUE_DEPTH);
    assert_eq!(book.codes.len(), QUEUE_DEPTH);
    assert!(!book.codes.contains(&fifth));
    assert!(!book.map.holds(&Name::parse(b"erin").expect("a name")));
    drop(book);
    assert!(rig.log().join("\n").contains("erin: a post refused: 4 posts already wait"));
}

/// T9: A SPENT CODE, AN UNKNOWN CODE, A CODE OF ANOTHER FORM and A CODE A
/// POST IN FLIGHT HOLDS are refused at the post, no docker call made; and
/// D-5 and D-6 refuse a record before any — the log naming the fault's
/// token, never the record.
#[test]
fn the_posts_refusals_before_any_docker_call() {
    let rig = rig(&inspects("alice"), Some(Vec::new()));
    let code = rig.invite();
    rig.admitted("alice", &code);
    assert_eq!(rig.post("bob", &record(true), &code), Err(Refusal::Invite), "held by the post in flight");
    assert_eq!(rig.post("bob", &record(true), "0123456789abcdef0123456789abcdef"), Err(Refusal::Invite), "unknown");
    assert_eq!(rig.post("bob", &record(true), "not a code"), Err(Refusal::Invite), "another form");
    let spent = rig.invite();
    crate::invites::spend(&rig.state, &spent, &Name::parse(b"carol").expect("a name")).expect("spent");
    assert_eq!(rig.post("bob", &record(true), &spent), Err(Refusal::Invite), "spent");
    let fresh = rig.invite();
    assert_eq!(rig.post("bob", "{\"type\":\"skep-enroll\"}", &fresh), Err(Refusal::Record));
    let preview = encode_enroll(&[Enrollment::new(PublicKey::parse(ALG_FNDSA512_PREVIEW_ED25519, &"9f".repeat(FNDSA512_PREVIEW_ED25519_KEY_LEN)).expect("a key"), true, None).expect("no label")]);
    assert_eq!(rig.post("bob", &preview, &fresh), Err(Refusal::Preview));
    assert_eq!(rig.post("b_b", &record(true), &fresh), Err(Refusal::Name));
    rig.fake.assert_done();
    assert!(rig.issued(&fresh));
    let log = rig.log().join("\n");
    assert!(log.contains("bob: a post refused: the record, bad_record") && log.contains("bob: a post refused: the record, preview_key"), "{log}");
    for never in [code.as_str(), spent.as_str(), fresh.as_str(), "skep-enroll", "9f9f", "b_b"] {
        assert!(!log.contains(never), "the log carries {never:?}: {log}");
    }
}

/// T10: A SIGN-UP through the service is kept and logged — its address in
/// no log line; a malformed one refused, nothing kept.
#[test]
fn a_sign_up_is_kept_and_its_address_is_in_no_log_line() {
    let rig = rig("", None);
    assert_eq!(rig.service.sign_up(b"someone@example.org"), Ok(()));
    assert_eq!(rig.service.sign_up(b"no address"), Err(SignUpRefusal::NotAnAddress));
    let kept = fs::read_to_string(rig.state.file(crate::signups::SIGNUPS)).expect("the file");
    assert_eq!(kept.lines().count(), 1);
    assert!(kept.starts_with("someone@example.org "));
    let log = rig.log().join("\n");
    assert_eq!(log, "a sign-up kept\na sign-up refused: no address");
}

/// T12: A MAIL OUTAGE — every try refused — is retried to its bound on the
/// sender's side and given up, THE STATUS LIVE THROUGHOUT: every try made
/// with the page already live, and live after.
#[test]
fn a_mail_outage_leaves_the_status_live_throughout() {
    let script = [
        inspects("alice"),
        inspects("alice"),
        to_the_serving_run(),
        line("run_serving", Some("alice"), 0, "", ""),
        line("health", Some("alice"), 0, PAIRED, ""),
        line("caddy_reload", None, 0, "", ""),
    ]
    .concat();
    let rig = rig(&script, Some(vec![75; crate::sender::MAIL_TRIES as usize]));
    let code = rig.invite();
    let token = rig.admitted("alice", &code);
    assert!(rig.service.run_next());
    let seen = rig.probe.seen.lock().unwrap().clone();
    assert_eq!(seen.len(), crate::sender::MAIL_TRIES as usize);
    assert!(seen.iter().all(|s| matches!(s, Some(Shown::Live(_)))), "a try made before the status was live");
    assert!(matches!(rig.service.status(&token), Some(Shown::Live(_))));
    assert!(messages(&rig.dir.path().join("mail.log")).expect("the log").is_empty());
    assert!(rig.log().join("\n").contains("alice: mail: given up after 7 tries; the board stands live"));
}

/// With no mail configured the board goes live and nothing is sent.
#[test]
fn with_no_mail_the_board_goes_live_and_nothing_is_sent() {
    let script = [
        inspects("alice"),
        inspects("alice"),
        to_the_serving_run(),
        line("run_serving", Some("alice"), 0, "", ""),
        line("health", Some("alice"), 0, PAIRED, ""),
        line("caddy_reload", None, 0, "", ""),
    ]
    .concat();
    let rig = rig(&script, None);
    let code = rig.invite();
    let token = rig.admitted("alice", &code);
    assert!(rig.service.run_next());
    assert!(matches!(rig.service.status(&token), Some(Shown::Live(_))));
    assert!(rig.probe.seen.lock().unwrap().is_empty());
    assert!(!rig.log().join("\n").contains("mail"));
}

/// The rebuild at the service's start: the snippets standing are its live
/// names.
#[test]
fn the_service_starts_with_the_snippets_live_names() {
    let rig = rig("", None);
    fs::write(rig.snippet("alice"), b"").expect("a snippet");
    let config = Config { boards_dir: rig.boards.clone(), suffix: "skep.host".into(), reply_to: "owner@skep.host".into() };
    let again = Service::new(config, rig.state.clone(), Box::new(Arc::clone(&rig.fake)), None, Arc::new(|_: &str| {}), Arc::new(|_| {})).expect("the service");
    assert_eq!(again.live(), 1);
}
