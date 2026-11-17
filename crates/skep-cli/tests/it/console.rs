//! The registrar's four commands through the binary (`skep review`, `skep
//! approve`, `skep deny`, `skep set-policy`; REG-4.107, REG-4.131): a
//! registry's door answered from a terminal and by the unattended hand,
//! over an ENFORCING board its registrar claimed.
//!
//! The board is claimed through the library; an account beside the
//! registrar's stands as the intake home and writes each request from its
//! own doc 1 under its own key; and every policy the cells stand under is
//! set with `skep set-policy` itself, typed at a pseudo-terminal. The
//! cells: the four verbs end to end, with what each prints; the doors that
//! refuse a pipe and the one that runs on it; the unattended hand's start,
//! its first pass and its two stops — between two requests, and with one
//! under way; the policy's four acts and the files it refuses; and a door
//! with no policy.

#![cfg(any(target_os = "macos", target_os = "linux"))]

use std::io::{BufRead, BufReader, Read};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc::{channel, Receiver};
use std::sync::Arc;
use std::time::{Duration, Instant};

use skep_client::board::{acked_addr, frames, Answer, Board, Opened, Scope, SessionBody, Token};
use skep_client::ceremony::claim::{self, ClaimOutcome, NotebookOptions};
use skep_client::ceremony::console::{read_queue, Door, Queue, State};
use skep_client::ceremony::deposit::{deposit, next_content_ordinal, Deposit, DepositKind};
use skep_client::ceremony::first_session::{mint_home, FirstSessionReads};
use skep_client::ceremony::handshake::{handshake, Site};
use skep_client::dial::{Dialer, PlainHttp};
use skep_client::person::scripted::{Script, Scripted};
use skep_client::sheet::{group_hex, Label};
use skep_client::sign::{session_payload, sig_hex, signer_from_seed, RecordFrame, Signer};
use skep_client::store::{FileStore, KeyStore};
use skep_client::Origin;
use skep_identity::{encode_enroll, AdmissionFrame, Enrollment};
use skep_registry::{encode_policy, encode_registration, parse_registration, Admission, AdmissionPolicy, Digits, Fresh, Hex64, HexDigits, RegistrationBody, RegistrationKind};
use skep_signature::HybridSigner;

use crate::common::{on_a_terminal_typing, origin, s, scrub, shell_word, skep, spawn, Run};

const T_REQUEST_FRESH: &str = "1.1.0.1.0.1.0.3.54.1.1";

/// A claimed ENFORCING board, its registrar's store, and an intake home.
struct Rig {
    dir: tempfile::TempDir,
    sd: skepd::Skepd,
    origin: String,
    board: Board,
    store: PathBuf,
    device: HybridSigner,
    door: Door,
    intake: Home,
}

/// An account beside the registrar's, keyed, with its home minted.
struct Home {
    account: String,
    home: String,
    principal: u64,
    signer: HybridSigner,
}

/// A FULL signed session under `signer` as `principal`, by the wire's own
/// three steps: the session of principal 0 — which mints top-level accounts
/// — opens so, by reference under the registrar's key.
fn session(board: &Board, principal: u64, signer: &HybridSigner) -> Token {
    let challenge = board.challenge(principal).expect("challenge");
    let payload = session_payload(board.signed(), &challenge.nonce, principal, Scope::Full);
    let sig = sig_hex(&Signer::sign(signer, &payload));
    match board.session_open(SessionBody::Signed { principal, nonce: &challenge.nonce, sig_hex: &sig, scope: Scope::Full }).expect("session") {
        Opened::Token(token) => token,
        other => panic!("the session answered {other:?}"),
    }
}

fn rig() -> Rig {
    let dir = tempfile::tempdir().unwrap();
    let sd = spawn(&dir.path().join("board"), false);
    let origin = origin(sd.port());
    let board = Board::new(Origin::parse(&origin).unwrap(), PlainHttp::new());
    let store = dir.path().join("registrar");
    let files = FileStore::open(&store);
    let fp = files.generate(Some(Label::new("registrar laptop").unwrap())).unwrap().0;
    let anchors = dir.path().join("anchors");
    let mut person = Scripted::new(vec![Script::LabelDefault, Script::LabelDefault]);
    let opts = NotebookOptions { principal: None, display_name: Some("a registrar".into()), anchor_out: vec![anchors.join("a"), anchors.join("b")], paper: false, host_name: "testhost".into(), date: "2026-11-16".into() };
    let ClaimOutcome::Ours(_) = claim::notebook(&board, &files, &mut person, &opts).unwrap_or_else(|h| panic!("{h}\n{}", person.transcript.join("\n"))) else { panic!("a stranger's board") };
    let device = files.load(&files.key_path(&fp)).expect("the device key").signer();
    let dialer: Arc<dyn Dialer> = Arc::new(PlainHttp::new());
    let door = Door::read(&board, dialer).expect("the door");

    // The intake home: a top-level account, delegated from principal 0's
    // session and keyed from the registrar's own, its home minted from its
    // own first signed session.
    let (principal, signer) = (7002u64, signer_from_seed(&[62; 32]));
    let zero = session(&board, 0, &device);
    let account = board.next_account_prefix("1").unwrap().expect("a next account");
    let Answer::Document(v) = board.op(Some(&zero), &frames::delegate(&account, principal, None)).expect("delegate") else { panic!("closed") };
    assert_eq!(acked_addr(&v), Some(account.as_str()), "{v}");
    board.session_close(&zero).unwrap();
    let own = handshake(&board, Scope::Full, &device, 1, Site::Console).expect("the registrar's session");
    let entry = Enrollment::new(Signer::public_key(&signer).clone(), false, Some("intake scribe".into())).unwrap();
    deposit(&board, own.token(), &Deposit { home: &door.home, subject: &account, kind: DepositKind::Enroll(vec![entry]), hand: Some(&device), id: "intake.genesis" }).unwrap_or_else(|h| panic!("the intake's genesis: {h}"));
    own.close().unwrap();
    let reads = FirstSessionReads::take(&board, &account, &Signer::fingerprint(&signer), None).expect("the reads");
    let as_intake = handshake(&board, Scope::Content, &signer, principal, Site::Session).expect("the intake's session");
    assert!(mint_home(&board, &reads, &as_intake, &signer).expect("the intake's home"));
    as_intake.close().unwrap();
    let intake = Home { home: reads.home, account, principal, signer };
    Rig { dir, sd, origin, board, store, device, door, intake }
}

impl Rig {
    /// The settings every registrar's command takes: the board and the store.
    fn settings(&self) -> Vec<String> {
        vec!["--board".into(), self.origin.clone(), "--dir".into(), s(&self.store).to_string()]
    }

    /// `skep <args>` with the settings, on pipes.
    fn piped(&self, args: &[&str]) -> Run {
        let settings = self.settings();
        let line: Vec<&str> = args.iter().copied().chain(settings.iter().map(String::as_str)).collect();
        skep(&line, &[], None)
    }

    /// `skep <args>` with the settings, at a pseudo-terminal, `typed` typed
    /// at it: the exit code, stdout, and what the terminal showed.
    fn at_a_terminal(&self, args: &[&str], typed: &str) -> (i32, String, String) {
        let (out, code) = (self.dir.path().join("stdout"), self.dir.path().join("code"));
        let _ = std::fs::remove_file(&out);
        let _ = std::fs::remove_file(&code);
        let settings = self.settings();
        let words: Vec<String> = args.iter().copied().chain(settings.iter().map(String::as_str)).map(shell_word).collect();
        let command = format!("{} {} > {}; echo $? > {}", shell_word(env!("CARGO_BIN_EXE_skep")), words.join(" "), shell_word(s(&out)), shell_word(s(&code)));
        let seen = on_a_terminal_typing(&command, typed, &code);
        let exit = std::fs::read_to_string(&code).unwrap_or_else(|e| panic!("the run's exit code: {e}: {seen}"));
        (exit.trim().parse().unwrap(), std::fs::read_to_string(&out).unwrap_or_default(), seen)
    }

    /// The door's policy set to `text` with `skep set-policy`, typed at a
    /// terminal: the version it stands as.
    fn set_policy(&self, text: &str) -> String {
        let file = self.dir.path().join("policy.json");
        std::fs::write(&file, text).unwrap();
        let (exit, out, seen) = self.at_a_terminal(&["set-policy", s(&file)], "publish\n");
        assert_eq!(exit, 0, "set-policy: {seen}");
        out.trim().strip_prefix("policy ").unwrap_or_else(|| panic!("`policy <version>` on stdout: {out:?}")).to_string()
    }

    /// `body` written as a fresh request from the intake home's own doc 1
    /// under its own key: the link's address.
    fn request(&self, body: &str) -> String {
        let kind = RegistrationKind::Fresh;
        let record = parse_registration(kind, body.as_bytes()).expect("a fresh request's body");
        let term = self.board.board_term().unwrap().expect("H.1");
        let (home, to) = (self.intake.home.as_str(), [self.door.account.as_str()]);
        let sigless = record.canonical_sigless();
        let frame = RecordFrame { alg: Signer::public_key(&self.intake.signer).alg(), board: term, home_account: &self.intake.account, home, ty: T_REQUEST_FRESH, to: &to, sigless: sigless.as_bytes() }.compose().expect("frame");
        let text = encode_registration(&record.body, Some(&sig_hex(&Signer::sign(&self.intake.signer, &frame))));
        let session = handshake(&self.board, Scope::Content, &self.intake.signer, self.intake.principal, Site::Session).expect("the intake's session");
        let (ordinal, as_of) = next_content_ordinal(&self.board, Some(session.token()), home).expect("ordinal");
        let Answer::Document(v) = session.op(&frames::insert_atom(home, ordinal, &text, T_REQUEST_FRESH, as_of, None)).expect("insert") else { panic!("closed") };
        let atom = acked_addr(&v).unwrap_or_else(|| panic!("the request's atom: {v}")).to_string();
        let Answer::Document(v) = session.op(&frames::make_link(home, &[&atom], &to, T_REQUEST_FRESH, None)).expect("link") else { panic!("closed") };
        let link = acked_addr(&v).unwrap_or_else(|| panic!("the request's link: {v}")).to_string();
        session.close().unwrap();
        link
    }

    /// A well-formed fresh request of applicant `n` for this door, written
    /// by the intake home: its link.
    fn good_request(&self, n: u8) -> String {
        self.request(&request_body(&self.door.id.to_string(), n, n))
    }

    fn queue(&self) -> Queue {
        read_queue(&self.board, None, &self.door).expect("the queue")
    }

    fn head(&self) -> u64 {
        self.board.health().unwrap().log_position()
    }

    /// A policy naming the rig's intake home.
    fn policy(&self, admission: Admission, approval: &str) -> String {
        let digits = |n: &str| Digits::new(n).unwrap();
        encode_policy(&AdmissionPolicy {
            admission,
            approval: approval.into(),
            intake: vec![skep_client::address::parse_address(&self.intake.account).unwrap()],
            intake_rate: digits("60"),
            intake_window: digits("3600"),
            intake_per_device: digits("3"),
            collection_interval: digits("1209600"),
            stale_request_interval: digits("2592000"),
            transcription_interval: digits("3600"),
            contact: "registrar@registry.example".into(),
            sponsors: None,
            grounds: vec!["No machine-rate sponsoring.".into(), "One registration a board.".into()],
        })
    }
}

/// Applicant `n`'s device key.
fn device_of(n: u8) -> HybridSigner {
    signer_from_seed(&[n.wrapping_mul(8).wrapping_add(1); 32])
}

/// The first 8 hex of applicant `n`'s device-key fingerprint: what an
/// officer types to answer its request.
fn row_of(n: u8) -> String {
    Signer::fingerprint(&device_of(n)).to_hex()[..8].to_string()
}

/// A fresh request's body for `door`, of applicant `n`, under the freshness
/// value `fresh`: two pairs and the device key, signed by the device key.
fn request_body(door: &str, n: u8, fresh: u8) -> String {
    let key = |k: u8| signer_from_seed(&[n.wrapping_mul(8).wrapping_add(k); 32]);
    let device = device_of(n);
    let entry = |signer: &HybridSigner, anchor: bool, label: &str| Enrollment::new(Signer::public_key(signer).clone(), anchor, Some(label.into())).unwrap();
    let pair = |a: u8, b: u8, name: &str| encode_enroll(&[entry(&key(a), true, &format!("{name} sheet a")), entry(&key(b), true, &format!("{name} sheet b")), entry(&device, false, "applicant laptop")]);
    let (node, board, shape) = (pair(2, 3, "node"), pair(4, 5, "org root"), RegistrationKind::Fresh.row().ordinal_path());
    let fresh = format!("{fresh:02x}").repeat(32);
    let frame = AdmissionFrame { door, fresh: &fresh, shape: &shape, node: &node, board: Some(&board) };
    let signature = HexDigits::new(sig_hex(&Signer::sign(&device, &frame.to_bytes()))).unwrap();
    encode_registration(
        &RegistrationBody::Fresh(Fresh { door: door.into(), fresh: Hex64::new(fresh).unwrap(), shape, node, board, signer: Hex64::new(Signer::fingerprint(&device).to_hex()).unwrap(), signature }),
        None,
    )
}

/// The value of the stdout line that opens with `name`.
fn field<'o>(out: &'o str, name: &str) -> &'o str {
    out.lines().find_map(|line| line.strip_prefix(name).and_then(|rest| rest.strip_prefix(' '))).unwrap_or_else(|| panic!("a `{name}` line on stdout: {out:?}"))
}

/// FENCE 14 (calls 2, 3, 5; the whole lane) — THE FOUR VERBS, END TO END.
/// `set-policy` publishes the door's policy; `review` prints the three
/// blocks, each request by its link address with its kind, its time, its
/// verdict, "no name given" and each key's label beside its grouped
/// fingerprint, and says the door's identifier and the policy on stderr;
/// `approve <link address>` at a terminal mints, binds and replies, and
/// answers a request that fails its check refused; `deny` cites the clause.
/// At an `n-vouches` door and at an `invitation-only` one `approve` refuses
/// before any write, naming the mode, while `review` and `deny` work there.
#[test]
fn the_four_verbs_answer_a_door_end_to_end() {
    let rig = rig();
    assert_eq!(rig.set_policy(&rig.policy(Admission::Open, "officer")), format!("{}.0.5.1", rig.door.account));
    let (first, replay, third, fourth) = (rig.good_request(1), rig.request(&request_body(&rig.door.id.to_string(), 2, 1)), rig.good_request(3), rig.good_request(4));

    // review: three blocks, read as a guest, on pipes.
    let run = rig.piped(&["review"]);
    assert_eq!(run.code, 0, "{run:?}");
    let lines = run.lines();
    assert_eq!((lines[0], lines[lines.len() - 2], lines[lines.len() - 1]), ("WAITING (4)", "APPROVED AND NOT COLLECTED (0)", "CLOSED (0)"), "{}", run.out);
    let line_of = |out: &str, link: &str| out.lines().find(|line| line.starts_with(&format!("{link}  "))).unwrap_or_else(|| panic!("{link} is listed: {out}")).to_string();
    let listed = line_of(&run.out, &first);
    let parts: Vec<&str> = listed.split("  ").collect();
    assert_eq!((parts[0], parts[1], parts[3], parts[4]), (first.as_str(), "fresh", "passes", "no name given"), "{listed}");
    assert!(parts[2].len() == "2026-11-16 14:02:11Z".len() && parts[2].ends_with('Z') && parts[2].starts_with("20"), "its time, in UTC: {listed}");
    assert!(line_of(&run.out, &replay).contains("  fails: freshness-spent (an earlier request at this door carries its freshness value)  no name given"), "{}", run.out);
    let fingerprint = Signer::fingerprint(&device_of(1)).to_hex();
    let grouped: Vec<String> = group_hex(&fingerprint).lines().map(|line| format!("      {line}")).collect();
    let at = lines.iter().position(|line| *line == "    device key — `applicant laptop`").expect("the device key's label");
    assert_eq!(&lines[at + 1..at + 3], grouped.as_slice(), "its fingerprint, grouped");
    for named in ["    org root pair, sheet a — `org root sheet a`", "    node pair, sheet b — `node sheet b`"] {
        assert!(lines.contains(&named), "{named}: {}", run.out);
    }
    assert!(run.err.contains(&format!("this door: `{}`", rig.door.id)) && run.err.contains(&format!("the policy standing: {}.0.5.1 — `open` admission, approved by `officer` (an officer's hand)", rig.door.account)), "{}", run.err);

    // approve <link address>: mints, binds, replies.
    let (exit, out, seen) = rig.at_a_terminal(&["approve", &first], &format!("{}\n", row_of(1)));
    assert_eq!(exit, 0, "{seen}");
    assert_eq!(out.lines().map(|line| line.split(' ').next().unwrap()).collect::<Vec<_>>(), ["approved", "prefix", "account", "principal", "answer"], "{out}");
    assert_eq!((field(&out, "approved"), field(&out, "prefix")), (first.as_str(), "1.2"));
    assert!(seen.contains("[REG-4.123] APPROVING the request") && seen.contains("type the first 8 hex of that fingerprint") && seen.contains("is APPROVED"), "{seen}");
    let queue = rig.queue();
    let thread = queue.thread(&first).unwrap();
    assert_eq!(thread.state, State::ApprovedNotCollected);
    assert_eq!(thread.answers[0].link, field(&out, "answer"));
    assert_eq!(thread.approved().unwrap().node_address.to_string(), field(&out, "account"));
    // A request that fails the check is answered refused, by the same verb.
    let (exit, out, seen) = rig.at_a_terminal(&["approve", &replay], "");
    assert_eq!((exit, out.lines().map(|line| line.to_string()).collect::<Vec<_>>()[..2].to_vec()), (0, vec![format!("refused {replay}"), "fault freshness-spent".to_string()]), "{seen}");
    // A wrong row declines, and nothing is written.
    let before = rig.head();
    let (exit, out, seen) = rig.at_a_terminal(&["approve", &third], "00000000\n");
    assert!(exit == 3 && out.is_empty() && seen.contains("the request was not approved: the confirmation was declined") && rig.head() == before, "{exit} {out} {seen}");

    // deny <link address> --clause <n>.
    let (exit, out, seen) = rig.at_a_terminal(&["deny", &third, "--clause", "2"], &format!("{}\n", row_of(3)));
    assert_eq!(exit, 0, "{seen}");
    assert_eq!(out, format!("denied {third}\npolicy {}.0.5.1\nclause 2\nanswer {}\n", rig.door.account, rig.queue().thread(&third).unwrap().answers[0].link));
    assert!(seen.contains("`One registration a board.`"), "the clause's words are said: {seen}");

    let run = rig.piped(&["review"]);
    let lines = run.lines();
    assert!(lines.contains(&"WAITING (1)") && lines.contains(&"APPROVED AND NOT COLLECTED (1)") && lines.contains(&"CLOSED (2)"), "{}", run.out);
    assert!(line_of(&run.out, &first).contains(&format!("  approved: prefix 1.2, account {}, principal ", field(&out_of(&rig, &first), "account"))), "{}", run.out);
    assert!(line_of(&run.out, &replay).contains("  refused: freshness-spent  ") && line_of(&run.out, &third).contains(&format!("  denied: clause 2 of {}.0.5.1  ", rig.door.account)), "{}", run.out);

    // At a door that is not open: approve refuses, naming the mode, before
    // any write; review and deny work.
    for (admission, mode) in [(Admission::NVouches(Digits::new("2").unwrap()), "n-vouches"), (Admission::InvitationOnly, "invitation-only")] {
        let version = rig.set_policy(&rig.policy(admission, "officer"));
        let before = rig.head();
        let (exit, out, seen) = rig.at_a_terminal(&["approve", &fourth], &format!("{}\n", row_of(4)));
        assert!(exit == 3 && out.is_empty(), "{mode}: {seen}");
        assert!(seen.contains(&format!("this door's admission is `{mode}`, and `skep approve` approves at an open door alone")), "{mode}: {seen}");
        assert_eq!(rig.head(), before, "{mode}: nothing was written");
        let run = rig.piped(&["review"]);
        assert!(run.code == 0 && run.out.starts_with("WAITING (") && run.err.contains(&format!("the policy standing: {version} — `{mode}` admission")), "{mode}: {run:?}");
    }
    let (exit, out, seen) = rig.at_a_terminal(&["deny", &fourth, "--clause", "1"], &format!("{}\n", row_of(4)));
    assert!(exit == 0 && out.starts_with(&format!("denied {fourth}\npolicy {}.0.5.3\nclause 1\n", rig.door.account)), "a denial at an invitation-only door: {seen}");
    rig.sd.shutdown();
}

/// The lines `skep approve` printed for `request`, re-read off the board:
/// its account, as the queue holds the approved answer.
fn out_of(rig: &Rig, request: &str) -> String {
    let queue = rig.queue();
    let approved = queue.thread(request).and_then(|thread| thread.approved().cloned()).expect("an approved answer");
    format!("account {}\n", approved.node_address)
}

/// A running `skep approve --auto`: its process, and its stdout by line.
struct Auto {
    child: Child,
    lines: Receiver<String>,
    err: std::thread::JoinHandle<String>,
}

impl Auto {
    /// The unattended hand started on pipes — no terminal anywhere — under
    /// `key`, with `envs` set.
    fn start(rig: &Rig, key: &Path, envs: &[(&str, &Path)]) -> Auto {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_skep"));
        cmd.args(["approve", "--auto", "--board", &rig.origin, "--dir", s(&rig.store), "--key", s(key)]).stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped());
        scrub(&mut cmd);
        for (name, value) in envs {
            cmd.env(name, value);
        }
        let mut child = cmd.spawn().expect("spawn skep approve --auto");
        let (tx, lines) = channel();
        let stdout = child.stdout.take().unwrap();
        std::thread::spawn(move || {
            for line in BufReader::new(stdout).lines().map_while(Result::ok) {
                let _ = tx.send(line);
            }
        });
        let mut stderr = child.stderr.take().unwrap();
        let err = std::thread::spawn(move || {
            let mut said = String::new();
            let _ = stderr.read_to_string(&mut said);
            said
        });
        Auto { child, lines, err }
    }

    /// The next line it prints on stdout, within a minute.
    fn line(&self) -> String {
        self.lines.recv_timeout(Duration::from_secs(60)).expect("a line on stdout within a minute")
    }

    fn signal(&self, name: &str) {
        let status = Command::new("kill").args([&format!("-{name}"), &self.child.id().to_string()]).status().expect("kill(1)");
        assert!(status.success(), "kill -{name}");
    }

    fn running(&mut self) -> bool {
        matches!(self.child.try_wait(), Ok(None))
    }

    /// Waits for the process to end, within `within`: its exit code, what it
    /// still printed, and what it said.
    fn ended(mut self, within: Duration) -> (Option<i32>, Vec<String>, String) {
        let started = Instant::now();
        while self.running() && started.elapsed() < within {
            std::thread::sleep(Duration::from_millis(20));
        }
        if self.running() {
            let _ = self.child.kill();
            panic!("the unattended hand did not end within {within:?}");
        }
        let code = self.child.wait().unwrap().code();
        let rest: Vec<String> = self.lines.try_iter().collect();
        (code, rest, self.err.join().unwrap())
    }
}

/// The registrar's labeled device key: a second device key of the
/// registrar's own set, in the registrar's store. Answers its file.
fn labeled_key(rig: &Rig) -> PathBuf {
    let files = FileStore::open(&rig.store);
    let fp = files.generate(Some(Label::new("registry console").unwrap())).unwrap().0;
    let path = files.key_path(&fp);
    let file = files.load(&path).unwrap();
    let own = handshake(&rig.board, Scope::Full, &rig.device, 1, Site::Console).expect("the registrar's session");
    let entry = Enrollment::new(file.public.clone(), false, Some("registry console".into())).unwrap();
    deposit(&rig.board, own.token(), &Deposit { home: &rig.door.home, subject: &rig.door.account, kind: DepositKind::Enroll(vec![entry]), hand: Some(&rig.device), id: "console.key" }).unwrap_or_else(|h| panic!("the console's key: {h}"));
    own.close().unwrap();
    path
}

/// FENCES 14, 15 and 16 (calls 4 (1), (3), (5), (7); call 1 item 3) — THE
/// UNATTENDED HAND, AND THE DOORS THAT WANT A PERSON. `approve <request>`,
/// `deny` and `set-policy`, run on pipes, each halt as a person door naming
/// its own moments and write nothing; `approve --auto`, run on pipes with no
/// terminal anywhere, refuses to start under a policy naming the officer,
/// and under open admission approved by `auto` does its first pass —
/// approving the request that passes and refusing the one that fails,
/// under the labeled key, one line each on stdout. Sent SIGTERM between two
/// reads of the queue it exits 0 at once, saying it stopped; started again
/// and sent SIGINT the same.
#[test]
fn the_unattended_hand_runs_on_pipes_and_stops_between_requests_and_the_person_doors_do_not() {
    let rig = rig();
    let key = labeled_key(&rig);
    let registrar_key = FileStore::open(&rig.store).key_path(&Signer::fingerprint(&rig.device));
    rig.set_policy(&rig.policy(Admission::Open, "officer"));
    let (passing, failing) = (rig.good_request(1), rig.request(&request_body(&rig.door.id.to_string(), 2, 1)));
    let file = rig.dir.path().join("next.json");
    std::fs::write(&file, rig.policy(Admission::Open, "auto")).unwrap();

    // The three person doors, on pipes.
    let before = rig.head();
    for (args, form, moments) in [
        (vec!["approve", passing.as_str(), "--key", s(&registrar_key)], "approve <request>", "the comparison of the request's keys and its typed confirmation"),
        (vec!["deny", passing.as_str(), "--clause", "1", "--key", s(&registrar_key)], "deny", "the clause's statement and its typed confirmation"),
        (vec!["set-policy", s(&file), "--key", s(&registrar_key)], "set-policy", "the policy's statement and its typed confirmation"),
    ] {
        let run = rig.piped(&args);
        assert_eq!(run.code, 3, "{args:?}: {run:?}");
        assert!(run.err.contains(&format!("`{form}` is a person door and requires a controlling terminal")) && run.err.contains(&format!("what a person answers here — {moments} —")), "{args:?}: {}", run.err);
        assert!(run.out.is_empty());
    }
    assert_eq!(rig.head(), before, "no person door wrote from a pipe");

    // It refuses to start under a policy naming the officer.
    let run = rig.piped(&["approve", "--auto", "--key", s(&key)]);
    assert_eq!(run.code, 3, "{run:?}");
    assert!(run.err.contains("the unattended hand does not start") && run.err.contains("is `open` admission approved by `officer`") && run.out.is_empty(), "{}", run.err);
    assert_eq!(rig.head(), before);

    // Open admission approved by `auto`: the first pass, on pipes.
    let (exit, _, seen) = rig.at_a_terminal(&["set-policy", s(&file), "--key", s(&registrar_key)], "publish\n");
    assert_eq!(exit, 0, "{seen}");
    let auto = Auto::start(&rig, &key, &[]);
    let (approved, refused) = (auto.line(), auto.line());
    let parts: Vec<&str> = approved.split(' ').collect();
    assert_eq!((parts[0], parts[1], parts[2], parts.len()), ("approved", passing.as_str(), "1.2", 6), "{approved}");
    assert!(refused.starts_with(&format!("refused {failing} freshness-spent ")), "{refused}");
    let queue = rig.queue();
    assert_eq!((queue.thread(&passing).unwrap().state, queue.thread(&failing).unwrap().state), (State::ApprovedNotCollected, State::Closed));

    // SIGTERM between two reads of the queue: exit 0, at once, saying so.
    let before = rig.head();
    auto.signal("TERM");
    let (code, rest, said) = auto.ended(Duration::from_secs(5));
    assert_eq!((code, rest.len()), (Some(0), 0), "{said}");
    assert!(said.contains("the unattended hand is watching the door") && said.trim_end().ends_with("the unattended hand is stopped, between two requests: nothing is left half done"), "{said}");
    assert_eq!(rig.head(), before, "it wrote nothing more");

    // SIGINT, the same, with nothing waiting.
    let mut auto = Auto::start(&rig, &key, &[]);
    std::thread::sleep(Duration::from_millis(1500));
    assert!(auto.running(), "it runs until it is stopped");
    auto.signal("INT");
    let (code, rest, said) = auto.ended(Duration::from_secs(5));
    assert_eq!((code, rest.len()), (Some(0), 0), "{said}");
    assert!(said.contains("the unattended hand is stopped"), "{said}");
    rig.sd.shutdown();
}

/// FENCE 16 (call 4 (1), (7)) — A STOP SENT WHILE AN APPROVAL IS UNDER WAY
/// LETS IT RUN TO ITS END. The unattended hand is held inside an approval —
/// its node account made and keyed, its binding and its answer not yet
/// written — and sent SIGTERM there: it does not end. Released, it writes
/// the binding and the answer, prints the act, and then exits 0 saying it
/// stopped, with the second waiting request untouched: the stop is read
/// between two requests, never inside one. SIGINT the same.
#[test]
fn a_stop_sent_inside_an_approval_lets_the_approval_finish_and_stops_before_the_next() {
    let rig = rig();
    let key = labeled_key(&rig);
    rig.set_policy(&rig.policy(Admission::Open, "auto"));
    for (round, signal) in ["TERM", "INT"].into_iter().enumerate() {
        let n = 1 + 2 * round as u8;
        let (under_way, next) = (rig.good_request(n), rig.good_request(n + 1));
        let hold = rig.dir.path().join(format!("hold-{signal}"));
        std::fs::create_dir(&hold).unwrap();
        let mut auto = Auto::start(&rig, &key, &[("SKEP_TEST_HOLD_APPROVAL", hold.as_path())]);
        let started = Instant::now();
        while !hold.join("held").exists() {
            assert!(auto.running() && started.elapsed() < Duration::from_secs(60), "{signal}: the approval reached its hold");
            std::thread::sleep(Duration::from_millis(20));
        }
        let held = rig.queue();
        let thread = held.thread(&under_way).unwrap();
        assert!(thread.approval.is_some() && thread.answers.is_empty(), "{signal}: held after the mint, before the reply");
        auto.signal(signal);
        std::thread::sleep(Duration::from_millis(800));
        assert!(auto.running(), "{signal}: a stop inside an approval does not end it");
        assert!(rig.queue().thread(&under_way).unwrap().answers.is_empty(), "{signal}: and the act waits where it was held");
        std::fs::write(hold.join("release"), b"go").unwrap();
        let printed = auto.line();
        assert!(printed.starts_with(&format!("approved {under_way} ")), "{signal}: the act ran to its end: {printed}");
        let (code, rest, said) = auto.ended(Duration::from_secs(10));
        assert_eq!((code, rest.len()), (Some(0), 0), "{signal}: {said}");
        assert!(said.trim_end().ends_with("the unattended hand is stopped, between two requests: nothing is left half done"), "{signal}: {said}");
        let queue = rig.queue();
        assert_eq!(queue.thread(&under_way).unwrap().state, State::ApprovedNotCollected, "{signal}: the reply stands on the thread");
        assert_eq!(queue.thread(&next).unwrap().state, State::Waiting, "{signal}: the next request was not begun");
        // The next request is left for the next run: answered here, so each
        // round starts from an empty queue.
        let (exit, _, seen) = rig.at_a_terminal(&["deny", &next, "--clause", "1"], &format!("{}\n", row_of(n + 1)));
        assert_eq!(exit, 0, "{seen}");
    }
    rig.sd.shutdown();
}

/// FENCES 17 and 18 (call 1 items 2 and 3; WELL-KNOWN CALLS 4 and 5) — THE
/// POLICY COMMAND, AND A DOOR WITH NONE. With no document 5, `review` says
/// the door has no policy and lists nothing, though a request stands on the
/// intake home; `approve`, `deny` and `approve --auto` refuse, naming it,
/// and write nothing. A file past 16 KiB, and one the parser refuses, are
/// refused by `set-policy` before the door and before any write: document 5
/// is not created. The first `set-policy` creates it and publishes
/// `.0.5.1`; a second publishes `.0.5.2` and creates nothing; the same file
/// again publishes nothing, asks nothing and says so; a declined
/// confirmation publishes nothing. And the request written while the door
/// had no policy is not admitted once it has one.
#[test]
fn set_policy_publishes_each_file_as_the_next_version_and_a_door_with_none_is_shut() {
    let rig = rig();
    let key = labeled_key(&rig);
    let document = format!("{}.0.5", rig.door.account);
    let early = rig.good_request(1);

    // No policy: review says so, and every act refuses before any write.
    let before = rig.head();
    let run = rig.piped(&["review"]);
    assert_eq!((run.code, run.out.as_str()), (0, "WAITING (0)\nAPPROVED AND NOT COLLECTED (0)\nCLOSED (0)\n"), "{run:?}");
    let no_policy = format!("this door has no policy: its policy document {document} has not been created");
    assert!(run.err.contains(&no_policy) && run.err.contains("A door with no policy is shut") && run.err.contains("`skep set-policy <file>`"), "{}", run.err);
    for (args, typed) in [(vec!["approve", early.as_str()], row_of(1)), (vec!["deny", early.as_str(), "--clause", "1"], row_of(1))] {
        let (exit, out, seen) = rig.at_a_terminal(&args, &format!("{typed}\n"));
        assert!(exit == 3 && out.is_empty() && seen.contains(&no_policy) && seen.contains("is shut"), "{args:?}: {seen}");
    }
    let run = rig.piped(&["approve", "--auto", "--key", s(&key)]);
    assert!(run.code == 3 && run.err.contains("the unattended hand does not start") && run.err.contains(&no_policy), "{run:?}");
    assert_eq!(rig.head(), before, "nothing was written");

    // Files that would stand as no policy: refused before any write, on a
    // pipe as at a terminal.
    let good = rig.policy(Admission::Open, "officer");
    let mut long = skep_registry::parse_policy(good.as_bytes()).unwrap();
    long.contact = "x".repeat(16_384);
    let file = rig.dir.path().join("refused.json");
    for (text, why) in [(encode_policy(&long), "past the cap of 16384"), (format!("{good}\n"), "the file is no admission policy: not_canonical"), ("{}".to_string(), "the file is no admission policy: wrong_type")] {
        std::fs::write(&file, text).unwrap();
        let run = rig.piped(&["set-policy", s(&file)]);
        assert!(run.code == 3 && run.out.is_empty() && run.err.contains(why) && run.err.contains("nothing was written"), "{why}: {run:?}");
    }
    let run = rig.piped(&["set-policy", s(&rig.dir.path().join("absent.json"))]);
    assert!(run.code == 3 && run.err.contains("could not be read"), "{run:?}");
    let run = rig.piped(&["set-policy"]);
    assert!(run.code == 2 && run.err.contains("a file is required: `skep set-policy <file>`"), "{run:?}");
    let absent = matches!(rig.board.op(None, &frames::doc_metadata(&document)).unwrap(), Answer::Document(v) if v["code"] == "doc_not_registered");
    assert!(absent && rig.head() == before, "document 5 is not created by a refused file");

    // A declined confirmation publishes nothing.
    std::fs::write(&file, &good).unwrap();
    let (exit, out, seen) = rig.at_a_terminal(&["set-policy", s(&file)], "no\n");
    assert!(exit == 3 && out.is_empty() && seen.contains("the policy was not published: the confirmation was declined") && rig.head() == before, "{seen}");

    // The first policy, the next, and the same file again.
    let (exit, out, seen) = rig.at_a_terminal(&["set-policy", s(&file)], "publish\n");
    assert_eq!((exit, out.as_str()), (0, format!("policy {document}.1\n").as_str()), "{seen}");
    assert!(seen.contains(&format!("this publishes the door's policy as {document}.1, creating the door's policy document first")) && seen.contains(&format!("the door's policy document {document} is created")) && seen.contains(&format!("the policy is published as {document}.1")), "{seen}");
    let next = rig.policy(Admission::Open, "auto");
    std::fs::write(&file, &next).unwrap();
    let (exit, out, seen) = rig.at_a_terminal(&["set-policy", s(&file)], "publish\n");
    assert_eq!((exit, out.as_str()), (0, format!("policy {document}.2\n").as_str()), "{seen}");
    assert!(!seen.contains("is created") && seen.contains("the unattended hand approves what passes"), "{seen}");
    let before = rig.head();
    let (exit, out, seen) = rig.at_a_terminal(&["set-policy", s(&file)], "");
    assert_eq!((exit, out.as_str()), (0, format!("policy {document}.2\n").as_str()), "the same file again: {seen}");
    assert!(seen.contains(&format!("the version standing, {document}.2, already holds this file: nothing was published")) && !seen.contains("type `publish`") && rig.head() == before, "{seen}");

    // What a guest reads at the head is the file's bytes, as text.
    let Answer::Document(v) = rig.board.op(None, &frames::retrieve_v(&document, 1, next.len() as u64)).unwrap() else { panic!("closed") };
    let read: String = v["items"].as_array().unwrap().iter().map(|item| item["content"].as_str().unwrap_or_else(|| panic!("per-byte text: {item}"))).collect();
    assert_eq!(read, next);

    // The request written while the door had no policy is not admitted.
    let admitted = rig.good_request(2);
    let run = rig.piped(&["review"]);
    assert!(run.out.starts_with(&format!("WAITING (1)\n{admitted}  fresh  ")) && !run.out.contains(&early), "{}", run.out);
    rig.sd.shutdown();
}
