//! T14 — THE BUILT BINARY, driven as a browser and the owner would drive it,
//! over the two fakes its `test-hooks` build takes (this crate's self
//! dev-dependency turns the feature on for the suite, no flag added): the
//! `invite` verb mints a code; `serve` runs on an ephemeral loopback port
//! with `--docker-fake` and `--mailer-fake` over a temp state directory; the
//! sign-up page, the claim form with the link's code, a sign-up, a post
//! through to the live reply at its status URL, the snippet, the one
//! mail; a second post on the name, a bad record, a preview record, an
//! unknown code, a status token never minted, a body past the cap — each
//! answered as the pages say; and THE STOP: SIGTERM, the default
//! disposition, ending the process. THE SWEEP (T22): started over a script
//! whose `volumes` lists one half-made name, the binary removes it before
//! its serving line, which carries the count. A START REFUSED — a snippet
//! directory that cannot be read, an address another listener holds — and
//! an invite not minted each exit 1, with no DATA line. No Docker runs:
//! every call is the script's, and the calls are read back after. Beside
//! it, `tidy` reads the crate's own source and manifest for the arrangement
//! `src/main.rs` and `ARCHITECTURE.md` §The provisioning service state.

#![cfg(unix)]

mod tidy;

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{Shutdown, TcpStream};
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use skep_identity::{encode_enroll, Enrollment, PublicKey, ALG_FNDSA512_PREVIEW_ED25519, ALG_MLDSA65_ED25519, FNDSA512_PREVIEW_ED25519_KEY_LEN, MLDSA65_ED25519_KEY_LEN};

/// The binary under test, built with `test-hooks`.
const BIN: &str = env!("CARGO_BIN_EXE_skep-provision");

/// The six DATA lines a fresh board's dark claim prints.
const SIX: &str = "claimant 1.0.1\\naccount 1.0.1\\nprincipal 1\\norigin http://127.0.0.1:8642\\nfirst act: from the device that generated the payload run `skep verify --board http://127.0.0.1:8642 --principal 1 --payload <the record it printed>`\\nsecond act: in your first signed session the setup act runs\\n";

/// A claimed alpha board's `/health`.
const PAIRED: &str = r#"{"auth":{"claimant":"1.0.1","local_trust":false,"origins":[],"signed_origins":["https://alice.skep.host"]},"chain_head":"00","head_time":null,"log_position":0,"media":{"uploads":true},"ok":true,"writes":{"halted":false}}"#;

/// The body cap the service reads under (`pages::MAX_BODY`): a record at
/// its cap, every byte percent-encoded, and 4 KiB.
const MAX_BODY: usize = 3 * 128 * 1024 + 4096;

/// A scratch directory under the system temp directory, removed when
/// dropped.
struct Scratch(PathBuf);

impl Scratch {
    fn new() -> Scratch {
        let mut raw = [0u8; 8];
        getrandom::fill(&mut raw).expect("OS entropy");
        let path = std::env::temp_dir().join(format!("skep-provision-it-{}", raw.iter().map(|b| format!("{b:02x}")).collect::<String>()));
        std::fs::create_dir(&path).expect("a scratch directory");
        Scratch(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// A record as a person's device prints it: one key of `alg`.
fn record(alg: &str, raw_len: usize) -> String {
    let key = PublicKey::parse(alg, &"9f".repeat(raw_len)).expect("a key");
    encode_enroll(&[Enrollment::new(key, true, None).expect("no label")])
}

/// Bytes as a browser's form sends them: every byte but the unreserved
/// percent-encoded.
fn form_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|&b| if b.is_ascii_alphanumeric() || b"-._~".contains(&b) { (b as char).to_string() } else { format!("%{b:02X}") }).collect()
}

/// One script line for the docker fake: TAB-separated, `\n` escaped by the
/// caller.
fn step(method: &str, name: &str, code: i32, stdout: &str) -> String {
    format!("{method}\t{name}\t{code}\t{stdout}\n")
}

/// `skep-provision invite`: its exit code, its stdout, its stderr.
fn invite(state: &Path) -> (i32, String, String) {
    let out = Command::new(BIN).args(["invite", "--address", "person@example.com", "--state-dir"]).arg(state).stdin(Stdio::null()).output().expect("the invite verb ran");
    (out.status.code().unwrap_or(-1), String::from_utf8_lossy(&out.stdout).into_owned(), String::from_utf8_lossy(&out.stderr).into_owned())
}

/// A code off the invite verb's one DATA line.
fn minted(state: &Path) -> String {
    let (code, out, err) = invite(state);
    assert_eq!(code, 0, "{err}");
    let line = out.trim_end();
    assert_eq!(out.lines().count(), 1, "one DATA line: {out}");
    line.strip_prefix("https://skep.host/claim?invite=").unwrap_or_else(|| panic!("the invite link: {line}")).to_owned()
}

/// THE SERVICE RUNNING: the child, its port off the serving line, the line
/// itself, its log.
struct Service {
    child: Child,
    port: u16,
    serving: String,
    log: Arc<Mutex<String>>,
}

impl Service {
    fn start(dir: &Path, script: &Path, mail: &Path) -> Service {
        let mut child = Command::new(BIN)
            .args(["serve", "--listen", "127.0.0.1:0", "--state-dir"])
            .arg(dir.join("state"))
            .arg("--boards-dir")
            .arg(dir.join("boards"))
            .args(["--reply-to", "owner@skep.host", "--from", "noreply@skep.host", "--docker-fake"])
            .arg(script)
            .arg("--mailer-fake")
            .arg(mail)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("serve started");
        let log = Arc::new(Mutex::new(String::new()));
        let into = Arc::clone(&log);
        let stderr = child.stderr.take().expect("its stderr");
        thread::spawn(move || {
            let mut reader = BufReader::new(stderr);
            let mut line = String::new();
            while let Ok(1..) = reader.read_line(&mut line) {
                into.lock().unwrap().push_str(&line);
                line.clear();
            }
        });
        let mut serving = String::new();
        BufReader::new(child.stdout.take().expect("its stdout")).read_line(&mut serving).expect("the serving line");
        let at = serving.strip_prefix("skep-provision: serving http://127.0.0.1:").unwrap_or_else(|| panic!("the serving line: {serving:?}; the log: {}", log.lock().unwrap()));
        let port = at[..at.find('/').expect("the address's end")].parse().expect("a port");
        assert!(serving.contains("mail on"), "{serving}");
        Service { child, port, serving, log }
    }

    /// One request: the status and the body.
    fn request(&self, method: &str, target: &str, body: &str) -> (u16, String) {
        let mut stream = TcpStream::connect(("127.0.0.1", self.port)).expect("connected");
        stream.set_read_timeout(Some(Duration::from_secs(60))).expect("a deadline");
        let head = format!("{method} {target} HTTP/1.1\r\nHost: skep.host\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\n\r\n", body.len());
        stream.write_all(head.as_bytes()).expect("the head");
        stream.write_all(body.as_bytes()).expect("the body");
        let _ = stream.shutdown(Shutdown::Write);
        read_answer(stream)
    }

    fn log(&self) -> String {
        self.log.lock().unwrap().clone()
    }

    /// THE STOP: SIGTERM, and the process's end by it.
    fn terminate(mut self) -> std::process::ExitStatus {
        let sent = Command::new("kill").args(["-TERM", &self.child.id().to_string()]).status().expect("kill ran");
        assert!(sent.success());
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            if let Some(status) = self.child.try_wait().expect("waited") {
                return status;
            }
            assert!(Instant::now() < deadline, "the service did not stop on SIGTERM");
            thread::sleep(Duration::from_millis(20));
        }
    }
}

impl Drop for Service {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// An answer read to the close: the status and the body.
fn read_answer(mut stream: TcpStream) -> (u16, String) {
    let mut raw = Vec::new();
    stream.read_to_end(&mut raw).expect("an answer");
    let text = String::from_utf8_lossy(&raw).into_owned();
    let (head, body) = text.split_once("\r\n\r\n").unwrap_or_else(|| panic!("a head: {text}"));
    let status = head.split(' ').nth(1).expect("a status").parse().expect("a number");
    (status, body.to_owned())
}

/// Polled until `done` answers `Some`, or the deadline passes.
fn until<T>(what: &str, mut done: impl FnMut() -> Option<T>) -> T {
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if let Some(t) = done() {
            return t;
        }
        assert!(Instant::now() < deadline, "{what} never came");
        thread::sleep(Duration::from_millis(20));
    }
}

/// T14: THE SERVICE, FROM THE FORM's POST TO THE LIVE PAGE, over the fakes —
/// and every refusal a post can meet, a status token never minted, a body
/// past the cap, and the stop.
#[test]
fn the_built_service_runs_a_post_from_the_form_to_the_live_page_over_the_fakes() {
    let dir = Scratch::new();
    std::fs::create_dir(dir.path().join("boards")).expect("the boards directory");
    let state = dir.path().join("state");
    let code = minted(&state);
    assert_eq!(code.len(), 32);
    let script = dir.path().join("docker.script");
    let steps = [
        step("volumes", "-", 0, ""),
        step("volume_inspect", "alice", 1, ""),
        step("container_inspect", "alice", 1, ""),
        step("volume_inspect", "alice", 1, ""),
        step("container_inspect", "alice", 1, ""),
        step("volume_create", "alice", 0, "alice\\n"),
        step("run_claim", "alice", 0, ""),
        step("sidecar_claim", "alice", 0, SIX),
        step("rm_force", "alice", 0, ""),
        step("run_serving", "alice", 0, ""),
        step("health", "alice", 0, PAIRED),
        step("caddy_reload", "-", 0, ""),
    ];
    std::fs::write(&script, steps.concat()).expect("the script");
    let mail = dir.path().join("mail.log");
    let service = Service::start(dir.path(), &script, &mail);

    // The sign-up page, and the claim form with the link's code: D-1, D-2,
    // D-3 and D-9 in the HTML.
    let (status, page) = service.request("GET", "/", "");
    assert_eq!(status, 200);
    assert!(page.contains("Your email address") && page.contains("action=\"/signup\""), "{page}");
    let (status, form) = service.request("GET", &format!("/claim?invite={code}"), "");
    assert_eq!(status, 200);
    for ruled in [
        "A board of your own at a name under skep.host. Your keys stay on your device: this page makes none.",
        "Your board's name",
        "one label: letters, digits and hyphens; it becomes ⟨name⟩.skep.host",
        "Your record",
        "On your own device run <code>skep keygen --anchors --anchor-out &lt;a&gt; --anchor-out &lt;b&gt;</code> (two papers, kept apart) or <code>skep keygen --payload</code>, and paste the one line it printed. Paste only what it printed: it holds no private key.",
        "Your invite code",
    ] {
        assert!(form.contains(ruled), "{ruled}");
    }
    assert!(form.contains(&format!("value=\"{code}\"")), "the link's code pre-filled");
    assert!(!form.contains("<script"));

    // A sign-up writes its line.
    let (status, thanks) = service.request("POST", "/signup", "address=someone%40example.org");
    assert_eq!(status, 200);
    assert!(thanks.contains("Thank you"), "{thanks}");
    let signups = std::fs::read_to_string(state.join("signups")).expect("the sign-up file");
    assert!(signups.starts_with("someone@example.org ") && signups.lines().count() == 1, "{signups}");

    // THE POST: D-7 and the status URL, then the live reply there.
    let record = record(ALG_MLDSA65_ED25519, MLDSA65_ED25519_KEY_LEN);
    let body = format!("name=alice&record={}%0D%0A&invite={code}", form_encode(record.as_bytes()));
    let (status, made) = service.request("POST", "/claim", &body);
    assert_eq!(status, 200, "{made}");
    assert!(made.contains("Your board is being made. Keep this page open: it shows your board when it is live."), "{made}");
    let at = made.find("https://skep.host/status/").expect("the status URL");
    let token: String = made[at + "https://skep.host/status/".len()..].chars().take_while(char::is_ascii_hexdigit).collect();
    assert_eq!(token.len(), 32);
    let live = until("the live reply", || {
        let (status, page) = service.request("GET", &format!("/status/{token}"), "");
        assert_eq!(status, 200);
        assert!(!page.contains("could not be made"), "D-8: {}", service.log());
        page.contains("Your board is live.").then_some(page)
    });
    assert!(live.contains("skep verify --board https://alice.skep.host --principal 1 --payload"), "{live}");
    assert!(live.contains("origin https://alice.skep.host") && !live.contains("127.0.0.1"), "{live}");
    assert!(dir.path().join("boards/alice.caddy").exists(), "the snippet");
    let mailed = until("the one mail", || std::fs::read_to_string(&mail).ok().filter(|m| m.contains("To: ")));
    assert_eq!(mailed.matches("=== skep-provision mail-fake: one message ===").count(), 1);
    assert!(mailed.contains("To: person@example.com\nFrom: noreply@skep.host\nReply-To: owner@skep.host\nSubject: Your board is live\n"), "{mailed}");

    // The refusals, each on the form at 200: a second post on the name (D-4,
    // off the snippet, no docker call); a bad record (D-5); a preview
    // record (D-6); an unknown code (the DRAFT row).
    let second = minted(&state);
    let (status, page) = service.request("POST", "/claim", &format!("name=alice&record={}&invite={second}", form_encode(record.as_bytes())));
    assert_eq!(status, 200);
    assert!(page.contains("That name is taken, or is not one label of letters, digits and hyphens. Choose another."), "{page}");
    let (_, page) = service.request("POST", "/claim", &format!("name=bob&record=%7B%22type%22%3A%22skep-enroll%22%7D&invite={second}"));
    assert!(page.contains("This is not a record skep keygen printed. Paste the whole line, exactly as printed."), "{page}");
    let preview = record_preview();
    let (_, page) = service.request("POST", "/claim", &format!("name=bob&record={}&invite={second}", form_encode(preview.as_bytes())));
    assert!(page.contains("This record names a preview key."), "{page}");
    let (_, page) = service.request("POST", "/claim", &format!("name=bob&record={}&invite=0123456789abcdef0123456789abcdef", form_encode(record.as_bytes())));
    assert!(page.contains("That invite code is not one this service issued, or it has been used."), "{page}");

    // A status token never minted is 404; a body past the cap 413, refused
    // at its head.
    assert_eq!(service.request("GET", "/status/0123456789abcdef0123456789abcdef", "").0, 404);
    let mut stream = TcpStream::connect(("127.0.0.1", service.port)).expect("connected");
    stream.write_all(format!("POST /claim HTTP/1.1\r\nHost: skep.host\r\nContent-Length: {}\r\n\r\n", MAX_BODY + 1).as_bytes()).expect("the head");
    assert_eq!(read_answer(stream).0, 413);

    // THE STOP: SIGTERM ends the process; the port then answers nothing.
    let port = service.port;
    let log = service.log();
    let status = service.terminate();
    assert_eq!(status.signal(), Some(15), "ended by SIGTERM: {status:?}");
    assert!(TcpStream::connect(("127.0.0.1", port)).is_err(), "the port still answers");

    // The calls were the script's, in order, none unexpected.
    let calls = std::fs::read_to_string(dir.path().join("docker.script.calls")).expect("the calls");
    let methods: Vec<&str> = calls.lines().map(|l| l.split('\t').next().unwrap_or("")).collect();
    assert_eq!(
        methods,
        ["volumes", "volume_inspect", "container_inspect", "volume_inspect", "container_inspect", "volume_create", "run_claim", "sidecar_claim", "rm_force", "run_serving", "health", "caddy_reload"],
        "{calls}"
    );
    assert!(!calls.contains("unexpected"), "{calls}");

    // The log names the board and its steps, and never a code, a token, an
    // address or the record.
    assert!(log.contains("skep-provision: alice: LIVE at https://alice.skep.host"), "{log}");
    for never in [code.as_str(), second.as_str(), token.as_str(), "person@example.com", "someone@example.org", "9f9f9f9f", "skep-enroll"] {
        assert!(!log.contains(never), "the log carries {never:?}: {log}");
    }
}

/// A record of the preview kind.
fn record_preview() -> String {
    record(ALG_FNDSA512_PREVIEW_ED25519, FNDSA512_PREVIEW_ED25519_KEY_LEN)
}

/// T22: THE SWEEP AT START — the built binary, over a script whose
/// `volumes` lists `bob` (no snippet) and `alice` (its snippet standing),
/// removes `bob` BEFORE its serving line: by the time the line is read the
/// script's `rm_force bob` and `volume_rm bob` are consumed and recorded,
/// nothing is called for `alice`, and the line carries `swept 1` beside
/// `live 1`; then the service serves — the sign-up page answers — and the
/// log names the name and the steps.
#[test]
fn the_built_service_sweeps_a_half_made_board_before_its_serving_line() {
    let dir = Scratch::new();
    let boards = dir.path().join("boards");
    std::fs::create_dir(&boards).expect("the boards directory");
    std::fs::write(boards.join("alice.caddy"), b"").expect("alice's snippet");
    let script = dir.path().join("docker.script");
    std::fs::write(&script, [step("volumes", "-", 0, "alice\\nbob\\n"), step("rm_force", "bob", 1, ""), step("volume_rm", "bob", 0, "")].concat()).expect("the script");
    let mail = dir.path().join("mail.log");
    let service = Service::start(dir.path(), &script, &mail);
    let calls = std::fs::read_to_string(dir.path().join("docker.script.calls")).expect("the calls");
    assert_eq!(calls, "volumes\t-\t0\nrm_force\tbob\t1\nvolume_rm\tbob\t0\n", "the sweep's calls, all made before the serving line");
    assert!(service.serving.contains(" live 1 swept 1 "), "{}", service.serving);
    assert_eq!(service.request("GET", "/", "").0, 200, "the service serves after the sweep");
    let log = until("the sweep's log", || Some(service.log()).filter(|l| l.contains("bob: sweep: done")));
    for line in ["skep-provision: bob: half-made at start (a volume, no snippet) — removing", "skep-provision: bob: sweep: rm_force: exit 1", "skep-provision: bob: sweep: volume_rm: exit 0"] {
        assert!(log.contains(line), "{line}: {log}");
    }
    assert!(!log.contains("alice"), "nothing for the routed name: {log}");
    assert!(!calls.contains("unexpected"), "{calls}");
    service.terminate();
}

/// `--version`: the one line in `skepd`'s form, exit 0.
#[test]
fn the_version_line_is_skepds_form_at_exit_0() {
    let out = Command::new(BIN).arg("--version").output().expect("ran");
    assert_eq!(out.status.code(), Some(0));
    let line = String::from_utf8(out.stdout).expect("text");
    assert!(line.starts_with(&format!("skep-provision {} (", env!("CARGO_PKG_VERSION"))) && line.ends_with(")\n"), "{line}");
}

/// A usage refusal is exit 2 with the usage text: `--mailer` without
/// `--from`, an unknown flag, `--workers 0` (T21), a missing required flag.
#[test]
fn a_usage_refusal_is_exit_2() {
    for args in [
        &["serve", "--state-dir", "/nonexistent", "--reply-to", "o@x", "--mailer", "/usr/sbin/sendmail"][..],
        &["serve", "--state-dir", "/nonexistent", "--reply-to", "o@x", "--bogus"],
        &["serve", "--state-dir", "/nonexistent", "--reply-to", "o@x", "--workers", "0"],
        &["serve", "--reply-to", "o@x"],
        &["invite", "--state-dir", "/nonexistent"],
        &[],
    ] {
        let out = Command::new(BIN).args(args).stdin(Stdio::null()).output().expect("ran");
        assert_eq!(out.status.code(), Some(2), "{args:?}");
        assert!(String::from_utf8_lossy(&out.stderr).contains("usage: skep-provision serve"), "{args:?}");
    }
}

/// A state directory other users can read is refused at start, exit 1, in
/// the daemon's words, nothing created in it.
#[test]
fn a_loose_state_directory_is_refused_at_start() {
    use std::os::unix::fs::PermissionsExt;
    let dir = Scratch::new();
    let state = dir.path().join("state");
    std::fs::create_dir(&state).expect("a directory");
    std::fs::set_permissions(&state, std::fs::Permissions::from_mode(0o755)).expect("loosened");
    let out = Command::new(BIN).args(["invite", "--address", "person@example.com", "--state-dir"]).arg(&state).output().expect("ran");
    assert_eq!(out.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&out.stderr).contains("is mode 755: other users of this machine can read the sign-up addresses and the invite codes; chmod 700"));
    assert_eq!(std::fs::read_dir(&state).expect("listed").count(), 0);
}

/// A START REFUSED, OR AN INVITE NOT MINTED, IS EXIT 1, the reason on
/// stderr and no DATA line on stdout: a snippet directory that cannot be
/// read — refused before any docker call; an address another listener
/// holds — the sweep made, no serving line; a code the invite file already
/// holds — no invite link.
#[test]
fn a_start_refused_or_an_invite_not_minted_is_exit_1() {
    let dir = Scratch::new();
    let script = dir.path().join("docker.script");
    std::fs::write(&script, step("volumes", "-", 0, "")).expect("the script");
    let calls = || std::fs::read_to_string(dir.path().join("docker.script.calls")).expect("the calls");
    let serve = |boards: &Path, listen: &str| {
        Command::new(BIN)
            .args(["serve", "--listen", listen, "--reply-to", "owner@skep.host", "--state-dir"])
            .arg(dir.path().join("state"))
            .arg("--boards-dir")
            .arg(boards)
            .arg("--docker-fake")
            .arg(&script)
            .stdin(Stdio::null())
            .output()
            .expect("ran")
    };
    let absent = serve(&dir.path().join("absent"), "127.0.0.1:0");
    assert_eq!(absent.status.code(), Some(1), "{absent:?}");
    assert!(String::from_utf8_lossy(&absent.stderr).contains("could not be read"), "{absent:?}");
    assert!(absent.stdout.is_empty(), "a serving line for a start refused");
    assert_eq!(calls(), "", "a docker call before the snippets were read");
    std::fs::create_dir(dir.path().join("boards")).expect("the boards directory");
    let held = std::net::TcpListener::bind("127.0.0.1:0").expect("a port");
    let bound = serve(&dir.path().join("boards"), &held.local_addr().expect("its address").to_string());
    assert_eq!(bound.status.code(), Some(1), "{bound:?}");
    assert!(String::from_utf8_lossy(&bound.stderr).contains("skep-provision: bind 127.0.0.1:"), "{bound:?}");
    assert!(bound.stdout.is_empty(), "a serving line for an address never bound");
    assert_eq!(calls(), "volumes\t-\t0\n", "the sweep made before the bind");
    let mint = || Command::new(BIN).args(["invite", "--address", "person@example.com", "--code", "abc", "--state-dir"]).arg(dir.path().join("state")).stdin(Stdio::null()).output().expect("ran");
    assert_eq!(mint().status.code(), Some(0));
    let again = mint();
    assert_eq!(again.status.code(), Some(1), "{again:?}");
    assert!(String::from_utf8_lossy(&again.stderr).contains("the invite file already holds that code"), "{again:?}");
    assert!(again.stdout.is_empty(), "an invite link for a code not minted");
}
