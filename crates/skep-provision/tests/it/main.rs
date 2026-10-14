//! T14 — THE BUILT BINARY, driven as a browser and the owner would drive it,
//! over the two fakes its `test-hooks` build takes (this crate's self
//! dev-dependency turns the feature on for the suite, no flag added): the
//! `invite` verb mints a code; `serve` runs on an ephemeral loopback port
//! with `--docker-fake` and `--mailer-fake` over a temp state directory,
//! under its unit's umask; the sign-up page, the claim form with the link's
//! code, a sign-up, a post through to the live reply at its status URL, the
//! snippet `0644` whatever that umask, the one mail; a second post on the
//! name, a bad record, a preview record, an unknown code, a status token
//! never minted, a body past the cap — each answered as the pages say; and
//! THE STOP: SIGTERM, the default disposition, ending the process. THE
//! CONNECTIONS' POOL: a connection past it waits in the listener's queue
//! until a thread frees — and one within it is answered beside a held one.
//! THE WORKERS' POOL: the boards `--workers 2` names made at once, and no
//! more. THE SWEEP (T22): started over a script whose `labelled_volumes`
//! lists one half-made name, the binary removes it before its serving line,
//! which carries the count. THE SERVING LINE: the RUNBOOK's, field for
//! field, with mail and without. A CALL's STDIN: the sweep's listing, run by
//! the host's runner through a `docker` on `PATH`, reads nothing of the
//! service's own. A START REFUSED — a snippet directory that cannot be read,
//! an address another listener holds — and an invite not minted each exit 1,
//! with no DATA line. THE STATE FILES: the `invite` verb under a shell's
//! `022` leaves every file in the state directory `0600`, its lock file
//! among them. No Docker runs: every call is a script's, and the calls are
//! read back after. Beside it, `tidy` reads the crate's own source and
//! manifest for the arrangement `src/main.rs` and `ARCHITECTURE.md` §The
//! provisioning service state.

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

use skep_identity::{encode_enroll, Enrollment, PublicKey, ALG_FNDSA512_PREVIEW_ED25519, ALG_MLDSA65_ED25519, ED25519_KEY_LEN, FNDSA512_PREVIEW_KEY_LEN, MLDSA65_KEY_LEN};

/// The binary under test, built with `test-hooks`.
const BIN: &str = env!("CARGO_BIN_EXE_skep-provision");

/// The umask the service's unit runs it under: `UMask=0077`
/// (`deploy/skep-provision.service`). `Service::start` starts a service
/// under it, as the unit runs the service on the VM.
const UNIT_UMASK: &str = "077";

/// The built binary as a shell runs it under `umask`: the umask set, then
/// the binary `exec`'d in the shell's place — the pid the stop signals, the
/// streams and the exit all the binary's own; the command's arguments
/// follow.
fn under_umask(umask: &str) -> Command {
    let mut command = Command::new("/bin/sh");
    command.args(["-c", "umask \"$1\" && shift && exec \"$0\" \"$@\"", BIN, umask]);
    command
}

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

/// A record as a person's device prints it: one key of `alg`, its
/// post-quantum half `pq_len` bytes of `9f` beside the Ed25519 base point's
/// encoding (RFC 8032: `58`, then thirty-one `66`) — a point by
/// construction, so the halves decode as the hosted genesis asks.
fn record(alg: &str, pq_len: usize) -> String {
    let mut ed25519 = [0x66; ED25519_KEY_LEN];
    ed25519[0] = 0x58;
    let key = PublicKey::from_halves(alg, &vec![0x9f; pq_len], &ed25519).expect("the row's widths");
    encode_enroll(&[Enrollment::new(key, true, None).expect("no label")])
}

/// Bytes as a browser's form sends them: every byte but the unreserved
/// percent-encoded.
fn form_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|&b| if b.is_ascii_alphanumeric() || b"-._~".contains(&b) { (b as char).to_string() } else { format!("%{b:02X}") }).collect()
}

/// One script line for the docker fake: TAB-separated, `\n` escaped by the
/// caller.
fn script_line(method: &str, name: &str, exit_code: i32, stdout: &str) -> String {
    format!("{method}\t{name}\t{exit_code}\t{stdout}\n")
}

/// `skep-provision invite`: its exit code, its stdout, its stderr.
fn invite(state_dir: &Path) -> (i32, String, String) {
    let out = Command::new(BIN).args(["invite", "--address", "person@example.com", "--state-dir"]).arg(state_dir).stdin(Stdio::null()).output().expect("the invite verb ran");
    (out.status.code().unwrap_or(-1), String::from_utf8_lossy(&out.stdout).into_owned(), String::from_utf8_lossy(&out.stderr).into_owned())
}

/// A code off the invite verb's one DATA line.
fn minted(state_dir: &Path) -> String {
    let (exit_code, out, err) = invite(state_dir);
    assert_eq!(exit_code, 0, "{err}");
    let line = out.trim_end();
    assert_eq!(out.lines().count(), 1, "one DATA line: {out}");
    line.strip_prefix("https://skep.host/claim?invite=").unwrap_or_else(|| panic!("the invite link: {line}")).to_owned()
}

/// THE SERVICE RUNNING: the child, its port off the serving line, the line
/// itself, its log — under its unit's umask, over the two fakes and with its
/// mail on, where `Service::start` starts it.
struct Service {
    child: Child,
    port: u16,
    serving: String,
    log: Arc<Mutex<String>>,
}

impl Service {
    fn start(dir: &Path, script: &Path, mail_log: &Path, extra: &[&str]) -> Service {
        let child = under_umask(UNIT_UMASK)
            .args(["serve", "--listen", "127.0.0.1:0", "--state-dir"])
            .arg(dir.join("state"))
            .arg("--boards-dir")
            .arg(dir.join("boards"))
            .args(["--reply-to", "owner@skep.host", "--from", "noreply@skep.host", "--docker-fake"])
            .arg(script)
            .arg("--mailer-fake")
            .arg(mail_log)
            .args(extra)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("serve started");
        let service = Service::running(child);
        assert!(service.serving.contains("mail on"), "{}", service.serving);
        service
    }

    /// THE SERVICE RUNNING as `child`, spawned with its stdout and its
    /// stderr piped: its stderr kept as its log, its serving line read and
    /// its port off it — the child killed when this is dropped.
    fn running(mut child: Child) -> Service {
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
        let from_port = serving.strip_prefix("skep-provision: serving http://127.0.0.1:").unwrap_or_else(|| panic!("the serving line: {serving:?}; the log: {}", log.lock().unwrap()));
        let port = from_port[..from_port.find('/').expect("the address's end")].parse().expect("a port");
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

/// T14: THE SERVICE, FROM THE FORM's POST TO THE LIVE PAGE, over the fakes
/// and under its unit's umask — the snippet it writes `0644`, that umask
/// notwithstanding — and every refusal a post can meet, a status token never
/// minted, a body past the cap, and the stop.
#[test]
fn the_built_service_runs_a_post_from_the_form_to_the_live_page_over_the_fakes() {
    use std::os::unix::fs::PermissionsExt;
    let dir = Scratch::new();
    std::fs::create_dir(dir.path().join("boards")).expect("the snippet directory");
    let state_dir = dir.path().join("state");
    let code = minted(&state_dir);
    assert_eq!(code.len(), 32);
    let script = dir.path().join("docker.script");
    let lines = [
        script_line("labelled_volumes", "-", 0, ""),
        script_line("volume_inspect", "alice", 1, ""),
        script_line("container_inspect", "alice", 1, ""),
        script_line("volume_inspect", "alice", 1, ""),
        script_line("container_inspect", "alice", 1, ""),
        script_line("volume_create", "alice", 0, "alice\\n"),
        script_line("run_claim", "alice", 0, ""),
        script_line("sidecar_claim", "alice", 0, SIX),
        script_line("rm_force", "alice", 0, ""),
        script_line("run_serving", "alice", 0, ""),
        script_line("health", "alice", 0, PAIRED),
        script_line("caddy_reload", "-", 0, ""),
    ];
    std::fs::write(&script, lines.concat()).expect("the script");
    let mail_log = dir.path().join("mail.log");
    let service = Service::start(dir.path(), &script, &mail_log, &[]);

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
    let signups = std::fs::read_to_string(state_dir.join("signups")).expect("the sign-up file");
    assert!(signups.starts_with("someone@example.org ") && signups.lines().count() == 1, "{signups}");

    // THE POST: D-7 and the status URL, then the live reply there.
    let record = record(ALG_MLDSA65_ED25519, MLDSA65_KEY_LEN);
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
    let snippet = std::fs::metadata(dir.path().join("boards/alice.caddy")).expect("the snippet");
    assert_eq!(snippet.permissions().mode() & 0o777, 0o644, "the snippet readable by the proxy's container, the unit's umask notwithstanding");
    let mailed = until("the one mail", || std::fs::read_to_string(&mail_log).ok().filter(|m| m.contains("To: ")));
    assert_eq!(mailed.matches("=== skep-provision mail-fake: one message ===").count(), 1);
    assert!(mailed.contains("To: person@example.com\nFrom: noreply@skep.host\nReply-To: owner@skep.host\nSubject: Your board is live\n"), "{mailed}");

    // The refusals, each on the form at 200: a second post on the name (D-4,
    // off the snippet, no docker call); a bad record (D-5); a preview
    // record (D-6); an unknown code (the DRAFT row).
    let second = minted(&state_dir);
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
    let stopped = service.terminate();
    assert_eq!(stopped.signal(), Some(15), "ended by SIGTERM: {stopped:?}");
    assert!(TcpStream::connect(("127.0.0.1", port)).is_err(), "the port still answers");

    // The calls were the script's, in order, none unexpected.
    let calls = std::fs::read_to_string(dir.path().join("docker.script.calls")).expect("the calls");
    let methods: Vec<&str> = calls.lines().map(|l| l.split('\t').next().unwrap_or("")).collect();
    assert_eq!(
        methods,
        [
            "labelled_volumes",
            "volume_inspect",
            "container_inspect",
            "volume_inspect",
            "container_inspect",
            "volume_create",
            "run_claim",
            "sidecar_claim",
            "rm_force",
            "run_serving",
            "health",
            "caddy_reload"
        ],
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
    record(ALG_FNDSA512_PREVIEW_ED25519, FNDSA512_PREVIEW_KEY_LEN)
}

/// T22: THE SWEEP AT START — the built binary, over a script whose
/// `labelled_volumes` lists `bob` (no snippet) and `alice` (its snippet
/// standing), removes `bob` BEFORE its serving line: by the time the line
/// is read the script's `rm_force bob`, `volume_rm bob` and the look at
/// what stands under `bob` after them are consumed and recorded, nothing is
/// called for `alice`, and the line carries `swept 1` beside `live 1`; then
/// the service serves — the sign-up page answers — and the log names the
/// name and the steps.
#[test]
fn the_built_service_sweeps_a_half_made_board_before_its_serving_line() {
    let dir = Scratch::new();
    let boards = dir.path().join("boards");
    std::fs::create_dir(&boards).expect("the snippet directory");
    std::fs::write(boards.join("alice.caddy"), b"").expect("alice's snippet");
    let script = dir.path().join("docker.script");
    let lines = [
        script_line("labelled_volumes", "-", 0, "alice\\nbob\\n"),
        script_line("rm_force", "bob", 1, ""),
        script_line("volume_rm", "bob", 0, ""),
        script_line("volume_inspect", "bob", 1, ""),
        script_line("container_inspect", "bob", 1, ""),
    ];
    std::fs::write(&script, lines.concat()).expect("the script");
    let mail_log = dir.path().join("mail.log");
    let service = Service::start(dir.path(), &script, &mail_log, &[]);
    let calls = std::fs::read_to_string(dir.path().join("docker.script.calls")).expect("the calls");
    assert_eq!(calls, "labelled_volumes\t-\t0\nrm_force\tbob\t1\nvolume_rm\tbob\t0\nvolume_inspect\tbob\t1\ncontainer_inspect\tbob\t1\n", "the sweep's calls, all made before the serving line");
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

/// THE CONNECTIONS' POOL: under `--connections 1` a connection that sends
/// nothing holds the one connection thread, and a second request waits in
/// the listener's queue, unanswered and with no thread made for it, until
/// the first closes; then it is answered — and the serving line names the
/// pool.
#[test]
fn a_connection_past_the_pool_waits_until_a_thread_frees() {
    let dir = Scratch::new();
    std::fs::create_dir(dir.path().join("boards")).expect("the snippet directory");
    let script = dir.path().join("docker.script");
    std::fs::write(&script, script_line("labelled_volumes", "-", 0, "")).expect("the script");
    let service = Service::start(dir.path(), &script, &dir.path().join("mail.log"), &["--connections", "1"]);
    assert!(service.serving.contains(" workers 3 connections 1 "), "{}", service.serving);
    let held = TcpStream::connect(("127.0.0.1", service.port)).expect("connected");
    let mut second = TcpStream::connect(("127.0.0.1", service.port)).expect("connected");
    second.write_all(b"GET / HTTP/1.1\r\nHost: skep.host\r\n\r\n").expect("the request");
    second.set_read_timeout(Some(Duration::from_secs(2))).expect("a deadline");
    let waited = second.read(&mut [0u8; 1]);
    assert!(matches!(&waited, Err(e) if matches!(e.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut)), "answered beside a held connection: {waited:?}");
    drop(held);
    second.set_read_timeout(Some(Duration::from_secs(30))).expect("a deadline");
    assert_eq!(read_answer(second).0, 200);
    service.terminate();
}

/// THE CONNECTIONS ARE THE FLAG's, NO FEWER: under `--connections 2` a
/// connection that sends nothing holds one thread, and a request beside it
/// is answered at once by the other — the test above shows `serve` makes no
/// more connection threads than the flag names, this one no fewer.
#[test]
fn a_request_beside_a_held_connection_is_answered_within_the_pool() {
    let dir = Scratch::new();
    std::fs::create_dir(dir.path().join("boards")).expect("the snippet directory");
    let script = dir.path().join("docker.script");
    std::fs::write(&script, script_line("labelled_volumes", "-", 0, "")).expect("the script");
    let service = Service::start(dir.path(), &script, &dir.path().join("mail.log"), &["--connections", "2"]);
    let held = TcpStream::connect(("127.0.0.1", service.port)).expect("connected");
    let mut beside = TcpStream::connect(("127.0.0.1", service.port)).expect("connected");
    beside.write_all(b"GET / HTTP/1.1\r\nHost: skep.host\r\n\r\n").expect("the request");
    beside.set_read_timeout(Some(Duration::from_secs(10))).expect("ten seconds, far inside the held connection's thirty");
    let mut raw = Vec::new();
    let read = beside.read_to_end(&mut raw);
    assert!(read.is_ok() && raw.starts_with(b"HTTP/1.1 200 OK\r\n"), "no second thread answered beside the held connection: {read:?} {}", String::from_utf8_lossy(&raw));
    drop(held);
    service.terminate();
}

/// THE WORKERS ARE THE FLAG's, NO FEWER AND NO MORE: under `--workers 2`,
/// alice's and bob's dark claims each answering exit 4 once — the dark
/// claim's own two-second pause, its daemon not yet listening — and carol
/// posted behind them, bob's claim run comes before alice's serving run,
/// made by the second worker while she waits, and carol's only after a
/// serving run, once a worker frees: `serve` makes the pool the flag names,
/// which no unit suite, spawning workers of its own, can see.
#[test]
fn serve_makes_the_workers_the_flag_names() {
    let dir = Scratch::new();
    std::fs::create_dir(dir.path().join("boards")).expect("the snippet directory");
    let state_dir = dir.path().join("state");
    let names = ["alice", "bob", "carol"];
    let codes: Vec<String> = names.iter().map(|_| minted(&state_dir)).collect();
    let flow = |name: &str| {
        let mut lines = vec![
            script_line("volume_inspect", name, 1, ""),
            script_line("container_inspect", name, 1, ""),
            script_line("volume_inspect", name, 1, ""),
            script_line("container_inspect", name, 1, ""),
            script_line("volume_create", name, 0, ""),
            script_line("run_claim", name, 0, ""),
        ];
        if name != "carol" {
            lines.push(script_line("sidecar_claim", name, 4, ""));
        }
        lines.extend([script_line("sidecar_claim", name, 0, SIX), script_line("rm_force", name, 0, ""), script_line("run_serving", name, 0, ""), script_line("health", name, 0, PAIRED)]);
        lines.concat()
    };
    let script = dir.path().join("docker.script");
    std::fs::write(&script, script_line("labelled_volumes", "-", 0, "") + &names.map(flow).concat() + &script_line("caddy_reload", "-", 0, "").repeat(names.len())).expect("the script");
    let service = Service::start(dir.path(), &script, &dir.path().join("mail.log"), &["--workers", "2"]);
    assert!(service.serving.contains(" workers 2 "), "{}", service.serving);
    let record = record(ALG_MLDSA65_ED25519, MLDSA65_KEY_LEN);
    let tokens: Vec<String> = names
        .iter()
        .zip(&codes)
        .map(|(name, code)| {
            let (status, made) = service.request("POST", "/claim", &format!("name={name}&record={}&invite={code}", form_encode(record.as_bytes())));
            assert_eq!(status, 200, "{name}: {made}");
            let at = made.find("https://skep.host/status/").unwrap_or_else(|| panic!("{name} admitted: {made}")) + "https://skep.host/status/".len();
            made[at..].chars().take_while(char::is_ascii_hexdigit).collect()
        })
        .collect();
    for token in &tokens {
        until("all three live", || {
            let (_, page) = service.request("GET", &format!("/status/{token}"), "");
            assert!(!page.contains("could not be made"), "D-8: {}", service.log());
            page.contains("Your board is live.").then_some(())
        });
    }
    let calls = std::fs::read_to_string(dir.path().join("docker.script.calls")).expect("the calls");
    let at = |call: &str| calls.lines().position(|l| l.starts_with(call)).unwrap_or_else(|| panic!("{call}: {calls}"));
    assert!(at("run_claim\tbob\t") < at("run_serving\talice\t"), "two workers, yet bob waited for alice: {calls}");
    assert!(at("run_claim\tcarol\t") > at("run_serving\talice\t").min(at("run_serving\tbob\t")), "two workers, yet carol ran beside alice and bob: {calls}");
    assert!(!calls.contains("unexpected"), "{calls}");
    service.terminate();
}

/// A CALL's STDIN IS NEVER THE SERVICE's OWN: the built binary over the
/// host's runner — no `--docker-fake` — its `docker` a script first on
/// `PATH` that keeps whatever reaches its stdin, and its own stdin a pipe
/// holding a line and then closed: the sweep's listing, a call with no
/// input, runs that `docker`, which reads nothing — a null stdin — where
/// one handed the service's own would read the line. Its own stdin is the
/// test's to set here, as no unit suite's is: the runner gives every test
/// process a null one, which a child inheriting it cannot tell from null.
#[test]
fn a_call_with_no_input_never_reads_the_services_own_stdin() {
    use std::os::unix::fs::PermissionsExt;
    let dir = Scratch::new();
    std::fs::create_dir(dir.path().join("boards")).expect("the snippet directory");
    let bin = dir.path().join("bin");
    std::fs::create_dir(&bin).expect("a directory for the program");
    std::fs::write(bin.join("docker"), format!("#!/bin/sh\nprintf '%s\\n' \"$*\" >> '{0}/argv'\ncat >> '{0}/stdin'\n", dir.path().display())).expect("the script");
    std::fs::set_permissions(bin.join("docker"), std::fs::Permissions::from_mode(0o700)).expect("executable");
    let path = format!("{}:{}", bin.display(), std::env::var("PATH").unwrap_or_default());
    let mut child = Command::new(BIN)
        .args(["serve", "--listen", "127.0.0.1:0", "--reply-to", "owner@skep.host", "--state-dir"])
        .arg(dir.path().join("state"))
        .arg("--boards-dir")
        .arg(dir.path().join("boards"))
        .env("PATH", path)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("serve started");
    let mut own_stdin = child.stdin.take().expect("its own stdin");
    own_stdin.write_all(b"the service's own stdin\n").expect("a line on it");
    drop(own_stdin);
    let service = Service::running(child);
    assert_eq!(std::fs::read_to_string(dir.path().join("argv")).expect("docker ran"), "volume ls -q --filter label=skep.provision=1\n", "the sweep's listing, by the host's runner");
    assert_eq!(std::fs::read_to_string(dir.path().join("stdin")).expect("its stdin kept"), "", "docker read the service's own stdin");
    service.terminate();
}

/// THE SERVING LINE IS THE RUNBOOK's: the line RUNBOOK §10 step 6 quotes,
/// read back at test time, field for field — its address and its two
/// directories this run's — with `--mailer` and `--from` given; and without
/// them it ends as that step says: `mail OFF (no --mailer and --from): no
/// follow-up mail is sent`.
#[test]
fn the_serving_line_is_the_runbooks_with_mail_and_without() {
    let runbook = std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("../../RUNBOOK.md")).expect("the RUNBOOK");
    let quoted = runbook.lines().map(str::trim).find(|l| l.starts_with("skep-provision: serving http://")).expect("the RUNBOOK's serving line").to_owned();
    for mailing in [true, false] {
        let dir = Scratch::new();
        std::fs::create_dir(dir.path().join("boards")).expect("the snippet directory");
        let script = dir.path().join("docker.script");
        std::fs::write(&script, script_line("labelled_volumes", "-", 0, "")).expect("the script");
        let mut command = Command::new(BIN);
        command
            .args(["serve", "--listen", "127.0.0.1:0", "--reply-to", "owner@skep.host", "--state-dir"])
            .arg(dir.path().join("state"))
            .arg("--boards-dir")
            .arg(dir.path().join("boards"))
            .arg("--docker-fake")
            .arg(&script);
        if mailing {
            command.args(["--from", "noreply@skep.host", "--mailer-fake"]).arg(dir.path().join("mail.log"));
        }
        let service = Service::running(command.stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().expect("serve started"));
        let ours = quoted
            .replace("0.0.0.0:8842", &format!("127.0.0.1:{}", service.port))
            .replace("/var/lib/skep-provision", &dir.path().join("state").display().to_string())
            .replace("/etc/caddy/boards", &dir.path().join("boards").display().to_string());
        let want = if mailing { ours } else { ours.replace(" mail on", " mail OFF (no --mailer and --from): no follow-up mail is sent") };
        assert_eq!(service.serving.trim_end(), want, "mailing {mailing}");
        service.terminate();
    }
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
    let state_dir = dir.path().join("state");
    std::fs::create_dir(&state_dir).expect("a directory");
    std::fs::set_permissions(&state_dir, std::fs::Permissions::from_mode(0o755)).expect("loosened");
    let out = Command::new(BIN).args(["invite", "--address", "person@example.com", "--state-dir"]).arg(&state_dir).output().expect("ran");
    assert_eq!(out.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&out.stderr).contains("is mode 755: other users of this machine can read the sign-up addresses and the invite codes; chmod 700"));
    assert_eq!(std::fs::read_dir(&state_dir).expect("listed").count(), 0);
}

/// EVERY FILE IN THE STATE DIRECTORY IS BORN `0600`, the lock file among
/// them, whatever the umask that makes it: the owner's `invite`, run as
/// RUNBOOK §10 step 7 runs it — `sudo -u`, under a shell's usual `022` —
/// makes the directory `0700` and the invite file and `invites.lock` beside
/// it each `0600`: nothing there another user of the machine can read.
#[test]
fn the_invite_verb_makes_every_state_file_0600_under_a_shells_umask() {
    use std::os::unix::fs::PermissionsExt;
    let dir = Scratch::new();
    let state_dir = dir.path().join("state");
    let out = under_umask("022").args(["invite", "--address", "person@example.com", "--state-dir"]).arg(&state_dir).stdin(Stdio::null()).output().expect("ran");
    assert_eq!(out.status.code(), Some(0), "{out:?}");
    let mode = |path: &Path| std::fs::metadata(path).expect("its mode").permissions().mode() & 0o777;
    assert_eq!(mode(&state_dir), 0o700);
    let mut born: Vec<(String, u32)> = std::fs::read_dir(&state_dir)
        .expect("listed")
        .map(|entry| {
            let entry = entry.expect("an entry");
            (entry.file_name().to_string_lossy().into_owned(), mode(&entry.path()))
        })
        .collect();
    born.sort();
    assert_eq!(born, [("invites".to_owned(), 0o600), ("invites.lock".to_owned(), 0o600)]);
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
    std::fs::write(&script, script_line("labelled_volumes", "-", 0, "")).expect("the script");
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
    std::fs::create_dir(dir.path().join("boards")).expect("the snippet directory");
    let held = std::net::TcpListener::bind("127.0.0.1:0").expect("a port");
    let bound = serve(&dir.path().join("boards"), &held.local_addr().expect("its address").to_string());
    assert_eq!(bound.status.code(), Some(1), "{bound:?}");
    assert!(String::from_utf8_lossy(&bound.stderr).contains("skep-provision: bind 127.0.0.1:"), "{bound:?}");
    assert!(bound.stdout.is_empty(), "a serving line for an address never bound");
    assert_eq!(calls(), "labelled_volumes\t-\t0\n", "the sweep made before the bind");
    let mint = || Command::new(BIN).args(["invite", "--address", "person@example.com", "--code", "abc", "--state-dir"]).arg(dir.path().join("state")).stdin(Stdio::null()).output().expect("ran");
    assert_eq!(mint().status.code(), Some(0));
    let again = mint();
    assert_eq!(again.status.code(), Some(1), "{again:?}");
    assert!(String::from_utf8_lossy(&again.stderr).contains("the invite file already holds that code"), "{again:?}");
    assert!(again.stdout.is_empty(), "an invite link for a code not minted");
}
