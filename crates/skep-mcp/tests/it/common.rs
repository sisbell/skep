//! The board the suites talk to, and the adapter under test.
//!
//! The fixture ([`Fixture`]): a temp data dir, an in-process daemon over it
//! at an ephemeral port — restarted at that port where a suite needs the
//! restart arm — and its board claimed through the library over a
//! `FileStore` with a scripted person, so the claimant's key and its binding
//! sit in the store the adapter signs from (principal 1 at `1.0.1`, its
//! agent space `1.0.1.1` delegated beside it); the library's walks for the
//! acts a person makes beside a running adapter — a second key enrolled, a
//! key retired; the blob seeding, copied from skepd's own suite: the
//! resumable upload's creation, the cell and its insert; the holds of
//! skepd's two process-wide seams, the write guard and the fetch stream,
//! armed only on a board run alone ([`Fixture::alone`]); and the poison of
//! the board's own kernel at its next commit. The driver
//! ([`Mcp`], from a [`Launch`]): the built `skep-mcp` binary spawned with its
//! settings — the fixture's, or any a test names — and real JSON-RPC driven
//! through its stdin/stdout, its stderr read where a test wants the lines.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Command, ExitStatus, Output, Stdio};
use std::sync::{Arc, Mutex, PoisonError, RwLock, RwLockReadGuard, RwLockWriteGuard};
use std::time::{Duration, Instant};

use serde_json::{json, Value};
use skep_client::board::{Answer, Board, Opened, SessionBody};
use skep_client::ceremony::claim::{self, ClaimOutcome, NotebookOptions};
use skep_client::ceremony::enroll::{enroll, EnrollOptions};
use skep_client::ceremony::retire::{retire, RetireOptions};
use skep_client::dial::PlainHttp;
use skep_client::person::scripted::{Script, Scripted};
use skep_client::sheet::Label;
use skep_client::store::{Binding, FileStore, KeySelector, KeyStore, Purpose};
use skep_client::{Origin, Token};
use skep_identity::{encode_enroll, Enrollment, Fingerprint};
use skepd::{embed, AuthOptions, Daemon, MediaOptions, Skepd, Step, DEFAULT_WORKERS};

// ── a self-owned temp dir (kept dependency-free) ────────────────────────

pub struct TempDir(PathBuf);

impl TempDir {
    pub fn new(tag: &str) -> TempDir {
        static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let n = SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!("skep-mcp-{tag}-{}-{n}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("create temp dir");
        TempDir(dir)
    }

    pub fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

// ── the daemon ──────────────────────────────────────────────────────────

pub fn origin(port: u16) -> String {
    format!("http://127.0.0.1:{port}")
}

/// skepd in-process over `dir` at `port` (0 for an ephemeral one), local
/// trust on and its own loopback origin configured, so a signed session
/// opens at the origin the adapter dials: the daemon's own start
/// (`skepd::embed`), then the wait for its cell index.
pub fn spawn_daemon(dir: &Path, port: u16) -> Skepd {
    spawn_signing_at(dir, port, origin)
}

/// [`spawn_daemon`], the daemon's configured signed origin `signed(port)`
/// in place of the one it is dialed at — a board moved to another name,
/// whose signed arm then refuses every session at the dialed one.
pub fn spawn_signing_at(dir: &Path, port: u16, signed: impl Fn(u16) -> String) -> Skepd {
    let configured = |port: u16| {
        let mut opts = AuthOptions::default();
        opts.local_trust = true;
        opts.configured = vec![skepd::Origin::parse(&signed(port)).expect("a canonical origin")];
        opts
    };
    let daemon = embed(dir, port, configured, MediaOptions::default(), DEFAULT_WORKERS).unwrap_or_else(|e| panic!("daemon start at {}: {e}", dir.display()));
    daemon.wait_for_the_index(Duration::from_secs(60)).unwrap_or_else(|e| panic!("{e}"));
    daemon
}

// ── the fixture ─────────────────────────────────────────────────────────

/// The claimant's account and its home, and the agent space the claim
/// delegates beside it.
pub const CLAIMANT_ACCOUNT: &str = "1.0.1";
pub const CLAIMANT_DOC1: &str = "1.0.1.0.1";
pub const AGENT_SPACE: &str = "1.0.1.1";

/// A claimed board: its daemon, its port, and the store that claimed it.
///
/// The store holds the claimant's key and its binding; the claim's anchors
/// sit beside it under `dir`.
pub struct Fixture {
    pub dir: TempDir,
    daemon: Option<Skepd>,
    port: u16,
    pub store: PathBuf,
    /// The claimant's device key's fingerprint, in hex.
    pub fingerprint: String,
    /// The fixture's hold on [`SEAMS`], released once its daemon has stopped.
    seams: SeamsHeld,
}

impl Fixture {
    /// Returns a fresh board, claimed by a fresh store, beside other tests'.
    pub fn new(tag: &str) -> Fixture {
        Fixture::open(tag, SeamsHeld::Shared { _guard: SEAMS.read().unwrap_or_else(PoisonError::into_inner) })
    }

    /// Returns a fresh board, claimed, while no other test's board runs.
    ///
    /// It is the fixture of a test that arms one of skepd's process-wide
    /// seams ([`WriteGuardHeld`], [`FetchStreamHeld`]), which park every
    /// board's work in the process.
    pub fn alone(tag: &str) -> Fixture {
        Fixture::open(tag, SeamsHeld::Alone { _guard: SEAMS.write().unwrap_or_else(PoisonError::into_inner) })
    }

    /// Returns a fresh board, claimed by a fresh store, under `seams`.
    fn open(tag: &str, seams: SeamsHeld) -> Fixture {
        let dir = TempDir::new(tag);
        let daemon = spawn_daemon(&dir.path().join("board"), 0);
        let port = daemon.port();
        let store = dir.path().join("store");
        let anchors = dir.path().join("anchors");
        let fingerprint = claim_board(&origin(port), &store, &anchors);
        Fixture { dir, daemon: Some(daemon), port, store, fingerprint, seams }
    }

    pub fn origin(&self) -> String {
        origin(self.port)
    }

    /// The library's board, dialed plainly.
    pub fn board(&self) -> Board {
        Board::new(Origin::parse(&self.origin()).expect("a canonical origin"), PlainHttp::new())
    }

    /// The board's data directory.
    pub fn board_dir(&self) -> PathBuf {
        self.dir.path().join("board")
    }

    /// The daemon stopped: the board gone until [`Fixture::restart`].
    pub fn stop(&mut self) {
        if let Some(daemon) = self.daemon.take() {
            daemon.shutdown();
        }
        let probe = self.board();
        let deadline = Instant::now() + Duration::from_secs(10);
        while probe.health().is_ok() {
            assert!(Instant::now() < deadline, "the stopped board still answers");
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    /// The daemon started again over the same board at the SAME port —
    /// the adapter's board is fixed for its life — every token it issued
    /// dead with it.
    pub fn restart(&mut self) {
        self.stop();
        self.daemon = Some(spawn_daemon(&self.board_dir(), self.port));
    }

    /// [`Fixture::restart`], the daemon now signing at another name alone
    /// (`http://localhost:<port>`), so its signed arm refuses every session
    /// at the origin the adapter dials: the origin state of a moved board.
    pub fn restart_signing_elsewhere(&mut self) {
        self.stop();
        self.daemon = Some(spawn_signing_at(&self.board_dir(), self.port, |port| format!("http://localhost:{port}")));
    }

    /// A bare session of the library's as `principal`, on the permissive
    /// board — a second session beside the adapter's, for writes the
    /// fixture makes itself.
    pub fn bare_session(&self, principal: u64) -> Token {
        match self.board().session_open(SessionBody::Bare { principal }).expect("the session open") {
            Opened::Token(token) => token,
            other => panic!("a bare session as principal {principal} on the permissive board: {other:?}"),
        }
    }

    /// One frame under `token`, answered by the board: its response document.
    pub fn op(&self, token: &Token, frame: Value) -> Value {
        match self.board().op(Some(token), &frame).expect("the op's transport") {
            Answer::Document(v) => v,
            other => panic!("{frame}: {other:?}"),
        }
    }

    /// One acknowledged write under `token`: its `addr`.
    pub fn write(&self, token: &Token, frame: Value) -> String {
        let v = self.op(token, frame.clone());
        assert!(v["resp"].as_str().is_some_and(|r| r.starts_with("ack")), "{frame}: {v}");
        v["addr"].as_str().unwrap_or_default().to_string()
    }

    /// A guest frame, answered by the board.
    pub fn guest(&self, frame: Value) -> Value {
        self.board().guest(&frame).expect("the guest read")
    }

    /// The agent space's principal — the seat `1.0.1.1` the claim delegated
    /// under the claimant's account, which holds no key of its own and opens
    /// BY REFERENCE with a key enrolled in the set above it.
    pub fn agent_principal(&self) -> u64 {
        let owner = self.guest(json!({"op": "effective_owner", "addr": AGENT_SPACE}));
        assert_eq!(owner["prefix"], AGENT_SPACE, "the agent space is a seat of its own: {owner}");
        owner["principal"].as_u64().expect("the agent space's principal")
    }

    /// A second device key enrolled into the claimant's set from the
    /// claimant's own store (the library's `enroll` walk, the comparison
    /// confirmed), the key generated into `store` and bound there — the
    /// device a person retires the adapter's key from. Its fingerprint, in
    /// hex.
    pub fn enroll_second_key(&self, store: &Path, label: &str) -> String {
        let second = FileStore::open(store);
        let id = second.generate(Some(Label::new(label).expect("a legal label"))).expect("keygen");
        let key = second.select(&KeySelector::Path(&second.key_path(&id.0)), Purpose::Read).expect("the key's facts");
        let record = Enrollment::new(key.public.clone(), false, Some(label.to_string())).expect("a legal label");
        let payload = encode_enroll(&[record]);
        let mut person = Scripted::new(vec![Script::Confirm(true)]);
        let claimant = FileStore::open(&self.store);
        enroll(&self.board(), &claimant, &mut person, &EnrollOptions { principal: 1, payload: format!("{payload}\n").into_bytes() })
            .unwrap_or_else(|h| panic!("the enrollment: {h}\n{}", person.transcript.join("\n")));
        second
            .bind(&Binding::Enrollment { origin: Origin::parse(&self.origin()).expect("a canonical origin"), principal: 1, account: CLAIMANT_ACCOUNT.into(), fingerprint: key.fingerprint })
            .expect("the binding appended");
        key.fingerprint.to_hex()
    }

    /// The key `fingerprint` (its hex, or a prefix) retired from `store`'s
    /// own bound key — another hand's retirement, through the library's
    /// `retire` walk with the preview confirmed.
    pub fn retire_from(&self, store: &Path, fingerprint: &str) {
        let mut person = Scripted::new(vec![Script::Confirm(true)]);
        retire(&self.board(), &FileStore::open(store), &mut person, &RetireOptions { principal: 1, fingerprint_prefix: fingerprint[..16].to_string() })
            .unwrap_or_else(|h| panic!("the retirement: {h}\n{}", person.transcript.join("\n")));
    }

    /// A picture seeded on the board: `bytes` uploaded under a bare session
    /// of principal 1's, its cell inserted into a fresh draft of the
    /// claimant's account under the same session (the deposit is the
    /// uploader's); the I-address the cell sits at, which `fetch`
    /// takes.
    pub fn seed_picture(&self, bytes: &[u8]) -> String {
        let token = self.bare_session(1);
        let draft = self.write(&token, json!({"op": "create_new_document", "account": CLAIMANT_ACCOUNT}));
        let (hash, size) = upload(self.port, token.as_str(), bytes);
        insert_cell(self.port, token.as_str(), &draft, &cell_of(&hash, size))
    }

    /// Returns the free permits of the board's write pool.
    ///
    /// Each is taken and handed back at once, so the count is the pool's
    /// width less the writes the board holds in flight.
    pub fn free_write_permits(&self) -> usize {
        let daemon = self.daemon.as_ref().expect("the board's daemon runs").daemon();
        let taken: Vec<_> = std::iter::from_fn(|| daemon.try_hold_write_permit()).collect();
        taken.len()
    }

    /// Poisons the board's kernel at its next commit.
    ///
    /// The commit's barrier fails, and so does the truncation that would
    /// repair it (`Daemon::fail_the_next_checkpoint_step` at `JournalBarrier`
    /// and `JournalRepair`, the dev provider's `poison` door): the write that
    /// meets it answers `poisoned`, its frames left in the journal the board's
    /// restart replays. Each arm fires once, and the kernel is the board's
    /// own, so no other test's board meets it.
    pub fn poison_the_next_commit(&self) {
        let daemon = self.daemon.as_ref().expect("the board's daemon runs").daemon();
        daemon.fail_the_next_checkpoint_step(Step::JournalBarrier, std::io::ErrorKind::Other);
        daemon.fail_the_next_checkpoint_step(Step::JournalRepair, std::io::ErrorKind::Other);
    }

    /// Returns the claimant's key's private seed, in hex, off its key file.
    pub fn key_seed_hex(&self) -> String {
        let store = FileStore::open(&self.store);
        let fingerprint = Fingerprint::parse_hex(&self.fingerprint).expect("the claimant's fingerprint");
        store.load(&store.key_path(&fingerprint)).expect("the claimant's key file").seed_hex()
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        if let Some(daemon) = self.daemon.take() {
            daemon.shutdown();
        }
    }
}

/// The suite's fence around skepd's process-wide test seams.
///
/// A test that arms one runs its board alone ([`Fixture::alone`]); every
/// other fixture holds the fence shared for its life. Under nextest — a
/// process per test, the gate's runner — it never waits; under `cargo test`
/// a hold never parks another test's board, whose adapter would answer
/// `unreachable` once its read bound ran out. No test holds two fixtures.
static SEAMS: RwLock<()> = RwLock::new(());

/// One fixture's hold on [`SEAMS`].
enum SeamsHeld {
    /// Beside every board but a seam-arming test's.
    Shared { _guard: RwLockReadGuard<'static, ()> },
    /// No other test's board beside it.
    Alone { _guard: RwLockWriteGuard<'static, ()> },
}

/// The board's write guard held: every plain write parks inside its daemon.
///
/// A write parks having taken its permit and both locks, its frame read,
/// until the drop (`Daemon::hold_the_write_guard`). The hold borrows the
/// board it is armed on, so it drops before that board: the daemon's stop
/// joins a parked worker.
#[must_use = "every plain write in the process parks until the drop"]
pub struct WriteGuardHeld<'f> {
    _board: &'f Fixture,
}

impl<'f> WriteGuardHeld<'f> {
    /// Returns the hold, armed on `board`.
    ///
    /// # Panics
    ///
    /// Where `board` does not run alone ([`Fixture::alone`]): the hold parks
    /// every board's writes in the process.
    pub fn arm(board: &'f Fixture) -> WriteGuardHeld<'f> {
        assert!(matches!(board.seams, SeamsHeld::Alone { .. }), "the write guard is held on a board run alone");
        Daemon::hold_the_write_guard();
        WriteGuardHeld { _board: board }
    }
}

impl Drop for WriteGuardHeld<'_> {
    fn drop(&mut self) {
        Daemon::release_the_write_guard();
    }
}

/// Every fetch stream held after its first chunk, until the drop.
///
/// It is `Daemon::hold_the_fetch_stream`, process-wide like the write guard,
/// and borrows the board it is armed on as the write guard's hold does.
#[must_use = "every fetch stream in the process parks until the drop"]
pub struct FetchStreamHeld<'f> {
    _board: &'f Fixture,
}

impl<'f> FetchStreamHeld<'f> {
    /// Returns the hold, armed on `board`.
    ///
    /// # Panics
    ///
    /// Where `board` does not run alone ([`Fixture::alone`]): the hold parks
    /// every board's fetch streams in the process.
    pub fn arm(board: &'f Fixture) -> FetchStreamHeld<'f> {
        assert!(matches!(board.seams, SeamsHeld::Alone { .. }), "the fetch stream is held on a board run alone");
        Daemon::hold_the_fetch_stream();
        FetchStreamHeld { _board: board }
    }
}

impl Drop for FetchStreamHeld<'_> {
    fn drop(&mut self) {
        Daemon::release_the_fetch_stream();
    }
}

/// A claimed board through the LIBRARY, as the dev provider's suite claims
/// one: a device key generated into `store`, the notebook walk run under
/// a scripted person (the two anchor boxes answered with their defaults),
/// the anchors placed under `anchors`; the store then holds the key and
/// the account's binding line. The key's fingerprint, in hex.
pub fn claim_board(board_origin: &str, store: &Path, anchors: &Path) -> String {
    let store = FileStore::open(store);
    let id = store.generate(Some(Label::new("notebook").expect("a legal label"))).expect("keygen");
    let board = Board::new(Origin::parse(board_origin).expect("a canonical origin"), PlainHttp::new());
    let mut person = Scripted::new(vec![Script::LabelDefault, Script::LabelDefault]);
    let opts = NotebookOptions {
        principal: None,
        display_name: Some("a name".into()),
        anchor_out: vec![anchors.join("a"), anchors.join("b")],
        paper: false,
        host_name: "testhost".into(),
        date: "2026-10-19".into(),
    };
    let ClaimOutcome::Ours(_) = claim::notebook(&board, &store, &mut person, &opts).unwrap_or_else(|h| panic!("{h}\n{}", person.transcript.join("\n"))) else { panic!("a stranger's board") };
    id.0.to_hex()
}

// ── minimal HTTP, for the blob seeding ──────────────────────────────────

/// One exchange with the daemon: the request written whole, the answer
/// read to its close — the status, the headers, the body.
pub fn http(port: u16, method: &str, path: &str, token: Option<&str>, body: &[u8]) -> (u16, Vec<(String, String)>, Vec<u8>) {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).expect("connect to skepd");
    stream.set_read_timeout(Some(Duration::from_secs(120))).expect("read timeout");
    stream.set_write_timeout(Some(Duration::from_secs(120))).expect("write timeout");
    let mut head = format!("{method} {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\nContent-Length: {}\r\n", body.len());
    if let Some(token) = token {
        head.push_str(&format!("Skepd-Session: {token}\r\n"));
    }
    head.push_str("Content-Type: application/json\r\n\r\n");
    // A write the daemon declined to read is no fault here: the answer is
    // the judge.
    let _ = stream.write_all(head.as_bytes());
    let _ = stream.write_all(body);
    let _ = stream.shutdown(std::net::Shutdown::Write);
    let mut raw = Vec::new();
    let _ = stream.read_to_end(&mut raw);
    let sep = raw.windows(4).position(|w| w == b"\r\n\r\n").unwrap_or_else(|| panic!("{method} {path}: no header terminator in {:?}", String::from_utf8_lossy(&raw)));
    let head = std::str::from_utf8(&raw[..sep]).expect("ascii head");
    let mut lines = head.split("\r\n");
    let status: u16 = lines.next().expect("status line").split_whitespace().nth(1).expect("status code").parse().expect("numeric status");
    let headers = lines.filter_map(|l| l.split_once(':')).map(|(k, v)| (k.trim().to_string(), v.trim().to_string())).collect();
    (status, headers, raw[sep + 4..].to_vec())
}

/// One frame on `/op` under `token`: its response document.
pub fn op(port: u16, token: Option<&str>, frame: &Value) -> Value {
    let (st, _, body) = http(port, "POST", "/op", token, frame.to_string().as_bytes());
    assert_eq!(st, 200, "op transport: {}", String::from_utf8_lossy(&body));
    serde_json::from_slice(&body).expect("op response is JSON")
}

/// The picture's cell kind, INTERIM (wire.md §Media).
pub const CELL_KIND: &str = "1.1.0.1.0.1.0.3.89";

/// THE UPLOAD: `bytes` deposited whole under `token` by the resumable
/// upload's creation-with-upload (`POST /blob/upload?length=<n>` with the
/// body), the rebuild window's `index_rebuilding` retried; the finish's
/// `hash` and `size`, the daemon's own.
pub fn upload(port: u16, token: &str, bytes: &[u8]) -> (String, u64) {
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        let (st, _, body) = http(port, "POST", &format!("/blob/upload?length={}", bytes.len()), Some(token), bytes);
        if st == 503 && String::from_utf8_lossy(&body).contains("\"index_rebuilding\"") {
            assert!(Instant::now() < deadline, "the upload: index_rebuilding for 60 s");
            std::thread::sleep(Duration::from_millis(10));
            continue;
        }
        assert_eq!(st, 200, "the upload: {}", String::from_utf8_lossy(&body));
        let v: Value = serde_json::from_slice(&body).expect("the finish's JSON");
        let hash = v["hash"].as_str().expect("the hash").to_string();
        assert_eq!(v["size"].as_u64(), Some(bytes.len() as u64), "{v}");
        return (hash, bytes.len() as u64);
    }
}

/// The canonical cell over `hash` at `size` — the form the daemon's parser
/// admits (wire.md §Media).
pub fn cell_of(hash: &str, size: u64) -> String {
    format!(r#"{{"type":"{CELL_KIND}","hash":"{hash}","size":{size}}}"#)
}

/// The cell inserted into `draft` at ordinal 1 under `token`, as ONE
/// composite value: the I-address it sits at.
pub fn insert_cell(port: u16, token: &str, draft: &str, cell: &str) -> String {
    let v = op(port, Some(token), &json!({"op": "insert", "doc": draft, "at": {"subspace": "1", "ordinal": "1"}, "values": [{"atom": cell}]}));
    assert_eq!(v["resp"], "ack_addr", "the cell's insert: {v}");
    v["addr"].as_str().expect("the cell's address").to_string()
}

/// `n` seeded pseudo-random bytes (SplitMix64) opening with `lead`, so a
/// large body is never stored in a fixture and never sniffs as an image.
pub fn seeded_bytes(n: usize, seed: u64, lead: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(n);
    out.extend_from_slice(&lead[..lead.len().min(n)]);
    let mut x = seed ^ 0x9E37_79B9_7F4A_7C15;
    while out.len() < n {
        x = x.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = x;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^= z >> 31;
        let take = (n - out.len()).min(8);
        out.extend_from_slice(&z.to_le_bytes()[..take]);
    }
    out
}

/// A reader of base64's standard alphabet, written apart from the adapter's
/// encoder: what a content block's `data` or `blob` decodes to.
pub fn base64_decode(text: &str) -> Vec<u8> {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let value = |c: u8| ALPHABET.iter().position(|&a| a == c).unwrap_or_else(|| panic!("not base64: {:?}", c as char)) as u32;
    let mut out = Vec::with_capacity(text.len() / 4 * 3);
    for group in text.as_bytes().chunks(4) {
        assert_eq!(group.len(), 4, "every group is four characters");
        let pad = group.iter().filter(|&&c| c == b'=').count();
        let n = group.iter().take(4 - pad).fold(0u32, |n, &c| (n << 6) | value(c)) << (6 * pad);
        out.extend_from_slice(&n.to_be_bytes()[1..4 - pad]);
    }
    out
}

/// Whether `text` holds a 32-lowercase-hex run that is no part of a longer
/// one — the shape of a session token.
pub fn holds_a_token(text: &str) -> bool {
    let bytes = text.as_bytes();
    let hexish = |b: u8| b.is_ascii_digit() || (b'a'..=b'f').contains(&b);
    let mut i = 0;
    while i < bytes.len() {
        if hexish(bytes[i]) {
            let start = i;
            while i < bytes.len() && hexish(bytes[i]) {
                i += 1;
            }
            if i - start == 32 {
                return true;
            }
        } else {
            i += 1;
        }
    }
    false
}

// ── the adapter under test ──────────────────────────────────────────────

/// The settings this adapter reads, each cleared from every run before a
/// test sets its own.
pub const VARIABLES: [&str; 5] = ["SKEP_BOARD", "SKEP_KEYSTORE", "SKEP_PRINCIPAL", "SKEP_COMMONS", "SKEPD_URL"];

/// A run of the built `skep-mcp` being composed: its arguments and its
/// environment, over the fixture's board and store or over what a test
/// names.
pub struct Launch {
    cmd: Command,
    log: Option<Stdio>,
}

impl Launch {
    /// A bare launch: every setting cleared, nothing named.
    pub fn new() -> Launch {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_skep-mcp"));
        for var in VARIABLES {
            cmd.env_remove(var);
        }
        Launch { cmd, log: None }
    }

    /// A launch over the fixture's board and store, acting as `principal`,
    /// by the three variables.
    pub fn over(fixture: &Fixture, principal: u64) -> Launch {
        Launch::new().env("SKEP_BOARD", fixture.origin()).env("SKEP_KEYSTORE", fixture.store.to_str().expect("a UTF-8 path")).env("SKEP_PRINCIPAL", principal.to_string())
    }

    pub fn env(mut self, var: &str, value: impl AsRef<std::ffi::OsStr>) -> Launch {
        self.cmd.env(var, value);
        self
    }

    #[cfg(unix)]
    pub fn arg(mut self, arg: impl AsRef<std::ffi::OsStr>) -> Launch {
        self.cmd.arg(arg);
        self
    }

    pub fn args<I: IntoIterator<Item = S>, S: AsRef<std::ffi::OsStr>>(mut self, args: I) -> Launch {
        self.cmd.args(args);
        self
    }

    /// The adapter's stderr as the test names it; inherited by default,
    /// read by [`Mcp::talk`] under [`Launch::logged`].
    pub fn stderr(mut self, log: Stdio) -> Launch {
        self.log = Some(log);
        self
    }

    /// The adapter's log read on a thread, for [`Mcp::talk`] and
    /// [`Mcp::finish_logged`].
    pub fn logged(self) -> Launch {
        self.stderr(Stdio::piped())
    }

    /// The adapter spawned, its stdin and stdout piped, its stderr as the
    /// launch named it: the child, for a driver of a suite's own.
    pub fn child(mut self) -> Child {
        let log = self.log.take().unwrap_or_else(Stdio::inherit);
        self.cmd.stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(log).spawn().expect("spawn skep-mcp")
    }

    /// The adapter spawned, its stdin and stdout piped.
    pub fn spawn(self) -> Mcp {
        let mut child = self.child();
        let stdin = child.stdin.take().expect("child stdin");
        let stdout = BufReader::new(child.stdout.take().expect("child stdout"));
        let talk = Arc::new(Mutex::new(String::new()));
        if let Some(stderr) = child.stderr.take() {
            let kept = Arc::clone(&talk);
            std::thread::spawn(move || {
                let mut reader = BufReader::new(stderr);
                let mut line = String::new();
                while let Ok(n) = reader.read_line(&mut line) {
                    if n == 0 {
                        break;
                    }
                    kept.lock().expect("the talk's lock").push_str(&line);
                    line.clear();
                }
            });
        }
        Mcp { child, stdin: Some(stdin), stdout, talk, next_id: 0 }
    }

    /// The adapter run to completion with stdin empty: its output.
    pub fn output(mut self) -> Output {
        let log = self.log.take().unwrap_or_else(Stdio::piped);
        self.cmd.stdin(Stdio::null()).stdout(Stdio::piped()).stderr(log).output().expect("run skep-mcp")
    }

    /// The adapter run to completion with stdin empty: its exit code and its
    /// stderr as text.
    pub fn refusal(self) -> (Option<i32>, String) {
        let out = self.output();
        (out.status.code(), String::from_utf8_lossy(&out.stderr).into_owned())
    }
}

impl Default for Launch {
    fn default() -> Launch {
        Launch::new()
    }
}

/// A running adapter.
pub struct Mcp {
    child: Child,
    stdin: Option<ChildStdin>,
    stdout: BufReader<ChildStdout>,
    /// The adapter's log so far, where the launch was `logged`.
    talk: Arc<Mutex<String>>,
    next_id: u64,
}

impl Mcp {
    pub fn send_line(&mut self, line: &str) {
        let stdin = self.stdin.as_mut().expect("stdin open");
        stdin.write_all(line.as_bytes()).expect("write to adapter");
        stdin.write_all(b"\n").expect("write newline");
        stdin.flush().expect("flush to adapter");
    }

    /// Raw bytes onto the adapter's stdin — for a line no `&str` can hold.
    pub fn send_bytes(&mut self, bytes: &[u8]) {
        let stdin = self.stdin.as_mut().expect("stdin open");
        stdin.write_all(bytes).expect("write to adapter");
        stdin.flush().expect("flush to adapter");
    }

    /// One message off stdout: every line is JSON, or the adapter died.
    pub fn read_message(&mut self) -> Value {
        let mut line = String::new();
        loop {
            line.clear();
            let n = self.stdout.read_line(&mut line).expect("read from adapter");
            assert!(n > 0, "adapter closed stdout unexpectedly:\n{}", self.talk());
            if !line.trim().is_empty() {
                return serde_json::from_str(line.trim()).unwrap_or_else(|e| panic!("adapter wrote a non-JSON line ({e}): {:.300?}", line));
            }
        }
    }

    /// Whether the adapter has closed its stdout — nothing more comes: a
    /// stop of its own, met before any line was answered.
    pub fn stdout_closed(&mut self) -> bool {
        let mut line = String::new();
        self.stdout.read_line(&mut line).expect("read from adapter") == 0
    }

    /// One request → its response (the adapter answers in order).
    pub fn request(&mut self, method: &str, params: Value) -> Value {
        self.next_id += 1;
        let id = self.next_id;
        self.send_line(&json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params}).to_string());
        let v = self.read_message();
        assert_eq!(v["id"], json!(id), "responses correlate by id: {v}");
        v
    }

    pub fn notify(&mut self, method: &str) {
        self.send_line(&json!({"jsonrpc": "2.0", "method": method}).to_string());
    }

    pub fn initialize(&mut self) -> Value {
        let v = self.request("initialize", json!({"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "test-harness", "version": "0"}}));
        self.notify("notifications/initialized");
        v["result"].clone()
    }

    /// The tools `tools/list` names, in order.
    pub fn tool_names(&mut self) -> Vec<String> {
        let v = self.request("tools/list", json!({}));
        v["result"]["tools"].as_array().expect("tools array").iter().map(|t| t["name"].as_str().expect("name").to_string()).collect()
    }

    /// tools/call, returning (isError, the one content block).
    pub fn call_block(&mut self, tool: &str, args: Value) -> (bool, Value) {
        let v = self.request("tools/call", json!({"name": tool, "arguments": args}));
        assert!(v.get("error").is_none(), "a call the adapter runs is never a JSON-RPC error: {v}");
        let result = &v["result"];
        assert_eq!(result["content"].as_array().map(Vec::len), Some(1), "one block: {result}");
        let is_error = result["isError"].as_bool().expect("isError present");
        (is_error, result["content"][0].clone())
    }

    /// tools/call, returning (isError, text) — the one text block's text.
    pub fn call(&mut self, tool: &str, args: Value) -> (bool, String) {
        let (is_error, block) = self.call_block(tool, args);
        assert_eq!(block["type"], "text", "one text block: {block}");
        (is_error, block["text"].as_str().expect("text block").to_string())
    }

    /// tools/call that must answer data: its text, parsed as JSON — a
    /// response document, a `refused` refusal, or an apparatus
    /// answer.
    pub fn call_json(&mut self, tool: &str, args: Value) -> Value {
        let (is_error, text) = self.call(tool, args);
        assert!(!is_error, "{tool}: unexpected isError: {text}\n{}", self.talk());
        serde_json::from_str(&text).unwrap_or_else(|e| panic!("tool result's text is not JSON ({e}): {text}"))
    }

    /// tools/call that must be `isError`: its text, parsed as JSON — the
    /// refusal's value.
    pub fn call_error(&mut self, tool: &str, args: Value) -> Value {
        let (is_error, text) = self.call(tool, args);
        assert!(is_error, "{tool}: expected isError: {text}");
        serde_json::from_str(&text).unwrap_or_else(|_| json!({"text": text}))
    }

    /// A write through the adapter, acknowledged: its answer.
    pub fn acked(&mut self, tool: &str, args: Value) -> Value {
        let v = self.call_json(tool, args.clone());
        assert!(v["resp"].as_str().is_some_and(|r| r.starts_with("ack")), "{tool} {args}: {v}\n{}", self.talk());
        v
    }

    /// The adapter's log so far (a `logged` launch).
    pub fn talk(&self) -> String {
        self.talk.lock().expect("the talk's lock").clone()
    }

    /// The log once it holds every one of `needles`, within `within`.
    pub fn talk_holding(&self, needles: &[&str], within: Duration) -> String {
        let deadline = Instant::now() + within;
        loop {
            let said = self.talk();
            if needles.iter().all(|n| said.contains(n)) {
                return said;
            }
            assert!(Instant::now() < deadline, "the adapter never said all of {needles:?}:\n{said}");
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    /// The adapter's exit, waited for up to `within` with stdin held open —
    /// a stop of its own; `None` where it outlives the wait.
    pub fn wait_exit(&mut self, within: Duration) -> Option<ExitStatus> {
        let deadline = Instant::now() + within;
        loop {
            if let Some(status) = self.child.try_wait().expect("poll the adapter") {
                return Some(status);
            }
            if Instant::now() >= deadline {
                return None;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    /// Close stdin (EOF) and reap — the clean-exit path under test.
    pub fn finish(mut self) -> ExitStatus {
        drop(self.stdin.take());
        self.child.wait().expect("wait for adapter")
    }

    /// Close stdin (EOF), reap, and read the adapter's log to its end.
    pub fn finish_logged(mut self) -> (ExitStatus, String) {
        drop(self.stdin.take());
        let status = self.child.wait().expect("wait for adapter");
        // The log's reader trails the exit by a line or two.
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut last = self.talk();
        while Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(50));
            let now = self.talk();
            if now == last {
                break;
            }
            last = now;
        }
        (status, last)
    }
}

impl Drop for Mcp {
    fn drop(&mut self) {
        drop(self.stdin.take());
        for _ in 0..250 {
            if let Ok(Some(_)) = self.child.try_wait() {
                return;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// The catalog the binary embeds — the expected tools/list and the base
/// for the drift fixtures.
pub fn embedded_catalog() -> Value {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/tools.json");
    serde_json::from_str(&std::fs::read_to_string(path).expect("read tools.json")).expect("tools.json parses")
}
