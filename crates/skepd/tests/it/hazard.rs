//! H3 — the dirty-crash program at the customer-facing surface.
//!
//! * **E — ack survival**: the real `skepd` binary is SIGKILLed at seeded
//!   random moments under sustained HTTP write load; every write the client
//!   saw acked must answer after reopen (`world_at` + read-back). Bounded
//!   rollback is NOT acceptable for an acked write — durable-before-visible
//!   is the line, and this is its end-to-end test.
//! * **F — sidecar independence**: `commits.log` is the daemon's own
//!   testimony, never the world. Mutilating it (torn tail, garbage, delete)
//!   must leave recovery untouched and degrade `/changes` to bare/null
//!   entries; inversely, a torn journal under an intact sidecar must not
//!   let the feed claim positions the recovered world lacks.
//! * **G — disk exhaustion** (`#[ignore]`, macOS `hdiutil`): on a tiny
//!   dedicated volume, acks must stop (typed `durability` rejections)
//!   before durability is compromised; after remount every acked position
//!   answers.
//! * **H — the claim window** (signed ops, s1): the claim and its head
//!   `H.1` are two transactions in one step; a process SIGKILLed between
//!   them — this test binary re-exec'd as a child and killed at the
//!   daemon's hold seam, the kernel hazard suite's self-exec pattern —
//!   reopens to a claimed board WITH `H.1`, written by the open before it
//!   serves, and takes an attested write at once.
//! * **E′ and H′ — the blob store** (media lane B; M-I5 (a) DURABLE
//!   BEFORE NAMED, ANSWERED AFTER RECORDED): the E program over whole-file
//!   PUTs — the real binary killed at seeded moments under PUT load; every
//!   acked PUT answers after reopen, listed to its principal and whole on
//!   disk, every un-acked one absent, a partial, or the finish's one
//!   residue, a leased whole file; no orphan partial stands — and the hold
//!   family inside the finish: power lost between the rename and the
//!   directory fsync, after a first rename into a new designation
//!   directory, and between a finish's rename and its record's retirement,
//!   each a child killed at the store's hold seam and the reopen judged.
//!
//! Finding protocol (per the H3 ruling): a test that discovers a real
//! violation is converted to `#[ignore = "FINDING-<n>: …"]` with its
//! assertion INTACT and the reproduction in a comment block — never
//! weakened, never left failing.

use crate::common;

use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{mpsc, Arc, Mutex};
use std::thread;
use std::time::Duration;

use common::{
    acked_addr, acked_at, blob_hex, board_term, cell_of, ceremony_before_the_claim, claim_board,
    claim_frame, claimed, create_frame, device_key, expect_resp, head_position, json, op,
    open_session, open_signed_session, seeded_bytes, spawn_configured, spawn_unclaimed,
    typed_link_frame, verdict, WalkUnheld, BLOB_UPLOAD, CLAIMANT_ACCOUNT, CLAIMANT_DOC1,
    CLAIMANT_PRINCIPAL, HEAD_MEMBER_1, T_ENROLL, T_GRANT,
};
use serde_json::Value;
use skep_blobs::Step;
use skep_engine::{Engine, KernelConfig};
use skep_kernel::{BurnedSeqPolicy, CheckpointPolicy, Durability, SaltSource};
use skepd::{Daemon, HttpRequest, Reply, Routed, Seq};

/// `HAZARD_EXHAUSTIVE=1` widens the trial counts.
fn exhaustive() -> bool {
    std::env::var_os("HAZARD_EXHAUSTIVE").is_some_and(|v| v == "1")
}

/// SplitMix64 — deterministic; the trial index is the whole reproduction.
struct SplitMix64(u64);

impl SplitMix64 {
    fn new(seed: u64) -> SplitMix64 {
        SplitMix64(seed ^ 0x9E37_79B9_7F4A_7C15)
    }

    fn next_range(&mut self, n: u64) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        (z ^ (z >> 31)) % n
    }
}

// ── plumbing: the real binary, a non-panicking client, socket-free judges ──

/// Spawn the real `skepd` binary on an ephemeral port (`--port 0`); the
/// bound port is parsed from its startup line.
pub(crate) fn spawn_skepd(dir: &Path) -> (Child, u16) {
    let mut child = Command::new(env!("CARGO_BIN_EXE_skepd"))
        .arg("--data-dir")
        .arg(dir)
        .args(["--port", "0", "--workers", &skepd::DEFAULT_WORKERS.to_string()])
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("spawn the skepd binary");
    let stdout = child.stdout.take().expect("skepd stdout");
    let mut line = String::new();
    BufReader::new(stdout).read_line(&mut line).expect("read skepd startup line");
    let port = line
        .split_once("http://127.0.0.1:")
        .and_then(|(_, rest)| rest.split('/').next())
        .and_then(|p| p.parse::<u16>().ok())
        .unwrap_or_else(|| {
            // Name the child's fate: a refused startup (Daemon::open error)
            // exits nonzero with its message on inherited stderr, above.
            let fate = match child.try_wait() {
                Ok(Some(status)) => format!("exited {status}"),
                Ok(None) => "still running".to_string(),
                Err(e) => format!("unwaitable: {e}"),
            };
            panic!("no port in skepd startup line {line:?} (child {fate}; its stderr is inherited above)")
        });
    (child, port)
}

/// One `/op` exchange that treats every transport mishap — refused connect,
/// reset, partial response — as "no ack": the honest client view while the
/// daemon is being killed. A parsed 200 body comes back whole.
fn try_op(port: u16, token: Option<&str>, frame: &str) -> Option<Value> {
    let mut s = TcpStream::connect(("127.0.0.1", port)).ok()?;
    let _ = s.set_nodelay(true);
    // Bounded like every judge: a wedged daemon becomes "no ack" (an honest
    // client view) instead of stalling the trial loop indefinitely.
    let _ = s.set_read_timeout(Some(Duration::from_secs(30)));
    let _ = s.set_write_timeout(Some(Duration::from_secs(30)));
    let mut head = format!(
        "POST /op HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\nContent-Length: {}\r\n",
        frame.len()
    );
    if let Some(token) = token {
        head.push_str(&format!("Skepd-Session: {token}\r\n"));
    }
    head.push_str("Content-Type: application/json\r\n\r\n");
    s.write_all(head.as_bytes()).ok()?;
    s.write_all(frame.as_bytes()).ok()?;
    let mut raw = Vec::new();
    s.read_to_end(&mut raw).ok()?;
    let sep = raw.windows(4).position(|w| w == b"\r\n\r\n")?;
    if !raw.starts_with(b"HTTP/1.1 200 ") {
        return None;
    }
    serde_json::from_slice(&raw[sep + 4..]).ok()
}

/// `Daemon::open` under a deadline: a reopen that hangs is a finding, and a
/// refusal where recovery was required is one too. A `Disconnected` recv is
/// the opener thread PANICKING — a distinct fate from a wedge, named as one
/// so the gate log attributes it to the right code path.
fn timed_daemon_open(dir: &Path, ctx: &str) -> Daemon {
    let d = dir.to_path_buf();
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        let _ = tx.send(Daemon::open(&d));
    });
    match rx.recv_timeout(Duration::from_secs(60)) {
        Ok(Ok(d)) => d,
        Ok(Err(e)) => panic!("FINDING ({ctx}): reopen refused where recovery was required: {e}"),
        Err(mpsc::RecvTimeoutError::Timeout) => {
            panic!("FINDING (wedge, {ctx}): Daemon::open hung past 60s")
        }
        Err(mpsc::RecvTimeoutError::Disconnected) => panic!(
            "FINDING ({ctx}): Daemon::open PANICKED during reopen — the opener thread's \
             panic message is printed above in this test's captured output"
        ),
    }
}

/// THE CELL INDEX's WALK AT OPEN runs on a thread of the reopened daemon's,
/// and its three readers — the PUT's creation and resume, the deposit read —
/// refuse `index_rebuilding` until it completes (ms5-R). A judgment of the
/// blob store after a reopen waits for it, bounded as the suite's spawns
/// wait, so what it reads is the reopened store and never the walk's window.
fn await_the_index(d: &Daemon, ctx: &str) {
    let deadline = std::time::Instant::now() + Duration::from_secs(60);
    while !d.index_is_ready() {
        assert!(
            std::time::Instant::now() < deadline,
            "FINDING (wedge, {ctx}): the cell index's walk at open did not complete within 60 s"
        );
        thread::sleep(Duration::from_millis(5));
    }
}

/// [`timed_daemon_open`], then [`await_the_index`], under the walk's fence
/// ([`WalkUnheld`]) from before the open until the walk completes: the
/// suite's walk-holding tests are threads of this process under plain
/// `cargo test`, and the fence keeps their hold off this reopen's walk — so
/// a `FINDING (wedge…)` from the wait names this daemon's walk and never
/// another test's hold.
fn timed_daemon_open_with_the_index(dir: &Path, ctx: &str) -> Daemon {
    let _unheld = WalkUnheld::take();
    let d = timed_daemon_open(dir, ctx);
    await_the_index(&d, ctx);
    d
}

/// Route one request through the socket-free router; the event stream is
/// unreachable from these paths.
fn route_raw(
    d: &Daemon,
    method: &str,
    path: &str,
    query: Option<&str>,
    token: Option<&str>,
    body: &[u8],
) -> Reply {
    let req = HttpRequest {
        method: method.to_string(),
        path: path.to_string(),
        query: query.map(str::to_string),
        session_token: token.map(str::to_string),
        origin: None,
        peer: skepd::Peer::Loopback,
        body: body.to_vec(),
    };
    match d.route(&req) {
        Routed::Reply(r) => r,
        // `Routed` is `#[non_exhaustive]`, so this arm covers the event
        // stream and every later variant the reply path cannot express. No
        // route this helper drives resolves to one.
        other => unreachable!("no test route resolves to {other:?}"),
    }
}

/// `POST /op` via the router; transport must be 200 (the returned document
/// may still be a rejection — callers decide).
fn route_op(d: &Daemon, token: Option<&str>, frame: &str) -> Value {
    let r = route_raw(d, "POST", "/op", None, token, frame.as_bytes());
    assert_eq!(r.status, 200, "op transport failed: {}", String::from_utf8_lossy(r.bytes()));
    json(r.bytes())
}

fn route_session(d: &Daemon, principal: u64) -> String {
    let r = route_raw(
        d,
        "POST",
        "/session",
        None,
        None,
        format!("{{\"principal\":{principal}}}").as_bytes(),
    );
    assert_eq!(r.status, 200, "session open failed: {}", String::from_utf8_lossy(r.bytes()));
    json(r.bytes())["session"].as_str().expect("session token").to_string()
}

fn retrieve_frame(doc: &str, width: u64) -> String {
    format!(
        r#"{{"op":"retrieve_v","specs":[{{"doc":"{doc}","span":{{"start":"1.1","width":"0.{width}"}}}}]}}"#
    )
}

/// Concatenated delivery text via the router (panics on a rejection).
fn read_text(d: &Daemon, doc: &str, width: u64) -> String {
    let v = route_op(d, None, &retrieve_frame(doc, width));
    expect_resp(&v, "delivery")["items"]
        .as_array()
        .expect("delivery items")
        .iter()
        .map(|i| i["content"].as_str().unwrap_or(""))
        .collect()
}

/// `GET /changes?since=0` entries as `(at, entry)` pairs.
fn changes_entries(d: &Daemon) -> Vec<(u64, Value)> {
    let r = route_raw(d, "GET", "/changes", Some("since=0"), None, b"");
    assert_eq!(r.status, 200, "/changes failed: {}", String::from_utf8_lossy(r.bytes()));
    let v = json(r.bytes());
    assert_eq!(v["more"], Value::Bool(false), "one page covers the fixture: {v}");
    v["changes"]
        .as_array()
        .expect("changes array")
        .iter()
        .map(|e| (e["at"].as_u64().expect("entry at"), e.clone()))
        .collect()
}

fn copy_dir(src: &Path, dst: &Path) {
    fs::create_dir_all(dst).expect("case dir");
    for e in fs::read_dir(src).expect("fixture dir lists") {
        let e = e.expect("dir entry");
        if e.file_type().expect("file type").is_file() {
            fs::copy(e.path(), dst.join(e.file_name())).expect("copy fixture file");
        }
    }
}

// ── E. Ack survival (durable-before-visible, end-to-end) ─────────────────

#[test]
fn e_acked_writes_survive_sigkill() {
    let trials: u64 = if exhaustive() { 36 } else { 12 };
    let mut total_acked = 0usize;
    let mut lost_ack_commits = 0usize;
    for trial in 0..trials {
        let (acked, lost) = e_trial(trial);
        total_acked += acked;
        lost_ack_commits += lost;
    }
    println!(
        "E: {trials} SIGKILL trials (seeds 0xE000+trial), {total_acked} acked writes verified \
         durable, {lost_ack_commits} committed-but-unacked in-flight writes (the SAFE(b)(iii) \
         lost-ack case, by design)"
    );
}

fn e_trial(trial: u64) -> (usize, usize) {
    let tmp = tempfile::tempdir().expect("tempdir");
    let dir = tmp.path().join("data");
    let (child, port) = spawn_skepd(&dir);
    let child = Arc::new(Mutex::new(child));

    // Setup over real HTTP (the killer is gated behind `go`, so these
    // panicking helpers run against a healthy daemon).
    let boot = open_session(port, 0);
    let v = op(port, Some(&boot), r#"{"op":"next_account_prefix","parent":"1"}"#);
    let prefix = expect_resp(&v, "maybe_addr")["addr"].as_str().expect("prefix").to_string();
    let v = op(
        port,
        Some(&boot),
        &format!(r#"{{"op":"delegate","new_prefix":"{prefix}","new_id":1}}"#),
    );
    let account = acked_addr(&v);
    let mut acks: Vec<u64> = vec![v["at"].as_u64().expect("delegate at")];
    let s1 = open_session(port, 1);
    let v = op(
        port,
        Some(&s1),
        &format!(r#"{{"op":"create_new_document","account":"{account}"}}"#),
    );
    let doc = acked_addr(&v);
    acks.push(v["at"].as_u64().expect("create at"));

    // The killer: SIGKILL at a seeded delay after the write load starts.
    let (go_tx, go_rx) = mpsc::channel::<()>();
    let killer = {
        let child = Arc::clone(&child);
        thread::spawn(move || {
            let _ = go_rx.recv();
            let mut rng = SplitMix64::new(0xE000 + trial);
            thread::sleep(Duration::from_millis(25 + rng.next_range(275)));
            let _ = child.lock().expect("child lock").kill();
        })
    };

    // Sustained sequential write load: one distinct byte per ordinal, each
    // ack recorded — the ground truth the reopened world must honor. The
    // document is the account's home, born published, so each append is a
    // DECLARED deposit at the head's fresh position (PUB-2.59; an undeclared
    // insert into a published document is the in-place edit the store
    // refuses, PUB-2.11). The chunks here and below are prose — PUB-2.60's
    // residue — declared under a MEMBER type, ENROLL's.
    let expect_char = |i: u64| char::from(b'a' + ((i - 1) % 26) as u8);
    let mut inserts_acked: u64 = 0;
    go_tx.send(()).expect("killer is waiting");
    let mut i: u64 = 0;
    loop {
        i += 1;
        let frame = format!(
            r#"{{"op":"insert","doc":"{doc}","at":{{"subspace":"1","ordinal":"{i}"}},"values":["{}"],"deposit":"{T_ENROLL}"}}"#,
            expect_char(i)
        );
        match try_op(port, Some(&s1), &frame) {
            Some(v) if v["resp"] == "ack_addr" => {
                acks.push(v["at"].as_u64().expect("insert ack at"));
                inserts_acked += 1;
            }
            Some(v) => panic!(
                "E trial {trial}: healthy sequential insert (ordinal {i}, after \
                 {} prior acks) answered non-ack: {v}",
                acks.len()
            ),
            None => break, // the daemon died mid-exchange; unacked from here
        }
        assert!(i < 500_000, "E trial {trial}: the killer never fired");
    }
    killer.join().expect("killer thread");
    {
        let mut c = child.lock().expect("child lock");
        let _ = c.kill();
        let _ = c.wait();
    }

    // Judge: reopen the same data dir in-process and hold every ack to the
    // contract.
    let ctx = format!("E trial {trial} (seed 0xE000+{trial}), {} acks", acks.len());
    let d = timed_daemon_open(&dir, &ctx);
    let head = d.log_position().0;
    let max_ack = *acks.iter().max().expect("setup acked");
    assert!(
        head >= max_ack,
        "FINDING (E, {ctx}): acked write vanished — recovered head {head} < acked {max_ack}; \
         bounded rollback is not acceptable for an acked write"
    );
    for &at in &acks {
        d.world_at(Seq(at)).unwrap_or_else(|e| {
            panic!("FINDING (E, {ctx}): acked position {at} unanswerable after SIGKILL: {e}")
        });
    }
    let k = inserts_acked;
    if k > 0 {
        let text = read_text(&d, &doc, k);
        let expect: String = (1..=k).map(expect_char).collect();
        assert_eq!(
            text, expect,
            "FINDING (E, {ctx}): recovered content diverges from the acked writes"
        );
    }
    // At most ONE committed-but-unacked write can exist (the single
    // in-flight request at the kill); anything past k+1 is a phantom.
    // Clipping semantics: the k+1-wide span always answers `delivery` —
    // of k chars (no in-flight write survived) or k+1 (the single
    // in-flight write committed before the kill). Either is legal; the
    // bytes must be exactly what the client sent.
    let probe = route_op(&d, None, &retrieve_frame(&doc, k + 1));
    assert_eq!(
        probe["resp"].as_str(),
        Some("delivery"),
        "E trial {trial}: unexpected probe response: {probe}"
    );
    let text: String = probe["items"]
        .as_array()
        .expect("items")
        .iter()
        .map(|i| i["content"].as_str().unwrap_or(""))
        .collect();
    let tlen = text.len() as u64;
    assert!(
        tlen == k || tlen == k + 1,
        "FINDING (E, {ctx}): recovered length {tlen} outside k..=k+1: {probe}"
    );
    let expect: String = (1..=tlen).map(expect_char).collect();
    assert_eq!(
        text, expect,
        "FINDING (E, {ctx}): the in-flight write's content is not the one the client sent"
    );
    let lost = if tlen == k + 1 { 1 } else { 0 };
    // Clipping semantics: the k+2-wide span answers `delivery` of the
    // present prefix. Phantom check = the delivered text may extend at
    // most one char (the single possible in-flight write) past the acks,
    // and that char must be the one the client sent.
    let beyond = route_op(&d, None, &retrieve_frame(&doc, k + 2));
    let btext: String = beyond["items"]
        .as_array()
        .map(|a| a.iter().map(|i| i["content"].as_str().unwrap_or("")).collect())
        .unwrap_or_default();
    let blen = btext.len() as u64;
    assert!(
        blen <= k + 1,
        "FINDING (E, {ctx}): phantom content beyond the one possible in-flight write: {beyond}"
    );
    let expect_max: String = (1..=blen).map(expect_char).collect();
    assert_eq!(
        btext, expect_max,
        "FINDING (E, {ctx}): recovered bytes diverge from what the client sent: {beyond}"
    );
    (acks.len(), lost)
}

// ── F. Sidecar independence ──────────────────────────────────────────────

#[test]
fn f_sidecar_mutilation_never_touches_the_world() {
    let base = tempfile::tempdir().expect("tempdir");
    let fixture = base.path().join("fixture");

    // Build the fixture through the socket-free router: seven committed
    // writes (delegate, create, five one-byte inserts), acks recorded.
    let mut acks: Vec<u64> = Vec::new();
    let doc: String;
    let pre_retrieve: Vec<u8>;
    {
        let d = Daemon::open(&fixture).expect("genesis open");
        let boot = route_session(&d, 0);
        let v = route_op(&d, Some(&boot), r#"{"op":"next_account_prefix","parent":"1"}"#);
        let prefix = expect_resp(&v, "maybe_addr")["addr"].as_str().expect("prefix").to_string();
        let v = route_op(
            &d,
            Some(&boot),
            &format!(r#"{{"op":"delegate","new_prefix":"{prefix}","new_id":1}}"#),
        );
        acks.push(v["at"].as_u64().expect("delegate at"));
        let account = acked_addr(&v);
        let s1 = route_session(&d, 1);
        let v = route_op(
            &d,
            Some(&s1),
            &format!(r#"{{"op":"create_new_document","account":"{account}"}}"#),
        );
        doc = acked_addr(&v);
        acks.push(v["at"].as_u64().expect("create at"));
        // Declared deposits at the published home's fresh positions
        // (PUB-2.59).
        for i in 1..=5u64 {
            let ch = char::from(b'a' + (i - 1) as u8);
            let v = route_op(
                &d,
                Some(&s1),
                &format!(
                    r#"{{"op":"insert","doc":"{doc}","at":{{"subspace":"1","ordinal":"{i}"}},"values":["{ch}"],"deposit":"{T_ENROLL}"}}"#
                ),
            );
            acks.push(v["at"].as_u64().expect("insert at"));
        }
        let r = route_raw(&d, "POST", "/op", None, None, retrieve_frame(&doc, 5).as_bytes());
        assert_eq!(r.status, 200);
        pre_retrieve = r.bytes().to_vec();
    }
    let head = *acks.last().expect("acks");
    let sidecar = |dir: &Path| dir.join("commits.log");
    let sidecar_len = fs::metadata(sidecar(&fixture)).expect("commits.log").len();

    // The world-intact judge: recovery byte-identical (as_of included) and
    // `/changes` still enumerating exactly the committed positions.
    let judge_world_intact = |dir: &Path, ctx: &str| -> Daemon {
        let d = timed_daemon_open(dir, ctx);
        assert_eq!(d.log_position().0, head, "{ctx}: the head must be untouched");
        let r = route_raw(&d, "POST", "/op", None, None, retrieve_frame(&doc, 5).as_bytes());
        assert_eq!(r.status, 200);
        assert_eq!(
            r.bytes(), pre_retrieve,
            "FINDING (F, {ctx}): the WORLD changed under a sidecar-only mutation"
        );
        let entries = changes_entries(&d);
        let positions: Vec<u64> = entries.iter().map(|(at, _)| *at).collect();
        assert_eq!(
            positions, acks,
            "FINDING (F, {ctx}): /changes does not enumerate exactly the committed positions"
        );
        d
    };

    // Control: an untouched copy keeps full metadata.
    {
        let case = base.path().join("control");
        copy_dir(&fixture, &case);
        let d = judge_world_intact(&case, "F control (untouched copy)");
        for (at, e) in changes_entries(&d) {
            assert!(e["op"].is_string(), "control: entry {at} lost its metadata: {e}");
        }
        let h = route_raw(&d, "GET", "/health", None, None, b"");
        assert!(!json(h.bytes())["head_time"].is_null(), "control: head_time is recorded");
    }

    // Torn tail (3 bytes off the final line): only the newest entry
    // degrades to bare; earlier metadata survives.
    {
        let case = base.path().join("torn-tail");
        copy_dir(&fixture, &case);
        let f = fs::OpenOptions::new().write(true).open(sidecar(&case)).expect("open sidecar");
        f.set_len(sidecar_len - 3).expect("tear the sidecar tail");
        let d = judge_world_intact(&case, "F torn sidecar tail");
        let entries = changes_entries(&d);
        let (last_at, last) = entries.last().expect("entries");
        // Bare: the testimony — `docs`, `key`, `time` — null, never invented;
        // the op and its terms the JOURNAL's where it names them (round 7's
        // as7-F3), which is no invention.
        assert!(
            last["key"].is_null() && last["time"].is_null() && last["docs"].is_null(),
            "torn tail: the lost entry {last_at} must answer bare/null, never invented: {last}"
        );
        let (first_at, first) = entries.first().expect("entries");
        assert_eq!(
            first["op"].as_str(),
            Some("delegate"),
            "torn tail: the intact prefix keeps its metadata (entry {first_at}): {first}"
        );
    }

    // Half the file gone: every position still enumerated, the damaged
    // region bare.
    {
        let case = base.path().join("half");
        copy_dir(&fixture, &case);
        let f = fs::OpenOptions::new().write(true).open(sidecar(&case)).expect("open sidecar");
        f.set_len(sidecar_len / 2).expect("halve the sidecar");
        let d = judge_world_intact(&case, "F sidecar halved");
        let entries = changes_entries(&d);
        let (last_at, last) = entries.last().expect("entries");
        assert!(
            last["key"].is_null() && last["time"].is_null(),
            "halved: the tail region answers bare (entry {last_at}): {last}"
        );
    }

    // Whole file garbage: everything bare, head_time null.
    {
        let case = base.path().join("garbage");
        copy_dir(&fixture, &case);
        fs::write(sidecar(&case), vec![0xFFu8; sidecar_len as usize]).expect("garbage sidecar");
        let d = judge_world_intact(&case, "F sidecar garbage");
        for (at, e) in changes_entries(&d) {
            assert!(
                e["key"].is_null() && e["time"].is_null() && e["docs"].is_null(),
                "garbage: entry {at} must be bare, never invented: {e}"
            );
        }
        let h = route_raw(&d, "GET", "/health", None, None, b"");
        assert!(
            json(h.bytes())["head_time"].is_null(),
            "garbage: head_time must be null, never invented"
        );
    }

    // File deleted: same degradation.
    {
        let case = base.path().join("deleted");
        copy_dir(&fixture, &case);
        fs::remove_file(sidecar(&case)).expect("delete sidecar");
        let d = judge_world_intact(&case, "F sidecar deleted");
        for (at, e) in changes_entries(&d) {
            assert!(
                e["key"].is_null() && e["time"].is_null() && e["docs"].is_null(),
                "deleted: entry {at} must be bare: {e}"
            );
        }
    }

    // The inverse: journal torn (final commit marker clipped), sidecar
    // intact — the feed must not claim the position the world lost.
    {
        let case = base.path().join("journal-torn");
        copy_dir(&fixture, &case);
        let seg = case.join("seg-1.wal");
        let jlen = fs::metadata(&seg).expect("segment").len();
        let f = fs::OpenOptions::new().write(true).open(&seg).expect("open segment");
        f.set_len(jlen - 4).expect("clip the final marker");
        let prev_head = acks[acks.len() - 2];
        let d = timed_daemon_open(&case, "F journal torn, sidecar intact");
        assert_eq!(
            d.log_position().0,
            prev_head,
            "the clipped final commit rolls back exactly one boundary"
        );
        let entries = changes_entries(&d);
        let claimed: Vec<u64> = entries.iter().map(|(at, _)| *at).collect();
        assert_eq!(
            claimed,
            acks[..acks.len() - 1].to_vec(),
            "FINDING (F): /changes claims positions the recovered world lacks"
        );
        assert_eq!(read_text(&d, &doc, 4), "abcd", "the surviving prefix reads back");
        // Clipping semantics (matches green: contents skip absent
        // positions): a span covering the rolled-back position answers
        // `delivery` of the surviving prefix ONLY — the rolled-back
        // write's byte must be absent from the delivered text.
        assert_eq!(
            read_text(&d, &doc, 5),
            "abcd",
            "FINDING (F): the rolled-back write's content still present"
        );
    }
    println!(
        "F: 6 sidecar/journal cases judged — world untouched under every sidecar mutation, \
         feed degraded to bare/null, no position claimed beyond the recovered head"
    );
}

// ── G. Disk exhaustion (best-effort, dedicated tiny volume) ──────────────

/// A tiny HFS+ disk image, attached for the test's lifetime and detached on
/// drop (best-effort with `-force` as the fallback).
struct Volume {
    img: PathBuf,
    mount: Option<PathBuf>,
}

impl Volume {
    fn create_and_attach(tmp: &Path) -> Volume {
        let img = tmp.join("hazard.dmg");
        let out = Command::new("hdiutil")
            .args(["create", "-size", "8m", "-fs", "HFS+", "-volname", "SKEPHAZG"])
            .arg(&img)
            .output()
            .expect("run hdiutil create");
        assert!(
            out.status.success(),
            "hdiutil create failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        let mut v = Volume { img, mount: None };
        v.attach();
        v
    }

    fn attach(&mut self) {
        let out = Command::new("hdiutil")
            .arg("attach")
            .arg(&self.img)
            .arg("-nobrowse")
            .output()
            .expect("run hdiutil attach");
        assert!(
            out.status.success(),
            "hdiutil attach failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        let text = String::from_utf8_lossy(&out.stdout).to_string();
        let mount = text
            .lines()
            .rev()
            .find_map(|l| l.find("/Volumes/").map(|i| l[i..].trim().to_string()))
            .map(PathBuf::from)
            .unwrap_or_else(|| panic!("no mount point in hdiutil attach output: {text}"));
        self.mount = Some(mount);
    }

    fn detach(&mut self) {
        if let Some(m) = self.mount.take() {
            let plain =
                Command::new("hdiutil").arg("detach").arg(&m).status().map(|s| s.success());
            if !plain.unwrap_or(false) {
                let _ = Command::new("hdiutil").args(["detach", "-force"]).arg(&m).status();
            }
        }
    }

    fn mount(&self) -> &Path {
        self.mount.as_deref().expect("volume attached")
    }
}

impl Drop for Volume {
    fn drop(&mut self) {
        self.detach();
    }
}

/// Scenario G. Ignored by default: it shells out to `hdiutil` (macOS-only,
/// slow, needs mount rights) — run it explicitly with
/// `cargo test -p skepd --test hazard -- --ignored g_disk_exhaustion`.
/// Honest by construction, never faked: a real volume really fills.
#[test]
#[ignore = "requires hdiutil (macOS) and mount rights; run with -- --ignored"]
fn g_disk_exhaustion_stops_acks_before_durability() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let mut vol = Volume::create_and_attach(tmp.path());
    let data = vol.mount().join("data");
    let ballast = vol.mount().join("ballast.bin");
    fs::write(&ballast, vec![0u8; 5 * 1024 * 1024]).expect("ballast");

    // The wire's string value form seats one Val PER BYTE, so each acked
    // insert occupies W positions and journals ~W bytes — small enough that
    // the volume fills over several commits, not one.
    const W: u64 = 8 * 1024;
    let chunk = "x".repeat(W as usize);
    let mut acks: Vec<u64> = Vec::new();
    let stop_code: String;
    let doc: String;
    {
        let d = Daemon::open(&data).expect("open on the tiny volume");
        let boot = route_session(&d, 0);
        let v = route_op(&d, Some(&boot), r#"{"op":"next_account_prefix","parent":"1"}"#);
        let prefix = expect_resp(&v, "maybe_addr")["addr"].as_str().expect("prefix").to_string();
        let v = route_op(
            &d,
            Some(&boot),
            &format!(r#"{{"op":"delegate","new_prefix":"{prefix}","new_id":1}}"#),
        );
        acks.push(v["at"].as_u64().expect("delegate at"));
        let account = acked_addr(&v);
        let s1 = route_session(&d, 1);
        let v = route_op(
            &d,
            Some(&s1),
            &format!(r#"{{"op":"create_new_document","account":"{account}"}}"#),
        );
        doc = acked_addr(&v);
        acks.push(v["at"].as_u64().expect("create at"));

        // Write until the volume refuses; the refusal must be TYPED
        // (`durability`, or `poisoned` if the tail truncation itself hit
        // the wall) — never an ack the disk cannot honor.
        let mut inserts_acked: u64 = 0;
        let mut consecutive = 0u32;
        stop_code = loop {
            let ord = inserts_acked * W + 1;
            let frame = format!(
                r#"{{"op":"insert","doc":"{doc}","at":{{"subspace":"1","ordinal":"{ord}"}},"values":["{chunk}"],"deposit":"{T_ENROLL}"}}"#
            );
            let v = route_op(&d, Some(&s1), &frame);
            match v["resp"].as_str() {
                Some("ack_addr") => {
                    acks.push(v["at"].as_u64().expect("insert at"));
                    inserts_acked += 1;
                    consecutive = 0;
                }
                Some("rejected") => {
                    let code = v["code"].as_str().unwrap_or("?").to_string();
                    assert!(
                        code == "durability" || code == "poisoned",
                        "FINDING (G): untyped/unexpected rejection under disk pressure: {v}"
                    );
                    consecutive += 1;
                    if consecutive >= 3 {
                        break code;
                    }
                }
                other => panic!("G: unexpected response {other:?}: {v}"),
            }
            assert!(inserts_acked < 4000, "G: the volume never filled — enlarge the ballast");
        };

        // Reads keep being served while the write path refuses.
        let h = route_raw(&d, "GET", "/health", None, None, b"");
        assert_eq!(h.status, 200, "reads must survive disk exhaustion");
        assert_eq!(read_text(&d, &doc, 1), "x", "content reads survive disk exhaustion");
    }

    // Free space, force the page cache out with a real remount, reopen,
    // and hold every ack.
    fs::remove_file(&ballast).expect("free the ballast");
    vol.detach();
    vol.attach();
    let data = vol.mount().join("data");
    let d = timed_daemon_open(&data, "G reopen after remount");
    let max_ack = *acks.iter().max().expect("acks");
    assert!(
        d.log_position().0 >= max_ack,
        "FINDING (G): acked write vanished after remount — head {} < acked {max_ack}",
        d.log_position().0
    );
    for &at in &acks {
        d.world_at(Seq(at)).unwrap_or_else(|e| {
            panic!("FINDING (G): acked position {at} unanswerable after remount: {e}")
        });
    }
    drop(d);
    println!(
        "G: {} acked writes; the write path stopped with typed '{}' rejections; every acked \
         position answered after remount",
        acks.len(),
        stop_code
    );
}

// ── H. The claim window (signed ops, s1) ─────────────────────────────────

/// The child's environment: the data dir of the board whose claim it is
/// killed inside. Set by the parent alone; its presence IS child mode.
const CLAIM_CRASH_DIR: &str = "SKEP_HAZARD_CLAIM_CRASH_DIR";

/// The claim link's committed position on a fresh board — the ceremony's
/// fifth commit (wire.md §A first board: positions 2, 3, 6, 9, 12).
const CLAIM_POSITION: u64 = 12;

/// `H.1`'s records above the claim: the staging draft's mint (1), the head
/// record's insert (3), the publish shot into `H` (4).
const H1_RECORDS: u64 = 8;

/// The kernel below the daemon's door, opened to LOOK and write nothing: a
/// manual checkpoint policy, the production retention, the salt unused by a
/// recover-only open. The judge's first witness, before `Daemon::open` is
/// allowed to repair anything.
fn kernel_below_the_door(dir: &Path) -> Engine {
    Engine::open(KernelConfig {
        durability: Durability::Fsync {
            journal_path: dir.to_path_buf(),
            retain_checkpoints: 2,
            burned_seq: BurnedSeqPolicy::Rollback,
        },
        checkpoint: CheckpointPolicy::Manual,
        salt: SaltSource::Seeded(0),
    })
    .expect("the crashed board's journal recovers below the door")
}

/// The child: a fresh unclaimed board served in-process, the daemon's hold
/// seam armed, the ceremony's first four steps, then the claim — whose
/// request the daemon holds at the crash window, announcing it on stderr
/// for the parent to kill. Never returns: the process dies under SIGKILL
/// inside the claim's request.
fn claim_crash_child(dir: &Path) -> ! {
    let sd = spawn_unclaimed(dir);
    let port = sd.port();
    sd.daemon().hold_between_the_claim_and_its_head();
    ceremony_before_the_claim(port);
    let signed = open_signed_session(port, CLAIMANT_PRINCIPAL, &device_key());
    // The claim, from the device's signed session (the ceremony's step 5),
    // posted through the non-panicking client: the answer never comes.
    let _ = try_op(port, Some(&signed), &claim_frame(CLAIMANT_DOC1, CLAIMANT_ACCOUNT));
    panic!("the claim answered: the daemon's hold seam did not hold");
}

/// H — A CRASH BETWEEN THE CLAIM AND ITS HEAD REOPENS TO A BOARD WITH `H.1`
/// (signed ops, s1: THE CLAIM WRITES `H.1`; the crash-window pin —
/// `Daemon::open` writes the first head of a claimed board whose journal
/// holds none, before it serves). The two are two transactions in one
/// serialized step, so a process that dies between them leaves the one
/// state in which the check's `board_unavailable` would otherwise answer
/// every attested write until the cadence's first head.
///
/// The pattern is the kernel hazard suite's scenario D: this test binary is
/// re-exec'd as a CHILD that serves a fresh board, arms the daemon's hold
/// seam (`Daemon::hold_between_the_claim_and_its_head`: the claim-flip tail
/// announces the window on stderr and parks, both locks held, after the
/// claim's commit is durable and the fold has flipped and before `H.1`'s
/// first commit opens), runs the ceremony and posts the claim. The parent
/// reads the announcement off the child's stderr and SIGKILLs it there. Then
/// it judges the data dir twice: BELOW THE DOOR the journal's head is the
/// claim's own position — the claim landed, no head did; THROUGH THE DOOR
/// the board is claimed, `H.1` stands at the claim's position with the
/// head's eight records above it and `prev` null, and — served — the board
/// takes an attested write at once, its slot filled. A third open writes
/// nothing: the repair is owed once.
#[test]
fn h_a_crash_between_the_claim_and_its_head_reopens_with_h1() {
    if let Some(dir) = std::env::var_os(CLAIM_CRASH_DIR) {
        claim_crash_child(Path::new(&dir));
    }
    let tmp = tempfile::tempdir().expect("tempdir");
    let dir = tmp.path().join("data");
    fs::create_dir_all(&dir).expect("data dir");

    // The child, killed at the window it announces.
    let exe = std::env::current_exe().expect("test binary path");
    let mut child = Command::new(exe)
        .args([
            "hazard::h_a_crash_between_the_claim_and_its_head_reopens_with_h1",
            "--exact",
            "--nocapture",
            "--test-threads=1",
        ])
        .env(CLAIM_CRASH_DIR, &dir)
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn the claim-crash child");
    let stderr = child.stderr.take().expect("child stderr");
    let (tx, rx) = mpsc::channel::<()>();
    let reader = thread::spawn(move || {
        for line in BufReader::new(stderr).lines() {
            let Ok(line) = line else { break };
            if line.contains(Daemon::CLAIM_HOLD_NOTICE) {
                let _ = tx.send(());
            } else {
                // The child's other notices, and a failing child's panic
                // message, land in this test's own output.
                eprintln!("[claim-crash child] {line}");
            }
        }
    });
    match rx.recv_timeout(Duration::from_secs(60)) {
        Ok(()) => {}
        Err(mpsc::RecvTimeoutError::Timeout) => {
            let _ = child.kill();
            panic!("FINDING (H): the child reached no hold within 60s — a wedge before the claim");
        }
        Err(mpsc::RecvTimeoutError::Disconnected) => {
            let _ = child.wait();
            panic!(
                "FINDING (H): the child exited before the hold — its stderr is forwarded above \
                 (a claim that answered means the seam did not hold)"
            );
        }
    }
    child.kill().expect("SIGKILL the held child");
    let _ = child.wait();
    reader.join().expect("stderr reader thread");

    // BELOW THE DOOR: the claim is the journal's last commit and no head's
    // record stands above it — the crash split the two transactions.
    {
        let engine = kernel_below_the_door(&dir);
        assert_eq!(
            engine.kernel().current_seq().0,
            CLAIM_POSITION,
            "FINDING (H): the crashed journal's head is not the claim's position"
        );
        drop(engine); // releases the journal-directory lock for the daemon
    }

    // THROUGH THE DOOR: the open writes `H.1` before it serves. Spawned with
    // the loopback origin configured, as every claimed fixture is, so the
    // signed arm admits the session below.
    let sd = spawn_configured(&dir, true);
    let port = sd.port();
    assert!(claimed(port), "the recovered fold is claimed");
    assert_eq!(
        head_position(port),
        CLAIM_POSITION + H1_RECORDS,
        "FINDING (H): the open did not write H.1's eight records above the claim"
    );
    let h1 = board_term(port).expect("FINDING (H): no H.1 after the reopen");
    assert_eq!(h1.log_position, CLAIM_POSITION, "H.1 names the claim's own position");
    let v = op(port, None, &common::retrieve_frame(HEAD_MEMBER_1, 1, 1));
    let atom = expect_resp(&v, "delivery")["items"][0]["atom"].as_str().expect("H.1's record");
    let rec: Value = serde_json::from_str(atom).expect("a skep-head record");
    assert!(rec["prev"].is_null(), "the first head: prev null: {rec}");
    assert!(rec["base"].is_null(), "no checkpoint: base null: {rec}");
    // Served, the board takes an attested write AT ONCE: a grant into the
    // published doc 1 from the claimant's signed session, its slot filled.
    let signed = open_signed_session(port, CLAIMANT_PRINCIPAL, &device_key());
    let v = op(port, Some(&signed), &typed_link_frame(CLAIMANT_DOC1, &[CLAIMANT_ACCOUNT], &[], T_GRANT));
    let at = acked_at(&v);
    assert!(
        sd.daemon().attestation_at(Seq(at)).expect("a boundary").is_some(),
        "the first attested write after the reopen is admitted and attested"
    );
    sd.shutdown();

    // A THIRD open writes nothing: `H.1` stands, the repair was owed once.
    let d = timed_daemon_open(&dir, "H: the reopen of a repaired board");
    assert_eq!(d.log_position().0, at, "a clean reopen of a headed board writes no head");
    let v = route_op(&d, None, &retrieve_frame("1.1.0.1.0.2.2", 1));
    assert_ne!(v["resp"].as_str(), Some("delivery"), "no H.2 was written: {v}");
}

// ── E′. The blob store under SIGKILL (media lane B) ──────────────────────

/// One whole PUT of `bytes` that treats every transport mishap — refused
/// connect, reset, partial response, a non-200 — as "no ack": the honest
/// client view while the daemon is being killed. A parsed 200 body comes
/// back whole. The one non-200 a client retries, `503 index_rebuilding` —
/// the cell index's walk at open unfinished — is retried here, bounded.
fn try_put(port: u16, token: &str, bytes: &[u8]) -> Option<Value> {
    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    loop {
        let mut s = TcpStream::connect(("127.0.0.1", port)).ok()?;
        let _ = s.set_nodelay(true);
        let _ = s.set_read_timeout(Some(Duration::from_secs(30)));
        let _ = s.set_write_timeout(Some(Duration::from_secs(30)));
        let head = format!(
            "POST {BLOB_UPLOAD}?length={} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\
             Content-Length: {}\r\nSkepd-Session: {token}\r\n\r\n",
            bytes.len(),
            bytes.len()
        );
        s.write_all(head.as_bytes()).ok()?;
        s.write_all(bytes).ok()?;
        let mut raw = Vec::new();
        s.read_to_end(&mut raw).ok()?;
        let sep = raw.windows(4).position(|w| w == b"\r\n\r\n")?;
        if raw.starts_with(b"HTTP/1.1 503 ")
            && String::from_utf8_lossy(&raw[sep + 4..]).contains("\"index_rebuilding\"")
            && std::time::Instant::now() < deadline
        {
            thread::sleep(Duration::from_millis(5));
            continue;
        }
        if !raw.starts_with(b"HTTP/1.1 200 ") {
            return None;
        }
        return serde_json::from_slice(&raw[sep + 4..]).ok();
    }
}

/// The principal's deposit read through the socket-free router, as
/// `(hash → (size, lapsed), the standing uploads' (id, offset))`.
fn deposit_read(d: &Daemon, token: &str) -> (std::collections::HashMap<String, (u64, bool)>, Vec<(String, u64)>) {
    let r = route_raw(d, "GET", BLOB_UPLOAD, None, Some(token), b"");
    assert_eq!(r.status, 200, "the deposit read: {}", String::from_utf8_lossy(r.bytes()));
    let v = json(r.bytes());
    let deposits = v["deposits"]
        .as_array()
        .expect("deposits")
        .iter()
        .map(|d| {
            (
                d["hash"].as_str().expect("hash").to_string(),
                (d["size"].as_u64().expect("size"), d["lapsed"].as_bool().expect("lapsed")),
            )
        })
        .collect();
    let uploads = v["uploads"]
        .as_array()
        .expect("uploads")
        .iter()
        .map(|u| (u["upload"].as_str().expect("upload").to_string(), u["offset"].as_u64().expect("offset")))
        .collect();
    (deposits, uploads)
}

/// THE STORE's INVARIANTS after a reopen, judged over the directory and
/// the principal's read together: every listed deposit is a whole file at
/// its hash; every standing upload's partial is exactly its offset long;
/// and no partial stands that no upload names.
fn judge_store_whole(d: &Daemon, dir: &Path, token: &str, ctx: &str) {
    let blake3_dir = dir.join("blobs").join("blake3");
    let (deposits, uploads) = deposit_read(d, token);
    for (hex, (size, lapsed)) in &deposits {
        assert!(!lapsed, "FINDING (E′, {ctx}): a listed deposit {hex} reads as lapsed");
        let bytes = fs::read(blake3_dir.join(hex))
            .unwrap_or_else(|e| panic!("FINDING (E′, {ctx}): a leased file {hex} is not there: {e}"));
        assert_eq!(bytes.len() as u64, *size, "FINDING (E′, {ctx}): {hex}'s length");
        assert_eq!(blob_hex(&bytes), *hex, "FINDING (E′, {ctx}): a leased file's bytes are not its hash's");
    }
    for (id, offset) in &uploads {
        let len = fs::metadata(blake3_dir.join(format!(".upload-{id}")))
            .unwrap_or_else(|e| panic!("FINDING (E′, {ctx}): a standing upload {id} has no partial: {e}"))
            .len();
        assert_eq!(len, *offset, "FINDING (E′, {ctx}): a partial's length is its record's offset");
    }
    if let Ok(entries) = fs::read_dir(&blake3_dir) {
        for e in entries {
            let name = e.expect("entry").file_name().to_string_lossy().into_owned();
            if let Some(id) = name.strip_prefix(".upload-") {
                assert!(
                    uploads.iter().any(|(u, _)| u == id),
                    "FINDING (E′, {ctx}): an orphan partial {name} stands after the reopen"
                );
            }
        }
    }
}

/// E′ — ACKED PUTs SURVIVE SIGKILL (M-I5 (a); the E program over the blob
/// store): the real binary under sustained whole-file PUT load is killed at
/// a seeded moment; after the reopen every acked PUT is listed to its
/// principal and whole on disk at its hash; at most one un-acked PUT
/// stands, as a leased whole file (the finish landed before the kill) or a
/// standing partial no longer than its bytes; and the store's invariants
/// hold whole.
#[test]
fn e_blob_acked_puts_survive_sigkill() {
    let trials: u64 = if exhaustive() { 24 } else { 8 };
    let mut total_acked = 0usize;
    let mut unacked_landed = 0usize;
    for trial in 0..trials {
        let (acked, landed) = e_blob_trial(trial);
        total_acked += acked;
        unacked_landed += landed;
    }
    println!(
        "E′: {trials} SIGKILL trials (seeds 0xB000+trial), {total_acked} acked PUTs verified whole \
         and listed, {unacked_landed} un-acked PUTs whose finish landed before the kill"
    );
}

fn e_blob_trial(trial: u64) -> (usize, usize) {
    let tmp = tempfile::tempdir().expect("tempdir");
    let dir = tmp.path().join("data");
    let (child, port) = spawn_skepd(&dir);
    let child = Arc::new(Mutex::new(child));
    // The board claimed over the wire (healthy: the killer waits on `go`).
    claim_board(port);
    let token = open_session(port, CLAIMANT_PRINCIPAL);

    let (go_tx, go_rx) = mpsc::channel::<()>();
    let killer = {
        let child = Arc::clone(&child);
        thread::spawn(move || {
            let _ = go_rx.recv();
            let mut rng = SplitMix64::new(0xB000 + trial);
            thread::sleep(Duration::from_millis(25 + rng.next_range(400)));
            let _ = child.lock().expect("child lock").kill();
        })
    };

    // Sustained whole-file PUTs of seeded bytes at seeded sizes.
    let mut rng = SplitMix64::new(0xB100 + trial);
    let mut acked: Vec<(String, Vec<u8>)> = Vec::new();
    go_tx.send(()).expect("killer is waiting");
    let mut i: u64 = 0;
    loop {
        i += 1;
        let n = 1 + rng.next_range(300 * 1024) as usize;
        let bytes = seeded_bytes(n, 0xB200 + trial * 100_000 + i);
        match try_put(port, &token, &bytes) {
            Some(v) => {
                assert_eq!(v["hash"].as_str(), Some(blob_hex(&bytes).as_str()), "E′ trial {trial}: the ack's hash");
                acked.push((blob_hex(&bytes), bytes));
            }
            None => break,
        }
        assert!(i < 100_000, "E′ trial {trial}: the killer never fired");
    }
    killer.join().expect("killer thread");
    {
        let mut c = child.lock().expect("child lock");
        let _ = c.kill();
        let _ = c.wait();
    }

    // Judge: reopen in-process.
    let ctx = format!("E′ trial {trial} (seed 0xB000+{trial}), {} acks", acked.len());
    let d = timed_daemon_open_with_the_index(&dir, &ctx);
    let token = route_session(&d, CLAIMANT_PRINCIPAL);
    let (deposits, uploads) = deposit_read(&d, &token);
    for (hex, bytes) in &acked {
        let (size, lapsed) = deposits
            .get(hex)
            .unwrap_or_else(|| panic!("FINDING (E′, {ctx}): acked PUT {hex} is not listed after reopen"));
        assert_eq!((*size, *lapsed), (bytes.len() as u64, false), "FINDING (E′, {ctx}): {hex}");
        let on_disk = fs::read(dir.join("blobs").join("blake3").join(hex))
            .unwrap_or_else(|e| panic!("FINDING (E′, {ctx}): acked PUT {hex} is not on disk: {e}"));
        assert_eq!(&on_disk, bytes, "FINDING (E′, {ctx}): acked PUT {hex}'s bytes");
    }
    // At most ONE un-acked PUT can have landed (the single in-flight
    // request at the kill), as a leased whole file; at most one partial.
    let landed = deposits.len().saturating_sub(acked.len());
    assert!(landed <= 1, "FINDING (E′, {ctx}): {landed} deposits past the acked set");
    assert!(uploads.len() <= 1, "FINDING (E′, {ctx}): {} standing uploads", uploads.len());
    judge_store_whole(&d, &dir, &token, &ctx);
    (acked.len(), landed)
}

// ── H′. A crash inside the finish (media lane B) ─────────────────────────

/// The child's environment: the data dir and the step the finish is held
/// at. Set by the parent alone; their presence IS child mode.
const BLOB_CRASH_DIR: &str = "SKEP_HAZARD_BLOB_CRASH_DIR";
const BLOB_CRASH_STEP: &str = "SKEP_HAZARD_BLOB_CRASH_STEP";

/// The bytes the held PUT carries at the steps past the rename, and at the
/// replace's link.
const HELD_BYTES: &[u8] = b"the bytes a crash inside the finish leaves behind";

/// The bytes the held PUT carries at `step`: at the two holds BEFORE THE
/// RENAME the body is sized to the partial's fsync grain, so the record's
/// offset — marked at the grain — stands where the crash story says it
/// does: exactly the length at `rename` (the finish's precondition met, the
/// EMPTY resume's case), and one grain short of the bytes written at
/// `partial_sync` (the last 100 bytes unmarked, an ordinary resume's
/// case); everywhere else the short fixture.
fn held_bytes(step: &str) -> Vec<u8> {
    match step {
        "rename" => seeded_bytes(skep_blobs::SYNC_GRAIN as usize, 0xE1),
        "partial_sync" => seeded_bytes(skep_blobs::SYNC_GRAIN as usize + 100, 0xE2),
        _ => HELD_BYTES.to_vec(),
    }
}

fn blob_step(name: &str) -> Step {
    match name {
        "partial_sync" => Step::PartialSync,
        "link_aside" => Step::LinkAside,
        "rename" => Step::Rename,
        "dir_sync" => Step::DirSync,
        "root_sync" => Step::RootSync,
        "record_retire" => Step::RecordRetire,
        "unlink_aside" => Step::UnlinkAside,
        other => panic!("no hold named {other}"),
    }
}

/// The child: a fresh board served in-process and claimed, the store's
/// hold seam armed at `step`, one whole PUT — whose finish parks at the
/// hold, announced on stderr for the parent to kill. At the two replace
/// steps, `link_aside` and the deferred `unlink_aside`, the name is put
/// once beforehand so the held PUT is a REPLACE; at the deferred step its
/// answer is written and the transport's thread parks in the deferred
/// unlink after it, so the child waits to be killed rather than reporting
/// the answer. Never returns.
fn blob_crash_child(dir: &Path, step: &str) -> ! {
    let sd = spawn_unclaimed(dir);
    let port = sd.port();
    claim_board(port);
    let token = open_session(port, CLAIMANT_PRINCIPAL);
    let bytes = held_bytes(step);
    if step == "unlink_aside" || step == "link_aside" {
        let first = try_put(port, &token, &bytes).expect("the first PUT, the name's");
        assert_eq!(first["hash"].as_str(), Some(blob_hex(&bytes).as_str()));
    }
    sd.daemon().hold_blob_finish_at(blob_step(step));
    let answered = try_put(port, &token, &bytes);
    if step == "unlink_aside" {
        // The replace answered — the hold is past the answer — and the
        // transport's worker parks; this thread waits for the kill.
        let _ = answered;
        loop {
            thread::park();
        }
    }
    panic!("the PUT answered: the blob store's hold seam did not hold");
}

/// H′ — A CRASH INSIDE THE FINISH REOPENS TO WHAT THE ORDER PROMISES
/// (M-I5 (a); M-I5 (c), the finish cut before its rename; `media.md` Op
/// inventory 1, the lease's crash story: "a crash leaves at worst a blob
/// with no lease, unreferenced and prunable, and never a lease naming bytes
/// that are not there"; clause (7): "a crash anywhere in the finish leaves
/// at worst a record that open's reconciliation retires, beside a file the
/// lease holds or the pruner may take" — and before the rename, "the
/// upload standing over its partial, which a resume at its record's offset
/// finishes, an empty one where that offset is its total"; mb-K2, the
/// replaced instance retired after the answer). Seven children, each
/// killed at a named hold — BEFORE THE PARTIAL's FSYNC (the body one grain
/// and a hundred bytes, the record's offset at the grain), BEFORE THE
/// REPLACE's LINK (the name present), BEFORE THE RENAME (the body exactly
/// one grain, the record's offset at the length), BEFORE THE DIRECTORY
/// FSYNC (between the rename and the directory's sync), BEFORE THE ROOT
/// FSYNC (after the first rename into a designation directory this process
/// created), BEFORE THE RECORD's RETIREMENT (after the lease's sync), and
/// at THE DEFERRED UNLINK of a replace's aside, after the answer — and the
/// reopen judged: at the three before the rename the upload STANDS over
/// its partial, cut back to its record's offset — at `rename` the offset
/// IS the length, the progress read says so, and an EMPTY resume at it
/// finishes and binds with no byte re-sent; at `partial_sync` the offset
/// lags one grain and an ordinary resume re-sends the hundred bytes past
/// it; at `link_aside` the first instance stands whole under its lease and
/// the held PUT's resume replaces it — at the two past the rename the
/// un-acked PUT is ABSENT from its principal's view (no lease, the file on
/// disk leaseless and prunable, its cell refused `unbound_cell`, its record
/// retired by the reconciliation), and a re-PUT of the bytes answers and
/// binds; at the retirement the lease stands over a whole file — the
/// finish's one residue — listed, its cell admitted, its record retired; at
/// the deferred unlink the reopen removes the aside, and the hash answers
/// whole under its lease. No partial stands after any of the seven once
/// the resumes have finished.
#[test]
fn h_a_crash_inside_the_blob_finish_reopens_to_what_the_order_promises() {
    if let (Some(dir), Ok(step)) = (std::env::var_os(BLOB_CRASH_DIR), std::env::var(BLOB_CRASH_STEP)) {
        blob_crash_child(Path::new(&dir), &step);
    }
    for step in ["partial_sync", "link_aside", "rename", "dir_sync", "root_sync", "record_retire", "unlink_aside"] {
        let bytes = held_bytes(step);
        let hex = blob_hex(&bytes);
        let tmp = tempfile::tempdir().expect("tempdir");
        let dir = tmp.path().join("data");
        fs::create_dir_all(&dir).expect("data dir");
        let exe = std::env::current_exe().expect("test binary path");
        let mut child = Command::new(exe)
            .args([
                "hazard::h_a_crash_inside_the_blob_finish_reopens_to_what_the_order_promises",
                "--exact",
                "--nocapture",
                "--test-threads=1",
            ])
            .env(BLOB_CRASH_DIR, &dir)
            .env(BLOB_CRASH_STEP, step)
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn the blob-crash child");
        let stderr = child.stderr.take().expect("child stderr");
        let (tx, rx) = mpsc::channel::<()>();
        let reader = thread::spawn(move || {
            for line in BufReader::new(stderr).lines() {
                let Ok(line) = line else { break };
                if line.contains(Daemon::BLOB_HOLD_NOTICE) {
                    let _ = tx.send(());
                } else {
                    eprintln!("[blob-crash child {step}] {line}");
                }
            }
        });
        match rx.recv_timeout(Duration::from_secs(60)) {
            Ok(()) => {}
            Err(mpsc::RecvTimeoutError::Timeout) => {
                let _ = child.kill();
                panic!("FINDING (H′ {step}): the child reached no hold within 60s");
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                let _ = child.wait();
                panic!("FINDING (H′ {step}): the child exited before the hold — its stderr is forwarded above");
            }
        }
        child.kill().expect("SIGKILL the held child");
        let _ = child.wait();
        reader.join().expect("stderr reader thread");

        // THE REOPEN, judged.
        let ctx = format!("H′ {step}");
        let d = timed_daemon_open_with_the_index(&dir, &ctx);
        let token = route_session(&d, CLAIMANT_PRINCIPAL);
        let file = dir.join("blobs").join("blake3").join(&hex);
        let (deposits, uploads) = deposit_read(&d, &token);
        let draft = acked_addr(&route_op(&d, Some(&token), &create_frame(CLAIMANT_ACCOUNT, Some(false))));
        let insert = |d: &Daemon| {
            let frame = serde_json::json!({
                "op": "insert", "doc": draft, "at": {"subspace": "1", "ordinal": "1"},
                "values": [{"atom": cell_of(&bytes, bytes.len() as u64)}],
            })
            .to_string();
            verdict(&route_op(d, Some(&token), &frame))
        };
        // The resume of a standing upload from `offset` with `body`: the
        // finish's answer where the offset reaches the length.
        let resume = |d: &Daemon, id: &str, offset: u64, body: &[u8]| -> Value {
            let r = route_raw(d, "PATCH", &format!("{BLOB_UPLOAD}/{id}"), Some(&format!("offset={offset}")), Some(&token), body);
            assert_eq!(r.status, 200, "{ctx}: the resume at {offset}: {}", String::from_utf8_lossy(r.bytes()));
            json(r.bytes())
        };
        match step {
            "partial_sync" | "rename" | "link_aside" => {
                // BEFORE THE RENAME: the upload stands over its partial at
                // its record's offset (M-I5 (c)), no lease of this PUT's
                // names the hash, and the resume at that offset finishes.
                let [(id, offset)] = uploads.as_slice() else {
                    panic!("FINDING ({ctx}): the upload stands over its partial after a crash before the rename: {uploads:?}")
                };
                let partial = dir.join("blobs").join("blake3").join(format!(".upload-{id}"));
                assert_eq!(fs::metadata(&partial).expect("the partial").len(), *offset, "{ctx}: the partial cut back to the record's offset");
                let r = route_raw(&d, "GET", &format!("{BLOB_UPLOAD}/{id}"), None, Some(&token), b"");
                assert_eq!(json(r.bytes())["offset"].as_u64(), Some(*offset), "{ctx}: the progress read answers the offset");
                let (expected_offset, before) = match step {
                    // The record's offset IS the length: the EMPTY resume.
                    "rename" => (bytes.len() as u64, deposits.len()),
                    // One grain marked, a hundred bytes past it unmarked.
                    "partial_sync" => (skep_blobs::SYNC_GRAIN, deposits.len()),
                    // The replace's held PUT: nothing marked (the body is
                    // under a grain); the first instance stands leased.
                    _ => {
                        assert!(file.is_file(), "{ctx}: the first instance stands at the name");
                        assert_eq!(deposits.get(&hex), Some(&(bytes.len() as u64, false)), "{ctx}: the first PUT's lease stands: {deposits:?}");
                        (0, deposits.len())
                    }
                };
                assert_eq!(*offset, expected_offset, "FINDING ({ctx}): the record's offset is where the grain marked it");
                if step != "link_aside" {
                    assert!(!file.is_file(), "{ctx}: no file at the hash before the rename");
                    assert!(deposits.is_empty(), "FINDING ({ctx}): a lease names bytes the rename never installed: {deposits:?}");
                    assert_eq!(insert(&d), "credential_refused:unbound_cell", "{ctx}: absent from the principal's view");
                }
                let remaining = &bytes[*offset as usize..];
                let answer = resume(&d, id, *offset, remaining);
                assert_eq!(answer["hash"].as_str(), Some(hex.as_str()), "FINDING ({ctx}): the resume of {} bytes finishes with the whole file's hash: {answer}", remaining.len());
                if step == "rename" {
                    assert!(remaining.is_empty(), "{ctx}: the empty resume re-sent nothing");
                }
                let (deposits, uploads) = deposit_read(&d, &token);
                assert!(uploads.is_empty(), "{ctx}: finished, the record is retired");
                assert_eq!(deposits.get(&hex), Some(&(bytes.len() as u64, false)), "{ctx}: leased: {deposits:?}");
                assert_eq!(deposits.len(), before.max(1), "{ctx}: one deposit per hash per account");
                assert_eq!(fs::read(&file).expect("the file"), bytes, "{ctx}: the file whole");
                assert!(!partial.exists(), "{ctx}: the partial renamed away");
                assert_eq!(insert(&d), "ok", "{ctx}: bound by the resume");
            }
            "dir_sync" | "root_sync" => {
                assert!(uploads.is_empty(), "FINDING ({ctx}): the record whose partial was renamed away is retired at open: {uploads:?}");
                // The rename survives a SIGKILL (the page cache holds it);
                // what the order promises is that nothing NAMES it.
                assert!(file.is_file(), "{ctx}: the renamed file stands on disk, leaseless");
                assert!(deposits.is_empty(), "FINDING ({ctx}): a lease names a file whose directory sync never ran: {deposits:?}");
                assert_eq!(insert(&d), "credential_refused:unbound_cell", "{ctx}: absent from the principal's view");
                // The repair: a re-PUT of the bytes through the socket-free
                // route answers the hash and binds.
                let r = route_raw(&d, "POST", BLOB_UPLOAD, Some(&format!("length={}", bytes.len())), Some(&token), &bytes);
                assert_eq!(r.status, 200, "{ctx}: the re-PUT: {}", String::from_utf8_lossy(r.bytes()));
                assert_eq!(json(r.bytes())["hash"].as_str(), Some(hex.as_str()));
                let (deposits, _) = deposit_read(&d, &token);
                assert_eq!(deposits.get(&hex), Some(&(bytes.len() as u64, false)));
                assert_eq!(insert(&d), "ok", "{ctx}: bound by the re-PUT");
            }
            "unlink_aside" => {
                assert!(uploads.is_empty(), "FINDING ({ctx}): the replace's record is retired: {uploads:?}");
                assert!(file.is_file(), "{ctx}: the hash stands");
                assert_eq!(fs::read(&file).expect("the file"), bytes, "FINDING ({ctx}): the hash answers the new bytes whole");
                assert_eq!(deposits.get(&hex), Some(&(bytes.len() as u64, false)), "FINDING ({ctx}): the replace's lease stands: {deposits:?}");
                let asides = fs::read_dir(dir.join("blobs").join("blake3"))
                    .expect("the designation directory")
                    .filter(|e| e.as_ref().unwrap().file_name().to_string_lossy().starts_with(".retired-"))
                    .count();
                assert_eq!(asides, 0, "FINDING ({ctx}): the reopen removes the aside a crash before the deferred unlink left");
                assert_eq!(insert(&d), "ok", "{ctx}: the cell is admitted under the lease");
            }
            _ => {
                assert!(uploads.is_empty(), "FINDING ({ctx}): the record whose partial was renamed away is retired at open: {uploads:?}");
                assert!(file.is_file(), "{ctx}: the leased file stands");
                assert_eq!(deposits.get(&hex), Some(&(bytes.len() as u64, false)), "FINDING ({ctx}): the lease that synced before the kill stands over a whole file: {deposits:?}");
                assert_eq!(insert(&d), "ok", "{ctx}: the finish's one residue is a bound deposit");
            }
        }
        judge_store_whole(&d, &dir, &token, &ctx);
    }
}

// ── P′. A crash inside the pruner's pass ─────────────────────────────────

/// The child's environment for the pruner's crash: the data dir alone;
/// its presence IS child mode.
const PRUNE_CRASH_DIR: &str = "SKEP_HAZARD_PRUNE_CRASH_DIR";

/// The four files the pruner's crash child deposits: one a cell names,
/// two lapsed and unreferenced, one under a live lease.
fn prune_crash_files() -> [Vec<u8>; 4] {
    [seeded_bytes(50_000, 0xC1), seeded_bytes(50_001, 0xC2), seeded_bytes(50_002, 0xC3), seeded_bytes(50_003, 0xC4)]
}

/// The child: a fresh board served in-process and claimed; three files
/// deposited under a one-second lease — the first named by a cell — and a
/// fourth under the default lease; the leases lapsed by the wall clock;
/// the pass's hold armed after its first unlink; the pass run on a thread
/// of its own, which parks there, announced on stderr for the parent to
/// kill. Never returns.
fn prune_crash_child(dir: &Path) -> ! {
    let sd = spawn_unclaimed(dir);
    let port = sd.port();
    claim_board(port);
    let token = open_session(port, CLAIMANT_PRINCIPAL);
    let [referenced, lapsed_a, lapsed_b, live] = prune_crash_files();
    sd.daemon().install_media_limits(None, None, Some(1_000), None);
    for bytes in [&referenced, &lapsed_a, &lapsed_b] {
        try_put(port, &token, bytes).expect("a PUT on a healthy daemon");
    }
    let draft = acked_addr(&op(port, Some(&token), &create_frame(CLAIMANT_ACCOUNT, Some(false))));
    let frame = serde_json::json!({
        "op": "insert", "doc": draft, "at": {"subspace": "1", "ordinal": "1"},
        "values": [{"atom": cell_of(&referenced, referenced.len() as u64)}],
    })
    .to_string();
    assert_eq!(verdict(&op(port, Some(&token), &frame)), "ok");
    sd.daemon().install_media_limits(None, None, None, None);
    try_put(port, &token, &live).expect("a PUT on a healthy daemon");
    thread::sleep(Duration::from_millis(1_200));
    sd.daemon().hold_the_prune_pass_after_a_rename();
    let daemon: &'static Daemon = unsafe_leak(sd);
    thread::spawn(move || {
        let _ = daemon.prune_now();
    });
    loop {
        thread::park();
    }
}

/// The served daemon leaked for the life of the child, so the pass's
/// thread can borrow it past this thread's park — the child exists to be
/// killed and frees nothing.
fn unsafe_leak(sd: skepd::Skepd) -> &'static Daemon {
    let sd: &'static skepd::Skepd = Box::leak(Box::new(sd));
    sd.daemon()
}

/// P′ — A CRASH INSIDE THE PRUNER's PASS, between a rename aside and its
/// unlink (M-I5 (b); Op inventory 2, "ONE FILE PER ACQUISITION — re-read,
/// rename aside, release, the aside unlinked after under no arm"): the
/// child is killed with its pass parked after its first rename aside — the
/// arm released, the aside standing, nothing naming it; the reopen removes
/// the aside, and its index and store agree — the file a cell names stands
/// and its base counts it, the file under a live lease stands and is
/// listed, of the two lapsed and unreferenced files at most one is gone, no
/// partial stands — and no acked PUT a lease holds is lost; the reopened
/// daemon's own pass then takes the other lapsed file and keeps the two.
#[test]
fn p_a_crash_inside_the_pruners_pass_reopens_to_an_index_and_a_store_that_agree() {
    if let Some(dir) = std::env::var_os(PRUNE_CRASH_DIR) {
        prune_crash_child(Path::new(&dir));
    }
    let tmp = tempfile::tempdir().expect("tempdir");
    let dir = tmp.path().join("data");
    fs::create_dir_all(&dir).expect("data dir");
    let exe = std::env::current_exe().expect("test binary path");
    let mut child = Command::new(exe)
        .args([
            "hazard::p_a_crash_inside_the_pruners_pass_reopens_to_an_index_and_a_store_that_agree",
            "--exact",
            "--nocapture",
            "--test-threads=1",
        ])
        .env(PRUNE_CRASH_DIR, &dir)
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn the prune-crash child");
    let stderr = child.stderr.take().expect("child stderr");
    let (tx, rx) = mpsc::channel::<()>();
    let reader = thread::spawn(move || {
        for line in BufReader::new(stderr).lines() {
            let Ok(line) = line else { break };
            if line.contains(Daemon::PRUNE_HOLD_NOTICE) {
                let _ = tx.send(());
            } else {
                eprintln!("[prune-crash child] {line}");
            }
        }
    });
    match rx.recv_timeout(Duration::from_secs(90)) {
        Ok(()) => {}
        Err(mpsc::RecvTimeoutError::Timeout) => {
            let _ = child.kill();
            panic!("FINDING (P′): the child reached no hold within 90s");
        }
        Err(mpsc::RecvTimeoutError::Disconnected) => {
            let _ = child.wait();
            panic!("FINDING (P′): the child exited before the hold — its stderr is forwarded above");
        }
    }
    child.kill().expect("SIGKILL the held child");
    let _ = child.wait();
    reader.join().expect("stderr reader thread");

    // THE ASIDE the kill left: the pass renamed one lapsed file aside under
    // the arm and parked before unlinking it.
    let blobs = dir.join("blobs").join("blake3");
    let asides = || -> usize {
        fs::read_dir(&blobs)
            .expect("the designation directory")
            .filter(|e| e.as_ref().unwrap().file_name().to_string_lossy().starts_with(".retired-"))
            .count()
    };
    assert_eq!(asides(), 1, "FINDING (P′): the pass parked after its rename aside leaves exactly that aside");

    // THE REOPEN, judged.
    let ctx = "P′";
    let d = timed_daemon_open_with_the_index(&dir, ctx);
    assert_eq!(asides(), 0, "FINDING (P′): the reopen removes the aside the crash left");
    let token = route_session(&d, CLAIMANT_PRINCIPAL);
    let [referenced, lapsed_a, lapsed_b, live] = prune_crash_files();
    assert!(blobs.join(blob_hex(&referenced)).is_file(), "FINDING ({ctx}): the file a cell names was unlinked");
    assert!(blobs.join(blob_hex(&live)).is_file(), "FINDING ({ctx}): the file under a live lease was unlinked");
    let standing = [&lapsed_a, &lapsed_b].iter().filter(|b| blobs.join(blob_hex(b)).is_file()).count();
    assert!(standing <= 1, "{ctx}: the pass unlinked one before the hold");
    let (deposits, uploads) = deposit_read(&d, &token);
    assert_eq!(deposits.get(&blob_hex(&live)), Some(&(live.len() as u64, false)), "FINDING ({ctx}): the live lease is listed over a whole file: {deposits:?}");
    assert!(uploads.is_empty(), "no partial stands: {uploads:?}");
    let r = route_raw(&d, "GET", BLOB_UPLOAD, None, Some(&token), b"");
    assert_eq!(json(r.bytes())["base"].as_u64(), Some(referenced.len() as u64), "FINDING ({ctx}): the reopen's index counts the named hash");
    assert_eq!(d.index_counts(), (1, 1, 0));
    judge_store_whole(&d, &dir, &token, ctx);
    // The reopened daemon's own pass: the other lapsed file goes, the two
    // stand.
    let pass = d.prune_now().expect("ready");
    assert_eq!(pass.unlinked, standing, "{pass:?}");
    assert_eq!(pass.kept, 2, "{pass:?}");
    assert!(blobs.join(blob_hex(&referenced)).is_file());
    assert!(blobs.join(blob_hex(&live)).is_file());
    assert!(!blobs.join(blob_hex(&lapsed_a)).exists() && !blobs.join(blob_hex(&lapsed_b)).exists());
}
