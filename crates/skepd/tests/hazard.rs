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
//!
//! Finding protocol (per the H3 ruling): a test that discovers a real
//! violation is converted to `#[ignore = "FINDING-<n>: …"]` with its
//! assertion INTACT and the reproduction in a comment block — never
//! weakened, never left failing.

mod common;

use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{mpsc, Arc, Mutex};
use std::thread;
use std::time::Duration;

use common::{acked_addr, expect_resp, json, op, open_session};
use serde_json::Value;
use skep_kernel::Seq;
use skepd::{Daemon, HttpRequest, Reply, Routed};

/// `HAZARD_EXHAUSTIVE=1` widens the trial counts.
fn exhaustive() -> bool {
    std::env::var_os("HAZARD_EXHAUSTIVE").is_some_and(|v| v == "1")
}

/// SplitMix64 — deterministic; the trial index is the whole reproduction.
struct Lcg(u64);

impl Lcg {
    fn new(seed: u64) -> Lcg {
        Lcg(seed ^ 0x9E37_79B9_7F4A_7C15)
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
fn spawn_skepd(dir: &Path) -> (Child, u16) {
    let mut child = Command::new(env!("CARGO_BIN_EXE_skepd"))
        .arg("--data-dir")
        .arg(dir)
        .args(["--port", "0", "--workers", "4"])
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
fn try_op(port: u16, session: Option<&str>, frame: &str) -> Option<Value> {
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
    if let Some(tok) = session {
        head.push_str(&format!("Skepd-Session: {tok}\r\n"));
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

/// Route one request through the socket-free router; the event stream is
/// unreachable from these paths.
fn handle_raw(
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
        body: body.to_vec(),
    };
    match d.handle(&req) {
        Routed::Reply(r) => r,
        Routed::EventStream => unreachable!("no test route resolves to the event stream"),
    }
}

/// `POST /op` via the router; transport must be 200 (the returned document
/// may still be a rejection — callers decide).
fn handle_op(d: &Daemon, session: Option<&str>, frame: &str) -> Value {
    let r = handle_raw(d, "POST", "/op", None, session, frame.as_bytes());
    assert_eq!(r.status, 200, "op transport failed: {}", String::from_utf8_lossy(&r.body));
    json(&r.body)
}

fn handle_session(d: &Daemon, principal: u64) -> String {
    let r = handle_raw(
        d,
        "POST",
        "/session",
        None,
        None,
        format!("{{\"principal\":{principal}}}").as_bytes(),
    );
    assert_eq!(r.status, 200, "session open failed: {}", String::from_utf8_lossy(&r.body));
    json(&r.body)["session"].as_str().expect("session token").to_string()
}

fn retrieve_frame(doc: &str, width: u64) -> String {
    format!(
        r#"{{"op":"retrieve_v","specs":[{{"doc":"{doc}","span":{{"start":"1.1","width":"0.{width}"}}}}]}}"#
    )
}

/// Concatenated delivery text via the router (panics on a rejection).
fn read_text(d: &Daemon, doc: &str, width: u64) -> String {
    let v = handle_op(d, None, &retrieve_frame(doc, width));
    expect_resp(&v, "delivery")["items"]
        .as_array()
        .expect("delivery items")
        .iter()
        .map(|i| i["content"].as_str().unwrap_or(""))
        .collect()
}

/// `GET /changes?since=0` entries as `(at, entry)` pairs.
fn changes_entries(d: &Daemon) -> Vec<(u64, Value)> {
    let r = handle_raw(d, "GET", "/changes", Some("since=0"), None, b"");
    assert_eq!(r.status, 200, "/changes failed: {}", String::from_utf8_lossy(&r.body));
    let v = json(&r.body);
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
            let mut rng = Lcg::new(0xE000 + trial);
            thread::sleep(Duration::from_millis(25 + rng.next_range(275)));
            let _ = child.lock().expect("child lock").kill();
        })
    };

    // Sustained sequential write load: one distinct byte per ordinal, each
    // ack recorded — the ground truth the reopened world must honor.
    let expect_char = |i: u64| char::from(b'a' + ((i - 1) % 26) as u8);
    let mut inserts_acked: u64 = 0;
    go_tx.send(()).expect("killer is waiting");
    let mut i: u64 = 0;
    loop {
        i += 1;
        let frame = format!(
            r#"{{"op":"insert","doc":"{doc}","at":{{"subspace":"1","ordinal":"{i}"}},"values":["{}"]}}"#,
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
    let probe = handle_op(&d, None, &retrieve_frame(&doc, k + 1));
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
    let beyond = handle_op(&d, None, &retrieve_frame(&doc, k + 2));
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
        let boot = handle_session(&d, 0);
        let v = handle_op(&d, Some(&boot), r#"{"op":"next_account_prefix","parent":"1"}"#);
        let prefix = expect_resp(&v, "maybe_addr")["addr"].as_str().expect("prefix").to_string();
        let v = handle_op(
            &d,
            Some(&boot),
            &format!(r#"{{"op":"delegate","new_prefix":"{prefix}","new_id":1}}"#),
        );
        acks.push(v["at"].as_u64().expect("delegate at"));
        let account = acked_addr(&v);
        let s1 = handle_session(&d, 1);
        let v = handle_op(
            &d,
            Some(&s1),
            &format!(r#"{{"op":"create_new_document","account":"{account}"}}"#),
        );
        doc = acked_addr(&v);
        acks.push(v["at"].as_u64().expect("create at"));
        for i in 1..=5u64 {
            let ch = char::from(b'a' + (i - 1) as u8);
            let v = handle_op(
                &d,
                Some(&s1),
                &format!(
                    r#"{{"op":"insert","doc":"{doc}","at":{{"subspace":"1","ordinal":"{i}"}},"values":["{ch}"]}}"#
                ),
            );
            acks.push(v["at"].as_u64().expect("insert at"));
        }
        let r = handle_raw(&d, "POST", "/op", None, None, retrieve_frame(&doc, 5).as_bytes());
        assert_eq!(r.status, 200);
        pre_retrieve = r.body;
    }
    let head = *acks.last().expect("acks");
    let sidecar = |dir: &Path| dir.join("commits.log");
    let sidecar_len = fs::metadata(sidecar(&fixture)).expect("commits.log").len();

    // The world-intact judge: recovery byte-identical (as_of included) and
    // `/changes` still enumerating exactly the committed positions.
    let judge_world_intact = |dir: &Path, ctx: &str| -> Daemon {
        let d = timed_daemon_open(dir, ctx);
        assert_eq!(d.log_position().0, head, "{ctx}: the head must be untouched");
        let r = handle_raw(&d, "POST", "/op", None, None, retrieve_frame(&doc, 5).as_bytes());
        assert_eq!(r.status, 200);
        assert_eq!(
            r.body, pre_retrieve,
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
        let h = handle_raw(&d, "GET", "/health", None, None, b"");
        assert!(!json(&h.body)["head_time"].is_null(), "control: head_time is recorded");
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
        assert!(
            last["op"].is_null() && last["time"].is_null() && last["docs"].is_null(),
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
        assert!(last["op"].is_null(), "halved: the tail region answers bare (entry {last_at}): {last}");
    }

    // Whole file garbage: everything bare, head_time null.
    {
        let case = base.path().join("garbage");
        copy_dir(&fixture, &case);
        fs::write(sidecar(&case), vec![0xFFu8; sidecar_len as usize]).expect("garbage sidecar");
        let d = judge_world_intact(&case, "F sidecar garbage");
        for (at, e) in changes_entries(&d) {
            assert!(
                e["op"].is_null() && e["time"].is_null() && e["docs"].is_null(),
                "garbage: entry {at} must be bare, never invented: {e}"
            );
        }
        let h = handle_raw(&d, "GET", "/health", None, None, b"");
        assert!(
            json(&h.body)["head_time"].is_null(),
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
            assert!(e["op"].is_null(), "deleted: entry {at} must be bare: {e}");
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
        let boot = handle_session(&d, 0);
        let v = handle_op(&d, Some(&boot), r#"{"op":"next_account_prefix","parent":"1"}"#);
        let prefix = expect_resp(&v, "maybe_addr")["addr"].as_str().expect("prefix").to_string();
        let v = handle_op(
            &d,
            Some(&boot),
            &format!(r#"{{"op":"delegate","new_prefix":"{prefix}","new_id":1}}"#),
        );
        acks.push(v["at"].as_u64().expect("delegate at"));
        let account = acked_addr(&v);
        let s1 = handle_session(&d, 1);
        let v = handle_op(
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
                r#"{{"op":"insert","doc":"{doc}","at":{{"subspace":"1","ordinal":"{ord}"}},"values":["{chunk}"]}}"#
            );
            let v = handle_op(&d, Some(&s1), &frame);
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
        let h = handle_raw(&d, "GET", "/health", None, None, b"");
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
