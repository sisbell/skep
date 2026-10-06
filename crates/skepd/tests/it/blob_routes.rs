//! MEDIA LANE B — THE PUT over the wire: the resumable upload's seven
//! clauses as vectors (`fixtures/media/uploads.json`, the vector set's
//! second file, PATTERNS P5 — one set, run here against the daemon and by
//! a client suite against its own implementation of the shape) — the
//! default per-account limit's echo, the floor at the creation and the
//! standing-uploads bound, the finish's empty resume and the closed board
//! among them — the H1 presence cells, the identifier on the one request,
//! a dropped connection's kept upload, the fence before the claim, the
//! closed board's kept upload, the upload family's log, the RSS bound
//! under a PUT at the cap, and ms4-K2's timing — reported, not asserted
//! (the board's sm-Q4).
//!
//! Every test names the register's clause it holds: M-I2 (e) THE
//! REQUESTER'S OWN RECORD BEFORE ANY SHARED FACT; M-I5 (a) DURABLE BEFORE
//! NAMED, ANSWERED AFTER RECORDED; M-I5 (c) THE DEPOSIT RECORD IS THE
//! PRINCIPAL'S, READABLE, EXACT; M-I5 (f) PICTURES NEVER STARVE OR STALL
//! THE JOURNAL; M-I6 (a) at its ZERO BASE; M-I6 (b) THE OWN SCOPE BOUNDS
//! THE DISK; M-I6 (d) THE LIMITS ARE ONE PUBLISHED RECORD; M-I6 (e)
//! REFUSED BEFORE THE BYTES MOVE; M-I6 (f) THE FLOOR IS THE HOST'S; M-I6
//! (h) THE REFUSAL'S FACE; M-I7 (e) A FACE NAMES AN ACT THE PERSON HOLDS;
//! D9 at the upload family's log.

use std::collections::{BTreeSet, HashMap};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{Shutdown, TcpStream};
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use serde_json::Value;
use skep_blobs::Step;

use crate::common;
use common::*;

fn fixture() -> Value {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/it/fixtures/media/uploads.json");
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()));
    serde_json::from_str(&text).expect("the fixture is JSON")
}

/// A step's body: a string's UTF-8, seeded bytes — from an offset `from`
/// where one is named, the tail a resume re-sends — or none.
fn body_of(v: &Value) -> Vec<u8> {
    match v {
        Value::Null => Vec::new(),
        Value::String(s) => s.as_bytes().to_vec(),
        Value::Object(o) => {
            let whole = seeded_bytes(
                o["bytes"].as_u64().expect("bytes") as usize,
                o["seed"].as_u64().expect("seed"),
            );
            let from = o.get("from").and_then(Value::as_u64).unwrap_or(0) as usize;
            whole[from..].to_vec()
        }
        other => panic!("a body is a string or {{bytes, seed[, from]}}: {other}"),
    }
}

/// A finish step by the fixture's name — the store's own seam.
fn finish_step(name: &str) -> Step {
    match name {
        "partial_sync" => Step::PartialSync,
        "link_aside" => Step::LinkAside,
        "rename" => Step::Rename,
        "dir_sync" => Step::DirSync,
        "root_sync" => Step::RootSync,
        "lease_sync" => Step::LeaseSync,
        "record_retire" => Step::RecordRetire,
        "unlink_aside" => Step::UnlinkAside,
        other => panic!("no finish step named {other}"),
    }
}

/// THE DEFAULT PER-ACCOUNT LIMIT as the fixture's `per_account: "default"`
/// expects it: one eighth of the capacity the daemon read at its open,
/// never below 256 MiB — the suite's own arithmetic over the same read.
fn default_limit(sd: &skepd::Skepd) -> u64 {
    let floor = 256 * 1024 * 1024;
    sd.daemon().media_capacity().map_or(floor, |c| (c / 8).max(floor))
}

/// THE PRINCIPALS a vector acts as: the claimant, a stranger seated as an
/// account, principal 0 (node tier), and the guest.
struct Cast {
    port: u16,
    a: String,
    b: Seat,
    boot: String,
}

impl Cast {
    fn new(port: u16) -> Cast {
        let a = open_session(port, CLAIMANT_PRINCIPAL);
        let b = seat_stranger(port, 971);
        let boot = open_session(port, 0);
        Cast { port, a, b, boot }
    }

    fn token(&self, who: &str) -> Option<&str> {
        match who {
            "a" => Some(&self.a),
            "b" => Some(&self.b.session),
            "boot" => Some(&self.boot),
            "guest" => None,
            other => panic!("no principal named {other}"),
        }
    }

    /// A fresh draft of `who`'s, to insert a cell into.
    fn draft(&self, who: &str) -> String {
        match who {
            "a" => owner_draft(self.port, &self.a),
            "b" => create_doc(self.port, &self.b.session, &self.b.account),
            other => panic!("{other} owns no draft"),
        }
    }
}

/// The interpreter's state across one vector's steps: the identifiers
/// bound by name, the bytes each upload has received (the whole file the
/// finish's hash covers), the expiries bound by name, and the open
/// streams.
#[derive(Default)]
struct Scene {
    uploads: HashMap<String, String>,
    bytes: HashMap<String, Vec<u8>>,
    expires: HashMap<String, u64>,
    streams: HashMap<String, (TcpStream, String)>,
    /// The default per-account limit the daemon under test computed.
    default_limit: u64,
}

impl Scene {
    fn id(&self, name: &str) -> String {
        self.uploads.get(name).cloned().unwrap_or_else(|| name.to_string())
    }
}

/// Judge one exchange against a step's `expect`.
fn judge(step: &Value, name: &str, scene: &mut Scene, status: u16, body: &[u8], sent: &[u8]) {
    let expect = &step["expect"];
    if expect.is_null() {
        return;
    }
    let text = String::from_utf8_lossy(body).to_string();
    assert_eq!(status, expect["status"].as_u64().expect("status") as u16, "{name}: {text}");
    let v: Value = if body.is_empty() { Value::Null } else { json(body) };
    if let Some(error) = expect["error"].as_str() {
        assert_eq!(v["error"].as_str(), Some(error), "{name}: {text}");
    }
    if let Some(per_account) = expect.get("per_account") {
        let want = match per_account {
            Value::String(s) if s == "default" => Value::Number(scene.default_limit.into()),
            other => other.clone(),
        };
        assert_eq!(v["per_account"], want, "{name}: the limit in force, echoed: {text}");
    }
    if let Some(detail) = expect["detail"].as_str() {
        assert_eq!(v["detail"].as_str(), Some(detail), "{name}: {text}");
    }
    if let Some(scope) = expect["scope"].as_str() {
        assert_eq!(v["scope"].as_str(), Some(scope), "{name}: {text}");
    }
    if let Some(ended) = expect["ended"].as_bool() {
        assert_eq!(v["ended"].as_bool(), Some(ended), "{name}: {text}");
    }
    if let Some(offset) = expect["offset"].as_u64() {
        assert_eq!(v["offset"].as_u64(), Some(offset), "{name}: {text}");
    }
    if let Some(length) = expect["length"].as_u64() {
        assert_eq!(v["length"].as_u64(), Some(length), "{name}: {text}");
    }
    if expect["upload"].as_bool() == Some(true) {
        let id = v["upload"].as_str().unwrap_or_else(|| panic!("{name}: an identifier: {text}"));
        assert_eq!(id.len(), 32, "{name}: 32 hex");
        assert!(id.bytes().all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c)), "{name}: lowercase hex");
    }
    if expect["finish"].as_bool() == Some(true) {
        assert_eq!(
            v,
            serde_json::json!({"designation": "blake3", "hash": blob_hex(sent), "size": sent.len()}),
            "{name}: the finish's whole shape, the hash the suite's own"
        );
    }
    if let Some(e) = expect["expires_eq"].as_str() {
        assert_eq!(v["expires"].as_u64(), Some(scene.expires[e]), "{name}: the expiry stands: {text}");
    }
    if let Some(e) = expect["expires_gt"].as_str() {
        assert!(v["expires"].as_u64().expect("expires") > scene.expires[e], "{name}: re-fixed later: {text}");
    }
    if let Some(deposits) = expect["deposits"].as_array() {
        let want: BTreeSet<String> = deposits.iter().map(|d| blob_hex(&body_of(d))).collect();
        let got: BTreeSet<String> = v["deposits"]
            .as_array()
            .expect("deposits")
            .iter()
            .map(|d| {
                assert_eq!(d["lapsed"].as_bool(), Some(false), "{name}: a whole deposit: {d}");
                assert_eq!(d["designation"].as_str(), Some("blake3"));
                d["hash"].as_str().expect("hash").to_string()
            })
            .collect();
        assert_eq!(got, want, "{name}: the deposits listed are the principal's own: {text}");
    }
    if let Some(uploads) = expect["uploads"].as_array() {
        let want: BTreeSet<String> = uploads.iter().map(|u| scene.id(u.as_str().expect("a name"))).collect();
        let got: BTreeSet<String> = v["uploads"]
            .as_array()
            .expect("uploads")
            .iter()
            .map(|u| u["upload"].as_str().expect("upload").to_string())
            .collect();
        assert_eq!(got, want, "{name}: the standing uploads: {text}");
    }
    if let Some(pending) = expect["pending"].as_u64() {
        assert_eq!(v["pending"].as_u64(), Some(pending), "{name}: {text}");
    }
    if let Some(base) = expect["base"].as_u64() {
        assert_eq!(v["base"].as_u64(), Some(base), "{name}: the base is the index's number: {text}");
    }
    if let Some(bind) = step["bind"].as_str() {
        let id = v["upload"].as_str().unwrap_or_else(|| panic!("{name}: binding {bind} needs an identifier: {text}"));
        scene.uploads.insert(bind.to_string(), id.to_string());
    }
    if let Some(bind) = step["bind_expires"].as_str() {
        scene.expires.insert(bind.to_string(), v["expires"].as_u64().expect("expires"));
    }
}

/// One raw request of the family on a socket of the test's own — the
/// head, then `send`'s bytes, the stream kept open for later steps.
fn stream_open(port: u16, token: &str, id: &str, offset: u64, declare: usize, send: &[u8]) -> TcpStream {
    let mut s = TcpStream::connect(("127.0.0.1", port)).expect("connect");
    s.set_read_timeout(Some(Duration::from_secs(30))).expect("timeout");
    let head = format!(
        "PATCH {BLOB_UPLOAD}/{id}?offset={offset} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\
         Content-Length: {declare}\r\nSkepd-Session: {token}\r\n\r\n"
    );
    s.write_all(head.as_bytes()).expect("head");
    s.write_all(send).expect("the first bytes");
    s.flush().ok();
    // Let the daemon take the bytes and claim the upload before the next
    // step asks for it.
    thread::sleep(Duration::from_millis(150));
    s
}

/// Run one vector of the set against a fresh claimed board — its uploads
/// CLOSED where the vector's `board` says so.
fn run_vector(vector: &Value) {
    let name = vector["name"].as_str().expect("a name");
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = match vector["board"].as_str() {
        Some("uploads_closed") => spawn_uploads_closed(dir.path()),
        None => spawn(dir.path()),
        Some(other) => panic!("{name}: no board named {other}"),
    };
    let port = sd.port();
    let cast = Cast::new(port);
    let mut scene = Scene { default_limit: default_limit(&sd), ..Scene::default() };
    for (i, step) in vector["steps"].as_array().expect("steps").iter().enumerate() {
        let at = format!("{name} step {i}");
        if let Some(s) = step.get("create") {
            let token = cast.token(s["as"].as_str().expect("as"));
            let body = body_of(&s["body"]);
            let path = match (s.get("query"), s.get("length")) {
                (Some(q), _) => format!("{BLOB_UPLOAD}?{}", q.as_str().expect("query")),
                (None, Some(l)) => format!("{BLOB_UPLOAD}?length={}", l.as_u64().expect("length")),
                (None, None) => BLOB_UPLOAD.to_string(),
            };
            let (st, _, resp) = blob_exchange(port, "POST", &path, token, &body);
            judge(step, &at, &mut scene, st, &resp, &body);
            if let Some(bind) = step["bind"].as_str() {
                scene.bytes.insert(bind.to_string(), body);
            }
        } else if let Some(s) = step.get("append") {
            let token = cast.token(s["as"].as_str().expect("as"));
            let id = scene.id(s["upload"].as_str().expect("upload"));
            let body = body_of(&s["body"]);
            let offset = s["offset"].as_u64().expect("offset");
            let (st, _, resp) = blob_append(port, token, &id, offset, &body);
            // The bytes count as the upload's where the answer took them:
            // a 200, or a finish that failed past them (`blob_io`, the
            // seam's injection), the upload standing over the partial.
            let taken = st == 200 || step["expect"]["error"].as_str() == Some("blob_io");
            let whole = if taken {
                let name = s["upload"].as_str().unwrap();
                let w = scene.bytes.entry(name.to_string()).or_default();
                // A resume continues from the record's offset: whatever an
                // earlier request left past it is cut back, as the daemon
                // cuts the partial.
                w.truncate(offset as usize);
                w.extend_from_slice(&body);
                w.clone()
            } else {
                Vec::new()
            };
            judge(step, &at, &mut scene, st, &resp, &whole);
        } else if let Some(s) = step.get("progress") {
            let token = cast.token(s["as"].as_str().expect("as"));
            let id = scene.id(s["upload"].as_str().expect("upload"));
            let (st, _, resp) = blob_progress(port, token, &id);
            judge(step, &at, &mut scene, st, &resp, &[]);
        } else if let Some(s) = step.get("read") {
            let token = cast.token(s["as"].as_str().expect("as"));
            let (st, _, resp) = blob_read(port, token);
            judge(step, &at, &mut scene, st, &resp, &[]);
        } else if let Some(s) = step.get("end") {
            let token = cast.token(s["as"].as_str().expect("as"));
            let id = scene.id(s["upload"].as_str().expect("upload"));
            let (st, _, resp) = blob_end(port, token, &id);
            judge(step, &at, &mut scene, st, &resp, &[]);
        } else if let Some(ms) = step.get("clock") {
            sd.daemon().advance_media_clock_ms(ms.as_u64().expect("ms"));
        } else if let Some(l) = step.get("limits") {
            // Installed WHOLE, as the channel installs a record: a member
            // absent from the step is the default, not the value before.
            sd.daemon().install_media_limits(
                l["per_account"].as_u64(),
                l["venue_total"].as_u64(),
                l["lease_interval_ms"].as_u64(),
                l["address"].as_str().map(str::to_string),
            );
        } else if let Some(f) = step.get("free_space") {
            sd.daemon().set_media_free_space(f.as_u64());
        } else if let Some(f) = step.get("fail_finish_at") {
            // The store's seam: every later finish fails at the named step
            // — `null` fails nothing again.
            sd.daemon().fail_blob_finish_at(f.as_str().map(finish_step));
        } else if let Some(s) = step.get("insert_cell") {
            let who = s["as"].as_str().expect("as");
            let token = cast.token(who).expect("a principal");
            let body = body_of(&s["body"]);
            let size = s["size"].as_u64().unwrap_or(body.len() as u64);
            let draft = cast.draft(who);
            let verdict = insert_cell(port, token, &draft, &body, size);
            assert_eq!(verdict, step["expect"]["verdict"].as_str().expect("verdict"), "{at}");
        } else if let Some(s) = step.get("stream_open") {
            let token = cast.token(s["as"].as_str().expect("as")).expect("a principal");
            let upload = s["upload"].as_str().expect("upload");
            let id = scene.id(upload);
            let send = body_of(&s["send"]);
            let stream = stream_open(port, token, &id, s["offset"].as_u64().expect("offset"), s["declare"].as_u64().expect("declare") as usize, &send);
            scene.bytes.entry(upload.to_string()).or_default().extend_from_slice(&send);
            scene.streams.insert(step["bind_stream"].as_str().expect("bind_stream").to_string(), (stream, upload.to_string()));
        } else if let Some(s) = step.get("stream_send") {
            let (stream, upload) = scene.streams.get_mut(s["stream"].as_str().expect("stream")).expect("an open stream");
            let body = body_of(&s["body"]);
            stream.write_all(&body).expect("send");
            stream.flush().ok();
            let upload = upload.clone();
            scene.bytes.entry(upload).or_default().extend_from_slice(&body);
        } else if let Some(s) = step.get("stream_finish") {
            let (mut stream, upload) = scene.streams.remove(s["stream"].as_str().expect("stream")).expect("an open stream");
            stream.shutdown(Shutdown::Write).ok();
            let mut raw = Vec::new();
            stream.read_to_end(&mut raw).expect("the answer");
            let (st, _, resp) = parse_response(&raw, &at);
            let whole = scene.bytes.get(&upload).cloned().unwrap_or_default();
            judge(step, &at, &mut scene, st, &resp, &whole);
        } else if let Some(s) = step.get("stream_close") {
            scene.streams.remove(s.as_str().expect("stream"));
        } else if let Some(s) = step.get("raw") {
            let token = cast.token(s["as"].as_str().expect("as"));
            let mut path = s["path"].as_str().expect("path").to_string();
            for (name, id) in &scene.uploads {
                path = path.replace(&format!("{{{name}}}"), id);
            }
            let body = body_of(&s["body"]);
            let (st, _, resp) = blob_exchange(port, s["method"].as_str().expect("method"), &path, token, &body);
            judge(step, &at, &mut scene, st, &resp, &body);
        } else {
            panic!("{at}: an unknown step {step}");
        }
    }
    sd.shutdown();
}

/// THE SEVEN CLAUSES AS VECTORS (M-I2 (e); M-I5 (a), (c), (f); M-I6 (a),
/// (b), (d), (e), (f), (h); M-I7 (e)): every vector of `uploads.json` runs
/// against a fresh claimed board and meets its expectations step by step —
/// the deposit read's `base` the index's number, moving as a cell lands;
/// its `per_account` the default limit the daemon computed from the
/// volume, a written record moving it; the floor at the creation and the
/// standing-uploads bound, each before any partial or record; the finish's
/// empty resume after a finish cut before its rename; the closed board's
/// two refusals before any byte — and the fixture pins the same constants
/// the daemon does, and names every refusal the family answers with its
/// status, the readiness refusal among them.
#[test]
fn the_seven_clauses_as_vectors_over_the_wire() {
    let fixture = fixture();
    let pins = &fixture["pins"];
    assert_eq!(pins["family"].as_str(), Some(BLOB_UPLOAD));
    assert_eq!(pins["designation"].as_str(), Some("blake3"));
    assert_eq!(pins["per_file_cap"].as_u64(), Some(64 * 1024 * 1024));
    assert_eq!(pins["chunk"].as_u64(), Some(64 * 1024));
    assert_eq!(pins["sync_grain"].as_u64(), Some(skep_blobs::SYNC_GRAIN));
    assert_eq!(pins["identifier_bytes"].as_u64(), Some(skep_blobs::IDENTIFIER_BYTES as u64));
    assert_eq!(pins["lease_interval_ms"].as_u64(), Some(7 * 24 * 3600 * 1000));
    assert_eq!(pins["lease_horizon_ms"].as_u64(), Some(30 * 24 * 3600 * 1000));
    assert_eq!(pins["floor_bytes"].as_u64(), Some(256 * 1024 * 1024));
    assert_eq!(pins["max_standing_uploads"].as_u64(), Some(8));
    assert_eq!(pins["default_limit_share"].as_u64(), Some(8));
    assert_eq!(pins["default_limit_floor_bytes"].as_u64(), Some(256 * 1024 * 1024));
    assert_eq!(pins["compaction_trigger"].as_u64(), Some(4));
    assert_eq!(pins["compaction_min_lines"].as_u64(), Some(1024));
    let refusals = fixture["refusals"].as_object().expect("refusals");
    for (name, status) in [
        ("malformed_blob", 400),
        ("upload_refused", 403),
        ("no_upload", 404),
        ("upload_held", 409),
        ("upload_offset", 409),
        ("upload_length", 400),
        ("payload_too_large", 413),
        ("deposit_refused", 507),
        ("blob_io", 500),
        ("index_rebuilding", 503),
    ] {
        assert_eq!(refusals[name].as_u64(), Some(status), "{name}");
    }
    let vectors = fixture["vectors"].as_array().expect("vectors");
    assert!(vectors.len() >= 18, "{} vectors", vectors.len());
    for required in [
        "the_default_limit_is_echoed_and_a_written_record_moves_it",
        "the_floor_at_the_creation",
        "the_standing_uploads_bound",
        "clause_7_the_empty_resume_after_a_finish_cut_before_its_rename",
        "the_closed_board",
    ] {
        assert!(vectors.iter().any(|v| v["name"] == required), "the set names {required}");
    }
    for vector in vectors {
        run_vector(vector);
    }
}

/// THE CLOSED BOARD KEEPS A STANDING UPLOAD AND SERVES ITS READS (M-I7
/// (e); wire.md §Media, THE UPLOAD SETTING): an upload created while the
/// board was open stands when the board is reopened with `--no-uploads` —
/// its progress read answers its offset, the deposit read lists it, its
/// resume is refused `uploads_closed` before any body byte and the upload
/// is KEPT, and its termination is served; `/health` echoes
/// `media.uploads` false on the closed board and true on the open one.
#[test]
fn a_closed_board_keeps_a_standing_upload_and_serves_its_reads() {
    let dir = tempfile::tempdir().expect("tempdir");
    let standing = {
        let sd = spawn(dir.path());
        let port = sd.port();
        assert_eq!(json(&get(port, "/health").1)["media"], serde_json::json!({"uploads": true}), "open by default, echoed");
        let token = open_session(port, CLAIMANT_PRINCIPAL);
        let (st, _, resp) = blob_create(port, Some(&token), 10, b"hello");
        assert_eq!(st, 200, "{}", String::from_utf8_lossy(&resp));
        let id = json(&resp)["upload"].as_str().expect("upload").to_string();
        sd.shutdown();
        id
    };
    let sd = spawn_uploads_closed(dir.path());
    let port = sd.port();
    assert_eq!(json(&get(port, "/health").1)["media"], serde_json::json!({"uploads": false}), "closed, echoed");
    let token = open_session(port, CLAIMANT_PRINCIPAL);
    let (st, _, resp) = blob_progress(port, Some(&token), &standing);
    assert_eq!((st, json(&resp)["offset"].as_u64()), (200, Some(5)), "the progress read is served");
    let (st, _, resp) = blob_read(port, Some(&token));
    assert_eq!(st, 200, "{}", String::from_utf8_lossy(&resp));
    assert_eq!(json(&resp)["uploads"].as_array().map(Vec::len), Some(1), "the deposit read lists it");
    let (st, _, resp) = blob_append(port, Some(&token), &standing, 5, b"world");
    let v = json(&resp);
    assert_eq!((st, v["error"].as_str(), v["detail"].as_str()), (403, Some("upload_refused"), Some("uploads_closed")), "{}", String::from_utf8_lossy(&resp));
    let (st, _, resp) = blob_progress(port, Some(&token), &standing);
    assert_eq!((st, json(&resp)["offset"].as_u64()), (200, Some(5)), "the refused resume kept the upload at its offset");
    let (st, _, _) = blob_end(port, Some(&token), &standing);
    assert_eq!(st, 204, "the termination is served");
    let (st, _, resp) = blob_progress(port, Some(&token), &standing);
    assert_eq!((st, json(&resp)["error"].as_str()), (404, Some("no_upload")));
    sd.shutdown();
}

/// THE UPLOAD FAMILY's LOG (D9; s6-op-h; `media.md` §Recovery, the restore
/// face's clause: skepd's log of the upload family records at most the path
/// and the status and never the principal): the real binary, its stderr
/// piped, runs the creation, a resume, the deposit read and an end under a
/// SIGNED session; the lines it writes during them are NONE — no request
/// line is written for the family at all — and its whole stderr carries
/// neither the session's token nor an upload's identifier, nor the
/// principal's number as a word of its own.
#[test]
fn the_upload_familys_log_names_no_principal_no_token_and_no_upload() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let dir = tmp.path().join("data");
    // A signed session on a claimed board needs a CONFIGURED origin, and an
    // origin carries the port: reserve one, release it, and launch the
    // binary on it with that origin — the shape a served board is launched
    // in. A lost rebind race costs one more attempt on a fresh port.
    let mut child = None;
    for _ in 0..12 {
        let reserved = std::net::TcpListener::bind(("127.0.0.1", 0)).expect("reserve a port");
        let port = reserved.local_addr().expect("the port").port();
        drop(reserved);
        let mut spawned = Command::new(env!("CARGO_BIN_EXE_skepd"))
            .arg("--data-dir")
            .arg(&dir)
            .args(["--port", &port.to_string(), "--workers", "8", "--origin", &format!("http://127.0.0.1:{port}")])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn the skepd binary");
        thread::sleep(Duration::from_millis(300));
        match spawned.try_wait().expect("the child's state") {
            Some(_) => continue,
            None => {
                child = Some(spawned);
                break;
            }
        }
    }
    let mut child = child.expect("the binary bound its reserved port");
    let stdout = child.stdout.take().expect("skepd stdout");
    let stderr = child.stderr.take().expect("skepd stderr");
    let lines: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let reader = {
        let lines = Arc::clone(&lines);
        thread::spawn(move || {
            for line in BufReader::new(stderr).lines() {
                let Ok(line) = line else { break };
                lines.lock().expect("the lines").push(line);
            }
        })
    };
    let mut line = String::new();
    BufReader::new(stdout).read_line(&mut line).expect("read skepd startup line");
    let port = line
        .split_once("http://127.0.0.1:")
        .and_then(|(_, rest)| rest.split('/').next())
        .and_then(|p| p.parse::<u16>().ok())
        .unwrap_or_else(|| panic!("no port in skepd startup line {line:?}"));
    claim_board(port);
    let signed = open_signed_session(port, CLAIMANT_PRINCIPAL, &device_key());
    // The cadence's first pass writes its line once the index is ready —
    // before the family's requests, so its line is never among theirs.
    let deadline = Instant::now() + Duration::from_secs(30);
    while !lines.lock().expect("the lines").iter().any(|l| l.contains("pruner:")) {
        assert!(Instant::now() < deadline, "the first pass's line never came");
        thread::sleep(Duration::from_millis(20));
    }
    let before = lines.lock().expect("the lines").len();
    let (st, _, resp) = blob_create(port, Some(&signed), 10, b"hello");
    assert_eq!(st, 200, "{}", String::from_utf8_lossy(&resp));
    let created = json(&resp)["upload"].as_str().expect("upload").to_string();
    let (st, _, _) = blob_append(port, Some(&signed), &created, 5, b"world");
    assert_eq!(st, 200);
    let (st, _, _) = blob_read(port, Some(&signed));
    assert_eq!(st, 200);
    let (st, _, resp) = blob_create(port, Some(&signed), 10, b"");
    assert_eq!(st, 200);
    let ended = json(&resp)["upload"].as_str().expect("upload").to_string();
    let (st, _, _) = blob_end(port, Some(&signed), &ended);
    assert_eq!(st, 204);
    thread::sleep(Duration::from_millis(300));
    let _ = child.kill();
    let _ = child.wait();
    reader.join().expect("stderr reader thread");
    let lines = lines.lock().expect("the lines").clone();
    let during: Vec<&String> = lines[before..].iter().collect();
    assert!(during.is_empty(), "FINDING (D9): the upload family wrote lines: {during:?}");
    let whole = lines.join("\n");
    assert!(!whole.contains(&signed), "FINDING (D9): the token is in the log");
    assert!(!whole.contains(&created) && !whole.contains(&ended), "FINDING (D9): an upload's identifier is in the log");
    let principal = CLAIMANT_PRINCIPAL.to_string();
    assert!(
        !whole.split(|c: char| !c.is_ascii_digit()).any(|word| word == principal),
        "FINDING (D9): the principal's number is in the log as a word of its own: {whole}"
    );
}

/// (1) THE IDENTIFIER REACHES THE UPLOADER BEFORE THE UPLOAD's FIRST BODY
/// BYTE on the ONE request (M-I5 (c)): a creation-with-upload sent with
/// `Expect: 100-continue` is answered the interim `100 Continue` carrying
/// `Upload-Id` before the body is invited, and the finish after it; the
/// identifier is the upload the deposit read would have listed had the
/// body never come.
#[test]
fn the_identifier_rides_the_interim_answer_before_the_first_body_byte() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let token = open_session(port, CLAIMANT_PRINCIPAL);
    let body = b"the picture's bytes";
    let mut s = TcpStream::connect(("127.0.0.1", port)).expect("connect");
    s.set_read_timeout(Some(Duration::from_secs(30))).expect("timeout");
    let head = format!(
        "POST {BLOB_UPLOAD}?length={} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\
         Content-Length: {}\r\nExpect: 100-continue\r\nSkepd-Session: {token}\r\n\r\n",
        body.len(),
        body.len()
    );
    s.write_all(head.as_bytes()).expect("head");
    // The interim: read up to its blank line, before a body byte is sent.
    let mut raw = Vec::new();
    let mut chunk = [0u8; 1024];
    while !raw.windows(4).any(|w| w == b"\r\n\r\n") {
        let n = s.read(&mut chunk).expect("the interim");
        assert!(n > 0, "closed before the interim: {}", String::from_utf8_lossy(&raw));
        raw.extend_from_slice(&chunk[..n]);
    }
    let interim = String::from_utf8_lossy(&raw).to_string();
    assert!(interim.starts_with("HTTP/1.1 100 Continue\r\n"), "{interim}");
    let id = interim
        .lines()
        .find_map(|l| l.strip_prefix("Upload-Id: "))
        .unwrap_or_else(|| panic!("the interim carries the identifier: {interim}"))
        .trim()
        .to_string();
    assert_eq!(id.len(), 32);
    // The upload stands at offset 0 before any body byte, listed to its
    // uploader and to nobody else.
    let (st, _, resp) = blob_progress(port, Some(&token), &id);
    assert_eq!(st, 200, "{}", String::from_utf8_lossy(&resp));
    assert_eq!(json(&resp)["offset"].as_u64(), Some(0));
    s.write_all(body).expect("the body");
    s.shutdown(Shutdown::Write).ok();
    let mut rest = Vec::new();
    s.read_to_end(&mut rest).expect("the answer");
    let (st, _, resp) = parse_response(&rest, "the finish");
    assert_eq!(st, 200, "{}", String::from_utf8_lossy(&resp));
    assert_eq!(json(&resp)["hash"].as_str(), Some(blob_hex(body).as_str()));
    let (st, _, _) = blob_progress(port, Some(&token), &id);
    assert_eq!(st, 404, "finished: the record is retired");
    sd.shutdown();
}

/// (3), (6) A CONNECTION DROPPED MID-BODY KEEPS ITS UPLOAD at the bytes it
/// had received, resumable from there (M-I5 (c): "a connection dropped
/// mid-body keeps its upload until the expiry"); and a resume stating the
/// written length where the record's offset is less is refused naming the
/// record's.
#[test]
fn a_dropped_connection_keeps_its_upload_and_a_resume_continues_it() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let token = open_session(port, CLAIMANT_PRINCIPAL);
    let (st, _, resp) = blob_create(port, Some(&token), 10, b"");
    assert_eq!(st, 200);
    let id = json(&resp)["upload"].as_str().expect("upload").to_string();
    {
        let s = stream_open(port, &token, &id, 0, 10, b"hel");
        // Dropped: the daemon meets EOF inside the body.
        drop(s);
    }
    // The upload stands at the three bytes it received.
    let deadline = Instant::now() + Duration::from_secs(10);
    let offset = loop {
        let (st, _, resp) = blob_progress(port, Some(&token), &id);
        assert_eq!(st, 200, "{}", String::from_utf8_lossy(&resp));
        let offset = json(&resp)["offset"].as_u64().expect("offset");
        if offset == 3 || Instant::now() > deadline {
            break offset;
        }
        thread::sleep(Duration::from_millis(50));
    };
    assert_eq!(offset, 3, "the bytes received before the drop are kept");
    let (st, _, resp) = blob_append(port, Some(&token), &id, 0, b"hello");
    assert_eq!(st, 409, "{}", String::from_utf8_lossy(&resp));
    assert_eq!(json(&resp)["offset"].as_u64(), Some(3));
    let (st, _, resp) = blob_append(port, Some(&token), &id, 3, b"loworld");
    assert_eq!(st, 200, "{}", String::from_utf8_lossy(&resp));
    assert_eq!(json(&resp)["hash"].as_str(), Some(blob_hex(b"helloworld").as_str()));
    sd.shutdown();
}

/// THE FENCE BEFORE THE CLAIM (M-I6 (b): "the upload is admitted on a
/// claimed board alone — `claim_first` before the claim"): on the
/// unclaimed board every act of the upload and the deposit read answers
/// `upload_refused` with `claim_first`, before any body byte; after the
/// claim the same session's PUT lands.
#[test]
fn every_act_of_the_upload_answers_claim_first_before_the_claim() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn_unclaimed(dir.path());
    let port = sd.port();
    ceremony_before_the_claim(port);
    let claimant = open_session(port, CLAIMANT_PRINCIPAL);
    for (st, _, resp) in [
        blob_create(port, Some(&claimant), 5, b"hello"),
        blob_read(port, Some(&claimant)),
        blob_progress(port, Some(&claimant), "0123456789abcdef0123456789abcdef"),
        blob_append(port, Some(&claimant), "0123456789abcdef0123456789abcdef", 0, b"x"),
        blob_end(port, Some(&claimant), "0123456789abcdef0123456789abcdef"),
    ] {
        assert_eq!(st, 403, "{}", String::from_utf8_lossy(&resp));
        let v = json(&resp);
        assert_eq!(v["error"].as_str(), Some("upload_refused"));
        assert_eq!(v["detail"].as_str(), Some("claim_first"));
    }
    assert!(!std::fs::read_dir(dir.path().join("blobs").join("blake3")).map_or(false, |d| d.count() > 0), "nothing deposited");
    let signed = open_signed_session(port, CLAIMANT_PRINCIPAL, &device_key());
    expect_resp(&op(port, Some(&signed), &claim_frame(CLAIMANT_DOC1, CLAIMANT_ACCOUNT)), "ack_addr");
    put_whole(port, &claimant, b"hello");
    assert_eq!(deposits_of(port, &claimant).len(), 1);
    sd.shutdown();
}

/// THE H1 PRESENCE CELLS (M-I2 (e); M-I5 (c); "NO ANSWER OF THE UPLOAD SAYS
/// WHETHER THE FILE WAS ALREADY HERE"): a PUT of a file another account
/// already holds answers BYTE-IDENTICALLY to a PUT of a fresh file — the
/// status, the headers, the body with the hash the only difference, and
/// the hash the file's own; the deposit read never lists another's deposit;
/// a second deposit of the same bytes by the same account is one deposit
/// listed once; and the file on disk is one file, whole.
#[test]
fn a_put_of_a_file_another_account_holds_answers_as_a_put_of_a_fresh_file() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let a = open_session(port, CLAIMANT_PRINCIPAL);
    let b = seat_stranger(port, 971).session;
    let held = seeded_bytes(200_000, 7);
    let fresh = seeded_bytes(200_000, 8);
    put_whole(port, &a, &held);
    let (st_held, headers_held, body_held) = blob_create(port, Some(&b), held.len() as u64, &held);
    let (st_fresh, headers_fresh, body_fresh) = blob_create(port, Some(&b), fresh.len() as u64, &fresh);
    assert_eq!((st_held, st_fresh), (200, 200));
    let normalized = |headers: &[(String, String)], body: &[u8], hex: &str| {
        let mut h: Vec<(String, String)> = headers.to_vec();
        h.retain(|(k, _)| !k.eq_ignore_ascii_case("Date"));
        (h, String::from_utf8_lossy(body).replace(hex, "<hash>"))
    };
    assert_eq!(
        normalized(&headers_held, &body_held, &blob_hex(&held)),
        normalized(&headers_fresh, &body_fresh, &blob_hex(&fresh)),
        "the two answers differ by the hash alone"
    );
    assert_eq!(json(&body_held)["hash"].as_str(), Some(blob_hex(&held).as_str()));
    let listed = |token: &str| -> BTreeSet<String> { deposits_of(port, token).into_iter().map(|(h, _, _)| h).collect() };
    assert_eq!(listed(&b), [blob_hex(&held), blob_hex(&fresh)].into_iter().collect());
    assert_eq!(listed(&a), [blob_hex(&held)].into_iter().collect(), "a's read lists a's deposits alone");
    put_whole(port, &b, &held);
    assert_eq!(listed(&b).len(), 2, "one deposit per hash per account");
    let file = dir.path().join("blobs").join("blake3").join(blob_hex(&held));
    assert_eq!(std::fs::read(&file).expect("the one file"), held);
    let partials = std::fs::read_dir(dir.path().join("blobs").join("blake3"))
        .expect("the designation directory")
        .filter(|e| e.as_ref().unwrap().file_name().to_string_lossy().starts_with(".upload-"))
        .count();
    assert_eq!(partials, 0, "no partial stands after a finish");
    sd.shutdown();
}

/// THE RSS BOUND UNDER A PUT AT THE CAP (M-I5 (f); the investigation
/// §3.4 "memory per in-flight PUT … O(chunk), never O(body)"): the real
/// binary's resident set, sampled through `ps` while a 64 MiB PUT streams
/// through it, grows by less than a quarter of the body — a body held
/// whole would grow it by the body. The number is printed; the bound is
/// generous on purpose (allocator slack, a worker's stack), and the arm's
/// one-chunk construction is pinned by its own unit test.
#[test]
fn rss_under_a_put_at_the_cap_grows_by_less_than_a_quarter_of_the_body() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let dir = tmp.path().join("data");
    let (mut child, port) = crate::hazard::spawn_skepd(&dir);
    let pid = child.id();
    claim_board(port);
    let token = open_session(port, CLAIMANT_PRINCIPAL);
    let rss_kb = move || -> u64 {
        let out = Command::new("ps").args(["-o", "rss=", "-p", &pid.to_string()]).output().expect("ps");
        String::from_utf8_lossy(&out.stdout).trim().parse().unwrap_or(0)
    };
    // A small PUT first, so the arm's buffer and the hasher are allocated
    // before the baseline is read.
    put_whole(port, &token, b"warm");
    let baseline = rss_kb();
    assert!(baseline > 0, "ps answers the daemon's resident set");
    let stop = Arc::new(AtomicBool::new(false));
    let sampler = {
        let stop = Arc::clone(&stop);
        thread::spawn(move || {
            let mut max = 0;
            while !stop.load(Ordering::Relaxed) {
                max = max.max(rss_kb());
                thread::sleep(Duration::from_millis(5));
            }
            max
        })
    };
    let body = seeded_bytes(64 * 1024 * 1024, 99);
    let started = Instant::now();
    put_whole(port, &token, &body);
    let took = started.elapsed();
    stop.store(true, Ordering::Relaxed);
    let peak = sampler.join().expect("sampler");
    let growth_kb = peak.saturating_sub(baseline);
    println!(
        "RSS under a 64 MiB PUT: baseline {baseline} KB, peak {peak} KB, growth {growth_kb} KB ({:.1} MiB); the PUT took {took:?}",
        growth_kb as f64 / 1024.0
    );
    assert!(
        growth_kb < 16 * 1024,
        "the resident set grew by {growth_kb} KB under a 64 MiB PUT: a body held whole, not streamed"
    );
    let _ = child.kill();
    let _ = child.wait();
}

/// ms4-K2 (sweep-4 media-leak's `put-replace-latency`; HELD, run in lane
/// B's fence REPORTED NOT ASSERTED — the board's sm-Q4): is the time from a
/// PUT's last body byte to its answer measurably longer on REPLACE than on
/// a create? 200 trials per arm at 1 MB, 16 MB and the per-file cap, the
/// target present (the same bytes PUT again — the rename over an existing
/// name) versus absent (fresh bytes); both distributions and the quantile
/// gap are printed; the one assertion is a sanity bound. `K2_TRIALS`
/// narrows the trial count for a quick look. The absent arm's files are
/// removed between trials so the disk holds one cap-sized file at a time.
#[test]
#[ignore = "timing test - gate-full only"]
fn put_answer_latency_does_not_separate_replace_from_create() {
    let trials: usize = std::env::var("K2_TRIALS").ok().and_then(|s| s.parse().ok()).unwrap_or(200);
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let token = open_session(port, CLAIMANT_PRINCIPAL);
    let blobs = dir.path().join("blobs").join("blake3");
    // One timed PUT: the time from the last body byte written to the first
    // answer byte read.
    let timed_put = |bytes: &[u8]| -> (Duration, String) {
        let mut s = TcpStream::connect(("127.0.0.1", port)).expect("connect");
        s.set_nodelay(true).ok();
        s.set_read_timeout(Some(Duration::from_secs(120))).expect("timeout");
        let head = format!(
            "POST {BLOB_UPLOAD}?length={} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\
             Content-Length: {}\r\nSkepd-Session: {token}\r\n\r\n",
            bytes.len(),
            bytes.len()
        );
        s.write_all(head.as_bytes()).expect("head");
        s.write_all(bytes).expect("body");
        s.flush().ok();
        let sent = Instant::now();
        let mut first = [0u8; 1];
        let n = s.read(&mut first).expect("the first answer byte");
        let latency = sent.elapsed();
        assert_eq!(n, 1);
        let mut raw = vec![first[0]];
        s.read_to_end(&mut raw).expect("the rest");
        let (st, _, body) = parse_response(&raw, "K2");
        assert_eq!(st, 200, "{}", String::from_utf8_lossy(&body));
        (latency, json(&body)["hash"].as_str().expect("hash").to_string())
    };
    let quantile = |sorted: &[Duration], q: f64| -> Duration {
        let i = ((sorted.len() - 1) as f64 * q).round() as usize;
        sorted[i]
    };
    println!("K2: {trials} trials per arm, the latency from the last body byte to the first answer byte");
    for (label, size) in [("1 MB", 1_000_000usize), ("16 MB", 16_000_000), ("the cap (64 MiB)", 64 * 1024 * 1024)] {
        // The present arm: one file, PUT first and then PUT again `trials`
        // times — every timed PUT a REPLACE of the name.
        let present = seeded_bytes(size, 1_000);
        let _ = timed_put(&present);
        let mut replace: Vec<Duration> = (0..trials).map(|_| timed_put(&present).0).collect();
        // The absent arm: fresh bytes per trial, the file removed after each.
        let mut create: Vec<Duration> = Vec::with_capacity(trials);
        for t in 0..trials {
            let fresh = seeded_bytes(size, 2_000 + t as u64);
            let (latency, hex) = timed_put(&fresh);
            create.push(latency);
            let _ = std::fs::remove_file(blobs.join(hex));
        }
        replace.sort();
        create.sort();
        let gap = |q: f64| quantile(&replace, q).as_secs_f64() * 1e3 - quantile(&create, q).as_secs_f64() * 1e3;
        println!(
            "K2 {label}: create  p50 {:?} p90 {:?} p99 {:?} max {:?}",
            quantile(&create, 0.5), quantile(&create, 0.9), quantile(&create, 0.99), create.last().unwrap()
        );
        println!(
            "K2 {label}: replace p50 {:?} p90 {:?} p99 {:?} max {:?}",
            quantile(&replace, 0.5), quantile(&replace, 0.9), quantile(&replace, 0.99), replace.last().unwrap()
        );
        println!("K2 {label}: the gap replace − create at p50 {:+.3} ms, p90 {:+.3} ms, p99 {:+.3} ms", gap(0.5), gap(0.9), gap(0.99));
        assert!(quantile(&create, 0.5) < Duration::from_secs(30) && quantile(&replace, 0.5) < Duration::from_secs(30), "sanity: a PUT answers");
    }
    sd.shutdown();
}

/// (4) AN EXPIRED UPLOAD's PARTIAL GOES AT THE NEXT OPEN (M-I6 (c); the
/// pruner's pass removes one while the daemon serves, `pruner.rs`): past
/// its expiry the identifier answers no upload and the bytes count
/// nothing; the partial file stands until a pass or the daemon's reopen,
/// when the reconciliation retires the record and removes it; a standing
/// upload survives the reopen with its offset. The expiry here is the
/// WALL CLOCK's — an installed record's interval of one millisecond —
/// since a restart keeps no test clock.
#[test]
fn an_expired_uploads_partial_goes_at_the_next_open_and_a_standing_one_survives_it() {
    let dir = tempfile::tempdir().expect("tempdir");
    let blobs = dir.path().join("blobs").join("blake3");
    let (expired, standing) = {
        let sd = spawn(dir.path());
        let port = sd.port();
        let token = open_session(port, CLAIMANT_PRINCIPAL);
        sd.daemon().install_media_limits(None, None, Some(500), None);
        let (st, _, resp) = blob_create(port, Some(&token), 10, b"hello");
        assert_eq!(st, 200, "{}", String::from_utf8_lossy(&resp));
        let expired = json(&resp)["upload"].as_str().unwrap().to_string();
        thread::sleep(Duration::from_millis(700));
        let (st, _, _) = blob_progress(port, Some(&token), &expired);
        assert_eq!(st, 404, "expired: no upload");
        assert_eq!(json(&blob_read(port, Some(&token)).2)["pending"].as_u64(), Some(0), "counts nothing");
        sd.daemon().install_media_limits(None, None, None, None);
        let (st, _, resp) = blob_create(port, Some(&token), 10, b"hello");
        assert_eq!(st, 200);
        let standing = json(&resp)["upload"].as_str().unwrap().to_string();
        assert!(blobs.join(format!(".upload-{expired}")).exists(), "the partial stands until a pass removes it");
        sd.shutdown();
        (expired, standing)
    };
    let sd = spawn(dir.path());
    let port = sd.port();
    let token = open_session(port, CLAIMANT_PRINCIPAL);
    assert!(!blobs.join(format!(".upload-{expired}")).exists(), "gone at the next open");
    assert!(blobs.join(format!(".upload-{standing}")).exists());
    let (st, _, resp) = blob_progress(port, Some(&token), &standing);
    assert_eq!(st, 200, "{}", String::from_utf8_lossy(&resp));
    assert_eq!(json(&resp)["offset"].as_u64(), Some(5), "the standing upload's offset survives the reopen");
    let (st, _, resp) = blob_append(port, Some(&token), &standing, 5, b"world");
    assert_eq!(st, 200, "{}", String::from_utf8_lossy(&resp));
    assert_eq!(json(&resp)["hash"].as_str(), Some(blob_hex(b"helloworld").as_str()), "the hash covers the bytes received before the reopen");
    sd.shutdown();
}
