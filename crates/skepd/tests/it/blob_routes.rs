//! MEDIA LANE B — THE PUT over the wire: the resumable upload's seven
//! clauses as vectors (`fixtures/media/uploads.json`, the vector set's
//! second file, PATTERNS P5 — one set, run here against the daemon and by
//! a client suite against its own implementation of the shape) — the
//! default per-account limit's echo, the floor at the creation and the
//! standing-uploads bound, the finish's empty resume, the closed board and
//! the upload permit pool among them — the H1 presence cells, the
//! identifier on the one request, a dropped connection's kept upload, the
//! fence before the claim, the closed board's kept upload, the upload pool
//! bounding the family and the liveness it keeps under trickling streams,
//! the upload family's log, the RSS bound under a PUT at the cap, and
//! ms4-K2's timing — reported, not asserted (the board's sm-Q4).
//!
//! Every test names the register's clause it holds: M-I2 (e) THE
//! REQUESTER'S OWN RECORD BEFORE ANY SHARED FACT; M-I5 (a) DURABLE BEFORE
//! NAMED, ANSWERED AFTER RECORDED; M-I5 (c) THE DEPOSIT RECORD IS THE
//! PRINCIPAL'S, READABLE, EXACT; M-I5 (f) PICTURES NEVER STARVE OR STALL
//! THE JOURNAL — the floor, and the upload pool counted into the worker
//! budget; M-I6 (a) at its ZERO BASE; M-I6 (b) THE OWN SCOPE BOUNDS
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
use skep_media::limits::{DEFAULT_LIMIT_FLOOR_BYTES, DEFAULT_LIMIT_SHARE};

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
/// expects it: one part in `DEFAULT_LIMIT_SHARE` of the capacity the daemon
/// read at its open, never below `DEFAULT_LIMIT_FLOOR_BYTES` — the suite's
/// own arithmetic over the same read, through the two constants.
fn default_limit(sd: &skepd::Skepd) -> u64 {
    sd.daemon()
        .media_capacity()
        .map_or(DEFAULT_LIMIT_FLOOR_BYTES, |c| (c / DEFAULT_LIMIT_SHARE).max(DEFAULT_LIMIT_FLOOR_BYTES))
}

/// The lines the MEDIA GATE has said through its own classed door — the
/// floor's binding and its lift — which the daemon's own record holds none
/// of (they are said below its door).
fn media_lines(sd: &skepd::Skepd) -> Vec<String> {
    sd.daemon().media_lines_said()
}

/// Wait for the cadence's first pass to have said its line (row 34, a
/// `landing:` on the daemon's record): the pass runs on the pruner's own
/// thread as soon as the index is ready, so a claim counting the daemon's
/// lines from a `before` takes it after the line has landed, not across it.
fn after_the_first_pass(sd: &skepd::Skepd) {
    wait_until("the cadence's first pass's line", || {
        sd.daemon().lines_said().iter().any(|l| l.starts_with("landing: pruner: "))
    });
}

/// Whether `line` carries a run of 32 hex digits — an upload's identifier,
/// or a session token's shape.
fn names_a_hex_id(line: &str) -> bool {
    line.split(|c: char| !c.is_ascii_hexdigit()).any(|run| run.len() >= 32)
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
/// finish's hash covers), the expiries bound by name, the open streams,
/// and the upload permits a `hold` step holds.
#[derive(Default)]
struct Scene<'a> {
    uploads: HashMap<String, String>,
    bytes: HashMap<String, Vec<u8>>,
    expires: HashMap<String, u64>,
    streams: HashMap<String, (TcpStream, String)>,
    /// The default per-account limit the daemon under test computed.
    default_limit: u64,
    /// The upload pool's permits a `hold` step holds through the daemon's
    /// hook — every one of the pool, as in-flight streams would hold them —
    /// released whole by `hold: null`.
    held: Vec<skepd::Permit<'a>>,
}

impl Scene<'_> {
    fn id(&self, name: &str) -> String {
        self.uploads.get(name).cloned().unwrap_or_else(|| name.to_string())
    }
}

/// Judge one exchange against a step's `expect`.
fn judge(step: &Value, name: &str, scene: &mut Scene<'_>, status: u16, body: &[u8], sent: &[u8]) {
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
    let pool = fixture()["pins"]["upload_pool"].as_u64().expect("upload_pool") as usize;
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
            let (st, _, resp) = blob_resume(port, token, &id, offset, &body);
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
            let (st, _, resp) = blob_deposit_read(port, token);
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
            // absent from the step is the default, not the value before —
            // the per-file cap the route's own where the step names none.
            sd.daemon()
                .install_media_limits(
                    l["per_account"].as_u64(),
                    l["venue_total"].as_u64(),
                    l["lease_interval_ms"].as_u64(),
                    l["per_file_cap"].as_u64(),
                    l["address"].as_str().map(str::to_string),
                )
                .unwrap_or_else(|e| panic!("{at}: the limits record is refused: {e}"));
        } else if let Some(f) = step.get("free_space") {
            sd.daemon().set_media_free_space(f.as_u64());
        } else if let Some(f) = step.get("fail_finish_at") {
            // The store's seam: every later finish fails at the named step
            // — `null` fails nothing again.
            sd.daemon().fail_blob_finish_at(f.as_str().map(finish_step));
        } else if let Some(h) = step.get("hold") {
            // The upload pool's seam (M-I5 (f)): every permit held through
            // the daemon's hook, as in-flight streams would hold them —
            // their count the fixture's pin — or, `null`, every one
            // released.
            match h {
                Value::String(pool_name) if pool_name == "upload_pool" => {
                    scene.held = std::iter::repeat_with(|| sd.daemon().try_hold_upload_permit())
                        .take_while(Option::is_some)
                        .flatten()
                        .collect();
                    assert_eq!(scene.held.len(), pool, "{at}: the pool's whole count held");
                }
                Value::Null => scene.held.clear(),
                other => panic!("{at}: no pool named {other}"),
            }
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
    // The scene borrows the daemon through any permit it still holds.
    drop(scene);
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
/// two refusals before any byte; the upload pool's refusal before any byte
/// with the upload kept — and the fixture pins the same constants the
/// daemon does — the pool's count and the two worker counts among them —
/// and names every refusal the family answers with its status, the
/// readiness refusal and the pool's among them.
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
    // The upload pool and the worker budget it is counted into: the pool's
    // count is pinned against the daemon by `the_upload_pool_bounds_the_family`
    // (the hook's drain), the two worker counts against the library here.
    assert_eq!(pins["upload_pool"].as_u64(), Some(4));
    assert_eq!(pins["min_workers"].as_u64(), Some(skepd::MIN_WORKERS as u64));
    assert_eq!(pins["default_workers"].as_u64(), Some(skepd::DEFAULT_WORKERS as u64));
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
        ("upload_busy", 503),
    ] {
        assert_eq!(refusals[name].as_u64(), Some(status), "{name}");
    }
    let vectors = fixture["vectors"].as_array().expect("vectors");
    assert!(vectors.len() >= 19, "{} vectors", vectors.len());
    for required in [
        "the_default_limit_is_echoed_and_a_written_record_moves_it",
        "the_floor_at_the_creation",
        "the_standing_uploads_bound",
        "clause_7_the_empty_resume_after_a_finish_cut_before_its_rename",
        "the_closed_board",
        "the_upload_permit_pool",
    ] {
        assert!(vectors.iter().any(|v| v["name"] == required), "the set names {required}");
    }
    for vector in vectors {
        run_vector(vector);
    }
}

/// THE FLOOR's SIZING AT THE OPEN (fs-1; M-I5 (f): the floor sized to keep
/// the journal writable THROUGH ITS NEXT CHECKPOINT, the larger of the
/// constant and twice a checkpoint's size plus one maximal segment; M-I6 (f)
/// THE FLOOR IS THE HOST'S; `operations.md` §4 row 14: the open sizes the
/// floor and the byte bound off the START POINT's header — the base the
/// open LOADED — never a skipped header's claim). The fixture's
/// `floor_bytes` pins the CONSTANT HALF; this carries the sizing. Two bases
/// stand: a small sound one, and a newer one whose header is made to claim
/// a 300 MiB body — the header reads, the base does not load, the open
/// passes it over with a warning and loads the older one as its start
/// point. The floor in force is then the constant, sized off the base that
/// loaded and not off the claim (which would have put it at 600 MiB plus a
/// segment), so a creation at 400 MiB of free space is admitted at once.
/// THE FIRST LANDING keeps the base the open loaded from beside the new one
/// and removes the skipped base as excess, whatever its age (retention
/// counts the bases that load), and the floor re-read from the landing is
/// the constant still.
#[test]
fn the_floor_in_force_is_sized_off_the_start_point_at_open_and_the_first_landing_removes_the_skipped_base(
) {
    let mib: u64 = 1024 * 1024;
    let dir = tempfile::tempdir().expect("tempdir");
    let (loaded, skipped) = {
        let sd = spawn(dir.path());
        let port = sd.port();
        assert_eq!(sd.daemon().media_floor_in_force(), 256 * mib, "no checkpoint: the constant");
        sd.daemon().checkpoint_now();
        let loaded = sd.daemon().newest_checkpoint().expect("the first base").seq.0;
        let owner = open_session(port, CLAIMANT_PRINCIPAL);
        acked_at(&op(
            port,
            Some(&owner),
            &format!(r#"{{"op":"create_new_document","account":"{CLAIMANT_ACCOUNT}"}}"#),
        ));
        sd.daemon().checkpoint_now();
        let skipped = sd.daemon().newest_checkpoint().expect("the second base").seq.0;
        assert!(skipped > loaded, "two bases at two positions: {loaded} then {skipped}");
        sd.shutdown();
        (loaded, skipped)
    };
    // The newer header's `body_len` — bytes 16..24, little-endian — made to
    // claim 300 MiB: the header reads, the base does not load.
    let path = dir.path().join(format!("checkpoint.{skipped}"));
    let mut bytes = std::fs::read(&path).expect("the checkpoint");
    let claimed_body = 300 * mib;
    bytes[16..24].copy_from_slice(&claimed_body.to_le_bytes());
    std::fs::write(&path, &bytes).expect("rewrite the header");

    let sd = spawn(dir.path());
    let port = sd.port();
    let recovery = sd.daemon().recovery().expect("a journaled daemon").clone();
    assert_eq!(recovery.start_point.0, loaded, "the open loaded the older base: {recovery:?}");
    assert_eq!(
        recovery.skipped.iter().map(|s| s.seq.0).collect::<Vec<_>>(),
        vec![skipped],
        "the doctored base was passed over at the open, and said"
    );
    let claimed_floor = 2 * (claimed_body + 88) + skep_kernel::MAX_SEGMENT_LEN;
    assert_eq!(
        sd.daemon().media_floor_in_force(),
        256 * mib,
        "sized off the start point's header — a small base, the constant — and never off the \
         skipped header's claim of {claimed_floor}"
    );
    let a = open_session(port, CLAIMANT_PRINCIPAL);
    sd.daemon().set_media_free_space(Some(400 * mib));
    let (st, _, body) = blob_create(port, Some(&a), 10, b"");
    assert_eq!(
        st,
        200,
        "the creation the constant admits is admitted at once: {}",
        String::from_utf8_lossy(&body)
    );

    // THE FIRST LANDING, at a position above both: retention counts the
    // bases that loaded, so the base the open loaded from stands beside the
    // new one and the skipped one is removed as excess.
    let owner = open_session(port, CLAIMANT_PRINCIPAL);
    acked_at(&op(
        port,
        Some(&owner),
        &format!(r#"{{"op":"create_new_document","account":"{CLAIMANT_ACCOUNT}"}}"#),
    ));
    sd.daemon().service_the_checkpoint_now();
    let landed = sd.daemon().newest_checkpoint().expect("the thread's checkpoint landed");
    assert!(landed.seq.0 > skipped, "{landed:?}");
    assert!(landed.len < mib, "a small board's checkpoint: {landed:?}");
    assert!(
        dir.path().join(format!("checkpoint.{loaded}")).is_file(),
        "the base the open loaded from is kept beside the new one"
    );
    assert!(
        !dir.path().join(format!("checkpoint.{skipped}")).exists(),
        "the skipped base is removed by the first landing, whatever its age"
    );
    assert!(dir.path().join(format!("checkpoint.{}", landed.seq.0)).is_file());
    assert_eq!(sd.daemon().media_floor_in_force(), 256 * mib, "re-read from the landing: the constant");
    let (st, _, body) = blob_create(port, Some(&a), 10, b"");
    assert_eq!(st, 200, "the same creation admitted: {}", String::from_utf8_lossy(&body));
    sd.daemon().set_media_free_space(None);
    sd.shutdown();
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
    let (st, _, resp) = blob_deposit_read(port, Some(&token));
    assert_eq!(st, 200, "{}", String::from_utf8_lossy(&resp));
    assert_eq!(json(&resp)["uploads"].as_array().map(Vec::len), Some(1), "the deposit read lists it");
    let (st, _, resp) = blob_resume(port, Some(&token), &standing, 5, b"world");
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

/// The asides standing under `blobs/blake3/` — the replaced instances'
/// second names, `.retired-<hex>-<n>` — in name order; none where the
/// directory does not exist yet.
fn asides_on_disk(data_dir: &Path) -> Vec<String> {
    let Ok(entries) = std::fs::read_dir(data_dir.join("blobs").join("blake3")) else {
        return Vec::new();
    };
    let mut asides: Vec<String> = entries
        .filter_map(|e| e.ok())
        .filter_map(|e| e.file_name().to_str().map(str::to_string))
        .filter(|name| name.starts_with(".retired-"))
        .collect();
    asides.sort();
    asides
}

/// The lines the daemon has said of the blob store — row 37 and its
/// clearing — in order.
fn blob_store_lines(sd: &skepd::Skepd) -> Vec<String> {
    sd.daemon().lines_said().into_iter().filter(|l| l.contains("blob store:")).collect()
}

/// Wait for `holds`, polling — the deferred unlink runs on the worker after
/// the reply is written, so what it says lands on the stream after the
/// client has its answer.
fn wait_until(what: &str, holds: impl Fn() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(20);
    while !holds() {
        assert!(Instant::now() < deadline, "{what}: not within 20 s");
        thread::sleep(Duration::from_millis(10));
    }
}

/// ROW 37 ON THE STREAM (`operations.md` §1.1 row 37; §1 NEVER — a line is
/// said once per condition, never per request; the ops lanes' D21). A1 —
/// ONE FAILURE LINE PER STANDING UNLINK FAULT, NAMING THE ASIDE: a second
/// deposit of the same bytes is a REPLACE, which queues the replaced
/// instance's aside for the deferred unlink the transport runs after the
/// reply; with the store's seam failing that step, the stream carries
/// EXACTLY ONE `failure:` line naming the aside as its name within
/// `blobs/`, the cause and the act that clears it, and three more requests
/// of the family while the fault stands — a deposit read, a second replace,
/// a deposit read — write NO further line of any kind (the D9 discipline:
/// the family's requests write nothing), the asides standing on disk. A2 —
/// THE CLEARING: the seam disarmed, the next request's deferred unlink
/// drains the queue and the stream carries EXACTLY ONE `landing:` line; a
/// further request and replace write nothing, and no aside stands.
#[test]
fn a_failed_aside_unlink_is_said_once_naming_the_aside_and_cleared_once_when_the_queue_drains() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let token = open_session(port, CLAIMANT_PRINCIPAL);
    let bytes = b"the picture's bytes, replaced under the seam";
    assert!(blob_store_lines(&sd).is_empty(), "a healthy board: no line of the blob store's");
    after_the_first_pass(&sd);

    // The first deposit stands alone; the replace, under the seam, queues
    // its aside and the deferred unlink fails at it.
    put_whole(port, &token, bytes);
    sd.daemon().fail_blob_finish_at(Some(Step::UnlinkAside));
    put_whole(port, &token, bytes);
    wait_until("row 37's line", || !blob_store_lines(&sd).is_empty());
    let asides = asides_on_disk(dir.path());
    assert_eq!(asides.len(), 1, "the replaced instance's aside stands: {asides:?}");
    assert_eq!(
        blob_store_lines(&sd),
        [format!(
            "failure: blob store: the aside blake3/{} could not be unlinked: injected failure at \
             UnlinkAside; it stands for the pass or the next open",
            asides[0]
        )],
        "said once, naming the aside within blobs/, the cause and the act"
    );

    // THE ONCE: three more requests of the family while the fault stands,
    // each running the deferred unlink into the same fault — no further
    // line, of this kind or any.
    let before = sd.daemon().lines_said().len();
    let (st, _, _) = blob_deposit_read(port, Some(&token));
    assert_eq!(st, 200);
    put_whole(port, &token, bytes);
    let (st, _, _) = blob_deposit_read(port, Some(&token));
    assert_eq!(st, 200);
    thread::sleep(Duration::from_millis(500));
    assert_eq!(
        sd.daemon().lines_said().len(),
        before,
        "FINDING (row 37; §1 NEVER): a line per request of the family:\n{}",
        sd.daemon().lines_said().join("\n")
    );
    assert_eq!(asides_on_disk(dir.path()).len(), 2, "both asides stand, the first at the head");

    // A2 — THE CLEARING: disarmed, the next request's deferred unlink drains
    // the queue.
    sd.daemon().fail_blob_finish_at(None);
    let (st, _, _) = blob_deposit_read(port, Some(&token));
    assert_eq!(st, 200);
    wait_until("the clearing line", || blob_store_lines(&sd).len() == 2);
    assert_eq!(blob_store_lines(&sd)[1], "landing: blob store: the asides unlink again");
    assert!(asides_on_disk(dir.path()).is_empty(), "the queue drained: no aside stands");
    let before = sd.daemon().lines_said().len();
    let (st, _, _) = blob_deposit_read(port, Some(&token));
    assert_eq!(st, 200);
    put_whole(port, &token, bytes);
    wait_until("the replace's aside unlinked", || asides_on_disk(dir.path()).is_empty());
    thread::sleep(Duration::from_millis(300));
    assert_eq!(
        sd.daemon().lines_said().len(),
        before,
        "a cleared fault writes nothing more:\n{}",
        sd.daemon().lines_said().join("\n")
    );
    sd.shutdown();
}

/// A3 — THE COMMON CASE IS SILENT (row 37; D9): a deposit and a replace with
/// no fault armed write NO line — the stream is unchanged by the family's
/// requests — the replaced instance's aside unlinked by the deferred step
/// after the reply.
#[test]
fn a_replace_with_no_fault_writes_no_line_and_its_aside_goes_after_the_reply() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let token = open_session(port, CLAIMANT_PRINCIPAL);
    let bytes = b"the picture's bytes, replaced in the common case";
    after_the_first_pass(&sd);
    let before = sd.daemon().lines_said().len();
    put_whole(port, &token, bytes);
    put_whole(port, &token, bytes);
    wait_until("the replace's aside unlinked", || asides_on_disk(dir.path()).is_empty());
    thread::sleep(Duration::from_millis(300));
    assert_eq!(
        sd.daemon().lines_said().len(),
        before,
        "the family's requests write nothing:\n{}",
        sd.daemon().lines_said().join("\n")
    );
    assert!(blob_store_lines(&sd).is_empty());
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
            .args(["--port", &port.to_string(), "--workers", &skepd::DEFAULT_WORKERS.to_string(), "--origin", &format!("http://127.0.0.1:{port}")])
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
    let (st, _, _) = blob_resume(port, Some(&signed), &created, 5, b"world");
    assert_eq!(st, 200);
    let (st, _, _) = blob_deposit_read(port, Some(&signed));
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

/// m9 — THE FLOOR's REFUSAL IS SAID ONCE PER BINDING (`operations.md` §1.1
/// m9; §4 row 7; §0 THE RATES: once per condition, never per request), the
/// D9 vector's sibling: the free space pinned one byte below the floor in
/// force, TWO creations refused `507 deposit_refused` scope `floor` — and
/// the gate's stream carries ONE `failure:` line, the ruled words with the
/// two figures as the daemon read them; the daemon's own record holds no
/// line of it (the family's requests write nothing there); and nothing of
/// the D9 list rides the line: not the principal's number as a word of its
/// own, not the session's token, not an upload's identifier (a refused
/// creation makes none).
#[test]
fn the_floors_refusal_is_said_once_per_binding_with_the_figures_and_no_party() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let token = open_session(port, CLAIMANT_PRINCIPAL);
    after_the_first_pass(&sd);
    assert!(media_lines(&sd).is_empty(), "a healthy board: no line of the gate's");
    let floor = sd.daemon().media_floor_in_force();
    let free = floor - 1;
    sd.daemon().set_media_free_space(Some(free));
    let before = sd.daemon().lines_said().len();
    for attempt in 1..=2 {
        let (st, _, body) = blob_create(port, Some(&token), 10, b"");
        assert_eq!(st, 507, "attempt {attempt}: {}", String::from_utf8_lossy(&body));
        let v = json(&body);
        assert_eq!(v["error"].as_str(), Some("deposit_refused"), "{v}");
        assert_eq!(v["scope"].as_str(), Some("floor"), "{v}");
    }
    let said = media_lines(&sd);
    assert_eq!(
        said,
        [format!(
            "failure: deposits refused at the floor: the volume's free space {free} bytes is below \
             the floor in force {floor}; every write but a deposit serves; the acts: room on the \
             volume, a pass run early"
        )],
        "FINDING (m9): the binding is said once, at its first refusal, in the ruled words"
    );
    assert_eq!(sd.daemon().lines_said().len(), before, "the family's requests write nothing on the daemon's record");
    let line = &said[0];
    assert!(!line.contains(&token), "FINDING (D9): the token rides the floor's line: {line}");
    assert!(!names_a_hex_id(line), "FINDING (D9): an identifier rides the floor's line: {line}");
    let principal = CLAIMANT_PRINCIPAL.to_string();
    assert!(
        !line.split(|c: char| !c.is_ascii_digit()).any(|word| word == principal),
        "FINDING (D9): the principal's number rides the floor's line: {line}"
    );
    sd.daemon().set_media_free_space(None);
    sd.shutdown();
}

/// m9 — THE LIFT IS SAID AT A FINISH, NEVER AT AN ADMISSION: after a binding
/// (its one failure line; the standing line re-saying it at each tick
/// meanwhile, in L9's words), the free space pinned back above the floor: a
/// creation ADMITTED says nothing — the next chunk may re-refuse — and the
/// upload that FINISHES says ONE `landing:` line with its size and the two
/// figures as the daemon read them at the finish; a second finish says
/// nothing more; and a later binding says the failure again, the flag
/// cleared by the lift. No party on the lift's line either.
#[test]
fn the_lift_is_said_once_at_the_first_finish_above_the_floor_and_never_at_an_admission() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let token = open_session(port, CLAIMANT_PRINCIPAL);
    let floor = sd.daemon().media_floor_in_force();
    // THE BINDING, said once; the standing line carries it meanwhile.
    sd.daemon().set_media_free_space(Some(floor - 1));
    let (st, _, _) = blob_create(port, Some(&token), 10, b"");
    assert_eq!(st, 507);
    assert_eq!(media_lines(&sd).len(), 1, "{:?}", media_lines(&sd));
    sd.daemon().set_standing_interval_millis(40);
    // The clause opens the line; a claimed board's `CLAIMED-PERMISSIVE`
    // clause rides it after.
    let standing = format!(
        "standing: deposits refused at the floor (free space {} below the floor in force {floor})",
        floor - 1
    );
    wait_until("the standing line's floor clause", || {
        sd.daemon().lines_said().iter().any(|l| l.starts_with(&standing))
    });
    // ROOM AGAIN: an admission alone says no lift.
    let room = floor + 1_000_000;
    sd.daemon().set_media_free_space(Some(room));
    let (st, _, resp) = blob_create(port, Some(&token), 10, b"hello");
    assert_eq!(st, 200, "{}", String::from_utf8_lossy(&resp));
    let id = json(&resp)["upload"].as_str().expect("upload").to_string();
    assert_eq!(media_lines(&sd).len(), 1, "an admission alone says no lift: {:?}", media_lines(&sd));
    // THE FINISH: the lift, once.
    let (st, _, resp) = blob_resume(port, Some(&token), &id, 5, b"world");
    assert_eq!(st, 200, "{}", String::from_utf8_lossy(&resp));
    assert_eq!(json(&resp)["size"].as_u64(), Some(10), "the finish: {}", String::from_utf8_lossy(&resp));
    let said = media_lines(&sd);
    assert_eq!(said.len(), 2, "{said:?}");
    assert_eq!(
        said[1],
        format!(
            "landing: deposits admitted again: an upload of 10 bytes finished with the volume's \
             free space {room} bytes above the floor in force {floor}"
        ),
        "FINDING (m9): the lift at the first finish, with the finished size and the figures"
    );
    assert!(!said[1].contains(&token) && !names_a_hex_id(&said[1]), "FINDING (D9): a party rides the lift: {}", said[1]);
    // A second finish: nothing more.
    put_whole(port, &token, b"another whole picture, finished above the floor");
    assert_eq!(media_lines(&sd).len(), 2, "a second finish says nothing: {:?}", media_lines(&sd));
    // A NEW BINDING: said again — the flag cleared by the lift.
    sd.daemon().set_media_free_space(Some(floor - 2));
    let (st, _, _) = blob_create(port, Some(&token), 10, b"");
    assert_eq!(st, 507);
    let said = media_lines(&sd);
    assert_eq!(said.len(), 3, "{said:?}");
    assert!(
        said[2].starts_with(&format!(
            "failure: deposits refused at the floor: the volume's free space {} bytes is below the \
             floor in force {floor};",
            floor - 2
        )),
        "the next binding is said again: {}",
        said[2]
    );
    sd.daemon().set_media_free_space(None);
    sd.shutdown();
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
    let (st, _, resp) = blob_resume(port, Some(&token), &id, 0, b"hello");
    assert_eq!(st, 409, "{}", String::from_utf8_lossy(&resp));
    assert_eq!(json(&resp)["offset"].as_u64(), Some(3));
    let (st, _, resp) = blob_resume(port, Some(&token), &id, 3, b"loworld");
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
        blob_deposit_read(port, Some(&claimant)),
        blob_progress(port, Some(&claimant), "0123456789abcdef0123456789abcdef"),
        blob_resume(port, Some(&claimant), "0123456789abcdef0123456789abcdef", 0, b"x"),
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

/// THE UPLOAD POOL BOUNDS THE FAMILY (M-I5 (f) PICTURES NEVER STARVE OR
/// STALL THE JOURNAL — "an upload at most an UPLOAD PERMIT POOL at once …
/// a creation past it refused retry-class"; P29; M-I6 (h) THE REFUSAL'S
/// FACE names no headroom and no holder; M-I7 (e) the face names the act
/// the person holds, the retry), the fetch pool's test's twin: with every
/// upload permit held through the hook — their count the fixture's pin — a
/// creation with no body answers `503 upload_busy`, its `detail` naming the
/// retry and no figure, and a creation-with-upload the same before any body
/// byte, the principal's deposit read listing no new upload (none was
/// made); a standing upload resumed answers the same and its progress read
/// answers the offset it stood at (KEPT); the progress read, the deposit
/// read and the termination are served while every permit is held; the
/// permits released, the creation and the resume are served.
#[test]
fn the_upload_pool_bounds_the_family() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let token = open_session(port, CLAIMANT_PRINCIPAL);
    // Two standing uploads before the hold: one to resume, one to end.
    let (st, _, resp) = blob_create(port, Some(&token), 10, b"hello");
    assert_eq!(st, 200, "{}", String::from_utf8_lossy(&resp));
    let standing = json(&resp)["upload"].as_str().expect("upload").to_string();
    let (st, _, resp) = blob_create(port, Some(&token), 10, b"");
    assert_eq!(st, 200, "{}", String::from_utf8_lossy(&resp));
    let ending = json(&resp)["upload"].as_str().expect("upload").to_string();
    let held: Vec<_> = std::iter::repeat_with(|| sd.daemon().try_hold_upload_permit())
        .take_while(Option::is_some)
        .flatten()
        .collect();
    assert_eq!(
        held.len(),
        fixture()["pins"]["upload_pool"].as_u64().expect("upload_pool") as usize,
        "the pool's whole count held"
    );
    // The creation past the pool: refused before any record, no upload made.
    let (st, _, resp) = blob_create(port, Some(&token), 10, b"");
    let v = json(&resp);
    assert_eq!((st, v["error"].as_str()), (503, Some("upload_busy")), "{}", String::from_utf8_lossy(&resp));
    let detail = v["detail"].as_str().expect("the refusal names the act");
    assert!(detail.contains("retry"), "{detail}");
    assert!(!detail.chars().any(|c| c.is_ascii_digit()), "no headroom and no count of holders: {detail}");
    // A creation-with-upload past the pool: the same, before any body byte.
    let (st, _, resp) = blob_create(port, Some(&token), 5, b"hello");
    assert_eq!((st, json(&resp)["error"].as_str()), (503, Some("upload_busy")), "{}", String::from_utf8_lossy(&resp));
    let (st, _, resp) = blob_deposit_read(port, Some(&token));
    assert_eq!(st, 200, "the deposit read takes no permit: {}", String::from_utf8_lossy(&resp));
    let listed: BTreeSet<String> = json(&resp)["uploads"]
        .as_array()
        .expect("uploads")
        .iter()
        .map(|u| u["upload"].as_str().expect("upload").to_string())
        .collect();
    assert_eq!(listed, [standing.clone(), ending.clone()].into_iter().collect(), "no upload was made past the pool");
    // The resume past the pool: refused, the upload KEPT where it stood.
    let (st, _, resp) = blob_resume(port, Some(&token), &standing, 5, b"world");
    let v = json(&resp);
    assert_eq!((st, v["error"].as_str()), (503, Some("upload_busy")), "{}", String::from_utf8_lossy(&resp));
    assert!(v["detail"].as_str().is_some_and(|d| d.contains("retry")));
    let (st, _, resp) = blob_progress(port, Some(&token), &standing);
    assert_eq!(
        (st, json(&resp)["offset"].as_u64()),
        (200, Some(5)),
        "the progress read takes no permit, and the refused resume kept the upload at its offset"
    );
    let (st, _, _) = blob_end(port, Some(&token), &ending);
    assert_eq!(st, 204, "the termination takes no permit");
    drop(held);
    let (st, _, resp) = blob_create(port, Some(&token), 10, b"");
    assert_eq!(st, 200, "a released permit serves the creation: {}", String::from_utf8_lossy(&resp));
    let (st, _, resp) = blob_resume(port, Some(&token), &standing, 5, b"world");
    assert_eq!(st, 200, "a released permit serves the resume: {}", String::from_utf8_lossy(&resp));
    assert_eq!(json(&resp)["hash"].as_str(), Some(blob_hex(b"helloworld").as_str()));
    sd.shutdown();
}

/// Read a response head off `s` up to its blank line — the interim `100
/// Continue` a client that asked for one is sent before the body is
/// invited.
fn read_interim(s: &mut TcpStream) -> String {
    let mut raw = Vec::new();
    let mut chunk = [0u8; 1024];
    while !raw.windows(4).any(|w| w == b"\r\n\r\n") {
        let n = s.read(&mut chunk).expect("the interim");
        assert!(n > 0, "closed before the interim: {}", String::from_utf8_lossy(&raw));
        raw.extend_from_slice(&chunk[..n]);
    }
    String::from_utf8_lossy(&raw).to_string()
}

/// Read a connection to its end — the daemon's close, or the reset it
/// answers a body left unread with — the bytes before it the answer.
fn read_to_any_end(s: &mut TcpStream) -> Vec<u8> {
    let mut raw = Vec::new();
    let mut chunk = [0u8; 8192];
    loop {
        match s.read(&mut chunk) {
            Ok(0) | Err(_) => break,
            Ok(n) => raw.extend_from_slice(&chunk[..n]),
        }
    }
    raw
}

/// THE LIVENESS UNDER TRICKLING UPLOADS (M-I5 (f) PICTURES NEVER STARVE OR
/// STALL THE JOURNAL: "an upload at most an UPLOAD PERMIT POOL at once
/// beside it, counted in the same budget, a creation past it refused
/// retry-class"; P29; M-I7 (e)) — the intake's vector as a real transfer,
/// and the one test that pins worker OCCUPANCY: the daemon served
/// in-process with ONE worker more than the pool holds, so the streams the
/// pool admits hold every worker but the one that answers. As many
/// creations-with-upload as the pool holds, each declaring two bytes, each
/// admitted — the interim `100 Continue` carrying its identifier is the
/// proof that the permit was taken and the record made — each sending its
/// first byte and then holding its socket open inside the idle bound for
/// as long as these assertions take; one more creation on a fresh
/// connection, sent no body byte, answers `503 upload_busy` before any; and
/// WHILE THE STREAMS STAND `GET /health` answers `ok`, `POST /session`
/// answers a session and a write on `/op` under the claimant's session is
/// acked — the three surfaces the record names. Then each stream sends its
/// last byte and is answered the finish, and a fresh creation is served:
/// the pool's count is the number of streams admitted, no more and no
/// fewer.
#[test]
fn trickling_uploads_fill_the_pool_and_never_the_daemon() {
    let pool = fixture()["pins"]["upload_pool"].as_u64().expect("upload_pool") as usize;
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn_with_workers(dir.path(), pool + 1);
    let port = sd.port();
    let token = open_session(port, CLAIMANT_PRINCIPAL);
    let creation = |expect_continue: bool| {
        let mut s = TcpStream::connect(("127.0.0.1", port)).expect("connect");
        s.set_read_timeout(Some(Duration::from_secs(30))).expect("timeout");
        let expect = if expect_continue { "Expect: 100-continue\r\n" } else { "" };
        let head = format!(
            "POST {BLOB_UPLOAD}?length=2 HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\
             Content-Length: 2\r\n{expect}Skepd-Session: {token}\r\n\r\n"
        );
        s.write_all(head.as_bytes()).expect("head");
        s
    };
    // The streams: a creation-with-upload each, admitted — the interim
    // says so — then holding a worker and a permit past its first byte.
    let mut streams: Vec<(TcpStream, [u8; 2])> = Vec::with_capacity(pool);
    for n in 0..pool {
        let body = [b'0' + n as u8, b'!'];
        let mut s = creation(true);
        let interim = read_interim(&mut s);
        assert!(interim.starts_with("HTTP/1.1 100 Continue\r\n"), "stream {n} admitted: {interim}");
        assert!(interim.contains("Upload-Id: "), "stream {n}'s record made: {interim}");
        s.write_all(&body[..1]).expect("the first byte");
        s.flush().ok();
        streams.push((s, body));
    }
    // One more, on a fresh connection, sent no body byte: refused before
    // any — on the one worker the streams leave free.
    let mut past = creation(false);
    let raw = read_to_any_end(&mut past);
    let (st, _, resp) = parse_response(&raw, "the creation past the pool");
    let v = json(&resp);
    assert_eq!((st, v["error"].as_str()), (503, Some("upload_busy")), "{}", String::from_utf8_lossy(&resp));
    assert!(v["detail"].as_str().is_some_and(|d| d.contains("retry")), "{}", String::from_utf8_lossy(&resp));
    // While the streams stand: the three surfaces the record names.
    let (st, body) = get(port, "/health");
    assert_eq!(st, 200, "{}", String::from_utf8_lossy(&body));
    assert_eq!(json(&body)["ok"].as_bool(), Some(true), "/health answers ok with every permit held");
    let fresh = open_session(port, CLAIMANT_PRINCIPAL);
    assert!(!fresh.is_empty(), "POST /session answers a session with every permit held");
    let draft = owner_draft(port, &token);
    assert!(!draft.is_empty(), "a write on /op is acked with every permit held");
    // Each stream's last byte: the finish.
    for (n, (mut s, body)) in streams.into_iter().enumerate() {
        s.write_all(&body[1..]).expect("the last byte");
        s.shutdown(Shutdown::Write).ok();
        let raw = read_to_any_end(&mut s);
        let (st, _, resp) = parse_response(&raw, "the finish");
        assert_eq!(st, 200, "stream {n}'s finish: {}", String::from_utf8_lossy(&resp));
        assert_eq!(json(&resp)["hash"].as_str(), Some(blob_hex(&body).as_str()));
    }
    // The permits returned with the streams: a fresh creation is served.
    let (st, _, resp) = blob_create(port, Some(&token), 2, b"");
    assert_eq!(st, 200, "the pool is whole again: {}", String::from_utf8_lossy(&resp));
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
        sd.daemon().install_media_limits(None, None, Some(500), None, None).expect("installs");
        let (st, _, resp) = blob_create(port, Some(&token), 10, b"hello");
        assert_eq!(st, 200, "{}", String::from_utf8_lossy(&resp));
        let expired = json(&resp)["upload"].as_str().unwrap().to_string();
        thread::sleep(Duration::from_millis(700));
        let (st, _, _) = blob_progress(port, Some(&token), &expired);
        assert_eq!(st, 404, "expired: no upload");
        assert_eq!(json(&blob_deposit_read(port, Some(&token)).2)["pending"].as_u64(), Some(0), "counts nothing");
        sd.daemon().install_media_limits(None, None, None, None, None).expect("installs");
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
    let (st, _, resp) = blob_resume(port, Some(&token), &standing, 5, b"world");
    assert_eq!(st, 200, "{}", String::from_utf8_lossy(&resp));
    assert_eq!(json(&resp)["hash"].as_str(), Some(blob_hex(b"helloworld").as_str()), "the hash covers the bytes received before the reopen");
    sd.shutdown();
}
