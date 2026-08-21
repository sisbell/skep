//! Shared fuzzing harness (hardening H2) — the pure oracle and mutation
//! logic that BOTH the in-gate tier-1 `#[test]`s
//! (`crates/skepd/tests/fuzz_*.rs`) and the ad-hoc nightly libFuzzer targets
//! (`skep/fuzz/`) drive. The pinned stable toolchain cannot compile
//! libFuzzer, so the tier-2 wrappers must be trivial by construction: they
//! call the functions here, which the gate DOES compile and test. Nothing
//! here is a stable API — the module is `#[doc(hidden)]` and may change with
//! the daemon.
//!
//! Every function serves one contract: **any bytes in → exactly one
//! well-formed answer out, never a panic, never a hang, never silence.** The
//! oracle functions PANIC on a violation (that is the finding); the exchange
//! helper never hangs (bounded socket deadlines); the mutation engine is a
//! pure, deterministic `(seed, corpus) → bytes`.
//!
//! Dependency posture: std plus this crate's own `serde_json`/codec only —
//! no `tempfile`, no server library — so exposing it adds nothing to a
//! production build but a handful of small functions. Daemon lifetime
//! (temp dirs, `serve`) stays with the caller, which is why the exchange
//! helpers take a live `port`, never a directory.

use std::io::{Read, Write};
use std::net::{Shutdown, TcpStream};
use std::time::Duration;

use serde_json::{Map, Number, Value};
use skep_febe::Codec;

use crate::JsonCodec;

/// SplitMix64 — the deterministic seed source the whole H-suite uses (H3's
/// pattern); the seed is the entire reproduction.
pub fn splitmix64(state: &mut u64) -> u64 {
    *state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
    let mut z = *state;
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

/// The 19 response shapes every client must decode (wire.md §The response
/// envelope + §Rejections); a `/op` answer always carries one of these in
/// `resp`.
pub const RESP_SHAPES: &[&str] = &[
    "ack",
    "ack_addr",
    "ack_edit",
    "delivery",
    "span_set",
    "addrs",
    "maybe_addr",
    "count",
    "page",
    "endsets",
    "runs",
    "bool",
    "link_value",
    "follow",
    "deletions",
    "compare",
    "orphans",
    "claims",
    "rejected",
];

/// The transport-level `error` names the HTTP surface is allowed to answer
/// (wire.md §HTTP status codes, §Reading history, §The change feed). A
/// non-2xx body naming anything else is a never-silent violation: an
/// undocumented failure a client cannot interpret.
pub const TRANSPORT_ERRORS: &[&str] = &[
    "malformed_session_request",
    "malformed_op_at",
    "write_at_history",
    "beyond_head",
    "not_a_position",
    "malformed_at",
    "malformed_changes",
    "malformed_http",
    "payload_too_large",
    "no_such_endpoint",
    "method_not_allowed",
    "history_reclaimed",
    "history_busy",
    "internal_panic",
    "history_io",
    "history_corrupt",
    "no_journal",
];

// ── the codec oracle ─────────────────────────────────────────────────────

/// The codec's never-silent contract under hostile bytes. Returning at all
/// witnesses that `parse` did not panic; a parse that succeeds must
/// canonicalize to a fixpoint (`marshal_request` of the parse re-parses and
/// re-marshals byte-identically — the observable round-trip, standing in for
/// `parse(marshal_request(x)) == x` without needing `Request: Eq`); a parse
/// that fails is simply the transport's Unparseable path. Returns whether
/// the frame parsed, so a caller can drive the "if it parses, it executes to
/// a single response" clause. **Panics only on an oracle violation.**
pub fn codec_roundtrip_oracle(frame: &[u8]) -> bool {
    let codec = JsonCodec;
    match codec.parse(frame) {
        Ok(req) => {
            let once = codec.marshal_request(&req);
            let reparsed = match codec.parse(&once) {
                Ok(r) => r,
                Err(e) => panic!(
                    "canonical re-parse FAILED: a parsed frame did not round-trip \
                     ({:?})\n  input:   {}\n  marshal: {}",
                    e.detail,
                    hex(frame),
                    String::from_utf8_lossy(&once),
                ),
            };
            let twice = codec.marshal_request(&reparsed);
            assert_eq!(
                once,
                twice,
                "marshal_request is not a canonical fixpoint (non-deterministic \
                 encoding)\n  input: {}\n  once:  {}\n  twice: {}",
                hex(frame),
                String::from_utf8_lossy(&once),
                String::from_utf8_lossy(&twice),
            );
            true
        }
        Err(_) => false,
    }
}

/// Lowercase hex of a byte slice — the reproduction form findings record.
pub fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

// ── the HTTP oracle ──────────────────────────────────────────────────────

/// One raw exchange against a running daemon: connect, write `raw` verbatim
/// (a complete request, a fragment, or garbage), half-close the write side
/// so the daemon sees EOF and cannot wait on a body that will never arrive,
/// then read to close under a bounded deadline. Returns whatever bytes came
/// back — empty for a clean close with no answer (a probe), a full response
/// otherwise. **Never hangs**: a wedged or streaming peer hits the read
/// deadline and returns what has arrived so far. Only a failed *connect* is
/// an `Err` (the daemon is gone).
pub fn http_raw_exchange(port: u16, raw: &[u8]) -> std::io::Result<Vec<u8>> {
    let mut s = TcpStream::connect(("127.0.0.1", port))?;
    s.set_nodelay(true).ok();
    s.set_read_timeout(Some(Duration::from_secs(5)))?;
    s.set_write_timeout(Some(Duration::from_secs(5)))?;
    // A write may fail if the daemon already answered and closed (an
    // oversized head, a refused method) — fine; still read what it sent.
    let _ = s.write_all(raw);
    let _ = s.shutdown(Shutdown::Write);
    let mut out = Vec::new();
    let mut chunk = [0u8; 8192];
    loop {
        match s.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => out.extend_from_slice(&chunk[..n]),
            // ANY read end — EOF, a deadline (a kept-open stream or a
            // mid-response wedge), or a reset/broken pipe (the daemon
            // answered a large hostile request and closed while we were still
            // writing) — returns the bytes gathered so far; the oracle judges
            // them. Only a failed CONNECT (above) is an error: the daemon is
            // gone. An empty `out` is a clean close the caller reads as such;
            // a partial response is a finding `check_http_response` catches.
            Err(_) => break,
        }
    }
    Ok(out)
}

/// The well-formedness oracle for one HTTP response: a parseable
/// `HTTP/1.1 <code>` status line, a header block of `Name: value` lines, the
/// universal `Access-Control-Allow-Origin` (wire v4), and a body whose
/// length agrees with `Content-Length` — except a `204` carries none and a
/// `text/event-stream` is an unbounded stream with no declared length.
/// Returns the status code. Callers gate on non-empty input first (an empty
/// response is a clean close, judged by the caller's own context).
pub fn check_http_response(bytes: &[u8]) -> Result<u16, String> {
    if bytes.is_empty() {
        return Err("no response bytes (server closed without answering)".into());
    }
    let sep = bytes
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or("no CRLFCRLF header terminator")?;
    let head = std::str::from_utf8(&bytes[..sep]).map_err(|_| "non-UTF-8 response head")?;
    let mut lines = head.split("\r\n");
    let status_line = lines.next().ok_or("empty response head")?;
    let mut parts = status_line.split(' ');
    match parts.next() {
        Some("HTTP/1.1") => {}
        _ => return Err(format!("status line is not HTTP/1.1: {status_line:?}")),
    }
    let status: u16 = parts
        .next()
        .ok_or("no status code")?
        .parse()
        .map_err(|_| format!("non-numeric status code: {status_line:?}"))?;

    let mut content_length: Option<usize> = None;
    let mut content_type = String::new();
    let mut saw_cors = false;
    for line in lines {
        if line.is_empty() {
            continue;
        }
        let (name, value) = line
            .split_once(':')
            .ok_or_else(|| format!("malformed header line: {line:?}"))?;
        let (name, value) = (name.trim(), value.trim());
        if name.eq_ignore_ascii_case("Content-Length") {
            content_length =
                Some(value.parse().map_err(|_| format!("bad Content-Length: {value:?}"))?);
        } else if name.eq_ignore_ascii_case("Content-Type") {
            content_type = value.to_ascii_lowercase();
        } else if name.eq_ignore_ascii_case("Access-Control-Allow-Origin") {
            saw_cors = true;
        }
    }
    if !saw_cors {
        return Err("response missing Access-Control-Allow-Origin (wire v4)".into());
    }
    let body = &bytes[sep + 4..];
    if content_type.contains("text/event-stream") {
        // An unbounded stream: no declared length, body is a prefix.
        return Ok(status);
    }
    if status == 204 {
        if !body.is_empty() {
            return Err("204 response carried a body".into());
        }
        return Ok(status);
    }
    match content_length {
        Some(n) if n == body.len() => Ok(status),
        Some(n) => Err(format!("Content-Length {n} disagrees with body length {}", body.len())),
        None => Err("non-204 response without Content-Length".into()),
    }
}

/// The envelope endpoints' oracle (wire.md §Reading history, §The change
/// feed, §Sessions): route the fuzz bytes to one of the four structured
/// endpoints, exchange, and demand a well-formed HTTP response whose error
/// name — on any non-2xx — is one wire.md documents. A 2xx is any documented
/// success. An empty answer (clean close) is accepted; the endpoint-specific
/// success shapes are asserted more tightly in the tier-1 tests. **Panics on
/// an undocumented error name or a malformed response** via the returned
/// `Err`, which callers surface.
pub fn envelope_oracle(port: u16, data: &[u8]) -> Result<(), String> {
    if data.is_empty() {
        return Ok(());
    }
    let payload = &data[1..];
    let raw = match data[0] % 4 {
        0 => build_post("/session", payload),
        1 => build_post("/op-at", payload),
        2 => build_get(&format!("/changes?{}", String::from_utf8_lossy(payload))),
        _ => build_get(&format!("/dump?{}", String::from_utf8_lossy(payload))),
    };
    let resp = http_raw_exchange(port, &raw).map_err(|e| format!("exchange: {e}"))?;
    if resp.is_empty() {
        return Ok(());
    }
    let status = check_http_response(&resp)?;
    if status >= 400 {
        let sep = resp.windows(4).position(|w| w == b"\r\n\r\n").expect("header terminator");
        let body = &resp[sep + 4..];
        let v: Value =
            serde_json::from_slice(body).map_err(|e| format!("error body is not JSON: {e}"))?;
        let name = v
            .get("error")
            .and_then(Value::as_str)
            .ok_or_else(|| format!("error response without an 'error' field: {v}"))?;
        if !TRANSPORT_ERRORS.contains(&name) {
            return Err(format!("undocumented transport error '{name}' (status {status})"));
        }
    }
    Ok(())
}

/// A minimal `POST <path>` with a JSON body and correct `Content-Length`.
pub fn build_post(path: &str, body: &[u8]) -> Vec<u8> {
    let mut v = format!(
        "POST {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\n\
         Content-Length: {}\r\n\r\n",
        body.len()
    )
    .into_bytes();
    v.extend_from_slice(body);
    v
}

/// A minimal bodyless `GET <path>` (the query rides in `path`).
pub fn build_get(path: &str) -> Vec<u8> {
    format!("GET {path} HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n").into_bytes()
}

// ── the grammar-aware mutation engine ────────────────────────────────────

/// One mutant from a corpus of example frames (tier-1's core). Raw byte
/// storms find panics; field-wise mutation finds the semantic edges — so
/// this parses a seeded base example, applies one seeded mutation, and
/// re-serializes: drop / duplicate / rename / retype / swap a field, junk a
/// tumbler's digits, deep-nest a value, splice two examples (field-merge),
/// truncate mid-frame, or splice at the byte level. Pure and deterministic
/// in `(seed, corpus)`; the recipe and base indices are recoverable from the
/// seed, which a failing tier-1 test records.
pub fn mutate(seed: u64, corpus: &[Vec<u8>]) -> Vec<u8> {
    if corpus.is_empty() {
        return Vec::new();
    }
    let mut st = seed ^ 0x243F_6A88_85A3_08D3;
    let base = &corpus[(splitmix64(&mut st) as usize) % corpus.len()];
    let recipe = splitmix64(&mut st) % 10;

    // Byte-level recipes need no valid JSON.
    if recipe == 8 {
        let mut v = base.clone();
        if !v.is_empty() {
            let cut = (splitmix64(&mut st) as usize) % v.len();
            v.truncate(cut);
        }
        return v;
    }
    if recipe == 9 {
        let other = &corpus[(splitmix64(&mut st) as usize) % corpus.len()];
        let a = if base.is_empty() { 0 } else { (splitmix64(&mut st) as usize) % base.len() };
        let b = if other.is_empty() { 0 } else { (splitmix64(&mut st) as usize) % other.len() };
        let mut v = base[..a].to_vec();
        v.extend_from_slice(&other[b..]);
        return v;
    }

    // Value-level recipes over a parsed base (every wire.md example is JSON).
    let mut val: Value = match serde_json::from_slice(base) {
        Ok(v) => v,
        Err(_) => return base.clone(),
    };
    match recipe {
        5 => {
            junk_first_tumbler(&mut val, &mut st);
        }
        6 => deep_nest_a_field(&mut val, &mut st),
        7 => splice_merge(&mut val, corpus, &mut st),
        r => {
            if let Value::Object(m) = &mut val {
                object_edit(m, r, &mut st);
            }
        }
    }
    serde_json::to_vec(&val).unwrap_or_else(|_| base.clone())
}

/// Recipes 0–4: structural edits over one object's fields.
fn object_edit(m: &mut Map<String, Value>, recipe: u64, st: &mut u64) {
    let keys: Vec<String> = m.keys().cloned().collect();
    if keys.is_empty() {
        return;
    }
    let k = keys[(splitmix64(st) as usize) % keys.len()].clone();
    match recipe {
        0 => {
            m.remove(&k);
        }
        1 => {
            // JSON cannot carry a duplicate key; duplicate the value under a
            // near-name, which is itself an unknown-field probe.
            if let Some(v) = m.get(&k).cloned() {
                m.insert(format!("{k}_dup"), v);
            }
        }
        2 => {
            if let Some(v) = m.remove(&k) {
                m.insert(edit_one_char(&k, st), v);
            }
        }
        3 => {
            if let Some(slot) = m.get_mut(&k) {
                *slot = retype(slot, st);
            }
        }
        4 => {
            if keys.len() >= 2 {
                let k2 = keys[(splitmix64(st) as usize) % keys.len()].clone();
                if k2 != k {
                    let a = m.get(&k).cloned();
                    let b = m.get(&k2).cloned();
                    if let (Some(a), Some(b)) = (a, b) {
                        m.insert(k, b);
                        m.insert(k2, a);
                    }
                }
            }
        }
        _ => {}
    }
}

/// Retype a value across the JSON type lattice (string↔number↔object↔array↔
/// null↔bool).
fn retype(v: &Value, st: &mut u64) -> Value {
    match splitmix64(st) % 6 {
        0 => Value::Null,
        1 => Value::Bool((splitmix64(st) & 1) == 0),
        2 => Value::Number(Number::from(splitmix64(st) as i64)),
        3 => Value::String(format!("mut{}", splitmix64(st) % 100_000)),
        4 => Value::Array(vec![v.clone()]),
        _ => {
            let mut m = Map::new();
            m.insert("wrapped".to_string(), v.clone());
            Value::Object(m)
        }
    }
}

/// Flip one byte of a key to a different ASCII letter — turns a known field
/// name into an unknown one (the never-silent-on-typos probe).
fn edit_one_char(k: &str, st: &mut u64) -> String {
    if k.is_empty() {
        return "x".into();
    }
    let mut bytes = k.as_bytes().to_vec();
    let i = (splitmix64(st) as usize) % bytes.len();
    bytes[i] = b'a' + (bytes[i].wrapping_add(1) % 26);
    String::from_utf8_lossy(&bytes).into_owned()
}

/// Junk the first tumbler-shaped string in the tree: empty components, a
/// huge natural, adjacent zeros, or a minus sign — the address-grammar
/// hostilities the leaf parsers must reject cleanly.
fn junk_first_tumbler(v: &mut Value, st: &mut u64) -> bool {
    match v {
        Value::String(s) if looks_like_tumbler(s) => {
            *s = match splitmix64(st) % 5 {
                0 => format!("{s}."),               // trailing dot ⇒ empty component
                1 => format!("{s}.{}", "9".repeat(40)), // huge natural
                2 => format!("{s}.0.0.1"),          // adjacent zeros
                3 => format!("{s}.-2"),             // minus sign
                _ => "1..2".to_string(),            // empty interior component
            };
            true
        }
        Value::Array(a) => a.iter_mut().any(|x| junk_first_tumbler(x, st)),
        Value::Object(m) => m.values_mut().any(|x| junk_first_tumbler(x, st)),
        _ => false,
    }
}

/// A dotted-decimal tumbler string: nonempty, digits and dots only, at least
/// one digit.
fn looks_like_tumbler(s: &str) -> bool {
    !s.is_empty()
        && s.bytes().all(|b| b.is_ascii_digit() || b == b'.')
        && s.bytes().any(|b| b.is_ascii_digit())
}

/// Deep-nest one field's value inside a seeded number of array wrappers — a
/// recursion-depth probe for the parsers.
fn deep_nest_a_field(v: &mut Value, st: &mut u64) {
    let Value::Object(m) = v else { return };
    let keys: Vec<String> = m.keys().cloned().collect();
    if keys.is_empty() {
        return;
    }
    let k = &keys[(splitmix64(st) as usize) % keys.len()];
    if let Some(slot) = m.get_mut(k) {
        let depth = 1 + splitmix64(st) % 8;
        for _ in 0..depth {
            *slot = Value::Array(vec![std::mem::replace(slot, Value::Null)]);
        }
    }
}

/// Splice two examples: merge another example's top-level fields into this
/// object, colliding keys and mixing operation shapes.
fn splice_merge(v: &mut Value, corpus: &[Vec<u8>], st: &mut u64) {
    let Value::Object(m) = v else { return };
    let other = &corpus[(splitmix64(st) as usize) % corpus.len()];
    if let Ok(Value::Object(om)) = serde_json::from_slice::<Value>(other) {
        for (k, val) in om {
            m.insert(k, val);
        }
    }
}
