//! Shared tier-1 fuzz plumbing (hardening H2): harvest wire.md's pinned
//! examples as the self-maintaining corpus (the same `<!-- wire: … -->`
//! fenced blocks `tests/wire_doc.rs` asserts, so the corpus grows with the
//! wire), plus the iteration budget and byte generators. Kept separate from
//! `tests/common/` (the socket helpers) — a fuzz test declares both.
//!
//! The mutation engine and oracles live in `skepd::fuzz_support` (the seam
//! the nightly libFuzzer targets share); this file is only the corpus and
//! the loop scaffolding the gate needs.

#![allow(dead_code)]

use std::path::Path;

use skepd::fuzz_support::splitmix64;

/// `FUZZ_EXHAUSTIVE=1` widens every budget — the deep, out-of-gate sweep.
pub fn exhaustive() -> bool {
    std::env::var_os("FUZZ_EXHAUSTIVE").is_some_and(|v| v == "1")
}

/// The iteration budget: `default` in-gate (whole tier under ~60 s), ×40
/// under `FUZZ_EXHAUSTIVE`.
pub fn iters(default: usize) -> usize {
    if exhaustive() {
        default * 40
    } else {
        default
    }
}

fn wire_md() -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs/wire.md");
    std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()))
}

/// (kind, name, body) for every `<!-- wire: … -->` fenced block — the exact
/// harvest `wire_doc.rs` uses, so the two corpora cannot diverge.
fn blocks() -> Vec<(String, String, String)> {
    let text = wire_md();
    let mut out = Vec::new();
    let mut lines = text.lines().peekable();
    while let Some(line) = lines.next() {
        let Some(rest) = line.trim().strip_prefix("<!-- wire:") else { continue };
        let rest = rest.trim().trim_end_matches("-->").trim();
        let mut parts = rest.split_whitespace();
        let kind = parts.next().expect("marker kind").to_string();
        let name = parts.next().expect("marker name").to_string();
        while let Some(l) = lines.peek() {
            if l.trim().is_empty() {
                lines.next();
            } else {
                break;
            }
        }
        let fence = lines.next().unwrap_or_else(|| panic!("no fence after marker '{name}'"));
        assert!(fence.trim().starts_with("```"), "marker '{name}' not followed by a fence");
        let mut body = String::new();
        for l in lines.by_ref() {
            if l.trim().starts_with("```") {
                break;
            }
            body.push_str(l);
            body.push('\n');
        }
        out.push((kind, name, body));
    }
    assert!(!out.is_empty(), "wire.md carries no marked examples");
    out
}

/// Every `request` example frame, as bytes — the codec/`POST /op` corpus.
pub fn request_frames() -> Vec<Vec<u8>> {
    blocks()
        .into_iter()
        .filter(|(k, _, _)| k == "request")
        .map(|(_, _, body)| body.trim().as_bytes().to_vec())
        .collect()
}

/// The read `frame` inside every `op_at` example — extra parseable frames
/// for the codec corpus.
pub fn op_at_frames() -> Vec<Vec<u8>> {
    blocks()
        .into_iter()
        .filter(|(k, _, _)| k == "op_at")
        .filter_map(|(_, _, body)| {
            let v: serde_json::Value = serde_json::from_str(&body).ok()?;
            let frame = v.get("frame")?;
            Some(serde_json::to_vec(frame).ok()?)
        })
        .collect()
}

/// The whole parseable-frame corpus: request examples plus op_at frames.
pub fn frame_corpus() -> Vec<Vec<u8>> {
    let mut v = request_frames();
    v.extend(op_at_frames());
    assert!(!v.is_empty(), "no parseable frames harvested from wire.md");
    v
}

/// The `op_at` envelope bodies (whole `{"at","frame"}` objects) — the
/// `/op-at` endpoint corpus.
pub fn op_at_envelopes() -> Vec<Vec<u8>> {
    blocks()
        .into_iter()
        .filter(|(k, _, _)| k == "op_at")
        .map(|(_, _, body)| body.trim().as_bytes().to_vec())
        .collect()
}

/// A seeded arbitrary byte string of length `0..=maxlen`.
pub fn random_bytes(st: &mut u64, maxlen: usize) -> Vec<u8> {
    let len = (splitmix64(st) as usize) % (maxlen + 1);
    (0..len).map(|_| (splitmix64(st) & 0xff) as u8).collect()
}

/// A seeded arbitrary *UTF-8* line (no newline) — for line protocols where
/// non-UTF-8 or an embedded newline changes the framing rather than the
/// payload.
pub fn random_utf8_line(st: &mut u64, maxlen: usize) -> String {
    let len = (splitmix64(st) as usize) % (maxlen + 1);
    let mut s = String::with_capacity(len);
    for _ in 0..len {
        // Bias toward JSON-ish punctuation and ASCII so the parser is
        // actually exercised, with the occasional wider scalar.
        let pick = splitmix64(st) % 32;
        let ch = match pick {
            0..=20 => {
                let ascii = b" {}[]\":,0123456789tfnul-.abcxyz";
                ascii[(splitmix64(st) as usize) % ascii.len()] as char
            }
            21..=28 => char::from_u32(0x20 + (splitmix64(st) as u32 % 0x5e)).unwrap_or('?'),
            _ => char::from_u32(0x100 + (splitmix64(st) as u32 % 0x2000)).unwrap_or('?'),
        };
        if ch != '\n' && ch != '\r' {
            s.push(ch);
        }
    }
    s
}
