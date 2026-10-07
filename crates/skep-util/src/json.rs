//! The JSON determinism helpers: the key-sorting object builder every JSON
//! object the daemon emits is built through, and the lowercase hex pair —
//! the encoding behind every hex the daemon writes, and the exact-inverse
//! parse behind every value it reads back only as its own emitter wrote
//! it. The daemon's codec and the media crate's cell each read hex the
//! other wrote, so ONE table serves both and the canonical rule cannot
//! drift between two copies.

use serde_json::{Map, Value};

/// Build a JSON object with keys sorted — THE determinism device. Every
/// JSON object the daemon emits is constructed through it — wire responses,
/// transport-error bodies, the commit stream's event payloads, and the
/// sidecar's own file lines — so canonical output is alphabetical-by-key
/// under any serde_json map backend. The sort is STABLE, which is what
/// makes "the last pair given wins" a fact about duplicate keys rather than
/// an accident of the sort.
pub fn obj(mut pairs: Vec<(&'static str, Value)>) -> Value {
    pairs.sort_by_key(|&(k, _)| k);
    let mut m = Map::new();
    for (k, v) in pairs {
        m.insert(k.to_string(), v);
    }
    Value::Object(m)
}

/// The ASCII hex table, LOWERCASE — the decode side of [`hex_string`], and
/// the ONE mapping the daemon holds from a hex byte to a nibble.
///
/// CASE IS POLICY and stays with each parser, which is the whole of what
/// the three differ by: the codec's `hex_digit` folds it and names the
/// offending character; [`parse_lower_hex`] REFUSES it, admitting only what
/// [`hex_string`] emits — the parse behind the nonce, the session token, the
/// published head's hashes and the media cells' hashes, so an uppercase nonce
/// is a syntax fault whose nonce survives rather than a burned credential,
/// and an uppercase cell hash spells no cell; and the session's signature
/// parser (`auth::session::parse_case_free_hex`) folds it, the signature
/// being decoded and never framed. None of them owns the table.
pub fn hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        _ => None,
    }
}

/// Exactly `N` bytes of LOWERCASE hex, or `None` — [`hex_string`]'s exact
/// inverse at a fixed width, and the parse of every value the daemon reads
/// back only as its own emitter wrote it: the handshake nonce and the
/// session token (AUTH-4.15, AUTH-4.17), the published head's hashes, a
/// picture cell's `hash` and a blind cell's `commitment` (`media/cell.rs`,
/// `media/blind.rs`: the canonical rule admits only what `encode` writes,
/// M-I3 (a)), and the hash an operator copies from the inventory's listing
/// into the pull (`tools::pull`). Each admits only what `hex_string`
/// produced, so an uppercase value — or a signed pair, which a radix parse
/// would read — is refused rather than normalized; what the refusal costs is
/// stated on each caller. The REFUSAL is this function's own, in the byte it
/// hands [`hex_nibble`].
pub fn parse_lower_hex<const N: usize>(s: &str) -> Option<[u8; N]> {
    if s.len() != N * 2 {
        return None;
    }
    let mut raw = [0u8; N];
    for (i, chunk) in s.as_bytes().chunks_exact(2).enumerate() {
        raw[i] = (hex_nibble(chunk[0])? << 4) | hex_nibble(chunk[1])?;
    }
    Some(raw)
}

/// Lowercase hex — the encoding behind `{"hex"}`, `{"atom_hex"}`, and the
/// fuzz harness's reproduction form, so all three read the same bytes back;
/// the daemon's `fuzz_support` re-exports it as its `hex`.
pub fn hex_string(b: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(b.len() * 2);
    for &byte in b {
        s.push(DIGITS[(byte >> 4) as usize] as char);
        s.push(DIGITS[(byte & 0x0f) as usize] as char);
    }
    s
}

#[cfg(test)]
mod tests;
