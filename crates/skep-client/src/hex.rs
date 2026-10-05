//! Lowercase hex, two digits a byte — the one spelling every hex this crate
//! emits takes (AUTH-1.3, AUTH-1.9); the decode admits either case, as the
//! wire's parsers do (AUTH-2.17).

/// Lowercase hex of `bytes`. Every emitter is in the acting half; the
/// feature-free build decodes alone.
#[cfg_attr(not(feature = "acting"), allow(dead_code))]
pub(crate) fn encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

/// The bytes `s` spells, either case; `None` on an odd length or a non-hex
/// byte — text of any content off the wire answers `None` and never panics.
pub(crate) fn decode(s: &str) -> Option<Vec<u8>> {
    fn nibble(c: u8) -> Option<u8> {
        match c {
            b'0'..=b'9' => Some(c - b'0'),
            b'a'..=b'f' => Some(c - b'a' + 10),
            b'A'..=b'F' => Some(c - b'A' + 10),
            _ => None,
        }
    }
    let digits = s.as_bytes();
    if digits.len() % 2 != 0 {
        return None;
    }
    let mut out = Vec::with_capacity(digits.len() / 2);
    for pair in digits.chunks_exact(2) {
        out.push((nibble(pair[0])? << 4) | nibble(pair[1])?);
    }
    Some(out)
}

/// Exactly 32 bytes from 64 hex digits, either case.
pub(crate) fn decode32(s: &str) -> Option<[u8; 32]> {
    if s.len() != 64 {
        return None;
    }
    decode(s)?.try_into().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_round_trips_and_refuses_odd_or_foreign_text() {
        assert_eq!(encode(&[0, 15, 255]), "000fff");
        assert_eq!(decode("000FFF"), Some(vec![0, 15, 255]));
        assert_eq!(decode("abc"), None);
        assert_eq!(decode("zz"), None);
        assert_eq!(decode32(&"ab".repeat(32)), Some([0xab; 32]));
        assert_eq!(decode32("ab"), None);
    }
}
