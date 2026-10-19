//! The bytes of a fetched file as a tool result: the type SNIFFED off the
//! bytes' magic, and the base64 the content block carries.
//!
//! The board declares no media type — a picture's cell is `{type, hash,
//! size}` and the fetch's `Content-Type` is always `application/octet-stream`
//! (wire.md §Media, THE FETCH: "the daemon reads no type off the bytes and
//! declares none it did not read") — so the adapter reads the magic itself:
//! PNG, JPEG, GIF and WebP are answered as an image block with the type the
//! magic names, and everything else as an embedded resource of
//! `application/octet-stream`. A sniffed type is never attested: a wrong
//! sniff is a wrong block, never a wrong byte. The encoder is written out
//! here rather than taken from a crate (RFC 4648 §4, the standard alphabet
//! with `=` padding), held to the RFC's own vectors by the unit tests.

/// The most bytes `fetch` answers: one JSON-RPC line carries the whole file
/// as base64, so the bound is the line's, well under the board's 64 MiB per
/// file (wire.md §Transport). Eight mebibytes is the frame routes' request
/// cap and skep-client's answer cap, the one figure the wire already
/// bounds a single exchange by, and its base64 line is under eleven
/// mebibytes — what an agent runtime takes in one message and what a
/// model takes as one image. Checked against the answer's `Content-Length`
/// before a byte is read; a file past it is refused naming the cap.
pub const MAX_FETCH_BYTES: u64 = 8 * 1024 * 1024;

/// Returns the image media type the bytes' magic names, where it names one.
///
/// PNG by its eight-byte signature, JPEG by its SOI marker and the `FF` that
/// follows, GIF by `GIF87a` or `GIF89a`, WebP by the RIFF header whose form
/// type is `WEBP`; `None` for every other byte string, the empty one
/// included.
pub fn sniff_image(bytes: &[u8]) -> Option<&'static str> {
    if bytes.starts_with(b"\x89PNG\r\n\x1a\n") {
        Some("image/png")
    } else if bytes.starts_with(b"\xff\xd8\xff") {
        Some("image/jpeg")
    } else if bytes.starts_with(b"GIF87a") || bytes.starts_with(b"GIF89a") {
        Some("image/gif")
    } else if bytes.len() >= 12 && bytes.starts_with(b"RIFF") && &bytes[8..12] == b"WEBP" {
        Some("image/webp")
    } else {
        None
    }
}

/// The standard alphabet (RFC 4648 §4).
const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Returns `bytes` as base64 (RFC 4648 §4): the standard alphabet, three
/// bytes to four characters, the last group padded with `=` to four.
pub fn base64(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    let (groups, remainder) = bytes.as_chunks::<3>();
    for [a, b, c] in groups {
        let n = (u32::from(*a) << 16) | (u32::from(*b) << 8) | u32::from(*c);
        for shift in [18, 12, 6, 0] {
            out.push(ALPHABET[((n >> shift) & 63) as usize] as char);
        }
    }
    match *remainder {
        [a] => {
            let n = u32::from(a) << 16;
            out.push(ALPHABET[((n >> 18) & 63) as usize] as char);
            out.push(ALPHABET[((n >> 12) & 63) as usize] as char);
            out.push_str("==");
        }
        [a, b] => {
            let n = (u32::from(a) << 16) | (u32::from(b) << 8);
            out.push(ALPHABET[((n >> 18) & 63) as usize] as char);
            out.push(ALPHABET[((n >> 12) & 63) as usize] as char);
            out.push(ALPHABET[((n >> 6) & 63) as usize] as char);
            out.push('=');
        }
        _ => {}
    }
    out
}

#[cfg(test)]
mod tests;
