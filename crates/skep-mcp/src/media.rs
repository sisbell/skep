//! A fetched file's bytes: read whole under a cap, sniffed, and encoded.
//!
//! [`read_whole`] reads the shell's streamed fetch under the adapter's cap,
//! [`sniff_image`] names the bytes' type off their magic, and [`base64`]
//! encodes them for the content block, which `server.rs` builds.
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

use std::io::Read;

use skep_client::dial::Headers;

/// The most bytes `fetch` answers: one JSON-RPC line carries the whole file
/// as base64, so the bound is the line's, well under the board's 64 MiB per
/// file (wire.md §Transport). Eight mebibytes is the frame routes' request
/// cap and skep-client's answer cap, the one figure the wire already
/// bounds a single exchange by, and its base64 line is under eleven
/// mebibytes — what an agent runtime takes in one message and what a
/// model takes as one image. Checked against the answer's `Content-Length`
/// before a byte is read; a file past it is refused naming the cap.
pub const MAX_FETCH_BYTES: u64 = 8 * 1024 * 1024;

/// What a fetched file came back as.
#[derive(Debug)]
pub enum FetchAnswer {
    /// The file's bytes, whole.
    Bytes(Vec<u8>),
    /// The file is declared past [`MAX_FETCH_BYTES`], and no byte was read.
    ///
    /// `length` is its head's `Content-Length`.
    DeclaredPastTheCap { length: u64 },
    /// The body ran past [`MAX_FETCH_BYTES`], and its read was dropped.
    ///
    /// No length was declared, or one the body overran: `read` bytes came,
    /// one past the cap, and how long the file is, nothing here knows.
    RanPastTheCap { read: u64 },
    /// The stream ended short of the declared length — the board's RESET
    /// (wire.md §Media, THE FETCH), or a read that failed: `read` bytes came.
    Cut { read: usize, length: Option<u64>, error: String },
}

/// Reads a fetched file's body whole under [`MAX_FETCH_BYTES`].
///
/// `headers` is the fetch's head: its `Content-Length`, where it declares
/// one, is held to the cap before a byte of `body` is read, and the body is
/// then read to one byte past the cap at most. A file past the cap and a
/// stream cut short are answers, not errors: the shell's refusal of the
/// fetch came earlier, as [`Backend::fetch`](crate::shell::Backend::fetch)'s
/// `Err`.
pub fn read_whole(headers: &Headers, body: impl Read) -> FetchAnswer {
    let length = headers.get("Content-Length").and_then(|v| v.trim().parse::<u64>().ok());
    if let Some(length) = length {
        if length > MAX_FETCH_BYTES {
            return FetchAnswer::DeclaredPastTheCap { length };
        }
    }
    let mut bytes = Vec::new();
    let read = body.take(MAX_FETCH_BYTES + 1).read_to_end(&mut bytes);
    if bytes.len() as u64 > MAX_FETCH_BYTES {
        return FetchAnswer::RanPastTheCap { read: bytes.len() as u64 };
    }
    if let Err(e) = read {
        return FetchAnswer::Cut { read: bytes.len(), length, error: e.to_string() };
    }
    if let Some(length) = length {
        if (bytes.len() as u64) < length {
            return FetchAnswer::Cut { read: bytes.len(), length: Some(length), error: "the stream ended short of its declared length".into() };
        }
    }
    FetchAnswer::Bytes(bytes)
}

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
