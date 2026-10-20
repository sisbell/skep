//! A fetched file's bytes: read whole under a cap, sniffed, and encoded.
//!
//! [`read_whole`] reads the shell's streamed fetch under the adapter's cap
//! and its deadline, [`sniff_image`] names the bytes' type off their magic,
//! and [`base64`] encodes them for the content block, which `server.rs`
//! builds.
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

use std::io::{self, Read};
use std::time::{Duration, Instant};

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

/// The longest a fetched file's body is read.
///
/// It is an honest board's own bound on its fetch stream — wire.md
/// §Transport's transfer bound of ten minutes and idle bound of thirty
/// seconds (skepd's `BLOB_TRANSFER_BOUND` and `BLOB_IDLE_BOUND`) — past which
/// the board has ended the stream itself, at its length or by a RESET short
/// of it, so it cuts nothing an honest board still sends. It bounds the
/// slowness skep-client's per-read bound cannot: the streamed form leaves
/// the body's time to its caller, a peer pacing a byte inside each per-read
/// bound renews that bound for as long as it likes, and this adapter
/// answers one call at a time. It is checked before each read, so the read
/// ends within one per-read bound past it.
const FETCH_DEADLINE: Duration = Duration::from_secs(10 * 60 + 30);

/// A body read under a deadline.
///
/// A read begun at or past `deadline` is refused `TimedOut`, unmade.
struct Deadlined<R> {
    body: R,
    deadline: Instant,
}

impl<R: Read> Read for Deadlined<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if Instant::now() >= self.deadline {
            return Err(io::Error::new(io::ErrorKind::TimedOut, "the file did not arrive within the fetch's deadline"));
        }
        self.body.read(buf)
    }
}

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
    /// The stream ended short, a read failed, or its deadline passed.
    ///
    /// The board's RESET (wire.md §Media, THE FETCH) is one: `read` bytes
    /// came, and `error` says why — the failed read's own, `UnexpectedEof`
    /// where the stream ended short of the declared length, or `TimedOut`
    /// where `FETCH_DEADLINE` passed before the file was whole.
    Cut { read: u64, length: Option<u64>, error: io::Error },
}

/// Reads a fetched file's body whole under the adapter's cap and deadline.
///
/// `headers` is the fetch's head: its `Content-Length`, where it declares
/// one, is held to [`MAX_FETCH_BYTES`] before a byte of `body` is read, and
/// the body is then read to one byte past the cap at most, each read begun
/// before `FETCH_DEADLINE` has passed. A file past the cap and a stream cut
/// short are answers, not errors: the shell's refusal of the fetch came
/// earlier, as [`Backend::fetch`](crate::shell::Backend::fetch)'s `Err`.
pub fn read_whole(headers: &Headers, body: impl Read) -> FetchAnswer {
    read_within(headers, body, FETCH_DEADLINE)
}

/// Reads a fetched file's body whole, its reads begun within `within`.
///
/// It is [`read_whole`] with the deadline given, so a test can shorten it.
fn read_within(headers: &Headers, body: impl Read, within: Duration) -> FetchAnswer {
    let length = headers.get("Content-Length").and_then(|v| v.trim().parse::<u64>().ok());
    if let Some(length) = length {
        if length > MAX_FETCH_BYTES {
            return FetchAnswer::DeclaredPastTheCap { length };
        }
    }
    let mut bytes = Vec::new();
    let read = Deadlined { body, deadline: Instant::now() + within }.take(MAX_FETCH_BYTES + 1).read_to_end(&mut bytes);
    if bytes.len() as u64 > MAX_FETCH_BYTES {
        return FetchAnswer::RanPastTheCap { read: bytes.len() as u64 };
    }
    if let Err(error) = read {
        return FetchAnswer::Cut { read: bytes.len() as u64, length, error };
    }
    if let Some(length) = length {
        if (bytes.len() as u64) < length {
            let error = io::Error::new(io::ErrorKind::UnexpectedEof, "the stream ended short of its declared length");
            return FetchAnswer::Cut { read: bytes.len() as u64, length: Some(length), error };
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
