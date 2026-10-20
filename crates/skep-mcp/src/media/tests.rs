use std::io;

use super::*;

/// The encoder against RFC 4648 §10's test vectors — the seven the RFC
/// lists, each padding case among them — and against a vector of every byte
/// value, decoded back by a reader of the alphabet written here apart from
/// the encoder, so an encoder that mapped one sextet wrong would fail.
#[test]
fn base64_matches_the_rfc_vectors_and_round_trips_every_byte() {
    for (plain, encoded) in [("", ""), ("f", "Zg=="), ("fo", "Zm8="), ("foo", "Zm9v"), ("foob", "Zm9vYg=="), ("fooba", "Zm9vYmE="), ("foobar", "Zm9vYmFy")] {
        assert_eq!(base64(plain.as_bytes()), encoded, "{plain:?}");
    }
    // Two fixed vectors beyond the RFC's: a byte string of the PNG
    // signature, and a line with every alphabet character's sextet.
    assert_eq!(base64(b"\x89PNG\r\n\x1a\n"), "iVBORw0KGgo=");
    assert_eq!(base64(&[0x00, 0x10, 0x83, 0x10, 0x51, 0x87, 0x20, 0x92, 0x8b, 0x30, 0xd3, 0x8f]), "ABCDEFGHIJKLMNOP");
    let every: Vec<u8> = (0u8..=255).collect();
    let encoded = base64(&every);
    assert_eq!(encoded.len(), 344, "256 bytes are 86 groups, the last padded");
    assert!(encoded.ends_with("/w=="), "the last byte, 0xff, alone in its group: {encoded}");
    assert_eq!(decode(&encoded), every, "the encoding reads back");
    for n in 0..=6usize {
        let bytes = &every[..n];
        assert_eq!(decode(&base64(bytes)), bytes, "{n} bytes round-trip");
    }
}

/// A reader of the standard alphabet, written apart from the encoder.
fn decode(text: &str) -> Vec<u8> {
    let value = |c: u8| ALPHABET.iter().position(|&a| a == c).expect("an alphabet character") as u32;
    let mut out = Vec::new();
    for group in text.as_bytes().chunks(4) {
        assert_eq!(group.len(), 4, "every group is four characters");
        let pad = group.iter().filter(|&&c| c == b'=').count();
        let n = group.iter().take(4 - pad).fold(0u32, |n, &c| (n << 6) | value(c)) << (6 * pad);
        let bytes = n.to_be_bytes();
        out.extend_from_slice(&bytes[1..4 - pad]);
    }
    out
}

/// The sniff names the four image types by their magic alone, and nothing else.
///
/// A JPEG by its SOI and the marker byte after it, a WebP by both halves of
/// its RIFF header — a header no longer than its twelve bytes included — and
/// a string that opens like one but is cut short, or is text, or is empty,
/// is no image.
#[test]
fn the_sniff_names_the_four_image_types_by_their_magic_alone() {
    assert_eq!(sniff_image(b"\x89PNG\r\n\x1a\nIHDR..."), Some("image/png"));
    assert_eq!(sniff_image(b"\xff\xd8\xff\xe0\x00\x10JFIF"), Some("image/jpeg"));
    assert_eq!(sniff_image(b"GIF89a\x01\x00\x01\x00"), Some("image/gif"));
    assert_eq!(sniff_image(b"GIF87a\x01\x00\x01\x00"), Some("image/gif"));
    assert_eq!(sniff_image(b"RIFF\x24\x00\x00\x00WEBPVP8 "), Some("image/webp"));
    assert_eq!(sniff_image(b"RIFF\x04\x00\x00\x00WEBP"), Some("image/webp"), "a WebP header no longer than its twelve bytes");
    for not_an_image in
        [&b""[..], b"\x89PNG\r\n", b"\xff\xd8\xd8", b"GIF90a", b"RIFF\x24\x00\x00\x00WAVE", b"RIFF\x24\x00\x00WEB", b"PNG\r\n\x1a\n", b"{\"type\":\"1.1.0.1.0.1.0.3.89\"}", b"hello, world"]
    {
        assert_eq!(sniff_image(not_an_image), None, "{:?}", String::from_utf8_lossy(not_an_image));
    }
}

/// The cap is the adapter's own, well under the board's 64 MiB per file,
/// and its base64 line stays under 11 MiB.
#[test]
fn the_cap_sits_well_under_the_boards_per_file_cap() {
    let (board_per_file, line_bound): (u64, u64) = (64 * 1024 * 1024, 11 * 1024 * 1024);
    assert_eq!(MAX_FETCH_BYTES, 8 * 1024 * 1024);
    assert!(MAX_FETCH_BYTES * 8 <= board_per_file, "the board serves eight times the cap");
    assert!(base64(&vec![0u8; MAX_FETCH_BYTES as usize]).len() < line_bound as usize, "the base64 line at the cap");
}

/// The read holds the cap both ways and tells a whole file from a cut one.
///
/// A declared length past the cap is refused before a byte of the body is read,
/// and a body that declares no length, or overruns the one it declares, is
/// refused once a byte past the cap has come — the two told apart; a body short
/// of its declared length is cut `UnexpectedEof`, and one broken off by a
/// failed read is cut with that read's own error, the bytes that came counted
/// — an undeclared file's length unknown; a body at its declared length is
/// whole, and so is one at the cap, declared or not.
#[test]
fn the_read_holds_the_cap_and_tells_a_whole_file_from_a_cut_one() {
    // A body no read may touch.
    struct Untouched;
    impl Read for Untouched {
        fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
            panic!("a byte of a file past the cap was read")
        }
    }
    // A body that breaks off after its bytes, as a reset stream does.
    struct BreaksAfter(&'static [u8]);
    impl Read for BreaksAfter {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            if self.0.is_empty() {
                return Err(io::Error::other("connection reset"));
            }
            let n = self.0.len().min(buf.len());
            buf[..n].copy_from_slice(&self.0[..n]);
            self.0 = &self.0[n..];
            Ok(n)
        }
    }
    let declared = |n: u64| Headers(vec![("Content-Length".to_string(), n.to_string())]);
    let undeclared = Headers(Vec::new());
    let past = MAX_FETCH_BYTES + 1;
    assert!(matches!(read_whole(&declared(past), Untouched), FetchAnswer::DeclaredPastTheCap { length } if length == past));
    let oversized = io::repeat(7).take(MAX_FETCH_BYTES + 2);
    assert!(matches!(read_whole(&undeclared, oversized), FetchAnswer::RanPastTheCap { read } if read == past), "the read stops one byte past the cap");
    let overrun = io::repeat(7).take(MAX_FETCH_BYTES + 2);
    assert!(matches!(read_whole(&declared(10), overrun), FetchAnswer::RanPastTheCap { read } if read == past), "a body past its own declared length is read to the cap too");
    match read_whole(&declared(10), &b"abcd"[..]) {
        FetchAnswer::Cut { read: 4, length: Some(10), error } => {
            assert_eq!(error.kind(), io::ErrorKind::UnexpectedEof, "{error}");
            assert!(error.to_string().contains("short of its declared length"), "{error}");
        }
        other => panic!("a short body is cut: {other:?}"),
    }
    match read_whole(&declared(10), BreaksAfter(b"abc")) {
        FetchAnswer::Cut { read: 3, length: Some(10), error } => {
            assert_eq!(error.kind(), io::ErrorKind::Other, "the failed read's own error: {error}");
            assert!(error.to_string().contains("connection reset"), "{error}");
        }
        other => panic!("a broken read is cut: {other:?}"),
    }
    assert!(matches!(read_whole(&undeclared, BreaksAfter(b"abc")), FetchAnswer::Cut { read: 3, length: None, .. }), "a broken read of an undeclared file is cut, its length unknown");
    assert!(matches!(read_whole(&declared(5), &b"hello"[..]), FetchAnswer::Whole(bytes) if bytes == b"hello"));
    let at_cap = read_whole(&undeclared, io::repeat(1).take(MAX_FETCH_BYTES));
    assert!(matches!(at_cap, FetchAnswer::Whole(bytes) if bytes.len() as u64 == MAX_FETCH_BYTES), "a file at the cap is whole");
    let declared_at_cap = read_whole(&declared(MAX_FETCH_BYTES), io::repeat(1).take(MAX_FETCH_BYTES));
    assert!(matches!(declared_at_cap, FetchAnswer::Whole(bytes) if bytes.len() as u64 == MAX_FETCH_BYTES), "a file declared at the cap is whole");
}

/// A body paced inside the per-read bound is cut at its deadline.
///
/// Each read yields one byte after a short wait, as a peer pacing bytes inside
/// skep-client's per-read bound does, so no read's own timeout fires: the
/// deadline alone ends the read, `TimedOut`, the bytes that came counted; a
/// body whose deadline has passed is never read; and the deadline is never
/// shorter than an honest board's stream.
#[test]
fn a_paced_body_is_cut_at_its_deadline_and_one_past_it_is_never_read() {
    // A hundred bytes, one each 20 ms: two seconds whole.
    struct Paced(usize);
    impl Read for Paced {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            if self.0 == 0 || buf.is_empty() {
                return Ok(0);
            }
            std::thread::sleep(Duration::from_millis(20));
            buf[0] = 7;
            self.0 -= 1;
            Ok(1)
        }
    }
    // A body no read may touch.
    struct Untouched;
    impl Read for Untouched {
        fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
            panic!("a body past its deadline was read")
        }
    }
    let declared = Headers(vec![("Content-Length".to_string(), "100".to_string())]);
    let started = Instant::now();
    match read_within(&declared, Paced(100), Duration::from_millis(200)) {
        FetchAnswer::Cut { read, length: Some(100), error } => {
            assert_eq!(error.kind(), io::ErrorKind::TimedOut, "{error}");
            assert!(read > 0 && read < 100, "the bytes that came, counted: {read}");
        }
        other => panic!("a paced body is cut at its deadline: {other:?}"),
    }
    assert!(started.elapsed() < Duration::from_secs(1), "cut at the deadline, not at the body's end: {:?}", started.elapsed());
    assert!(matches!(read_within(&Headers(Vec::new()), Untouched, Duration::ZERO), FetchAnswer::Cut { read: 0, length: None, .. }), "a body past its deadline is never read");
    assert!(FETCH_DEADLINE >= Duration::from_secs(10 * 60 + 30), "never shorter than an honest board's stream");
}
