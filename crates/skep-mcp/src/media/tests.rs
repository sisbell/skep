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

/// The sniff names the four image types by their magic alone and nothing
/// else: a JPEG by its SOI and the marker byte after it, a WebP by both
/// halves of its RIFF header, and a string that opens like one but is cut
/// short, or is text, or is empty, is no image.
#[test]
fn the_sniff_names_the_four_image_types_by_their_magic_alone() {
    assert_eq!(sniff_image(b"\x89PNG\r\n\x1a\nIHDR..."), Some("image/png"));
    assert_eq!(sniff_image(b"\xff\xd8\xff\xe0\x00\x10JFIF"), Some("image/jpeg"));
    assert_eq!(sniff_image(b"GIF89a\x01\x00\x01\x00"), Some("image/gif"));
    assert_eq!(sniff_image(b"GIF87a\x01\x00\x01\x00"), Some("image/gif"));
    assert_eq!(sniff_image(b"RIFF\x24\x00\x00\x00WEBPVP8 "), Some("image/webp"));
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
/// A declared length past the cap is refused before a byte of the body is
/// read, and a body that declares no length, or overruns the one it
/// declares, is refused once a byte past the cap has come — the two told
/// apart; a body short of its declared length, or broken off by a
/// failed read, is cut, the bytes that came counted; a body at its declared
/// length is whole, and so is one at the cap that declares no length.
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
        FetchAnswer::Cut { read: 4, length: Some(10), error } => assert!(error.contains("short of its declared length"), "{error}"),
        other => panic!("a short body is cut: {other:?}"),
    }
    match read_whole(&declared(10), BreaksAfter(b"abc")) {
        FetchAnswer::Cut { read: 3, length: Some(10), error } => assert!(error.contains("connection reset"), "{error}"),
        other => panic!("a broken read is cut: {other:?}"),
    }
    assert!(matches!(read_whole(&declared(5), &b"hello"[..]), FetchAnswer::Bytes(bytes) if bytes == b"hello"));
    let at_cap = read_whole(&undeclared, io::repeat(1).take(MAX_FETCH_BYTES));
    assert!(matches!(at_cap, FetchAnswer::Bytes(bytes) if bytes.len() as u64 == MAX_FETCH_BYTES), "a file at the cap is whole");
}
