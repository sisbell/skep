//! T3 — THE NAME's GRAMMAR: the label rule after the lowercase, each
//! refusal for its reason — an error saying it — which refusal speaks where
//! two faults hold, and the alphabet at every byte; a name Docker cannot
//! take as a name alone refused — one byte, a hosts-file name, hex digits
//! alone — at the form and read back alike; a name read back as this
//! service wrote it, never lowercased; and the host and the public origin a
//! name stands at under a suffix.

use super::*;

/// T3: THE GRAMMAR — `Alice` admitted as `alice`; `xy` and a 63-byte label
/// admitted; a hyphen at either end, a 64-byte label, a dot, an underscore
/// and the empty name refused, each for its reason.
#[test]
fn the_name_is_one_lowercase_label_of_letters_digits_and_hyphens() {
    assert_eq!(Name::parse(b"Alice").expect("lowercased").as_str(), "alice");
    assert_eq!(Name::parse(b"xy").expect("two bytes").as_str(), "xy");
    let longest = "x".repeat(63);
    assert_eq!(Name::parse(longest.as_bytes()).expect("63 bytes").as_str(), longest);
    assert_eq!(Name::parse(b"ALICE-2").expect("digits and an inner hyphen").as_str(), "alice-2");
    assert_eq!(Name::parse(b"-a"), Err(NameRefused::HyphenAtEitherEnd));
    assert_eq!(Name::parse(b"a-"), Err(NameRefused::HyphenAtEitherEnd));
    assert_eq!(Name::parse("a".repeat(64).as_bytes()), Err(NameRefused::TooLong), "64 bytes");
    assert_eq!(Name::parse(b"a.b"), Err(NameRefused::OutOfTheAlphabet));
    assert_eq!(Name::parse(b"a_b"), Err(NameRefused::OutOfTheAlphabet));
    assert_eq!(Name::parse(b""), Err(NameRefused::Empty));
    assert_eq!(Name::parse(b"a b"), Err(NameRefused::OutOfTheAlphabet));
    assert_eq!(Name::parse("caf\u{e9}".as_bytes()), Err(NameRefused::OutOfTheAlphabet));
    assert_eq!(Name::parse(&[b'a', 0xff]), Err(NameRefused::OutOfTheAlphabet));
}

/// WHICH REFUSAL SPEAKS where two faults hold: the first in the grammar's
/// order — bytes that are not text before a field too long, a field too
/// long before a byte outside the alphabet, a byte outside the alphabet
/// before a hyphen at an end, a hyphen at an end before a field too short,
/// a field too short before hex digits alone — one case for each pair that
/// can hold at once (an empty field is text, and no longer than a label; a
/// hosts-file name is neither short nor hex digits alone).
#[test]
fn where_two_faults_hold_the_first_in_the_grammars_order_speaks() {
    let not_text_and_too_long = [&[0xff][..], "a".repeat(MAX_NAME_BYTES).as_bytes()].concat();
    assert_eq!(Name::parse(&not_text_and_too_long), Err(NameRefused::OutOfTheAlphabet));
    let too_long_and_out_of_the_alphabet = format!("{}_", "a".repeat(MAX_NAME_BYTES));
    assert_eq!(Name::parse(too_long_and_out_of_the_alphabet.as_bytes()), Err(NameRefused::TooLong));
    assert_eq!(Name::parse(b"-a_"), Err(NameRefused::OutOfTheAlphabet), "out of the alphabet and a hyphen at an end");
    assert_eq!(Name::parse(b"-"), Err(NameRefused::HyphenAtEitherEnd), "a hyphen at an end and one byte");
    assert_eq!(Name::parse(b"a"), Err(NameRefused::TooShort), "one byte and hex digits alone");
}

/// THE ALPHABET AT EVERY BYTE: `x`, one byte, `x` is a name iff the byte is
/// a letter, a digit or a hyphen — a capital lowercased — and
/// `OutOfTheAlphabet` for every other: a brace, a slash, a colon, an `@`, a
/// quote, a control character and every byte past ASCII among them. (`x`
/// frames the byte, so that no name of the three is hex digits alone.)
#[test]
fn every_byte_but_a_letter_a_digit_or_a_hyphen_is_refused() {
    for b in 0..=255u8 {
        let answered = Name::parse(&[b'x', b, b'x']);
        if b.is_ascii_alphanumeric() || b == b'-' {
            let lowered = format!("x{}x", char::from(b.to_ascii_lowercase()));
            assert_eq!(answered.as_ref().map(Name::as_str), Ok(lowered.as_str()), "{b:#04x}");
        } else {
            assert_eq!(answered, Err(NameRefused::OutOfTheAlphabet), "{b:#04x}");
        }
    }
}

/// A NAME DOCKER CANNOT TAKE AS A NAME ALONE IS REFUSED, at the form and
/// never at `docker volume create`, the health wait or a `docker rm -f`:
/// one byte; each name every container's hosts file answers; and hex
/// digits alone — a container's ID is 64 lowercase hex digits, and a
/// container command reads a name no container carries as an ID's unique
/// prefix — each refused read back too; a name with one letter past `f` or
/// a hyphen, and one merely holding a hosts word, admitted.
#[test]
fn a_name_docker_cannot_take_as_a_name_alone_is_refused() {
    for one in ["x", "a", "7", "Z"] {
        assert_eq!(Name::parse(one.as_bytes()), Err(NameRefused::TooShort), "{one}");
        assert_eq!(Name::exact(&one.to_ascii_lowercase()), None, "{one}");
    }
    for hosts in ["localhost", "LocalHost", "ip6-localhost", "ip6-loopback", "ip6-localnet", "ip6-mcastprefix", "ip6-allnodes", "ip6-allrouters"] {
        assert_eq!(Name::parse(hosts.as_bytes()), Err(NameRefused::HostsFileName), "{hosts}");
        assert_eq!(Name::exact(&hosts.to_ascii_lowercase()), None, "{hosts}");
    }
    let longest_hex = "f".repeat(MAX_NAME_BYTES);
    for hex in ["ab", "00", "cafe", "CAFE", "2024", "deadbeef", longest_hex.as_str()] {
        assert_eq!(Name::parse(hex.as_bytes()), Err(NameRefused::HexDigitsAlone), "{hex}");
        assert_eq!(Name::exact(&hex.to_ascii_lowercase()), None, "{hex}");
    }
    let one_past_f = format!("{}g", "f".repeat(MAX_NAME_BYTES - 1));
    for admitted in ["xy", "cafes", "a-b", "0x1f", "c0ffee-2", "localhost2", "ip6", one_past_f.as_str()] {
        assert_eq!(Name::parse(admitted.as_bytes()).as_ref().map(Name::as_str), Ok(admitted), "{admitted}");
    }
}

/// EACH REFUSAL IS AN ERROR saying its reason — and never the field, which
/// may hold anything a person typed.
#[test]
fn each_refusal_is_an_error_saying_its_reason() {
    let said: Vec<String> =
        [NameRefused::Empty, NameRefused::TooLong, NameRefused::OutOfTheAlphabet, NameRefused::HyphenAtEitherEnd, NameRefused::TooShort, NameRefused::HostsFileName, NameRefused::HexDigitsAlone]
            .iter()
            .map(|refused| (refused as &dyn std::error::Error).to_string())
            .collect();
    assert_eq!(
        said,
        [
            "the name is empty",
            "the name is longer than one label's 63 bytes",
            "the name holds a character outside letters, digits and hyphens",
            "the name begins or ends with a hyphen",
            "the name is one character, too short for a Docker name",
            "the name is one every container's hosts file answers, which never reaches the board",
            "the name is hex digits alone, which Docker reads as a container's ID",
        ]
    );
}

/// A NAME AS THIS SERVICE WROTE IT: `alice` and an inner hyphen read back
/// as they stand; `Alice`, which a post's field would lowercase, is no name
/// this service wrote, and neither is anything out of the grammar — one
/// byte, a hosts-file name and hex digits alone among it.
#[test]
fn a_name_read_back_as_written_is_never_lowercased() {
    assert_eq!(Name::exact("alice"), Some(Name::parse(b"alice").expect("a name")));
    assert_eq!(Name::exact("alice-2").map(|n| n.as_str().to_owned()), Some("alice-2".to_owned()));
    for unwritten in ["Alice", "ALICE", "a_b", "-a", "a-", "", "a.b", "x", "cafe", "localhost"] {
        assert_eq!(Name::exact(unwritten), None, "{unwritten:?}");
    }
}

/// The host and the PUBLIC origin a name stands at under a suffix.
#[test]
fn the_name_stands_at_its_host_and_its_public_origin() {
    let name = Name::parse(b"alice").expect("a name");
    assert_eq!(name.host("skep.host"), "alice.skep.host");
    assert_eq!(name.origin("skep.host"), "https://alice.skep.host");
}
