//! T3 — THE NAME's GRAMMAR: the label rule after the lowercase, each
//! refusal for its reason — an error saying it — which refusal speaks where
//! two faults hold, and the alphabet at every byte; a name read back as
//! this service wrote it, never lowercased; and the host and the public
//! origin a name stands at under a suffix.

use super::*;

/// T3: THE GRAMMAR — `Alice` admitted as `alice`; `a` and a 63-byte label
/// admitted; a hyphen at either end, a 64-byte label, a dot, an underscore
/// and the empty name refused, each for its reason.
#[test]
fn the_name_is_one_lowercase_label_of_letters_digits_and_hyphens() {
    assert_eq!(Name::parse(b"Alice").expect("lowercased").as_str(), "alice");
    assert_eq!(Name::parse(b"a").expect("one byte").as_str(), "a");
    let longest = "a".repeat(MAX_NAME_BYTES);
    assert_eq!(Name::parse(longest.as_bytes()).expect("63 bytes").as_str(), longest);
    assert_eq!(Name::parse(b"ALICE-2").expect("digits and an inner hyphen").as_str(), "alice-2");
    assert_eq!(Name::parse(b"-a"), Err(NameRefused::HyphenAtEitherEnd));
    assert_eq!(Name::parse(b"a-"), Err(NameRefused::HyphenAtEitherEnd));
    assert_eq!(Name::parse("a".repeat(MAX_NAME_BYTES + 1).as_bytes()), Err(NameRefused::TooLong));
    assert_eq!(Name::parse(b"a.b"), Err(NameRefused::NotALabel));
    assert_eq!(Name::parse(b"a_b"), Err(NameRefused::NotALabel));
    assert_eq!(Name::parse(b""), Err(NameRefused::Empty));
    assert_eq!(Name::parse(b"a b"), Err(NameRefused::NotALabel));
    assert_eq!(Name::parse("caf\u{e9}".as_bytes()), Err(NameRefused::NotALabel));
    assert_eq!(Name::parse(&[b'a', 0xff]), Err(NameRefused::NotALabel));
}

/// WHICH REFUSAL SPEAKS where two faults hold: the first in the grammar's
/// order — bytes that are not text before a field too long, a field too
/// long before a byte outside the alphabet, a byte outside the alphabet
/// before a hyphen at an end — one case for each pair that can hold at
/// once (an empty field is text, and no longer than a label).
#[test]
fn where_two_faults_hold_the_first_in_the_grammars_order_speaks() {
    let not_text_and_too_long = [&[0xff][..], "a".repeat(MAX_NAME_BYTES).as_bytes()].concat();
    assert_eq!(Name::parse(&not_text_and_too_long), Err(NameRefused::NotALabel));
    let too_long_and_out_of_the_alphabet = format!("{}_", "a".repeat(MAX_NAME_BYTES));
    assert_eq!(Name::parse(too_long_and_out_of_the_alphabet.as_bytes()), Err(NameRefused::TooLong));
    assert_eq!(Name::parse(b"-a_"), Err(NameRefused::NotALabel), "out of the alphabet and a hyphen at an end");
}

/// THE ALPHABET AT EVERY BYTE: `a`, one byte, `a` is a name iff the byte is
/// a letter, a digit or a hyphen — a capital lowercased — and `NotALabel`
/// for every other: a brace, a slash, a colon, an `@`, a quote, a control
/// character and every byte past ASCII among them.
#[test]
fn every_byte_but_a_letter_a_digit_or_a_hyphen_is_refused() {
    for b in 0..=255u8 {
        let answered = Name::parse(&[b'a', b, b'a']);
        if b.is_ascii_alphanumeric() || b == b'-' {
            let lowered = format!("a{}a", char::from(b.to_ascii_lowercase()));
            assert_eq!(answered.as_ref().map(Name::as_str), Ok(lowered.as_str()), "{b:#04x}");
        } else {
            assert_eq!(answered, Err(NameRefused::NotALabel), "{b:#04x}");
        }
    }
}

/// EACH REFUSAL IS AN ERROR saying its reason — and never the field, which
/// may hold anything a person typed.
#[test]
fn each_refusal_is_an_error_saying_its_reason() {
    let said: Vec<String> =
        [NameRefused::Empty, NameRefused::TooLong, NameRefused::NotALabel, NameRefused::HyphenAtEitherEnd].iter().map(|refused| (refused as &dyn std::error::Error).to_string()).collect();
    assert_eq!(said, ["the name is empty", "the name is longer than one label's 63 bytes", "the name holds a character outside letters, digits and hyphens", "the name begins or ends with a hyphen"]);
}

/// A NAME AS THIS SERVICE WROTE IT: `alice` and an inner hyphen read back
/// as they stand; `Alice`, which a post's field would lowercase, is no name
/// this service wrote, and neither is anything out of the grammar.
#[test]
fn a_name_read_back_as_written_is_never_lowercased() {
    assert_eq!(Name::exact("alice"), Some(Name::parse(b"alice").expect("a name")));
    assert_eq!(Name::exact("alice-2").map(|n| n.as_str().to_owned()), Some("alice-2".to_owned()));
    for unwritten in ["Alice", "ALICE", "a_b", "-a", "a-", "", "a.b"] {
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
