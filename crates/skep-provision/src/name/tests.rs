//! T3 — THE NAME's GRAMMAR: the label rule after the lowercase, each
//! refusal for its reason; a name read back as this service wrote it,
//! never lowercased; and the host and the public origin a name stands at
//! under a suffix.

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
    assert_eq!(Name::parse(b"-a"), Err(NameRefused::Hyphen));
    assert_eq!(Name::parse(b"a-"), Err(NameRefused::Hyphen));
    assert_eq!(Name::parse("a".repeat(MAX_NAME_BYTES + 1).as_bytes()), Err(NameRefused::TooLong));
    assert_eq!(Name::parse(b"a.b"), Err(NameRefused::NotALabel));
    assert_eq!(Name::parse(b"a_b"), Err(NameRefused::NotALabel));
    assert_eq!(Name::parse(b""), Err(NameRefused::Empty));
    assert_eq!(Name::parse(b"a b"), Err(NameRefused::NotALabel));
    assert_eq!(Name::parse("caf\u{e9}".as_bytes()), Err(NameRefused::NotALabel));
    assert_eq!(Name::parse(&[b'a', 0xff]), Err(NameRefused::NotALabel));
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
