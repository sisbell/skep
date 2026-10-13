//! T2 — THE FORM's DECODE: the fields in order, `+` a space, `%XX` the
//! byte — every byte, in either case — and every other byte itself, a bad
//! escape refused — an error saying where — the first of a field given
//! twice, a CRLF kept as given, a value kept as bytes, and none of them in
//! the form's `Debug`; and a fourth field refused, whatever its shape, a
//! body of `a&` to the pages' cap among them.

use super::*;

/// The fields as byte-string pairs, to compare whole.
fn pairs(form: &Form) -> Vec<(&[u8], &[u8])> {
    form.fields().iter().map(|(n, v)| (n.as_slice(), v.as_slice())).collect()
}

/// T2: three fields decode IN ORDER, `+` a space, and the braces, the quote
/// and the colon a browser percent-encodes restored.
#[test]
fn three_fields_decode_in_order_with_plus_a_space_and_the_escapes_restored() {
    let form = decode(b"a=1&b=x+y&c=%7B%22k%22%3A1%7D").expect("a form");
    assert_eq!(pairs(&form), vec![(&b"a"[..], &b"1"[..]), (&b"b"[..], &b"x y"[..]), (&b"c"[..], &br#"{"k":1}"#[..])]);
}

/// T2: `%XX` IS THE BYTE IT NAMES, FOR EVERY BYTE AND IN EITHER CASE — the
/// digits and letters the other cases here never reach among them, which a
/// label's UTF-8 does (`é` is `%C3%A9`) — and every byte but `%`, `+` and
/// `&` passes through a value as itself.
#[test]
fn every_byte_decodes_from_its_escape_and_passes_through_as_itself() {
    for b in 0..=255u8 {
        for escaped in [format!("v=%{b:02X}"), format!("v=%{b:02x}")] {
            assert_eq!(decode(escaped.as_bytes()).map(|form| form.get("v").map(<[u8]>::to_vec)), Ok(Some(vec![b])), "{escaped}");
        }
        if !b"%+&".contains(&b) {
            assert_eq!(decode(&[b'v', b'=', b]).expect("a form").get("v"), Some(&[b][..]), "the byte {b:#04x}, raw");
        }
    }
}

/// T2: a `%` that two hex digits do not follow is REFUSED, at its offset in
/// the body — never passed through; either case of hex digit is one.
#[test]
fn a_percent_without_two_hex_digits_is_refused_at_its_offset() {
    let cases: [(&[u8], usize); 7] = [(b"a=%4", 2), (b"a=%zz", 2), (b"a=%", 2), (b"a=1&b=%G1", 6), (b"%2=x", 0), (b"a=%4g", 2), (b"a=1&&b=%", 7)];
    for (body, at) in cases {
        assert_eq!(decode(body), Err(Undecodable::Escape(BadEscape { at })), "{}", String::from_utf8_lossy(body));
    }
    assert_eq!(decode(b"a=%7b%7B").expect("both cases").get("a"), Some(&b"{{"[..]));
    let refused: &dyn std::error::Error = &BadEscape { at: 6 };
    assert_eq!(refused.to_string(), "the `%` at byte 6 is not followed by two hex digits");
}

/// T2: a field given twice yields THE FIRST, both kept in the order sent.
#[test]
fn a_field_given_twice_yields_the_first() {
    let form = decode(b"name=alice&name=bob").expect("a form");
    assert_eq!(form.get("name"), Some(&b"alice"[..]));
    assert_eq!(form.fields().len(), 2);
}

/// T2: a CRLF inside a value is KEPT AS GIVEN — percent-encoded, as a
/// browser sends a textarea's line break, and raw.
#[test]
fn crlf_inside_a_value_is_kept_as_given() {
    assert_eq!(decode(b"record=x%0D%0Ay").expect("a form").get("record"), Some(&b"x\r\ny"[..]));
    assert_eq!(decode(b"record=x\r\ny").expect("a form").get("record"), Some(&b"x\r\ny"[..]));
    assert_eq!(decode(b"record=line%0D%0A").expect("a form").get("record"), Some(&b"line\r\n"[..]));
}

/// The split's edges: a part with no `=` is a name with an empty value, an
/// empty part no field, a value's own `=` kept, an empty body no field.
#[test]
fn the_split_at_its_edges() {
    let form = decode(b"a&&b=2&").expect("a form");
    assert_eq!(pairs(&form), vec![(&b"a"[..], &b""[..]), (&b"b"[..], &b"2"[..])]);
    assert_eq!(decode(b"a=1=2").expect("a form").get("a"), Some(&b"1=2"[..]));
    assert!(decode(b"").expect("an empty form").fields().is_empty());
    assert_eq!(decode(b"x=1").expect("a form").get("y"), None);
    assert_eq!(decode(b"a%20b=c").expect("a name decoded too").get("a b"), Some(&b"c"[..]));
}

/// A value stays BYTES: bytes that are not text reach the record's judge as
/// sent.
#[test]
fn a_value_stays_bytes() {
    assert_eq!(decode(b"record=%FF%FE").expect("a form").get("record"), Some(&[0xff_u8, 0xfe][..]));
}

/// A form's `Debug` shows the count of its fields alone: a value may be a
/// record, an invite code or an address.
#[test]
fn a_forms_debug_shows_none_of_its_values() {
    assert_eq!(format!("{:?}", decode(b"record=%7B%7D&invite=c0de").expect("a form")), "Form { fields: 2 }");
}

/// THE FIELDS' CAP: three fields decode, and an empty part is no field; a
/// fourth is refused, whatever its shape — a bad escape in it among them —
/// and a body of `a&` to the pages' cap is refused at its fourth field,
/// never copied whole 48 times over; the refusal says the cap.
#[test]
fn a_fourth_field_is_refused() {
    assert_eq!(decode(b"a&b&c").map(|form| form.fields().len()), Ok(MAX_FIELDS));
    assert_eq!(decode(b"a&&b&&c&&").map(|form| form.fields().len()), Ok(MAX_FIELDS), "an empty part is no field");
    for body in [&b"a&b&c&d"[..], b"=&=&=&=", b"a=1&b=2&c=3&%zz"] {
        assert_eq!(decode(body), Err(Undecodable::TooManyFields), "{}", String::from_utf8_lossy(body));
    }
    assert_eq!(decode(&b"a&".repeat(198_656)), Err(Undecodable::TooManyFields));
    assert_eq!(decode(b"a=%zz&b&c&d"), Err(Undecodable::Escape(BadEscape { at: 2 })), "a bad escape in a field within the cap speaks first");
    let refused: &dyn std::error::Error = &Undecodable::TooManyFields;
    assert_eq!(refused.to_string(), "the body names more than 3 fields");
}
