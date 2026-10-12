//! T2 — THE FORM's DECODE: the fields in order, `+` a space, `%XX` the
//! byte, a bad escape refused, the first of a field given twice, a CRLF
//! kept as given, a value kept as bytes.

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

/// T2: a `%` that two hex digits do not follow is REFUSED, at its offset in
/// the body — never passed through; either case of hex digit is one.
#[test]
fn a_percent_without_two_hex_digits_is_refused_at_its_offset() {
    let cases: [(&[u8], usize); 7] = [(b"a=%4", 2), (b"a=%zz", 2), (b"a=%", 2), (b"a=1&b=%G1", 6), (b"%2=x", 0), (b"a=%4g", 2), (b"a=1&&b=%", 7)];
    for (body, at) in cases {
        assert_eq!(decode(body), Err(BadEscape { at }), "{}", String::from_utf8_lossy(body));
    }
    assert_eq!(decode(b"a=%7b%7B").expect("both cases").get("a"), Some(&b"{{"[..]));
    assert_eq!(BadEscape { at: 6 }.to_string(), "the `%` at byte 6 is not followed by two hex digits");
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
